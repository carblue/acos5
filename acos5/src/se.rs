/*
 * se.rs: Driver 'acos5' - Security Environment (SE) related code
 *
 * Copyright (C) 2019  Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110-1335  USA
 */

/*
cos5's management of access rights is complex (SAC, SAE, SM ...)

How SE-related processing works/is implemented here:

For SAC (Security Attributes Compact),
based solely on SCB (Security Condition Bytes) in file/directory FCI/FCP header data,
e.g. scb8 [0xFF, 0x41, 2, 3, 4, 0, 0, 0xFF] for file_id 0x4101 in directory 0x4100:
SCB 0   : no restriction/always allow
SCB 0xFF: never allow

for all other byte values it must be decoded and retrieved from relevant Security Environment file,
which file access restrictions apply, i.e. which pin must be verified or which sym. key must be
authenticated or whether Secure Messaging must be applied.
SCB 2 may e.g. entail: Do verify the global (Security Officer/admin) pin id 1, stored in MF's pin file
SCB 3 may e.g. entail: Do verify the local (User) pin id 1, stored in current DF's pin file
The user will see in opensc-tool -f a CHV entry instead for both SCB 2 and 3, and a 1 for the global pin 1,
and a 129 for the local pin 1
(for local, 0x80 get's added)
During processing of acos5_init, the HashMap 'files' will be filled for all existing files with data
about absolute path and those data retrieved from cos5 'Get Card Info, P1=2: File Information' among which
essentially is FDB (File Descriptor Byte), all other info like scb8 get's retrieved lazily only
(during select_file/process_fci processing).

On each selection of a directory (if no info is stored already), the associated SE-file within that
directory will be selected and all of it's records evaluated and the content stored in Vec<SACinfo>,
a separate Vec<SACinfo> for each SE file id/directory, attached to directory's hashmap data.
Vec<SACinfo> data applies to a directory and all its "directly" contained files except sub-directories.
This Vec<SACinfo>  is then moved to the 'files' entry for that directory.
Back to the example scb8 [0xFF, 0x41, 2, 3, 4, 0, 0, 0xFF] for file_id 0x4101 in directory 0x4100:
dp.files[0x4101] knows it's absolute path [0x3F, 0, 0x41, 0, 0x41, 1], with last 2 bytes (fid)
stripped of get's the absolute path of relevant directory 0x4100. This HashMap entry has a Vec<SACinfo>
stored with an entry for reference 2 (responsible for SCB 2)
For simple cases like SCB between 1 and 14, there will be one only entry in SACinfo's array crts with a
tag 0xA4, the usage field indicates what action to perform: Authenticate or Verify (in our example Verify)
and refs[0] contains 0x01, i.e. global Pin 1, thus show CHV1 to the user for SCB 2.

TODO Clarify: cos5 allows more complicated cases:
SCB between 1 and 14 means: one of possible multiple conditions must be fulfilled, i.e. there might have
been another pin id in refs[1] or even more in our example above, that may be verified as an alternative,
in order to give access.
SCB between 129 and 142 means: All conditions must be fulfilled

TODO consolidate, remove redundancy

There is another example, even more complex in the re. manual:
AT is A4 09 83 01 84 83 01 01 95 01 88h; contains 2 conditions inside it.
1st condition in AT is: 83 01 84 95 01 88h -> Allow cmd if local  KEY #04 is authentic. AND if local  PIN #04 is verif.;
2nd condition in AT is: 83 01 01 95 01 88h -> Allow cmd if global KEY #01 is authentic. AND if global PIN #01 is verif.;
It's clear how to encode this in SACinfo, but how to communicate this to opensc (sc_file_add_acl_entry;
what to be shown in opensc-tool -f


For SAE (Security Attributes Expanded), TODO
*/

#![allow(clippy::module_name_repetitions)]

use opensc_sys::opensc::{sc_card, sc_file_add_acl_entry};
use opensc_sys::types::{sc_file, sc_crt, SC_AC_NONE, SC_AC_NEVER, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE,
SC_AC_CHV, SC_AC_AUT, SC_AC_PRO,
SC_AC_OP_LIST_FILES, SC_AC_OP_SELECT, SC_AC_OP_DELETE, SC_AC_OP_CREATE_EF,
SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_READ,
SC_AC_OP_UPDATE, SC_AC_OP_CRYPTO, SC_AC_OP_DELETE_SELF, SC_AC_OP_CREATE, SC_AC_OP_WRITE,
SC_AC_OP_GENERATE, SC_MAX_CRTS_IN_SE};

use opensc_sys::errors::{SC_SUCCESS};
use opensc_sys::asn1::{sc_asn1_read_tag, SC_ASN1_TAG_EOC};

use crate::constants_types::{DataPrivate, FDB_RSA_KEY_EF, FDB_SE_FILE, FDB_SYMMETRIC_KEY_EF, SACinfo, SAEinfo, Tlv,
                             is_DFMF, FDB_ECC_KEY_EF, UPDATE, CRYPTO, DELETE_SELF, CREATE_EF, CREATE_DF,
                             file_id_from_path_value /*, p_void*/};
use crate::path::{current_path_df};

/*
It's not possible to map file access conditions from ACOS5 (scb8) to OpenSC exactly:
1. ACOS5 (but not OpenSC) allows to OR-combine access conditions, saying somethings like: "At least one of the following conditions must be fulfilled".
   OpenSC only has the AND operator, saying: "All of the following conditions must be fulfilled".
   Therefore se_file_add_acl_entry will pass only the first of several OR-combined alternatives to OpenSC
2. As far as I understand the OpenSC code, it doesn't allow authentication of a key as file access condition, the way ACOS5
   does that via external authentication procedure, i.e. it's not about comparing secrets directly as with pins, but indirectly:
   whether both parties encrypt a challenge to the same result value, which implies the keys used must be the same.
   se_file_add_acl_entry will map that as SC_AC_AUT, but don't use that as a file access condition, except it's
   the SM key 0x81 and SCB has SM bit 0x40 set.

   SC_AC_CHV, SC_AC_AUT and SC_AC_PRO will be passed to OpenSC:
   SC_AC_CHV is okay and OpenSC knows it must ask the user for a pin verification.
   SC_AC_AUT Don't use. OpenSC doesn't know what to ask the user for and will default to an inappropriate transport key verification
   SC_AC_PRO It's assumed that it's a marker only to visualize in opensc-tool, that this operation will be SM protected,
     but OpenSC does nothing else with that
*/
pub fn map_scb8_to_acl(card: &mut sc_card, file: &mut sc_file, scb8: [u8; 8], fdb: u8)
{
    /* select_file is always allowed */
    assert_eq!(    SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, SC_AC_OP_SELECT,     SC_AC_NONE, SC_AC_KEY_REF_NONE) } );
    if is_DFMF(fdb) {
        /* list_files is always allowed for MF/DF */
        assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_NONE, SC_AC_KEY_REF_NONE) } );
        /* for opensc-tool also add the general SC_AC_OP_CREATE, which shall comprise both, SC_AC_OP_CREATE_EF and SC_AC_OP_CREATE_DF (added below later)  */
        se_file_add_acl_entry(card, file, scb8[CREATE_EF], SC_AC_OP_CREATE);
        se_file_add_acl_entry(card, file, scb8[CREATE_DF], SC_AC_OP_CREATE);
    }
    else {
        /* for an EF, acos doesn't distinguish access right update <-> write, thus add SC_AC_OP_WRITE as a synonym to SC_AC_OP_UPDATE */
        se_file_add_acl_entry(card, file, scb8[UPDATE], SC_AC_OP_WRITE);
        /* usage of SC_AC_OP_DELETE_SELF <-> SC_AC_OP_DELETE seems to be in confusion in opensc, thus for opensc-tool and EF add SC_AC_OP_DELETE to SC_AC_OP_DELETE_SELF
           My understanding is:
           SC_AC_OP_DELETE_SELF designates the right to delete the EF/DF that contains this right in it's SCB
           SC_AC_OP_DELETE      designates the right of a directory, that a contained file may be deleted; acos calls that Delete Child
        */
        se_file_add_acl_entry(card, file, scb8[DELETE_SELF], SC_AC_OP_DELETE);
    }
    /* for RSA key file add SC_AC_OP_GENERATE to SC_AC_OP_CRYPTO */
    if [FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&fdb) {
        se_file_add_acl_entry(card, file, scb8[CRYPTO], SC_AC_OP_GENERATE); // MSE/PSO Commands
    }

    let ops_df_mf  = [ SC_AC_OP_DELETE/*_CHILD*/, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_ef_chv = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    0xFF,               SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_key    = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_se     = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];

    for idx_scb8 in 0..7 {
        let op =
            if       is_DFMF(fdb)                                         { ops_df_mf [idx_scb8] }
            else if  fdb == FDB_SE_FILE                                   { ops_se    [idx_scb8] }
            else if  fdb == FDB_RSA_KEY_EF || fdb == FDB_SYMMETRIC_KEY_EF { ops_key   [idx_scb8] }
            else                                                          { ops_ef_chv[idx_scb8] };
        se_file_add_acl_entry(card, file, scb8[idx_scb8], op);
    }
}

/**
 * Controls 'decoding' of SCB meaning and finally calls sc_file_add_acl_entry
 * @apiNote TODO add SM and logical AND/OR of access control conditions (if OpenSc can handle that)
 * @param  card  INOUT
 * @param  file  INOUT it's field acl (Access Control List) will get an sc_acl_entry added
 * @param  scb   IN    the Security Condition Byte (SCB) for @param op, as retrieved from FCI; it's pointing to an SE id
 *                     in associated Sec. Env. file, or it's an encoding of either SC_AC_NONE or SC_AC_NEVER
 * @param  op    IN    the operation that @param scb refers to, e.g. SC_AC_OP_READ
 */
#[allow(clippy::needless_return)]
fn se_file_add_acl_entry(card: &mut sc_card, file: &mut sc_file, scb: u8, op: u32)
{
//    assert!(!card.ctx.is_null());
//    let ctx = unsafe { &mut *card.ctx };
//    let f = c"se_file_add_acl_entry";
    let mut rv;
    if op == 0xFF {} // it's used to denote, that there is no operation that this scb can refer to; e.g. for  EF/CHV, the byte at 3. position has no meaning
    else if  scb == 0
    {
        rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE) };
        assert_eq!(SC_SUCCESS, rv);
    }
    else if  scb == 0xFF
    {
        rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE) };
        assert_eq!(SC_SUCCESS, rv);
    }
    else if [0, 15].contains(&(scb & 0x0F)) || (scb & 0x30) != 0 || (scb & 0xC0) == 0xC0 // these bit combinations are not allowed
    {
        rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE) };
        assert_eq!(SC_SUCCESS, rv);
    }
    else {
        let file_id = u16::try_from(file.id).unwrap();
        let res_se_sm = if (scb & 0x40) == 0 {(false,false)}
                                    else {se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb & 0x0F)};
        let pin_ref = se_get_references(card, file_id, scb & 0x0F, &sc_crt::new_AT(0x08), false);
        if !pin_ref.is_empty() {
/*
SCB: 01; [80 01 01  A4 09 83 01 81 83 01 01 95 01 08]                                => CHV129 (CHV1 as OR alternative get's dropped)
SCB: 01; [80 01 01  A4 09 83 01 01 83 01 81 95 01 08]                                => CHV1   (CHV129 as OR alternative get's dropped)

SCB: 41; [80 01 01  A4 09 83 01 81 83 01 01 95 01 08]                                => invalid, missing info for SM
SCB: 41; [80 01 01  A4 09 83 01 81 83 01 01 95 01 08  B4 08 84 00 95 01 30 80 01 02] => CHV129 PROT (CHV1 as OR alternative get's dropped)
SCB: 41; [80 01 01  A4 09 83 01 01 83 01 81 95 01 08  B4 08 84 00 95 01 30 80 01 02] => CHV1   PROT (CHV129 as OR alternative get's dropped)

SCB: 81; [80 01 01  A4 09 83 01 81 83 01 01 95 01 08]                                => CHV129 CHV1 (AND: both conditions must be fulfilled)
*/
            if (scb & 0x40) != 0 && !res_se_sm.0 { // invalid, missing info for SM
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE) };
                assert_eq!(SC_SUCCESS, rv);
                return;
            }
            /* SM implicitly has the (unsupported by OpenSC) OR operator for access conditions, thus drop any references except the first */
            let loop_cnt = if (scb & 0x40) != 0 || (scb & 0x80) == 0 { 1_usize }
                                  else { pin_ref.len() };
            for &elem in pin_ref.iter().take(loop_cnt) {
                rv =unsafe { sc_file_add_acl_entry(file, op, SC_AC_CHV, elem.into()) };
                assert_eq!(SC_SUCCESS, rv);
            }
            if (scb & 0x40) != 0 && res_se_sm.0 { // SM processing is requested and possible: add SC_AC_PRO as a marker
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE) };
                assert_eq!(SC_SUCCESS, rv);
                return;
            }

            return;
        }
/* */
        let mut contains_sm_key : bool = false;
        let key_ref = se_get_references(card, file_id, scb & 0x0F, &sc_crt::new_AT(0x80), false);
        if !key_ref.is_empty() {
/*
key 0x81 by CONVENTION is the one that get's authenticated in SM mode, thus itself and alternatives get stripped
SCB: 01; [80 01 01  A4 09 83 01 81 83 01 01 95 01 80]                                => AUT129 (AUT1 as OR alternative get's dropped)
SCB: 01; [80 01 01  A4 09 83 01 01 83 01 81 95 01 80]                                => AUT1   (AUT129 as OR alternative get's dropped)

SCB: 41; [80 01 01  A4 09 83 01 81 83 01 01 95 01 80]                                => invalid, missing info for SM
SCB: 41; [80 01 01  A4 06          83 01 81 95 01 80  B4 08 84 00 95 01 30 80 01 02] => PROT
SCB: 41; [80 01 01  A4 09 83 01 01 83 01 81 95 01 80  B4 08 84 00 95 01 30 80 01 02] => PROT
SCB: 41; [80 01 01  A4 09 83 01 01 83 01 82 95 01 80  B4 08 84 00 95 01 30 80 01 02] => AUT1   PROT (AUT130 as OR alternative get's dropped)

SCB: 81; [80 01 01  A4 09 83 01 81 83 01 01 95 01 80]                                => AUT129 AUT1 (AND: both conditions must be fulfilled)
SCB: 81; [80 01 01  A4 09 83 01 01 83 01 81 95 01 80  B4 08 84 00 95 01 30 80 01 02] => AUT1 AUT129 (AND: both conditions must be fulfilled)
*/
            if (scb & 0x40) != 0 {
                if !res_se_sm.0 {
                    rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE) };
                    assert_eq!(SC_SUCCESS, rv);
                    return;
                }
                contains_sm_key = key_ref.iter().any(|&x| x == 0x81);
            }

            /* SM implicitly has the (unsupported by OpenSC) OR operator for access conditions, thus drop any references except the first */
            let loop_cnt = if contains_sm_key { 0_usize }
                                  else if (scb & 0x40) != 0 || (scb & 0x80) == 0 { 1_usize }
                                  else { key_ref.len() };
            for &elem in key_ref.iter().take(loop_cnt) {
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_AUT, elem.into()) };
                assert_eq!(SC_SUCCESS, rv);
            }
            if (scb & 0x40) != 0 && res_se_sm.0 {
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE) };
                assert_eq!(SC_SUCCESS, rv);
                return;
            }

            return;

        }
/* */
        let pin_key_ref = se_get_references(card, file_id, scb & 0x0F, &sc_crt::new_AT(0x88), false);
        if !pin_key_ref.is_empty() {
/*
key 0x81 by CONVENTION is the one that get's authenticated in SM mode, thus itself and alternatives get stripped
SCB: 01; [80 01 01  A4 09 83 01 81 83 01 01 95 01 88]                                => CHV129 AUT129 (CHV1   AUT1   as OR alternative get's dropped)
SCB: 01; [80 01 01  A4 09 83 01 01 83 01 81 95 01 88]                                => CHV1   AUT1   (CHV129 AUT129 as OR alternative get's dropped)

SCB: 41; [80 01 01  A4 09 83 01 81 83 01 01 95 01 88]                                => invalid, missing info for SM
SCB: 41; [80 01 01  A4 06          83 01 81 95 01 88  B4 08 84 00 95 01 30 80 01 02] => CHV129 PROT
SCB: 41; [80 01 01  A4 09 83 01 01 83 01 81 95 01 88  B4 08 84 00 95 01 30 80 01 02] => CHV1   AUT1 PROT
SCB: 41; [80 01 01  A4 09 83 01 01 83 01 82 95 01 88  B4 08 84 00 95 01 30 80 01 02] => CHV1   AUT1 PROT (CHV130 AUT130 as OR alternative get's dropped)

SCB: 81; [80 01 01  A4 09 83 01 81 83 01 01 95 01 88]                                => CHV129 AUT129 CHV1 AUT1 (AND: both conditions must be fulfilled)
*/
            if (scb & 0x40) != 0 {
                if !res_se_sm.0 {
                    rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE) };
                    assert_eq!(SC_SUCCESS, rv);
                    return;
                }
                contains_sm_key = pin_key_ref.iter().any(|&x| x == 0x81);
            }

            /* SM implicitly has the (unsupported by OpenSC) OR operator for access conditions, thus drop any references except the first */
            let loop_cnt = //if contains_sm_key { 0_usize }
                if (scb & 0x40) != 0 || (scb & 0x80) == 0 { 1_usize }
                else { pin_key_ref.len() };
            for &elem in pin_key_ref.iter().take(loop_cnt) {
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_CHV, elem.into()) };
                assert_eq!(SC_SUCCESS, rv);
                if contains_sm_key {}
                else {
                    rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_AUT, elem.into()) };
                    assert_eq!(SC_SUCCESS, rv);
                }
            }
            if (scb & 0x40) != 0 && res_se_sm.0 {
                rv = unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, SC_AC_KEY_REF_NONE) };
                assert_eq!(SC_SUCCESS, rv);
                return;
            }

            return;
        }
/* */
    }
}


/**
 * Performs look-up of SCB meaning in the database - HashMap dp.files - based on a search_template
 * @apiNote
 * @param   card             INOUT
 * @param   file_id          IN    the file_id, for which info is requested; relevant is the SE file info of file_id's directory
 * @param   se_reference     IN    the SE file record's id (3.byte) matching SCB & 0x0F, though 0x0F is RFU for cos5 !
 * @param   search_template  IN    usually searching for CRT_TAG_AT, CRT_TAG_CCT or CRT_TAG_CT_SYM
 * @return  pin/sym. key reference ==  pin/sym. key id (global)  or  pin/sym. key id | 0x80 (local)
 */
pub fn se_get_references(card: &mut sc_card, file_id: u16, se_reference: u8, search_template: &sc_crt, skip_usage: bool) -> Vec<u32>
{
    let mut result : Vec<u32> = Vec::with_capacity(8); //SC_AC_KEY_REF_NONE;
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if dp.files.contains_key(&file_id) {
        let dp_files_value = &dp.files[&file_id];
        let fdb        = dp_files_value.1[0];
        let file_id_dir =
            if is_DFMF(fdb) { file_id }
            else {
/*
                                    if path_len<4 {
                                        let x = dp.files.get(&file_id).unwrap();
                                        println!("fdb: {:X}", fdb);
                                        println!("x.0: {:X?}", x.0);
                                        println!("x.1: {:X?}", x.1);
                                        if x.2.is_some() {
                                            println!("x.2: {:X?}", x.2);
                                        }
                                        println!("file_id: {:X}", file_id);
                                        println!("se_reference: {:X}", se_reference);
                                        println!("search_template.tag: {:X}", search_template.tag);
                                        println!("search_template.usage: {:X}", search_template.usage);
                                        println!("search_template.algo: {:X}", search_template.algo);
                                        println!("search_template.refs[0]: {:X}", search_template.refs[0]);
                                    }
*/
                let path_len = usize::from(dp_files_value.1[1]);
                assert!(path_len>=4);
                u16::from_be_bytes([dp_files_value.0[path_len-4], dp_files_value.0[path_len-3]])
            };
//        println!("file_id_dir: {:X}", file_id_dir);
        if let Some(vec_sac_info) = &dp.files[&file_id_dir].3 {
            for sac_info in vec_sac_info {
                if sac_info.reference == u32::from(se_reference) {
                    for crt in &sac_info.crts[..sac_info.crts_len] {
                        if crt.tag   != search_template.tag                  { continue; }
                        if crt.usage != search_template.usage && !skip_usage { continue; }
                        for &elem in &crt.refs {
                            if elem != 0 { result.push(elem); }
                            else         { break; /*for elem*/ }
                        }
                        break; // for crt
                    }
                    break; // for sac_info
                }
            }
        }
    }

    Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as p_void;
    if result.is_empty() /*== SC_AC_KEY_REF_NONE*/ {
//        println!("No entries crt.refs for file_id: {}, se_reference: {}, search_template: {:?}", file_id, se_reference, search_template);
    }
    result
}

/**
 * Performs look-up of SCB meaning in the database - HashMap dp.files - (internal search_templates)
 * @apiNote
 * @param   card             INOUT
 * @param   file_id          IN    the file_id, for which info is requested; relevant is the SE file info of file_id's directory
 * @param   se_reference     IN    the SE file record's id (3.byte) matching SCB & 0x0F, though 0x0F is RFU for cos5 !
 * @return  a tuple: 1. elem: whether the CRT templates match the requirements for SM, forcing at least SM mode Authenticity (SM-sign)
                     2. elem: whether there also is a CT template, forcing SM mode Confidentiality (SM-sign + SM-enc)
 */
pub fn se_get_is_scb_suitable_for_sm_has_ct(card: &mut sc_card, file_id: u16, se_reference: u8) -> (bool, bool)
{
    let mut result = (false /*is_suitable_for_sm*/, false /*has_ct*/);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if dp.files.contains_key(&file_id) {
        let dp_files_value = &dp.files[&file_id];
        let fdb        = dp_files_value.1[0];
        let file_id_dir = if is_DFMF(fdb) { file_id }
                                else {
                                    let path_len = usize::from(dp_files_value.1[1]);
                                    assert!(path_len>=4);
                                    u16::from_be_bytes([dp_files_value.0[path_len-4], dp_files_value.0[path_len-3]])
                                };
//        println!("file_id_dir: {:X}", file_id_dir);
        if let Some(vec_sac_info) = &dp.files[&file_id_dir].3 {
            for sac_info in vec_sac_info {
                if sac_info.reference == u32::from(se_reference) {
                    /*
                    if template has no (AT and) CCT, then it's unusable for SM
                    if template's usage != 0x30, then it's unusable for SM
                    if template has a B8, then it's for Confidentiality, else for authenticity
                    */
/*
                    #[allow(non_snake_case)]
                    let search_template_AT = sc_crt::new_AT(0x88);
                    #[allow(non_snake_case)]
                    let mut AT_found = false;
                    for crt in &sac_info.crts[0..sac_info.crts_len] {
                        if crt.tag   != search_template_AT.tag   { continue; }
                        if (crt.usage & search_template_AT.usage) == 0 { continue; }
                        /* TODO any special requirement ref. pin/key ? */
                        AT_found = true;
                        break;
                    }
*/
                    #[allow(non_snake_case)]
                    let search_template_CCT = sc_crt::new_CCT(0x30);
                    #[allow(non_snake_case)]
                    let mut CCT_found = false;
                    for crt in &sac_info.crts[0..sac_info.crts_len] {
                        if crt.tag   != search_template_CCT.tag   { continue; }
                        if (crt.usage & search_template_CCT.usage) != search_template_CCT.usage { continue; }
                        if crt.algo  != 0x02   { continue; }
                        if ![0x84_u8, 0x81, 0x82, 0x83, 1,2,3].contains(&(u8::try_from(crt.refs[0]).unwrap())) { continue; }
                        CCT_found = true;
                        break;
                    }

                    #[allow(non_snake_case)]
                    let search_template_CT = sc_crt::new_CT(0x30);
                    #[allow(non_snake_case)]
                    let mut CT_found = false;
                    for crt in &sac_info.crts[0..sac_info.crts_len] {
                        if crt.tag   != search_template_CT.tag   { continue; }
                        if (crt.usage & search_template_CT.usage) != search_template_CT.usage   { continue; }
                        if crt.algo  != 0x02   { continue; }
                        if ![0x84_u8, 0x81, 0x82, 0x83, 1,2,3].contains(&(u8::try_from(crt.refs[0]).unwrap())) { continue; }
                        CT_found = true;
                        break;
                    }
                    result = (/*AT_found &&*/ CCT_found /*is_suitable_for_sm*/, CT_found /*has_ct*/);
                    break;
                }
            }
        }
    }
    Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as p_void;
    result
}

pub fn se_get_sae_scb(card: &mut sc_card, cla_ins_p1_p2: [u8; 4]) -> u8
{
    let mut scb = 0;
    let file_id_dir = file_id_from_path_value(current_path_df(card));

    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    assert!(dp.files.contains_key(&file_id_dir));
    if let Some(vec_sae_info) = &dp.files[&file_id_dir].4 {
        for sae_info in vec_sae_info {
            if sae_info.ins == cla_ins_p1_p2[1] {
                if (sae_info.tag_AMDO&8)>0 && sae_info.cla != cla_ins_p1_p2[0] { continue; }
//              if (sae_info.tag_AMDO&4)>0 && sae_info.ins != cla_ins_p1_p2[1] { continue; }
                if (sae_info.tag_AMDO&2)>0 && sae_info.p1  != cla_ins_p1_p2[2] { continue; }
                if (sae_info.tag_AMDO&1)>0 && sae_info.p2  != cla_ins_p1_p2[3] { continue; }

                match sae_info.tag_SCDO {
                    0x90 => { scb = 0;            break; }, // always allowed, thus no constraint
                    0x97 => { scb = 0xFF;         break; }, // always disallowed
                    0x9E |
                    0xA4 => { scb = sae_info.scb; break; }, // depends on scb
                    0xA0 | 0xAF => { /*panic!();*/ }, // not implemented
                    _    => { unreachable!("Encountered unexpected byte"); },
                }
            }
        }
    }
    Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as p_void;
    scb
}

/*
 * Parses an SE file's record beginning from it's 4. byte, e.g.
 * Sending:  00 B2 01 04 38                                           <= read record no. 1, 56 bytes, from SE file
 *                 |
 * Received: 80 01 01  A4 06 83 01 81 95 01 08  and 45 more 00 bytes  <= data.as_ptr() must point to A4; the byte before A4 i.e. 01, is record's id; this should be the same as the record nr. read
 *
 * @param   reference     IN    record's id, readable as 3.byte from record's data (SE file's record no should be the same to avoid confusion)
 * @param   data          IN    the data to fill se_info_node with, in this example [A4 06 83 01 81 95 01 08 ...]
 * @param   se_info_node  INOUT; on IN, a default-initialized struct, on OUT with the data interpreted filled in
 * @return                the number of bytes parsed from data
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn se_parse_sac(/*card: &mut sc_card,*/ reference: u32, data: &[u8], se_info_node: &mut SACinfo) -> i32 // se_parse_crts
{
    if data.is_empty() || data[0] == 0 {
        return 0;
    }
    //make sure, that se_info_node is a default-initialized struct
//    se_info_node = SACinfo::default();

    let mut data_ptr = data.as_ptr();
    let mut cla_out = 0_u32;
    let mut tag_out = 0_u32;
    let mut taglen = 0_usize;
    let mut buflen_remaining = data.len(); // to be updated after sc_asn1_read_tag changes data_ptr: Then buf and buflen_remaining are in sync. again for the next call
    let mut idx_crts = 0_usize;

    se_info_node.reference = reference;

    while buflen_remaining > 0 {
        let mut rv = unsafe{sc_asn1_read_tag(&mut data_ptr, buflen_remaining, &mut cla_out, &mut tag_out, &mut taglen)};
        if  rv != SC_SUCCESS || tag_out == SC_ASN1_TAG_EOC {
            return i32::try_from(data.len() - buflen_remaining).unwrap();
        }
        assert!(!data_ptr.is_null());
        buflen_remaining -= 2;

        se_info_node.crts_len += 1;
        assert!(se_info_node.crts_len <= SC_MAX_CRTS_IN_SE);
        se_info_node.crts[idx_crts].tag = cla_out | tag_out;

        let mut idx_refs = 0_usize;
        let mut taglen_remaining = taglen;
        assert!(taglen_remaining <= buflen_remaining);
        while taglen_remaining > 0 {
            rv = unsafe { sc_asn1_read_tag(&mut data_ptr, taglen_remaining, &mut cla_out, &mut tag_out, &mut taglen) };
            assert_eq!(rv, SC_SUCCESS);
            taglen_remaining -= 2 + taglen; // for taglen>0, the data_ptr must still be updated to point to the next TLV
            buflen_remaining -= 2 + taglen;
            match u8::try_from(cla_out | tag_out).unwrap() {
                0x80 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].algo = u32::from(*data_ptr);
                        data_ptr = data_ptr.add(1);
                    };
                },
                0x81 => { assert_eq!(taglen, 2); },
                0x83 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].refs[idx_refs] = u32::from(*data_ptr);
                        data_ptr = data_ptr.add(1);
                    };
                    idx_refs += 1;
                },
                0x84 => {
                    assert_eq!(taglen, 0);
                    se_info_node.crts[idx_crts].refs[idx_refs] = 0x84;
                    idx_refs += 1;
                },
//              0x87 => {},//8/16
                0x95 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].usage = u32::from(*data_ptr);
                        data_ptr = data_ptr.add(1);
                    };
                },
                _ => ()
            }
        }
        idx_crts += 1;
    }

    i32::try_from(data.len() - buflen_remaining).unwrap()
}


/// # Errors
///
/// Will return `Err` if there are errors in the SAE encoding
pub fn se_parse_sae(vec_sac_info_opt: &mut Option<Vec<SACinfo>>, value_bytes_tag_fcp_sae: &[u8]) -> Result<Vec<SAEinfo>, i32>
{
    use crate::no_cdecl::{convert_amdo_to_cla_ins_p1_p2_array};

    // add the A4 tag as virtual SE-file record (SAC), starting with se record id 16, the max. of real ones is 14
    let mut idx_virtual = 15_u8;
    let mut vec_sae_info = Vec::with_capacity(6);
//    let mut rem = value_bytes_tag_fcp_sae;
    assert!(value_bytes_tag_fcp_sae.len()<=32);
    let mut tlv = Tlv::new(value_bytes_tag_fcp_sae);
    loop {
        tlv = match tlv.next() {
            Some(item) => item,
            None => break,
        };
//println!("parsed: {:X?}", tlv);
        assert_eq!(0x80, tlv.tag() & 0xF0);
        assert_eq!((tlv.tag() & 0x0F).count_ones(), tlv.length().into());
        assert_eq!(4, tlv.tag() & 4); // ins must be included
        let mut sae_info = SAEinfo { tag_AMDO: tlv.tag(), ..SAEinfo::default() };
        let cla_ins_p1_p2 = match convert_amdo_to_cla_ins_p1_p2_array(tlv.tag(), tlv.value()) {
            Ok(cla_ins_p1_p2)  => cla_ins_p1_p2,
            Err(e)      => return Err(e),
        };
        sae_info.cla = cla_ins_p1_p2[0];
        sae_info.ins = cla_ins_p1_p2[1];
        sae_info.p1  = cla_ins_p1_p2[2];
        sae_info.p2  = cla_ins_p1_p2[3];

        /* at least 1 SCDO must follow */
        tlv = match tlv.next() {
            Some(item) => item,
            None => return Err(-1),
        };
//println!("parsed: {:X?}", tlv);
        assert!([0x90, 0x97, 0x9E, 0xA4, 0xA0, 0xAF].contains(&tlv.tag()));
        sae_info.tag_SCDO = tlv.tag();
        match tlv.tag() {
            0x90 => sae_info.scb = 0,
            0x97 => sae_info.scb = 0xFF,
            0x9E => {
                assert_eq!(1, tlv.length());
                sae_info.scb = tlv.value()[0];
            },
            0xA4 => {
                assert!(tlv.length()>=6 && num_integer::Integer::is_multiple_of(&tlv.length(), &3));
                let mut sac_info = SACinfo::default();
                idx_virtual += 1;
                sae_info.scb       = idx_virtual;
                sac_info.reference = idx_virtual.into();
                sac_info.crts_len  = 1;
                sac_info.crts[0].tag = tlv.tag().into();
                let mut idx_ref = 0;
                for chunk in tlv.value().chunks(3) {
                    assert_eq!(1, chunk[1]);
                    match chunk[0] {
                        0x95 => { sac_info.crts[0].usage         = chunk[2].into(); },
                        0x83 => { sac_info.crts[0].refs[idx_ref] = chunk[2].into(); idx_ref += 1; },
                        0x81 => { /*if card.type_== SC_CARD_TYPE_ACOS5_EVO_V4 {TODO EVO also has tag 0x81} else {panic!()}*/ }
                        _    => unreachable!("Encountered unexpected byte"),
                    }
                }
                vec_sac_info_opt.get_or_insert(Vec::new()).push(sac_info);
            },
            _ => {} // TODO for now: skip support of tags A0 and AF
        }
        vec_sae_info.push(sae_info);
    } // loop
    vec_sae_info.shrink_to_fit();
    Ok(vec_sae_info)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_se_parse_sac() {
        let mut sac_info = SACinfo::default();
        let data : [u8; 11] = [/* 80 01 01 */ 0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,   0x00, 0x00, 0x00];
        let mut rv = se_parse_sac(1, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
//        assert_eq!(sac_info.next, std::ptr::null_mut());
        assert_eq!(sac_info.reference, 1);
        assert_eq!(sac_info.crts_len,  1);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x81,0,0,0,0,0,0,0]}); // => CHV129

        sac_info =  SACinfo::default();
        /* this is a non-functional entry from ACS */
        let data : [u8; 33] = [/* 80 01 02 */
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,
            0xB4, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xB8, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,  0x00, 0x00, 0x00];
        rv = se_parse_sac(2, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 2);
        assert_eq!(sac_info.crts_len,  3);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x81,0,0,0,0,0,0,0]}); // => CHV129
        assert_eq!(sac_info.crts[1],   sc_crt{tag: 0xB4, usage: 8, algo: 2, refs: [   1,0,0,0,0,0,0,0]});
        assert_eq!(sac_info.crts[2],   sc_crt{tag: 0xB8, usage: 8, algo: 2, refs: [   1,0,0,0,0,0,0,0]});

        sac_info =  SACinfo::default();
        let data : [u8; 11] = [/* 80 01 03 */
            0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08,  0x00, 0x00, 0x00];
        rv = se_parse_sac(3, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 3);
        assert_eq!(sac_info.crts_len,  1);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [   1,0,0,0,0,0,0,0]}); // => CHV1

        sac_info =  SACinfo::default();
        let data : [u8; 14] = [/* 80 01 04 */
            0xA4, 0x09, 0x83, 0x01, 0x81, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08,      0x00, 0x00, 0x00];
        rv = se_parse_sac(4, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 4);
        assert_eq!(sac_info.crts_len,  1);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x81,0x01,0,0,0,0,0,0]}); // => CHV1 and/or CHV129

        sac_info =  SACinfo::default();
        let data : [u8; 21] = [/* 80 01 05 */
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x80,
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,   0x00, 0x00, 0x00];
        rv = se_parse_sac(5, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 5);
        assert_eq!(sac_info.crts_len,  2);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 0x80, algo: 0, refs: [0x81,0,0,0,0,0,0,0]}); // => PROT when used as SCB 0x45
        assert_eq!(sac_info.crts[1],   sc_crt{tag: 0xB4, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});

        sac_info =  SACinfo::default();
        let data : [u8; 31] = [/* 80 01 06 */
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x80,
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xB8, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,   0x00, 0x00, 0x00];
        rv = se_parse_sac(6, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 6);
        assert_eq!(sac_info.crts_len,  3);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 0x80, algo: 0, refs: [0x81,0,0,0,0,0,0,0]}); // => PROT when used as SCB 0x46
        assert_eq!(sac_info.crts[1],   sc_crt{tag: 0xB4, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(sac_info.crts[2],   sc_crt{tag: 0xB8, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});

        sac_info =  SACinfo::default();
        let data : [u8; 31] = [/* 80 01 07 */
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xB8, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,   0x00, 0x00, 0x00];
        rv = se_parse_sac(7, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 7);
        assert_eq!(sac_info.crts_len,  3);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 0x08, algo: 0, refs: [0x81,0,0,0,0,0,0,0]}); // => CHV129
        assert_eq!(sac_info.crts[1],   sc_crt{tag: 0xB4, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(sac_info.crts[2],   sc_crt{tag: 0xB8, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});

        sac_info =  SACinfo::default();
        let data : [u8; 9] = [/* 80 01 08 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00];
        rv = se_parse_sac(8, &data, &mut sac_info);
        assert_eq!(rv, 0);
        assert_eq!(sac_info, SACinfo::default());

        sac_info =  SACinfo::default();
        let data : [u8; 34] = [/* 80 01 09 */
            0xA4, 0x09, 0x83, 0x01, 0x82, 0x83, 0x01, 0x83, 0x95, 0x01, 0x80,
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xB8, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,   0x00, 0x00, 0x00];
        rv = se_parse_sac(9, &data, &mut sac_info);
        assert_eq!(usize::try_from(rv).unwrap(), data.len()-3);
        assert_eq!(sac_info.reference, 9);
        assert_eq!(sac_info.crts_len,  3);
        assert_eq!(sac_info.crts[0],   sc_crt{tag: 0xA4, usage: 0x80, algo: 0, refs: [0x82,0x83,0,0,0,0,0,0]}); // =>
        assert_eq!(sac_info.crts[1],   sc_crt{tag: 0xB4, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(sac_info.crts[2],   sc_crt{tag: 0xB8, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
    }

    #[test]
    fn test_se_parse_sae() { // $ cargo test test_se_parse_sae
        let v =   [0x84, 0x01, 0x20, 0x9E, 0x01, 0x46,
                            0x84, 0x01, 0x24, 0x9E, 0x01, 0x46,
                            0x8C, 0x02, 0x80, 0x30, 0x97, 0x00,
                            0x84, 0x01, 0x22, 0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08];
        let mut sac_info_expected = SACinfo { reference: 0x10, crts_len: 1, ..SACinfo::default() };
        sac_info_expected.crts[0] = sc_crt { tag: 0xA4, usage: 8, algo: 0, refs: [0x81, 0, 0, 0, 0, 0, 0, 0] };
        let vec_sae_info_expected = vec![
            SAEinfo { tag_AMDO: 0x84, cla: 0,    ins: 0x20, p1: 0, p2: 0, tag_SCDO: 0x9E, scb: 0x46 },
            SAEinfo { tag_AMDO: 0x84, cla: 0,    ins: 0x24, p1: 0, p2: 0, tag_SCDO: 0x9E, scb: 0x46 },
            SAEinfo { tag_AMDO: 0x8C, cla: 0x80, ins: 0x30, p1: 0, p2: 0, tag_SCDO: 0x97, scb: 0xFF },
            SAEinfo { tag_AMDO: 0x84, cla: 0,    ins: 0x22, p1: 0, p2: 0, tag_SCDO: 0xA4, scb: 0x10 } ];

        let mut vec_sac_info_opt : Option<Vec<SACinfo>> = None;
        let res = se_parse_sae(&mut vec_sac_info_opt, &v);
        assert_eq!(sac_info_expected, vec_sac_info_opt.unwrap()[0]);
        assert_eq!(vec_sae_info_expected, res.unwrap());
    }
}
