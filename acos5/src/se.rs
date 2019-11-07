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
stored with an entry for reference 2 (respomsible for SCB 2)
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

use std::os::raw::{c_ulong, c_int, c_uint, c_void};

use opensc_sys::opensc::{sc_card, sc_file_add_acl_entry};
use opensc_sys::types::{sc_file, sc_crt, SC_AC_NONE, SC_AC_UNKNOWN, SC_AC_NEVER, SC_AC_CHV, SC_AC_AUT, SC_AC_PRO,
                        SC_AC_KEY_REF_NONE};
use opensc_sys::errors::{SC_SUCCESS};
use opensc_sys::asn1::{sc_asn1_read_tag, SC_ASN1_TAG_EOC};

use crate::constants_types::*;
use crate::path::current_path_df;


/**
 * Controls 'decoding' of SCB meaning and finally calls sc_file_add_acl_entry
 * @apiNote TODO add SM and logical AND/OR of access control conditions (if OpenSc can handle that)
 * @param  card  INOUT
 * @param  file  INOUT it's field acl (Access Control List) will get an sc_acl_entry added
 * @param  scb   IN    the Security Condition Byte (SCB) for @param op, as retrieved from FCI; it's pointing to an SE id
 *                     in associated Sec. Env. file, or it's an encoding of either SC_AC_NONE or SC_AC_NEVER
 * @param  op    IN    the operation that @param scb refers to, e.g. SC_AC_OP_READ
 */
pub fn se_file_add_acl_entry(card: &mut sc_card, file: &mut sc_file, scb: u8/*scb8: &[u8; 8], idx_scb8: usize*/,
                             op: u32 /*, int line*/)
{
    if op == 0xFF {} // it's used to denote, that there is no operation that this scb can refer to; e.g. for  EF/CHV, the byte at 3. position has no meaning
    else if  scb == 0
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE) }); }
    else if  scb == 0xFF
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE) }); }
    else if scb.trailing_zeros() >= 4 || (scb & 0x0F) == 0x0F || (scb & 0x30) != 0 || (scb & 0xC0) == 0xC0
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE) }); }
    else if           (scb & 0x80) == 0x80
    {} // TODO  all conditions must be satisfied opposed to one of a set of conditions
       // TODO  the 'one of a set of conditions' case just tries the first in sc_crt.refs, it doesn't try the (possible) alternatives
    else if      (scb & 0x40) == 0x40 // SM
    { // almost a copy of the else branch with SC_AC_PRO instead of SC_AC_CHV/SC_AC_AUT
        let pin_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x08));
        if pin_ref     != SC_AC_KEY_REF_NONE { assert_eq!(SC_SUCCESS, unsafe {
            sc_file_add_acl_entry(    file, op, SC_AC_PRO, pin_ref) }); }
        else {
            let key_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x80));
            if key_ref != SC_AC_KEY_REF_NONE { assert_eq!(SC_SUCCESS, unsafe {
                sc_file_add_acl_entry(file, op, SC_AC_PRO, key_ref) }); }
            else {
                let pin_key_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x88));
                if pin_key_ref != SC_AC_KEY_REF_NONE {
                    assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, pin_key_ref) });
//                  assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, pin_key_ref) });
                }
                else {  assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN,
                                                                              SC_AC_KEY_REF_NONE) }); }
            }
        }
    }
    else {
        let pin_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x08));
        if pin_ref     != SC_AC_KEY_REF_NONE { assert_eq!(SC_SUCCESS, unsafe {
            sc_file_add_acl_entry(    file, op, SC_AC_CHV, pin_ref) }); }
        else {
            let key_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x80));
            if key_ref != SC_AC_KEY_REF_NONE { assert_eq!(SC_SUCCESS, unsafe {
                sc_file_add_acl_entry(file, op, SC_AC_AUT, key_ref) }); }
            else {
                let pin_key_ref : c_ulong = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x88));
                if pin_key_ref != SC_AC_KEY_REF_NONE {
                    assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_CHV, pin_key_ref) });
                    assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_AUT, pin_key_ref) });
                }
                else {  assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN,
                                                                              SC_AC_KEY_REF_NONE) }); }
            }
        }
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
fn se_get_reference(card: &mut sc_card, file_id: c_int, se_reference: u8, search_template: &sc_crt) -> c_ulong
{
    let mut result : c_ulong = SC_AC_KEY_REF_NONE;
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let file_id = file_id as u16;
    if dp.files.contains_key(&file_id) {
        let dp_files_value = &dp.files[&file_id];
        let fdb        = dp_files_value.1[0];
        let file_id_dir = if is_DFMF(fdb) { file_id }
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
                                    let path_len = dp_files_value.1[1] as usize;
                                    assert!(path_len>=4);
                                    u16::from_be_bytes([dp_files_value.0[path_len-4], dp_files_value.0[path_len-3]])
                                };
//        println!("file_id_dir: {:X}", file_id_dir);
        if let Some(vec_seinfo) = &dp.files[&file_id_dir].3 {
            for sac_info in vec_seinfo {
                if sac_info.reference == u32::from(se_reference) {
                    for crt in &sac_info.crts[..sac_info.crts_len] {
                        if crt.tag   != search_template.tag   { continue; }
                        if crt.usage != search_template.usage { continue; }
                        result = c_ulong::from(crt.refs[0]); // TODO there may also be crt.refs[1] or more
                        break;
                    }
                    break;
                }
            }
        }
    }

    card.drv_data = Box::into_raw(dp) as *mut c_void;
    if result == SC_AC_KEY_REF_NONE {
//        println!("file_id: {}, se_reference: {}, search_template: {:?}", file_id, se_reference, search_template);
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
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    if dp.files.contains_key(&file_id) {
        let dp_files_value = &dp.files[&file_id];
        let fdb        = dp_files_value.1[0];
        let file_id_dir = if is_DFMF(fdb) { file_id }
                                else {
                                    let path_len = dp_files_value.1[1] as usize;
                                    assert!(path_len>=4);
                                    u16::from_be_bytes([dp_files_value.0[path_len-4], dp_files_value.0[path_len-3]])
                                };
//        println!("file_id_dir: {:X}", file_id_dir);
        if let Some(vec_seinfo) = &dp.files[&file_id_dir].3 {
//        match &dp.files[&file_id_dir].3 {
//            Some(vec_seinfo) => {
            for sac_info in vec_seinfo {
                if sac_info.reference == u32::from(se_reference) {
                    /*
                    if template has no AT and CCT, then it's unusable for SM
                    if template's usage != 0x30, then it's unusable for SM
                    if template has a B8, then it's for Confidentiality, else for authenticity
                    */
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

                    #[allow(non_snake_case)]
                    let search_template_CCT = sc_crt::new_CCT(0x30);
                    #[allow(non_snake_case)]
                    let mut CCT_found = false;
                    for crt in &sac_info.crts[0..sac_info.crts_len] {
                        if crt.tag   != search_template_CCT.tag   { continue; }
                        if (crt.usage & search_template_CCT.usage) != search_template_CCT.usage { continue; }
                        if crt.algo  != 0x02   { continue; }
                        if ![0x84_u8, 0x81, 0x82, 0x83, 1,2,3].contains(&(crt.refs[0] as u8)) { continue; }
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
                        if ![0x84_u8, 0x81, 0x82, 0x83, 1,2,3].contains(&(crt.refs[0] as u8)) { continue; }
                        CT_found = true;
                        break;
                    }
                    result = (AT_found && CCT_found /*is_suitable_for_sm*/, CT_found /*has_ct*/);
                    break;
                }
            }
        }
    }
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    result
}

pub fn se_get_sae_scb(card: &mut sc_card, cla_ins_p1_p2: &[u8]) -> u8
{
    assert_eq!(4, cla_ins_p1_p2.len());
    let cp_df = current_path_df(card);
    let file_id_dir = u16::from_be_bytes([cp_df[cp_df.len()-2], cp_df[cp_df.len()-1]]);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    assert!(dp.files.contains_key(&file_id_dir));
    let mut scb = 0;
    match &dp.files[&file_id_dir].4 {
        None => {},
        Some(vec_saeinfo) => {
            for elem in vec_saeinfo {
                if elem.ins == cla_ins_p1_p2[1] {
                    if (elem.tag_AMDO&8)>0 && elem.cla != cla_ins_p1_p2[0] { continue; }
//                  if (elem.tag_AMDO&4)>0 && elem.ins != cla_ins_p1_p2[1] { continue; }
                    if (elem.tag_AMDO&2)>0 && elem.p1  != cla_ins_p1_p2[2] { continue; }
                    if (elem.tag_AMDO&1)>0 && elem.p2  != cla_ins_p1_p2[3] { continue; }

                    if elem.tag_SCDO == 0x90                               { continue; } // always allowed, thus no constraint
////println!("se_get_sae_scb  *elem: {:X?},  cla_ins_p1_p2: {:X?}", *elem, cla_ins_p1_p2);
//se_get_sae_scb  *elem: SAEinfo { tag_AMDO: 84, cla: 0, ins: 20, p1: 0, p2: 0, tag_SCDO: 9E, scb: 43 },  cla_ins_p1_p2: [0, 20, 0, 81]
                    if elem.tag_SCDO == 0x97                               { scb=0xFF;     break; } // always disallowed
                    if elem.tag_SCDO == 0x9E                               { scb=elem.scb; break; } // depends on scb
//                    if elem.tag_SCDO == 0xA4                               { scb=elem.scb; break; } // depends on scb
                }
            }
        }
    }
    card.drv_data = Box::into_raw(dp) as *mut c_void;
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
pub fn se_parse_sac(/*card: &mut sc_card,*/ reference: c_uint, data: &[u8], se_info_node: &mut SACinfo) -> c_int // se_parse_crts
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
        if  rv != SC_SUCCESS || tag_out == SC_ASN1_TAG_EOC as u32 {
            return (data.len() - buflen_remaining) as i32;
        }
        assert!(!data_ptr.is_null());
        buflen_remaining -= 2;

        se_info_node.crts_len += 1;
        se_info_node.crts[idx_crts].tag = cla_out | tag_out;

        let mut idx_refs = 0_usize;
        let mut taglen_remaining = taglen;
        assert!(taglen_remaining <= buflen_remaining);
        while taglen_remaining > 0 {
            rv = unsafe { sc_asn1_read_tag(&mut data_ptr, taglen_remaining, &mut cla_out, &mut tag_out, &mut taglen) };
            assert_eq!(rv, SC_SUCCESS);
            taglen_remaining -= 2 + taglen; // for taglen>0, the data_ptr must still be updated to point to the next TLV
            buflen_remaining -= 2 + taglen;
            match (cla_out | tag_out) as u8 {
                0x80 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].algo = u32::from(*data_ptr);
                        data_ptr = data_ptr.add(1)
                    };
                },
                0x81 => { assert_eq!(taglen, 2); },
                0x83 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].refs[idx_refs] = u32::from(*data_ptr);
                        data_ptr = data_ptr.add(1)
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
                        data_ptr = data_ptr.add(1)
                    };
                },
                _ => ()
            }
        }
        idx_crts += 1;
    }

    (data.len() - buflen_remaining) as i32
}


pub fn se_parse_sae(vec_sac_info: &mut Option<Vec<SACinfo>>, value_bytes_tag_fcp_sae: &[u8]) -> Result<Vec<SAEinfo>, c_int>
{
    use num_integer::Integer;
    use iso7816_tlv::simple::Tlv;
//    use std::convert::TryFrom;
    use crate::no_cdecl::{convert_amdo_to_cla_ins_p1_p2_array};

    // add the A4 tag as virtual SE-file record (SAC), starting with se record id 16, the max. of real ones is 14
    let mut idx_virtual = 15_u32;
    let mut vec_sae_info = Vec::with_capacity(6);
    let mut rem = value_bytes_tag_fcp_sae;
    assert!(rem.len()<=32);
    loop {
        if rem.is_empty() {
            break;
        }
        let (parsed, rem_tmp) = Tlv::parse(rem);
        rem = rem_tmp;
        let tlv = match parsed {
            Ok(tlv) => tlv,
            Err(_e) => return Err(-1),
        };
//println!("parsed: {:X?}", tlv);
        let mut tag : u8 = tlv.tag().into(); // Into::<u8>::into(tlv.tag());
//        let my_tag /*: u8*/ = Into::<u8>::into(Tag::try_from(127_u8).unwrap().tag());
        let _my_tag /*: u8*/ = Into::<u8>::into(tlv.tag());
        assert_eq!( tag & 0xF0, 0x80);
        assert_eq!((tag & 0x0F).count_ones() as usize, tlv.length());
        assert_eq!( tag & 0x04, 4); // ins must be included
        let mut sae_info = SAEinfo::default();
        sae_info.tag_AMDO = tag;
        let cla_ins_p1_p2 = match convert_amdo_to_cla_ins_p1_p2_array(tag, tlv.value()) {
            Ok(cla_ins_p1_p2)  => cla_ins_p1_p2,
            Err(e)      => return Err(e),
        };
        sae_info.cla = cla_ins_p1_p2[0];
        sae_info.ins = cla_ins_p1_p2[1];
        sae_info.p1  = cla_ins_p1_p2[2];
        sae_info.p2  = cla_ins_p1_p2[3];

        /* at least 1 SCDO must follow */
        assert!(!rem.is_empty());

        let (parsed, rem_tmp) = Tlv::parse(rem);
        rem = rem_tmp;
        let tlv = match parsed {
            Ok(tlv) => tlv,
            Err(_e) => return Err(-1),
        };
//println!("parsed: {:X?}", tlv);
        tag = tlv.tag().into();
        assert!([0x90, 0x97, 0x9E, 0xA4, 0xA0, 0xAF].contains(&tag));
        sae_info.tag_SCDO = tag;
        match tag {
            0x90 => sae_info.scb = 0,
            0x97 => sae_info.scb = 0xFF,
            0x9E => {
                assert_eq!(1, tlv.length());
                sae_info.scb = tlv.value()[0];
            },
            0xA4 => {
                assert!(tlv.length()>=6 && tlv.length().is_multiple_of(&3));
                let mut sac_info = SACinfo::default();
                idx_virtual += 1;
                let mut idx_ref = 0_usize;
                sac_info.reference = idx_virtual;
                sac_info.crts_len  = 1;
                sac_info.crts[0].tag = u32::from(tag);
                for chunk in tlv.value().chunks(3) {
                    assert_eq!(1, chunk[1]);
                    match chunk[0] {
                        0x95 => { sac_info.crts[0].usage         = u32::from(chunk[2]); },
                        0x83 => { sac_info.crts[0].refs[idx_ref] = u32::from(chunk[2]); idx_ref += 1; },
                        0x81 => { /*if card.type_== SC_CARD_TYPE_ACOS5_EVO_V4 {TODO EVO also has tag 0x81} else {panic!()}*/ }
                        _    => panic!("unexpected"),
                    }
                    if      chunk[0]==0x95 { sac_info.crts[0].usage         = u32::from(chunk[2]); }
                    else if chunk[0]==0x83 { sac_info.crts[0].refs[idx_ref] = u32::from(chunk[2]); idx_ref += 1;}
                    else                   { panic!(); } // TODO EVO also has tag 0x81
                }
                if (*vec_sac_info).is_none() { *vec_sac_info = Some(Vec::new()) }
//                (*vec_sac_info).unwrap().push(sac_info);
                (*vec_sac_info).as_mut().unwrap().push(sac_info);
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
        let mut seinfo = SACinfo::default();
        let data : [u8; 11] = [/* 80 01 01 */ 0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,   0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 1, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 1);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x81,0,0,0,0,0,0,0]});

        seinfo =  SACinfo::default();
        let data : [u8; 33] = [/* 80 01 02 */
            0xB4, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xB8, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,       0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 2, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
        assert_eq!(seinfo.reference, 2);
        assert_eq!(seinfo.crts_len,  3);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xB4, usage: 8, algo: 2, refs: [   1,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[1],   sc_crt{tag: 0xB8, usage: 8, algo: 2, refs: [   1,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[2],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x81,0,0,0,0,0,0,0]});

        seinfo =  SACinfo::default();
        let data : [u8; 14] = [/* 80 01 04 */
            0xA4, 0x09, 0x83, 0x01, 0x01, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,      0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 4, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
        assert_eq!(seinfo.reference, 4);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [0x01,0x81,0,0,0,0,0,0]});

        seinfo =  SACinfo::default();
        let data : [u8; 31] = [/* 80 01 05 */
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xB8, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xA4, 0x06, 0x83, 0x01, 0x82, 0x95, 0x01, 0x80,       0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 5, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
        assert_eq!(seinfo.reference, 5);
        assert_eq!(seinfo.crts_len,  3);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xB4, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[1],   sc_crt{tag: 0xB8, usage: 0x30, algo: 2, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[2],   sc_crt{tag: 0xA4, usage: 0x80, algo: 0, refs: [0x82,0,0,0,0,0,0,0]});

        seinfo =  SACinfo::default();
        let data : [u8; 9] = [/* 80 01 06 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 6, &data, &mut seinfo);
        assert_eq!(rv as usize, 0);
        assert_eq!(seinfo, SACinfo::default());

        seinfo =  SACinfo::default();
        let data : [u8; 11] = [/* 80 01 01 */
            0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08,     0x00, 0x00, 0x00];
        let rv = se_parse_sac(/*card: &mut sc_card,*/ 1, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
        assert_eq!(seinfo.reference, 1);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 8, algo: 0, refs: [1,0,0,0,0,0,0,0]});
    }
/*
    #[test]
    fn test_se_parse_sae() {
pub fn se_parse_sae(vec_sac_info: &mut Option<Vec<SACinfo>>, value_bytes_tag_fcp_sae: &[u8]) -> Result<Vec<SAEinfo>, c_int>

    }
*/
}
