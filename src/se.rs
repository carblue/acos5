/*
 * se.rs: Driver 'acos5_64' - Security Environment (SE) related code
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
During processing of acos5_64_init, the HashMap 'files' will be filled for all existing files with data
about absolute path and those data retrieved from cos5 'Get Card Info, P1=2: File Information' among which
essentially is FDB (File Descriptor Byte), all other info like scb8 get's retrieved lazily only
(during select_file/process_fci processing).

On each selection of a directory (if no info is stored already), the associated SE-file within that
directory will be selected and all of it's records evaluated and the content stored in Vec<SeInfo>,
a separate Vec<SeInfo> for each SE file id/directory, attached to directory's hashmap data.
Vec<SeInfo> data applies to a directory and all its "directly" contained files except sub-directories.
This Vec<SeInfo>  is then moved to the 'files' entry for that directory.
Back to the example scb8 [0xFF, 0x41, 2, 3, 4, 0, 0, 0xFF] for file_id 0x4101 in directory 0x4100:
dp.files[0x4101] knows it's absolute path [0x3F, 0, 0x41, 0, 0x41, 1], with last 2 bytes (fid)
stripped of get's the absolute path of relevant directory 0x4100. This HashMap entry has a Vec<SeInfo>
stored with an entry for reference 2 (respomsible for SCB 2)
For simple cases like SCB between 1 and 14, there will be one only entry in SeInfo's array crts with a
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
It's clear how to encode this in SeInfo, but how to communicate this to opensc (sc_file_add_acl_entry;
what to be shown in opensc-tool -f


For SAE (Security Attributes Expanded), TODO
*/

use std::os::raw::{c_ulong, c_int, c_void};

use opensc_sys::opensc::{sc_card, sc_file_add_acl_entry};
use opensc_sys::types::{sc_file, sc_crt, SC_AC_NONE, SC_AC_UNKNOWN, SC_AC_NEVER, SC_AC_CHV, SC_AC_AUT,
                        SC_AC_KEY_REF_NONE};
use opensc_sys::errors::{SC_SUCCESS};
use opensc_sys::asn1::{sc_asn1_read_tag, SC_ASN1_TAG_EOC};

use crate::constants_types::*;


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
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_NONE, SC_AC_KEY_REF_NONE as c_ulong) }); }
    else if  scb == 0xFF
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_NEVER, SC_AC_KEY_REF_NONE as c_ulong) }); }
    else if  (scb & 0x0F) == 0 || (scb & 0x0F) == 0x0F || (scb & 0x30) != 0 || (scb & 0xC0) == 0xC0
    { assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE as c_ulong) }); }
    else {
        if           (scb & 0x80) == 0x80 {} // FIXME
//        else if      (scb & 0x40) == 0x40 // SM TODO
//            { unsafe { sc_file_add_acl_entry(file, op, SC_AC_PRO, 0); } }
        else {
            let pin_ref = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x08));
            if pin_ref         != SC_AC_KEY_REF_NONE as c_ulong { assert_eq!(SC_SUCCESS, unsafe {
                sc_file_add_acl_entry(file, op, SC_AC_CHV, pin_ref) }); }
            else {
                let key_ref     = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x80));
                if key_ref     != SC_AC_KEY_REF_NONE as c_ulong { assert_eq!(SC_SUCCESS, unsafe {
                    sc_file_add_acl_entry(file, op, SC_AC_AUT, key_ref) }); }
                else {
                    let pin_key_ref = se_get_reference(card, file.id, scb & 0x0F, &sc_crt::new_AT(0x88));
                    if pin_key_ref != SC_AC_KEY_REF_NONE as c_ulong {
                        assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_CHV, pin_key_ref) });
                        assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_AUT, pin_key_ref) });
                    }
                    else {  assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, op, SC_AC_UNKNOWN,
                                                                                  SC_AC_KEY_REF_NONE as c_ulong) }); }
                }
            }
        }
    }
}


/**
 * Performs look-up of SCB meaning in the database - HashMap dp.files - based on a search_template
 * @apiNote
 * @param   card             INOUT
 * @param   file_id          IN    the file_id, for which info is requested; relevant is the SE file info of file_id's directory
 * @param   se_reference     IN    the SE file records id (3.byte) matching SCB & 0x0F, though 0x0F is RFU for cos5 !
 * @param   search_template  IN    usually searching for CRT_TAG_AT, CRT_TAG_CCT or CRT_TAG_CT_SYM
 * @return  pin/sym. key reference ==  pin/sym. key id (global)  or  pin/sym. key id | 0x80 (local)
 */
fn se_get_reference(card: &mut sc_card, file_id: c_int, se_reference: u8, search_template: &sc_crt) -> c_ulong
{
    let mut result : c_ulong = SC_AC_KEY_REF_NONE as c_ulong;
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let file_id = file_id as u16;
    if dp.files.contains_key(&file_id) {
        let fdb        = dp.files[&file_id].1[0];
        let path_len = dp.files[&file_id].1[1] as usize;
        let file_id_dir = if fdb & 0x38 == 0x38 { file_id }
                                else {
                                    let tmp = &dp.files[&file_id].0[path_len-4..path_len-2];
                                    u16_from_array_begin(tmp)
                                };
//        println!("file_id_dir: {:X}", file_id_dir);
        match &dp.files[&file_id_dir].3 {
            None => { result = 0; },
            Some(vec_seinfo) => {
                for elem in vec_seinfo {
                    if elem.reference == se_reference as c_int {
                        for j in 0..elem.crts_len {
                            if elem.crts[j].tag   != search_template.tag   { continue; }
                            if elem.crts[j].usage != search_template.usage { continue; }
                            result = elem.crts[j].refs[0] as c_ulong;
                            break;
                        }
                        break;
                    }
                }
            }
        }
    }

    card.drv_data = Box::into_raw(dp) as *mut c_void;
    if result == SC_AC_KEY_REF_NONE as c_ulong {
//        println!("file_id: {}, se_reference: {}, search_template: {:?}", file_id, se_reference, search_template);
    }
    result
}


/*
 * Parses an SE file's record beginning from it's 4. byte, e.g.
 * Sending:  00 B2 01 04 38                                           <= read record no. 1, 56 bytes, from SE file
 *                 |
 * Received: 80 01 01  A4 06 83 01 81 95 01 08  and 45 more 00 bytes  <= data.as_ptr() must point to A4; the byte before A4 i.e. 01, is record's id; this should be the same as the record nr. read
 *
 * @param   reference     IN    record's id, readable as 3.byte from record's data (SE file's record no should be the same to avoid confusion)
 * @param   data          IN    the data to fill se_info_node with, in this example [A4 06 83 01 81 95 01 08 ...]
 * @param   se_info_node  INOUT on IN, a default-initialized struct, on OUT with the data interpreted filled in
 * @return                the number of bytes parsed from data
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn se_parse_crts(/*card: &mut sc_card,*/ reference: c_int, data: &[u8], se_info_node: &mut SeInfo) -> c_int
{
    if data.len() == 0 || data[0] == 0 {
        return 0;
    }
    //make sure, that se_info_node is a default-initialized struct
//    se_info_node = Default::default();

    let mut data_ptr = data.as_ptr();
    let mut cla_out = 0u32;
    let mut tag_out = 0u32;
    let mut taglen = 0usize;
    let mut buflen_remaining = data.len(); // to be updated after sc_asn1_read_tag changes data_ptr: Then buf and buflen_remaining are in sync. again for the next call
    let mut idx_crts = 0usize;

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

        let mut idx_refs = 0usize;
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
                        se_info_node.crts[idx_crts].algo = *data_ptr as u32;
                        data_ptr = data_ptr.add(1)
                    };
                },
                0x81 => { assert_eq!(taglen, 2); },
                0x83 => {
                    assert_eq!(taglen, 1);
                    unsafe {
                        se_info_node.crts[idx_crts].refs[idx_refs] = *data_ptr as u32;
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
                        se_info_node.crts[idx_crts].usage = *data_ptr as u32;
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


#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(v0_15_0))] // TODO check why the test fails for v0_15_0 (sc_asn1_read_tag ?)
    #[test]
    fn test_se_parse_crts() {
        let mut seinfo : SeInfo =  Default::default();
        let data : [u8; 11] = [/* 80 01 01 */ 0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,   0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 1, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 1);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 0x08, algo: 0, refs: [0x81,0,0,0,0,0,0,0]});

        seinfo =  Default::default();
        let data : [u8; 33] = [/* 80 01 02 */
            0xB4, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xB8, 0x09, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08, 0x80, 0x01, 0x02,
            0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,       0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 2, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 2);
        assert_eq!(seinfo.crts_len,  3);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xB4, usage: 0x08, algo: 0x02, refs: [0x01,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[1],   sc_crt{tag: 0xB8, usage: 0x08, algo: 0x02, refs: [0x01,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[2],   sc_crt{tag: 0xA4, usage: 0x08, algo: 0x00, refs: [0x81,0,0,0,0,0,0,0]});

        seinfo =  Default::default();
        let data : [u8; 14] = [/* 80 01 04 */
            0xA4, 0x09, 0x83, 0x01, 0x01, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,      0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 4, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 4);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 0x08, algo: 0x00, refs: [0x01,0x81,0,0,0,0,0,0]});

        seinfo =  Default::default();
        let data : [u8; 31] = [/* 80 01 05 */
            0xB4, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xB8, 0x08, 0x84, 0x00, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02,
            0xA4, 0x06, 0x83, 0x01, 0x82, 0x95, 0x01, 0x80,       0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 5, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 5);
        assert_eq!(seinfo.crts_len,  3);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xB4, usage: 0x30, algo: 0x02, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[1],   sc_crt{tag: 0xB8, usage: 0x30, algo: 0x02, refs: [0x84,0,0,0,0,0,0,0]});
        assert_eq!(seinfo.crts[2],   sc_crt{tag: 0xA4, usage: 0x80, algo: 0x00, refs: [0x82,0,0,0,0,0,0,0]});

        seinfo =  Default::default();
        let data : [u8; 9] = [/* 80 01 06 */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 6, &data, &mut seinfo);
        assert_eq!(rv as usize, 0);
        assert_eq!(seinfo, Default::default());
//        assert_eq!(seinfo.next, std::ptr::null_mut());

        seinfo =  Default::default();
        let data : [u8; 11] = [/* 80 01 01 */
            0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x08,     0x00, 0x00, 0x00];
        let rv = se_parse_crts(/*card: &mut sc_card,*/ 1, &data, &mut seinfo);
        assert_eq!(rv as usize, data.len()-3);
//        assert_eq!(seinfo.next, std::ptr::null_mut());
        assert_eq!(seinfo.reference, 1);
        assert_eq!(seinfo.crts_len,  1);
        assert_eq!(seinfo.crts[0],   sc_crt{tag: 0xA4, usage: 0x08, algo: 0x00, refs: [1,0,0,0,0,0,0,0]});
    }
}
