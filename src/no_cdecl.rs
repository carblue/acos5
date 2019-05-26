/*
 * no_cdecl.rs: Driver 'acos5_64' - Miscellaneous functions referring to sc_path or sc_path.value
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

//extern crate bitintr;
//use bitintr::Popcnt;

//#![feature(const_fn)]

use std::os::raw::{c_int, c_void, c_uint, c_uchar, c_ulong/*, c_uchar*/};
use std::ffi::{/*CString,*/ CStr};


use opensc_sys::opensc::{sc_card, sc_pin_cmd_data,
                         sc_transmit_apdu, sc_bytes2apdu_wrapper, sc_get_iso7816_driver, sc_file_free, sc_read_record,
                         /*sc_verify,*/ sc_format_path, sc_select_file,
                         SC_RECORD_BY_REC_NR, SC_PIN_ENCODING_ASCII, SC_READER_SHORT_APDU_MAX_RECV_SIZE
};
use opensc_sys::types::{/*sc_aid, sc_path, SC_MAX_AID_SIZE, SC_MAX_PATH_SIZE, sc_file_t,
    SC_MAX_ATR_SIZE, SC_FILE_TYPE_DF,  */  sc_path, sc_file, sc_apdu, SC_PATH_TYPE_FILE_ID/*, SC_PATH_TYPE_PATH*/,
                        SC_MAX_APDU_BUFFER_SIZE, SC_MAX_PATH_SIZE, //SC_AC_CHV,
                        SC_APDU_FLAGS_CHAINING,
                        SC_APDU_CASE_1, /*SC_APDU_CASE_2_SHORT,*/ SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT
};
use opensc_sys::log::{sc_do_log, sc_dump_hex, SC_LOG_DEBUG_NORMAL};
use opensc_sys::errors::{/*sc_strerror, SC_ERROR_NO_READERS_FOUND, SC_ERROR_UNKNOWN, SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_NOT_SUPPORTED, */
                         SC_SUCCESS, SC_ERROR_INVALID_ARGUMENTS,
                         SC_ERROR_KEYPAD_MSG_TOO_LONG/*, SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL*/
,SC_ERROR_WRONG_LENGTH, SC_ERROR_NOT_ALLOWED, SC_ERROR_FILE_NOT_FOUND, SC_ERROR_INCORRECT_PARAMETERS
//,SC_ERROR_CARD_CMD_FAILED, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
};
use opensc_sys::internal::{sc_atr_table};


use crate::constants_types::*;
use crate::se::se_parse_crts;
use crate::path::cut_path;

use super::{acos5_64_list_files, acos5_64_select_file};


/*
The task of track_iso7816_select_file next to SELECT:
Update card.cache.current_path such that it's always valid (pointing to the currently selected EF/DF),
both before and after the call to iso7816_select_file (even if failing)

same @param and @return as iso7816_select_file
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn track_iso7816_select_file(card: &mut sc_card, path: &sc_path, file_out: *mut *mut sc_file) -> c_int
{
    assert_eq!(path.type_, SC_PATH_TYPE_FILE_ID);
    assert_eq!(path.len,   2);
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"track_iso7816_select_file\0").unwrap();
    let format_1   = CStr::from_bytes_with_nul(b"   called.  curr_type: %d, curr_value: %s\0").unwrap();
    let format_2   = CStr::from_bytes_with_nul(b"              to_type: %d,   to_value: %s\0").unwrap();
    let format_3   = CStr::from_bytes_with_nul(b"returning:  curr_type: %d, curr_value: %s\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_1.as_ptr(), card.cache.current_path.type_,
                       sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len) ) };
    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_2.as_ptr(), path.type_,
                       sc_dump_hex(path.value.as_ptr(), path.len) ) };

    let rv = unsafe { (*(*sc_get_iso7816_driver()).ops).select_file.unwrap()(card, path, file_out) };

    /*
    0x6283, SC_ERROR_CARD_CMD_FAILED, "Selected file invalidated" //// Target file has been blocked but selected
    0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied" //// Target file has wrong checksum in its header or file is corrupted; probably selected, but inaccessible: test that
    0x6986, SC_ERROR_NOT_ALLOWED,  "Command not allowed (no current EF)" //// No Master File found in card; no MF found
    0x6A82, SC_ERROR_FILE_NOT_FOUND, "File not found" //// Target file not found
    0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters P1-P2" //// Invalid P1 or P2. P2 must be 00h and P1 must be 00h or 04h
    0x6A87, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with P1-P2" //// Wrong P3 length. P3 is not compatible with P1.
      SC_ERROR_CARD_CMD_FAILED if iso7816_check_sw encounters unknown error
    */
    if rv == SC_ERROR_WRONG_LENGTH ||
       rv == SC_ERROR_NOT_ALLOWED  ||
       rv == SC_ERROR_FILE_NOT_FOUND ||
       rv == SC_ERROR_INCORRECT_PARAMETERS /*shouldn't be emitted for select file*/ {
        // select failed, no new card.cache.current_path, do nothing
    }
    else {
/*
        rv == SC_SUCCESS ||
        rv == SC_ERROR_CARD_CMD_FAILED ||
        rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
*/
        let file_id = u16_from_array_begin(&path.value[0..2]);
        let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        if file_out.is_null() {

        }
        else {

        }
assert!(dp.files.contains_key(&file_id));
        let dp_files_value = &dp.files[&file_id];
        card.cache.current_path.value = dp_files_value.0;
        card.cache.current_path.len   = dp_files_value.1[1] as usize;
        card.drv_data = Box::into_raw(dp) as *mut c_void;
    }

    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_3.as_ptr(), card.cache.current_path.type_,
                       sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len) ) };
    rv
}



/* process path by chunks, 2 byte each and select_file with SC_PATH_TYPE_FILE_ID */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn select_file_by_path(card: &mut sc_card, path: &sc_path, file_out: *mut *mut sc_file) -> c_int
{
    let mut path1 = sc_path { ..*path };
    let rv = cut_path(card, path, &mut path1);
    if rv != SC_SUCCESS {
        return rv;
    }

    let len = path1.len;
    if  len % 2 != 0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let mut path2 = sc_path { len: 2, ..Default::default() }; // SC_PATH_TYPE_FILE_ID

    for i in 0..len/2 {
        path2.value[0] = path1.value[i*2  ];
        path2.value[1] = path1.value[i*2+1];
        let rv = track_iso7816_select_file(card, &path2, file_out);
        unsafe {
            if (i+1)<len/2 && !file_out.is_null() && !(*file_out).is_null() {
                sc_file_free(*file_out);
                *file_out = std::ptr::null_mut();
            }
        }
        if rv != SC_SUCCESS {
            return rv;
        }
    }
    SC_SUCCESS
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn enum_dir(card: &mut sc_card, path: &sc_path/*, depth: c_int*/) -> c_int
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"enum_dir\0").unwrap();
    let format   = CStr::from_bytes_with_nul(b"called for path: %s\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr(),
                       sc_dump_hex(path.value.as_ptr(), path.len) ) };

    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    assert!(path.len >= 2);
    let file_id = u16_from_array_begin(&path.value[path.len-2..path.len]);
    let fdb = dp.files[&file_id].1[0];
    let dp_files_value = dp.files.entry(file_id).or_insert(([0u8;SC_MAX_PATH_SIZE], [0u8;8], None, None));
    dp_files_value.0    = path.value;
    dp_files_value.1[1] = path.len as u8;
    let mrl = dp_files_value.1[4] as usize;
    let nor  = dp_files_value.1[5] as c_uint;
    card.drv_data = Box::into_raw(dp) as *mut c_void;

    if fdb == FDB_SE_FILE && mrl>0 && nor>0 {
        let mut file_out_ptr_mut: *mut sc_file = std::ptr::null_mut();
        let mut rv = acos5_64_select_file(card, path, &mut file_out_ptr_mut);
        assert_eq!(rv, SC_SUCCESS);
        let mut vec_seinfo : Vec<SeInfo> = Vec::new();
        for rec_nr in 1..1+nor {
            let buf = &mut [0u8; 255];
            rv = unsafe { sc_read_record(card, rec_nr, buf.as_mut_ptr(), mrl, SC_RECORD_BY_REC_NR as c_ulong) };
/* * /
// TODO temporary if SE file is pin-protected for READ
if rv < 0 && card.type_== SC_CARD_TYPE_ACOS5_64_V3  // currently has SO_PIN same as User pin
{
    let pin = [0x31u8, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]; //if path.len>4 { [0x31u8, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38] }
//                     else           { [0x38u8, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31] };
    let mut tries_left : c_int = 0;
    rv = unsafe { sc_verify(card, SC_AC_CHV, if path.len>4 {0x81} else {0x01}, pin.as_ptr(), pin.len(), &mut tries_left) };
    assert!(rv == 0);
    rv = unsafe { sc_read_record(card, rec_nr, buf.as_mut_ptr(), mrl, SC_RECORD_BY_REC_NR) };
}
/ * */
            assert!(rv >= 0);
            if rv >= 1 && buf[0] == 0 || rv >= 3 && buf[2] == 0 {
                break;
            }
            if rv >= 3 {
                assert_eq!(rec_nr, buf[2] as u32); // not really required but recommended
            }
            let mut seinfo : SeInfo = Default::default();
            let rv = se_parse_crts(buf[2] as c_int,&buf[3..], &mut seinfo);
            assert!(rv > 0);
            vec_seinfo.push(seinfo);
        }
        assert!(path.len >= 4);
        let file_id_dir = u16_from_array_begin(&path.value[path.len-4..path.len-2]);
        let mut dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        let dp_files_value = dp.files.entry(file_id_dir).or_insert(([0u8;SC_MAX_PATH_SIZE], [0u8;8], None, None));
        dp_files_value.3 = Some(vec_seinfo);
        card.drv_data = Box::into_raw(dp) as *mut c_void;
    }

    if (fdb & FDB_DF) == FDB_DF { // DF/MF
        assert!(path.len <= SC_MAX_PATH_SIZE-2);
        let mut file_out_ptr_mut: *mut sc_file = std::ptr::null_mut();
        let rv = acos5_64_select_file(card, path, &mut file_out_ptr_mut);
        assert_eq!(rv, SC_SUCCESS);
        let mut files_contained= [0u8; (SC_MAX_APDU_BUFFER_SIZE/2)*2];
        let rv = acos5_64_list_files(card, files_contained.as_mut_ptr(), files_contained.len());
/*
        println!("files_contained: {:?}", &files_contained[  ..32]);
        println!("files_contained: {:?}", &files_contained[32..64]);
        println!("files_contained: {:?}", &files_contained[64..96]);
*/
        assert!(rv >= 0);
        for i in 0..(rv/2) as usize {
            let mut tmppath : sc_path = *path;
            tmppath.value[tmppath.len  ] = files_contained[2*i  ];
            tmppath.value[tmppath.len+1] = files_contained[2*i+1];
            tmppath.len += 2;
//            assert_eq!(tmppath.len, ((depth+2)*2) as usize);
            enum_dir(card, &tmppath/*, depth + 1*/);
        }
    }
  SC_SUCCESS
}


/*
 * convert_bytes_tag_fcp_sac_to_scb_array expands the "compressed" tag_fcp_sac (0x8C) bytes from card file/director's
 * header to a 'standard' 8 byte SCB array, interpreting the AM byte (AMB);
 * The position of a SCB within the array is related to a command/operation, that is controlled by this byte
 * The value of SCB refers to a record id in Security Environment file, that stores details of conditions that must be
 * met in order to grant access
 * SC's byte positions are assigned values matching the AM bit-representation in reference manual, i.e. it is reversed
 * to what many other cards do:
 * Bit 7 of AM byte indicates what is stored to byte-index 7 of SC ( Not Used by ACOS )
 * Bit 0 of AM byte indicates what is stored to byte-index 0 of SC ( EF: READ, DF/MF:  Delete_Child )
 * Bits 0,1,2 may have different meaning depending on file type, from bits 3 to 6/7 (unused) meanings are the same for
 * all file types
 * Maybe later integrate this in acos5_64_process_fci
 * @param  bytes_tag_fcp_sac IN  the TLV's V bytes readable from file header for tag 0x8C, same order from left to right;
 *                               number of bytes: min: 0, max. 8
 *                               If there are >= 1 bytes, the first is AM
 * @param  scb8          OUT     8 SecurityConditionBytes, from leftmost (index 0)'READ'/'Delete_Child' to
 *                               (6)'SC_AC_OP_DELETE_SELF', (7)'unused'
 *
 * The reference manual contains a table indicating the possible combinations of bits allowed for a scb:
 * For any violation, None will be returned
 */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn convert_bytes_tag_fcp_sac_to_scb_array(bytes_tag_fcp_sac: &[u8]) -> Result<[u8; 8], c_int>
{
//   assert_eq!(0b0101_1010u16.popcnt(), 4);
    let mut scb8 = [0u8; 8];
    scb8[7] = 0xFF; // though not expected to be accidentally set, it get's overriden to NEVER: it's not used by ACOS

    if bytes_tag_fcp_sac.len() == 0 {
        return Ok(scb8);
    }
    assert!(bytes_tag_fcp_sac.len() <= 8);

    let mut idx = 0;
    let amb = bytes_tag_fcp_sac[idx];
    idx += 1;
    if amb.count_ones() as usize != bytes_tag_fcp_sac.len()-1 { // the count of 1-valued bits of amb Byte must equal (taglen-1), the count of bytes following amb
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }

    for pos in 0..8 {
        if (amb & (0b1000_0000 >> pos)) != 0 { //assert(i);we should never get anything for scb8[7], it's not used by ACOS
            scb8[7-pos] = bytes_tag_fcp_sac[idx];
            idx += 1;
        }
    }
    Ok(scb8)
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn pin_get_policy(card: &mut sc_card, data: &mut sc_pin_cmd_data, tries_left: *mut c_int) -> c_int
{
/* when is AODF read for the pin details info info ? */
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"pin_get_policy\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    data.pin1.min_length = 4; /* min length of PIN */
    data.pin1.max_length = 8; /* max length of PIN */
    data.pin1.stored_length = 8; /* stored length of PIN */
    data.pin1.encoding = SC_PIN_ENCODING_ASCII; /* ASCII-numeric, BCD, etc */
//  data.pin1.pad_length    = 0; /* filled in by the card driver */
    data.pin1.pad_char = 0xFF;
    data.pin1.offset = 5; /* PIN offset in the APDU */
//  data.pin1.length_offset = 5;
    data.pin1.length_offset = 0; /* Effective PIN length offset in the APDU */

    data.pin1.max_tries = 8;//pin_tries_max; /* Used for signaling back from SC_PIN_CMD_GET_INFO */ /* assume: 8 as factory setting; max allowed number of retries is unretrievable with proper file access condition NEVER read */

    let command = [0x00u8, 0x20, 0x00, data.pin_reference as u8];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x63 || (apdu.sw2 & 0xC0) != 0xC0 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or 'Get remaining number of retries left for the PIN' \
                     failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                            format.as_ptr()) };
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    data.pin1.tries_left = (apdu.sw2 & 0x0Fu32) as c_int; //  63 Cnh     n is remaining tries


    if !tries_left.is_null() {
        unsafe { *tries_left = data.pin1.tries_left };
    }
    SC_SUCCESS
}

pub /*const*/ fn acos5_64_atrs_supported() -> [sc_atr_table; 3]
{
    let acos5_64_atrs: [sc_atr_table; 3] = [
        sc_atr_table {
            atr:     CStr::from_bytes_with_nul(ATR_V2).unwrap().as_ptr(),
            atrmask: CStr::from_bytes_with_nul(ATR_MASK).unwrap().as_ptr(),
            name:    CStr::from_bytes_with_nul(NAME_V2).unwrap().as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_64_V2,
            flags: 0,
            card_atr: std::ptr::null_mut(),
        },
        sc_atr_table {
            atr:     CStr::from_bytes_with_nul(ATR_V3).unwrap().as_ptr(),
            atrmask: CStr::from_bytes_with_nul(ATR_MASK).unwrap().as_ptr(),
            name:    CStr::from_bytes_with_nul(NAME_V3).unwrap().as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_64_V3,
            flags: 0,
            card_atr: std::ptr::null_mut(),
        },
        Default::default(),
    ];
    acos5_64_atrs
}

pub fn set_is_running_cmd_long_response(card: &mut sc_card, value: bool)
{
    let mut dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    dp.is_running_cmd_long_response = value;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
}

pub fn get_is_running_cmd_long_response(card: &mut sc_card) -> bool
{
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let result = dp.is_running_cmd_long_response;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    result
}

/*
pub fn set_is_running_compute_signature(card: &mut sc_card, value: bool)
{
    let mut dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    dp.is_running_compute_signature = value;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
}

pub fn get_is_running_compute_signature(card: &mut sc_card) -> bool
{
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let result = dp.is_running_compute_signature;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    result
}
*/


pub fn get_rsa_algo_flags(card: &mut sc_card) -> c_uint
{
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let result = dp.rsa_algo_flags;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    result
}

/* this is tailored for a special testing use case, don't use generally, SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC */
pub fn encrypt_public_rsa(card: *mut sc_card, signature: *mut c_uchar, siglen: usize)
{
    let card_ref_mut = unsafe { &mut *card };
    let mut path = Default::default();
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3f0041004133\0").unwrap().as_ptr(), &mut path); } // type = SC_PATH_TYPE_PATH;
    let file_ptr_address = std::ptr::null_mut();
    let mut rv = unsafe { sc_select_file(card_ref_mut, &path, file_ptr_address) };
    assert_eq!(rv, SC_SUCCESS);
    let command = [0u8, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x12, 0x81, 0x02, 0x41, 0x33, 0x95, 0x01, 0x80];
    let mut apdu = Default::default();
    rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    assert_eq!(rv, SC_SUCCESS);
    let command = [0u8, 0x2A, 0x84, 0x80, 0x02, 0xFF, 0xFF, 0xFF]; // will replace lc, cmd_data, le later; the last 4 bytes are placeholders only for sc_bytes2apdu_wrapper
    apdu = Default::default();
    rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    let mut rbuf = [0u8; 512];
    assert_eq!(rbuf.len(), siglen);
    apdu.data    = signature;
    apdu.datalen = siglen;
    apdu.lc      = siglen;
    apdu.resp    = rbuf.as_mut_ptr();
    apdu.resplen = siglen;
    apdu.le      = std::cmp::min(siglen, SC_READER_SHORT_APDU_MAX_RECV_SIZE);
    if apdu.lc > card_ref_mut.max_send_size {
        apdu.flags |= SC_APDU_FLAGS_CHAINING as c_ulong;
    }

    set_is_running_cmd_long_response(card_ref_mut, true); // switch to false is done by acos5_64_get_response
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    assert_eq!(rv, SC_SUCCESS);

    println!("signature 'decrypted' with public key:");
    println!("{:X?}", &rbuf[  0.. 32]);
    println!("{:X?}", &rbuf[ 32.. 64]);
    println!("{:X?}", &rbuf[ 64.. 96]);
    println!("{:X?}", &rbuf[ 96..128]);
    println!("{:X?}", &rbuf[128..160]);
    println!("{:X?}", &rbuf[160..192]);
    println!("{:X?}", &rbuf[192..224]);
    println!("{:X?}", &rbuf[224..256]);
    println!("{:X?}", &rbuf[256..288]);
    println!("{:X?}", &rbuf[288..320]);
    println!("{:X?}", &rbuf[320..352]);
    println!("{:X?}", &rbuf[352..384]);
    println!("{:X?}", &rbuf[384..416]);
    println!("{:X?}", &rbuf[416..448]);
    println!("{:X?}", &rbuf[448..480]);
    println!("{:X?}", &rbuf[480..512]);
}

/*
  The EMSA-PKCS1-v1_5 DigestInfo prefix (all content excluding the trailing hash) is known, same the length of hash
  guess by length of known length of DigestInfo, whether the input likely is a DigestInfo and NOT some other raw data
*/
pub fn is_any_of_di_by_len(len: usize) -> bool
{
   let known_len = [34u8, 35, 47, 51, 67, 83];
    for i in 0..known_len.len() {
        if known_len[i] as usize == len { return true; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{convert_bytes_tag_fcp_sac_to_scb_array};

    #[test]
    fn test_convert_bytes_tag_fcp_sac_to_scb_array() {
        // the complete TLV : [0x8C, 0x07,  0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02]
        let bytes_tag_fcp_sac = [0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02];
        let mut scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x02, 0x00, 0xFF, 0xFF, 0x04, 0x03, 0x02, 0xFF]);

        let bytes_tag_fcp_sac : [u8; 0] = [];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        let bytes_tag_fcp_sac = [0x00];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        let bytes_tag_fcp_sac = [0x7F, 0xFF, 0xFF, 0x03, 0x03, 0x01, 0x03, 0x01];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x01, 0x03, 0x01, 0x03, 0x03, 0xFF, 0xFF, 0xFF]);

        let bytes_tag_fcp_sac = [0x62, 0x06, 0x05, 0x01];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0xFF]);

        let bytes_tag_fcp_sac = [0x2B, 0x05, 0x03, 0x01, 0x45];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x45, 0x01, 0x00, 0x03, 0x00, 0x05, 0x00, 0xFF]);
    }
}
