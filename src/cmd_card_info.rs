/*
 * cmd_card_info.rs: Driver 'acos5_64' - cos5 'Card Info' cmds and other, callable via sc_card_ctl (acos5_64_card_ctl)
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

/* functions callable via sc_card_ctl(acos5_64_card_ctl), mostly used by acos5_64_gui */

use std::os::raw::{c_int, c_uint /*, c_void, c_char, c_uchar*/};
use std::ffi::{/*CString,*/ CStr};

use opensc_sys::opensc::{sc_transmit_apdu, sc_card, sc_bytes2apdu_wrapper};
use opensc_sys::types::{/*sc_path, sc_file,*/ sc_apdu, sc_serial_number, SC_MAX_SERIALNR/*, SC_MAX_PATH_SIZE*/};
use opensc_sys::log::{sc_do_log, SC_LOG_DEBUG_NORMAL};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_KEYPAD_MSG_TOO_LONG/*, SC_ERROR_FILE_NOT_FOUND*/};

use crate::constants_types::*;
//use super::{acos5_64_select_file};

/*
 * What it does
 * @apiNote  SC_CARDCTL_GET_SERIALNR
 * @param
 * @return
 */
pub fn get_serialnr(card: &mut sc_card) -> Result<sc_serial_number, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_serialnr\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let len_card_serial_number = if card.type_ == SC_CARD_TYPE_ACOS5_64_V3 {8u8} else {6u8};
    let command = [0x80u8, 0x14, 0x00, 0x00, len_card_serial_number];
    let len_card_serial_number = len_card_serial_number as usize;
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert!(len_card_serial_number <= SC_MAX_SERIALNR);

    let mut serial : sc_serial_number = Default::default();
    apdu.resp = serial.value.as_mut_ptr();
    apdu.resplen = SC_MAX_SERIALNR;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < len_card_serial_number {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Serial Number' failed\0")
                     .unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    serial.len = len_card_serial_number;
    Ok(serial)
}


pub fn get_count_files_curr_df(card: &mut sc_card) -> Result<usize, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_count_files_curr_df\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x01, 0x00];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Operation Number of files \
                     under the currently selected DF' failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(apdu.sw2 as usize)
}

pub fn get_file_info(card: &mut sc_card, reference: u8) -> Result<[u8; 8], c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_file_info\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x02, reference, 0x08];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    let mut rbuf = [0u8; 8];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < rbuf.len() {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'File ID'-retrieval failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

pub fn get_free_space(card: &mut sc_card) -> Result<c_uint, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_free_space\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x04, 0x00, 0x02];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);

    let mut rbuf = [0u8; 2];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get Free Space' failed\0")
                     .unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(u16_from_array_begin(&rbuf) as c_uint)
}

pub fn get_ident_self(card: &mut sc_card) -> Result<bool, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_ident_self\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x05, 0x00];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x95 || apdu.sw2 != 0x40 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed ! ### Card doesn't match ###\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }

    if apdu.sw1 != 0x95 || apdu.sw2 != 0x40 {
        let format = CStr::from_bytes_with_nul(b"ACOS5-64 'Get Card Info: Identity Self'-check reports an unexpected, \
                     non-ACOS5-64 response ! ### Card doesn't match ###\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        Ok(false)
    }
    else { Ok(true) }
}

pub fn get_cos_version(card: &mut sc_card) -> Result<[u8; 8], c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_cos_version\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x06, 0x00, 0x08];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    let mut rbuf = [0u8; 8];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < rbuf.len() {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'ACOS version'-retrieval failed\0")
                     .unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_manufacture_date(card: &mut sc_card) -> Result<c_uint, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_manufacture_date\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x07, 0x00, 0x04];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);

    let mut rbuf = [0u8; 4];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get ROM_Manufacture_Date' \
                     failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(u32_from_array_begin(&rbuf) as c_uint)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_rom_sha1(card: &mut sc_card) -> Result<[u8; 20], c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_rom_sha1\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x08, 0x00, 0x14];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    let mut rbuf = [0u8; 20];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < rbuf.len() {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get ROM SHA1'-retrieval \
                     failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_op_mode_byte(card: &mut sc_card) -> Result<c_uint, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_op_mode_byte\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x09, 0x00];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90  || (apdu.sw2 != 0 && apdu.sw2 != 1 && apdu.sw2 != 2 && apdu.sw2 != 16) {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Operation Mode Byte' \
                     failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
/*  apdu.sw2:
     0: FIPS 140-2 Level 3–Compliant Mode
     1: Emulated 32K Mode
     2: 64K Mode
    16: NSH-1 Mode
*/
    Ok(apdu.sw2)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_fips_compliance(card: &mut sc_card) -> Result<bool, c_int> // is_FIPS_compliant==true
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_fips_compliance\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x0A, 0x00];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    let status_word = u16_from_array_begin(&[apdu.sw1 as u8, apdu.sw2 as u8]) as c_uint;
    let format = CStr::from_bytes_with_nul(b"'Get Card Info: Verify FIPS Compliance' returned status word: 0x%04X  \
                 (FIPS-compliant if it's 0x9000)\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr(),
                       status_word) };
    Ok(status_word == 0x9000)
    /* status_word == 0x9000 <=> is_FIPS_compliant==true */
}

//  V2.00 *DOES NOT* supports this command
pub fn get_pin_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_pin_auth_state\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x0B, reference, 0x01];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);

    let mut rbuf = [0u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get Pin Authentication \
                     State' failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf[0] == 1)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_key_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, c_int>
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"get_pin_auth_state\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe {sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr())};

    let command = [0x80u8, 0x14, 0x0C, reference, 0x01];
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);

    let mut rbuf = [0u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
        let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get Key Authentication \
                     State' failed\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr()) };
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf[0] == 1)
}
