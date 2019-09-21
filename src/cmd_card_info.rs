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

use std::os::raw::{c_int, c_uint, c_uchar};
use std::ffi::{CStr};

use opensc_sys::opensc::{sc_card, sc_transmit_apdu, sc_bytes2apdu_wrapper, sc_check_sw};
use opensc_sys::types::{sc_serial_number, SC_MAX_SERIALNR, SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_KEYPAD_MSG_TOO_LONG};

use crate::constants_types::*;
use crate::wrappers::*;

/*
 * What it does
 * @apiNote  SC_CARDCTL_GET_SERIALNR
 * @param
 * @return
 */
pub fn get_serialnr(card: &mut sc_card) -> Result<sc_serial_number, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_serialnr\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    if card.serialnr.len > 0 {
        return Ok(card.serialnr);
    }
    let len_card_serial_number = if card.type_ == SC_CARD_TYPE_ACOS5_64_V3 {8u8} else {6u8};
    let command = [0x80u8, 0x14, 0x00, 0x00, len_card_serial_number];
    let len_card_serial_number = len_card_serial_number as usize;
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
    assert!(len_card_serial_number <= SC_MAX_SERIALNR);

    let mut serial : sc_serial_number = Default::default();
    apdu.resp = serial.value.as_mut_ptr();
    apdu.resplen = SC_MAX_SERIALNR;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen < len_card_serial_number {
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
            b"Error: ACOS5-64 'Get Card Info: Serial Number' failed\0").unwrap());
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    serial.len = len_card_serial_number;
    card.serialnr.value = serial.value;
    card.serialnr.len   = serial.len;
    Ok(serial)
}


pub fn get_count_files_curr_df(card: &mut sc_card) -> Result<usize, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_count_files_curr_df\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x01, 0x00];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"Error: ACOS5-64 'Get Card Info: Operation Number of files \
                     under the currently selected DF' failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(apdu.sw2 as usize)
}

pub fn get_file_info(card: &mut sc_card, reference: u8) -> Result<[u8; 8], c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_file_info\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x02, reference, 0x08];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
    let mut rbuf = [0u8; 8];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen < rbuf.len() {
        let fmt = CStr::from_bytes_with_nul(b"Error: ACOS5-64 'File ID'-retrieval failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

pub fn get_free_space(card: &mut sc_card) -> Result<c_uint, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_free_space\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80, 0x14, 0x04, 0x00, 0x02];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0u8; 2];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"Error: ACOS5-64 'Get Card Info: Get Free Space' failed\0")
                         .unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(u16_from_array_begin(&rbuf) as c_uint)
}

pub fn get_ident_self(card: &mut sc_card) -> Result<bool, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_ident_self\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x05, 0x00];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    if apdu.sw1 != 0x95 || apdu.sw2 != 0x40 {
        let fmt = CStr::from_bytes_with_nul(b"ACOS5-64 'Get Card Info: Identity Self'-check reports an unexpected, \
                     non-ACOS5-64 response ! ### Card doesn't match ###\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        Ok(false)
    }
    else { Ok(true) }
}

pub fn get_cos_version(card: &mut sc_card) -> Result<[u8; 8], c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"get_cos_version\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x06, 0x00, 0x08];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
    let mut rbuf = [0u8; 8];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < rbuf.len() {
        let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'ACOS version'-retrieval failed\0")
                     .unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_manufacture_date(card: &mut sc_card) -> Result<c_uint, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_manufacture_date\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x07, 0x00, 0x04];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0u8; 4];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
        let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get ROM_Manufacture_Date' \
                     failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(u32_from_array_begin(&rbuf) as c_uint)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_rom_sha1(card: &mut sc_card) -> Result<[u8; 20], c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_rom_sha1\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x08, 0x00, 0x14];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
    let mut rbuf = [0u8; 20];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen < rbuf.len() {
        let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Get ROM SHA1'-retrieval \
                     failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_op_mode_byte(card: &mut sc_card) -> Result<c_uchar, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_op_mode_byte\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x09, 0x00];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90  || (apdu.sw2 != 0 && apdu.sw2 != 1 && apdu.sw2 != 2 && apdu.sw2 != 16) {
        let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu or ACOS5-64 'Get Card Info: Operation Mode Byte' \
                     failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
/*  apdu.sw2:
     0: FIPS 140-2 Level 3–Compliant Mode
     1: Emulated 32K Mode
     2: 64K Mode
    16: NSH-1 Mode
*/
    Ok(apdu.sw2 as c_uchar)
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
#[allow(non_snake_case)]
pub fn get_op_mode_byte_EEPROM(card: &mut sc_card) -> Result<c_uchar, c_int>
{
/*
            /* The meaning of operation_mode_byte depends on card type:
               V2.00:  0 (default factory setting): 64k mode, any other is: Emulated 32K mode
               V3.00:  0 (default factory setting): FIPS mode, 1: Emulated 32K mode, 2: 64k mode, 16: NSH-1 mode
            */
            let mut operation_mode_byte = 0xFFu8; // also called compatibility byte
            apdu.p2 = 0x91;
            apdu.resp = &mut operation_mode_byte;
            apdu.resplen = 1;
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
            if rv != SC_SUCCESS || apdu.resplen != 1 {
                wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Operation Mode Byte' failed\0").unwrap());
                return SC_ERROR_KEYPAD_MSG_TOO_LONG;
            }
*/
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_op_mode_byte_EEPROM\0").unwrap();
    let mut operation_mode_byte = 0xFFu8; // also called compatibility byte
    let command = [0u8, 0xB0, 0xC1, 0x91, 1];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    /* The meaning of operation_mode_byte depends on card type:
       V2.00:  0 (default factory setting): 64k mode, any other is: Emulated 32K mode
       V3.00:  0 (default factory setting): FIPS mode, 1: Emulated 32K mode, 2: 64k mode, 16: NSH-1 mode
    */
    apdu.resp = &mut operation_mode_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Operation Mode Byte' failed\0").unwrap());
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(operation_mode_byte)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_fips_compliance(card: &mut sc_card) -> Result<bool, c_int> // is_FIPS_compliant==true
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_fips_compliance\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x0A, 0x00];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    let status_word = u16_from_array_begin(&[apdu.sw1 as u8, apdu.sw2 as u8]) as c_uint;
    let fmt = CStr::from_bytes_with_nul(b"'Get Card Info: Verify FIPS Compliance' returned status word: 0x%04X  \
                 (FIPS-compliant if it's 0x9000)\0").unwrap();
    #[cfg(log)]
    wr_do_log_t(card.ctx, f_log, line!(), fun, status_word, fmt);
    Ok(status_word == 0x9000)
    /* status_word == 0x9000 <=> is_FIPS_compliant==true */
}

//  V2.00 *DOES NOT* supports this command
pub fn get_pin_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_pin_auth_state\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80u8, 0x14, 0x0B, reference, 0x01];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"Error: ACOS5-64 'Get Card Info: Get Pin Authentication \
                     State' failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf[0] == 1)
}

//  V2.00 *DOES NOT* supports this command
pub fn get_key_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, c_int>
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_pin_auth_state\0").unwrap();
    #[cfg(log)]
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());

    let command = [0x80, 0x14, 0x0C, reference, 1];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"Error: ACOS5-64 'Get Card Info: Get Key Authentication \
                     State' failed\0").unwrap();
        #[cfg(log)]
        wr_do_log(card.ctx, f_log, line!(), fun, fmt);
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(rbuf[0] == 1)
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
#[allow(non_snake_case)]
pub fn get_zeroize_card_disable_byte_EEPROM(card: &mut sc_card) -> Result<c_uchar, c_int>
{
    /*
            let mut zeroize_card_disable_byte = 0xFFu8;
            apdu.p2 = 0x92;
            apdu.resp = &mut zeroize_card_disable_byte;
            apdu.resplen = 1;
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
            if rv != SC_SUCCESS || apdu.resplen != 1  {
                wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Zeroize Card Disable Flag' failed\0").unwrap());
                return SC_ERROR_KEYPAD_MSG_TOO_LONG;
            }
    */
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_zeroize_card_disable_byte_EEPROM\0").unwrap();
    let mut zeroize_card_disable_byte = 0xFFu8; // also called compatibility byte
    let command = [0, 0xB0, 0xC1, 0x92, 1];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    apdu.resp = &mut zeroize_card_disable_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Zeroize Card Disable Byte' failed\0").unwrap());
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(zeroize_card_disable_byte)
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
#[allow(non_snake_case)]
pub fn get_card_life_cycle_byte_EEPROM(card: &mut sc_card) -> Result<c_uchar, c_int>
{
/*
let command = [0u8, 0xB0, 0xC1, 0x84, 1];
let mut apdu = Default::default();
let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
assert_eq!(rv, SC_SUCCESS);
assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

let mut card_life_cycle_byte = 0xFFu8;
apdu.resp = &mut card_life_cycle_byte;
apdu.resplen = 1;
rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
if rv != SC_SUCCESS || apdu.resplen != 1  {
wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Card Life Cycle Byte' failed\0").unwrap());
return SC_ERROR_KEYPAD_MSG_TOO_LONG;
}
*/
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"get_zeroize_card_disable_byte_EEPROM\0").unwrap();
    let mut card_life_cycle_byte = 0xFFu8;
    let command = [0, 0xB0, 0xC1, 0x84, 1];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    apdu.resp = &mut card_life_cycle_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
    wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"ACOS5-64 'Get Card Life Cycle Byte' failed\0").unwrap());
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    Ok(card_life_cycle_byte)
}
