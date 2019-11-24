/*
 * cmd_card_info.rs: Driver 'acos5' - cos5 'Card Info' cmds and other, callable via sc_card_ctl (acos5_card_ctl)
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

/* functions callable via sc_card_ctl(acos5_card_ctl), mostly used by acos5_gui */

use std::ffi::CStr;
use std::convert::TryFrom;

use opensc_sys::opensc::{sc_card, sc_transmit_apdu, sc_bytes2apdu_wrapper, sc_check_sw};
use opensc_sys::types::{sc_serial_number, sc_apdu, SC_MAX_SERIALNR, SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_CARD_CMD_FAILED};

use crate::constants_types::*;
use crate::wrappers::*;

/*
 * Get card's (hardware) serial number
 * @apiNote  SC_CARDCTL_GET_SERIALNR; exempt from this function, card.serialnr MUST be treated as immutable
 * @param   card
 * @return  serial number (6 for SC_CARD_TYPE_ACOS5_64_V2 or 8 bytes) or an error encoding
 */
//QS
pub fn get_serialnr(card: &mut sc_card) -> Result<sc_serial_number, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_serialnr\0");
    log3ifc!(ctx,f,line!());
    if card.serialnr.len > 0 {
        return Ok(card.serialnr);
    }

    let len_card_serial_number: u8 = if card.type_ > SC_CARD_TYPE_ACOS5_64_V2 {8} else {6};
    let command = [0x80, 0x14, 0, 0, len_card_serial_number];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);
    debug_assert!(SC_MAX_SERIALNR >= usize::from(len_card_serial_number));

    let mut serial = sc_serial_number::default();
    apdu.resp =    serial.value.as_mut_ptr();
    apdu.resplen = serial.value.len(); // SC_MAX_SERIALNR
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != usize::from(len_card_serial_number) {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Serial Number' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    serial.len = usize::from(len_card_serial_number);
    card.serialnr.value = serial.value;
    card.serialnr.len   = serial.len;
    Ok(serial)
}


//QS
pub fn get_count_files_curr_df(card: &mut sc_card) -> Result<u16, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_count_files_curr_df\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 1, 0];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_1, apdu.cse);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Operation Number of files \
            under the currently selected DF' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    Ok(u16::try_from(apdu.sw2).unwrap())
}


/* Note that reference starts from 0 with V2 and V3, but with V4 reference starts from 1 */
pub fn get_file_info(card: &mut sc_card, reference: u8) -> Result<[u8; 8], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_file_info\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 2, reference+ if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {1} else {0}, 8];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);
    let mut rbuf = [0; 8];
    apdu.resp    =  rbuf.as_mut_ptr();
    apdu.resplen =  rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == rbuf.len() {
        Ok(rbuf)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'File ID'-retrieval failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}


/* free_space in bytes */
//TODO allow nonminimal_bool, a false positive here
#[cfg_attr(feature = "cargo-clippy", allow(clippy::nonminimal_bool))]
pub fn get_free_space(card: &mut sc_card) -> Result<u32, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_free_space\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 4, 0, if card.type_> SC_CARD_TYPE_ACOS5_64_V3 {3} else {2}];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);

    let mut rbuf = [0; 4];
    apdu.resp    = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && (card.type_>  SC_CARD_TYPE_ACOS5_64_V3 && apdu.resplen == 3 ||
                            card.type_<= SC_CARD_TYPE_ACOS5_64_V3 && apdu.resplen == 2) {
        Ok(u32::from_be_bytes(rbuf) >> if card.type_> SC_CARD_TYPE_ACOS5_64_V3 {8} else {16})
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Get Free Space' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}


// true, then it's acos5
//TODO allow nonminimal_bool, a false positive here
#[cfg_attr(feature = "cargo-clippy", allow(clippy::nonminimal_bool))]
pub fn get_ident_self(card: &mut sc_card) -> Result<bool, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_ident_self\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 5, 0];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_1, apdu.cse);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    if apdu.sw1 == 0x95 && (card.type_>  SC_CARD_TYPE_ACOS5_64_V3 && apdu.sw2 == 0xC0 ||
                            card.type_<= SC_CARD_TYPE_ACOS5_64_V3 && apdu.sw2 == 0x40) {
        Ok(true)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Identity Self'-check reports \
                an unexpected, non-ACOS5 response ! ### Card doesn't match ###\0"));
        Ok(false)
    }
}

pub fn get_cos_version(card: &mut sc_card) -> Result<[u8; 8], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_cos_version\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 6, 0, 8];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);
    let mut rbuf = [0; 8];
    apdu.resp    = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == rbuf.len() {
        Ok(rbuf)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: 'ACOS5 version'-retrieval failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  ONLY V3.00 *DOES* support this command
pub fn get_manufacture_date(card: &mut sc_card) -> Result<u32, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_manufacture_date\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 7, 0, 4];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0; 4];
    apdu.resp    = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == rbuf.len() {
        Ok(u32::from_be_bytes(rbuf))
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Get ROM_Manufacture_Date' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  V2.00 *DOES NOT* supports this command
pub fn get_rom_sha1(card: &mut sc_card) -> Result<[u8; 20], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_rom_sha1\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 8, 0, 20];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);
    let mut rbuf = [0; 20];
    apdu.resp    = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == rbuf.len() {
        Ok(rbuf)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Get ROM SHA1'-retrieval failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  V2.00 *DOES NOT* supports this command
pub fn get_op_mode_byte(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_op_mode_byte\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 9, 0];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_1, apdu.cse);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && (apdu.sw2 == 0 || apdu.sw2 == 1 || apdu.sw2 == 2 || apdu.sw2 == 16) {
        /*  for SC_CARD_TYPE_ACOS5_64_V3: apdu.sw2:
             0: FIPS 140-2 Level 3–Compliant Mode
             1: Emulated 32K Mode
             2: 64K Mode
            16: NSH-1 Mode

            for SC_CARD_TYPE_ACOS5_EVO_V4: apdu.sw2:
             0: FIPS 140-2 Level 3–Compliant Mode
             1: Default Mode (Non-FIPS)
        */
        Ok(u8::try_from(apdu.sw2).unwrap())
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Operation Mode Byte' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
pub fn get_op_mode_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_op_mode_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let mut operation_mode_byte : u8 = 0xFF; // also called compatibility byte
    let command = [0, 0xB0, 0xC1, 0x91, 1];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);

    apdu.resp    = &mut operation_mode_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == 1 {
        Ok(operation_mode_byte)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Operation Mode Byte' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  V2.00 *DOES NOT* supports this command
pub fn get_fips_compliance(card: &mut sc_card) -> Result<bool, i32> // is_FIPS_compliant==true
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_fips_compliance\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 10, 0];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_1, apdu.cse);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.sw2==0 {
        log3if!(ctx,f,line!(), cstru!(b"'Get Card Info: Verify FIPS Compliance' returned: Card's \
            file system **does** comply with FIPS requirements and Operation Mode is FIPS\0"));
        Ok(true)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"'Get Card Info: Verify FIPS Compliance' returned: Card's \
            file system **does not** comply with FIPS requirements or Operation Mode is other than FIPS\0"));
        Ok(false)
    }
}

//  ONLY V3.00 *DOES* support this command
pub fn get_pin_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_pin_auth_state\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 11, reference/*, 1*/];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_1, apdu.cse);

/*
    debug_assert_eq!(SC_APDU_CASE_2_SHORT, apdu.cse);
    let mut rbuf = [0_u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
*/
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS {
        Ok(true)
    }
    else if apdu.sw1 == 0x6F && apdu.sw2 == 0 {
        Ok(false)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Get Pin Authentication State' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  ONLY V3.00 *DOES* support this command
pub fn get_key_auth_state(card: &mut sc_card, reference: u8) -> Result<bool, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_key_auth_state\0");
    log3ifc!(ctx,f,line!());

    let command = [0x80, 0x14, 12, reference/*, 1*/];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    debug_assert_eq!(apdu.cse, SC_APDU_CASE_1);

/*
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
    let mut rbuf = [0_u8; 1];
    apdu.resp = rbuf.as_mut_ptr();
    apdu.resplen = rbuf.len();
*/
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS {
        Ok(/*rbuf[0] == 1*/true)
    }
    else if apdu.sw1 == 0x6F && apdu.sw2 == 0 {
        Ok(false)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Get Key Authentication State' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
pub fn get_zeroize_card_disable_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_zeroize_card_disable_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let command = [0, 0xB0, 0xC1, 0x92, 1];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut zeroize_card_disable_byte : u8 = 0xFF;
    apdu.resp = &mut zeroize_card_disable_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Zeroize Card Disable Byte' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    Ok(zeroize_card_disable_byte)
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
pub fn get_card_life_cycle_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_card_life_cycle_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let mut card_life_cycle_byte : u8 = 0xFF;
    let command = [0, 0xB0, 0xC1, 0x84, 1];
    let mut apdu = sc_apdu::default();
    let mut rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    apdu.resp = &mut card_life_cycle_byte;
    apdu.resplen = 1;
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Life Cycle Byte' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    Ok(card_life_cycle_byte)
}
