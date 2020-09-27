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

/* functions, (most of) callable via sc_card_ctl(acos5_card_ctl), mostly used by acos5_gui */

use std::convert::TryFrom;

use opensc_sys::opensc::{sc_card, sc_transmit_apdu, sc_check_sw};
use opensc_sys::types::{sc_serial_number, SC_MAX_SERIALNR, SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_CARD_CMD_FAILED};

use crate::constants_types::{build_apdu, SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3};
use crate::wrappers::{wr_do_log};

//QS
/// Get card's (hardware identifying) serial number. Copies result to card.serialnr
///
/// @apiNote  `SC_CARDCTL_GET_SERIALNR`; exempt from this function, card.serialnr MUST be treated as immutable. It's not
/// clear to me if for `SC_CARD_TYPE_ACOS5_64_V3` the last 2 bytes are meaningful if not in FIPS mode (at least they are
/// the same for each call, thus this uncertainty doesn't matter).\
/// @return  serial number (6 bytes for `SC_CARD_TYPE_ACOS5_64_V2`, otherwise 8 bytes) or an OpenSC error
///
/// # Errors
///
/// Will return `Err` if sc_transmit_apdu or sc_check_sw fails, or apdu.resplen is wrong (for the card type)
pub fn get_serialnr(card: &mut sc_card) -> Result<sc_serial_number, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_serialnr\0");
    log3ifc!(ctx,f,line!());
    if card.serialnr.len > 0 {
        return Ok(card.serialnr);
    }

    let len_serial_num: usize = if card.type_ > SC_CARD_TYPE_ACOS5_64_V2 {8} else {6};
    debug_assert!(SC_MAX_SERIALNR >= len_serial_num);
    let mut serial = sc_serial_number::default();
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 0, 0, u8::try_from(len_serial_num).unwrap()], SC_APDU_CASE_2_SHORT, &mut serial.value);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != len_serial_num {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Serial Number' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    serial.len = len_serial_num;
    card.serialnr.value = serial.value;
    card.serialnr.len   = serial.len;
    Ok(serial)
}


//QS
/// Get count of files within currently selected DF.
///
/// @apiNote  `SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF`; ATTENTION: There shouldn't be more than 255 files in a DF, but
/// if there are more, then the function panics, because the following command get_file_info
/// works based on byte-size indexing only !\
/// @return  count of files or an OpenSC error
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_count_files_curr_df(card: &mut sc_card) -> Result<u16, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_count_files_curr_df\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 1, 0], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Info: Number of files \
            under the currently selected DF' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    if apdu.sw2 > 255 {
        panic!("There are more than 255 children in this DF !");
        /*
        driver's working currently depends on populating the HashMap files with all card content during card_init, but
        that would be impossible with more than 255 children in a DF: I.e. checking for duplicates would be incomplete
        and all assertions that any file is contained in  HashMap files  would be wrong
        */
    }
    Ok(u16::try_from(apdu.sw2).unwrap())
}


//QS
/// Get compact file information (8 bytes) of file referenced within currently selected DF.\
/// The 8 bytes are: FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI
///
/// @apiNote  `SC_CARDCTL_ACOS5_GET_FILE_INFO`; for clients: for all card types indexing starts from 0. This function will
/// care for cards, that behave differently\
/// @return  file information (8 bytes) or an OpenSC error
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_file_info(card: &mut sc_card, reference: u8) -> Result<[u8; 8], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_file_info\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0; 8];
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 2, reference+ if card.type_>SC_CARD_TYPE_ACOS5_64_V3 {1} else {0}, 8],
        SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == rbuf.len() {
        Ok(rbuf)
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'File Info'-retrieval failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}


//QS
/// Get free EEPROM space in bytes.
///
/// @apiNote  SC_CARDCTL_ACOS5_GET_FREE_SPACE
/// @return  free EEPROM space or an OpenSC error
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_free_space(card: &mut sc_card) -> Result<u32, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_free_space\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0; 4];
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 4, 0, if card.type_> SC_CARD_TYPE_ACOS5_64_V3 {3} else {2}],
         SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_is_ident_self_okay(card: &mut sc_card) -> Result<bool, i32> // get_ident_self
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_is_ident_self_okay\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 5, 0], SC_APDU_CASE_1, &mut[]);
    let rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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

///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_cos_version(card: &mut sc_card) -> Result<[u8; 8], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_cos_version\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0; 8];
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 6, 0, 8], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_manufacture_date(card: &mut sc_card) -> Result<u32, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_manufacture_date\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0; 4];
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 7, 0, 4], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_rom_sha1(card: &mut sc_card) -> Result<[u8; 20], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_rom_sha1\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0; 20];
    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 8, 0, 20], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_op_mode_byte(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_op_mode_byte\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 9, 0], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_op_mode_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_op_mode_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0xFF; 1];
    let mut apdu = build_apdu(ctx, &[0, 0xB0, 0xC1, 0x91, 1], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS && apdu.resplen == 1 {
        Ok(rbuf[0]) // also called compatibility byte
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Operation Mode Byte' failed\0"));
        Err(SC_ERROR_CARD_CMD_FAILED)
    }
}

//  V2.00 *DOES NOT* supports this command
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_is_fips_compliant(card: &mut sc_card) -> Result<bool, i32> // is_FIPS_compliant==true get_fips_compliance
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_is_fips_compliant\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 10, 0], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_is_pin_authenticated(card: &mut sc_card, reference: u8) -> Result<bool, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_pin_auth_state\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 11, reference], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_is_key_authenticated(card: &mut sc_card, reference: u8) -> Result<bool, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_key_auth_state\0");
    log3ifc!(ctx,f,line!());

    let mut apdu = build_apdu(ctx, &[0x80, 0x14, 12, reference], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv == SC_SUCCESS {
        Ok(true)
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
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_zeroize_card_disable_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_zeroize_card_disable_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0xFF; 1];
    let mut apdu = build_apdu(ctx, &[0, 0xB0, 0xC1, 0x92, 1], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Zeroize Card Disable Byte' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    Ok(rbuf[0])
}

/* This is NOT a card command, but reading from EEPROM; allowed only in stage manufacturer */
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
pub fn get_card_life_cycle_byte_eeprom(card: &mut sc_card) -> Result<u8, i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"get_card_life_cycle_byte_eeprom\0");
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0xFF; 1];
    let mut apdu = build_apdu(ctx, &[0, 0xB0, 0xC1, 0x84, 1], SC_APDU_CASE_2_SHORT, &mut rbuf);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen != 1 {
        log3if!(ctx,f,line!(), cstru!(b"Error: ACOS5 'Get Card Life Cycle Byte' failed\0"));
        return Err(SC_ERROR_CARD_CMD_FAILED);
    }
    Ok(rbuf[0])
}
