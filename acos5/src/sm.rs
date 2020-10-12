/*
 * sm.rs: Driver 'acos5' - Secure Messaging file
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
Secure Messaging is handled transparently towards OpenSC, meaning, it's done when necessary, but not communicated
towards OpenSC (OpenSC wouldn't help anyway but just confuse if setting SC_AC_PRO is used)
*/

extern crate libc;
extern crate num_integer;
extern crate opensc_sys;

// libc doesn't provide snprintf for windows
#[cfg(not(windows))]
use libc::snprintf;

use libc::{free, strlen};
use num_integer::Integer;

use std::os::raw::{c_char, c_ulong};
// use std::ffi::CStr;
use std::ptr::{null, null_mut};
use std::slice::from_raw_parts;
use std::convert::TryFrom;

use opensc_sys::opensc::{sc_context, sc_card, sc_hex_to_bin, sc_transmit_apdu,
                         sc_check_sw, sc_pin_cmd_data, SC_PIN_STATE_LOGGED_IN, SC_PIN_STATE_LOGGED_OUT,
                         SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK};
use opensc_sys::types::{SC_APDU_CASE_4_SHORT};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_SM_KEYSET_NOT_FOUND, SC_ERROR_UNKNOWN_DATA_RECEIVED, SC_ERROR_INVALID_DATA,
                         SC_ERROR_SM_IFD_DATA_MISSING, SC_ERROR_SM_AUTHENTICATION_FAILED,
                         SC_ERROR_SM_NOT_INITIALIZED, SC_ERROR_SM, SC_ERROR_PIN_CODE_INCORRECT, SC_ERROR_AUTH_METHOD_BLOCKED,
                         SC_ERROR_KEYPAD_MSG_TOO_LONG};
    /*, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_NOT_SUPPORTED*/
use opensc_sys::sm::{sm_info, SM_SMALL_CHALLENGE_LEN, SM_CMD_FILE_READ, SM_CMD_FILE_UPDATE, SM_CMD_PIN};
    /*, sm_cwa_session, SM_CMD_PIN_VERIFY, SM_CMD_FILE_CREATE, SM_CMD_FILE_DELETE, SM_CMD_FILE,*/
use opensc_sys::log::{sc_dump_hex}; /*, SC_LOG_DEBUG_NORMAL, SC_LOG_DEBUG_SM*/
use opensc_sys::scconf::{scconf_block, scconf_find_blocks, scconf_get_str};

use crate::constants_types::{ACOS5_OBJECT_REF_LOCAL, ACOS5_OBJECT_REF_MAX, CARD_DRV_SHORT_NAME, DataPrivate, build_apdu,
                             p_void, SC_CARD_TYPE_ACOS5_EVO_V4};
use crate::crypto::{DES_KEY_SZ, DES_KEY_SZ_u8, des_ecb3_unpadded_8, des_ede3_cbc_pad_80_mac, des_ede3_cbc_pad_80, Encrypt, Decrypt};
use crate::no_cdecl::{authenticate_external, authenticate_internal};
use crate::wrappers::{wr_do_log, wr_do_log_rv, wr_do_log_sds, wr_do_log_t, wr_do_log_tttt, wr_do_log_tu, wr_do_log_tuv,
                      wr_do_log_tuvw};


#[allow(clippy::cast_possible_truncation)]
#[allow(non_upper_case_globals)]
pub const SM_SMALL_CHALLENGE_LEN_u8 : u8 = SM_SMALL_CHALLENGE_LEN as u8;

/*
TODO There is a lot of code duplication here: Abstract as much as possible for the 4 APDU cases, but first test
  thoroughly that all is working as expected
*/

/*
/*
 * @struct sm_module_operations
 *    API to use external SM modules:
 *    - 'initialize' - get APDU(s) to initialize SM session;                                 // mandatory function
 *    - 'get apdus' - get secured APDUs to execute particular command;
 *    - 'finalize' - get APDU(s) to finalize SM session;
 *    - 'module init' - initialize external module (allocate data, read configuration, ...);
 *    - 'module cleanup' - free resources allocated by external module.
 */

// mandatory func
/**
 * Initialize
 *
 * Read keyset from the OpenSC configuration file,
 * get and return the APDU(s) to initialize SM session.
 */
#[no_mangle]
pub extern "C" fn initialize(_ctx: *mut sc_context, _sm_info: *mut sm_info, _rdata: *mut sc_remote_data) -> i32
{
    SC_SUCCESS
}

// mandatory func
#[no_mangle]
pub extern "C" fn get_apdus(_ctx: *mut sc_context, _sm_info: *mut sm_info, _init_data: *mut u8,
                            _init_len: usize, _rdata: *mut sc_remote_data) -> i32
{
    SC_SUCCESS
}


/*
// non-mandatory func
#[no_mangle]
pub extern "C" fn finalize(_ctx: *mut sc_context, _sm_info: *mut sm_info, _rdata: *mut sc_remote_data,
                           _out: *mut u8, _out_len: usize) -> i32
{
    SC_SUCCESS
}
*/

/*
// non-mandatory func
#[no_mangle]
pub extern "C" fn module_init(ctx_ptr: *mut sc_context, data_ptr: *const c_char) -> i32
{
    if ctx_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let ctx = unsafe { &mut *ctx_ptr };
    let f = cstru!(b"SM module: module_init\0");
    log3if!(ctx,f,line!(), cstru!(b"called with data_ptr: %p\0"), data_ptr);
    for elem in ctx.card_drivers.iter_mut() {
        if (*elem).is_null() { break; }
        unsafe {
            let drv = &mut *(*elem);
            if !drv.short_name.is_null() {
                println!("Driver supported: {:?}", CStr::from_ptr(drv.short_name));
            }
            if CStr::from_ptr(drv.short_name) == cstru!(b"acos5_64\0") &&
                !ctx.forced_driver.is_null() {
//                unsafe { ctx.forced_driver = acos5_64_get_card_driver(); }
                let mut drv2  = &mut *ctx.forced_driver;
                (*drv2.ops).read_binary = Some(acos5_64_read_binary);
                println!("Driver supported: {:?}", CStr::from_ptr(drv.short_name));
                break;
            }
        }
    }
    SC_SUCCESS
}
*/

/*
// non-mandatory func
#[no_mangle]
pub extern "C" fn module_cleanup(_ctx: *mut sc_context) -> i32
{
    SC_SUCCESS
}
*/


/* This is an optional function, yet if it's not exported, the sanity_check will treat SM as unavailable, no matter what */
// non-mandatory func
#[allow(dead_code)]
//#[no_mangle] pub extern "C"
fn test(_ctx: *mut sc_context, _sm_info: *mut sm_info, out: *mut c_char) -> i32
{
    unsafe { *out = 66u8 as c_char };
    SC_SUCCESS
}
*/

fn get_ck_enc_card(card: &sc_card) -> [u8; 3*DES_KEY_SZ] { // get_cwa_keyset_enc_card
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.cwa_keyset.enc });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.icc.k[..DES_KEY_SZ] });
    result
}

fn get_ck_mac_host(card: &sc_card) -> [u8; 3*DES_KEY_SZ] { // get_cwa_keyset_mac_host
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.cwa_keyset.mac });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.ifd.k[..DES_KEY_SZ] });
    result
}
//
fn get_cs_enc(card: &sc_card/*cwa: &sm_cwa_session*/) -> [u8; 3*DES_KEY_SZ] { // get_cwa_session_enc
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.session_enc });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.icc.k[DES_KEY_SZ..2*DES_KEY_SZ] });
    result
}

fn get_cs_mac(card: &sc_card/*cwa: &sm_cwa_session*/) -> [u8; 3*DES_KEY_SZ] { // get_cwa_session_mac
    let mut result = [0; 3*DES_KEY_SZ];
    result[..2*DES_KEY_SZ].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.session_mac });
    result[2*DES_KEY_SZ..].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.ifd.k[DES_KEY_SZ..2*DES_KEY_SZ] });
    result
}

fn sm_incr_ssc(card: &mut sc_card) {
    let ssc = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mut x = u16::from_be_bytes([ssc[6], ssc[7]]);
    x = x.wrapping_add(1);
    unsafe { card.sm_ctx.info.session.cwa.ssc[6..8].copy_from_slice(&x.to_be_bytes()) };
}


#[cfg(not(windows))]
fn sm_cwa_config_get_keyset(ctx: &mut sc_context, sm_info: &mut sm_info) -> i32
{
    let cwa_session = unsafe { &mut sm_info.session.cwa };
    let cwa_keyset = &mut cwa_session.cwa_keyset;
    let mut sm_conf_block = null_mut::<scconf_block>();
    let crt_at = &cwa_session.params.crt_at;

    let mut name : [c_char; 128] = [0; 128];
    let mut hex  : [u8; 48]      = [0; 48];
    let mut hex_len;
    let mut rv : i32;
    let ref_ = i32::from(u8::try_from(crt_at.refs[0]).unwrap() & ACOS5_OBJECT_REF_MAX);

    let f  = cstru!(b"sm_cwa_config_get_keyset\0");

    /* look for sc block in opensc.conf */
    for elem in &ctx.conf_blocks {
        if (*elem).is_null() { break; }
        let blocks_ptr = unsafe { scconf_find_blocks(ctx.conf, *elem,
            cstru!(/*b"secure_messaging\0"*/ b"card_driver\0").as_ptr(),
        /*sm_info.config_section.as_ptr()*/ cstru!(CARD_DRV_SHORT_NAME).as_ptr()) };
        if blocks_ptr.is_null() { continue; }
        sm_conf_block = unsafe { *blocks_ptr }; // blocks[0];

        unsafe { free(blocks_ptr as p_void) };
        if !sm_conf_block.is_null() { break; }
    }

    /*
        for (ii = 0; ctx->conf_blocks[ii]; ii++) {
            blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm_info->config_section);
            if (blocks) {
                sm_conf_block = blocks[0];
                free(blocks);
            }

            if (sm_conf_block)
                break;
        }
    */
    log3if!(ctx,f,line!(), cstru!(b"CRT(algo:%X,ref:%X)\0"), crt_at.algo, crt_at.refs[0]);


    /* Keyset ENC */
    if sm_info.current_aid.len>0 && (u8::try_from(crt_at.refs[0]).unwrap() & ACOS5_OBJECT_REF_LOCAL) >0 {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), cstru!(b"keyset_%s_%02i_enc\0").as_ptr(),
                          sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
    }
    else {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), cstru!(b"keyset_%02i_enc\0").as_ptr(), ref_) };
    }
    let mut value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), null::<c_char>()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        log3if!(ctx,f,line!(), cstru!(b"No %s value in OpenSC config\0"), name.as_ptr());
        return SC_ERROR_SM_KEYSET_NOT_FOUND;
    }

////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "keyset::enc(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value), value);
    log3if!(ctx,f,line!(), cstru!(b"keyset::enc(%zu) %s\0"), unsafe { strlen(value) }, value);
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        cwa_keyset.enc.copy_from_slice(unsafe { from_raw_parts(value as *const u8, 2*DES_KEY_SZ) });
        cwa_session.icc.k[..DES_KEY_SZ].copy_from_slice(unsafe { from_raw_parts(
            value.add(2*DES_KEY_SZ) as *const u8, DES_KEY_SZ) });
    }
    else {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
        if rv != SC_SUCCESS {
////sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get %s: hex to bin failed for '%s'; error %i", name, value, rv);
            log3if!(ctx,f,line!(), cstru!(b"SM get %s: hextobin failed for '%s'; error %i\0"), name.as_ptr(),value,rv);
            return SC_ERROR_UNKNOWN_DATA_RECEIVED;
        }

////sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ENC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len, sc_dump_hex(hex, hex_len));
        log3if!(ctx,f,line!(), cstru!(b"ENC(%zu) %s\0"), hex_len, unsafe {sc_dump_hex(hex.as_ptr(), hex_len)});
        if hex_len != 3*DES_KEY_SZ {
            return SC_ERROR_INVALID_DATA;
        }
        cwa_keyset.enc.copy_from_slice(&hex[..2*DES_KEY_SZ]);
        cwa_session.icc.k[..DES_KEY_SZ].copy_from_slice(&hex[2*DES_KEY_SZ..3*DES_KEY_SZ]);
    }
////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "%s %s", name, sc_dump_hex(cwa_keyset->enc, 3*DES_KEY_SZ));
    log3if!(ctx,f,line!(), cstru!(b"%s %s\0"),name.as_ptr(),unsafe{sc_dump_hex(cwa_keyset.enc.as_ptr(), 2*DES_KEY_SZ)});

    /* Keyset MAC */
    if sm_info.current_aid.len>0 && (u8::try_from(crt_at.refs[0]).unwrap() & ACOS5_OBJECT_REF_LOCAL) >0 {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), cstru!(b"keyset_%s_%02i_mac\0").as_ptr(),
                          sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
    }
    else {
//                snprintf(name, sizeof(name), "keyset_%02i_mac", ref);
        unsafe { snprintf(name.as_mut_ptr(), name.len(), cstru!(b"keyset_%02i_mac\0").as_ptr(), ref_) };
    }
    value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), null::<c_char>()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        log3if!(ctx,f,line!(), cstru!(b"No %s value in OpenSC config\0"), name.as_ptr());
        return SC_ERROR_SM_KEYSET_NOT_FOUND;
    }

////sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "keyset::mac(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value), value);
    log3if!(ctx,f,line!(), cstru!(b"keyset::mac(%zu) %s\0"), unsafe { strlen(value) }, value);
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        cwa_keyset.mac.copy_from_slice(unsafe { from_raw_parts(value as *const u8, 2*DES_KEY_SZ) });
        cwa_session.ifd.k[..DES_KEY_SZ].copy_from_slice(unsafe {
            from_raw_parts(value.add(2*DES_KEY_SZ) as *const u8, DES_KEY_SZ) });
    }
    else   {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
        if rv != SC_SUCCESS {
////sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get '%s': hex to bin failed for '%s'; error %i", name, value, rv);
            log3if!(ctx,f,line!(), cstru!(b"SM get %s: hextobin failed for '%s'; error %i\0"),name.as_ptr(), value, rv);
            return SC_ERROR_UNKNOWN_DATA_RECEIVED;
        }

////sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "MAC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len, sc_dump_hex(hex, hex_len));
        log3if!(ctx,f,line!(), cstru!(b"MAC(%zu) %s\0"), hex_len, unsafe {sc_dump_hex(hex.as_ptr(), hex_len)});
        if hex_len != 3*DES_KEY_SZ {
            return SC_ERROR_INVALID_DATA;
        }

        cwa_keyset.mac.copy_from_slice(&hex[..2*DES_KEY_SZ]);
        cwa_session.ifd.k[..DES_KEY_SZ].copy_from_slice(&hex[2*DES_KEY_SZ..3*DES_KEY_SZ]);
    }
//sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "%s %s", name, sc_dump_hex(cwa_keyset->mac, 2*DES_KEY_SZ));
    log3if!(ctx,f,line!(), cstru!(b"%s %s\0"),name.as_ptr(), unsafe{sc_dump_hex(cwa_keyset.mac.as_ptr(),2*DES_KEY_SZ)});

    cwa_keyset.sdo_reference = crt_at.refs[0];


    /* IFD parameters */
    //memset(cwa_session, 0, sizeof(struct sm_cwa_session));
//            value = scconf_get_str(sm_conf_block, "ifd_serial", NULL);
    value = unsafe { scconf_get_str(sm_conf_block, cstru!(b"ifd_serial\0").as_ptr(), null::<c_char>()) };
    if value.is_null() {
        return SC_ERROR_SM_IFD_DATA_MISSING;
    }
    hex_len = hex.len();
    rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
    if rv != SC_SUCCESS   {
//sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
        log3if!(ctx,f,line!(), cstru!(b"SM get 'ifd_serial': hex to bin failed for '%s'; error %i\0"), value, rv);
        return SC_ERROR_UNKNOWN_DATA_RECEIVED;
    }

    if hex_len != cwa_session.ifd.sn.len() {
//                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
//                        "SM get 'ifd_serial': invalid IFD serial length: %"SC_FORMAT_LEN_SIZE_T"u",
//                        hex_len);
        log3if!(ctx,f,line!(), cstru!(b"SM get 'ifd_serial': invalid IFD serial length: %zu\0"), hex_len);
        return SC_ERROR_UNKNOWN_DATA_RECEIVED;
    }

//            memcpy(cwa_session->ifd.sn, hex, hex_len);
    /*
                rv = RAND_bytes(cwa_session->ifd.rnd, DES_KEY_SZ_u8 as i32);
                if (!rv)   {
                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
                    return SC_ERROR_SM_RAND_FAILED;
                }
    */
    /*
                rv = RAND_bytes(cwa_session->ifd.k, 32);
                if (!rv)   {
                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "Generate random error: %i", rv);
                    return SC_ERROR_SM_RAND_FAILED;
                }
    */
    /*
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.Serial: %s", sc_dump_hex(cwa_session->ifd.sn, sizeof(cwa_session->ifd.sn)));
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.Rnd: %s", sc_dump_hex(cwa_session->ifd.rnd, sizeof(cwa_session->ifd.rnd)));
sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "IFD.K: %s", sc_dump_hex(cwa_session->ifd.k, sizeof(cwa_session->ifd.k)));
    */
    SC_SUCCESS
}

fn sm_cwa_initialize(card: &mut sc_card/*, sm_info: &mut sm_info, _rdata: &mut sc_remote_data*/) -> i32
{
    /*
    ck_mac_host: [F1, E0, D0, C1, B0, A1, 89, 8, 7, 16, 45, 4, 13, 2, 1, F1, 89, FE, B3, C8, 37, 45, 16, 94] corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    ck_enc_card: [F1, 1, 2, 13, 4, 85, 16, 7, 8, 49, A1, B0, C1, D0, E0, F1, 45, 89, B3, 16, FE, 94, 37, C8] corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc

    keyset_41434F53504B43532D313576312E3030_02_mac = "F1:E0:D0:C1:B0:A1:89:08:07:16:45:04:13:02:01:F1:89:FE:B3:C8:37:45:16:94"; # corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    keyset_41434F53504B43532D313576312E3030_02_enc = "F1:01:02:13:04:85:16:07:08:49:A1:B0:C1:D0:E0:F1:45:89:B3:16:FE:94:37:C8"; # corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc
    */
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"sm_cwa_initialize\0");
    log3ifc!(ctx,f,line!());
    /* Mutual Authentication Procedure with 2 different keys, (key card) kc and (key terminal/host) kh */
/*
    /* External Authentication */
    let mut rv = unsafe {
        sc_get_challenge(card, card.sm_ctx.info.session.cwa.card_challenge.as_mut_ptr(), SM_SMALL_CHALLENGE_LEN) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
    unsafe { card.sm_ctx.info.session.cwa.ssc = card.sm_ctx.info.session.cwa.card_challenge };
    let re = des_ecb3_unpadded_8(unsafe { &card.sm_ctx.info.session.cwa.card_challenge }, &get_ck_mac_host(card),
                                 Encrypt);

    let mut cmd_ext = [0, 0x82, 0, 0x81 /*(key terminal/host) kh*/, SM_SMALL_CHALLENGE_LEN_u8, 0, 0, 0, 0, 0, 0, 0, 0];
    cmd_ext[5..5 + SM_SMALL_CHALLENGE_LEN].copy_from_slice(&re);
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(ctx, &cmd_ext, &mut apdu);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(SC_APDU_CASE_3_SHORT, apdu.cse);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
*/
    match authenticate_external(card, 0x81, &get_ck_mac_host(card)) {
        Ok(val) => if !val { return SC_ERROR_SM_AUTHENTICATION_FAILED; },
        Err(_e) => { return SC_ERROR_SM_AUTHENTICATION_FAILED; },
    }
    unsafe { card.sm_ctx.info.session.cwa.ssc = card.sm_ctx.info.session.cwa.card_challenge };
    /*
        /* Internal Authentication */
        let mut rv = unsafe {
            RAND_bytes(card.sm_ctx.info.session.cwa.host_challenge.as_mut_ptr(), i32::from(SM_SMALL_CHALLENGE_LEN_u8)) };
        if rv != 1 {
            rv = SC_ERROR_SM_RAND_FAILED;
            log3ifr!(ctx,f,line!(), rv);
            return rv;
        }
        let mut cmd_int = [0, 0x88, 0, 0x82 /*(key card) kc*/,
            SM_SMALL_CHALLENGE_LEN_u8, 0, 0, 0, 0, 0, 0, 0, 0, SM_SMALL_CHALLENGE_LEN_u8];
        cmd_int[5..5 + SM_SMALL_CHALLENGE_LEN].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.host_challenge });
        let mut apdu = sc_apdu::default();
        rv = sc_bytes2apdu_wrapper(ctx, &cmd_int, &mut apdu);
        assert_eq!(SC_SUCCESS, rv);
        debug_assert_eq!(SC_APDU_CASE_4_SHORT, apdu.cse);
        debug_assert_eq!(SM_SMALL_CHALLENGE_LEN, apdu.le);
        let mut challenge_encrypted_by_card = [0; SM_SMALL_CHALLENGE_LEN];
        apdu.resplen = SM_SMALL_CHALLENGE_LEN;
        apdu.resp = challenge_encrypted_by_card.as_mut_ptr();

        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if rv != SC_SUCCESS {
            log3ifr!(ctx,f,line!(), rv);
            return rv;
        }

        let challenge_encrypted_by_host = des_ecb3_unpadded_8(unsafe { &card.sm_ctx.info.session.cwa.host_challenge },
                                &get_ck_enc_card(card), Encrypt);
        if  challenge_encrypted_by_host != challenge_encrypted_by_card.to_vec() {
            return SC_ERROR_SM_AUTHENTICATION_FAILED;
        }
    */
    match authenticate_internal(card, 0x82, &get_ck_enc_card(card)) {
        Ok(val) => if !val { return SC_ERROR_SM_AUTHENTICATION_FAILED; },
        Err(_e) => { return SC_ERROR_SM_AUTHENTICATION_FAILED; },
    }
    /* session key(s) generation. acos5 does it internally automatically and we must do the same here */
    /* EVO: allows TDES and AES; for TDES the ref. manual is inconsistent: 32 byte deriv data for a max 24 byte session key ? */
    /* TODO : for EVO, switch to AES/256 */
    let mut deriv_data = Vec::with_capacity(3 * DES_KEY_SZ);
    unsafe {
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[4..8]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[0..4]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[0..4]);
        deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[4..8]);
        if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[0..4]);
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[4..8]);
        }
        else {
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.host_challenge[0..4]);
            deriv_data.extend_from_slice(&card.sm_ctx.info.session.cwa.card_challenge[4..8]);
        }
        card.sm_ctx.info.session.cwa.card_challenge.copy_from_slice(&[0; 8]);
        card.sm_ctx.info.session.cwa.host_challenge.copy_from_slice(&[0; 8]);
    }
//        writefln("deriv_data_plain:     0x [ %(%x %) ]", deriv_data);

    let sess_enc_buf = des_ecb3_unpadded_8(&deriv_data, &get_ck_enc_card(card), Encrypt);
    let sess_mac_buf = des_ecb3_unpadded_8(&deriv_data, &get_ck_mac_host(card), Encrypt);
    assert_eq!(3 * DES_KEY_SZ, sess_enc_buf.len());
    assert_eq!(3 * DES_KEY_SZ, sess_mac_buf.len());
    unsafe {
        card.sm_ctx.info.session.cwa.session_enc.copy_from_slice(&sess_enc_buf[..2*DES_KEY_SZ]);
        card.sm_ctx.info.session.cwa.icc.k[DES_KEY_SZ..2*DES_KEY_SZ].copy_from_slice(&sess_enc_buf[2*DES_KEY_SZ..]);
        card.sm_ctx.info.session.cwa.session_mac.copy_from_slice(&sess_mac_buf[..2*DES_KEY_SZ]);
        card.sm_ctx.info.session.cwa.ifd.k[DES_KEY_SZ..2*DES_KEY_SZ].copy_from_slice(&sess_mac_buf[2*DES_KEY_SZ..]);
    }
//println!("is_key_authenticated(card, 0x81): {}", get_is_key_authenticated(card, 0x81).unwrap()); // : true
//println!("is_key_authenticated(card, 0x82): {}", get_is_key_authenticated(card, 0x82).unwrap()); // : false
    SC_SUCCESS
}

fn sm_dur(cmd: u32) -> u128
{
    match cmd {
        SM_CMD_FILE_READ | SM_CMD_FILE_UPDATE => 300,
        SM_CMD_PIN  => 200,
        _           => 150,
    }
}

fn sm_manage_keyset(card: &mut sc_card) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"sm_manage_keyset\0");
    log3ifc!(ctx,f,line!());
    if unsafe { card.sm_ctx.info.session.cwa.session_mac.ne(&[0; 16]) } {
        SC_SUCCESS
    }
    else {
        log3if!(ctx,f,line!(), cstru!(b"Current AID: %s\0"),
            unsafe { sc_dump_hex(card.sm_ctx.info.current_aid.value.as_ptr(), card.sm_ctx.info.current_aid.len) });

//        case SM_TYPE_CWA14890:
        let rv;
        #[cfg(not(windows))]
        { rv = sm_cwa_config_get_keyset(ctx, &mut card.sm_ctx.info); }
        #[cfg(    windows)]
        { rv = SC_ERROR_SM; }
        if rv < SC_SUCCESS {
            log3ifr!(ctx,f,line!(), cstru!(b"SM acos5 configuration error\0"), rv);
        }
        rv
    }
}

/*
try to pass repetitive commands through the same SM session, but open a new session for new commands.
Also, some commands like verify always get a new session
repetitive commands: e.g. read_binary with large count will be chunk'ed to max. 240 bytes : same session

*: an SM command x or y is requested
timeline:                   *x                *x                *y                *x                *
         <- unknown cmd ? -> <- curr cmd: x -> <- curr cmd: x -> <- curr cmd: y -> <- curr cmd: x ->
                             <- last cmd: ? -> <- last cmd: x -> <- last cmd: x -> <- last cmd: y -> <- last cmd: x ->
                            =new_session      =dep on timing    =new_session      =new_session
*/
fn sm_manage_initialize(card: &mut sc_card) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"sm_manage_initialize\0");
    log3ifc!(ctx,f,line!());

    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let last_sm_cmd = dp.sm_cmd;
    dp.sm_cmd = card.sm_ctx.info.cmd;
    let last_time_stamp = dp.time_stamp;
    dp.time_stamp = std::time::Instant::now();
    card.drv_data = Box::into_raw(dp) as p_void;

//println!("elapsed ms: {}, last_sm_cmd: {:X}, this_sm_cmd: {:X}", last_time_stamp.elapsed().as_millis(), last_sm_cmd, card.sm_ctx.info.cmd);
    if  last_sm_cmd==0 || last_sm_cmd!=card.sm_ctx.info.cmd ||
        last_time_stamp.elapsed().as_millis() > sm_dur(last_sm_cmd) ||
        ![SM_CMD_FILE_READ, SM_CMD_FILE_UPDATE].contains(&card.sm_ctx.info.cmd)
    {
        let rv = sm_cwa_initialize(card/*, sm_info, rdata*/);
        if rv != SC_SUCCESS {
            log3if!(ctx,f,line!(),cstru!(b"Error: #################### SM initializing failed ####################\0"));
        }

        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        dp.time_stamp = std::time::Instant::now();
        card.drv_data = Box::into_raw(dp) as p_void;
        rv
    }
    else {
        SC_SUCCESS
    }
}

/* Naming
hdr:     bytes for mac_cmd/mac_resp generation, starting with 0x89, 0x04, cla, ins, p1, p2 and possibly more bytes; encapsulates the variability of cla, ins
hdr_vec: bytes for mac_cmd/mac_resp generation, if assembling bytes is more complex than just using fixed hdr

data: either plain or encrypted; input, the command data to be used in cmd/cmd_vec and mac_cmd
data_encrypted

resp: either plain or encrypted, output, command's response data to be used for Decrypting them first if applicable and mac_resp
resp_decrypted

cmd:     bytes for the APDU
cmd_vec: bytes for the APDU, if assembling bytes is more complex than just using fixed cmd

mac_cmd:
mac_resp:

*/

// TODO all code below assumes block_size is 8, i.e. using exclusively TDES for SM, which is not true anymore for ACOS5-EVO

//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_2_SHORT: no command data, but expects response data (with SM, there are command data: the tagged le)
pub fn sm_common_read(card: &mut sc_card,
                      idx: u16,
                      buf: &mut [u8],
//                      count: usize,
                      flags: c_ulong,
                      bin: bool,
                      has_ct: bool,
                      fdb: u8) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( if bin {b"sm_read_binary\0"} else {b"sm_read_record\0"});
    log3if!(ctx,f,line!(), cstru!(b"called with flags %zu\0"), flags);

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

    /* sc_read_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes,
       i.e. count<=255; it's okay to read less*/
//println!("sm_common_read          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_common_update        get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_erase_binary         get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_delete_file          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_create               get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd  verify      get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd_get_policy   get_cs_enc:  {:X?}\n", get_cs_enc(card));

//println!("sm_common_read          get_cs_mac:  {:X?}\n", get_cs_mac(card));
    assert!(buf.len()<256);
    let count = std::cmp::min(buf.len(), 255);
    let len_read = std::cmp::min(if has_ct {239_u8} else {240_u8},u8::try_from(count).unwrap());
////println!("len_read : {}", len_read);
    let len_read2 : u8 = len_read.next_multiple_of(&DES_KEY_SZ_u8);// padding added if required
////println!("len_read2: {}", len_read2);
    debug_assert!(len_read2.is_multiple_of(&DES_KEY_SZ_u8));
    assert!(len_read2 <= 240);
    let pos : usize = if has_ct {13} else {12};
    let len_resp = u8::try_from(pos).unwrap() +
        if has_ct { len_read2 + if len_read.is_multiple_of(&DES_KEY_SZ_u8) {DES_KEY_SZ_u8} else {0} } else { len_read };
////println!("len_resp: {}", len_resp);
    /* cmd without SM: SC_APDU_CASE_2_SHORT; with SM: SC_APDU_CASE_4_SHORT */
/*
    let hdr;
    if bin {
        hdr = [0x89u8,4, if fdb!=9 {0x0C} else {0x8C},
                         if fdb!=9 {0xB0} else {0xCA}, idx_arr[0],idx_arr[1],  0x97,1,len_read];
    }
    else {
        assert!(idx<32);
        hdr = [0x89u8,4, 0x0C, 0xB2, idx as u8,4,  0x97,1,len_read]; // there is no separate command for read sym. key record
    }
*/
    let hdr =
        if bin {
            let idx_arr : [u8; 2] = idx.to_be_bytes();
            [0x89_u8,4, if fdb!=9 {0x0C}else{0x8C}, if fdb!=9 {0xB0}else{0xCA}, idx_arr[0],idx_arr[1], 0x97,1,len_read]
        }
        else {
            assert!(idx<32);
            [0x89_u8,4, 0x0C, 0xB2, u8::try_from(idx).unwrap(),4,  0x97,1,len_read]
        };

////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 9,  hdr[6],hdr[7],hdr[8],
        0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], len_resp /*>0, otherwise arbitrary*/];
    let mut rbuf = vec![0_u8; usize::from(len_resp)];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());

    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f, line!(), rv);
        return rv;
    }

    /* verify mac_resp */
    let mut mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    if has_ct { mac_resp_in.extend_from_slice(&[0x87_u8, len_resp -u8::try_from(pos-1).unwrap(), rbuf[pos-1]]); }
    else      { mac_resp_in.extend_from_slice(&[0x81_u8, len_read]); }
    mac_resp_in.extend_from_slice(&rbuf[pos..]);

    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }

    if has_ct {
        ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
        let resp_decrypted = des_ede3_cbc_pad_80(&rbuf[pos..pos+usize::from(len_read2)],
                                          &get_cs_enc(card), &mut ivec, Decrypt, rbuf[pos-1]);
        assert_eq!(usize::from(len_read), resp_decrypted.len());
        assert!(resp_decrypted.len() <= count);
        buf[..usize::from(len_read)].copy_from_slice(&resp_decrypted);
    }
    else {
        buf[..usize::from(len_read)].copy_from_slice(&rbuf[pos..pos+usize::from(len_read)]);
    }

    rv = i32::from(len_read);
    log3ifr!(ctx,f,line!(), rv);
    rv
}


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_3_SHORT: yes command data, but doesn't expect response data (with SM, there are response data)
pub fn sm_common_update(card: &mut sc_card,
                        idx: u16,
                        buf: &[u8],
//                        count: usize,
                        flags: c_ulong,
                        bin: bool,
                        has_ct: bool,
                        _fdb: u8) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( if bin {b"sm_update_binary\0"} else {b"sm_update_record\0"});
    log3if!(ctx,f,line!(), cstru!(b"called with flags %zu\0"), flags);

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

    /* sc_update_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes, i.e. count<=255; it's okay to update less*/
//println!("sm_common_update        get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_common_update        get_cs_mac:  {:X?}\n", get_cs_mac(card));
    assert!(buf.len()<256);
    let count = std::cmp::min(buf.len(), 255);
    let len_update = std::cmp::min(if has_ct {232_u8} else {240_u8/*checked*/},u8::try_from(count).unwrap());
////println!("len_update : {}", len_update);
    let len_update2 = len_update.next_multiple_of(&DES_KEY_SZ_u8); // padding added if required
////println!("len_update2: {}", len_update2);
    debug_assert!(len_update2.is_multiple_of(&DES_KEY_SZ_u8));
    assert!(len_update2 <= 240);
    let pi = if has_ct && !len_update.is_multiple_of(&DES_KEY_SZ_u8) {1_u8} else {0_u8};
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr =
        if bin {
            let idx_arr : [u8; 2] = idx.to_be_bytes();
            [0x89_u8,4, 0x0C, // if fdb!=9 {0x0C} else {0x0C/ *0x8C* /}
                        0xD6, // if fdb!=9 {0xD6} else {0xD6/ *0xDA* /}
                idx_arr[0], idx_arr[1] ]
        }
        else {
            assert!(idx<32);
            [0x89_u8,4, 0x0C, if idx==0 && flags==0 {0xE2} else {0xDC},
                u8::try_from(idx).unwrap(),        if idx==0 && flags==0 {0}    else {4} ]
        };

////println!("sm_common_update ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
////println!("sm_common_update ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let data_encrypted = des_ede3_cbc_pad_80(&buf[..usize::from(len_update)],
          &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len_update2));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len_update2));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_update2, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_update] );
        hdr_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len_update2) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_update2, 0x87, 1 +len_update2, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_update,  0x81,    len_update] );
        cmd_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = vec![0_u8; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());

    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    rv = i32::from(len_update);
    log3ifr!(ctx,f,line!(), rv);
    rv
} // sm_common_update


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_3_SHORT:
// no command data, but expects response data (with SM, there are command data: the tagged le)
pub fn sm_erase_binary(card: &mut sc_card, idx: u16, count: u16, flags: c_ulong, has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( b"sm_erase_binary\0");
    log3if!(ctx,f,line!(), cstru!(b"called with flags %zu\0"), flags);

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

//println!("sm_erase_binary         get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_erase_binary         get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_2_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let idx_arr : [u8; 2] = idx.to_be_bytes();
    let hdr = [0x89_u8,4, 0x0C, 0x0E, idx_arr[0],idx_arr[1] /*,  0x97,1,len_read*/];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let data_encrypted = des_ede3_cbc_pad_80(&(idx + count).to_be_bytes(),
        &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(DES_KEY_SZ, data_encrypted.len());

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 11);
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 9, 1] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    2] );
        hdr_vec.extend_from_slice(& (idx + count).to_be_bytes() );
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +8 +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(&[17, 0x87, 9, 1]);
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(&[10, 0x81, 2]);
        cmd_vec.extend_from_slice(& (idx + count).to_be_bytes() );
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac_cmd[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    debug_assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    /* verify mac_resp */
    let /*mut*/ mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    rv = i32::from(count);
    log3ifr!(ctx,f,line!(), rv);
    rv
} // sm_erase_binary


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_1 or SC_APDU_CASE_3_SHORT:
// Doesn't expect response data (with SM, )
pub fn sm_delete_file(card: &mut sc_card) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( b"sm_delete_file\0");
    log3ifc!(ctx,f,line!());

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }
//println!("sm_delete_file          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_delete_file          get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0xE4, 0,0];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    debug_assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    log3ifr!(ctx,f,line!(), rv);
    rv
} // sm_delete_file


//TODO this doesn't work for SM Confidentiality (has_ct==true)
pub fn sm_create_file(card: &mut sc_card,
                        buf: &[u8], // starting with 0x62
                        has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( b"sm_create_file\0");
    log3ifc!(ctx,f,line!());

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

//println!("sm_create_file          get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_create_file          get_cs_mac:  {:X?}\n", get_cs_mac(card));
//    let count = std::cmp::min(buf.len(), 255);
    let len_update = std::cmp::min(if has_ct {232_u8} else {240_u8},u8::try_from(buf.len()).unwrap());
    assert!(buf.len()<= usize::from(len_update));
////println!("len_update : {}", len_update);
    let len_update2 = len_update.next_multiple_of(&DES_KEY_SZ_u8); // padding added if required
////println!("len_update2: {}", len_update2);
    debug_assert!(len_update2.is_multiple_of(&DES_KEY_SZ_u8));
    assert!(len_update2 <= 240);
    let pi = if has_ct && !len_update.is_multiple_of(&DES_KEY_SZ_u8) {1_u8} else {0_u8};
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0xE0, 0, 0];
//println!("sm_common_update ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
//println!("sm_common_update ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let data_encrypted = des_ede3_cbc_pad_80(&buf[..usize::from(len_update)],
       &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len_update2));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len_update2));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_update2, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_update] );
        hdr_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len_update2) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_update2, 0x87, 1 +len_update2, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_update,  0x81,    len_update] );
        cmd_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(card);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                            &get_cs_mac(card), &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    log3if!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
//    rv = i32::from(len_update);
    log3ifr!(ctx,f,line!(), rv);
    rv
} // sm_create_file


pub fn sm_pin_cmd(card: &mut sc_card,
                  pin_cmd_data: &mut sc_pin_cmd_data,
                  tries_left: &mut i32,
                  has_ct: bool) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"sm_pin_cmd\0");
    log3if!(ctx,f,line!(), cstru!(b"called for cmd: %u\0"), pin_cmd_data.cmd);

    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

//println!("sm_pin_cmd  verify      get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd  verify      get_cs_mac:  {:X?}\n", get_cs_mac(card));
    let ins : u8 = match pin_cmd_data.cmd {
        SC_PIN_CMD_VERIFY  => 0x20,
        SC_PIN_CMD_CHANGE  => 0x24,
        SC_PIN_CMD_UNBLOCK => 0x2C,
        _ => panic!("unexpected pin command"),
    };
    let mut pin_data : Vec<u8> = Vec::with_capacity(16);
    pin_data.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin1.data,
                                                       usize::try_from(pin_cmd_data.pin1.len).unwrap()) });
    let mut len_pin = u8::try_from(pin_cmd_data.pin1.len).unwrap();
    if ins == 0x24 || ins == 0x2C {
        len_pin *= 2;
        pin_data.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin2.data,
                                                           usize::try_from(pin_cmd_data.pin2.len).unwrap()) });
    }
////println!("len_pin : {}", len_pin);
    let len2_pin : u8 = len_pin.next_multiple_of(&DES_KEY_SZ_u8); // padding added if required
////println!("len2_pin: {}", len2_pin);
    debug_assert!(len2_pin.is_multiple_of(&DES_KEY_SZ_u8));
//    assert!(len2_pin <= DES_KEY_SZ_u8);
    let pi = if has_ct && !len_pin.is_multiple_of(&DES_KEY_SZ_u8) {1_u8} else {0_u8};
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, ins, 0, u8::try_from(pin_cmd_data.pin_reference).unwrap()];
////println!("sm_pin_cmd ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
////println!("sm_pin_cmd ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let data_encrypted = des_ede3_cbc_pad_80(&pin_data, &get_cs_enc(card), &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), usize::from(len2_pin));

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ usize::from(len2_pin));
    hdr_vec.extend_from_slice(&hdr);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len2_pin, pi] );
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_pin] );
        hdr_vec.extend_from_slice(&pin_data);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec, &get_cs_mac(card), &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +usize::from(len2_pin) +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len2_pin, 0x87, 1 +len2_pin, pi] );
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_pin,  0x81,    len_pin] );
        cmd_vec.extend_from_slice(&pin_data);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4]);
    cmd_vec.extend_from_slice(&mac[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd_vec, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }
    let mut cmd_failure = false;
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        cmd_failure = true;
        pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
        if      rv==SC_ERROR_PIN_CODE_INCORRECT  { pin_cmd_data.pin1.tries_left = i32::from(rbuf[3]&0x0F);
                                                   *tries_left = pin_cmd_data.pin1.tries_left; }
        else if rv==SC_ERROR_AUTH_METHOD_BLOCKED { pin_cmd_data.pin1.tries_left = 0;
                                                   *tries_left = pin_cmd_data.pin1.tries_left; }
//        log3ifr!(ctx,f,line!(), rv);
//        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, rbuf[2], rbuf[3]];
    sm_incr_ssc(card);
    ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
////println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if cmd_failure || rbuf[2]!=0x90 || rbuf[3]!=0 { log3ifr!(ctx,f,line!(), rv); return rv; }
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_IN;

    log3ifr!(ctx,f,line!(), rv);
    rv
}

pub fn sm_pin_cmd_get_policy(card: &mut sc_card,
                             pin_cmd_data: &mut sc_pin_cmd_data/*, pin_reference: u8*/,
                             tries_left: &mut i32) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!( b"sm_pin_cmd_get_policy\0");
    log3ifc!(ctx,f,line!());

    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }
//println!("sm_pin_cmd_get_policy   get_cs_enc:  {:X?}\n", get_cs_enc(card));
//println!("sm_pin_cmd_get_policy   get_cs_mac:  {:X?}\n", get_cs_mac(card));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0x20, 0, u8::try_from(pin_cmd_data.pin_reference).unwrap()];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(card);
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr, &get_cs_mac(card), &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = [0; 10];
    let mut apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
    assert_eq!(apdu.le, rbuf.len());
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), rv);
        return rv;
    }

    if !(u32::from(rbuf[2]) == 0x63 && (u32::from(rbuf[3]) & 0xC0) == 0xC0) {
        log3if!(ctx,f,line!(), cstru!(b"Error: 'Get remaining number of retries left for the PIN' failed\0"));
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }


    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x63, rbuf[3]];
    sm_incr_ssc(card);
    ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in, &get_cs_mac(card), &mut ivec);
////println!("mac_resp:                 {:X?}", mac_resp);
    log3ift!(ctx,f,line!(), cstru!(b"mac_resp verification: [%02X %02X %02X %02X]\0"),
        mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3]);
    if rbuf[6..10] != mac_resp[..4] {
        rv = SC_ERROR_SM;
    }
    else {
        pin_cmd_data.pin1.tries_left = i32::from(rbuf[3] & 0x0F); //  63 Cnh     n is remaining tries
        *tries_left = pin_cmd_data.pin1.tries_left;
    }
    log3ifr!(ctx,f,line!(), rv);
    rv
}
