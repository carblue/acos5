extern crate libc;
extern crate num_integer;
extern crate opensc_sys;

use libc::{free, snprintf, strlen};
use num_integer::Integer;

use std::os::raw::{c_int, c_char, c_uchar, c_ulong, c_void/*, c_uint*/};
use std::ffi::CStr;
use std::ptr::{copy_nonoverlapping};
use std::slice::from_raw_parts;

use opensc_sys::opensc::{sc_context, sc_card, sc_hex_to_bin, sc_get_challenge, sc_bytes2apdu_wrapper, sc_transmit_apdu,
                         sc_check_sw, sc_pin_cmd_data, SC_PIN_STATE_LOGGED_IN, SC_PIN_STATE_LOGGED_OUT};
use opensc_sys::types::{SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT, sc_apdu/*, SC_AC_CHV*/};
use opensc_sys::errors::{sc_strerror, SC_SUCCESS, SC_ERROR_SM_KEYSET_NOT_FOUND, SC_ERROR_UNKNOWN_DATA_RECEIVED, SC_ERROR_INVALID_DATA,
                         SC_ERROR_SM_IFD_DATA_MISSING, SC_ERROR_SM_RAND_FAILED, SC_ERROR_SM_AUTHENTICATION_FAILED,
                         SC_ERROR_SM_NOT_INITIALIZED, SC_ERROR_SM, SC_ERROR_PIN_CODE_INCORRECT, SC_ERROR_AUTH_METHOD_BLOCKED,
                         SC_ERROR_KEYPAD_MSG_TOO_LONG
                         /*, sc_strerror, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_NOT_SUPPORTED*/};
use opensc_sys::sm::{sm_info, sm_cwa_session, SM_SMALL_CHALLENGE_LEN};
use opensc_sys::log::{sc_dump_hex, sc_do_log, SC_LOG_DEBUG_NORMAL/*, SC_LOG_DEBUG_SM*/};
use opensc_sys::scconf::{scconf_block, scconf_find_blocks, scconf_get_str};

use crate::constants_types::*;
use crate::crypto::{DES_KEY_SZ, DES_KEY_SZ_u8, des_ecb3_unpadded_8, des_ede3_cbc_pad_80_mac, des_ede3_cbc_pad_80, Encrypt, Decrypt, RAND_bytes};
use crate::wrappers::*;

/*
TODO There is a lot of code duplication here: Abstract as much as possible for the 4 APDU cases, but first test thoroughly
  that all is working as expected
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
pub extern "C" fn initialize(_ctx: *mut sc_context, _sm_info: *mut sm_info, _rdata: *mut sc_remote_data) -> c_int
{
    SC_SUCCESS
}

// mandatory func
#[no_mangle]
pub extern "C" fn get_apdus(_ctx: *mut sc_context, _sm_info: *mut sm_info, _init_data: *mut c_uchar,
                            _init_len: usize, _rdata: *mut sc_remote_data) -> c_int
{
    SC_SUCCESS
}


/*
// non-mandatory func
#[no_mangle]
pub extern "C" fn finalize(_ctx: *mut sc_context, _sm_info: *mut sm_info, _rdata: *mut sc_remote_data,
                           _out: *mut c_uchar, _out_len: usize) -> c_int
{
    SC_SUCCESS
}
*/

/*
// non-mandatory func
#[no_mangle]
pub extern "C" fn module_init(ctx_ptr: *mut sc_context, data_ptr: *const c_char) -> c_int
{
    if ctx_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun = CStr::from_bytes_with_nul(b"SM module: module_init\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(ctx_ptr, f_log, line!(), fun, data_ptr, CStr::from_bytes_with_nul(b"called with data_ptr: %p\0").unwrap());
    }
    let ctx = unsafe { &mut *ctx_ptr };
    for elem in ctx.card_drivers.iter_mut() {
        if (*elem).is_null() { break; }
        unsafe {
            let drv = &mut *(*elem);
            if !drv.short_name.is_null() {
                println!("Driver supported: {:?}", CStr::from_ptr(drv.short_name));
            }
            if CStr::from_ptr(drv.short_name) == CStr::from_bytes_with_nul(b"acos5_64\0").unwrap() &&
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
pub extern "C" fn module_cleanup(_ctx: *mut sc_context) -> c_int
{
    SC_SUCCESS
}
*/


/* This is an optional function, yet if it's not exported, the sanity_check will treat SM as unavailable, no matter what */
// non-mandatory func
#[allow(dead_code)]
//#[no_mangle] pub extern "C"
fn test(_ctx: *mut sc_context, _sm_info: *mut sm_info, out: *mut c_char) -> c_int
{
    unsafe { *out = 66u8 as c_char };
    SC_SUCCESS
}
*/

fn get_cwa_keyset_enc_card(cwa: &sm_cwa_session) -> [c_uchar; 3*DES_KEY_SZ] {
    let mut result = [0_u8; 3*DES_KEY_SZ];
    unsafe { copy_nonoverlapping(cwa.cwa_keyset.enc.as_ptr(), result.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(cwa.icc.k.as_ptr(),          result.as_mut_ptr().add(2*DES_KEY_SZ), DES_KEY_SZ) };
    result
}

fn get_cwa_keyset_mac_host(cwa: &sm_cwa_session) -> [c_uchar; 3*DES_KEY_SZ] {
    let mut result = [0_u8; 3*DES_KEY_SZ];
    unsafe { copy_nonoverlapping(cwa.cwa_keyset.mac.as_ptr(), result.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(cwa.ifd.k.as_ptr(),          result.as_mut_ptr().add(2*DES_KEY_SZ), DES_KEY_SZ) };
    result
}
//
fn get_cwa_session_enc(cwa: &sm_cwa_session) -> [c_uchar; 3*DES_KEY_SZ] {
    let mut result = [0_u8; 3*DES_KEY_SZ];
    unsafe { copy_nonoverlapping(cwa.session_enc.as_ptr(),         result.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(cwa.icc.k.as_ptr().add(DES_KEY_SZ), result.as_mut_ptr().add(2*DES_KEY_SZ), DES_KEY_SZ) };
    result
}

fn get_cwa_session_mac(cwa: &sm_cwa_session) -> [c_uchar; 3*DES_KEY_SZ] {
    let mut result = [0_u8; 3*DES_KEY_SZ];
    unsafe { copy_nonoverlapping(cwa.session_mac.as_ptr(),         result.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(cwa.ifd.k.as_ptr().add(DES_KEY_SZ), result.as_mut_ptr().add(2*DES_KEY_SZ), DES_KEY_SZ) };
    result
}

/* increments ssc by 1; only the last 2 bytes will change, and possibly wrap */
fn sm_incr_ssc(ssc: &mut [u8; DES_KEY_SZ]) {
    if ssc[7] != 0xFF {
        ssc[7] += 1;
        return;
    }
    ssc[7] = 0x00;
    if ssc[6] != 0xFF { ssc[6] += 1; }
    else              { ssc[6] = 0x00; }
}


fn sm_cwa_config_get_keyset(ctx: &mut sc_context, sm_info: &mut sm_info) -> c_int
{
    let cwa_session = unsafe { &mut sm_info.session.cwa };
    let cwa_keyset = &mut cwa_session.cwa_keyset;
    let mut sm_conf_block : *mut scconf_block = std::ptr::null_mut();
    let crt_at = &cwa_session.params.crt_at;

    let mut name : [c_char; 128] = [0; 128];
    let mut hex  : [c_uchar; 48] = [0; 48];
    let mut hex_len;
    let mut rv : c_int;
    let ref_ = i32::from((crt_at.refs[0] as u8) & ACOS5_OBJECT_REF_MAX);

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"sm_cwa_config_get_keyset\0").unwrap();

    /* look for sc block in opensc.conf */
    for elem in &ctx.conf_blocks {
        if (*elem).is_null() { break; }
        let blocks_ptr = unsafe { scconf_find_blocks(ctx.conf, *elem,
            CStr::from_bytes_with_nul(/*b"secure_messaging\0"*/ b"card_driver\0").unwrap().as_ptr(),
        /*sm_info.config_section.as_ptr()*/ CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap().as_ptr()) };//card_driver acos5_external
        if blocks_ptr.is_null() { continue; }
        sm_conf_block = unsafe { *blocks_ptr }; // blocks[0];

        unsafe { free(blocks_ptr as *mut c_void) };
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
////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "CRT(algo:%X,ref:%X)", crt_at->algo, crt_at->refs[0]);
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as c_int, fun.as_ptr(),
                       CStr::from_bytes_with_nul(b"CRT(algo:%X,ref:%X)\0").unwrap().as_ptr(), crt_at.algo, crt_at.refs[0]) };
    /* Keyset ENC */
    if sm_info.current_aid.len>0 && (crt_at.refs[0] as u8 & ACOS5_OBJECT_REF_LOCAL) >0 {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), CStr::from_bytes_with_nul(b"keyset_%s_%02i_enc\0").unwrap().as_ptr(),
                          sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
    }
    else {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), CStr::from_bytes_with_nul(b"keyset_%02i_enc\0").unwrap().as_ptr(), ref_) };
    }
    let value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), std::ptr::null()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        wr_do_log_t(ctx, f_log, line!(), fun, name.as_ptr(), CStr::from_bytes_with_nul(b"No %s value in OpenSC config\0").unwrap());
        return SC_ERROR_SM_KEYSET_NOT_FOUND;
    }

////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "keyset::enc(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value), value);
    wr_do_log_tu(ctx, f_log, line!(), fun, unsafe { strlen(value) }, value, CStr::from_bytes_with_nul(b"keyset::enc(%zu) %s\0").unwrap());
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        unsafe { copy_nonoverlapping(value as *const c_uchar,                cwa_keyset.enc.as_mut_ptr(), 2*DES_KEY_SZ) };
        unsafe { copy_nonoverlapping(value.add(2*DES_KEY_SZ) as *const c_uchar, cwa_session.icc.k.as_mut_ptr(), DES_KEY_SZ) };
    }
    else   {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
        if rv != SC_SUCCESS {
////                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get %s: hex to bin failed for '%s'; error %i", name, value, rv);
            wr_do_log_tuv(ctx, f_log, line!(), fun, name.as_ptr(), value, rv, CStr::from_bytes_with_nul(b"SM get %s: hex to bin failed for '%s'; error %i\0").unwrap());
            return SC_ERROR_UNKNOWN_DATA_RECEIVED;
        }

////                sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "ENC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len, sc_dump_hex(hex, hex_len));
        wr_do_log_tu(ctx, f_log, line!(), fun, hex_len, unsafe {sc_dump_hex(hex.as_ptr(), hex_len)}, CStr::from_bytes_with_nul(b"ENC(%zu) %s\0").unwrap());
        if hex_len != 3*DES_KEY_SZ {
            return SC_ERROR_INVALID_DATA;
        }
        unsafe { copy_nonoverlapping(hex.as_ptr(),                cwa_keyset.enc.as_mut_ptr(), 2*DES_KEY_SZ) };
        unsafe { copy_nonoverlapping(hex.as_ptr().add(2*DES_KEY_SZ), cwa_session.icc.k.as_mut_ptr(), DES_KEY_SZ) };
    }
////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "%s %s", name, sc_dump_hex(cwa_keyset->enc, 3*DES_KEY_SZ));
    wr_do_log_tu(ctx, f_log, line!(), fun, name.as_ptr(), unsafe {sc_dump_hex(cwa_keyset.enc.as_ptr(), 2*DES_KEY_SZ)}, CStr::from_bytes_with_nul(b"%s %s\0").unwrap());

    /* Keyset MAC */
    if sm_info.current_aid.len>0 && (crt_at.refs[0] as u8 & ACOS5_OBJECT_REF_LOCAL) >0 {
        unsafe { snprintf(name.as_mut_ptr(), name.len(), CStr::from_bytes_with_nul(b"keyset_%s_%02i_mac\0").unwrap().as_ptr(),
                          sc_dump_hex(sm_info.current_aid.value.as_ptr(), sm_info.current_aid.len), ref_) };
    }
    else {
//                snprintf(name, sizeof(name), "keyset_%02i_mac", ref);
        unsafe { snprintf(name.as_mut_ptr(), name.len(), CStr::from_bytes_with_nul(b"keyset_%02i_mac\0").unwrap().as_ptr(), ref_) };
    }
    let value = unsafe { scconf_get_str(sm_conf_block, name.as_ptr(), std::ptr::null()) };

    if value.is_null() {
////                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "No %s value in OpenSC config", name);
        wr_do_log_t(ctx, f_log, line!(), fun, name.as_ptr(), CStr::from_bytes_with_nul(b"No %s value in OpenSC config\0").unwrap());
        return SC_ERROR_SM_KEYSET_NOT_FOUND;
    }

////            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "keyset::mac(%"SC_FORMAT_LEN_SIZE_T"u) %s", strlen(value), value);
    wr_do_log_tu(ctx, f_log, line!(), fun, unsafe { strlen(value) }, value, CStr::from_bytes_with_nul(b"keyset::mac(%zu) %s\0").unwrap());
    if unsafe { strlen(value) } == 3*DES_KEY_SZ {
        unsafe { copy_nonoverlapping(value as *const c_uchar,                cwa_keyset.mac.as_mut_ptr(), 2*DES_KEY_SZ) };
        unsafe { copy_nonoverlapping(value.add(2*DES_KEY_SZ) as *const c_uchar, cwa_session.ifd.k.as_mut_ptr(), DES_KEY_SZ) };
    }
    else   {
        hex_len = hex.len();
        rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
        if rv != SC_SUCCESS {
////                    sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get '%s': hex to bin failed for '%s'; error %i", name, value, rv);
            wr_do_log_tuv(ctx, f_log, line!(), fun, name.as_ptr(), value, rv, CStr::from_bytes_with_nul(b"SM get %s: hex to bin failed for '%s'; error %i\0").unwrap());
            return SC_ERROR_UNKNOWN_DATA_RECEIVED;
        }

////                sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "MAC(%"SC_FORMAT_LEN_SIZE_T"u) %s", hex_len, sc_dump_hex(hex, hex_len));
        wr_do_log_tu(ctx, f_log, line!(), fun, hex_len, unsafe {sc_dump_hex(hex.as_ptr(), hex_len)}, CStr::from_bytes_with_nul(b"MAC(%zu) %s\0").unwrap());
        if hex_len != 3*DES_KEY_SZ {
            return SC_ERROR_INVALID_DATA;
        }

        unsafe { copy_nonoverlapping(hex.as_ptr(),                cwa_keyset.mac.as_mut_ptr(), 2*DES_KEY_SZ) };
        unsafe { copy_nonoverlapping(hex.as_ptr().add(2*DES_KEY_SZ), cwa_session.ifd.k.as_mut_ptr(), DES_KEY_SZ) };
    }
//            sc_debug(ctx, SC_LOG_DEBUG_NORMAL, "%s %s", name, sc_dump_hex(cwa_keyset->mac, 2*DES_KEY_SZ));
    wr_do_log_tu(ctx, f_log, line!(), fun, name.as_ptr(), unsafe {sc_dump_hex(cwa_keyset.mac.as_ptr(), 2*DES_KEY_SZ)}, CStr::from_bytes_with_nul(b"%s %s\0").unwrap());

    cwa_keyset.sdo_reference = crt_at.refs[0];


    /* IFD parameters */
    //memset(cwa_session, 0, sizeof(struct sm_cwa_session));
//            value = scconf_get_str(sm_conf_block, "ifd_serial", NULL);
    let value = unsafe { scconf_get_str(sm_conf_block, CStr::from_bytes_with_nul(b"ifd_serial\0").unwrap().as_ptr(), std::ptr::null()) };
    if value.is_null() {
        return SC_ERROR_SM_IFD_DATA_MISSING;
    }
    hex_len = hex.len();
    rv = unsafe { sc_hex_to_bin(value, hex.as_mut_ptr(), &mut hex_len) };
    if rv != SC_SUCCESS   {
//                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE, "SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
        wr_do_log_tu(ctx, f_log, line!(), fun, value, rv, CStr::from_bytes_with_nul(b"SM get 'ifd_serial': hex to bin failed for '%s'; error %i\0").unwrap());
        return SC_ERROR_UNKNOWN_DATA_RECEIVED;
    }

    if hex_len != cwa_session.ifd.sn.len() {
//                sc_debug(ctx, SC_LOG_DEBUG_VERBOSE,
//                        "SM get 'ifd_serial': invalid IFD serial length: %"SC_FORMAT_LEN_SIZE_T"u",
//                        hex_len);
        wr_do_log_t(ctx, f_log, line!(), fun, hex_len, CStr::from_bytes_with_nul(b"SM get 'ifd_serial': invalid IFD serial length: %zu\0").unwrap());
        return SC_ERROR_UNKNOWN_DATA_RECEIVED;
    }

//            memcpy(cwa_session->ifd.sn, hex, hex_len);
    /*
                rv = RAND_bytes(cwa_session->ifd.rnd, DES_KEY_SZ_u8 as c_int);
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

fn sm_cwa_initialize(card: &mut sc_card/*, sm_info: &mut sm_info, _rdata: &mut sc_remote_data*/) -> c_int
{
    /*
    cwa_keyset_mac_host: [F1, E0, D0, C1, B0, A1, 89, 8, 7, 16, 45, 4, 13, 2, 1, F1, 89, FE, B3, C8, 37, 45, 16, 94] corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    cwa_keyset_enc_card: [F1, 1, 2, 13, 4, 85, 16, 7, 8, 49, A1, B0, C1, D0, E0, F1, 45, 89, B3, 16, FE, 94, 37, C8] corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc

    keyset_41434F53504B43532D313576312E3030_02_mac = "F1:E0:D0:C1:B0:A1:89:08:07:16:45:04:13:02:01:F1:89:FE:B3:C8:37:45:16:94"; # corresponds to key_reference 0x81 (external auth. key terminal/host in DF 0x4100) kh, that will be authenticated
    keyset_41434F53504B43532D313576312E3030_02_enc = "F1:01:02:13:04:85:16:07:08:49:A1:B0:C1:D0:E0:F1:45:89:B3:16:FE:94:37:C8"; # corresponds to key_reference 0x82 (internal auth. key card          in DF 0x4100) kc
    */
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"sm_cwa_initialize\0").unwrap();
    /* Mutual Authentication Procedure with 2 different keys, (key card) kc and (key terminal/host) kh */
    /* External Authentication */
    let mut rv = unsafe { sc_get_challenge(card, card.sm_ctx.info.session.cwa.card_challenge.as_mut_ptr(), SM_SMALL_CHALLENGE_LEN) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
    unsafe { card.sm_ctx.info.session.cwa.ssc  = card.sm_ctx.info.session.cwa.card_challenge };
    let scwa = unsafe { &card.sm_ctx.info.session.cwa };
    let re = des_ecb3_unpadded_8(&scwa.card_challenge[..], &get_cwa_keyset_mac_host(scwa)[..], Encrypt);

    let mut cmd = [0, 0x82, 0, 0x81 /*(key terminal/host) kh*/, SM_SMALL_CHALLENGE_LEN as u8, 0,0,0,0,0,0,0,0];
    unsafe { copy_nonoverlapping(re.as_ptr(), cmd.as_mut_ptr().add(5), SM_SMALL_CHALLENGE_LEN) };
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* Internal Authentication */
    rv = unsafe { RAND_bytes(card.sm_ctx.info.session.cwa.host_challenge.as_mut_ptr(), SM_SMALL_CHALLENGE_LEN as c_int) };
    if rv != 1 {
        rv = SC_ERROR_SM_RAND_FAILED;
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
    let mut cmd = [0, 0x88, 0, 0x82 /*(key card) kc*/, SM_SMALL_CHALLENGE_LEN as u8, 0,0,0,0,0,0,0,0  ,SM_SMALL_CHALLENGE_LEN as u8];
    unsafe { copy_nonoverlapping(card.sm_ctx.info.session.cwa.host_challenge.as_ptr(), cmd.as_mut_ptr().add(5), SM_SMALL_CHALLENGE_LEN) };
    apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    assert_eq!(apdu.le, SM_SMALL_CHALLENGE_LEN);
    let mut chall_encrypted_by_card = [0_u8; SM_SMALL_CHALLENGE_LEN];
    apdu.resplen = SM_SMALL_CHALLENGE_LEN;
    apdu.resp    = chall_encrypted_by_card.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    let scwa = unsafe { &card.sm_ctx.info.session.cwa };
    let chall_encrypted_by_host = des_ecb3_unpadded_8(&scwa.host_challenge[..], &get_cwa_keyset_enc_card(scwa)[..], Encrypt);
    if  chall_encrypted_by_host != chall_encrypted_by_card.to_vec() {
        return SC_ERROR_SM_AUTHENTICATION_FAILED;
    }

    /* session keys generation. acos5 does it internally automatically and we must do the same here */
    let mut deriv_data = Vec::with_capacity(3*DES_KEY_SZ);
    deriv_data.extend_from_slice(&scwa.card_challenge[4..8]);
    deriv_data.extend_from_slice(&scwa.host_challenge[0..4]);
    deriv_data.extend_from_slice(&scwa.card_challenge[0..4]);
    deriv_data.extend_from_slice(&scwa.host_challenge[4..8]);
    deriv_data.extend_from_slice(&scwa.host_challenge[0..4]);
    deriv_data.extend_from_slice(&scwa.card_challenge[4..8]);
//        writefln("deriv_data_plain:     0x [ %(%x %) ]", deriv_data);

    let sess_enc_buf = des_ecb3_unpadded_8(deriv_data.as_slice(), &get_cwa_keyset_enc_card(scwa)[..], Encrypt);
    let sess_mac_buf = des_ecb3_unpadded_8(deriv_data.as_slice(), &get_cwa_keyset_mac_host(scwa)[..], Encrypt);
    assert_eq!(3*DES_KEY_SZ, sess_enc_buf.len());
    assert_eq!(3*DES_KEY_SZ, sess_mac_buf.len());

    unsafe { copy_nonoverlapping(sess_enc_buf.as_ptr(),                         card.sm_ctx.info.session.cwa.session_enc.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(sess_enc_buf.as_ptr().add(2*DES_KEY_SZ), card.sm_ctx.info.session.cwa.icc.k.as_mut_ptr().add(DES_KEY_SZ), DES_KEY_SZ) };

    unsafe { copy_nonoverlapping(sess_mac_buf.as_ptr(),                         card.sm_ctx.info.session.cwa.session_mac.as_mut_ptr(), 2*DES_KEY_SZ) };
    unsafe { copy_nonoverlapping(sess_mac_buf.as_ptr().add(2*DES_KEY_SZ), card.sm_ctx.info.session.cwa.ifd.k.as_mut_ptr().add(DES_KEY_SZ), DES_KEY_SZ) };
    SC_SUCCESS
}


fn sm_manage_keyset(card: &mut sc_card) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"sm_manage_keyset\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    if unsafe { card.sm_ctx.info.session.cwa.session_mac.ne(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]) } {
        SC_SUCCESS
    }
    else {
////    sc_debug(card_ctx, SC_LOG_DEBUG_NORMAL, "Current AID: %s", sc_dump_hex(sm_info->current_aid.value, sm_info->current_aid.len));
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe{sc_dump_hex(card.sm_ctx.info.current_aid.value.as_ptr(), card.sm_ctx.info.current_aid.len)}, CStr::from_bytes_with_nul(b"Current AID: %s\0").unwrap());

//        case SM_TYPE_CWA14890:
        let rv = sm_cwa_config_get_keyset(card_ctx, &mut card.sm_ctx.info);
//            LOG_TEST_RET(ctx, rv, "SM iasecc configuration error");
        if rv < SC_SUCCESS {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"SM acos5 configuration error\0").unwrap().as_ptr(),
                          rv, sc_strerror(rv), CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap() )};
        }
        rv
    }
}

fn sm_manage_initialize(card: &mut sc_card) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"sm_manage_initialize\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let past = dp.time_stamp;
    dp.time_stamp = std::time::Instant::now();
    card.drv_data = Box::into_raw(dp) as *mut c_void;

//println!("elapsed ms: {}", past.elapsed().as_millis());
    if past.elapsed().as_millis() > 150 {
        let rv = sm_cwa_initialize(card/*, sm_info, rdata*/);
        if rv != SC_SUCCESS {
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"SM acos5 initializing error\0").unwrap());
        }

        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        dp.time_stamp = std::time::Instant::now();
        card.drv_data = Box::into_raw(dp) as *mut c_void;

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
//                      buf_ptr: *mut c_uchar,
//                      count: usize,
                      flags: c_ulong,
                      bin: bool,
                      has_ct: bool,
                      fdb: u8) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( if bin {b"sm_read_binary\0"} else {b"sm_read_record\0"}).unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, flags, CStr::from_bytes_with_nul(b"called with flags %zu\0").unwrap());
    }

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

    /* sc_read_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes, i.e. count<=255; it's okay to read less*/
////println!("sm_common_read get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_common_read get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    assert!(buf.len()<256);
    let count = std::cmp::min(buf.len(), 255);
    let len_read = std::cmp::min(if has_ct {239_u8} else {240_u8},count as u8);
////println!("len_read : {}", len_read);
    let len_read2    = len_read.next_multiple_of(&DES_KEY_SZ_u8);// padding added if required
////println!("len_read2: {}", len_read2);
    assert!(len_read2.is_multiple_of(&DES_KEY_SZ_u8));
    assert!(len_read2 <= 240);
    let pos : usize = if has_ct {13} else {12};
    let len_resp = pos as u8 + if has_ct { len_read2 + if len_read.is_multiple_of(&DES_KEY_SZ_u8) {DES_KEY_SZ_u8} else {0} }
                                    else      { len_read };
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
            [0x89_u8,4, if fdb!=9 {0x0C} else {0x8C}, if fdb!=9 {0xB0} else {0xCA}, idx_arr[0],idx_arr[1],  0x97,1,len_read]
        }
        else {
            assert!(idx<32);
            [0x89_u8,4, 0x0C, 0xB2,                                              idx as u8,4,  0x97,1,len_read]
        };

////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr[..],
                &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 9,  hdr[6],hdr[7],hdr[8],
        0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], len_resp /*>0, otherwise arbitrary*/];
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    let mut rbuf = vec![0_u8; len_resp as usize];
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* verify mac_resp */
    let mut mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    if has_ct { mac_resp_in.extend_from_slice(&vec![0x87_u8, len_resp -(pos-1) as u8, rbuf[pos-1]][..]); }
    else      { mac_resp_in.extend_from_slice(&vec![0x81_u8, len_read][..]); }
    mac_resp_in.extend_from_slice(&rbuf[pos..]);

    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                          &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }

    if has_ct {
        let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
        let resp_decrypted = des_ede3_cbc_pad_80(&rbuf[pos..pos+len_read2 as usize],
                                          &get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa })[..],
                                          &mut ivec, Decrypt, rbuf[pos-1]);
        assert_eq!(len_read as usize, resp_decrypted.len());
        assert!(resp_decrypted.len() <= count);

        unsafe { copy_nonoverlapping(resp_decrypted.as_ptr(),      buf.as_mut_ptr(), len_read as usize) };
    }
    else {
        unsafe { copy_nonoverlapping(rbuf.as_ptr().add(pos), buf.as_mut_ptr(), len_read as usize) };
    }

    rv = i32::from(len_read);
    wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
    rv
}


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_3_SHORT: yes command data, but doesn't expect response data (with SM, there are response data)
pub fn sm_common_update(card: &mut sc_card,
                        idx: u16,
                        buf: &[u8],
//                        buf_ptr: *const c_uchar,
//                        count: usize,
                        flags: c_ulong,
                        bin: bool,
                        has_ct: bool,
                        _fdb: u8) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( if bin {b"sm_update_binary\0"} else {b"sm_update_record\0"}).unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, flags, CStr::from_bytes_with_nul(b"called with flags %zu\0").unwrap());
    }

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

    /* sc_update_binary has a loop to chunk input into max. sc_get_max_recv_size(card) bytes, i.e. count<=255; it's okay to update less*/
////println!("sm_common_update get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_common_update get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    assert!(buf.len()<256);
    let count = std::cmp::min(buf.len(), 255);
    let len_update = std::cmp::min(if has_ct {232_u8} else {240_u8},count as u8);
////println!("len_update : {}", len_update);
    let len_update2 = len_update.next_multiple_of(&DES_KEY_SZ_u8); // padding added if required
////println!("len_update2: {}", len_update2);
    assert!(len_update2.is_multiple_of(&DES_KEY_SZ_u8));
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
            idx as u8,        if idx==0 && flags==0 {0}    else {4} ]
        };

////println!("sm_common_update ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
////println!("sm_common_update ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let data_encrypted = des_ede3_cbc_pad_80(&buf[..usize::from(len_update)],
          &get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), len_update2 as usize);

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ len_update2 as usize);
    hdr_vec.extend_from_slice(&hdr[..]);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_update2 as u8, pi] [..]);
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_update as u8] [..]);
        hdr_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec,
                               &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +len_update2 as usize +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_update2, 0x87, 1 +len_update2, pi] [..]);
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_update,  0x81,    len_update] [..]);
        cmd_vec.extend_from_slice(&buf[..usize::from(len_update)]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4][..]);
    cmd_vec.extend_from_slice(&mac.as_slice()[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, cmd_vec.as_slice(), &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    let mut rbuf = vec![0_u8; 10];
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in[..],
                     &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    rv = i32::from(len_update);
    wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
    rv
} // sm_common_update


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_3_SHORT: no command data, but expects response data (with SM, there are command data: the tagged le)
pub fn sm_erase_binary(card: &mut sc_card, idx: u16, count: u16, flags: c_ulong, has_ct: bool) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( b"sm_erase_binary\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, flags, CStr::from_bytes_with_nul(b"called with flags %zu\0").unwrap());
    }

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

////println!("sm_common_read get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_common_read get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    /* cmd without SM: SC_APDU_CASE_2_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let idx_arr : [u8; 2] = idx.to_be_bytes();
    let hdr = [0x89_u8,4, 0x0C, 0x0E, idx_arr[0],idx_arr[1] /*,  0x97,1,len_read*/];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let data_encrypted = des_ede3_cbc_pad_80(&(idx + count).to_be_bytes()[..],
        &get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), DES_KEY_SZ);

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 11);
    hdr_vec.extend_from_slice(&hdr[..]);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 9, 1] [..]);
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    2] [..]);
        hdr_vec.extend_from_slice(& (idx + count).to_be_bytes() [..]);
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr_vec,
                         &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +8 +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(&[17, 0x87, 9, 1][..]);
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(&[10, 0x81, 2][..]);
        cmd_vec.extend_from_slice(& (idx + count).to_be_bytes() [..]);
    }
    cmd_vec.extend_from_slice(&[0x8E, 4][..]);
    cmd_vec.extend_from_slice(&mac_cmd.as_slice()[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd_vec, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    let mut rbuf = vec![0_u8; 10];
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* verify mac_resp */
    let /*mut*/ mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                                      &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    rv = count as c_int;
    wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
    rv
} // sm_erase_binary


//#[no_mangle] // original APDU type (without SM): SC_APDU_CASE_1 or SC_APDU_CASE_3_SHORT: Doesn't expect response data (with SM, )
pub fn sm_delete_file(card: &mut sc_card) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( b"sm_delete_file\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }
////println!("sm_common_read get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_common_read get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0xE4, 0,0];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr[..],
                         &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = vec![0_u8; 10];
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd[..], &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                          &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
    rv
} // sm_delete_file


pub fn sm_pin_cmd_verify(card: &mut sc_card, pin_cmd_data: &mut sc_pin_cmd_data, tries_left: &mut c_int, has_ct: bool) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( b"sm_pin_cmd_verify\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }

////println!("sm_pin_cmd_verify get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_pin_cmd_verify get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    let len_pin = pin_cmd_data.pin1.len as u8;
////println!("len_pin : {}", len_pin);
    let len_pin2 = len_pin.next_multiple_of(&DES_KEY_SZ_u8); // padding added if required
////println!("len_pin2: {}", len_pin2);
    assert!(len_pin2.is_multiple_of(&DES_KEY_SZ_u8));
    assert!(len_pin2 <= DES_KEY_SZ_u8);
    let pi = if has_ct && !len_pin.is_multiple_of(&DES_KEY_SZ_u8) {1_u8} else {0_u8};
////println!("pi: {}", pi);
    /* cmd without SM: SC_APDU_CASE_3_SHORT; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0x20, 0, pin_cmd_data.pin_reference as u8];
////println!("sm_pin_cmd_verify ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
////println!("sm_pin_cmd_verify ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
//                              &pin_user[..],
//                              unsafe { from_raw_parts(pin_cmd_data.pin1.data, std::cmp::max(0,pin_cmd_data.pin1.len) as usize) }
//                              ,

    let data_encrypted = des_ede3_cbc_pad_80(unsafe { from_raw_parts(pin_cmd_data.pin1.data, pin_cmd_data.pin1.len as usize) },
        &get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec, Encrypt, 0);
////println!("data_encrypted.len(): {}, data_encrypted: {:X?}", data_encrypted.len(), data_encrypted);
    assert_eq!(data_encrypted.len(), len_pin2 as usize);

    let mut hdr_vec : Vec<u8> = Vec::with_capacity(hdr.len()+ 3+ len_pin2 as usize);
    hdr_vec.extend_from_slice(&hdr[..]);
    if has_ct {
        hdr_vec.extend_from_slice(& [0x87, 1+ len_pin2 as u8, pi] [..]);
        hdr_vec.extend_from_slice(&data_encrypted);
    }
    else {
        hdr_vec.extend_from_slice(& [0x81,    len_pin as u8] [..]);
        hdr_vec.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin1.data, pin_cmd_data.pin1.len as usize) });
    }
////println!("hdr_vec: {:X?}", hdr_vec);
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac = des_ede3_cbc_pad_80_mac(&hdr_vec,
        &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac:                 {:X?}", mac);
    let mut cmd_vec : Vec<u8> = Vec::with_capacity(hdr.len()-2 +4 +len_pin2 as usize +6 +1);
    cmd_vec.extend_from_slice(&hdr[2..]);
    if has_ct {
        cmd_vec.extend_from_slice(& [9 +len_pin2, 0x87, 1 +len_pin2, pi] [..]);
        cmd_vec.extend_from_slice(&data_encrypted);
    }
    else {
        cmd_vec.extend_from_slice(& [8 +len_pin,  0x81,    len_pin] [..]);
        cmd_vec.extend_from_slice(unsafe { from_raw_parts(pin_cmd_data.pin1.data, pin_cmd_data.pin1.len as usize) });
    }
    cmd_vec.extend_from_slice(&[0x8E, 4][..]);
    cmd_vec.extend_from_slice(&mac.as_slice()[0..4]);
    cmd_vec.push(10);
////println!("cmd_vec:                 {:X?}", cmd_vec);
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, cmd_vec.as_slice(), &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    let mut rbuf = vec![0_u8; 10];
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_OUT;
        if      rv==SC_ERROR_PIN_CODE_INCORRECT  { pin_cmd_data.pin1.tries_left = i32::from(rbuf[3]&0x0F); *tries_left = pin_cmd_data.pin1.tries_left; }
        else if rv==SC_ERROR_AUTH_METHOD_BLOCKED { pin_cmd_data.pin1.tries_left = 0;                       *tries_left = pin_cmd_data.pin1.tries_left; }
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }

    /* verify mac_resp */
    let mac_resp_in = [hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x90, 0];
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe { card.sm_ctx.info.session.cwa.ssc };
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in[..],
        &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        return SC_ERROR_SM;
    }
    pin_cmd_data.pin1.logged_in = SC_PIN_STATE_LOGGED_IN;

    wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
    rv
}

//pub fn pin_get_policy(card: &mut sc_card, data: &mut sc_pin_cmd_data, tries_left: &mut c_int) -> c_int
//let rv = sm_pin_cmd_get_policy(card, pin_cmd_data, if tries_left_ptr.is_null() { &mut dummy_tries_left }
pub fn sm_pin_cmd_get_policy(card: &mut sc_card, pin_cmd_data: &mut sc_pin_cmd_data/*, pin_reference: u8*/, tries_left: &mut c_int) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul( b"sm_pin_cmd_get_policy\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    pin_cmd_data.pin1.tries_left = -1;
    *tries_left = pin_cmd_data.pin1.tries_left;

    if sm_manage_keyset(card) != SC_SUCCESS || sm_manage_initialize(card) != SC_SUCCESS {
        return SC_ERROR_SM_NOT_INITIALIZED;
    }
////println!("sm_common_read get_cwa_session_enc: {:X?}", get_cwa_session_enc(unsafe { &card.sm_ctx.info.session.cwa }));
////println!("sm_common_read get_cwa_session_mac: {:X?}", get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa }));
    /* cmd without SM: SC_APDU_CASE_1; with SM: SC_APDU_CASE_4_SHORT */
    let hdr = [0x89_u8,4, 0x0C, 0x20, 0,pin_cmd_data.pin_reference as u8];
////println!("sm_common_read ssc old:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
////println!("sm_common_read ssc new:                 {:X?}", unsafe { card.sm_ctx.info.session.cwa.ssc });
    let mac_cmd = des_ede3_cbc_pad_80_mac(&hdr[..],
        &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
////println!("mac_cmd:                 {:X?}", mac_cmd);
    let cmd  = [hdr[2],hdr[3],hdr[4],hdr[5], 6, 0x8E,4, mac_cmd[0],mac_cmd[1],mac_cmd[2],mac_cmd[3], 10];
    let mut rbuf = vec![0_u8; 10];
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &cmd[..], &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);
    assert_eq!(apdu.le, rbuf.len());
    apdu.resplen =      rbuf.len();
    apdu.resp = rbuf.as_mut_ptr();

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
/*
    rv = unsafe { sc_check_sw(card, u32::from(rbuf[2]), u32::from(rbuf[3])) };
    if rv != SC_SUCCESS {
        wr_do_log_rv(card_ctx, f_log, line!(), fun, rv);
        return rv;
    }
*/


    if !(u32::from(rbuf[2]) == 0x63 && (u32::from(rbuf[3]) & 0xC0) == 0xC0) {
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu or 'Get remaining number of retries left for the PIN' \
                     failed\0").unwrap();
            wr_do_log(card_ctx, f_log, line!(), fun, fmt);
        }
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }


    /* verify mac_resp */
    let mac_resp_in = vec![hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5], 0x99, 2, 0x63, rbuf[3]];
    sm_incr_ssc(unsafe { &mut card.sm_ctx.info.session.cwa.ssc });
    let mut ivec = unsafe {card.sm_ctx.info.session.cwa.ssc};
    let mac_resp = des_ede3_cbc_pad_80_mac(&mac_resp_in,
                                           &get_cwa_session_mac(unsafe { &card.sm_ctx.info.session.cwa })[..], &mut ivec);
//println!("mac_resp:                 {:X?}", mac_resp);
    wr_do_log_tttt(card_ctx, f_log, line!(), fun, mac_resp[0], mac_resp[1], mac_resp[2], mac_resp[3],
                   CStr::from_bytes_with_nul(b"mac_resp verification: [%02X %02X %02X %02X]\0").unwrap());
    if rbuf[6..10] != mac_resp[..4] {
        rv = SC_ERROR_SM;
    }
    else {
        pin_cmd_data.pin1.tries_left = i32::from(rbuf[3]&0x0F); //  63 Cnh     n is remaining tries
        *tries_left = pin_cmd_data.pin1.tries_left;
    }
    wr_do_log_rv(card_ctx, f_log, line!(), fun, SC_SUCCESS);
    rv
}


#[cfg(test)]
mod tests {
    use crate::crypto::DES_KEY_SZ;
    use super::sm_incr_ssc;

    #[test]
    fn test_sm_incr_ssc() {
        let mut ssc: [u8; DES_KEY_SZ]  = [1,2,3,4,5,6, 0xFE,0xFE];
        sm_incr_ssc(&mut ssc);
        assert_eq!(ssc, [1,2,3,4,5,6, 0xFE,0xFF]);
        sm_incr_ssc(&mut ssc);
        assert_eq!(ssc, [1,2,3,4,5,6, 0xFF,0x00]);
        sm_incr_ssc(&mut ssc);
        assert_eq!(ssc, [1,2,3,4,5,6, 0xFF,0x01]);
        ssc = [1,2,3,4,5,6, 0xFF,0xFF];
        sm_incr_ssc(&mut ssc);
        assert_eq!(ssc, [1,2,3,4,5,6, 0,0]);
        sm_incr_ssc(&mut ssc);
        assert_eq!(ssc, [1,2,3,4,5,6, 0,1]);
    }
}
