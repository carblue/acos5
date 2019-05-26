/*
 * lib.rs: Driver 'acos5_64' - main library file
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
 https://www.acs.com.hk/en/products/18/cryptomate64-usb-cryptographic-tokens/

 https://www.acs.com.hk/en/products/308/acos5-64-v3.00-cryptographic-card-contact/
 https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens/

 TODO Many error returns are provisorily set to SC_ERROR_KEYPAD_MSG_TOO_LONG to be refined later
 TODO Only set to anything other than SC_ERROR_KEYPAD_MSG_TOO_LONG, if that's the final setting
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
*/

//#![feature(const_fn)]

extern crate opensc_sys;

use std::os::raw::{c_int, c_uint, c_void, c_char, c_uchar, c_ulong};
use std::ffi::CStr;
use std::ptr::{copy_nonoverlapping};
use std::collections::HashMap;

use opensc_sys::opensc::{/*sc_get_version, sc_print_path, sc_path_set, sc_format_path, sc_path_print,
    sc_file_valid, sc_file_new, sc_file_free,
    sc_hex_to_bin, sc_bin_to_hex, sc_bin_to_hex_wrapper, sc_hex_to_bin_wrapper,
    sc_context_param_t, sc_context_t, sc_context_create, sc_release_context, sc_ctx_get_reader,
    sc_ctx_get_reader_count, sc_lock, sc_unlock, SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER, sc_card_t,
    sc_reader, sc_detect_card_presence, sc_connect_card, sc_disconnect_card*/
    /*, SC_READER_CARD_PRESENT, sc_reader_t, sc_select_file, sc_get_mf_path, */
    /*sc_card_operations, sc_get_iso7816_driver, sc_get_version,*/
    sc_card, sc_card_driver, sc_card_operations, sc_pin_cmd_data, sc_security_env,
    sc_get_iso7816_driver, sc_file_add_acl_entry, sc_format_path,
    sc_file_set_prop_attr, sc_transmit_apdu, sc_bytes2apdu_wrapper, sc_check_sw,
    SC_CARD_CAP_RNG, SC_CARD_CAP_USE_FCI_AC,
    /*SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH,*/
    SC_READER_SHORT_APDU_MAX_SEND_SIZE, SC_READER_SHORT_APDU_MAX_RECV_SIZE,
    SC_ALGORITHM_RSA, SC_ALGORITHM_ONBOARD_KEY_GEN, SC_ALGORITHM_RSA_RAW,
    SC_SEC_OPERATION_SIGN, SC_SEC_OPERATION_DECIPHER, SC_SEC_ENV_FILE_REF_PRESENT,
    SC_SEC_OPERATION_DERIVE, //SC_ALGORITHM_DES, SC_ALGORITHM_3DES,

    SC_PIN_CMD_GET_INFO, SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK,
    SC_ALGORITHM_RSA_PAD_NONE, SC_ALGORITHM_RSA_PAD_PKCS1, SC_ALGORITHM_RSA_PAD_ISO9796//, SC_ALGORITHM_RSA_PAD_PSS
};

#[cfg(not(v0_15_0))]
use opensc_sys::opensc::{SC_CARD_CAP_ISO7816_PIN_INFO};

#[cfg(not(any(v0_15_0, v0_16_0)))]
use opensc_sys::opensc::{SC_CARD_CAP_SESSION_PIN, SC_PIN_CMD_GET_SESSION_PIN, SC_ALGORITHM_AES};

#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
use opensc_sys::opensc::{SC_ALGORITHM_AES_FLAGS/*, SC_SEC_OPERATION_WRAP, SC_SEC_OPERATION_UNWRAP*/};

use opensc_sys::types::{/*sc_aid, sc_path, SC_MAX_AID_SIZE, SC_PATH_TYPE_FILE_ID, sc_file_t, SC_MAX_ATR_SIZE, */
    sc_apdu, sc_path, sc_file, sc_serial_number, SC_PATH_TYPE_PATH, SC_FILE_TYPE_INTERNAL_EF, SC_MAX_PATH_SIZE,
//    SC_PATH_TYPE_PATH_PROT, SC_PATH_TYPE_FROM_CURRENT, SC_PATH_TYPE_PARENT, SC_PATH_TYPE_FILE_ID, SC_MAX_CRTS_IN_SE,
    /* SC_AC_UNKNOWN, SC_AC_NEVER, SC_AC_PRO, SC_AC_CHV, SC_AC_AUT, sc_crt,*/
    SC_FILE_TYPE_DF, SC_FILE_EF_TRANSPARENT, SC_AC_NONE, SC_AC_KEY_REF_NONE,
    SC_AC_OP_LIST_FILES,
    SC_AC_OP_SELECT,
    SC_AC_OP_DELETE, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK,
    SC_AC_OP_READ,   SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO, SC_AC_OP_DELETE_SELF,
    SC_AC_OP_CREATE, SC_AC_OP_WRITE, SC_AC_OP_GENERATE, SC_APDU_FLAGS_CHAINING, SC_APDU_FLAGS_NO_GET_RESP,

    /*SC_APDU_CASE_1,*/ SC_APDU_CASE_2_SHORT, SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT
};

use opensc_sys::errors::{/* SC_ERROR_NO_READERS_FOUND, SC_ERROR_UNKNOWN, */ sc_strerror, SC_SUCCESS, SC_ERROR_INTERNAL,
    SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_KEYPAD_MSG_TOO_LONG, SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INCOMPATIBLE_KEY,
    /*SC_ERROR_WRONG_PADDING,*/SC_ERROR_WRONG_CARD, SC_ERROR_WRONG_PADDING, SC_ERROR_INCORRECT_PARAMETERS};
use opensc_sys::internal::{_sc_card_add_rsa_alg/*, sc_pkcs1_encode*/};
#[cfg(not(any(v0_15_0, v0_16_0)))]
use opensc_sys::internal::{_sc_match_atr};
/*  for feature(const_fn)
#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
use opensc_sys::internal::{sc_atr_table};
*/

use opensc_sys::log::{sc_do_log, sc_dump_hex, SC_LOG_DEBUG_NORMAL};
use opensc_sys::cardctl::{SC_CARDCTL_GET_SERIALNR};
use opensc_sys::asn1::{sc_asn1_find_tag/*, sc_asn1_skip_tag, sc_asn1_read_tag, sc_asn1_print_tags*/};
use opensc_sys::iso7816::{ISO7816_TAG_FCP_TYPE, ISO7816_TAG_FCP_LCS};
use opensc_sys::pkcs15::{sc_pkcs15_pubkey_rsa, sc_pkcs15_bignum, sc_pkcs15_encode_pubkey_rsa};


#[allow(dead_code)]
pub mod cmd_card_info;
use crate::cmd_card_info::*;

#[allow(dead_code)]
pub mod constants_types;
use crate::constants_types::*;

#[allow(dead_code)]
pub mod missing_exports;
use crate::missing_exports::*;

#[allow(dead_code)]
pub mod no_cdecl;
use crate::no_cdecl::{select_file_by_path, convert_bytes_tag_fcp_sac_to_scb_array, enum_dir,
    pin_get_policy, track_iso7816_select_file, acos5_64_atrs_supported,
                      /*encrypt_public_rsa,*/ get_rsa_algo_flags,
    set_is_running_cmd_long_response, get_is_running_cmd_long_response, is_any_of_di_by_len};
// choose new name ? denoting, that there are rust-mangled, non-externC functions, that don't relate to se
// (security environment) nor relate to sm (secure messaging) nor relate to pkcs15/pkcs15-init

#[allow(dead_code)]
pub mod path;
use crate::path::*;

#[allow(dead_code)]
pub mod se;
use crate::se::{se_file_add_acl_entry};

#[allow(dead_code)]
pub mod wrappers;
use crate::wrappers::*;


/* #[no_mangle] pub extern fn  is the same as  #[no_mangle] pub extern "C" fn
   for the time being, be explicit using  #[no_mangle] pub extern "C" fn */


/// A mandatory library export
/// @apiNote  If @return doesn't match the version of OpenSC binary libopensc.so/dll, this library
///           will be unloaded immediately; depends on build.rs setup ref. "cargo:rustc-cfg=v0_??_0".
///           Current auto-adaption to binary version in build.rs (for pkg-config supporting OS) may not be correct
///           for OpenSC master code not yet inspected. auto-adaption for OpenSC 0.15.0 - 0.19.0 is okay
/// @return   The OpenSC release version, that this driver implementation supports
#[no_mangle]
pub extern "C" fn sc_driver_version() -> *const c_char {
    if       cfg!(v0_15_0) { CStr::from_bytes_with_nul(b"0.15.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_16_0) { CStr::from_bytes_with_nul(b"0.16.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_17_0) { CStr::from_bytes_with_nul(b"0.17.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_18_0) { CStr::from_bytes_with_nul(b"0.18.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_19_0) { CStr::from_bytes_with_nul(b"0.19.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_20_0) { CStr::from_bytes_with_nul(b"0.20.0\0").unwrap().as_ptr() }
    else                   { CStr::from_bytes_with_nul(b"0.0.0\0" ).unwrap().as_ptr() }
}


/// A mandatory library export
/// @apiNote TODO inspect behavior in multi-threading context
/// @param   name passed in by OpenSC (acc. opensc.conf: assoc. 'acos5_64' <-> ATR or card_driver acos5_64 {...})
/// @return  function pointer; calling that returns acos5_64's sc_card_driver struct address
#[no_mangle]
pub extern "C" fn sc_module_init(name: *const c_char) -> *mut c_void {
    let func_ptr =
        if unsafe { CStr::from_ptr(name) } == CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap() {
            acos5_64_get_card_driver
        }
        else {
            unsafe { std::mem::transmute::<usize, extern "C" fn() -> *mut sc_card_driver>(0) }
        };
    func_ptr as *mut c_void
}



/*
 * What it does
 * @apiNote
 * @return
 */
extern "C" fn acos5_64_get_card_driver() -> *mut sc_card_driver
{
/*
static struct sc_card_operations iso_ops = {
    no_match,
    iso7816_init,    /* init   */
    NULL,            /* finish */
    iso7816_read_binary,
    iso7816_write_binary,
    iso7816_update_binary,
    NULL,            /* erase_binary */
    iso7816_read_record,
    iso7816_write_record,
    iso7816_append_record,
    iso7816_update_record,
    iso7816_select_file,
    iso7816_get_response,
    iso7816_get_challenge,
    NULL,            /* verify */
    NULL,            /* logout */
    iso7816_restore_security_env,
    iso7816_set_security_env,
    iso7816_decipher,
    iso7816_compute_signature,
    NULL,            /* change_reference_data */
    NULL,            /* reset_retry_counter   */
    iso7816_create_file,
    iso7816_delete_file,
    NULL,            /* list_files */
    iso7816_check_sw,
    NULL,            /* card_ctl */
    iso7816_process_fci,
    iso7816_construct_fci,
    iso7816_pin_cmd,
    iso7816_get_data,
    NULL,            /* put_data */
    NULL,            /* delete_record */
    NULL,            /* read_public_key */
    NULL,            /* card_reader_lock_obtained */
    NULL,            /* wrap */
    NULL             /* unwrap */
};
*/
    let iso_ops: sc_card_operations = unsafe { *(*sc_get_iso7816_driver()).ops };
    /* SM: all usages of iso7816_ functions must be re-evaluated for the subset, that ACOS5-64 can alternatively support via SM */
    let b_sc_card_operations : Box<sc_card_operations> = Box::new( sc_card_operations {
        match_card:            Some(acos5_64_match_card),        // no_match     is insufficient for cos5: It just doesn't match any ATR
        init:                  Some(acos5_64_init),              // iso7816_init is insufficient for cos5: It just returns SC_SUCCESS without doing anything
        finish:                Some(acos5_64_finish),            // NULL
        /* when SM get's introduced for SM mode acl, all SM-capable file ops binary/record must be replaced */
        select_file:           Some(acos5_64_select_file),       // iso7816_select_file is insufficient for cos5: It will be used, but in a controlled manner only
        get_response:          Some(acos5_64_get_response),      // iso7816_get_response is insufficient for some cos5 commands with more than 256 bytes to fetch
        /* get_challenge:  iso7816_get_challenge  is usable, but only with P3==8, thus a wrapper is required */
        get_challenge:         Some(acos5_64_get_challenge),     // iso7816_get_challenge
        /* verify:                                                 NULL, deprecated */
        /* logout:         Some(acos5_64_logout),                // NULL */
        restore_security_env:  None,                             // iso7816_restore_security_env
        set_security_env:      Some(acos5_64_set_security_env),  // iso7816_set_security_env
            /* iso7816_set_security_env doesn't work for signing; do set CRT B6 and B8 */
        decipher:              Some(acos5_64_decipher),          // iso7816_decipher,  not suitable for cos5
        compute_signature:     Some(acos5_64_compute_signature), // iso7816_compute_signature,  not suitable for cos5
        /* change_reference_data: NULL, deprecated */
        /* reset_retry_counter:   NULL, deprecated */
        /* create_file: iso7816_create_file  is usable, provided that construct_fci is suitable */
        /* delete_file: iso7816_delete_file  is usable, BUT pay ATTENTION, how path.len selects among alternatives;
                        AND, even with path, it must first be selected */
        list_files:            Some(acos5_64_list_files),        // NULL
        /* check_sw:                                         // iso7816_check_sw
            iso7816_check_sw basically is usable except that for pin_cmd cmd=SC_PIN_CMD_GET_INFO, the correct answer like
            0x63C8 (8 tries left) is interpreted as a failing pin verification trial (SC_ERROR_PIN_CODE_INCORRECT)
            thus trying to go with iso7816_check_sw, reroute that pin_cmd cmd=SC_PIN_CMD_GET_INFO to not employ check_sw
           TODO  iso7816_check_sw has an internal table to map return status to text: this doesn't match the ACOS5 mapping in some cases, THUS maybe switching on/off check_sw==iso7816_check_sw may be required
        */
        card_ctl:              Some(acos5_64_card_ctl),          // NULL
        process_fci:           Some(acos5_64_process_fci),       // iso7816_process_fci is insufficient for cos5: It will be used, but more has to be done for cos5
        /* construct_fci: iso7816_construct_fci, */
        pin_cmd:               Some(acos5_64_pin_cmd),           // iso7816_pin_cmd
            /* pin_cmd:
            SC_PIN_CMD_GET_INFO: iso7816_pin_cmd not suitable for SC_PIN_CMD_GET_INFO (only because the status word is
                                   mis-interpreted by iso7816_check_sw as failed pin verification)
            SC_PIN_CMD_VERIFY:   iso7816_pin_cmd is okay for  SC_PIN_CMD_VERIFY
            SC_PIN_CMD_CHANGE:   iso7816_pin_cmd is okay for  SC_PIN_CMD_CHANGE
            SC_PIN_CMD_UNBLOCK:  iso7816_pin_cmd is okay for  SC_PIN_CMD_UNBLOCK
            */
        get_data:              None,                         // iso7816_get_data may be sufficient?, but will be turned into unsupported: no reading of sensitive sym./asym. key data allowed, even if possible
                                                             // The public key file also is readable only by cos5 command 'Get Key': handle this separately; opensc erroneously uses sc_read_binary for that
        /* put_data:                                            NULL, */
        /* delete_record:                                       NULL, */
        read_public_key:       Some(acos5_64_read_public_key),   // NULL
        /* card_reader_lock_obtained:                           NULL, */
        /* wrap:                                                NULL, */
        /* unwrap:                                              NULL, */

        ..iso_ops // untested so far whether functionality from iso is sufficient for cos5
    } );

    let b_sc_card_driver : Box<sc_card_driver> = Box::new( sc_card_driver {
        name:       CStr::from_bytes_with_nul(CARD_DRV_NAME).unwrap().as_ptr(),
        short_name: CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap().as_ptr(),
        ops:        Box::into_raw(b_sc_card_operations),
        ..Default::default()
    } );
    Box::into_raw(b_sc_card_driver)
}


/*
match_card as other cards do,
(based on ATR from driver and/or opensc.conf? )
additionally optional:
exclude non-64K, i.e. exclude
V2: 32K mode

V3: 32K mode
V3: FIPS mode
V3: Brasil mode

additionally optional:
check cos version

additionally optional:
check operation Mode Byte Setting for V3

TODO how to set opensc.conf, such that a minimum of trials to match atr is done
*/
/**
 *  @param  card  sc_card object (treated as *const sc_card)
 *  @return 1 on succcess i.e. card did match, otherwise 0
 */
/*
 * Implements sc_card_operations function 'match_card'
 * @see opensc_sys::opensc pub struct sc_card_operations
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_match_card(card: *mut sc_card) -> c_int
{
    if card.is_null() {
        return 0;
    }

    let card_ref     : &sc_card     = unsafe { &    *card };
    let card_ref_mut : &mut sc_card = unsafe { &mut *card };

    let file = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_match_card\0").unwrap();
    if cfg!(log) {
        let fmt  = CStr::from_bytes_with_nul(b"called. Try to match card with ATR %s\0").unwrap();
        wr_do_log_t(card_ref.ctx, file, line!(), fun, fmt,
                    unsafe { sc_dump_hex(card_ref.atr.value.as_ptr(), card_ref.atr.len) } );
    }

    #[cfg(any(v0_17_0, v0_18_0))]
    let mut acos5_64_atrs = acos5_64_atrs_supported();
    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
//    const   acos5_64_atrs : [sc_atr_table; 3] = acos5_64_atrs_supported();
    let     acos5_64_atrs = acos5_64_atrs_supported();
    /* check whether card.atr can be found in acos5_64_atrs_supported[i].atr, iff yes, then
       card.type_ will be set accordingly, but not before the successful return of match_card */
    let mut type_out : c_int = 0;
    #[cfg(any(v0_15_0, v0_16_0))]
    let idx_acos5_64_atrs = -1; // no match, because: _sc_match_atr is not callable: OpenSC not patched / not implemented
    #[cfg(any(v0_17_0, v0_18_0))]
    let idx_acos5_64_atrs = unsafe { _sc_match_atr(card_ref_mut, (&mut acos5_64_atrs).as_mut_ptr(), &mut type_out) };
    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
    let idx_acos5_64_atrs = unsafe { _sc_match_atr(card_ref_mut, (   & acos5_64_atrs).as_ptr(),     &mut type_out) };
////    println!("idx_acos5_64_atrs: {}, card.type_: {}, type_out: {}, &card.atr.value[..19]: {:?}\n", idx_acos5_64_atrs, card_ref.type_, type_out, &card_ref.atr.value[..19]);

    card_ref_mut.type_ = 0;

    if idx_acos5_64_atrs < 0 || idx_acos5_64_atrs+2 > acos5_64_atrs.len() as i32 {
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"Card doesn't match: Differing ATR\0").unwrap();
            wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
        }
        return 0;
    }
    let idx_acos5_64_atrs = idx_acos5_64_atrs as usize;

    /* check for 'Identity Self' */
    match get_ident_self(card_ref_mut) {
        Ok(val) => if !val { return 0; },
        Err(e) => { return e; },
    };

    /*  testing area for acos5_64_card_ctl * /
        let mut cos_version : CardCtlArray8 = Default::default();
        let rv = acos5_64_card_ctl(card_ref_mut, SC_CARDCTL_GET_COS_VERSION,
                                   &mut cos_version as *mut CardCtlArray8 as *mut c_void);
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"cos_version: %02X %02X %02X %02X %02X %02X %02X %02X (rv %d)\0").unwrap();
            wr_do_log_8u8_i32(card_ref.ctx, file, line!(), fun, fmt, cos_version.value, rv);
        }
    / * */


    /* * / //optional checks
    /* check for 'Card OS Version' */
    let rbuf_card_os_version = match get_cos_version(card_ref_mut) {
        Ok(val) => val,
        Err(e) => return e,
    };

    //    println!("rbuf_card_os_version: {:?}", &rbuf_card_os_version[..]);
    // rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05, 0x02, 0x00, 0x40] from Cryptomate64  b"ACOS___@"
    // rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05, 0x03, 0x01, 0x40] from CryptoMate Nano in op mode 64 K
    // rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05, 0x03, 0x00, 0x40] from CryptoMate Nano in op mode FIPS
        if rbuf_card_os_version[..5] != [0x41u8, 0x43, 0x4F, 0x53, 0x05] || rbuf_card_os_version[7] !=  0x40
        {
            if cfg!(log) {
                let fmt = CStr::from_bytes_with_nul(b"Card doesn't match: sc_transmit_apdu or ACOS5-64 'Card OS Version'\
                    -check failed\0").unwrap();
                wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
            }
            return 0;
        }
        match type_out {
            /* rbuf_card_os_version[5] is the major version */
            /* rbuf_card_os_version[6] is the minor version
               probably minor version reflects the  'Operation Mode Byte Setting',
               thus relax req. for SC_CARD_TYPE_ACOS5_64_V3, iff FIPS mode should ever be supported */
            SC_CARD_TYPE_ACOS5_64_V2  =>  { if rbuf_card_os_version[5] != 2    ||  rbuf_card_os_version[6] != 0    { return 0; } },
            SC_CARD_TYPE_ACOS5_64_V3  =>  { if rbuf_card_os_version[5] != 3 /* ||  rbuf_card_os_version[6] != 1 */ { return 0; } },
             _                             =>  { return 0; },
        }

        /* excludes any mode except 64K (no FIPS, no 32K, no brasil) */
        if type_out == SC_CARD_TYPE_ACOS5_64_V3 {

            /* check 'Operation Mode Byte Setting', must be set to  */
            let op_mode_byte = match get_op_mode_byte(card_ref_mut) {
                Ok(op_mb) => op_mb,
                Err(_err) =>  0x7FFF_FFFFu32,
            };

            if op_mode_byte != 2 {
                if cfg!(log) {
                    let fmt = CStr::from_bytes_with_nul(b"ACOS5-64 v3.00 'Operation mode==Non-FIPS (64K)'-check failed. Trying to change the mode of operation to Non-FIPS/64K mode (no other mode is supported currently)....\0").unwrap();
                    wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
                }
                // FIXME try to change the operation mode byte if there is no MF
                let mf_path_ref: &sc_path = unsafe { &*sc_get_mf_path() };
                let mut file : *mut sc_file = std::ptr::null_mut();
                let mut rv = unsafe { sc_select_file(card_ref_mut, mf_path_ref, &mut file) };
                println!("rv from sc_select_file: {}, file: {:?}", rv, file); // rv from sc_select_file: -1200, file: 0x0
                let fmt = CStr::from_bytes_with_nul(b"Card doesn't match: sc_transmit_apdu or 'change to operation mode 64K' failed ! Have a look into docs how to change the mode of operation to Non-FIPS/64K mode. No other mode is supported currently\0").unwrap();
                if rv == SC_SUCCESS {
                    #[cfg(log)]
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
                    return 0;
                }
                // if sc_select_file failed, try to write value 2 to address 0xC191
                let command : [u8; 6] = [0u8, 0xD6, 0xC1, 0x91, 0x01, 0x02];
                let mut apdu = Default::default();
                rv = sc_bytes2apdu_wrapper(card_ref.ctx, &command, &mut apdu);
                assert_eq!(rv, SC_SUCCESS);
                assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
                rv = unsafe { sc_transmit_apdu(card_ref_mut, &mut apdu) };
                if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
                    #[cfg(log)]
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
                    return 0;
                }
                else {
                    let fmt = CStr::from_bytes_with_nul(b"Card was set to Operation Mode 64K (SUCCESS) !\0").unwrap();
                    #[cfg(log)]
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
                }
            }
        }
    / **/

    // Only now, on success,   set card.type
    card_ref_mut.type_ = type_out;
    if cfg!(log) {
        let fmt = CStr::from_bytes_with_nul(b"'%s' card matched\0").unwrap();
        wr_do_log_t(card_ref.ctx, file, line!(), fun, fmt, acos5_64_atrs[idx_acos5_64_atrs].name);
    }
    1
}


/*
what can we rely on, when this get's called:
1. card.atr  was set
2. card.type was set by match_card, but it may still be incorrect, as a forced_card driver ignores
     a no-match on ATR and nevertheless calls init, thus rule out non-matching ATR card finally here
*/
/**
 *  @param  card  struct sc_card object
 *  @return SC_SUCCESS or error code from errors.rs
 */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_init(card: *mut sc_card) -> c_int
{
    if card.is_null() {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let card_ref:         &sc_card = unsafe { &    *card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };

    let file = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_init\0").unwrap();
    if cfg!(log) {
        let fmt = CStr::from_bytes_with_nul(b"called with card.type: %d, card.atr.value: %s\0").unwrap();
        wr_do_log_tu(card_ref.ctx, file, line!(), fun, fmt,  card_ref.type_,
                     unsafe { sc_dump_hex(card_ref.atr.value.as_ptr(), card_ref.atr.len) });
    }
    /* Undo 'force_card_driver = acos5_64;'  if the ATR doesn't match with acos5_64_atrs_supported */
    for elem in &acos5_64_atrs_supported() {
        if elem.atr.is_null() {
            if cfg!(log) {
                let fmt = CStr::from_bytes_with_nul(b"### Error, have to skip external driver 'acos5_64'! \
                    Got here, though the ATR doesn't match (probably by using 'force_card_driver = acos5_64;') ###\0")
                    .unwrap();
                wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
            }
            return SC_ERROR_WRONG_CARD;
        }
        if elem.type_ == card_ref.type_ {
            card_ref_mut.name = elem.name;
            card_ref_mut.flags = elem.flags; // FIXME maybe omit her and set later
            break;
        }
    }

    unsafe{sc_format_path(CStr::from_bytes_with_nul(b"3F00\0").unwrap().as_ptr(), &mut card_ref_mut.cache.current_path);} // type = SC_PATH_TYPE_PATH;
    card_ref_mut.cla  = 0x00;                                        // int      default APDU class (interindustry)
    card_ref_mut.max_send_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; // 0x0FF; // 0x0FFFF for usb-reader, 0x0FF for chip/card;  Max Lc supported by the card
    card_ref_mut.max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE; // reduced as long as iso7816_read_binary is used: 0==0x100 is not understood // 0x100; // 0x10000 for usb-reader, 0x100 for chip/card;  Max Le supported by the card, decipher (in chaining mode) with a 4096-bit key returns 2 chunks of 256 bytes each !!

    /* possibly more SC_CARD_CAP_* apply, TODO clarify */
    card_ref_mut.caps = (SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC) as c_ulong;
    if cfg!(not(    v0_15_0))           { card_ref_mut.caps |=  SC_CARD_CAP_ISO7816_PIN_INFO as c_ulong; }
    if cfg!(not(any(v0_15_0, v0_16_0))) { card_ref_mut.caps |=  SC_CARD_CAP_SESSION_PIN      as c_ulong; }
    /* card_ref_mut.caps |= SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH   what exactly is this? */ //#[cfg(not(any(v0_15_0, v0_16_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_ONCARD_SESSION_OBJECTS          what exactly is this? */ //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_WRAP_KEY */    //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_UNWRAP_KEY */  //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* The reader of USB CryptoMate64/CryptoMate Nano supports extended APDU, but the card doesn't: Thus no SC_CARD_CAP_APDU_EXT */

    /*
       ATTENTION with rsa_algo_flags here (for _sc_card_add_rsa_alg):
       acos5_64_decipher and acos5_64_compute_signature functions MUST somehow get the information about the RSA modulus length in bytes because the ACOS5 command  'get_response'
       works differently than OpenSC expects: 'get_response' doesn't inform about how many bytes are left to retrieve, if modulus length>256 !
       For e.g. (1792 bit) modulus length==224, those functions send once 0x61E0 and iso7816_get_response does work, because it gets the info about 224 bytes to fetch.
       For      (2048 bit) modulus length==256, those functions send once 0x6100 and iso7816_get_response does work, because it interprets 0x00 as 256.
       For e.g. (2304 bit) modulus length==288, those functions send once 0x6100 and iso7816_get_response doesn't work any more, because it won't know about 32 bytes more than 256 bytes to fetch.

       OpenSC sets out_bufferLen inconsistently either equal to modulus length or greater for sc_compute_signature and sc_decipher, thus the only way to get the info about keyLen is via inLen to
       functions sc_compute_signature and sc_decipher, i.e. the driver MUST get inData that are padded already by OpenSC (resulting in inLen==modulus length).
       Since current master, SC_ALGORITHM_RSA_PAD_NONE==SC_ALGORITHM_RSA_RAW==1, thus exactly only SC_ALGORITHM_RSA_PAD_NONE would be enough for our purpose !
       Release versions up to 0.19.0
       Setting any of SC_ALGORITHM_RSA_PADS, SC_ALGORITHM_RSA_PAD_PKCS1, SC_ALGORITHM_RSA_PAD_ANSI, SC_ALGORITHM_RSA_PAD_ISO9796, SC_ALGORITHM_RSA_PAD_PSS  is wrong for our purpose

       cos5 natively supports PKCS #1 padding and ISO 9796-2 scheme 1 padding
       possibly the driver will support more padding schemes
       TODO support PSS signature scheme
    */

    let mut rsa_algo_flags = SC_ALGORITHM_ONBOARD_KEY_GEN;
    /* card or driver does not do the padding before compute_signature, but expects OpenSC to supply the padding:
       Thus inLen==keyLen */
//  #[cfg(    any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))]
    rsa_algo_flags |= SC_ALGORITHM_RSA_RAW;
    rsa_algo_flags |= SC_ALGORITHM_RSA_PAD_NONE; // for cfg!(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)) this is a NOOP, as SC_ALGORITHM_RSA_PAD_NONE is zero then

    /* alternatively, since acos5_64_compute_signature is adaptive to SC_ALGORITHM_RSA_PAD_PKCS1, select that padding method:
    driver will do the padding, thus will receive from OpenSC the digestInfo only, but this doesn't always work: It
    requires, that outLen==keyLen, but some OpenSC code doesn't comply  TODO locate and PR the bug * /

    rsa_algo_flags |= SC_ALGORITHM_RSA_PAD_PKCS1;  / * */

    /* SC_ALGORITHM_NEED_USAGE : Don't use that: the driver will handle that for sign internally ! */
    /* Though there is now some more hash related info in opensc.h, still it's not clear to me whether to apply any of
         SC_ALGORITHM_RSA_HASH_NONE or SC_ALGORITHM_RSA_HASH_SHA256 etc. */

    /* */
    let is_v3_fips_compliant = card_ref.type_ == SC_CARD_TYPE_ACOS5_64_V3 &&
        get_op_mode_byte(card_ref_mut).unwrap()==0 && get_fips_compliance(card_ref_mut).unwrap();
    let mut rv;
    let     rsa_key_len_from = if is_v3_fips_compliant {2048u32} else { 512u32};
    let     rsa_key_len_step = if is_v3_fips_compliant {1024u32} else { 256u32};
    let     rsa_key_len_to   = if is_v3_fips_compliant {3072u32} else {4096u32};
    let mut rsa_key_len = rsa_key_len_from;
    while   rsa_key_len <= rsa_key_len_to {
        rv = unsafe { _sc_card_add_rsa_alg(card_ref_mut, rsa_key_len, rsa_algo_flags as c_ulong, 0/*0x10001*/) };
        if rv != SC_SUCCESS {
            return rv;
        }
        rsa_key_len += rsa_key_len_step;
    }

/*
    missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_DES,   56); // input with effective key_length as required by tool pkcs11-init; key value will be transformed to des/64 odd parity
    missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_DES,   64); // input interpreted as given as des/64,   NOT cheked for odd parity
//missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 112);
    missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 128); // input interpreted as given as 3des/128, NOT cheked for odd parity
//missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 168);
    missingExport_sc_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 192); // input interpreted as given as 3des/192, NOT cheked for odd parity
*/
    if cfg!(not(any(v0_15_0, v0_16_0))) {
        let aes_algo_flags = SC_ALGORITHM_AES;
//        if cfg!(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))) {
//            aes_algo_flags |= SC_ALGORITHM_AES_FLAGS;
//        }

        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  128, aes_algo_flags);
        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  192, aes_algo_flags);
        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  256, aes_algo_flags);
    }
/*
OpenSC v0.19.0:

user@host:~$ pkcs11-tool --list-mechanisms
Using slot 0 with a present token (0x0)
Supported mechanisms:
  SHA-1, digest
  SHA256, digest
  SHA384, digest
  SHA512, digest
  MD5, digest
  RIPEMD160, digest
  GOSTR3411, digest
  RSA-X-509, keySize={,4096}, hw, decrypt, sign, verify
  RSA-PKCS, keySize={,4096}, hw, decrypt, sign, verify
  SHA1-RSA-PKCS, keySize={,4096}, sign, verify
  RIPEMD160-RSA-PKCS, keySize={,4096}, sign, verify
  RSA-PKCS-PSS, keySize={,4096}, hw, sign
  SHA1-RSA-PKCS-PSS, keySize={,4096}, sign
  RSA-PKCS-KEY-PAIR-GEN, keySize={,4096}, generate_key_pair

user@host:~$ p11tool --list-mechanisms pkcs11:model=PKCS%2315;manufacturer=Advanced%20Card%20Systems%20Ltd.;
  [0x0220] CKM_SHA_1
  [0x0250] CKM_SHA256
[0x0260] CKM_SHA384                <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
  [0x0270] CKM_SHA512
  [0x0210] CKM_MD5
[0x0240] CKM_RIPEMD160             <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x1210] CKM_GOSTR3411             <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
  [0x0003] CKM_RSA_X_509
  [0x0001] CKM_RSA_PKCS
  [0x0006] CKM_SHA1_RSA_PKCS
  [0x0040] CKM_SHA256_RSA_PKCS
[0x0042] CKM_SHA512_RSA_PKCS       <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x000d] CKM_RSA_PKCS_PSS          <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x000e] CKM_SHA1_RSA_PKCS_PSS     <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x0043] CKM_SHA256_RSA_PKCS_PSS   <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
  [0x0000] CKM_RSA_PKCS_KEY_PAIR_GEN

{
since OpenSC v0.20.0 (==git-master, Latest commit 65a86b8):
[0x0255] CKM_SHA224                <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x0005] CKM_MD5_RSA_PKCS          <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
[0x0045] CKM_SHA512_RSA_PKCS_PSS   <= opensc-pkcs11.so supports this, but libacospkcs11.so doesn't
  [0x1081] CKM_AES_ECB             <= new
  [0x1082] CKM_AES_CBC             <= new
  [0x1085] CKM_AES_CBC_PAD         <= new
}

user@host:~$ p11tool --list-mechanisms pkcs11:model=CTM64;manufacturer=Advanced%20Card%20Systems%20Ltd.;
  [0x0000] CKM_RSA_PKCS_KEY_PAIR_GEN
  [0x0001] CKM_RSA_PKCS
  [0x0003] CKM_RSA_X_509
  [0x0220] CKM_SHA_1
  [0x0210] CKM_MD5
  [0x0250] CKM_SHA256
  [0x0270] CKM_SHA512
  [0x1081] CKM_AES_ECB         <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't up to v0.19.0
  [0x1082] CKM_AES_CBC         <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't up to v0.19.0
  [0x1085] CKM_AES_CBC_PAD     <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't up to v0.19.0
[0x0121] CKM_DES_ECB           <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0122] CKM_DES_CBC           <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0125] CKM_DES_CBC_PAD       <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0132] CKM_DES3_ECB          <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0133] CKM_DES3_CBC          <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0136] CKM_DES3_CBC_PAD      <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1080] CKM_AES_KEY_GEN       <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0120] CKM_DES_KEY_GEN       <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0130] CKM_DES2_KEY_GEN      <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x0131] CKM_DES3_KEY_GEN      <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1101] CKM_DES_CBC_ENCRYPT_DATA   <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1100] CKM_DES_ECB_ENCRYPT_DATA   <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1102] CKM_DES3_ECB_ENCRYPT_DATA  <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1103] CKM_DES3_CBC_ENCRYPT_DATA  <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1104] CKM_AES_ECB_ENCRYPT_DATA   <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
[0x1105] CKM_AES_CBC_ENCRYPT_DATA   <= libacospkcs11.so supports this, but opensc-pkcs11.so doesn't
  [0x0040] CKM_SHA256_RSA_PKCS
  [0x0006] CKM_SHA1_RSA_PKCS
[0x80000001] UNKNOWN                some CKM_VENDOR_DEFINED ?


file 5032 before changes applied (stripping any supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL.  thus there will be no (possibly conflicting info from there):
30 74 02 01 01 04 06 serial no 6 bytes 0C 1A 41
64 76 61 6E 63 65 64 20 43 61 72 64 20 53 79 73
74 65 6D 73 20 4C 74 64 2E 80 12 43 54 4D 36 34
5F serial no bin              12 bytes 03 02 05
20 A2 33 30 0F 02 01 01 02 01 00 05 00 03 02 00
01 02 01 10 30 0F 02 01 02 02 01 01 05 00 03 02
00 5C 02 01 10 30 0F 02 01 03 02 01 0E 05 00 03
02 00 50 02 01 10

file 5032 after stripping any supportedAlgorithms [2] SEQUENCE OF AlgorithmInfo OPTIONAL.  thus there will be no (possibly conflicting info from there):
30 3F 02 01 01 04 06 00 00 00 00 00 00 0C 1A 41
64 76 61 6E 63 65 64 20 43 61 72 64 20 53 79 73
74 65 6D 73 20 4C 74 64 2E 80 12 43 54 4D 36 34
5F 30 30 30 30 30 30 30 30 30 30 30 30 03 02 04
20

SEQUENCE (5 elem)
  INTEGER 1
  OCTET STRING (6 byte) 000000000000
  UTF8String Advanced Card Systems Ltd.
  [0] CTM64_000000000000
  BIT STRING (4 bit) 0010

*/
////////////////////////////////////////
    let mut files : HashMap<KeyTypeFiles, ValueTypeFiles> = HashMap::with_capacity(50);
    files.insert(0x3F00, (
        [0u8; SC_MAX_PATH_SIZE],
        [0x3F, 0xFF, 0x3F, 0x00, 0x00, 0x00, 0xFF, 0xFF], // File Info, 0xFF are incorrect byte settings, corrected later
        None, //Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), // scb8, ditto. concerning 0xFF
        None, // Some(vec_seinfo), // None
    ));

    let dp = Box::new( DataPrivate {
        files,
        rsa_algo_flags, // remember the padding scheme etc. selected for RSA; required in acos5_64_set_security_env
        is_running_init: true,
        is_running_cmd_long_response: false,
/*        is_running_compute_signature: false, // maybe, acos5_64_decipher will need to know, that it was called by
          acos5_64_compute_signature */
    } );

    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
/*
    let format = CStr::from_bytes_with_nul(b"##### No select_file should have been called so far #####\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr()) };
*/
    let mut path : sc_path = Default::default();
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F00\0").unwrap().as_ptr(), &mut path); } // type = SC_PATH_TYPE_PATH;
    let rv = enum_dir(card_ref_mut, &path/*, 0*/); /* FIXME Doing to much here degrades performance, possibly for no value */
/*  some code fragments, left for possible reuse ?
    for key in files.keys() {
        println!("Hashmap key: {:X?}, len: {:X}", &key[0..key[16] as usize], key[16]);
    }

    println!("Hashmap: {:?}", files);

    let iso_ops: sc_card_operations  = unsafe { *(*sc_get_iso7816_driver()).ops };
    let y :  Box<sc_card_operations> = Box::new(iso_ops);
    iso_ops_ptr: Box::into_raw(y), // *mut sc_card_operations

    let rv = check_file_system(card_ref_mut);
*/

    let mut dp : Box<DataPrivate> = unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };
    dp.files.shrink_to_fit();
    dp.is_running_init = false;
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
    rv
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_finish(card: *mut sc_card) -> c_int
{
    if card.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref     : &sc_card     = unsafe { &*card };
    let card_ref_mut : &mut sc_card = unsafe { &mut *card };

    let file = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_finish\0").unwrap();
    if cfg!(log) {
        let fmt  = CStr::from_bytes_with_nul(CALLED).unwrap();
        wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
    }

    assert!(!card_ref.drv_data.is_null(), "drv_data is null");
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card_ref.drv_data as *mut DataPrivate) };
//    println!("Hashmap: {:?}", dp.files);
//    there may be other Boxes that might need to be taken over again
    drop(dp);
    card_ref_mut.drv_data = std::ptr::null_mut();
    SC_SUCCESS
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_card_ctl(card: *mut sc_card, command: c_ulong, data: *mut c_void) -> c_int
{
    assert!(!card.is_null());
//    let card_ref = unsafe { &*card };
    let card_ref_mut = unsafe { &mut *card };

    match command as c_uint {
        SC_CARDCTL_GET_SERIALNR =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let serial_number = match get_serialnr(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_sc_serial_number = data as *mut sc_serial_number;
                unsafe { *ptr_sc_serial_number = serial_number };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_COUNT_FILES_CURR_DF=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let count_files_curr_df = match get_count_files_curr_df(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_size_t = data as *mut usize;
                unsafe { *ptr_size_t = count_files_curr_df };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_FILE_INFO=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let ptr_file_info = data as *mut CardCtlArray8;
                let reference = unsafe { (*ptr_file_info).reference };
                let file_info = match get_file_info(card_ref_mut, reference) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                unsafe { (*ptr_file_info).value = file_info };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_FREE_SPACE=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let free_space = match get_free_space(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_c_uint = data as *mut c_uint;
                unsafe { *ptr_c_uint = free_space };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_IDENT_SELF=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let is_hwacos5_64 = match get_ident_self(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_c_uint = data as *mut c_uint;
                unsafe { *ptr_c_uint = if is_hwacos5_64 {1} else {0} };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_COS_VERSION=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let cos_version = match get_cos_version(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_cos_version = data as *mut CardCtlArray8;
                unsafe { (*ptr_cos_version).value = cos_version };
                SC_SUCCESS
            },


        SC_CARDCTL_GET_ROM_MANUFACTURE_DATE=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let manufacture_date = match get_manufacture_date(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_c_uint = data as *mut c_uint;
                unsafe { *ptr_c_uint = manufacture_date };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_ROM_SHA1=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let rom_sha1 = match get_rom_sha1(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_rom_sha1 = data as *mut CardCtlArray20;
                unsafe { (*ptr_rom_sha1).value = rom_sha1 };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_OP_MODE_BYTE=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let op_mode_byte = match get_op_mode_byte(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_c_uint = data as *mut c_uint;
                unsafe { *ptr_c_uint = op_mode_byte };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_FIPS_COMPLIANCE =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let is_fips_compliant = match get_fips_compliance(card_ref_mut) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                let ptr_c_uint = data as *mut c_uint;
                unsafe { *ptr_c_uint = if is_fips_compliant {1} else {0} };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_PIN_AUTH_STATE=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let ptr_pin_auth_state = data as *mut CardCtlAuthState;
                let reference = unsafe { (*ptr_pin_auth_state).reference };
                let pin_auth_state = match get_pin_auth_state(card_ref_mut, reference) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                unsafe { (*ptr_pin_auth_state).value = pin_auth_state };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_KEY_AUTH_STATE=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let ptr_key_auth_state = data as *mut CardCtlAuthState;
                let reference = unsafe { (*ptr_key_auth_state).reference };
                let key_auth_state = match get_key_auth_state(card_ref_mut, reference) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                unsafe { (*ptr_key_auth_state).value = key_auth_state };
                SC_SUCCESS
            },
        SC_CARDCTL_GET_FILES_HASHMAP_INFO=>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let ptr_files_hashmap_info = data as *mut CardCtlArray32;
                let key = unsafe { (*ptr_files_hashmap_info).key };
                let files_hashmap_info = match get_files_hashmap_info(card_ref_mut, key) {
                    Ok(val) => val,
                    Err(e) => return e,
                };
                unsafe { (*ptr_files_hashmap_info).value = files_hashmap_info };
                SC_SUCCESS
            },
        SC_CARDCTL_UPDATE_FILES_HASHMAP =>
            {
                SC_ERROR_NO_CARD_SUPPORT
/*
                update_hashmap(card); // temporarily removed from  cmd_card_info.rs: Not yet ready
                SC_SUCCESS
*/
            },
        _   => SC_ERROR_NO_CARD_SUPPORT
    }
}

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_select_file(card: *mut sc_card, path: *const sc_path, file_out: *mut *mut sc_file) -> c_int
{
/*
  Basically, the iso implementation for select_file can work for acos (and always will finally be called), but only if given appropriate parameters.
  A small part of the following select_file implementation is dedicated to solve that, heading: use path.type_ == SC_PATH_TYPE_FILE_ID only.
  But other requirements make the implementation quite complex:
  1. It's necessary to ensure, that the file selected really resides at the given/selected location (path): If acos doesn't find a file within the selected directory,
     it will look-up several other paths, thus may find another one, not intended to be selected (acos allows duplicate file ids, given the containing directories differ).
     There is no way other than disallowing duplicate file/directory ids by the driver and to ensure rule compliance, also when updating by create_file and delete_file.
     Function acos5_64_init does invoke scanning the card's file system and populate a hash map with i.a. File Information from 'Get Card Info';
     The 'original' 8 bytes (unused will be replaced by other values) are: {FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI}> to hold all file ids as key,
     and will reject even a matching card that contains file id duplicate(s).
     TODO this is not enforced currently

  2. The access control implemented by acos also is quite complex: Security Attributes Compact (SAC) and Security Attributes Expanded (SAE) and boils down to this:
     Purely by selecting a file/directory, the information about 'rights for acos commands to be allowed to execute' is not complete but must be looked up, different for each directory.
     Thus it suggests itself to also employ a table like structure holding that information: On each selection of a directory, a look-up will be performed if the info is available, otherwise
     retrieved and stored to the table. Any commands that alter the relevant info source (Security Environment File and it's records) must also update the look up table.
     The source for SAE is coded within the directory's header meta data (immutable as long as the directory exists) and may also refer to the Security Environment File (with mutable data).

  3. As preface: acos uses the select command also for extraordinary tasks like 'Clear the internal memory collecting Control Reference Templates (CRT)' or revoke PIN/KEY access rigths etc.
     which must be emitted in order to take effect. On the other hand, with a simplistic impl. of select_file, it turns out that many select commands are superfluous: E.g. coming from selected path
     3F00410043004305 in order to select 3F00410043004307 (both files in the same directory) the simple impl. will select in turn 3F00, 4100, 4300 and finally 4307,
     though for acos it would be sufficient to issue select 4307 right away.
     Thus there will be some logic required (making use of acos 'search files at different places' capability to speed up performance and distinguish from cases,
     where selects must not be stripped off (i.e. when the selection path ends at a directory - even if it's the same as the actual - selection must not be skipped).
     For this, the info from 1. comes in handy.

     8.2.1.  Verify PIN
This command is used to submit a PIN code to gain access rights. Access rights achieved will be
invalidated when a new DF is selected. Command submission with P3=0 will return the remaining
number of retries left for the PIN.

There is an undocumented order dependence:
This works       :  select_file, verify_pin, set_security_env
This doesn't work:  select_file, set_security_env, verify_pin

     8.4.2.1.  Set Security Environment
To clear the accumulated CRT’s, issue a SELECT FILE command

  Format of HashMap<KeyTypeFiles, ValueTypeFiles> :
  pub type KeyTypeFiles   = u16;
  //                                 path (absolute)                 File Info        scb8                SeInfo
  pub type ValueTypeFiles = (Option<[u8; SC_MAX_PATH_SIZE]>, Option<[u8; 8]>, Option<[u8; 8]>, Option<Vec<SeInfo>>);
  1. tuple element: path, the absolute path, 16 bytes
  2. tuple element: originally it contains File Information from acos command 'Get Card Info': {FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI}
                    FDB: the File Descriptor Byte
                   *DCB (unused by acos): will be replaced by path.len of 1. tuple element, the len actually used for the path
                    FILE ID: 2 bytes containing the file id, the same as hash map entry's key
                   *SIZE or MRL: For record-based file types, the Max.Record Length, otherwise (if it's not MF/DF), the MSB of file size;
                                 for MF/DF, this byte holds MSB of associated SE file id
                   *SIZE or NOR: For record-based file types, the Number Of Records created for this file, otherwise (if it's not MF/DF), the LSB of file size;
                                 for MF/DF, this byte holds LSB of associated SE file id
                   *SFI  Short file Identifier (unused by the driver and opensc?): will be replaced by PKCS#15 file type
                    LCSI: Life Cycle Status Integer
  3. tuple element: scb8, 8 Security Condition Bytes after conversion, i.e. scb8[3..8] refer to Deactivate/SC_AC_OP_INVALIDATE, Activate/SC_AC_OP_REHABILITATE, Terminate/SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF, Unused Byte
(later here: sm_mode8: Coding Secure Messaging required or not, same operations referred to by position as in scb8, i.e. an SCB 0x45 will have set at same position in sm_mode8: Either SM_MODE_CCT or SM_MODE_CCT_AND_CT_SYM, depending on content of Security Environment file record id 5)
  4. tuple element: SeInfo referring to SAC (SAE is not covered so far)
                    Each vector element covers the content of Security Environment file's record, identified by reference==record's SE id (should be the same as record number)
                    SeInfo is stored for DF/MF only, each of which have different vectors
(later here: SaeInfo)




  If file_out != NULL then, as long as iso7816_select_file behavior is not mimiced completely, it's important to call iso7816_select_file finally: It will call process_fci
  and evaluate the file header bytes !
  Main reasons why this function exists:
    acos supports P2==0 and (P1==0 (SC_PATH_TYPE_FILE_ID) or P1==4 (SC_PATH_TYPE_DF_NAME)) only
  - Not all path.type_ are handled correctly for ACOS5-64 by iso7816_select_file (depending also on file_out):
    SC_PATH_TYPE_FILE_ID can be handled by iso7816_select_file (for file_out == NULL sets incorrectly sets p2 = 0x0C, but then on error sw1sw2 == 0x6A86 corrects to p2=0
    SC_PATH_TYPE_PATH will set P1 to 8, unknown by acos, but can be worked around splitting the path into len=2 temporary path segments with SC_PATH_TYPE_FILE_ID
*/
// TODO if !file_out.is_null() then all file_out returned - but the last - must be free'd

    if card.is_null() || path.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref_mut = unsafe { &mut *card };
    let path_ref = unsafe { & *path };

    if card_ref_mut.cache.current_path.len==0 { // first setting of  card.cache.current_path.len  done in acos5_64_init
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(path_ref.len>=2);

    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_select_file\0").unwrap();
    let format   = CStr::from_bytes_with_nul(b"        called\0").unwrap();
/*
    let format_1   = CStr::from_bytes_with_nul(b"called.  from_type: %d, from_value: %s\0").unwrap();
    let format_2   = CStr::from_bytes_with_nul(b"called.    to_type: %d,   to_value: %s\0").unwrap();
*/
    #[cfg(log)]
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
/*
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_1.as_ptr(), card_ref.cache.current_path.type_,
                       sc_dump_hex(card_ref.cache.current_path.value.as_ptr(), card_ref.cache.current_path.len) ) };
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_2.as_ptr(), path_ref.type_,
                       sc_dump_hex(path_ref.value.as_ptr(), path_ref.len) ) };
*/

    if path_ref.type_ == SC_PATH_TYPE_PATH {
        let len = path_ref.len;
        let path_target = &path_ref.value[..len];
        let current_path_df = current_path_df(card_ref_mut);
        let path1 = sc_path { value: [path_ref.value[len-2],  path_ref.value[len-1], 0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2, ..Default::default() }; // SC_PATH_TYPE_FILE_ID
        if      is_search_rule1_match(path_target, current_path_df) { // path_target is the currently selected DF: select_file MUST NOT be dropped
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule1_match: true (select_file target is the currently selected DF)\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule2_match(path_target, current_path_df) { // path_target is a EF/DF located (directly) within currently selected DF: select_file MUST NOT be dropped
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule2_match: true (select_file target is a EF/DF located (directly) within currently selected DF)\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }

        else if is_search_rule3_match(path_target, current_path_df) {
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule3_match: true (select_file target is the parent DF of currently selected DF)\0").unwrap();
            #[cfg(log)]
                unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule4_match(path_target, current_path_df) {
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule4_match: true (select_file target is a EF/DF located (directly) within the parent DF of currently selected DF)\0").unwrap();
            #[cfg(log)]
                unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }

        else if is_search_rule5_match(path_target) {
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule5_match: true (select_file target is MF)\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule6_match(path_target) {
            let format   = CStr::from_bytes_with_nul(b"        is_search_rule6_match: true (select_file target is a EF/DF located (directly) within MF)\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
    }

    let rv = match path_ref.type_ {
        SC_PATH_TYPE_PATH        =>  select_file_by_path(card_ref_mut, path_ref, file_out),
/*
            SC_PATH_TYPE_PATH_PROT | SC_PATH_TYPE_FROM_CURRENT | SC_PATH_TYPE_PARENT
                                          => SC_ERROR_KEYPAD_MSG_TOO_LONG,
*/
            /* for SC_PATH_TYPE_FILE_ID and SC_PATH_TYPE_DF_NAME : */
        _        =>  track_iso7816_select_file(card_ref_mut, path_ref, file_out),
    };
    rv
}

/*
Specific Return Status Code of cos5 Get Response
SW1 SW2   Definition
6b 00h    Wrong P1 or P2. Value must be 00h.
6C XXh    Incorrect P3. Value must be XXh.       actually OpenSC catches this an retransmits once with corrected XX
6A 88h    No data available

*/

/* get_response:   iso7816_get_response, limited to read max. 0xFF/(0x100 with card.max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE;) bytes, does work,
        see the impl. for more than 256 bytes: my_get_response
        get_response returns how many more bytes there are still to retrieve by a following call to get_response */
/*
 * What it does
 * @apiNote  ATTENTION SPECIAL MEANING of @return
 * @param  card
 * @param  count INOUT IN  how many bytes are expected that can be fetched;
                       OUT how many bytes actually were fetched by this call and were written to buf
 * @param  buf
 * @return how many bytes can be expected to be fetched the next time, this function get's called: It's a guess only
 */
extern "C" fn acos5_64_get_response(card: *mut sc_card, count: *mut usize, buf: *mut c_uchar) -> c_int
{
    if card.is_null() || buf.is_null() || count.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_rm = unsafe { &mut *card };
//    let count = unsafe { &mut *count };
    assert!(unsafe{*count} <= 256);
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func = CStr::from_bytes_with_nul(b"acos5_64_get_response\0").unwrap();
    let format = CStr::from_bytes_with_nul(b"called with: *count: %zu\0").unwrap();
    let format_1 = CStr::from_bytes_with_nul(b"returning with: *count: %zu, rv: %d\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_rm.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), *count) };

    /* request at most max_recv_size bytes */
//    let mrs = me_get_max_recv_size(card_rm);
//    assert_eq!(mrs, 256);
//    let rlen = if unsafe{*count} > mrs {mrs} else {unsafe{*count}};
    let rlen = std::cmp::min(unsafe{*count}, me_get_max_recv_size(card_rm));
    unsafe{ *count = 0 };
//println!("### acos5_64_get_response rlen: {}", rlen);
    let command = [0u8, 0xC0, 0x00, 0x00, 0xFF]; // will replace le later; the last byte is a placeholder only for sc_bytes2apdu_wrapper
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card_rm.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
//    sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xC0, 0x00, 0x00);
    apdu.le      = rlen;
    apdu.resplen = rlen;
    apdu.resp    = buf;
    /* don't call GET RESPONSE recursively */
    apdu.flags  |= SC_APDU_FLAGS_NO_GET_RESP as c_ulong;

    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
    if rv != SC_SUCCESS {
        if      apdu.sw1==0x6B && apdu.sw2==0x00 {
println!("### acos5_64_get_response returned 0x6B00:   Wrong P1 or P2. Value must be 00h.");
        }
        else if apdu.sw1==0x6A && apdu.sw2==0x88 {
println!("### acos5_64_get_response returned 0x6A88:   No data available.");
        }
        else {
println!("### acos5_64_get_response returned apdu.sw1: {:X}, apdu.sw2: {:X}   Unknown error code", apdu.sw1, apdu.sw2);
        }
        #[cfg(log)]
        unsafe { sc_do_log(card_rm.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format_1.as_ptr(), *count, rv) };
        return rv;
    }
    if !(apdu.sw1==0x6A && apdu.sw2==0x88) && apdu.resplen == 0 {
//    LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        #[cfg(log)]
        unsafe { sc_do_log(card_rm.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format_1.as_ptr(), *count, rv) };
        return rv;
    }

    unsafe{ *count = apdu.resplen };

    if      apdu.sw1==0x90 && apdu.sw2==0x00 {
        /* for some cos5 commands, it's NOT necessarily true, that status word 0x9000 signals "no more data to read" */
        rv = if get_is_running_cmd_long_response(card_rm) {set_is_running_cmd_long_response(card_rm, false); 256} else {0 /* no more data to read */};
        /* switching of here should also work for e.g. a 3072 bit key:
           The first  invocation by sc_get_response is with *count==256 (set by sc_get_response)
           The second invocation by sc_get_response is with *count==256 (got from rv, line above), fails, as the correct rv should have been 128,
             but the failure doesn't crawl up to this function, as a retransmit with corrected value 128 will be done in the low sc_transmit layer;
             thus there should be only 1 situation when (apdu.sw1==0x6A && apdu.sw2==0x88) get's to this function: For a 2048 bit RSA  key operation with is_running_cmd_long_response==true
            */
    }
/*
    else if apdu.sw1 == 0x61 { // this never get's returned by command
        rv = if apdu.sw2 == 0 {256} else {apdu.sw2 as c_int};    /* more data to read */
    }
    else if apdu.sw1 == 0x62 && apdu.sw2 == 0x82 { // this never get's returned by command
        rv = 0; /* Le not reached but file/record ended */
    }
*/
    else if apdu.sw1==0x6A && apdu.sw2==0x88 {
        rv = 0;
    }
    else {
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    }
    #[cfg(log)]
    unsafe { sc_do_log(card_rm.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_1.as_ptr(), *count, rv) };
    rv
}

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_get_challenge(card: *mut sc_card, buf: *mut c_uchar, count: usize) -> c_int
{
    if card.is_null() || buf.is_null() || count > 1024/* 1024*/ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref_mut = unsafe { &mut *card };
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func = CStr::from_bytes_with_nul(b"acos5_64_get_challenge\0").unwrap();
    let format = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr()) };
    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).get_challenge.unwrap() };
    let is_count_multiple8 =  count%8 == 0;
    let loop_count = count/8 + (if is_count_multiple8 {0usize} else {1usize});
    let mut len_rem = count;
    for i in 0..loop_count {
        if i+1<loop_count || is_count_multiple8 {
            let rv = unsafe { func_ptr(card, buf.add(i*8), 8) };
            if rv != SC_SUCCESS { return rv; }
            len_rem -= 8;
        }
        else {
            assert!(len_rem>0 && len_rem<8);
            let mut buf_temp = [0u8; 8];
            let rv = unsafe { func_ptr(card, buf_temp.as_mut_ptr(), 8) }; // buf.add(i*8)
            if rv != SC_SUCCESS { return rv; }
            unsafe { copy_nonoverlapping(buf_temp.as_ptr(), buf.add(i*8), len_rem) };
        }
    }
    SC_SUCCESS
}

/*
 * what's expected are the file IDs of files within the selected directory.
 * as opensc-tool provides as buf u8[SC_MAX_APDU_BUFFER_SIZE], max 130 files for each directory can be listed
 * @param  card    INOUT
 * @param  buf     INOUT
 * @param  buflen  IN
 * @return         number of bytes put into buf <= buflen
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_list_files(card: *mut sc_card, buf: *mut c_uchar, buflen: usize) -> c_int
{
    if card.is_null() || buf.is_null() || buflen<2 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref_mut = unsafe { &mut *card };
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_list_files\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr()) };

    /* retrieve the number of files in the currently selected directory*/
    let numfiles = match get_count_files_curr_df(card_ref_mut) {
        Ok(val) => if val > buflen/2 {buflen/2} else {val},
        Err(e) => return e,
    };
    if numfiles > 0 {
        let mut dp = unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };

        /* collect the IDs of files in the currently selected directory */
        for i  in 0..numfiles {
            let mut rbuf = match get_file_info(card_ref_mut, i as u8) {
                Ok(val) => val,
                Err(e) => {
                    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
                    return e
                },
            };
            unsafe {
                *buf.add(i * 2    ) = rbuf[2];
                *buf.add(i * 2 + 1) = rbuf[3];
            }
            rbuf[6] = match rbuf[0] { // replaces the unused ISO7816_RFU_TAG_FCP_SFI
                FDB_CHV_EF           => PKCS15_FILE_TYPE_PIN,
                FDB_SYMMETRIC_KEY_EF => PKCS15_FILE_TYPE_SECRETKEY,
                _                         => PKCS15_FILE_TYPE_NONE, // the default: not relevant for PKCS#15; will be changed for some files later on
            };
            let file_id = u16_from_array_begin(&rbuf[2..4]);
            dp.files.entry(file_id).or_insert(([0u8;SC_MAX_PATH_SIZE], rbuf, None, None));
        }

        card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
    }
    (numfiles as c_int)*2
}


/*
 *  Evaluates file header bytes from TLV with T= ISO7816_TAG_FCI or ISO7816_TAG_FCP,
 *  provided from select_file response data (opensc calls this function only from iso7816_select_file)
 *
 *  @apiNote  iso7816_select_file positions buf by calling sc_asn1_read_tag such that the first 2 bytes (Tag 0x6F and
 *            L==buflen are skipped)
 *  @param  card    INOUT
 *  @param  file    INOUT iso7816_select_file allocates a file object, field 'path' assigned
 *  @param  buf     IN    Must point to V[0] of FCI's first TLV
 *  @param  buflen  IN    L of FCI's first TLV
 *  @return         SC_SUCCESS or error code from errors.rs
 */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_process_fci(card: *mut sc_card, file: *mut sc_file,
    buf: *const c_uchar, buflen: usize) -> c_int
{
/*
  Many tags are detected by iso7816_process_fci, but it misses to search for
  0x8C  ISO7816_RFU_TAG_FCP_SAC
  0x8D  ISO7816_RFU_TAG_FCP_SEID
  0xAB  ISO7816_RFU_TAG_FCP_SAE

//  0x82  ISO7816_TAG_FCP_TYPE must be evaluated once more for proprietary EF: SE file : mark it as internal EF: opensc-tool prints only for
//  SC_FILE_TYPE_WORKING_EF, SC_FILE_TYPE_INTERNAL_EF, SC_FILE_TYPE_DF
//  file sizes are missing for structure: linear-fixed and linear-variable
*/
    assert!(!card.is_null() && !file.is_null());
    let card_ref = unsafe { & *card };
    let card_ref_mut = unsafe { &mut *card };

    assert!(!file.is_null());
//    let file_ref = unsafe { & *file };
    let file_ref_mut = unsafe { &mut *file };

    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_process_fci\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };

    let mut vec_bytes_tag_fcp_sac : Vec<c_uchar> = Vec::with_capacity(8);
    let mut len_bytes_tag_fcp_sac = 0usize;

    let ptr_bytes_tag_fcp_sac = unsafe { sc_asn1_find_tag(card_ref.ctx, buf, buflen, ISO7816_RFU_TAG_FCP_SAC as c_uint,
                                                          &mut len_bytes_tag_fcp_sac) };
    assert!(!ptr_bytes_tag_fcp_sac.is_null());
    for i in 0..len_bytes_tag_fcp_sac {
        unsafe { vec_bytes_tag_fcp_sac.push(*ptr_bytes_tag_fcp_sac.add(i)) };
    }

    let scb8 = match convert_bytes_tag_fcp_sac_to_scb_array(vec_bytes_tag_fcp_sac.as_slice()) {
        Ok(scb8)  => scb8,
        Err(e)      => return e,
    };
/*
    let mut buf_vec : Vec<c_uchar> = Vec::with_capacity(90);
    for i in 0..buflen {
        unsafe { buf_vec.push(*buf.add(i)) };
    }
    println!("buf_vec: {:X?}, scb8: {:X?}", buf_vec, scb8);
*/
    let rv = unsafe { (*(*sc_get_iso7816_driver()).ops).process_fci.unwrap()(card, file, buf, buflen) };
    assert_eq!(rv, SC_SUCCESS);
/* */
    /* save all the FCI data for future use */
    let rv = unsafe { sc_file_set_prop_attr(file, buf, buflen) };
    assert_eq!(rv, SC_SUCCESS);
/* */
    // retrieve FDB FileDescriptorByte and perform some corrective actions
    // if file_ref_mut.type_== 0 || (file_ref_mut.type_!= SC_FILE_TYPE_DF && file_ref_mut.ef_structure != SC_FILE_EF_TRANSPARENT)
    let mut len_bytes_tag_fcp_type = 0usize;
    let     ptr_bytes_tag_fcp_type = unsafe { sc_asn1_find_tag(card_ref.ctx, buf, buflen, ISO7816_TAG_FCP_TYPE as c_uint, &mut len_bytes_tag_fcp_type) };
    assert!(!ptr_bytes_tag_fcp_type.is_null());
    assert!( len_bytes_tag_fcp_type >=2 );
    let fdb = unsafe { *ptr_bytes_tag_fcp_type };
    if file_ref_mut.type_ == 0 && fdb == FDB_SE_FILE {
        file_ref_mut.type_ = SC_FILE_TYPE_INTERNAL_EF;
    }
    if file_ref_mut.type_!= SC_FILE_TYPE_DF && file_ref_mut.ef_structure != SC_FILE_EF_TRANSPARENT { // for non-transparent EF multiply MaxRecordLen and NumberOfRecords as a file size hint
//        82, 6, 1C, 0, 0, 30, 0, 1
        assert!(len_bytes_tag_fcp_type >= 5 && len_bytes_tag_fcp_type <= 6);
        file_ref_mut.size = unsafe { (*ptr_bytes_tag_fcp_type.offset(3) as usize) *
                                     (*ptr_bytes_tag_fcp_type.add(len_bytes_tag_fcp_type-1) as usize) };
    }
    let mut sefile_id = [0u8;2];
    if (fdb & FDB_DF) == FDB_DF {
        let mut len_bytes_tag_fcp_seid = 0usize;
        let     ptr_bytes_tag_fcp_seid = unsafe { sc_asn1_find_tag(card_ref.ctx, buf, buflen,
                                                  ISO7816_RFU_TAG_FCP_SEID as c_uint, &mut len_bytes_tag_fcp_seid) };
        assert!(  !ptr_bytes_tag_fcp_seid.is_null());
        assert_eq!(len_bytes_tag_fcp_seid, 2);
        sefile_id = unsafe { [*ptr_bytes_tag_fcp_seid, *ptr_bytes_tag_fcp_seid.offset(1)] };
//        println!("sefile_id: {:?}", sefile_id);
    }

    /* select_file is always allowed */
    assert_eq!(    SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, SC_AC_OP_SELECT,     SC_AC_NONE, SC_AC_KEY_REF_NONE as c_ulong) } );
    if (fdb & FDB_DF) == FDB_DF { // it's FDB_MF or FDB_DF
        /* list_files is always allowed for MF/DF */
        assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_NONE, SC_AC_KEY_REF_NONE as c_ulong) } );
        /* for opensc-tool also add the general SC_AC_OP_CREATE, which shall comprise both, SC_AC_OP_CREATE_EF and SC_AC_OP_CREATE_DF (added below later)  */
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[1], SC_AC_OP_CREATE);
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[2], SC_AC_OP_CREATE);
    }
    else {
        /* for an EF, acos doesn't distinguish access right update <-> write, thus add SC_AC_OP_WRITE as a synonym to SC_AC_OP_UPDATE */
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[1], SC_AC_OP_WRITE);
        /* usage of SC_AC_OP_DELETE_SELF <-> SC_AC_OP_DELETE seems to be in confusion in opensc, thus for opensc-tool and EF add SC_AC_OP_DELETE to SC_AC_OP_DELETE_SELF
           My understanding is:
           SC_AC_OP_DELETE_SELF designates the right to delete the EF/DF that contains this right in it's SCB
           SC_AC_OP_DELETE      designates the right of a directory, that a contained file may be deleted; acos calls that Delete Child
        */
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[6], SC_AC_OP_DELETE);
    }
    /* for RSA key file add SC_AC_OP_GENERATE to SC_AC_OP_CRYPTO */
    if fdb == FDB_RSA_KEY_EF {
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[2], SC_AC_OP_GENERATE);
    }

    let ops_df_mf  : [u32; 7] = [ SC_AC_OP_DELETE/*_CHILD*/, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_ef_chv : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    0xFF,               SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_key    : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_se     : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];

    for idx_scb8 in 0..7 {
        let op =
            if      (fdb & FDB_DF) == FDB_DF                              { ops_df_mf [idx_scb8] }
            else if  fdb == FDB_SE_FILE                                   { ops_se    [idx_scb8] }
            else if  fdb == FDB_RSA_KEY_EF || fdb == FDB_SYMMETRIC_KEY_EF { ops_key   [idx_scb8] }
            else                                                          { ops_ef_chv[idx_scb8] };
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[idx_scb8], op);
    }

    let mut dp : Box<DataPrivate> = unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };
    let file_id = file_ref_mut.id as u16;
    if dp.files.contains_key(&file_id) {
        let dp_files_value_ref_mut = dp.files.entry(file_id).or_insert(([0u8;SC_MAX_PATH_SIZE], [0u8;8], None, None));
        if dp_files_value_ref_mut.2.is_none() {
            dp_files_value_ref_mut.2  = Some(scb8);
        }
        if dp_files_value_ref_mut.1[0] == FDB_MF && dp_files_value_ref_mut.1[4..] == [0x00u8, 0x00, 0xFF, 0xFF] { // correct the initially unknown/incorrect lcsi setting
            let mut len_bytes_tag_fcp_lcs = 0usize;
            let     ptr_bytes_tag_fcp_lcs = unsafe { sc_asn1_find_tag(card_ref.ctx, buf, buflen,
                                                     ISO7816_TAG_FCP_LCS as c_uint, &mut len_bytes_tag_fcp_lcs) };
            assert!(  !ptr_bytes_tag_fcp_lcs.is_null());
            assert_eq!(len_bytes_tag_fcp_lcs, 1);
            let lcsi = unsafe { *ptr_bytes_tag_fcp_lcs };
            dp_files_value_ref_mut.1[7]  = lcsi;
        }
        if dp_files_value_ref_mut.1[0] & FDB_DF == FDB_DF && dp_files_value_ref_mut.1[4..6] == [0u8, 0] {
            dp_files_value_ref_mut.1[4]  = sefile_id[0];
            dp_files_value_ref_mut.1[5]  = sefile_id[1];
        }
    }
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;

    SC_SUCCESS
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_pin_cmd(card: *mut sc_card, data: *mut sc_pin_cmd_data, tries_left: *mut c_int) -> c_int
{
    if card.is_null() || data.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref_mut = unsafe { &mut *card };
    let pin_cmd_data_ref_mut = unsafe { &mut *data };

    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func = CStr::from_bytes_with_nul(b"acos5_64_pin_cmd\0").unwrap();
    let format = CStr::from_bytes_with_nul(b"called for cmd: %d\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), pin_cmd_data_ref_mut.cmd) };

    if      SC_PIN_CMD_GET_INFO == pin_cmd_data_ref_mut.cmd {
        pin_get_policy(card_ref_mut, pin_cmd_data_ref_mut, tries_left)
    }
    else if SC_PIN_CMD_VERIFY == pin_cmd_data_ref_mut.cmd { // pin1 is used, pin2 unused
        if data.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
//        let pindata_rm = unsafe {&mut *data};
//println!("sc_pin_cmd_data:  flags: {:X}, pin_type: {:X}, pin_reference: {:X}, apdu: {:?}", pindata_rm.flags, pindata_rm.pin_type, pindata_rm.pin_reference, pindata_rm.apdu);
//println!("sc_pin_cmd_pin 1: len: {}, [{:X},{:X},{:X},{:X}]", pindata_rm.pin1.len, unsafe{*pindata_rm.pin1.data.add(0)}, unsafe{*pindata_rm.pin1.data.add(1)}, unsafe{*pindata_rm.pin1.data.add(2)}, unsafe{*pindata_rm.pin1.data.add(3)});
        unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, data, tries_left) }
    }
    else if SC_PIN_CMD_CHANGE == pin_cmd_data_ref_mut.cmd { // pin1 is old pin, pin2 is new pin
        if data.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
//        let pindata_rm = unsafe {&mut *data};
//        println!("sc_pin_cmd_data:  flags: {:X}, pin_type: {:X}, pin_reference: {:X}, apdu: {:?}", pindata_rm.flags, pindata_rm.pin_type, pindata_rm.pin_reference, pindata_rm.apdu);
//        println!("sc_pin_cmd_pin 1: len: {}, [{:X},{:X},{:X},{:X}]", pindata_rm.pin1.len, unsafe{*pindata_rm.pin1.data.add(0)}, unsafe{*pindata_rm.pin1.data.add(1)}, unsafe{*pindata_rm.pin1.data.add(2)}, unsafe{*pindata_rm.pin1.data.add(3)});
//        println!("sc_pin_cmd_pin 2: len: {}, [{:X},{:X},{:X},{:X}]", pindata_rm.pin2.len, unsafe{*pindata_rm.pin2.data.add(0)}, unsafe{*pindata_rm.pin2.data.add(1)}, unsafe{*pindata_rm.pin2.data.add(2)}, unsafe{*pindata_rm.pin2.data.add(3)});
        unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, data, tries_left) }
    }
    else if SC_PIN_CMD_UNBLOCK == pin_cmd_data_ref_mut.cmd { // pin1 is PUK, pin2 is new pin for the one blocked
        if data.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
//        let pindata_rm = unsafe {&mut *data};
//        println!("sc_pin_cmd_data:  flags: {:X}, pin_type: {:X}, pin_reference: {:X}, apdu: {:?}", pindata_rm.flags, pindata_rm.pin_type, pindata_rm.pin_reference, pindata_rm.apdu);
//        println!("sc_pin_cmd_pin 1: len: {}, [{:X},{:X},{:X},{:X}]", pindata_rm.pin1.len, unsafe{*pindata_rm.pin1.data.add(0)}, unsafe{*pindata_rm.pin1.data.add(1)}, unsafe{*pindata_rm.pin1.data.add(2)}, unsafe{*pindata_rm.pin1.data.add(3)});
//        println!("sc_pin_cmd_pin 2: len: {}, [{:X},{:X},{:X},{:X}]", pindata_rm.pin2.len, unsafe{*pindata_rm.pin2.data.add(0)}, unsafe{*pindata_rm.pin2.data.add(1)}, unsafe{*pindata_rm.pin2.data.add(2)}, unsafe{*pindata_rm.pin2.data.add(3)});
        unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, data, tries_left) }
    }
    else if cfg!(not(any(v0_15_0, v0_16_0))) && SC_PIN_CMD_GET_SESSION_PIN == pin_cmd_data_ref_mut.cmd {
        SC_ERROR_NO_CARD_SUPPORT
    }
    else {
        SC_ERROR_NO_CARD_SUPPORT
/*
        unsafe {
            if !tries_left.is_null() /* || pin_cmd_data_ref_mut.cmd == SC_PIN_CMD_GET_INFO */ {
                println!("tries_left: {}", *tries_left);
            }
            /* */

            if !pin_cmd_data_ref_mut.pin1.data.is_null() {
                let mut arr_pin = [0u8; 8];
                for i in 0..pin_cmd_data_ref_mut.pin1.len as usize {
                    arr_pin[i] = *pin_cmd_data_ref_mut.pin1.data.add(i);
                }
                println!("pin1.data: {:?}, pin_cmd_data: {:?}", arr_pin, *pin_cmd_data_ref_mut); // , *pin_cmd_data_ref_mut.apdu
            }
            else {
                println!("pin_cmd_data: {:?}", *pin_cmd_data_ref_mut);
            }

            /*       */
        }

        let rv = unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, data, tries_left) };
        if rv != SC_SUCCESS {
            return rv;
        }
*/
    }
}
/*
00 2C 01 81 08 38 37 36 35 34 33 32 31
00 2C 00 81 10 38 37 36 35 34 33 32 31 31 32 33 34 35 36 37 38  87654321 12345678
*/

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_read_public_key(card: *mut sc_card, algorithm: c_uint, key_path: *mut sc_path,
     key_reference: c_uint, modulus_length: c_uint, out: *mut *mut c_uchar, out_len: *mut usize) -> c_int
{
    if card.is_null() || key_path.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref     : &sc_card     = unsafe { &*card };
//    let card_ref_mut : &mut sc_card = unsafe { &mut *card };
    let key_path_ref : &sc_path = unsafe { &*key_path };

    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_read_public_key\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    let format_1 = CStr::from_bytes_with_nul(RETURNING_INT_CSTR).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr() ) };

    if algorithm != SC_ALGORITHM_RSA {
//        let format_1 = CStr::from_bytes_with_nul(RETURNING_ERRCODE_ERRSTR).unwrap();
//        let format_2 = CStr::from_bytes_with_nul(RETURNING_ERRCODE).unwrap();
       //LOG_FUNC_RETURN(ctx, SC_ERROR_NO_CARD_SUPPORT);
        let rv = SC_ERROR_NO_CARD_SUPPORT;
//        if rv <= 0 {
            #[cfg(log)]
            unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                               format_1.as_ptr(), rv, sc_strerror(rv) ) };
//        }
//        else {
//            #[cfg(log)]
//            unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
//                               format_2.as_ptr(), rv) };
//        }
        return rv;
    }
    assert!(modulus_length>=512 && modulus_length<=4096);
//    #[allow(non_snake_case)]
    let mlbyte : usize = (modulus_length as usize)/8; /* key modulus_length in byte (expected to be a multiple of 32)*/
    let le_total = mlbyte + 21;
    let format = CStr::from_bytes_with_nul(b"read public key(ref:%i; modulus_length:%i; modulus_bytes:%zu)\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), key_reference, modulus_length, mlbyte); }

    let mut file_out_ptr_mut: *mut sc_file = std::ptr::null_mut();
//    let mut rv = select_file_by_path(card_ref_mut, key_path_ref, &mut file_out_ptr_mut, true/*, true*/);
    let mut rv = acos5_64_select_file(card, key_path, &mut file_out_ptr_mut);
    if rv != SC_SUCCESS {
        let format   = CStr::from_bytes_with_nul(b"failed to select public key file\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr() ) };
        return rv;
    }

    /* retrieve the raw content of currently selected RSA pub file */
    let command : [u8; 5] = [0x80, 0xCA, 0x00, 0x00, 0xFF];
    let mut apdu : sc_apdu = Default::default();
    rv = sc_bytes2apdu_wrapper(card_ref.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

    let mut rbuf = [0u8; RSAPUB_MAX_LEN];
    let mut le_remaining = le_total;
    while le_remaining > 0 {
        let offset = le_total - le_remaining;
        apdu.le      =  if le_remaining > 0xFFusize {0xFFusize} else {le_remaining};
        apdu.resp    =  unsafe { rbuf.as_mut_ptr().add(offset) };
        apdu.resplen =  rbuf.len() - offset;
        apdu.p1      =  ((offset >> 8) & 0xFFusize) as u8;
        apdu.p2      =  ( offset       & 0xFFusize) as u8;
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS {
            let format   = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                               format.as_ptr() ) };
            return rv;
        }
        assert_eq!(apdu.resplen, apdu.le);
        le_remaining -= apdu.le;
    }

    /* check the raw content of RSA pub file
00 20 41 F1 03 00 00 00 00 00 00 00 00 00 00 00 . A.............
00 00 01 00 01 6A 54 EB 93 CD 31 9E 37 2D 59 74 .....jT...1.7-Yt
3F004100 41 31
     */
    if  rbuf[0] != 0 ||
        rbuf[1] != ((modulus_length+8)/128) as u8 ||   /* encode_key_RSA_ModulusBitLen(modulus_length) */
        rbuf[2] != key_path_ref.value[key_path_ref.len-2] /* FIXME RSAKEYID_CONVENTION */ ||
//        rbuf[3] != ( (key_path_ref.value[key_path_ref.len-1] as u16 +0xC0u16)       & 0xFFu16) as u8 /* FIXME RSAKEYID_CONVENTION */ ||
       (rbuf[4] & 3u8) != 3u8
    {
        let format = CStr::from_bytes_with_nul(b"failed: check the raw content of RSA pub file\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr() ) };
        return SC_ERROR_INCOMPATIBLE_KEY;
    }

    // skip leading zero bytes of exponent; usually only 3 of 16 bytes are used; otherwise pkcs15-tool.c:read_ssh_key doesn't work
    let mut view = &rbuf[5..21];
    while view.len() > 0 && view[0] == 0 {
        view = &view[1..];
    }
    let raw_exponent_len = view.len();
    assert!(raw_exponent_len>0 && raw_exponent_len<=16);
    let rsa_key = sc_pkcs15_pubkey_rsa {
        exponent: sc_pkcs15_bignum{ data: unsafe { rbuf.as_mut_ptr().add(21-raw_exponent_len) }, len: raw_exponent_len},
        modulus:  sc_pkcs15_bignum{ data: unsafe { rbuf.as_mut_ptr().add(21) }, len: mlbyte }
    };

    /* transform the raw content to der-encoded */
    if rsa_key.exponent.len > 0 && rsa_key.modulus.len > 0 {
        rv = unsafe { sc_pkcs15_encode_pubkey_rsa(card_ref.ctx, &rsa_key, out, out_len) };
        if rv < 0 {
            let format_1a = CStr::from_bytes_with_nul(b"sc_pkcs15_encode_pubkey_rsa failed: returning with: %d (%s)\n\0")
                            .unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                               format_1a.as_ptr(), rv, sc_strerror(rv) ) };
            return rv;
        }
    }
    else {
        rv = SC_ERROR_INTERNAL;
        let format_1b = CStr::from_bytes_with_nul(b"if rsa_key.exponent.len > 0 && rsa_key.modulus.len > 0  failure: \
            returning with: %d (%s)\n\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format_1b.as_ptr(), rv, sc_strerror(rv) ) };
        return SC_ERROR_INTERNAL;
    }
    SC_SUCCESS
}


/* set_security_env:  Initializes the security environment on card
 *   according to <env>, and stores the environment as <se_num> on the
 *   card. If se_num <= 0, the environment will not be stored. */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
extern "C" fn acos5_64_set_security_env(card: *mut sc_card, env: *const sc_security_env, _se_num: c_int) -> c_int
{
    if card.is_null() || env.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref        = unsafe { &    *card };
    let card_ref_mut = unsafe { &mut *card };
    let env_ref   = unsafe { &    *env };
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_set_security_env\0").unwrap();
    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), ) };

    if SC_SEC_OPERATION_DERIVE == env_ref.operation
//        || ( cfg!(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))) && (SC_SEC_OPERATION_WRAP == env_ref.operation || SC_SEC_OPERATION_UNWRAP == env_ref.operation) )
    {
        return SC_ERROR_NO_CARD_SUPPORT;
    }
    else if (SC_SEC_OPERATION_SIGN     == env_ref.operation ||
             SC_SEC_OPERATION_DECIPHER == env_ref.operation)   &&
        env_ref.algorithm==SC_ALGORITHM_RSA && (env_ref.flags as c_uint & SC_SEC_ENV_FILE_REF_PRESENT)==SC_SEC_ENV_FILE_REF_PRESENT
    {
        // TODO where is the decision taken to use PKCS#1 scheme padding?
        let rsa_algo_flags_no_rng = !SC_ALGORITHM_ONBOARD_KEY_GEN & get_rsa_algo_flags(card_ref_mut);
        let algo = if (rsa_algo_flags_no_rng & SC_ALGORITHM_RSA_PAD_ISO9796) == 0 {0x10u8} else {0x11u8};
        let path_idx = env_ref.file_ref.len - 2;
        if SC_SEC_OPERATION_SIGN == env_ref.operation {
            let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB6, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,  env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
            let mut apdu : sc_apdu = Default::default();
            let mut rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
            assert_eq!(rv, SC_SUCCESS);
            assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
            if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
                let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or 'Set SecEnv for Sign' failed\0").unwrap();
                #[cfg(log)]
                unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(), format.as_ptr()) };
                return SC_ERROR_KEYPAD_MSG_TOO_LONG;
            }
        }
        // sign may need decrypt (for non-SHA1/SHA256 hashes), thus prepare for a CCT as well
        let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x13, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu : sc_apdu = Default::default();
        let mut rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            let format = CStr::from_bytes_with_nul(b"sc_transmit_apdu or 'Set SecEnv for Decrypt' failed\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                               format.as_ptr()) };
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }

    }
//    else if SC_SEC_OPERATION_DECIPHER == env_ref.operation && env_ref.algorithm==SC_ALGORITHM_RSA &&
//        (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) == SC_SEC_ENV_FILE_REF_PRESENT {
//    }
    else {
        return SC_ERROR_NO_CARD_SUPPORT;
    }
    SC_SUCCESS
}


/* decipher:  Engages the deciphering operation.  Card will use the
 *   security environment set in a call to set_security_env or
 *   restore_security_env.
 *
 *  Status Wordss while processing:
 *  While sending (flag SC_APDU_FLAGS_CHAINING set conditionally) transmit of chunks returns 0x9000 for cos5, until all data are sent. The last transmit returns e.g. SW 0x6100,
 *  meaning, there are 256 bytes or more to fetch, or a one only transmit for keylen<=2048 returns e.g. 0x61E0 or 0x6100.
 *  decrypted data for keylen<=2048 can be easily, automatically fetched with regular commands called by sc_transmit_apdu (sc_get_response, iso7816_get_response;
 *  olen  = apdu->resplen (before calling sc_single_transmit; after calling sc_single_transmit, all commands that return a SM 0x61?? set apdu->resplen to 0)
 *  olen get's passed to sc_get_response, which is the total size of output buffer offered.
 *  For keylen>2048
 00 C0 00 00 00
 */
/*
 * What it does The function currently relies on, that the crgram_len==keylen_bytes i.o. to control amount of bytes to expect from get_response (if keylen_bytes>256)
 * @apiNote
 * @param
 * @return  error code or number of bytes written into out
 */
extern "C" fn acos5_64_decipher(card: *mut sc_card, crgram: *const c_uchar, crgram_len: usize,
                                                    out:      *mut c_uchar,     outlen: usize) -> c_int
{
    if card.is_null() || crgram.is_null() || out.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref:         &sc_card = unsafe { &    *card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };

    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"acos5_64_decipher\0").unwrap();
//    let format   = CStr::from_bytes_with_nul(CALLED).unwrap();
    let format   = CStr::from_bytes_with_nul(b"called with: crgram_len: %u, outlen: %u\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), crgram_len, outlen) };
    assert!(outlen >= crgram_len);

    let command = [0u8, 0x2A, 0x80, 0x84, 0x02, 0xFF, 0xFF, 0xFF]; // will replace lc, cmd_data and le later; the last 4 bytes are placeholders only for sc_bytes2apdu_wrapper
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_4_SHORT);

    apdu.data    = crgram;
    apdu.datalen = crgram_len;
    apdu.lc      = crgram_len;
    apdu.resp    = out;
    apdu.resplen = outlen;
    apdu.le      = std::cmp::min(crgram_len, SC_READER_SHORT_APDU_MAX_RECV_SIZE);
    if apdu.lc > card_ref_mut.max_send_size {
        apdu.flags |= SC_APDU_FLAGS_CHAINING as c_ulong;
    }

    set_is_running_cmd_long_response(card_ref_mut, true); // switch to false is done by acos5_64_get_response
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00
    {
        let format = CStr::from_bytes_with_nul(b"### 0x%02X%02X: sc_transmit_apdu or decipher failed or it's impossible \
            to retrieve the answer from get_response ###\0").unwrap();
        #[cfg(log)]
        unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                           format.as_ptr(), apdu.sw1, apdu.sw2) };
        /* while using pkcs11-tool -l -t
        it may happen, that a sign-key get's tested with a hash algo unsupported by compute_signature, thus it must revert to use acos5_64_decipher,
        but the key isn't generated with decrypt capability: Then fake a success here, knowing, that a verify signature will fail
        Update: this doesn't help, check_sw kicks in and aborts on error 0x6A80 */
        if rv == SC_ERROR_INCORRECT_PARAMETERS { // 0x6A80 error code get's transformed by iso7816_check_sw to SC_ERROR_INCORRECT_PARAMETERS
            apdu.sw1 = 0x90;
            apdu.sw2 = 0x00;
            let format = CStr::from_bytes_with_nul(b"### decipher failed with error code 0x6A80: Multiple possible \
               reasons for the failure; a likely harmless one is, that the key is not capable to decipher but was used \
               for deciphering (maybe called from compute_signature, i.e. the intent was signing with a hash algo that \
               compute_signature doesn't support; compute_signature reverts to decipher for any hash algo other than \
               SHA-1 or SHA-256) ###\0").unwrap();
            #[cfg(log)]
            unsafe { sc_do_log(card_ref_mut.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                               format.as_ptr()) };
        }
        assert!(rv<0);
        return rv;
    }
    let format = CStr::from_bytes_with_nul(b"returning from acos5_64_decipher with: %d\n\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format.as_ptr(), crgram_len as c_int) };
    crgram_len as c_int
}


/*
 * What it does
 Ideally this function should be adaptive, meaning it works for SC_ALGORITHM_RSA_RAW (SC_ALGORITHM_RSA_PAD_NONE)
 as well as for e.g. SC_ALGORITHM_RSA_PAD_PKCS1

 The function currently relies on, that data_len==keylen_bytes i.o. to control amount of bytes to expect from get_response (if keylen_bytes>256)
 It's not safe to use outlen as indicator for  keylen_bytes, e.g.: pkcs15-crypt --sign --key=5 --input=test_in_sha1.hex --output=test_out_sig_pkcs1.hex --sha-1 --pkcs1 --pin=12345678
 uses outlen==1024

 * @apiNote
 * @param
 * @return  error code (neg. value) or number of bytes written into out
 */
extern "C" fn acos5_64_compute_signature(card: *mut sc_card, data: *const c_uchar, data_len: usize,
                                                              out:   *mut c_uchar,   outlen: usize) -> c_int
{
    if data_len == 0 || outlen == 0 {
        return SC_SUCCESS;
    }
    if card.is_null() || data.is_null() || out.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(data_len <= outlen);
    assert!(data_len <= 512); // cos5 supports max RSA 4096 bit keys

    let card_ref:         &sc_card = unsafe { &    *card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };

    let file = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_compute_signature\0").unwrap();
    if cfg!(log) {
        let fmt = CStr::from_bytes_with_nul(b"called with: data_len: %zu, outlen: %zu\0").unwrap();
        wr_do_log_zz(card_ref.ctx, file, line!(), fun, fmt, data_len, outlen);
    }

    let mut vec_in : Vec<u8> = Vec::with_capacity(512);
    for i in 0..data_len {
        vec_in.push(unsafe { *data.add(i) } );
    }
    assert!(vec_in.len()>0);
    let rsa_algo_flags_no_rng = !SC_ALGORITHM_ONBOARD_KEY_GEN & get_rsa_algo_flags(card_ref_mut);
//println!("Sign: rsa_algo_flags_no_rng: 0x{:X}, input len: {}, input data: {:?}", rsa_algo_flags_no_rng, vec_in.len(), vec_in);
    let digest_info =
        if rsa_algo_flags_no_rng != SC_ALGORITHM_RSA_RAW { vec_in.as_slice() } // then vec_in IS digest_info
        else { // rsa_algo_flags_no_rng == SC_ALGORITHM_RSA_RAW
            match me_pkcs1_strip_01_padding(&vec_in) {
                Ok(digest_info) => digest_info,
                Err(e) => {
                    if e != SC_ERROR_WRONG_PADDING || vec_in[vec_in.len() - 1] != 0xbc {
                        return e;
                    }
                    else { // it may be data for RSA PPS signature
                        return -1;
//                      return acos5_64_decipher(card, data, data_len, out, outlen);
                    }
                }
            }
        };
//println!("digest_info.len(): {}, digest_info: {:X?}", digest_info.len(), digest_info);
    if digest_info.len() == 0 { // if there is no content to sign, then don't sign
        return SC_SUCCESS;
    }

    let digest_info_prefix_sha256 = [0x30u8, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
    // id_rsassa_pkcs1_v1_5_with_sha512_256 and id_rsassa_pkcs1_v1_5_with_sha3_256 also have a digest_info.len() == 51
    if (digest_info.len() != 35 /*SHA-1*/ && digest_info.len() != 51 /*SHA-256*/) || (digest_info.len() == 51 && digest_info[..19]!=digest_info_prefix_sha256)
    {   /* this will fail if key_len != outlen */
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"### Switch to acos5_64_decipher, because acos5_64_compute_signature \
                can't handle the hash algo ###\0").unwrap();
            wr_do_log(card_ref.ctx, file, line!(), fun, fmt);
        }
        let rv : c_int;
        /* digest_info.len() is from SC_ALGORITHM_RSA_RAW/SC_ALGORITHM_RSA_PAD_NONE or SC_ALGORITHM_RSA_PAD_PKCS1 */
        /* is_any_of_di_by_len or ? could go further an compare digest_info_prefix to known ones as well
           With that done, a possible attacker can control nothing but the hash value (and signature scheme to be used)
           TODO implement delaying, if consecutive trials to sign are detected, revoke PIN verification etc.
             or enable an additional layer where user MUST accept or deny sign operation (see DNIE) */
        if      SC_ALGORITHM_RSA_PAD_PKCS1 & rsa_algo_flags_no_rng > 0 && is_any_of_di_by_len(digest_info.len())
        {
/* difficult to get this right, trying to substitute pkcs1_add_01_padding by sc_pkcs1_encode
            let mut buf = [0u8; 512];
            let mut buf_len = std::cmp::min(512, outlen);
            rv = unsafe { sc_pkcs1_encode(card_ref_mut.ctx, rsa_algo_flags_no_rng as c_ulong, digest_info.as_ptr(), digest_info.len(),
                                          buf.as_mut_ptr(), &mut buf_len, buf_len) };
            if rv != SC_SUCCESS {
                return rv;
            }
            rv = acos5_64_decipher(card, buf.as_ptr(), buf_len, out, outlen);

0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] sec.c:59:sc_compute_signature: called
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] acos5_64:1894:acos5_64_compute_signature: called with: data_len: 83, outlen: 512
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] acos5_64:1934:acos5_64_compute_signature: ### Switch to acos5_64_decipher, because acos5_64_compute_signature can't handle the hash algo ###
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] padding.c:243:sc_pkcs1_encode: called
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] padding.c:247:sc_pkcs1_encode: hash algorithm 0x0, pad algorithm 0x2
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] padding.c:252:sc_pkcs1_encode: Unable to add digest info 0x0
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] padding.c:253:sc_pkcs1_encode: returning with: -1400 (Internal error)
0x7f25a7c8ff80 18:35:17.552 [opensc-pkcs11] sec.c:63:sc_compute_signature: returning with: -1400 (Internal error)
*/

            let vec = match me_pkcs1_add_01_padding(digest_info, outlen)
            {
                Ok(vec) => vec,
                Err(e) => return e,
            };
//            assert_eq!(vec.len(), 512);
            rv = acos5_64_decipher(card, vec.as_ptr(), vec.len(), out, outlen);
        }
        else if SC_ALGORITHM_RSA_RAW & rsa_algo_flags_no_rng > 0  {
            rv = acos5_64_decipher(card, data, data_len, out, outlen);
        }
        else {
            rv = 0; // do nothing
        }
        /* acos5_64_decipher will fail if the key is not capable to decrypt */
        /* temporary: "decrypt" signature (out) to stdout * /
        if rv>0 {
            encrypt_public_rsa(card, out, /*data_len*/ outlen);
        }
        / * */
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"returning from acos5_64_compute_signature with: %d\n\0").unwrap();
            wr_do_log_t(card_ref.ctx, file, line!(), fun, fmt, rv);
        }
        return rv;
    }
    else { // SHA-1 and SHA-256 hashes, what the card can handle natively
        assert!(digest_info.len() == 35 || digest_info.len() == 51);
        let hash = if digest_info.len()==35 { &digest_info[15..] } else { &digest_info[19..] };
        assert!(hash.len()==20 || hash.len()==32);

        set_is_running_cmd_long_response(card_ref_mut, true); // switch to false is done by acos5_64_get_response
        let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).compute_signature.unwrap() };
        let rv = unsafe { func_ptr(card, hash.as_ptr(), hash.len(), out, outlen) };
        if rv <= 0 {
            if cfg!(log) {
                let fmt = CStr::from_bytes_with_nul(b"iso7816_compute_signature failed or apdu.resplen==0. rv: %d\0")
                                 .unwrap();
                wr_do_log_t(card_ref.ctx, file, line!(), fun, fmt, rv);
            }
            return rv;
        }
        /* temporary: "decrypt" signature (out) to stdout * /
        encrypt_public_rsa(card,out, data_len);
        / * */
    }
    let fmt   = CStr::from_bytes_with_nul(RETURNING_INT).unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line!() as i32, fun.as_ptr(),
                       fmt.as_ptr(), data_len as c_int) };
    data_len as c_int
}
