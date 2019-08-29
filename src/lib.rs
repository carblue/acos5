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

 https://help.github.com/en/articles/changing-a-remotes-url

 Table 4 - Data within a command-response pair : APDU case
Case     Command data     Expected response data
1         No data             No data
2         No data             Data
3         Data                No data
4         Data                Data

 TODO Many error returns are provisorily set to SC_ERROR_KEYPAD_MSG_TOO_LONG to be refined later
 TODO Only set to anything other than SC_ERROR_KEYPAD_MSG_TOO_LONG, if that's the final setting
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
*/

//#![feature(const_fn)]
//#![feature(ptr_offset_from)]

extern crate libc;

extern crate opensc_sys;
//extern crate bitintr; //no_cdecl.rs
//extern crate ring;
//use ring::digest::{/*Context, Digest,*/ digest, SHA256/*, Algorithm, Context*/};

//extern crate data_encoding;
//use data_encoding::HEXUPPER;

use std::os::raw::{c_int, c_uint, c_void, c_char, c_uchar, c_ulong};
use std::ffi::CStr;
use std::ptr::{copy_nonoverlapping};
use std::collections::HashMap;
//use std::fs;

use opensc_sys::opensc::{sc_card, sc_card_driver, sc_card_operations, sc_pin_cmd_data, sc_security_env,
sc_get_iso7816_driver, sc_file_add_acl_entry, sc_format_path, sc_file_set_prop_attr, sc_transmit_apdu,
sc_bytes2apdu_wrapper, sc_check_sw, SC_CARD_CAP_RNG, SC_CARD_CAP_USE_FCI_AC, SC_READER_SHORT_APDU_MAX_SEND_SIZE,
SC_READER_SHORT_APDU_MAX_RECV_SIZE, SC_ALGORITHM_RSA, SC_ALGORITHM_ONBOARD_KEY_GEN, SC_ALGORITHM_RSA_RAW,
SC_SEC_OPERATION_SIGN, SC_SEC_OPERATION_DECIPHER, SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION_DERIVE,
SC_PIN_CMD_GET_INFO, SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK, SC_ALGORITHM_RSA_PAD_PKCS1,
SC_ALGORITHM_RSA_PAD_ISO9796, SC_ALGORITHM_RSA_HASH_NONE, SC_SEC_ENV_KEY_REF_PRESENT, SC_SEC_ENV_ALG_REF_PRESENT,
SC_SEC_ENV_ALG_PRESENT, SC_ALGORITHM_3DES, SC_ALGORITHM_DES/*, sc_file_new, sc_file_free, sc_select_file*/
};

#[cfg(not(    v0_15_0))]
use opensc_sys::opensc::{SC_CARD_CAP_ISO7816_PIN_INFO};
#[cfg(not(any(v0_15_0, v0_16_0)))]
use opensc_sys::opensc::{SC_CARD_CAP_SESSION_PIN/*, SC_PIN_CMD_GET_SESSION_PIN*/, SC_ALGORITHM_AES};
#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0)))]
use opensc_sys::opensc::{SC_SEC_ENV_KEY_REF_SYMMETRIC};
//#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
//use opensc_sys::opensc::{SC_ALGORITHM_RSA_PAD_PSS};
#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
use opensc_sys::opensc::{SC_SEC_ENV_PARAM_IV, SC_SEC_ENV_PARAM_TARGET_FILE, SC_ALGORITHM_AES_FLAGS,
                         SC_ALGORITHM_AES_CBC_PAD, SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB/*, SC_SEC_OPERATION_WRAP, SC_SEC_OPERATION_UNWRAP*/};

use opensc_sys::types::{/*sc_aid, sc_path, SC_MAX_AID_SIZE, SC_PATH_TYPE_FILE_ID, sc_file_t, SC_MAX_ATR_SIZE, */
    sc_apdu, sc_path, sc_file, sc_serial_number, SC_PATH_TYPE_PATH, SC_FILE_TYPE_INTERNAL_EF, SC_MAX_PATH_SIZE,
//    SC_PATH_TYPE_PATH_PROT, SC_PATH_TYPE_FROM_CURRENT, SC_PATH_TYPE_PARENT, SC_PATH_TYPE_FILE_ID, SC_MAX_CRTS_IN_SE,
    /* SC_AC_UNKNOWN, SC_AC_NEVER, SC_AC_PRO, SC_AC_AUT, sc_crt,*/ //SC_AC_CHV,
    SC_FILE_TYPE_DF, SC_FILE_EF_TRANSPARENT, SC_AC_NONE, SC_AC_KEY_REF_NONE,
    SC_AC_OP_LIST_FILES,
    SC_AC_OP_SELECT,
    SC_AC_OP_DELETE, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK,
    SC_AC_OP_READ,   SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO, SC_AC_OP_DELETE_SELF,
    SC_AC_OP_CREATE, SC_AC_OP_WRITE, SC_AC_OP_GENERATE, SC_APDU_FLAGS_CHAINING, SC_APDU_FLAGS_NO_GET_RESP,

    SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT, SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT
};

use opensc_sys::errors::{sc_strerror, SC_SUCCESS, SC_ERROR_INTERNAL, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_KEYPAD_MSG_TOO_LONG,
                         SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INCOMPATIBLE_KEY, SC_ERROR_WRONG_CARD, SC_ERROR_WRONG_PADDING,
                         SC_ERROR_INCORRECT_PARAMETERS, SC_ERROR_NOT_SUPPORTED, SC_ERROR_BUFFER_TOO_SMALL};
use opensc_sys::internal::{_sc_card_add_rsa_alg, sc_pkcs1_encode};
#[cfg(    any(v0_15_0, v0_16_0))]
use opensc_sys::internal::{sc_atr_table};
#[cfg(not(any(v0_15_0, v0_16_0)))]
use opensc_sys::internal::{_sc_match_atr};

use opensc_sys::log::{sc_do_log, sc_dump_hex, SC_LOG_DEBUG_NORMAL};
use opensc_sys::cardctl::{SC_CARDCTL_GET_SERIALNR, SC_CARDCTL_LIFECYCLE_SET};
use opensc_sys::asn1::{sc_asn1_find_tag, sc_asn1_put_tag/*, sc_asn1_skip_tag, sc_asn1_read_tag, sc_asn1_print_tags*/};
use opensc_sys::iso7816::{ISO7816_TAG_FCP_TYPE, ISO7816_TAG_FCP_LCS,  ISO7816_TAG_FCP, ISO7816_TAG_FCP_SIZE,
                          ISO7816_TAG_FCP_FID};
use opensc_sys::pkcs15::{sc_pkcs15_pubkey_rsa, sc_pkcs15_bignum, sc_pkcs15_encode_pubkey_rsa, sc_pkcs15_bind,
                         sc_pkcs15_unbind, sc_pkcs15_auth_info, sc_pkcs15_get_objects, SC_PKCS15_TYPE_AUTH_PIN, sc_pkcs15_object}; // , SC_PKCS15_AODF

#[allow(dead_code)]
pub mod    cmd_card_info;
use crate::cmd_card_info::*;

#[allow(dead_code)]
pub mod    constants_types;
use crate::constants_types::*;

#[allow(dead_code)]
pub mod    missing_exports;
use crate::missing_exports::{me_card_add_symmetric_alg, me_card_find_alg, me_get_max_recv_size,
                             me_pkcs1_strip_01_padding//, me_get_encoding_flags
};

#[allow(dead_code)]
pub mod    no_cdecl;
use crate::no_cdecl::{select_file_by_path, convert_bytes_tag_fcp_sac_to_scb_array, enum_dir,
    pin_get_policy, track_iso7816_select_file, acos5_64_atrs_supported,
                      /*encrypt_public_rsa,*/ get_sec_env, set_sec_env,// get_rsa_caps,
    get_is_running_cmd_long_response, set_is_running_cmd_long_response, is_any_known_digestAlgorithm,
    sym_en_decrypt,
    generate_asym, encrypt_asym, get_files_hashmap_info, update_hashmap,
    logical_xor
};
// choose new name ? denoting, that there are rust-mangled, non-externC functions, that don't relate to se
// (security environment) nor relate to sm (secure messaging) nor relate to pkcs15/pkcs15-init

#[allow(dead_code)]
pub mod    path;
use crate::path::*;

#[allow(dead_code)]
pub mod    se;
use crate::se::{se_file_add_acl_entry};

#[allow(dead_code)]
#[cfg(enable_acos5_64_ui)]
pub mod    user_consent;
#[cfg(enable_acos5_64_ui)]
use crate::user_consent::{set_ui_ctx, get_ui_ctx, acos5_64_ask_user_consent};


#[allow(dead_code)]
pub mod    wrappers;
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
        if unsafe { CStr::from_ptr(name) } == CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap()
        { acos5_64_get_card_driver }
        else
        { unsafe { std::mem::transmute::<usize, extern "C" fn() -> *mut sc_card_driver>(0) } };
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
    /* SM: all usages of iso7816_ functions must be re-evaluated for the subset, that ACOS5-64 is able to alternatively support via SM */
    let b_sc_card_operations : Box<sc_card_operations> = Box::new( sc_card_operations {
        match_card:            Some(acos5_64_match_card),        // no_match     is insufficient for cos5: It just doesn't match any ATR
        init:                  Some(acos5_64_init),              // iso7816_init is insufficient for cos5: It just returns SC_SUCCESS without doing anything
        finish:                Some(acos5_64_finish),            // NULL
        /* when SM get's introduced for SM mode acl, all SM-capable file ops binary/record must be replaced
           ATTENTION: calling the iso7816_something_record functions requires using flag SC_RECORD_BY_REC_NR  or it won't work as expected !!!
        */
        erase_binary:          Some(acos5_64_erase_binary),      // NULL
        select_file:           Some(acos5_64_select_file),       // iso7816_select_file is insufficient for cos5: It will be used, but in a controlled manner only
        get_response:          Some(acos5_64_get_response),      // iso7816_get_response is insufficient for some cos5 commands with more than 256 bytes to fetch
            /* get_challenge:  iso7816_get_challenge  is usable, but only with P3==8, thus a wrapper is required */
        get_challenge:         Some(acos5_64_get_challenge),     // iso7816_get_challenge
        /* verify:                NULL, deprecated */
        logout:                Some(acos5_64_logout),            // NULL
        /* restore_security_env                                  // iso7816_restore_security_env */
        set_security_env:      Some(acos5_64_set_security_env),  // iso7816_set_security_env
            /* iso7816_set_security_env doesn't work for signing; do set CRT B6 and B8 */
        decipher:              Some(acos5_64_decipher),          // iso7816_decipher,  not suitable for cos5
        compute_signature:     Some(acos5_64_compute_signature), // iso7816_compute_signature,  not suitable for cos5
        /* change_reference_data: NULL, deprecated */
        /* reset_retry_counter:   NULL, deprecated */
            /* create_file: iso7816_create_file  is usable, provided that construct_fci is suitable */
        create_file:           Some(acos5_64_create_file),       // iso7816_create_file
            /* delete_file: iso7816_delete_file  is usable, BUT pay ATTENTION, how path.len selects among alternatives;
                        AND, even with path, it must first be selected */
        delete_file:           Some(acos5_64_delete_file),       // iso7816_delete_file
        list_files:            Some(acos5_64_list_files),        // NULL
        /* check_sw:                                         // iso7816_check_sw
            iso7816_check_sw basically is usable except that for pin_cmd cmd=SC_PIN_CMD_GET_INFO, the correct answer like
            0x63C8 (8 tries left) is interpreted as a failing pin verification trial (SC_ERROR_PIN_CODE_INCORRECT)
            thus trying to go with iso7816_check_sw, reroute that pin_cmd cmd=SC_PIN_CMD_GET_INFO to not employ check_sw
           TODO  iso7816_check_sw has an internal table to map return status to text: this doesn't match the ACOS5 mapping in some cases, THUS maybe switching on/off check_sw==iso7816_check_sw may be required
        */
        card_ctl:              Some(acos5_64_card_ctl),          // NULL
        process_fci:           Some(acos5_64_process_fci),       // iso7816_process_fci is insufficient for cos5: It will be used, but more has to be done for cos5
        construct_fci:         Some(acos5_64_construct_fci),     // iso7816_construct_fci
        pin_cmd:               Some(acos5_64_pin_cmd),           // iso7816_pin_cmd
            /* pin_cmd:
            SC_PIN_CMD_GET_INFO: iso7816_pin_cmd not suitable for SC_PIN_CMD_GET_INFO (only because the status word is
                                   mis-interpreted by iso7816_check_sw as failed pin verification)
            SC_PIN_CMD_VERIFY:   iso7816_pin_cmd is okay for  SC_PIN_CMD_VERIFY
            SC_PIN_CMD_CHANGE:   iso7816_pin_cmd is okay for  SC_PIN_CMD_CHANGE
            SC_PIN_CMD_UNBLOCK:  iso7816_pin_cmd is okay for  SC_PIN_CMD_UNBLOCK
            */
        get_data: Some(acos5_64_get_data),                       // iso7816_get_data (usable except wrong cla byte) calls cos5 'Get Key'
        /* put_data:                                             NULL, */
        /* delete_record:                                        NULL, */
        read_public_key:       Some(acos5_64_read_public_key),   // NULL
        /* card_reader_lock_obtained:                            NULL, */
        /* wrap:                                                 NULL, */
        /* unwrap:                                               NULL, */

        ..iso_ops // untested so far whether remaining functionality from iso is sufficient for cos5
/* from iso_ops:
    iso7816_read_binary,
    iso7816_write_binary,
    iso7816_update_binary,

    iso7816_read_record,
    iso7816_write_record,
    iso7816_append_record,
    iso7816_update_record,

    NULL,            /* verify,                deprecated */
    iso7816_restore_security_env,
    NULL,            /* change_reference_data, deprecated */
    NULL,            /* reset_retry_counter,   deprecated */

    iso7816_check_sw,

    NULL,            /* put_data */
    NULL,            /* delete_record */

    NULL,            /* card_reader_lock_obtained */
    NULL,            /* wrap */
    NULL             /* unwrap */
*/
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
 * @return 1 on success (this driver will serve the card), 0 otherwise
 */
extern "C" fn acos5_64_match_card(card: *mut sc_card) -> c_int
{
    if card.is_null() {
        return 0;
    }

    let card_ref     : &sc_card     = unsafe { &    *card };
    let card_ref_mut : &mut sc_card = unsafe { &mut *card };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_match_card\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ref.ctx, f_log, line!(),fun,unsafe{sc_dump_hex(card_ref.atr.value.as_ptr(), card_ref.atr.len)},
            CStr::from_bytes_with_nul(b"called. Try to match card with ATR %s\0").unwrap() );
    }

    #[cfg(any(v0_15_0, v0_16_0))]
    let acos5_64_atrs : [sc_atr_table; 1] = [Default::default()]; // only because: _sc_match_atr is not callable: OpenSC not patched / not implemented
    #[cfg(any(v0_17_0, v0_18_0))]
    let mut acos5_64_atrs = acos5_64_atrs_supported();
    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
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
            wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Card doesn't match: \
                      Differing ATR\0").unwrap());
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
        let rv = acos5_64_card_ctl(card_ref_mut, SC_CARDCTL_ACOS5_GET_COS_VERSION,
                                   &mut cos_version as *mut CardCtlArray8 as *mut c_void);
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"cos_version: %02X %02X %02X %02X %02X %02X %02X %02X (rv %d)\0").unwrap();
            wr_do_log_8u8_i32(card_ref.ctx, f_log, line!(), fun, fmt, cos_version.value, rv);
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
                wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
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
                    wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
                }
                // FIXME try to change the operation mode byte if there is no MF
                let mf_path_ref: &sc_path = unsafe { &*sc_get_mf_path() };
                let mut file : *mut sc_file = std::ptr::null_mut();
                let mut rv = unsafe { sc_select_file(card_ref_mut, mf_path_ref, &mut file) };
                println!("rv from sc_select_file: {}, file: {:?}", rv, file); // rv from sc_select_file: -1200, file: 0x0
                let fmt = CStr::from_bytes_with_nul(b"Card doesn't match: sc_transmit_apdu or 'change to operation mode 64K' failed ! Have a look into docs how to change the mode of operation to Non-FIPS/64K mode. No other mode is supported currently\0").unwrap();
                if rv == SC_SUCCESS {
                    #[cfg(log)]
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
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
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
                    return 0;
                }
                else {
                    let fmt = CStr::from_bytes_with_nul(b"Card was set to Operation Mode 64K (SUCCESS) !\0").unwrap();
                    #[cfg(log)]
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), fmt.as_ptr()) };
                }
            }
        }
    / **/

    // Only now, on success,   set card.type
    card_ref_mut.type_ = type_out;
    if cfg!(log) {
        wr_do_log_t(card_ref.ctx, f_log, line!(), fun, acos5_64_atrs[idx_acos5_64_atrs].name,
                    CStr::from_bytes_with_nul(b"'%s' card matched\0").unwrap());
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

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_init\0").unwrap();
    if cfg!(log) {
        wr_do_log_tu(card_ref.ctx, f_log, line!(), fun, card_ref.type_, unsafe {sc_dump_hex(card_ref.atr.value.as_ptr(),
        card_ref.atr.len) }, CStr::from_bytes_with_nul(b"called with card.type: %d, card.atr.value: %s\0").unwrap());
    }
    /* Undo 'force_card_driver = acos5_64;'  if match_card reports 'no match' */
    for elem in &acos5_64_atrs_supported() {
        if elem.atr.is_null() {
            if cfg!(log) {
                wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"### Error, have to skip \
                    external driver 'acos5_64'! Got here, though match_card reported 'no match' (probably by using \
                    'force_card_driver = acos5_64;') ###\0").unwrap());
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
    /* max_send_size  IS  treated as a constant (won't change) */
    card_ref_mut.max_send_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; // 0x0FF; // 0x0FFFF for usb-reader, 0x0FF for chip/card;  Max Lc supported by the card
    /* max_recv_size  IS NOT  treated as a constant (it will be set temporarily to SC_READER_SHORT_APDU_MAX_RECV_SIZE where commands do support interpreting le byte 0 as 256 (le is 1 byte only!), like e.g. acos5_64_compute_signature) */
    /* some commands return 0x6100, meaning, there are 256==SC_READER_SHORT_APDU_MAX_RECV_SIZE  bytes (or more) to fetch */
    card_ref_mut.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; //reduced as long as iso7816_read_binary is used: 0==0x100 is not understood // 0x100; // 0x10000 for usb-reader, 0x100 for chip/card;  Max Le supported by the card, decipher (in chaining mode) with a 4096-bit key returns 2 chunks of 256 bytes each !!

    /* possibly more SC_CARD_CAP_* apply, TODO clarify */
    card_ref_mut.caps    = (SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC) as c_ulong;
    #[cfg(not(v0_15_0))]
    { card_ref_mut.caps |=  SC_CARD_CAP_ISO7816_PIN_INFO as c_ulong; }
    #[cfg(not(any(v0_15_0, v0_16_0)))]
    { card_ref_mut.caps |=  SC_CARD_CAP_SESSION_PIN      as c_ulong; }
    /* card_ref_mut.caps |= SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH   what exactly is this? */ //#[cfg(not(any(v0_15_0, v0_16_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_ONCARD_SESSION_OBJECTS          what exactly is this? */ //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_WRAP_KEY */    //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* card_ref_mut.caps |= SC_CARD_CAP_UNWRAP_KEY */  //#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    /* The reader of USB CryptoMate64/CryptoMate Nano supports extended APDU, but the card doesn't: Thus no SC_CARD_CAP_APDU_EXT */

    let rsa_algo_flags = SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_RSA_PAD_PKCS1;
//  #[cfg(    any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))]
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_RAW; // PSS works with that only currently via acos5_64_decipher; declaring SC_ALGORITHM_RSA_PAD_PSS seems superfluous
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_PAD_PKCS1;
//    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
//    { rsa_algo_flags |= SC_ALGORITHM_RSA_PAD_PSS; }
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_PAD_ISO9796; // cos5 supports ISO9796, but don't use this, see https://www.iacr.org/archive/eurocrypt2000/1807/18070070-new.pdf
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_PAD_NONE; // for cfg!(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)) this is a NOOP, as SC_ALGORITHM_RSA_PAD_NONE is zero then

    /* SC_ALGORITHM_NEED_USAGE : Don't use that: the driver will handle that for sign internally ! */
    /* Though there is now some more hash related info in opensc.h, still it's not clear to me whether to apply any of
         SC_ALGORITHM_RSA_HASH_NONE or SC_ALGORITHM_RSA_HASH_SHA256 etc. */
//    rsa_algo_flags |= SC_ALGORITHM_RSA_HASH_NONE;
//    rsa_algo_flags |= SC_ALGORITHM_RSA_HASH_SHA256;
//    rsa_algo_flags |= SC_ALGORITHM_MGF1_SHA256;

    let is_v3_fips_compliant = card_ref.type_ == SC_CARD_TYPE_ACOS5_64_V3 &&
        get_op_mode_byte(card_ref_mut).unwrap()==0 && get_fips_compliance(card_ref_mut).unwrap();
    let mut rv;
    let     rsa_key_len_from : u32 = if is_v3_fips_compliant { 2048 } else {  512 };
    let     rsa_key_len_step : u32 = if is_v3_fips_compliant { 1024 } else {  256 };
    let     rsa_key_len_to   : u32 = if is_v3_fips_compliant { 3072 } else { 4096 };
    let mut rsa_key_len = rsa_key_len_from;
    while   rsa_key_len <= rsa_key_len_to {
        rv = unsafe { _sc_card_add_rsa_alg(card_ref_mut, rsa_key_len, rsa_algo_flags as c_ulong, 0/*0x10001*/) };
        if rv != SC_SUCCESS {
            return rv;
        }
        rsa_key_len += rsa_key_len_step;
    }

    /* ACOS5_64 is capable of DES, but I think we can just skip that insecure algo; and the next, 3DES/128 with key1==key3 should NOT be used */
//    me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_3DES as c_uint,  128, 0);
    me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_3DES as c_uint,  192, 0);

    #[cfg(not(any(v0_15_0, v0_16_0)))]
    {
        let aes_algo_flags : c_uint;
        #[cfg(    any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))]
        { aes_algo_flags = 0; }
        #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
        { aes_algo_flags = SC_ALGORITHM_AES_FLAGS; }
        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  128, aes_algo_flags);
        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  192, aes_algo_flags);
        me_card_add_symmetric_alg(card_ref_mut, SC_ALGORITHM_AES as c_uint,  256, aes_algo_flags);
        assert!(!me_card_find_alg(card_ref_mut, SC_ALGORITHM_AES, 256, std::ptr::null_mut() as *mut c_void).is_null());
    }
////////////////////////////////////////
    /* stores serialnr in card.serialnr, required for enum_dir */
    match get_serialnr(card_ref_mut) {
        Ok(_val) => (),
        Err(e) => return e,
    };
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
        sec_env: Default::default(),
        rsa_caps: rsa_algo_flags,
        is_running_init: true,
        is_running_cmd_long_response: false,
        do_generate_rsa_crt: true,
        do_generate_rsa_add_decrypt: true,
        do_generate_rsa_standard_pub_exponent: true,
        #[cfg(enable_acos5_64_ui)]
        ui_ctx: Default::default(),
    } );
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
    let mut path = Default::default();
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F00\0").unwrap().as_ptr(), &mut path); } // type = SC_PATH_TYPE_PATH;
    rv = enum_dir(card_ref_mut, &path, true/*, 0*/); /* FIXME Doing to much here degrades performance, possibly for no value */
    assert_eq!(rv, SC_SUCCESS);

    let mut dp= unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };
    dp.files.shrink_to_fit();
    dp.is_running_init = false;

    #[cfg(enable_acos5_64_ui)]
    {
        /* read environment from configuration file */
//println!("dp.ui_ctx.user_consent_enabled: {}", dp.ui_ctx.user_consent_enabled);
        rv = set_ui_ctx(card_ref_mut, &mut dp.ui_ctx);
//println!("dp.ui_ctx.user_consent_enabled: {}", dp.ui_ctx.user_consent_enabled);
        if rv < SC_SUCCESS {
            wr_do_log_sds(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"set_ui_ctx failed.\0").unwrap().as_ptr(),
                          rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap() );
        }
    }
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
    rv
} // acos5_64_init


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
    let card_ref        = unsafe { &*card };
    let card_ref_mut = unsafe { &mut *card };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_finish\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
////////////////////
//    acos5_64_logout(card);
    /* some testing code, unrelated (to acos5_64_finish) */
/*
        let mut path = Default::default();
        unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F004100\0").unwrap().as_ptr(), &mut path) };
        let mut rv =  unsafe { sc_select_file(card_ref_mut, &path, std::ptr::null_mut()/*file: *mut *mut sc_file*/) };
        assert_eq!(rv, SC_SUCCESS);

        let file_ref_mut = unsafe { &mut *sc_file_new() };
        // file MUST have assigned 'type_attr' and 'sec_attr', id,
        file_ref_mut.id = 0x4104;
        file_ref_mut.type_attr_len = 6;
        file_ref_mut.type_attr = unsafe { libc::malloc(file_ref_mut.type_attr_len) as *mut c_uchar };
        unsafe { copy_nonoverlapping([0x02u8, 0x00, 0x00, 0x15, 0x00, 0x01].as_ptr(), file_ref_mut.type_attr, file_ref_mut.type_attr_len) };
        file_ref_mut.sec_attr_len = 8;
        file_ref_mut.sec_attr = unsafe { libc::malloc(file_ref_mut.sec_attr_len) as *mut c_uchar };
        unsafe { copy_nonoverlapping([0x7Fu8, 0x03, 0xFF, 0x00, 0xFF, 0xFF, 0x01, 0xFF].as_ptr(), file_ref_mut.sec_attr, file_ref_mut.sec_attr_len) };

    //    let mut outlen = 86usize;
    //    let mut out = [0u8; 86];
        rv = acos5_64_create_file(card, file_ref_mut);
    //    let rv = acos5_64_construct_fci(card_ref_mut, file_ref_mut,out.as_mut_ptr(), &mut outlen);
        unsafe { sc_file_free(file_ref_mut) };
*/
/*
    let mut path = Default::default();
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F004100\0").unwrap().as_ptr(), &mut path) };
    let mut rv =  unsafe { sc_select_file(card_ref_mut, &path, std::ptr::null_mut()/*file: *mut *mut sc_file*/) };
    assert_eq!(rv, SC_SUCCESS);
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"i3908\0").unwrap().as_ptr(), &mut path) };
    rv = acos5_64_delete_file(card, &path);
*/
/*
       let mut path = Default::default();
       unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F0041003908\0").unwrap().as_ptr(), &mut path) };
       let mut rv = unsafe { sc_select_file(card, &path, std::ptr::null_mut()) };
       assert_eq!(rv, SC_SUCCESS);
       rv = acos5_64_erase_binary(card_ref_mut, 1, 0xFFFF, 0);

           let file_ref_mut = unsafe { &mut *sc_file_new() };
           file_ref_mut.id = 0x4101;
           file_ref_mut.type_attr_len = 6;
           file_ref_mut.type_attr = unsafe { libc::malloc(file_ref_mut.type_attr_len) as *mut c_uchar };
           unsafe { copy_nonoverlapping([0x0Au8, 0x00, 0x00, 0x15, 0x00, 0x01].as_ptr(), file_ref_mut.type_attr, file_ref_mut.type_attr_len) };
       // file MUST have assigned 'type_attr' and 'sec_attr'
           file_ref_mut.sec_attr_len = 8;
           file_ref_mut.sec_attr = unsafe { libc::malloc(file_ref_mut.sec_attr_len) as *mut c_uchar };
           unsafe { copy_nonoverlapping([0x7Fu8, 0x03, 0xFF, 0x00, 0xFF, 0xFF, 0x01, 0xFF].as_ptr(), file_ref_mut.sec_attr, file_ref_mut.sec_attr_len) };

           let mut outlen = 86usize;
           let mut out = [0u8; 86];
           let rv = acos5_64_construct_fci(card_ref_mut, file_ref_mut,out.as_mut_ptr(), &mut outlen);
           assert_eq!(rv, SC_SUCCESS);
           unsafe { sc_file_free(file_ref_mut) };
       println!("acos5_64_construct_fci: outlen: {}, out: {:X?}", outlen, &out[..24]);
       //acos5_64_construct_fci: outlen: 24, out: [62, 16, 83, 2, 41, 1, 82, 6, A, 0, 0, 15, 0, 1, 8C, 8, 7F, 3, FF, 0, FF, FF, 1, FF]
       */

    /* * /
    let mut path = Default::default();
    unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F0041004121\0").unwrap().as_ptr(), &mut path) };
    let rv = unsafe { sc_select_file(card, &path, std::ptr::null_mut()) };
    assert_eq!(rv, SC_SUCCESS);
    let path_file = CStr::from_bytes_with_nul(b"/path/to/cert.der\0").unwrap();
    let read_result = fs::read(path_file.to_str().unwrap());
    let rv = unsafe { sc_update_binary(card, 0, read_result.unwrap().as_ptr(), 1637, 0) };
    assert_eq!(rv, 1637);
/ * */

    /* another testing area for acos5_64_card_ctl * /
        let mut path= Default::default();
        unsafe { sc_format_path(CStr::from_bytes_with_nul(b"3F0041004102\0").unwrap().as_ptr(), &mut path) };
        let mut rv =  unsafe { sc_select_file(card_ref_mut, &path, std::ptr::null_mut()/*file: *mut *mut sc_file*/) };
        assert_eq!(rv, SC_SUCCESS);
        let mut tries_left= 0i32;
//        rv = unsafe { sc_verify(card_ref_mut, SC_AC_CHV, 0x81, [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38].as_ptr(), 8, &mut tries_left) };
        assert_eq!(rv, SC_SUCCESS);

        let mut crypt_sym = CardCtl_crypt_sym {
            indata: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
                     0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            indata_len:  33,
            outdata_len: 32, // experimental, not the real limit
    //        iv:  [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 14, 15, 16],
    //        iv_len: 16,
            key_ref: 0x83, // has stored a 256 bit key for AES usage

    //        pad_type: BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5,//BLOCKCIPHER_PAD_TYPE_ANSIX9_23, //BLOCKCIPHER_PAD_TYPE_PKCS5, //BLOCKCIPHER_PAD_TYPE_ZEROES,
            perform_mse: true,
    /*
            block_size: 16,
            key_len: 32,
            pad_type: BLOCKCIPHER_PAD_TYPE_PKCS5,
            local: true,
            cbc: true,
            encrypt : true,
            perform_mse: false,
    */
            .. Default::default()
        };
        rv = acos5_64_card_ctl(card_ref_mut, SC_CARDCTL_ACOS5_ENCRYPT_SYM.into(), &mut crypt_sym as *mut CardCtl_crypt_sym as *mut c_void);
        println!("rv: {}, outdata_len: {}", rv, crypt_sym.outdata_len);
        if rv == SC_SUCCESS {
            println!("indata_len:      {}",   &crypt_sym.indata_len);
            println!("outdata[ 0..32]: {:?}", &crypt_sym.outdata[ 0..32]);
            println!("outdata[32..{}]: {:?}", crypt_sym.outdata_len, &crypt_sym.outdata[32..crypt_sym.outdata_len]);
        }
    / **/
////////////////////
    assert!(!card_ref.drv_data.is_null(), "drv_data is null");
    let dp : Box<DataPrivate> = unsafe { Box::from_raw(card_ref.drv_data as *mut DataPrivate) };
//    println!("Hashmap: {:?}", dp.files);
//    there may be other Boxes that might need to be taken over again
    drop(dp);
    card_ref_mut.drv_data = std::ptr::null_mut();
    SC_SUCCESS
}


/**
  Erases bytes (i.e. sets bytes to value 0x00) in a transparent file, within a chosen range of file's size
  The underlying card command does that beginning from a start_offset until either end_offset or end of file
  This OpenSC function has the parameter idx for start_offset, and a parameter 'count' for how many bytes shall be cleared to zero.
  Use the special value count=0xFFFF (a value far beyond possible file sizes) in order to denote clearing bytes until the end of the file
  TODO check what happens if end_offset > file's size

@param count indicates the number of bytes to erase"
@return SC_SUCCESS or other SC_..., NO length !
@requires prior file selection
*/
extern "C" fn acos5_64_erase_binary(card: *mut sc_card, idx: c_uint, count: usize, flags: c_ulong) -> c_int
{
    assert!(!card.is_null());
    let card_ref_mut = unsafe { &mut *card };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_erase_binary\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    let mut data = [0x00u8, 0x00];
    let command = [0x00u8, 0x0E, 0x00, 0x00,  0x02, 0xFF, 0xFF];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
    apdu.flags = flags;

    if idx != 0 {
        apdu.p1 = ((idx >> 8) as u8) & 0xFF; // start_offset (included)
        apdu.p2 = (idx & 0xFF) as u8;        // dito
    }
    if count == 0xFFFF {
        apdu.cse = SC_APDU_CASE_1;
        apdu.lc = 0;
        apdu.datalen = 0;
        apdu.data = std::ptr::null();
    }
    else {
        let end_offset =  idx + count as c_uint; // end_offset (not included; i.e. byte at that address doesn't get erased)
        data[0] = ((end_offset >> 8) as u8) & 0xFF;
        data[1] = (end_offset & 0xFF) as u8;
        apdu.data = data.as_ptr();
    }

    rv = unsafe { sc_transmit_apdu(card_ref_mut, &mut apdu) };
    if rv != SC_SUCCESS || apdu.sw1!=0x90 || apdu.sw2!=0x00 {
        if cfg!(log) {
            wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"#### Failed to erase binary\0")
                .unwrap());
        }
    }
    rv
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
    let card_ref_mut = unsafe { &mut *card };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_card_ctl\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    match command as c_uint {
        SC_CARDCTL_LIFECYCLE_SET =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else              { SC_ERROR_NOT_SUPPORTED }, // see sc_pkcs15init_bind
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
        SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF =>
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
        SC_CARDCTL_ACOS5_GET_FILE_INFO=>
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
        SC_CARDCTL_ACOS5_GET_FREE_SPACE=>
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
        SC_CARDCTL_ACOS5_GET_IDENT_SELF=>
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
        SC_CARDCTL_ACOS5_GET_COS_VERSION=>
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


        SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE=>
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
        SC_CARDCTL_ACOS5_GET_ROM_SHA1=>
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
        SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE=>
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
        SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE =>
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
        SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE=>
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
        SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE=>
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
        SC_CARDCTL_ACOS5_HASHMAP_GET_FILE_INFO=>
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
        SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO =>
            {
                update_hashmap(card_ref_mut);
                SC_SUCCESS
            },
        SC_CARDCTL_ACOS5_SDO_CREATE =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                acos5_64_create_file(card, data as *mut sc_file)
            },
        SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_EXIST =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let generate_crypt_asym_data = unsafe { &mut *(data as *mut CardCtl_generate_crypt_asym) };
                /* suppose select_file, authenticate, (possibly setting MSE) etc. was done already */
                generate_asym(card_ref_mut, generate_crypt_asym_data)
            },
        SC_CARDCTL_ACOS5_ENCRYPT_ASYM =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let generate_crypt_asym_data = unsafe { &mut *(data as *mut CardCtl_generate_crypt_asym) };
                /* suppose select_file, authenticate, (possibly setting MSE) etc. was done already */
                encrypt_asym(card_ref_mut, generate_crypt_asym_data, false)
            },
        SC_CARDCTL_ACOS5_ENCRYPT_SYM |
        SC_CARDCTL_ACOS5_DECRYPT_SYM     =>
            if data.is_null() { SC_ERROR_INVALID_ARGUMENTS }
            else {
                let crypt_sym_data = unsafe { &mut *(data as *mut CardCtl_crypt_sym) };
                if !logical_xor(crypt_sym_data.outdata_len > 0, !crypt_sym_data.outfile.is_null())  ||
                   !logical_xor(crypt_sym_data.indata_len  > 0, !crypt_sym_data.infile.is_null())   ||
                   ![8u8, 16].contains(&crypt_sym_data.block_size)  ||
                   ![BLOCKCIPHER_PAD_TYPE_ZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5,
                        BLOCKCIPHER_PAD_TYPE_PKCS5, BLOCKCIPHER_PAD_TYPE_ANSIX9_23/*, BLOCKCIPHER_PAD_TYPE_W3C*/]
                        .contains(&crypt_sym_data.pad_type)
//                    || crypt_sym_data.iv != [0u8; 16]
                { return SC_ERROR_INVALID_ARGUMENTS; }

                let rv = sym_en_decrypt(card_ref_mut, crypt_sym_data);
                if rv > 0 {SC_SUCCESS} else {SC_ERROR_KEYPAD_MSG_TOO_LONG}
            },
        _   => SC_ERROR_NO_CARD_SUPPORT
    }
} // acos5_64_card_ctl

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

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_select_file\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(b"        called\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, fmt);
    }

    if path_ref.type_ == SC_PATH_TYPE_PATH {
        let len = path_ref.len;
        let path_target = &path_ref.value[..len];
        let current_path_df = current_path_df(card_ref_mut);
        let path1 = sc_path { value: [path_ref.value[len-2],  path_ref.value[len-1], 0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2, ..Default::default() }; // SC_PATH_TYPE_FILE_ID
        if      is_search_rule1_match(path_target, current_path_df) { // path_target is the currently selected DF: select_file MUST NOT be dropped
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule1_match: \
                    true (select_file target is the currently selected DF)\0").unwrap());
            }
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule2_match(path_target, current_path_df) { // path_target is a EF/DF located (directly) within currently selected DF: select_file MUST NOT be dropped
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule2_match: \
                    true (select_file target is a EF/DF located (directly) within currently selected DF)\0").unwrap());
            }
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule3_match(path_target, current_path_df) {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule3_match: \
                    true (select_file target is the parent DF of currently selected DF)\0").unwrap());
            }
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule4_match(path_target, current_path_df) {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule4_match: \
true (select_file target is a EF/DF located (directly) within the parent DF of currently selected DF)\0").unwrap());
            }
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule5_match(path_target) {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule5_match: \
                    true (select_file target is MF)\0").unwrap());
            }
            return track_iso7816_select_file(card_ref_mut, &path1, file_out)
        }
        else if is_search_rule6_match(path_target) {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"        is_search_rule6_match: \
                    true (select_file target is a EF/DF located (directly) within MF)\0").unwrap());
            }
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
6C XXh    Incorrect P3. Value must be XXh.       actually OpenSC catches this and retransmits once with corrected XX
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
    let cnt_in = unsafe { *count };
    assert!(cnt_in <= 256);
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun = CStr::from_bytes_with_nul(b"acos5_64_get_response\0").unwrap();
    let fmt = CStr::from_bytes_with_nul(b"called with: *count: %zu\0").unwrap();
    let fmt_1 = CStr::from_bytes_with_nul(b"returning with: *count: %zu, rv: %d\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_rm.ctx, f_log, line!(), fun, cnt_in, fmt);
    }

    card_rm.max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE;
    /* request at most max_recv_size bytes */
    let rlen = std::cmp::min(cnt_in, me_get_max_recv_size(card_rm));
    unsafe{ *count = 0 };
//println!("### acos5_64_get_response rlen: {}", rlen);
    let command = [0u8, 0xC0, 0x00, 0x00, 0xFF]; // will replace le later; the last byte is a placeholder only for sc_bytes2apdu_wrapper
    let mut apdu : sc_apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card_rm.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);
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
        if cfg!(log) {
            wr_do_log_tu(card_rm.ctx, f_log, line!(), fun, unsafe { *count }, rv, fmt_1);
        }
        card_rm.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
        return rv;
    }
    if !(apdu.sw1==0x6A && apdu.sw2==0x88) && apdu.resplen == 0 {
//    LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if cfg!(log) {
            wr_do_log_tu(card_rm.ctx, f_log, line!(), fun, unsafe { *count }, rv, fmt_1);
        }
        card_rm.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
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
    if cfg!(log) {
        wr_do_log_tu(card_rm.ctx, f_log, line!(), fun, unsafe { *count }, rv, fmt_1);
    }

    card_rm.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
    rv
}

/*
 * Get data from card's PRNG; as card's command supplies a fixed number of 8 bytes, some administration is required for count!= multiple of 8
 * @apiNote
 * @param count how many bytes are requested from RNG
 * @return MUST return the number of challenge bytes stored to buf
 */
extern "C" fn acos5_64_get_challenge(card: *mut sc_card, buf: *mut c_uchar, count: usize) -> c_int
{
    if card.is_null() || buf.is_null() || count > 1024/* 1024*/ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref_mut = unsafe { &mut *card };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun = CStr::from_bytes_with_nul(b"acos5_64_get_challenge\0").unwrap();
    let fmt = CStr::from_bytes_with_nul(b"called with request for %zu bytes\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, count, fmt);
    }
    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).get_challenge.unwrap() };
    let is_count_multiple8 =  count%8 == 0;
    let loop_count = count/8 + (if is_count_multiple8 {0usize} else {1usize});
    let mut len_rem = count;
    for i in 0..loop_count {
        if i+1<loop_count || is_count_multiple8 {
            let rv = unsafe { func_ptr(card, buf.add(i*8), 8) };
            if rv != 8 { return rv; }
            len_rem -= 8;
        }
        else {
            assert!(len_rem>0 && len_rem<8);
            let mut buf_temp = [0u8; 8];
            let rv = unsafe { func_ptr(card, buf_temp.as_mut_ptr(), 8) };
            if rv != 8 { return rv; }
            unsafe { copy_nonoverlapping(buf_temp.as_ptr(), buf.add(i*8), len_rem) };
        }
    }
/*
    if cfg!(log) {
        wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, count, CStr::from_bytes_with_nul(b"returning with requested %zu bytes supplied\0").unwrap());
    }
*/
    count as c_int
}

/* currently refers to pins only, but what about authenticated keys */
extern "C" fn acos5_64_logout(card: *mut sc_card) -> c_int
{
    if card.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref_mut = unsafe { &mut *card };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_logout\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    // FIXME content of pin_references are 'hard-coded' here: they are known via AODF
//    let pin_references = &[0x81u8, 1][..];
    let command = [0x80u8, 0x2E, 0x00, 0x00];
    let mut apdu = Default::default();
    let mut rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);

    let aid = std::ptr::null_mut();
    let mut p15card = std::ptr::null_mut();
    rv = unsafe { sc_pkcs15_bind(card, aid, &mut p15card) };
    if rv < SC_SUCCESS {
        if cfg!(log) {
            wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"failed: sc_pkcs15_bind\0").unwrap());
        }
    }
    assert!(!p15card.is_null());
    let mut p15objects : [*mut sc_pkcs15_object; 10] = [std::ptr::null_mut(); 10];
    let nn_objs = unsafe { sc_pkcs15_get_objects(p15card, SC_PKCS15_TYPE_AUTH_PIN, &mut p15objects[0], 10) } as usize;
    for i in 0..nn_objs {
        let auth_info_ref = unsafe { &*((*p15objects[i]).data as *mut sc_pkcs15_auth_info) };
        apdu.p2 = unsafe { auth_info_ref.attrs.pin.reference } as u8; //*pin_reference;
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                    (b"sc_transmit_apdu or ACOS5-64 'Logout' failed\0").unwrap());
            }
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }
    }
    rv = unsafe { sc_pkcs15_unbind(p15card) }; // calls sc_pkcs15_pincache_clear
    if rv < SC_SUCCESS {
        if cfg!(log) {
            wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"failed: sc_pkcs15_unbind\0").unwrap());
        }
    }
    SC_SUCCESS
}


/* TODO this isn't yet completed: 1. the hashmap-entry/path+fileinfo must be set and 2. there is more to do for MF/DF */
/* expects some entries in file, see acos5_64_construct_fci */
extern "C" fn acos5_64_create_file(card: *mut sc_card, file: *mut sc_file) -> c_int
{
    if card.is_null() || file.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let file_ref = unsafe { & *file };
    if file_ref.id == 0 || file_ref.type_attr.is_null() || file_ref.type_attr_len == 0 ||
                           file_ref.sec_attr.is_null()  || file_ref.sec_attr_len == 0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref_mut = unsafe { &mut *card };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_create_file\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).create_file.unwrap() };
    let rv = unsafe { func_ptr(card, file) };
    if rv != SC_SUCCESS {
        if cfg!(log) {
            wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, rv,
                        CStr::from_bytes_with_nul(b"acos5_64_create_file failed. rv: %d\0").unwrap());
        }
    }
    else {
//        let file_ref  = unsafe { & *file };
//        let buf : [u8; 2] = [((file_ref.id >> 8) as u8) & 0xFF, (file_ref.id & 0xFF) as u8];
//        let file_id = file_ref.id as u16; //u16_from_array_begin(&buf[..]);
        let mut dp = unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };
        let mut x = dp.files.entry(file_ref.id as u16).or_insert(([0u8;SC_MAX_PATH_SIZE], [9u8, 0, 0, 0, 0, 0, 0xFF, 5], None, None));
        x.0 = file_ref.path.value;
//      x.1[0] = 0x09;
        x.1[1] = file_ref.path.len as c_uchar;
        x.1[2] = file_ref.path.value[file_ref.path.len-2];
        x.1[3] = file_ref.path.value[file_ref.path.len-1];
        x.1[4] = ((file_ref.size >> 8) & 0xFF) as c_uchar;
        x.1[5] = ( file_ref.size       & 0xFF) as c_uchar;

        card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
        if cfg!(log) {
            wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, file_ref.id,
                        CStr::from_bytes_with_nul(b"file_id %04X added to hashmap\0").unwrap());
        }
    }
    rv
}

/* expects a path of type SC_PATH_TYPE_FILE_ID and a path.len of 2 or 0 (0 means: delete currently selected file) */
extern "C" fn acos5_64_delete_file(card: *mut sc_card, path: *const sc_path) -> c_int
{
    if card.is_null() || path.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ref_mut = unsafe { &mut *card };
    let path_ref= unsafe { &*path };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_delete_file\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).delete_file.unwrap() };
    let rv = unsafe { func_ptr(card, path) };
    if rv != SC_SUCCESS {
        if cfg!(log) {
            wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, rv,
                        CStr::from_bytes_with_nul(b"acos5_64_delete_file failed. rv: %d\0").unwrap());
        }
    }
    else {
        let mut dp = unsafe { Box::from_raw(card_ref_mut.drv_data as *mut DataPrivate) };
        let file_id = u16_from_array_begin(&path_ref.value[path_ref.len-2 .. path_ref.len]);
        let rm_result = dp.files.remove(&file_id);
        assert!(rm_result.is_some());
        card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;
        assert!(card_ref_mut.cache.current_path.len > 2);
//        card_ref_mut.cache.current_path.value =
        card_ref_mut.cache.current_path.len   -= 2;
        if cfg!(log) {
            wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, file_id,
                        CStr::from_bytes_with_nul(b"file_id %04X deleted from hashmap\0").unwrap());
        }
    }
    rv
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
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_list_files\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, fmt);
    }

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
//                FDB_RSA_KEY_EF       => PKCS15_FILE_TYPE_RSAPRIVATEKEY, // must be corrected for public key files later on
                _                         => PKCS15_FILE_TYPE_NONE, // the default: not relevant for PKCS#15; will be changed for some files later on
            };
            let file_id = u16_from_array_begin(&rbuf[2..4]);
            dp.files.entry(file_id).or_insert(([0u8;SC_MAX_PATH_SIZE], rbuf, None, None));
/*
            if rbuf[0]==FDB_RSA_KEY_EF && dp.files[&file_id].2.is_some() && dp.files[&file_id].2.unwrap()[0]==0 {
                if let Some(x) = dp.files.get_mut(&file_id) {
                    (*x).1[6] = PKCS15_FILE_TYPE_RSAPUBLICKEY;
                }
            }
*/
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

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_process_fci\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
    if cfg!(log) {
        wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
    }

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
    if is_DFMF(fdb) {
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
    if is_DFMF(fdb) {
        /* list_files is always allowed for MF/DF */
        assert_eq!(SC_SUCCESS, unsafe { sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_NONE, SC_AC_KEY_REF_NONE as c_ulong) } );
        /* for opensc-tool also add the general SC_AC_OP_CREATE, which shall comprise both, SC_AC_OP_CREATE_EF and SC_AC_OP_CREATE_DF (added below later)  */
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[1], SC_AC_OP_CREATE); // Create EF
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[2], SC_AC_OP_CREATE); // Create DF
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
        se_file_add_acl_entry(card_ref_mut, file_ref_mut, scb8[2], SC_AC_OP_GENERATE); // MSE/PSO Commands
    }

    let ops_df_mf  : [u32; 7] = [ SC_AC_OP_DELETE/*_CHILD*/, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_ef_chv : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    0xFF,               SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_key    : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];
    let ops_se     : [u32; 7] = [ SC_AC_OP_READ,             SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF ];

    for idx_scb8 in 0..7 {
        let op =
            if       is_DFMF(fdb)                                         { ops_df_mf [idx_scb8] }
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
        if dp_files_value_ref_mut.1[0] == FDB_RSA_KEY_EF && dp_files_value_ref_mut.1[6] == 0xFF {
            dp_files_value_ref_mut.1[6] = if scb8[0] == 0xFF {PKCS15_FILE_TYPE_RSAPRIVATEKEY} else {PKCS15_FILE_TYPE_RSAPUBLICKEY};
        }
        if dp_files_value_ref_mut.1[0] == FDB_MF && dp_files_value_ref_mut.1[4..] == [0u8, 0, 0xFF, 0xFF] { // correct the initially unknown/incorrect lcsi setting
            let mut len_bytes_tag_fcp_lcs = 0usize;
            let     ptr_bytes_tag_fcp_lcs = unsafe { sc_asn1_find_tag(card_ref.ctx, buf, buflen,
                                                     ISO7816_TAG_FCP_LCS as c_uint, &mut len_bytes_tag_fcp_lcs) };
            assert!(  !ptr_bytes_tag_fcp_lcs.is_null());
            assert_eq!(len_bytes_tag_fcp_lcs, 1);
            let lcsi = unsafe { *ptr_bytes_tag_fcp_lcs };
            dp_files_value_ref_mut.1[7]  = lcsi;
        }
        if is_DFMF(dp_files_value_ref_mut.1[0]) && (dp_files_value_ref_mut.1[4..6] == [0u8; 2]) {
            dp_files_value_ref_mut.1[4]  = sefile_id[0];
            dp_files_value_ref_mut.1[5]  = sefile_id[1];
        }
    }
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;

    SC_SUCCESS
}


// assembles the byte string/data part for file creation via command "Create File"
// file MUST have assigned 'type_attr' and 'sec_attr' (for SAC)
// TODO special treatment for DF/MF is missing: mandatory ISO7816_RFU_TAG_FCP_SEID, optional ISO7816_RFU_TAG_FCP_SAE, optional ISO7816_TAG_FCP_DF_NAME
//#[allow(dead_code)]
extern "C" fn acos5_64_construct_fci(card: *mut sc_card, file: *const sc_file,
                                     out: *mut c_uchar, outlen: *mut usize) -> c_int
{
/*
6F 16  83 02 2F 00   82 02 01 00  80 02 00 21  8C 08 7F 01 FF 01 01 FF 01 00
6F 30  83 02 41 00 88 01 00 8A 01 05 82 02 38 00 8D 02 41 03 84 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30 8C 08 7F 03 FF 00 01 01 01 01 AB 00

6F 16  83 02 41 01   82 06 0A 00 00 15 00 01   8C 08 7F 03 FF 00 FF FF 01 FF
6F 16  83 02 41 02   82 06 0C 00 00 25 00 0C   8C 08 7F 03 FF 00 FF 01 01 FF
6F 16  83 02 41 03   82 06 1C 00 00 38 00 08   8C 08 7F 03 FF 00 FF 00 03 00

6F 16  83 02 50 31   82 02 01 00  80 02 00 6C  8C 08 7F 03 FF 00 03 FF 00 00
6F 16  83 02 41 11   82 02 01 00  80 02 00 80  8C 08 7F 03 FF 00 03 FF 00 00
6F 16  83 02 41 20   82 02 01 00  80 02 06 80  8C 08 7F 01 FF 00 01 FF 01 00

6F 16  83 02 41 31   82 02 09 00  80 02 02 15  8C 08 7F 01 FF 00 01 00 01 00
6F 16  83 02 41 F1   82 02 09 00  80 02 05 05  8C 08 7F 01 FF 00 01 01 01 FF
*/
    if card.is_null() || file.is_null() || out.is_null() || outlen.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let outlen_ref_mut = unsafe { &mut *outlen };
    if *outlen_ref_mut < 2 {
        return SC_ERROR_BUFFER_TOO_SMALL;
    }
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };
    let file_ref:         &sc_file = unsafe { &    *file };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_construct_fci\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
    if cfg!(log) {
        wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, fmt);
    }
    let mut buf = [0u8; 2];
    let mut ptr_diff_sum : usize = 0; // difference/distance of p and out   #![feature(ptr_offset_from)]
	let mut p = out;
    unsafe { *p = ISO7816_TAG_FCP }; // *p++ = 0x6F;  p++;
    p = unsafe { p.add(2) };
    ptr_diff_sum += 2;

    /* 4 bytes will be written for tag ISO7816_TAG_FCP_FID (0x83)  MANDATORY */
    buf[0] = ((file_ref.id >> 8) as u8) & 0xFF;
    buf[1] = (file_ref.id & 0xFF) as u8;
    unsafe { sc_asn1_put_tag(ISO7816_TAG_FCP_FID as c_uint, buf.as_ptr(), 2, p, *outlen_ref_mut-ptr_diff_sum, &mut p) };
    ptr_diff_sum += 4;

    /* 1 or 5 bytes will be written for tag ISO7816_TAG_FCP_TYPE (0x82) MANDATORY */
    assert!(!file_ref.type_attr.is_null() && file_ref.type_attr_len > 0 && file_ref.type_attr_len <= 6); // e.g.  {82 06} 0A 00 00 15 00 01
    let fdb = unsafe { *file_ref.type_attr };
    unsafe { sc_asn1_put_tag(ISO7816_TAG_FCP_TYPE as c_uint, file_ref.type_attr, file_ref.type_attr_len,
                             p, *outlen_ref_mut-ptr_diff_sum, &mut p) };
    ptr_diff_sum += 2+file_ref.type_attr_len;

    /* 3 bytes will be written for tag ISO7816_TAG_FCP_LCS (0x8A) */
    buf[0] = 5; // skip cos5 command "Activate File" and create as activated
    unsafe { sc_asn1_put_tag(ISO7816_TAG_FCP_LCS as c_uint, buf.as_ptr(), 1, p, *outlen_ref_mut-ptr_diff_sum, &mut p) };
    ptr_diff_sum += 3;

    if [FDB_TRANSPARENT_EF, FDB_RSA_KEY_EF].contains(&fdb) { // any non-record-based, non-DF/MF fdb
        /* 4 bytes will be written for tag ISO7816_TAG_FCP_SIZE (0x80) */
        assert!(file_ref.size > 0);
        buf[0] = ((file_ref.size >> 8) as u8) & 0xFF;
        buf[1] = (file_ref.size & 0xFF) as u8;
        unsafe { sc_asn1_put_tag(ISO7816_TAG_FCP_SIZE as c_uint, buf.as_ptr(), 2, p, *outlen_ref_mut-ptr_diff_sum, &mut p) };
        ptr_diff_sum += 4;
    }

    /*  bytes will be written for tag ISO7816_RFU_TAG_FCP_SAC (0x8C) MANDATORY */
    assert!(!file_ref.sec_attr.is_null() && file_ref.sec_attr_len > 0 && file_ref.sec_attr_len <= 9); // e.g.  {8C 08} 7F 03 FF 00 FF FF 01 FF
    unsafe { sc_asn1_put_tag(ISO7816_RFU_TAG_FCP_SAC as c_uint, file_ref.sec_attr, file_ref.sec_attr_len,
                             p, *outlen_ref_mut-ptr_diff_sum, &mut p) };
    ptr_diff_sum += 2+file_ref.sec_attr_len;

    unsafe { *out.add(1) = (ptr_diff_sum-2) as c_uchar; };
    *outlen_ref_mut = ptr_diff_sum;


    /*
            else {
                buf[0] = file->shareable ? 0x40 : 0;
                switch (file->type) {
                case SC_FILE_TYPE_INTERNAL_EF:
                    buf[0] |= 0x08;
                    /* fall through */
                case SC_FILE_TYPE_WORKING_EF:
                    buf[0] |= file->ef_structure & 7;
                    break;
                case SC_FILE_TYPE_DF:
                    buf[0] |= 0x38;
                    break;
                default:
                    return SC_ERROR_NOT_SUPPORTED;
                }
                sc_asn1_put_tag(0x82, buf, 1, p, *outlen - (p - out), &p);
            }
    */
    /* 0x84 = DF name */
/*
    if (file->prop_attr_len) {
                assert(sizeof(buf) >= file->prop_attr_len);
                memcpy(buf, file->prop_attr, file->prop_attr_len);
                sc_asn1_put_tag(0x85, buf, file->prop_attr_len,
                        p, *outlen - (p - out), &p);
    }
    if (file->sec_attr_len) {
                assert(sizeof(buf) >= file->sec_attr_len);
                memcpy(buf, file->sec_attr, file->sec_attr_len);
                sc_asn1_put_tag(0x86, buf, file->sec_attr_len,
                        p, *outlen - (p - out), &p);
    }
    out[1] = p - out - 2;

    *outlen = p - out;
    return 0;
*/
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

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_pin_cmd\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(b"called for cmd: %d\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, pin_cmd_data_ref_mut.cmd, fmt);
    }

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
    else if cfg!(not(any(v0_15_0, v0_16_0))) && /*SC_PIN_CMD_GET_SESSION_PIN*/ 4 == pin_cmd_data_ref_mut.cmd {
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
extern "C" fn acos5_64_get_data(card_ptr: *mut sc_card, offset: c_uint, buf: *mut c_uchar, buflen: usize) -> c_int
{
    if card_ptr.is_null() || buf.is_null() || buflen == 0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card : &mut sc_card = unsafe { &mut *card_ptr };
    let mut rv: i32;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_get_data\0").unwrap();

    if buflen <= 256 {
        card.cla = 0x80;
        rv = unsafe { (*(*sc_get_iso7816_driver()).ops).get_data.unwrap()(card, offset, buf, buflen) };
        card.cla = 0;
    }
    else {
        /* retrieve the raw content of currently selected RSA pub file (this is a code fragment from acos5_64_read_public_key) */
        let command : [u8; 5] = [0x80, 0xCA, 0x00, 0x00, 0xFF];
        let mut apdu : sc_apdu = Default::default();
        rv = sc_bytes2apdu_wrapper(card.ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_2_SHORT);

//        let mut rbuf = [0u8; RSAPUB_MAX_LEN];
        let mut le_remaining = buflen;
        while le_remaining > 0 {
            let offset = buflen - le_remaining;
            apdu.le      =  if le_remaining > 0xFFusize {0xFFusize} else {le_remaining};
            apdu.resp    =  unsafe { buf.add(offset) };
            apdu.resplen =  buflen - offset;
            apdu.p1      =  ((offset >> 8) & 0xFFusize) as u8;
            apdu.p2      =  ( offset       & 0xFFusize) as u8;
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
            if rv != SC_SUCCESS || apdu.resplen == 0 {
                if cfg!(log) {
                    if apdu.resplen == 0 || (apdu.sw1==0x69 && apdu.sw1==0x82) {
                        wr_do_log_t(card.ctx, f_log, line!(), fun, apdu.resplen, CStr::from_bytes_with_nul(b"non-readable file; apdu.resplen: %zu\0").unwrap());
                    }
                    else {
                        wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"sc_transmit_apdu failed or some other error\0").unwrap());
                    }
                }
                return rv;
            }
            assert_eq!(apdu.resplen, apdu.le);
            le_remaining -= apdu.le;
        }
        rv = buflen as c_int;
    }
    rv
}

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
//    let key_path_ref : &sc_path = unsafe { &*key_path };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"acos5_64_read_public_key\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
    let fmt_1 = CStr::from_bytes_with_nul(RETURNING_INT_CSTR).unwrap();
//  let fmt_2 = CStr::from_bytes_with_nul(RETURNING_INT).unwrap();
    if cfg!(log) {
        wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
    }

    if algorithm != SC_ALGORITHM_RSA {
        let rv = SC_ERROR_NO_CARD_SUPPORT;
        if cfg!(log) {
            wr_do_log_tu(card_ref.ctx, f_log, line!(), fun, rv, unsafe { sc_strerror(rv) }, fmt_1);
        }
        return rv;
    }
    assert!(modulus_length>=512 && modulus_length<=4096);
    let mlbyte : usize = (modulus_length as usize)/8; /* key modulus_length in byte (expected to be a multiple of 32)*/
    let le_total = mlbyte + 21;
    let fmt = CStr::from_bytes_with_nul(b"read public key(ref:%i; modulus_length:%i; modulus_bytes:%zu)\0").unwrap();
    if cfg!(log) {
        unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(),
                           fmt.as_ptr(), key_reference, modulus_length, mlbyte); }
    }

    let mut file_out_ptr_mut: *mut sc_file = std::ptr::null_mut();
//    let mut rv = select_file_by_path(card_ref_mut, key_path_ref, &mut file_out_ptr_mut, true/*, true*/);
    let mut rv = acos5_64_select_file(card, key_path, &mut file_out_ptr_mut);
    if rv != SC_SUCCESS {
        if cfg!(log) {
            wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"failed to select public key file\0")
                      .unwrap());
        }
        return rv;
    }

    // TODO use instead : acos5_64_get_data
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
            if cfg!(log) {
                wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"sc_transmit_apdu failed\0")
                          .unwrap());
            }
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
//        rbuf[2] != key_path_ref.value[key_path_ref.len-2] /* FIXME RSAKEYID_CONVENTION */ ||
//        rbuf[3] != ( (key_path_ref.value[key_path_ref.len-1] as u16 +0xC0u16)       & 0xFFu16) as u8 /* FIXME RSAKEYID_CONVENTION */ ||
       (rbuf[4] & 3u8) != 3u8
    {
        if cfg!(log) {
            wr_do_log(card_ref.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                      (b"failed: check the raw content of RSA pub file\0").unwrap());
        }
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
            if cfg!(log) {
                wr_do_log_tu(card_ref.ctx, f_log, line!(), fun, rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul
                             (b"sc_pkcs15_encode_pubkey_rsa failed: returning with: %d (%s)\n\0").unwrap());
            }
            return rv;
        }
    }
    else {
        rv = SC_ERROR_INTERNAL;
        if cfg!(log) {
            wr_do_log_tu(card_ref.ctx, f_log, line!(), fun, rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul
            (b"if rsa_key.exponent.len > 0 && rsa_key.modulus.len > 0  failure: returning with: %d (%s)\n\0").unwrap());
        }
        return SC_ERROR_INTERNAL;
    }
    SC_SUCCESS
}


extern "C" fn acos5_64_set_security_env(card: *mut sc_card, env: *const sc_security_env, _se_num: c_int) -> c_int
{
    if card.is_null() || env.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }

    let card_ref        = unsafe { &    *card };
    let card_ref_mut = unsafe { &mut *card };
    let env_ref   = unsafe { &    *env };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_set_security_env\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
    if cfg!(log) {
        wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
    }
//println!("set_security_env: *env: sc_security_env: {:?}", *env_ref);
    set_sec_env(card_ref_mut, env_ref);
    let mut rv;

    if SC_SEC_OPERATION_DERIVE == env_ref.operation
//        || ( cfg!(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0))) && (SC_SEC_OPERATION_WRAP == env_ref.operation || SC_SEC_OPERATION_UNWRAP == env_ref.operation) )
    {
        return SC_ERROR_NO_CARD_SUPPORT;
    }

    else if (SC_SEC_OPERATION_GENERATE_RSAPRIVATE == env_ref.operation ||
             SC_SEC_OPERATION_GENERATE_RSAPUBLIC  == env_ref.operation)   &&
             (env_ref.flags as c_uint & SC_SEC_ENV_FILE_REF_PRESENT) > 0 &&
             (env_ref.flags as c_uint & SC_SEC_ENV_ALG_PRESENT) > 0 && env_ref.algorithm==SC_ALGORITHM_RSA
    {
        let path_idx = env_ref.file_ref.len - 2;
        let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB6, 0x0A, 0x80, 0x01, 0x10, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01,
            if SC_SEC_OPERATION_GENERATE_RSAPRIVATE == env_ref.operation {0x40} else {0x80}];
        let mut apdu = Default::default();
        rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                    (b"sc_transmit_apdu or 'Set SecEnv for Generate Key pair' failed\0").unwrap());
            }
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }
    }

    else if (SC_SEC_OPERATION_SIGN     == env_ref.operation ||
             SC_SEC_OPERATION_DECIPHER == env_ref.operation)   &&
        env_ref.algorithm==SC_ALGORITHM_RSA && (env_ref.flags as c_uint & SC_SEC_ENV_FILE_REF_PRESENT) > 0
    {
        // TODO where is the decision taken to use PKCS#1 scheme padding?
        let algo = if (env_ref.algorithm_flags & SC_ALGORITHM_RSA_PAD_ISO9796) == 0 {0x10u8} else {0x11u8};
        let path_idx = env_ref.file_ref.len - 2;
        if SC_SEC_OPERATION_SIGN == env_ref.operation {
            let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB6, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,  env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
            let mut apdu : sc_apdu = Default::default();
            rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
            assert_eq!(rv, SC_SUCCESS);
            assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
            if !(rv == SC_SUCCESS && apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
                if cfg!(log) {
                    wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                        (b"sc_transmit_apdu or 'Set SecEnv for Sign' failed\0").unwrap());
                }
                return SC_ERROR_KEYPAD_MSG_TOO_LONG;
            }
        }
        /* sign may need decrypt (for non-SHA1/SHA256 hashes), thus prepare for a CT as well */
        let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x13, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu : sc_apdu = Default::default();
        rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                    (b"sc_transmit_apdu or 'Set SecEnv for Decrypt' failed\0").unwrap());
            }
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }
    }

    else if SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC == env_ref.operation   &&
            env_ref.algorithm==SC_ALGORITHM_RSA && (env_ref.flags as c_uint & SC_SEC_ENV_FILE_REF_PRESENT) > 0
    {
//        let algo = 0x12; // encrypt: 0x12, decrypt: 0x13
        let path_idx = env_ref.file_ref.len - 2;
        let command: [u8; 15] = [0x00, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x12, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu : sc_apdu = Default::default();
        rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
        if !(rv == SC_SUCCESS && apdu.sw1 == 0x90 && apdu.sw2 == 0x00) {
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul
                    (b"sc_transmit_apdu or 'Set SecEnv for encrypt_asym' failed\0").unwrap());
            }
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }
    }

    else if [SC_SEC_OPERATION_ENCIPHER_SYMMETRIC, SC_SEC_OPERATION_DECIPHER_SYMMETRIC].contains(&env_ref.operation)  &&
            (env_ref.flags as c_uint & SC_SEC_ENV_KEY_REF_PRESENT) > 0 &&
            (env_ref.flags as c_uint & SC_SEC_ENV_ALG_REF_PRESENT) > 0
    {
        if cfg!(any(v0_15_0, v0_16_0)) || env_ref.key_ref_len == 0 {
            return SC_ERROR_NOT_SUPPORTED;
        }
        #[cfg(not(any(v0_15_0, v0_16_0)))]
        {
            if (env_ref.flags as c_uint & SC_SEC_ENV_ALG_PRESENT) == 0  ||
                ![SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&env_ref.algorithm) {
                return SC_ERROR_NOT_SUPPORTED;
            }
            #[cfg(not(    v0_17_0))]
            { if env_ref.flags as c_uint & SC_SEC_ENV_KEY_REF_SYMMETRIC == 0 {return SC_ERROR_NOT_SUPPORTED;} }
            #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
            {
                if (env_ref.algorithm & SC_ALGORITHM_AES) > 0 &&
                    ![SC_ALGORITHM_AES_CBC_PAD,
                      SC_ALGORITHM_AES_CBC,
                      SC_ALGORITHM_AES_ECB].contains(&env_ref.algorithm_flags)
                { return SC_ERROR_NOT_SUPPORTED; }
            }

            let mut vec =   // made for cbc and blockSize == 16
                vec![0u8,  0x22, 0x01,  0xB8, 0xFF,
                     0x95, 0x01, 0x40,
                     0x80, 0x01, 0xFF,
                     0x83, 0x01, 0xFF,
                     0x87, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

            if env_ref.algorithm == SC_ALGORITHM_AES {
                #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
                    { if env_ref.algorithm_flags == SC_ALGORITHM_AES_ECB {vec.truncate(vec.len()-18);} }
                #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
                    {
                        if [4, 5].contains(&env_ref.algorithm_ref)
                        { vec.truncate(vec.len()-18); }
                    }
            }
            else { // then it's SC_ALGORITHM_3DES | SC_ALGORITHM_DES
                vec.truncate(vec.len()-8);
                let pos = vec.len()-9;
                vec[pos] = 8; // IV has len == 8. assuming it's CBC
                if [0, 1].contains(&env_ref.algorithm_ref)
                { vec.truncate(vec.len()-10); }
            }

            /*  transferring the iv is missing below 0.20.0 */
            #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
            {
                for sec_env_param in env_ref.params.iter() {
                    match sec_env_param.param_type {
                        SC_SEC_ENV_PARAM_IV=> {
                            assert!(vec.len() >= 16);
                            assert_eq!(vec[15] as c_uint, sec_env_param.value_len);
                            assert_eq!(vec.len(), 16+sec_env_param.value_len as usize);
                            unsafe { copy_nonoverlapping(sec_env_param.value as *const c_uchar, vec.as_mut_ptr().add(16), sec_env_param.value_len as usize) };
                        },
                        SC_SEC_ENV_PARAM_TARGET_FILE=> { continue; }
                        _ => { break; },
                    }
                }
/* * /

//                env_ref.algorithm_flags = if crypt_sym.cbc {if crypt_sym.pad_type==BLOCKCIPHER_PAD_TYPE_PKCS5 {SC_ALGORITHM_AES_CBC_PAD} else {SC_ALGORITHM_AES_CBC} } else {SC_ALGORITHM_AES_ECB};
//                env_ref.params[0] = sc_sec_env_param { param_type: SC_SEC_ENV_PARAM_IV, value: crypt_sym.iv.as_mut_ptr() as *mut c_void, value_len: crypt_sym.iv_len.into() };
                // for 3DES/DES use this to select CBC/ECB: with param_type: SC_SEC_ENV_PARAM_DES_ECB or SC_SEC_ENV_PARAM_DES_CBC

                if [SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&env_ref.algorithm) {
                    for i in 0..SC_SEC_ENV_MAX_PARAMS {
                        if vec.len()<=14 {break;}
                        if env_ref.params[i].param_type==SC_SEC_ENV_PARAM_DES_ECB { vec.truncate(vec.len()-10); }
                    }
                }
pub const SC_SEC_ENV_PARAM_DES_ECB           : c_uint = 3;
pub const SC_SEC_ENV_PARAM_DES_CBC           : c_uint = 4;
    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
    pub params :          [sc_sec_env_param; SC_SEC_ENV_MAX_PARAMS],
/ * */
            }

            vec[ 4] = (vec.len()-5) as u8;
            vec[10] = env_ref.algorithm_ref as c_uchar;
            vec[13] = env_ref.key_ref[0];

            let mut apdu = Default::default();
            rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &vec, &mut apdu);
            assert_eq!(rv, SC_SUCCESS);
            assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
            if rv != SC_SUCCESS {
                return rv;
            }
            rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
            if rv != SC_SUCCESS {
                return rv;
            }
        }
    }

    else {
        return SC_ERROR_NO_CARD_SUPPORT;
    }
    SC_SUCCESS
}

/* Should this be restricted by inspecting the padding for correctness ? */
/* decipher:  Engages the deciphering operation.  Card will use the
 *   security environment set in a call to set_security_env or
 *   restore_security_env.
 *
 *  Status Words while processing:
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
//    let card_ref:         &sc_card = unsafe { &    *card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_64_decipher\0").unwrap();
    if cfg!(log) {
        wr_do_log_tt(card_ref_mut.ctx, f_log, line!(), fun, crgram_len, outlen,
                     CStr::from_bytes_with_nul(b"called with: crgram_len: %zu, outlen: %zu\0").unwrap());
    }
    assert!(outlen >= crgram_len);

    #[cfg(enable_acos5_64_ui)]
        {
            if get_ui_ctx(card_ref_mut).user_consent_enabled == 1 {
                /* (Requested by DGP): on signature operation, ask user consent */
                rv = acos5_64_ask_user_consent();
                if rv < 0 {
                    wr_do_log_sds(card_ref_mut.ctx, f_log, line!(), fun,CStr::from_bytes_with_nul(b"User consent denied\0")
                        .unwrap().as_ptr(), rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap());
                    return rv;
                }
            }
        }

    let command = [0, 0x2A, 0x80, 0x84, 0x02, 0xFF, 0xFF, 0xFF]; // will replace lc, cmd_data and le later; the last 4 bytes are placeholders only for sc_bytes2apdu_wrapper
    let mut apdu = Default::default();
    rv = sc_bytes2apdu_wrapper(card_ref_mut.ctx, &command, &mut apdu);
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
        if cfg!(log) {
            wr_do_log_tt(card_ref_mut.ctx, f_log, line!(), fun, apdu.sw1, apdu.sw2,
                         CStr::from_bytes_with_nul(b"### 0x%02X%02X: sc_transmit_apdu or decipher failed or \
                         it's impossible to retrieve the answer from get_response ###\0").unwrap());
        }
        /* while using pkcs11-tool -l -t
        it may happen, that a sign-key get's tested with a hash algo unsupported by compute_signature, thus it must revert to use acos5_64_decipher,
        but the key isn't generated with decrypt capability: Then fake a success here, knowing, that a verify signature will fail
        Update: this doesn't help, check_sw kicks in and aborts on error 0x6A80 */
        if rv == SC_ERROR_INCORRECT_PARAMETERS { // 0x6A80 error code get's transformed by iso7816_check_sw to SC_ERROR_INCORRECT_PARAMETERS
            apdu.sw1 = 0x90;
            apdu.sw2 = 0x00;
            if cfg!(log) {
                wr_do_log(card_ref_mut.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"### \
                decipher failed with error code 0x6A80: Multiple possible reasons for the failure; a likely harmless \
                one is, that the key is not capable to decipher but was used for deciphering (maybe called from \
                compute_signature, i.e. the intent was signing with a hash algo that compute_signature doesn't support; \
                compute_signature reverts to decipher for any hash algo other than SHA-1 or SHA-256) ###\0").unwrap() );
            }
        }
        assert!(rv<0);
        return rv;
    }
    if cfg!(log) {
        wr_do_log_t(card_ref_mut.ctx, f_log, line!(), fun, crgram_len,
                    CStr::from_bytes_with_nul(b"returning from acos5_64_decipher with: %zu\n\0").unwrap());
    }
    crgram_len as c_int
}


/*
1. DO very very carefully inspect where acos5_64_compute_signature transfers the operation to acos5_64_decipher:
   It MUST NOT happen, that an attacker can use acos5_64_compute_signature to pass arbitrary data to acos5_64_decipher, except of Length hLen (HashLength which is max 64 bytes)

2. This should be the place to check, that the integer representing the 'message' is smaller than the integer representing the RSA key modulus !
   BUT, that's not possible here (there is no knowledge here about the RSA key modulus) !
   EMSA-PKCS1-v1_5:
       emLen = RSA key modulus length in bytes, e.g. for a 4096 bit key: 512
       EM starts with bytes 0x00, 0x01  (EM = 0x00 || 0x01 || PS || 0x00 || T).
       Thus the modulus must start with bytes > 0x00, 0x01, e.g. the minimum is 0x00, 0x02:
           Check in acos5_gui when generating a key pair, that this condition is met

   EMSA-PSS:
      11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB to zero.

      12. Let EM = maskedDB || H || 0xbc.

      emBits must be less than  int RSA_bits(const RSA *rsa); // RSA_bits() returns the number of significant bits.



   Definition :
         DigestInfo ::= SEQUENCE {
          digestAlgorithm DigestAlgorithm,
          digest OCTET STRING
      }

   In the following, digestAlgorithm includes the tag for SEQUENCE and a length byte (behind SEQUENCE)
   Input allowed: optional_padding  +  digestAlgorithm  +  digest

   For RSASSA-PKCS1-v1_5:
       Only for sha1 and sha256, as an exception, both optional_padding + digestAlgorithm, may be omitted from input, for all other digestAlgorithm is NOT optional.

   RSASSA-PSS : Only works with SC_ALGORITHM_RSA_RAW declared in acos5_64_init()

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
    if card.is_null() || data.is_null() || out.is_null() || outlen < 64 { // cos5 supports RSA beginning from moduli 512 bits = 64 bytes
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(data_len <= outlen);
    assert!(data_len <= 512); // cos5 supports max RSA 4096 bit keys

    let card_ref:         &sc_card = unsafe { &    *card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *card };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_64_compute_signature\0").unwrap();
    if cfg!(log) {
        wr_do_log_tt(card_ref.ctx, f_log, line!(), fun, data_len, outlen,
                     CStr::from_bytes_with_nul(b"called with: data_len: %zu, outlen: %zu\0").unwrap());
    }
    //   sha1     sha256  +sha1  +sha224  +sha256  +sha384  +sha512
    if ![20usize, 32,     35,    47,      51,      67,      83, outlen].contains(&data_len) {
        return SC_ERROR_WRONG_PADDING;
    }
    #[allow(non_snake_case)]
    let digestAlgorithm_sha1   = [0x30u8, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    #[allow(non_snake_case)]
    let digestAlgorithm_sha256 = [0x30u8, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

    #[cfg(    any(v0_15_0, v0_16_0, v0_17_0, v0_18_0))]
    let mut rv = SC_SUCCESS;
    #[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
    let mut rv; // = SC_SUCCESS;

    let mut vec_in : Vec<c_uchar> = Vec::with_capacity(512);
    /*
       if data_len==20, assume it's a SHA-1   digest and prepend digestAlgorithm
       if data_len==32, assume it's a SHA-256 digest and prepend digestAlgorithm
     */
    if      data_len == 20 {
        vec_in.extend_from_slice(&digestAlgorithm_sha1[..]);
    }
    else if data_len == 32 {
        vec_in.extend_from_slice(&digestAlgorithm_sha256[..]);
    }
    for i in 0..data_len {
        vec_in.push(unsafe { *data.add(i) } );
    }
//    assert!(vec_in.len()>0);

    let sec_env_algo_flags = get_sec_env(card_ref_mut).algorithm_flags;
//println!("Sign: sec_env_algo_flags: 0x{:X}, output len: {}, input len: {}, input data: {:X?}", sec_env_algo_flags, outlen, vec_in.len(), vec_in);
    let digest_info =
        if sec_env_algo_flags != SC_ALGORITHM_RSA_RAW { vec_in.as_slice() } // then vec_in IS digest_info
        else { // sec_env_algo_flags == SC_ALGORITHM_RSA_RAW (in v0.20.0 that's the same as sec_env_algo_flags == SC_ALGORITHM_RSA_PAD_NONE)
            match me_pkcs1_strip_01_padding(&vec_in) { // TODO possibly also try pkcs1_strip_PSS_padding
                Ok(digest_info) => digest_info,
                Err(e) => {
/* */
                    if [35, 51].contains(&vec_in.len()) {
                        if (vec_in.len() == 35 && &vec_in.as_slice()[0..15] == &digestAlgorithm_sha1[..]) ||
                           (vec_in.len() == 51 && &vec_in.as_slice()[0..19] == &digestAlgorithm_sha256[..])
                        {
                            &vec_in[..]
                        }
                        else {
                            return e;
                        }
                    }
/* */
                    else if e != SC_ERROR_WRONG_PADDING || vec_in[vec_in.len() - 1] != 0xbc {
                        return e;
                    }
                    else {
                        return -1;
                        /* forward to acos5_64_decipher only, if this is really secure; a pss padding can't be detected unambiguously */
//                        return acos5_64_decipher(card, data, data_len, out, outlen);
                    }
                }
            }
        };
//println!("digest_info.len(): {}, digest_info: {:X?}", digest_info.len(), digest_info);
    if digest_info.len() == 0 { // if there is no content to sign, then don't sign
        return SC_SUCCESS;
    }

    // id_rsassa_pkcs1_v1_5_with_sha512_256 and id_rsassa_pkcs1_v1_5_with_sha3_256 also have a digest_info.len() == 51

    if (digest_info.len() == 35 /*SHA-1*/ || digest_info.len() == 51 /*SHA-256*/) && (digest_info.len() != 51 || digest_info[..19]==digestAlgorithm_sha256[..])
    {

        #[cfg(enable_acos5_64_ui)]
            {
                if get_ui_ctx(card_ref_mut).user_consent_enabled == 1 {
                    /* (Requested by DGP): on signature operation, ask user consent */
                    rv = acos5_64_ask_user_consent();
                    if rv < 0 {
                        wr_do_log_sds(card_ref_mut.ctx, f_log, line!(), fun,CStr::from_bytes_with_nul(b"User consent denied\0")
                            .unwrap().as_ptr(), rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap());
                        return rv;
                    }
                }
            }

        // SHA-1 and SHA-256 hashes, what the card can handle natively
//        assert!(digest_info.len() == 35 || digest_info.len() == 51);
        let hash = if digest_info.len()==35 { &digest_info[15..] } else { &digest_info[19..] };
//        assert!(hash.len()==20 || hash.len()==32);

        set_is_running_cmd_long_response(card_ref_mut, true); // switch to false is done by acos5_64_get_response
        let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).compute_signature.unwrap() };
        rv = unsafe { func_ptr(card, hash.as_ptr(), hash.len(), out, outlen) };
        if rv <= 0 {
            if cfg!(log) {
                wr_do_log_t(card_ref.ctx, f_log, line!(), fun, rv,
                            CStr::from_bytes_with_nul(b"iso7816_compute_signature failed or apdu.resplen==0. rv: %d\0").unwrap());
            }
//            return rv;
        }
        /* temporary: "decrypt" signature (out) to stdout * /
        encrypt_public_rsa(card,out, data_len);
        / * */
    }
    else {   /* for other digests than SHA-1/SHA-256:  this will fail if key_len != outlen */
        if cfg!(log) {
            let fmt = CStr::from_bytes_with_nul(b"### Switch to acos5_64_decipher, because \
                acos5_64_compute_signature can't handle the hash algo ###\0").unwrap();
            wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);
        }
        /* digest_info.len() is from SC_ALGORITHM_RSA_RAW/SC_ALGORITHM_RSA_PAD_NONE or SC_ALGORITHM_RSA_PAD_PKCS1 */
        /* is_any_known_digestAlgorithm or ? could go further and compare digestAlgorithm to known ones as well
           With that done, a possible attacker can control nothing but the hash value (and signature scheme to be used)
           TODO implement delaying, if consecutive trials to sign are detected, revoke PIN verification etc.
             or enable an additional layer where user MUST accept or deny sign operation (see DNIE) */
        if (SC_ALGORITHM_RSA_PAD_PKCS1 & sec_env_algo_flags) > 0 && is_any_known_digestAlgorithm(digest_info)
        {
/* calling me_get_encoding_flags is not necessary, it's done within sc_pkcs1_encode anyway.
   Here just for curiosity/inspection * /
            let mut pflags = 0;
            let mut sflags = 0;
            rv = me_get_encoding_flags(card_ref_mut.ctx, sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE,
                                       get_rsa_caps(card_ref_mut), &mut pflags, &mut sflags);
println!("pflags: {}, sflags: {}", pflags, sflags);
            if rv != SC_SUCCESS {
                return rv;
            }
/ * */
            let mut vec = vec![0u8; 512];
            let mut vec_len = std::cmp::min(512, outlen);
            rv = unsafe { sc_pkcs1_encode(card_ref_mut.ctx, (sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE) as c_ulong, digest_info.as_ptr(),
                                          digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len *
                                          if cfg!(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)) {1} else {8}) };
            if rv != SC_SUCCESS {
                return rv;
            }
            rv = acos5_64_decipher(card, vec.as_ptr(), vec_len, out, outlen);
        }
        else if (SC_ALGORITHM_RSA_RAW  & sec_env_algo_flags) > 0  {
            rv = acos5_64_decipher(card, data, data_len, out, outlen);
        }
/*
        else if cfg!(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0))) {
        #[       cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0)))]
        {
            if (SC_ALGORITHM_RSA_PAD_PSS & sec_env_algo_flags) > 0 /*&& is_any_known_digestAlgorithm(digest_info.len()*/) {
                rv = 0; // do nothing
/*
sc_pkcs1_encode with SC_ALGORITHM_RSA_PAD_PSS does work only since v0.20.0
when pkcs1_strip_PSS_padding works
                    let mut vec = vec![0u8; 512];
                    let mut vec_len = std::cmp::min(512, outlen);
                    if cfg!(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)) {
                        rv = unsafe { sc_pkcs1_encode(card_ref_mut.ctx, (sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE) as c_ulong, digest_info.as_ptr(),
                                                      digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len) };
                    }
                    else {
                        rv = unsafe { sc_pkcs1_encode(card_ref_mut.ctx, (sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE) as c_ulong, digest_info.as_ptr(),
                                                      digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len*8) };
                    }
                    if rv != SC_SUCCESS {
                        return rv;
                    }
                    rv = acos5_64_decipher(card, data, data_len, out, outlen);
*/
            }
            else {
                rv = 0; // do nothing
            }
        }}
*/
        else {
            rv = 0; // do nothing
        }
        /* temporary: "decrypt" signature (out) to stdout * /
        if rv>0 {
            encrypt_public_rsa(card, out, /*data_len*/ outlen);
        }
        / * */
        if cfg!(log) {
            wr_do_log_t(card_ref.ctx, f_log, line!(), fun, rv,
                CStr::from_bytes_with_nul(b"returning from acos5_64_compute_signature with: %d\n\0").unwrap());
        }
//        return rv;
    }
    if cfg!(log) {
        wr_do_log_t(card_ref.ctx, f_log, line!(), fun, data_len as c_int,
                    CStr::from_bytes_with_nul(RETURNING_INT).unwrap());
    }
    rv
//    data_len as c_int
}
