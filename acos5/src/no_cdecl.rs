/*
 * no_cdecl.rs: Driver 'acos5' - Miscellaneous functions
 *
 * Copyright (C) 2019-  Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110  USA
 */

//use super::bitintr::Popcnt;
//#![feature(const_fn)]
#![allow(clippy::too_many_lines)]

use std::os::raw::{c_char, c_ulong, c_void};
use std::ffi::{CStr, CString};
use std::fs;//::{read/*, write*/};
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use function_name::named;
use opensc_sys::opensc::{sc_card, sc_pin_cmd_data, sc_security_env, sc_transmit_apdu,
                         sc_read_record, sc_format_path, sc_select_file, sc_check_sw, //SC_ALGORITHM_RSA_PAD_PKCS1,
                         SC_RECORD_BY_REC_NR, SC_PIN_ENCODING_ASCII, SC_READER_SHORT_APDU_MAX_RECV_SIZE,
                         SC_SEC_ENV_ALG_PRESENT, SC_SEC_ENV_FILE_REF_PRESENT, SC_ALGORITHM_RSA, SC_SEC_ENV_KEY_REF_PRESENT,
                         SC_ALGORITHM_3DES, SC_ALGORITHM_DES, sc_get_iso7816_driver, SC_SEC_ENV_ALG_REF_PRESENT,
                         sc_format_apdu, sc_file_new, sc_file_get_acl_entry, sc_check_apdu, sc_list_files,
                         sc_set_security_env, sc_get_challenge, sc_get_mf_path, SC_ALGORITHM_EC,
                         SC_SEC_OPERATION_SIGN, SC_SEC_OPERATION_DECIPHER, SC_ALGORITHM_AES,
                         SC_PIN_STATE_LOGGED_IN, SC_PIN_STATE_LOGGED_OUT, SC_PIN_STATE_UNKNOWN};
//                         ,SC_SEC_OPERATION_ENCRYPT_SYM, SC_SEC_OPERATION_DECRYPT_SYM
//use opensc_sys::opensc::{SC_SEC_ENV_KEY_REF_SYMMETRIC};
use opensc_sys::opensc::{SC_ALGORITHM_AES_CBC_PAD, SC_SEC_OPERATION_UNWRAP,
                         SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB, sc_sec_env_param, SC_SEC_ENV_PARAM_IV
};

use opensc_sys::types::{sc_object_id,sc_apdu, /*sc_aid, sc_path, SC_MAX_AID_SIZE, SC_MAX_PATH_SIZE, sc_file_t,
    SC_MAX_ATR_SIZE, SC_FILE_TYPE_DF,  */  sc_path, sc_file, SC_PATH_TYPE_FILE_ID,// SC_PATH_TYPE_PATH,
                        SC_MAX_APDU_BUFFER_SIZE, SC_MAX_PATH_SIZE, SC_APDU_FLAGS_CHAINING,
                        SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT, SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT,
                        SC_PATH_TYPE_DF_NAME, SC_PATH_TYPE_PATH, SC_PATH_TYPE_FROM_CURRENT, SC_PATH_TYPE_PARENT,
                        SC_AC_NONE, SC_AC_CHV, SC_AC_TERM, SC_AC_PRO, SC_AC_AUT, SC_AC_SYMBOLIC, SC_AC_SEN, SC_AC_SCB, SC_AC_IDA, SC_AC_SESSION/*, SC_AC_CONTEXT_SPECIFIC*/, SC_AC_UNKNOWN, SC_AC_NEVER,
                        sc_acl_entry, SC_MAX_AC_OPS
                        ,SC_AC_OP_READ
                        ,SC_AC_OP_UPDATE
                        ,SC_AC_OP_CRYPTO
    ,SC_AC_OP_DELETE
    ,SC_AC_OP_CREATE_EF
    ,SC_AC_OP_CREATE_DF
    ,SC_AC_OP_INVALIDATE
    ,SC_AC_OP_REHABILITATE
    ,SC_AC_OP_LOCK
    ,SC_AC_OP_DELETE_SELF
};
use opensc_sys::log::sc_dump_hex;
use opensc_sys::errors::{/*SC_ERROR_NO_READERS_FOUND, SC_ERROR_UNKNOWN, SC_ERROR_NOT_SUPPORTED, */
                         SC_SUCCESS, SC_ERROR_INVALID_ARGUMENTS, //SC_ERROR_KEYPAD_TIMEOUT,
                         SC_ERROR_KEYPAD_MSG_TOO_LONG,/*, SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL*/
SC_ERROR_WRONG_LENGTH, SC_ERROR_NOT_ALLOWED, SC_ERROR_FILE_NOT_FOUND, SC_ERROR_INCORRECT_PARAMETERS, SC_ERROR_CARD_CMD_FAILED,
SC_ERROR_OUT_OF_MEMORY, SC_ERROR_UNKNOWN_DATA_RECEIVED, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_NO_CARD_SUPPORT,
SC_ERROR_SM_RAND_FAILED, SC_ERROR_KEYPAD_TIMEOUT, SC_ERROR_INVALID_DATA
};
use opensc_sys::internal::sc_atr_table;
use opensc_sys::asn1::sc_asn1_read_tag;
use opensc_sys::iso7816::{ISO7816_TAG_FCI, ISO7816_TAG_FCP};
use opensc_sys::sm::{SM_SMALL_CHALLENGE_LEN, SM_CMD_FILE_READ, SM_CMD_FILE_UPDATE};

use crate::wrappers::{wr_do_log, wr_do_log_rv, wr_do_log_t, wr_do_log_tu,/* wr_do_log_tt, wr_do_log_ttt,*/
                      wr_do_log_tuv, wr_do_log_rv_ret, wr_do_log_sds_ret};
use crate::constants_types::{ATR_MASK, ATR_V2, ATR_V3, BLOCKCIPHER_PAD_TYPE_ANSIX9_23, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES,
                             BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, BLOCKCIPHER_PAD_TYPE_PKCS7,
                             BLOCKCIPHER_PAD_TYPE_ZEROES, CardCtlSymCrypt, CardCtlGenerateAsymCrypt, DataPrivate,
                             FDB_CYCLIC_EF, FDB_LINEAR_VARIABLE_EF, FDB_RSA_KEY_EF, FDB_SE_FILE,
                             FDB_SYMMETRIC_KEY_EF, NAME_V2, NAME_V3, FDB_ECC_KEY_EF, //PKCS15_FILE_TYPE_ECCPRIVATEKEY,
                             // PKCS15_FILE_TYPE_ECCPUBLICKEY, PKCS15_FILE_TYPE_RSAPRIVATEKEY, PKCS15_FILE_TYPE_RSAPUBLICKEY,
                             SACinfo, SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3,
                             /*SC_SEC_OPERATION_DECIPHER_RSAPRIVATE, */ // SC_SEC_OPERATION_DECIPHER_SYMMETRIC,
                             SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC, //SC_SEC_OPERATION_ENCIPHER_SYMMETRIC,
                             SC_SEC_OPERATION_GENERATE_RSAPRIVATE, SC_SEC_OPERATION_GENERATE_RSAPUBLIC,
                             Acos5EcCurve, build_apdu, is_DFMF, ATR_MASK_TCK, // p_void,
                             // ISO7816_RFU_TAG_FCP_SFI, ISO7816_RFU_TAG_FCP_SAC, ISO7816_RFU_TAG_FCP_SEID, ISO7816_RFU_TAG_FCP_SAE,
                             GuardFile, SC_CARD_TYPE_ACOS5_EVO_V4, NAME_V4, ATR_V4_1, ATR_V4_2, ATR_V4_3, //, ATR_V4
                             file_id_from_path_value, file_id_se,
                             CRT_TAG_HT, CRT_TAG_CCT, CRT_TAG_DST, CRT_TAG_CT,
                             SC_SEC_OPERATION_GENERATE_ECCPRIVATE, SC_SEC_OPERATION_GENERATE_ECCPUBLIC //, APDUShortExtendedSwitcher
};
use crate::se::{se_parse_sac, se_get_is_scb_suitable_for_sm_has_ct};
use crate::path::{cut_path, file_id_from_cache_current_path, current_path_df, is_impossible_file_match};
use crate::missing_exports::me_get_max_recv_size;
use crate::cmd_card_info::is_pin_authenticated;
use crate::sm::{SM_SMALL_CHALLENGE_LEN_u8, sm_common_read, sm_common_update};
use crate::crypto::{RAND_bytes, des_ecb3_unpadded_8, Encrypt};

use super::acos5_process_fci;/*, acos5_list_files, acos5_select_file, acos5_set_security_env*/

#[allow(dead_code)] // currently unused
#[cold]
#[must_use]
fn sc_ac_op_name_from_idx(idx: usize) -> &'static CStr
{
    match idx {
         0  => c"SC_AC_OP_SELECT",
         1  => c"SC_AC_OP_LOCK",
         2  => c"SC_AC_OP_DELETE",
         3  => c"SC_AC_OP_CREATE",
         4  => c"SC_AC_OP_REHABILITATE",
         5  => c"SC_AC_OP_INVALIDATE",
         6  => c"SC_AC_OP_LIST_FILES",
         7  => c"SC_AC_OP_CRYPTO",
         8  => c"SC_AC_OP_DELETE_SELF",
         9  => c"SC_AC_OP_PSO_DECRYPT",
        10  => c"SC_AC_OP_PSO_ENCRYPT",
        11  => c"SC_AC_OP_PSO_COMPUTE_SIGNATURE",
        12  => c"SC_AC_OP_PSO_VERIFY_SIGNATURE",
        13  => c"SC_AC_OP_PSO_COMPUTE_CHECKSUM",
        14  => c"SC_AC_OP_PSO_VERIFY_CHECKSUM",
        15  => c"SC_AC_OP_INTERNAL_AUTHENTICATE",
        16  => c"SC_AC_OP_EXTERNAL_AUTHENTICATE",
        17  => c"SC_AC_OP_PIN_DEFINE",
        18  => c"SC_AC_OP_PIN_CHANGE",
        19  => c"SC_AC_OP_PIN_RESET",
        20  => c"SC_AC_OP_ACTIVATE",
        21  => c"SC_AC_OP_DEACTIVATE",
        22  => c"SC_AC_OP_READ",
        23  => c"SC_AC_OP_UPDATE",
        24  => c"SC_AC_OP_WRITE",
        25  => c"SC_AC_OP_RESIZE",
        26  => c"SC_AC_OP_GENERATE",
        27  => c"SC_AC_OP_CREATE_EF",
        28  => c"SC_AC_OP_CREATE_DF",
        29  => c"SC_AC_OP_ADMIN",
        30  => c"SC_AC_OP_PIN_USE",
        _   => c"UNKNOWN",
    }
}

/* card command  External Authentication
includes getting a challenge from the card. setting card.sm_ctx.info.session.cwa.ssc is not part of this command anymore
key_host_reference must be enabled for External Authentication and it's Error Counter must have tries_left>0
*/
///
/// # Panics
/// # Errors
///
#[named]
pub fn authenticate_external(card: &mut sc_card, key_host_reference: u8, key_host: &[u8]) -> Result<bool, i32> {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    assert_eq!(24, key_host.len());
    if key_host_reference==0 || (key_host_reference&0x7F)>31 {
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS));
    }

    let mut rv = unsafe {
        sc_get_challenge(card, card.sm_ctx.info.session.cwa.card_challenge.as_mut_ptr(), SM_SMALL_CHALLENGE_LEN)
    };
    if rv != SC_SUCCESS {
        return Err(log3ifr_ret!(ctx,f,line!(), rv));
    }
    //    unsafe { card.sm_ctx.info.session.cwa.ssc = card.sm_ctx.info.session.cwa.card_challenge };
    let re = des_ecb3_unpadded_8(unsafe { &card.sm_ctx.info.session.cwa.card_challenge }, key_host,
                                 Encrypt);
    /* (key terminal/host) kh */
    let mut command = [0, 0x82, 0, key_host_reference, SM_SMALL_CHALLENGE_LEN_u8, 0, 0, 0, 0, 0, 0, 0, 0];
    command[5..5 + SM_SMALL_CHALLENGE_LEN].copy_from_slice(&re);
    let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(log3ifr_ret!(ctx,f,line!(), rv)); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return Err(log3ifr_ret!(ctx,f,line!(), rv));
    }
    log3ifr!(ctx,f,line!(), SC_SUCCESS);
    Ok(apdu.sw2==0)
}

///
/// # Panics
/// # Errors
///
#[named]
pub fn authenticate_internal(card: &mut sc_card, key_card_reference: u8, key_card: &[u8]) -> Result<bool, i32> {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    assert_eq!(24, key_card.len());
    let mut rv = unsafe {
        RAND_bytes(card.sm_ctx.info.session.cwa.host_challenge.as_mut_ptr(), i32::from(SM_SMALL_CHALLENGE_LEN_u8))
    };
    if rv != 1 {
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_SM_RAND_FAILED));
    }
    /* (key card) kc */
    let mut command = [0, 0x88, 0, key_card_reference, SM_SMALL_CHALLENGE_LEN_u8, 0, 0, 0, 0, 0, 0, 0, 0,
        SM_SMALL_CHALLENGE_LEN_u8];
    command[5..5 + SM_SMALL_CHALLENGE_LEN].copy_from_slice(unsafe { &card.sm_ctx.info.session.cwa.host_challenge });
    let mut challenge_encrypted_by_card = [0_u8; SM_SMALL_CHALLENGE_LEN];
    let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_4_SHORT, &mut challenge_encrypted_by_card);
    debug_assert_eq!(SM_SMALL_CHALLENGE_LEN, apdu.le);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return Err(log3ifr_ret!(ctx,f,line!(), rv)); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return Err(log3ifr_ret!(ctx,f,line!(), rv));
    }
    log3ifr!(ctx,f,line!(), SC_SUCCESS);
    Ok(des_ecb3_unpadded_8(unsafe { &card.sm_ctx.info.session.cwa.host_challenge }, key_card, Encrypt)
        == challenge_encrypted_by_card)
}

// reference: 1..=31
// TODO adapt for EVO
///
/// # Panics
///
#[named]
pub fn logout_pin(card: &mut sc_card, reference: u8) -> i32 {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    if reference == 0  ||  reference & 0x7F > 31 {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
    }

    let mut apdu = build_apdu(ctx, &[0x80, 0x2E, 0, reference], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), c"Error: ACOS5 'Logout command' failed. Returning with", SC_ERROR_CARD_CMD_FAILED);
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

// reference: 1..=31
// TODO adapt for EVO and potentially collapse with logout_pin
///
/// # Panics
///
#[allow(dead_code)]
#[cold]
#[named]
fn logout_key(card: &mut sc_card, reference: u8) -> i32 {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    if reference == 0  ||  reference & 0x7F > 31 {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
    }
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.sm_cmd = 0;
    card.drv_data = Box::into_raw(dp).cast::<c_void>();

    let mut apdu = build_apdu(ctx, &[0x80, 0x8A, 0, reference], SC_APDU_CASE_1, &mut[]);
    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), c"Error: ACOS5 'De-authenticate command' failed. Returning with", SC_ERROR_CARD_CMD_FAILED);
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

/*
In principle, iso7816_select_file is usable in a controlled manner, but if file_out is null, the first shot for an APDU is wrong, the second corrected one is okay,
thus issue a correct APDU right away
The code differs from the C version in 1 line only, where setting apdu.p2 = 0x0C;
*/

/**/
///
/// # Panics
///
//allow cognitive_complexity: This is almost equal to iso7816_select_file. Thus for easy comparison, don't split this
#[allow(dead_code)] // currently unused
#[cold]
#[named]
fn iso7816_select_file_replica(card: &mut sc_card, in_path_ref: &sc_path, file_out: &mut Option<&mut *mut sc_file>) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let mut apdu = sc_apdu::default();
    let mut buf    = [0_u8; SC_MAX_APDU_BUFFER_SIZE];
    let mut pathvalue = [0_u8; SC_MAX_PATH_SIZE];
    let mut pathvalue_ptr = pathvalue.as_mut_ptr();
    let mut r : i32;
//    let pathlen : i32;
//    let pathtype : i32;
    let mut select_mf = 0;
//    let mut file: *mut sc_file = null_mut();
//    let mut buffer : *const u8;
    let mut buffer_len : usize = 0;
    let mut cla : u32 = 0;
    let mut tag : u32 = 0;

/*
    log3if!(ctx,f,line!(), fmt_1, card.cache.current_path.type_,
        unsafe {sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len)});
*/
    log3if!(ctx,f,line!(), c"called with file_out: %p\n", file_out.as_mut().map_or_else(null_mut, |p| *p) /*if let Some(p)=file_out {p} else {null_mut()}*/ );

    /*
        if (card == NULL || in_path_ref == NULL) {
            return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
        }
    */

    pathvalue[..in_path_ref.len].copy_from_slice(&in_path_ref.value[..in_path_ref.len]);
    let mut pathlen = in_path_ref.len;
    let mut pathtype = in_path_ref.type_;

    if in_path_ref.aid.len > 0 {
        if pathlen == 0 {
            pathvalue[..in_path_ref.aid.len].copy_from_slice(&in_path_ref.aid.value[..in_path_ref.aid.len]);
            pathlen = in_path_ref.aid.len;
            pathtype = SC_PATH_TYPE_DF_NAME;
        }
        else {
            /* First, select the application */
            unsafe { sc_format_apdu(card, &mut apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0) };
            apdu.data = in_path_ref.aid.value.as_ptr();
            apdu.datalen = in_path_ref.aid.len;
            apdu.lc      = in_path_ref.aid.len;

            r =  unsafe { sc_transmit_apdu(card, &mut apdu) };
            if r < 0 {
                return log3ifr_ret!(ctx,f,line!(), c"APDU transmit failed. Returning with", r);
            }
            r = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
            if r != SC_SUCCESS {
                return log3ifr_ret!(ctx,f,line!(), r);
            }

            if pathtype == SC_PATH_TYPE_PATH || pathtype == SC_PATH_TYPE_DF_NAME {
                pathtype = SC_PATH_TYPE_FROM_CURRENT;
            }
        }
    }

    unsafe { sc_format_apdu(card, &mut apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0, 0) };

    match pathtype {
        SC_PATH_TYPE_FILE_ID => {
                apdu.p1 = 0;
                if pathlen != 2 {
                    return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
                }
            },
        SC_PATH_TYPE_DF_NAME => {
                apdu.p1 = 4;
            },
        SC_PATH_TYPE_PATH => {
                apdu.p1 = 8;
                if pathlen >= 2 && pathvalue[0]==0x3F && pathvalue[1]==0 {
                    if pathlen == 2 {    /* only 3F00 supplied */
                        select_mf = 1;
                        apdu.p1 = 0;
                    }
                    else {
                        pathvalue_ptr = unsafe { pathvalue_ptr.add(2) };
                        pathlen -= 2;
                    }
                }
            },
        SC_PATH_TYPE_FROM_CURRENT => {
                apdu.p1 = 9;
            },
        SC_PATH_TYPE_PARENT => {
                apdu.p1 = 3;
                pathlen = 0;
                apdu.cse = SC_APDU_CASE_2_SHORT;
            },
        _ => {
                return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
            },
    }

    apdu.lc = pathlen;
    apdu.data = pathvalue_ptr;
    apdu.datalen = pathlen;

    if file_out.is_none() {
////        apdu.p2 = 0x0C;        /* first record, return nothing */
        apdu.cse = if apdu.lc == 0 {SC_APDU_CASE_1} else {SC_APDU_CASE_3_SHORT};
    }
    else {
        apdu.p2 = 0;        /* first record, return FCI */
        apdu.resp = buf.as_mut_ptr();
        apdu.resplen = buf.len();
        apdu.le = std::cmp::min(me_get_max_recv_size(card), 256);
    }

    r = unsafe { sc_transmit_apdu(card, &mut apdu) };
    if r < 0 {
        return log3ifr_ret!(ctx,f,line!(), c"APDU transmit failed. Returning with", r);
    }

    if file_out.is_none() {
        /* For some cards 'SELECT' can be only with request to return FCI/FCP. */
        r = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if apdu.sw1 == 0x6A && apdu.sw2 == 0x86 {
            apdu.p2 = 0x00;
            if unsafe { sc_transmit_apdu(card, &mut apdu) } == SC_SUCCESS {
                r = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
            }
        }
        if apdu.sw1 == 0x61 {
            r = SC_SUCCESS;
        }

        return log3ifr_ret!(ctx,f,line!(), r);
    }

    r = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if r != SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), r);
    }

    if let Some(file_out_ptr) = file_out {
        if apdu.resplen == 0 {
            /* For some cards 'SELECT' MF or DF_NAME do not return FCI. */
            if select_mf>0 || pathtype == SC_PATH_TYPE_DF_NAME {
                let file = match unsafe { sc_file_new() }  {
                    ptr if ptr.is_null() =>
                        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_OUT_OF_MEMORY),
                    ptr => unsafe { &mut *ptr },
                };
                file.path = *in_path_ref;
                **file_out_ptr = file;
                return log3ifr_ret!(ctx,f,line!(), SC_SUCCESS);
            }
        }
    }

    if apdu.resplen < 2 {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED);
    }

    match unsafe { *apdu.resp } {
        ISO7816_TAG_FCI |
        ISO7816_TAG_FCP => {
            let file : &mut sc_file = match unsafe { sc_file_new() }  {
                ptr if ptr.is_null() =>
                    return log3ifr_ret!(ctx,f,line!(), SC_ERROR_OUT_OF_MEMORY),
                ptr => unsafe { &mut *ptr },
            };
            file.path = *in_path_ref;
/*
            if card->ops->process_fci == NULL {
                sc_file_free(file);
                LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
            }
*/
            let mut buffer : *const u8 = apdu.resp;
            r = unsafe { sc_asn1_read_tag(&mut buffer, apdu.resplen, &mut cla, &mut tag, &mut buffer_len) };
            if r == SC_SUCCESS {
                debug_assert_eq!(cla+tag, ISO7816_TAG_FCI.into() /* 0x6F */);
                r = acos5_process_fci(card, file, buffer, buffer_len); // card->ops->process_fci(card, file, buffer, buffer_len);
                assert_eq!(SC_SUCCESS, r);
            }
            assert!(file_out.is_some());
            if let Some(file_out_ptr) = file_out {
                **file_out_ptr = file;
            }
        },
        _ =>    return log3ifr_ret!(ctx,f,line!(), SC_ERROR_UNKNOWN_DATA_RECEIVED),
    }

    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
} // iso7816_select_file_replica
/**/

/*
The task of tracking_select_file next to SELECT:
Update card.cache.current_path such that it's always valid (pointing to the currently selected EF/DF),
both before and after the call to iso7816_select_file (even if failing)

same @param and @return as iso7816_select_file
*/
/* for SC_PATH_TYPE_FILE_ID and SC_PATH_TYPE_DF_NAME : */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
///
/// # Panics
///
#[named]
pub fn tracking_select_file(card: &mut sc_card, path_ref: &sc_path, file_out: Option<&mut *mut sc_file>, force_process_fci: bool) -> i32
{
    debug_assert!((path_ref.type_ == SC_PATH_TYPE_FILE_ID && path_ref.len==2) ||
                  (path_ref.type_ == SC_PATH_TYPE_DF_NAME && path_ref.len>=2));
    assert!(!card.ctx.is_null());
    if path_ref.type_ == SC_PATH_TYPE_FILE_ID && is_impossible_file_match(path_ref) {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let fmt_1   = c"    called. curr_type: %d, curr_value: %s, force_process_fci: %d";
    let fmt_2   = c"              to_type: %d,   to_value: %s";
    let fmt_3   = c"returning:  curr_type: %d, curr_value: %s, rv=%d";
    log3if!(ctx,f,line!(), fmt_1, card.cache.current_path.type_,
        unsafe {sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len)}, force_process_fci);
    log3if!(ctx,f,line!(), fmt_2, path_ref.type_, unsafe {sc_dump_hex(path_ref.value.as_ptr(), path_ref.len)});
    let mut file = null_mut();
    let guard_file = GuardFile::new(&mut file);
//println!("file_out.is_null: {}", file_out.is_none());
    let file_tmp : Option<&mut *mut sc_file> = if force_process_fci {unsafe{guard_file.as_mut()}} else {file_out};
    #[allow(clippy::unnecessary_unwrap)]
    let rv = unsafe { (*(*sc_get_iso7816_driver()).ops).select_file.
        expect("The OpenSC iso7816_driver didn't implement the method 'select_file' !")
        (card, path_ref, if file_tmp.is_some() {file_tmp.unwrap()} else {&mut file} ) };
//    let rv = iso7816_select_file_replica(card, path_ref, &mut file_tmp);
    let mut file_id : u16 = 0;
/*
        if rv==SC_SUCCESS && path_ref.type_ == SC_PATH_TYPE_DF_NAME {
            0//u16::try_from(unsafe { (*(*file_tmp.unwrap())).id } ).unwrap()  // TODO
        }
        else {0};
*/
    /*
    0x6283, SC_ERROR_CARD_CMD_FAILED, "Selected file invalidated" //// Target file has been blocked but selected
    0x6982, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, "Security status not satisfied" //// Target file has wrong checksum in its header or file is corrupted; probably selected, but inaccessible: test that
    0x6986, SC_ERROR_NOT_ALLOWED,  "Command not allowed (no current EF)" //// No Master File found in card; no MF found
    0x6A82, SC_ERROR_FILE_NOT_FOUND, "File not found" //// Target file not found
    0x6A86, SC_ERROR_INCORRECT_PARAMETERS,"Incorrect parameters P1-P2" //// Invalid P1 or P2. P2 must be 00h and P1 must be 00h or 04h
    0x6A87, SC_ERROR_INCORRECT_PARAMETERS,"Lc inconsistent with P1-P2" //// Wrong P3 length. P3 is not compatible with P1.
      SC_ERROR_CARD_CMD_FAILED if iso7816_check_sw encounters unknown error
    */
    if [      SC_ERROR_WRONG_LENGTH,
              SC_ERROR_NOT_ALLOWED,
              SC_ERROR_FILE_NOT_FOUND,
              SC_ERROR_INCORRECT_PARAMETERS,
              SC_ERROR_UNKNOWN_DATA_RECEIVED,
              SC_ERROR_INVALID_ARGUMENTS,
              SC_ERROR_INVALID_DATA ].contains(&rv) {
        // select failed, no new card.cache.current_path, do nothing
    }
    else if [ SC_SUCCESS,
              SC_ERROR_CARD_CMD_FAILED,
              SC_ERROR_SECURITY_STATUS_NOT_SATISFIED ].contains(&rv) {
        // file got selected
        if path_ref.type_ == SC_PATH_TYPE_FILE_ID {
            file_id = if path_ref.value[0..2] == [0x3F_u8, 0xFF][..] {file_id_from_path_value(current_path_df(card))}
                      else {u16::from_be_bytes([path_ref.value[0], path_ref.value[1]])};
        }
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        assert!(dp.files.contains_key(&file_id));
        let dp_files_value = &dp.files[&file_id];
        card.cache.current_path.value = dp_files_value.0;
        card.cache.current_path.len   = usize::from(dp_files_value.1[1]);
        let _unused = Box::leak(dp);
    }
    else {
        unreachable!("calling `iso7816_select_file_replica` returned the error code rv: {rv}. Function \
            `tracking_select_file` doesn't yet handle that error (whether to adapt card.cache.current_path?)");
    }

    log3if!(ctx,f,line!(), fmt_3, card.cache.current_path.type_,
        unsafe {sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len)}, rv);
    rv
}


/* process path by chunks, 2 byte each and select_file with SC_PATH_TYPE_FILE_ID
   1. Don't select more than necessary
   2. Suppress process_fci for intermediate selections
   */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
///
/// # Panics
///
pub fn select_file_by_path(card: &mut sc_card, path_ref: &sc_path, file_out: Option<&mut *mut sc_file>, force_process_fci: bool) -> i32
{
    /* manage file_out and force_process_fci: They need to be active only eventually for the target file_id */
    if  path_ref.len%2 != 0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let mut path1 = *path_ref;
    cut_path(&mut path1.value[..path1.len], &mut path1.len, current_path_df(card));
    if  path1.len%2 != 0 || path1.len==0 {
        return SC_ERROR_CARD_CMD_FAILED;
    }

    let target_idx = path1.len/2 -1; // it's the max. i index in the following loop

    let mut path2 = sc_path { len: 2, ..sc_path::default() }; // SC_PATH_TYPE_FILE_ID

    for (i, chunk) in path1.value[..path1.len].chunks_exact(2).enumerate() {
        assert!(i<=target_idx);
        path2.value[..2].copy_from_slice(chunk);
        let rv=
            if i<target_idx {
                tracking_select_file(card, &path2, None, false)
            }
            else {
                continue;
                // tracking_select_file(card, &path2, file_out, force_process_fci)
            };

        if rv != SC_SUCCESS {
            return rv;
        }
    }
    tracking_select_file(card, &path2, file_out, force_process_fci)
}

/* FIPS compliance dictates these values for SC_CARD_TYPE_ACOS5_64_V3 */
// #[allow(dead_code)]
///
/// # Panics
///
#[cold]
fn get_known_sec_env_entry_v3_fips(is_local: bool, rec_nr: u32, buf: &mut [u8])
{
    assert_eq!(buf.len(), 33);
    assert!( is_local || [1, 2].contains(&rec_nr));
    assert!(!is_local || [1, 2, 3, 4, 5].contains(&rec_nr));

    if is_local {
        match  rec_nr {
            /* SEID #1: Security Officer Key 0x01 must be authenticated. */
            1 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x01,  0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x80,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]); },
            /* SEID #2: Security Officer Key 0x01 must be authenticated and command must be in Secure Messaging mode (using Key 0x02). */
            2 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x02,  0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x80,
                0xB4, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30,
                0xB8, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30 ]); },
            /* SEID #3: User PIN must be verified. */
            3 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x03,  0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]); },
            /* SEID #4: User PIN must be verified and use Secure Messaging with Encryption Key (using Key 0x02). */
            4 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x04,  0xA4, 0x06, 0x83, 0x01, 0x81, 0x95, 0x01, 0x08,
                0xB4, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30,
                0xB8, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30 ]); },
            /* SEID #5: Use under Secure Messaging with Encryption Key (using Key 0x02). */
            5 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x05,  0xB4, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30,
                0xB8, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30,
                0, 0, 0, 0, 0, 0, 0, 0 ]); },
            _ => (),
        }
    }
    else {
       match  rec_nr {
           /* SEID #1: Security Officer Key 0x01 must be authenticated. */
           1 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x01,  0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x80,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]); },
           /* SEID #2: Security Officer Key 0x01 must be authenticated and command must be in Secure Messaging mode (using Key 0x02). */
           2 => { buf.copy_from_slice(&[0x80_u8, 0x01, 0x02,  0xA4, 0x06, 0x83, 0x01, 0x01, 0x95, 0x01, 0x80,
                                                                  0xB4, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30,
                                                                  0xB8, 0x09, 0x80, 0x01, 0x02, 0x83, 0x01, 0x02, 0x95, 0x01, 0x30 ]); },
           _ => (),
       }
    }
}

/* This is the first function that calls select_file
 * What it does
 * @apiNote
 * @param
 * @return
 */
///
/// # Panics
///
#[named]
pub fn enum_dir(card: &mut sc_card, path_ref: &sc_path, only_se_df: bool/*, depth: i32*/) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let mut fmt   = c"called for path: %s";
    log3if!(ctx,f,line!(), fmt, unsafe {sc_dump_hex(path_ref.value.as_ptr(), path_ref.len)});

    let file_id = file_id_from_path_value(&path_ref.value[..path_ref.len]);
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let mut dp_files_value = dp.files.get_mut(&file_id).unwrap();
    let fdb = dp_files_value.1[0];
    dp_files_value.0    = path_ref.value;
    dp_files_value.1[1] = u8::try_from(path_ref.len).unwrap();
    /* assumes meaningful values in dp_files_value.1 */
    let mrl = usize::from(dp_files_value.1[4]); // MRL: Max. Record Length; this is correct only if the file is record-based
    let nor  = u32::from(dp_files_value.1[5]);   // NOR: Number Of Records
    card.drv_data = Box::into_raw(dp).cast::<c_void>();

    let is_se_file_only =  fdb == FDB_SE_FILE && only_se_df;
    let is_ef_dir =  file_id == 0x2F00  &&  path_ref.len == 4;

    /* needs to be done once only */
    if is_se_file_only && mrl>0 && nor>0
    {
        /* file has the only purpose to invoke scb8 retrieval */
        let mut file = null_mut();
        let guard_file = GuardFile::new(&mut file);
        let mut rv = unsafe { sc_select_file(card, path_ref, *guard_file) };
        assert_eq!(rv, SC_SUCCESS);
        assert!(!file.is_null());
        let mut acl_entry_read_method: u32 = SC_AC_UNKNOWN;
        let entry = unsafe { sc_file_get_acl_entry(file, SC_AC_OP_READ) };
        if !entry.is_null() {
            acl_entry_read_method = unsafe { (*entry).method };
        }

        let is_local =  path_ref.len>=6;
//      let len /*_card_serial_number*/ = if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 {6_u8} else {8_u8};
        let /*mut*/ pin_verified = false;
/*
        if false && SC_AC_CHV == acl_entry_read_method {
            /* card.type_== SC_CARD_TYPE_ACOS5_64_V2 have 6 byte serial numbers, SC_CARD_TYPE_ACOS5_64_V3 have 8 byte.
              We are comparing based on 8 bytes, thus append 2 zero bytes for SC_CARD_TYPE_ACOS5_64_V2 when comparing here;
               also, the pin ids may be different from local 0x81 or global 0x01 used here (to be adjusted) */
            if card.serialnr.value[..8]==[0xFF_u8, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,  0,0][..] { // this is only for serialnr: FF EE DD CC BB AA of a SC_CARD_TYPE_ACOS5_64_V2
                let mut tries_left = 0;
                let pin_user:  [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]; // User pin, local  12345678
                let pin_admin: [u8; 8] = [0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31]; // SO_PIN, global   87654321
                let mut pin_user_verified  = false;
                let mut pin_admin_verified = false;
                let is_wrong_acs_initialized = true;
                if is_local {
                    rv = unsafe { sc_verify(card, SC_AC_CHV, 0x80|1, pin_user.as_ptr(), pin_user.len(), &mut tries_left) };
                    pin_user_verified =  rv==SC_SUCCESS;// assert_eq!(rv, SC_SUCCESS);
                    println!("Pin verification performed for ser.num [0xFF_u8, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,  0,0] and sec. env. file {:X}, resulting in pin_user_verified={}", file_id, pin_user_verified);
                }
                else if !is_wrong_acs_initialized {
                    rv = unsafe { sc_verify(card, SC_AC_CHV, 1, pin_admin.as_ptr(), pin_admin.len(), &mut tries_left) };
                    pin_admin_verified =  rv==SC_SUCCESS;// assert_eq!(rv, SC_SUCCESS);
                    println!("Pin verification performed for ser.num [0xFF_u8, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,  0,0] and sec. env. file {:X}, resulting in pin_admin_verified={}", file_id, pin_admin_verified);
                }
                pin_verified = pin_user_verified || pin_admin_verified;
            }
            else if card.serialnr.value[..8]==[0xFF_u8, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,  9,8][..] { // this example is for a SC_CARD_TYPE_ACOS5_64_V3
                /* same as before for another Serial no. */
            }
        }
*/
        let mut vec_sac_info = Vec::with_capacity(14);
        if (card.type_== SC_CARD_TYPE_ACOS5_64_V3  &&  SC_AC_AUT==acl_entry_read_method) ||
             SC_AC_NONE == acl_entry_read_method ||
            (SC_AC_CHV  == acl_entry_read_method && pin_verified)
        {
            /*
              TODO only if  card.type_== SC_CARD_TYPE_ACOS5_64_V3 &&
                            get_op_mode_byte==0 &&
                            get_fips_compliance == true
              then take record entries from get_known_sec_env_entry_v3_fips
              pub fn get_op_mode_byte(card: &mut sc_card) -> Result<u8, i32>
              pub fn get_fips_compliance(card: &mut sc_card) -> Result<bool, i32> // is_FIPS_compliant==true
            */

            for rec_nr in 1..=nor {
                let mut buf = [0_u8; 255];
                /* The case for V3 being FIPS-compliant, see 9.0. FIPS Mode File System Requirements: Don't read but take known entries */
                if card.type_== SC_CARD_TYPE_ACOS5_64_V3  &&  SC_AC_AUT==acl_entry_read_method {
                    get_known_sec_env_entry_v3_fips(is_local, rec_nr, &mut buf[..33]);
                }
                else {
                    rv = unsafe { cfg_if::cfg_if! {
                        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
                            sc_read_record(card, rec_nr, buf.as_mut_ptr(), mrl, SC_RECORD_BY_REC_NR)
                        }
                        else {
                            sc_read_record(card, rec_nr, 0, buf.as_mut_ptr(), mrl, SC_RECORD_BY_REC_NR)
                        }
                    }};
                    assert!(rv >= 0);
                    if rv >= 1 && buf[0] == 0 || rv >= 3 && buf[2] == 0 { // "empty" record
                        break;
                    }
                    if rv >= 3 {
                        assert_eq!(rec_nr, u32::from(buf[2]) /*se id*/); // not really required but recommended: enforces, that se id x(>0) is stored in record indexed x (beginning with index 1)
                    }
                }
                let mut sac_info = SACinfo::default();
                let rv = se_parse_sac(u32::from(buf[2]),&buf[3..], &mut sac_info);
                assert!(rv > 0);
                vec_sac_info.push(sac_info);
            }
        }

        assert!(path_ref.len >= 4);
        let file_id_dir = u16::from_be_bytes([path_ref.value[path_ref.len-4], path_ref.value[path_ref.len-3]]);

        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        assert!(dp.files.contains_key(&file_id_dir));
        dp_files_value = dp.files.get_mut(&file_id_dir).unwrap(); // &mut tuple
        /* DF's SAE processing was done already, i.e. dp_files_value.3 may be Some */
        dp_files_value.3.get_or_insert(Vec::new()).extend_from_slice(&vec_sac_info);
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
    }
    else if is_DFMF(fdb)
    {
        assert!(path_ref.len <= SC_MAX_PATH_SIZE);
        /* file has the only purpose to invoke scb8 retrieval */
        let mut file = null_mut();
        let guard_file = GuardFile::new(&mut file);
        let mut rv = unsafe { sc_select_file(card, path_ref, *guard_file) };
        if rv < 0 && path_ref.len==2 && path_ref.value[0]==0x3F && path_ref.value[1]==0 {
            let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
            dp.does_mf_exist = false;
            card.drv_data = Box::into_raw(dp).cast::<c_void>();
            return log3ifr_ret!(ctx,f,line!(), SC_SUCCESS);
        }
        assert_eq!(rv, SC_SUCCESS);
        if path_ref.len == 16 {
            fmt  = c"### enum_dir: couldn't visit all files due to OpenSC path.len limit.\
 Such deep file system structures are not recommended, nor supported by cos5 with file access control! ###";
            log3if!(ctx,f,line!(), fmt);
        }
        else {
            let mut files_contained= vec![0_u8; 2*255];
            rv = /*acos5_list_files*/ unsafe { sc_list_files(card, files_contained.as_mut_ptr(), files_contained.len()) };
            if rv < SC_SUCCESS {
                return log3ifr_ret!(ctx,f,line!(), rv);
            }
            // debug_assert!(num_integer::Integer::is_multiple_of(&rv, &2));
            files_contained.truncate(usize::try_from(rv).unwrap());
            /* * /
                    println!("chunk1 files_contained: {:?}", &files_contained[  ..32]);
                    println!("chunk2 files_contained: {:?}", &files_contained[32..64]);
                    println!("chunk3 files_contained: {:?}", &files_contained[64..96]);
            / * */
            assert!(rv >= 0 && rv%2 == 0);

            for chunk in files_contained.chunks_exact(2) {
                let mut tmp_path = *path_ref;
                tmp_path.value[tmp_path.len..tmp_path.len+2].copy_from_slice(chunk);
                tmp_path.len += 2;
//              assert_eq!(tmp_path.len, ((depth+2)*2) as usize);
                let _unused = enum_dir(card, &tmp_path, only_se_df/*, depth + 1*/);
            }
        }
    }
    else if is_ef_dir /* || [FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&fdb)*/ {
        /* file has the only purpose to invoke scb8 retrieval */
        let mut file = null_mut();
        let guard_file = GuardFile::new(&mut file);
        let rv = unsafe { sc_select_file(card, path_ref, *guard_file) };
        assert_eq!(rv, SC_SUCCESS);
/*
        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        if let Some(x) = dp.files.get_mut(&file_id) {
            /* how to distinguish RSAPUB from RSAPRIV without reading ? Assume unconditionally allowed to read: RSAPUB*/
            if fdb == FDB_RSA_KEY_EF {
                (*x).1[6] = if (*x).2.unwrap()[0] == 0 {PKCS15_FILE_TYPE_RSAPUBLICKEY} else {PKCS15_FILE_TYPE_RSAPRIVATEKEY};
            }
            else {
                (*x).1[6] = if (*x).2.unwrap()[0] == 0 {PKCS15_FILE_TYPE_ECCPUBLICKEY} else {PKCS15_FILE_TYPE_ECCPRIVATEKEY};
            }
        }
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
*/
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
} // enum_dir

///
/// # Panics
///
#[named]
fn enum_dir_gui(card: &mut sc_card, path_ref: &sc_path/*, only_se_df: bool*/ /*, depth: i32*/) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let mut fmt   = c"called for path: %s";
    log3if!(ctx,f,line!(), fmt, unsafe {sc_dump_hex(path_ref.value.as_ptr(), path_ref.len)});

    assert!(path_ref.len >= 2);
    let file_id = file_id_from_path_value(&path_ref.value[..path_ref.len]);

    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let dp_files_value = &dp.files[&file_id];
    let fdb = dp_files_value.1[0];
    let is_none_2 = dp_files_value.2.is_none();
    let _unused = Box::leak(dp);

    if is_DFMF(fdb)
    {
        assert!(path_ref.len <= SC_MAX_PATH_SIZE);
        let mut rv = unsafe { sc_select_file(card, path_ref, null_mut()) };
        assert_eq!(rv, SC_SUCCESS);
        if path_ref.len == 16 {
            fmt  = c"### enum_dir_gui: couldn't visit all files due to OpenSC path.len limit.\
 Such deep file system structures are not recommended, nor supported by cos5 with file access control! ###";
            log3if!(ctx,f,line!(), fmt);
        }
        else {
            let mut files_contained= vec![0_u8; 2*255];
            rv = unsafe { sc_list_files(card, files_contained.as_mut_ptr(), files_contained.len()) };
            if rv < SC_SUCCESS || (rv%2)==1 {
                return log3ifr_ret!(ctx,f,line!(), rv);
            }
            files_contained.truncate(usize::try_from(rv).unwrap());
            for chunk in files_contained.chunks_exact(2) {
                let mut tmp_path = *path_ref;
                tmp_path.value[tmp_path.len  ] = chunk[0];
                tmp_path.value[tmp_path.len+1] = chunk[1];
                tmp_path.len += 2;
                let _unused = enum_dir_gui(card, &tmp_path/*, only_se_df*/ /*, depth + 1*/);
            }
        }
    }
    else if is_none_2 {
        let rv = unsafe { sc_select_file(card, path_ref, null_mut()) };
        assert_eq!(rv, SC_SUCCESS);
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
} // enum_dir_gui


///
/// # Errors
///
/// # Panics
/// # Errors
///
pub fn convert_amdo_to_cla_ins_p1_p2_array(amdo_tag: u8, amdo_bytes: &[u8]) -> Result<[u8; 4], i32> //Access Mode Data Object
{
    assert!(!amdo_bytes.is_empty() && amdo_bytes.len() <= 4);
    let amb = amdo_tag&0x0F;
    assert!(amb>0);
    if amdo_bytes.len() != amb.count_ones().try_into().unwrap() { // the count of 1-valued bits of amb Byte must equal  the count of bytes following amb
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    let mut idx = 0;
    let mut cla_ins_p1_p2 = [0_u8; 4];
    for (pos, item) in cla_ins_p1_p2.iter_mut().enumerate() { // for pos in 0..4
        if (amb & (0b1000 >> u8::try_from(pos).unwrap())) != 0 { //assert(i);we should never get anything for scb8[7], it's not used by ACOS
            *item = amdo_bytes[idx];
            idx += 1;
        }
    }
    Ok(cla_ins_p1_p2)
}

pub const ACL_CATEGORY_DF_MF  : u8 =  1;
pub const ACL_CATEGORY_EF_CHV : u8 =  2;
pub const ACL_CATEGORY_KEY    : u8 =  3;
pub const ACL_CATEGORY_SE     : u8 =  4;

// TODO overhaul this: may be shorter and smarter
/*
This MUST match exactly how *mut sc_acl_entry are added in acos5_process_fci or profile.c
*/
///
/// # Panics
/// # Errors
///
pub fn convert_acl_array_to_bytes_tag_fcp_sac(/*card: &mut sc_card,*/ acl: &[*mut sc_acl_entry; SC_MAX_AC_OPS], acl_category: u8) -> Result<[u8; 8], i32>
{
    // let ctx = unsafe { &mut *card.ctx };
    // log3ifc!(ctx,c"convert_acl_array_to_bytes_tag_fcp_sac",line!());
    const SC_AC_FLAGS_ALL_ALLOWED : [u32; 12] = [
        SC_AC_NONE, SC_AC_CHV, SC_AC_TERM, SC_AC_PRO, SC_AC_AUT, SC_AC_SYMBOLIC, SC_AC_SEN, SC_AC_SCB, SC_AC_IDA, SC_AC_SESSION/*, SC_AC_CONTEXT_SPECIFIC*/, SC_AC_UNKNOWN, SC_AC_NEVER];
    let mut result = [0x7F_u8,0,0,0,0,0,0,0];
    match acl_category {
        ACL_CATEGORY_SE => {
            let p = acl[usize::try_from(SC_AC_OP_READ).unwrap()];
            if p.is_null() {                      result[7] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[7] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[7] = 0xFF; }
        },
        ACL_CATEGORY_DF_MF => {
            let mut p = acl[usize::try_from(SC_AC_OP_DELETE).unwrap()];
            if p.is_null() {                      result[7] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[7] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_DELETE sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[7] = u8::try_from(p_ref.key_ref).unwrap();
            }
            p = acl[usize::try_from(SC_AC_OP_CREATE_EF).unwrap()];
            if p.is_null() {                      result[6] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[6] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_CREATE_EF sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[6] = u8::try_from(p_ref.key_ref).unwrap();
            }
            p = acl[usize::try_from(SC_AC_OP_CREATE_DF).unwrap()];
            if p.is_null() {                      result[5] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[5] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[5] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[5] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_CREATE_DF sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[5] = u8::try_from(p_ref.key_ref).unwrap();
            }
        }
        ACL_CATEGORY_KEY => {
            let mut p = acl[usize::try_from(SC_AC_OP_READ).unwrap()];
            if p.is_null() {                      result[7] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[7] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_READ sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[7] = u8::try_from(p_ref.key_ref).unwrap();
            }
            p = acl[usize::try_from(SC_AC_OP_UPDATE).unwrap()];
            if p.is_null() {                      result[6] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[6] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_UPDATE sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[6] = u8::try_from(p_ref.key_ref).unwrap();
            }
            p = acl[usize::try_from(SC_AC_OP_CRYPTO).unwrap()];
            if p.is_null() {                      result[5] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[5] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[5] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[5] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_CRYPTO sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[5] = u8::try_from(p_ref.key_ref).unwrap();
            }
        }
        ACL_CATEGORY_EF_CHV => {
            let mut p = acl[usize::try_from(SC_AC_OP_READ).unwrap()];
            if p.is_null() {                      result[7] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[7] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[7] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_READ sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[7] = u8::try_from(p_ref.key_ref).unwrap();
            }
            p = acl[usize::try_from(SC_AC_OP_UPDATE).unwrap()];
            if p.is_null() {                      result[6] = 0; }
            else if p==(1 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else if p==(2 as *mut sc_acl_entry) { result[6] = 0; }
            else if p==(3 as *mut sc_acl_entry) { result[6] = 0xFF; }
            else {
                let p_ref = unsafe { &*p };
//println!("SC_AC_OP_UPDATE sc_acl_entry: {:?}", *p_ref );
                if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
                { return Err(SC_ERROR_NOT_ALLOWED); }
                result[6] = u8::try_from(p_ref.key_ref).unwrap();
            }
        },
        _ => (),
    };
    let mut p = acl[usize::try_from(SC_AC_OP_INVALIDATE).unwrap()];
    if p.is_null() {                      result[4] = 0; }
    else if p==(1 as *mut sc_acl_entry) { result[4] = 0xFF; }
    else if p==(2 as *mut sc_acl_entry) { result[4] = 0; }
    else if p==(3 as *mut sc_acl_entry) { result[4] = 0xFF; }
    else {
        let p_ref = unsafe { &*p };
//println!("SC_AC_OP_INVALIDATE sc_acl_entry: {:?}", *p_ref );
        if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
        { return Err(SC_ERROR_NOT_ALLOWED); }
        result[4] = u8::try_from(p_ref.key_ref).unwrap();
    }

    p = acl[usize::try_from(SC_AC_OP_REHABILITATE).unwrap()];
    if p.is_null() {                      result[3] = 0; }
    else if p==(1 as *mut sc_acl_entry) { result[3] = 0xFF; }
    else if p==(2 as *mut sc_acl_entry) { result[3] = 0; }
    else if p==(3 as *mut sc_acl_entry) { result[3] = 0xFF; }
    else {
        let p_ref = unsafe { &*p };
//println!("SC_AC_OP_REHABILITATE sc_acl_entry: {:?}", *p_ref );
        if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
        { return Err(SC_ERROR_NOT_ALLOWED); }
        result[3] = u8::try_from(p_ref.key_ref).unwrap();
    }

    p = acl[usize::try_from(SC_AC_OP_LOCK).unwrap()];
    if p.is_null() {                      result[2] = 0; }
    else if p==(1 as *mut sc_acl_entry) { result[2] = 0xFF; }
    else if p==(2 as *mut sc_acl_entry) { result[2] = 0; }
    else if p==(3 as *mut sc_acl_entry) { result[2] = 0xFF; }
    else {
        let p_ref = unsafe { &*p };
//println!("SC_AC_OP_LOCK sc_acl_entry: {:?}", *p_ref );
        if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
        { return Err(SC_ERROR_NOT_ALLOWED); }
        result[2] = u8::try_from(p_ref.key_ref).unwrap();
    }

    p = acl[usize::try_from(SC_AC_OP_DELETE_SELF).unwrap()];
    if p.is_null() {                      result[1] = 0; }
    else if p==(1 as *mut sc_acl_entry) { result[1] = 0xFF; }
    else if p==(2 as *mut sc_acl_entry) { result[1] = 0; }
    else if p==(3 as *mut sc_acl_entry) { result[1] = 0xFF; }
    else {
        let p_ref = unsafe { &*p };
//println!("SC_AC_OP_DELETE_SELF sc_acl_entry: {:?}", *p_ref );
        if !SC_AC_FLAGS_ALL_ALLOWED.contains(&p_ref.method)
        { return Err(SC_ERROR_NOT_ALLOWED); }
        result[1] = u8::try_from(p_ref.key_ref).unwrap();
    }

    Ok(result)
} // convert_acl_array_to_bytes_tag_fcp_sac


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
///
/// # Panics
///
#[named]
pub fn pin_get_policy(card: &mut sc_card, data: &mut sc_pin_cmd_data, tries_left: &mut i32) -> i32
{
/* when is AODF read for the pin details info info ? */
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    data.pin1.min_length = 4; /* min length of PIN */
    data.pin1.max_length = 8; /* max length of PIN */
    #[cfg(v0_20_0)]
    {
        data.pin1.stored_length = 8; /* stored length of PIN */
    }
    data.pin1.encoding = SC_PIN_ENCODING_ASCII; /* ASCII-numeric, BCD, etc */
//  data.pin1.pad_length    = 0; /* filled in by the card driver */
    data.pin1.pad_char = 0xFF;
    data.pin1.offset = 5; /* PIN offset in the APDU */
    #[cfg(v0_20_0)]
    {
//      data.pin1.length_offset = 5;
        data.pin1.length_offset = 0; /* Effective PIN length offset in the APDU */
    }

    data.pin1.max_tries = 8;//pin_tries_max; /* Used for signaling back from SC_PIN_CMD_GET_INFO */ /* assume: 8 as factory setting; max allowed number of retries is unretrievable with proper file access condition NEVER read */

    let mut apdu = build_apdu(ctx, &[0x00_u8, 0x20, 0x00, u8::try_from(data.pin_reference).unwrap()], SC_APDU_CASE_1, &mut[]);
    let rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
    if apdu.sw1 == 0x63 && ((apdu.sw2 & 0xC0) == 0xC0) {}
    else {
        return log3ifr_ret!(ctx,f,line!(), c"Error: 'Get remaining number of retries left for the PIN' failed. Returning with", SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    data.pin1.tries_left = i32::try_from(apdu.sw2 & 0x0F_u32).unwrap(); //  63 Cnh     n is remaining tries
    *tries_left = data.pin1.tries_left;
    if card.type_ == SC_CARD_TYPE_ACOS5_64_V3 {
        match is_pin_authenticated(card, data.pin_reference.try_into().unwrap()) {
            Ok(val) => data.pin1.logged_in = if val {SC_PIN_STATE_LOGGED_IN} else {SC_PIN_STATE_LOGGED_OUT},
            Err(_e) => data.pin1.logged_in = SC_PIN_STATE_UNKNOWN,
        }
    }
    else {
//        data.pin1.logged_in = SC_PIN_STATE_LOGGED_IN; // without this, session will be closed for pkcs11-tool -t -l, since v0.20.0
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

#[must_use]
pub fn acos5_supported_atrs() -> [sc_atr_table; 6]
{
    [
        sc_atr_table {
            atr:     ATR_V2.as_ptr(),
            atrmask: ATR_MASK.as_ptr(),
            name:    NAME_V2.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_64_V2,
            flags: 0,
            card_atr: null_mut(),
        },
        sc_atr_table {
            atr:     ATR_V3.as_ptr(),
            atrmask: ATR_MASK.as_ptr(),
            name:    NAME_V3.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_64_V3,
            flags: 0,
            card_atr: null_mut(),
        },
/*
        sc_atr_table {
            atr:     ATR_V4.as_ptr(),
            atrmask: ATR_MASK.as_ptr(),
            name:    NAME_V4.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_EVO_V4,
            flags: 0,
            card_atr: null_mut(),
        },
*/
        sc_atr_table {
            atr:     ATR_V4_1.as_ptr(),
            atrmask: ATR_MASK_TCK.as_ptr(),
            name:    NAME_V4.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_EVO_V4,
            flags: 0,
            card_atr: null_mut(),
        },
        sc_atr_table {
            atr:     ATR_V4_2.as_ptr(),
            atrmask: ATR_MASK_TCK.as_ptr(),
            name:    NAME_V4.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_EVO_V4,
            flags: 0,
            card_atr: null_mut(),
        },
        sc_atr_table {
            atr:     ATR_V4_3.as_ptr(),
            atrmask: ATR_MASK_TCK.as_ptr(),
            name:    NAME_V4.as_ptr(),
            type_: SC_CARD_TYPE_ACOS5_EVO_V4,
            flags: 0,
            card_atr: null_mut(),
        },
        sc_atr_table::default(),
    ]
}

/*  ECC: Curves P-224/P-256/P-384/P-521 */
#[must_use]
pub fn acos5_supported_ec_curves() -> [Acos5EcCurve; 4]
{
    [
        Acos5EcCurve {
            curve_name: c"nistp224".as_ptr(),
            curve_oid:  sc_object_id { value : [1, 3, 132, 0, 33,  -1,0,0,0,0,0,0,0,0,0,0] },
            size: 224,
        },
        Acos5EcCurve {
            curve_name: c"nistp256".as_ptr(),
            curve_oid:  sc_object_id { value : [1, 2, 840, 10045, 3, 1, 7,  -1,0,0,0,0,0,0,0,0] },
            size: 256,
        },
        Acos5EcCurve {
            curve_name: c"nistp384".as_ptr(),
            curve_oid:  sc_object_id { value : [1, 3, 132, 0, 34,  -1,0,0,0,0,0,0,0,0,0,0] },
            size: 384,
        },
        Acos5EcCurve {
            curve_name: c"nistp521".as_ptr(),
            curve_oid:  sc_object_id { value : [1, 3, 132, 0, 35,  -1,0,0,0,0,0,0,0,0,0,0] },
            size: 521,
        },
//        Acos5EcCurve::default(),
    ]
}

pub fn set_is_running_cmd_long_response(card: &mut sc_card, value: bool)
{
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.is_running_cmd_long_response = value;
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
}

pub fn get_is_running_cmd_long_response(card: &mut sc_card) -> bool
{
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let result = dp.is_running_cmd_long_response;
    let _unused = Box::leak(dp);
    result
}

pub fn set_is_running_compute_signature(card: &mut sc_card, value: bool)
{
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.is_running_compute_signature = value;
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
}

pub fn get_is_running_compute_signature(card: &mut sc_card) -> bool
{
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let result = dp.is_running_compute_signature;
    let _unused = Box::leak(dp);
    result
}

/*
pub fn set_rsa_caps(card: &mut sc_card, value: u32)
{
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.rsa_caps = value;
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
}

#[allow(dead_code)]
#[cold]
#[must_use]
fn get_rsa_caps(card: &mut sc_card) -> c_ulong
{
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let result = dp.rsa_caps.try_into().unwrap();
    let _unused = Box::leak(dp);
    result
}
*/

pub fn set_sec_env(card: &mut sc_card, value: &sc_security_env)
{
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.sec_env = *value;
    // if sc_get_encoding_flags evaluates: secure algorithm flags == 0x0, then set SC_ALGORITHM_RSA_RAW
//    dp.sec_env.algorithm_flags = std::cmp::max(dp.sec_env.algorithm_flags, SC_ALGORITHM_RSA_PAD_PKCS1);
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
    set_sec_env_mod_len(card, value);
}

pub fn get_sec_env(card: &mut sc_card) -> sc_security_env
{
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let result = dp.sec_env;
    let _unused = Box::leak(dp);
    result
}

pub fn get_sec_env_mod_len(card: &mut sc_card) -> usize
{
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let result = usize::from(dp.sec_env_mod_len);
    let _unused = Box::leak(dp);
    result
}

///
/// # Panics
///
fn set_sec_env_mod_len(card: &mut sc_card, env_ref: &sc_security_env)
{
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.sec_env_mod_len = 0;
    if env_ref.algorithm==SC_ALGORITHM_RSA && (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0 {
        assert!(env_ref.file_ref.len >= 2);
        let path_idx = env_ref.file_ref.len - 2;
        let file_id = u16::from_be_bytes([env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1]]);
        let file_size = file_id_se(dp.files[&file_id].1);
        if [SC_SEC_OPERATION_SIGN,
            SC_SEC_OPERATION_DECIPHER /*, SC_SEC_OPERATION_DECIPHER_RSAPRIVATE*/].contains(&env_ref.operation) { //priv
            assert!(file_size>=5);
            let x = ((file_size-5)*2)/5;
            if x*5/2 == file_size-5  &&  x % 32 == 0 { dp.sec_env_mod_len = x; }
            else if    (file_size-5)       % 32 == 0 { dp.sec_env_mod_len = file_size-5; }
        }
        else if [SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC].contains(&env_ref.operation) {
            assert!(file_size>=21);
            if (file_size-21)                 % 32 == 0 { dp.sec_env_mod_len = file_size-21; }
        }
        else if SC_SEC_OPERATION_UNWRAP == env_ref.operation { //priv
            assert!(file_size>=5);
            let x = ((file_size-5)*2)/5;
            if x*5/2 == file_size-5  &&  x % 32 == 0 { dp.sec_env_mod_len = x; }
            else if    (file_size-5)       % 32 == 0 { dp.sec_env_mod_len = file_size-5; }
        }
//println!("\nfile_id: 0x{:X}, file_size: {}, modulusLenBytes: {}", file_id, file_size, dp.sec_env_mod_len);
    }
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
}
//std::cmp::min(512,outlen)

/// # Safety
///
/// This function should not be called before the horsemen are ready.
/* this is tailored for a special testing use case, don't use generally, SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC */
//TODO integrate this into encrypt_asym
///
/// # Panics
///
#[allow(dead_code)]
#[cold]
fn encrypt_public_rsa(card_ptr: *mut sc_card, signature: *const u8, siglen: usize)
{
/*
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
*/
    assert!(!card_ptr.is_null());
    assert!(unsafe { !(*card_ptr).ctx.is_null() });
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let mut path = sc_path::default();
    unsafe { sc_format_path(c"3f0041004133".as_ptr(), &mut path); } // type = SC_PATH_TYPE_PATH;
    let mut file = null_mut();
    let guard_file = GuardFile::new(&mut file);
    // why this selection is done ?
    let mut rv = unsafe { sc_select_file(card, &path, *guard_file) };
    assert_eq!(rv, SC_SUCCESS);
    let mut apdu = build_apdu(ctx, &[0_u8, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x12, 0x81, 0x02, 0x41, 0x33, 0x95, 0x01, 0x80], SC_APDU_CASE_3_SHORT, &mut[]);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    assert_eq!(rv, SC_SUCCESS);
    let mut rbuf = [0_u8; 512];
    assert_eq!(rbuf.len(), siglen);
    apdu = build_apdu(ctx, &[0_u8, 0x2A, 0x84, 0x80, 0x02, 0xFF, 0xFF, 0xFF], SC_APDU_CASE_4_SHORT, &mut rbuf);
    apdu.data    = signature;
    apdu.datalen = siglen;
    apdu.lc      = siglen;
    apdu.le      = std::cmp::min(siglen, SC_READER_SHORT_APDU_MAX_RECV_SIZE);
    if apdu.lc > card.max_send_size {
        apdu.flags |= SC_APDU_FLAGS_CHAINING;
    }

    set_is_running_cmd_long_response(card, true); // switch to false is done by acos5_get_response
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

///
/// # Panics
///
pub fn encrypt_asym(card: &mut sc_card, crypt_data: &mut CardCtlGenerateAsymCrypt, print: bool) -> i32
{
    /*  don't use print==true: it's a special, tailored case (with some hard-code crypt_data) for testing purposes */
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let mut senv = sc_security_env {
        operation: SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC,
        flags    : SC_SEC_ENV_FILE_REF_PRESENT,
        algorithm: SC_ALGORITHM_RSA,
        file_ref: sc_path { len: 2, ..sc_path::default() }, // file_ref.value[0..2] = fidRSApublic.getub2;
        ..sc_security_env::default()
    };
    if crypt_data.perform_mse {
        senv.file_ref.value[..2].copy_from_slice(&crypt_data.file_id_pub.to_be_bytes());
//        command = [0_u8, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x12, 0x81, 0x02, (crypt_data.file_id_pub >> 8) as u8, (crypt_data.file_id_pub & 0xFF) as u8, 0x95, 0x01, 0x80];
    }
    else if print {
        senv.file_ref.value[0] = 0x41;
        senv.file_ref.value[1] = 0x33;
        let mut path = sc_path::default();
        let mut file = null_mut();
        let guard_file = GuardFile::new(&mut file);
        unsafe { sc_format_path(c"3f0041004133".as_ptr(), &mut path); } // path.type_ = SC_PATH_TYPE_PATH;
        rv = unsafe { sc_select_file(card, &path, *guard_file) };
        assert_eq!(rv, SC_SUCCESS);
//        command = [0_u8, 0x22, 0x01, 0xB8, 0x0A, 0x80, 0x01, 0x12, 0x81, 0x02, 0x41, 0x33, 0x95, 0x01, 0x80];
    }

    if crypt_data.perform_mse || print {
        rv = /*acos5_set_security_env*/ unsafe { sc_set_security_env(card, &senv, 0) };
        if rv < 0 {
            /*
                            mixin (log!(__FUNCTION__,  "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC"));
                            hstat.SetString(IUP_TITLE, "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC");
                            return IUP_DEFAULT;
            */
            return rv;
        }
    }
    let mut rbuf = [0_u8; 512];
 //   assert_eq!(rbuf.len(), siglen);
    // will replace lc, cmd_data, le later; the last 4 bytes are placeholders only for sc_bytes2apdu
    let mut apdu = build_apdu(ctx, &[0_u8, 0x2A, 0x84, 0x80, 0x02, 0xFF, 0xFF, 0xFF], SC_APDU_CASE_4_SHORT, &mut rbuf);
    apdu.data    = crypt_data.data.as_ptr();
    apdu.datalen = crypt_data.data_len;
    apdu.lc      = crypt_data.data_len;
    apdu.le      = std::cmp::min(crypt_data.data_len, SC_READER_SHORT_APDU_MAX_RECV_SIZE);
    if apdu.lc > card.max_send_size {
        apdu.flags |= SC_APDU_FLAGS_CHAINING;
    }

    set_is_running_cmd_long_response(card, true); // switch to false is done by acos5_get_response
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.resplen, crypt_data.data_len);
    let dst = &mut crypt_data.data[.. crypt_data.data_len];
    dst.copy_from_slice(&rbuf[.. crypt_data.data_len]);

    if print {
        println!("signature 'decrypted' with public key:");
        println!("{:X?}", &rbuf[0..32]);
        println!("{:X?}", &rbuf[32..64]);
        println!("{:X?}", &rbuf[64..96]);
        println!("{:X?}", &rbuf[96..128]);
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
    0
} // encrypt_asym

///
/// # Panics
///
#[named]
pub fn generate_asym(card: &mut sc_card, data: &mut CardCtlGenerateAsymCrypt) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    let mut rv;

    if data.perform_mse {
        let mut senv = sc_security_env {
            operation: if data.key_curve_code==0 {SC_SEC_OPERATION_GENERATE_RSAPRIVATE} else {SC_SEC_OPERATION_GENERATE_ECCPRIVATE},
            flags    : SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT,
            algorithm: if data.key_curve_code==0 {SC_ALGORITHM_RSA} else {SC_ALGORITHM_EC},
            file_ref: sc_path { len: 2, ..sc_path::default() }, // file_ref.value[0..2] = fidRSAprivate.getub2;
            ..sc_security_env::default()
        };
        senv.file_ref.value[..2].copy_from_slice(&data.file_id_priv.to_be_bytes());
        rv = /*acos5_set_security_env*/ unsafe { sc_set_security_env(card, &senv, 0) };
        if rv < 0 {
/* mixin (log!(__FUNCTION__,  "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPRIVATE")); */
            return log3ifr_ret!(ctx,f,line!(), rv);
        }

        let mut senv = sc_security_env {
            operation: if data.key_curve_code==0 {SC_SEC_OPERATION_GENERATE_RSAPUBLIC} else {SC_SEC_OPERATION_GENERATE_ECCPUBLIC},
            flags    : SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT,
            algorithm: if data.key_curve_code==0 {SC_ALGORITHM_RSA} else {SC_ALGORITHM_EC},
            file_ref: sc_path { len: 2, ..sc_path::default() }, // file_ref.value[0..2] = fidRSApublic.getub2;
            ..sc_security_env::default()
        };
        senv.file_ref.value[..2].copy_from_slice(&data.file_id_pub.to_be_bytes());
        rv = /*acos5_set_security_env*/ unsafe { sc_set_security_env(card, &senv, 0) };
        if rv < 0 {
/* mixin (log!(__FUNCTION__,  "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC")); */
            return log3ifr_ret!(ctx,f,line!(), rv);
        }
    }

    if data.key_curve_code==0 {
        let mut command = [0_u8, 0x46, 0,0,18, data.key_len_code, data.key_priv_type_code, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        if data.do_generate_with_standard_rsa_pub_exponent { command[4] = 2; }
        else { command[7..23].copy_from_slice(&data.rsa_pub_exponent); }
        let mut apdu = build_apdu(ctx, &command[.. command.len() - if data.do_generate_with_standard_rsa_pub_exponent {16} else {0}], SC_APDU_CASE_3_SHORT, &mut[]);
//log3if!(ctx,f,line!(), c"%s", unsafe {sc_dump_hex(command.as_ptr(), 7)});
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
        rv = unsafe { sc_check_apdu(card, &apdu) };
    }
    else {
        let command = [0_u8, 0x46, 0,0,1, data.key_curve_code];
        let mut apdu = build_apdu(ctx, &command[.. command.len()], SC_APDU_CASE_3_SHORT, &mut[]);
//log3if!(ctx,f,line!(), c"%s", unsafe {sc_dump_hex(command.as_ptr(), 7)});
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
        rv = unsafe { sc_check_apdu(card, &apdu) };
    }
    log3ifr_ret!(ctx,f,line!(), rv)
}


/*
  The EMSA-PKCS1-v1_5 DigestInfo digestAlgorithm (all content excluding the trailing hash) is known, same the length of hash
  guess by length of known length of DigestInfo, whether the input likely is a DigestInfo and NOT some other raw data

  This function refers only to hash algorithms other than sha1 / sha256
*/
#[allow(non_snake_case)]
#[must_use]
pub fn is_any_known_digestAlgorithm(digest_info: &[u8]) -> bool
{
    let known_len = [34_usize, 35, 47, 51, 67, 83];
    if !known_len.contains(&digest_info.len()) {
        return false;
    }
/*
RFC 8017                      PKCS #1 v2.2                 November 2016


               DigestInfo ::= SEQUENCE {
                   digestAlgorithm AlgorithmIdentifier,
                   digest OCTET STRING
               }

   Notes:

   1.  For the nine hash functions mentioned in Appendix B.1, the DER
       encoding T of the DigestInfo value is equal to the following:
   ... MD2 and MD5 will be omitted
    //   sha1     sha256  +sha1  +sha224  +sha256  +sha384  +sha512
    if ![20usize, 32,     35,    47,      51,      67,      83, outlen].contains(&data_len) {
        return SC_ERROR_WRONG_PADDING;
    }

    #[allow(non_snake_case)]
    let digestAlgorithm_sha1   = [0x30_u8, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    #[allow(non_snake_case)]
    let digestAlgorithm_sha256 = [0x30_u8, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
*/
//  let digestAlgorithm_ripemd160_?         = [0x30_u8, 0x22, 0x30, 0x0A, 0x06, 0x06, 0x2B, 0x24, 0x03, 0x03, 0x01, 0x02, 0x05, 0x00, 0x04, 0x14];
    let digest_algorithm_ripemd160  = [0x30_u8, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14];
//                                               30,     21,   30,    9,    6,    5,   2B,   24,    3,    2,    1,    5,    0,    4,   14
    let digest_algorithm_md2        = [0x30_u8, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10];
    let digest_algorithm_md5        = [0x30_u8, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10];

    let digest_algorithm_sha224     = [0x30_u8, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c];
    let digest_algorithm_sha512_224 = [0x30_u8, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c];
    let digest_algorithm_sha512_256 = [0x30_u8, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20];
    let digest_algorithm_sha384     = [0x30_u8, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];
    let digest_algorithm_sha512     = [0x30_u8, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];


    match digest_info.len() {
        35 =>  if digest_info[..15] == digest_algorithm_ripemd160    { return true; },
        34 =>  if digest_info[..18] == digest_algorithm_md2
                || digest_info[..18] == digest_algorithm_md5         { return true; }
        47 =>  if digest_info[..19] == digest_algorithm_sha224
                || digest_info[..19] == digest_algorithm_sha512_224  { return true; },
        51 =>  if digest_info[..19] == digest_algorithm_sha512_256   { return true; },
        67 =>  if digest_info[..19] == digest_algorithm_sha384       { return true; },
        83 =>  if digest_info[..19] == digest_algorithm_sha512       { return true; },
        _  =>  (),
    };
    false
}

///
/// # Panics
///
#[must_use]
fn trailing_blockcipher_padding_calculate(
    block_size   : u8, // 16 or 8
    padding_type : u8, // any of BLOCKCIPHER_PAD_TYPE_*
    rem          : u8  // block_size_overhang   == len (input len to blockcipher encrypt, may be != block_size) % block_size; 0 <= rem < block_size
) -> Vec<u8> // in general: 0 <= result_len <= block_size, but different for some padding_type
{
    assert!(rem < block_size);
    assert!(block_size == 16 || block_size == 8);
    assert!([BLOCKCIPHER_PAD_TYPE_ZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64,
        BLOCKCIPHER_PAD_TYPE_PKCS7, BLOCKCIPHER_PAD_TYPE_ANSIX9_23/*, BLOCKCIPHER_PAD_TYPE_W3C*/].contains(&padding_type));
    let mut vec : Vec<u8> = Vec::with_capacity(usize::from(block_size));
    match padding_type {
        BLOCKCIPHER_PAD_TYPE_ZEROES => {
            for _i in 0..block_size- if rem==0 {block_size} else {rem}
                { vec.push(0x00); }
            },
        BLOCKCIPHER_PAD_TYPE_ONEANDZEROES => {
            vec.push(0x80);
            for _i in 0..block_size-rem-1 { vec.push(0x00); }
        },
        BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64 => {
            if rem != 0 {
                vec.push(0x80);
                for _i in 0..block_size-rem-1 { vec.push(0x00); }
            }
        },
        BLOCKCIPHER_PAD_TYPE_PKCS7 => {
            let pad_byte = block_size-rem;
            vec.resize(vec.len()+usize::from(pad_byte), pad_byte);
        },
        BLOCKCIPHER_PAD_TYPE_ANSIX9_23 => {
            let pad_byte = block_size-rem;
            for _i in 0..pad_byte-1 { vec.push(0x00); }
            vec.push(pad_byte);

        },
/*
        BLOCKCIPHER_PAD_TYPE_W3C => {

        },
*/
        _ => ()
    }
    vec
}

///
/// # Panics
/// # Errors
///
fn trailing_blockcipher_padding_get_length(
    block_size   : u8, // 16 or 8
    padding_type : u8, // any of BLOCKCIPHER_PAD_TYPE_*
    last_block_values: &[u8]
) -> Result<u8,i32> // in general: 0 <= result_len <= block_size, but different for some padding_type
{
    assert_eq!(usize::from(block_size), last_block_values.len());
    match padding_type {
        BLOCKCIPHER_PAD_TYPE_ZEROES => {
            let mut cnt = 0_u8;
            for b in last_block_values.iter().rev() {
                if *b==0 { cnt += 1; }
                else {
                    break;
                }
            }
            if cnt==block_size {return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);}
            Ok(cnt)
        },
        BLOCKCIPHER_PAD_TYPE_ONEANDZEROES => {
            let mut cnt = 0_u8;
            for b in last_block_values.iter().rev() {
                if *b==0 { cnt += 1; }
                else {
                    if *b!=0x80 {return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);}
                    cnt += 1;
                    break;
                }
            }
            if cnt==block_size && last_block_values[0]==0 {return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);}
            Ok(cnt)
        },
        BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64 => {
            /* last byte 0x80 will be interpreted as padding, thus plaintext data can't end with 0x80 ! TODO possibly check while encrypting for trailing byte 0x80 */
            if ![0_u8, 0x80].contains(&last_block_values[usize::from(block_size-1)]) {return Ok(0);}
            let mut cnt = 0_u8;
            for b in last_block_values.iter().rev() {
                if *b==0 { cnt += 1; }
                else {
                    if *b!=0x80 {/*what to do now? assume wrong padding or payload?*/ return Ok(0)/*Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)*/;}
                    cnt += 1;
                    break;
                }
            }
            if cnt==block_size && [0_u8, 0x80].contains(&last_block_values[0]) {return Ok(0)/*Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)*/;}
            Ok(cnt)
        },
        BLOCKCIPHER_PAD_TYPE_PKCS7 => {
            let pad_byte = last_block_values[last_block_values.len()-1];
            let mut cnt = 1_u8;
            for (i, &b) in last_block_values[..usize::from(block_size-1)].iter().rev().enumerate() {
                if b==pad_byte && i+1 < usize::from(pad_byte) { cnt += 1 }
                else {break}
            }
            if cnt != pad_byte {return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)}
            Ok(cnt)
        },
        BLOCKCIPHER_PAD_TYPE_ANSIX9_23 => {
            let pad_byte = last_block_values[last_block_values.len()-1];
            let mut cnt = 1_u8;
            for (i,b) in last_block_values[..usize::from(block_size-1)].iter().rev().enumerate() {
                if *b==0 && i+1<usize::from(pad_byte) { cnt += 1; }
                else {break;}
            }
            if cnt != pad_byte {return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);}
            Ok(cnt)
        },
/*
        BLOCKCIPHER_PAD_TYPE_W3C => {
Ok(0)
        },
*/
        _ => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)
    }
} // trailing_blockcipher_padding_get_length

// omitted signature verification and V2.00/V3.00 RSA signing acc. ISO 9796-2
///
/// # Errors
///
#[allow(clippy::match_bool)]
pub fn algo_ref_mse_sedo(card_type: i32, // one of: SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3, SC_CARD_TYPE_ACOS5_EVO_V4
                         sec_operation: i32, // required only for CRT_TAG_DST: one of: SC_SEC_OPERATION_SIGN, SC_SEC_OPERATION_GENERATE_RSAPRIVATE, SC_SEC_OPERATION_GENERATE_ECCPRIVATE
                         sedo_tag: u8,   // one of: (CRT_TAG_AT, CRT_TAG_KAT,) CRT_TAG_HT, CRT_TAG_CCT, CRT_TAG_DST, CRT_TAG_CT
                         #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                         algorithm: u32, // one of: SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES,
                         #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                         algorithm: c_ulong, // one of: SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES,
                         len_bytes: u8,  // one of: (key_len AES): 16,24,32  hash_len: 20, 28. 32, 48, 64
                         // ecies: u8,
                         op_mode_cbc: bool, //  true  => cbc,  false => ecb
                         cmac: bool,        //  true  => cmac, false => N/A  used in CCT only
) -> Result<u8, i32>  {
//println!("algo_ref_mse_sedo called");
    match sedo_tag {
        CRT_TAG_HT  =>  match len_bytes {
            /*SHA1*/        0x14 => match card_type {
                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x80),
                                        _                         => Ok(0x20),
                                    },
            /*SHA256*/      0x20 => match card_type {
                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x82),
                                        _                         => Ok(0x21),
                                    },
            /*SHA224*/      0x1C => match card_type {
                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x81),
                                        _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                    },
            /*SHA384*/      0x30 => match card_type {
                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x84),
                                        _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                    },
            /*SHA512*/      0x40 => match card_type {
                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x88),
                                        _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                    },
                            _    => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                        },
        CRT_TAG_CCT =>  match algorithm {
                           SC_ALGORITHM_AES  => match card_type {
                                                    SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x15),
                                                    _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                },
                           SC_ALGORITHM_3DES => match cmac {
                                                   true => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x15),
                                                                _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                            },
                                                    _    => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x13),
                                                                _                         => Ok(0x02),
                                                            },
                                                },
                           SC_ALGORITHM_DES  => match card_type {
                                                    SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x11),
                                                    _                         => Ok(0x03),
                                                },
                           _                 => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                        },
        CRT_TAG_DST =>  match algorithm {
                            SC_ALGORITHM_RSA => match sec_operation {
                                                    SC_SEC_OPERATION_SIGN => match card_type {
                                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x20),
                                                        _                         => Ok(0x10),
                                                    },
                                                    SC_SEC_OPERATION_GENERATE_RSAPRIVATE => match card_type {
                                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x22),
                                                        _                         => Ok(0x10),
                                                    },
                                                    _                             => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                },
                            SC_ALGORITHM_EC  => match sec_operation {
                                                    SC_SEC_OPERATION_SIGN => match card_type {
                                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x40),
                                                        _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                    },
                                                    SC_SEC_OPERATION_GENERATE_ECCPRIVATE => match card_type {
                                                        SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x42),
                                                        _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                    },
                                                    _                             => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                },
                            _                => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                        },
        CRT_TAG_CT  =>  match algorithm {
                            SC_ALGORITHM_RSA => match card_type {
                                                    SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x24),
                                                    _                         => Ok(0x12), // 0x13
                                                },
                            SC_ALGORITHM_EC  => match card_type {
                                                    SC_CARD_TYPE_ACOS5_EVO_V4 => match len_bytes {
                                                                                     16 => Ok(0x44),
                                                                                     24 => Ok(0x45),
                                                                                     32 => Ok(0x46),
                                                                                     _  => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                                                 },
                                                    _                         => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                                                },
                            SC_ALGORITHM_AES => match op_mode_cbc {
                                                    true => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x15),
                                                                _                         => Ok(0x06), // 0x07
                                                            },
                                                    _    => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x14),
                                                                _                         => Ok(0x04), // 0x05
                                                            },
                                                },
                            SC_ALGORITHM_3DES => match op_mode_cbc {
                                                    true => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x13),
                                                                _                         => Ok(0x02),
                                                            },
                                                    _    => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x12),
                                                                _                         => Ok(0x00),
                                                            },
                                                },
                            SC_ALGORITHM_DES => match op_mode_cbc {
                                                    true => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x11),
                                                                _                         => Ok(0x03),
                                                            },
                                                    _    => match card_type {
                                                                SC_CARD_TYPE_ACOS5_EVO_V4 => Ok(0x10),
                                                                _                         => Ok(0x01),
                                                            },
                                                },
                            _                => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
                        },
        _           =>  Err(SC_ERROR_KEYPAD_MSG_TOO_LONG),
    }
}

///
/// # Errors
///
pub fn algo_ref_sym_store(card_type: i32,
                          #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                          algorithm: u32,
                          #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                          algorithm: c_ulong,
                          key_len_bytes: u8) -> Result<u8, i32>
{
    match algorithm {
        SC_ALGORITHM_AES => match key_len_bytes {
                16 => Ok(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x22} else {0x02 /*0x03, 0x01, 0x00*/}),
                24 => Ok(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x24} else {0x12 /*0x13*/}),
                32 => Ok(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x28} else {0x22 /*0x23*/}),
                _  => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)
            },
        SC_ALGORITHM_3DES => match key_len_bytes {
                16 => Ok(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x12} else {0x04 /*0x00*/}),
                24 => Ok(0x14),
                _  => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)
            },
        SC_ALGORITHM_DES => match key_len_bytes {
                8  => Ok(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x11} else {0x05 /*0x01*/}),
                _  => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)
            },
        _          => Err(SC_ERROR_KEYPAD_MSG_TOO_LONG)
    }
}


///
/// # Errors
fn vecu8_from_file(path_ptr: *const c_char) -> std::io::Result<Vec<u8>>
{
    if path_ptr.is_null() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
    }
    let path_str = match unsafe { CStr::from_ptr(path_ptr).to_str() } {
        Ok(path) => path,
        Err(_e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "oh no!")),
    };
    fs::read(path_str)
}

/*
7.4.3.6.  Symmetric Key Encrypt does    work with chaining for CryptoMate64;                               CryptoMate Nano say's, it doesn't support chaining
7.4.3.7.  Symmetric Key Decrypt doesn't work with chaining for CryptoMate64, though it should per ref.man; CryptoMate Nano say's, it doesn't support chaining
if inData is not a multiple of blockSize, then addPadding80 will be done and outData must be able to receive that
*/
/* This function cares for padding the input TODO */
/* Acc to ref. manual, V2.00 uses chaining, while V3.00 does not !
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)

*/
/*
TODO as of 2020-12-19: The input method `inbuf` (for OpenSC) got tested to be working correctly, for both CryptoMate64 and CryptoMate Nano
including for messages > max_send_size
but the other input methods `infile` and `indata` (for acos5_gui) still need to be checked !
*/
///
/// # Panics
///
#[allow(non_snake_case)]
#[named]
pub fn sym_en_decrypt(card: &mut sc_card, crypt_sym: &mut CardCtlSymCrypt) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), if crypt_sym.encrypt {c"called for encryption"}
                           else {c"called for decryption"});

    let block_size = usize::from(crypt_sym.block_size);
    let indata_len;
    let indata_ptr : *const u8;
    let mut vec_in = Vec::new();
    let Len1: usize;
    if crypt_sym.infile.is_null() && crypt_sym.inbuf.is_null() {
        indata_len = std::cmp::min(crypt_sym.indata_len, crypt_sym.indata.len());
        Len1 = indata_len;
        indata_ptr = crypt_sym.indata.as_ptr();
    }
    else if !crypt_sym.inbuf.is_null() {
        vec_in.extend_from_slice(unsafe { from_raw_parts(crypt_sym.inbuf, crypt_sym.indata_len) });
        let len = vec_in.len();
        assert!(len >= crypt_sym.block_size.into());
        debug_assert_eq!(crypt_sym.indata_len, len);
        if !crypt_sym.encrypt || ((crypt_sym.algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) > 0) {
            Len1 = crypt_sym.indata_len; // for ECB and CBC this is Len2 ! Len1 is not known
        }
        else {
            Len1 = crypt_sym.indata_len.saturating_sub(
            usize:: from(trailing_blockcipher_padding_get_length(
                crypt_sym.block_size,
                crypt_sym.pad_type,
                &vec_in[len.saturating_sub(crypt_sym.block_size.into()) .. len]
            ).unwrap() ) );// -> Result<u8,i32>
        }
        if crypt_sym.encrypt && (crypt_sym.algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) > 0 {
            debug_assert_eq!(BLOCKCIPHER_PAD_TYPE_PKCS7, crypt_sym.pad_type);
            vec_in.extend_from_slice(&trailing_blockcipher_padding_calculate(crypt_sym.block_size, crypt_sym.pad_type,
                u8::try_from(len- num_integer::Integer::prev_multiple_of(&len, &block_size)).unwrap()) );
//println!("acos5_encrypt_sym {:02X?}", vec_in.as_slice());
        }
        indata_len = vec_in.len();
        indata_ptr = vec_in.as_ptr();
        debug_assert!(num_integer::Integer::is_multiple_of(&indata_len, &block_size));
    }
    else {
        vec_in.extend_from_slice(match vecu8_from_file(crypt_sym.infile) {
            Ok(vec) => vec,
            Err(e) => return e.raw_os_error().unwrap(),
        }.as_ref());
        indata_len = vec_in.len();
        Len1 = indata_len;
        indata_ptr = vec_in.as_ptr();
    }

    let mut rv;
    // let Len1 = indata_len;
    let Len0 =  num_integer::Integer::prev_multiple_of(&Len1, &block_size); // (Len1/block_size) * block_size;
    let Len2 = (Len1+ usize::from(crypt_sym.encrypt && [BLOCKCIPHER_PAD_TYPE_PKCS7].contains(&crypt_sym.pad_type))).
        next_multiple_of(block_size); // i.e. 1,,block_size bytes get added for encryption if acc. padding was selected
    if !crypt_sym.encrypt {
        assert_eq!(Len1, Len0);
        assert_eq!(Len1, Len2);
    }

    let outdata_len;
    let outdata_ptr;
    let mut vec_out = Vec::new();

    if crypt_sym.outfile.is_null() && crypt_sym.outbuf.is_null() {
        outdata_len = crypt_sym.outdata.len();
        outdata_ptr = crypt_sym.outdata.as_mut_ptr();
    }
    else if !crypt_sym.outbuf.is_null() {
        outdata_len = crypt_sym.outdata_len;
        outdata_ptr = crypt_sym.outbuf;
    }
    else {
        vec_out.resize(Len2, 0_u8);
        outdata_len = Len2;
        outdata_ptr = vec_out.as_mut_ptr();
    }
    assert!(Len2<=outdata_len);

//assert!(indata_len >= 32);
//let mut fmt  = c"called with indata_len: %zu, first 32 bytes: %s";
//log3if!(ctx,f,line!(), fmt, indata_len, unsafe {sc_dump_hex(indata_ptr, 32)});
//fmt = c"called with infile_name: %s, outfile_name: %s";
//log3ift!(ctx,f,line!(), fmt, crypt_sym.infile, crypt_sym.outfile);

    if !crypt_sym.infile.is_null() && !crypt_sym.outfile.is_null()
    { assert_ne!(crypt_sym.infile, crypt_sym.outfile); } // FIXME doesn't work for symbolic links: the check is meant for using copy_nonoverlapping
/*
    let mut inDataRem = Vec::with_capacity(block_size);
    if crypt_sym.encrypt && Len1 != Len2 {
        inDataRem.extend_from_slice(unsafe { from_raw_parts(indata_ptr.add(Len0), Len1-Len0) });
        inDataRem.extend_from_slice(&trailing_blockcipher_padding_calculate(crypt_sym.block_size, crypt_sym.pad_type, u8::try_from(Len1-Len0).unwrap()) );
        assert_eq!(inDataRem.len(), block_size);
    }
*/

    let condition_weak = crypt_sym.cbc && !crypt_sym.encrypt;
    // let condition      = condition_weak && crypt_sym.perform_mse;

    let mut senv = sc_security_env::default();
    if crypt_sym.perform_mse || condition_weak {
        /* Security Environment */
        senv = sc_security_env {
            operation: 7,// TODO if crypt_sym.encrypt {SC_SEC_OPERATION_ENCRYPT_SYM} else {SC_SEC_OPERATION_DECRYPT_SYM},
            flags    : SC_SEC_ENV_KEY_REF_PRESENT | SC_SEC_ENV_ALG_REF_PRESENT | SC_SEC_ENV_ALG_PRESENT,
            algorithm: if crypt_sym.block_size==16 {SC_ALGORITHM_AES} else if crypt_sym.key_len==8 {SC_ALGORITHM_DES} else {SC_ALGORITHM_3DES},
            key_ref: [crypt_sym.key_ref, 0,0,0,0,0,0,0],
            key_ref_len: 1,
            algorithm_ref: algo_ref_mse_sedo(card.type_, 0, CRT_TAG_CT,
                if crypt_sym.block_size==16 {SC_ALGORITHM_AES} else if crypt_sym.key_len==8 {SC_ALGORITHM_DES} else {SC_ALGORITHM_3DES},
                         0, crypt_sym.cbc, false).unwrap().into(),
            ..sc_security_env::default()
        };
        // { senv.flags |= SC_SEC_ENV_KEY_REF_SYMMETRIC; }
               if (senv.algorithm & SC_ALGORITHM_AES) > 0 {
                if !crypt_sym.cbc {
                    senv.algorithm_flags |= SC_ALGORITHM_AES_ECB;
                }
                else if crypt_sym.pad_type == BLOCKCIPHER_PAD_TYPE_PKCS7 {
                    senv.algorithm_flags |= SC_ALGORITHM_AES_CBC_PAD;
                }
                else {
                    senv.algorithm_flags |= SC_ALGORITHM_AES_CBC;
                }
            }

            if crypt_sym.iv_len > 0 {
                assert_eq!(crypt_sym.iv_len, block_size);
                let sec_env_param = sc_sec_env_param {
                    param_type: SC_SEC_ENV_PARAM_IV,
                    value: crypt_sym.iv.as_mut_ptr().cast::<c_void>(),
                    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                    value_len: u32::try_from(crypt_sym.iv_len).unwrap(),
                    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                    value_len: crypt_sym.iv_len,
                };
                senv.params[0] = sec_env_param;
            }

            if crypt_sym.perform_mse {
                rv = /*acos5_set_security_env*/ unsafe { sc_set_security_env(card, &senv, 0) };
                if rv < 0 {
                    /*
                      mixin (log!(__FUNCTION__,  "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC"));
                      hstat.SetString(IUP_TITLE, "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC");
                      return IUP_DEFAULT;
                    */
                    return log3ifr_ret!(ctx,f,line!(), rv);
                }
            }
    }

    /* encrypt / decrypt */
    let mut first = true;
    let max_send = 256_usize - block_size;
    let command : [u8; 7] = [if !crypt_sym.cbc || Len2<=max_send {0_u8} else {0x10_u8}, 0x2A,
        if crypt_sym.encrypt {0x84_u8} else {0x80_u8},
        if crypt_sym.encrypt {0x80_u8} else {0x84_u8}, 0x01, 0xFF, 0xFF]; // needs some correction
    let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_4_SHORT, &mut[]);
    let mut cnt = 0_usize; // counting apdu.resplen bytes received;
    let mut path = sc_path::default();
    /* select currently selected DF (clear accumulated CRT) */
    unsafe { sc_format_path(c"3FFF".as_ptr(), &mut path); }


    while cnt < Len2 /*cnt < Len0 || (cnt == Len0 && Len1 != Len2) */{
        if first { first = false; }
        else if condition_weak {
            rv = unsafe { sc_select_file(card, &path, null_mut()) }; // clear accumulated CRT
            assert_eq!(rv, SC_SUCCESS);
            rv = /*acos5_set_security_env*/ unsafe { sc_set_security_env(card, &senv, 0) };
            if rv < 0 {
                    /*
                    tlv_new[posIV..posIV+blockSize] = inData[cnt-blockSize..cnt];
                      mixin (log!(__FUNCTION__,  "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC"));
                      hstat.SetString(IUP_TITLE, "acos5_set_security_env failed for SC_SEC_OPERATION_GENERATE_RSAPUBLIC");
                      return IUP_DEFAULT;
                    */
                return log3ifr_ret!(ctx,f,line!(), rv);
            }
        }

        if !crypt_sym.cbc || Len2-cnt <= max_send || condition_weak { apdu.cla = 0 }
        // if cnt < Len0 {
        apdu.data = unsafe { indata_ptr.add(cnt) };
        apdu.datalen = std::cmp::min(max_send, Len2-cnt);
        /* correct IV for next loop cycle */
        if condition_weak {
            crypt_sym.iv.copy_from_slice(unsafe { from_raw_parts(indata_ptr.add(cnt + apdu.datalen - block_size), block_size) });
            senv.params[0].value = unsafe { indata_ptr.add(cnt + apdu.datalen - block_size).cast_mut() }.cast::<c_void>();
        }
/*
        else {
            apdu.cla  = 0;
            apdu.data    = inDataRem.as_ptr();
            apdu.datalen = inDataRem.len();
        }
*/
        apdu.lc = apdu.datalen;
        apdu.le = apdu.datalen;
        apdu.resp = unsafe { outdata_ptr.add(cnt) };
        apdu.resplen = outdata_len-cnt;
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS  {
            return log3ifr_ret!(ctx,f,line!(), rv);
        }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if rv != SC_SUCCESS  {
            return log3ifr_ret!(ctx,f,line!(), rv);
        }
        if apdu.resplen == 0 {
            return log3ifr_ret!(ctx,f,line!(), SC_ERROR_KEYPAD_MSG_TOO_LONG);
        }
        assert_eq!(apdu.datalen, apdu.resplen);
        cnt += apdu.datalen;
    }
    assert_eq!(Len2, cnt);



    if crypt_sym.encrypt  || (crypt_sym.algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) == 0 {
        crypt_sym.outdata_len = cnt;
    }
    if !crypt_sym.encrypt && (crypt_sym.algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) != 0 {
        let mut last_block_values = [0_u8; 16];
        last_block_values.copy_from_slice(unsafe {from_raw_parts(outdata_ptr.add(cnt-block_size), block_size)});
        let len_padding = trailing_blockcipher_padding_get_length(crypt_sym.block_size, crypt_sym.pad_type,
                                                            &last_block_values[..block_size]);
        if len_padding.is_err() { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_KEYPAD_TIMEOUT); }
        crypt_sym.outdata_len = cnt - usize::from(len_padding.unwrap());
    }

    if !crypt_sym.encrypt {
/*
        let mut last_block_values = [0_u8; 16];
        last_block_values[..block_size].copy_from_slice(unsafe {from_raw_parts(outdata_ptr.add(cnt-block_size), block_size)});
        crypt_sym.outdata_len = cnt - usize::from(trailing_blockcipher_padding_get_length(crypt_sym.block_size, crypt_sym.pad_type,
            &last_block_values[..block_size]).unwrap());
*/
        if !crypt_sym.outfile.is_null() {
            vec_out.truncate(crypt_sym.outdata_len);
        }
    }

    if !crypt_sym.outfile.is_null() {
        let path = unsafe { CStr::from_ptr(crypt_sym.outfile) };
        let path_str = match path.to_str() {
            Ok(path_str) => path_str,
            Err(e) =>
                return log3ifr_ret!(ctx,f,line!(), i32::try_from(e.valid_up_to()).unwrap()),
        };
        match fs::write(path_str, vec_out) {
            Ok(()) => (),
            Err(e) =>
                return log3ifr_ret!(ctx,f,line!(), e.raw_os_error().unwrap()),
        }
    }

    rv = i32::try_from(crypt_sym.outdata_len).unwrap();
    log3if!(ctx,f,line!(), if crypt_sym.encrypt {c"encryption: returning with %d"}
                           else {c"decryption: returning with %d"}, rv);
    rv
} // sym_en_decrypt


///
/// # Panics
/// # Errors
///
#[named]
pub fn files_hashmap_info(card: &mut sc_card, key: u16) -> Result<[u8; 32], i32>
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    let mut rbuf = [0_u8; 32];
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
/*
A0 2F 30 0E 0C 05 45 43 6B 65 79 03 02 06 C0 04 01 01 30 0F 04 01 09 03 03 06 20 40 03 02 03 B8 02 01 09 A1 0C 30 0A 30 08 04 06 3F 00 41 00 41 F9
A0 2C 30 0B 0C 05 45 43 6B 65 79 03 02 06 40 30 0F 04 01 09 03 03 06 02 00 03 02 03 09 02 01 09 A1 0C 30 0A 30 08 04 06 3F 00 41 00 41 39

temporary only: acos5_gui expects the 32 bytes in another order, which is done here, i.e. provide in rbuf what acos5_gui expects

alias  TreeTypeFS = tree_k_ary.Tree!ub32; // 8 bytes + length of pathlen_max considered (, here SC_MAX_PATH_SIZE = 16) + 8 bytes SAC (file access conditions)
                            path                    File Info       scb8
pub type ValueTypeFiles = ([u8; SC_MAX_PATH_SIZE], [u8; 8], Option<[u8; 8]>, ...
File Info originally:  {FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI}
File Info actually:    {FDB, *,   FILE ID, FILE ID, *,           *,           *,   LCSI}
*/
    if dp.files.contains_key(&key) {
        let dp_files_value_ref = &dp.files[&key];
            rbuf[ 0.. 8].copy_from_slice(&dp_files_value_ref.1);
            rbuf[ 8..24].copy_from_slice(&dp_files_value_ref.0);
        if let Some(scb8) = &dp_files_value_ref.2 {
            rbuf[24..32].copy_from_slice(scb8);
        }
        else {
            log3if!(ctx,f,line!(), c"### forgot to call update_hashmap first ###");
        }
    }
    else {
        let _unused = Box::leak(dp);
        return Err(log3ifr_ret!(ctx,f,line!(), SC_ERROR_FILE_NOT_FOUND));
    }

    let _unused = Box::leak(dp);
    log3ifr!(ctx,f,line!(), SC_SUCCESS);
    Ok(rbuf)
}


// when update_hashmap returns all entries have: 1. path, 2. File Info: [u8; 8], 3. scb8: Option<[u8; 8]>.is_some, 4. for DF s, SACinfo: Option<Vec<SACinfo>>.is_some
/// The function ensures, that
///   all dp.files[?].2 are Some, and
///   all dp.files[?].1[6] are set for internal EF +? (this currently doesn't include detecting file content matches the OpenSC-implemented PKCS#15
///   conformance; `OpenSC` is not 2016:ISO/IEC 7816-15 compliant)
///
/// Possibly this function will be followed by another one that does the PKCS#15 introspection into files to detect the type, thus moving the
/// over-complicated code from `acos5_gui` to the driver and overhaul that
/// @apiNote  Called from `acos5_gui` and ? (`pccs15_init` `sanity_check` ?)
/// @param    card
///
/// # Panics
///
#[named]
pub fn update_hashmap(card: &mut sc_card) {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    // let mut path = sc_path::default();
    // unsafe { sc_format_path(c"3F00".as_ptr(), &mut path); } // type = SC_PATH_TYPE_PATH;
    let rv = enum_dir_gui(card, unsafe { &*sc_get_mf_path() });
    assert_eq!(rv, SC_SUCCESS);

    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let fmt1  = c"key: %04X, val.1: %s";
    let fmt2  = c"key: %04X, val.2: %s";
    for (key, val) in &dp.files {
        if let Some(scb8) = val.2 {
            log3if!(ctx,f,line!(), fmt1, *key, unsafe { sc_dump_hex(val.1.as_ptr(), 8) });
            log3if!(ctx,f,line!(), fmt2, *key, unsafe { sc_dump_hex(scb8.as_ptr(), 8) });
        }
    }
    for (key, val) in &dp.files {
        if val.2.is_none() {
            log3if!(ctx,f,line!(), fmt1, *key, unsafe { sc_dump_hex(val.1.as_ptr(), 8) });
        }
    }
    let _unused = Box::leak(dp);
    log3ifr!(ctx,f,line!(), SC_SUCCESS);
}

/*
TODO: Optimization possible for EVO: Able to read 256-4096 bytes in 1 go, no need for repeated calls
of cos 8.1.3.  Read Binary, see especially the coding for 256 bytes ! */
///
/// # Panics
///
pub fn common_read(card: &mut sc_card,
                   idx: u16,
                   buf: &mut [u8],
                   flags: c_ulong,
                   bin: bool) -> i32
{
    if card.ctx.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f = if bin {c"common_read for acos5_read_binary"} else {c"common_read for acos5_read_record"};
    log3ifc!(ctx,f,line!());

    let file_id = file_id_from_cache_current_path(card);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let x = &dp.files[&file_id];
    let fdb      = x.1[0];
    assert!(x.2.is_some());
    let scb_read = x.2.unwrap()[0];
    let _unused = Box::leak(dp);
    // let _anon = APDUShortExtendedSwitcher::new(card);

    if scb_read == 0xFF {
        log3ifr_ret!(ctx,f,line!(),
            if bin {c"No read_binary will be done: The file has acl NEVER READ"}
            else   {c"No read_record will be done: The file has acl NEVER READ"},
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
    }
    else if (scb_read & 0x40) == 0x40 {
        let res_se_sm = if (scb_read & 0x40) == 0x40 { se_get_is_scb_suitable_for_sm_has_ct
            (card, file_id, scb_read & 0x0F) } else { (false, false) };
        if res_se_sm.0 {
            card.sm_ctx.info.cmd = SM_CMD_FILE_READ;
            log3ifr_ret!(ctx,f,line!(), sm_common_read(card, idx, buf, flags, bin, res_se_sm.1, fdb))
        }
        else {
            log3ifr_ret!(ctx,f,line!(),
                if bin {c"No read_binary will be done: The file has acl SM-protected READ"}
                else   {c"No read_record will be done: The file has acl SM-protected READ"},
                    SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
        }
    }
    else if bin && [FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&fdb) {
        card.cla = 0x80;
        let rv = unsafe { (*(*sc_get_iso7816_driver()).ops).get_data.unwrap()
            (card, u32::from(idx), buf.as_mut_ptr(), buf.len()) };
        card.cla = 0;
        log3ifr_ret!(ctx,f,line!(), rv)
    }
    else { unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            if bin {
                (*(*sc_get_iso7816_driver()).ops).read_binary.unwrap()
                (card, u32::from(idx), buf.as_mut_ptr(), buf.len(), flags)
            }
            else {
                (*(*sc_get_iso7816_driver()).ops).read_record.unwrap()
                (card, u32::from(idx), buf.as_mut_ptr(), buf.len(), flags)
            }
        }
        else {
            if bin {
                let mut myflags: c_ulong = flags;
                log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).read_binary.unwrap()
                    (card, u32::from(idx), buf.as_mut_ptr(), buf.len(), &mut myflags))
            }
            else {
                log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).read_record.unwrap()
                    (card, u32::from(idx), 0, buf.as_mut_ptr(), buf.len(), flags))
            }
        }
    } } }
} // common_read


///
/// # Panics
///
pub fn common_update(card: &mut sc_card,
                     idx: u16,
                     buf: &[u8],
                     flags: c_ulong,
                     bin: bool) -> i32
{
    if card.ctx.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f = if bin {c"acos5_update_binary"}
                   else if idx>0 {c"acos5_update_record"} else {c"acos5_append_record"};
    log3ifc!(ctx,f,line!());

    let file_id = file_id_from_cache_current_path(card);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let x = &dp.files[&file_id];
    let fdb      = x.1[0];
    assert!(x.2.is_some());
    let scb_update = x.2.unwrap()[1];
    let _unused = Box::leak(dp);
    // idx==0 means 'append_record' is requested
    if !bin && idx==0 && ![FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_SYMMETRIC_KEY_EF, FDB_SE_FILE].contains(&fdb) {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_ALLOWED);
    }

    if scb_update == 0xFF {
        log3ifr_ret!(ctx,f,line!(),
            if bin {c"No update_binary will be done: The file has acl NEVER UPDATE"}
            else   {c"No update_record will be done: The file has acl NEVER UPDATE"},
            SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
    }
    else if (scb_update & 0x40) == 0x40 {
        let res_se_sm = if (scb_update & 0x40) == 0x40 { se_get_is_scb_suitable_for_sm_has_ct
            (card, file_id, scb_update & 0x0F) } else { (false, false) };
        if res_se_sm.0 {
            card.sm_ctx.info.cmd = SM_CMD_FILE_UPDATE;
            sm_common_update(card, idx, buf, flags, bin, res_se_sm.1, fdb)
        }
        else {
            log3ifr_ret!(ctx,f,line!(),
                if bin {c"No update_binary will be done: The file has acl SM-protected UPDATE"}
                else   {c"No update_record will be done: The file has acl SM-protected UPDATE"},
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
        }
    }
    else if bin && fdb == FDB_RSA_KEY_EF { // no put_key support currently
        log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT)
    }
    else {
        unsafe {
            #[allow(clippy::collapsible_else_if)]
            if !bin && idx==0 && flags==0 {
                log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).append_record.unwrap()(card, buf.as_ptr(), buf.len(), flags))
            }
            else { cfg_if::cfg_if! {
                if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
                    if bin { log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).update_binary.unwrap()
                        (card, u32::from(idx), buf.as_ptr(), buf.len(), flags)) }
                    else   { log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).update_record.unwrap()
                        (card, u32::from(idx), buf.as_ptr(), buf.len(), flags)) }
                }
                else {
                    if bin { log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).update_binary.unwrap()
                        (card, u32::from(idx),    buf.as_ptr(), buf.len(), flags)) }
                    else   { log3ifr_ret!(ctx,f,line!(), (*(*sc_get_iso7816_driver()).ops).update_record.unwrap()
                        (card, u32::from(idx), 0, buf.as_ptr(), buf.len(), flags)) }
                }
            }
        }}
    }
}


#[cfg(test)]
mod tests {
    use super::{convert_amdo_to_cla_ins_p1_p2_array, algo_ref_mse_sedo, SC_SEC_OPERATION_SIGN,
                trailing_blockcipher_padding_calculate, trailing_blockcipher_padding_get_length,
                SC_ALGORITHM_RSA};
    use crate::constants_types::*;

    #[cfg(dont_test__this_signature_changed)]
    #[test]
    fn test_fci() {
        let mut fci = FCI::new_parsed(&[
            /*0x6F, 0x30,*/ 0x83, 0x02, 0x41, 0x00, 0x88, 0x01, 0x00, 0x8A, 0x01, 0x05, 0x82, 0x02, 0x38, 0x00,
            0x8D, 0x02, 0x41, 0x03, 0x84, 0x10, 0x41, 0x43, 0x4F, 0x53, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31,
            0x35, 0x76, 0x31, 0x2E, 0x30, 0x30, 0x8C, 0x08, 0x7F, 0x03, 0xFF, 0x00, 0x01, 0x01, 0x01, 0x01,
            0xAB, 0x00]);
        assert_eq!(fci, FCI { fdb: 0x38, fid: 0x4100, size: 0, lcsi: 5, df_name: b"ACOSPKCS-15v1.00".to_vec(),
            scb8: [1_u8,1,1,1,0,255,3,255], sae: vec![], seid: 0x4103, mrl: 0, nor: 0 });

        fci = FCI::new_parsed(&[
            /*0x6F, 0x1E,*/ 0x83, 0x02, 0x41, 0x10, 0x88, 0x01, 0x10, 0x8A, 0x01, 0x05, 0x82, 0x02, 0x01, 0x00,
           0x80, 0x02, 0x03, 0x00, 0x8C, 0x08, 0x7F,   0x00, 0xFF, 0x00, 0x03, 0xFF, 0x00, 0x00,   0xAB, 0x00
        ]);
        assert_eq!(fci, FCI { fdb: 0x01, fid: 0x4110, size: 0x0300, lcsi: 5, df_name: vec![],
            scb8: [0_u8,0,255,3,0,255,0,255], sae: vec![], seid: 0, mrl: 0, nor: 0 });
    }

    #[test]
    fn test_convert_bytes_tag_fcp_sac_to_scb_array() -> Result<(), i32> {
        // the complete TLV : [0x8C, 0x07,  0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02]
        let bytes_tag_fcp_sac = [0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02];
        let mut scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x02, 0x00, 0xFF, 0xFF, 0x04, 0x03, 0x02, 0xFF]);

        let bytes_tag_fcp_sac : [u8; 0] = [];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        let bytes_tag_fcp_sac = [0x00];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]);

        let bytes_tag_fcp_sac = [0x7F, 0xFF, 0xFF, 0x03, 0x03, 0x01, 0x03, 0x01];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x01, 0x03, 0x01, 0x03, 0x03, 0xFF, 0xFF, 0xFF]);

        let bytes_tag_fcp_sac = [0x62, 0x06, 0x05, 0x01];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x06, 0xFF]);

        let bytes_tag_fcp_sac = [0x2B, 0x05, 0x03, 0x01, 0x45];
        scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac)?;
        assert_eq!(scb8, [0x45, 0x01, 0x00, 0x03, 0x00, 0x05, 0x00, 0xFF]);
        Ok(())
    }

    #[test]
    #[should_panic(expected = "bytes_tag_fcp_sac.len() > 8")]
    fn test_convert_bytes_tag_fcp_sac_to_scb_array_panic() {
        // the complete TLV : [0x8C, 0x07,  0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02]
        let bytes_tag_fcp_sac = [0x8C, 0x07,  0x7D, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0x02];
        let scb8 = convert_bytes_tag_fcp_sac_to_scb_array(&bytes_tag_fcp_sac).unwrap();
        assert_eq!(scb8, [0x02, 0x00, 0xFF, 0xFF, 0x04, 0x03, 0x02, 0xFF]);
    }

    #[test]
    fn test_convert_amdo_to_cla_ins_p1_p2_array() -> Result<(), i32> {
        let amdo_bytes = [0xAA_u8];
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 8, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0,0,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 4, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0, 0xAA, 0,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 2, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0,0, 0xAA, 0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 1, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0,0,0,  0xAA]);

        let amdo_bytes = [0xAA_u8, 0xBB];
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 9, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0,0,0xBB]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array(10, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0,0xBB,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array(12, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0xBB,0,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array(5, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0, 0xAA, 0,0xBB]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array(6, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0, 0xAA, 0xBB,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array(3, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0,0, 0xAA, 0xBB]);

        let amdo_bytes = [0xAA_u8, 0xBB, 0xCC];
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 11, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0,0xBB, 0xCC]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 13, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0xBB, 0,0xCC]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 14, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0xBB, 0xCC,0]);
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 7, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0, 0xAA, 0xBB, 0xCC]);

        let amdo_bytes = [0xAA_u8, 0xBB, 0xCC, 0xDD];
        let cla_ins_p1_p2 = convert_amdo_to_cla_ins_p1_p2_array( 15, &amdo_bytes[..])?;
        assert_eq!(cla_ins_p1_p2, [0xAA,  0xBB, 0xCC, 0xDD]);
        Ok(())
    }

    #[test]
    fn test_trailing_blockcipher_padding_calculate() {
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ZEROES, 3).as_slice(), &[0_u8,0,0,0,0]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ZEROES, 7).as_slice(), &[0_u8]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ZEROES, 0).as_slice(), &[0_u8; 0]);

        // this is implemented in libopensc as well: sodium_pad
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, 3).as_slice(), &[0x80_u8,0,0,0,0]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, 7).as_slice(), &[0x80_u8]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, 0).as_slice(), &[0x80_u8, 0,0,0,0,0,0,0]);

        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, 3).as_slice(), &[0x80_u8,0,0,0,0]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, 7).as_slice(), &[0x80_u8]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, 0).as_slice(), &[0_u8; 0]);

        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_PKCS7, 3).as_slice(), &[0x05_u8; 5]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_PKCS7, 7).as_slice(), &[0x01_u8; 1]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_PKCS7, 0).as_slice(), &[0x08_u8; 8]);

        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, 3).as_slice(), &[0_u8,0,0,0,5]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, 7).as_slice(), &[1_u8]);
        assert_eq!(trailing_blockcipher_padding_calculate(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, 0).as_slice(), &[0_u8,0,0,0,0,0,0,8]);
    }

    #[test]
    fn test_trailing_blockcipher_padding_get_length() -> Result<(), i32> {
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ZEROES, &[0_u8,2,1,0,0,0,0,0])?, 5);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ZEROES, &[0_u8,6,5,4,3,2,1,0])?, 1);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ZEROES, &[0_u8,7,6,5,4,3,2,1])?, 0);

        // something similar is implemented in libopensc as well: sodium_unpad
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, &[0_u8,0,0,0x80,0,0,0,0])?, 5);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, &[0_u8,0,0,0,0,0,0,0x80])?, 1);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, &[0x80_u8,0,0,0,0,0,0,0])?, 8);

        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, &[0_u8,0,0,0x80,0,0,0,0])?, 5);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, &[0_u8,0,0,0,0,0,0,0x80])?, 1);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, &[0x80_u8,0,0,0,0,0,0,0])?, 0);

        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_PKCS7, &[0_u8,5,5,5,5,5,5,5])?, 5);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_PKCS7, &[0_u8,1,1,1,1,1,1,1])?, 1);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_PKCS7, &[8_u8,8,8,8,8,8,8,8])?, 8);

        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, &[0_u8,0,0,0,0,0,0,5])?, 5);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, &[0_u8,0,0,0,0,0,0,1])?, 1);
        assert_eq!(trailing_blockcipher_padding_get_length(8,BLOCKCIPHER_PAD_TYPE_ANSIX9_23, &[0_u8,0,0,0,0,0,0,8])?, 8);
        Ok(())
    }
    //TODO extend to check for AES block_size=16 bytes

    #[test]
    fn test_algo_ref_mse_sedo() -> Result<(), i32> {
        let mut rsa_key_gen = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_64_V2, SC_SEC_OPERATION_GENERATE_RSAPRIVATE, CRT_TAG_DST,
                                                SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_key_gen, Ok(0x10));
        rsa_key_gen = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_EVO_V4, SC_SEC_OPERATION_GENERATE_RSAPRIVATE, CRT_TAG_DST,
                                        SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_key_gen, Ok(0x22));

        let mut rsa_sign = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_64_V2, SC_SEC_OPERATION_SIGN, CRT_TAG_DST,
                                                SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_sign, Ok(0x10));
        rsa_sign = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_EVO_V4, SC_SEC_OPERATION_SIGN, CRT_TAG_DST,
                                             SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_sign, Ok(0x20));

        let mut rsa_decipher = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_64_V2, 0, CRT_TAG_CT,
                                                SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_decipher, Ok(0x12));//0x13;
        rsa_decipher = algo_ref_mse_sedo(SC_CARD_TYPE_ACOS5_EVO_V4, 0, CRT_TAG_CT,
                                        SC_ALGORITHM_RSA, 0, false, false);
        assert_eq!(rsa_decipher, Ok(0x24));

        Ok(())
    }

}
/*
Beginning script execution...

Sending: 00 A4 00 00 02 41 00
Received: 61 32
0x32 bytes of response still available.

Sending: 00 C0 00 00 32
Received: 6F 30 83 02 41 00 88 01 00 8A 01 05 82 02 38 00
8D 02 41 03 84 10 41 43 4F 53 50 4B 43 53 2D 31
35 76 31 2E 30 30 8C 08 7F 03 FF 03 03 01 01 01
AB 00 90 00
Normal processing.

Sending: 00 A4 00 00 02 41 10
Received: 61 20
0x20 bytes of response still available.

Sending: 00 C0 00 00 20
Received: 6F 1E 83 02 41 10 88 01 10 8A 01 05 82 02 01 00
80 02 03 00 8C 08 7F 00 FF 00 03 FF 00 00 AB 00
90 00
Normal processing.

Sending: 00 B0 00 00 FF
Received: A0 2B 30 0F 0C 06 43 41 72 6F 6F 74 03 02 06 C0
04 01 01 30 0A 04 01 01 03 01 00 03 02 03 B8 A1
0C 30 0A 30 08 04 06 3F 00 41 00 12 01 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90
00
Normal processing.

Sending: 00 A4 00 00 02 41 11
Received: 61 20
0x20 bytes of response still available.

Sending: 00 C0 00 00 20
Received: 6F 1E 83 02 41 11 88 01 11 8A 01 05 82 02 01 00
80 02 03 00 8C 08 7F 00 FF 00 03 FF 00 00 AB 00
90 00
Normal processing.

Sending: 00 B0 00 00 FF
Received: A0 28 30 0C 0C 06 43 41 72 6F 6F 74 03 02 06 40
30 0A 04 01 01 03 01 00 03 02 03 48 A1 0C 30 0A
30 08 04 06 3F 00 41 00 11 01 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 90
00
Normal processing.

Script was executed without error...

 */
