/*
 * sm.h: Support of Secure Messaging
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@opentrust.com>
 *                      OpenTrust <www.opentrust.com>
 * Copyright (C) 2019-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
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


use std::os::raw::{c_int, c_uchar, c_char, c_uint, c_ulong, c_void};

use crate::types::{sc_apdu, sc_remote_data, sc_path, sc_aid, sc_serial_number, SC_MAX_APDU_BUFFER_SIZE,
    sc_tlv_data, sc_crt, sc_cplc};
use crate::opensc::{sc_card, sc_context};


#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
pub const SHA_DIGEST_LENGTH : u32 = 20;
#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
pub const SHA1_DIGEST_LENGTH : u32 = 20;
#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
pub const SHA256_DIGEST_LENGTH : u32 = 32;

pub const SM_TYPE_GP_SCP01 : u32 = 0x100;
pub const SM_TYPE_CWA14890 : u32 = 0x400;
pub const SM_TYPE_DH_RSA   : u32 = 0x500;


/** don't use SM */
pub const SM_MODE_NONE     : u32 = 0x0;
/** let the card driver decide when to use SM, possibly based on the card's ACLs */
pub const SM_MODE_ACL      : u32 = 0x100;
/** use SM for all commands */
pub const SM_MODE_TRANSMIT : u32 = 0x200;

pub const SM_CMD_INITIALIZE  : u32 = 0x10;
pub const SM_CMD_MUTUAL_AUTHENTICATION : u32 = 0x20;
pub const SM_CMD_RSA   : u32 = 0x100;
pub const SM_CMD_RSA_GENERATE  : u32 = 0x101;
pub const SM_CMD_RSA_UPDATE  : u32 = 0x102;
pub const SM_CMD_RSA_READ_PUBLIC  : u32 = 0x103;
pub const SM_CMD_FILE   : u32 = 0x200;
pub const SM_CMD_FILE_READ  : u32 = 0x201;
pub const SM_CMD_FILE_UPDATE  : u32 = 0x202;
pub const SM_CMD_FILE_CREATE  : u32 = 0x203;
pub const SM_CMD_FILE_DELETE  : u32 = 0x204;
pub const SM_CMD_PIN   : u32 = 0x300;
pub const SM_CMD_PIN_VERIFY  : u32 = 0x301;
pub const SM_CMD_PIN_RESET  : u32 = 0x302;
pub const SM_CMD_PIN_SET_PIN  : u32 = 0x303;
pub const SM_CMD_PSO   : u32 = 0x400;
pub const SM_CMD_PSO_DST   : u32 = 0x401;
pub const SM_CMD_APDU   : u32 = 0x500;
pub const SM_CMD_APDU_TRANSMIT  : u32 = 0x501;
pub const SM_CMD_APDU_RAW   : u32 = 0x502;
pub const SM_CMD_APPLET   : u32 = 0x600;
pub const SM_CMD_APPLET_DELETE  : u32 = 0x601;
pub const SM_CMD_APPLET_LOAD  : u32 = 0x602;
pub const SM_CMD_APPLET_INSTALL  : u32 = 0x603;
pub const SM_CMD_EXTERNAL_AUTH  : u32 = 0x700;
pub const SM_CMD_EXTERNAL_AUTH_INIT : u32 = 0x701;
pub const SM_CMD_EXTERNAL_AUTH_CHALLENGE : u32 = 0x702;
pub const SM_CMD_EXTERNAL_AUTH_DOIT : u32 = 0x703;
pub const SM_CMD_SDO_UPDATE  : u32 = 0x800;
pub const SM_CMD_FINALIZE   : u32 = 0x900;

pub const SM_RESPONSE_CONTEXT_TAG  : u32 = 0xA1;
pub const SM_RESPONSE_CONTEXT_DATA_TAG : u32 = 0xA2;

pub const SM_MAX_DATA_SIZE    : u32 = 0xE0;

pub const SM_SMALL_CHALLENGE_LEN : usize = 8;

pub const SM_GP_SECURITY_NO  : u32 = 0x00;
pub const SM_GP_SECURITY_MAC  : u32 = 0x01;
pub const SM_GP_SECURITY_ENC  : u32 = 0x03;

/* Global Platform (SCP01) data types */
/*
 * @struct sm_type_params_gp
 * Global Platform SM channel parameters
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_type_params_gp {
    pub level : c_uint,
    pub index : c_uint,
    pub version : c_uint,

    pub cplc : sc_cplc,
}

/*
 * @struct sm_gp_keyset
 * Global Platform keyset:
 * - version, index;
 * - keyset presented in three parts: 'ENC', 'MAC' and 'KEK';
 * - keyset presented in continuous manner - raw or 'to be diversified'.
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_gp_keyset {
    pub version : c_int,
    pub index : c_int,
    pub enc : [c_uchar; 16usize],
    pub mac : [c_uchar; 16usize],
    pub kek : [c_uchar; 16usize],

    pub kmc : [c_uchar; 48usize],
    pub kmc_len : c_uint,
}

/*
 * @struct sm_gp_session
 * Global Platform SM session data
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_gp_session {
    pub gp_keyset : sm_gp_keyset,

    pub params : sm_type_params_gp,

    pub host_challenge : [c_uchar; SM_SMALL_CHALLENGE_LEN],
    pub card_challenge : [c_uchar; SM_SMALL_CHALLENGE_LEN],

    pub session_enc : *mut c_uchar,
    pub session_mac : *mut c_uchar,
    pub session_kek : *mut c_uchar,
    pub mac_icv : [c_uchar; 8usize],
}

/* CWA, IAS/ECC data types */

/*
 * @struct sm_type_params_cwa
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_type_params_cwa {
    pub crt_at : sc_crt,
}

#[cfg(impl_default)]
impl Default for sm_type_params_cwa {
    fn default() -> sm_type_params_cwa {
        sm_type_params_cwa {
            crt_at: Default::default(),
        }
    }
}

/*
 * @struct sm_cwa_keyset
 * CWA keyset:
 * - SDO reference;
 * - 'ENC' and 'MAC' 3DES keys.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_cwa_keyset {
    pub sdo_reference : c_uint,
    pub enc : [c_uchar; 16usize],
    pub mac : [c_uchar; 16usize],
}

#[cfg(impl_default)]
impl Default for sm_cwa_keyset {
    fn default() -> sm_cwa_keyset {
        sm_cwa_keyset {
            sdo_reference: 0,
            enc: [0u8; 16usize],
            mac: [0u8; 16usize]
        }
    }
}

/*
 * @struct sm_cwa_token_data
 * CWA token data:
 * - serial;
 * - 'small' random;
 * - 'big' random.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_cwa_token_data {
    pub sn : [c_uchar; 8usize],
    pub rnd : [c_uchar; 8usize],
    pub k : [c_uchar; 32usize],
}

#[cfg(impl_default)]
impl Default for sm_cwa_token_data {
    fn default() -> sm_cwa_token_data {
        sm_cwa_token_data {
            sn: [0u8; 8usize],
            rnd: [0u8; 8usize],
            k: [0u8; 32usize]
        }
    }
}

/*
 * @struct sm_cwa_session
 * CWA working SM session data:
 * - ICC and IFD token data;
 * - ENC and MAC session keys;
 * - SSC (SM Sequence Counter);
 * - 'mutual authentication' data.
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_cwa_session {
    pub cwa_keyset : sm_cwa_keyset,

    pub params : sm_type_params_cwa,

    pub icc : sm_cwa_token_data,
    pub ifd : sm_cwa_token_data,

    pub session_enc : [c_uchar; 16usize],
    pub session_mac : [c_uchar; 16usize],

    pub ssc : [c_uchar; 8usize],

    pub host_challenge : [c_uchar; SM_SMALL_CHALLENGE_LEN],
    pub card_challenge : [c_uchar; SM_SMALL_CHALLENGE_LEN],

    pub mdata : [c_uchar; 0x48],
    pub mdata_len : usize,
}

#[cfg(impl_default)]
impl Default for sm_cwa_session {
    fn default() -> sm_cwa_session {
        sm_cwa_session {
            cwa_keyset: Default::default(),
            params: Default::default(),
            icc: Default::default(),
            ifd: Default::default(),
            session_enc: [0u8; 16usize],
            session_mac: [0u8; 16usize],
            ssc: [0u8; 8usize],
            host_challenge: [0u8; SM_SMALL_CHALLENGE_LEN],
            card_challenge: [0u8; SM_SMALL_CHALLENGE_LEN],
            mdata: [0u8; 0x48usize],
            mdata_len: 0
        }
    }
}

/*
 * @struct sm_dh_session
 * DH SM session data:
 */
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_dh_session {
    pub g : sc_tlv_data,
    pub N : sc_tlv_data,
    pub ifd_p : sc_tlv_data,
    pub ifd_y : sc_tlv_data,
    pub icc_p : sc_tlv_data,
    pub shared_secret : sc_tlv_data,

    pub session_enc : [c_uchar; 16usize],
    pub session_mac : [c_uchar; 16usize],

    pub card_challenge : [c_uchar; 32usize],

    pub ssc : [c_uchar; 8usize],
}

/*
 * @struct sm_info is the
 * placehold for the secure messaging working data:
 * - SM type;
 * - SM session state;
 * - command to execute by external SM module;
 * - data related to the current card context.
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sm_info__union {
    pub gp  : sm_gp_session,
    pub cwa : sm_cwa_session,
    pub dh  : sm_dh_session,
//    _bindgen_union_align : [ u64 ; 39usize ],
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_info {
    pub config_section : [c_char; 64usize],
    pub card_type : c_uint,

    pub cmd : c_uint,      /* e.g. SM_CMD_EXTERNAL_AUTH */
    pub cmd_data : *mut c_void,

    pub sm_type : c_uint,  /* e.g. SM_TYPE_CWA14890 */
    pub session : sm_info__union,

    pub serialnr : sc_serial_number,

    pub security_condition : c_uint, /* unused */

    pub current_path_df : sc_path,
    pub current_path_ef : sc_path,
    pub current_aid : sc_aid,

    pub rdata : *mut c_uchar,
    pub rdata_len : usize,
}

/*
 * @struct sm_card_response
 * data type to return card response.
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_card_response {
    pub num : c_int,

    pub data : [c_uchar; SC_MAX_APDU_BUFFER_SIZE],
    pub data_len : usize,

    pub mac : [c_uchar; 8usize],
    pub mac_len : usize,

    pub sw1 : c_uchar,
    pub sw2 : c_uchar,

    pub next : *mut sm_card_response,
    pub prev : *mut sm_card_response,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sm_card_response_t = sm_card_response;
*/

//struct sc_context;
//struct sc_card;

/*
 * @struct sm_card_operations
 * card driver handlers related to secure messaging (in 'APDU TRANSMIT' mode)
 * - 'open' - initialize SM session;
 * - 'encode apdu' - SM encoding of the raw APDU;
 * - 'decrypt response' - decode card answer;
 * - 'close' - close SM session.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_card_operations {
    pub open : Option < unsafe extern "C" fn (card: *mut sc_card) -> c_int >,
    pub get_sm_apdu : Option < unsafe extern "C" fn (card: *mut sc_card, apdu: *mut sc_apdu,
                                                     sm_apdu: *mut *mut sc_apdu) -> c_int >,
    pub free_sm_apdu : Option < unsafe extern "C" fn (card: *mut sc_card, apdu: *mut sc_apdu,
                                                      sm_apdu: *mut *mut sc_apdu) -> c_int >,
    pub close : Option < unsafe extern "C" fn (card: *mut sc_card) -> c_int >,

    pub read_binary : Option < unsafe extern "C" fn (card: *mut sc_card, idx: c_uint, buf: *mut c_uchar, count: usize)
        -> c_int >,
    pub update_binary : Option < unsafe extern "C" fn (card: *mut sc_card, idx: c_uint, buf: *const c_uchar, count: usize)
        -> c_int >,
}

/*
 * @struct sm_module_operations
 * API to use external SM modules:
 * - 'initialize' - get APDU(s) to initialize SM session;
 * - 'get apdus' - get secured APDUs to execute particular command;
 * - 'finalize' - get APDU(s) to finalize SM session;
 * - 'module init' - initialize external module (allocate data, read configuration, ...);
 * - 'module cleanup' - free resources allocated by external module.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sm_module_operations {
    pub initialize : Option < unsafe extern "C" fn (ctx: *mut sc_context, info: *mut sm_info, out: *mut sc_remote_data)
        -> c_int >,
    pub get_apdus : Option < unsafe extern "C" fn (ctx: *mut sc_context, sm_info: *mut sm_info, init_data: *mut c_uchar,
                                                   init_len: usize, out: *mut sc_remote_data) -> c_int >,
    pub finalize : Option < unsafe extern "C" fn (ctx: *mut sc_context, info: *mut sm_info, rdata: *mut sc_remote_data,
                                                  out: *mut c_uchar, out_len: usize) -> c_int >,
    pub module_init : Option < unsafe extern "C" fn (ctx: *mut sc_context, data: *const c_char) -> c_int >,
    pub module_cleanup : Option < unsafe extern "C" fn (ctx: *mut sc_context) -> c_int >,

    pub test : Option < unsafe extern "C" fn (ctx: *mut sc_context, info: *mut sm_info, out: *mut c_char) -> c_int >,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_module {
    pub filename : [c_char; 128usize],
    pub handle : *mut c_void,

    pub ops : sm_module_operations,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sm_module_t = sm_module;
*/

/* @struct sm_context
 * SM context -- top level of the SM data type
 * - SM mode ('ACL' or 'APDU TRANSMIT'), flags;
 * - working SM data;
 * - card operations related to SM in 'APDU TRANSMIT' mode;
 * - external SM module;
 * - 'lock'/'unlock' handlers to allow SM transfer in the locked card session.
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sm_context {
    pub config_section : [c_char; 64usize],
    pub sm_mode  : c_uint,  /* e.g. SM_MODE_NONE */
    pub sm_flags : c_uint,  /* unused */

    pub info : sm_info,

    pub ops : sm_card_operations,

    pub module : sm_module,

    pub app_lock :   Option< unsafe extern "C" fn () -> c_ulong >,
    pub app_unlock : Option< unsafe extern "C" fn () >,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sm_context_t = sm_context;
*/

extern "C" {
pub fn sc_sm_parse_answer(arg1: *mut sc_card, arg2: *mut c_uchar, arg3: usize, arg4: *mut sm_card_response) -> c_int;

/*

*/
pub fn sc_sm_update_apdu_response(arg1: *mut sc_card, arg2: *mut c_uchar, arg3: usize, arg4: c_int, arg5: *mut sc_apdu)
    -> c_int;

pub fn sc_sm_single_transmit(arg1: *mut sc_card, arg2: *mut sc_apdu) -> c_int;

/**
 * @brief Stops SM and frees allocated resources.
 *
 * Calls \a card->sm_ctx.ops.close() if available and \c card->sm_ctx.sm_mode
 * is \c SM_MODE_TRANSMIT
 *
 * @param[in] card
 *
 * @return \c SC_SUCCESS or error code if an error occurred
 */
pub fn sc_sm_stop(card: *mut sc_card) -> c_int;
}
