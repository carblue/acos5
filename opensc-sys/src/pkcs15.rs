/*
 * pkcs15.h: OpenSC PKCS#15 header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
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

#[cfg(v0_17_0)]
use std::os::raw::c_ulonglong;
use std::os::raw::{c_ulong, c_uchar, c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::opensc::{sc_card, sc_app_info, sc_context, sc_ec_parameters, sc_algorithm_id, sc_supported_algo_info};
use crate::types::{sc_file, sc_object_id, sc_path, sc_aid, SC_MAX_SUPPORTED_ALGORITHMS};
#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
use crate::scconf::scconf_block;
use crate::aux_data::sc_auxiliary_data;


////pub const SC_PKCS15_CACHE_DIR        ".eid"

pub const SC_PKCS15_PIN_MAGIC       : usize = 0x3141_5926;
pub const SC_PKCS15_MAX_PINS        : usize = 8;
pub const SC_PKCS15_MAX_LABEL_SIZE  : usize = 255;
pub const SC_PKCS15_MAX_ID_SIZE     : usize = 255;

/* When changing this value, change also initialisation of the
 * static ASN1 variables, that use this macro,
 * like for example, 'c_asn1_access_control_rules'
 * in src/libopensc/asn1.c */
pub const SC_PKCS15_MAX_ACCESS_RULES      : usize = 8;

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone /*,  PartialEq*/)]
pub struct sc_pkcs15_id {
    pub value : [c_uchar; SC_PKCS15_MAX_ID_SIZE],
    pub len : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_id_t = sc_pkcs15_id;
*/

impl Default for sc_pkcs15_id {
    fn default() -> Self {
        Self {
            value: [0; SC_PKCS15_MAX_ID_SIZE],
            len: 0
        }
    }
}

pub const SC_PKCS15_CO_FLAG_PRIVATE     : u32 =   0x0000_0001;
pub const SC_PKCS15_CO_FLAG_MODIFIABLE  : u32 =   0x0000_0002;
pub const SC_PKCS15_CO_FLAG_OBJECT_SEEN : u32 =   0x8000_0000; /* for PKCS #11 module */

pub const SC_PKCS15_PIN_FLAG_CASE_SENSITIVE            : u32 =  0x0001;
pub const SC_PKCS15_PIN_FLAG_LOCAL                     : u32 =  0x0002;
pub const SC_PKCS15_PIN_FLAG_CHANGE_DISABLED           : u32 =  0x0004;
pub const SC_PKCS15_PIN_FLAG_UNBLOCK_DISABLED          : u32 =  0x0008;
pub const SC_PKCS15_PIN_FLAG_INITIALIZED               : u32 =  0x0010;
pub const SC_PKCS15_PIN_FLAG_NEEDS_PADDING             : u32 =  0x0020;
pub const SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN            : u32 =  0x0040;
pub const SC_PKCS15_PIN_FLAG_SO_PIN                    : u32 =  0x0080;
pub const SC_PKCS15_PIN_FLAG_DISABLE_ALLOW             : u32 =  0x0100;
pub const SC_PKCS15_PIN_FLAG_INTEGRITY_PROTECTED       : u32 =  0x0200;
pub const SC_PKCS15_PIN_FLAG_CONFIDENTIALITY_PROTECTED : u32 =  0x0400;
pub const SC_PKCS15_PIN_FLAG_EXCHANGE_REF_DATA         : u32 =  0x0800;

pub const SC_PKCS15_PIN_TYPE_FLAGS_MASK : u32 =
      SC_PKCS15_PIN_FLAG_LOCAL | SC_PKCS15_PIN_FLAG_INITIALIZED
    | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN | SC_PKCS15_PIN_FLAG_SO_PIN;

pub const SC_PKCS15_PIN_TYPE_FLAGS_SOPIN      : u32 = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_SO_PIN;
pub const SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL : u32 = SC_PKCS15_PIN_FLAG_INITIALIZED;
pub const SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL  : u32 = SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL | SC_PKCS15_PIN_FLAG_LOCAL;
pub const SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL : u32 = SC_PKCS15_PIN_FLAG_INITIALIZED | SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN;
pub const SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL  : u32 = SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL | SC_PKCS15_PIN_FLAG_LOCAL;

pub const SC_PKCS15_PIN_TYPE_BCD            : u32 =   0;
pub const SC_PKCS15_PIN_TYPE_ASCII_NUMERIC  : u32 =   1;
pub const SC_PKCS15_PIN_TYPE_UTF8           : u32 =   2;
pub const SC_PKCS15_PIN_TYPE_HALFNIBBLE_BCD : u32 =   3;
pub const SC_PKCS15_PIN_TYPE_ISO9564_1      : u32 =   4;

pub const SC_PKCS15_PIN_AUTH_TYPE_PIN       : u32 =   0;
pub const SC_PKCS15_PIN_AUTH_TYPE_BIOMETRIC : u32 =   1;
pub const SC_PKCS15_PIN_AUTH_TYPE_AUTH_KEY  : u32 =   2;
pub const SC_PKCS15_PIN_AUTH_TYPE_SM_KEY    : u32 =   3;

/* PinAttributes as they are defined in PKCS#15 v1.1 for PIN authentication object */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_pin_attributes {
    pub flags : c_uint,
    pub type_ : c_uint,
    pub min_length : usize,
    pub stored_length : usize,
    pub max_length : usize,
    pub reference : c_int,
    pub pad_char : c_uchar,
}

/* AuthKeyAttributes of the authKey authentication object */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_authkey_attributes {
    pub derived : c_int,
    pub skey_id : sc_pkcs15_id,
}

/* BiometricAttributes of the biometricTemplate authentication object */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_biometric_attributes {
    pub flags : c_uint,
    pub template_id : sc_object_id,
    /* ... */
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_pkcs15_auth_info__bindgen_ty_1 {
    pub pin : sc_pkcs15_pin_attributes,
    pub bio : sc_pkcs15_biometric_attributes,
    pub authkey : sc_pkcs15_authkey_attributes,
//    _bindgen_union_align : [ u64 ; 34usize ] ,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_auth_info {
    /* CommonAuthenticationObjectAttributes */
    pub auth_id : sc_pkcs15_id,

    /* AuthObjectAttributes */
    pub path : sc_path,
    pub auth_type : c_uint,
    pub attrs : sc_pkcs15_auth_info__bindgen_ty_1,

    /* authentication method: CHV, SEN, SYMBOLIC, ... */
    pub auth_method : c_uint,

    pub tries_left : c_int,
    pub max_tries : c_int,
    pub logged_in : c_int,
    pub max_unlocks : c_int,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_auth_info_t = sc_pkcs15_auth_info;
*/

pub const SC_PKCS15_ALGO_OP_COMPUTE_CHECKSUM  : u32 =  0x01;
pub const SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE : u32 =  0x02;
pub const SC_PKCS15_ALGO_OP_VERIFY_CHECKSUM   : u32 =  0x04;
pub const SC_PKCS15_ALGO_OP_VERIFY_SIGNATURE  : u32 =  0x08;
pub const SC_PKCS15_ALGO_OP_ENCIPHER          : u32 =  0x10;
pub const SC_PKCS15_ALGO_OP_DECIPHER          : u32 =  0x20;
pub const SC_PKCS15_ALGO_OP_HASH              : u32 =  0x40;
pub const SC_PKCS15_ALGO_OP_GENERATE_KEY      : u32 =  0x80;

/* A large integer, big endian notation */

#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct sc_pkcs15_bignum {
    pub data: *mut c_uchar,
    pub len:  usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_bignum_t = sc_pkcs15_bignum;
*/

impl Default for sc_pkcs15_bignum {
    fn default() -> Self {
        Self {
            data: null_mut(),
            len: 0
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_der {
    pub value : *mut c_uchar,
    pub len : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_der_t = sc_pkcs15_der;
*/

impl Default for sc_pkcs15_der {
    fn default() -> Self {
        Self {
            value: null_mut(),
            len: 0
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_u8 {
    pub value : *mut c_uchar,
    pub len : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_u8_t = sc_pkcs15_u8;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_data {
    pub data : *mut c_uchar, /* DER encoded raw data object */
    pub data_len : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_data_t = sc_pkcs15_data;
*/

//#define sc_pkcs15_skey sc_pkcs15_data
#[allow(non_camel_case_types)]
pub type sc_pkcs15_skey = sc_pkcs15_data;

/*
//#define sc_pkcs15_skey_t sc_pkcs15_data_t
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_skey_t = sc_pkcs15_data_t;
*/

#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct sc_pkcs15_pubkey_rsa {
    pub modulus:  sc_pkcs15_bignum,
    pub exponent: sc_pkcs15_bignum,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_prkey_rsa {
    /* public components */
    pub modulus : sc_pkcs15_bignum,
    pub exponent : sc_pkcs15_bignum,

    /* private components */
    pub d : sc_pkcs15_bignum,
    pub p : sc_pkcs15_bignum,
    pub q : sc_pkcs15_bignum,

    /* optional CRT elements */
    pub iqmp : sc_pkcs15_bignum,
    pub dmp1 : sc_pkcs15_bignum,
    pub dmq1 : sc_pkcs15_bignum,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_pubkey_dsa {
    pub pub_ : sc_pkcs15_bignum,
    pub p : sc_pkcs15_bignum,
    pub q : sc_pkcs15_bignum,
    pub g : sc_pkcs15_bignum,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_prkey_dsa {
    /* public components */
    pub pub_ : sc_pkcs15_bignum,
    pub p : sc_pkcs15_bignum,
    pub q : sc_pkcs15_bignum,
    pub g : sc_pkcs15_bignum,

    /* private key */
    pub priv_ : sc_pkcs15_bignum,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_gost_parameters {
    pub key : sc_object_id,
    pub hash : sc_object_id,
    pub cipher : sc_object_id,
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_pubkey_ec {
    pub params : sc_ec_parameters,
    pub ecpointQ : sc_pkcs15_u8, /* This is NOT DER, just value and length */
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_prkey_ec {
    pub params : sc_ec_parameters,
    pub privateD : sc_pkcs15_bignum, /* note this is bignum */
    pub ecpointQ : sc_pkcs15_u8, /* This is NOT DER, just value and length */
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_pubkey_gostr3410 {
    pub params : sc_pkcs15_gost_parameters,
    pub xy : sc_pkcs15_bignum,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_prkey_gostr3410 {
    pub params : sc_pkcs15_gost_parameters,
    pub d : sc_pkcs15_bignum,
}

/* Decoded key */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_pkcs15_pubkey__bindgen_ty_1 {
    pub rsa : sc_pkcs15_pubkey_rsa,
    pub dsa : sc_pkcs15_pubkey_dsa,
    pub ec  : sc_pkcs15_pubkey_ec,
    pub gostr3410 : sc_pkcs15_pubkey_gostr3410,
//    _bindgen_union_align : [ u64 ; 26usize ] ,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_pubkey {
    pub algorithm : c_int,
    pub alg_id : *mut sc_algorithm_id,

    /* Decoded key */
    pub u : sc_pkcs15_pubkey__bindgen_ty_1,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_pubkey_t = sc_pkcs15_pubkey;
*/

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_pkcs15_prkey__bindgen_ty_1 {
    pub rsa : sc_pkcs15_prkey_rsa,
    pub dsa : sc_pkcs15_prkey_dsa,
    pub ec  : sc_pkcs15_prkey_ec,
    pub gostr3410 : sc_pkcs15_prkey_gostr3410,
    pub secret : sc_pkcs15_skey,
// _bindgen_union_align : [ u64 ; 26usize ],
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_prkey {
    pub algorithm : c_uint,
/* TODO do we need:    struct sc_algorithm_id * alg_id; */

    pub u : sc_pkcs15_prkey__bindgen_ty_1,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_prkey_t = sc_pkcs15_prkey;
*/

/* Enveloped objects can be used to provide additional
 * protection to non-native private keys */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_enveloped_data {
    /* recipient info */
    pub id : sc_pkcs15_id, /* key ID */
    pub ke_alg : sc_algorithm_id, /* key-encryption algo */
    pub key : *mut c_uchar,  /* encrypted key */
    pub key_len : usize,
    pub ce_alg : sc_algorithm_id, /* content-encryption algo */
    pub content : *mut c_uchar, /* encrypted content */
    pub content_len : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_cert {
    pub version : c_int,
    pub serial : *mut c_uchar,
    pub serial_len : usize,
    pub issuer : *mut c_uchar,
    pub issuer_len : usize,
    pub subject : *mut c_uchar,
    pub subject_len : usize,
    pub extensions : *mut c_uchar, // the field name is crl     in opensc version 0.15.0 and 0.16.0
    pub extensions_len : usize,    // the field name is crl_len in opensc version 0.15.0 and 0.16.0

    pub key : *mut sc_pkcs15_pubkey,

    pub data : sc_pkcs15_der,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_cert_t = sc_pkcs15_cert;
*/

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_cert_info {
    pub id : sc_pkcs15_id, /* correlates to private key id */
    pub authority : c_int, /* boolean */
    /* identifiers [2] SEQUENCE OF CredentialIdentifier{{KeyIdentifiers}} */
    pub path : sc_path,

    pub value : sc_pkcs15_der,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_cert_info_t = sc_pkcs15_cert_info;
*/

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_data_info {
    /* FIXME: there is no pkcs15 ID in DataType */
    pub id : sc_pkcs15_id,

    /* Identify the application:
     * either or both may be set */
    pub app_label : [c_char; SC_PKCS15_MAX_LABEL_SIZE],
    pub app_oid : sc_object_id,

    pub path : sc_path,

    pub data : sc_pkcs15_der,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_data_info_t = sc_pkcs15_data_info;
*/

/* keyUsageFlags are the same for all key types */
pub const SC_PKCS15_PRKEY_USAGE_ENCRYPT        : u32 =   0x01;
pub const SC_PKCS15_PRKEY_USAGE_DECRYPT        : u32 =   0x02;
pub const SC_PKCS15_PRKEY_USAGE_SIGN           : u32 =   0x04;
pub const SC_PKCS15_PRKEY_USAGE_SIGNRECOVER    : u32 =   0x08;
pub const SC_PKCS15_PRKEY_USAGE_WRAP           : u32 =   0x10;
pub const SC_PKCS15_PRKEY_USAGE_UNWRAP         : u32 =   0x20;
pub const SC_PKCS15_PRKEY_USAGE_VERIFY         : u32 =   0x40;
pub const SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER  : u32 =   0x80;
pub const SC_PKCS15_PRKEY_USAGE_DERIVE         : u32 =  0x100;
pub const SC_PKCS15_PRKEY_USAGE_NONREPUDIATION : u32 =  0x200;

pub const SC_PKCS15_PRKEY_ACCESS_SENSITIVE        : u32 =  0x01;
pub const SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE      : u32 =  0x02;
pub const SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE  : u32 =  0x04;
pub const SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE : u32 =  0x08;
pub const SC_PKCS15_PRKEY_ACCESS_LOCAL            : u32 =  0x10;

pub const SC_PKCS15_PARAMSET_GOSTR3410_A : u32 =          1;
pub const SC_PKCS15_PARAMSET_GOSTR3410_B : u32 =          2;
pub const SC_PKCS15_PARAMSET_GOSTR3410_C : u32 =          3;

pub const SC_PKCS15_GOSTR3410_KEYSIZE : u32 =             256;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_keyinfo_gostparams {
    pub gostr3410 : c_uint,
    pub gostr3411 : c_uint,
    pub gost28147 : c_uint,
}
/* AccessMode bit definitions specified in PKCS#15 v1.1
 * and extended by IAS/ECC v1.0.1 specification. */
pub const SC_PKCS15_ACCESS_RULE_MODE_READ        : u32 =   0x01;
pub const SC_PKCS15_ACCESS_RULE_MODE_UPDATE      : u32 =   0x02;
pub const SC_PKCS15_ACCESS_RULE_MODE_EXECUTE     : u32 =   0x04;
pub const SC_PKCS15_ACCESS_RULE_MODE_DELETE      : u32 =   0x08;
pub const SC_PKCS15_ACCESS_RULE_MODE_ATTRIBUTE   : u32 =   0x10;
pub const SC_PKCS15_ACCESS_RULE_MODE_PSO_CDS     : u32 =   0x20;
pub const SC_PKCS15_ACCESS_RULE_MODE_PSO_VERIFY  : u32 =   0x40;
pub const SC_PKCS15_ACCESS_RULE_MODE_PSO_DECRYPT : u32 =   0x80;
pub const SC_PKCS15_ACCESS_RULE_MODE_PSO_ENCRYPT : u32 =  0x100;
pub const SC_PKCS15_ACCESS_RULE_MODE_INT_AUTH    : u32 =  0x200;
pub const SC_PKCS15_ACCESS_RULE_MODE_EXT_AUTH    : u32 =  0x400;

#[repr(C)]
#[derive(Default, /*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_accessrule {
    pub access_mode : c_uint,
    pub auth_id : sc_pkcs15_id,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_accessrule_t = sc_pkcs15_accessrule;
*/

/*
/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN       39
 * #define CONTAINER_MAP_VALID_CONTAINER        1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER      2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *      WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *      BYTE bFlags;
 *      BYTE bReserved;
 *      WORD wSigKeySizeBits;
 *      WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
#define SC_MD_MAX_CONTAINER_NAME_LEN 39
#define SC_MD_CONTAINER_MAP_VALID_CONTAINER    0x01
#define SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER  0x02
*/
/*
/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * typedef struct _CARD_CACHE_FILE_FORMAT
 * {
 *    BYTE bVersion;        // Cache version
 *    BYTE bPinsFreshness;  // Card PIN
 *    WORD wContainersFreshness;
 *    WORD wFilesFreshness;
 * } CARD_CACHE_FILE_FORMAT, *PCARD_CACHE_FILE_FORMAT;
 */
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_key_params {
    pub data : *mut c_void,
    pub len : usize,
    pub free_params : Option< unsafe extern "C" fn (arg1: *mut c_void) >,
}

impl Default for sc_pkcs15_key_params {
    fn default() -> Self {
        Self {
            data: null_mut() as *mut c_void,
            len: 0,
            free_params: None
        }
    }
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_prkey_info {
    pub id : sc_pkcs15_id, /* correlates to public certificate id */
    pub usage : c_uint,
    pub access_flags : c_uint,
    pub native : c_int,
    pub key_reference : c_int,
    /* convert to union if other types are supported */
    pub modulus_length : usize, /* RSA in bits; Attention: This seems to get set according to MSB set */
    pub field_length : usize,   /* EC in bits */

    pub algo_refs : [c_uint; SC_MAX_SUPPORTED_ALGORITHMS] ,

    pub subject : sc_pkcs15_der,

    pub params : sc_pkcs15_key_params,

    pub path : sc_path,

    /* Non-pkcs15 data, like MD CMAP record */
    pub aux_data : *mut sc_auxiliary_data,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_prkey_info_t = sc_pkcs15_prkey_info;
*/

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct sc_pkcs15_pubkey_info__bindgen_ty_1 {
    pub raw  : sc_pkcs15_der,
    pub spki : sc_pkcs15_der,
}

#[repr(C)]
#[derive(Default, /*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_pubkey_info {
    pub id : sc_pkcs15_id,  /* correlates to private key id */
    pub usage : c_uint,
    pub access_flags : c_uint,
    pub native : c_int,
    pub key_reference : c_int,
    /* convert to union if other types are supported */
    pub modulus_length : usize, /* RSA in bits; Attention: This seems to get set according to MSB set */
    pub field_length : usize,   /* EC in bits */

    pub algo_refs : [c_uint ; SC_MAX_SUPPORTED_ALGORITHMS],

    pub subject : sc_pkcs15_der,

    pub params : sc_pkcs15_key_params,

    pub path : sc_path,

    pub direct : sc_pkcs15_pubkey_info__bindgen_ty_1,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_pubkey_info_t = sc_pkcs15_pubkey_info;
*/

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_skey_info {
    pub id : sc_pkcs15_id,
    pub usage : c_uint,
    pub access_flags : c_uint,
    pub native : c_int,
    pub key_reference : c_int,
    pub value_len : usize,
    pub key_type : c_ulong,  /* e.g. CKK_AES */
    pub algo_refs : [c_uint; SC_MAX_SUPPORTED_ALGORITHMS],
    pub path : sc_path, /* if on card */
    pub data : sc_pkcs15_der,
}

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_skey_info_t = sc_pkcs15_skey_info;
*/

pub const SC_PKCS15_TYPE_CLASS_MASK       : u32 =  0xF00;

pub const SC_PKCS15_TYPE_PRKEY            : u32 =  0x100;
pub const SC_PKCS15_TYPE_PRKEY_RSA        : u32 =  0x101;
pub const SC_PKCS15_TYPE_PRKEY_DSA        : u32 =  0x102;
pub const SC_PKCS15_TYPE_PRKEY_GOSTR3410  : u32 =  0x103;
pub const SC_PKCS15_TYPE_PRKEY_EC         : u32 =  0x104;

pub const SC_PKCS15_TYPE_PUBKEY           : u32 =  0x200;
pub const SC_PKCS15_TYPE_PUBKEY_RSA       : u32 =  0x201;
pub const SC_PKCS15_TYPE_PUBKEY_DSA       : u32 =  0x202;
pub const SC_PKCS15_TYPE_PUBKEY_GOSTR3410 : u32 =  0x203;
pub const SC_PKCS15_TYPE_PUBKEY_EC        : u32 =  0x204;

pub const SC_PKCS15_TYPE_SKEY             : u32 =  0x300;
pub const SC_PKCS15_TYPE_SKEY_GENERIC     : u32 =  0x301; // this seems to cover i.a. AES
pub const SC_PKCS15_TYPE_SKEY_DES         : u32 =  0x302;
pub const SC_PKCS15_TYPE_SKEY_2DES        : u32 =  0x303;
pub const SC_PKCS15_TYPE_SKEY_3DES        : u32 =  0x304;

pub const SC_PKCS15_TYPE_CERT             : u32 =  0x400;
pub const SC_PKCS15_TYPE_CERT_X509        : u32 =  0x401;
pub const SC_PKCS15_TYPE_CERT_SPKI        : u32 =  0x402;

pub const SC_PKCS15_TYPE_DATA_OBJECT      : u32 =  0x500;

pub const SC_PKCS15_TYPE_AUTH             : u32 =  0x600;
pub const SC_PKCS15_TYPE_AUTH_PIN         : u32 =  0x601;
pub const SC_PKCS15_TYPE_AUTH_BIO         : u32 =  0x602;
pub const SC_PKCS15_TYPE_AUTH_AUTHKEY     : u32 =  0x603;

//#define SC_PKCS15_TYPE_TO_CLASS(t)        (1 << ((t) >> 8))
pub const SC_PKCS15_SEARCH_CLASS_PRKEY    : u32 =  0x0002;
pub const SC_PKCS15_SEARCH_CLASS_PUBKEY   : u32 =  0x0004;
pub const SC_PKCS15_SEARCH_CLASS_SKEY     : u32 =  0x0008;
pub const SC_PKCS15_SEARCH_CLASS_CERT     : u32 =  0x0010;
pub const SC_PKCS15_SEARCH_CLASS_DATA     : u32 =  0x0020;
pub const SC_PKCS15_SEARCH_CLASS_AUTH     : u32 =  0x0040;

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_object {
    pub type_ : c_uint, /* e.g. SC_PKCS15_TYPE_PRKEY_RSA */
    /* CommonObjectAttributes */
    pub label : [c_char; SC_PKCS15_MAX_LABEL_SIZE],    /* zero terminated */
    pub flags : c_uint,
    pub auth_id : sc_pkcs15_id,

    pub usage_counter : c_int,
    pub user_consent : c_int,

    pub access_rules : [sc_pkcs15_accessrule; SC_PKCS15_MAX_ACCESS_RULES],

    /* Object type specific data */
    pub data : *mut c_void,
    /* emulated object pointer */
    pub emulated : *mut c_void,

    pub df :   *mut sc_pkcs15_df,     /* can be NULL, if object is 'floating' */
    pub next : *mut sc_pkcs15_object, /* used only internally */
    pub prev : *mut sc_pkcs15_object, /* used only internally */

    pub content : sc_pkcs15_der,

    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    pub session_object : c_int,       /* used internally. if nonzero, object is a session object. */
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_object_t = sc_pkcs15_object;
*/

#[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
#[cfg(impl_default)]
impl Default for sc_pkcs15_object {
    fn default() -> Self {
        Self {
            type_: 0,
            label: [0; SC_PKCS15_MAX_LABEL_SIZE],
            flags: 0,
            auth_id: sc_pkcs15_id::default(),
            usage_counter: 0,
            user_consent: 0,
            access_rules: [sc_pkcs15_accessrule::default(); SC_PKCS15_MAX_ACCESS_RULES],
            data: null_mut(),
            emulated: null_mut(),
            df: null_mut(),
            next: null_mut(),
            prev: null_mut(),
            content: sc_pkcs15_der::default(),
//            session_object: 0,
        }
    }
}

#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
#[cfg(impl_default)]
impl Default for sc_pkcs15_object {
    fn default() -> Self {
        Self {
            type_: 0,
            label: [0; SC_PKCS15_MAX_LABEL_SIZE],
            flags: 0,
            auth_id: sc_pkcs15_id::default(),
            usage_counter: 0,
            user_consent: 0,
            access_rules: [sc_pkcs15_accessrule::default(); SC_PKCS15_MAX_ACCESS_RULES],
            data: null_mut(),
            emulated: null_mut(),
            df: null_mut(),
            next: null_mut(),
            prev: null_mut(),
            content: sc_pkcs15_der::default(),
            session_object: 0,
        }
    }
}

/* PKCS #15 DF types */
pub const SC_PKCS15_PRKDF         : c_uchar =  0;
pub const SC_PKCS15_PUKDF         : c_uchar =  1;
pub const SC_PKCS15_PUKDF_TRUSTED : c_uchar =  2;
pub const SC_PKCS15_SKDF          : c_uchar =  3;
pub const SC_PKCS15_CDF           : c_uchar =  4;
pub const SC_PKCS15_CDF_TRUSTED   : c_uchar =  5;
pub const SC_PKCS15_CDF_USEFUL    : c_uchar =  6;
pub const SC_PKCS15_DODF          : c_uchar =  7;
pub const SC_PKCS15_AODF          : c_uchar =  8;
pub const SC_PKCS15_DF_TYPE_COUNT : usize =  9;

//struct sc_pkcs15_card;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_df {
    pub path : sc_path,
    pub record_length : c_int,
    pub type_ : c_uint,  /* e.g. SC_PKCS15_PRKDF */
    pub enumerated : c_int,

    pub next : *mut sc_pkcs15_df,
    pub prev : *mut sc_pkcs15_df,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_df_t = sc_pkcs15_df;
*/

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15_unusedspace {
    pub path : sc_path,
    pub auth_id : sc_pkcs15_id,

    pub next : *mut sc_pkcs15_unusedspace,
    pub prev : *mut sc_pkcs15_unusedspace,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_unusedspace_t = sc_pkcs15_unusedspace;
*/

pub const SC_PKCS15_CARD_MAGIC      : u32 =  0x1020_3040;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_sec_env_info {
    pub se : c_int,
    pub owner : sc_object_id,
    pub aid : sc_aid,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_sec_env_info_t = sc_pkcs15_sec_env_info;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_last_update {
    pub gtime : *mut c_char,
    pub path : sc_path,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_last_update_t = sc_pkcs15_last_update;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_profile_indication {
    pub oid : sc_object_id,
    pub name : *mut c_char,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_profile_indication_t = sc_pkcs15_profile_indication;
*/

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_tokeninfo {
    pub version : c_uint,
    pub flags : c_uint,
    pub label : *mut c_char,
    pub serial_number : *mut c_char,
    pub manufacturer_id : *mut c_char,

    pub last_update : sc_pkcs15_last_update,
    pub profile_indication : sc_pkcs15_profile_indication,

    pub preferred_language : *mut c_char,
    pub seInfo : *mut *mut sc_pkcs15_sec_env_info,
    pub num_seInfo : usize,

    pub supported_algos : [sc_supported_algo_info; SC_MAX_SUPPORTED_ALGORITHMS],
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_tokeninfo_t = sc_pkcs15_tokeninfo;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_operations {
    pub parse_df : Option< unsafe extern "C" fn(arg1: *mut sc_pkcs15_card, arg2: *mut sc_pkcs15_df) -> c_int >,
    pub clear : Option< unsafe extern "C" fn(arg1: *mut sc_pkcs15_card) >,
    pub get_guid : Option< unsafe extern "C" fn(arg1: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                                arg3: *mut c_uchar, arg4 : *mut usize) -> c_int > ,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_md_data {
    dummy: *mut c_void, // since opensc source release v0.16.0, the details are hidden ATTENTION: This may not be dereferenced !!!
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_card__sc_pkcs15_card_opts {
    pub use_file_cache : c_int,
    pub use_pin_cache : c_int,
    pub pin_cache_counter : c_int,
    pub pin_cache_ignore_user_consent : c_int,
    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    pub private_certificate : c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_card {
    pub card : *mut sc_card,
    pub flags : c_uint,

    pub app : *mut sc_app_info,

    pub file_app         : *mut sc_file,
    pub file_tokeninfo   : *mut sc_file,
    pub file_odf         : *mut sc_file,
    pub file_unusedspace : *mut sc_file,

    pub df_list : *mut sc_pkcs15_df,
    pub obj_list : *mut sc_pkcs15_object,
    pub tokeninfo : *mut sc_pkcs15_tokeninfo,
    pub unusedspace_list : *mut sc_pkcs15_unusedspace,
    pub unusedspace_read : c_int,

    pub opts : sc_pkcs15_card__sc_pkcs15_card_opts,

    pub magic : c_uint,

    pub dll_handle : *mut c_void,   /* shared lib for emulated cards */
    pub md_data : *mut sc_md_data,  /* minidriver specific data */

    pub ops : sc_pkcs15_operations,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_card_t = sc_pkcs15_card;
*/

/* flags suitable for sc_pkcs15_tokeninfo */
pub const SC_PKCS15_TOKEN_READONLY        : c_uint =  0x01;
pub const SC_PKCS15_TOKEN_LOGIN_REQUIRED  : c_uint =  0x02; /* Don't use */
pub const SC_PKCS15_TOKEN_PRN_GENERATION  : c_uint =  0x04;
pub const SC_PKCS15_TOKEN_EID_COMPLIANT   : c_uint =  0x08;

/* flags suitable for struct sc_pkcs15_card */
pub const SC_PKCS15_CARD_FLAG_EMULATED : u32 = 0x0200_0000;

/* suitable for struct sc_pkcs15_card.opts.private_certificate */
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_PKCS15_CARD_OPTS_PRIV_CERT_PROTECT    : u32 = 0;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_PKCS15_CARD_OPTS_PRIV_CERT_IGNORE     : u32 = 1;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_PKCS15_CARD_OPTS_PRIV_CERT_DECLASSIFY : u32 = 2;

/* X509 bits for certificate usage extansion */
pub const SC_X509_DIGITAL_SIGNATURE   : u32 =  0x0001; // not available in opensc version 0.15.0 and 0.16.0
pub const SC_X509_NON_REPUDIATION     : u32 =  0x0002; // dito
pub const SC_X509_KEY_ENCIPHERMENT    : u32 =  0x0004; // dito
pub const SC_X509_DATA_ENCIPHERMENT   : u32 =  0x0008; // dito
pub const SC_X509_KEY_AGREEMENT       : u32 =  0x0010; // dito
pub const SC_X509_KEY_CERT_SIGN       : u32 =  0x0020; // dito
pub const SC_X509_CRL_SIGN            : u32 =  0x0040; // dito
pub const SC_X509_ENCIPHER_ONLY       : u32 =  0x0080; // dito
pub const SC_X509_DECIPHER_ONLY       : u32 =  0x0100; // dito

extern "C" {

/* sc_pkcs15_bind:  Binds a card object to a PKCS #15 card object
 * and initializes a new PKCS #15 card object.  Will return
 * SC_ERROR_PKCS15_APP_NOT_FOUND, if the card hasn't got a
 * valid PKCS #15 file structure. */
pub fn sc_pkcs15_bind(card: *mut sc_card, aid: *mut sc_aid, pkcs15_card: *mut *mut sc_pkcs15_card) -> c_int;

/* sc_pkcs15_unbind:  Releases a PKCS #15 card object, and frees any
 * memory allocations done on the card object. */
pub fn sc_pkcs15_unbind(card: *mut sc_pkcs15_card) -> c_int;

pub fn sc_pkcs15_bind_internal(p15card: *mut sc_pkcs15_card, aid: *mut sc_aid) -> c_int;

pub fn sc_pkcs15_get_objects(p15card: *mut sc_pkcs15_card, type_: c_uint, ret: *mut *mut sc_pkcs15_object,
                             ret_count: usize) -> c_int;

pub fn sc_pkcs15_get_objects_cond(p15card: *mut sc_pkcs15_card, type_: c_uint,
            func: Option< unsafe extern "C" fn (arg1: *mut sc_pkcs15_object, arg2: *mut c_void) -> c_int >,
            func_arg: *mut c_void, ret: *mut *mut sc_pkcs15_object, ret_count: usize) -> c_int;

pub fn sc_pkcs15_find_object_by_id(p15card: *mut sc_pkcs15_card, arg2: c_uint, arg3: *const sc_pkcs15_id,
    arg4: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_card_new() -> *mut sc_pkcs15_card;

pub fn sc_pkcs15_card_free(p15card: *mut sc_pkcs15_card);

pub fn sc_pkcs15_card_clear(p15card: *mut sc_pkcs15_card);

#[cfg(    any(         v0_18_0, v0_19_0))]
    fn sc_pkcs15_tokeninfo_new() -> *mut sc_pkcs15_tokeninfo;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_pkcs15_tokeninfo_new() -> *mut sc_pkcs15_tokeninfo;

#[cfg(    any(         v0_18_0, v0_19_0))]
    fn sc_pkcs15_free_tokeninfo(tokeninfo: *mut sc_pkcs15_tokeninfo);
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_pkcs15_free_tokeninfo(tokeninfo: *mut sc_pkcs15_tokeninfo);

pub fn sc_pkcs15_decipher(p15card: *mut sc_pkcs15_card, prkey_obj: *const sc_pkcs15_object, flags: c_ulong,
                          in_: *const c_uchar , inlen: usize, out: *mut c_uchar, outlen: usize) -> c_int;

pub fn sc_pkcs15_derive(p15card: *mut sc_pkcs15_card, prkey_obj: *const sc_pkcs15_object, flags: c_ulong,
                        in_: *const c_uchar, inlen: usize, out: *mut c_uchar, poutlen: *mut usize) -> c_int;

#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_pkcs15_unwrap(p15card: *mut sc_pkcs15_card,
                        key: *const sc_pkcs15_object,
                        target_key: *mut sc_pkcs15_object,
                        flags: c_ulong,
                        in_: *const c_uchar, inlen: usize,
                        param: *const c_uchar, paramlen: usize) -> c_int;

#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_pkcs15_wrap(p15card: *mut sc_pkcs15_card,
                      key: *const sc_pkcs15_object,
                      target_key: *mut sc_pkcs15_object,
                      flags: c_ulong,
                      cryptogram: *mut c_uchar, crgram_len: *mut usize,
                      param: *const c_uchar, paramlen: usize) -> c_int;

pub fn sc_pkcs15_compute_signature(p15card: *mut sc_pkcs15_card, prkey_obj: *const sc_pkcs15_object, alg_flags: c_ulong,
                                   in_: *const c_uchar, inlen: usize, out: *mut c_uchar, outlen: usize) -> c_int;

pub fn sc_pkcs15_read_pubkey(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                             arg3: *mut *mut sc_pkcs15_pubkey) -> c_int;

pub fn sc_pkcs15_decode_pubkey_rsa(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_rsa, arg3: *const c_uchar,
                                   arg4: usize) -> c_int;

pub fn sc_pkcs15_encode_pubkey_rsa(ctx: *mut sc_context, rsa_key: *const sc_pkcs15_pubkey_rsa, out: *mut *mut c_uchar,
                                   out_len: *mut usize) -> c_int; // API_CHANGED

pub fn sc_pkcs15_decode_pubkey_dsa(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_dsa, arg3: *const c_uchar,
                                   arg4: usize) -> c_int;

pub fn sc_pkcs15_encode_pubkey_dsa(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_dsa, arg3: *mut *mut c_uchar,
                                   arg4: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_pubkey_gostr3410(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_gostr3410,
                                         arg3: *const c_uchar, arg4: usize) -> c_int;

pub fn sc_pkcs15_encode_pubkey_gostr3410(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_gostr3410,
                                         arg3: *mut *mut c_uchar, arg4: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_pubkey_ec(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_ec, arg3: *const c_uchar,
                                  arg4: usize) -> c_int;

pub fn sc_pkcs15_encode_pubkey_ec(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey_ec, arg3: *mut *mut c_uchar,
                                  arg4: *mut usize) -> c_int;


pub fn sc_pkcs15_decode_pubkey(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey, arg3: *const c_uchar,
                               arg4: usize) -> c_int;

pub fn sc_pkcs15_encode_pubkey(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey, arg3: *mut *mut c_uchar,
                               arg4: *mut usize) -> c_int ;

pub fn sc_pkcs15_encode_pubkey_as_spki(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey, arg3: *mut *mut c_uchar,
                                       arg4: *mut usize) -> c_int;

pub fn sc_pkcs15_erase_pubkey(arg1: *mut sc_pkcs15_pubkey);

pub fn sc_pkcs15_free_pubkey(arg1: *mut sc_pkcs15_pubkey);

pub fn sc_pkcs15_pubkey_from_prvkey(arg1: *mut sc_context, arg2: *mut sc_pkcs15_prkey, arg3: *mut *mut sc_pkcs15_pubkey)
    -> c_int;

pub fn sc_pkcs15_dup_pubkey(arg1: *mut sc_context, arg2: *mut sc_pkcs15_pubkey, arg3: *mut *mut sc_pkcs15_pubkey)
    -> c_int;

pub fn sc_pkcs15_pubkey_from_cert(arg1: *mut sc_context, arg2: *mut sc_pkcs15_der, arg3: *mut *mut sc_pkcs15_pubkey)
    -> c_int;

fn sc_pkcs15_pubkey_from_spki_file(arg1: *mut sc_context, arg2: *mut c_char, arg3: *mut *mut sc_pkcs15_pubkey) -> c_int;

fn sc_pkcs15_pubkey_from_spki_fields(arg1: *mut sc_context, arg2: *mut *mut sc_pkcs15_pubkey, arg3: *mut c_uchar,
                                     arg4: usize, arg5: c_int) -> c_int;

fn sc_pkcs15_encode_prkey(arg1: *mut sc_context, arg2: *mut sc_pkcs15_prkey, arg3: *mut *mut c_uchar, arg4: *mut usize)
    -> c_int;

pub fn sc_pkcs15_free_prkey(prkey: *mut sc_pkcs15_prkey);

pub fn sc_pkcs15_free_key_params(params: *mut sc_pkcs15_key_params);

pub fn sc_pkcs15_read_data_object(p15card: *mut sc_pkcs15_card, info: *const sc_pkcs15_data_info,
                                  data_object_out:  *mut *mut sc_pkcs15_data) -> c_int;

pub fn sc_pkcs15_find_data_object_by_id(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                        out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_data_object_by_app_oid(p15card: *mut sc_pkcs15_card, app_oid: *const sc_object_id,
                                             out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_data_object_by_name(p15card: *mut sc_pkcs15_card, app_label: *const c_char, label: *const c_char,
                                          out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_free_data_object(data_object: *mut sc_pkcs15_data);

pub fn sc_pkcs15_read_certificate(card: *mut sc_pkcs15_card, info: *const sc_pkcs15_cert_info,
                                  cert: *mut *mut sc_pkcs15_cert) -> c_int;

pub fn sc_pkcs15_free_certificate(cert: *mut sc_pkcs15_cert);

pub fn sc_pkcs15_find_cert_by_id(card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                 out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_get_name_from_dn(ctx: *mut sc_context, dn: *const c_uchar, dn_len: usize, type_: *const sc_object_id,
                                  name: *mut *mut c_uchar, name_len: *mut usize) -> c_int;

fn sc_pkcs15_get_extension(ctx: *mut sc_context, cert: *mut sc_pkcs15_cert, type_: *const sc_object_id,
                           ext_val: *mut *mut c_uchar, ext_val_len: *mut usize, is_critical: *mut c_int) -> c_int;

#[cfg(    v0_17_0)]
fn sc_pkcs15_get_bitstring_extension(ctx: *mut sc_context, cert: *mut sc_pkcs15_cert, type_: *const sc_object_id,
                                     value: *mut c_ulonglong, is_critical: *mut c_int) -> c_int;
#[cfg(not(v0_17_0))]
fn sc_pkcs15_get_bitstring_extension(ctx: *mut sc_context, cert: *mut sc_pkcs15_cert, type_: *const sc_object_id,
                                     value: *mut c_uint, is_critical: *mut c_int) -> c_int;

/* sc_pkcs15_create_cdf:  Creates a new certificate DF on a card pointed
 * by <card>.  Information about the file, such as the file ID, is read
 * from <file>.  <certs> has to be NULL-terminated. */
fn sc_pkcs15_create_cdf(card: *mut sc_pkcs15_card, file: *mut sc_file, certs: *mut *const sc_pkcs15_cert_info) -> c_int;

//fn sc_pkcs15_create(p15card: *mut sc_pkcs15_card, card: *mut sc_card) -> c_int;

pub fn sc_pkcs15_find_prkey_by_id(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                  out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_prkey_by_id_usage(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id, usage: c_uint,
                                        out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_prkey_by_reference(p15card: *mut sc_pkcs15_card, arg2: *const sc_path, arg3: c_int,
                                         arg4: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_pubkey_by_id(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                   out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_skey_by_id(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                 out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_verify_pin(p15card: *mut sc_pkcs15_card, pin_obj: *mut sc_pkcs15_object, pincode : *const c_uchar,
                            pinlen: usize) -> c_int;

pub fn sc_pkcs15_verify_pin_with_session_pin(p15card: *mut sc_pkcs15_card, pin_obj: *mut sc_pkcs15_object,
                                             pincode: *const c_uchar, pinlen: usize, sessionpin: *const c_uchar,
                                             sessionpinlen: *mut usize) -> c_int;

pub fn sc_pkcs15_change_pin(p15card: *mut sc_pkcs15_card, pin_obj: *mut sc_pkcs15_object, oldpincode: *const c_uchar,
                            oldpinlen: usize, newpincode: *const c_uchar, newpinlen: usize) -> c_int;

pub fn sc_pkcs15_unblock_pin(p15card: *mut sc_pkcs15_card, pin_obj: *mut sc_pkcs15_object, puk: *const c_uchar,
                             puklen: usize, newpin: *const c_uchar, newpinlen: usize) -> c_int;

pub fn sc_pkcs15_get_pin_info(p15card: *mut sc_pkcs15_card, pin_obj: *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_pin_by_auth_id(p15card: *mut sc_pkcs15_card, id: *const sc_pkcs15_id,
                                     out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_pin_by_reference(p15card: *mut sc_pkcs15_card, path: *const sc_path, reference: c_int,
                                       out: *mut *mut sc_pkcs15_object) -> c_int;

fn sc_pkcs15_find_pin_by_type_and_reference(p15card: *mut sc_pkcs15_card, path: *const sc_path, auth_method: c_uint,
                                            reference: c_int, out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_so_pin(p15card: *mut sc_pkcs15_card, out: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_find_pin_by_flags(p15card: *mut sc_pkcs15_card, flags: c_uint, mask: c_uint, index: *mut c_int,
                                   out: *mut *mut sc_pkcs15_object) -> c_int;

fn sc_pkcs15_pincache_add(p15card: *mut sc_pkcs15_card, arg2: *mut sc_pkcs15_object, arg3: *const c_uchar, arg4: usize);

fn sc_pkcs15_pincache_revalidate(p15card: *mut sc_pkcs15_card, obj: *const sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_pincache_clear(p15card: *mut sc_pkcs15_card);

fn sc_pkcs15_encode_dir(ctx: *mut sc_context, p15card: *mut sc_pkcs15_card, buf: *mut *mut c_uchar, buflen: *mut usize)
    -> c_int;

pub fn sc_pkcs15_parse_tokeninfo(ctx: *mut sc_context, ti: *mut sc_pkcs15_tokeninfo, buf: *const c_uchar, blen: usize)
    -> c_int;

pub fn sc_pkcs15_encode_tokeninfo(ctx: *mut sc_context, ti: *mut sc_pkcs15_tokeninfo, buf: *mut *mut c_uchar,
                                  buflen: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_odf(ctx: *mut sc_context, p15card: *mut sc_pkcs15_card, buf: *mut *mut c_uchar,
                            buflen: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_df(ctx: *mut sc_context, p15card: *mut sc_pkcs15_card, df: *mut sc_pkcs15_df,
                           buf: *mut *mut c_uchar, bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_cdf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                                  bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_prkdf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                                    bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_pukdf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                                    bufsize: *mut usize) -> c_int;

fn sc_pkcs15_encode_skdf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                               buflen: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_dodf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                                   bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_encode_aodf_entry(ctx: *mut sc_context, obj: *const sc_pkcs15_object, buf: *mut *mut c_uchar,
                                   bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_parse_df(p15card: *mut sc_pkcs15_card, df: *mut sc_pkcs15_df) -> c_int;

fn sc_pkcs15_read_df(p15card: *mut sc_pkcs15_card, df: *mut sc_pkcs15_df) -> c_int;

pub fn sc_pkcs15_decode_cdf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                  bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_dodf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                   bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_aodf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                   bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_prkdf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                    bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_pukdf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                    bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_decode_skdf_entry(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object, buf: *mut *const c_uchar,
                                   bufsize: *mut usize) -> c_int;
/*
fn sc_pkcs15_decode_enveloped_data(ctx: *mut sc_context, result: *mut sc_pkcs15_enveloped_data, buf: *const c_uchar,
                                   buflen: usize) -> c_int;

fn sc_pkcs15_encode_enveloped_data(ctx: *mut sc_context, data: *mut sc_pkcs15_enveloped_data, buf: *mut *mut c_uchar,
                                   buflen: *mut usize) -> c_int;
*/
pub fn sc_pkcs15_add_object(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_remove_object(p15card: *mut sc_pkcs15_card, obj: *mut sc_pkcs15_object);

pub fn sc_pkcs15_add_df(p15card: *mut sc_pkcs15_card, arg2: c_uint, arg3: *const sc_path) -> c_int;

pub fn sc_pkcs15_add_unusedspace(p15card: *mut sc_pkcs15_card, path: *const sc_path, auth_id: *const sc_pkcs15_id)
    -> c_int;

pub fn sc_pkcs15_remove_unusedspace(p15card: *mut sc_pkcs15_card, unusedspace: *mut sc_pkcs15_unusedspace);

pub fn sc_pkcs15_parse_unusedspace(buf: *const c_uchar, buflen: usize, p15card: *mut sc_pkcs15_card) -> c_int;

pub fn sc_pkcs15_encode_unusedspace(ctx: *mut sc_context, p15card: *mut sc_pkcs15_card, buf: *mut *mut c_uchar,
                                    buflen: *mut usize) -> c_int;

/* Deduce private key attributes from corresponding certificate */
pub fn sc_pkcs15_prkey_attrs_from_cert(p15card: *mut sc_pkcs15_card, arg2: *mut sc_pkcs15_object,
                                       arg3: *mut *mut sc_pkcs15_object) -> c_int;

pub fn sc_pkcs15_free_prkey_info(key: *mut sc_pkcs15_prkey_info);

pub fn sc_pkcs15_free_pubkey_info(key: *mut sc_pkcs15_pubkey_info);

pub fn sc_pkcs15_free_cert_info(cert: *mut sc_pkcs15_cert_info);

pub fn sc_pkcs15_free_data_info(data: *mut sc_pkcs15_data_info);

pub fn sc_pkcs15_free_auth_info(auth_info: *mut sc_pkcs15_auth_info);

pub fn sc_pkcs15_free_object(obj: *mut sc_pkcs15_object);

/* Generic file i/o */
pub fn sc_pkcs15_read_file(p15card : *mut sc_pkcs15_card, path: *const sc_path, buf: *mut *mut c_uchar,
                           buflen: *mut usize) -> c_int;

/* Caching functions */
pub fn sc_pkcs15_read_cached_file(p15card: *mut sc_pkcs15_card, path: *const sc_path, buf: *mut *mut c_uchar,
                                  bufsize: *mut usize) -> c_int;

pub fn sc_pkcs15_cache_file(p15card: *mut sc_pkcs15_card, path: *const sc_path, buf: *const c_uchar,
                            bufsize: usize) -> c_int;

/* PKCS #15 ID handling functions */
pub fn sc_pkcs15_compare_id(id1: *const sc_pkcs15_id, id2: *const sc_pkcs15_id) -> c_int;

pub fn sc_pkcs15_print_id(id: *const sc_pkcs15_id) -> *const c_char;

pub fn sc_pkcs15_format_id(id_in: *const c_char, id_out: *mut sc_pkcs15_id);

pub fn sc_pkcs15_hex_string_to_id(in_: *const c_char, out: *mut sc_pkcs15_id) -> c_int;

/// malloc involved
pub fn sc_der_copy(dst: *mut sc_pkcs15_der, src: *const sc_pkcs15_der) -> c_int;

pub fn sc_pkcs15_get_object_id(arg1: *const sc_pkcs15_object, arg2: *mut sc_pkcs15_id) -> c_int;

pub fn sc_pkcs15_get_object_guid(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object, arg3: c_uint,
                                 arg4: *mut c_uchar, arg5: *mut usize) -> c_int;

pub fn sc_pkcs15_serialize_guid(arg1: *mut c_uchar, arg2: usize, arg3: c_uint, arg4: *mut c_char, arg5: usize) -> c_int;

pub fn sc_encode_oid(arg1: *mut sc_context, arg2: *mut sc_object_id, arg3: *mut *mut c_uchar, arg4: *mut usize) -> c_int;

/* Get application by type: 'protected', 'generic' */
pub fn sc_pkcs15_get_application_by_type(card: *mut sc_card, arg2: *mut c_char) -> *mut sc_app_info;

/* Prepend 'parent' to 'child' in case 'child' is a relative path */
pub fn sc_pkcs15_make_absolute_path(parent: *const sc_path, child: *mut sc_path) -> c_int;

/* Clean and free object content */
fn sc_pkcs15_free_object_content(arg1: *mut sc_pkcs15_object);

/* Allocate and set object content */
fn sc_pkcs15_allocate_object_content(arg1: *mut sc_context, arg2: *mut sc_pkcs15_object, arg3: *const c_uchar,
                                         arg4: usize) -> c_int;

/* find algorithm from card's supported algorithms by operation and mechanism */
fn sc_pkcs15_get_supported_algo(p15card: *mut sc_pkcs15_card, operation: c_uint, mechanism: c_uint)
    -> *mut sc_supported_algo_info;

/* find algorithm from card's supported algorithms by operation, mechanism and object_id */
fn sc_pkcs15_get_specific_supported_algo(p15card: *mut sc_pkcs15_card,
                                         operation: c_uint, mechanism: c_uint, algo_oid: *const sc_object_id)
    -> *mut sc_supported_algo_info;

fn sc_pkcs15_add_supported_algo_ref(arg1: *mut sc_pkcs15_object, arg2: *mut sc_supported_algo_info) -> c_int;

pub fn sc_pkcs15_fix_ec_parameters(arg1: *mut sc_context, arg2: *mut sc_ec_parameters) -> c_int;

/* Convert the OpenSSL key data type into the OpenSC key */
fn sc_pkcs15_convert_bignum(dst: *mut sc_pkcs15_bignum, bignum: *const c_void) -> c_int;

pub fn sc_pkcs15_convert_prkey(key: *mut sc_pkcs15_prkey, evp_key: *mut c_void) -> c_int;

pub fn sc_pkcs15_convert_pubkey(key: *mut sc_pkcs15_pubkey, evp_key: *mut c_void) -> c_int;

/* Get 'LastUpdate' string */
pub fn sc_pkcs15_get_lastupdate(p15card: *mut sc_pkcs15_card) -> *mut c_char;

/* Allocate generalized time string */
fn sc_pkcs15_get_generalized_time(ctx: *mut sc_context, out: *mut *mut c_char) -> c_int;
}

/* New object search API.
 * More complex, but also more powerful.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15_search_key {
    pub class_mask : c_uint,
    pub type_ : c_uint,
    pub id : *const sc_pkcs15_id,
    pub app_oid : *const sc_object_id,
    pub path : *const sc_path,
    pub usage_mask : c_uint,
    pub usage_value : c_uint,
    pub flags_mask : c_uint,
    pub flags_value : c_uint,

    pub match_reference : c_uint, // unsigned int match_reference : 1;  bit field declaration; only values 0 and 1 allowed
    pub reference : c_int,
    pub app_label : *const c_char,
    pub label : *const c_char,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15_search_key_t = sc_pkcs15_search_key;
*/

extern "C" { pub fn sc_pkcs15_search_objects(arg1: *mut sc_pkcs15_card, arg2: *mut sc_pkcs15_search_key,
                                             arg3: *mut *mut sc_pkcs15_object, arg4: usize) -> c_int; }

/* This structure is passed to the new sc_pkcs15emu_*_init functions */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
pub struct sc_pkcs15emu_opt {
    pub blk : *mut scconf_block,
    pub flags : c_uint,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_pkcs15emu_opt_t = sc_pkcs15emu_opt;
*/

#[cfg(any(v0_17_0, v0_18_0, v0_19_0))]
pub const SC_PKCS15EMU_FLAGS_NO_CHECK : u32 =   0x00000001;

extern "C" {
pub fn sc_pkcs15_bind_synthetic(p15card: *mut sc_pkcs15_card, aid: *mut sc_aid) -> c_int;
pub fn sc_pkcs15_is_emulation_only(card: *mut sc_card) -> c_int;
pub fn sc_pkcs15emu_object_add(p15card: *mut sc_pkcs15_card, arg2: c_uint, arg3: *const sc_pkcs15_object,
                               arg4: *const c_void) -> c_int;

/* some wrapper functions for sc_pkcs15emu_object_add */
pub fn sc_pkcs15emu_add_pin_obj(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                arg3: *const sc_pkcs15_auth_info) -> c_int;
pub fn sc_pkcs15emu_add_rsa_prkey(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                  arg3: *const sc_pkcs15_prkey_info) -> c_int;
pub fn sc_pkcs15emu_add_rsa_pubkey(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                   arg3: *const sc_pkcs15_pubkey_info) -> c_int;
pub fn sc_pkcs15emu_add_ec_prkey(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                 arg3: *const sc_pkcs15_prkey_info) -> c_int;
pub fn sc_pkcs15emu_add_ec_pubkey(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                  arg3: *const sc_pkcs15_pubkey_info) -> c_int;
pub fn sc_pkcs15emu_add_x509_cert(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                  arg3: *const sc_pkcs15_cert_info) -> c_int;
pub fn sc_pkcs15emu_add_data_object(p15card: *mut sc_pkcs15_card, arg2: *const sc_pkcs15_object,
                                    arg3: *const sc_pkcs15_data_info) -> c_int;
}
