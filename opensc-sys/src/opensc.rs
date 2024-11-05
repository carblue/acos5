/*
 * opensc.h: OpenSC library header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file src/libopensc/opensc.h
 * OpenSC library core header file
 */

/*
#ifdef ENABLE_SM
#include "libopensc/sm.h"
#endif

#if defined(_WIN32) && !(defined(__MINGW32__) && defined (__MINGW_PRINTF_FORMAT))
#define SC_FORMAT_LEN_SIZE_T "I"
#define SC_FORMAT_LEN_PTRDIFF_T "I"
#else
/* hope SUSv3 ones work */
#define SC_FORMAT_LEN_SIZE_T "z"
#define SC_FORMAT_LEN_PTRDIFF_T "t"
#endif
*/

use libc::FILE;

use std::os::raw::{c_char, c_ulong, c_void};
#[cfg(impl_default)]
use std::ptr::{null, null_mut};

use crate::types::{sc_apdu, sc_path, sc_file, sc_acl_entry, sc_object_id, sc_lv_data, sc_aid, sc_ddo, sc_atr,
                   sc_serial_number, sc_version, sc_remote_data, sc_uid,
                   SC_MAX_SUPPORTED_ALGORITHMS, SC_MAX_CARD_APPS, SC_MAX_CARD_DRIVERS};
#[cfg(v0_20_0)]
use crate::types::SC_MAX_SDO_ACLS;
use crate::scconf::{scconf_context, scconf_block};
use crate::internal::sc_atr_table;
use crate::sm::sm_context;
use crate::simclist::list_t;
#[cfg(impl_default)]
use crate::simclist::list_attributes_s;

/*
   WARNING
   The OpenSC API exhibits a lot of inconsistencies referring to types
   E.g. SC_SEC_OPERATION_* all have positive values, but the main usage field sc_security_env.operation is typed i32,
   that's why that group of constants (all originating from #define) is typed here i32 as well

   All other pub const (except SC_PIN_STATE_*) are typed either u32 or usize
   (usize only, if they appear preferrably as array size or preferrably are used as usize)

   flags are often but not always used as c_ulong in functions, but never the value exceeds u32.max
*/
pub const SC_SEC_OPERATION_DECIPHER     : i32 = 0x0001;
pub const SC_SEC_OPERATION_SIGN         : i32 = 0x0002;
pub const SC_SEC_OPERATION_AUTHENTICATE : i32 = 0x0003;
pub const SC_SEC_OPERATION_DERIVE       : i32 = 0x0004;
pub const SC_SEC_OPERATION_WRAP         : i32 = 0x0005;
pub const SC_SEC_OPERATION_UNWRAP       : i32 = 0x0006;
cfg_if::cfg_if! {
    if #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))] {
        pub const SC_SEC_OPERATION_ENCRYPT_SYM  : i32 = 0x0007;
        pub const SC_SEC_OPERATION_DECRYPT_SYM  : i32 = 0x0008;
    }
}

/* sc_security_env flags */
pub const SC_SEC_ENV_ALG_REF_PRESENT         : c_ulong = 0x0001;
pub const SC_SEC_ENV_FILE_REF_PRESENT        : c_ulong = 0x0002;
pub const SC_SEC_ENV_KEY_REF_PRESENT         : c_ulong = 0x0004;
pub const SC_SEC_ENV_KEY_REF_SYMMETRIC       : c_ulong = 0x0008; // when will this be used?
pub const SC_SEC_ENV_ALG_PRESENT             : c_ulong = 0x0010;
pub const SC_SEC_ENV_TARGET_FILE_REF_PRESENT : c_ulong = 0x0020;  /* unused */

/* sc_security_env additional parameters */
pub const SC_SEC_ENV_MAX_PARAMS              : usize = 10;
pub const SC_SEC_ENV_PARAM_IV                : u32 = 1;
pub const SC_SEC_ENV_PARAM_TARGET_FILE       : u32 = 2;       /* unused */

//pub const SC_SEC_ENV_PARAM_DES_ECB           : u32 = 3;
//pub const SC_SEC_ENV_PARAM_DES_CBC           : u32 = 4;

/* PK algorithms */
cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
    pub const SC_ALGORITHM_RSA       : u32 = 0;
    #[cfg(any(v0_20_0, v0_21_0, v0_22_0))]
    pub const SC_ALGORITHM_DSA       : u32 = 1;
    pub const SC_ALGORITHM_EC        : u32 = 2;
    pub const SC_ALGORITHM_GOSTR3410 : u32 = 3;
    pub const SC_ALGORITHM_EDDSA     : u32 = 4;
    pub const SC_ALGORITHM_XEDDSA    : u32 = 5;

    /* Symmetric algorithms */
    pub const SC_ALGORITHM_DES       : u32 = 64;
    pub const SC_ALGORITHM_3DES      : u32 = 65;
    pub const SC_ALGORITHM_GOST      : u32 = 66;
    pub const SC_ALGORITHM_AES       : u32 = 67;
    pub const SC_ALGORITHM_UNDEFINED : u32 = 68;    /* used with CKK_GENERIC_SECRET type keys */

    /* Hash algorithms */
    pub const SC_ALGORITHM_MD5       : u32 = 128;
    pub const SC_ALGORITHM_SHA1      : u32 = 129;
    pub const SC_ALGORITHM_GOSTR3411 : u32 = 130;
}
else {
    pub const SC_ALGORITHM_RSA       : c_ulong = 0;
    pub const SC_ALGORITHM_EC        : c_ulong = 2;
    pub const SC_ALGORITHM_GOSTR3410 : c_ulong = 3;
    pub const SC_ALGORITHM_EDDSA     : c_ulong = 4;
    pub const SC_ALGORITHM_XEDDSA    : c_ulong = 5;

    /* Symmetric algorithms */
    pub const SC_ALGORITHM_DES       : c_ulong = 64;
    pub const SC_ALGORITHM_3DES      : c_ulong = 65;
    pub const SC_ALGORITHM_GOST      : c_ulong = 66;
    pub const SC_ALGORITHM_AES       : c_ulong = 67;
    pub const SC_ALGORITHM_UNDEFINED : c_ulong = 68;    /* used with CKK_GENERIC_SECRET type keys */

    /* Hash algorithms */
    pub const SC_ALGORITHM_MD5       : c_ulong = 128;
    pub const SC_ALGORITHM_SHA1      : c_ulong = 129;
    pub const SC_ALGORITHM_GOSTR3411 : c_ulong = 130;
}}

/* Key derivation algorithms */
pub const SC_ALGORITHM_PBKDF2    : u32 = 192;

/* Key encryption algorithms */
pub const SC_ALGORITHM_PBES2     : u32 = 256;

/* Question: Does this refer to RSA only or to any key type ? */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_ONBOARD_KEY_GEN : u32     = 0x8000_0000;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_ONBOARD_KEY_GEN : c_ulong = 0x8000_0000;
/* need usage = either sign or decrypt. keys with both? decrypt, emulate sign */
pub const SC_ALGORITHM_NEED_USAGE      : u32 = 0x4000_0000;
pub const SC_ALGORITHM_SPECIFIC_FLAGS  : u32 = 0x001F_FFFF;

/*look at libopensc/padding.c: sc_get_encoding_flags/sc_pkcs1_encode, how these flags are processed */

/* If the card is willing to produce a cryptogram padded with the following
 * methods, set these flags accordingly.  These flags are exclusive: an RSA card
 * must support at least one of them, and exactly one of them must be selected
 * for a given operation. */
/** Use SC_ALGORITHM_RSA_RAW, if card/driver expects an in_len to card.ops.compute_signature == RSA_modulus_length bytes,
    i.e. won't pad itself before signing; for versions since 0.20.0, switch to using SC_ALGORITHM_RSA_PAD_NONE for that purpose\
    TODO find the code locations where in_len!=outlen
*/
#[cfg(any(    v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_RSA_RAW         : u32 = 0x0000_0001;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_RSA_RAW         : c_ulong = 0x0000_0001;

cfg_if::cfg_if! {
if #[cfg(v0_20_0)] {
    pub const SC_ALGORITHM_RSA_PADS : u32 = 0x0000_001F; // this is WITH SC_ALGORITHM_RSA_PAD_NONE
}
else if #[cfg(any(v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
    pub const SC_ALGORITHM_RSA_PADS : u32 = 0x0000_003F; // this is WITH SC_ALGORITHM_RSA_PAD_NONE
}
else /* v0_25_0 */ {
    pub const SC_ALGORITHM_RSA_PADS : u32 = 0x0000_00FF; // this is WITH SC_ALGORITHM_RSA_PAD_NONE
}}

cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
    /* Use SC_ALGORITHM_RSA_PAD_NONE, if card/driver expects an in_len to card.ops.compute_signature == RSA_modulus_length bytes,
    i.e. card/driver won't pad before signing */
pub const SC_ALGORITHM_RSA_PAD_NONE : u32 = 0x0000_0001; // SC_ALGORITHM_RSA_RAW

    /** Use SC_ALGORITHM_RSA_PAD_PKCS1, if card/driver expects as input to card.ops.compute_signature: EMSA-PKCS1-v1_5 DigestInfo\
     https://tools.ietf.org/html/rfc8017#page-62\
     Not OpenSC, but the card/driver will pad according to EMSA-PKCS1-v1_5; EMSA = Encoding Method for Signature with Appendix
     before signing */
pub const SC_ALGORITHM_RSA_PAD_ANSI    : u32 = 0x0000_0004;
pub const SC_ALGORITHM_RSA_PAD_ISO9796 : u32 = 0x0000_0008;
pub const SC_ALGORITHM_RSA_PAD_PSS     : u32 = 0x0000_0010; /* PKCS#1 v2.0 PSS */
#[cfg(not(v0_20_0))]
pub const SC_ALGORITHM_RSA_PAD_OAEP    : u32 = 0x0000_0020; /* PKCS#1 v2.0 OAEP */
    pub const SC_ALGORITHM_RSA_PAD_PKCS1   : u32 = 0x0000_0002; /* PKCS#1 v1.5 padding */
}
else {
/* Use SC_ALGORITHM_RSA_PAD_NONE, if card/driver expects an in_len to card.ops.compute_signature == RSA_modulus_length bytes,
    i.e. card/driver won't pad before signing */
pub const SC_ALGORITHM_RSA_PAD_NONE : u32 = 0x0000_0001; // SC_ALGORITHM_RSA_RAW

/** Use SC_ALGORITHM_RSA_PAD_PKCS1, if card/driver expects as input to card.ops.compute_signature: EMSA-PKCS1-v1_5 DigestInfo\
   <https://tools.ietf.org/html/rfc8017#page-62>
   Not OpenSC, but the card/driver will pad according to EMSA-PKCS1-v1_5; EMSA = Encoding Method for Signature with Appendix
   before signing */
pub const SC_ALGORITHM_RSA_PAD_ANSI    : c_ulong = 0x0000_0004;
pub const SC_ALGORITHM_RSA_PAD_ISO9796 : c_ulong = 0x0000_0008;
pub const SC_ALGORITHM_RSA_PAD_PSS     : c_ulong = 0x0000_0010; /* PKCS#1 v2.0 PSS */
pub const SC_ALGORITHM_RSA_PAD_OAEP    : c_ulong = 0x0000_0020; /* PKCS#1 v2.0 OAEP */
pub const SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01  : c_ulong = 0x0000_0040; /* PKCS#1 v1.5 padding type 1 */
pub const SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02  : c_ulong = 0x0000_0080; /* PKCS#1 v1.5 padding type 2 */
pub const SC_ALGORITHM_RSA_PAD_PKCS1	      : c_ulong = SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_01 | SC_ALGORITHM_RSA_PAD_PKCS1_TYPE_02; /* PKCS#1 v1.5 (type 1 or 2) */
}}
/* If the card is willing to produce a cryptogram with the following
 * hash values, set these flags accordingly.  The interpretation of the hash
 * flags depends on the algorithm and padding chosen: for RSA, the hash flags
 * determine how the padding is constructed and do not describe the first
 * hash applied to the document before padding begins.
 *
 *   - For PAD_NONE, ANSI X9.31, (and ISO9796?), the hash value is therefore
 *     ignored.  For ANSI X9.31, the input data must already have the hash
 *     identifier byte appended (eg 0x33 for SHA-1).
 *   - For PKCS1 (v1.5) the hash is recorded in the padding, and HASH_NONE is a
 *     valid value, meaning that the hash's DigestInfo has already been
 *     prepended to the data, otherwise the hash id is put on the front.
 *   - For PSS (PKCS#1 v2.0) the hash is used to derive the padding from the
 *     already-hashed message.
 *
 * In no case is the hash actually applied to the entire document.
 *
 * It's possible that the card may support different hashes for PKCS1 and PSS
 * signatures; in this case the card driver has to pick the lowest-denominator
 * when it sets these flags to indicate its capabilities. */
cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
pub const SC_ALGORITHM_RSA_HASH_NONE      : u32 = 0x0000_0100; /* only applies to PKCS1 padding */
pub const SC_ALGORITHM_RSA_HASH_SHA1      : u32 = 0x0000_0200;
pub const SC_ALGORITHM_RSA_HASH_MD5       : u32 = 0x0000_0400;
pub const SC_ALGORITHM_RSA_HASH_MD5_SHA1  : u32 = 0x0000_0800;
pub const SC_ALGORITHM_RSA_HASH_RIPEMD160 : u32 = 0x0000_1000;
pub const SC_ALGORITHM_RSA_HASH_SHA256    : u32 = 0x0000_2000;
pub const SC_ALGORITHM_RSA_HASH_SHA384    : u32 = 0x0000_4000;
pub const SC_ALGORITHM_RSA_HASH_SHA512    : u32 = 0x0000_8000;
pub const SC_ALGORITHM_RSA_HASH_SHA224    : u32 = 0x0001_0000;
pub const SC_ALGORITHM_RSA_HASHES      : u32 = 0x0001_FF00; // this is WITH SC_ALGORITHM_RSA_HASH_NONE
}
else {
pub const SC_ALGORITHM_RSA_HASH_NONE  : c_ulong = 0x0000_0100; /* only applies to PKCS1 padding */
pub const SC_ALGORITHM_RSA_HASH_SHA1      : c_ulong = 0x0000_0200;
pub const SC_ALGORITHM_RSA_HASH_MD5       : c_ulong = 0x0000_0400;
pub const SC_ALGORITHM_RSA_HASH_MD5_SHA1  : c_ulong = 0x0000_0800;
pub const SC_ALGORITHM_RSA_HASH_RIPEMD160 : c_ulong = 0x0000_1000;
pub const SC_ALGORITHM_RSA_HASH_SHA256    : c_ulong = 0x0000_2000;
pub const SC_ALGORITHM_RSA_HASH_SHA384    : c_ulong = 0x0000_4000;
pub const SC_ALGORITHM_RSA_HASH_SHA512    : c_ulong = 0x0000_8000;
pub const SC_ALGORITHM_RSA_HASH_SHA224    : c_ulong = 0x0001_0000;
pub const SC_ALGORITHM_RSA_HASHES      : c_ulong = 0x0001_FF00; // this is WITH SC_ALGORITHM_RSA_HASH_NONE
}}

/* This defines the hashes to be used with MGF1 in PSS padding */ // since v0_20_0
pub const SC_ALGORITHM_MGF1_SHA1       : u32 = 0x0010_0000;
pub const SC_ALGORITHM_MGF1_SHA256     : u32 = 0x0020_0000;
pub const SC_ALGORITHM_MGF1_SHA384     : u32 = 0x0040_0000;
pub const SC_ALGORITHM_MGF1_SHA512     : u32 = 0x0080_0000;
pub const SC_ALGORITHM_MGF1_SHA224     : u32 = 0x0100_0000;
pub const SC_ALGORITHM_MGF1_HASHES     : u32 = 0x01F0_0000;

/* These flags are exclusive: a GOST R34.10 card must support at least one or the
 * other of the methods, and exactly one of them applies to any given operation.
 * Note that the GOST R34.11 hash is actually applied to the data (ie if this
 * algorithm is chosen the entire unhashed document is passed in). */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_GOSTR3410_RAW   : u32 = 0x0002_0000;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_GOSTR3410_RAW   : c_ulong = 0x0002_0000;

#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_GOSTR3410_HASH_NONE : u32     = SC_ALGORITHM_GOSTR3410_RAW; /*XXX*/
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_GOSTR3410_HASH_NONE : c_ulong = SC_ALGORITHM_GOSTR3410_RAW; /*XXX*/

pub const SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411 : u32 = 0x0008_0000;

pub const SC_ALGORITHM_GOSTR3410_HASHES    : u32 = 0x000A_0000;
/*TODO: -DEE Should the above be 0x000E0000 */
/* Or should the HASH_NONE be 0x00000100  and HASHES be 0x00080010 */

/* The ECDSA flags are exclusive, and exactly one of them applies to any given
 * operation.  If ECDSA with a hash is specified, then the data passed in is
 * the entire document, unhashed, and the hash is applied once to it before
 * truncating and signing.  These flags are distinct from the RSA hash flags,
 * which determine the hash ids the card is willing to put in RSA message
 * padding. */
/* May need more bits if card can do more hashes */
/* TODO: -DEE Will overload RSA_HASHES with EC_HASHES */
/* Not clear if these need their own bits or not */
/* The PIV card does not support and hashes */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_ECDH_CDH_RAW        : u32 = 0x0020_0000;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_ECDH_CDH_RAW        : c_ulong = 0x0020_0000;
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_ECDSA_RAW           : u32 = 0x0010_0000;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_ECDSA_RAW           : c_ulong = 0x0010_0000;
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_ECDSA_HASH_NONE     : u32 = SC_ALGORITHM_RSA_HASH_NONE;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_ECDSA_HASH_NONE : c_ulong = SC_ALGORITHM_RSA_HASH_NONE;
cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
pub const SC_ALGORITHM_ECDSA_HASH_SHA1     : u32 = SC_ALGORITHM_RSA_HASH_SHA1;
pub const SC_ALGORITHM_ECDSA_HASH_SHA224   : u32 = SC_ALGORITHM_RSA_HASH_SHA224;
pub const SC_ALGORITHM_ECDSA_HASH_SHA256   : u32 = SC_ALGORITHM_RSA_HASH_SHA256;
pub const SC_ALGORITHM_ECDSA_HASH_SHA384   : u32 = SC_ALGORITHM_RSA_HASH_SHA384;
pub const SC_ALGORITHM_ECDSA_HASH_SHA512   : u32 = SC_ALGORITHM_RSA_HASH_SHA512;
pub const SC_ALGORITHM_ECDSA_HASHES        : u32 = SC_ALGORITHM_ECDSA_HASH_SHA1 |
                                                   SC_ALGORITHM_ECDSA_HASH_SHA224 |
                                                   SC_ALGORITHM_ECDSA_HASH_SHA256 |
                                                   SC_ALGORITHM_ECDSA_HASH_SHA384 |
                                                   SC_ALGORITHM_ECDSA_HASH_SHA512;
}
else {
pub const SC_ALGORITHM_ECDSA_HASH_SHA1   : c_ulong = SC_ALGORITHM_RSA_HASH_SHA1;
pub const SC_ALGORITHM_ECDSA_HASH_SHA224 : c_ulong = SC_ALGORITHM_RSA_HASH_SHA224;
pub const SC_ALGORITHM_ECDSA_HASH_SHA256 : c_ulong = SC_ALGORITHM_RSA_HASH_SHA256;
pub const SC_ALGORITHM_ECDSA_HASH_SHA384 : c_ulong = SC_ALGORITHM_RSA_HASH_SHA384;
pub const SC_ALGORITHM_ECDSA_HASH_SHA512 : c_ulong = SC_ALGORITHM_RSA_HASH_SHA512;
pub const SC_ALGORITHM_ECDSA_HASHES      : c_ulong = SC_ALGORITHM_ECDSA_HASH_SHA1 |
                                                     SC_ALGORITHM_ECDSA_HASH_SHA224 |
                                                     SC_ALGORITHM_ECDSA_HASH_SHA256 |
                                                     SC_ALGORITHM_ECDSA_HASH_SHA384 |
                                                     SC_ALGORITHM_ECDSA_HASH_SHA512;
}
}
/* EdDSA algorithms */
pub const SC_ALGORITHM_EDDSA_RAW           : u32 = 0x0040_0000;
pub const SC_ALGORITHM_XEDDSA_RAW          : u32 = 0x0080_0000;

/* define mask of all algorithms that can do raw */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub const SC_ALGORITHM_RAW_MASK            : u32 = SC_ALGORITHM_RSA_RAW |
                                                   SC_ALGORITHM_GOSTR3410_RAW |
                                                   SC_ALGORITHM_ECDH_CDH_RAW |
                                                   SC_ALGORITHM_ECDSA_RAW;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub const SC_ALGORITHM_RAW_MASK        : c_ulong = SC_ALGORITHM_RSA_RAW |
                                                   SC_ALGORITHM_GOSTR3410_RAW |
                                                   SC_ALGORITHM_ECDH_CDH_RAW |
                                                   SC_ALGORITHM_ECDSA_RAW;

/* extended algorithm bits for selected mechs */
cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
pub const SC_ALGORITHM_EXT_EC_F_P          : u32     = 0x0000_0001;
pub const SC_ALGORITHM_EXT_EC_F_2M         : u32     = 0x0000_0002;
pub const SC_ALGORITHM_EXT_EC_ECPARAMETERS : u32     = 0x0000_0004;
pub const SC_ALGORITHM_EXT_EC_NAMEDCURVE   : u32     = 0x0000_0008;
pub const SC_ALGORITHM_EXT_EC_UNCOMPRESES  : u32     = 0x0000_0010;
pub const SC_ALGORITHM_EXT_EC_COMPRESS     : u32     = 0x0000_0020;
}
else {
pub const SC_ALGORITHM_EXT_EC_F_P          : c_ulong = 0x0000_0001;
pub const SC_ALGORITHM_EXT_EC_F_2M         : c_ulong = 0x0000_0002;
pub const SC_ALGORITHM_EXT_EC_ECPARAMETERS : c_ulong = 0x0000_0004;
pub const SC_ALGORITHM_EXT_EC_NAMEDCURVE   : c_ulong = 0x0000_0008;
pub const SC_ALGORITHM_EXT_EC_UNCOMPRESES  : c_ulong = 0x0000_0010;
pub const SC_ALGORITHM_EXT_EC_COMPRESS     : c_ulong = 0x0000_0020;
}}
/* symmetric algorithm flags. More algorithms to be added when implemented. */
cfg_if::cfg_if! {
if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
pub const SC_ALGORITHM_AES_ECB     : u32     = 0x0100_0000;
pub const SC_ALGORITHM_AES_CBC     : u32     = 0x0200_0000;
pub const SC_ALGORITHM_AES_CBC_PAD : u32     = 0x0400_0000;
pub const SC_ALGORITHM_AES_FLAGS   : u32     = 0x0F00_0000;
}
else {
pub const SC_ALGORITHM_AES_ECB     : c_ulong = 0x0100_0000;
pub const SC_ALGORITHM_AES_CBC     : c_ulong = 0x0200_0000;
pub const SC_ALGORITHM_AES_CBC_PAD : c_ulong = 0x0400_0000;
pub const SC_ALGORITHM_AES_FLAGS   : c_ulong = 0x0F00_0000;
}}

/* Event masks for sc_wait_for_event() */
pub const SC_EVENT_CARD_INSERTED   : u32 = 0x0001;
pub const SC_EVENT_CARD_REMOVED    : u32 = 0x0002;
pub const SC_EVENT_CARD_EVENTS     : u32 = SC_EVENT_CARD_INSERTED | SC_EVENT_CARD_REMOVED;
pub const SC_EVENT_READER_ATTACHED : u32 = 0x0004;
pub const SC_EVENT_READER_DETACHED : u32 = 0x0008;
pub const SC_EVENT_READER_EVENTS   : u32 = SC_EVENT_READER_ATTACHED | SC_EVENT_READER_DETACHED;

pub const MAX_FILE_SIZE : usize = 65535; // since v0_20_0

#[repr(C)]
#[derive(/*Default, not possible for v0_20_0 */ Debug, Copy, Clone)]
pub struct sc_supported_algo_info {
    pub reference : u32,   /* a unique reference that is used for cross-reference purposes from PrKDFs and PuKDFs */
    pub mechanism : u32,   /* CKM_* */
    #[cfg(v0_20_0)]
    pub parameters : *mut sc_object_id, /* OID for ECC, NULL for RSA */  // since opensc source release v0.18.0
    #[cfg(not(v0_20_0))]
    pub parameters : sc_object_id, /* OID for ECC */  // since opensc source release v0.21.0
    pub operations : u32, /* identifies operations the card can perform with a particular mechanism */
    pub algo_id : sc_object_id,
    pub algo_ref : u32,  /* indicates the identifier used by the card for denoting this algorithm */
}

#[cfg(impl_default)]
#[allow(clippy::derivable_impls)]
impl Default for sc_supported_algo_info {
    fn default() -> Self {
        Self {
            reference: 0,
            mechanism: 0,
            #[cfg(v0_20_0)]
            parameters: null_mut(), /* OID for ECC, NULL for RSA */  // since opensc source release v0.18.0
            #[cfg(not(v0_20_0))]
            parameters: sc_object_id::default(), /* OID for ECC */  // since opensc source release v0.21.0
            operations: 0,
            algo_id: sc_object_id::default(),
            algo_ref: 0,
        }
    }
}

/// except in struct sc_security_env, unused currently
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_sec_env_param {
    pub param_type : u32,   /* e.g. SC_SEC_ENV_PARAM_IV */
    pub value : *mut c_void,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub value_len  : u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub value_len  : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_sec_env_param_t = sc_sec_env_param;
*/

#[cfg(impl_default)]
impl Default for sc_sec_env_param {
    fn default() -> Self {
        Self {
            param_type: 0,
            value: null_mut(),
            value_len: 0
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_security_env {
    pub flags           : c_ulong,    /* e.g. SC_SEC_ENV_KEY_REF_SYMMETRIC, ... */
    pub operation       : i32,      /* SC_SEC_OPERATION */
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub algorithm       : u32,  /* if used, set flag SC_SEC_ENV_ALG_PRESENT */
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub algorithm       : c_ulong,  /* if used, set flag SC_SEC_ENV_ALG_PRESENT */
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub algorithm_flags : u32,  /* e.g. SC_ALGORITHM_RSA_RAW  or SC_ALGORITHM_AES_CBC_PAD */
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub algorithm_flags : c_ulong,  /* e.g. SC_ALGORITHM_RSA_RAW  or SC_ALGORITHM_AES_CBC_PAD */

    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1)))]
    pub key_size_bits : usize,

    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub algorithm_ref   : u32,  /* if used, set flag SC_SEC_ENV_ALG_REF_PRESENT */
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub algorithm_ref   : c_ulong,  /* if used, set flag SC_SEC_ENV_ALG_REF_PRESENT */

    pub file_ref        : sc_path,    /* if used, set flag SC_SEC_ENV_FILE_REF_PRESENT */
    pub key_ref : [u8; 8],  /* if used, set flag SC_SEC_ENV_KEY_REF_PRESENT */
    pub key_ref_len : usize,
    pub target_file_ref : sc_path,    /* unused;  target key file in unwrap operation; if used, set flag SC_SEC_ENV_TARGET_FILE_REF_PRESENT */

    pub supported_algos : [sc_supported_algo_info; SC_MAX_SUPPORTED_ALGORITHMS],
    /* optional parameters */
    pub params :          [sc_sec_env_param; SC_SEC_ENV_MAX_PARAMS],
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_security_env_t = sc_security_env;
*/

#[cfg(impl_default)]
impl Default for sc_security_env {
    fn default() -> Self {
        Self {
            flags: 0,
            operation: 0,
            algorithm: 0,
            algorithm_flags: 0,
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1)))]
            key_size_bits: 0,
            algorithm_ref: 0,
            file_ref: sc_path::default(),
            key_ref: [0; 8],
            key_ref_len: 0,
            target_file_ref : sc_path::default(),
            supported_algos: [sc_supported_algo_info::default(); SC_MAX_SUPPORTED_ALGORITHMS],
            params : [sc_sec_env_param::default(); SC_SEC_ENV_MAX_PARAMS],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_algorithm_id {
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub algorithm : u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub algorithm : c_ulong,
    pub oid : sc_object_id,
    pub params : *mut c_void,
}

#[cfg(impl_default)]
impl Default for sc_algorithm_id {
    fn default() -> Self {
        Self {
            algorithm: 0,
            oid: sc_object_id::default(),
            params: null_mut()
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pbkdf2_params {
    pub salt : [u8; 16],
    pub salt_len : usize,
    pub iterations : i32,
    pub key_length : usize,
    pub hash_alg : sc_algorithm_id,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pbes2_params {
    pub derivation_alg : sc_algorithm_id,
    pub key_encr_alg   : sc_algorithm_id,
}

/*
 * The ecParameters can be presented as
 * - name of curve;
 * - OID of named curve;
 * - implicit parameters.
 *
 * type - type(choice) of 'EC domain parameters' as it present in CKA_EC_PARAMS (PKCS#11).
          Recommended value '1' -- namedCurve.
 * field_length - EC key size in bits.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_ec_parameters {
    pub named_curve : *mut c_char,
    pub id : sc_object_id,
    pub der : sc_lv_data,

    pub type_ : i32,
    pub field_length : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_algorithm_info__union_sc_rsa_info {
    pub exponent : c_ulong,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_algorithm_info__union_sc_ec_info {
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub ext_flags : u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub ext_flags : c_ulong,
    pub params : sc_ec_parameters,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_algorithm_info__union {
    pub rsa : sc_algorithm_info__union_sc_rsa_info,
    pub ec  : sc_algorithm_info__union_sc_ec_info,
//    _bindgen_union_align : [u64 ; 14usize],
}

#[cfg(acos5_impl_default)]
impl Default for sc_algorithm_info__union {
    fn default() -> Self {
        Self {
            rsa : sc_algorithm_info__union_sc_rsa_info { exponent : 0x1_0001 },
        }
    }
}

#[repr(C)]
#[derive(Default, /*Debug,*/ Copy, Clone)]
pub struct sc_algorithm_info {
    pub algorithm  : u32,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub key_length : u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub key_length : usize,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub flags      : u32,    /* e.g. SC_ALGORITHM_RSA_RAW  or SC_ALGORITHM_AES_CBC_PAD, see struct sc_security_env, field algorithm_flags */
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub flags      : c_ulong,    /* e.g. SC_ALGORITHM_RSA_RAW  or SC_ALGORITHM_AES_CBC_PAD, see struct sc_security_env, field algorithm_flags */

    pub u : sc_algorithm_info__union,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_algorithm_info_t = sc_algorithm_info;
*/
/*
#[cfg(acos5_impl_default)]
#[cfg(impl_default)]
impl Default for sc_algorithm_info {
    fn default() -> Self {
        Self {
            algorithm: 0,
            key_length: 0,
            flags: 0,
            u: sc_algorithm_info__union::default()
        }
    }
}
*/
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_app_info {
    pub label : *mut c_char,

    pub aid : sc_aid,
    pub ddo : sc_ddo,

    pub path : sc_path,

    pub rec_nr : i32,  /* -1, if EF(DIR) is transparent */
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_app_info_t = sc_app_info;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_ef_atr {
    pub card_service : u8,
    pub df_selection : u8,
    pub unit_size : usize,
    pub card_capabilities : u8,
    pub max_command_apdu : usize,
    pub max_response_apdu : usize,

    pub aid : sc_aid,

    pub pre_issuing : [u8 ; 6],
    pub pre_issuing_len : usize,

    pub issuer_data : [u8 ; 16],
    pub issuer_data_len : usize,

    pub allocation_oid : sc_object_id,

    pub status : u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_card_cache {
    pub current_path : sc_path,
    pub current_ef : *mut sc_file,
    pub current_df : *mut sc_file,

    pub valid : i32,
}

pub const SC_PROTO_T0   : u32 = 0x0000_0001;
pub const SC_PROTO_T1   : u32 = 0x0000_0002;
pub const SC_PROTO_RAW  : u32 = 0x0000_1000;
pub const SC_PROTO_ANY  : u32 = 0xFFFF_FFFF;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_reader_driver {
    pub name : *const c_char,
    pub short_name : *const c_char,
    pub ops : *mut sc_reader_operations,

    pub dll : *mut c_void,
}

/* reader flags */
pub const SC_READER_CARD_PRESENT     : u32 = 0x0000_0001;
pub const SC_READER_CARD_CHANGED     : u32 = 0x0000_0002;
pub const SC_READER_CARD_INUSE       : u32 = 0x0000_0004;
pub const SC_READER_CARD_EXCLUSIVE   : u32 = 0x0000_0008;
pub const SC_READER_HAS_WAITING_AREA : u32 = 0x0000_0010;
pub const SC_READER_REMOVED          : u32 = 0x0000_0020;
pub const SC_READER_ENABLE_ESCAPE    : u32 = 0x0000_0040;

/* reader capabilities */
pub const SC_READER_CAP_DISPLAY              : u32 = 0x0000_0001;
pub const SC_READER_CAP_PIN_PAD              : u32 = 0x0000_0002;
pub const SC_READER_CAP_PACE_EID             : u32 = 0x0000_0004;
pub const SC_READER_CAP_PACE_ESIGN           : u32 = 0x0000_0008;
pub const SC_READER_CAP_PACE_DESTROY_CHANNEL : u32 = 0x0000_0010;
pub const SC_READER_CAP_PACE_GENERIC         : u32 = 0x0000_0020;

/* reader send/receive length of short APDU */
pub const SC_READER_SHORT_APDU_MAX_SEND_SIZE : usize = 255;
pub const SC_READER_SHORT_APDU_MAX_RECV_SIZE : usize = 256;

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_reader__atr_info {
    pub hist_bytes : *mut u8,
    pub hist_bytes_len : usize,
    pub Fi : i32,
    pub f : i32,
    pub Di : i32,
    pub N : i32,
    pub FI : u8,
    pub DI : u8,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_reader {
    pub ctx : *mut sc_context,
    pub driver : *const sc_reader_driver,
    pub ops : *const sc_reader_operations,
    pub drv_data : *mut c_void,
    pub name : *mut c_char,
    pub vendor : *mut c_char,     // since opensc source release v0.16.0
    pub version_major : u8,  // since opensc source release v0.16.0
    pub version_minor : u8,  // since opensc source release v0.16.0

    pub flags               : c_ulong,
    pub capabilities        : c_ulong,
    pub supported_protocols : u32,
    pub active_protocol     : u32,
    pub max_send_size : usize, /* Max Lc supported by the reader layer */
    pub max_recv_size : usize, /* Mac Le supported by the reader layer */

    pub atr : sc_atr,
    pub uid : sc_uid,                    // since opensc source release v0.17.0
    pub atr_info : sc_reader__atr_info,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_reader_t = sc_reader;
*/

/* This will be the new interface for handling PIN commands.
 * It is supposed to support pin pads (with or without display)
 * attached to the reader.
 */
pub const SC_PIN_CMD_VERIFY          : u32 = 0; // ins = 0x20;
pub const SC_PIN_CMD_CHANGE          : u32 = 1; // ins = 0x24;
pub const SC_PIN_CMD_UNBLOCK         : u32 = 2; // ins = 0x2C;
pub const SC_PIN_CMD_GET_INFO        : u32 = 3; // ins = 0x20;
pub const SC_PIN_CMD_GET_SESSION_PIN : u32 = 4;  // since opensc source release v0.17.0

/* flags */
pub const SC_PIN_CMD_USE_PINPAD      : u32 = 0x0001;
pub const SC_PIN_CMD_NEED_PADDING    : u32 = 0x0002;
pub const SC_PIN_CMD_IMPLICIT_CHANGE : u32 = 0x0004;

pub const SC_PIN_ENCODING_ASCII      : u32 = 0;
pub const SC_PIN_ENCODING_BCD        : u32 = 1;
pub const SC_PIN_ENCODING_GLP        : u32 = 2; /* Global Platform - Card Specification v2.0.1 */

/** Values for sc_pin_cmd_pin.logged_in */
pub const SC_PIN_STATE_UNKNOWN       : i32 = -1;    // since opensc source release v0.17.0
pub const SC_PIN_STATE_LOGGED_OUT    : i32 = 0;     // since opensc source release v0.17.0
pub const SC_PIN_STATE_LOGGED_IN     : i32 = 1;     // since opensc source release v0.17.0

/* A card driver receives the sc_pin_cmd_data and sc_pin_cmd_pin structures filled in by the
 * caller, with the exception of the fields returned by the driver for SC_PIN_CMD_GET_INFO.
 * It may use and update any of the fields before passing the structure to the ISO 7816 layer for
 * processing.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pin_cmd_pin {
    pub prompt : *const c_char, /* Prompt to display */

    pub data : *const u8, /* PIN, set to NULL when using pin pad */
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub len : i32, /* set to 0 when using pin pad */
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub len : usize, /* set to 0 when using pin pad */

    pub min_length    : usize, /* min length of PIN */
    pub max_length    : usize, /* max length of PIN */
    #[cfg(v0_20_0)]
    pub stored_length : usize, /* stored length of PIN */

    pub encoding : u32, /* ASCII-numeric, BCD, etc */

    pub pad_length : usize, /* PIN padding options, used with SC_PIN_CMD_NEED_PADDING */
    pub pad_char : u8,

    pub offset        : usize, /* PIN offset in the APDU when using pin pad */
    #[cfg(v0_20_0)]
    pub length_offset : usize, /* Effective PIN length offset in the APDU */

    pub max_tries  : i32, /* Used for signaling back from SC_PIN_CMD_GET_INFO; ACOS5: gets set in the pin record but is not retrievable */
    pub tries_left : i32, /* Used for signaling back from SC_PIN_CMD_GET_INFO  or if the command failed */
    pub logged_in : i32,  /* Used for signaling back from SC_PIN_CMD_GET_INFO, see SC_PIN_STATE_*; ACOS5: any other than ACOS5-64 V3.00: not retrievable */  // since opensc source release v0.17.0

    #[cfg(v0_20_0)]
    pub acls : [sc_acl_entry; SC_MAX_SDO_ACLS],
}

#[cfg(acos5_impl_default)]
impl Default for sc_pin_cmd_pin {
    fn default() -> Self {
        Self {
            prompt: null(),
            data: null(),
            len: 0,
            min_length: 4,    // not imposed by acos
            max_length: 8,    // this may be different for ACOS5-EVO
            #[cfg(v0_20_0)]
            stored_length: 8, // this may be different for ACOS5-EVO
            encoding: 0,      // 0 == SC_PIN_ENCODING_ASCII
            pad_length: 8,
            pad_char: 0xFF,
            offset: 5,        // this may be different for ACOS5-EVO
            #[cfg(v0_20_0)]
            length_offset: 0,
            max_tries: 8,  // 1-14 or 0xFF(unlimited)
            tries_left: 8, // 0-14 or 0xFF(unlimited)
            logged_in: 0, // 0 == SC_PIN_STATE_LOGGED_OUT
            #[cfg(v0_20_0)]
            acls: [sc_acl_entry::default(); SC_MAX_SDO_ACLS]
        }
    }
}


/* A NULL in apdu means that the APDU is prepared by the ISO 7816 layer, which also handles PIN
 * padding and setting offset fields for the PINs (for PIN-pad use). A non-NULL in APDU means that
 * the card driver has prepared the APDU (including padding) and set the PIN offset fields.
 *
 * Note that flags apply to both PINs for multi-PIN operations.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pin_cmd_data {
    pub cmd   : u32,       /* e.g. SC_PIN_CMD_GET_INFO */
    pub flags : u32,       /* e.g. SC_PIN_CMD_NEED_PADDING */

    pub pin_type : u32,    /* usually SC_AC_CHV */
    pub pin_reference : i32,
    #[cfg(not(v0_20_0))]
    pub puk_reference : i32, /* non-zero means that reference is available */

    pub pin1 : sc_pin_cmd_pin,
    pub pin2 : sc_pin_cmd_pin,

    pub apdu : *mut sc_apdu,  /* APDU of the PIN command */
}

#[cfg(acos5_impl_default)]
impl Default for sc_pin_cmd_data {
    fn default() -> Self {
        Self {
            cmd: 0,      // 0 == SC_PIN_CMD_VERIFY
            flags: 2,    // 2 == SC_PIN_CMD_NEED_PADDING  TODO check that for acos5 and how it works
            pin_type: 1, // 1 == SC_AC_CHV
            pin_reference: 0,
            #[cfg(not(v0_20_0))]
            puk_reference: 0,
            pin1: sc_pin_cmd_pin::default(),
            pin2: sc_pin_cmd_pin::default(),
            apdu: null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_reader_operations {
    /* Called during sc_establish_context(), when the driver
     * is loaded */
    pub init : Option< unsafe extern "C" fn (ctx: *mut sc_context) -> i32 >,
    /* Called when the driver is being unloaded.  finish() has to
     * release any resources. */
    pub finish : Option< unsafe extern "C" fn (ctx: *mut sc_context) -> i32 >,
    /* Called when library wish to detect new readers
     * should add only new readers. */
    pub detect_readers : Option< unsafe extern "C" fn (ctx: *mut sc_context) -> i32 >,

    pub cancel : Option< unsafe extern "C" fn (ctx: *mut sc_context) -> i32 >,
    /* Called when releasing a reader.  release() has to
     * deallocate the private data.  Other fields will be
     * freed by OpenSC. */
    pub release : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,

    pub detect_card_presence : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,
    pub connect : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,
    pub disconnect : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,
    pub transmit : Option< unsafe extern "C" fn (reader: *mut sc_reader, apdu: *mut sc_apdu) -> i32 >,
    pub lock : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,
    pub unlock : Option< unsafe extern "C" fn (reader: *mut sc_reader) -> i32 >,
    pub set_protocol : Option< unsafe extern "C" fn (reader: *mut sc_reader, proto: u32) -> i32 >,
    /* Pin pad functions */
    pub display_message : Option< unsafe extern "C" fn (arg1: *mut sc_reader, arg2: *const c_char) -> i32 >,
    pub perform_verify : Option< unsafe extern "C" fn (arg1: *mut sc_reader, arg2: *mut sc_pin_cmd_data) -> i32 >,
    pub perform_pace : Option< unsafe extern "C" fn (reader: *mut sc_reader,
        establish_pace_channel_input: *mut c_void,
        establish_pace_channel_output: *mut c_void) -> i32 >,

    /* Wait for an event */
    pub wait_for_event : Option< unsafe extern "C" fn (ctx: *mut sc_context, event_mask: u32,
        event_reader: *mut *mut sc_reader, event: *mut u32,
        timeout: i32, reader_states: *mut *mut c_void) -> i32 >,
    /* Reset a reader */
    pub reset : Option< unsafe extern "C" fn (arg1: *mut sc_reader, arg2: i32) -> i32 >,
    /* Used to pass in PC/SC handles to minidriver */
    pub use_reader : Option< unsafe extern "C" fn (ctx: *mut sc_context, pcsc_context_handle: *mut c_void,
        pcsc_card_handle: *mut c_void) -> i32 >,
}

/*
 * Card flags
 *
 * Used to hint about card specific capabilities and algorithms
 * supported to the card driver. Used in sc_atr_table and
 * card_atr block structures in the configuration file.
 *
 * Unknown, card vendor specific values may exists, but must
 * not conflict with values defined here. All actions defined
 * by the flags must be handled by the card driver themselves.
 */

/* Mask for card vendor specific values */
pub const SC_CARD_FLAG_VENDOR_MASK : c_ulong = 0xFFFF_0000;

/* Hint SC_CARD_CAP_RNG */
pub const SC_CARD_FLAG_RNG         : c_ulong = 0x0000_0002;
pub const SC_CARD_FLAG_KEEP_ALIVE  : c_ulong = 0x0000_0004; // since opensc source release v0.18.0

/*
 * Card capabilities
 */

/* Card can handle large (> 256 bytes) buffers in calls to
 * read_binary, write_binary and update_binary; if not,
 * several successive calls to the corresponding function
 * is made. */
pub const SC_CARD_CAP_APDU_EXT     : c_ulong = 0x0000_0001;

/* Card has on-board random number source. */
pub const SC_CARD_CAP_RNG          : c_ulong = 0x0000_0004;

/* Card supports ISO7816 PIN status queries using an empty VERIFY */
pub const SC_CARD_CAP_ISO7816_PIN_INFO : c_ulong = 0x0000_0008; // since opensc source release v0.16.0

/* Use the card's ACs in sc_pkcs15init_authenticate(),
 * instead of relying on the ACL info in the profile files. */
pub const SC_CARD_CAP_USE_FCI_AC     : c_ulong = 0x0000_0010;

/* Card (or card driver) supports a protected authentication mechanism */
pub const SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH : c_ulong = 0x0000_0100; // since opensc source release v0.17.0

/* Card (or card driver) supports generating a session PIN */
pub const SC_CARD_CAP_SESSION_PIN : c_ulong = 0x0000_0200; // since opensc source release v0.17.0

/* Card and driver supports handling on card session objects.
 * If a driver has this capability, the driver handles storage and operations
 * with objects that CKA_TOKEN set to FALSE. If a driver doesn't support this,
 * OpenSC handles them as in memory objects.*/
pub const SC_CARD_CAP_ONCARD_SESSION_OBJECTS : c_ulong = 0x0000_0400;

/* Card (or card driver) supports key wrapping operations */
pub const SC_CARD_CAP_WRAP_KEY   : c_ulong = 0x0000_0800;
/* Card (or card driver) supports key unwrapping operations */
pub const SC_CARD_CAP_UNWRAP_KEY : c_ulong = 0x0000_1000;

/* Card supports symmetric/secret key algorithms (currently at least AES, modes ECB and CBC) */
// #[cfg(sym_hw_encrypt)]
// pub const SC_CARD_CAP_SYM_KEY_ALGOS : c_ulong = 0x0000_2000;

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_card {
    pub ctx : *mut sc_context,
    pub reader : *mut sc_reader,

    pub atr : sc_atr,
    pub uid : sc_uid, // since opensc source release v0.17.0

    pub type_ : i32,   /* Card type, for card driver internal use */
    pub caps : c_ulong,
    pub flags : c_ulong,
    pub cla : i32,
    pub max_send_size : usize, /* Max Lc supported by the card */
    pub max_recv_size : usize, /* Max Le supported by the card */

    pub app : [*mut sc_app_info; SC_MAX_CARD_APPS],
    pub app_count : i32,

    pub ef_atr : *mut sc_ef_atr,

    pub algorithms : *mut sc_algorithm_info,
    pub algorithm_count : i32,

    pub lock_count : i32,

    pub driver : *mut sc_card_driver,
    pub ops : *mut sc_card_operations,
    pub name : *const c_char,
    pub drv_data : *mut c_void,
    pub max_pin_len : i32,

    pub cache : sc_card_cache,

    pub serialnr : sc_serial_number,
    pub version : sc_version,

    pub mutex : *mut c_void,
//#ifdef ENABLE_SM
    pub sm_ctx : sm_context,
//#endif

    pub magic : u32,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_card_t = sc_card;
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_card_operations {
    /** @brief Match a card with the given card driver.
     *
     * Called in sc_connect_card().  Must return 1, if the current
     * card can be handled with this driver, or 0 otherwise.  ATR
     * field of the sc_card struct is filled in before calling
     * this function. It is recommended not to modify `card` during this call.
     * */
    pub match_card : Option< unsafe extern "C" fn (card : *mut sc_card) -> i32 >,

    /** @brief Initialize a card.
     *
     * Called when ATR of the inserted card matches an entry in ATR
     * table.  May return SC_ERROR_INVALID_CARD to indicate that
     * the card cannot be handled with this driver. drv_data may be used to
     * store card driver's (allocated) private data. */
    pub init : Option< unsafe extern "C" fn (card: *mut sc_card) -> i32 >,

    /** @brief Deinitialize a card.
     *
     * Called when the `card` object is being freed.  finish() has to
     * deallocate all possible private data. */
    pub finish : Option< unsafe extern "C" fn (card: *mut sc_card) -> i32 >,

    /* ISO 7816-4 functions */

    /**
     * @brief Read data from a binary EF with a single command
     *
     * Implementation of this call back is optional and may be NULL.
     *
     * @param  card   struct sc_card object on which to issue the command
     * @param  idx    index within the file with the data to read
     * @param  buf    buffer to the read data
     * @param  count  number of bytes to read
     * @param  flags  flags for the READ BINARY command (optional)
     * @return number of bytes read or an error code
     *
     * @see sc_read_binary()
     */
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
    pub read_binary   : Option< unsafe extern "C" fn (card: *mut sc_card, idx: u32,
                                                      buf: *mut u8, count: usize, flags: c_ulong) -> i32 >,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub read_binary   : Option< unsafe extern "C" fn (card: *mut sc_card, idx: u32,
                                                      buf: *mut u8, count: usize, flags: *mut c_ulong) -> i32 >,

    /**
     * @brief Write data to a binary EF with a single command
     *
     * Implementation of this call back is optional and may be NULL.
     *
     * @param  card   struct sc_card object on which to issue the command
     * @param  idx    index within the file for the data to be written
     * @param  buf    buffer with the data
     * @param  count  number of bytes to write
     * @param  flags  flags for the WRITE BINARY command (currently not used)
     * @return number of bytes written or an error code
     *
     * @see sc_write_binary()
     */
    pub write_binary  : Option< unsafe extern "C" fn (card: *mut sc_card, idx: u32,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,
    /** @brief Updates the content of a binary EF
     *
     * Implementation of this call back is optional and may be NULL.
     *
     * @param  card   struct sc_card object on which to issue the command
     * @param  idx    index within the file for the data to be updated
     * @param  buf    buffer with the new data
     * @param  count  number of bytes to update
     * @param  flags  flags for the UPDATE BINARY command (currently not used)
     * @return number of bytes written or an error code
     *
     * @see sc_update_binary()
     */
    pub update_binary : Option< unsafe extern "C" fn (card: *mut sc_card, idx: u32,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,

    /**
     * @brief Sets (part of) the content fo an EF to its logical erased state
     *
     * Implementation of this call back is optional and may be NULL.
     *
     * @param  card   struct sc_card object on which to issue the command
     * @param  idx    index within the file for the data to be erased
     * @param  count  number of bytes to erase
     * @param  flags  flags for the ERASE BINARY command (currently not used)
     * @return number of bytes erased or an error code
     *
     * @see sc_erase_binary()
     */
    pub erase_binary  : Option< unsafe extern "C" fn (card: *mut sc_card, idx: u32,
                                                      count: usize, flags: c_ulong) -> i32 >,

    /* rec_nr: assuming OpenSC has the convention to start rec_nr from 1 to NOR */
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
    pub read_record   : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32,
                                                      buf:   *mut u8, count: usize, flags: c_ulong) -> i32 >,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub read_record   : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32, idx: u32,
                                                      buf:   *mut u8, count: usize, flags: c_ulong) -> i32 >,
    pub write_record  : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,
    pub append_record : Option< unsafe extern "C" fn (card: *mut sc_card,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
    pub update_record : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub update_record : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32, idx: u32,
                                                      buf: *const u8, count: usize, flags: c_ulong) -> i32 >,

    /* select_file: Does the equivalent of SELECT FILE command specified
     *   in ISO7816-4. Stores information about the selected file to
     *   <file>, if not NULL. */
    pub select_file : Option< unsafe extern "C" fn (card: *mut sc_card, path: *const sc_path,
                                                    file_out: *mut *mut sc_file) -> i32 >,
    /**
     * The iso7816_get_response function is limited to return by @param count / @return: max. sc_get_max_recv_size() bytes
     * @param  count  INOUT  IN the requested amount of bytes, OUT: apdu.resplen<=sc_get_max_recv_size(card)
     * @return  error code or : 0 for statusword 0x9000 (no more data to read) or for apdu.sw1 == 0x61:
                                r = apdu.sw2 == 0 ? 256 : apdu.sw2;    (more data to read)
     */
    pub get_response : Option< unsafe extern "C" fn (card: *mut sc_card, count: *mut usize,
                                                     buf: *mut u8) -> i32 >,
    /**
     * Get random data from the card
     *
     * Implementation of this call back is optional and may be NULL.
     *
     * @param  card   struct sc_card object on which to issue the command
     * @param  buf    buffer to be filled with random data
     * @param  count  number of random bytes to initialize
     * @return number of random bytes successfully initialized (i.e. `count` or less bytes) or an error code
     */
    pub get_challenge : Option< unsafe extern "C" fn (card: *mut sc_card,
                                                      buf: *mut u8, count: usize) -> i32 >,

    /*
     * ISO 7816-8 functions
     */

    #[deprecated(since="0.0.0", note="please use `pin_cmd` instead")]
    /* verify:  Verifies reference data of type <acl>, identified by
     *   <ref_qualifier>. If <tries_left> is not NULL, number of verifying
     *   tries left is saved in case of verification failure, if the
     *   information is available. */
    pub verify : Option< unsafe extern "C" fn (card: *mut sc_card, type_: u32, ref_qualifier: i32,
                                               data: *const u8, data_len: usize, tries_left: *mut i32) -> i32 >, // old interface for pin: don't implement this, but use pin_cmd instead (see: sec.c:sc_pin_cmd)

    /* logout: Resets all access rights that were gained. */
    pub logout : Option< unsafe extern "C" fn (card: *mut sc_card) -> i32 >,

    /* restore_security_env:  Restores a previously saved security
     *   environment, and stores information about the environment to
     *   <env_out>, if not NULL. */
    pub restore_security_env : Option< unsafe extern "C" fn (card: *mut sc_card, se_num: i32) -> i32 >,

    /* set_security_env:  Initializes the security environment on card
     *   according to <env>, and stores the environment as <se_num> on the
     *   card. If se_num <= 0, the environment will not be stored. */
    pub set_security_env : Option< unsafe extern "C" fn (card: *mut sc_card,
                                                         env: *const sc_security_env, se_num: i32) -> i32 >,
    /* decipher:  Engages the deciphering operation.  Card will use the
     *   security environment set in a call to set_security_env or
     *   restore_security_env. */
    pub decipher : Option< unsafe extern "C" fn (card: *mut sc_card, crgram: *const u8, crgram_len: usize,
                                                 out: *mut u8, outlen: usize) -> i32 >,


    /* compute_signature:  Generates a digital signature on the card.  Similar
     *   to the function decipher. */
    pub compute_signature : Option< unsafe extern "C" fn (card: *mut sc_card, data: *const u8, data_len: usize,
                                                          out: *mut u8, outlen: usize) -> i32 >,

    #[deprecated(since="0.0.0", note="please use `pin_cmd` instead")]
    pub change_reference_data : Option< unsafe extern "C" fn (card: *mut sc_card, type_: u32, ref_qualifier: i32,
                                                              old: *const u8, oldlen: usize, newref: *const u8,
                                                              newlen: usize, tries_left: *mut i32) -> i32 >,  // old interface for pin: don't implement this, but use pin_cmd instead (see: sec.c:sc_pin_cmd)
    #[deprecated(since="0.0.0", note="please use `pin_cmd` instead")]
    pub reset_retry_counter : Option< unsafe extern "C" fn (card: *mut sc_card, type_: u32, ref_qualifier: i32,
                                                            puk: *const u8, puklen: usize, newref: *const u8,
                                                            newlen: usize) -> i32 >, // old interface for pin: don't implement this, but use pin_cmd instead (see: sec.c:sc_pin_cmd)

    /*
     * ISO 7816-9 functions
     */
    pub create_file : Option< unsafe extern "C" fn (card: *mut sc_card, file: *mut sc_file) -> i32 >,

    pub delete_file : Option< unsafe extern "C" fn (card: *mut sc_card, path: *const sc_path) -> i32 >,

    /* list_files:  Enumerates all the files in the current DF, and
     *   writes the corresponding file identifiers to <buf>.  Returns
     *   the number of bytes stored. */
    pub list_files : Option< unsafe extern "C" fn (card: *mut sc_card, buf: *mut u8, buflen: usize) -> i32 >,

    pub check_sw : Option< unsafe extern "C" fn (card: *mut sc_card, sw1: u32, sw2: u32) -> i32 >,

    pub card_ctl : Option< unsafe extern "C" fn (card: *mut sc_card, command: c_ulong, data: *mut c_void) -> i32 >,

    pub process_fci : Option< unsafe extern "C" fn (card: *mut sc_card, file: *mut sc_file,
                                                    buf: *const u8, buflen: usize) -> i32 >,

    pub construct_fci : Option< unsafe extern "C" fn (card: *mut sc_card, file: *const sc_file,
                                                      out: *mut u8, outlen: *mut usize) -> i32 >,

    /* pin_cmd: verify/change/unblock command; optionally using the
     * card's pin pad if supported.
     */
    pub pin_cmd : Option< unsafe extern "C" fn (card: *mut sc_card, data: *mut sc_pin_cmd_data,
                                                tries_left: *mut i32) -> i32 >,

    pub get_data : Option< unsafe extern "C" fn (card: *mut sc_card, offset: u32, buf: *mut u8,
                                                 buflen: usize) -> i32 >,

    pub put_data : Option< unsafe extern "C" fn (arg1: *mut sc_card, arg2: u32, arg3: *const u8,
                                                 arg4: usize) -> i32 >,

    pub delete_record : Option< unsafe extern "C" fn (card: *mut sc_card, rec_nr: u32) -> i32 >,

    pub read_public_key : Option< unsafe extern "C" fn (card: *mut sc_card, algorithm: u32, key_path: *mut sc_path,
                                                        key_reference: u32, modulus_length: u32,
                                                        out: *mut *mut u8, out_len: *mut usize) -> i32 >,

    pub card_reader_lock_obtained: Option< unsafe extern "C" fn (arg1: *mut sc_card, was_reset: i32) -> i32 >,  // since opensc source release v0.17.0

    pub wrap : Option< unsafe extern "C" fn (card: *mut sc_card, out: *mut u8, outlen: usize) -> i32 >,

    pub unwrap : Option< unsafe extern "C" fn (card: *mut sc_card, crgram: *const u8, crgram_len: usize) -> i32 >,

    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
    pub encrypt_sym : Option< unsafe extern "C" fn (card: *mut sc_card, plaintext: *const u8, plaintext_len: usize, out: *mut u8, outlen: *mut usize) -> i32 >,

    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
    pub decrypt_sym : Option< unsafe extern "C" fn (card: *mut sc_card, EncryptedData: *const u8, EncryptedDataLen: usize, out: *mut u8, outlen: *mut usize) -> i32 >,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_card_driver {
    pub name       : *const c_char,
    pub short_name : *const c_char,
    pub ops        : *mut sc_card_operations,
    pub atr_map    : *mut sc_atr_table, /* ATTENTION: ultimately ctx.c:sc_release_context calls card.c:_sc_free_atr, free's all pointers !!! */
    pub natrs      : u32,
    pub dll        : *mut c_void,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_card_driver_t = sc_card_driver;
*/

#[cfg(impl_default)]
impl Default for sc_card_driver {
    fn default() -> Self {
        Self {
            name:       null(),
            short_name: null(),
            ops:        null_mut(),
            atr_map:    null_mut(),
            natrs:      0,
            dll:        null_mut()
        }
    }
}

/**
 * @struct sc_thread_context
 * Structure for the locking function to use when using libopensc
 * in a multi-threaded application.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_thread_context {
    /** the version number of this structure (0 for this version) */
    pub ver : u32,
    /** creates a mutex object */
    pub create_mutex : Option< unsafe extern "C" fn (arg1: *mut *mut c_void) -> i32 >,
    /** locks a mutex object (blocks until the lock has been acquired) */
    pub lock_mutex : Option< unsafe extern "C" fn (arg1: *mut c_void) -> i32 >,
    /** unlocks a mutex object  */
    pub unlock_mutex : Option< unsafe extern "C" fn (arg1: *mut c_void) -> i32 >,
   /** destroys a mutex object */
    pub destroy_mutex : Option< unsafe extern "C" fn (arg1: *mut c_void) -> i32 >,
    /** returns unique identifier for the thread (can be NULL) */
    pub thread_id : Option< unsafe extern "C" fn () -> c_ulong >,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_thread_context_t = sc_thread_context;
*/

/** Stop modifying or using external resources
 *
 * Currently this is used to avoid freeing duplicated external resources for a
 * process that has been forked. For example, a child process may want to leave
 * the duplicated card handles for the parent process. With this flag the child
 * process indicates that shall the reader shall ignore those resources when
 * calling sc_disconnect_card.
 */
pub const SC_CTX_FLAG_TERMINATE             : c_ulong = 0x0000_0001;  // since opensc source release v0.16.0
/** removed in 0.18.0 and later */
pub const SC_CTX_FLAG_PARANOID_MEMORY       : c_ulong = 0x0000_0002;  // since opensc source release v0.16.0
pub const SC_CTX_FLAG_DEBUG_MEMORY          : c_ulong = 0x0000_0004;  // since opensc source release v0.16.0
pub const SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER : c_ulong = 0x0000_0008;  // since opensc source release v0.16.0
pub const SC_CTX_FLAG_DISABLE_POPUPS        : c_ulong = 0x0000_0010;  // since opensc source release v0.17.0
pub const SC_CTX_FLAG_DISABLE_COLORS        : c_ulong = 0x0000_0020;  // since opensc source release v0.20.0

// typedef struct ossl3ctx ossl3ctx_t; // since v0_24_0 : see also  opensc-0.xy.0/src/libopensc/sc-ossl-compat.h

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_context {
    pub conf : *mut scconf_context,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
    pub conf_blocks : [*mut scconf_block; 3],
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub conf_blocks : [*mut scconf_block; 4],
    pub app_name : *mut c_char,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub exe_path : *mut c_char,
    pub debug : i32,
    pub flags : c_ulong,                // since opensc source release v0.16.0

    pub debug_file : *mut FILE,
    pub debug_filename : *mut c_char,
    pub preferred_language : *mut c_char,

    pub readers : list_t,

    pub reader_driver : *mut sc_reader_driver,
    pub reader_drv_data : *mut c_void,

    pub card_drivers : [*mut sc_card_driver; SC_MAX_CARD_DRIVERS],
    pub forced_driver : *mut sc_card_driver,

    pub thread_ctx : *mut sc_thread_context,
    pub mutex : *mut c_void,

    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub ossl3ctx : *mut c_void, // TODO ossl3ctx_t * ; // ifdef ENABLE_OPENSSL

    pub magic : u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub disable_hw_pkcs1_padding : i32,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_context_t = sc_context;
*/

#[cfg(impl_default)]
impl Default for sc_context {
    fn default() -> Self {
        Self {
            conf: null_mut(),
            #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
            conf_blocks: [null_mut(); 3],
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
            conf_blocks: [null_mut(); 4],
            app_name: null_mut(),
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
            exe_path: null_mut(),
            debug: 0,
            flags: 0,

            debug_file: null_mut(),
            debug_filename: null_mut(),
            preferred_language: null_mut(),
            readers: list_t {
                head_sentinel: null_mut(),
                tail_sentinel: null_mut(),
                mid:           null_mut(),
                numels: 0,
                spareels: null_mut(),
                spareelsnum: 0,
                iter_active: 0,
                iter_pos: 0,
                iter_curentry: null_mut(),
                attrs: list_attributes_s {
                    comparator: None,
                    seeker: None,
                    meter: None,
                    copy_data: 0,
                    hasher: None,
                    serializer: None,
                    unserializer: None
                }
            },
            reader_driver: null_mut(),
            reader_drv_data:null_mut(),
            card_drivers: [null_mut(); SC_MAX_CARD_DRIVERS],
            forced_driver: null_mut(),
            thread_ctx: null_mut(),
            mutex: null_mut(),
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
            ossl3ctx: null_mut(),
            magic: 0,
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
            disable_hw_pkcs1_padding: 0,
        }
    }
}

#[cfg(impl_display)]
impl std::fmt::Display for sc_context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        assert!(!self.app_name.is_null());
        let app_name = unsafe { std::ffi::CStr::from_ptr(self.app_name) };
        write!(f, "app_name: {:?}, debug: {}, magic: {}, card_drivers[{:?}, {:?}, {:?}, {:?}, ...],\n\
          conf_blocks[{:?}, {:?}, {:?}]",
        app_name, self.debug, self.magic,
        self.card_drivers[0], self.card_drivers[1], self.card_drivers[2], self.card_drivers[3],
        self.conf_blocks[0], self.conf_blocks[1], self.conf_blocks[2])
    }
}


unsafe extern "C" {

/* APDU handling functions */

/** Sends a APDU to the card
 *  @param  card  struct sc_card object to which the APDU should be send
 *  @param  apdu  sc_apdu object of the APDU to be send
 *  @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_transmit_apdu(card: *mut sc_card, apdu: *mut sc_apdu) -> i32;

pub fn sc_format_apdu(card: *mut sc_card, apdu: *mut sc_apdu, cse: i32, ins: i32, p1: i32, p2: i32);

/** Format an APDU based on the data to be sent and received.
 *
 * Calls \a sc_transmit_apdu() by determining the APDU case based on \a datalen
 * and \a resplen. As result, no chaining or GET RESPONSE will be performed in
 * sc_format_apdu().
 */
pub fn sc_format_apdu_ex(apdu: *mut sc_apdu,
    cla: u8, ins: u8, p1: u8, p2: u8,
    data: *const u8, datalen: usize,
    resp: *mut u8, resplen: usize);

pub fn sc_check_apdu(card: *mut sc_card, apdu: *const sc_apdu) -> i32;

/** Transforms an APDU from binary to its @c sc_apdu representation
 *  @param  ctx     sc_context object (used for logging)
 *  @param  buf     APDU to be encoded as an @c sc_apdu object
 *  @param  len     length of @a buf
 *  @param  apdu    @c sc_apdu object to initialize
 *  @return SC_SUCCESS on success and an error code otherwise
 *  @note On successful initialization apdu->data will point to @a buf with an
 *  appropriate offset. Only free() @a buf, when apdu->data is not needed any
 *  longer.
 *  @note On successful initialization @a apdu->resp and apdu->resplen will be
 *  0. You should modify both if you are expecting data in the response APDU.
 */
pub fn sc_bytes2apdu(ctx: *mut sc_context, buf: *const u8, len: usize, apdu: *mut sc_apdu) -> i32;

/** Encodes a APDU as an octet string
 *  @param  ctx     sc_context object (used for logging)
 *  @param  apdu    APDU to be encoded as an octet string
 *  @param  proto   protocol version to be used
 *  @param  out     output buffer of size outlen.
 *  @param  outlen  size of the output buffer
 *  @return SC_SUCCESS on success and an error code otherwise
 */
fn sc_apdu2bytes(ctx: *mut sc_context, apdu: *const sc_apdu,
    proto: u32, out: *mut u8, outlen: usize) -> i32; // since opensc source release v0.18.0; not declared pub because not exported from libopensc.so

/** Calculates the length of the encoded APDU in octets.
 *  @param  apdu   the APDU
 *  @param  proto  the desired protocol
 *  @return length of the encoded APDU
 */
fn sc_apdu_get_length(apdu: *const sc_apdu, proto: u32) -> usize; // since opensc source release v0.18.0; not declared pub because not exported from libopensc.so

pub fn sc_check_sw (card: *mut sc_card, sw1: u32, sw2: u32) -> i32;

/********************************************************************/
/*                  opensc context functions                        */
/********************************************************************/

#[deprecated(since="0.0.0", note="please use `sc_context_create` instead")]
/**
 * Establishes an OpenSC context. Note: this function is deprecated,
 * please use sc_context_create() instead.
 * @param ctx A pointer to a pointer that will receive the allocated context
 * @param app_name A string that identifies the application, used primarily
 * in finding application-specific configuration data. Can be NULL.
 */
pub fn sc_establish_context(ctx: *mut *mut sc_context, app_name: *const c_char) -> i32;

}

/**
 * @struct sc_context initialization parameters
 * Structure to supply additional parameters, for example
 * mutex information, to the sc_context creation.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_context_param {
    /** version number of this structure (0 for this version) */
    pub ver : u32,
    /** name of the application (used for finding application
      *  dependent configuration data). If NULL the name "default"
      *  will be used. */
    pub app_name : *const c_char,
    /** context flags */
    pub flags : c_ulong,
    /** mutex functions to use (optional) */
    pub thread_ctx : *mut sc_thread_context,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub debug : i32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
    pub debug_file : *mut FILE,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_context_param_t = sc_context_param;
*/

#[cfg(impl_default)]
impl Default for sc_context_param {
    fn default() -> Self {
        Self {
            ver: 0,
            app_name: null(),
            flags: 0,
            thread_ctx: null_mut(),
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
            debug: 0,
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
            debug_file: null_mut(),
        }
    }
}

unsafe extern "C" {

/**
 * Repairs an already existing sc_context object. This may occur if
 * multithreaded issues mean that another context in the same heap is deleted.
 * @param  ctx   pointer to a sc_context pointer containing the (partial)
 *               context.
 * @return SC_SUCCESS or an error value if an error occurred.
 */
fn sc_context_repair(ctx: *mut *mut sc_context) -> i32; // not declared pub because not exported from libopensc.so

/**
 * Creates a new sc_context object.
 * @param  ctx   pointer to a sc_context pointer for the newly
 *               created sc_context object.
 * @param  parm  parameters for the sc_context creation (see
 *               sc_context_param for a description of the supported
 *               options)..
 * @return SC_SUCCESS on success and an error code otherwise.
 */
pub fn sc_context_create(ctx: *mut *mut sc_context, parm: *const sc_context_param) -> i32;
/**
 * Releases an established OpenSC context
 * @param ctx A pointer to the context structure to be released
 */
pub fn sc_release_context(ctx: *mut sc_context) -> i32;

/**
 * Detect new readers available on system.
 * @param  ctx  OpenSC context
 * @return SC_SUCCESS on success and an error code otherwise.
 */
pub fn sc_ctx_detect_readers(ctx: *mut sc_context) -> i32;

/**
 * In windows: get configuration option from environment or from registers.
 * @param env name of environment variable
 * @param reg name of register value
 * @param key path of register key
 * @return SC_SUCCESS on success and an error code otherwise.
 */
pub fn sc_ctx_win32_get_config_value(env: *const c_char, reg: *const c_char, key: *const c_char,
    out: *mut c_void, out_size: *mut usize) -> i32;       // since opensc source release v0.19.0

/**
 * Returns a pointer to the specified sc_reader object
 * @param  ctx  OpenSC context
 * @param  i    number of the reader structure to return (starting with 0)
 * @return the requested sc_reader object or NULL if the index is
 *         not available
 */
pub fn sc_ctx_get_reader(ctx: *mut sc_context, i: u32) -> *mut sc_reader;

/**
 * Pass in pointers to handles to be used for the pcsc reader.
 * This is used by cardmod to pass in handles provided by BaseCSP
 *
 * @param  ctx   pointer to a sc_context
 * @param  pcsc_context_handle pointer to the  new context_handle to use
 * @param  pcsc_card_handle pointer to the new card_handle to use
 * @return SC_SUCCESS or 1 on success and an error code otherwise. A return of 1 indicates to call reinit_card_for, as the reader has changed.
 */
pub fn sc_ctx_use_reader(ctx: *mut sc_context, pcsc_context_handle: *mut c_void, pcsc_card_handle: *mut c_void) -> i32;

/**
 * detect if the given handles are referencing `reader`
 *
 * 0 -> handles also point to `reader`
 * 1 -> handles don't point to `reader`, but to a different reader
 */
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
fn pcsc_check_reader_handles(ctx: *mut sc_context, reader: *mut sc_reader, pcsc_context_handle: *mut c_void, pcsc_card_handle: *mut c_void) -> i32;

/**
 * Returns a pointer to the specified sc_reader object
 * @param  ctx  OpenSC context
 * @param  name name of the reader to look for
 * @return the requested sc_reader object or NULL if the reader is
 *         not available
 */
pub fn sc_ctx_get_reader_by_name(ctx: *mut sc_context, name: *const c_char) -> *mut sc_reader;

/**
 * Returns a pointer to the specified sc_reader object
 * @param  ctx  OpenSC context
 * @param  id id of the reader (starting from 0)
 * @return the requested sc_reader object or NULL if the reader is
 *         not available
 */
pub fn sc_ctx_get_reader_by_id(ctx: *mut sc_context, id: u32) -> *mut sc_reader;

/**
 * Returns the number a available sc_reader objects
 * @param  ctx  OpenSC context
 * @return the number of available reader objects
 */
pub fn sc_ctx_get_reader_count(ctx: *mut sc_context) -> u32;

pub fn _sc_delete_reader(ctx: *mut sc_context, reader: *mut sc_reader) -> i32;

/**
 * Redirects OpenSC debug log to the specified file
 * @param  ctx existing OpenSC context
 * @param  filename path to the file or "stderr" or "stdout"
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_ctx_log_to_file(ctx: *mut sc_context, filename: *const c_char) -> i32;

/**
 * Forces the use of a specified card driver
 * @param ctx OpenSC context
 * @param short_name The short name of the driver to use (e.g. 'cardos')
 */
pub fn sc_set_card_driver(ctx: *mut sc_context, short_name: *const c_char) -> i32;

/**
 * Connects to a card in a reader and auto-detects the card driver.
 * The ATR (Answer to Reset) string of the card is also retrieved.
 * @param reader Reader structure
 * @param card The allocated card object will go here
 */
pub fn sc_connect_card(reader: *mut sc_reader, card: *mut *mut sc_card) -> i32;
/**
 * Disconnects from a card, and frees the card structure. Any locks
 * made by the application must be released before calling this function.
 * NOTE: The card is not reset nor powered down after the operation.
 * @param  card  The card to disconnect
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_disconnect_card(card: *mut sc_card) -> i32;

/**
 * Checks if a card is present in a reader
 * @param reader Reader structure
 * @retval If an error occurred, the return value is a (negative)
 * OpenSC error code. If no card is present, 0 is returned.
 * Otherwise, a positive value is returned, which is a
 * combination of flags. The flag SC_READER_CARD_PRESENT is
 * always set. In addition, if the card was exchanged,
 * the SC_READER_CARD_CHANGED flag is set.
 */
pub fn sc_detect_card_presence(reader: *mut sc_reader) -> i32;

/**
 * Waits for an event on readers.
 *
 * In case of a reader event (attached/detached), the list of reader is
 * adjusted accordingly. This means that a subsequent call to
 * `sc_ctx_detect_readers()` is not needed.
 *
 * @note Only PC/SC backend implements this. An infinite timeout on macOS does
 * not detect reader events (use a limited timeout instead if needed).
 *
 * @param ctx (IN) pointer to a Context structure
 * @param event_mask (IN) The types of events to wait for; this should
 *   be ORed from one of the following:
 *   - SC_EVENT_CARD_REMOVED
 *   - SC_EVENT_CARD_INSERTED
 *   - SC_EVENT_READER_ATTACHED
 *   - SC_EVENT_READER_DETACHED
 * @param event_reader (OUT) the reader on which the event was detected
 * @param event (OUT) the events that occurred. This is also ORed
 *   from the constants listed above.
 * @param timeout Amount of millisecs to wait; -1 means forever
 * @retval < 0 if an error occurred
 * @retval = 0 if a an event happened
 * @retval = 1 if the timeout occurred
 */
pub fn sc_wait_for_event (ctx: *mut sc_context, event_mask: u32,
    event_reader: *mut *mut sc_reader, event: *mut u32,
    timeout: i32, reader_states: *mut *mut c_void) -> i32;

/**
 * Resets the card.
 * NOTE: only PC/SC backend implements this function at this moment.
 * @param card The card to reset.
 * @param do_cold_reset 0 for a warm reset, 1 for a cold reset (unpower)
 * @retval SC_SUCCESS on success
 */
pub fn sc_reset(card: *mut sc_card, do_cold_reset: i32) -> i32;

/**
 * Cancel all pending PC/SC calls
 * NOTE: only PC/SC backend implements this function.
 * @param ctx pointer to application context
 * @retval SC_SUCCESS on success
 */
pub fn sc_cancel(ctx: *mut sc_context) -> i32;

/**
 * Tries acquire the reader lock.
 * @param  card  The card to lock
 * @retval SC_SUCCESS on success
 */
pub fn sc_lock(card: *mut sc_card) -> i32;

/**
 * Unlocks a previously acquired reader lock.
 * @param  card  The card to unlock
 * @retval SC_SUCCESS on success
 */
pub fn sc_unlock(card: *mut sc_card) -> i32;

/**
 * @brief Calculate the maximum size of R-APDU payload (Ne).
 *
 * Takes card limitations into account such as extended length support as well
 * as the reader's limitation for data transfer.
 *
 * @param card Initialized card object with its reader
 *
 * @return maximum Ne
 */
fn sc_get_max_recv_size(card: *const sc_card) -> usize; // not declared pub because not exported from libopensc.so

/**
 * @brief Calculate the maximum size of C-APDU payload (Nc).
 *
 * Takes card limitations into account such as extended length support as well
 * as the reader's limitation for data transfer.
 *
 * @param card
 *
 * @return maximum Nc
 */
fn sc_get_max_send_size(card: *const sc_card) -> usize; // not declared pub because not exported from libopensc.so


/********************************************************************/
/*                ISO 7816-4 related functions                      */
/********************************************************************/

/**
 * Does the equivalent of ISO 7816-4 command SELECT FILE.
 * @param  card  struct sc_card object on which to issue the command
 * @param  path  The path, file id or name of the desired file
 * @param  file  If not NULL, will receive a pointer to a new structure
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_select_file(card: *mut sc_card, path: *const sc_path, file: *mut *mut sc_file) -> i32;
/**
 * List file ids within a DF
 * @param  card    struct sc_card object on which to issue the command
 * @param  buf     buffer for the read file ids (the filed ids are
 *                 stored in the buffer as a sequence of 2 byte values)
 * @param  buflen  length of the supplied buffer
 * @return number of files ids read or an error code
 */
pub fn sc_list_files(card: *mut sc_card, buf: *mut u8, buflen: usize) -> i32;
/**
 * @brief Read data from a binary EF
 *
 * If `count` exceeds the card's transmission limits, multiple commands are issued.
 *
 * @param  card   struct sc_card object on which to issue the command
 * @param  idx    index within the file with the data to read
 * @param  buf    buffer to the read data
 * @param  count  number of bytes to read
 * @param  flags  flags for the READ BINARY command (currently not used)
 * @return number of bytes read or an error code
 */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
pub fn sc_read_binary(card: *mut sc_card, idx: u32, buf: *mut u8,
                      count: usize, flags: c_ulong) -> i32;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
pub fn sc_read_binary(card: *mut sc_card, idx: u32, buf: *mut u8,
                      count: usize, flags: *mut c_ulong) -> i32;
/**
 * Write data to a binary EF
 * @param  card   struct sc_card object on which to issue the command
 * @param  idx    index within the file for the data to be written
 * @param  buf    buffer with the data
 * @param  count  number of bytes to write
 * @param  flags  flags for the WRITE BINARY command (currently not used)
 * @return number of bytes written or an error code
 */
pub fn sc_write_binary(card: *mut sc_card, idx: u32, buf: *const u8,
    count: usize, flags: c_ulong) -> i32;
/**
 * Updates the content of a binary EF
 * @param  card   struct sc_card object on which to issue the command
 * @param  idx    index within the file for the data to be updated
 * @param  buf    buffer with the new data
 * @param  count  number of bytes to update
 * @param  flags  flags for the UPDATE BINARY command (currently not used)
 * @return number of bytes written or an error code
 */
pub fn sc_update_binary(card: *mut sc_card, idx: u32, buf: *const u8,
    count: usize, flags: c_ulong) -> i32;

/**
 * Sets (part of) the content fo an EF to its logical erased state
 * @param  card   struct sc_card object on which to issue the command
 * @param  idx    index within the file for the data to be erased
 * @param  count  number of bytes to erase
 * @param  flags  flags for the ERASE BINARY command (currently not used)
 * @return number of bytes written or an error code
 */
pub fn sc_erase_binary(card: *mut sc_card, idx: u32,
    count: usize, flags: c_ulong) -> i32;
} // extern "C"
pub const SC_RECORD_EF_ID_MASK : c_ulong = 0x0_001F;
/** flags for record operations */
/** use first record */
pub const SC_RECORD_BY_REC_ID  : c_ulong = 0x0_0000;
/** use the specified record number */
pub const SC_RECORD_BY_REC_NR  : c_ulong = 0x0_0100;
/** use currently selected record */
pub const SC_RECORD_CURRENT    : c_ulong = 0;

unsafe extern "C" {

/**
 * Reads a record from the current (i.e. selected) file.
 * @param  card    struct sc_card object on which to issue the command
 * @param  rec_nr  SC_READ_RECORD_CURRENT or a record number starting from 1
 * @param  idx     index within the record with the data to read
 * @param  buf     Pointer to a buffer for storing the data
 * @param  count   Number of bytes to read
 * @param  flags   flags (may contain a short file id of a file to select)
 * @retval number of bytes read or an error value
 */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
pub fn sc_read_record(card: *mut sc_card, rec_nr: u32, buf: *mut u8,
                      count: usize, flags: c_ulong) -> i32;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
pub fn sc_read_record(card: *mut sc_card, rec_nr: u32, idx: u32, buf: *mut u8,
                      count: usize, flags: c_ulong) -> i32;

/**
 * Writes data to a record from the current (i.e. selected) file.
 * @param  card    struct sc_card object on which to issue the command
 * @param  rec_nr  SC_READ_RECORD_CURRENT or a record number starting from 1
 * @param  buf     buffer with to the data to be written
 * @param  count   number of bytes to write
 * @param  flags   flags (may contain a short file id of a file to select)
 * @retval number of bytes written or an error value
 */
pub fn sc_write_record(card: *mut sc_card, rec_nr: u32, buf: *const u8,
    count: usize, flags: c_ulong) -> i32;
/**
 * Appends a record to the current (i.e. selected) file.
 * @param  card    struct sc_card object on which to issue the command
 * @param  buf     buffer with to the data for the new record
 * @param  count   length of the data
 * @param  flags   flags (may contain a short file id of a file to select)
 * @retval number of bytes written or an error value
 */
pub fn sc_append_record(card: *mut sc_card, buf: *const u8, count: usize,
    flags: c_ulong) -> i32;
/**
 * Updates the data of a record from the current (i.e. selected) file.
 * @param  card    struct sc_card object on which to issue the command
 * @param  rec_nr  SC_READ_RECORD_CURRENT or a record number starting from 1
 * @param  idx     index within the record with the data to read
 * @param  buf     buffer with to the new data to be written
 * @param  count   number of bytes to update
 * @param  flags   flags (may contain a short file id of a file to select)
 * @retval number of bytes written or an error value
 */
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
pub fn sc_update_record(card: *mut sc_card, rec_nr: u32, buf: *const u8,
    count: usize, flags: c_ulong) -> i32;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
pub fn sc_update_record(card: *mut sc_card, rec_nr: u32, idx: u32, buf: *const u8,
                        count: usize, flags: c_ulong) -> i32;
pub fn sc_delete_record(card: *mut sc_card, rec_nr: u32) -> i32;
/* get/put data functions */

/// Caller of sc_card.sc_card_operations.get_data
/// seems to refer to Data Object file, not to confuse with cos5 "Get Key"
/// OpenSC (exempt from card specific code) currently uses that from opensc-explorer only
pub fn sc_get_data(card: *mut sc_card, arg2: u32, arg3: *mut u8, arg4: usize) -> i32;
pub fn sc_put_data(card: *mut sc_card, arg2: u32, arg3: *const u8, arg4: usize) -> i32;
/**
 * Gets challenge from the card (normally random data).
 * @param  card    struct sc_card object on which to issue the command
 * @param  rndout  buffer for the returned random challenge. Note that the buffer may be only partially initialized on error.
 * @param  len     length of the challenge
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_get_challenge(card: *mut sc_card, rndout: *mut u8, len: usize) -> i32;

/********************************************************************/
/*              ISO 7816-8 related functions                        */
/********************************************************************/

pub fn sc_restore_security_env(card: *mut sc_card, se_num: i32) -> i32;


/// Caller of sc_card.sc_card_operations.set_security_env
///
/// params passed : Nothing else but all req. by set_security_env{env, se_num  as per @param}\
/// @apiNote  checked OKAY for @param consistency, same  @param names\
/// @param  card    INOUT\
/// @param  env     IN\
/// @param  se_num  IN\
pub fn sc_set_security_env(card: *mut sc_card,
    env: *const sc_security_env, se_num: i32) -> i32;

/// Caller of sc_card.sc_card_operations.decipher
///
/// params passed : Nothing else but all req. by decipher{data, data_len, out, outlen  as per @param}\
/// @apiNote  checked OKAY for @param consistency, same  @param names\
/// @param  card        INOUT struct sc_card object\
/// @param  crgram      IN    data to be decrypted\
/// @param  crgram_len  IN    data's length\
/// @param  out         OUTIF plain text after decryption\
/// @param  outlen      IN    \
/// @return SC_SUCCESS on success, SC_ERROR
pub fn sc_decipher(card: *mut sc_card, crgram: *const u8, crgram_len: usize,
    out: *mut u8, outlen: usize) -> i32;
//(card: *mut sc_card, crgram: *const u8, crgram_len: usize,
//out: *mut u8, outlen: usize) -> i32 >,


/// Caller of sc_card.sc_card_operations.compute_signature
///
/// params passed : Nothing else but all req. by compute_signature{data, data_len, out, outlen  as per @param}\
/// @apiNote  checked OKAY for @param consistency, same  @param names\
/// @param  card      INOUT struct sc_card object\
/// @param  data      IN    data to be signed (may be a hash only, or a digestInfo, or complete:
///                         padding+digestInfo (data_len==keyModLen as length in bytes)\
/// @param  data_len  IN    data's length\
/// @param  out       OUTIF signature\
/// @param  outlen    IN    Number of bytes available in out for signature, MUST at least be keyModLen reserved for
///                         signature (RSA,)\
/// @return SC_SUCCESS on success, SC_ERROR
pub fn sc_compute_signature(card: *mut sc_card, data: *const u8, data_len: usize,
                            out: *mut u8, outlen: usize) -> i32;

/// A wrapper function for sc_pin_cmd, specifically/only for pin verification
///
/// type of *data : sc_pin_cmd_data\
/// params passed : sc_pin_cmd_data.{cmd: SC_PIN_CMD_VERIFY, pin_type, pin_reference, pin1.data, pin1.len as per @param}\
/// @apiNote  Not passed: sc_pin_cmd_data.{flags, pin2, apdu}, nothing passed about pin1 except see above\
/// @param  card    INOUT struct sc_card object\
/// @param  type_   IN    usually SC_AC_CHV\
/// @param  ref_    IN    a pin_reference known by the card os (e.g. for acos5: pin id 0x01 local => ref_ == 0x81)\
/// @param  buf     IN    pin data\
/// @param  buflen  IN    pin data's length\
/// @param  tries_left  OUTIF\
/// @return SC_SUCCESS on success, SC_ERROR
pub fn sc_verify(card: *mut sc_card, type_: u32, ref_: i32, pin: *const u8, pinlen: usize,
                 tries_left: *mut i32) -> i32;

/**
 * Resets the security status of the card (i.e. withdraw all granted
 * access rights). Note: not all card operating systems support a logout
 * command and in this case SC_ERROR_NOT_SUPPORTED is returned.
 * @param  card  struct sc_card object
 * @return SC_SUCCESS on success, SC_ERROR_NOT_SUPPORTED if the card
 *         doesn't support a logout command and an error code otherwise
 */
pub fn sc_logout(card: *mut sc_card) -> i32;
pub fn sc_pin_cmd(card: *mut sc_card, arg1: *mut sc_pin_cmd_data, tries_left: *mut i32) -> i32;
pub fn sc_change_reference_data(card: *mut sc_card, type_: u32, ref_: i32, old: *const u8, oldlen: usize,
    newref: *const u8, newlen: usize,
    tries_left: *mut i32) -> i32;
pub fn sc_reset_retry_counter(card: *mut sc_card, type_: u32,
    ref_: i32, puk: *const u8, puklen: usize,
    newref: *const u8, newlen: usize) -> i32;
pub fn sc_build_pin(buf: *mut u8, buflen: usize, pin: *mut sc_pin_cmd_pin, pad: i32) -> i32;

#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
pub fn sc_encrypt_sym(card: *mut sc_card, Data: *const u8, DataLen: usize, out: *mut u8, outlen: *mut usize) -> i32;

#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
pub fn sc_decrypt_sym(card: *mut sc_card, EncryptedData: *const u8, EncryptedDataLen: usize,
                      out: *mut u8, outlen: *mut usize) -> i32;

/********************************************************************/
/*               ISO 7816-9 related functions                       */
/********************************************************************/

pub fn sc_create_file(card: *mut sc_card, file: *mut sc_file) -> i32;
pub fn sc_delete_file(card: *mut sc_card, path: *const sc_path) -> i32;

/* Card controls */

/// Caller of sc_card.sc_card_operations.card_ctl
/// params passed : Nothing else but all req. by card_ctl{command, data  as per @param}\
/// @apiNote  checked OKAY for @param consistency, same  @param names\
/// @param  card     INOUT struct sc_card object\
/// @param  command  IN     the command requested, SC_CARDCTL_* (cardctl.rs)\
/// @param  data     INOUT? the type depends on @param  command, typically some specialized struct\
/// @return SC_SUCCESS on success, SC_ERROR
pub fn sc_card_ctl(card: *mut sc_card, command: c_ulong, data: *mut c_void) -> i32;

/// the file is valid, if 1 is returned, otherwise its *NOT* valid and 0 get'd returned
/// @binding: No memory problem
pub safe fn sc_file_valid(file: *const sc_file) -> i32;
/// @binding: returns C heap allocated memory
pub safe fn sc_file_new() -> *mut sc_file;
/// @binding: deallocates C heap allocated memory; WARNING: Don't use file after calling sc_file_free,
///           dangling pointer not assigned to null !
pub safe fn sc_file_free(file: *mut sc_file);
pub fn sc_file_dup(dest: *mut *mut sc_file, src: *const sc_file);

/// Adds to a file's acl\[operation\] entry the IN method and key_ref. See specia treatment for SC_AC_NEVER existing already
///
/// @param  file       INOUTIF file.acl\[operation\] will receive symbolic addresses or malloc'ed *mut sc_acl_entry
///                            with method and key_ref set (crts and next not set)\
/// @param  operation  IN  one of types::SC_AC_OP_  e.g. SC_AC_OP_READ\
/// @param  method     IN  one of types::SC_AC_*  e.g. SC_AC_NEVER\
/// @param  key_ref    IN  key or pin reference as used within card, or SC_AC_KEY_REF_NONE\
/// @return SC_SUCCESS or error code
/// @apiNote  The function (for some methods) will add symbolic addresses (i.e. that can't be dereferenced)
pub fn sc_file_add_acl_entry(file: *mut sc_file, operation: u32, method: u32, key_ref: c_ulong) -> i32;
pub fn sc_file_get_acl_entry(file: *const sc_file, operation: u32) -> *const sc_acl_entry;
pub fn sc_file_clear_acl_entries(file: *mut sc_file, operation: u32);
pub fn sc_file_set_sec_attr(file: *mut sc_file, sec_attr: *const u8, sec_attr_len: usize) -> i32;
pub fn sc_file_set_prop_attr(file: *mut sc_file, prop_attr: *const u8, prop_attr_len: usize) -> i32;
pub fn sc_file_set_type_attr(file: *mut sc_file, type_attr: *const u8, type_attr_len: usize) -> i32;
pub fn sc_file_set_content(file: *mut sc_file, content: *const u8, content_len: usize) -> i32;

/********************************************************************/
/*               Key wrapping and unwrapping                        */
/********************************************************************/
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
pub fn sc_unwrap(card: *mut sc_card, data: *const u8,
                 data_len: usize, out: *mut u8, outlen: usize);

#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
pub fn sc_wrap(card: *mut sc_card, data: *const u8,
               data_len: usize, out: *mut u8, outlen: usize);

/********************************************************************/
/*             sc_path handling functions                           */
/********************************************************************/

/**
 * Sets the content of a sc_path object.
 * @param  path    sc_path object to set
 * @param  type    type of path
 * @param  id      value of the path
 * @param  id_len  length of the path value
 * @param  index   index within the file
 * @param  count   number of bytes
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_path_set(path: *mut sc_path, type_: i32, id: *const u8,
    id_len: usize, index: i32, count: i32) -> i32;

/// @param path_in: e.g. "i3F00" or ""I3f00"" or "3F004100" C strings (null term.). Must not be null
///
/// @binding: No memory problem only if path_out points to allocated sc_path or null!
pub fn sc_format_path(path_in: *const c_char, path_out: *mut sc_path);

/**
 * Return string representation of the given sc_path object
 * Warning: as static memory is used for the return value
 *          this function is not thread-safe !!!
 * @param  path  sc_path object of the path to be printed
 * @return pointer to a const buffer with the string representation
 *         of the path
 */
pub fn sc_print_path(path: *const sc_path) -> *const c_char;

/**
 * Prints the sc_path object to a character buffer
 * @param  buf     pointer to the buffer
 * @param  buflen  size of the buffer
 * @param  path    sc_path object to be printed
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_path_print(buf: *mut c_char, buflen: usize, path : *const sc_path) -> i32;

/**
 * Compares two sc_path objects
 * @param  patha  sc_path object of the first path
 * @param  pathb  sc_path object of the second path
 * @return 1 if both paths are equal and 0 otherwise
 */
pub fn sc_compare_path(patha: *const sc_path, pathb: *const sc_path) -> i32;

/**
 * Concatenate two sc_path values and store the result in
 * d (note: d can be the same as p1 or p2).
 * @param  d   destination sc_path object
 * @param  p1  first sc_path object
 * @param  p2  second sc_path object
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_concatenate_path(d: *mut sc_path, p1: *const sc_path, p2: *const sc_path) -> i32;
/**
 * Appends a sc_path object to another sc_path object (note:
 * this function is a wrapper for sc_concatenate_path)
 * @param  dest  destination sc_path object
 * @param  src   sc_path object to append
 * @return SC_SUCCESS on success and an error code otherwise
 */
pub fn sc_append_path(dest: *mut sc_path, src: *const sc_path) -> i32;
/**
 * Checks whether one path is a prefix of another path
 * @param  prefix  sc_path object with the prefix
 * @param  path    sc_path object with the path which should start
 *                 with the given prefix
 * @return 1 if the parameter prefix is a prefix of path and 0 otherwise
 */
pub fn sc_compare_path_prefix(prefix: *const sc_path, path: *const sc_path) -> i32;
pub fn sc_append_path_id (dest: *mut sc_path, id: *const u8, idlen: usize) -> i32;
pub fn sc_append_file_id(dest: *mut sc_path, fid: u32) -> i32;

/**
 * Returns a const sc_path object for the MF
 * @return sc_path object of the MF
 */
/// ATTENTION: Mind, that some member values settings seem suspicious:
/// count: 0, but should be -1
/// type_: SC_PATH_TYPE_PATH, but maybe should be SC_PATH_TYPE_FILE_ID
/// aid: all 0
/// @binding: No memory problem!  returns pointer to .rodata of libopensc.so
pub fn sc_get_mf_path() -> *const sc_path;


/********************************************************************/
/*             miscellaneous functions                              */
/********************************************************************/

/// The function converts a C string containing characters (hexadecimal 'digit' only) to an u8 representation,
/// i.e. each 2 c_char from input form  1 u8 of output
/// @param in_: input to be interpreted, length must be a multiple of 2; c_char allowed are '0'-'9', 'a'-'f' and 'A'-'F'
/// @param out: output buffer offered
/// @binding: No memory problem only if outlen is set correctly for out: outlen must be <= out.len()!
/// The function reads within the limits of zero terminated in_ and writes to out
/// Example: A call with in_: b"3F004100\0" and outlen>=4  will result in out: 0x [63, 0, 65, 0 ...], outlen: 4
pub fn sc_hex_to_bin(in_: *const c_char, out: *mut u8, outlen: *mut usize) -> i32;

/// The function converts an u8 array to a string representing the input as hexadecimal, human-readable/printable form.
/// It's the inverse function of sc_hex_to_bin.
/// @param in_: The u8 array input to be interpreted, may be NULL iff in_len==0
/// @param in_len: Less or equal to the amount of bytes memory-safely available from in_, may be 0
/// @param out: output buffer offered for the string represention, *MUST NOT* be NULL and *MUST* be sufficiently
///             allocated, see out_len
/// @param out_len: *MUST* be at least 1 and state how many bytes at least are memory-safely available within out to be
///                 written, including the \0 termination byte that will be written unconditionally.
/// @param separator: The character to be used to separate the u8 string representions. Any value<32 (32 corresponds
///                   to ' ' i.e. space) will suppress separation
/// The algorithm will require for out_len (otherwise resulting in an error SC_ERROR_BUFFER_TOO_SMALL):
///   1 (\0 termination byte) + 2*in_len + optional_separation_bytes
/// optional_separation_bytes = 0  if in_len<=1 or separator<' ',  otherwise
/// optional_separation_bytes = in_len-1, i.e. there will be no trailing separator character
/// Example: input \[0x3f\], in_len=1, requiring an out_len>=3, will write this to out: \[0x33,0x66,0x00\] which reads as "3f"
/// Example: input \[0x3f, 0x01\], in_len=2, separator=':', requiring an out_len>=6, will write this to out:
///   \[0x33, 0x66, 0x3A, 0x30, 0x31, 0x00\] which reads as "3f:01"
/// @binding: No memory problem only if the requirements above are met!

/// containing characters (hexadecimal 'digit' only), i.e. each 1 u8 from input form 2 c_char  of output.
/// possibly separated by a delimiter character
/// The function reads within the limits of zero terminated in_ and writes to out

/**
 * Converts an u8 array to a string representing the input as hexadecimal,
 * human-readable/printable form. It's the inverse function of sc_hex_to_bin.
 *
 * @param in The u8 array input to be interpreted, may be NULL iff in_len==0
 * @param in_len Less or equal to the amount of bytes available from in
 * @param out output buffer offered for the string representation, *MUST NOT*
 *             be NULL and *MUST* be sufficiently sized, see out_len
 * @param out_len *MUST* be at least 1 and state the maximum of bytes available
 *                 within out to be written, including the \0 termination byte
 *                 that will be written unconditionally
 * @param separator The character to be used to separate the u8 string
 *                   representations. `0` will suppress separation.
 *
 * Example: input \[0x3f\], in_len=1, requiring an out_len>=3, will write to out:
 * \[0x33, 0x66, 0x00\] which reads as "3f"
 * Example: input \[0x3f, 0x01\], in_len=2, separator=':', req. an out_len>=6,
 * writes to out: \[0x33, 0x66, 0x3A, 0x30, 0x31, 0x00\] which reads as "3f:01"
 */
pub fn sc_bin_to_hex(in_: *const u8, in_len: usize, out: *mut c_char, out_len: usize, separator: i32) -> i32;
    fn sc_right_trim(buf: *mut u8, len: usize) -> usize; // not declared pub because not exported from libopensc.so

pub fn sc_get_conf_block(ctx: *mut sc_context, name1: *const c_char, name2: *const c_char, priority: i32)
                         -> *mut scconf_block;
/**
 * Initializes a given OID
 * @param  oid  sc_object_id object to be initialized
 */
pub fn sc_init_oid(oid: *mut sc_object_id);
/**
 * Converts a given OID in ascii form to a internal sc_object_id object
 * @param  oid  OUT sc_object_id object for the result
 * @param  in   ascii string with the oid ("1.2.3.4.5...")
 * @return SC_SUCCESS or an error value if an error occurred.
 */
pub fn sc_format_oid(oid: *mut sc_object_id, in_: *const c_char) -> i32;
/**
 * Compares two sc_object_id objects
 * @param  oid1  the first sc_object_id object
 * @param  oid2  the second sc_object_id object
 * @return 1 if the oids are equal and a zero value otherwise
 */
pub fn sc_compare_oid(oid1: *const sc_object_id, oid2: *const sc_object_id) -> i32;
/**
 * Validates a given OID
 * @param  oid  sc_object_id object to be validated
 */
pub fn sc_valid_oid(oid: *const sc_object_id) -> i32;

/* Base64 encoding/decoding functions */
pub fn sc_base64_encode(in_: *const u8, inlen: usize, out: *mut u8, outlen: usize,
    linelength: usize) -> i32;
pub fn sc_base64_decode(in_: *const c_char, out: *mut u8, outlen: usize) -> i32;

/**
 * Clears a memory buffer (note: when OpenSSL is used this is
 * currently a wrapper for OPENSSL_cleanse() ).
 * @param  ptr  pointer to the memory buffer
 * @param  len  length of the memory buffer
 */
pub fn sc_mem_clear(ptr: *mut c_void, len: usize);
pub fn sc_mem_secure_alloc(len: usize) -> *mut c_void;  // added since opensc source release v0.20.0
pub fn sc_mem_secure_free(ptr: *mut c_void, len: usize);  // added since opensc source release v0.20.0
/*  added since opensc source release v0.23.0
#define sc_mem_secure_clear_free(ptr, len) do { \
sc_mem_clear(ptr, len); \
sc_mem_secure_free(ptr, len); \
} while (0);
*/
pub fn sc_mem_reverse(buf: *mut u8, len: usize) -> i32;

pub fn sc_get_cache_dir(ctx: *mut sc_context, buf: *mut c_char, bufsize: usize) -> i32;
pub fn sc_make_cache_dir(ctx: *mut sc_context) -> i32;

/**/
pub fn sc_enum_apps(card: *mut sc_card) -> i32;
pub fn sc_find_app(card: *mut sc_card, aid: *mut sc_aid) -> *mut sc_app_info;
pub fn sc_free_apps(card: *mut sc_card);
pub fn sc_parse_ef_atr(card: *mut sc_card) -> i32;
pub fn sc_free_ef_atr(card: *mut sc_card);
fn sc_parse_ef_gdo(card: *mut sc_card,
        iccsn: *mut u8, iccsn_len: *mut usize,
        chn: *mut u8, chn_len: *mut usize) -> i32;  // added since opensc source release v0.18.0
pub fn sc_update_dir(card: *mut sc_card, app: *mut sc_app_info) -> i32;

fn sc_invalidate_cache(card: *mut sc_card);  // added since opensc source release v0.18.0
pub fn sc_print_cache(card: *mut sc_card);

cfg_if::cfg_if! {
    if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
        pub fn sc_card_find_rsa_alg(card: *mut sc_card, key_length: u32) -> *mut sc_algorithm_info;
        pub fn sc_card_find_ec_alg(card: *mut sc_card, field_length: u32, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
            fn sc_card_find_gostr3410_alg(card: *mut sc_card, key_length: u32) -> *mut sc_algorithm_info;
    }
    else {
        pub fn sc_card_find_rsa_alg(card: *mut sc_card, key_length: usize) -> *mut sc_algorithm_info;
        pub fn sc_card_find_ec_alg(card: *mut sc_card, field_length: usize, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
            fn sc_card_find_gostr3410_alg(card: *mut sc_card, key_length: usize) -> *mut sc_algorithm_info;
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(v0_22_0, v0_23_0, v0_24_0))] {
        fn sc_card_find_eddsa_alg(card: *mut sc_card,
                                  field_length: u32, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
        fn sc_card_find_xeddsa_alg(card: *mut sc_card,
                                   field_length: u32, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
    }
    else if #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))] {
        fn sc_card_find_eddsa_alg(card: *mut sc_card,
                                  field_length: usize, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
        fn sc_card_find_xeddsa_alg(card: *mut sc_card,
                                   field_length: usize, curve_oid: *mut sc_object_id) -> *mut sc_algorithm_info;
    }
}
#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
fn sc_card_find_alg(card: *mut sc_card,
                    algorithm: u32, key_length: u32, param: *mut c_void) -> *mut sc_algorithm_info;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
fn sc_card_find_alg(card: *mut sc_card,
                    algorithm: u32, key_length: usize, param: *mut c_void) -> *mut sc_algorithm_info;

pub fn sc_match_atr_block(ctx: *mut sc_context, driver: *mut sc_card_driver, atr: *mut sc_atr) -> *mut scconf_block;

/**
 * Get CRC-32 digest
 * @param value pointer to data used for CRC calculation
 * @param len length of data used for CRC calculation
 */
pub fn sc_crc32(value: *const u8, len: usize) -> u32; // changed since opensc source release v0.18.0

/**
 * Find a given tag in a compact TLV structure
 * @param\[in\]  buf  input buffer holding the compact TLV structure
 * @param\[in\]  len  length of the input buffer @buf in bytes
 * @param\[in\]  tag  compact tag to search for - high nibble: plain tag, low nibble: length.
 *                  If length is 0, only the plain tag is used for searching,
 *                  in any other case, the length must also match.
 * @param\[out\] outlen pointer where the size of the buffer returned is to be stored
 * @return pointer to the tag value found within @buf, or NULL if not found/on error
 */
fn sc_compacttlv_find_tag(buf: *const u8, len: usize, tag: u8, outlen: *mut usize) -> *const u8;  // added since opensc source release v0.19.0

/**
 * Used to initialize the @c sc_remote_data structure --
 * reset the header of the 'remote APDUs' list, set the handlers
 * to manipulate the list.
 */
pub fn sc_remote_data_init(rdata: *mut sc_remote_data);


/**
 * Copy and allocate if needed EC parameters data
 * @dst destination
 * @src source
 */
fn sc_copy_ec_params(arg1: *mut sc_ec_parameters, arg2: *mut sc_ec_parameters) -> i32;

} // extern "C"


#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_card_error {
    pub SWs: u32,
    pub errorno: i32,
    pub errorstr: *const c_char,
}

unsafe extern "C" {
/// Release version of installed OpenSC software/binary libopensc.so/dll, opensc-pkcs11.so etc.
///
/// @return  returns what is defined in source code's config.h: #define PACKAGE_VERSION "0.??.0",
/// @binding: No memory problem!  returns pointer to .rodata of libopensc.so
/// @test available
pub safe fn sc_get_version() -> *const c_char;

/*
#define SC_IMPLEMENT_DRIVER_VERSION(a) \
 static const char *drv_version = (a); \
 const char *sc_driver_version()\
 { \
  return drv_version; \
 }
*/

/// The ISO 7816 reference driver, i.e. name, short_name and ops (of course no atr_map, natrs, neither dll)
///
/// It's value are a lot of generic implementations for sc_card.sc_card_operations, some are NULL\
/// @return   returns non-NULL pointer to statically allocated sc_card_driver{data and function pointers}\
/// @apiNote  The mutability of returned sc_card_driver doesn't make sense to me, should be used as *const sc_card_driver\
/// @binding: No memory problem!  returns pointers to either .rodata or .text of libopensc.so\
/// @test available
pub fn sc_get_iso7816_driver() -> *mut sc_card_driver;

/**
 * @brief Read a complete EF by short file identifier.
 *
 * @param\[in\]     card
 * @param\[in\]     sfid   Short file identifier
 * @param\[in,out\] ef     Where to save the file. the buffer will be allocated
 *                       using \c realloc() and should be set to NULL, if
 *                       empty.
 * @param\[in,out\] ef_len Length of \a *ef
 *
 * @note The appropriate directory must be selected before calling this function.
 * */
pub fn iso7816_read_binary_sfid(card: *mut sc_card, sfid: u8,
    ef: *mut *mut u8, ef_len: *mut usize) -> i32;       // since opensc source release v0.17.0

/**
 * @brief Write a complete EF by short file identifier.
 *
 * @param\[in\] card
 * @param\[in\] sfid   Short file identifier
 * @param\[in\] ef     Data to write
 * @param\[in\] ef_len Length of \a ef
 *
 * @note The appropriate directory must be selected before calling this function.
 * */
pub fn iso7816_write_binary_sfid (card: *mut sc_card, sfid: u8,
    ef: *mut u8, ef_len: usize) -> i32;                // since opensc source release v0.17.0

/**
* @brief Update a EF by short file identifier.
*
* @param\[in\] card   card
* @param\[in\] sfid   Short file identifier
* @param\[in\] ef     Data to write
* @param\[in\] ef_len Length of \a ef
*
* @note The appropriate directory must be selected before calling this function.
* */
pub fn iso7816_update_binary_sfid(card: *mut sc_card, sfid: u8,
                                  ef: *mut u8, ef_len: usize) -> i32;

/**
 * @brief Set verification status of a specific PIN to “not verified”
 *
 * @param\[in\] card
 * @param\[in\] pin_reference  PIN reference written to P2
 *
 * @note The appropriate directory must be selected before calling this function.
 * */
fn iso7816_logout(card: *mut sc_card, pin_reference: u8) -> i32;

/*
 * @brief Format PIN APDU for modification by card driver
 *
 * @param\[in\] card           card
 * @param\[in\] apdu           apdu structure to update with PIN APDU
 * @param\[in\] data           pin command data to set into the APDU
 * @param\[in\] buf            buffer for APDU data field
 * @param\[in\] buf_len        maximum buffer length
 */
#[cfg(not(v0_20_0))]
fn iso7816_build_pin_apdu(card: *mut sc_card, apdu: *mut sc_apdu,
                          data: *mut sc_pin_cmd_data, buf: *mut u8, buf_len: usize) -> i32;

/**
 * Free a buffer returned by OpenSC.
 * Use this instead your C libraries free() to free memory allocated by OpenSC.
 * For more details see <https://github.com/OpenSC/OpenSC/issues/2054>
 *
 * @param\[in\] p the buffer
 */
#[cfg(not(v0_20_0))]
pub fn sc_free(p: *mut c_void);

} // extern "C"


// wrappers

/*
pub fn sc_hex_to_bin_wrapper(in_: String /*&str*/) -> Result<Vec<u8>, i32>
{
    let mut vec: Vec<u8> = Vec::with_capacity((in_.len()+1)/2);
    let mut vec_length: usize = vec.capacity();
/*
    // copy in_ into new allocated Vec<u8>
    let mut vec_str: Vec<u8> = Vec::with_capacity(in_.len()+1);
    for element in in_.bytes() {
        vec_str.push(element);
    }
    let c_string : CString = CString::new(vec_str).expect("CString::new failed");
*/
    let c_string : CString = CString::new(in_).expect("CString::new failed");

//    unsafe {
        let rv = unsafe { sc_hex_to_bin(c_string.as_ptr(), vec.as_mut_ptr(), &mut vec_length) };
        if rv == 0 {
            // update the length to what was initialized.
            debug_assert!(vec_length<=vec.capacity(),"vec_length = {}, vec.capacity() = {}", vec_length, vec.capacity());
            unsafe { vec.set_len(vec_length) };
            Ok(vec)
        }
        else {
            Err(rv)
        }
//    }
}

/// The function converts an u8 array to a string representing the input as hexadecimal, human-readable/printable form.
/// It's the inverse function of sc_hex_to_bin.
/// @param in_: input to be interpreted, in_.len() may be 0
////// @param out: output buffer offered, *MUST NOT* be NULL and sufficiently allocated, see out_len
////// @param out_len: *MUST* be at least 1 and state how many bytes at least are safely available within out to be
/// written, including the \0 termination byte that will be written unconditionally.
////// The algorithm will require for out_len: 1 (\0 termination byte) + 2*in_len + optional_separation_bytes
////// optional_separation_bytes = 0  if in_len<=1 or separator<' ',  otherwise
////// optional_separation_bytes = in_len-1, i.e. there will be no trailing separator character
/// Example: input [0x3f], requiring an out_len>=3, will write this to out: [0x33, 0x66, 0x00] which reads as "3f"
/// Example: input [0x3f, 0x01], in_len=2, separator=':', requiring an out_len>=6, will write this to out:
/// [0x33, 0x66, 0x3A, 0x30, 0x31, 0x00] which reads as "3f:01"

/// @binding: No memory problem only if the requirements above are met!
/// The function reads within the limits of zero terminated in_ and writes to out
//b fn sc_bin_to_hex(in_: *const u8, in_len: usize, out: *mut c_char, out_len: usize, separator: i32) -> i32;
pub fn sc_bin_to_hex_wrapper(in_: &[u8], separator: i32) -> Result<String, i32>
{
//println!("Length in_ : {}", in_.len());
    let cap = 1+ in_.len()*2 + if separator>0 && !in_.is_empty() { in_.len()-1 } else { 0 };
    let mut vec: Vec<u8> = Vec::with_capacity(cap);
    vec.resize(cap-1, b'<'); // hold the characters excluding \0
assert_eq!(vec.len(), cap-1);

//println!("Length vec : {}", vec.len());
    let c_string = CString::new(vec).expect("CString::new failed"); // adds a \0 byte as termination
assert_eq!(c_string.as_bytes_with_nul().len(), cap);
//println!("Length raw : {}", cap);

    let raw: *mut c_char = c_string.into_raw(); // = null_mut();
/*
     due to a bug in C code (before commit https://github.com/OpenSC/OpenSC/commit/fd20ffe6081c3bc4b0c207f16787f353cd21c61f) in line:  if (pos + 3 + sep_len >= end)
     which should be correctly:       if (pos + 3 + in_len==0?0:sep_len >  end)
     the BUFFER_TOO_SMALL checking in C requires 1-2 exessive bytes to be pretended to be offered (i.e. 1-2 more than actually required)
     thus currently cheat sc_bin_to_hex to be offered 2 more bytes than actually allocated
     let in_ : *const u8 = null();

     frankmorgner:bin_hex
*/

    let rv = unsafe { sc_bin_to_hex(in_.as_ptr(), in_.len(), raw, cap+2, separator) };
//    assert_eq!(rv, 0);
    let c_string = unsafe { CString::from_raw(raw) };

    if rv == 0 {
        Ok(c_string.into_string().expect("c_string.into_string() call failed"))
    }
    else {
        Err(rv)
    }
}
*/

pub fn sc_bytes2apdu_wrapper(ctx: &mut sc_context, r#in: &[u8], apdu: &mut sc_apdu) -> i32 {
    unsafe { sc_bytes2apdu(ctx, r#in.as_ptr(), r#in.len(), apdu) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use super::*;

    #[test]
    fn test_sc_get_version() { // $ cargo test test_sc_get_version -- --nocapture
        println!("\n### Release version of installed OpenSC binaries is  {:?}  ###\n",
                 unsafe { CStr::from_ptr(sc_get_version()) });
    }

    #[test]
    fn test_sc_get_iso7816_driver() { // $ cargo test test_sc_get_iso7816_driver
        assert_eq!(false, unsafe { sc_get_iso7816_driver().is_null() });
    }
}
