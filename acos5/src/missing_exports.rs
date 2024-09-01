/*
 * missing_exports.rs: Driver 'acos5' - OpenSC code duplicated
 *
 * card.c: General smart card functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * padding.c: miscellaneous padding functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003 - 2007  Nils Larsch <larsch@trustcenter.de>
 *
 * missing_exports.rs:
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

/*
OpenSC has some useful code, that's not available from libopensc.so due to missing 'export',
see file src/libopensc/libopensc.exports

1. Try to convince OpenSC to make that callable from libopensc.so/opensc.dll
2. In the meantime, for the external driver, that code must be duplicated here in Rust
*/
use std::ffi::CString;
use std::os::raw::c_void;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
use std::os::raw::c_ulong;

use std::slice;
use function_name::named;
use opensc_sys::opensc::{/*sc_context,*/ sc_card, sc_algorithm_info, SC_CARD_CAP_APDU_EXT,
                         SC_READER_SHORT_APDU_MAX_RECV_SIZE, //SC_READER_SHORT_APDU_MAX_SEND_SIZE, SC_PROTO_T0,
                         SC_ALGORITHM_EC, sc_compare_oid
/*                      ,SC_ALGORITHM_RSA_PAD_NONE, SC_ALGORITHM_RSA_PAD_PKCS1,
                         SC_ALGORITHM_RSA_HASH_NONE,
                         SC_ALGORITHM_RSA_HASH_MD5,
                         SC_ALGORITHM_RSA_HASH_SHA1,
                         SC_ALGORITHM_RSA_HASH_SHA256,
                         SC_ALGORITHM_RSA_HASH_SHA384,
                         SC_ALGORITHM_RSA_HASH_SHA512,
                         SC_ALGORITHM_RSA_HASH_SHA224,
                         SC_ALGORITHM_RSA_HASH_RIPEMD160,
                         SC_ALGORITHM_RSA_HASH_MD5_SHA1*/
};

use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL, SC_ERROR_OUT_OF_MEMORY, SC_ERROR_INVALID_ARGUMENTS};

use opensc_sys::types::sc_object_id; /*, sc_apdu, SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT, SC_APDU_CASE_2_EXT,
                        SC_APDU_CASE_3_SHORT, SC_APDU_CASE_3_EXT, SC_APDU_CASE_4_SHORT, SC_APDU_CASE_4_EXT*/

//use crate::constants_types::p_void;
use crate::wrappers::{wr_do_log, wr_do_log_rv_ret};

/*
/** Calculates the length of the encoded APDU in octets.
 *  @param  apdu   the APDU
 *  @param  proto  the desired protocol
 *  @return length of the encoded APDU
 */
#[must_use]
pub fn me_apdu_get_length(apdu: &sc_apdu, proto: u32) -> usize
{
    match apdu.cse {
        SC_APDU_CASE_1 => {
            if proto == SC_PROTO_T0 {5} else {4}
        },
        SC_APDU_CASE_2_SHORT => {
            5
        },
        SC_APDU_CASE_2_EXT => {
            if proto == SC_PROTO_T0 {5} else {7}
        },
        SC_APDU_CASE_3_SHORT => {
            apdu.lc + 5
        },
        SC_APDU_CASE_3_EXT => {
            apdu.lc + if proto == SC_PROTO_T0 {5} else {7}
        },
        SC_APDU_CASE_4_SHORT => {
            apdu.lc + if proto == SC_PROTO_T0 {5} else {6}
        },
        SC_APDU_CASE_4_EXT => {
            apdu.lc + if proto == SC_PROTO_T0 {5} else {9}
        },
        _ => {
            0
        },
    }
}
*/

/// An equivalent copy of: src/libopensc/card.c:  `size_t` `sc_get_max_recv_size(const` `sc_card_t` *card)
/* for acos5_get_response and iso7816_select_file_replica only */
#[must_use]
pub fn me_get_max_recv_size(card: &sc_card) -> usize
{
    if card.reader.is_null() {
        return 0;
    }
    let card_reader = unsafe { &*card.reader };
    let mut max_recv_size = card.max_recv_size;

    /* initialize max_recv_size to a meaningful value */
    if max_recv_size == 0 {
        max_recv_size = if (card.caps & SC_CARD_CAP_APDU_EXT) == 0 {/*256*/ SC_READER_SHORT_APDU_MAX_RECV_SIZE}
                        else {0x1_0000};
    }

    /*  Override card limitations with reader limitations. */
    if card_reader.max_recv_size != 0 && (card_reader.max_recv_size < max_recv_size) {
        max_recv_size = card_reader.max_recv_size;
    }
    max_recv_size
}

/*
/* no usage currently */
pub fn me_get_max_send_size(card: &sc_card) -> usize
{ // an equivalent copy of sc_get_max_send_size
    if /*card == NULL ||*/ card.reader.is_null() {
        return 0;
    }
    let card_reader = unsafe { & *card.reader };
    let mut max_send_size = card.max_send_size;

    /* initialize max_send_size to a meaningful value */
    if max_send_size == 0 {
        max_send_size = if (card.caps & SC_CARD_CAP_APDU_EXT) != 0 &&
            card_reader.active_protocol != SC_PROTO_T0 {0x1_0000-1} else {SC_READER_SHORT_APDU_MAX_SEND_SIZE};
    }

    /*  Override card limitations with reader limitations. */
    if card_reader.max_send_size != 0 && (card_reader.max_send_size < card.max_send_size) {
        max_send_size = card_reader.max_send_size;
    }
    max_send_size
}
*/

#[named]
fn me_card_add_algorithm(card: &mut sc_card, info: &sc_algorithm_info) -> i32
{
    if card.ctx.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    let p_ptr = unsafe { libc::realloc(card.algorithms.cast::<c_void>(), usize::try_from(card.algorithm_count + 1).unwrap() *
        size_of::<sc_algorithm_info>()) }.cast::<sc_algorithm_info>();

    if p_ptr.is_null() {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_OUT_OF_MEMORY);
    }
    card.algorithms = p_ptr;
    let p = unsafe { &mut * p_ptr.add(card.algorithm_count.try_into().unwrap()) };
    card.algorithm_count += 1;
    *p = *info;
//println!("card.algorithm_count: {}, p.algorithm: {}, p.key_length: {}, p.flags: {}", card.algorithm_count, p.algorithm, p.key_length, p.flags);
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

pub fn me_card_add_symmetric_alg(card: &mut sc_card,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                                 algorithm: u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                                 algorithm: c_ulong,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                                 key_length: u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                                 key_length: usize,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                                 flags: u32,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                                 flags: c_ulong,
                                ) -> i32
{ // same as in opensc
    let info = sc_algorithm_info {
        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                                       algorithm,
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                                       algorithm: algorithm.try_into().unwrap(),
        key_length, flags, .. sc_algorithm_info::default()
    };
    me_card_add_algorithm(card, &info)
}


pub fn me_card_find_alg(card: &mut sc_card,
                        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                        algorithm: u32,
                        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                        algorithm: c_ulong,
                        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                        key_length: u32,
                        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                        key_length: usize,
                        param_opt: Option<*const sc_object_id>)
    -> Option<*const sc_algorithm_info>
{
    for info in unsafe { slice::from_raw_parts(card.algorithms, card.algorithm_count.try_into().unwrap()) } {
        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
        if info.algorithm != algorithm { continue; }
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
        if info.algorithm != algorithm.try_into().unwrap() { continue; }
        if info.key_length != key_length { continue; }

        if let Some(param) = param_opt {
            #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
            let comp : u32 = SC_ALGORITHM_EC;
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
            let comp : u32 = SC_ALGORITHM_EC.try_into().unwrap();
            if info.algorithm == comp && unsafe { sc_compare_oid(param, &info.u.ec.params.id) } != 0 {
                continue;
            }
        }
        return Some(info);
    }
    None
}

/*
/**
 * Get the necessary padding and sec. env. flags.
 * @param  ctx     IN  sc_context object
 * @param  iflags  IN  the desired algorithms flags
 * @param  caps    IN  the card / key capabilities
 * @param  pflags  OUT the padding flags to use
 * @param  sflags  OUT the security env. algorithm flag to use
 * @return SC_SUCCESS on success and an error code otherwise
 */
#[named]
pub fn me_get_encoding_flags(ctx: *mut sc_context, iflags: u32, caps: u32,
                             pflags: &mut u32, sflags: &mut u32) -> i32
{
    const DIGEST_INFO_PREFIX: [u32; 9] = [
        SC_ALGORITHM_RSA_HASH_NONE,
        SC_ALGORITHM_RSA_HASH_MD5,
        SC_ALGORITHM_RSA_HASH_SHA1,
        SC_ALGORITHM_RSA_HASH_SHA256,
        SC_ALGORITHM_RSA_HASH_SHA384,
        SC_ALGORITHM_RSA_HASH_SHA512,
        SC_ALGORITHM_RSA_HASH_SHA224,
        SC_ALGORITHM_RSA_HASH_RIPEMD160,
        SC_ALGORITHM_RSA_HASH_MD5_SHA1
    ];

    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    log3ift!(ctx,f,line!(), c"iFlags 0x%X, card capabilities 0x%X", iflags, caps);
    {

        /* For ECDSA and GOSTR, we don't do any padding or hashing ourselves, the
         * card has to support the requested operation.  Similarly, for RSA with
         * raw padding (raw RSA) and ISO9796, we require the card to do it for us.
         * Finally, for PKCS1 (v1.5 and PSS) and ASNI X9.31 we can apply the padding
         * ourselves if the card supports raw RSA. */

        /* TODO: Could convert GOSTR3410_HASH_GOSTR3411 -> GOSTR3410_RAW and
         *       ECDSA_HASH_ -> ECDSA_RAW using OpenSSL (not much benefit though). */

        if (caps & iflags) == iflags {
            /* Card supports the signature operation we want to do, great, let's
             * go with it then. */
            *sflags = iflags;
            *pflags = 0;
        }
        else if (caps & SC_ALGORITHM_RSA_PAD_PSS) > 0 &&
              (iflags & SC_ALGORITHM_RSA_PAD_PSS) > 0
        {
            *sflags |=  SC_ALGORITHM_RSA_PAD_PSS;
        }
        else if (caps & SC_ALGORITHM_RSA_RAW) > 0 &&
             ((iflags & SC_ALGORITHM_RSA_PAD_PKCS1) > 0
                || (iflags & SC_ALGORITHM_RSA_PAD_PSS) > 0
                || (iflags & SC_ALGORITHM_RSA_PAD_NONE) > 0)
        {
            /* Use the card's raw RSA capability on the padded input */
            *sflags = SC_ALGORITHM_RSA_PAD_NONE;
            *pflags = iflags;
        }
        else if (caps & (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) > 0  &&
              (iflags &  SC_ALGORITHM_RSA_PAD_PKCS1) > 0
        {
            /* A corner case - the card can partially do PKCS1, if we prepend the
             * DigestInfo bit it will do the rest. */
            *sflags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
            *pflags = iflags & SC_ALGORITHM_RSA_HASHES;
        }
        else if (iflags & SC_ALGORITHM_AES) == SC_ALGORITHM_AES  /* TODO: seems like this constant does not belong to the same set of flags used form asymmetric algos. Fix this! */
        {
            *sflags = 0;
            *pflags = 0;
        }
        else if (iflags & SC_ALGORITHM_AES_FLAGS) > 0
        {
            *sflags = iflags & SC_ALGORITHM_AES_FLAGS;
            if (iflags &     SC_ALGORITHM_AES_CBC_PAD) > 0
                 { *pflags = SC_ALGORITHM_AES_CBC_PAD; }
            else { *pflags = 0; }
        }
        else {
            // LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "unsupported algorithm");
            return log3ifr_ret!(ctx,f,line!(), c"unsupported algorithm. Returning with", SC_ERROR_NOT_SUPPORTED);
        }
    }
    log3ift!(ctx,f,line!(), c"pad flags 0x%X, secure algorithm flags 0x%X", *pflags, *sflags);
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
} // pub fn me_get_encoding_flags
*/

/* Signature schemes supported natively by ACOS5:
ISO 9796-2 scheme 1 padding  http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf
PKCS #1: RSA Encryption  Version 1.5 with hash algos: SHA-1 and SHA-256 (other hash algo support done by the driver)



PKCS #1: RSA Encryption                   Version 1.5  https://tools.ietf.org/html/rfc2313
PKCS #1: RSA Cryptography Specifications  Version 2.0  https://tools.ietf.org/html/rfc2437
Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography
                           Specifications Version 2.1  https://tools.ietf.org/html/rfc3447
PKCS #1: RSA Cryptography Specifications  Version 2.2  https://tools.ietf.org/html/rfc8017
                                                       http://www.rfc-editor.org/errata/rfc8017
*/

///  Strips PKCS#1-v1.5 padding (BT==0x01); @param `in_dat` is meant to be signed, using the private part of RSA key pair
///  @apiNote replaces `internals.rs:sc_pkcs1_strip_01_padding`, ATTENTION: Intentionally not identical to opensc code !
///  @param  `in_dat`  IN Input data for sign operation, having PKCS#1-v1.5 padding (with BT==0x01)
///  @return         A view into `in_dat` after stripping (BlockType==0x01) padding, which is `DigestInfo`, or
///                  if no valid PKCS#1-v1.5 padding for sign operation could be detected, the function returns
///                  either `SC_ERROR_INTERNAL` or `SC_ERROR_WRONG_PADDING`.
///                  If an error occurs, `in_dat` may still be: Input data for sign operation, having PKCS#1-PSS padding,
///                  which has format: Let EM = maskedDB || H || 0xbc; (or maybe ISO 9796-2 scheme 1 padding ?)
///                  if `in_dat`'s last byte is not 0xbc, `in_dat`'s type of data is unknown
///
/// Example: `me_pkcs1_strip_01_padding` for `in_dat`:
/// 0001FFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
/// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFFFFFFFFFF00305130
/// 0D060960864801650304020305000440 2B16E868F69142C1F72BAE04A5F37534 3F223FA9A7690B431D5D26169970F302
/// 9FD4361205B444642423EC012CB29AC0 CD23064E2267C830362C90878898D327
///
/// returns:
/// 305130
/// 0D060960864801650304020305000440 2B16E868F69142C1F72BAE04A5F37534 3F223FA9A7690B431D5D26169970F302
/// 9FD4361205B444642423EC012CB29AC0 CD23064E2267C830362C90878898D327
///
/// which is (ASN.1 - decoded):
/// SEQUENCE (2 elem)
///   SEQUENCE (2 elem)
///     OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.3 sha-512 (NIST Algorithm)
///     NULL
///   OCTET STRING (64 byte) 2B16E868F69142C1F72BAE04A5F375343F223FA9A7690B431D5D26169970F3029FD436…
///
/// # Errors
///
/// Will return `Err` if there is no valid 01 padding
pub fn me_pkcs1_strip_01_padding(in_dat: &[u8]) -> Result<&[u8], i32>
{
    let  in_len = in_dat.len();
    let mut len = in_dat.len();

    if in_len < 11 {
        return Err(SC_ERROR_INTERNAL);
    }
    /* skip leading zero byte */
    if in_dat[0] != 0x00 || in_dat[1] != 0x01 {
        return Err(SC_ERROR_WRONG_PADDING);
    }
    len -= 2;

    while in_dat[in_len-len] == 0xff && len != 0 {
        len -= 1;
    }

    if len == 0 || in_len - len < 10 || in_dat[in_len-len] != 0x00 {
        return Err(SC_ERROR_WRONG_PADDING);
    }
    len -= 1;

    Ok(&in_dat[in_len-len..])
}

/*
pub fn me_pkcs1_add_01_padding(digest_info: &[u8], outlen: usize) -> Result<Vec<u8>, i32>
{
    if 11+digest_info.len() > outlen {
        return Err(SC_ERROR_KEYPAD_MSG_TOO_LONG);
    }
    let mut vec : Vec<u8> = Vec::with_capacity(outlen);
    vec.push(0);
    vec.push(1);
    for _i in 0..outlen-digest_info.len()-3 {
        vec.push(0xFF);
    }
    vec.push(0);
    for b in digest_info {
        vec.push(*b);
    }
    Ok(vec)
}
*/

/* remove pkcs1 BT02 padding */
/* returns length of padding to be removed from vec's crgram_len such that net message/plain text remains */
pub fn me_pkcs1_strip_02_padding(vec: &mut Vec<u8>) -> i32 //-> Result<Vec<u8>, i32>
{
//0  1  2  3  4  5  6  7  8  9  10  11
//00 02 1  2  3  4  5  6  7  8  00          PS_Len==8 is the minimum length of PS
    if vec.len() < 11 {
        return SC_ERROR_INTERNAL;
    }
    if vec[0] != 0 || vec[1] != 2 {
        return SC_ERROR_WRONG_PADDING;
    }
    vec[0] = 1; // arbitrary any non-0 value
    let pos = match vec.iter().position(|&x| x == 0) {
        Some(pos) => pos+1, // the position where the message==plain text starts
        None => return SC_ERROR_WRONG_PADDING,
    };
    if pos < 11 {
        return SC_ERROR_WRONG_PADDING;
    }
    drop(vec.drain(..pos));
    i32::try_from(pos).unwrap()
}

#[cfg(test)]
mod tests {
    use super::{me_pkcs1_strip_01_padding, me_pkcs1_strip_02_padding, SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL};
//    use opensc_sys::errors::{SC_SUCCESS};

    #[test]
    fn test_me_pkcs1_strip_01_padding() {
        let input = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAB];
        assert_eq!(me_pkcs1_strip_01_padding(&input), Ok(&input[11..]));
        let input = [0x00, 0x01,       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        assert_eq!(me_pkcs1_strip_01_padding(&input), Err(SC_ERROR_INTERNAL));
        let input = [0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAB];
        assert_eq!(me_pkcs1_strip_01_padding(&input), Err(SC_ERROR_WRONG_PADDING));
        let input = [0x00, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAB];
        assert_eq!(me_pkcs1_strip_01_padding(&input), Err(SC_ERROR_WRONG_PADDING));
        let input = [0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0xAB];
        assert_eq!(me_pkcs1_strip_01_padding(&input), Err(SC_ERROR_WRONG_PADDING));
    }

    #[test]
    fn test_me_pkcs1_strip_02_padding() {
        let mut vec = vec![0_u8, 2,  1,2,3,4,5,6,7,8,  0,  0xAB];
        assert_eq!(me_pkcs1_strip_02_padding(&mut vec), 11);
        assert_eq!(vec[0], 0xAB);
    }
}
