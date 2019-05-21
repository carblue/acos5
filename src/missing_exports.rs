/*
 * missing_exports.rs: Driver 'acos5_64' - OpenSC code duplicated
 *
 * card.c: General smart card functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * padding.c: miscellaneous padding functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003 - 2007  Nils Larsch <larsch@trustcenter.de>
 *
 * missing_exports.rs:
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
OpenSC has some useful code, that's not available from libopensc.so due to missing 'export',
see file src/libopensc/libopensc.exports

1. Try to convince OpenSC to make that callable from libopensc.so/opensc.dll
2. In the meantime, for the external driver, that code must be duplicated here in Rust
*/

use std::os::raw::{c_int};

/*
//use std::ptr::{copy_nonoverlapping};
//use std::ffi::{/*CString,*/ CStr};

//use opensc_sys::types::{sc_apdu};
//use opensc_sys::log::{sc_do_log, SC_LOG_DEBUG_NORMAL};
//use crate::constants_types::*;
//use super::{};
*/
use opensc_sys::opensc::{sc_card, SC_CARD_CAP_APDU_EXT, SC_PROTO_T0,
                         SC_READER_SHORT_APDU_MAX_SEND_SIZE, SC_READER_SHORT_APDU_MAX_RECV_SIZE};
use opensc_sys::errors::{SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL
//                       , SC_ERROR_INVALID_ARGUMENTS, SC_SUCCESS, SC_ERROR_NOT_SUPPORTED
};


/* for acos5_64_get_response only */
pub fn me_get_max_recv_size(card: &sc_card) -> usize
{ // an equivalent copy of sc_get_max_recv_size
    if /*card == NULL ||*/ card.reader.is_null() {
        return 0;
    }
    let card_reader = unsafe { & *card.reader };
    let mut max_recv_size = card.max_recv_size;

    /* initialize max_recv_size to a meaningful value */
    if max_recv_size == 0 {
        max_recv_size = if card.caps & SC_CARD_CAP_APDU_EXT != 0 {0x1_0000} else {SC_READER_SHORT_APDU_MAX_RECV_SIZE};
    }

    /*  Override card limitations with reader limitations. */
    if card_reader.max_recv_size != 0 && (card_reader.max_recv_size < card.max_recv_size) {
        max_recv_size = card_reader.max_recv_size;
    }
    max_recv_size
}

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
        max_send_size = if card.caps & SC_CARD_CAP_APDU_EXT != 0 &&
            card_reader.active_protocol != SC_PROTO_T0 {0x1_0000-1} else {SC_READER_SHORT_APDU_MAX_SEND_SIZE};
    }

    /*  Override card limitations with reader limitations. */
    if card_reader.max_send_size != 0 && (card_reader.max_send_size < card.max_send_size) {
        max_send_size = card_reader.max_send_size;
    }
    max_send_size
}


/* Signature schemes supported natively by ACOS5-64:
ISO 9796-2 scheme 1 padding  http://www.sarm.am/docs/ISO_IEC_9796-2_2002(E)-Character_PDF_document.pdf
PKCS #1: RSA Encryption  Version 1.5 with hash algos: SHA-1 and SHA-256 (other hash algo support done by the driver)



PKCS #1: RSA Encryption                   Version 1.5  https://tools.ietf.org/html/rfc2313
PKCS #1: RSA Cryptography Specifications  Version 2.0  https://tools.ietf.org/html/rfc2437
Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography
                           Specifications Version 2.1  https://tools.ietf.org/html/rfc3447
PKCS #1: RSA Cryptography Specifications  Version 2.2  https://tools.ietf.org/html/rfc8017
                                                       http://www.rfc-editor.org/errata/rfc8017
*/

///  Strips PKCS#1-v1.5 padding (BT==0x01); @param in_dat is meant to be signed, using the private part of RSA key pair
///  @apiNote replaces internals.rs:sc_pkcs1_strip_01_padding, ATTENTION: Intentionally not identical to opensc code !
///  @param  in_dat  IN Input data for sign operation, having PKCS#1-v1.5 padding (with BT==0x01)
///  @return         A view into in_dat after stripping (BlockType==0x01) padding, which is DigestInfo, or
///                  if no valid PKCS#1-v1.5 padding for sign operation could be detected, the function returns
///                  either SC_ERROR_INTERNAL or SC_ERROR_WRONG_PADDING.
///                  If an error occurs, in_dat may still be: Input data for sign operation, having PKCS#1-PSS padding,
///                  which has format: Let EM = maskedDB || H || 0xbc; (or maybe ISO 9796-2 scheme 1 padding ?)
///                  if in_dat's last byte is not 0xbc, in_dat's type of data is unknown
///
/// Example: me_pkcs1_strip_01_padding for in_dat:
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
pub fn me_pkcs1_strip_01_padding(in_dat: &[u8]) -> Result<&[u8], c_int>
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


#[cfg(test)]
mod tests {
    use super::{me_pkcs1_strip_01_padding, SC_ERROR_WRONG_PADDING, SC_ERROR_INTERNAL};

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
}
