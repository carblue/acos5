/*
 * errors.h: OpenSC error codes
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

use std::os::raw::{c_char, c_int};

/// "Success"
pub const SC_SUCCESS                             : c_int =   0;

/* Errors related to reader operation */
/// "Generic reader error"
pub const SC_ERROR_READER                        : c_int =  -1100;
/// "No readers found"
pub const SC_ERROR_NO_READERS_FOUND              : c_int =  -1101;
/* Unused: -1102 */
/* Unused: -1103 */
/// "Card not present"
pub const SC_ERROR_CARD_NOT_PRESENT              : c_int =  -1104;
/// "Card removed"
pub const SC_ERROR_CARD_REMOVED                  : c_int =  -1105;
/// "Card reset"
pub const SC_ERROR_CARD_RESET                    : c_int =  -1106;
/// "Transmit failed"
pub const SC_ERROR_TRANSMIT_FAILED               : c_int =  -1107;
/// "Timed out while waiting for user input"
pub const SC_ERROR_KEYPAD_TIMEOUT                : c_int =  -1108;
/// "Input operation cancelled by user"
pub const SC_ERROR_KEYPAD_CANCELLED              : c_int =  -1109;
/// "The two PINs did not match"
pub const SC_ERROR_KEYPAD_PIN_MISMATCH           : c_int =  -1110;
/// "Message too long (keypad)"
pub const SC_ERROR_KEYPAD_MSG_TOO_LONG           : c_int =  -1111;
/// "Timeout while waiting for event from card reader"
pub const SC_ERROR_EVENT_TIMEOUT                 : c_int =  -1112;
/// "Unresponsive card (correctly inserted?)"
pub const SC_ERROR_CARD_UNRESPONSIVE             : c_int =  -1113;
/// "Reader detached (hotplug device?)"
pub const SC_ERROR_READER_DETACHED               : c_int =  -1114;
/// "Reader reattached (hotplug device?)"
pub const SC_ERROR_READER_REATTACHED             : c_int =  -1115;
/// "Reader in use by another application"
pub const SC_ERROR_READER_LOCKED                 : c_int =  -1116;

/* Resulting from a card command or related to the card*/
/// "Card command failed"
pub const SC_ERROR_CARD_CMD_FAILED               : c_int =  -1200;
/// "File not found"
pub const SC_ERROR_FILE_NOT_FOUND                : c_int =  -1201;
/// "Record not found"
pub const SC_ERROR_RECORD_NOT_FOUND              : c_int =  -1202;
/// "Unsupported CLA byte in APDU"
pub const SC_ERROR_CLASS_NOT_SUPPORTED           : c_int =  -1203;
/// "Unsupported INS byte in APDU"
pub const SC_ERROR_INS_NOT_SUPPORTED             : c_int =  -1204;
/// "Incorrect parameters in APDU"
pub const SC_ERROR_INCORRECT_PARAMETERS          : c_int =  -1205;
/// "Wrong length"
pub const SC_ERROR_WRONG_LENGTH                  : c_int =  -1206;
/// "Card memory failure"
pub const SC_ERROR_MEMORY_FAILURE                : c_int =  -1207;
/// "Card does not support the requested operation"
pub const SC_ERROR_NO_CARD_SUPPORT               : c_int =  -1208;
/// "Not allowed"
pub const SC_ERROR_NOT_ALLOWED                   : c_int =  -1209;
/// "Card is invalid or cannot be handled"
pub const SC_ERROR_INVALID_CARD                  : c_int =  -1210;
/// "Security status not satisfied"
pub const SC_ERROR_SECURITY_STATUS_NOT_SATISFIED : c_int =  -1211;
/// "Authentication method blocked"
pub const SC_ERROR_AUTH_METHOD_BLOCKED           : c_int =  -1212;
/// "Unknown data received from card"
pub const SC_ERROR_UNKNOWN_DATA_RECEIVED         : c_int =  -1213;
/// "PIN code or key incorrect"
pub const SC_ERROR_PIN_CODE_INCORRECT            : c_int =  -1214;
/// "File already exists"
pub const SC_ERROR_FILE_ALREADY_EXISTS           : c_int =  -1215;
/// "Data object not found"
pub const SC_ERROR_DATA_OBJECT_NOT_FOUND         : c_int =  -1216;
/// "Not enough memory on card"
pub const SC_ERROR_NOT_ENOUGH_MEMORY             : c_int =  -1217;
/// "Part of returned data may be corrupted"
pub const SC_ERROR_CORRUPTED_DATA                : c_int =  -1218;
/// "End of file/record reached before reading Le bytes"
pub const SC_ERROR_FILE_END_REACHED              : c_int =  -1219;
/// "Reference data not usable"
pub const SC_ERROR_REF_DATA_NOT_USABLE           : c_int =  -1220;

/* Returned by OpenSC library when called with invalid arguments */
/// "Invalid arguments"
pub const SC_ERROR_INVALID_ARGUMENTS             : c_int =  -1300;
/* Unused: -1301 */
/* Unused: -1302 */
/// "Buffer too small"
pub const SC_ERROR_BUFFER_TOO_SMALL              : c_int =  -1303;
/// "Invalid PIN length"
pub const SC_ERROR_INVALID_PIN_LENGTH            : c_int =  -1304;
/// "Invalid data"
pub const SC_ERROR_INVALID_DATA                  : c_int =  -1305;

/* Resulting from OpenSC internal operation */
/// "Internal error"
pub const SC_ERROR_INTERNAL                      : c_int =  -1400;
/// "Invalid ASN.1 object"
pub const SC_ERROR_INVALID_ASN1_OBJECT           : c_int =  -1401;
/// "Required ASN.1 object not found"
pub const SC_ERROR_ASN1_OBJECT_NOT_FOUND         : c_int =  -1402;
/// "Premature end of ASN.1 stream"
pub const SC_ERROR_ASN1_END_OF_CONTENTS          : c_int =  -1403;
/// "Out of memory"
pub const SC_ERROR_OUT_OF_MEMORY                 : c_int =  -1404;
/// "Too many objects"
pub const SC_ERROR_TOO_MANY_OBJECTS              : c_int =  -1405;
/// "Object not valid"
pub const SC_ERROR_OBJECT_NOT_VALID              : c_int =  -1406;
/// "Requested object not found"
pub const SC_ERROR_OBJECT_NOT_FOUND              : c_int =  -1407;
/// "Not supported"
pub const SC_ERROR_NOT_SUPPORTED                 : c_int =  -1408;
/// "Passphrase required"
pub const SC_ERROR_PASSPHRASE_REQUIRED           : c_int =  -1409;
/// "Inconsistent configuration"
pub const SC_ERROR_INCONSISTENT_CONFIGURATION    : c_int =  -1410;
/// "Decryption failed"
pub const SC_ERROR_DECRYPT_FAILED                : c_int =  -1411;
/// "Wrong padding"
pub const SC_ERROR_WRONG_PADDING                 : c_int =  -1412;
/// "Unsupported card"
pub const SC_ERROR_WRONG_CARD                    : c_int =  -1413;
/// "Unable to load external module"
pub const SC_ERROR_CANNOT_LOAD_MODULE            : c_int =  -1414;
/// "EF offset too large"
pub const SC_ERROR_OFFSET_TOO_LARGE              : c_int =  -1415;
/// "Not implemented"
pub const SC_ERROR_NOT_IMPLEMENTED               : c_int =  -1416;
/// "Invalid Simple TLV object",
#[cfg(not(any(v0_17_0, v0_18_0)))]
pub const SC_ERROR_INVALID_TLV_OBJECT            : c_int =  -1417; // since opensc source release v0.19.0
/// "Premature end of Simple TLV stream"
#[cfg(not(any(v0_17_0, v0_18_0)))]
pub const SC_ERROR_TLV_END_OF_CONTENTS           : c_int =  -1418; // since opensc source release v0.19.0

/* Relating to PKCS #15 init stuff */
/// "Generic PKCS#15 initialization error"
pub const SC_ERROR_PKCS15INIT                    : c_int =  -1500;
/// "Syntax error"
pub const SC_ERROR_SYNTAX_ERROR                  : c_int =  -1501;
/// "Inconsistent or incomplete PKCS#15 profile"
pub const SC_ERROR_INCONSISTENT_PROFILE          : c_int =  -1502;
/// "Key length/algorithm not supported by card"
pub const SC_ERROR_INCOMPATIBLE_KEY              : c_int =  -1503;
/// "No default (transport) key available"
pub const SC_ERROR_NO_DEFAULT_KEY                : c_int =  -1504;
/// "Non unique object ID"
pub const SC_ERROR_NON_UNIQUE_ID                 : c_int =  -1505;
/// "Unable to load key and certificate(s) from file"
pub const SC_ERROR_CANNOT_LOAD_KEY               : c_int =  -1506;
/* Unused: -1007 */
/// "File template not found"
pub const SC_ERROR_TEMPLATE_NOT_FOUND            : c_int =  -1508;
/// "Invalid PIN reference"
pub const SC_ERROR_INVALID_PIN_REFERENCE         : c_int =  -1509;
/// "File too small"
pub const SC_ERROR_FILE_TOO_SMALL                : c_int =  -1510;

/* Related to secure messaging */
/// "Generic Secure Messaging error"
pub const SC_ERROR_SM                            : c_int =  -1600;
/// "Data enciphering error"
pub const SC_ERROR_SM_ENCRYPT_FAILED             : c_int =  -1601;
/// "Invalid secure messaging level"
pub const SC_ERROR_SM_INVALID_LEVEL              : c_int =  -1602;
///"No session keys"
pub const SC_ERROR_SM_NO_SESSION_KEYS            : c_int =  -1603;
/// "Invalid session keys"
pub const SC_ERROR_SM_INVALID_SESSION_KEY        : c_int =  -1604;
/// "Secure Messaging not initialized"
pub const SC_ERROR_SM_NOT_INITIALIZED            : c_int =  -1605;
/// "Cannot authenticate card"
pub const SC_ERROR_SM_AUTHENTICATION_FAILED      : c_int =  -1606;
/// "Random generation error"
pub const SC_ERROR_SM_RAND_FAILED                : c_int =  -1607;
/// "Secure messaging keyset not found"
pub const SC_ERROR_SM_KEYSET_NOT_FOUND           : c_int =  -1608;
/// "IFD data missing"
pub const SC_ERROR_SM_IFD_DATA_MISSING           : c_int =  -1609;
/// "SM not applied"
pub const SC_ERROR_SM_NOT_APPLIED                : c_int =  -1610;
/// "SM session already active"
pub const SC_ERROR_SM_SESSION_ALREADY_ACTIVE     : c_int =  -1611;
/// "Invalid checksum"
pub const SC_ERROR_SM_INVALID_CHECKSUM           : c_int =  -1612;

/* Errors that do not fit the categories above */
/// "Unknown error"
pub const SC_ERROR_UNKNOWN                       : c_int =  -1900;
/// "PKCS#15 compatible smart card not found"
pub const SC_ERROR_PKCS15_APP_NOT_FOUND          : c_int =  -1901;

extern "C" {
    /// Returns the text (C string) associated with the error number `sc_errno` defined in this module.
    ///
    /// @param sc_errno  IN:<br>
    /// if 0 (==SC_SUCCESS), it's no error but success, returns "Success".<br>
    /// if sc_errno or it's negated value (i.e. -abs(sc_errno)) matches any of the predefined  pub const SC_ERROR_...,
    /// then the text contained in the error text database (@see function errors.c::sc_strerror) is returned,<br>
    /// otherwise "Unknown error" will be returned.<br>
    /// @return  associated text
    ///
    /// Thus it's recommended to use as param only predefined 'SC_SUCCESS' or any of 'SC_ERROR_...'
    ///
    /// Rust: No memory problem!  returns pointer to .rodata of libopensc.so
    /// @test available
    pub fn sc_strerror(sc_errno: c_int) -> *const c_char;
}


#[cfg(test)]
mod tests {
    use std::ffi::{CStr};
    use super::*;

    #[test]
    fn test_sc_strerror() {
        let data0      = b"Success\0";
        let data1900n = b"Unknown error\0";
        let data1     = data1900n;
        let data1n    = data1900n;
        let data1099  = data1900n;
        let data1099n = data1900n;

        let data1117  = data1900n;
        let data1117n = data1900n;
        let data1221n = data1900n;
        let data1306n = data1900n;

        #[cfg(    any(v0_17_0, v0_18_0))]
        let data1417n = data1900n;
        #[cfg(not(any(v0_17_0, v0_18_0)))]
        let data1419n = data1900n;
        let data1511n = data1900n;
        let data1613n = data1900n;
        let data1902  = data1900n;
        let data1902n = data1900n;

        let data1100  = b"Generic reader error\0";
        let data1100n = b"Generic reader error\0";
        let data1116n = b"Reader in use by another application\0";
        let data1200n = b"Card command failed\0";
        let data1220n = b"Reference data not usable\0";

        #[cfg(not(any(v0_17_0, v0_18_0)))]
        let data1417n = b"Invalid Simple TLV object\0";
        #[cfg(not(any(v0_17_0, v0_18_0)))]
        let data1418n = b"Premature end of Simple TLV stream\0";

        let data1600n = b"Generic Secure Messaging error\0";
        let data1612n = b"Invalid checksum\0";
//      let data1900n = b"Unknown error\0";
        let data1901n = b"PKCS#15 compatible smart card not found\0";

        unsafe {
//          assert_eq!(CStr::from_ptr(data0.as_ptr() as *const c_char).to_bytes_with_nul(), CStr::from_ptr(sc_strerror(SC_SUCCESS)).to_bytes_with_nul());
            assert_eq!(CStr::from_bytes_with_nul(data0    ).unwrap(), CStr::from_ptr(sc_strerror( SC_SUCCESS)));
            assert_eq!(CStr::from_bytes_with_nul(data1    ).unwrap(), CStr::from_ptr(sc_strerror(  1)));
            assert_eq!(CStr::from_bytes_with_nul(data1n   ).unwrap(), CStr::from_ptr(sc_strerror( -1)));
            assert_eq!(CStr::from_bytes_with_nul(data1099 ).unwrap(), CStr::from_ptr(sc_strerror(  1099)));
            assert_eq!(CStr::from_bytes_with_nul(data1099n).unwrap(), CStr::from_ptr(sc_strerror( -1099)));

            assert_eq!(CStr::from_bytes_with_nul(data1117 ).unwrap(), CStr::from_ptr(sc_strerror( 1117)));
            assert_eq!(CStr::from_bytes_with_nul(data1117n).unwrap(), CStr::from_ptr(sc_strerror( -1117)));
            assert_eq!(CStr::from_bytes_with_nul(data1221n).unwrap(), CStr::from_ptr(sc_strerror( -1221)));
            assert_eq!(CStr::from_bytes_with_nul(data1306n).unwrap(), CStr::from_ptr(sc_strerror( -1306)));

            #[cfg(    any(v0_17_0, v0_18_0))]
            assert_eq!(CStr::from_bytes_with_nul(data1417n).unwrap(), CStr::from_ptr(sc_strerror(  -1417)));
            #[cfg(not(any(v0_17_0, v0_18_0)))]
            assert_eq!(CStr::from_bytes_with_nul(data1419n).unwrap(), CStr::from_ptr(sc_strerror(  -1419)));
            assert_eq!(CStr::from_bytes_with_nul(data1511n).unwrap(), CStr::from_ptr(sc_strerror(  -1511)));
            assert_eq!(CStr::from_bytes_with_nul(data1613n).unwrap(), CStr::from_ptr(sc_strerror(-1613)));
            assert_eq!(CStr::from_bytes_with_nul(data1902 ).unwrap(), CStr::from_ptr(sc_strerror( 1902)));
            assert_eq!(CStr::from_bytes_with_nul(data1902n).unwrap(), CStr::from_ptr(sc_strerror(-1902)));

            assert_eq!(CStr::from_bytes_with_nul(data1100 ).unwrap(), CStr::from_ptr(sc_strerror(-SC_ERROR_READER)));
            assert_eq!(CStr::from_bytes_with_nul(data1100n).unwrap(), CStr::from_ptr(sc_strerror( SC_ERROR_READER)));
            assert_eq!(CStr::from_bytes_with_nul(data1116n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_READER_LOCKED)));
            assert_eq!(CStr::from_bytes_with_nul(data1200n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_CARD_CMD_FAILED)));
            assert_eq!(CStr::from_bytes_with_nul(data1220n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_REF_DATA_NOT_USABLE)));

            #[cfg(not(any(v0_17_0, v0_18_0)))]
            assert_eq!(CStr::from_bytes_with_nul(data1417n).unwrap(), CStr::from_ptr(sc_strerror( SC_ERROR_INVALID_TLV_OBJECT)));
            #[cfg(not(any(v0_17_0, v0_18_0)))]
            assert_eq!(CStr::from_bytes_with_nul(data1418n).unwrap(), CStr::from_ptr(sc_strerror(  SC_ERROR_TLV_END_OF_CONTENTS)));

            assert_eq!(CStr::from_bytes_with_nul(data1600n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_SM)));
            assert_eq!(CStr::from_bytes_with_nul(data1612n).unwrap(), CStr::from_ptr(sc_strerror( SC_ERROR_SM_INVALID_CHECKSUM)));
            assert_eq!(CStr::from_bytes_with_nul(data1900n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_UNKNOWN)));
            assert_eq!(CStr::from_bytes_with_nul(data1901n).unwrap(), CStr::from_ptr(sc_strerror(SC_ERROR_PKCS15_APP_NOT_FOUND)));
        }
    }
}
