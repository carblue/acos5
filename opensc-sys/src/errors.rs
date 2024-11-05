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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

use std::os::raw::c_char;

/// "Success"
pub const SC_SUCCESS                             : i32 =   0;

/* Errors related to reader operation */
/// "Generic reader error"
pub const SC_ERROR_READER                        : i32 =  -1100;
/// "No readers found"
pub const SC_ERROR_NO_READERS_FOUND              : i32 =  -1101;
/* Unused: -1102 */
/* Unused: -1103 */
/// "Card not present"
pub const SC_ERROR_CARD_NOT_PRESENT              : i32 =  -1104;
/// "Card removed"
pub const SC_ERROR_CARD_REMOVED                  : i32 =  -1105;
/// "Card reset"
pub const SC_ERROR_CARD_RESET                    : i32 =  -1106;
/// "Transmit failed"
pub const SC_ERROR_TRANSMIT_FAILED               : i32 =  -1107;
/// "Timed out while waiting for user input"
pub const SC_ERROR_KEYPAD_TIMEOUT                : i32 =  -1108;
/// "Input operation cancelled by user"
pub const SC_ERROR_KEYPAD_CANCELLED              : i32 =  -1109;
/// "The two PINs did not match"
pub const SC_ERROR_KEYPAD_PIN_MISMATCH           : i32 =  -1110;
/// "Message too long (keypad)"
pub const SC_ERROR_KEYPAD_MSG_TOO_LONG           : i32 =  -1111;
/// "Timeout while waiting for event from card reader"
pub const SC_ERROR_EVENT_TIMEOUT                 : i32 =  -1112;
/// "Unresponsive card (correctly inserted?)"
pub const SC_ERROR_CARD_UNRESPONSIVE             : i32 =  -1113;
/// "Reader detached (hotplug device?)"
pub const SC_ERROR_READER_DETACHED               : i32 =  -1114;
/// "Reader reattached (hotplug device?)"
pub const SC_ERROR_READER_REATTACHED             : i32 =  -1115;
/// "Reader in use by another application"
pub const SC_ERROR_READER_LOCKED                 : i32 =  -1116;

/* Resulting from a card command or related to the card*/
/// "Card command failed"
pub const SC_ERROR_CARD_CMD_FAILED               : i32 =  -1200;
/// "File not found"
pub const SC_ERROR_FILE_NOT_FOUND                : i32 =  -1201;
/// "Record not found"
pub const SC_ERROR_RECORD_NOT_FOUND              : i32 =  -1202;
/// "Unsupported CLA byte in APDU"
pub const SC_ERROR_CLASS_NOT_SUPPORTED           : i32 =  -1203;
/// "Unsupported INS byte in APDU"
pub const SC_ERROR_INS_NOT_SUPPORTED             : i32 =  -1204;
/// "Incorrect parameters in APDU"
pub const SC_ERROR_INCORRECT_PARAMETERS          : i32 =  -1205;
/// "Wrong length"
pub const SC_ERROR_WRONG_LENGTH                  : i32 =  -1206;
/// "Card memory failure"
pub const SC_ERROR_MEMORY_FAILURE                : i32 =  -1207;
/// "Card does not support the requested operation"
pub const SC_ERROR_NO_CARD_SUPPORT               : i32 =  -1208;
/// "Not allowed"
pub const SC_ERROR_NOT_ALLOWED                   : i32 =  -1209;
/// "Card is invalid or cannot be handled"
pub const SC_ERROR_INVALID_CARD                  : i32 =  -1210;
/// "Security status not satisfied"
pub const SC_ERROR_SECURITY_STATUS_NOT_SATISFIED : i32 =  -1211;
/// "Authentication method blocked"
pub const SC_ERROR_AUTH_METHOD_BLOCKED           : i32 =  -1212;
/// "Unknown data received from card"
pub const SC_ERROR_UNKNOWN_DATA_RECEIVED         : i32 =  -1213;
/// "PIN code or key incorrect"
pub const SC_ERROR_PIN_CODE_INCORRECT            : i32 =  -1214;
/// "File already exists"
pub const SC_ERROR_FILE_ALREADY_EXISTS           : i32 =  -1215;
/// "Data object not found"
pub const SC_ERROR_DATA_OBJECT_NOT_FOUND         : i32 =  -1216;
/// "Not enough memory on card"
pub const SC_ERROR_NOT_ENOUGH_MEMORY             : i32 =  -1217;
/// "Part of returned data may be corrupted"
pub const SC_ERROR_CORRUPTED_DATA                : i32 =  -1218;
/// "End of file/record reached before reading Le bytes"
pub const SC_ERROR_FILE_END_REACHED              : i32 =  -1219;
/// "Reference data not usable"
pub const SC_ERROR_REF_DATA_NOT_USABLE           : i32 =  -1220;

/* Returned by OpenSC library when called with invalid arguments */
/// "Invalid arguments"
pub const SC_ERROR_INVALID_ARGUMENTS             : i32 =  -1300;
/* Unused: -1301 */
/* Unused: -1302 */
/// "Buffer too small"
pub const SC_ERROR_BUFFER_TOO_SMALL              : i32 =  -1303;
/// "Invalid PIN length"
pub const SC_ERROR_INVALID_PIN_LENGTH            : i32 =  -1304;
/// "Invalid data"
pub const SC_ERROR_INVALID_DATA                  : i32 =  -1305;

/* Resulting from OpenSC internal operation */
/// "Internal error"
pub const SC_ERROR_INTERNAL                      : i32 =  -1400;
/// "Invalid ASN.1 object"
pub const SC_ERROR_INVALID_ASN1_OBJECT           : i32 =  -1401;
/// "Required ASN.1 object not found"
pub const SC_ERROR_ASN1_OBJECT_NOT_FOUND         : i32 =  -1402;
/// "Premature end of ASN.1 stream"
pub const SC_ERROR_ASN1_END_OF_CONTENTS          : i32 =  -1403;
/// "Out of memory"
pub const SC_ERROR_OUT_OF_MEMORY                 : i32 =  -1404;
/// "Too many objects"
pub const SC_ERROR_TOO_MANY_OBJECTS              : i32 =  -1405;
/// "Object not valid"
pub const SC_ERROR_OBJECT_NOT_VALID              : i32 =  -1406;
/// "Requested object not found"
pub const SC_ERROR_OBJECT_NOT_FOUND              : i32 =  -1407;
/// "Not supported"
pub const SC_ERROR_NOT_SUPPORTED                 : i32 =  -1408;
/// "Passphrase required"
pub const SC_ERROR_PASSPHRASE_REQUIRED           : i32 =  -1409;
/// "Inconsistent configuration"
pub const SC_ERROR_INCONSISTENT_CONFIGURATION    : i32 =  -1410;
/// "Decryption failed"
pub const SC_ERROR_DECRYPT_FAILED                : i32 =  -1411;
/// "Wrong padding"
pub const SC_ERROR_WRONG_PADDING                 : i32 =  -1412;
/// "Unsupported card"
pub const SC_ERROR_WRONG_CARD                    : i32 =  -1413;
/// "Unable to load external module"
pub const SC_ERROR_CANNOT_LOAD_MODULE            : i32 =  -1414;
/// "EF offset too large"
pub const SC_ERROR_OFFSET_TOO_LARGE              : i32 =  -1415;
/// "Not implemented"
pub const SC_ERROR_NOT_IMPLEMENTED               : i32 =  -1416;
/// "Invalid Simple TLV object",
pub const SC_ERROR_INVALID_TLV_OBJECT            : i32 =  -1417; // since opensc source release v0.19.0
/// "Premature end of Simple TLV stream"
pub const SC_ERROR_TLV_END_OF_CONTENTS           : i32 =  -1418; // since opensc source release v0.19.0

/* Relating to PKCS #15 init stuff */
/// "Generic PKCS#15 initialization error"
pub const SC_ERROR_PKCS15INIT                    : i32 =  -1500;
/// "Syntax error"
pub const SC_ERROR_SYNTAX_ERROR                  : i32 =  -1501;
/// "Inconsistent or incomplete PKCS#15 profile"
pub const SC_ERROR_INCONSISTENT_PROFILE          : i32 =  -1502;
/// "Key length/algorithm not supported by card"
pub const SC_ERROR_INCOMPATIBLE_KEY              : i32 =  -1503;
/// "No default (transport) key available"
pub const SC_ERROR_NO_DEFAULT_KEY                : i32 =  -1504;
/// "Non unique object ID"
pub const SC_ERROR_NON_UNIQUE_ID                 : i32 =  -1505;
/// "Unable to load key and certificate(s) from file"
pub const SC_ERROR_CANNOT_LOAD_KEY               : i32 =  -1506;
/* Unused: -1007 */
/// "File template not found"
pub const SC_ERROR_TEMPLATE_NOT_FOUND            : i32 =  -1508;
/// "Invalid PIN reference"
pub const SC_ERROR_INVALID_PIN_REFERENCE         : i32 =  -1509;
/// "File too small"
pub const SC_ERROR_FILE_TOO_SMALL                : i32 =  -1510;

/* Related to secure messaging */
/// "Generic Secure Messaging error"
pub const SC_ERROR_SM                            : i32 =  -1600;
/// "Data enciphering error"
pub const SC_ERROR_SM_ENCRYPT_FAILED             : i32 =  -1601;
/// "Invalid secure messaging level"
pub const SC_ERROR_SM_INVALID_LEVEL              : i32 =  -1602;
///"No session keys"
pub const SC_ERROR_SM_NO_SESSION_KEYS            : i32 =  -1603;
/// "Invalid session keys"
pub const SC_ERROR_SM_INVALID_SESSION_KEY        : i32 =  -1604;
/// "Secure Messaging not initialized"
pub const SC_ERROR_SM_NOT_INITIALIZED            : i32 =  -1605;
/// "Cannot authenticate card"
pub const SC_ERROR_SM_AUTHENTICATION_FAILED      : i32 =  -1606;
/// "Random generation error"
pub const SC_ERROR_SM_RAND_FAILED                : i32 =  -1607;
/// "Secure messaging keyset not found"
pub const SC_ERROR_SM_KEYSET_NOT_FOUND           : i32 =  -1608;
/// "IFD data missing"
pub const SC_ERROR_SM_IFD_DATA_MISSING           : i32 =  -1609;
/// "SM not applied"
pub const SC_ERROR_SM_NOT_APPLIED                : i32 =  -1610;
/// "SM session already active"
pub const SC_ERROR_SM_SESSION_ALREADY_ACTIVE     : i32 =  -1611;
/// "Invalid checksum"
pub const SC_ERROR_SM_INVALID_CHECKSUM           : i32 =  -1612;

/* Errors that do not fit the categories above */
/// "Unknown error"
pub const SC_ERROR_UNKNOWN                       : i32 =  -1900;
/// "PKCS#15 compatible smart card not found"
pub const SC_ERROR_PKCS15_APP_NOT_FOUND          : i32 =  -1901;

unsafe extern "C" {
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
    pub fn sc_strerror(sc_errno: i32) -> *const c_char;
}


#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use super::*;

    #[test]
    fn test_sc_strerror() {
        let data0      = c"Success";
        let data1900n = c"Unknown error";
        let data1     = data1900n;
        let data1n    = data1900n;
        let data1099  = data1900n;
        let data1099n = data1900n;

        let data1117  = data1900n;
        let data1117n = data1900n;
        let data1221n = data1900n;
        let data1306n = data1900n;

        let data1419n = data1900n;
        let data1511n = data1900n;
        let data1613n = data1900n;
        let data1902  = data1900n;
        let data1902n = data1900n;

        let data1100  = c"Generic reader error";
        let data1100n = c"Generic reader error";
        let data1116n = c"Reader in use by another application";
        let data1200n = c"Card command failed";
        let data1220n = c"Reference data not usable";

        let data1417n = c"Invalid Simple TLV object";
        let data1418n = c"Premature end of Simple TLV stream";

        let data1600n = c"Generic Secure Messaging error";
        let data1612n = c"Invalid checksum";
//      let data1900n = c"Unknown error";
        let data1901n = c"PKCS#15 compatible smart card not found";

        unsafe {
//          assert_eq!(data0.as_ptr() as *const c_char).to_bytes_with_nul(), CStr::from_ptr(sc_strerror(SC_SUCCESS)).to_bytes_with_nul());
            assert_eq!(data0    , CStr::from_ptr(sc_strerror( SC_SUCCESS)));
            assert_eq!(data1    , CStr::from_ptr(sc_strerror(  1)));
            assert_eq!(data1n   , CStr::from_ptr(sc_strerror( -1)));
            assert_eq!(data1099,  CStr::from_ptr(sc_strerror(  1099)));
            assert_eq!(data1099n, CStr::from_ptr(sc_strerror( -1099)));

            assert_eq!(data1117 , CStr::from_ptr(sc_strerror( 1117)));
            assert_eq!(data1117n, CStr::from_ptr(sc_strerror( -1117)));
            assert_eq!(data1221n, CStr::from_ptr(sc_strerror( -1221)));
            assert_eq!(data1306n, CStr::from_ptr(sc_strerror( -1306)));

            assert_eq!(data1419n, CStr::from_ptr(sc_strerror(  -1419)));
            assert_eq!(data1511n, CStr::from_ptr(sc_strerror(  -1511)));
            assert_eq!(data1613n, CStr::from_ptr(sc_strerror(-1613)));
            assert_eq!(data1902 , CStr::from_ptr(sc_strerror( 1902)));
            assert_eq!(data1902n, CStr::from_ptr(sc_strerror(-1902)));

            assert_eq!(data1100 , CStr::from_ptr(sc_strerror(-SC_ERROR_READER)));
            assert_eq!(data1100n, CStr::from_ptr(sc_strerror( SC_ERROR_READER)));
            assert_eq!(data1116n, CStr::from_ptr(sc_strerror(SC_ERROR_READER_LOCKED)));
            assert_eq!(data1200n, CStr::from_ptr(sc_strerror(SC_ERROR_CARD_CMD_FAILED)));
            assert_eq!(data1220n, CStr::from_ptr(sc_strerror(SC_ERROR_REF_DATA_NOT_USABLE)));

            assert_eq!(data1417n, CStr::from_ptr(sc_strerror( SC_ERROR_INVALID_TLV_OBJECT)));
            assert_eq!(data1418n, CStr::from_ptr(sc_strerror(  SC_ERROR_TLV_END_OF_CONTENTS)));

            assert_eq!(data1600n, CStr::from_ptr(sc_strerror(SC_ERROR_SM)));
            assert_eq!(data1612n, CStr::from_ptr(sc_strerror( SC_ERROR_SM_INVALID_CHECKSUM)));
            assert_eq!(data1900n, CStr::from_ptr(sc_strerror(SC_ERROR_UNKNOWN)));
            assert_eq!(data1901n, CStr::from_ptr(sc_strerror(SC_ERROR_PKCS15_APP_NOT_FOUND)));
        }
    }
}
