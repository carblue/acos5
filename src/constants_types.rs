/*
 * constants_types.rs: Driver 'acos5_64' - Code common to driver, pkcs15init and sm libraries, partially also acos5_gui
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

use std::os::raw::{c_uchar, c_int, c_uint};
use std::collections::HashMap;

use opensc_sys::opensc::{sc_security_env};
use opensc_sys::types::{sc_crt, SC_MAX_CRTS_IN_SE, SC_MAX_PATH_SIZE};
use opensc_sys::pkcs15::{SC_PKCS15_PRKDF, SC_PKCS15_PUKDF, SC_PKCS15_PUKDF_TRUSTED,
                         SC_PKCS15_SKDF, SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED, SC_PKCS15_CDF_USEFUL,
                         SC_PKCS15_DODF, SC_PKCS15_AODF};

// for an internal driver these 2 will move to cards.h
pub const SC_CARD_TYPE_ACOS5_64_V2 : i32 = 16003;
pub const SC_CARD_TYPE_ACOS5_64_V3 : i32 = 16004;

pub const ATR_V2   : &[u8; 57] = b"3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00\0"; // Using reader with a card: ACS CryptoMate64 00 00
pub const ATR_V3   : &[u8; 57] = b"3b:be:96:00:00:41:05:30:00:00:00:00:00:00:00:00:00:90:00\0"; // Using reader with a card: ACS CryptoMate (T2) 00 00  ; this is CryptoMate Nano
pub const ATR_MASK : &[u8; 57] = b"FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF\0";
pub const NAME_V2  : &[u8; 43] = b"ACOS5-64 v2.00: Smart Card or CryptoMate64\0";
pub const NAME_V3  : &[u8; 46] = b"ACOS5-64 v3.00: Smart Card or CryptoMate Nano\0";

pub const CARD_DRV_NAME       : &[u8;  96] = b"'acos5_64', suitable for ACOS5-64 v2.00 and v3.00 (Smart Card / CryptoMate64 / CryptoMate Nano)\0";
pub const CARD_DRV_SHORT_NAME : &[u8;   9] = b"acos5_64\0";

pub const CARD_DRIVER         : &[u8;  12] = b"card_driver\0";
pub const MODULE              : &[u8;   7] = b"module\0";
pub const LIB_DRIVER_NIX      : &[u8;  15] = b"libacos5_64.so\0";

pub const CARD_SM_SHORT_NAME  : &[u8;  12] = b"acos5_64_sm\0";
pub const SECURE_MESSAGING    : &[u8;  17] = b"secure_messaging\0";
pub const MODULE_PATH         : &[u8;  12] = b"module_path\0";
pub const MODULE_NAME         : &[u8;  12] = b"module_name\0";
pub const LIB_SM_NIX          : &[u8;  18] = b"libacos5_64_sm.so\0";

pub const CRATE               : &[u8;   9] = b"acos5_64\0"; // search acos5_64 mention in debug log file; each function should at least log CALLED, except small helpers or code that is clearly covered by only one possible surrounding function's called
pub const CALLED              : &[u8;   7] = b"called\0";
pub const RETURNING           : &[u8;  10] = b"returning\0";
pub const RETURNING_INT_CSTR  : &[u8;  25] = b"returning with: %d (%s)\n\0";
pub const RETURNING_INT       : &[u8;  20] = b"returning with: %d\n\0";

//pub const V_0_0_0   : &[u8; 6] = b"0.0.0\0";
//pub const V_0_15_0  : &[u8; 7] = b"0.15.0\0";
//pub const V_0_16_0  : &[u8; 7] = b"0.16.0\0";
//pub const V_0_17_0  : &[u8; 7] = b"0.17.0\0";
//pub const V_0_18_0  : &[u8; 7] = b"0.18.0\0";
//pub const V_0_19_0  : &[u8; 7] = b"0.19.0\0";

// iso7816 ReservedFutureUse tags used by acos, that are not part of iso7816.h/rs
//pub const ISO7816_RFU_TAG_FCP_SFI  : u8 = 0x88;  /* L:1,    V: Short File Identifier (SFI). 5 LSbs of File ID if unspecified. Applies to: Any file */
pub const ISO7816_RFU_TAG_FCP_SAC  : u8 = 0x8C;    /* L:0-8,  V: Security Attribute Compact (SAC). Applies to: Any file */
pub const ISO7816_RFU_TAG_FCP_SEID : u8 = 0x8D;    /* L:2,    V: Security Environment File identifier (SE File associated with this DF). Applies to: DFs */
//pub const ISO7816_RFU_TAG_FCP_SAE  : u8 = 0xAB;  /* L:0-32, V: Security Attribute Extended (SAE). Applies to: DFs */

//ACOS5 File Descriptor Bytes, the proprietary encoding of file types, the first within V of Tag ISO7816_TAG_FCP_TYPE:
pub const FDB_MF                 : u8 = 0x3F; // Master File     MF
pub const FDB_DF                 : u8 = 0x38; // Dedicated File  DF
/* Working Elementary Files  EF */
pub const FDB_TRANSPARENT_EF     : u8 = 0x01; // Transparent EF     == SC_FILE_EF_TRANSPARENT
pub const FDB_LINEAR_FIXED_EF    : u8 = 0x02; // Linear-Fixed EF    == SC_FILE_EF_LINEAR_FIXED
pub const FDB_LINEAR_VARIABLE_EF : u8 = 0x04; // Linear-Variable EF == SC_FILE_EF_LINEAR_VARIABLE
pub const FDB_CYCLIC_EF          : u8 = 0x06; // Cyclic EF          == SC_FILE_EF_CYCLIC
/* Internal EF */
pub const FDB_RSA_KEY_EF         : u8 = 0x09; // RSA Key EF, for private and public key file
pub const FDB_CHV_EF             : u8 = 0x0A; // CHV EF, for the pin file, max 1 only in each DF
pub const FDB_SYMMETRIC_KEY_EF   : u8 = 0x0C; // Symmetric Key EF,         max 1 only in each DF
pub const FDB_PURSE_EF           : u8 = 0x0E; // Purse EF since V3.00
/* Proprietary EF */
pub const FDB_SE_FILE            : u8 = 0x1C; // SE File,              exactly 1 only in each DF

/* the Control Reference Template Tags (CRT) understood by acos
ATTENTION with CRT_TAG_CT Confidentiality Template: In reality acos makes no difference for asym/sym, there is 0xB8 only
The distinction is artificial and for some reason, corrected later
*/
pub const CRT_TAG_HT      : u32 = 0xAA;   // Hash Template                 : AND:      Algorithm
pub const CRT_TAG_AT      : u32 = 0xA4;   // Authentication Template       : AND: UQB, Pin_Key,
pub const CRT_TAG_DST     : u32 = 0xB6;   // Digital Signature Template    : AND: UQB, Algorithm, KeyFile_RSA
pub const CRT_TAG_CT_ASYM : u32 = 0xB8+1; // Confidentiality Template      : AND: UQB, Algorithm       OR: KeyFile_RSA
pub const CRT_TAG_CT_SYM  : u32 = 0xB8+0; // Confidentiality Template      : AND: UQB, Algorithm       OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
pub const CRT_TAG_CT      : u32 = 0xB8;   // Confidentiality Template
pub const CRT_TAG_CCT     : u32 = 0xB4;   // Cryptographic Checksum Templ. : AND: UQB, Algorithm  ;    OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
pub const CRT_TAG_NA      : u32 = 0x00;   // N/A unknown

// the following bytes indicate, whether an SC Byte encodes Secure Messaging, it does't guarantee, that the referred command allows SM at all
pub const SM_MODE_NONE           : u8 = 0; // SM is not enforced/impossible as of SCB setting
pub const SM_MODE_CCT            : u8 = 1; // SM is enforced, providing Authenticity, specified by a  Cryptographic Checksum Template
pub const SM_MODE_CCT_AND_CT_SYM : u8 = 2; // SM is enforced, providing Authenticity and Confidentiality, specified by a  Cryptographic Checksum Template and Confidentiality Template (ref. key for sym. algorithm)

pub const PKCS15_FILE_TYPE_PRKDF         : u8 =  SC_PKCS15_PRKDF;         // = 0,
pub const PKCS15_FILE_TYPE_PUKDF         : u8 =  SC_PKCS15_PUKDF;         // = 1,
pub const PKCS15_FILE_TYPE_PUKDF_TRUSTED : u8 =  SC_PKCS15_PUKDF_TRUSTED; // = 2,   USES DETECTION LIKE PKCS15_FILE_TYPE_PUKDF !
pub const PKCS15_FILE_TYPE_SKDF          : u8 =  SC_PKCS15_SKDF;          // = 3,
pub const PKCS15_FILE_TYPE_CDF           : u8 =  SC_PKCS15_CDF;           // = 4,
pub const PKCS15_FILE_TYPE_CDF_TRUSTED   : u8 =  SC_PKCS15_CDF_TRUSTED;   // = 5,   USES DETECTION LIKE PKCS15_FILE_TYPE_CDF !
pub const PKCS15_FILE_TYPE_CDF_USEFUL    : u8 =  SC_PKCS15_CDF_USEFUL;    // = 6,   USES DETECTION LIKE PKCS15_FILE_TYPE_CDF !
pub const PKCS15_FILE_TYPE_DODF          : u8 =  SC_PKCS15_DODF;          // = 7,
pub const PKCS15_FILE_TYPE_AODF          : u8 =  SC_PKCS15_AODF;          // = 8,

pub const PKCS15_FILE_TYPE_DIR           : u8 =  10; // file 0x2F00  (preassigned acc. to ISO/IEC 7816-4)
pub const PKCS15_FILE_TYPE_ODF           : u8 =  11; // file 0x5031  (preassigned acc. to ISO/IEC 7816-4 or indicated in file 0x2F00)
pub const PKCS15_FILE_TYPE_TOKENINFO     : u8 =  12; // file 0x5032  (preassigned acc. to ISO/IEC 7816-4 or indicated in file 0x2F00)
pub const PKCS15_FILE_TYPE_UNUSED        : u8 =  13; // file 0x5033  (preassigned acc. to ISO/IEC 7816-4 or indicated in file 0x2F00)   DOESN'T NEED DETECTION  ???
pub const PKCS15_FILE_TYPE_APPDF         : u8 =  14; // file 0x4100  (arbitrary, indicated in file 0x2F00)       DOESN'T NEED DETECTION !

pub const PKCS15_FILE_TYPE_RSAPRIVATEKEY : u8 =  16;
pub const PKCS15_FILE_TYPE_RSAPUBLICKEY  : u8 =  9;  // e.g. file 0x4131  (arbitrary, when readable by read_public_key, asn1-der-encoded public RSA key file) RSA_PUB
pub const PKCS15_FILE_TYPE_SECRETKEY     : u8 =  17; // iEF with cos5
pub const PKCS15_FILE_TYPE_CERT          : u8 =  15;
pub const PKCS15_FILE_TYPE_DATA          : u8 =  19;
pub const PKCS15_FILE_TYPE_PIN           : u8 =  18; // iEF with cos5
pub const PKCS15_FILE_TYPE_NONE          : u8 =  0xFF; // should not happen to extract a path for this

pub const RSAPUB_MAX_LEN           : usize = 5 + 16 + 512; // the max. file size requirement for RSA public key (4096 bit == 512 byte; 16 byte is the max. public exponent length)
pub const RSAPRIV_MAX_LEN_STD      : usize = 5 +      512; // the max. file size requirement for RSA private key (non-CRT)
pub const RSAPRIV_MAX_LEN_CRT      : usize = 5 +   5* 256; // the max. file size requirement for RSA private key stored in CRT manner

//https://cryptosys.net/pki/manpki/pki_paddingschemes.html
// don't use BLOCKCIPHER_PAD_TYPE_ZEROES, if it's required to retrieve the message length exactly
pub const BLOCKCIPHER_PAD_TYPE_ZEROES             : u8 =  0; // as for  CKM_AES_CBC: adds max block size minus one null bytes (0 ≤ N < B Blocksize)
pub const BLOCKCIPHER_PAD_TYPE_ONEANDZEROES       : u8 =  1; // Unconditionally add a byte of value 0x80 followed by as many zero bytes as is necessary to fill the input to the next exact multiple of B
// be careful with BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5: It can't unambiguously be detected, what is padding, what is payload
pub const BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5 : u8 =  2; // Used in ACOS5 SM: Only if in_len isn't a multiple of blocksize, then add a byte of value 0x80 followed by as many zero bytes as is necessary to fill the input to the next exact multiple of B
// BLOCKCIPHER_PAD_TYPE_PKCS5 is the recommended one, otherwise BLOCKCIPHER_PAD_TYPE_ONEANDZEROES and BLOCKCIPHER_PAD_TYPE_ANSIX9_23 (BLOCKCIPHER_PAD_TYPE_W3C) also exhibit unambiguity
pub const BLOCKCIPHER_PAD_TYPE_PKCS5              : u8 =  3; // as for CKM_AES_CBC_PAD: If the block length is B then add N padding bytes (1 < N ≤ B Blocksize) of value N to make the input length up to the next exact multiple of B. If the input length is already an exact multiple of B then add B bytes of value B
pub const BLOCKCIPHER_PAD_TYPE_ANSIX9_23          : u8 =  4; // If N padding bytes are required (1 < N ≤ B Blocksize) set the last byte as N and all the preceding N-1 padding bytes as zero.
// BLOCKCIPHER_PAD_TYPE_W3C is not recommended
//b const BLOCKCIPHER_PAD_TYPE_W3C                : u8 =  5; // If N padding bytes are required (1 < N ≤ B Blocksize) set the last byte as N and all the preceding N-1 padding bytes as arbitrary byte values.

pub const SC_SEC_ENV_PARAM_DES_ECB           : c_uint = 3;
pub const SC_SEC_ENV_PARAM_DES_CBC           : c_uint = 4;

/* see opensc-sys: opensc.rs
pub const SC_SEC_OPERATION_DECIPHER            : c_int = 0x0001;
pub const SC_SEC_OPERATION_SIGN                : c_int = 0x0002;
pub const SC_SEC_OPERATION_AUTHENTICATE        : c_int = 0x0003;
pub const SC_SEC_OPERATION_DERIVE              : c_int = 0x0004;
#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_SEC_OPERATION_WRAP                : c_int = 0x0005;
#[cfg(not(any(v0_15_0, v0_16_0, v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_SEC_OPERATION_UNWRAP              : c_int = 0x0006;
*/
pub const SC_SEC_OPERATION_GENERATE_RSAPRIVATE : c_int = 0x0007; // sc_set_security_env must know this related to file id
pub const SC_SEC_OPERATION_GENERATE_RSAPUBLIC  : c_int = 0x0008; // sc_set_security_env must know this related to file id

pub const SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC  : c_int = 0x0009;
pub const SC_SEC_OPERATION_DECIPHER_RSAPRIVATE : c_int = 0x000A;

pub const SC_SEC_OPERATION_ENCIPHER_SYMMETRIC  : c_int = 0x000B;
pub const SC_SEC_OPERATION_DECIPHER_SYMMETRIC  : c_int = 0x000C;

/*
/*
 * Generic card_ctl calls, see opensc-sys: cardctl.rs
 */
pub const SC_CARDCTL_GENERIC_BASE            : c_uint =  0x0000_0000;
pub const SC_CARDCTL_ERASE_CARD              : c_uint =  0x0000_0001;
pub const SC_CARDCTL_GET_DEFAULT_KEY         : c_uint =  0x0000_0002;
pub const SC_CARDCTL_LIFECYCLE_GET           : c_uint =  0x0000_0003;
pub const SC_CARDCTL_LIFECYCLE_SET           : c_uint =  0x0000_0004;
pub const SC_CARDCTL_GET_SERIALNR            : c_uint =  0x0000_0005; // data: *mut sc_serial_number,  get_serialnr
pub const SC_CARDCTL_GET_SE_INFO             : c_uint =  0x0000_0006;
pub const SC_CARDCTL_GET_CHV_REFERENCE_IN_SE : c_uint =  0x0000_0007;
pub const SC_CARDCTL_PKCS11_INIT_TOKEN       : c_uint =  0x0000_0008;
pub const SC_CARDCTL_PKCS11_INIT_PIN         : c_uint =  0x0000_0009;
*/
/*
 * Proprietary card_ctl calls
 *
 * for an internal driver these will move to cardctl.h
*/
pub const SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF : c_uint =  0x0000_0011; // data: *mut usize,  get_count_files_curr_DF
pub const SC_CARDCTL_ACOS5_GET_FILE_INFO           : c_uint =  0x0000_0012; // data: *mut CardCtlArray8,  get_file_info
pub const SC_CARDCTL_ACOS5_GET_FREE_SPACE          : c_uint =  0x0000_0014; // data: *mut c_uint,  get_free_space
pub const SC_CARDCTL_ACOS5_GET_IDENT_SELF          : c_uint =  0x0000_0015; // data: *mut c_uint,  get_ident_self
pub const SC_CARDCTL_ACOS5_GET_COS_VERSION         : c_uint =  0x0000_0016; // data: *mut CardCtlArray8,  get_cos_version
/* available only since ACOS5-64 V3: */
pub const SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE: c_uint =  0x0000_0017; // data: *mut c_uint,  get_manufacture_date
pub const SC_CARDCTL_ACOS5_GET_ROM_SHA1            : c_uint =  0x0000_0018; // data: *mut CardCtlArray20,  get_rom_sha1
pub const SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE        : c_uint =  0x0000_0019; // data: *mut c_uint,  get_op_mode_byte
pub const SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE     : c_uint =  0x0000_001A; // data: *mut c_uint,  get_fips_compliance
pub const SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE      : c_uint =  0x0000_001B; // data: *mut CardCtlAuthState,  get_pin_auth_state
pub const SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE      : c_uint =  0x0000_001C; // data: *mut CardCtlAuthState,  get_key_auth_state

pub const SC_CARDCTL_ACOS5_UPDATE_FILES_HASHMAP    : c_uint =  0x0000_0020; // data: null
pub const SC_CARDCTL_ACOS5_GET_FILES_HASHMAP_INFO  : c_uint =  0x0000_0021; // data: *mut CardCtlArray32,  get_files_hashmap_info

pub const SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST  : c_uint =  0x0000_0022; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files exist, sec_env setting excluded
pub const SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE : c_uint =  0x0000_0023; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files must be created, sec_env setting excluded
pub const SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST_MSE  : c_uint =  0x0000_0024; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files exist, sec_env setting included
pub const SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE_MSE : c_uint =  0x0000_0025; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files must be created, sec_env setting included

pub const SC_CARDCTL_ACOS5_ENCRYPT_SYM             : c_uint =  0x0000_0026; // data: *mut CardCtl_crypt_sym,  do_encrypt_sym
pub const SC_CARDCTL_ACOS5_ENCRYPT_ASYM            : c_uint =  0x0000_0027; // data: *mut CardCtl_crypt_asym, do_encrypt_asym; Signature verification with public key
//pub const SC_CARDCTL_ACOS5_DECRYPT_SYM           : c_uint =  0x0000_0028; // data: *mut CardCtl_crypt_sym,  do_decrypt_sym
////pub const SC_CARDCTL_ACOS5_DECRYPT_ASYM        : c_uint =  0x0000_0029; // data: *mut CardCtl_crypt_asym, do_decrypt_asym; is available via decipher




/* common types and general function(s) */

// struct for SC_CARDCTL_GET_FILE_INFO and SC_CARDCTL_GET_COS_VERSION
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlArray8 {
    pub reference  : c_uchar,      // IN  indexing begins with 0, used for SC_CARDCTL_GET_FILE_INFO
    pub value      : [c_uchar; 8], // OUT
}

impl Default for CardCtlArray8 {
    fn default() -> CardCtlArray8 {
        CardCtlArray8 {
            reference: 0, // used by SC_CARDCTL_GET_FILE_INFO only
            value: [0u8; 8]
        }
    }
}

// struct for SC_CARDCTL_GET_ROM_SHA1
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlArray20 {
    pub value      : [c_uchar; 20], // OUT
}

impl Default for CardCtlArray20 {
    fn default() -> CardCtlArray20 {
        CardCtlArray20 {
            value: [0u8; 20]
        }
    }
}

// struct for SC_CARDCTL_GET_PIN_AUTH_STATE and SC_CARDCTL_GET_KEY_AUTH_STATE
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlAuthState {
    pub reference  : c_uchar, // IN  pin/key reference, | 0x80 for local
    pub value      : bool,    // OUT
}

impl Default for CardCtlAuthState {
    fn default() -> CardCtlAuthState {
        CardCtlAuthState {
            reference: 0,
            value: false
        }
    }
}

// struct for SC_CARDCTL_GET_FILES_HASHMAP_INFO
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlArray32 {
    pub key    : u16,           // IN   file_id
    pub value  : [c_uchar; 32], // OUT  in the order as acos5_64_gui defines // alias  TreeTypeFS = Tree_k_ary!ub32;
}

impl Default for CardCtlArray32 {
    fn default() -> CardCtlArray32 {
        CardCtlArray32 {
            key: 0,
            value: [0u8; 32]
        }
    }
}

// struct for SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST and SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE, SC_CARDCTL_ACOS5_ENCRYPT_ASYM// data: *mut CardCtl_generate_crypt_asym, do_generate_asym, do_crypt_asym
// not all data are require for do_crypt_asym (exponent, exponent_std, key_len_code, key_priv_type_code)
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct CardCtl_generate_crypt_asym {
    pub data : [c_uchar; 512],   // INOUT for crypt_asym (performs cos5  'RSA Public Key Encrypt')
    pub data_len : usize,        // len bytes used within in_data
    pub file_id_priv : u16,       // IN  if any of file_id_priv/file_id_pub is 0, then file_id selection will depend on acos5_64.profile,
    pub file_id_pub  : u16,       // IN  if both are !=0, then the given values are preferred
    pub exponent : [c_uchar; 16], // public exponent
    pub exponent_std  : bool,  // whether the default exponent 0x10001 shall be used and the exponent field disregarded; otherwise all 16 bytes from exponent will be used
    pub key_len_code  : c_uchar,  //
    pub key_priv_type_code : c_uchar,  // as required by cos5 Generate RSA Key Pair
    pub perform_mse   : bool,     // IN parameter, whether MSE Manage Security Env. shall be done (here) prior to generation
    pub op_success   : bool,     // OUT parameter, whether generation succeeded
/*
Key Length Indicator :  1 byte 0x04-0x20    dependence on SC_CARD_TYPE_ACOS5_64_V2 / SC_CARD_TYPE_ACOS5_64_V3 (FIPS)
Private Key Type     :  1 byte 1-6 (incl. CRT or NON-CRT) dependence on SC_CARD_TYPE_ACOS5_64_V2 / SC_CARD_TYPE_ACOS5_64_V3 (FIPS)
*/
}

impl Default for CardCtl_generate_crypt_asym {
    fn default() -> CardCtl_generate_crypt_asym {
        CardCtl_generate_crypt_asym {
            data: [0u8; 512],
            data_len: 0,
            file_id_priv: 0,
            file_id_pub: 0,
            exponent: [0u8; 16],
            exponent_std: true,    // the standard exponent 0x10001 will be used
            key_len_code: 0x20,    // 4096 bit
            key_priv_type_code: 6, // CRT, sign+decrypt
            perform_mse: false,
            op_success: false
        }
    }
}


// struct for SC_CARDCTL_ENCRYPT_SYM // data: *mut CardCtl_crypt_sym, do_encrypt_sym
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct CardCtl_crypt_sym {
    pub infile       : *const char, //  path/to/file where the indata may be read from, interpreted as an [c_uchar]; if!= null has preference over indata
    pub indata       : [c_uchar; 64],
    pub indata_len   : usize,
    pub outfile      : *const char, //  path/to/file where the outdata may be written to, interpreted as an [c_uchar]; if!= null has preference over outdata
    pub outdata      : [c_uchar; 64],
    pub outdata_len  : usize,
    pub iv           : [c_uchar; 16],
    pub iv_len       : usize, // 0==unused or equal to block_size, i.e. 16 for AES, else 8

//  pub key_id       : c_uchar, // how the key is known by OpenSC in SKDF: id
    pub key_ref      : c_uchar, // how the key is known by cos5: e.g. internal local key with id 3 has key_ref: 0x83
    pub block_size   : c_uchar, // 16: AES; 8: 3DES or DES
    pub key_len      : c_uchar, // in bytes
    pub pad_type     : c_uchar, // BLOCKCIPHER_PAD_TYPE_*
//    pub use_sess_key : bool, // if true, the session key will be used and key_ref ignored
    pub local        : bool, // whether local or global key to use; used to select MF or appDF where the key file resides
    pub cbc          : bool, // true: CBC Mode, false: ECB
    pub enc_dec      : bool, // true: encrypt,  false: decrypt
}

impl Default for CardCtl_crypt_sym {
    fn default() -> CardCtl_crypt_sym {
        CardCtl_crypt_sym {
            infile: std::ptr::null(),
            indata: [0u8; 64],
            indata_len: 0,
            outfile: std::ptr::null(),
            outdata: [0u8; 64],
            outdata_len: 0,
            iv: [0u8; 16],
            iv_len: 0,
            key_ref: 0,
            block_size: 16, // set as default: AES 256 bit CBC, encryption with local key and PKCS5 padding
            key_len: 32,
            pad_type: BLOCKCIPHER_PAD_TYPE_PKCS5, // the recommended one, one of those that are able to be de-pad'ed unambiguously
//            use_sess_key: false,
            local: true,
            cbc: true,
            enc_dec: true
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////
/* Stores 1 record of SecurityEnvironment File, intended to be placed in a Vec */
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct SeInfo {
    pub reference  : c_int, // the SE file's record no == stored id in record  TODO check if this can be typed c_uint
    pub crts_len   : usize,                       /* what is used actually in crts */
    pub crts       : [sc_crt; SC_MAX_CRTS_IN_SE], // align(8) // SC_MAX_CRTS_IN_SE==12
}

impl Default for SeInfo {
    fn default() -> SeInfo {
        SeInfo {
            reference:  0,
            crts_len:   0,
            crts:       [Default::default(); SC_MAX_CRTS_IN_SE],
        }
    }
}

pub type KeyTypeFiles   = u16;
//                          path                    File Info       scb8                SeInfo
pub type ValueTypeFiles = ([u8; SC_MAX_PATH_SIZE], [u8; 8], Option<[u8; 8]>, Option<Vec<SeInfo>>);
// File Info originally:  {FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI}
// File Info actually:    {FDB, *,   FILE ID, FILE ID, *,           *,           *,   LCSI}

#[repr(C)]
#[derive(Debug /*, Copy*/, Clone)]
pub struct DataPrivate { // see settings in acos5_64_init
    pub files : HashMap< KeyTypeFiles, ValueTypeFiles >,
    pub sec_env : sc_security_env, // remember the input of last call to acos5_64_set_security_env; especially algorithm_flags will be required in compute_signature
//  pub sec_env_algo_flags : c_uint, // remember the padding scheme etc. selected for RSA; required in acos5_64_set_security_env
    pub rsa_caps : c_uint, // remember how the rsa_algo_flags where set for _sc_card_add_rsa_alg
    pub is_running_init : bool, // true as long as acos5_64_init runs: It may be used to control behavior of acos5_64_list_files (lazily filling hashmap)
    /* some commands like sign, decipher etc. may supply > 256 bytes to get_response, but the exact number will not be known (the only info is 0x6100),
       thus guessing, there are another 256 bytes will be turned on with: true; guessing is limited to those commands, that turn on this feature.
       It's trial and error, not efficient as a general behavior of acos5_64_get_response
         false: acos5_64_get_response behaves (exactly?) like iso7816_get_response
     */
    pub is_running_cmd_long_response : bool,
    /*  is_running_compute_signature: false, // maybe, acos5_64_decipher will need to know, that it was called by acos5_64_compute_signature */
}


/**
 * Converts the first 2 bytes of input slice to an u16; panics if slice.len()<2
 * @apiNote
 * @param   array  IN slice; most significant byte at index 0, i.e. &[0x3F, 0] will be converted to 0x3F00
 * @return  the u16 result of conversion
 */
pub fn u16_from_array_begin(array: &[u8]) -> u16
{
    assert!(array.len()>=2);
    (array[0] as u16) << 8  |  array[1] as u16
}

pub fn u32_from_array_begin(array: &[u8]) -> u32
{
    assert!(array.len()>=4);
    (array[0] as u32) << 24  |  (array[1] as u32) << 16  |  (array[2] as u32) << 8  |  array[3] as u32
}
