/*
 * constants_types.rs: Driver 'acos5' - Code common to driver and pkcs15 libraries, partially also acos5_gui
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

#![allow(dead_code)]

use std::os::raw::{c_char, c_uchar, c_ulong, c_void};
use std::ops::{Deref, DerefMut};
use std::collections::HashMap;
use std::ffi::CStr;

use opensc_sys::opensc::{sc_context, sc_card, sc_security_env, sc_file_free, sc_bytes2apdu,
                         SC_ALGORITHM_AES/*, SC_CARD_CAP_APDU_EXT*/};

use opensc_sys::types::{sc_file, sc_apdu, sc_crt, sc_object_id, SC_MAX_CRTS_IN_SE, SC_MAX_PATH_SIZE};
use opensc_sys::pkcs15::{SC_PKCS15_PRKDF, SC_PKCS15_PUKDF, SC_PKCS15_PUKDF_TRUSTED,
                         SC_PKCS15_SKDF, SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED, SC_PKCS15_CDF_USEFUL,
                         SC_PKCS15_DODF, SC_PKCS15_AODF, sc_pkcs15_id};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_INTERNAL};
use opensc_sys::iso7816::{/*ISO7816_TAG_FCI, ISO7816_TAG_FCP,*/ ISO7816_TAG_FCP_SIZE, ISO7816_TAG_FCP_TYPE,
                          ISO7816_TAG_FCP_FID, ISO7816_TAG_FCP_DF_NAME, ISO7816_TAG_FCP_LCS};

/*
Limits:
max. 255 children within a DF, otherwise get_count_files_curr_df will panic

file size: driver's general max: u16::max
V2:
V3:
V4: 38911

MRL, NOR: driver's general max: u8::max
V2: 255, 255
V3:
V4: 4096, 65535

CHV:
V2: max. 21 bytes (5+2*8), Pin ids from 1-31; max 31 global pins + 31 local pins
V3:
V4: max. 45 bytes (5+2*20), Pin ids from 1-30

Sym key:
V2: max 37 bytes
V3:
V4: min 12/20, Key ids from 1-30

SE file:
V2: max 37 bytes, ids from 1-14 ?
V3:
V4: min 12/20, ids from 1-30 ?
*/

// see also useful declarations in libopensc/iasecc.h:
pub const ACOS5_OBJECT_REF_LOCAL  : u8 = 0x80;
pub const ACOS5_OBJECT_REF_GLOBAL : u8 = 0x00;

pub const ACOS5_OBJECT_REF_MIN    : u8 = 0x01;
pub const ACOS5_OBJECT_REF_MAX    : u8 = 0x1F;

// for an internal driver these 3 will move to cards.h
pub const SC_CARD_TYPE_ACOS5_BASE   : i32 = 16001;
//  const SC_CARD_TYPE_ACOS5_32_V1  : i32 = 16002; // = SC_CARD_TYPE_ACOS5_BASE + 1;
pub const SC_CARD_TYPE_ACOS5_64_V2  : i32 = 16003; // = SC_CARD_TYPE_ACOS5_BASE + 2;
pub const SC_CARD_TYPE_ACOS5_64_V3  : i32 = 16004; // = SC_CARD_TYPE_ACOS5_BASE + 3;
pub const SC_CARD_TYPE_ACOS5_EVO_V4 : i32 = 16005; // = SC_CARD_TYPE_ACOS5_BASE + 4;

//  const ATR_V1      : &[u8; 57] = b"3b:be:18:00:00:41:05:01:00:00:00:00:00:00:00:00:00:90:00\0"; // *NOT* supported: ACOS5 Card (ACOS5-32 V1.00)
pub const ATR_V2      : &[u8; 57] = b"3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00\0"; // Using reader with a card: ACS CryptoMate64 00 00
pub const ATR_V3      : &[u8; 57] = b"3b:be:96:00:00:41:05:30:00:00:00:00:00:00:00:00:00:90:00\0"; // Using reader with a card: ACS CryptoMate (T2) 00 00 ; reported by my CryptoMate Nano
/* TODO check ATRs of different EVO card hardware: contact / contactless / combi */
pub const ATR_V4_0    : &[u8; 57] = b"3b:9e:96:80:01:41:05:40:00:00:00:00:00:00:00:00:00:90:00\0";    // unverified currently
pub const ATR_V4_1    : &[u8; 60] = b"3b:9e:96:80:01:41:05:41:00:00:00:00:00:00:00:00:00:90:00:1c\0"; // unverified currently
pub const ATR_V4_2    : &[u8; 60] = b"3b:9e:96:80:01:41:05:42:00:00:00:00:00:00:00:00:00:90:00:1f\0"; // Using reader with a card: ACS CryptoMate EVO 00 00
pub const ATR_V4_3    : &[u8; 60] = b"3b:9e:96:80:01:41:05:43:00:00:00:00:00:00:00:00:00:90:00:1e\0"; // Using reader with a card: ACS CryptoMate EVO 00 00
pub const ATR_MASK    : &[u8; 57] = b"FF:FF:00:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF\0";
pub const ATR_MASK_TCK: &[u8; 60] = b"FF:FF:00:FF:FF:FF:FF:F0:00:00:00:00:00:00:00:00:00:FF:FF:00\0";
pub const NAME_V2  : &CStr = c"ACOS5-64 V2.00: Smart Card or CryptoMate64";
pub const NAME_V3  : &CStr = c"ACOS5-64 V3.00: Smart Card or CryptoMate Nano";
pub const NAME_V4  : &CStr = c"ACOS5-EVO V4.X0: Smart Card EVO or CryptoMate EVO";

pub const CARD_DRV_NAME       : &CStr = c"'acos5_external', supporting ACOS5 Smart Card V2.00 (CryptoMate64), V3.00 (CryptoMate Nano)";
pub const CARD_DRV_SHORT_NAME : &CStr = c"acos5_external";

//pub const CRATE               : &[u8;   6] = b"acos5\0"; // search acos5 mention in debug log file; each function should at least log CALLED, except small helpers or code that is clearly covered by only one possible surrounding function's called
//pub const CALLED              : &[u8;   7] = b"called\0";
//pub const RETURNING           : &[u8;  10] = b"returning\0";
//pub const RETURNING_INT       : &[u8;  20] = b"returning with: %d\n\0";
//pub const RETURNING_INT_CSTR  : &[u8;  25] = b"returning with: %d (%s)\n\0";
//pub const CSTR_INT_CSTR       : &[u8;  13] =             b"%s: %d (%s)\n\0";

/*
pub const CARD_DRIVER         : &[u8;  12] = b"card_driver\0";
pub const MODULE              : &[u8;   7] = b"module\0";
pub const LIB_DRIVER_NIX      : &[u8;  12] = b"libacos5.so\0";

pub const USER_CONSENT_CMD_NIX : &[u8;  18] = b"/usr/bin/pinentry\0"; // substituted by IUP

pub const _0_17_0  : &[u8; 7] = b"0.17.0\0";
pub const _0_18_0  : &[u8; 7] = b"0.18.0\0";
pub const _0_19_0  : &[u8; 7] = b"0.19.0\0";
pub const _0_20_0  : &[u8; 7] = b"0.20.0\0";
pub const _0_21_0  : &[u8; 7] = b"0.21.0\0";
pub const _0_0_0   : &[u8; 6] = b"0.0.0\0";
*/

// iso7816 ReservedFutureUse tags used by acos, that are not part of iso7816.h/rs
pub const ISO7816_RFU_TAG_FCP_SFI  : u8 = 0x88;    /* L:1,    V: Short File Identifier (SFI). 5 LSbs of File ID if unspecified. Applies to: Any file */
pub const ISO7816_RFU_TAG_FCP_SAC  : u8 = 0x8C;    /* L:0-8,  V: Security Attribute Compact (SAC). Applies to: Any file */
pub const ISO7816_RFU_TAG_FCP_SEID : u8 = 0x8D;    /* L:2,    V: Security Environment File identifier (SE File associated with this DF). Applies to: DFs */
pub const ISO7816_RFU_TAG_FCP_SAE  : u8 = 0xAB;    /* L:0-32, V: Security Attribute Extended (SAE). Applies to: DF s */

//ACOS5 File Descriptor Bytes, the proprietary encoding of file types, the first within V of Tag ISO7816_TAG_FCP_TYPE:
pub const FDB_MF                 : u8 = 0x3F; // Master File     MF
pub const FDB_DF                 : u8 = 0x38; // Dedicated File  DF, same as opensc-sys.iso7816.ISO7816_FILE_TYPE_DF
/* Working Elementary Files  EF */
pub const FDB_TRANSPARENT_EF     : u8 = 0x01; // Transparent EF     == opensc-sys.types.SC_FILE_EF_TRANSPARENT; same as opensc-sys.iso7816.ISO7816_FILE_TYPE_TRANSPARENT_EF
pub const FDB_LINEAR_FIXED_EF    : u8 = 0x02; // Linear-Fixed EF    == opensc-sys.types.SC_FILE_EF_LINEAR_FIXED
pub const FDB_LINEAR_VARIABLE_EF : u8 = 0x04; // Linear-Variable EF == opensc-sys.types.SC_FILE_EF_LINEAR_VARIABLE
pub const FDB_CYCLIC_EF          : u8 = 0x06; // Cyclic EF          == opensc-sys.types.SC_FILE_EF_CYCLIC
/* Internal EF */
pub const FDB_RSA_KEY_EF         : u8 = 0x09; // RSA Key EF, for private and public key file; distinguish by PKCS15_FILE_TYPE_RSAPRIVATEKEY or PKCS15_FILE_TYPE_RSAPUBLICKEY
pub const FDB_CHV_EF             : u8 = 0x0A; // CHV EF, for the pin file, max 1 file only in each DF
pub const FDB_SYMMETRIC_KEY_EF   : u8 = 0x0C; // Symmetric Key EF,         max 1 file only in each DF;  PKCS15_FILE_TYPE_SECRETKEY
pub const FDB_PURSE_EF           : u8 = 0x0E; // Purse EF, since ACOS5-64 V3.00
pub const FDB_ECC_KEY_EF         : u8 = 0x19; // Elliptic Curve Cryptography Key EF, for private and public key file; distinguish by PKCS15_FILE_TYPE_ECCPRIVATEKEY or PKCS15_FILE_TYPE_ECCPUBLICKEY
/* Proprietary internal EF */
pub const FDB_SE_FILE            : u8 = 0x1C; // Security Environment File, exactly 1 file only in each DF; DF's header/FCI points to this

/* the Control Reference Template (CRT) Tags understood by acos
ATTENTION with CRT_TAG_CT Confidentiality Template: In reality acos makes no difference for asym/sym, there is 0xB8 only
The distinction is artificial and for some reason, corrected later
*/
pub const CRT_TAG_HT      : u8 = 0xAA;   // Hash Template                 : AND:      Algorithm
pub const CRT_TAG_AT      : u8 = 0xA4;   // Authentication Template       : AND: UQB, Pin_Key,
pub const CRT_TAG_DST     : u8 = 0xB6;   // Digital Signature Template    : AND: UQB, Algorithm, KeyFile_RSA
//pub const CRT_TAG_CT_ASYM : u8 = 0xB8+1; // Confidentiality Template      : AND: UQB, Algorithm       OR: KeyFile_RSA
//pub const CRT_TAG_CT_SYM  : u8 = 0xB8+0; // Confidentiality Template      : AND: UQB, Algorithm       OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
pub const CRT_TAG_CT      : u8 = 0xB8;   // Confidentiality Template
pub const CRT_TAG_CCT     : u8 = 0xB4;   // Cryptographic Checksum Templ. : AND: UQB, Algorithm  ;    OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
pub const CRT_TAG_KAT     : u8 = 0xA6;   // Key Agreement Template. The KAT defines which parameters to use in key derivation operations. available only with EVO
pub const CRT_TAG_NA      : u8 = 0x00;   // N/A unknown

// the following bytes indicate, whether an SC Byte encodes Secure Messaging, it does't guarantee, that the referred command allows SM at all
//pub const SM_MODE_NONE           : u8 = 0; // SM is not enforced/impossible as of SCB setting
//pub const SM_MODE_CCT            : u8 = 1; // SM is enforced, providing Authenticity, specified by a  Cryptographic Checksum Template
//pub const SM_MODE_CCT_AND_CT_SYM : u8 = 2; // SM is enforced, providing Authenticity and Confidentiality, specified by a  Cryptographic Checksum Template and Confidentiality Template (ref. key for sym. algorithm)

                                                 /* PKCS #15 DF types, see pkcs15.rs */
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
pub const PKCS15_FILE_TYPE_ECCPRIVATEKEY : u8 =  20;
pub const PKCS15_FILE_TYPE_ECCPUBLICKEY  : u8 =  21;

pub const PKCS15_FILE_TYPE_SECRETKEY     : u8 =  17; // iEF with cos5
pub const PKCS15_FILE_TYPE_CERT          : u8 =  15;
pub const PKCS15_FILE_TYPE_DATA          : u8 =  19;
pub const PKCS15_FILE_TYPE_PIN           : u8 =  18; // iEF with cos5
pub const PKCS15_FILE_TYPE_BIOMETRIC     : u8 =  22;
pub const PKCS15_FILE_TYPE_AUTHKEY       : u8 =  23;
pub const PKCS15_FILE_TYPE_NONE          : u8 =  0xFF; // should not happen to extract a path for this

pub const RSA_MAX_LEN_MODULUS      : usize = 512; // bytes; as bits: 512*8 = 4096
pub const RSAPUB_MAX_LEN           : usize = 5 + 16 + RSA_MAX_LEN_MODULUS; // the max. file size (byte) requirement for RSA public key (4096 bit == 512 byte; 16 byte is the max. public exponent length)
pub const RSAPRIV_MAX_LEN_STD      : usize = 5 +      RSA_MAX_LEN_MODULUS; // the max. file size (byte) requirement for RSA private key (non-CRT)
pub const RSAPRIV_MAX_LEN_CRT      : usize = 5 +   5*(RSA_MAX_LEN_MODULUS/2); // the max. file size (byte) requirement for RSA private key stored in CRT manner


//https://cryptosys.net/pki/manpki/pki_paddingschemes.html
// don't use BLOCKCIPHER_PAD_TYPE_ZEROES, if it's required to retrieve the message length exactly
pub const BLOCKCIPHER_PAD_TYPE_ZEROES             : u8 =  0; // as for  CKM_AES_CBC: adds max block size minus one null bytes (0 ≤ N < B Blocksize)
pub const BLOCKCIPHER_PAD_TYPE_ONEANDZEROES       : u8 =  1; // Unconditionally add a byte of value 0x80 followed by as many zero bytes as is necessary to fill the input to the next exact multiple of B
// be careful with BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64: It can't unambiguously be detected, what is padding, what is payload: Therefore ACOS5 uses a 'Padding Indicator' byte Pi, telling, whether padding was applied or not
// ACOS5-EVO uses BLOCKCIPHER_PAD_TYPE_ONEANDZEROES (which is not ambiguous), and still uses the now superfluous  'Padding Indicator' byte Pi
pub const BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64 : u8 =  2; // Used in ACOS5-64 SM: Only if in_len isn't a multiple of blocksize, then add a byte of value 0x80 followed by as many zero bytes (0-6) as is necessary to fill the input to the next exact multiple of B
// BLOCKCIPHER_PAD_TYPE_PKCS7 is the recommended one, otherwise BLOCKCIPHER_PAD_TYPE_ONEANDZEROES and BLOCKCIPHER_PAD_TYPE_ANSIX9_23 (BLOCKCIPHER_PAD_TYPE_W3C) also exhibit unambiguity
pub const BLOCKCIPHER_PAD_TYPE_PKCS7              : u8 =  3; // as for CKM_AES_CBC_PAD: If the block length is B then add N padding bytes (1 < N ≤ B Blocksize) of value N to make the input length up to the next exact multiple of B. If the input length is already an exact multiple of B then add B bytes of value B
pub const BLOCKCIPHER_PAD_TYPE_ANSIX9_23          : u8 =  4; // If N padding bytes are required (1 < N ≤ B Blocksize) set the last byte as N and all the preceding N-1 padding bytes as zero.
// BLOCKCIPHER_PAD_TYPE_W3C is not recommended
//b const BLOCKCIPHER_PAD_TYPE_W3C                : u8 =  5; // If N padding bytes are required (1 < N ≤ B Blocksize) set the last byte as N and all the preceding N-1 padding bytes as arbitrary byte values.

//pub const SC_SEC_ENV_PARAM_DES_ECB           : u32 = 3;
//pub const SC_SEC_ENV_PARAM_DES_CBC           : u32 = 4;

/* see opensc-sys: opensc.rs
pub const SC_SEC_OPERATION_DECIPHER     : i32 = 0x0001;
pub const SC_SEC_OPERATION_SIGN         : i32 = 0x0002;
pub const SC_SEC_OPERATION_AUTHENTICATE : i32 = 0x0003;
pub const SC_SEC_OPERATION_DERIVE       : i32 = 0x0004;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_SEC_OPERATION_WRAP         : i32 = 0x0005;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_SEC_OPERATION_UNWRAP       : i32 = 0x0006;
//#[cfg(sym_hw_encrypt)]
//pub const SC_SEC_OPERATION_ENCRYPT_SYM  : i32 = 0x0007;
//#[cfg(sym_hw_encrypt)]
//pub const SC_SEC_OPERATION_DECRYPT_SYM  : i32 = 0x0008;

*/
//pub const SC_SEC_OPERATION_ENCIPHER : i32 = 0x0009;
pub const SC_SEC_OPERATION_GENERATE_RSAPRIVATE : i32 = 0x000A; // sc_set_security_env must know this related to file id
pub const SC_SEC_OPERATION_GENERATE_RSAPUBLIC  : i32 = 0x000B; // sc_set_security_env must know this related to file id
pub const SC_SEC_OPERATION_GENERATE_ECCPRIVATE : i32 = 0x000C; // sc_set_security_env must know this related to file id
pub const SC_SEC_OPERATION_GENERATE_ECCPUBLIC  : i32 = 0x000D; // sc_set_security_env must know this related to file id

pub const SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC  : i32 = 0x000E; // to be substituted by SC_SEC_OPERATION_ENCIPHER and SC_SEC_ENV_KEY_REF_ASYMMETRIC
//b const SC_SEC_OPERATION_DECIPHER_RSAPRIVATE : i32 = 0x000F; // to be substituted by SC_SEC_OPERATION_DECIPHER and SC_SEC_ENV_KEY_REF_ASYMMETRIC
pub const SC_SEC_OPERATION_ENCIPHER_ECCPUBLIC  : i32 = 0x000F; // to be substituted by SC_SEC_OPERATION_ENCIPHER and SC_SEC_ENV_KEY_REF_ASYMMETRIC

// pub const SC_SEC_OPERATION_ENCIPHER_SYMMETRIC  : i32 = 0x0010; // to be substituted by SC_SEC_OPERATION_ENCIPHER and SC_SEC_ENV_KEY_REF_SYMMETRIC
// pub const SC_SEC_OPERATION_DECIPHER_SYMMETRIC  : i32 = 0x0011; // to be substituted by SC_SEC_OPERATION_DECIPHER and SC_SEC_ENV_KEY_REF_SYMMETRIC

/*
/*
 * Generic card_ctl calls, see opensc-sys: cardctl.rs
 */
pub const SC_CARDCTL_GENERIC_BASE            : c_ulong =  0x0000_0000;
pub const SC_CARDCTL_ERASE_CARD              : c_ulong =  0x0000_0001;
pub const SC_CARDCTL_GET_DEFAULT_KEY         : c_ulong =  0x0000_0002;
pub const SC_CARDCTL_LIFECYCLE_GET           : c_ulong =  0x0000_0003;
pub const SC_CARDCTL_LIFECYCLE_SET           : c_ulong =  0x0000_0004;
pub const SC_CARDCTL_GET_SERIALNR            : c_ulong =  0x0000_0005; // data: *mut sc_serial_number,  get_serialnr
pub const SC_CARDCTL_GET_SE_INFO             : c_ulong =  0x0000_0006;
pub const SC_CARDCTL_GET_CHV_REFERENCE_IN_SE : c_ulong =  0x0000_0007;
pub const SC_CARDCTL_PKCS11_INIT_TOKEN       : c_ulong =  0x0000_0008;
pub const SC_CARDCTL_PKCS11_INIT_PIN         : c_ulong =  0x0000_0009;
*/
/*
 * Proprietary card_ctl calls
 *
 * for an internal driver these will move to cardctl.h
*/
pub const SC_CARDCTL_ACOS5_SANITY_CHECK            : c_ulong =  0x0000_0010; // data: null

pub const SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF : c_ulong =  0x0000_0011; // data: *mut u16,  get_count_files_curr_df
pub const SC_CARDCTL_ACOS5_GET_FILE_INFO           : c_ulong =  0x0000_0012; // data: *mut CardCtlArray8,  get_file_info
pub const SC_CARDCTL_ACOS5_GET_FREE_SPACE          : c_ulong =  0x0000_0014; // data: *mut u32,  get_free_space
pub const SC_CARDCTL_ACOS5_GET_IDENT_SELF          : c_ulong =  0x0000_0015; // data: *mut bool,  get_is_ident_self_okay
pub const SC_CARDCTL_ACOS5_GET_COS_VERSION         : c_ulong =  0x0000_0016; // data: *mut [u8; 8],  get_cos_version
/* available only since ACOS5-64 V3, but not all supported by SC_CARD_TYPE_ACOS5_EVO_V4: */
pub const SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE: c_ulong =  0x0000_0017; // data: *mut u32,  get_manufacture_date
pub const SC_CARDCTL_ACOS5_GET_ROM_SHA1            : c_ulong =  0x0000_0018; // data: *mut [u8; 20],  get_rom_sha1
pub const SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE        : c_ulong =  0x0000_0019; // data: *mut u8,  get_op_mode_byte
pub const SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE     : c_ulong =  0x0000_001A; // data: *mut bool,  get_is_fips_compliant
pub const SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE      : c_ulong =  0x0000_001B; // data: *mut CardCtlAuthState,  get_is_pin_authenticated
pub const SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE      : c_ulong =  0x0000_001C; // data: *mut CardCtlAuthState,  get_is_key_authenticated

pub const SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE      : c_ulong =  0x0000_001D; // data: *mut CardCtlAlgoRefSymStore,  algo_ref_sym_store

pub const SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO   : c_ulong =  0x0000_001E; // data: null
pub const SC_CARDCTL_ACOS5_HASHMAP_GET_FILE_INFO   : c_ulong =  0x0000_001F; // data: *mut CardCtlArray32,  get_files_hashmap_info

pub const SC_CARDCTL_ACOS5_SDO_CREATE              : c_ulong =  0x0000_0020; // data: *mut sc_file
pub const SC_CARDCTL_ACOS5_SDO_DELETE              : c_ulong =  0x0000_0021; // data:
pub const SC_CARDCTL_ACOS5_SDO_STORE               : c_ulong =  0x0000_0022; // data:

pub const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES  : c_ulong =  0x0000_0023; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files exist, sec_env setting excluded
//b const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_CREATE : c_ulong =  0x0000_0024; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files must be created, sec_env setting excluded
pub const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_SET : c_ulong =  0x0000_0024; // data: *mut CardCtl_generate_inject_asym,do_generate_inject
pub const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_GET : c_ulong =  0x0000_0025; // data: *mut CardCtl_generate_inject_asym,do_generate_inject
//pub const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_EXIST_MSE  : c_ulong =  0x0000_0025; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files exist, sec_env setting included
//pub const SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_CREATE_MSE : c_ulong =  0x0000_0026; // data: *mut CardCtl_generate_crypt_asym, do_generate_asym;  RSA files must be created, sec_env setting included

pub const SC_CARDCTL_ACOS5_ENCRYPT_SYM             : c_ulong =  0x0000_0027; // data: *mut CardCtl_crypt_sym,  do_encrypt_sym
pub const SC_CARDCTL_ACOS5_ENCRYPT_ASYM            : c_ulong =  0x0000_0028; // data: *mut CardCtl_crypt_asym, do_encrypt_asym; Signature verification with public key
pub const SC_CARDCTL_ACOS5_DECRYPT_SYM             : c_ulong =  0x0000_0029; // data: *mut CardCtl_crypt_sym,  do_decrypt_sym
//pub const SC_CARDCTL_ACOS5_DECRYPT_ASYM        : c_ulong =  0x0000_002A; // data: *mut CardCtl_crypt_asym, do_decrypt_asym; is available via decipher

// array indices of some file related commands in scb8:
pub const READ         : usize =  0;
pub const DELETE_CHILD : usize =  0;
pub const UPDATE       : usize =  1;
pub const CREATE_EF    : usize =  1;
pub const CRYPTO       : usize =  2;
pub const CREATE_DF    : usize =  2;
pub const DELETE_SELF  : usize =  6;


#[allow(non_camel_case_types)]
pub type p_void = *mut c_void;

/*
/* For EVO only: new() switches to Extended APDU syntax, drop() switches back to Short APDU syntax */
pub struct ApduShortExtendedSwitcher(u8);

impl ApduShortExtendedSwitcher {
    pub fn new(card: &mut sc_card) -> Self {
//println!("New for ApduShortExtendedSwitcher");
        if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
/* * /
            card.caps |= SC_CARD_CAP_APDU_EXT;
/ * */
        }
        ApduShortExtendedSwitcher(0)
    }
}

impl Drop for ApduShortExtendedSwitcher {
    fn drop(&mut self) {
//println!("Drop for ApduShortExtendedSwitcher");
/* * /
        if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
            card.caps &= !SC_CARD_CAP_APDU_EXT;
        }
/ * */
    }
}
*/

/* Represents the FCI content, File Control Information */
#[derive(Debug, Clone, PartialEq)]
pub struct Fci {
    pub fdb : u8,
    pub fid : u16,
    pub size : u16,
    pub lcsi : u8,

    pub df_name : Vec<u8>,
    pub scb8 : [u8; 8],
    pub sae : Vec<u8>,
    pub seid : u16,

    pub mrl : u16,
    pub nor : u16,
}

impl Default for Fci {
    fn default() -> Self {
        Self {
            fdb: 0,
            fid: 0,
            size: 0,
            lcsi: 0,
            df_name: Vec::with_capacity(16),
            scb8: [0; 8],
            sae: Vec::with_capacity(32),
            seid: 0,
            mrl: 0,
            nor: 0
        }
    }
}

impl Fci {
    /*
        pub fn new(fdb: u8, fid : u16, size: u16, lcsi: u8, df_name: Vec<u8>, scb8: [u8; 8], sae: Vec<u8>, seid : u16, mrl: u8, nor: u8) -> Self {
            Fci { fdb, fid, size, lcsi, df_name, scb8, sae, seid, mrl, nor }
        }
    */
    #[allow(clippy::match_wild_err_arm)]
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn new_parsed(card: &sc_card, fci_bytes_sequence_body: &[u8]) -> Self {
        let mut result = Fci::default();
        // let tlv_iter = Tlv::new(fci_bytes_sequence_body);
        for tlv in Tlv::new(fci_bytes_sequence_body) {
            match tlv.tag() {
                ISO7816_TAG_FCP_TYPE => {
                    let len = tlv.length();
                    assert!([1,2,5,6].contains(&len));
                    result.fdb = tlv.value()[0];
                    // TODO adapt for EVO
                    if len == 6 && card.type_==SC_CARD_TYPE_ACOS5_EVO_V4 {
                        result.mrl = u16::from_be_bytes([tlv.value()[2], tlv.value()[3]]);
                        result.nor = u16::from_be_bytes([tlv.value()[4], tlv.value()[5]]);
                        result.size = result.mrl * result.nor;
                    }
                    else if len > 2 {
                        result.mrl = tlv.value()[3].into();
                        result.nor = tlv.value()[usize::from(len)-1].into();
                        result.size = result.mrl * result.nor;
                    }
                },
                ISO7816_TAG_FCP_FID => {
                    assert_eq!(2, tlv.length());
                    result.fid = u16::from_be_bytes( [ tlv.value()[0], tlv.value()[1] ]);
                },
                ISO7816_TAG_FCP_SIZE => {
                    assert_eq!(2, tlv.length());
                    result.size = u16::from_be_bytes( [ tlv.value()[0], tlv.value()[1] ]);
                },
                ISO7816_TAG_FCP_LCS => {
                    assert_eq!(1, tlv.length());
                    result.lcsi = tlv.value()[0];
                },
                ISO7816_TAG_FCP_DF_NAME => {
                    result.df_name.extend_from_slice(tlv.value());
                },
                ISO7816_RFU_TAG_FCP_SFI => {
                    assert_eq!(1, tlv.length());
                    // result.sfi = tlv.value()[0];
                },
                ISO7816_RFU_TAG_FCP_SAC => {
                    result.scb8 = match convert_bytes_tag_fcp_sac_to_scb_array(tlv.value()) {
                        Ok(val)  => val,
                        Err(_e)     => panic!(),
                    };
                },
                ISO7816_RFU_TAG_FCP_SAE => {
                    result.sae.extend_from_slice(tlv.value());
                },
                ISO7816_RFU_TAG_FCP_SEID => {
                    assert_eq!(2, tlv.length());
                    result.seid = u16::from_be_bytes( [ tlv.value()[0], tlv.value()[1] ]);
                },
                _ => unreachable!()
            }
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct Tlv<'a> {
    tag: u8,
    length: u8,
    value: &'a [u8],

    rem: &'a [u8],
}

impl<'a> Tlv<'a> {
    #[must_use]
    pub fn new(input: &'a[u8]) -> Self {
        Self { tag: 0, length: 0, value: input, rem: input }
    }

    #[must_use]
    pub fn tag(&self) -> u8 {
        self.tag
    }
    #[must_use]
    pub fn length(&self) -> u8 {
        self.length
    }
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

impl<'a> Iterator for Tlv<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.is_empty() {
            None
        }
        else {
            assert!(self.rem.len()>=2);
            self.tag    = self.rem[0];
            self.length = self.rem[1];
            self.rem    = &self.rem[2..];
            let len = usize::from(self.length);
            assert!(self.rem.len() >= len);
            self.value  = &self.rem[..len]; // can this be easily replaced using split_at ?
            self.rem    = &self.rem[  len..];
            Some(self.clone())
        }
    }
}

// #[derive(Debug, Eq, PartialEq)]
pub struct GuardFile(*mut *mut sc_file);

impl GuardFile {
    /// Creates a guard for the specified element.
    pub fn new(inner: *mut *mut sc_file) -> Self {
//println!("GuardFile");
        GuardFile(inner)
    }
    /*
        /// Forgets this guard and unwraps out the contained element.
        pub fn unwrap(self) -> E {
            let inner = self.0;
            forget(self);   // Don't drop me or I'll destroy `inner`!
            inner
        }
    */
}

impl Drop for GuardFile {
    fn drop(&mut self) {
        if !self.0.is_null() && unsafe { !(*self.0).is_null() } {
//println!("Drop for file path: {:X?}", unsafe { (*(*self.0)).path.value });
            unsafe { sc_file_free(*self.0) }
        }
    }
}

/// Be careful on deferecing so you don't store another copy of the element somewhere.
impl Deref for GuardFile {
    type Target = *mut *mut sc_file;
    // fn deref(&self) -> &Self::Target;
    fn deref(&self) -> & *mut *mut sc_file {
        &self.0
    }
}

/// Be careful on deferecing so you don't store another copy of the element somewhere.
impl DerefMut for GuardFile {
    // fn deref_mut(&mut self) -> &mut Self::Target;
    fn deref_mut(&mut self) -> &mut *mut *mut sc_file {
        &mut self.0
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct Acos5EcCurve {
    pub curve_name : *const c_char,
    pub curve_oid  : sc_object_id,
    pub size       : u32,
}
/* more related to acos5_pkcs15 */
/* more related to acos5_sm */

/* common types and general function(s) */

// struct for SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlAlgoRefSymStore {
    pub card_type: i32,     // IN
    pub algorithm: u32,     // IN
    pub key_len_bytes: u8,  // IN
    pub value        : u8,  // OUT
}

// struct for SC_CARDCTL_GET_FILE_INFO
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlArray8 {
    pub reference  : u8,      // IN  indexing begins with 0, used for SC_CARDCTL_GET_FILE_INFO
    pub value      : [u8; 8], // OUT
}

// struct for SC_CARDCTL_GET_FILES_HASHMAP_INFO
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlArray32 {
    pub key    : u16,      // IN   file_id
    pub value  : [u8; 32], // OUT  in the order as acos5_gui defines // alias  TreeTypeFS = Tree_k_ary!ub32;
}

// struct for SC_CARDCTL_GET_PIN_AUTH_STATE and SC_CARDCTL_GET_KEY_AUTH_STATE
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct CardCtlAuthState {
    pub reference  : u8,   // IN  pin/key reference, | 0x80 for local
    pub value      : bool, // OUT
}

// struct for SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_EXIST and SC_CARDCTL_ACOS5_GENERATE_KEY_FILES_CREATE, SC_CARDCTL_ACOS5_ENCRYPT_ASYM// data: *mut CardCtl_generate_crypt_asym, do_generate_asym, do_crypt_asym
// not all data are require for do_crypt_asym (exponent, exponent_std, key_len_code, key_priv_type_code)
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct CardCtl_generate_crypt_asym {
    pub rsa_pub_exponent : [u8; 16], // public exponent
    pub data : [u8; RSA_MAX_LEN_MODULUS],   // INOUT for crypt_asym (performs cos5  'RSA Public Key Encrypt')
    pub data_len : usize,        // len bytes used within in_data
    pub file_id_priv : u16,       // IN  if any of file_id_priv/file_id_pub is 0, then file_id selection will depend on acos5_external.profile,
    pub file_id_pub  : u16,       // IN  if both are !=0, then the given values are preferred
    pub key_len_code : u8,   // cos5 specific encoding for modulus length: key_len_code*128==modulus length canonical in bits (canonical means neglecting that possibly some MSB are not set to 1)
    pub key_priv_type_code : u8,  // as required by cos5 Generate RSA Key Pair: allowed key-usage and standard/CRT format qualification
    pub key_curve_code : u8,      // if !=0 then ECC; MAKE shurethis can only be set to != 0 by EVO only !!! required by cos5 Generate ECC Key Pair: Indicates which NIST recommended elliptic curves over prime fields to use in generating the key pair

    pub do_generate_rsa_crt : bool,         // whether RSA private key file shall be generated in ChineseRemainderTheorem-style
    pub do_generate_rsa_add_decrypt_for_sign : bool, // whether RSA private key file shall be generated adding decrypt capability iff sign is requested
    pub do_generate_with_standard_rsa_pub_exponent : bool, // whether RSA key pair will contain the "standard" public exponent e=0x010001==65537; otherwise the user supplied 16 byte exponent will be used

    pub do_create_files : bool, // if this is set to true, then the files MUST exist and set in file_id_priv and file_id_pub
//    pub is_key_pair_created_and_valid_for_generation : bool, // set only in acos5_64_pkcs15init_create_key/acos5_64_pkcs15init_generate_key; and whether the following 2 fields contain valid file_ids, to be queried by acos5_64_pkcs15init_generate_key

    pub perform_mse   : bool,     // IN parameter, whether MSE Manage Security Env. shall be done (here) prior to crypto operation
}

impl Default for CardCtl_generate_crypt_asym {
    fn default() -> Self {
        Self {
            rsa_pub_exponent: [0; 16],
            data: [0; RSA_MAX_LEN_MODULUS],
            data_len: 0,
            file_id_priv: 0,
            file_id_pub: 0,
            key_len_code: 0,
            key_priv_type_code: 0,

            key_curve_code: 0, // -> RSA is selected !!!

            do_generate_rsa_crt: false,         // whether RSA private key file shall be generated in ChineseRemainderTheorem-style
            do_generate_rsa_add_decrypt_for_sign: false, // whether RSA private key file shall be generated adding decrypt iff sign is requested
            do_generate_with_standard_rsa_pub_exponent: true, // whether RSA key pair will contain the "standard" public exponent e=0x010001==65537; otherwise the user supplied 16 byte exponent will be used
                                                               // true: the standard exponent 0x10001 will be used
            do_create_files: true, // if this is set to true, then the files MUST exist and set in file_id_priv and file_id_pub
//            is_key_pair_created_and_valid_for_generation: false,
            perform_mse: true,
        }
    }
}

/* RSA key pair generation: using this allows specific input from acos5_gui and disabling file creation, while all calls will go via sc_pkcs15init_generate_key, i.e.
   acos5_gui will always call sc_card_ctl(SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT) prior to sc_card_ctl(SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_EXIST) */
#[repr(C)]
#[derive(/*Default,*/ Debug, Copy, Clone)]
pub struct CardCtl_generate_inject_asym {
    pub rsa_pub_exponent : [u8; 16], // IN public exponent
    pub file_id_priv : u16,       // OUT  if any of file_id_priv/file_id_pub is 0, then file_id selection will depend on acos5_external.profile,
    pub file_id_pub  : u16,       // OUT  if both are !=0, then the given values are preferred
    pub do_generate_rsa_crt : bool,         // IN whether RSA private key file shall be generated in ChineseRemainderTheorem-style
    pub do_generate_rsa_add_decrypt_for_sign : bool, // IN whether RSA private key file shall be generated adding decrypt capability iff sign is requested
    pub do_generate_with_standard_rsa_pub_exponent : bool, // IN whether RSA key pair will contain the "standard" public exponent e=0x010001==65537; otherwise the user supplied 16 byte exponent will be used
    pub do_create_files : bool, // IN if this is set to true, then the files MUST exist and set in file_id_priv and file_id_pub
}

impl Default for CardCtl_generate_inject_asym {
    fn default() -> Self {
        Self {
            rsa_pub_exponent: [0; 16],
            file_id_priv: 0,
            file_id_pub: 0,
            do_generate_rsa_crt: false,
            do_generate_rsa_add_decrypt_for_sign: false,
            do_generate_with_standard_rsa_pub_exponent: true,
            do_create_files: true,
        }
    }
}

// struct for SC_CARDCTL_ACOS5_ENCRYPT_SYM and SC_CARDCTL_ACOS5_DECRYPT_SYM// data: *mut CardCtl_crypt_sym, do_encrypt_sym
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct CardCtl_crypt_sym {
    /* input is from : infile xor indata, i.e. assert!(logical_xor(indata_len > 0, !infile.is_null() )); */
    pub infile       : *const c_char, //  path/to/file where the indata may be read from, interpreted as an [u8]; if!= null has preference over indata
    pub inbuf        : *const c_uchar,
    pub indata       : [u8; RSA_MAX_LEN_MODULUS+16],
    pub indata_len   : usize,
    pub outfile      : *const c_char, //  path/to/file where the outdata may be written to, interpreted as an [u8]; if!= null has preference over outdata
    pub outbuf       : *mut c_uchar,
    pub outdata      : [u8; RSA_MAX_LEN_MODULUS+32],
    pub outdata_len  : usize,
    /* until OpenSC v0.20.0  iv is [0u8; 16], then use sc_sec_env_param and SC_SEC_ENV_PARAM_IV */
    pub iv           : [u8; 16],
    pub iv_len       : usize, // 0==unused or equal to block_size, i.e. 16 for AES, else 8

    pub algorithm       : u32, // e.g. SC_ALGORITHM_AES
    pub algorithm_flags : u32, // e.g. SC_ALGORITHM_AES_CBC_PAD
//  pub key_id       : u8, // how the key is known by OpenSC in SKDF: id
    pub key_ref      : u8, // how the key is known by cos5: e.g. internal local key with id 3 has key_ref: 0x83
    pub block_size   : u8, // 16: AES; 8: 3DES or DES
    pub key_len      : u8, // in bytes
    pub pad_type     : u8, // BLOCKCIPHER_PAD_TYPE_*
//    pub use_sess_key : bool, // if true, the session key will be used and key_ref ignored
    pub local        : bool, // whether local or global key to use; used to select MF or appDF where the key file resides
    pub cbc          : bool, // true: CBC Mode, false: ECB
    pub encrypt      : bool, // true: encrypt,  false: decrypt
    pub perform_mse  : bool, // IN parameter, whether MSE Manage Security Env. shall be done (here) prior to crypto operation
}

impl Default for CardCtl_crypt_sym {
    fn default() -> Self {
        Self {
            infile: std::ptr::null(),
            inbuf: std::ptr::null(),
            indata: [0; RSA_MAX_LEN_MODULUS+16],
            indata_len: 0,
            outfile: std::ptr::null(),
            outbuf: std::ptr::null_mut(),
            outdata: [0; RSA_MAX_LEN_MODULUS+32],
            outdata_len: 0,
            iv: [0; 16],
            iv_len: 0,
            algorithm: SC_ALGORITHM_AES,
            algorithm_flags: 0, // SC_ALGORITHM_AES_CBC_PAD,
            key_ref: 0,
            block_size: 16, // set as default: AES 256 bit CBC, encryption with local key and BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64
            key_len: 32,
            pad_type: BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, // one of those that are able to be de-pad'ed unambiguously
//            use_sess_key: false,
            local: true,
            cbc: true,
            encrypt: true,
            perform_mse: false,
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////
/* Stores 1 record of Security Environment File, intended to be placed in a Vec, stored with the DF */
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct SACinfo /*SeInfo*/ {
    pub reference  : u32, // the SE file's record no == stored id/ SE id in record
    pub crts_len   : usize,                       /* what is used actually in crts */
    pub crts       : [sc_crt; SC_MAX_CRTS_IN_SE], // align(8) // SC_MAX_CRTS_IN_SE==12
}

/*
AB 0B 84 01 2C
        97 00
      84 01 24
        9E 01 42

enum SCDO_TAG : ubyte { // Security Condition Data Object (SCDO) tags
	Always_Deny  = 0x97, //0  len 0
	Always_Allow = 0x90, //1  len 0
	SC_Byte      = 0x9E, //2  len 1
	AuthT        = 0xA4, //3  len var
	Any          = 0xA0, //4  len var
	All          = 0xAF, //5  len var
}
*/
/*
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct SCDO { // for SCDO_TAGs Always_Deny ..AuthT every scdo content is in scdo[0] and tag==tag_sub ; for SCDO_TAG.All and SCDO_TAG.Any, tag!=tag_sub
    pub tag_sub : u8, // tells, which of the following fields is relevant
    pub scb     : i32,   // reference_and_SM indication;
    pub crt     : sc_crt,  // for SCDO_TAG.AuthT
}
*/

/* Stores SAE information for an instruction from <AMDO><SCDO> simple-TLV, intended to be placed in a Vec, stored with the DF
   TODO SCDO Tags 0xA0 and 0xAF are not yet covered */
#[allow(clippy::upper_case_acronyms)]
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct SAEinfo {
    pub tag_AMDO : u8,    // AMDO TAG: 0x80 < tag_AMDO < 0x90
    pub cla      : u8,
    pub ins      : u8,
    pub p1       : u8,
    pub p2       : u8,

    pub tag_SCDO : u8,    // SCDO TAG: 0x90 <= tag_SCDO <= 0xAF  ; the 'leading' tag of a <AMDO><SCDO_oneAtLeast><SCDO_opt><SCDO_opt> group, that of <SCDO_oneAtLeast>
    pub scb      : u8,
//    pub scdo : [SCDO; 3], // CONVENTION : max 3 conditions for SCDO_TAG.Any or SCDO_TAG.All
//    pub scdo_len : i32,
}

pub type KeyTypeFiles   = u16;
//                          path                    File Info       scb8                SACinfo               SAEinfo
pub type ValueTypeFiles = ([u8; SC_MAX_PATH_SIZE], [u8; 8], Option<[u8; 8]>, Option<Vec<SACinfo>>, Option<Vec<SAEinfo>>);
// File Info originally:  {FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI}
// File Info actually:    {FDB, *,   FILE ID, FILE ID, *,           *,           *,   LCSI}
//                              ^ path len actually used
//                                                     ^            ^ misc., e.g. SE-file id for MF/DF
//                                                                               ^ PKCS#15 file type or 0xFF, see PKCS15_FILE_TYPE_*
#[repr(C)]
#[derive(/*Debug, Copy,*/ Clone)]
pub struct DataPrivate { // see settings in acos5_init
    #[cfg(not(target_os = "windows"))]
    pub pkcs15_definitions : crate::tasn1_sys::asn1_node, // used only as asn1_node_const, except in acos5_finish: asn1_delete_structure
    pub files : HashMap< KeyTypeFiles, ValueTypeFiles >,
    pub sec_env : sc_security_env, // remember the input of last call to acos5_64_set_security_env; especially algorithm_flags will be required in compute_signature
    pub agc : CardCtl_generate_crypt_asym,  // generate_asym, encrypt_asym
    pub agi : CardCtl_generate_inject_asym, // asym_generate_inject_data
//  pub sec_env_algo_flags : u32, // remember the padding scheme etc. selected for RSA; required in acos5_64_set_security_env
    pub time_stamp : std::time::Instant,
    pub sm_cmd : u32,
    pub rsa_caps : u32, // remember how the rsa_algo_flags where set for _sc_card_add_rsa_alg
    pub sec_env_mod_len : u16, //u32,
    pub rfu_align_pad1  : u16,
    pub does_mf_exist : bool,
    pub is_fips_mode : bool, // the Operation Mode Byte (for V3 or V4) is set to FIPS, opposed to 64K or any other mode: Special restrictions may apply
    pub is_fips_compliant : bool, // if is_fips_mode==true and also get_fips_compliance reports true, then this is true, else false (e.g. always for V2)
    pub is_running_init : bool, // true as long as acos5_64_init runs: It may be used to control behavior of acos5_64_list_files (lazily filling hashmap)
    /* some commands like sign, decipher etc. may supply > 256 bytes to get_response, but the exact number will not be known (the only info is 0x6100),
       thus guessing, there are another 256 bytes will be turned on with: true; guessing is limited to those commands, that turn on this feature.
       It's trial and error, not efficient as a general behavior of acos5_64_get_response
         false: acos5_64_get_response behaves (exactly?) like iso7816_get_response
     */
    pub is_running_compute_signature : bool, /* acos5_64_decipher needs to know, whether it was called by acos5_64_compute_signature */
    pub is_running_cmd_long_response : bool,
    pub is_cap_apdu_ext_enabled : bool, // was is_unwrap_op_in_progress
    pub rfu_align_pad2 : bool, // reserved future use, just inserted for alignment reason (fill the gap)
    pub sym_key_file_id : u16,
    pub sym_key_rec_idx : u8,
    pub sym_key_rec_cnt : u8,
    pub last_keygen_priv_id: sc_pkcs15_id,
    #[cfg(iup_user_consent)]
    pub ui_ctx : ui_context,
}


/*  returns true, if given a fdb parameter that represents type MF or DF, which are directories,
    returns false for any other fdb, which are 'real' files */
#[allow(non_snake_case)]
#[must_use]
#[inline]
pub fn is_DFMF(fdb: u8) -> bool
{
    (fdb & FDB_DF) == FDB_DF
}

/// Wraps sc_bytes2apdu
///
/// Additionally it
/// 1. Asserts SC_SUCCESS of call to sc_bytes2apdu
/// 2. Asserts, that the provided argument `cse` actually got assigned to apdu.cse
/// 3. If rbuf is not empty, then it assigns the provided argument `rbuf` to apdu.resp and apdu.resplen
///
/// # Examples
///
/// ```
/// use opensc_sys::{types::SC_APDU_CASE_4_SHORT, opensc::sc_context};
/// use acos5::constants_types::build_apdu;
/// # // don't use this terrible hack ref. ctx in regular code; it's done just to get around the ctx dependency
/// # let mut ctx = unsafe { &mut *std::ptr::null_mut::<sc_context>() };
/// let mut rbuf = [0_u8; 512];
/// let cmd = [0_u8, 0x2A, 0x84, 0x80, 0x02, 0xFF, 0xFF, 0x40];
/// let apdu = build_apdu(ctx, &cmd, SC_APDU_CASE_4_SHORT, &mut rbuf);
/// assert_eq!(apdu.cla, 0);
/// assert_eq!(apdu.ins, 0x2A);
/// assert_eq!(apdu.p1,  0x84);
/// assert_eq!(apdu.p2,  0x80);
/// assert_eq!(apdu.lc,  2);
/// assert_eq!(apdu.le,  0x40);
/// assert_eq!(apdu.data,    unsafe { cmd.as_ptr().add(5) });
/// assert_eq!(apdu.datalen, 2);
/// assert_eq!(apdu.resp,    rbuf.as_mut_ptr());
/// assert_eq!(apdu.resplen, rbuf.len());
/// ```
#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn build_apdu(ctx: &mut sc_context, cmd: &[u8], cse: i32, rbuf: &mut [u8]) -> sc_apdu {
    let mut apdu = sc_apdu::default();
    let rv = unsafe { sc_bytes2apdu(ctx, cmd.as_ptr(), cmd.len(), &mut apdu) };
    assert_eq!(SC_SUCCESS, rv);
    debug_assert_eq!(cse, apdu.cse);
    if !rbuf.is_empty() {
        apdu.resp    = rbuf.as_mut_ptr();
        apdu.resplen = rbuf.len();
    }
    apdu
}

#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn is_child_of(child: &ValueTypeFiles, parent: &ValueTypeFiles) -> bool {
    let pos = usize::from(parent.1[1]);
    assert!(pos < 16);
    let mut path = parent.0;
    path[pos..pos+2].copy_from_slice(&child.1[2..4]);
    path == child.0  &&  pos+2 == child.1[1].into()
}

/* The following 2 functions take the file id from the last valid path component */
#[allow(clippy::missing_panics_doc)]
#[must_use]
pub fn file_id_from_path_value(path_value: &[u8]) -> u16
{
    let len = path_value.len();
    assert!(len>=2);
    u16::from_be_bytes([path_value[len-2], path_value[len-1]])
}

#[must_use]
pub fn file_id(file_info_bytes: [u8; 8]) ->u16 {
    u16::from_be_bytes([file_info_bytes[2], file_info_bytes[3]])
}

/*
 a 2-byte slot [4..6] gets used only by some file types:
 for DF/MF its the id of an SE file
 for non-record based file types its the file size
*/
#[must_use]
pub fn file_id_se(file_info_bytes: [u8; 8]) ->u16 {
    u16::from_be_bytes([file_info_bytes[4], file_info_bytes[5]])
}

/* SCB: Security Condition Byte
 * convert_bytes_tag_fcp_sac_to_scb_array expands the (possibly) "compressed" tag_fcp_sac (0x8C) bytes from card file/director's
 * header to a 'standard' 8 byte SCB array, interpreting the AM byte (AMB);
 * The position of a SCB within the array is related to a command/operation, that is controlled by this byte
 * The value of SCB refers to a record id in Security Environment file, that stores details of conditions that must be
 * met in order to grant access
 * SC's byte positions are assigned values matching the AM bit-representation in reference manual, i.e. it is reversed
 * to what many other cards do:
 * Bit 7 of AM byte indicates what is stored to byte-index 7 of SC ( Not Used by ACOS )
 * Bit 0 of AM byte indicates what is stored to byte-index 0 of SC ( EF: READ, DF/MF:  Delete_Child )
 * Bits 0,1,2 may have different meaning depending on file type, from bits 3 to 6/7 (unused) meanings are the same for
 * all file types
 * Maybe later integrate this in acos5_process_fci
 * @param  bytes_tag_fcp_sac IN  the TLV's V bytes readable from file header for tag 0x8C, same order from left to right;
 *                               number of bytes: min: 0, max. 8
 *                               If there are >= 1 bytes, the first is AM (telling by 1 bits which bytes will follow)
 * @param  scb8          OUT     8 SecurityConditionBytes, from leftmost (index 0)'READ'/'Delete_Child' to
 *                               (6)'SC_AC_OP_DELETE_SELF', (7)'unused'
 *
 * The reference manual contains a table indicating the possible combinations of bits allowed for a scb:
 * For any violation, Err will be returned
 */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
///
/// # Errors
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::missing_panics_doc)]
pub fn convert_bytes_tag_fcp_sac_to_scb_array(bytes_tag_fcp_sac: &[u8]) -> Result<[u8; 8], i32>
{
    let mut scb8 = [0_u8; 8]; // if AM has no 1 bit for a command/operation, then it's : always allowed
    scb8[7] = 0xFF; // though not expected to be accidentally set, it gets overridden to NEVER: it's not used by ACOS

    if bytes_tag_fcp_sac.is_empty() {
        return Ok(scb8);
    }
    assert!(bytes_tag_fcp_sac.len() <= 8, "bytes_tag_fcp_sac.len() > 8");

    let mut idx = 0;
    let amb = bytes_tag_fcp_sac[idx];
    idx += 1;
    if usize::try_from(amb.count_ones()).unwrap() != bytes_tag_fcp_sac.len()-1 { // the count of 1-valued bits of amb Byte must equal (taglen-1), the count of bytes following amb
        return Err(SC_ERROR_INTERNAL);
    }

    for pos in 0..8 {
        if (amb & (0b1000_0000 >> pos)) != 0 { //assert(i);we should never get anything for scb8[7], it's not used by ACOS
            scb8[7-pos] = bytes_tag_fcp_sac[idx];
            idx += 1;
        }
    }
    Ok(scb8)
}

////////////////
////////////////

cfg_if::cfg_if! {
    if #[cfg(iup_user_consent)] {
        use libc::{free};
        //use opensc_sys::opensc::{sc_card/*, SC_CTX_FLAG_DISABLE_POPUPS*/};
        use opensc_sys::errors::{SC_ERROR_KEYPAD_MSG_TOO_LONG, SC_ERROR_NOT_ALLOWED};
        use opensc_sys::scconf::{scconf_find_blocks, scconf_get_bool/*, scconf_get_str*/};


        #[repr(C)]
        #[derive(Debug, Copy, Clone)]
        pub struct ui_context {
            //    pub user_consent_app : *const c_char,
            pub user_consent_enabled : i32,
        }


        impl Default for ui_context {
            fn default() -> Self {
                Self {
        //            user_consent_app: std::ptr::null(),
                    user_consent_enabled: 0
                }
            }
        }


        pub fn get_ui_ctx(card: &mut sc_card) -> ui_context
        {
            let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
            let ui_ctx = dp.ui_ctx;
            Box::leak(dp);
            // card.drv_data = Box::into_raw(dp) as p_void;
            ui_ctx
        }


        /* IUP Interface */
        pub enum Ihandle {}
        extern {
            pub fn IupOpen(argc: *const i32, argv: *const *const *const c_char) -> i32;
            pub fn IupClose();
            pub fn IupMessageDlg() -> *mut Ihandle; // https://webserver2.tecgraf.puc-rio.br/iup/en/dlg/iupmessagedlg.html
            pub fn IupDestroy(ih: *mut Ihandle);
            pub fn IupPopup(ih: *mut Ihandle, x: i32, y: i32) -> i32;
            //    pub fn IupSetAttributes(ih: *mut Ihandle, str: *const c_char) -> *mut Ihandle;
            pub fn IupSetAttribute(ih: *mut Ihandle, name: *const c_char, value: *const c_char);
            pub fn IupGetAttribute(ih: *mut Ihandle, name: *const c_char) -> *mut c_char;
        }

        /* called once only from acos5_init */
        pub fn set_ui_ctx(card: &mut sc_card, ui_ctx: &mut ui_context) -> i32
        {
            if card.ctx.is_null() {
                return SC_ERROR_KEYPAD_MSG_TOO_LONG;
            }
            /* set default values */
//            ui_ctx.user_consent_app = cstru!(USER_CONSENT_CMD_NIX).as_ptr();
            ui_ctx.user_consent_enabled = 1;

            /* look for sc block in opensc.conf */
            let ctx = unsafe { &mut *card.ctx };
            for elem in ctx.conf_blocks.iter() {
                if elem.is_null() { break; }

                let blocks_ptr = unsafe { scconf_find_blocks(ctx.conf, *elem,
                                                             c"card_driver".as_ptr(),
                                                             CARD_DRV_SHORT_NAME.as_ptr()) };
                if blocks_ptr.is_null() { continue; }
                let blk_ptr = unsafe { *blocks_ptr };

                unsafe { free(blocks_ptr as p_void) };
                if blk_ptr.is_null() { continue; }
                /* fill private data with configuration parameters */
//                ui_ctx.user_consent_app =    /* def user consent app is "pinentry" */
//              /*(char *)*/ unsafe { scconf_get_str(blk_ptr, cstru!(b"user_consent_app\0").as_ptr(), cstru!(USER_CONSENT_CMD_NIX).as_ptr()) };
                ui_ctx.user_consent_enabled =    /* user consent is enabled by default */
                    unsafe { scconf_get_bool(blk_ptr, cstru!(b"user_consent_enabled\0").as_ptr(), 1) };
            }
            /* possibly read disable_popups; this then may disable as well */
            if ui_ctx.user_consent_enabled == 1 { unsafe { IupOpen(std::ptr::null(), std::ptr::null()) }; }
            SC_SUCCESS
        }

        /**
         * Ask for user consent.
         *
         * Check for user consent configuration,
         * Invoke proper gui app and check result
         *
         * @param card pointer to sc_card structure
         * @param title Text to appear in the window header
         * @param text Message to show to the user
         * @return SC_SUCCESS on user consent OK , else error code
         */
        pub fn acos5_ask_user_consent() -> i32
        {
            unsafe {
                let dlg_ptr = IupMessageDlg();
                assert!(!dlg_ptr.is_null());
                IupSetAttribute(dlg_ptr, cstru!(b"DIALOGTYPE\0").as_ptr(), cstru!(b"QUESTION\0").as_ptr());
                IupSetAttribute(dlg_ptr, cstru!(b"TITLE\0").as_ptr(), cstru!(b"RSA private key usage\0").as_ptr());
                IupSetAttribute(dlg_ptr, cstru!(b"BUTTONS\0").as_ptr(), cstru!(b"YESNO\0").as_ptr());
                IupSetAttribute(dlg_ptr, cstru!(b"VALUE\0").as_ptr(), cstru!(b"Got a request to use an RSA private key (e.g. for a sign operation).\nDo You accept ?\n(Use 'Yes' only if this makes sense at this point)\0").as_ptr());
                IupPopup(dlg_ptr, 0xFFFF, 0xFFFF);
                let b_response_ptr = IupGetAttribute(dlg_ptr, cstru!(b"BUTTONRESPONSE\0").as_ptr()); // BUTTONRESPONSE: Number of the pressed button. Can be "1", "2" or "3". Default: "1".
                assert!(!b_response_ptr.is_null());
                let result_ok = *b_response_ptr == 49;
                IupDestroy(dlg_ptr);
                /* IupClose();  can't be used here, otherwise - using acos5_gui - this would close the acos5_gui application and crash that */
                if !result_ok { SC_ERROR_NOT_ALLOWED }
                else          { SC_SUCCESS }
            }
        }
    }
}
