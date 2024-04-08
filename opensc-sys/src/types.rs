/*
 * types.h: OpenSC general types
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

// Binding state: tabs:    ?, header:    ? (except pub const type checks), checkAPI15-19:    ?, checkEXPORTS15-19:    ?, compareD17-18:    ?, doc:    ?, tests:    ?
// TODO check IN, OUT etc., rename parameter names for a unified interface; #DEFINE/#UNDEF influence on struct size etc.: none: OKAY  (no direct (non-#include #define influence on struct sizes))

use std::os::raw::c_ulong;
#[cfg(impl_default)]
use std::ptr::{null, null_mut};

/* various maximum values */
pub const SC_MAX_CARD_DRIVERS           : usize =    48;
pub const SC_MAX_CARD_DRIVER_SNAME_SIZE : usize =    16;
pub const SC_MAX_CARD_APPS              : usize =     8;
pub const SC_MAX_APDU_BUFFER_SIZE       : usize =   0xFF+6;   /* 261 takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
pub const SC_MAX_EXT_APDU_BUFFER_SIZE   : usize =   0xFFFF+3; /* 65538 */
pub const SC_MAX_APDU_DATA_SIZE         : usize = 0xFF;   // == SC_READER_SHORT_APDU_MAX_SEND_SIZE
pub const SC_MAX_APDU_RESP_SIZE         : usize = 0xFF+1; // == SC_READER_SHORT_APDU_MAX_RECV_SIZE
pub const SC_MAX_EXT_APDU_DATA_SIZE     : usize = 0xFFFF;
pub const SC_MAX_EXT_APDU_RESP_SIZE     : usize = 0xFFFF+1;
pub const SC_MAX_PIN_SIZE               : usize =   256; /* OpenPGP card has 254 max */
pub const SC_MAX_ATR_SIZE               : usize =    33;
pub const SC_MAX_UID_SIZE               : usize =    10;
pub const SC_MAX_AID_SIZE               : usize =    16;
pub const SC_MAX_AID_STRING_SIZE        : usize = SC_MAX_AID_SIZE * 2 + 3;
pub const SC_MAX_IIN_SIZE               : usize =    10;
pub const SC_MAX_OBJECT_ID_OCTETS       : usize =    16;
pub const SC_MAX_PATH_SIZE              : usize =    16;
pub const SC_MAX_PATH_STRING_SIZE       : usize = SC_MAX_PATH_SIZE * 2 + 3;
pub const SC_MAX_SDO_ACLS               : usize =     8;
pub const SC_MAX_CRTS_IN_SE             : usize =    12;
pub const SC_MAX_SE_NUM                 : usize =     8;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
pub const SC_MAX_PKCS15_EMULATORS       : usize =    48;

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c,
 * src/libopensc/pkcs15-prkey.c and src/libopensc/pkcs15-skey.c
 * `grep "src/libopensc/types.h SC_MAX_SUPPORTED_ALGORITHMS  defined as"'
 */
cfg_if::cfg_if! {
    if #[cfg(v0_20_0)] {
        pub const SC_MAX_SUPPORTED_ALGORITHMS   : usize =  8;
    }
    else {
        pub const SC_MAX_SUPPORTED_ALGORITHMS   : usize =  16; /* since opensc source release v0.21.0 */
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_lv_data {
    pub value : *mut u8,
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_tlv_data {
    pub tag   : u32,
    pub value : *mut u8,
    pub len   : usize,
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct sc_object_id {
    pub value : [i32; SC_MAX_OBJECT_ID_OCTETS],
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct sc_aid {
    pub value : [u8; SC_MAX_AID_SIZE],
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_atr {
    pub value : [u8; SC_MAX_ATR_SIZE],
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_uid { // since opensc source release v0.17.0
    pub value : [u8; SC_MAX_UID_SIZE],
    pub len   : usize,
}

/* Issuer ID */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_iid {
    pub value : [u8; SC_MAX_IIN_SIZE],
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_version {
    pub hw_major : u8,
    pub hw_minor : u8,

    pub fw_major : u8,
    pub fw_minor : u8,
}

/* Discretionary ASN.1 data object */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_ddo {
    pub aid : sc_aid,
    pub iid : sc_iid,
    pub oid : sc_object_id,

    pub len   : usize,
    pub value : *mut u8,
}

pub const SC_PATH_TYPE_FILE_ID:      i32 =  0;
pub const SC_PATH_TYPE_DF_NAME:      i32 =  1;
pub const SC_PATH_TYPE_PATH:         i32 =  2;
/* path of a file containing EnvelopedData objects */
pub const SC_PATH_TYPE_PATH_PROT:    i32 =  3;
pub const SC_PATH_TYPE_FROM_CURRENT: i32 =  4;
pub const SC_PATH_TYPE_PARENT:       i32 =  5;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct sc_path {
    pub value : [u8; SC_MAX_PATH_SIZE],
    pub len : usize,

 /* The next two fields are used in PKCS15, where
  * a Path object can reference a portion of a file -
  * count octets starting at offset index.
  */
    pub index : i32,
    pub count : i32,

    pub type_ : i32,

    pub aid : sc_aid,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_path_t = sc_path;
*/

impl Default for sc_path {
    fn default() -> Self {
        Self {
            value: [0; SC_MAX_PATH_SIZE],
            len:    0,
            index:  0,
            count:  -1,
            type_:  0, // SC_PATH_TYPE_FILE_ID
            aid:    sc_aid::default()
        }
    }
}

/* Control reference template */
#[repr(C)]
#[derive(Default, Debug, Copy, Clone,  PartialEq)]
pub struct sc_crt {
    pub tag   : u32,
    pub usage : u32,  /* Usage Qualifier Byte */
    pub algo  : u32,  /* Algorithm ID */
    pub refs  : [u32; 8], /* Security Object References */
}

#[allow(non_snake_case)]
#[cfg(impl_newAT_newCCT_newCT)]
impl sc_crt {
    /* new with Authentication Template tag 0xA4 */
    #[must_use]
    pub fn new_AT(usage: u32) -> Self {
        Self { tag: 0xA4, usage, ..Self::default() }
    }

    /* new with Cryptographic Checksum Template tag 0xB4 */
    #[must_use]
    pub fn new_CCT(usage: u32) -> Self {
        Self { tag: 0xB4, usage, ..Self::default() }
    }

    /* new with Confidentiality Template tag 0xB8 */
    #[must_use]
    pub fn new_CT(usage: u32) -> Self {
        Self { tag: 0xB8, usage, ..Self::default() }
    }
}

/* Access Control flags */
pub const SC_AC_NONE             : u32 =  0x0000_0000;
pub const SC_AC_CHV              : u32 =  0x0000_0001; /* Card Holder Verif. */
pub const SC_AC_TERM             : u32 =  0x0000_0002; /* Terminal auth. */
pub const SC_AC_PRO              : u32 =  0x0000_0004; /* Secure Messaging */ /* just a marker: the OpenSC framework will do nothing else than print */
pub const SC_AC_AUT              : u32 =  0x0000_0008; /* Key auth. */
pub const SC_AC_SYMBOLIC         : u32 =  0x0000_0010; /* internal use only */
pub const SC_AC_SEN              : u32 =  0x0000_0020; /* Security Environment. */
pub const SC_AC_SCB              : u32 =  0x0000_0040; /* IAS/ECC SCB byte. */
pub const SC_AC_IDA              : u32 =  0x0000_0080; /* PKCS#15 authentication ID */
pub const SC_AC_SESSION          : u32 =  0x0000_0100; /* Session PIN */ // since opensc source release v0.17.0
pub const SC_AC_CONTEXT_SPECIFIC : u32 =  0x0000_0200; /* Context specific login */ // since opensc source release v0.18.0

pub const SC_AC_UNKNOWN          : u32 =  0xFFFF_FFFE;
pub const SC_AC_NEVER            : u32 =  0xFFFF_FFFF;

/* Operations relating to access control */
pub const SC_AC_OP_SELECT                : u32 =   0;
pub const SC_AC_OP_LOCK                  : u32 =   1;
pub const SC_AC_OP_DELETE                : u32 =   2;
pub const SC_AC_OP_CREATE                : u32 =   3;
pub const SC_AC_OP_REHABILITATE          : u32 =   4;
pub const SC_AC_OP_INVALIDATE            : u32 =   5;
pub const SC_AC_OP_LIST_FILES            : u32 =   6;
pub const SC_AC_OP_CRYPTO                : u32 =   7;
pub const SC_AC_OP_DELETE_SELF           : u32 =   8;
pub const SC_AC_OP_PSO_DECRYPT           : u32 =   9;
pub const SC_AC_OP_PSO_ENCRYPT           : u32 =  10;
pub const SC_AC_OP_PSO_COMPUTE_SIGNATURE : u32 =  11;
pub const SC_AC_OP_PSO_VERIFY_SIGNATURE  : u32 =  12;
pub const SC_AC_OP_PSO_COMPUTE_CHECKSUM  : u32 =  13;
pub const SC_AC_OP_PSO_VERIFY_CHECKSUM   : u32 =  14;
pub const SC_AC_OP_INTERNAL_AUTHENTICATE : u32 =  15;
pub const SC_AC_OP_EXTERNAL_AUTHENTICATE : u32 =  16;
pub const SC_AC_OP_PIN_DEFINE            : u32 =  17;
pub const SC_AC_OP_PIN_CHANGE            : u32 =  18;
pub const SC_AC_OP_PIN_RESET             : u32 =  19;
pub const SC_AC_OP_ACTIVATE              : u32 =  20;
pub const SC_AC_OP_DEACTIVATE            : u32 =  21;
pub const SC_AC_OP_READ                  : u32 =  22;
pub const SC_AC_OP_UPDATE                : u32 =  23;
pub const SC_AC_OP_WRITE                 : u32 =  24;
pub const SC_AC_OP_RESIZE                : u32 =  25;
pub const SC_AC_OP_GENERATE              : u32 =  26;
pub const SC_AC_OP_CREATE_EF             : u32 =  27;
pub const SC_AC_OP_CREATE_DF             : u32 =  28;
pub const SC_AC_OP_ADMIN                 : u32 =  29;
pub const SC_AC_OP_PIN_USE               : u32 =  30;
/* If you add more OPs here, make sure you increase SC_MAX_AC_OPS*/
pub const SC_MAX_AC_OPS                : usize =  31;

/* the use of SC_AC_OP_ERASE is deprecated, SC_AC_OP_DELETE should be used
 * instead  */
#[deprecated(since="0.0.0", note="please use `SC_AC_OP_DELETE` instead")]
pub const SC_AC_OP_ERASE                 : u32 =  SC_AC_OP_DELETE;

pub const SC_AC_KEY_REF_NONE             : c_ulong =  0xFFFF_FFFF;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_acl_entry {
    pub method  : u32, /* See SC_AC_* */
    pub key_ref : u32, /* SC_AC_KEY_REF_NONE or an integer */

    #[cfg(v0_20_0)]
    pub crts    : [sc_crt; SC_MAX_CRTS_IN_SE],

    pub next    : *mut sc_acl_entry,
}

#[cfg(impl_default)]
impl Default for sc_acl_entry {
    fn default() -> Self {
        Self {
            method: 0, // 0 == SC_AC_OP_SELECT
            key_ref: 0,
            #[cfg(v0_20_0)]
            crts: [sc_crt::default(); SC_MAX_CRTS_IN_SE],
            next: null_mut()
        }
    }
}

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_acl_entry_t = sc_acl_entry;
*/

/* File types */
pub const SC_FILE_TYPE_UNKNOWN     : u32 =  0x00;  // since v0_21_0
pub const SC_FILE_TYPE_DF          : u32 =  0x04;
pub const SC_FILE_TYPE_INTERNAL_EF : u32 =  0x03;
pub const SC_FILE_TYPE_WORKING_EF  : u32 =  0x01;
pub const SC_FILE_TYPE_BSO         : u32 =  0x10;

/* EF structures */
pub const SC_FILE_EF_UNKNOWN             : u32 =  0x00; // e.g. for MF, DF
pub const SC_FILE_EF_TRANSPARENT         : u32 =  0x01;
pub const SC_FILE_EF_LINEAR_FIXED        : u32 =  0x02;
pub const SC_FILE_EF_LINEAR_FIXED_TLV    : u32 =  0x03;
pub const SC_FILE_EF_LINEAR_VARIABLE     : u32 =  0x04;
pub const SC_FILE_EF_LINEAR_VARIABLE_TLV : u32 =  0x05;
pub const SC_FILE_EF_CYCLIC              : u32 =  0x06;
pub const SC_FILE_EF_CYCLIC_TLV          : u32 =  0x07;

/* File flags */
cfg_if::cfg_if! {
if #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))] {
    pub const SC_FILE_FLAG_COMPRESSED_AUTO  : c_ulong =  0x01;
    pub const SC_FILE_FLAG_COMPRESSED_ZLIB  : c_ulong =  0x02;
    pub const SC_FILE_FLAG_COMPRESSED_GZIP  : c_ulong =  0x04;
}}

/* File status flags */
/* ISO7816-4: Unless otherwise specified, the security attributes are valid for the operational state.*/
pub const SC_FILE_STATUS_ACTIVATED : u32       = 0x00; /* ISO7816-4: Operational state (activated)   (5, 7) */
pub const SC_FILE_STATUS_INVALIDATED : u32     = 0x01; /* ISO7816-4: Operational state (deactivated) (4, 6) */

/* Full access in this state, (at least for SetCOS 4.4 ) */
pub const SC_FILE_STATUS_CREATION : u32        = 0x02; /* ISO7816-4: Creation state, (1) */

pub const SC_FILE_STATUS_INITIALISATION : u32  = 0x03; /* ISO7816-4: Initialisation state, (3) */
pub const SC_FILE_STATUS_NO_INFO : u32         = 0x04; /* ISO7816-4: No information given, (0) */
pub const SC_FILE_STATUS_TERMINATION : u32     = 0x0c; /* ISO7816-4: Termination state (12,13,14,15) */
pub const SC_FILE_STATUS_PROPRIETARY : u32     = 0xf0; /* ISO7816-4: codes > 15 */

/* reserved for future use by ISO/IEC */
pub const SC_FILE_STATUS_RFU_2 : u32           = 0x07; /* ISO7816-4: (0x02) */
pub const SC_FILE_STATUS_RFU_8 : u32           = 0x08; /* ISO7816-4: (0x08) */
pub const SC_FILE_STATUS_RFU_9 : u32           = 0x09; /* ISO7816-4: (0x09) */
pub const SC_FILE_STATUS_RFU_10 : u32          = 0x0a; /* ISO7816-4: (0x0a) */
pub const SC_FILE_STATUS_RFU_11 : u32          = 0x0b; /* ISO7816-4: (0x0b) */

pub const SC_FILE_STATUS_UNKNOWN : u32         = 0xff; /* if tag 0x8A is missing, there is no information about LCSB */


#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct sc_file {
    pub path : sc_path,
    pub name : [u8; SC_MAX_AID_SIZE /*16usize*/], /* DF name */
    pub namelen : usize, /* length of DF name */

    pub type_        : u32, /* See constant values defined above */  // binding: name changed from type to type_
    pub ef_structure : u32, /* See constant values defined above */
    pub status       : u32, /* See constant values defined above */
    pub shareable    : u32, /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */
    pub size         : usize,  /* Size of file (in bytes) */
    pub id           : i32,  /* file identifier (2 bytes) */
    pub sid          : i32,  /* short EF identifier (1 byte) */
    pub acl          : [*mut sc_acl_entry; SC_MAX_AC_OPS], /* Access Control List */
    #[cfg(not(any(v0_20_0, v0_21_0)))]
    acl_inactive     : i32,  /* if set, the card access control mechanism is not active */

    pub record_length : usize, /* max. length in case of record-oriented EF */
    pub record_count  : usize, /* Valid, if not transparent EF or DF */

    pub sec_attr      : *mut u8, /* security data in proprietary format. tag '86' */
    pub sec_attr_len  : usize,

    pub prop_attr     : *mut u8, /* proprietary information. tag '85'*/
    pub prop_attr_len : usize,

    pub type_attr     : *mut u8, /* file descriptor data. tag '82'.
        replaces the file's type information (DF, EF, ...) */
    pub type_attr_len : usize,

    pub encoded_content     : *mut u8, /* file's content encoded to be used in the file creation command */
    pub encoded_content_len : usize, /* size of file's encoded content in bytes */

    pub magic : u32,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_file_t = sc_file;
*/
/*
#[cfg(impl_default)]
impl Default for sc_file {
    fn default() -> Self {
        Self {
            path: sc_path::default(),
            name: [0; SC_MAX_AID_SIZE],
            namelen: 0,
            type_: 0,
            ef_structure: 0,
            status: 0,
            shareable: 0,
            size: 0,
            id: 0,
            sid: 0,
            acl: [null_mut(); SC_MAX_AC_OPS],
            sec_attr: null_mut(),
            sec_attr_len: 0,
            prop_attr: null_mut(),
            prop_attr_len: 0,
            type_attr: null_mut(),
            type_attr_len: 0,
            encoded_content: null_mut(),
            encoded_content_len: 0,
            magic: 0x1442_6950
        }
    }
}
*/
/* Different APDU cases */
pub const SC_APDU_CASE_NONE    : i32 =  0x00;
pub const SC_APDU_CASE_1       : i32 =  0x01;
pub const SC_APDU_CASE_2_SHORT : i32 =  0x02;
pub const SC_APDU_CASE_3_SHORT : i32 =  0x03;
pub const SC_APDU_CASE_4_SHORT : i32 =  0x04;
pub const SC_APDU_SHORT_MASK   : i32 =  0x0f;
pub const SC_APDU_EXT          : i32 =  0x10;
pub const SC_APDU_CASE_2_EXT   : i32 =  SC_APDU_CASE_2_SHORT | SC_APDU_EXT;
pub const SC_APDU_CASE_3_EXT   : i32 =  SC_APDU_CASE_3_SHORT | SC_APDU_EXT;
pub const SC_APDU_CASE_4_EXT   : i32 =  SC_APDU_CASE_4_SHORT | SC_APDU_EXT;
/* following types let OpenSC decides whether to use short or extended APDUs */
pub const SC_APDU_CASE_2       : i32 =  0x22;
pub const SC_APDU_CASE_3       : i32 =  0x23;
pub const SC_APDU_CASE_4       : i32 =  0x24;

/* use command chaining if the Lc value is greater than normally allowed */
pub const SC_APDU_FLAGS_CHAINING     : c_ulong =  0x0000_0001;
/* do not automatically call GET RESPONSE to read all available data */
pub const SC_APDU_FLAGS_NO_GET_RESP  : c_ulong =  0x0000_0002;
/* do not automatically try a re-transmit with a new length if the card
 * returns 0x6Cxx (wrong length)
 */
pub const SC_APDU_FLAGS_NO_RETRY_WL  : c_ulong =  0x0000_0004;
/* APDU is from Secure Messaging  */
pub const SC_APDU_FLAGS_NO_SM        : c_ulong =  0x0000_0008; // since opensc source release v0.17.0
/* let SM do the command chaining  */
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
pub const SC_APDU_FLAGS_SM_CHAINING  : c_ulong =  0x0000_0010;

pub const SC_APDU_ALLOCATE_FLAG      : c_ulong =  0x01;
pub const SC_APDU_ALLOCATE_FLAG_DATA : c_ulong =  0x02;
pub const SC_APDU_ALLOCATE_FLAG_RESP : c_ulong =  0x04;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_apdu {
    pub cse : i32,   /* APDU case */
    pub cla : u8, /* CLA bytes */
    pub ins : u8, /* INS bytes */
    pub p1  : u8, /* P1 bytes */
    pub p2  : u8, /* P2 bytes */
    pub lc : usize,   /* Lc bytes */
    pub le : usize,   /* Le bytes */
    pub data : *const u8, /* S-APDU data */
    pub datalen : usize,   /* length of data in S-APDU */
    pub resp : *mut u8,  /* R-APDU data buffer */
    pub resplen : usize,   /* in: size of R-APDU buffer,
                           * out: length of data returned in R-APDU */
    pub control : u8,  /* Set if APDU should go to the reader */
    pub allocation_flags : u32, /* APDU allocation flags */

    pub sw1 : u32,  /* Status words returned in R-APDU */
    pub sw2 : u32,  /* Status words returned in R-APDU */
    pub mac : [u8; 8],
    pub mac_len : usize,

    pub flags : c_ulong, //unsigned long flags;

    pub next : *mut sc_apdu,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_apdu_t = sc_apdu ;
*/

#[cfg(impl_default)]
impl Default for sc_apdu {
    fn default() -> Self {
        Self {
            cse              :  0,
            cla              :  0,
            ins              :  0,
            p1               :  0,
            p2               :  0,
            lc               :  0,
            le               :  0,
            data             :  null(),
            datalen          :  0,
            resp             :  null_mut(),
            resplen          :  0,
            control          :  0,
            allocation_flags :  0,
            sw1              :  0,
            sw2              :  0,
            mac              :  [0; 8],
            mac_len          :  0,
            flags            :  0,
            next             :  null_mut(),
        }
    }
}

/* Card manager Production Life Cycle data (CPLC)
 * (from the Open Platform specification) */
pub const SC_CPLC_TAG      : u32   =  0x9F7F;
pub const SC_CPLC_DER_SIZE : usize = 45;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_cplc {
    pub ic_fabricator : [u8; 2],
    pub ic_type : [u8; 2],
    pub os_data : [u8; 6],
    pub ic_date : [u8; 2],
    pub ic_serial : [u8; 4],
    pub ic_batch_id : [u8; 2],
    pub ic_module_data : [u8; 4],
    pub icc_manufacturer : [u8; 2],
    pub ic_embed_date : [u8; 2],
    pub pre_perso_data : [u8; 6],
    pub personalizer_data : [u8; 6],

    pub value : [u8; SC_CPLC_DER_SIZE],
    pub len : usize,
}


/* 'Issuer Identification Number' is a part of ISO/IEC 7812 PAN definition */
#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct sc_iin {
    pub mii : u8,              /* industry identifier */
    pub country : u32,           /* country identifier */
    pub issuer_id : c_ulong,        /* issuer identifier */
}

/* structure for the card serial number (normally the ICCSN) */
pub const SC_MAX_SERIALNR : usize = 32;

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct sc_serial_number {
    pub value : [u8; SC_MAX_SERIALNR],
    pub len : usize,

    pub iin : sc_iin,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_serial_number_t = sc_serial_number;
*/

/**
 * @struct sc_remote_apdu data
 * Structure to supply the linked APDU data used in
 * communication with the external (SM) modules.
 */
pub const SC_REMOTE_APDU_FLAG_NOT_FATAL     : u32   =  0x01;
pub const SC_REMOTE_APDU_FLAG_RETURN_ANSWER : u32   =  0x02;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_remote_apdu {
    pub sbuf : [u8; 2*SC_MAX_APDU_BUFFER_SIZE],
    pub rbuf : [u8; 2*SC_MAX_APDU_BUFFER_SIZE],
    pub apdu : sc_apdu,

    pub flags : u32, /* e.g. SC_REMOTE_APDU_FLAG_RETURN_ANSWER */

    pub next : *mut sc_remote_apdu,
}

#[cfg(impl_default)]
impl Default for sc_remote_apdu {
    fn default() -> Self {
        Self {
            sbuf: [0; 2*SC_MAX_APDU_BUFFER_SIZE],
            rbuf: [0; 2*SC_MAX_APDU_BUFFER_SIZE],
            apdu: sc_apdu::default(),
            flags: 0,
            next: null_mut()
        }
    }
}

/**
 * @struct sc_remote_data
 * Frame for the list of the @c sc_remote_apdu data with
 * the handlers to allocate and free.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_remote_data {
    pub data : *mut sc_remote_apdu,
    pub length : i32,

    /**
     * Handler to allocate a new @c sc_remote_apdu data and add it to the list.
     * @param rdata Self pointer to the @c sc_remote_data
     * @param out Pointer to newly allocated member
     */
    pub alloc : Option< unsafe extern "C" fn (rdata: *mut sc_remote_data,
                                              out: *mut *mut sc_remote_apdu) -> i32 >,
    /**
     * Handler to free the list of @c sc_remote_apdu data
     * @param rdata Self pointer to the @c sc_remote_data
     */
    pub free  : Option< unsafe extern "C" fn (rdata: *mut sc_remote_data) >,
}

#[cfg(impl_default)]
impl Default for sc_remote_data {
    fn default() -> Self {
        Self {
            data: null_mut(),
            length: 0,
            alloc: None,
            free: None
        }
    }
}
