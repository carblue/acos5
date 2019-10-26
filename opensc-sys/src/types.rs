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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110-1335  USA
 */

// Binding state: tabs:    ?, header:    ? (except pub const type checks), checkAPI15-19:    ?, checkEXPORTS15-19:    ?, compareD17-18:    ?, doc:    ?, tests:    ?
// TODO check IN, OUT etc., rename paramater names for a unified interface; #DEFINE/#UNDEF influence on struct size etc.: none: OKAY  (no direct (non-#include #define influence on struct sizes))

use std::os::raw::{c_uchar, c_uint, c_int, c_ulong};
//use std::option::Option;

//typedef unsigned char u8; pub type u8 = c_uchar ;  std::os::raw::c_uchar definition: type c_uchar = u8;

/* various maximum values */
pub const SC_MAX_CARD_DRIVERS           : usize =    48;
pub const SC_MAX_CARD_DRIVER_SNAME_SIZE : usize =    16;
pub const SC_MAX_CARD_APPS              : usize =     8;
pub const SC_MAX_APDU_BUFFER_SIZE       : usize =   261; /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_MAX_APDU_DATA_SIZE         : usize =  0xFF;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_MAX_APDU_RESP_SIZE         : usize = 0xFF+1;

pub const SC_MAX_EXT_APDU_BUFFER_SIZE   : usize = 65538;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_MAX_EXT_APDU_DATA_SIZE     : usize = 0xFFFF;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub const SC_MAX_EXT_APDU_RESP_SIZE     : usize = 0xFFFF+1;
pub const SC_MAX_PIN_SIZE               : usize =   256; /* OpenPGP card has 254 max */
pub const SC_MAX_ATR_SIZE               : usize =    33;
pub const SC_MAX_UID_SIZE               : usize =    10; /* since opensc source release v0.17.0 */
pub const SC_MAX_AID_SIZE               : usize =    16;
pub const SC_MAX_AID_STRING_SIZE        : usize = (SC_MAX_AID_SIZE * 2 + 3);
pub const SC_MAX_IIN_SIZE               : usize =    10;
pub const SC_MAX_OBJECT_ID_OCTETS       : usize =    16;
pub const SC_MAX_PATH_SIZE              : usize =    16;
pub const SC_MAX_PATH_STRING_SIZE       : usize = (SC_MAX_PATH_SIZE * 2 + 3);
pub const SC_MAX_SDO_ACLS               : usize =     8;
pub const SC_MAX_CRTS_IN_SE             : usize =    12;
pub const SC_MAX_SE_NUM                 : usize =     8;

/* When changing this value, pay attention to the initialization of the ASN1
 * static variables that use this macro, like, for example,
 * 'c_asn1_supported_algorithms' in src/libopensc/pkcs15.c
 */
pub const SC_MAX_SUPPORTED_ALGORITHMS   : usize =     8;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_lv_data {
    pub value : *mut c_uchar,
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_tlv_data {
    pub tag   : c_uint,
    pub value : *mut c_uchar,
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct sc_object_id {
    pub value : [c_int; SC_MAX_OBJECT_ID_OCTETS],
}

#[cfg(impl_default)]
impl Default for sc_object_id {
    fn default() -> sc_object_id {
        sc_object_id {
            value: [0; SC_MAX_OBJECT_ID_OCTETS]
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_aid {
    pub value : [c_uchar; SC_MAX_AID_SIZE],
    pub len   : usize,
}

#[cfg(impl_default)]
impl Default for sc_aid {
    fn default() -> sc_aid {
        sc_aid  {
            value: [0; SC_MAX_AID_SIZE],
            len: 0
        }
    }
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_atr {
    pub value : [c_uchar; SC_MAX_ATR_SIZE],
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_uid { // since opensc source release v0.17.0
    pub value : [c_uchar; SC_MAX_UID_SIZE],
    pub len   : usize,
}

/* Issuer ID */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_iid {
    pub value : [c_uchar; SC_MAX_IIN_SIZE],
    pub len   : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_version {
    pub hw_major : c_uchar,
    pub hw_minor : c_uchar,

    pub fw_major : c_uchar,
    pub fw_minor : c_uchar,
}

/* Discretionary ASN.1 data object */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_ddo {
    pub aid : sc_aid,
    pub iid : sc_iid,
    pub oid : sc_object_id,

    pub len   : usize,
    pub value : *mut c_uchar,
}

pub const SC_PATH_TYPE_FILE_ID:      c_int =  0;
pub const SC_PATH_TYPE_DF_NAME:      c_int =  1;
pub const SC_PATH_TYPE_PATH:         c_int =  2;
/* path of a file containing EnvelopedData objects */
pub const SC_PATH_TYPE_PATH_PROT:    c_int =  3;
pub const SC_PATH_TYPE_FROM_CURRENT: c_int =  4;
pub const SC_PATH_TYPE_PARENT:       c_int =  5;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_path {
    pub value : [c_uchar; SC_MAX_PATH_SIZE],
    pub len : usize,

 /* The next two fields are used in PKCS15, where
  * a Path object can reference a portion of a file -
  * count octets starting at offset index.
  */
    pub index : c_int,
    pub count : c_int,

    pub type_ : c_int,

    pub aid : sc_aid,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_path_t = sc_path;
*/

#[cfg(impl_default)]
impl Default for sc_path {
    fn default() -> sc_path {
        sc_path {
            value: [0; SC_MAX_PATH_SIZE],
            len:    0,
            index:  0,
            count:  -1,
            type_:  0, // SC_PATH_TYPE_FILE_ID
            aid:    Default::default()
        }
    }
}

/* Control reference template */
#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct sc_crt {
    pub tag   : c_uint,
    pub usage : c_uint,  /* Usage Qualifier Byte */
    pub algo  : c_uint,  /* Algorithm ID */
    pub refs  : [c_uint; 8usize], /* Security Object References */
}

#[allow(non_snake_case)]
#[cfg(impl_newAT_newCCT_newCT)]
impl sc_crt {
    /* new with Authentication Template tag 0xA4 */
    pub fn new_AT(usage: c_uint) -> sc_crt {
        sc_crt { tag: 0xA4, usage, ..Default::default() }
    }

    /* new with Cryptographic Checksum Template tag 0xB4 */
    pub fn new_CCT(usage: c_uint) -> sc_crt {
        sc_crt { tag: 0xB4, usage, ..Default::default() }
    }

    /* new with Confidentiality Template tag 0xB8 */
    pub fn new_CT(usage: c_uint) -> sc_crt {
        sc_crt { tag: 0xB8, usage, ..Default::default() }
    }
}

#[cfg(impl_default)]
impl Default for sc_crt {
    fn default() -> sc_crt {
        sc_crt {
            tag:   0,
            usage: 0,
            algo:  0,
            refs:  [0; 8]
        }
    }
}

/* Access Control flags */
pub const SC_AC_NONE             : c_uint =  0x0000_0000;
pub const SC_AC_CHV              : c_uint =  0x0000_0001; /* Card Holder Verif. */
pub const SC_AC_TERM             : c_uint =  0x0000_0002; /* Terminal auth. */
pub const SC_AC_PRO              : c_uint =  0x0000_0004; /* Secure Messaging */
pub const SC_AC_AUT              : c_uint =  0x0000_0008; /* Key auth. */
pub const SC_AC_SYMBOLIC         : c_uint =  0x0000_0010; /* internal use only */
pub const SC_AC_SEN              : c_uint =  0x0000_0020; /* Security Environment. */
pub const SC_AC_SCB              : c_uint =  0x0000_0040; /* IAS/ECC SCB byte. */
pub const SC_AC_IDA              : c_uint =  0x0000_0080; /* PKCS#15 authentication ID */
pub const SC_AC_SESSION          : c_uint =  0x0000_0100; /* Session PIN */ // since opensc source release v0.17.0
#[cfg(not(v0_17_0))]
pub const SC_AC_CONTEXT_SPECIFIC : c_uint =  0x0000_0200; /* Context specific login */ // since opensc source release v0.18.0

pub const SC_AC_UNKNOWN          : c_uint =  0xFFFF_FFFE;
pub const SC_AC_NEVER            : c_uint =  0xFFFF_FFFF;

/* Operations relating to access control */
pub const SC_AC_OP_SELECT                : c_uint =   0;
pub const SC_AC_OP_LOCK                  : c_uint =   1;
pub const SC_AC_OP_DELETE                : c_uint =   2;
pub const SC_AC_OP_CREATE                : c_uint =   3;
pub const SC_AC_OP_REHABILITATE          : c_uint =   4;
pub const SC_AC_OP_INVALIDATE            : c_uint =   5;
pub const SC_AC_OP_LIST_FILES            : c_uint =   6;
pub const SC_AC_OP_CRYPTO                : c_uint =   7;
pub const SC_AC_OP_DELETE_SELF           : c_uint =   8;
pub const SC_AC_OP_PSO_DECRYPT           : c_uint =   9;
pub const SC_AC_OP_PSO_ENCRYPT           : c_uint =  10;
pub const SC_AC_OP_PSO_COMPUTE_SIGNATURE : c_uint =  11;
pub const SC_AC_OP_PSO_VERIFY_SIGNATURE  : c_uint =  12;
pub const SC_AC_OP_PSO_COMPUTE_CHECKSUM  : c_uint =  13;
pub const SC_AC_OP_PSO_VERIFY_CHECKSUM   : c_uint =  14;
pub const SC_AC_OP_INTERNAL_AUTHENTICATE : c_uint =  15;
pub const SC_AC_OP_EXTERNAL_AUTHENTICATE : c_uint =  16;
pub const SC_AC_OP_PIN_DEFINE            : c_uint =  17;
pub const SC_AC_OP_PIN_CHANGE            : c_uint =  18;
pub const SC_AC_OP_PIN_RESET             : c_uint =  19;
pub const SC_AC_OP_ACTIVATE              : c_uint =  20;
pub const SC_AC_OP_DEACTIVATE            : c_uint =  21;
pub const SC_AC_OP_READ                  : c_uint =  22;
pub const SC_AC_OP_UPDATE                : c_uint =  23;
pub const SC_AC_OP_WRITE                 : c_uint =  24;
pub const SC_AC_OP_RESIZE                : c_uint =  25;
pub const SC_AC_OP_GENERATE              : c_uint =  26;
pub const SC_AC_OP_CREATE_EF             : c_uint =  27;
pub const SC_AC_OP_CREATE_DF             : c_uint =  28;
pub const SC_AC_OP_ADMIN                 : c_uint =  29;
pub const SC_AC_OP_PIN_USE               : c_uint =  30;
/* If you add more OPs here, make sure you increase SC_MAX_AC_OPS*/
pub const SC_MAX_AC_OPS                : usize =  31;

/* the use of SC_AC_OP_ERASE is deprecated, SC_AC_OP_DELETE should be used
 * instead  */
#[deprecated(since="0.0.0", note="please use `SC_AC_OP_DELETE` instead")]
pub const SC_AC_OP_ERASE                 : c_uint =  SC_AC_OP_DELETE;

pub const SC_AC_KEY_REF_NONE             : c_uint =  0xFFFF_FFFF;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_acl_entry {
    pub method  : c_uint, /* See SC_AC_* */
    pub key_ref : c_uint, /* SC_AC_KEY_REF_NONE or an integer */

    pub crts    : [sc_crt; SC_MAX_CRTS_IN_SE],

    pub next    : *mut sc_acl_entry,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_acl_entry_t = sc_acl_entry;
*/

/* File types */
pub const SC_FILE_TYPE_DF          : c_uint =  0x04;
pub const SC_FILE_TYPE_INTERNAL_EF : c_uint =  0x03;
pub const SC_FILE_TYPE_WORKING_EF  : c_uint =  0x01;
pub const SC_FILE_TYPE_BSO         : c_uint =  0x10;

/* EF structures */
pub const SC_FILE_EF_UNKNOWN             : c_uint =  0x00; // e.g. for MF, DF
pub const SC_FILE_EF_TRANSPARENT         : c_uint =  0x01;
pub const SC_FILE_EF_LINEAR_FIXED        : c_uint =  0x02;
pub const SC_FILE_EF_LINEAR_FIXED_TLV    : c_uint =  0x03;
pub const SC_FILE_EF_LINEAR_VARIABLE     : c_uint =  0x04;
pub const SC_FILE_EF_LINEAR_VARIABLE_TLV : c_uint =  0x05;
pub const SC_FILE_EF_CYCLIC              : c_uint =  0x06;
pub const SC_FILE_EF_CYCLIC_TLV          : c_uint =  0x07;

/* File status flags */
pub const SC_FILE_STATUS_ACTIVATED   : c_uint =  0x00;
pub const SC_FILE_STATUS_INVALIDATED : c_uint =  0x01;
pub const SC_FILE_STATUS_CREATION    : c_uint =  0x02; /* Full access in this state,
      (at least for SetCOS 4.4 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_file {
    pub path : sc_path ,
    pub name : [c_uchar; SC_MAX_AID_SIZE /*16usize*/], /* DF name */
    pub namelen : usize, /* length of DF name */

    pub type_        : c_uint, /* See constant values defined above */  // binding: name changed from type to type_
    pub ef_structure : c_uint, /* See constant values defined above */
    pub status       : c_uint, /* See constant values defined above */
    pub shareable    : c_uint, /* true(1), false(0) according to ISO 7816-4:2005 Table 14 */
    pub size         : usize,  /* Size of file (in bytes) */
    pub id           : c_int,  /* file identifier (2 bytes) */
    pub sid          : c_int,  /* short EF identifier (1 byte) */
    pub acl          : [*mut sc_acl_entry; SC_MAX_AC_OPS], /* Access Control List */

    #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
    pub record_length : c_int, /* In case of fixed-length or cyclic EF */
    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    pub record_length : usize, /* In case of fixed-length or cyclic EF */
    #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
    pub record_count  : c_int, /* Valid, if not transparent EF or DF */
    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    pub record_count  : usize, /* Valid, if not transparent EF or DF */

    pub sec_attr      : *mut c_uchar, /* security data in proprietary format. tag '86' */
    pub sec_attr_len  : usize,

    pub prop_attr     : *mut c_uchar, /* proprietary information. tag '85'*/
    pub prop_attr_len : usize,

    pub type_attr     : *mut c_uchar, /* file descriptor data. tag '82'.
        replaces the file's type information (DF, EF, ...) */
    pub type_attr_len : usize,

    pub encoded_content     : *mut c_uchar, /* file's content encoded to be used in the file creation command */
    pub encoded_content_len : usize, /* size of file's encoded content in bytes */

    pub magic : c_uint,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_file_t = sc_file;
*/
/*
#[cfg(impl_default)]
impl Default for sc_file {
    fn default() -> sc_file {
        sc_file {
            path: Default::default(),
            name: [0u8; SC_MAX_AID_SIZE],
            namelen: 0,
            type_: 0,
            ef_structure: 0,
            status: 0,
            shareable: 0,
            size: 0,
            id: 0,
            sid: 0,
            acl: [std::ptr::null_mut(); SC_MAX_AC_OPS],
            sec_attr: std::ptr::null_mut(),
            sec_attr_len: 0,
            prop_attr: std::ptr::null_mut(),
            prop_attr_len: 0,
            type_attr: std::ptr::null_mut(),
            type_attr_len: 0,
            encoded_content: std::ptr::null_mut(),
            encoded_content_len: 0,
            magic: 0x14426950
        }
    }
}
*/
/* Different APDU cases */
pub const SC_APDU_CASE_NONE    : c_int =  0x00;
pub const SC_APDU_CASE_1       : c_int =  0x01;
pub const SC_APDU_CASE_2_SHORT : c_int =  0x02;
pub const SC_APDU_CASE_3_SHORT : c_int =  0x03;
pub const SC_APDU_CASE_4_SHORT : c_int =  0x04;
pub const SC_APDU_SHORT_MASK   : c_int =  0x0f;
pub const SC_APDU_EXT          : c_int =  0x10;
pub const SC_APDU_CASE_2_EXT   : c_int =  SC_APDU_CASE_2_SHORT | SC_APDU_EXT;
pub const SC_APDU_CASE_3_EXT   : c_int =  SC_APDU_CASE_3_SHORT | SC_APDU_EXT;
pub const SC_APDU_CASE_4_EXT   : c_int =  SC_APDU_CASE_4_SHORT | SC_APDU_EXT;
/* following types let OpenSC decides whether to use short or extended APDUs */
pub const SC_APDU_CASE_2       : c_int =  0x22;
pub const SC_APDU_CASE_3       : c_int =  0x23;
pub const SC_APDU_CASE_4       : c_int =  0x24;

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

pub const SC_APDU_ALLOCATE_FLAG      : c_ulong =  0x01;
pub const SC_APDU_ALLOCATE_FLAG_DATA : c_ulong =  0x02;
pub const SC_APDU_ALLOCATE_FLAG_RESP : c_ulong =  0x04;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_apdu {
    pub cse : c_int,   /* APDU case */
    pub cla : c_uchar, /* CLA bytes */
    pub ins : c_uchar, /* INS bytes */
    pub p1  : c_uchar, /* P1 bytes */
    pub p2  : c_uchar, /* P2 bytes */
    pub lc : usize,   /* Lc bytes */
    pub le : usize,   /* Le bytes */
    pub data : *const c_uchar, /* S-APDU data */
    pub datalen : usize,   /* length of data in S-APDU */
    pub resp : *mut c_uchar,  /* R-APDU data buffer */
    pub resplen : usize,   /* in: size of R-APDU buffer,
                           * out: length of data returned in R-APDU */
    pub control : c_uchar,  /* Set if APDU should go to the reader */
    pub allocation_flags : c_uint, /* APDU allocation flags */

    pub sw1 : c_uint,  /* Status words returned in R-APDU */
    pub sw2 : c_uint,  /* Status words returned in R-APDU */
    pub mac : [c_uchar; 8usize],
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
    fn default() -> sc_apdu {
        sc_apdu {
            cse              :  0,
            cla              :  0,
            ins              :  0,
            p1               :  0,
            p2               :  0,
            lc               :  0,
            le               :  0,
            data             :  std::ptr::null(),
            datalen          :  0,
            resp             :  std::ptr::null_mut(),
            resplen          :  0,
            control          :  0,
            allocation_flags :  0,
            sw1              :  0,
            sw2              :  0,
            mac              :  [0; 8],
            mac_len          :  0,
            flags            :  0,
            next             :  std::ptr::null_mut(),
        }
    }
}

/* Card manager Production Life Cycle data (CPLC)
 * (from the Open Platform specification) */
pub const SC_CPLC_TAG      : c_uint   =  0x9F7F;
pub const SC_CPLC_DER_SIZE : usize = 45;

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_cplc {
    pub ic_fabricator : [c_uchar; 2usize],
    pub ic_type : [c_uchar; 2usize],
    pub os_data : [c_uchar; 6usize],
    pub ic_date : [c_uchar; 2usize],
    pub ic_serial : [c_uchar; 4usize],
    pub ic_batch_id : [c_uchar; 2usize],
    pub ic_module_data : [c_uchar; 4usize],
    pub icc_manufacturer : [c_uchar; 2usize],
    pub ic_embed_date : [c_uchar; 2usize],
    pub pre_perso_data : [c_uchar; 6usize],
    pub personalizer_data : [c_uchar; 6usize],

    pub value : [c_uchar; SC_CPLC_DER_SIZE],
    pub len : usize,
}


/* 'Issuer Identification Number' is a part of ISO/IEC 7812 PAN definition */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_iin {
    pub mii : c_uchar,              /* industry identifier */
    pub country : c_uint,           /* country identifier */
    pub issuer_id : c_ulong,        /* issuer identifier */
}

#[cfg(impl_default)]
impl Default for sc_iin {
    fn default() -> sc_iin {
        sc_iin {
            mii: 0,
            country: 0,
            issuer_id: 0
        }
    }
}

/* structure for the card serial number (normally the ICCSN) */
pub const SC_MAX_SERIALNR : usize = 32;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_serial_number {
    pub value : [c_uchar; SC_MAX_SERIALNR],
    pub len : usize,

    pub iin : sc_iin,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_serial_number_t = sc_serial_number;
*/

#[cfg(impl_default)]
impl Default for sc_serial_number {
    fn default() -> sc_serial_number {
        sc_serial_number {
            value: [0; SC_MAX_SERIALNR],
            len: 0,
            iin: Default::default()
        }
    }
}

/**
 * @struct sc_remote_apdu data
 * Structure to supply the linked APDU data used in
 * communication with the external (SM) modules.
 */
pub const SC_REMOTE_APDU_FLAG_NOT_FATAL     : c_uint   =  0x01;
pub const SC_REMOTE_APDU_FLAG_RETURN_ANSWER : c_uint   =  0x02;

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_remote_apdu {
    pub sbuf : [c_uchar; 2*SC_MAX_APDU_BUFFER_SIZE],
    pub rbuf : [c_uchar; 2*SC_MAX_APDU_BUFFER_SIZE],
    pub apdu : sc_apdu,

    pub flags : c_uint, /* e.g. SC_REMOTE_APDU_FLAG_RETURN_ANSWER */

    pub next : *mut sc_remote_apdu,
}

#[cfg(impl_default)]
impl Default for sc_remote_apdu {
    fn default() -> sc_remote_apdu {
        sc_remote_apdu {
            sbuf: [0; 2*SC_MAX_APDU_BUFFER_SIZE],
            rbuf: [0; 2*SC_MAX_APDU_BUFFER_SIZE],
            apdu: Default::default(),
            flags: 0,
            next: std::ptr::null_mut()
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
    pub length : c_int,

    /**
     * Handler to allocate a new @c sc_remote_apdu data and add it to the list.
     * @param rdata Self pointer to the @c sc_remote_data
     * @param out Pointer to newly allocated member
     */
    pub alloc : Option< unsafe extern "C" fn (rdata: *mut sc_remote_data,
                                              out: *mut *mut sc_remote_apdu) -> c_int >,
    /**
     * Handler to free the list of @c sc_remote_apdu data
     * @param rdata Self pointer to the @c sc_remote_data
     */
    pub free  : Option< unsafe extern "C" fn (rdata: *mut sc_remote_data) >,
}

#[cfg(impl_default)]
impl Default for sc_remote_data {
    fn default() -> sc_remote_data {
        sc_remote_data {
            data: std::ptr::null_mut(),
            length: 0,
            alloc: None,
            free: None
        }
    }
}
