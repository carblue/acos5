/*
 * Copyright (C) 2002-2014 Free Software Foundation, Inc.
 * Copyright (C) 2020-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * The file libtasn1.h this is derived from, is part of LIBTASN1.
 *
 * LIBTASN1 is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * LIBTASN1 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with LIBTASN1; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

//! Both driver components (libacos5.so/dll and libacos5_pkcs15.so/dll) share this same file

#![allow(dead_code, non_upper_case_globals/*, non_camel_case_types, non_snake_case*/)]

/**
 * `libtasn1:Short_Description`:
 *
 * GNU ASN.1 library
 */
/**
 * `libtasn1:Long_Description`:
 *
 * The Libtasn1 library provides Abstract Syntax Notation One (ASN.1, as
 * specified by the X.680 ITU-T recommendation) parsing and structures
 * management, and Distinguished Encoding Rules (DER, as per X.690)
 * encoding and decoding functions.
 */


/*
#ifndef ASN1_API
#if defined ASN1_BUILDING && defined HAVE_VISIBILITY && HAVE_VISIBILITY
#define ASN1_API __attribute__((__visibility__("default")))
#elif defined ASN1_BUILDING && defined _MSC_VER && ! defined ASN1_STATIC
#define ASN1_API __declspec(dllexport)
#elif defined _MSC_VER && ! defined ASN1_STATIC
#define ASN1_API __declspec(dllimport)
#else
#define ASN1_API
#endif
#endif

#ifdef __GNUC__
# define __LIBTASN1_CONST__  __attribute__((const))
# define __LIBTASN1_PURE__  __attribute__((pure))
#else
# define __LIBTASN1_CONST__
# define __LIBTASN1_PURE__
#endif

#include <sys/types.h>
#include <time.h>
#include <stdio.h>  /* for FILE* */

#ifdef __cplusplus
extern "C"
{
#endif
*/

use std::os::raw::{c_uchar, c_char, c_uint, c_int, c_ulong, c_long, c_void};
use std::ptr::null;

/**
 * `ASN1_VERSION`:
 *
 * Version of the library as a string.
 */
pub const ASN1_VERSION: &[u8; 7_usize] = b"4.16.0\0";

/**
 * `ASN1_VERSION_MAJOR`:
 *
 * Major version number of the library.
 */
pub const ASN1_VERSION_MAJOR: u32 = 4;

/**
 * `ASN1_VERSION_MINOR`:
 *
 * Minor version number of the library.
 */
pub const ASN1_VERSION_MINOR: u32 = 16;

/**
 * `ASN1_VERSION_PATCH`:
 *
 * Patch version number of the library.
 */
pub const ASN1_VERSION_PATCH: u32 = 0;

/**
 * `ASN1_VERSION_NUMBER`:
 *
 * Version number of the library as a number.
 */
pub const ASN1_VERSION_NUMBER: u32 = 0x0004_1000;


/*
#if defined __GNUC__ && !defined ASN1_INTERNAL_BUILD
# define _ASN1_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
# if _ASN1_GCC_VERSION >= 30100
#  define _ASN1_GCC_ATTR_DEPRECATED __attribute__ ((__deprecated__))
# endif
#endif

#ifndef _ASN1_GCC_ATTR_DEPRECATED
#define _ASN1_GCC_ATTR_DEPRECATED
#endif
*/

/*****************************************/
/* Errors returned by libtasn1 functions */
/*****************************************/
pub const ASN1_SUCCESS: u32 = 0;
pub const ASN1_FILE_NOT_FOUND: u32 = 1;
pub const ASN1_ELEMENT_NOT_FOUND: u32 = 2;
pub const ASN1_IDENTIFIER_NOT_FOUND: u32 = 3;
pub const ASN1_DER_ERROR: u32 = 4;
pub const ASN1_VALUE_NOT_FOUND: u32 = 5;
pub const ASN1_GENERIC_ERROR: u32 = 6;
pub const ASN1_VALUE_NOT_VALID: u32 = 7;
pub const ASN1_TAG_ERROR: u32 = 8;
pub const ASN1_TAG_IMPLICIT: u32 = 9;
pub const ASN1_ERROR_TYPE_ANY: u32 = 10;
pub const ASN1_SYNTAX_ERROR: u32 = 11;
pub const ASN1_MEM_ERROR: u32 = 12;
pub const ASN1_MEM_ALLOC_ERROR: u32 = 13;
pub const ASN1_DER_OVERFLOW: u32 = 14;
pub const ASN1_NAME_TOO_LONG: u32 = 15;
pub const ASN1_ARRAY_ERROR: u32 = 16;
pub const ASN1_ELEMENT_NOT_EMPTY: u32 = 17;
pub const ASN1_TIME_ENCODING_ERROR: u32 = 18;
pub const ASN1_RECURSION: u32 = 19;

/*************************************/
/* Constants used in asn1_visit_tree */
/*************************************/
pub const ASN1_PRINT_NAME: u32 = 1;
pub const ASN1_PRINT_NAME_TYPE: u32 = 2;
pub const ASN1_PRINT_NAME_TYPE_VALUE: u32 = 3;
pub const ASN1_PRINT_ALL: u32 = 4;

/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
pub const ASN1_CLASS_UNIVERSAL        : u32 = 0x00; /* old: 1 */
pub const ASN1_CLASS_APPLICATION      : u32 = 0x40; /* old: 2 */
pub const ASN1_CLASS_CONTEXT_SPECIFIC : u32 = 0x80; /* old: 3 */
pub const ASN1_CLASS_PRIVATE          : u32 = 0xC0; /* old: 4 */
pub const ASN1_CLASS_STRUCTURED       : u32 = 0x20;

/*****************************************/
/* Constants returned by asn1_read_tag   */
/*****************************************/
pub const ASN1_TAG_BOOLEAN          : u32 = 0x01;
pub const ASN1_TAG_INTEGER          : u32 = 0x02;
pub const ASN1_TAG_SEQUENCE         : u32 = 0x10;
pub const ASN1_TAG_SET              : u32 = 0x11;
pub const ASN1_TAG_OCTET_STRING     : u32 = 0x04;
pub const ASN1_TAG_BIT_STRING       : u32 = 0x03;
pub const ASN1_TAG_UTCTime          : u32 = 0x17;
pub const ASN1_TAG_GENERALIZEDTime  : u32 = 0x18;
pub const ASN1_TAG_OBJECT_ID        : u32 = 0x06;
pub const ASN1_TAG_ENUMERATED       : u32 = 0x0A;
pub const ASN1_TAG_NULL             : u32 = 0x05;
pub const ASN1_TAG_GENERALSTRING    : u32 = 0x1B;
pub const ASN1_TAG_NUMERIC_STRING   : u32 = 0x12;
pub const ASN1_TAG_IA5_STRING       : u32 = 0x16;
pub const ASN1_TAG_TELETEX_STRING   : u32 = 0x14;
pub const ASN1_TAG_PRINTABLE_STRING : u32 = 0x13;
pub const ASN1_TAG_UNIVERSAL_STRING : u32 = 0x1C;
pub const ASN1_TAG_BMP_STRING       : u32 = 0x1E;
pub const ASN1_TAG_UTF8_STRING      : u32 = 0x0C;
pub const ASN1_TAG_VISIBLE_STRING   : u32 = 0x1A;

/**
 * `asn1_node`:
 *
 * Structure definition used for the node of the tree
 * that represents an ASN.1 DEFINITION.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct asn1_node_st {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
pub type asn1_node = *mut asn1_node_st;
#[allow(non_camel_case_types)]
pub type asn1_node_const = *const asn1_node_st;

/**
 * `ASN1_MAX_NAME_SIZE`:
 *
 * Maximum number of characters of a name
 * inside a file with ASN1 definitions.
 */
pub const ASN1_MAX_NAME_SIZE: u32 = 64;


/**
 * `asn1_static_node`:
 * @name: Node name
 * @type: Node typ
 * @value: Node value
 *
 * For the on-disk format of ASN.1 trees, created by `asn1_parser2array()`.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct asn1_static_node_st {
    pub name: *const c_char, /* Node name */
    pub type_: c_uint, /* Node type */
    pub value: *const c_void, /* Node value */
}

impl asn1_static_node_st {
    pub fn new(name: &std::ffi::CStr, type_: c_uint, value: &std::ffi::CStr) -> Self {
        Self { name: name.as_ptr(), type_, value: value.as_ptr().cast::<c_void>() }
    }
    pub fn new_name_null(type_: c_uint, value: &std::ffi::CStr) -> Self {
        Self { name: null(), type_, value: value.as_ptr().cast::<c_void>() }
    }
    pub fn new_value_null(name: &std::ffi::CStr, type_: c_uint) -> Self {
        Self { name: name.as_ptr(), type_, value: null() }
    }
    pub fn new_name_value_null(type_: c_uint) -> Self {
        Self { name: null(), type_, value: null() }
    }
}

#[allow(non_camel_case_types)]
pub type asn1_static_node = asn1_static_node_st;

/* List of constants for field type of node_asn  */
pub const ASN1_ETYPE_INVALID: u32 = 0;
pub const ASN1_ETYPE_CONSTANT: u32 = 1;
pub const ASN1_ETYPE_IDENTIFIER: u32 = 2;
pub const ASN1_ETYPE_INTEGER: u32 = 3;
pub const ASN1_ETYPE_BOOLEAN: u32 = 4;
pub const ASN1_ETYPE_SEQUENCE: u32 = 5;
pub const ASN1_ETYPE_BIT_STRING: u32 = 6;
pub const ASN1_ETYPE_OCTET_STRING: u32 = 7;
pub const ASN1_ETYPE_TAG: u32 = 8;
pub const ASN1_ETYPE_DEFAULT: u32 = 9;
pub const ASN1_ETYPE_SIZE: u32 = 10;
pub const ASN1_ETYPE_SEQUENCE_OF: u32 = 11;
pub const ASN1_ETYPE_OBJECT_ID: u32 = 12;
pub const ASN1_ETYPE_ANY: u32 = 13;
pub const ASN1_ETYPE_SET: u32 = 14;
pub const ASN1_ETYPE_SET_OF: u32 = 15;
pub const ASN1_ETYPE_DEFINITIONS: u32 = 16;
pub const ASN1_ETYPE_CHOICE: u32 = 18;
pub const ASN1_ETYPE_IMPORTS: u32 = 19;
pub const ASN1_ETYPE_NULL: u32 = 20;
pub const ASN1_ETYPE_ENUMERATED: u32 = 21;
pub const ASN1_ETYPE_GENERALSTRING: u32 = 27;
pub const ASN1_ETYPE_NUMERIC_STRING: u32 = 28;
pub const ASN1_ETYPE_IA5_STRING: u32 = 29;
pub const ASN1_ETYPE_TELETEX_STRING: u32 = 30;
pub const ASN1_ETYPE_PRINTABLE_STRING: u32 = 31;
pub const ASN1_ETYPE_UNIVERSAL_STRING: u32 = 32;
pub const ASN1_ETYPE_BMP_STRING: u32 = 33;
pub const ASN1_ETYPE_UTF8_STRING: u32 = 34;
pub const ASN1_ETYPE_VISIBLE_STRING: u32 = 35;
pub const ASN1_ETYPE_UTC_TIME: u32 = 36;
pub const ASN1_ETYPE_GENERALIZED_TIME: u32 = 37;

/**
 * `ASN1_DELETE_FLAG_ZEROIZE`:
 *
 * Used by: `asn1_delete_structure2()`
 *
 * Zeroize values prior to deinitialization.
 */
pub const ASN1_DELETE_FLAG_ZEROIZE: u32 = 1;

/**
 * `ASN1_DECODE_FLAG_ALLOW_PADDING`:
 *
 * Used by: `asn1_der_decoding2()`
 *
 * This flag would allow arbitrary data past the DER data.
 */
pub const ASN1_DECODE_FLAG_ALLOW_PADDING: u32 = 1;
/**
 * `ASN1_DECODE_FLAG_STRICT_DER`:
 *
 * Used by: `asn1_der_decoding2()`
 *
 * This flag would ensure that no BER decoding takes place.
 */
pub const ASN1_DECODE_FLAG_STRICT_DER: u32 = 2;
/**
 * `ASN1_DECODE_FLAG_ALLOW_INCORRECT_TIME`:
 *
 * Used by: `asn1_der_decoding2()`
 *
 * This flag will tolerate Time encoding errors when in strict DER.
 */
pub const ASN1_DECODE_FLAG_ALLOW_INCORRECT_TIME: u32 = 4;


/**
 * `asn1_data_node_st`:
 * @name: Node name
 * @value: Node value
 * @`value_len`: Node value size
 * @type: Node value type (`ASN1_ETYPE`_*)
 *
 * Data node inside a #`asn1_node` structure.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct asn1_data_node_st {
    pub name: *const c_char, /* Node name */
    pub value: *const c_void, /* Node value */
    pub value_len: c_uint, /* Node value size */
    pub type_: c_uint, /* Node value type (ASN1_ETYPE_*) */
}

/***********************************/
/*  Fixed constants                */
/***********************************/

/**
 * `ASN1_MAX_ERROR_DESCRIPTION_SIZE`:
 *
 * Maximum number of characters
 * of a description message
 * (null character included).
 */
pub const ASN1_MAX_ERROR_DESCRIPTION_SIZE: u32 = 128;

/***********************************/
/*  Functions definitions          */
/***********************************/

extern "C" {
    pub fn asn1_parser2tree(
        file: *const c_char,
        definitions: *mut asn1_node,
        error_desc: *mut c_char
    ) -> c_int;

    pub fn asn1_parser2array(
        inputFileName: *const c_char,
        outputFileName: *const c_char,
        vectorName: *const c_char,
        error_desc: *mut c_char
    ) -> c_int;

    pub fn asn1_array2tree(
        array: *const asn1_static_node,
        definitions: *mut asn1_node,
        errorDescription: *mut c_char
    ) -> c_int;

    pub fn asn1_print_structure(
        out: *mut libc::FILE,
        structure: asn1_node_const,
        name: *const c_char,
        mode: c_int
    );

    pub fn asn1_create_element(
        definitions: asn1_node_const,
        source_name: *const c_char,
        element: *mut asn1_node
    ) -> c_int;

    pub fn asn1_delete_structure(structure: *mut asn1_node) -> c_int;

    pub fn asn1_delete_structure2(
        structure: *mut asn1_node,
        flags: c_uint
    ) -> c_int;

    pub fn asn1_delete_element(
        structure: asn1_node,
        element_name: *const c_char
    ) -> c_int;

    pub fn asn1_write_value(
        node_root: asn1_node,
        name: *const c_char,
        ivalue: *const c_void,
        len: c_int
    ) -> c_int;

    pub fn asn1_read_value(
        root: asn1_node_const,
        name: *const c_char,
        ivalue: *mut c_void,
        len: *mut c_int
    ) -> c_int;

    pub fn asn1_read_value_type(
        root: asn1_node_const,
        name: *const c_char,
        ivalue: *mut c_void,
        len: *mut c_int,
        etype: *mut c_uint
    ) -> c_int;

    pub fn asn1_read_node_value(
        node: asn1_node_const,
        data: *mut asn1_data_node_st
    ) -> c_int;

    pub fn asn1_number_of_elements(
        element: asn1_node_const,
        name: *const c_char,
        num: *mut c_int
    ) -> c_int;

    pub fn asn1_der_coding(
        element: asn1_node_const,
        name: *const c_char,
        ider: *mut c_void,
        len: *mut c_int,
        ErrorDescription: *mut c_char
    ) -> c_int;

    pub fn asn1_der_decoding2(
        element: *mut asn1_node,
        ider: *const c_void,
        max_ider_len: *mut c_int,
        flags: c_uint,
        errorDescription: *mut c_char
    ) -> c_int;

    pub fn asn1_der_decoding(
        element: *mut asn1_node,
        ider: *const c_void,
        ider_len: c_int,
        errorDescription: *mut c_char
    ) -> c_int;

    /* Do not use. Use asn1_der_decoding() instead. */
    #[deprecated(
    since = "1.4.16",
    note = "Please use the asn1_der_decoding function instead"
    )]
    pub fn asn1_der_decoding_element(
        structure: *mut asn1_node,
        elementName: *const c_char,
        ider: *const c_void,
        len: c_int,
        errorDescription: *mut c_char
    ) -> c_int;

    pub fn asn1_der_decoding_startEnd(
        element: asn1_node,
        ider: *const c_void,
        ider_len: c_int,
        name_element: *const c_char,
        start: *mut c_int,
        end: *mut c_int
    ) -> c_int;

    pub fn asn1_expand_any_defined_by(
        definitions: asn1_node_const,
        element: *mut asn1_node
    ) -> c_int;

    pub fn asn1_expand_octet_string(
        definitions: asn1_node_const,
        element: *mut asn1_node,
        octetName: *const c_char,
        objectName: *const c_char
    ) -> c_int;

    pub fn asn1_read_tag(
        root: asn1_node_const,
        name: *const c_char,
        tagValue: *mut c_int,
        classValue: *mut c_int
    ) -> c_int;

    pub fn asn1_find_structure_from_oid(
        definitions: asn1_node_const,
        oidValue: *const c_char
    ) -> *const c_char;

    // #[ffi_pure]
    pub fn asn1_check_version(
        req_version: *const c_char
    ) -> *const c_char;

    // #[ffi_pure]
    pub fn asn1_strerror(error: c_int) -> *const c_char;

    pub fn asn1_perror(error: c_int);
}

pub const ASN1_MAX_TAG_SIZE: u32 = 4;
pub const ASN1_MAX_LENGTH_SIZE: u32 = 9;
pub const ASN1_MAX_TL_SIZE: u32 = ASN1_MAX_TAG_SIZE+ASN1_MAX_LENGTH_SIZE;

extern "C" {
    pub fn asn1_get_length_der(
        der: *const c_uchar,
        der_len: c_int,
        len: *mut c_int
    ) -> c_long;

    pub fn asn1_get_length_ber(
        ber: *const c_uchar,
        ber_len: c_int,
        len: *mut c_int
    ) -> c_long;

    pub fn asn1_length_der(
        len: c_ulong,
        der: *mut c_uchar,
        der_len: *mut c_int
    );

/* Other utility functions. */

    pub fn asn1_decode_simple_der(
        etype: c_uint,
        der: *const c_uchar,
        _der_len: c_uint,
        str_: *mut *const c_uchar,
        str_len: *mut c_uint
    ) -> c_int;

    pub fn asn1_decode_simple_ber(
        etype: c_uint,
        der: *const c_uchar,
        _der_len: c_uint,
        str_: *mut *mut c_uchar,
        str_len: *mut c_uint,
        ber_len: *mut c_uint
    ) -> c_int;

    pub fn asn1_encode_simple_der(
        etype: c_uint,
        str_: *const c_uchar,
        str_len: c_uint,
        tl: *mut c_uchar,
        tl_len: *mut c_uint
    ) -> c_int;

    pub fn asn1_find_node(
        pointer: asn1_node_const,
        name: *const c_char
    ) -> asn1_node;

    pub fn asn1_copy_node(
        dst: asn1_node,
        dst_name: *const c_char,
        src: asn1_node_const,
        src_name: *const c_char
    ) -> c_int;

    pub fn asn1_dup_node(
        src: asn1_node_const,
        src_name: *const c_char
    ) -> asn1_node;

/* Internal and low-level DER utility functions. */

    pub fn asn1_get_tag_der(
        der: *const c_uchar,
        der_len: c_int,
        cls: *mut c_uchar,
        len: *mut c_int,
        tag: *mut c_ulong
    ) -> c_int;

    pub fn asn1_octet_der(
        str_: *const c_uchar,
        str_len: c_int,
        der: *mut c_uchar,
        der_len: *mut c_int
    );

    pub fn asn1_get_octet_der(
        der: *const c_uchar,
        der_len: c_int,
        ret_len: *mut c_int,
        str_: *mut c_uchar,
        str_size: c_int,
        str_len: *mut c_int
    ) -> c_int;

    pub fn asn1_bit_der(
        str_: *const c_uchar,
        bit_len: c_int,
        der: *mut c_uchar,
        der_len: *mut c_int
    );

    pub fn asn1_get_bit_der(
        der: *const c_uchar,
        der_len: c_int,
        ret_len: *mut c_int,
        str_: *mut c_uchar,
        str_size: c_int,
        bit_len: *mut c_int
    ) -> c_int;

    pub fn asn1_get_object_id_der(
        der: *const c_uchar,
        der_len: c_int,
        ret_len: *mut c_int,
        str_: *mut c_char,
        str_size: c_int
    ) -> c_int;

    fn asn1_object_id_der(
        str_: *const c_char,
        der: *mut c_uchar,
        der_len: *mut c_int,
        flags: c_uint
    ) -> c_int;
}

/* Compatibility types */
/*
/**
 * asn1_retCode:
 *
 * Type formerly returned by libtasn1 functions.
 *
 * Deprecated: 3.0: Use int instead.
 */
typedef int asn1_retCode;

/**
 * node_asn_struct:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
#define node_asn_struct asn1_node_st

/**
 * node_asn:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
#define node_asn asn1_node_st

/**
 * ASN1_TYPE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_node instead.
 */
#define ASN1_TYPE asn1_node

/**
 * ASN1_TYPE_EMPTY:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use NULL instead.
 */
#define ASN1_TYPE_EMPTY NULL

/**
 * static_struct_asn:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
#define static_struct_asn asn1_static_node_st

/**
 * ASN1_ARRAY_TYPE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
#define ASN1_ARRAY_TYPE asn1_static_node

/**
 * asn1_static_node_t:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_static_node instead.
 */
#define asn1_static_node_t asn1_static_node

/**
 * node_data_struct:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_data_node_st instead.
 */
#define node_data_struct asn1_data_node_st

/**
 * ASN1_DATA_NODE:
 *
 * Compat #define.
 *
 * Deprecated: 3.0: Use #asn1_data_node_st instead.
 */
#define ASN1_DATA_NODE asn1_data_node_st
*/
