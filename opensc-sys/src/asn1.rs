/*
 * asn1.h: ASN.1 header file
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

// Binding state: tabs: OKAY, header is OKAY (except pub const type checks), checkAPI15-19: OKAY, checkEXPORTS15-19: OKAY, compareD18-19: missing, doc: == tests,
// tests: test__sc_asn1_encode not ready, missing for  sc_asn1_sig_value_rs_to_sequence and  sc_asn1_sig_value_sequence_to_rs\
// TODO check IN, OUT etc., rename paramater names for a unified interface; #DEFINE/#UNDEF dependancy of struct size etc.: none: OKAY  (no direct (non-#include) #define influence on struct sizes)
// $ grep -rn 'sc_copy_asn1_entry\|sc_format_asn1_entry'

//! The API for ASN.1 functions is somewhat confusing at first glance, as there are several similar functions, thus some overview:
//! ( The functions that may or do C-allocate heap memory, are marked ** )
//!
//! 1. Basic sc_asn1_entry related functions:
//!    - sc_format_asn1_entry
//!    - sc_copy_asn1_entry
//!
//! 2. TLV related functions
//!    - sc_asn1_read_tag  is THE 'building block'/basic function of this group, that analyzes the TLV at current position,
//!        returns class, tag and tagLen information, also advancing the pointer to V of TLV. All the following use this one.
//!    - sc_asn1_find_tag  finds a given tag, advancing the pointer accordingly, or fails to find
//!    - sc_asn1_skip_tag  skips a given tag at current position, allowing access to both the skipped tag's V and the next TLV
//!    - sc_asn1_verify_tag  is almost the same as sc_asn1_skip_tag, just suppresses info about next TLV
//!
//!    - sc_asn1_put_tag  creates a single TLV byte sequence from it's input
//!    - sc_asn1_write_element     **  same as sc_asn1_put_tag, but get_s written to a malloc'ed buffer
//!    - sc_asn1_print_tags
//!
//! 3. Decoding functions: There are building block' functions, that decode DER data of known ASN.1 primitive type to corresponding C types directly,
//!    and the general decoding function _sc_asn1_decode ** (making use of former), that decodes to an  array of sc_asn1_entry:
//!
//!    Basic:
//!    - sc_asn1_decode_integer
//!    - sc_asn1_decode_bit_string     **
//!    - sc_asn1_decode_bit_string_ni  **
//!    - sc_asn1_decode_object_id
//!    - sc_asn1_decode_algorithm_id
//!
//!    2 more general decoding functions with similar interface and that call _sc_asn1_decode ** (allocates for
//!      SC_ASN1_OCTET_STRING, SC_ASN1_BIT_STRING, SC_ASN1_BIT_STRING_NI, SC_ASN1_GENERALIZEDTIME, SC_ASN1_UTF8STRING):
//!    - sc_asn1_decode_choice, calls with choice=1 and depth=0,  **
//!    - sc_asn1_decode,        calls with choice=0 and depth=0,  **
//!
//! 4. Encoding functions: Analogous to Decoding, there are building block' functions, that encode C types directly to DER data of known corresponding ASN.1 primitive type,
//!    and the general encoding function _sc_asn1_encode ** (making use of former), that encodes from an array of sc_asn1_entry\
//!    Most of the encoding functions do C-allocate heap memory:
//!
//!    Basic:
//!    - sc_asn1_encode_object_id     **
//!    - sc_asn1_encode_algorithm_id  **
//!
//!    1 more general decoding function with similar interface and that calls _sc_asn1_encode **:
//!    - sc_asn1_encode,        calls with depth=0,  **


use std::os::raw::{c_char, c_uint, c_int, c_void, c_uchar};
#[cfg(impl_default)]
use std::ptr::{null, null_mut};

use crate::opensc::{sc_context, sc_algorithm_id};
use crate::types::{sc_object_id};


#[repr(C)]
#[derive(Debug, Copy, Clone,  PartialEq)]
pub struct sc_asn1_entry {
    pub name  : *const c_char,
    pub type_ : c_uint,
    pub tag   : c_uint,
    pub flags : c_uint,
    pub parm  : *mut c_void,
    pub arg   : *mut c_void,
}

#[cfg(impl_default)]
impl Default for sc_asn1_entry {
    fn default() -> Self {
        Self {
            name :  null(),
            type_:  0,
            tag  :  0,
            flags:  0,
            parm :  null_mut(),
            arg  :  null_mut(),
        }
    }
}

/* //used internally by C code only
use crate::pkcs15::sc_pkcs15_object;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_asn1_pkcs15_object {
    pub p15_obj            : *mut sc_pkcs15_object,
    pub asn1_class_attr    : *mut sc_asn1_entry,
    pub asn1_subclass_attr : *mut sc_asn1_entry,
    pub asn1_type_attr     : *mut sc_asn1_entry,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_asn1_pkcs15_algorithm_info {
    pub id : c_int,
    pub oid : sc_object_id,
    pub decode : Option< unsafe extern "C" fn (arg1: *mut sc_context, arg2: *mut *mut c_void, arg3: *const c_uchar,
                                               arg4: usize, arg5: c_int) -> c_int >,
    pub encode : Option< unsafe extern "C" fn (arg1: *mut sc_context, arg2: *mut c_void, arg3: *mut *mut c_uchar,
                                               arg4: *mut usize, arg5: c_int) -> c_int >,
    pub free   : Option< unsafe extern "C" fn (arg1: *mut c_void) >,
}
*/


extern "C" {

/* Utility functions */

/// Sets some content of an sc_asn1_entry object (mostly used by functions, that parse PKCS#15 content)
///
/// @param  entry        INOUT  object to set (partially, not all fields will be set)\
/// @param  parm         INIF=  -> entry.parm; the lifetime of parm must outlive entry (if it's not NULL/&mut used)\
/// @param  arg          INIF=  -> entry.arg;  the lifetime of arg  must outlive entry (if it's not NULL/&mut used)\
/// @param  set_present  IN     if != 0, then -> entry.flags |= SC_ASN1_PRESENT;\
/// RUST USER The lifetimes (in comments) must be respected for pointers as if they were references\
/// RUST TODO check any C code usage of  *mut sc_asn1_entry, which may have received any kind of memory for fields parm
///   and arg, even NULL pointers; There now may be multiple aliases for the same mutable memory, thus make sure, that no double free occurs\
/// @test available
pub fn sc_format_asn1_entry/*<'a>*/(entry: /*'a*/ *mut sc_asn1_entry, parm: /*'a*/ *mut c_void, arg: /*'a*/ *mut c_void,
                                    set_present: c_int);

/// Copies all content of an array of sc_asn1_entry objects (shallow struct copy; mostly used by functions, that parse PKCS#15 content, with static lifetime @param src)
///
/// @param  src   IN   object to read from. src must be a pointer to an array of sc_asn1_entry and
///                    array's last element must have src.name==NULL, indicating the (to be excluded) terminating element.\
/// @param  dest  OUT  Receiving address for: object to write to. dest must be a pointer to an existing array of
///                    sc_asn1_entry and  must have at least the same number of array elements as src.\
/// WARNING: Violation of any of the @param requirements will corrupt memory and/or cause SIGSEGV\
/// RUST USER The lifetimes (in comments) must be respected for pointers as if they were references\
/// RUST TODO same as with sc_format_asn1_entry: check any C code usage of  *mut sc_asn1_entry, which may have received any kind of memory for fields parm
///   and arg, even NULL pointers; There now are multiple aliases for the same mutable memory, thus make sure, that no double free occurs\
/// @test available
pub fn sc_copy_asn1_entry/*<'a>*/(src: /*'a*/ *const sc_asn1_entry, dest: /*'a*/ *mut sc_asn1_entry);

/* DER tag and length parsing */

///XXX Decodes DER content from a c_uchar array and writes to an array of sc_asn1_entry objects
///
/// @param  ctx   INOUT  for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  asn1  INOUT  pointer to an existing array of sc_asn1_entry objects to set.
///                      Must be sufficiently sized to hold the data from in_/len to be decoded.\
///                      The type_, tag and flags fields must be set to guide decoding: There
///                      are const arrays predefined in several source code files that cover a
///                      lot of pkcs#15 structures, to look-up as a guide, see file PKCS#15_subset_supported_by_OpenSC.txt.\
///                      Only parm and arg fields will be set by this function, pointing to existing memory.
///                      On return, asn1 may be changed to point to another element of the sc_asn1_entry array !\
/// @param  in_   IN     c_uchar array to read DER encoded content from, must be positioned at T of TLV\
/// @param  len   IN     sizeof(in_) readable from in_ onwards\
/// @param  newp  OUTIF  Receiving address for: Position within in_ pointing right after the DER bytes decoded by the call\
/// @param  left  OUTIF  Receiving address for: Remainder of len readable from in_ beginning from *newp\
/// @return       SC_SUCCESS or error code\
/// RUST TODO heap memory allocated for parm and arg: take care, how they are used lateron, who/where to free them lateron, lifetime !\
/// @test available, included ih other test
/// For SC_ASN1_SE_INFO/TokenInfo's "seInfo  SEQUENCE OF SecurityEnvironmentInfo OPTIONAL,"  heap memory is involved
pub fn sc_asn1_decode       (ctx: *mut sc_context, asn1: *mut sc_asn1_entry,
                             in_: *const c_uchar, len: usize, newp: *mut *const c_uchar, left: *mut usize) -> c_int;

///XXX Decodes choice DER content from a c_uchar array and writes to an array of sc_asn1_entry objects
///
/// @param  ctx   INOUT  for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  asn1  INOUT  pointer to an existing array of sc_asn1_entry objects to set.
///                      Must be sufficiently sized to hold the data from in_/len to be decoded.\
///                      The type_, tag and flags fields must be set to guide decoding: There
///                      are const arrays predefined in several source code files that cover a
///                      lot of pkcs#15 structures, to look-up as a guide, see file PKCS#15_subset_supported_by_OpenSC.txt.\
///                      Only parm and arg fields will be set by this function, pointing to existing memory.
///                      On return, asn1 may be changed to point to another element of the sc_asn1_entry array !\
/// @param  in_   IN     c_uchar array to read DER encoded content from, must be positioned at T of TLV\
/// @param  len   IN     sizeof(in_) readable from in_ onwards\
/// @param  newp  OUTIF  Receiving address for: Position within in_ pointing right after the DER bytes decoded by the call\
/// @param  left  OUTIF  Receiving address for: Remainder of len readable from in_ beginning from *newp\
/// @return       SC_SUCCESS or error code\
/// RUST TODO heap memory allocated for parm and arg: take care, how they are used lateron, who/where to free them lateron, lifetime !
pub fn sc_asn1_decode_choice(ctx: *mut sc_context, asn1: *mut sc_asn1_entry,
                             in_: *const c_uchar, len: usize, newp: *mut *const c_uchar, left: *mut usize) -> c_int;

///XXX Undocumented, untested
/// uses heap allocation
pub fn sc_asn1_encode       (ctx: *mut sc_context, asn1: *const sc_asn1_entry,
                             buf: *mut *mut c_uchar, bufsize: *mut usize) -> c_int;

///XXX Decodes DER content from a c_uchar array and writes to an array of sc_asn1_entry objects, same as sc_asn1_decode,
/// but with 2 additional IN params choice, depth
///
/// @param  ctx     INOUT  for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  asn1    INOUT  pointer to an existing array of sc_asn1_entry objects to set.
///                        Must be sufficiently sized to hold the data from in_/len to be decoded.\
///                        The type_, tag and flags fields must be set to guide decoding: There
///                        are const arrays predefined in several source code files that cover a
///                        lot of pkcs#15 structures, to look-up as a guide, see file PKCS#15_subset_supported_by_OpenSC.txt.\
///                        Only parm and arg fields will be set by this function, pointing to existing memory.
///                        On return, asn1 may be changed to point to another element of the sc_asn1_entry array !\
/// @param  in_     IN     c_uchar array to read DER encoded content from, must be positioned at T of TLV\
/// @param  len     IN     sizeof(in_) readable from in_ onwards\
/// @param  newp    OUTIF  Receiving address for: Position within in_ pointing right after the DER bytes decoded by the call\
/// @param  left    OUTIF  Receiving address for: Remainder of len readable from in_ beginning from *newp\
/// @param  choice  IN     ?\
/// @param  depth   IN     ?\
/// @return         SC_SUCCESS or error code\
/// RUST TODO heap memory allocated for parm and arg: take care, how they are used lateron, who/where to free them lateron, lifetime !\
/// @test available
pub fn _sc_asn1_decode(ctx: *mut sc_context, asn1: *mut sc_asn1_entry,
           in_: *const c_uchar, len: usize, newp: *mut *const c_uchar, left: *mut usize,
           choice: c_int, depth: c_int) -> c_int;

///XXX Undocumented, untested
/// uses heap allocation
/// @test FAILURE
pub fn _sc_asn1_encode(ctx: *mut sc_context, asn1: *const sc_asn1_entry,
           ptr: *mut *mut c_uchar, size: *mut usize, depth: c_int) -> c_int;

/// Evaluates a TLV byte sequence, THE basic building block function
///
/// @param  buf      INOUT  Must point to a T of TLV; buf[0] get's evaluated for cla_out and tag_out,
///                         the next byte(s) for taglen. On success, buf is positioned at V[0] of TLV\
/// @param  buflen   IN     Number of bytes available in buf from position buf onwards\
/// @param  cla_out  OUT    Receiving address for: Class\
/// @param  tag_out  OUT    Receiving address for: Tag\
/// @param  taglen   OUT    Receiving address for: Number of bytes available in V\
/// @return          SC_SUCCESS or error code\
/// On error, buf may have been set to NULL, and (except on SC_ERROR_ASN1_END_OF_CONTENTS) no OUT param get's set\
/// OUT tag_out and taglen are guaranteed to have values set on SC_SUCCESS (cla_out only, if also (buf[0] != 0xff && buf[0] != 0))\
/// @test available
pub fn sc_asn1_read_tag(buf: *mut *const c_uchar, buflen: usize, cla_out: *mut c_uint,
                        tag_out: *mut c_uint, taglen: *mut usize) -> c_int;

/// Evaluates TLV byte sequences in order to find first occurence of tag
///
/// @param  ctx     INOUT  unused parameter\
/// @param  buf     IN     Must point to a T of TLV s; Beginning at buf[0] the first occurence of tag is searched\
/// @param  buflen  IN     Number of bytes available in buf from position buf onwards\
/// @param  tag     IN     Tag\
/// @param  taglen  OUT    Receiving address for: Number of bytes available in V for tag found\
/// @return         on success: a pointer to V[0] of TLV for tag found, on error: returns NULL and taglen is 0\
/// @test available
pub fn sc_asn1_find_tag(ctx: *mut sc_context, buf: *const c_uchar,
                        buflen: usize, tag: c_uint, taglen: *mut usize) -> *const c_uchar;

/// A wrapper for sc_asn1_skip_tag
///
/// @param  ctx     INOUT  for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  buf     IN     Must point to a T of TLV s\
/// @param  buflen  IN     sizeof(buf)\
/// @param  tag     IN     Tag to be skipped\
/// @param  taglen  OUT    Receiving address for: Number of bytes available in V of skipped tag; recommended to be initialized
///                        by the caller with 0, as the function omits initialization on error, or to be used only after error check\
/// @return         on success: a pointer to V[0] of TLV of skipped tag, on non-match: returns NULL\
pub fn sc_asn1_verify_tag (ctx: *mut sc_context, buf: *const c_uchar,
                           buflen: usize, tag: c_uint, taglen: *mut usize) -> *const c_uchar;

/// Evaluates a TLV byte sequence and if tag matches, positions buf to the next TLV
///
/// @param  ctx     INOUT  for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  buf     INOUT  IN: Must point to a T of TLV s; OUT: on success get's set to the beginning of next TLV\
/// @param  buflen  INOUT  IN: sizeof(buf); OUT: remaining from position buf onwards (if no error occurs)\
/// @param  tag     IN     Tag to be skipped\
/// @param  taglen  OUT    Receiving address for: Number of bytes available in V of skipped tag; recommended to be initialized
///                        by the caller with 0, as the function omits initialization on error, or to be used only after error check\
/// @return         on success: a pointer to V[0] of TLV of skipped tag, on non-match: returns NULL\
/// @test available
pub fn sc_asn1_skip_tag(ctx: *mut sc_context, buf : *mut *const c_uchar,
                        buflen: *mut usize, tag: c_uint, taglen: *mut usize) -> *const c_uchar;

/* DER encoding */

/// Writes a TL or TLV byte sequences
/// @param  tag      IN     Tag to be written\
/// @param  data     INIF   V to be written. If data is NULL or datalen is zero, then the data field will not be written.
///                         This is helpful for constructed structures.\
/// @param  datalen  IN     L (V's/data's length) to be written\
/// @param  out      OUTIF  if != NULL, the start address for: TLV bytes to be written; the underlying  buffer
///                         should  be sized sufficiently to receive the complete TLV\
///                         if == NULL or outlen==0, then @return will be the length of bytes that would be written;\
/// @param  outlen   IN     Number of bytes available within the underlying buffer of out to be written\
/// @param  ptr      OUTIF  Receiving address for: Pointer, pointing past TLV written, i.e. location of the next
///                         possible ASN.1 object\
/// @return          0 or (condition see @param out) the number of bytes that would be written\
/// @test available
pub fn sc_asn1_put_tag(tag: c_uint, data: *const c_uchar, datalen: usize, out: *mut c_uchar, outlen: usize,
                       ptr: *mut *mut c_uchar) -> c_int;

/* ASN.1 printing functions */

/// Prints DER data to stdout
///
/// @param  buf     IN  DER data array\
/// @param  buflen  IN  Length of DER data array\
/// @test available
pub fn sc_asn1_print_tags(buf: *const c_uchar, buflen: usize);

/* ASN.1 object decoding functions */

fn sc_asn1_utf8string_to_ascii(buf: *const c_uchar, buflen: usize, outbuf: *mut c_uchar, outlen: usize) -> c_int;

/// Decodes DER bit_string bytes to byte buffer
///
/// @param inbuf   IN  bit_string array, V of TLV\
/// @param inlen   IN  Length of bit_string array\
/// @param outbuf  OUT Start address of receiving buffer array\
/// @param outlen  IN  Length of receiving buffer array\
/// @return        Number of bits decoded (<=8*outlen)\
/// @test available
pub fn sc_asn1_decode_bit_string(inbuf: *const c_uchar, inlen: usize, outbuf: *mut c_void, outlen: usize) -> c_int;

/* non-inverting version */

/// Decodes bit_string bytes, non-inverting version
///
/// @param inbuf   IN  bit_string array, V of TLV\
/// @param inlen   IN  Length of bit_string array\
/// @param outbuf  OUT Start address of receiving buffer array\
/// @param outlen  IN  Length of receiving buffer array\
/// @return        Number of bits decoded (<=8*outlen)\
/// @test available
pub fn sc_asn1_decode_bit_string_ni(inbuf: *const c_uchar, inlen: usize, outbuf: *mut c_void, outlen: usize) -> c_int;

/// Decodes DER integer bytes (max 4) to c_int
///
/// @param inbuf   IN  points to V of TLV\
/// @param inlen   IN  L of TLV\
/// @param outbuf  OUT Receiving address for: Decoded c_int\
/// @return        SC_SUCCESS or error code\
/// @test available
pub fn sc_asn1_decode_integer(inbuf: *const c_uchar, inlen: usize, out: *mut c_int) -> c_int;

/// Decodes DER object_id bytes to sc_object_id
///
/// @param inbuf   IN  object_id array, V of TLV\
/// @param inlen   IN  Length of object_id array\
/// @param id      OUT Receiving sc_object_id\
/// @return        SC_SUCCESS or error code\
/// @test available
pub fn sc_asn1_decode_object_id(inbuf: *const c_uchar, inlen: usize, id: *mut sc_object_id) -> c_int;

/// Produces malloc'ed DER bytes from sc_object_id data
///
/// @param buf    INOUTIF\
/// @param buflen OUTIF\
/// @param id     IN\
/// @return\
/// @test available
pub fn sc_asn1_encode_object_id(buf: *mut *mut c_uchar, buflen: *mut usize, id: *const sc_object_id) -> c_int;

/* algorithm encoding/decoding  (implemented in pkcs15-algo.c) */

/// Decodes DER algorithm_id bytes to sc_algorithm_id
///
/// @param  ctx    INOUT for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  inbuf  IN    algorithm_id array, V of TLV\
/// @param  inlen  IN    Length of algorithm_id array\
/// @param  id     OUT   Receiving sc_algorithm_id\
/// @param  depth  IN\
/// @return        SC_SUCCESS or error code\
/// @test available
pub fn sc_asn1_decode_algorithm_id(ctx: *mut sc_context, inbuf: *const c_uchar, inlen: usize,
                                   id: *mut sc_algorithm_id, depth: c_int) -> c_int;

/// Produces malloc'ed DER bytes from sc_algorithm_id data
///
/// @param  ctx      INOUT for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  buf      OUTIF\
/// @param  buf_len  OUTIF\
/// @param  id       IN\
/// @param  depth    IN\
/// @return          SC_SUCCESS or error code\
/// @test available
pub fn sc_asn1_encode_algorithm_id(ctx: *mut sc_context, buf: *mut *mut c_uchar, buf_len: *mut usize,
                                   id: *const sc_algorithm_id, depth: c_int) -> c_int;

/// Clear sc_algorithm_id
///
/// @param  id  INOUT  sc_algorithm_id
pub fn sc_asn1_clear_algorithm_id(id: *mut sc_algorithm_id);

/* ASN.1 object encoding functions */

/// writes TLV to malloc'ed *out
///
/// @param  ctx      INOUT for logging only (On Linux it may be regarded as IN! + modifying internals of debug_file: *mut FILE)\
/// @param  tag      IN\
/// @param  data     IN\
/// @param  datalen  IN\
/// @param  out      OUTIF\
/// @param  outlen   OUTIF\
/// @return          SC_SUCCESS or error code\
/// @test available
pub fn sc_asn1_write_element(ctx: *mut sc_context, tag: c_uint, data : *const c_uchar, datalen: usize,
                             out: *mut *mut c_uchar, outlen: *mut usize) -> c_int;

/// Undocumented, untested
pub fn sc_asn1_sig_value_rs_to_sequence(ctx: *mut sc_context, in_: *mut c_uchar, inlen: usize,
                                        buf: *mut *mut c_uchar, buflen: *mut usize) -> c_int;

/// Undocumented, untested
#[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
pub fn sc_asn1_sig_value_sequence_to_rs(ctx: *mut sc_context, in_: *mut c_uchar, inlen: usize,
                                        buf: *mut c_uchar, buflen: usize) -> c_int;
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_asn1_sig_value_sequence_to_rs(ctx: *mut sc_context, in_: *const c_uchar, inlen: usize,
                                        buf: *mut c_uchar, buflen: usize) -> c_int;
} // extern "C"

pub const SC_ASN1_CLASS_MASK            : c_uint = 0x3000_0000;
pub const SC_ASN1_UNI                   : c_uint = 0x0000_0000; /* Universal */
pub const SC_ASN1_APP                   : c_uint = 0x1000_0000; /* Application */
pub const SC_ASN1_CTX                   : c_uint = 0x2000_0000; /* Context */
pub const SC_ASN1_PRV                   : c_uint = 0x3000_0000; /* Private */
pub const SC_ASN1_CONS                  : c_uint = 0x0100_0000;

pub const SC_ASN1_TAG_MASK              : c_uint = 0x00FF_FFFF;
pub const SC_ASN1_TAGNUM_SIZE           : usize = 3;

/* sc_asn1_entry.flags   SC_ASN1_PRESENT <-> SC_ASN1_EMPTY_ALLOWED */
pub const SC_ASN1_PRESENT               : c_uint = 0x0000_0001;
pub const SC_ASN1_OPTIONAL              : c_uint = 0x0000_0002;
pub const SC_ASN1_ALLOC                 : c_uint = 0x0000_0004;
pub const SC_ASN1_UNSIGNED              : c_uint = 0x0000_0008;
pub const SC_ASN1_EMPTY_ALLOWED         : c_uint = 0x0000_0010;

/* sc_asn1_entry.type_   SC_ASN1_BOOLEAN <-> SC_ASN1_CALLBACK */
pub const SC_ASN1_BOOLEAN               : c_uint = 1;
pub const SC_ASN1_INTEGER               : c_uint = 2;
pub const SC_ASN1_BIT_STRING            : c_uint = 3;
pub const SC_ASN1_BIT_STRING_NI         : c_uint = 128;
pub const SC_ASN1_OCTET_STRING          : c_uint = 4;
pub const SC_ASN1_NULL                  : c_uint = 5;
pub const SC_ASN1_OBJECT                : c_uint = 6;
pub const SC_ASN1_ENUMERATED            : c_uint = 10;
pub const SC_ASN1_UTF8STRING            : c_uint = 12;
pub const SC_ASN1_SEQUENCE              : c_uint = 16;
pub const SC_ASN1_SET                   : c_uint = 17;
pub const SC_ASN1_PRINTABLESTRING       : c_uint = 19;
pub const SC_ASN1_UTCTIME               : c_uint = 23;
pub const SC_ASN1_GENERALIZEDTIME       : c_uint = 24;

/* internal structures */
pub const SC_ASN1_STRUCT                : c_uint = 129;
pub const SC_ASN1_CHOICE                : c_uint = 130;
pub const SC_ASN1_BIT_FIELD             : c_uint = 131;    /* bit string as integer */

/* 'complex' structures */
pub const SC_ASN1_PATH                  : c_uint = 256;
pub const SC_ASN1_PKCS15_ID             : c_uint = 257;
pub const SC_ASN1_PKCS15_OBJECT         : c_uint = 258;
pub const SC_ASN1_ALGORITHM_ID          : c_uint = 259;
pub const SC_ASN1_SE_INFO               : c_uint = 260;

/* use callback function */
pub const SC_ASN1_CALLBACK              : c_uint = 384;

pub const SC_ASN1_TAG_CLASS             : c_uint = 0xC0;
pub const SC_ASN1_TAG_UNIVERSAL         : c_uint = 0x00;
pub const SC_ASN1_TAG_APPLICATION       : c_uint = 0x40;
pub const SC_ASN1_TAG_CONTEXT           : c_uint = 0x80;
pub const SC_ASN1_TAG_PRIVATE           : c_uint = 0xC0;

pub const SC_ASN1_TAG_CONSTRUCTED       : c_uint = 0x20;
pub const SC_ASN1_TAG_PRIMITIVE         : c_uint = 0x1F;

/* sc_asn1_entry.tag   SC_ASN1_TAG_EOC <-> SC_ASN1_TAG_ESCAPE_MARKER,   maybe bitOR'ed e.g. with */
pub const SC_ASN1_TAG_EOC               : c_uint = 0;
pub const SC_ASN1_TAG_BOOLEAN           : c_uint = 1;
pub const SC_ASN1_TAG_INTEGER           : c_uint = 2;
pub const SC_ASN1_TAG_BIT_STRING        : c_uint = 3;
pub const SC_ASN1_TAG_OCTET_STRING      : c_uint = 4;
pub const SC_ASN1_TAG_NULL              : c_uint = 5;
pub const SC_ASN1_TAG_OBJECT            : c_uint = 6;
pub const SC_ASN1_TAG_OBJECT_DESCRIPTOR : c_uint = 7;
pub const SC_ASN1_TAG_EXTERNAL          : c_uint = 8;
pub const SC_ASN1_TAG_REAL              : c_uint = 9;
pub const SC_ASN1_TAG_ENUMERATED        : c_uint = 10;
pub const SC_ASN1_TAG_UTF8STRING        : c_uint = 12;
pub const SC_ASN1_TAG_SEQUENCE          : c_uint = 16;
pub const SC_ASN1_TAG_SET               : c_uint = 17;
pub const SC_ASN1_TAG_NUMERICSTRING     : c_uint = 18;
pub const SC_ASN1_TAG_PRINTABLESTRING   : c_uint = 19;
pub const SC_ASN1_TAG_T61STRING         : c_uint = 20;
pub const SC_ASN1_TAG_TELETEXSTRING     : c_uint = 20;
pub const SC_ASN1_TAG_VIDEOTEXSTRING    : c_uint = 21;
pub const SC_ASN1_TAG_IA5STRING         : c_uint = 22;
pub const SC_ASN1_TAG_UTCTIME           : c_uint = 23;
pub const SC_ASN1_TAG_GENERALIZEDTIME   : c_uint = 24;
pub const SC_ASN1_TAG_GRAPHICSTRING     : c_uint = 25;
pub const SC_ASN1_TAG_ISO64STRING       : c_uint = 26;
pub const SC_ASN1_TAG_VISIBLESTRING     : c_uint = 26;
pub const SC_ASN1_TAG_GENERALSTRING     : c_uint = 27;
pub const SC_ASN1_TAG_UNIVERSALSTRING   : c_uint = 28;
pub const SC_ASN1_TAG_BMPSTRING         : c_uint = 30;
pub const SC_ASN1_TAG_ESCAPE_MARKER     : c_uint = 31;


#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr::{null, null_mut};
    use libc::free;
    use crate::errors::SC_SUCCESS;
    use crate::pkcs15::{sc_pkcs15_id, sc_pkcs15_pubkey_rsa/*, SC_PKCS15_MAX_ID_SIZE*/};
    use crate::opensc::SC_ALGORITHM_SHA1;
    use super::*;

    #[repr(C)]
    #[derive(/*Debug,*/ Copy, Clone)]
    struct State {
        state: c_int
    }

    #[test]
    fn test_sc_format_asn1_entry() {
        let mut entry = sc_asn1_entry { flags: 0x50, ..sc_asn1_entry::default() };
        let mut state = State { state: 20 };
        let state_ptr= &mut state as *mut _ as *mut c_void;
        let mut arg = 127i8;
        let arg_ptr  = &mut arg   as *mut _ as *mut c_void;

        unsafe { sc_format_asn1_entry(&mut entry, state_ptr, arg_ptr, 1); }
        assert_eq!(entry.flags, 0x51);
        let data_parm = unsafe { &*(entry.parm as *mut State) };
        let data_arg      = unsafe {  *(entry.arg  as *mut i8) };
        assert_eq!(data_parm.state, 20);
        assert_eq!(data_arg,        127);

        entry.flags = 0x50;
        unsafe { sc_format_asn1_entry(&mut entry, state_ptr, arg_ptr, 0); }
        assert_eq!(entry.flags, 0x50);
    }

    #[test]
    fn test_sc_copy_asn1_entry() {
        let mut state = State { state: 20 };
        let state_ptr = &mut state as *mut _ as *mut c_void;
        let mut arg = 127i8;
        let arg_ptr = &mut arg   as *mut _ as *mut c_void;

        let name1 = CStr::from_bytes_with_nul(b"name1\0").unwrap(); //.as_ptr();
        let name2 = CStr::from_bytes_with_nul(b"name2\0").unwrap(); //.as_ptr();

        let src = [
            sc_asn1_entry { name: name1.as_ptr(), flags: 0x50, parm: state_ptr, arg: arg_ptr, ..sc_asn1_entry::default() },
            sc_asn1_entry { name: name2.as_ptr(), flags: 0x60, parm: state_ptr, arg: arg_ptr, ..sc_asn1_entry::default() },
            sc_asn1_entry::default()
        ];
        let mut dest = [
            sc_asn1_entry::default(),
            sc_asn1_entry::default(),
            sc_asn1_entry::default()
        ];

        unsafe { sc_copy_asn1_entry(src.first().unwrap(), dest.first_mut().unwrap()); }
        assert_eq!( unsafe { CStr::from_ptr(dest[0].name) }, name1);
        assert_eq!(dest[0].flags, 0x50);
        assert_eq!( unsafe { CStr::from_ptr(dest[1].name) }, name2);
        assert_eq!(dest[1].flags, 0x60);
    }

    #[test]
    fn test_sc_pkcs15_decode_pubkey_rsa() {
        let public_key_coefficients = CStr::from_bytes_with_nul(b"publicKeyCoefficients\0").unwrap();
        let modulus = CStr::from_bytes_with_nul(b"modulus\0").unwrap();
        let exponent = CStr::from_bytes_with_nul(b"exponent\0").unwrap();

        let   c_asn1_public_key = [
            sc_asn1_entry { name: public_key_coefficients.as_ptr(), type_: SC_ASN1_STRUCT,
                tag: SC_ASN1_TAG_SEQUENCE | SC_ASN1_CONS/*, flags: 0*/, ..sc_asn1_entry::default() },
            sc_asn1_entry::default()
        ];
        let mut asn1_public_key = [sc_asn1_entry::default(); 2];
        unsafe { sc_copy_asn1_entry(c_asn1_public_key.first().unwrap(), asn1_public_key.first_mut().unwrap()) };

        let   c_asn1_rsa_pub_coefficients = [
            sc_asn1_entry { name: modulus.as_ptr(),  type_: SC_ASN1_OCTET_STRING, tag: SC_ASN1_TAG_INTEGER,
                flags: SC_ASN1_ALLOC | SC_ASN1_UNSIGNED, ..sc_asn1_entry::default() },
            sc_asn1_entry { name: exponent.as_ptr(), type_: SC_ASN1_OCTET_STRING, tag: SC_ASN1_TAG_INTEGER,
                flags: SC_ASN1_ALLOC | SC_ASN1_UNSIGNED, ..sc_asn1_entry::default() },
            sc_asn1_entry::default()
        ];
        let mut asn1_rsa_pub_coeff = [sc_asn1_entry::default(); 3];
        unsafe { sc_copy_asn1_entry(c_asn1_rsa_pub_coefficients.first().unwrap(),
                                     asn1_rsa_pub_coeff.first_mut().unwrap()) };
        ////////////////////////
        let mut ctx = sc_context::default();
        let mut newp= null();
        let mut left = 0;
        let buf : [c_uchar; 105] = [
            0x30, 0x67,
            0x02, 0x60,
            0x68
            , 0x29, 0xE6, 0xE2, 0xC1, 0xB4, 0x15, 0x8B, 0x66, 0x32, 0xA2, 0xEA, 0x61, 0xD1, 0x3E, 0x16, 0xAD
            , 0x10, 0xED, 0x4D, 0xA5, 0x93, 0x30, 0x61, 0x98, 0x3C, 0x8B, 0xFC, 0x16, 0x94, 0xD8, 0x4B, 0x14
            , 0x82, 0x07, 0xBE, 0x37, 0xF1, 0xBC, 0xB6, 0x28, 0x0C, 0x45, 0xD7, 0x7B, 0xF4, 0x12, 0x0E, 0x2A
            , 0x13, 0x53, 0x49, 0x1B, 0x35, 0x55, 0x46, 0x84, 0x6A, 0xD5, 0x36, 0xB2, 0xE8, 0x91, 0x74, 0x6C
            /*        … skipping 416 bytes …
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            //       , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            //       , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02

            //        … skipping 416 bytes … */
            , 0x7F, 0xB3, 0x00, 0xE8, 0x81, 0xC1, 0xA4, 0x09, 0x0C, 0xD3, 0xC5, 0x16, 0xE2, 0xBB, 0xDC, 0x02
            , 0x8D, 0x13, 0x91, 0x25, 0x3E, 0x97, 0x3E, 0xEA, 0x34, 0x1E, 0xCB, 0x83, 0xDC, 0x1C, 0xB5, 0x02
            , 0x03, 0x01, 0x00, 0x01
        ];
        unsafe { sc_format_asn1_entry(asn1_public_key.as_mut_ptr(), asn1_rsa_pub_coeff.as_mut_ptr() as *mut c_void,
                                      null_mut() as *mut c_void, 0) };

        let mut key = sc_pkcs15_pubkey_rsa::default();
        let key_modulus_parm_ptr : *mut c_void = &mut key.modulus.data  as *mut _ as *mut c_void;
        let key_modulus_arg_ptr  : *mut c_void = &mut key.modulus.len   as *mut _ as *mut c_void;
        let key_exponent_parm_ptr: *mut c_void = &mut key.exponent.data as *mut _ as *mut c_void;
        let key_exponent_arg_ptr : *mut c_void = &mut key.exponent.len  as *mut _ as *mut c_void;

        unsafe { sc_format_asn1_entry(asn1_rsa_pub_coeff.as_mut_ptr(),
                                      key_modulus_parm_ptr, key_modulus_arg_ptr, 0); }
        unsafe { sc_format_asn1_entry(asn1_rsa_pub_coeff.as_mut_ptr().offset(1),
                                      key_exponent_parm_ptr, key_exponent_arg_ptr, 0); }

        let rv = unsafe { sc_asn1_decode(&mut ctx, asn1_public_key.as_mut_ptr(), buf.as_ptr(), buf.len(),
                                              &mut newp, &mut left) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(key.modulus.len,  96);
        assert_eq!(key.exponent.len,  3);
    }

    #[test]
    fn test_sc_asn1_read_tag() {
        let file5031 : [c_uchar; 60] = [
            0xA8, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x11, 0xA0, 0x0A, 0x30, 0x08,
            0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x12, 0xA1, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00,
            0x41, 0x00, 0x41, 0x13, 0xA3, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x14,
            0xA4, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x15
        ];
        let mut buf : *const c_uchar = file5031.first().unwrap();
        let mut cla_out : c_uint = 0;
        let mut tag_out : c_uint = 0;
        let mut taglen  : usize  = 0;

        let rv = unsafe { sc_asn1_read_tag(&mut buf, file5031.len(), &mut cla_out, &mut tag_out, &mut taglen) };
        assert_eq!(rv, SC_SUCCESS);
//        println!("cla_out: {:X}, tag_out: {:X}, taglen: {}", cla_out, tag_out, taglen);
        assert_eq!(cla_out, 0xA0);
        assert_eq!(tag_out, 8);
        assert_eq!(taglen,  0x0A);
        assert!(!buf.is_null());
        let mut vec : Vec<c_uchar> = Vec::with_capacity(14);
        unsafe {
            let p : *const c_uchar = buf;
            for i in 0..14 {
                vec.push(*p.offset(i));
            }
        }
        // OCTET STRING (6 byte) 3F0041004111  within a sequence
        assert_eq!(vec, [/*0xA8, 0x0A,*/ 0x30,0x08,0x04,0x06,0x3F,0x00,0x41,0x00,0x41,0x11,0xA0,0x0A,0x30,0x08]);
    }

    #[test]
    fn test_sc_asn1_find_tag() {
        let mut ctx = sc_context::default();
        let file5031 : [c_uchar; 60] = [
            0xA8, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x11, 0xA0, 0x0A, 0x30, 0x08,
            0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x12, 0xA1, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00,
            0x41, 0x00, 0x41, 0x13, 0xA3, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x14,
            0xA4, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x15
        ];
        let buf : *const c_uchar = file5031.first().unwrap();
        let mut taglen  : usize  = 0;

        let rv : *const c_uchar = unsafe { sc_asn1_find_tag(&mut ctx, buf, file5031.len(), 0xA0, &mut taglen) };
        assert_eq!(taglen,  0x0A);
        assert!(!rv.is_null());
        let mut vec : Vec<c_uchar> = Vec::with_capacity(14);
        unsafe {
            let p : *const c_uchar = rv;
            for i in 0..14 {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec, [/*0xA0, 0x0A,*/ 0x30,0x08,0x04,0x06,0x3F,0x00,0x41,0x00,0x41,0x12,0xA1,0x0A,0x30,0x08]);

        taglen = 0;
        let rv : *const c_uchar = unsafe { sc_asn1_find_tag(&mut ctx, buf, file5031.len(), 0xA4, &mut taglen) };
        assert_eq!(taglen,  0x0A);
        assert!(!rv.is_null());
        let mut vec : Vec<c_uchar> = Vec::with_capacity(0x0A);
        unsafe {
            let p : *const c_uchar = rv;
            for i in 0..0x0A {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec,  [/* 0xA4, 0x0A,*/ 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x15]);
    }

    #[test]
    fn test_sc_asn1_skip_tag() {
        let mut ctx = sc_context::default();
        let file_prkdf : [c_uchar; 53] = [
            0x30, 0x31, 0x30, 0x0F, 0x0C, 0x06, 0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74, 0x03, 0x02, 0x06, 0xC0,
            0x04, 0x01, 0x01, 0x30, 0x0C, 0x04, 0x01, 0x03, 0x03, 0x03, 0x06, 0x20, 0x40, 0x03, 0x02, 0x03,
            0xB8, 0xA1, 0x10, 0x30, 0x0E, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0xF1, 0x02,
            0x02, 0x10, 0x00, 0xFF, 0xFF
        ];
        let mut buf : *const c_uchar = file_prkdf.first().unwrap();
        buf = unsafe { buf.offset(4) };
        let mut buflen : usize = file_prkdf.len() - 4;
        let mut taglen  : usize  = 0;
        let rv : *const c_uchar = unsafe { sc_asn1_skip_tag(&mut ctx, &mut buf, &mut buflen, 0x0C, &mut taglen) };
        assert!(!rv.is_null());
        assert_eq!(buflen, file_prkdf.len() - 4 - 8); // remaining len of buf for reading, skipping
        let mut vec : Vec<c_uchar> = Vec::with_capacity(7);
        unsafe {
            let p : *const c_uchar = buf;
            for i in 0..7 {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec,  [0x03, 0x02, 0x06, 0xC0, 0x04, 0x01, 0x01,]);
        assert_eq!(taglen, 6);
        let mut vec : Vec<c_uchar> = Vec::with_capacity(6);
        unsafe {
            let p : *const c_uchar = rv;
            for i in 0..6 {vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec,  [0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74]);
        ////
        let mut buf : *const c_uchar = file_prkdf.first().unwrap();
        let mut buflen : usize = file_prkdf.len();
        let mut taglen  : usize  = 0;
        let rv : *const c_uchar = unsafe { sc_asn1_skip_tag(&mut ctx, &mut buf, &mut buflen,
                                                            SC_ASN1_CONS | SC_ASN1_SEQUENCE, &mut taglen) };
        assert!(!rv.is_null());
        assert_eq!(buflen, 2); // remaining len of buf for reading, skipping
        let mut vec : Vec<c_uchar> = Vec::with_capacity(2);
        unsafe {
            let p : *const c_uchar = buf;
            for i in 0..2 {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec,  [0xFF, 0xFF]);
        assert_eq!(taglen, 0x31);
        let mut vec : Vec<c_uchar> = Vec::with_capacity(14);
        unsafe {
            let p : *const c_uchar = rv;
            for i in 0..14 {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec, [/*0x30, 0x31,*/ 0x30,0x0F,0x0C,0x06,0x43,0x41,0x72,0x6F,0x6F,0x74,0x03,0x02,0x06,0xC0]);
    }

    #[test]
    fn test_sc_asn1_decode_integer() {
        let integer_in : [c_uchar; 2] = [0x10, 0x00];
        let mut integer_out: c_int   = 0;
        let rv = unsafe { sc_asn1_decode_integer(integer_in.as_ptr(), integer_in.len(), &mut integer_out) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(integer_out, 4096);
    }

    #[test]
    fn test_sc_asn1_decode_bit_string2() {
        let array_in      : [c_uchar; 3] = [0x06, 0x20, 0x40];
        let mut array_out : [c_uchar; 2] = [0, 0];
        let rv = unsafe { sc_asn1_decode_bit_string(array_in.as_ptr(), array_in.len(),
                                                    array_out.as_mut_ptr() as *mut c_void, array_out.len()) };
        assert_eq!(rv, 10);
        assert!(rv as usize<=(array_in.len()-1)*8-array_in[0] as usize);
        assert_eq!(array_out, [4, 2]);
    }

    #[test]
    fn test_sc_asn1_decode_bit_string1() {
        let array_in      : [c_uchar; 2] = [0x06, 0xC0];
        let mut array_out : [c_uchar; 2] = [0, 0];
        let rv = unsafe { sc_asn1_decode_bit_string(array_in.as_ptr(), array_in.len(),
            array_out.as_mut_ptr() as *mut c_void, array_out.len()) };
        assert_eq!(rv, 2);
        assert!(rv as usize<=(array_in.len()-1)*8-array_in[0] as usize);
        assert_eq!(array_out, [3, 0]);
    }

    #[test]
    fn test_sc_asn1_decode_bit_string_ni() {
        let array_in      = [0x06, 0xC0];
        let mut array_out : [c_uchar; 2] = [0, 0];
        let rv = unsafe { sc_asn1_decode_bit_string_ni(array_in.as_ptr(), array_in.len(),
            array_out.as_mut_ptr() as *mut c_void, array_out.len()) };
        assert_eq!(rv, 2);
        assert!(rv as usize<=(array_in.len()-1)*8-array_in[0] as usize);
        assert_eq!(array_out, [0xC0, 0]);
    }

    #[test]
    fn test_sc_asn1_decode_object_id() {
        let array_in : [c_uchar; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let mut oid_out = sc_object_id::default();
        let     oid_exp = sc_object_id { value: [1, 2, 840, 113549, 1, 1, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1] };
        let rv = unsafe { sc_asn1_decode_object_id(array_in.as_ptr(), array_in.len(), &mut oid_out) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(oid_out, oid_exp);
    }

    #[test]
    fn test_sc_asn1_encode_object_id() {
        let der_exp = [0x2Au8, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let id = sc_object_id { value: [1, 2, 840, 113549, 1, 1, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1] };
        let mut buf_ptr = null_mut();
        let mut buf_len = 0usize;

        let rv = unsafe { sc_asn1_encode_object_id(&mut buf_ptr, &mut buf_len, &id) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(buf_len, 9);
        let mut vec : Vec<u8> = Vec::with_capacity(16);
        for i in 0..buf_len {
            vec.push( unsafe { *buf_ptr.add(i) } );
        }
        assert_eq!(vec.as_slice(), der_exp);
        unsafe { free(buf_ptr as *mut c_void) };
    }

    #[test]
    fn test_sc_asn1_decode_algorithm_id() {
        let mut ctx = sc_context::default();
        /*
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.2.840.113549.1.1.11 sha256WithRSAEncryption (PKCS #1)
            NULL
        */
        let in_ : [c_uchar; 13] = [/*30 0D*/ 0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,  0x05,0x00];
        let mut id = sc_algorithm_id::default();
        let rv = unsafe { sc_asn1_decode_algorithm_id(&mut ctx, in_.as_ptr(), in_.len(), &mut id, 0) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(id.algorithm, 0xFFFF_FFFF);
        assert_eq!(id.oid, sc_object_id { value: [1, 2, 840, 113549, 1, 1, 11, -1, -1, -1, -1, -1, -1, -1, -1, -1] });
        assert_eq!(id.params, null_mut());

        unsafe { sc_asn1_clear_algorithm_id(&mut id); }
        assert_eq!(id.params, null_mut());
    }

    #[test]
    fn test_sc_asn1_encode_algorithm_id() {
        let der_exp = [/*30 0C*/ 0x06u8, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07, 0x05, 0x00];
        let mut ctx = sc_context::default();
        let id = sc_algorithm_id { algorithm: SC_ALGORITHM_SHA1, ..sc_algorithm_id::default() };
        let mut buf_ptr : *mut c_uchar = null_mut();
        let mut buf_len = 0usize;

        let rv = unsafe { sc_asn1_encode_algorithm_id(&mut ctx, &mut buf_ptr, &mut buf_len, &id, 0) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(buf_len, 12);
        let mut vec : Vec<u8> = Vec::with_capacity(16);
        for i in 0..buf_len {
            vec.push( unsafe { *buf_ptr.add(i) } );
        }
        assert_eq!(vec.as_slice(), der_exp);
        unsafe { free(buf_ptr as *mut c_void) };
    }

    #[test]
    fn test_sc_asn1_print_tags() {
        let file_prkdf : [c_uchar; 51] = [
            0x30, 0x31, 0x30, 0x0F, 0x0C, 0x06, 0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74, 0x03, 0x02, 0x06, 0xC0,
            0x04, 0x01, 0x01, 0x30, 0x0C, 0x04, 0x01, 0x03, 0x03, 0x03, 0x06, 0x20, 0x40, 0x03, 0x02, 0x03,
            0xB8, 0xA1, 0x10, 0x30, 0x0E, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0xF1, 0x02,
            0x02, 0x10, 0x00
        ];
        unsafe { sc_asn1_print_tags(file_prkdf.as_ptr(), file_prkdf.len()) };
    }

    #[test]
    fn test_sc_asn1_put_tag() {
        let mut fci = [0x62u8, 0,  0,0,0,0,0xFF,0/*,0,0,0,0,0,0,0,0*/];
        let mut p = unsafe { fci.as_mut_ptr().add(2) };
        let data = [0x41, 0x11];
        let rv = unsafe { sc_asn1_put_tag(0x80, data.as_ptr(), data.len(), p, fci.len()-2, &mut p) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(fci, [0x62u8, 0,  0x80, 2, 0x41, 0x11, 0xFF,0/*,0,0,0,0,0,0,0,0*/]);
        assert_eq!(0xFF, unsafe { *p});
    }

    #[test]
    fn test_sc_asn1_write_element() {
        let mut ctx = sc_context::default();
        let mut p : *mut c_uchar = null_mut();//= buf.as_mut_ptr();
        let mut outlen = 0usize;
        let data = [0x01, 0x02, 0x03, 0x04];
        let rv = unsafe { sc_asn1_write_element(&mut ctx, 0x04, data.as_ptr(), data.len(), &mut p, &mut outlen) };
        let mut vec : Vec<u8> = Vec::with_capacity(10);
        assert_eq!(rv, SC_SUCCESS);
        for i in 0..outlen {
            vec.push( unsafe { *p.add(i) } );
        }
        assert_eq!(vec.as_slice(), [4u8, 4, 1, 2, 3, 4]);
        assert_eq!(outlen, 6);
        unsafe { free(p as *mut c_void) };
    }

    #[test]
    #[allow(non_snake_case)]
    fn test__sc_asn1_decode() {
        let mut  ctx = sc_context::default();
        let label  : &CStr = CStr::from_bytes_with_nul(b"label\0").unwrap();
        let flags  : &CStr = CStr::from_bytes_with_nul(b"flags\0").unwrap();
        #[allow(non_snake_case)]
        let authId : &CStr = CStr::from_bytes_with_nul(b"authId\0").unwrap(); // auth_id

        let mut label_parm : Vec<c_uchar> = Vec::with_capacity(7);
        for _i in 0..label_parm.capacity() {
            label_parm.push(0);
        }
//        label_parm[6] = 0xFF;
        let label_parm_ptr  = label_parm.as_mut_ptr();
        let label_arg : Box<usize>   = Box::new(label_parm.capacity());
        let label_arg_ptr = Box::into_raw(label_arg);

        let flags_parm : Box<usize>   = Box::new(0);
        let flags_parm_ptr = Box::into_raw(flags_parm);
        let flags_arg  : Box<usize>   = Box::new(4);
        let flags_arg_ptr  = Box::into_raw(flags_arg);

        #[allow(non_snake_case)]
        let auth_id_parm = Box::new(sc_pkcs15_id::default());
        let auth_id_parm_ptr = Box::into_raw(auth_id_parm);

        let asn1_array = &mut [
            sc_asn1_entry { name: label.as_ptr(),  type_: SC_ASN1_UTF8STRING, tag: SC_ASN1_TAG_UTF8STRING,
                flags: SC_ASN1_OPTIONAL,
                parm: label_parm_ptr as *mut c_void, arg: label_arg_ptr as *mut c_void, ..sc_asn1_entry::default() },
            sc_asn1_entry { name: flags.as_ptr(),  type_: SC_ASN1_BIT_FIELD,  tag: SC_ASN1_TAG_BIT_STRING,
                flags: SC_ASN1_OPTIONAL, parm: flags_parm_ptr   as *mut c_void, arg: flags_arg_ptr as *mut c_void },
            sc_asn1_entry { name: authId.as_ptr(), type_: SC_ASN1_PKCS15_ID,  tag: SC_ASN1_TAG_OCTET_STRING,
                flags: SC_ASN1_OPTIONAL, parm: auth_id_parm_ptr as *mut c_void, ..sc_asn1_entry::default() },
            sc_asn1_entry::default()
        ];
        let asn1 : *mut sc_asn1_entry = asn1_array.as_mut_ptr();
        let file_prkdf : [c_uchar; 51] = [
            0x30, 0x31, 0x30, 0x0F, 0x0C, 0x06, 0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74, 0x03, 0x02, 0x06, 0xC0,
            0x04, 0x01, 0x01, 0x30, 0x0C, 0x04, 0x01, 0x03, 0x03, 0x03, 0x06, 0x20, 0x40, 0x03, 0x02, 0x03,
            0xB8, 0xA1, 0x10, 0x30, 0x0E, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0xF1, 0x02,
            0x02, 0x10, 0x00
        ];

        let mut in_  : *const c_uchar = file_prkdf.as_ptr();
        in_ = unsafe { in_.offset(4) };
        let mut newp : *const c_uchar = null();
        let mut left : usize = 0;

        /* WARNING: asn1 may be changed to point to another element of asn1_array */
        let rv = unsafe { _sc_asn1_decode(&mut ctx, asn1, in_, file_prkdf.len()-4, &mut newp, &mut left, 0,0) };

        assert_eq!(rv,   SC_SUCCESS);
        assert_eq!(left, file_prkdf.len()-4 -15);
        let mut vec : Vec<c_uchar> = Vec::with_capacity(13);
        unsafe {
            let p : *const c_uchar = newp;
            for i in 0..13 {
                vec.push(*p.offset(i));
            }
        }
        assert_eq!(vec,  [0x30, 0x0C, 0x04, 0x01, 0x03, 0x03, 0x03, 0x06, 0x20, 0x40, 0x03, 0x02, 0x03]);
//        assert_eq!(*asn1, sc_asn1_entry { name: label.as_ptr(),  type_: SC_ASN1_UTF8STRING,
//            tag: SC_ASN1_TAG_UTF8STRING, flags: SC_ASN1_OPTIONAL | SC_ASN1_PRESENT, ..sc_asn1_entry::default() });

        assert_eq!(asn1_array[0].flags, SC_ASN1_OPTIONAL | SC_ASN1_PRESENT);
        let label_arg    = unsafe { Box::from_raw(label_arg_ptr) };
        assert_eq!(label_parm.as_slice(),  [0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74, 0]);
        assert_eq!(*label_arg,  7);

        assert_eq!(asn1_array[1].flags, SC_ASN1_OPTIONAL | SC_ASN1_PRESENT);
        let flags_parm = unsafe { Box::from_raw(flags_parm_ptr) };
        assert_eq!(*flags_parm, 3);
        let flags_arg    = unsafe { Box::from_raw(flags_arg_ptr) };
        assert_eq!(*flags_arg,  4);

        assert_eq!(asn1_array[2].flags, SC_ASN1_OPTIONAL | SC_ASN1_PRESENT);
        let auth_id_parm = unsafe { Box::from_raw(auth_id_parm_ptr) };
        assert_eq!(auth_id_parm.len,      1);
        assert_eq!(auth_id_parm.value[0], 1);
        assert_eq!(asn1_array[2].arg,   null_mut());
    }

    /// Undocumented, untested
    ///
    /// @param  ctx INOUT
    /// @param  asn1 IN
    /// @param  ptr
    /// @param  size
    /// @param  depth
//    pub fn _sc_asn1_encode(ctx: *mut sc_context, asn1: *const sc_asn1_entry,
//                           ptr: *mut *mut c_uchar, size: *mut usize, depth: c_int) -> c_int;
    #[test]
    #[allow(non_snake_case)]
    fn test__sc_asn1_encode() {
        let mut  ctx = sc_context::default();
        let label  : &CStr = CStr::from_bytes_with_nul(b"label\0").unwrap();
        let flags  : &CStr = CStr::from_bytes_with_nul(b"flags\0").unwrap();
        #[allow(non_snake_case)]
        let authId : &CStr = CStr::from_bytes_with_nul(b"authId\0").unwrap(); // auth_id

        let mut label_parm : Vec<c_uchar> = Vec::with_capacity(7);
        for _i in 0..label_parm.capacity() {
            label_parm.push(0);
        }
//        label_parm[6] = 0xFF;
        let label_parm_ptr  = label_parm.as_mut_ptr();
        let label_arg : Box<usize>   = Box::new(label_parm.capacity());
        let label_arg_ptr = Box::into_raw(label_arg);

        let flags_parm : Box<usize>   = Box::new(0);
        let flags_parm_ptr = Box::into_raw(flags_parm);
        let flags_arg  : Box<usize>   = Box::new(4);
        let flags_arg_ptr  = Box::into_raw(flags_arg);

        let auth_id_parm = Box::new(sc_pkcs15_id::default());
        let auth_id_parm_ptr = Box::into_raw(auth_id_parm);

        let asn1_array = &mut [
            sc_asn1_entry { name: label.as_ptr(),  type_: SC_ASN1_UTF8STRING, tag: SC_ASN1_TAG_UTF8STRING,
                flags: SC_ASN1_OPTIONAL,
                parm: label_parm_ptr as *mut c_void, arg: label_arg_ptr as *mut c_void, ..sc_asn1_entry::default() },
            sc_asn1_entry { name: flags.as_ptr(),  type_: SC_ASN1_BIT_FIELD,  tag: SC_ASN1_TAG_BIT_STRING,
                flags: SC_ASN1_OPTIONAL, parm: flags_parm_ptr   as *mut c_void, arg: flags_arg_ptr as *mut c_void },
            sc_asn1_entry { name: authId.as_ptr(), type_: SC_ASN1_PKCS15_ID,  tag: SC_ASN1_TAG_OCTET_STRING,
                flags: SC_ASN1_OPTIONAL, parm: auth_id_parm_ptr as *mut c_void, ..sc_asn1_entry::default() },
            sc_asn1_entry::default()
        ];

        let mut ptr : *mut c_uchar = null_mut();
        let mut size = 0usize;
        let rv = unsafe { _sc_asn1_encode(&mut ctx, asn1_array.as_ptr(), &mut ptr, &mut size, 0) };
        assert_eq!(rv,   SC_SUCCESS);
//        assert!(!ptr.is_null());
        if !ptr.is_null() {
            let mut vec : Vec<c_uchar> = Vec::with_capacity(size);
            unsafe {
                let p : *const c_uchar = ptr;
                for i in 0..size {
                    vec.push(*p.add(i));
                }
            }
            assert_eq!(vec.as_slice(), [0u8]);
        }
    }

    #[test]
    fn test_sc_der_copy() {
        use crate::pkcs15::{sc_der_copy, sc_pkcs15_der};
        let mut file_prkdf = [
            0x30, 0x31, 0x30, 0x0F, 0x0C, 0x06, 0x43, 0x41, 0x72, 0x6F, 0x6F, 0x74, 0x03, 0x02, 0x06, 0xC0,
            0x04, 0x01, 0x01, 0x30, 0x0C, 0x04, 0x01, 0x03, 0x03, 0x03, 0x06, 0x20, 0x40, 0x03, 0x02, 0x03,
            0xB8, 0xA1, 0x10, 0x30, 0x0E, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0xF1, 0x02,
            0x02, 0x10, 0x00
        ];
        let     pkcs15_der = sc_pkcs15_der { value: file_prkdf.as_mut_ptr(), len: file_prkdf.len() };
        let mut pkcs15_der_copied = sc_pkcs15_der::default();
        let rv = unsafe { sc_der_copy(&mut pkcs15_der_copied, &pkcs15_der) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(pkcs15_der.len,   pkcs15_der_copied.len);
        assert_eq!(0x30u8, unsafe { *pkcs15_der_copied.value });
        assert_eq!(0x10u8, unsafe { *pkcs15_der_copied.value.offset(49) });
        // malloc involved
        unsafe { free(pkcs15_der_copied.value as *mut c_void) };
    }
}
