/*
 * aux-data.h: Non PKCS#15, non ISO7816 data
 *             Used to pass auxiliary data from non PKCS#15, non ISO7816 applications (like minidriver)
 *             to card specific part through the standard PKCS#15 and ISO7816 frameworks
 *
 * Copyright (C) 2016  Viktor Tarasov <viktor.tarasov@gmail.com>
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

use std::os::raw::c_char;

use crate::opensc::sc_context;

pub const SC_AUX_DATA_TYPE_NO_DATA        : u32 = 0x00;
pub const SC_AUX_DATA_TYPE_MD_CMAP_RECORD : u32 = 0x01;

/* From Windows Smart Card Minidriver Specification
 * Version 7.06
 *
 * #define MAX_CONTAINER_NAME_LEN       39
 * #define CONTAINER_MAP_VALID_CONTAINER        1
 * #define CONTAINER_MAP_DEFAULT_CONTAINER      2
 * typedef struct _CONTAINER_MAP_RECORD
 * {
 *      WCHAR wszGuid [MAX_CONTAINER_NAME_LEN + 1];
 *      BYTE bFlags;
 *      BYTE bReserved;
 *      WORD wSigKeySizeBits;
 *      WORD wKeyExchangeKeySizeBits;
 * } CONTAINER_MAP_RECORD, *PCONTAINER_MAP_RECORD;
 */
pub const SC_MD_MAX_CONTAINER_NAME_LEN          : usize   = 39;
pub const SC_MD_CONTAINER_MAP_VALID_CONTAINER   : u8 = 0x01;
pub const SC_MD_CONTAINER_MAP_DEFAULT_CONTAINER : u8 = 0x02;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_md_cmap_record {
    pub guid : [u8; SC_MD_MAX_CONTAINER_NAME_LEN + 1],
    pub guid_len : usize,
    pub flags : u32,
    pub keysize_sign : u32,
    pub keysize_keyexchange : u32,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_auxiliary_data__bindgen_ty_1 {
    pub cmap_record : sc_md_cmap_record,
//    _bindgen_union_align : [u64; 8usize],
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_auxiliary_data {
    pub type_ : u32,
    pub data : sc_auxiliary_data__bindgen_ty_1,
}

extern "C" {
pub fn sc_aux_data_set_md_flags(arg1: *mut sc_context, arg2: *mut sc_auxiliary_data, arg3: u8) -> i32;
pub fn sc_aux_data_allocate(arg1: *mut sc_context, arg2: *mut *mut sc_auxiliary_data,
                            arg3: *mut sc_auxiliary_data) -> i32;
pub fn sc_aux_data_set_md_guid(arg1: *mut sc_context, arg2: *mut sc_auxiliary_data, arg3: *mut c_char) -> i32;
pub fn sc_aux_data_free(arg1: *mut *mut sc_auxiliary_data);
pub fn sc_aux_data_get_md_guid(arg1: *mut sc_context, arg2: *mut sc_auxiliary_data, arg3: u32, arg4: *mut u8,
                               arg5: *mut usize) -> i32;
fn sc_aux_data_get_md_flags(arg1: *mut sc_context, arg2: *mut sc_auxiliary_data, arg3: *mut u8) -> i32;
}
