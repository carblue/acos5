/*
 * Card profile information (internal)
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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

use std::os::raw::{c_char, c_void};
use crate::opensc::{sc_card, sc_app_info};
use crate::types::{sc_path, sc_file};
use crate::scconf::scconf_list;

use crate::pkcs15::{SC_PKCS15_DF_TYPE_COUNT, sc_pkcs15_card, sc_pkcs15_auth_info, sc_pkcs15_id};

use crate::pkcs15_init::sc_pkcs15init_operations;


//#define SC_PKCS15_PROFILE_SUFFIX    "profile"


/* Obsolete */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct auth_info {
    pub next : *mut auth_info,
    pub type_ : u32,        /* CHV, AUT, PRO */
    pub ref_ : u32,
    pub key_len : usize,
    pub key : [u8; 32],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct file_info {
    pub ident : *mut c_char,
    pub next : *mut file_info,
    pub file : *mut sc_file,
    pub dont_free : u32,
    pub parent : *mut file_info,

    /* Template support */
    pub instance : *mut file_info,
    pub base_template : *mut sc_profile,
    pub inst_index : u32,
    pub inst_path : sc_path,

    /* Profile extension dependent on the application ID (sub-profile).
     * Sub-profile is loaded when binding to the particular application
     * of the multi-application PKCS#15 card. */
    pub profile_extension : *mut c_char,
}

/* For now, we assume the PUK always resides
 * in the same file as the PIN
 */
#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct pin_info {
    pub id : i32,
    pub next : *mut pin_info,
    pub file_name : *mut c_char, /* obsolete */
    pub file_offset : u32, /* obsolete */
    pub file : *mut file_info, /* obsolete */

    pub pin : sc_pkcs15_auth_info,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_macro {
    pub name : *mut c_char,
    pub next : *mut sc_macro,
    pub value : *mut scconf_list,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_macro_t = sc_macro;
*/

/* Template support.
 *
 * Templates are EFs or entire hierarchies of DFs/EFs.
 * When instantiating a template, the file IDs of the
 * EFs and DFs are combined from the value given in the
 * profile, and the last octet of the pkcs15 ID.
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_template {
    pub name : *mut c_char,
    pub next : *mut sc_template,
    pub data : *mut sc_profile,
    pub file : *mut file_info,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_template_t = sc_template;
*/

pub const SC_PKCS15INIT_MAX_OPTIONS : usize = 16;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_profile__bindgen_ty_1 {
    pub direct_certificates : u32,
    pub encode_df_length : u32,
    pub do_last_update : u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_profile {
    pub name : *mut c_char,
    pub options : [*mut c_char; SC_PKCS15INIT_MAX_OPTIONS],

    pub card : *mut sc_card,
    pub driver : *mut c_char,
    pub ops : *mut sc_pkcs15init_operations,
    pub dll : *mut c_void , /* handle for dynamic modules */

    pub mf_info : *mut file_info,
    pub df_info : *mut file_info,
    pub ef_list : *mut file_info,
    pub df : [*mut sc_file; SC_PKCS15_DF_TYPE_COUNT],

    pub pin_list : *mut pin_info,
    pub auth_list : *mut auth_info,
    pub template_list : *mut sc_template,
    pub macro_list : *mut sc_macro,

    pub pin_domains : u32,
    pub pin_maxlen : u32,
    pub pin_minlen : u32,
    pub pin_pad_char : u32,
    pub pin_encoding : u32,
    pub pin_attempts : u32,
    pub puk_attempts : u32,
    pub rsa_access_flags : u32,
    #[cfg(any(v0_20_0, v0_21_0, v0_22_0))]
    pub dsa_access_flags : u32,

    pub pkcs15 : sc_profile__bindgen_ty_1,

    /* PKCS15 information */
    pub p15_spec : *mut sc_pkcs15_card, /* as given by profile */
    pub p15_data : *mut sc_pkcs15_card, /* as found on card */
    /* flag to indicate whether the TokenInfo::lastUpdate field
     * needs to be updated (in other words: if the card content
     * has been changed) */
    pub dirty : i32,

    /* PKCS15 object ID style */
    pub id_style : u32,

    /* Minidriver support style */
    pub md_style : u32,
}

extern "C" {
    fn sc_profile_new() -> *mut sc_profile;
    fn sc_profile_load(arg1: *mut sc_profile, arg2: *const c_char) -> i32;
    fn sc_profile_finish(arg1: *mut sc_profile, arg2: *const sc_app_info) -> i32;
    fn sc_profile_free(arg1: *mut sc_profile);
    fn sc_profile_build_pkcs15(arg1: *mut sc_profile) -> i32;
    fn sc_profile_get_pin_info(arg1: *mut sc_profile, arg2: i32, arg3: *mut sc_pkcs15_auth_info);
    fn sc_profile_get_pin_id(arg1: *mut sc_profile, arg2: u32, arg3: *mut i32) -> i32;
    fn sc_profile_get_file(arg1: *mut sc_profile, arg2: *const c_char, arg3: *mut *mut sc_file) -> i32;
    fn sc_profile_get_file_by_path(arg1 : *mut sc_profile, arg2: *const sc_path, arg3: *mut *mut sc_file) -> i32;
    fn sc_profile_get_path(arg1: *mut sc_profile, arg2: *const c_char, arg3: *mut sc_path) -> i32;
    fn sc_profile_get_file_in(arg1 : *mut sc_profile, arg2: *const sc_path, arg3: *const c_char, arg4: *mut *mut sc_file)
        -> i32;
    fn sc_profile_instantiate_template(arg1: *mut sc_profile, arg2: *const c_char, arg3: *const sc_path,
        arg4: *const c_char, arg5: *const sc_pkcs15_id, arg6: *mut *mut sc_file) -> i32;
    fn sc_profile_add_file(arg1: *mut sc_profile, arg2: *const c_char, arg3: *mut sc_file) -> i32;
    fn sc_profile_get_file_instance(arg1: *mut sc_profile, arg2: *const c_char, arg3: i32, arg4: *mut *mut sc_file)
        -> i32;
    fn sc_profile_get_pin_id_by_reference(arg1: *mut sc_profile, arg2: u32, arg3: i32,
        arg4: *mut sc_pkcs15_auth_info) -> i32;
    fn sc_profile_get_parent(profile: *mut sc_profile, arg1: *const c_char, arg2: *mut *mut sc_file) -> i32;
}
