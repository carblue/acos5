/*
 * Function prototypes for pkcs15-init
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

use std::os::raw::{c_char, c_ulong, c_void};
use crate::opensc::{sc_card, sc_app_info};
use crate::types::{sc_file, sc_path, sc_aid, sc_object_id};
use crate::pkcs15::{sc_pkcs15_card, sc_pkcs15_id, sc_pkcs15_auth_info, sc_pkcs15_prkey_info,
                    sc_pkcs15_object, sc_pkcs15_prkey, sc_pkcs15_pubkey, sc_pkcs15_prkey_rsa,
                    sc_pkcs15_tokeninfo, sc_pkcs15_der, sc_pkcs15_skey, sc_pkcs15_df};
use crate::profile::sc_profile;

/*
pub const DEFAULT_PRIVATE_KEY_LABEL "Private Key"
pub const DEFAULT_SECRET_KEY_LABEL  "Secret Key"
*/
pub const SC_PKCS15INIT_X509_DIGITAL_SIGNATURE : u32 =    0x0080;
pub const SC_PKCS15INIT_X509_NON_REPUDIATION   : u32 =    0x0040;
pub const SC_PKCS15INIT_X509_KEY_ENCIPHERMENT  : u32 =    0x0020;
pub const SC_PKCS15INIT_X509_DATA_ENCIPHERMENT : u32 =    0x0010;
pub const SC_PKCS15INIT_X509_KEY_AGREEMENT     : u32 =    0x0008;
pub const SC_PKCS15INIT_X509_KEY_CERT_SIGN     : u32 =    0x0004;
pub const SC_PKCS15INIT_X509_CRL_SIGN          : u32 =    0x0002;

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_profile_t = sc_profile; /* opaque type */
*/


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_operations {
    /*
     * Erase everything that's on the card
     */
    pub erase_card : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> i32 >,

    /*
     * New style API
     */

    /*
     * Card-specific initialization of PKCS15 meta-information.
     * Currently used by the cflex driver to read the card's
     * serial number and use it as the pkcs15 serial number.
     */
    pub init_card  : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> i32 >,

    /*
     * Create a DF
     */
    pub create_dir : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                   file: *mut sc_file) -> i32 >,
    /*
     * Create a "pin domain". This is for cards such as
     * the cryptoflex that need to put their pins into
     * separate directories
     */
    pub create_domain : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                      id: *const sc_pkcs15_id, file: *mut *mut sc_file) -> i32 >,

    /*
     * Select a PIN reference
     */
    pub select_pin_reference : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                             pin_ainfo: *mut sc_pkcs15_auth_info) -> i32 >,

    /*
     * Create a PIN object within the given DF.
     *
     * The pin_info object is completely filled in by the caller.
     * The card driver can reject the pin reference; in this case
     * the caller needs to adjust it.
     */
    pub create_pin : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,file:*mut sc_file,
                                                   object: *mut sc_pkcs15_object, arg5: *const u8, arg6: usize,
                                                   arg7: *const u8, arg8: usize) -> i32 >,

    /*
     * Select a reference for a private key object
     */
    pub select_key_reference : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                             arg3: *mut sc_pkcs15_prkey_info) -> i32 >,

    /*
     * Create an empty key object. (acos5_64: don't use this for symmetric keys)
     * @apiNote  Called only from src/pkcs15init/pkcs15-lib.c: 4 "master" functions call it immediately before
     *           these possible "master" operations:
     *           generate_key ("driving/master function": sc_pkcs15init_generate_key)  MUST create 2 files (also the public one)
     *           generate_key ("driving/master function": sc_pkcs15init_generate_secret_key)
     *           store_key    ("driving/master function": sc_pkcs15init_store_private_key)
     *           store_key    ("driving/master function": sc_pkcs15init_store_secret_key)
     *
     *           Thus it's possible that this may be a noop and the relevant code included in "master" operation
     */
    pub create_key : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                   object: *mut sc_pkcs15_object) -> i32 >,

    /*
     * Store (any kind of) key on the card
     */
    pub store_key : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                  object: *mut sc_pkcs15_object, key: *mut sc_pkcs15_prkey) -> i32 >,

    /*
     * Generate key
     * @apiNote  The "driving function" for this is: src/pkcs15init/pkcs15-lib.c:sc_pkcs15init_generate_key(arguments)
     */
    pub generate_key : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                     object: *mut sc_pkcs15_object, arg4: *mut sc_pkcs15_pubkey) -> i32 >,

    /*
     * Encode private/public key
     * These are used mostly by the Cryptoflex/Cyberflex drivers.
     */
    pub encode_private_key : Option< unsafe extern "C" fn (profile: *mut sc_profile, arg2: *mut sc_card,
                                                           arg3: *mut sc_pkcs15_prkey_rsa, arg4: *mut u8,
                                                           arg5: *mut usize, arg6: i32) -> i32 >,

    pub encode_public_key :  Option< unsafe extern "C" fn (profile: *mut sc_profile, arg2: *mut sc_card,
                                                           arg3: *mut sc_pkcs15_prkey_rsa, arg4: *mut u8,
                                                           arg5: *mut usize, arg6: i32) -> i32 >,

    /*
     * Finalize card
     * Ends the initialization phase of the smart card/token
     * (actually this command is currently only for starcos spk 2.3
     * cards).
     */
    pub finalize_card : Option< unsafe extern "C" fn (card: *mut sc_card) -> i32 >,

    /*
     * Delete object
     */
    pub delete_object : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                      object: *mut sc_pkcs15_object, path: *const sc_path) -> i32 >,

    /*
     * Support of pkcs15init emulation
     */
    pub emu_update_dir : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                       arg3: *mut sc_app_info) -> i32 >,

    pub emu_update_any_df : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                          op: u32, object: *mut sc_pkcs15_object) -> i32 >,

    pub emu_update_tokeninfo : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                             arg3: *mut sc_pkcs15_tokeninfo) -> i32 >,

    pub emu_write_info : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                       object: *mut sc_pkcs15_object) -> i32 >,

    pub emu_store_data : Option< unsafe extern "C" fn (p15card: *mut sc_pkcs15_card, profile: *mut sc_profile,
                                                       object: *mut sc_pkcs15_object, arg4: *mut sc_pkcs15_der,
                                                       path: *mut sc_path) -> i32 >,

    pub sanity_check : Option< unsafe extern "C" fn (profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> i32 >,
}


/* Do not change these or reorder these */
pub const SC_PKCS15INIT_ID_STYLE_NATIVE  : u32 = 0;
pub const SC_PKCS15INIT_ID_STYLE_MOZILLA : u32 = 1;
pub const SC_PKCS15INIT_ID_STYLE_RFC2459 : u32 = 2;

pub const SC_PKCS15INIT_SO_PIN    : u32 = 0;
pub const SC_PKCS15INIT_SO_PUK    : u32 = 1;
pub const SC_PKCS15INIT_USER_PIN  : u32 = 2;
pub const SC_PKCS15INIT_USER_PUK  : u32 = 3;
pub const SC_PKCS15INIT_NPINS     : u32 = 4;

pub const SC_PKCS15INIT_MD_STYLE_NONE     : u32 = 0;
pub const SC_PKCS15INIT_MD_STYLE_GEMALTO  : u32 = 1;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_callbacks {
    /*
     * Get a PIN from the front-end. The first argument is
     * one of the SC_PKCS15INIT_XXX_PIN/PUK macros.
     */
    pub get_pin : Option < unsafe extern "C" fn (arg1: *mut sc_profile, arg2: i32, arg3: *const sc_pkcs15_auth_info,
                                                 arg4: *const c_char, arg5: *mut u8, arg6: *mut usize) -> i32 >,

    /*
     * Get a transport/secure messaging key from the front-end.
     */
    pub get_key : Option < unsafe extern "C" fn (arg1: *mut sc_profile, arg2: i32, arg3: i32, arg4: *const u8,
                                                 arg5: usize, arg6: *mut u8, arg7: *mut usize) -> i32 >,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_initargs {
    pub so_pin : *const u8,
    pub so_pin_len : usize,
    pub so_puk : *const u8,
    pub so_puk_len : usize,
    pub so_pin_label : *const c_char,
    pub label : *const c_char,
    pub serial : *const c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_pinargs {
    pub auth_id : sc_pkcs15_id,
    pub label : *const c_char,
    pub pin : *const u8,
    pub pin_len : usize,

    pub puk_id : sc_pkcs15_id,
    pub puk_label : *const c_char,
    pub puk : *const u8,
    pub puk_len : usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_keyarg_gost_params {
    pub gostr3410 : u8,
    pub gostr3411 : u8,
    pub gost28147 : u8,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_pkcs15init_prkeyargs__bindgen_ty_1 {
    pub gost : sc_pkcs15init_keyarg_gost_params,
//    _bindgen_union_align : [ u8 ; 3usize ],
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15init_prkeyargs {
    /* TODO: member for private key algorithm: currently is used algorithm from 'key' member */
    pub id : sc_pkcs15_id,
    pub auth_id : sc_pkcs15_id,
    pub label : *mut c_char,
    pub guid : *mut u8,
    pub guid_len : usize,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub usage : c_ulong,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub usage : u32,
    pub x509_usage : c_ulong,
    pub flags : u32,
    pub access_flags : u32,
    pub user_consent : i32,

    pub params : sc_pkcs15init_prkeyargs__bindgen_ty_1,

    pub key : sc_pkcs15_prkey,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15init_keygen_args {
    pub prkey_args : sc_pkcs15init_prkeyargs,
    pub pubkey_label : *const c_char,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union sc_pkcs15init_pubkeyargs__bindgen_ty_1 {
    pub gost : sc_pkcs15init_keyarg_gost_params,
//    _bindgen_union_align : [ u8 ; 3usize ] ,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct sc_pkcs15init_pubkeyargs {
    pub id : sc_pkcs15_id,
    pub auth_id : sc_pkcs15_id,
    pub label : *const c_char,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub usage : c_ulong,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub usage : u32,
    pub x509_usage : c_ulong,

    pub params : sc_pkcs15init_pubkeyargs__bindgen_ty_1,

    pub key : sc_pkcs15_pubkey,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_dataargs {
    pub id : sc_pkcs15_id,
    pub label : *const c_char,
    pub auth_id : sc_pkcs15_id,
    pub app_label : *const c_char,
    pub app_oid : sc_object_id,

    pub der_encoded : sc_pkcs15_der, /* Wrong name: is not DER encoded */
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_skeyargs {
    pub id : sc_pkcs15_id,
    pub auth_id : sc_pkcs15_id,
    pub label : *const c_char,
    #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
    pub usage : c_ulong,
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    pub usage : u32,
    pub flags : u32,
    pub access_flags : u32,
    pub algorithm : c_ulong, /* User requested algorithm */
    pub value_len : c_ulong, /* User requested length */
    pub session_object : i32, /* If nonzero. this is a session object, which will
                                   be cleared from card when the session is closed.*/
    pub user_consent : i32,
    pub key : sc_pkcs15_skey,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_pkcs15init_certargs {
    pub id : sc_pkcs15_id,
    pub label : *const c_char,
    pub update : i32,

    pub x509_usage : c_ulong,
    pub authority : u8,
    pub der_encoded : sc_pkcs15_der,
}

pub const P15_ATTR_TYPE_LABEL : u32 =  0;
pub const P15_ATTR_TYPE_ID    : u32 =  1;
pub const P15_ATTR_TYPE_VALUE : u32 =  2; // since v0_20_0


extern "C" {
fn sc_pkcs15init_new_object(arg1: i32, arg2: *const c_char, arg3: *mut sc_pkcs15_id, arg4: *mut c_void)
    -> *mut sc_pkcs15_object;

fn sc_pkcs15init_free_object(arg1: *mut sc_pkcs15_object);

pub fn sc_pkcs15init_set_callbacks(arg1: *mut sc_pkcs15init_callbacks);

pub fn sc_pkcs15init_bind(arg1: *mut sc_card, arg2: *const c_char, arg3: *const c_char, app_info: *mut sc_app_info, arg4: *mut *mut sc_profile) -> i32;

pub fn sc_pkcs15init_unbind(arg1: *mut sc_profile);

pub fn sc_pkcs15init_set_p15card(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card);

pub fn sc_pkcs15init_set_lifecycle(arg1: *mut sc_card, arg2: i32) -> i32;

pub fn sc_pkcs15init_erase_card(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_aid) -> i32;

/* XXX could this function be merged with ..._set_lifecycle ?? */
pub fn sc_pkcs15init_finalize_card(arg1: *mut sc_card, arg2: *mut sc_profile) -> i32;

pub fn sc_pkcs15init_add_app(arg1: *mut sc_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_initargs) -> i32;

pub fn sc_pkcs15init_store_pin(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_pinargs) -> i32;

pub fn sc_pkcs15init_generate_key(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_keygen_args, keybits: u32, arg4: *mut *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_generate_secret_key(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile,
                                         arg3: *mut sc_pkcs15init_skeyargs, arg4: *mut *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_store_private_key(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_prkeyargs, arg4: *mut *mut sc_pkcs15_object) -> i32;
/*
extern int    sc_pkcs15init_store_split_key(struct sc_pkcs15_card *,
                struct sc_profile *,
                struct sc_pkcs15init_prkeyargs *,
                struct sc_pkcs15_object **,
                struct sc_pkcs15_object **);
*/
pub fn sc_pkcs15init_store_public_key(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_pubkeyargs, arg4: *mut *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_store_secret_key(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_skeyargs, arg4: *mut *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_store_certificate(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15init_certargs, arg4: *mut *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_store_data_object(arg1: *mut sc_pkcs15_card , arg2: *mut sc_profile , arg3: *mut sc_pkcs15init_dataargs, arg4: *mut *mut sc_pkcs15_object) -> i32;

/* Change the value of a pkcs15 attribute.
 * new_attrib_type can (currently) be either P15_ATTR_TYPE_LABEL or
 *   P15_ATTR_TYPE_ID.
 * If P15_ATTR_TYPE_LABEL, then *new_value is a struct sc_pkcs15_id;
 * If P15_ATTR_TYPE_ID, then *new_value is a char array.
 */
pub fn sc_pkcs15init_change_attrib(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15_object, arg4: i32, arg5: *mut c_void, arg6: i32) -> i32;

fn sc_pkcs15init_add_object(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile, arg2: u32, arg3: *mut sc_pkcs15_object) -> i32;

pub fn sc_pkcs15init_delete_object(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15_object) -> i32;

/* Replace an existing cert with a new one, which is assumed to be
 * compatible with the corresponding private key (e.g. the old and
 * new cert should have the same public key).
 */
pub fn sc_pkcs15init_update_certificate(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15_object, arg4: *const u8, arg5: usize) -> i32;

pub fn sc_pkcs15init_create_file(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *mut sc_file) -> i32;

#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
pub fn sc_pkcs15init_update_file(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *mut sc_file, arg4: *mut c_void, arg5: u32) -> i32;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
pub fn sc_pkcs15init_update_file(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *mut sc_file, arg4: *mut c_void, arg5: usize) -> i32;

pub fn sc_pkcs15init_authenticate(profile: *mut sc_profile, p15card: *mut sc_pkcs15_card, file: *mut sc_file, op: i32) -> i32;

pub fn sc_pkcs15init_fixup_file(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *mut sc_file) -> i32;

pub fn sc_pkcs15init_get_pin_info(arg1: *mut sc_profile, arg2: i32, arg3: *mut sc_pkcs15_auth_info) -> i32;
/*
extern int    sc_profile_get_pin_retries(struct sc_profile *, int);
*/
pub fn sc_pkcs15init_get_manufacturer(arg1: *mut sc_profile, arg2: *mut *const c_char) -> i32;

pub fn sc_pkcs15init_get_serial(arg1: *mut sc_profile, arg2: *mut *const c_char) -> i32;

pub fn sc_pkcs15init_set_serial(arg1: *mut sc_profile, arg2: *const c_char) -> i32;

pub fn sc_pkcs15init_verify_secret(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *mut sc_file, arg4: u32, arg5: i32) -> i32;

pub fn sc_pkcs15init_delete_by_path(arg1: *mut sc_profile, arg2: *mut sc_pkcs15_card, arg3: *const sc_path) -> i32;

pub fn sc_pkcs15init_update_any_df(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile, arg3: *mut sc_pkcs15_df, arg4: i32) -> i32;
/*
extern int    sc_pkcs15init_select_intrinsic_id(struct sc_pkcs15_card *, struct sc_profile *,
            int, struct sc_pkcs15_id *, void *);
*/
/* Erasing the card structure via rm -rf */
pub fn sc_pkcs15init_erase_card_recursively(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile) -> i32;

pub fn sc_pkcs15init_rmdir(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile, arg3: *mut sc_file) -> i32;
/*
extern int    sc_pkcs15_create_pin_domain(struct sc_profile *, struct sc_pkcs15_card *,
                const struct sc_pkcs15_id *, struct sc_file **);

extern int    sc_pkcs15init_get_pin_reference(struct sc_pkcs15_card *,
                struct sc_profile *, unsigned, int);
*/
pub fn sc_pkcs15init_sanity_check(arg1: *mut sc_pkcs15_card, arg2: *mut sc_profile) -> i32;

pub fn sc_pkcs15init_finalize_profile(card: *mut sc_card, profile: *mut sc_profile, aid: *mut sc_aid) -> i32;
/*
since v0_20_0, no library export
extern int    sc_pkcs15init_unwrap_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile,
        struct sc_pkcs15_object *key, u8* wrapped_key, size_t wrapped_key_len,
        struct sc_pkcs15init_skeyargs *keyargs, struct sc_pkcs15_object **res_obj);
*/
}
