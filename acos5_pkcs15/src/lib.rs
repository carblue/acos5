//! This is an optional shared library, meant to be used alongside the driver library from carblue/acos5
//! It provides functions, that OpenSC categorizes within pkcs15init (see opensc_sys::pkcs15_init struct sc_pkcs15init_operations)

//! The bulk of driver functions access a card in a read-only manner, a few only in write-access manner as 'building block' functions:
/*
write_binary
update_binary
erase_binary
put_data
write_record
append_record
update_record
delete_record
create_file
delete_file
pin_cmd

None of these respect, that an OpenSC supported card must be PKCS#15 compliant, i.e. many modifications to card's file system must be reflected in PKCS#15 'information structures' like EF.PrKDF and alike.
E.g. generating a new RSA key pair involves with cos5:
create_file twice within current application directory, observing directory access rights, possibly asking for authorization,
setting the CRTs for RSA key pair generation and actually invoking key generation,
finally updating EF.PrKDF and EF.PuKDF (shouldn't those exist, first create those).
One unmentioned aspect is, what are the file ids to be created, with which access rigths?
All these options shall be highly configurable by the user, but not get into one's way with bothering questions: acos5-external.profile file is the configuration file for that.
Place it to /usr/share/opensc/ (where all the other OpenSC .profile files like pkcs15.profile reside).

But the OpenSC framework doesn't provide configurability for all possible options a card may come up with; that's why i.a. card-specific tools like /usr/bin/iasecc-tool do exist and I provide such a tool for cos5
 in carblue/acos5_gui: E.g. concerning above RSA key pair generation, it provides optionally restricting a RSA private key to be sign-only or decrypt-only. This is not the same as declared by key attributes via PKCS#15, which is just information without commitment. The cos5 option is a commitment: a sign-only generated private key will fail to decrypt anything passed by OpenSC to the driver in order to decrypt. It's usable only to compute a signature with corresponding cos5 command based on a hash, but unusable using cos5 command for decrypting (the distinction here is 'purpose', disregarding that the underlying math operation - raw RSA exponentiation - is the same).
 
This library provides all the PKCS#15 related functionality, that is specific to ACOS5
The OpenSC category pkcs15init presumably got it's name because the bulk of functions is required by a card initialization from scratch for a PKCS#15 compliant card
*/

/*
opensc.conf entry required within

app default {
    ......
    # PKCS #15
    framework pkcs15 {
        ...
        pkcs15init "acos5-external" {
            # The location of the pkcs15init library that supplements driver 'acos5-external': /path/to/libacos5_pkcs15.so/dll;
            # /path/to/ may be omitted, if it's located in a standard library search path of the OS
            module = "/something/like/path/to/acos5_pkcs15/target/releaseORdebug/libacos5_pkcs15.so";
        }
        ...
    }
}

Content within ... (excluded) must be adapted and added, otherwise there will be no support related to pkcs15init for ACOS5


pkcs15init:
  loaded by: src/pkcs15init/pkcs15-lib.c:load_dynamic_driver  // RTLD_LAZY
unloaded by: src/pkcs15init/pkcs15-lib.c:sc_pkcs15init_unbind
Message in debug_file: successfully loaded pkcs15init driver 'acos5-external'
*/

#![cfg_attr(feature = "cargo-clippy", warn(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::doc_markdown))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::similar_names))]


extern crate libc;
extern crate opensc_sys;
//extern crate pkcs11;
//extern crate libloading as lib;

use libc::{free}; // strlen
//use pkcs11::types::{CKM_DES_ECB, CKM_DES3_ECB, CKM_AES_ECB};

use std::os::raw::{c_void, c_uchar, c_char, c_int, c_uint};
use std::ffi::{CStr};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::collections::{HashSet};

use opensc_sys::opensc::{sc_context, sc_card, sc_select_file, sc_file_free, sc_card_ctl, SC_ALGORITHM_DES, SC_ALGORITHM_3DES, SC_ALGORITHM_AES, sc_card_find_rsa_alg, sc_file_new, sc_bytes2apdu_wrapper, sc_transmit_apdu, sc_file_dup,  sc_delete_file, sc_check_sw};

use opensc_sys::profile::{sc_profile};
use opensc_sys::pkcs15::{sc_pkcs15_card, sc_pkcs15_object, sc_pkcs15_prkey, sc_pkcs15_pubkey, sc_pkcs15_skey_info,
                         SC_PKCS15_TYPE_SKEY_DES, SC_PKCS15_TYPE_SKEY_3DES, SC_PKCS15_TYPE_SKEY_GENERIC,
                         sc_pkcs15_prkey_info, sc_pkcs15_pubkey_info, //sc_pkcs15_prkey_rsa,
                         SC_PKCS15_TYPE_PRKEY_RSA, SC_PKCS15_TYPE_PUBKEY_RSA, sc_pkcs15_auth_info, //sc_pkcs15_id,
                         SC_PKCS15_PRKDF, SC_PKCS15_PUKDF, SC_PKCS15_SKDF, SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED,
                         SC_PKCS15_DODF, sc_pkcs15_read_pubkey, sc_pkcs15_free_pubkey, sc_pkcs15_der,
                         SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE,
                         SC_PKCS15_PRKEY_USAGE_SIGN, SC_PKCS15_PRKEY_USAGE_DECRYPT, SC_PKCS15_TYPE_CLASS_MASK, SC_PKCS15_TYPE_SKEY,
                         SC_PKCS15_PRKEY_ACCESS_SENSITIVE, SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE, SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE, SC_PKCS15_PRKEY_ACCESS_LOCAL
};
//, sc_pkcs15_bignum, sc_pkcs15_pubkey_rsa
use opensc_sys::pkcs15_init::{sc_pkcs15init_operations, sc_pkcs15init_authenticate/*, sc_pkcs15init_pubkeyargs*/};
use opensc_sys::errors::{sc_strerror, SC_SUCCESS, SC_ERROR_KEYPAD_MSG_TOO_LONG,
                         SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_NOT_SUPPORTED, SC_ERROR_NON_UNIQUE_ID,
                         SC_ERROR_INCONSISTENT_PROFILE, SC_ERROR_OUT_OF_MEMORY//, SC_ERROR_NOT_IMPLEMENTED, SC_ERROR_FILE_ALREADY_EXISTS
                         //,SC_ERROR_INCONSISTENT_CONFIGURATION, SC_ERROR_UNKNOWN, SC_ERROR_FILE_NOT_FOUND
};
//use opensc_sys::sm::{sm_info};
use opensc_sys::types::{sc_file, sc_path, sc_apdu, SC_AC_OP_CREATE_EF, SC_AC_OP_DELETE, SC_AC_OP_READ, SC_AC_OP_DELETE_SELF,//SC_AC_OP_DELETE_SELF, SC_FILE_TYPE_INTERNAL_EF,
                        SC_AC_OP_UPDATE, SC_APDU_CASE_1/*, SC_APDU_CASE_3*/, SC_PATH_TYPE_PATH, sc_acl_entry};
// SC_FILE_EF_TRANSPARENT, SC_FILE_STATUS_CREATION, SC_MAX_PATH_SIZE,  SC_PATH_TYPE_FILE_ID, SC_AC_OP_DELETE
//use opensc_sys::types::{/*SC_MAX_CRTS_IN_SE, sc_crt*/};
use opensc_sys::log::{/*sc_do_log, SC_LOG_DEBUG_NORMAL,*/ sc_dump_hex};

pub mod    missing_exports; // this is NOT the same as in acos5
use crate::missing_exports::{me_profile_get_file, me_pkcs15_dup_bignum};

pub mod    constants_types; // shared file among modules acos5, acos5_pkcs15 and acos5_sm
use crate::constants_types::*;

pub mod    wrappers; // shared file among modules acos5, acos5_pkcs15 and acos5_sm
use crate::wrappers::*;

pub mod    no_cdecl; // this is NOT the same as in acos5
use crate::no_cdecl::{/*call_dynamic_update_hashmap, call_dynamic_sm_test,*/ rsa_modulus_bits_canonical, first_of_free_indices};


const BOTH : u32 = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT;

/// A mandatory library export
/// @apiNote  If @return doesn't match the version of OpenSC binary libopensc.so/dll, this library
///           will be unloaded immediately; depends on build.rs setup ref. "cargo:rustc-cfg=v0_??_0".
///           Current auto-adaption to binary version in build.rs (for pkg-config supporting OS) may not be correct
///           for OpenSC master code not yet inspected. auto-adaption for OpenSC 0.17.0 - 0.20.0-rc2 is okay
/// @return   The OpenSC release version, that this driver implementation supports
#[no_mangle]
pub extern "C" fn sc_driver_version() -> *const c_char {
    if       cfg!(v0_17_0) { CStr::from_bytes_with_nul(b"0.17.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_18_0) { CStr::from_bytes_with_nul(b"0.18.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_19_0) { CStr::from_bytes_with_nul(b"0.19.0\0").unwrap().as_ptr() }
    else  if cfg!(v0_20_0) { CStr::from_bytes_with_nul(b"0.20.0\0").unwrap().as_ptr() }
    else                   { CStr::from_bytes_with_nul(b"0.0.0\0" ).unwrap().as_ptr() } // will definitely cause rejection by OpenSC
}

#[no_mangle]
#[cfg_attr(feature = "cargo-clippy", allow(clippy::missing_safety_doc))]
pub unsafe extern "C" fn sc_module_init(name: *const c_char) -> *mut c_void {
    if !name.is_null() && CStr::from_ptr(name) == CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap() {
        acos5_get_pkcs15init_ops as *mut c_void
    }
    else {
        null_mut::<c_void>()
    }
}

extern "C" fn acos5_get_pkcs15init_ops() -> *mut sc_pkcs15init_operations {
    let b_sc_pkcs15init_operations = Box::new(sc_pkcs15init_operations {
        // there are no default functions
        /* erase_card : Erase everything that's on the card */
        erase_card : Some(acos5_pkcs15_erase_card), // called only from src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_erase_card
        /* init_card: This get's called before addDF creation i.o. to do card-specific actions.
             Card-specific initialization of PKCS15 meta-information.
             Currently used by the cflex driver to read the card's serial number and use it as the pkcs15 serial number.
         */
        init_card  : None, // called only from src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app
        /* create_dir : Create a DF */
        create_dir : None,//Some(acos5_pkcs15_create_dir), // does nothing
        /* create_domain: Some cards need to keep all their PINs in separate directories.
           Create a subdirectory now, and put the pin into this subdirectory
             Create a "pin domain". This is for cards such as the cryptoflex that need to put their pins into separate directories
         */
        create_domain        : None, // called only from src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_create_pin
        select_pin_reference : Some(acos5_pkcs15_select_pin_reference), // does nothing
        create_pin : Some(acos5_pkcs15_create_pin), // does nothing
        select_key_reference : None, // called only from src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_init_prkdf
        /* create_key :
           For generate_key (RSA) this does all of the required work before calling generate_key
         */
        create_key : Some(acos5_pkcs15_create_key),
        store_key  : Some(acos5_pkcs15_store_key),
        generate_key : Some(acos5_pkcs15_generate_key),
        encode_private_key : None, // doesn't get called by OpenSC
        encode_public_key  : None, // doesn't get called by OpenSC
        finalize_card : Some(acos5_pkcs15_finalize_card), // does nothing // probably not required for ACOS5; called only from src/pkcs15init/pkcs15-lib.c:sc_pkcs15init_finalize_card
        delete_object : Some(acos5_pkcs15_delete_object), // does nothing
        // how about the emu support at all? is that required? What exactly is that?
        emu_update_dir : None,
        emu_update_any_df : None,// : Some(acos5_pkcs15_emu_update_any_df), // does nothing
        emu_update_tokeninfo : None,
        emu_write_info : None,
        emu_store_data : Some(acos5_pkcs15_emu_store_data), // interceptor to correct/set data for SC_PKCS15_TYPE_PUBKEY_RSA
        /* there are rare OpenSC uses currently */
        sanity_check : None,// : Some(acos5_pkcs15_sanity_check),
    } );

    Box::into_raw(b_sc_pkcs15init_operations)
}

/*
erase_card is handled differently by cards: Some do delete only PKCS#15 related stuff.
ACOS5's command 'Zeroize Card User Data' removes everything from the card including MF, thus it will afterwards be in
a virgin/pristine state like from factory. This state allows writes into EEPROM memory, e.g.
for setting Operation Mode, Zeroize Card User Data Disable Flag etc. (see reference manual).

ACOS5 has a flag which decides, whether this command is possible at all: Zeroize Card User Data Disable Flag
Be very careful with this Flag/Byte (byte at  EEPROM Area address 0xC192), that it's value is 0. Otherwise
reinitializing the card will be impossible forever.

Get's called only from  src/pkcs15init/pkcs15-lib.c:sc_pkcs15init_erase_card
How to invoke this:
pkcs15-init --erase-card --so-pin <arg>          (MF's DELETE_SELF SCB probably is SOPIN)
*/
//TODO temporarily allow cast_possible_wrap  for sc_pkcs15init_authenticate
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_possible_wrap))]
extern "C" fn acos5_pkcs15_erase_card(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card) -> c_int
{
    if profile_ptr.is_null() || p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card     = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let mut rv;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun = CStr::from_bytes_with_nul(b"acos5_pkcs15_erase_card\0").unwrap();
    if cfg!(log) {
        let fmt = CStr::from_bytes_with_nul(CALLED).unwrap();
        wr_do_log(card_ctx, f_log, line!(), fun, fmt);
    }
    {
        let mut file_out = unsafe { &mut *sc_file_new() };
        file_out.path = sc_path { value: [0x3F,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2, ..sc_path::default() };
        /* Authenticate arbitrary op that's protected by SOPIN */
        rv = unsafe { sc_pkcs15init_authenticate(profile_ptr, p15card_ptr, file_out, SC_AC_OP_DELETE as c_int) };
        unsafe { sc_file_free(file_out) };
    }
    if rv < 0 {
        if cfg!(log) {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"SOPIN verification failed\0").unwrap().as_ptr(), rv, sc_strerror(rv),
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        }
        return rv;
    }

    let command = [0x80, 0x30, 0, 0];
    let mut apdu = sc_apdu::default();
    rv = sc_bytes2apdu_wrapper(card_ctx, &command, &mut apdu);
    assert_eq!(rv, SC_SUCCESS);
    assert_eq!(apdu.cse, SC_APDU_CASE_1);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"### Impossible to Zeroize Card User Data ###\0").unwrap();
        if cfg!(log) {
            wr_do_log(card_ctx, f_log, line!(), fun, fmt);
        }
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
/*
    let fmt  = CStr::from_bytes_with_nul(b"Ready to erase card's content\0").unwrap();
    wr_do_log(card_ctx, f_log, line!(), fun, fmt);
*/
    rv
}


/*
 * Create a DF
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app  and  sc_pkcs15_create_pin_domain
 */
#[allow(dead_code)]
extern "C" fn acos5_pkcs15_create_dir(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                      df_ptr: *mut sc_file) -> c_int
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || df_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let df = unsafe { & *df_ptr };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_create_dir\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, df.id, CStr::from_bytes_with_nul(b"called  with df.id %X\0").unwrap());
    }
/*
*/

    let create_dfs = [(SC_PKCS15_PRKDF, CStr::from_bytes_with_nul(b"PKCS15-PrKDF\0").unwrap()), (SC_PKCS15_PUKDF, CStr::from_bytes_with_nul(b"PKCS15-PuKDF\0").unwrap()),
                                  (SC_PKCS15_SKDF, CStr::from_bytes_with_nul(b"PKCS15-SKDF\0").unwrap()),   (SC_PKCS15_DODF, CStr::from_bytes_with_nul(b"PKCS15-DODF\0").unwrap()),
                                  (SC_PKCS15_CDF, CStr::from_bytes_with_nul(b"PKCS15-CDF\0").unwrap()),     (SC_PKCS15_CDF_TRUSTED, CStr::from_bytes_with_nul(b"PKCS15-CDF-TRUSTED\0").unwrap())];
    let mut file : *mut sc_file;
    if df.id == /* 0x4100 0x5015*/ 0x4100 as c_int {
        if cfg!(log) {
            wr_do_log_t(card_ctx, f_log, line!(), fun, df.id, CStr::from_bytes_with_nul(b"Select (%X)\0").unwrap());
        }
        /*let mut rv =*/ unsafe { sc_select_file(card, &df.path, null_mut()) };

        for (_key,value) in &create_dfs { //for (ii = 0; create_dfs[ii]; ii++)
            if cfg!(log) {
                wr_do_log_t(card_ctx, f_log, line!(), fun, value.as_ptr(), CStr::from_bytes_with_nul(b"Create '%s'\0").unwrap());
            }

            file = null_mut();
            let rv = me_profile_get_file(profile, value.as_ptr(), &mut file);
            unsafe { sc_file_free(file) };
            if rv != SC_SUCCESS {
                if cfg!(log) {
                    wr_do_log_t(card_ctx, f_log, line!(), fun, value.as_ptr(), CStr::from_bytes_with_nul(b"Inconsistent profile: cannot find %s\0").unwrap());
                }
                return SC_ERROR_INCONSISTENT_PROFILE;//LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
            }
//            rv = sc_pkcs15init_add_object(p15card, profile_ptr, create_dfs_val[ii], NULL);

//pub fn me_pkcs15init_add_object(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile, arg2: c_uint, arg3: *mut sc_pkcs15_object) -> c_int;

//            if (rv != SC_ERROR_FILE_ALREADY_EXISTS)
//                LOG_TEST_RET(ctx, rv, "Failed to create MyEID xDF file");
        }
    }

//    LOG_FUNC_RETURN(p15card.card.ctx, rv);

    SC_SUCCESS
}


/*
 * Select a PIN reference
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app  and  sc_pkcs15init_create_pin
 */
extern "C" fn acos5_pkcs15_select_pin_reference(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                                pin_ainfo_ptr: *mut sc_pkcs15_auth_info) -> c_int
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null()  || (*(*p15card_ptr).card).ctx.is_null() } || pin_ainfo_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_select_pin_reference\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    SC_SUCCESS
}

/*
 * Create a PIN object within the given DF.
 *
 * The pin_info object is completely filled in by the caller.
 * The card driver can reject the pin reference; in this case
 * the caller needs to adjust it.
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app,  sc_pkcs15init_store_puk  and  sc_pkcs15init_create_pin
 */
extern "C" fn acos5_pkcs15_create_pin(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                      file_ptr: *mut sc_file,
                                      _object_ptr: *mut sc_pkcs15_object, _arg5: *const c_uchar, _arg6: usize,
                                      _arg7: *const c_uchar, _arg8: usize) -> c_int
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } || file_ptr.is_null()  {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_create_pin\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    SC_SUCCESS
}

/*
 * Create an empty key object. (acos5: don't use this for symmetric keys)
 *
 * Before this, the profile template generation has run, thus the new file id s are known, i.e. for generate_key, always
 * new keys will be generated. Generating key content in existing RSA key pair files must be done separate from generate_key.
 * The profile template generation seems to be based on what file id s are already existing in PrKDF/PuKDF, i.e. the new
 * file id s may already exist and must then be first deleted. TODO deleting is not yet covered
 *
 */
//TODO temporarily allow cognitive_complexity
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cognitive_complexity))]
//TODO temporarily allow cast_possible_wrap  for sc_pkcs15init_authenticate
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_possible_wrap))]
//TODO temporarily allow cast_sign_loss
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_sign_loss))]
//TODO temporarily allow cast_possible_truncation
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_possible_truncation))]
//TODO temporarily allow too_many_lines
#[cfg_attr(feature = "cargo-clippy", allow(clippy::too_many_lines))]
extern "C" fn acos5_pkcs15_create_key(profile_ptr: *mut sc_profile,
                                             p15card_ptr: *mut sc_pkcs15_card,
                                             object_ptr: *mut sc_pkcs15_object) -> c_int
{
// TODO must handle create RSA key pair  And  generate sym. key !!!!!!
// TODO use dp.agi.do_create_files
// TODO use dp.agi.file_id_priv
// TODO use dp.agi.file_id_pub
// TODO SC_PKCS15_TYPE_PRKEY_EC
    if p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let p15card = unsafe { &mut *p15card_ptr };
    let card = unsafe { &mut *p15card.card };
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_create_key\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, object_ptr, CStr::from_bytes_with_nul(b"called with object_ptr: %p\0").unwrap());
    }

    if profile_ptr.is_null() || object_ptr.is_null() || unsafe { (*object_ptr).data.is_null() } {
        if cfg!(log) {
            wr_do_log_tu(card_ctx, f_log, line!(), fun, profile_ptr, object_ptr, CStr::from_bytes_with_nul(b"called with profile_ptr: %p, object_ptr: %p\0").unwrap());
            if !object_ptr.is_null() {
                wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { (*object_ptr).data }, CStr::from_bytes_with_nul(b"called with object.data: %p\0").unwrap());
            }
        }
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let profile = unsafe { &mut *profile_ptr };
    let object      = unsafe { &mut *object_ptr };
    let mut rv;
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.type_, CStr::from_bytes_with_nul(b"object.type: %X\0").unwrap());
    }

    if SC_PKCS15_TYPE_SKEY == (object.type_ & SC_PKCS15_TYPE_CLASS_MASK) {
        /*
        FIXME How to distinguish, whether this is for an unwrap operation or store_key operation
        for unwrap, this will be printed for hannu's unwraptest
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:398:acos5_pkcs15_create_key: called with object_ptr: 0x5643e082ac60
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:414:acos5_pkcs15_create_key: object.type: 301                    SC_PKCS15_TYPE_SKEY_GENERIC
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:420:acos5_pkcs15_create_key: key_info.id: 09                     set in hannu's unwraptest as new id
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:421:acos5_pkcs15_create_key: key_info.usage: 30                  SC_PKCS15_PRKEY_USAGE_UNWRAP | SC_PKCS15_PRKEY_USAGE_WRAP
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:422:acos5_pkcs15_create_key: key_info.access_flags: 0            to be updated !!!
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:423:acos5_pkcs15_create_key: key_info.native: 1
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:424:acos5_pkcs15_create_key: key_info.key_reference: 0           to be updated !!!
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:425:acos5_pkcs15_create_key: key_info.value_len (in bits): 256
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:426:acos5_pkcs15_create_key: key_info.key_type: 31               enum CKK_AES = 0x0000001FUL;
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:427:acos5_pkcs15_create_key: key_info.algo_refs[0]: 0            to be updated !!!
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:428:acos5_pkcs15_create_key: key_info.algo_refs[1]: 0            to be updated !!!
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:429:acos5_pkcs15_create_key: key_info.algo_refs[2]: 0
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:430:acos5_pkcs15_create_key: key_info.path: 3F004100             to be updated !!!
P:6445; T:0x140296631560000 10:54:08.502 [opensc-pkcs11] acos5:434:acos5_pkcs15_create_key: Currently we won't create any sym. secret key, but pretend to have done that
P:6        */
        let key_info = unsafe { &mut *(object.data as *mut sc_pkcs15_skey_info) };
        if cfg!(log) {
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) }, CStr::from_bytes_with_nul(b"key_info.id: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.usage, CStr::from_bytes_with_nul(b"key_info.usage: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.access_flags, CStr::from_bytes_with_nul(b"key_info.access_flags: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.native, CStr::from_bytes_with_nul(b"key_info.native: %d\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_reference, CStr::from_bytes_with_nul(b"key_info.key_reference: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.value_len, CStr::from_bytes_with_nul(b"key_info.value_len (in bits): %zu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_type, CStr::from_bytes_with_nul(b"key_info.key_type: %zu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[0], CStr::from_bytes_with_nul(b"key_info.algo_refs[0]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[1], CStr::from_bytes_with_nul(b"key_info.algo_refs[1]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[2], CStr::from_bytes_with_nul(b"key_info.algo_refs[2]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }, CStr::from_bytes_with_nul(b"key_info.path: %s\0").unwrap());
            if !key_info.data.value.is_null() && key_info.data.len>0 {
                wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.data.value, key_info.data.len) }, CStr::from_bytes_with_nul(b"key_info.data: %s\0").unwrap());
            }
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Currently we won't create any sym. secret key, but pretend to have done that\0").unwrap());
        }

        if SC_PKCS15_TYPE_SKEY_GENERIC == object.type_ {
            unsafe { copy_nonoverlapping([1 /*AES ECB*/, 2 /*AES CBC*/].as_ptr(),
                                         key_info.algo_refs.as_mut_ptr(), 2); }
        }
        key_info.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_LOCAL;
        let mut file_id_sym_keys = 0_u16;
        key_info.path.index = first_of_free_indices(p15card, &mut file_id_sym_keys);
        assert!(key_info.path.index<=255);
        assert!(key_info.path.index>0 && file_id_sym_keys>0);
        unsafe { copy_nonoverlapping(file_id_sym_keys.to_be_bytes().as_ptr(),
                                     key_info.path.value.as_mut_ptr().add(key_info.path.len), 2); }
        key_info.path.len += 2;
        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        let mrl = dp.files[&file_id_sym_keys].1[4];
//      let nor = dp.files[&file_id_sym_keys].1[5];
        dp.is_unwrap_op_in_progress = true;
        dp.sym_key_file_id = file_id_sym_keys;
        //TODO temporarily allow cast_possible_truncation
        dp.sym_key_rec_idx = key_info.path.index as u8;
        dp.sym_key_rec_cnt = mrl;
        card.drv_data = Box::into_raw(dp) as *mut c_void;

        key_info.path.count = i32::from(mrl);//0x25;
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.path.index, CStr::from_bytes_with_nul(b"key_info.path.index: %d\0").unwrap());
        key_info.key_reference = 0x80 | key_info.path.index;

/*
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:500:acos5_pkcs15_create_key: called with object_ptr: 0x55d7c73a1ce0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:516:acos5_pkcs15_create_key: called for object.type: 301
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:522:acos5_pkcs15_create_key: key_info.id: 09
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:523:acos5_pkcs15_create_key: key_info.usage: 30
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:524:acos5_pkcs15_create_key: key_info.access_flags: 0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:525:acos5_pkcs15_create_key: key_info.native: 1
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:526:acos5_pkcs15_create_key: key_info.key_reference: 0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:527:acos5_pkcs15_create_key: key_info.value_len: 256
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:528:acos5_pkcs15_create_key: key_info.key_type: 31
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:529:acos5_pkcs15_create_key: key_info.algo_refs[0]: 0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:530:acos5_pkcs15_create_key: key_info.algo_refs[1]: 0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:531:acos5_pkcs15_create_key: key_info.algo_refs[2]: 0
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:532:acos5_pkcs15_create_key: key_info.path: 3F004100
P:13407; T:0x140114465912640 20:32:12.192 [opensc-pkcs11] acos5:536:acos5_pkcs15_create_key: Currently we won't create any sym. secret key, but pretend to have done that

P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1444:acos5_pkcs15_emu_store_data: called for object.type 301
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1513:acos5_pkcs15_emu_store_data: key_info.id: 09
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1514:acos5_pkcs15_emu_store_data: key_info.usage: 30
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1515:acos5_pkcs15_emu_store_data: key_info.access_flags: 1D
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1516:acos5_pkcs15_emu_store_data: key_info.native: 1
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1517:acos5_pkcs15_emu_store_data: key_info.key_reference: 9
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1518:acos5_pkcs15_emu_store_data: key_info.value_len: 256
P:15775; T:0x140345097463616 22:23:51.689 [opensc-pkcs11] acos5:1519:acos5_pkcs15_emu_store_data: key_info.key_type: 31
P:15775; T:0x140345097463616 22:23:51.690 [opensc-pkcs11] acos5:1520:acos5_pkcs15_emu_store_data: key_info.algo_refs[0]: 1
P:15775; T:0x140345097463616 22:23:51.690 [opensc-pkcs11] acos5:1521:acos5_pkcs15_emu_store_data: key_info.algo_refs[1]: 2
P:15775; T:0x140345097463616 22:23:51.690 [opensc-pkcs11] acos5:1522:acos5_pkcs15_emu_store_data: key_info.algo_refs[2]: 0
P:15775; T:0x140345097463616 22:23:51.690 [opensc-pkcs11] acos5:1523:acos5_pkcs15_emu_store_data: key_info.path: 3F0041004102
P*/
        return SC_SUCCESS;
    }

    let key_info = unsafe { &mut *(object.data as *mut sc_pkcs15_prkey_info) };
    if SC_PKCS15_TYPE_PRKEY_RSA != object.type_ || (key_info.usage & (SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT)) == 0 {
        if cfg!(log) {
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Failed: Only RSA is supported\0").unwrap());
        }
        return SC_ERROR_NOT_SUPPORTED;
    }
    key_info.modulus_length = rsa_modulus_bits_canonical(key_info.modulus_length);
    let keybits = key_info.modulus_length;
    if keybits < 512 || keybits > 4096 || (keybits % 256) > 0 {
        rv = SC_ERROR_INVALID_ARGUMENTS;
        unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Invalid RSA key size\0").
            unwrap().as_ptr(), rv, sc_strerror(rv),
                      CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        return rv;
    }
    /* Check that the card supports the requested modulus length */
    //TODO temporarily allow cast_possible_truncation
    if unsafe { sc_card_find_rsa_alg(card, keybits as c_uint).is_null() } {
        if cfg!(log) {
            wr_do_log_t(card_ctx, f_log, line!(), fun, keybits, CStr::from_bytes_with_nul(b"Failed: Unsupported RSA key size %zu\0").unwrap());
        }
        rv = SC_ERROR_INVALID_ARGUMENTS;
        return rv;
    }
    /* TODO Think about other checks or possibly refuse to generate keys if file access rights are wrong */

/* * /
    if !profile.name.is_null() {
        wr_do_log_t(card_ctx, f_log, line!(), fun, profile.name, CStr::from_bytes_with_nul(b"profile.name: %s\0").unwrap());
    }
    if !profile.options[0].is_null() {
        wr_do_log_t(card_ctx, f_log, line!(), fun, profile.options[0], CStr::from_bytes_with_nul(b"profile.options[0]: %s\0").unwrap());
    }
    if !profile.options[1].is_null() {
        wr_do_log_t(card_ctx, f_log, line!(), fun, profile.options[1], CStr::from_bytes_with_nul(b"profile.options[1]: %s\0").unwrap());
    }
/* */
    let mut elem = profile.df_info;
    while !elem.is_null() {
        let df_info = unsafe { & *elem };
        if !df_info.file.is_null() {
            let file_ref = unsafe { & *df_info.file };
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, CStr::from_bytes_with_nul(b"df_info file_ref.path: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.type_, CStr::from_bytes_with_nul(b"df_info file_ref.type: 0x%X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.id,    CStr::from_bytes_with_nul(b"df_info file_ref.id:   0x%X\0").unwrap());
        }
        elem = unsafe { (*elem).next };
    }
/ * */
/*
    elem = profile.ef_list;
    while !elem.is_null() {
        let ef_list = unsafe { & *elem };
        if !ef_list.file.is_null() {
            let file_ref = unsafe { & *ef_list.file };
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, CStr::from_bytes_with_nul(b"ef_list file_ref.path: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.type_, CStr::from_bytes_with_nul(b"ef_list file_ref.type: 0x%X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.id,    CStr::from_bytes_with_nul(b"ef_list file_ref.id:   0x%X\0").unwrap());
        }
        elem = unsafe { (*elem).next };
    }
*/
/* * /
    let tmp = profile.template_list;
    if !tmp.is_null() {
        elem = unsafe { (*tmp).file };
        while !elem.is_null() {
            let tmp_file_info = unsafe { & *elem };
            if !tmp_file_info.file.is_null() {
                let file_ref = unsafe { & *tmp_file_info.file };
                wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, CStr::from_bytes_with_nul(b"template_list_file file_ref.path: %s\0").unwrap());
                wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.type_, CStr::from_bytes_with_nul(b"template_list_file file_ref.type: 0x%X\0").unwrap());
                wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.id,    CStr::from_bytes_with_nul(b"template_list_file file_ref.id:   0x%X\0").unwrap());
            }
            elem = unsafe { (*elem).next };
        }
    }
/ * */
/* * /

    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, profile.id_style, CStr::from_bytes_with_nul(b"profile.id_style: %u\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.type_, CStr::from_bytes_with_nul(b"object.type: 0x%X\0").unwrap()); // pub const SC_PKCS15_TYPE_PRKEY_RSA        : u32 =  0x101;
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.label.as_ptr(), CStr::from_bytes_with_nul(b"object.label: %s\0").unwrap()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.flags, CStr::from_bytes_with_nul(b"object.flags: 0x%X\0").unwrap()); // 3: SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE ??
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.auth_id.len, CStr::from_bytes_with_nul(b"object.auth_id.len: %zu\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.auth_id.value[0], CStr::from_bytes_with_nul(b"object.auth_id.value[0]: %u\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.usage_counter, CStr::from_bytes_with_nul(b"object.usage_counter: %d\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.user_consent, CStr::from_bytes_with_nul(b"object.user_consent: %d\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.access_rules[0].access_mode, CStr::from_bytes_with_nul(b"object.access_rules[0].access_mode: %X\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.df, CStr::from_bytes_with_nul(b"object.df: %p\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) }, CStr::from_bytes_with_nul(b"key_info.id: %s\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.usage, CStr::from_bytes_with_nul(b"key_info.usage: 0x%X\0").unwrap()); // 46 SC_PKCS15_PRKEY_USAGE_UNWRAP | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.access_flags, CStr::from_bytes_with_nul(b"key_info.access_flags: 0x%X\0").unwrap()); // 29  SC_PKCS15_PRKEY_ACCESS_LOCAL | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_SENSITIVE
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.native, CStr::from_bytes_with_nul(b"key_info.native: %d\0").unwrap()); // 1
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_reference, CStr::from_bytes_with_nul(b"key_info.key_reference: 0x%X\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.modulus_length, CStr::from_bytes_with_nul(b"key_info.modulus_length: %zu\0").unwrap()); // 3072
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[0], CStr::from_bytes_with_nul(b"key_info.algo_refs[0]: 0x%X\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.subject.len, CStr::from_bytes_with_nul(b"key_info.subject.len: %zu\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.params.len, CStr::from_bytes_with_nul(b"key_info.params.len: %zu\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }, CStr::from_bytes_with_nul(b"key_info.path: %s\0").unwrap()); // 3F00410041F5
    }
/ * */
    let mut file_priv = null_mut();
    rv = me_profile_get_file(profile, CStr::from_bytes_with_nul(b"template-private-key\0").unwrap().as_ptr(), &mut file_priv);
    if rv != SC_SUCCESS {
        if cfg!(log) {
            wr_do_log_t(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"private-key\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"Inconsistent profile: cannot find %s\0").unwrap());
        }
        return SC_ERROR_INCONSISTENT_PROFILE;//LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
    }
    assert!(!file_priv.is_null());
    let mut file_priv = unsafe { &mut *file_priv };
    assert_eq!(file_priv.path.type_, SC_PATH_TYPE_PATH);
    assert!(file_priv.path.len >= 4 && file_priv.path.len<=16);
    assert_eq!(file_priv.acl[SC_AC_OP_READ as usize], 0x1 as *mut sc_acl_entry); // NEVER allowed to be read
    assert_eq!(file_priv.path.len, key_info.path.len+2);
/* */
    let app_name = unsafe { CStr::from_ptr(card_ctx.app_name) }; // app_name: "pkcs15-init"
//    println!("app_name: {:?}", app_name);
//
    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    if app_name == CStr::from_bytes_with_nul(b"acos5_gui \0").unwrap() {
        dp.agc.do_create_files = dp.agi.do_create_files;
        if !dp.agc.do_create_files && dp.agi.file_id_priv!=0 && dp.agi.file_id_pub!=0 {

        }
        dp.agc.do_generate_rsa_crt = card.type_==SC_CARD_TYPE_ACOS5_64_V3 || dp.agi.do_generate_rsa_crt;
        dp.agc.do_generate_rsa_add_decrypt_for_sign = dp.agi.do_generate_rsa_add_decrypt_for_sign;
        dp.agc.do_generate_with_standard_rsa_pub_exponent = dp.agi.do_generate_with_standard_rsa_pub_exponent;
        if ! dp.agc.do_generate_with_standard_rsa_pub_exponent {
            dp.agc.rsa_pub_exponent = dp.agi.rsa_pub_exponent;
        }
    }
    else {
        let mut prop_do_generate_rsa_crt                           : bool = true;
        let mut prop_do_generate_rsa_add_decrypt_for_sign          : bool = true;
//      let mut prop_do_do_generate_with_standard_rsa_pub_exponent : bool = true;
        if !file_priv.prop_attr.is_null() {
            if file_priv.prop_attr_len >= 1 { prop_do_generate_rsa_crt                  = unsafe{*file_priv.prop_attr.add(0)} != 0; }
            if file_priv.prop_attr_len >= 2 { prop_do_generate_rsa_add_decrypt_for_sign = unsafe{*file_priv.prop_attr.add(1)} != 0; }
        }
//println!("prop_do_generate_rsa_crt:                           {}", prop_do_generate_rsa_crt);
//println!("prop_do_generate_rsa_add_decrypt_for_sign:          {}", prop_do_generate_rsa_add_decrypt_for_sign);
        dp.agc.do_create_files = true;
        dp.agc.do_generate_rsa_crt = card.type_==SC_CARD_TYPE_ACOS5_64_V3 || prop_do_generate_rsa_crt;
        dp.agc.do_generate_rsa_add_decrypt_for_sign = prop_do_generate_rsa_add_decrypt_for_sign;
        dp.agc.do_generate_with_standard_rsa_pub_exponent = true;
        dp.agc.rsa_pub_exponent = [0; 16];
    }
    let do_create_files = dp.agc.do_create_files;
    file_priv.size = 5 + keybits/16 * if dp.agc.do_generate_rsa_crt {5} else {2};
    card.drv_data = Box::into_raw(dp) as *mut c_void;
//
    if !file_priv.prop_attr.is_null() {
        unsafe { free(file_priv.prop_attr as *mut c_void) }; // file->prop_attr = malloc(len);
        file_priv.prop_attr = null_mut();
    }

    /* The following is the possible starting value for key priv file path */
    file_priv.path.value[file_priv.path.len-2] = file_priv.path.value[file_priv.path.len-4];
    let mut fid_priv_possible : HashSet<u16> = HashSet::with_capacity(0x30);
    let mut fid_pub_possible  : HashSet<u16> = HashSet::with_capacity(0x30);
    {
        let fid = u16::from_be_bytes([file_priv.path.value[file_priv.path.len-2], file_priv.path.value[file_priv.path.len-1]]);
//        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_priv.path.value.as_ptr(), file_priv.path.len) }, CStr::from_bytes_with_nul(b"file_priv.path: %s\0").unwrap());
        for i in 0..0x30 { fid_priv_possible.insert(fid+i); }
        for i in 0..0x30 { fid_pub_possible.insert( fid+i +0x30); }
    }
    /* examine existing key priv file path */
    let mut _cnt_priv = 0_u8;
    let mut p15obj_list_ptr = p15card.obj_list;
    while !p15obj_list_ptr.is_null() {
        let p15obj = unsafe { &*p15obj_list_ptr };
        if SC_PKCS15_TYPE_PRKEY_RSA == p15obj.type_ && !p15obj.df.is_null() {
/* * /
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"   \0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.type_, CStr::from_bytes_with_nul(b"p15obj.type_: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.label.as_ptr(), CStr::from_bytes_with_nul(b"p15obj.label: %s\0").unwrap()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.flags, CStr::from_bytes_with_nul(b"p15obj.flags: 0x%X\0").unwrap()); // 3: SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE ??
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.auth_id.len, CStr::from_bytes_with_nul(b"p15obj.auth_id.len: %zu\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.auth_id.value[0], CStr::from_bytes_with_nul(b"p15obj.auth_id.value[0]: %u\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.usage_counter, CStr::from_bytes_with_nul(b"p15obj.usage_counter: %d\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.user_consent, CStr::from_bytes_with_nul(b"p15obj.user_consent: %d\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.access_rules[0].access_mode, CStr::from_bytes_with_nul(b"p15obj.access_rules[0].access_mode: %X\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.df, CStr::from_bytes_with_nul(b"p15obj.df: %p\0").unwrap()); // 1
            wr_do_log_t(card_ctx, f_log, line!(), fun, p15obj.session_object, CStr::from_bytes_with_nul(b"p15obj.session_object: %d\0").unwrap()); // 1
/ * */
            _cnt_priv += 1;
            assert!(!p15obj.data.is_null());
            let p15obj_prkey_info_path = & unsafe { &mut *(p15obj.data as *mut sc_pkcs15_prkey_info) }.path;
//            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(p15obj_prkey_info_path.value.as_ptr(), p15obj_prkey_info_path.len) }, CStr::from_bytes_with_nul(b"p15obj_prkey_info_path: %s\0").unwrap());
            let fid_priv_used = u16::from_be_bytes([p15obj_prkey_info_path.value[p15obj_prkey_info_path.len-2],
                                                    p15obj_prkey_info_path.value[p15obj_prkey_info_path.len-1]]);
            fid_priv_possible.remove(&fid_priv_used);
            fid_pub_possible.remove(&fid_priv_used);
        }
        p15obj_list_ptr = p15obj.next;
    }

    let mut fid_priv_possible_min = 0xFFFF_u16;
    for elem in &fid_priv_possible {
        if *elem < fid_priv_possible_min && fid_pub_possible.contains(&(*elem+0x30)) { fid_priv_possible_min = *elem; }
    }

//    println!("fid_priv_possible.len(): {}", fid_priv_possible.len());
//    println!("fid_publ_possible.len(): {}", fid_pub_possible.len());
//    println!("fid_priv_existing.len(): {}", _cnt_priv);
    if fid_priv_possible_min == 0xFFFF {
        println!("The maximum of 48 RSA key pairs is exceeded. First delete one for a free file id slot");
        rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
        unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
            b"### The maximum of 48 RSA key pairs is exceeded. First delete one for a free file id slot ###\0").
            unwrap().as_ptr(), rv, sc_strerror(rv),
                      CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        return rv;
    }
    println!("This file id will be chosen for the private RSA key:  {:X}", fid_priv_possible_min);
    /* The final values for path and fid_priv */
    //TODO temporarily allow cast_possible_truncation
    file_priv.path.value[file_priv.path.len-1] = (fid_priv_possible_min & 0x00FF) as u8;
    file_priv.id = i32::from(u16::from_be_bytes([file_priv.path.value[file_priv.path.len-2],
                                                 file_priv.path.value[file_priv.path.len-1]]));

    wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_priv.path.value.as_ptr(), file_priv.path.len) }, CStr::from_bytes_with_nul(b"file_priv.path: %s\0").unwrap());
    wr_do_log_t(card_ctx, f_log, line!(), fun, file_priv.id, CStr::from_bytes_with_nul(b"file_priv.id: %X\0").unwrap());
//
    //TODO temporarily allow cast_possible_truncation
    unsafe { copy_nonoverlapping((file_priv.id as u16).to_be_bytes().as_ptr(),
                                 key_info.path.value.as_mut_ptr().add(key_info.path.len), 2); }
    key_info.path.len += 2;
    key_info.path.type_ = SC_PATH_TYPE_PATH;
    assert_eq!(key_info.path.value, file_priv.path.value);

    let mut file_pub : *mut sc_file = null_mut();
    unsafe { sc_file_dup(&mut file_pub, file_priv) };
    if file_pub.is_null() {
        return SC_ERROR_OUT_OF_MEMORY;
    }
    let mut file_pub = unsafe { &mut *file_pub };
    file_pub.size = 21 + keybits/8;
    file_pub.path.value[file_pub.path.len-1] += 0x30;
    file_pub.id                              += 0x30;
    println!("This file id will be chosen for the public  RSA key:  {:X}", file_pub.id);
    if app_name == CStr::from_bytes_with_nul(b"acos5_gui \0").unwrap() {
        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        //TODO temporarily allow cast_possible_truncation
        dp.agi.file_id_priv = file_priv.id as u16;
        dp.agi.file_id_pub  = file_pub.id  as u16;
        card.drv_data = Box::into_raw(dp) as *mut c_void;
    }
    // TODO don't leak old file_pub.acl[SC_AC_OP_READ]
    file_pub.acl[SC_AC_OP_READ as usize] = 0x2 as *mut sc_acl_entry; // ALWAYS allowed to be read

    let file_priv_has_to_be_deleted = if do_create_files {SC_SUCCESS == unsafe{sc_select_file(card, &file_priv.path, null_mut())}} else {false};
    let file_pub_has_to_be_deleted  = if do_create_files {SC_SUCCESS == unsafe{sc_select_file(card,  &file_pub.path, null_mut())}} else {false};

    /* delete potentially existing file with file_id of file_priv in card's file system */
    #[allow(non_snake_case)]
    let pathDFparent = sc_path { len: file_priv.path.len-2, ..file_priv.path };
    #[allow(non_snake_case)]
    let mut fileDFparent: *mut sc_file = null_mut();
    rv = unsafe { sc_select_file(card, &pathDFparent, &mut fileDFparent) };
    if rv < 0 {
        unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
            b"DF for the private objects not defined\0").unwrap().as_ptr(), rv, sc_strerror(rv),
            CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        if !fileDFparent.is_null() {
            unsafe { sc_file_free(fileDFparent) };
        }
        unsafe { sc_file_free(file_priv) };
        unsafe { sc_file_free(file_pub) };
        return rv;
    }

    if do_create_files {
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, fileDFparent, SC_AC_OP_CREATE_EF as c_int) };
        if rv < 0 {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"SC_AC_OP_CREATE_EF authentication failed for parent DF\0").
                unwrap().as_ptr(), rv, sc_strerror(rv),
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
            unsafe { sc_file_free(fileDFparent) };
            unsafe { sc_file_free(file_priv) };
            unsafe { sc_file_free(file_pub) };
            return rv;
        }
        if file_priv_has_to_be_deleted || file_pub_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, fileDFparent, SC_AC_OP_DELETE as c_int) };
            if rv < 0 {
                unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                    b"SC_AC_OP_CREATE_EF authentication failed for parent DF\0").
                    unwrap().as_ptr(), rv, sc_strerror(rv),
                    CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
                unsafe { sc_file_free(fileDFparent) };
                unsafe { sc_file_free(file_priv) };
                unsafe { sc_file_free(file_pub) };
                return rv;
            }
        }
        if file_priv_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, SC_AC_OP_DELETE_SELF as c_int) };
            if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_delete_file(card, &file_priv.path) };
            if rv != SC_SUCCESS { return rv; }
        }
        if file_pub_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, SC_AC_OP_DELETE_SELF as c_int) };
            if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_delete_file(card, &file_pub.path) };
            if rv != SC_SUCCESS { return rv; }
        }
    }
    unsafe { sc_file_free(fileDFparent) };

    /* actual file creation on card */
/* */
    if do_create_files {
        rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_CREATE, file_priv as *mut sc_file as *mut c_void) };
        if rv < 0 {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"create file_priv failed\0").
                unwrap().as_ptr(), rv, sc_strerror(rv),
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
            return rv;
        }
        rv = unsafe { sc_select_file(card, &file_priv.path, null_mut()) };
        if rv != SC_SUCCESS {
            return rv;
        }
        let command = [0x00, 0x44, 0x00, 0x00];
        let mut apdu = sc_apdu::default();
        rv = sc_bytes2apdu_wrapper(card_ctx, &command, &mut apdu);
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(apdu.cse, SC_APDU_CASE_1);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed or ### File Activation failed for private key ###\0").unwrap();
            #[cfg(log)]
                wr_do_log(card_ctx, f_log, line!(), fun, fmt);
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }

        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, SC_AC_OP_UPDATE as c_int) };
        if rv != SC_SUCCESS { return rv; }

        rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_CREATE, file_pub as *mut sc_file as *mut c_void) };
        if rv < 0 {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"create file_pub failed\0").unwrap().as_ptr(), rv, sc_strerror(rv),
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
            return rv;
        }
        rv = unsafe { sc_select_file(card, &file_pub.path, null_mut()) };
        if rv != SC_SUCCESS {
            return rv;
        }
        apdu.sw1 = 0;
        apdu.sw2 = 0;
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            let fmt = CStr::from_bytes_with_nul(b"sc_transmit_apdu failed or ### File Activation failed for public key ###\0").unwrap();
            #[cfg(log)]
                wr_do_log(card_ctx, f_log, line!(), fun, fmt);
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }

        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, SC_AC_OP_UPDATE as c_int) };
        if rv != SC_SUCCESS { return rv; }
    }
    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    //TODO temporarily allow cast_possible_truncation
    dp.agc.file_id_priv = file_priv.id as u16;
    unsafe { sc_file_free(file_priv) };
    dp.agc.file_id_pub  = file_pub.id as u16;
    unsafe { sc_file_free(file_pub) };
    dp.agc.key_len_code = (keybits / 128) as u8;

    dp.agc.key_priv_type_code = match key_info.usage & BOTH {
        SC_PKCS15_PRKEY_USAGE_SIGN => 1,
        SC_PKCS15_PRKEY_USAGE_DECRYPT => 2,
        BOTH => 3,
        _ => return SC_ERROR_KEYPAD_MSG_TOO_LONG,
    };
    if dp.agc.key_priv_type_code==1 && dp.agc.do_generate_rsa_add_decrypt_for_sign {
        dp.agc.key_priv_type_code = 3;
    }
    if dp.agc.do_generate_rsa_crt {
        dp.agc.key_priv_type_code += 3;
    }

//    dp.agc.is_key_pair_created_and_valid_for_generation = true;
    dp.agc.perform_mse = true;
    /* setting of dp.agc  is complete, ready for generation */
    card.drv_data = Box::into_raw(dp) as *mut c_void;

    rv = SC_SUCCESS;
    if cfg!(log) {
        wr_do_log_tu(card_ctx, f_log, line!(), fun, rv, unsafe { sc_strerror(rv) },
                     CStr::from_bytes_with_nul(RETURNING_INT_CSTR).unwrap());
    }
    rv
} // acos5_pkcs15_create_key


/* e.g. pkcs15-init --store-secret-key text_file --secret-key-algorithm 3des     --auth-id 01 --id 02
 *      pkcs15-init --store-secret-key file      --secret-key-algorithm 3des/128 --auth-id 01 --id 03
 *      pkcs15-init --store-secret-key file      --secret-key-algorithm 3des/128 --auth-id 01 --id 07
 *
 *  file to be written by a hex-editor, i.e. containing hexadecimal values , containing probably unprintable bytes, no BOM, no line feed, carriage return etc.
 *  if 128 of des/128 is omitted, i.e. des only, it will be the default value 192=24 bytes
 *  auth-id is the pin that protects the secret key file
 *  id is the key reference==key record
 */
/*
required: id. okay but must be controlled, 1-15 5 bit
              Unblocking info needs version_identifier KEY_SECRET_UNBLOCK_YES
Key Type      needs version_identifiers KEY_SECRET_INTERNALAUTH_YES, KEY_SECRET_EXTERNALAUTH_YES
Key Info      needs numerical info ?
Algorithm Reference   okay, from opensc
Key Value             okay, from opensc


00A40000024100
00C0000032
00A40000024114
00C0000020
00B00000FF
000E000000
00B00000FF
 */
// does something, but it's not correct
#[cfg_attr(feature = "cargo-clippy", allow(clippy::if_not_else))]
extern "C" fn acos5_pkcs15_store_key(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                        object: *mut sc_pkcs15_object, key: *mut sc_pkcs15_prkey) -> c_int
{ // does nothing currently, except logging CALLED
    if p15card.is_null() || unsafe { (*p15card).card.is_null() || (*(*p15card).card).ctx.is_null() } || object.is_null() || unsafe { (*object).data.is_null() } || key.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let object_mr = unsafe { &mut *object };
    let key_mr = unsafe { &mut *key };
    let skey_mr = unsafe { &mut key_mr.u.secret };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_store_key\0").unwrap();
    if cfg!(log) {
        let fmt  = CStr::from_bytes_with_nul(CALLED).unwrap();
        wr_do_log(card_ctx, f_log, line!(), fun, fmt);
    }
    if true /*SC_PKCS15_TYPE_SKEY == (object.type_ & SC_PKCS15_TYPE_CLASS_MASK)*/ {
        if cfg!(log) {
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Currently we won't store any key, but pretend to have done that\0").unwrap());
        }
        return SC_SUCCESS;
    }

//#[cfg(not(any(v0_15_0, v0_16_0)))]  for secret key
    let rv : i32;

    //TODO temporarily allow if_not_else
    if ![SC_ALGORITHM_DES, SC_ALGORITHM_3DES, SC_ALGORITHM_AES].contains(&key_mr.algorithm) {
        rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    else {
        let skey_info = unsafe { &mut *(object_mr.data as *mut sc_pkcs15_skey_info) };
/*
$ pkcs15-init --store-secret-key=des192_2.hex  --secret-key-algorithm 3des/192 --auth-id 01 --id 07
Using reader with a card: ACS CryptoMate64 00 00

$ pkcs15-init --store-secret-key=aes256_6.hex  --secret-key-algorithm aes/256 --auth-id 01 --id 08
Using reader with a card: ACS CryptoMate64 00 00
$

0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-skey.c:164:sc_pkcs15_decode_skdf_entry: returning with: 0 (Success)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15.c:2081:sc_pkcs15_parse_df: returning with: 0 (Success)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:1300:sc_pkcs15init_init_skdf: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:2851:select_object_path: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:2876:select_object_path: key-domain.secret-key @3f004100 (auth_id.len=1)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:2898:select_object_path: instantiated template path 3f0041004103
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:2927:select_object_path: returns object path '3f0041004103'
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:2928:select_object_path: returning with: 0 (Success)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:1371:sc_pkcs15init_init_skdf: returning with: 0 (Success)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] acos5    :346:acos5_pkcs15_store_key: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] acos5    :467:acos5_pkcs15_store_key_secret: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:3143:sc_pkcs15init_add_object: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:3144:sc_pkcs15init_add_object: add object 0x560d72a49550 to DF of type 3
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:3168:sc_pkcs15init_add_object: Append object
0x7f24cddfef80 16:20:36.707 [pkcs15-init] acos5    :511:acos5_pkcs15_emu_update_any_df: called
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:3187:sc_pkcs15init_add_object: returning with: 0 (Success)
0x7f24cddfef80 16:20:36.707 [pkcs15-init] pkcs15-lib.c:1938:sc_pkcs15init_store_secret_key: returning with: 0 (Success)
*/
        skey_info.value_len = 64;
        skey_mr.data_len    =  8;

        assert_eq!(3, object_mr.flags);
        assert_eq!(3, skey_info.usage);
        assert_eq!(skey_mr.data_len, skey_info.value_len/8);
        assert_eq!(1,     skey_info.id.len);
        match key_mr.algorithm {
            SC_ALGORITHM_DES => {
                assert_eq!(/*CKM_DES_ECB*/ 0x121, skey_info.key_type);
                assert_eq!(SC_PKCS15_TYPE_SKEY_DES, object_mr.type_);
            },

            SC_ALGORITHM_3DES => {
                assert_eq!(/*CKM_DES3_ECB*/ 0x132, skey_info.key_type);
                assert_eq!(SC_PKCS15_TYPE_SKEY_3DES, object_mr.type_);
            }
            SC_ALGORITHM_AES => {
                assert_eq!(/*CKM_AES_ECB*/ 0x1081, skey_info.key_type);
                assert_eq!(SC_PKCS15_TYPE_SKEY_GENERIC, object_mr.type_);
            }
            _ =>  {
                rv = SC_ERROR_NOT_SUPPORTED;
                return rv;
            }
        }

        let key_id = skey_info.id.value[0];
        if key_id == 0 || key_id > 31 {
            rv = SC_ERROR_NON_UNIQUE_ID;
            return rv;
        }
        let mut vec = Vec::with_capacity(skey_mr.data_len);
        for i in 0..skey_mr.data_len {
            unsafe { vec.push( *skey_mr.data.add(i)) };
        }
        rv = acos5_pkcs15_store_key_secret(card_ctx, &skey_info.path.value[0..skey_info.path.len], key_id,
                                                  key_mr.algorithm, vec.as_slice() );
    }
    rv
} // acos5_pkcs15_store_key


// does nothing currently, except logging CALLED
fn acos5_pkcs15_store_key_secret(
    ctx_ptr: *mut sc_context,
    _path: &[c_uchar],
    _key_id: c_uchar,
    _key_algorithm: c_uint /* e.g. SC_ALGORITHM_DES */,
    _key_value: &[c_uchar]
) -> c_int
{
    /*
    sc_context* ctx = card.ctx;
    int rv = SC_ERROR_UNKNOWN;
    ubyte[25] command_data; // this length is allocated
    ubyte     pos;
    /*
    mixin (log!(__PRETTY_FUNCTION__, "called"));
    mixin log_scope_exit;
    scope(exit)
    log_scope_exit_do(__LINE__, __FUNCTION__);

    mixin (log!(__FUNCTION__, "path:           %s", "sc_dump_hex(path.ptr, path.length)"));
    mixin (log!(__FUNCTION__, "key_id:         %u", "key_id"));
    mixin (log!(__FUNCTION__, "key_algorithm:  %u", "key_algorithm"));
    mixin (log!(__FUNCTION__, "key_value:      %s", "sc_dump_hex(key_value.ptr, key_value.length)"));
    mixin (log!(__FUNCTION__, "alg_encoding: 0x%X", "encode_key_secret_alg(key_algorithm, key_value.length)"));
    */
    // apdu select path iso_select_file mit Fileangabe wegen NOR and MRL, Prüfen NOR <-> key_id, Prüfen später, ob der benötigte speicherplatz verfügbar
    // check ACL

    command_data[pos++] = 0x80 | key_id; //  Key ID    unblocking info
    command_data[pos++] = 0x00;          //  Key Type  Internal/External or nothing unclear if 0 is valid
    command_data[pos++] = 0xFF;          //  Key Info  counters for error/usage     unclear how to handle for Key Type=0 and if min len is 1 even if not required

    switch (key_algorithm) {
    case SC_ALGORITHM_DES:
    assert(canFind([7,8], key_value.length));
    command_data[pos++] = encode_key_secret_alg(key_algorithm, 8); //  Algorithm Reference==ACOS encoding for the algo
    command_data[pos..pos+8] = (key_value.length==7 ? transform_key_effective_to_DES_cblock_odd_parity(key_value) : key_value[]);
    mixin (log!(__FUNCTION__, "this will be written: %s", "sc_dump_hex(command_data.ptr, command_data.length)"));
    // apdu  Put Key or update record key_id
    // return rv;
    break;

    default:
    break;
    }
    return rv=SC_SUCCESS;
    */
    if ctx_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card_ctx = unsafe { &mut *ctx_ptr };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_store_key_secret\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    0
}


// will be called for both RSA and symmetric key
// does nothing currently, except logging CALLED
/*
 * Generate key
 * @apiNote  The "driving function" for this is: src/pkcs15init/pkcs15-lib.c: sc_pkcs15init_generate_key(arguments),
 *           which calls after completion of generate_key:
 *           update PrKDF entry:
 *           sc_pkcs15_encode_pubkey
 *
 */
extern "C" fn acos5_pkcs15_generate_key(profile_ptr: *mut sc_profile,
                                               p15card_ptr: *mut sc_pkcs15_card,
                                               p15object_ptr: *mut sc_pkcs15_object,
                                               p15pubkey_ptr: *mut sc_pkcs15_pubkey) -> c_int
{ // TODO must handle create RSA key pair  And  generate sym. key !!!!!!
    if profile_ptr.is_null() || p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } ||
       p15object_ptr.is_null() || unsafe { (*p15object_ptr).data.is_null() } || p15pubkey_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
//    let p15card = unsafe { &mut *p15card_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let object_priv = unsafe { &mut *p15object_ptr};
    let key_info_priv = unsafe { &mut *(object_priv.data as *mut sc_pkcs15_prkey_info) };
    let p15pubkey = unsafe { &mut *p15pubkey_ptr };
    let mut rv;// = SC_ERROR_UNKNOWN;
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_generate_key\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    if SC_PKCS15_TYPE_PRKEY_RSA != object_priv.type_ {
        if cfg!(log) {
            wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Failed: Only RSA is supported\0").unwrap());
        }
        return SC_ERROR_NOT_SUPPORTED;
    }
//    let keybits = rsa_modulus_bits_canonical(key_info_priv.modulus_length);
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let mut agc = dp.agc;
//    let is_key_pair_created_and_valid_for_generation = dp.agc.is_key_pair_created_and_valid_for_generation;
    let dp_files_value_ref = &dp.files[&dp.agc.file_id_pub];
    let path_pub = sc_path { type_: SC_PATH_TYPE_PATH, value: dp_files_value_ref.0, len: dp_files_value_ref.1[1] as usize, ..sc_path::default()};
/*
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info_priv.id.value.as_ptr(), key_info_priv.id.len) }, CStr::from_bytes_with_nul(b"key_info_priv.id: %s\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info_priv.usage, CStr::from_bytes_with_nul(b"key_info_priv.usage: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info_priv.access_flags, CStr::from_bytes_with_nul(b"key_info_priv.access_flags: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info_priv.native, CStr::from_bytes_with_nul(b"key_info_priv.native: %d\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info_priv.modulus_length, CStr::from_bytes_with_nul(b"key_info_priv.modulus_length: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, keybits, CStr::from_bytes_with_nul(b"keybits: %zu\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info_priv.path.value.as_ptr(), key_info_priv.path.len) }, CStr::from_bytes_with_nul(b"key_info_priv.path: %s\0").unwrap());

        wr_do_log_t(card_ctx, f_log, line!(), fun, dp.file_id_key_pair_priv, CStr::from_bytes_with_nul(b"dp.file_id_key_pair_priv: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, dp.file_id_key_pair_pub,  CStr::from_bytes_with_nul(b"dp.file_id_key_pair_pub:  0x%X\0").unwrap());
//        wr_do_log_t(card_ctx, f_log, line!(), fun, is_key_pair_created_and_valid_for_generation, CStr::from_bytes_with_nul(b"is_key_pair_created_and_valid_for_generation: %d\0").unwrap());

        wr_do_log_t(card_ctx, f_log, line!(), fun, dp.agc.do_generate_rsa_crt, CStr::from_bytes_with_nul(b"dp.agc.do_generate_rsa_crt: %d\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, dp.do_generate_rsa_add_decrypt, CStr::from_bytes_with_nul(b"dp.do_generate_rsa_add_decrypt: %d\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, dp.do_generate_rsa_standard_pub_exponent, CStr::from_bytes_with_nul(b"dp.do_generate_rsa_standard_pub_exponent: %d\0").unwrap());

        wr_do_log_t(card_ctx, f_log, line!(), fun, p15pubkey.algorithm, CStr::from_bytes_with_nul(b"p15pubkey.algorithm: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, p15pubkey.alg_id,    CStr::from_bytes_with_nul(b"p15pubkey.alg_id:    %p\0").unwrap());
    }
*/
    card.drv_data = Box::into_raw(dp) as *mut c_void;
/*
    if !is_key_pair_created_and_valid_for_generation {
        rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
        if cfg!(log) {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"not allowed due to is_key_pair_created_and_valid_for_generation\0")
                .unwrap().as_ptr(), rv, unsafe { sc_strerror(rv) },
                          CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        }
        return rv;
    }
*/
    //gen_keypair; the data get prepared in acos5_pkcs15_create_key
    rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES, &mut agc as *mut CardCtl_generate_crypt_asym as *mut c_void) };
    if rv != SC_SUCCESS {
        let fmt = CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap();
        if cfg!(log) {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"command 'Generate RSA Key Pair' failed\0").unwrap().as_ptr(), rv, sc_strerror(rv), fmt) };
        }
        return rv;
    }

    let mut key_info_pub = sc_pkcs15_pubkey_info { modulus_length: key_info_priv.modulus_length, path: path_pub, ..sc_pkcs15_pubkey_info::default() };
    let object_pub = sc_pkcs15_object { type_: SC_PKCS15_TYPE_PUBKEY_RSA, data: &mut key_info_pub as *mut sc_pkcs15_pubkey_info as *mut c_void,  ..sc_pkcs15_object::default() };
    let mut p15pubkey2_ptr = null_mut();
    rv = unsafe { sc_pkcs15_read_pubkey(p15card_ptr, &object_pub, &mut p15pubkey2_ptr) };
    if rv != SC_SUCCESS {
        if cfg!(log) {
            unsafe { wr_do_log_sds(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(
                b"sc_pkcs15_read_pubkey failed\0").unwrap().as_ptr(), rv, sc_strerror(rv),
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap()) };
        }
        return rv;
    }
    assert!(!p15pubkey2_ptr.is_null());
    unsafe {
        p15pubkey.algorithm = (*p15pubkey2_ptr).algorithm;
        rv = me_pkcs15_dup_bignum(&mut p15pubkey.u.rsa.modulus,  &(*p15pubkey2_ptr).u.rsa.modulus);
        if rv != SC_SUCCESS { return rv; }
        rv = me_pkcs15_dup_bignum(&mut p15pubkey.u.rsa.exponent, &(*p15pubkey2_ptr).u.rsa.exponent);
        if rv != SC_SUCCESS { return rv; }
        sc_pkcs15_free_pubkey(p15pubkey2_ptr);
    };

    rv = SC_SUCCESS;
    if cfg!(log) {
        wr_do_log_tu(card_ctx, f_log, line!(), fun, rv, unsafe { sc_strerror(rv) }, CStr::from_bytes_with_nul(RETURNING_INT_CSTR).unwrap());
    }
    rv
} // acos5_pkcs15_generate_key


/*
 * Finalize card
 * Ends the initialization phase of the smart card/token
 * (actually this command is currently only for starcos spk 2.3
 * cards).
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:
 */
extern "C" fn acos5_pkcs15_finalize_card(card_ptr: *mut sc_card) -> c_int
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *card_ptr };
    let card_ctx = unsafe { &mut *card.ctx };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_finalize_card\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    SC_SUCCESS
}

/*
 * Create a "pin domain". This is for cards such as
 * the cryptoflex that need to put their pins into
 * separate directories
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_create_pin
 */
/*
 * Delete object
 */
extern "C" fn acos5_pkcs15_delete_object(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
    object_ptr: *mut sc_pkcs15_object, path_ptr: *const sc_path) -> c_int
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } ||
        object_ptr.is_null() ||  path_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let card_ctx = unsafe { &mut *card.ctx };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_delete_object\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    SC_SUCCESS
}

/*
// does nothing currently, except logging CALLED
/* This function shall intercept one call to sc_pkcs15init_update_any_df:
   When a PuKDF shall be updated; anything else shall be passed to sc_pkcs15init_update_any_df directly */
extern "C" fn  acos5_pkcs15_emu_update_any_df(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                 _op: c_uint, _object: *mut sc_pkcs15_object) -> c_int
{ //ops->emu_update_any_df(profile, p15card, SC_AC_OP_CREATE, object);
    if p15card.is_null() || unsafe { (*p15card).card.is_null() || (*(*p15card).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_emu_update_any_df\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }

    SC_SUCCESS
}
*/

/* required for sc_pkcs15init_generate_key in order to do some corrections ref. public ḱey */
/* required for unwrap */
extern "C" fn acos5_pkcs15_emu_store_data(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile,
    object_ptr: *mut sc_pkcs15_object, _der_data: *mut sc_pkcs15_der, path: *mut sc_path) -> c_int
{
    if profile.is_null() || p15card.is_null() || object_ptr.is_null() || unsafe { (*p15card).card.is_null() ||
        (*(*p15card).card).ctx.is_null() || (*object_ptr).data.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card).card };
    let card_ctx = unsafe { &mut *card.ctx };
    let object = unsafe { &mut *object_ptr };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"acos5_pkcs15_emu_store_data\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.type_, CStr::from_bytes_with_nul(b"called for object.type %X\0").unwrap()); // SC_PKCS15_TYPE_PRKEY_RSA / SC_PKCS15_TYPE_PUBKEY_RSA
        if !path.is_null() && unsafe{(*path).len > 0} {
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex((*path).value.as_ptr(), (*path).len) }, CStr::from_bytes_with_nul(b"path: %s\0").unwrap()); // 0
        }
    }
    if SC_PKCS15_TYPE_PUBKEY_RSA == object.type_ {
        let key_info = unsafe { &mut *(object.data as *mut sc_pkcs15_pubkey_info) };
/*
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.label.as_ptr(), CStr::from_bytes_with_nul(b"object.label: %s\0").unwrap()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.flags, CStr::from_bytes_with_nul(b"object.flags: 0x%X\0").unwrap()); // 0x2: SC_PKCS15_CO_FLAG_MODIFIABLE
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.auth_id.len, CStr::from_bytes_with_nul(b"object.auth_id.len: %zu\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.auth_id.value[0], CStr::from_bytes_with_nul(b"object.auth_id.value[0]: %u\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.usage_counter, CStr::from_bytes_with_nul(b"object.usage_counter: %d\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.user_consent, CStr::from_bytes_with_nul(b"object.user_consent: %d\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.access_rules[0].access_mode, CStr::from_bytes_with_nul(b"object.access_rules[0].access_mode: %X\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, object.df, CStr::from_bytes_with_nul(b"object.df: %p\0").unwrap()); // (nil)

        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) }, CStr::from_bytes_with_nul(b"key_info.id: %s\0").unwrap()); // 08
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.usage, CStr::from_bytes_with_nul(b"key_info.usage: 0x%X\0").unwrap()); // 0xD1 SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER | SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_ENCRYPT
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.access_flags, CStr::from_bytes_with_nul(b"key_info.access_flags: 0x%X\0").unwrap()); // 0x0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.native, CStr::from_bytes_with_nul(b"key_info.native: %d\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_reference, CStr::from_bytes_with_nul(b"key_info.key_reference: 0x%X\0").unwrap()); // 0x0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.modulus_length, CStr::from_bytes_with_nul(b"key_info.modulus_length: %zu\0").unwrap()); // 3071
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[0], CStr::from_bytes_with_nul(b"key_info.algo_refs[0]: 0x%X\0").unwrap()); // 0x0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.subject.len, CStr::from_bytes_with_nul(b"key_info.subject.len: %zu\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.params.len, CStr::from_bytes_with_nul(b"key_info.params.len: %zu\0").unwrap()); // 0
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }, CStr::from_bytes_with_nul(b"key_info.path: %s\0").unwrap()); // empty
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.direct.raw.len, CStr::from_bytes_with_nul(b"key_info.direct.raw.len: %zu\0").unwrap()); //  398
        wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.direct.spki.len, CStr::from_bytes_with_nul(b"key_info.direct.spki.len: %zu\0").unwrap()); // 422
        if !arg4.is_null() {
            unsafe {
                wr_do_log_t(card_ctx, f_log, line!(), fun, (*arg4).len, CStr::from_bytes_with_nul(b"der_length: %zu\0").unwrap()); // 398
                (*_der_data).len = 0;
            }
        }
*/
        key_info.modulus_length = rsa_modulus_bits_canonical(key_info.modulus_length);
        key_info.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_LOCAL;
        key_info.native = 1;

        let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        let dp_files_value_ref = &dp.files[&dp.agc.file_id_pub];
//        if dp.agc.is_key_pair_created_and_valid_for_generation {
            key_info.path = sc_path { type_: SC_PATH_TYPE_PATH, value: dp_files_value_ref.0, len: dp_files_value_ref.1[1] as usize, ..sc_path::default()};
//        }
//        dp.agc.is_key_pair_created_and_valid_for_generation = false; // this is the antagonist of: acos5_pkcs15_create_key: dp.is_key_pair_created_and_valid_for_generation = true;
        card.drv_data = Box::into_raw(dp) as *mut c_void;
    }
    else if SC_PKCS15_TYPE_SKEY_GENERIC == object.type_ {
        /* called from unwrapping a RSA_WRAPPED_AES_KEY */
        let key_info = unsafe { &mut *(object.data as *mut sc_pkcs15_skey_info) };
        if cfg!(log) {
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) }, CStr::from_bytes_with_nul(b"key_info.id: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.usage, CStr::from_bytes_with_nul(b"key_info.usage: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.access_flags, CStr::from_bytes_with_nul(b"key_info.access_flags: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.native, CStr::from_bytes_with_nul(b"key_info.native: %d\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_reference, CStr::from_bytes_with_nul(b"key_info.key_reference: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.value_len, CStr::from_bytes_with_nul(b"key_info.value_len: %zu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.key_type, CStr::from_bytes_with_nul(b"key_info.key_type: %zu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[0], CStr::from_bytes_with_nul(b"key_info.algo_refs[0]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[1], CStr::from_bytes_with_nul(b"key_info.algo_refs[1]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, key_info.algo_refs[2], CStr::from_bytes_with_nul(b"key_info.algo_refs[2]: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }, CStr::from_bytes_with_nul(b"key_info.path: %s\0").unwrap());
            if !key_info.data.value.is_null() && key_info.data.len>0 {
                wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(key_info.data.value, key_info.data.len) }, CStr::from_bytes_with_nul(b"key_info.data: %s\0").unwrap());
            }
        }
    }
    SC_SUCCESS
}

/* Not yet ready
 * Diagnostics of card's file system; invoked by acos5_gui and $ pkcs15-init --sanity-check
   @return always SUCCESS ?, but useful only with debug log enabled; search for  sanity_check  there
   Everything in debug_file between lines containing
   update_hashmap: returning
   ...
   acos5_pkcs15_sanity_check: returning
   is relevant as diagnostics


cos5 defines: there must be exactly 1 only security environment file in each directory, referred to by tag 0x8D in directory's header

check, that relevant files are activated (LCSI==5), thus security/access right management in effect
SAC:
check, that the SCB bits are the allowed ones only, see table 25 Security Condition Byte (REF-ACOS5-64-1.07.pdf)
check, that all SCBs used for directory and it's files have a dedicated entry in associated SE file, that they can refer to and
possibly forbid deleting a record in SE file that would lead to a 'dangling pointer'
check, that all those records have an AT CRT (tag 0xA4)
check, that all uses of 0x40 in SCB also have a CCT (tag 0xB4) and/or CT (tag 0xB8) entry in the record pointed to
check, that for AT, CCT and CT, the pins/keys referred to actually do exist
During writing of pin/key file records: make sure, that the parameters given are reasonable (error/retry/usage counters) and
for keys pay attention to the usage (external/internal auth.; only external authentication may authenticate a key) and algo and it's op mode
for the intention in CCT and CT

Remember, that the security is given only for path len max. 10/12? Thus warn about sensitive files that go unprotected

*/
/*
#[allow(dead_code)]
extern "C" fn acos5_pkcs15_sanity_check(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> c_int
{
    if p15card.is_null() || unsafe { (*p15card).card.is_null()} {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let card_ref:         &sc_card = unsafe { &    *(*p15card).card };
    let card_ref_mut: &mut sc_card = unsafe { &mut *(*p15card).card };
    if  card_ref.ctx.is_null() {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let ctx_ref_mut: &mut sc_context = unsafe { &mut *card_ref.ctx };

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_pkcs15_sanity_check\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(CALLED).unwrap();
//  #[cfg(log)] if cfg!(log) {}
    wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);

    /* select MF; if it doesn't exist, there's nothing to check */

    /* fill the hashmap: there are possibly not all scb8 retrieved so far and PKCS#15 file type yet unknown */
    let _dummy = call_dynamic_update_hashmap(card_ref_mut); // all scb8 are complete, same for the byte containing the PKCS#15 file type, i.e. the file really contains content acc. to that file type

//    let ctx  : *mut sc_context = null_mut() as *mut sc_context;
    let info = null_mut() as *mut sm_info;
    let mut out: c_char = 65u8 as c_char;
    let sm_available = false;
/* */
        match call_dynamic_sm_test(ctx_ref_mut, info, &mut out) {
            Ok(val) => { println!("acos5_sm call to test succeeded !"); val==SC_SUCCESS },
            Err(_e) => { println!("acos5_sm call to test didn't succeed !"); false },
        };
/* */
    /* check all, what cos5 requires
       each DF (incl. MF) points to a SE file that does exist
       scb8 <-> SACinfo:  references do exist in SACinfo and there is an AT template included; the AT template refers to pins and sym. keys that do exist

       warn about SCB that are invalid or not yet supported (and/or conditions)
       info if there are SE file records unused so far
    */
    // TODO check data race condition for dp
    let dp = unsafe { Box::from_raw(card_ref.drv_data as *mut DataPrivate) };

//    let mut path3908 = sc_path::default();
    /* DF/MF must point to existing SE-File with correct FDB==0x1C */
    for (key, val) in dp.files.iter() {
        if is_DFMF(val.1[0]) {
            let file_id_se = u16::from_be_bytes([val.1[4], val.1[5]]);
            if file_id_se == 0u16 {
                let fmt   = CStr::from_bytes_with_nul(b"FCI of DF/MF %04X doesn't specify a mandatory SE file (tag 0x8D missing or zero content)\0").unwrap();
//              #[cfg(log)] if cfg!(log) {}
                wr_do_log_t(card_ref.ctx, f_log, line!(), fun, *key as c_uint, fmt);
            }
            else if !dp.files.contains_key(&file_id_se) {
                let fmt   = CStr::from_bytes_with_nul(b"FCI of DF/MF %04X specifies a non-existant, mandatory SE file id (file %04X is missing)\0").unwrap();
//              #[cfg(log)] if cfg!(log) {}
                wr_do_log_tt(card_ref.ctx, f_log, line!(), fun, *key as c_uint, file_id_se as c_uint, fmt);
            }
            else if dp.files[&file_id_se].1[0] != FDB_SE_FILE {
                let fmt   = CStr::from_bytes_with_nul(b"FCI of DF/MF %04X specifies an existant, mandatory SE file id %04X that has incompatible cos5 file type (FDB != 0x1C)\0").unwrap();
//              #[cfg(log)] if cfg!(log) {}
                wr_do_log_tt(card_ref.ctx, f_log, line!(), fun, *key as c_uint, file_id_se as c_uint, fmt);
            }
        }
        if *key == 0x3908u16 {
//            path3908.value = val.0;
//            path3908.len   = val.1[1] as usize;
//            if path3908.len > 2 {
//                path3908.type_ = SC_PATH_TYPE_PATH;
//            }
            if !sm_available {
                if val.2.unwrap()[0] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'read_binary', but the Secure Messaging library doesn't yet exist: Impossible to read that file\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }
                if val.2.unwrap()[1] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'update_binary', but the Secure Messaging library doesn't yet exist: Impossible to modify content of that file\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }


                if val.2.unwrap()[3] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'deactivate_file', but the Secure Messaging library doesn't yet exist: Impossible to deactivate/invalidate that file\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }
                if val.2.unwrap()[4] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'activate_file', but the Secure Messaging library doesn't yet exist: Impossible to activate/rehabilitate that file\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }
                if val.2.unwrap()[5] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'terminate_file', but the Secure Messaging library doesn't yet exist: Impossible to unmodifiably terminate/lock that file\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }
                if val.2.unwrap()[6] & 0x40 > 0 {
                    let format = CStr::from_bytes_with_nul(b"SCB of file %04X enforces SM for 'delete_file', but the Secure Messaging library doesn't yet exist: Impossible to delete that file (except by 'erase_card')\0").unwrap();
//                  #[cfg(log)] if cfg!(log) {}
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, fun.as_ptr(), format.as_ptr(), *key as c_uint) };
                }
            }
        }
    }
    card_ref_mut.drv_data = Box::into_raw(dp) as *mut c_void;


    /*
    warn about non-recommended SCB settings (skip SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE_SELF)
    For each file:
    scb8 checking: collect the SC bytes, that are not 0x00 or 0xFF
    For specific files:
    fdb==FDB_CHV_EF,           SCB[0] should be 0xFF,     SCB[1] should not be 0xFF
    fdb==FDB_SYMMETRIC_KEY_EF, SCB[0] should be 0xFF,     SCB[1] should not be 0xFF
    fdb==FDB_RSA_KEY_EF priv,  SCB[0] should be 0xFF,     SCB[1] should not be 0xFF
    fdb==FDB_SE_FILE,          SCB[0] should not be 0xFF, SCB[1] should not be 0xFF


    warn about non-activated files/dir
    */

/*
if the SM implementing library is available and function test is exported, then assume, that SM is working.
if not, then complain where SCBs use SM
    assert!(!card_ref.driver.is_null());
    let handle = unsafe { (*card_ref.driver).dll }; // void *sc_dlsym(void *handle, const char *symbol)
    assert!(!handle.is_null());
    {
        return dlsym(handle, symbol);
    }
*/

    let fmt   = CStr::from_bytes_with_nul(RETURNING_INT_CSTR).unwrap();
    wr_do_log(card_ref.ctx, f_log, line!(), fun, fmt);

    SC_SUCCESS
} // acos5_pkcs15_sanity_check
*/

/*
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
*/
