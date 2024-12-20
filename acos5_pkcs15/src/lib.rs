/*
 * lib.rs: Driver 'acos5_pkcs15' - main library file
 *
 * Copyright (C) 2019-  Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110  USA
 */

//! This is an optional shared library, meant to be used alongside the driver library from carblue/acos5
//! It provides functions, that OpenSC categorizes within pkcs15init (see opensc_sys::pkcs15_init struct sc_pkcs15init_operations)

//! The bulk of driver functions access a card in a read-only manner, a few only in write-access manner as 'building block' functions:

// TODO the profile related code and scconf wasn't investigated in depth and isn't yet understood well, thus there might
//   be some inconsistency and hard coded content and it's far from being robust concerning users modifying the file
//   acos5_external.profile.

// TODO once I faced an error with EF.PrKDF re-creation after deletion because of some error in function
//   convert_acl_array_to_bytes_tag_fcp_sac
//   match acl_category  ACL_CATEGORY_EF_CHV (for file 0x4110 EF.PrKDF with Nano) =>  SC_AC_OP_INVALIDATE
//   if p_ref.method!=SC_AC_SCB { return Err(-1); }   <== this seems to have broken the re-creation !!!!

// TODO therefore, for the time being be careful about ACL input from .profile and overwrite it, as e.g. the new
//   function my_file_dup does (temporary replacement for sc_file_dup)
//   check usage of me_profile_get_file  and  my_file_dup/sc_file_dup, both in acos5_pkcs15_create_key (and acos5_pkcs15_create_dir)

// TODO acos5_pkcs15_create_key needs to be split and revamped : Far too complex, long, hard to understand
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
        pkcs15init "acos5_external" {
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

#![warn(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::private_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs)]
//#![warn(rustdoc::missing_doc_code_examples)]

#![expect(rustdoc::private_doc_tests)]
#![warn(rustdoc::invalid_codeblock_attributes)]
#![warn(rustdoc::invalid_html_tags)]
#![warn(rustdoc::invalid_rust_codeblocks)]
#![warn(rustdoc::bare_urls)]
#![warn(rustdoc::unescaped_backticks)]
#![warn(rustdoc::redundant_explicit_links)]

#![warn(absolute_paths_not_starting_with_crate)] //    fully qualified paths that start with a module name instead of `crate`, `self`, or an extern crate name
#![warn(ambiguous_negative_literals)] //    ambiguous negative literals operations
//#![warn(closure_returning_async_block)] //     closure that returns `async {}` could be rewritten as an async closure
#![warn(deprecated_in_future)] //     detects use of items that will be deprecated in a future version
#![warn(deprecated_safe_2024)] //     detects unsafe functions being used as safe functions
#![expect(edition_2024_expr_fragment_specifier)] //     The `expr` fragment specifier will accept more expressions in the 2024 edition. To keep the existing behavior, use the `expr_2021` fragment specifier.
#![warn(elided_lifetimes_in_paths)] //     hidden lifetime parameters in types are deprecated
#![warn(explicit_outlives_requirements)] //     outlives requirements can be inferred
#![warn(ffi_unwind_calls)] //     call to foreign functions or function pointers with FFI_unwind ABI
//#![warn(fuzzy_provenance_casts)] //     a fuzzy integer to pointer cast is used

#![warn(impl_trait_overcaptures)] //     `impl Trait` will capture more lifetimes than possibly intended in edition 2024
#![warn(keyword_idents_2018)] //     detects edition keywords being used as an identifier
#![warn(keyword_idents_2024)] //     detects edition keywords being used as an identifier
#![warn(let_underscore_drop)] //     non-binding let on a type that implements `Drop`
//#![warn(lossy_provenance_casts)] //     a lossy pointer to integer cast is used
#![warn(macro_use_extern_crate)] //     the `#[macro_use]` attribute is now deprecated in favor of using macros via the module system
#![warn(meta_variable_misuse)] //     possible meta-variable misuse at macro definition
#![warn(missing_abi)] //     No declared ABI for extern declaration
#![warn(missing_copy_implementations)] //     detects potentially-forgotten implementations of `Copy`
#![warn(missing_debug_implementations)] //     detects missing implementations of Debug
//// #![warn(missing_docs)] //     detects missing documentation for public members
#![warn(missing_unsafe_on_extern)] //     detects missing unsafe keyword on extern declarations
//#![warn(multiple_supertrait_upcastable)] //     detect when an object-safe trait has multiple supertraits
//#![warn(must_not_suspend)] //     use of a `#[must_not_suspend]` value across a yield point
#![warn(non_ascii_idents)] //     detects non-ASCII identifiers
//#![warn(non_exhaustive_omitted_patterns)] //     detect when patterns of types marked `non_exhaustive` are missed
#![warn(non_local_definitions)] //     checks for non-local definitions
#![warn(redundant_imports)] //    imports that are redundant due to being imported already
#![warn(redundant_lifetimes)] //     detects lifetime parameters that are redundant because they are equal to some other named lifetime
#![warn(rust_2021_incompatible_closure_captures)] //     detects closures affected by Rust 2021 changes
#![warn(rust_2021_incompatible_or_patterns)] //     detects usage of old versions of or-patterns
#![warn(rust_2021_prefixes_incompatible_syntax)] //     identifiers that will be parsed as a prefix in Rust 2021
#![warn(rust_2021_prelude_collisions)] //     detects the usage of trait methods which are ambiguous with traits added to the prelude in future editions
//#![warn(rust_2024_incompatible_pat)] //     detects patterns whose meaning will change in Rust 2024
#![warn(rust_2024_prelude_collisions)] //    detects the usage of trait methods which are ambiguous with traits added to the prelude in future editions
#![warn(single_use_lifetimes)] //     detects lifetime parameters that are only used once
#![warn(tail_expr_drop_order)] //    Detect and warn on significant change in drop order in tail expression location
#![warn(trivial_casts)] //     detects trivial casts which could be removed
#![expect(trivial_numeric_casts)] //     detects trivial casts of numeric types which could be removed
#![warn(unit_bindings)] //     binding is useless because it has the unit `()` type
#![expect(unnameable_types)] //     effective visibility of a type is larger than the area in which it can be named
#![expect(unreachable_pub)] //     `pub` items not reachable from crate root
#![warn(unsafe_attr_outside_unsafe)] //     detects unsafe attributes outside of unsafe
#![expect(unsafe_code)] //     usage of `unsafe` code and other potentially unsound constructs
#![warn(unsafe_op_in_unsafe_fn)] //     unsafe operations in unsafe functions without an explicit unsafe block are deprecated
#![warn(unstable_features)] //     enabling unstable features
#![warn(unused_crate_dependencies)] //     crate dependencies that are never used
#![warn(unused_extern_crates)] //     extern crates that are never used
#![warn(unused_import_braces)] //     unnecessary braces around an imported item
#![warn(unused_lifetimes)] //     detects lifetime parameters that are never used
#![expect(unused_macro_rules)] //     detects macro rules that were not used
#![warn(unused_qualifications)] //     detects unnecessarily qualified names
#![warn(unused_results)] //     unused result of an expression in a statement
#![warn(variant_size_differences)] //     detects enums with widely varying variant sizes

#![warn(clippy::all)]
#![warn(clippy::pedantic)]

#![expect(unused_macros)]  // unused macro definition: `log3ift`
#![warn(clippy::doc_lazy_continuation)]
#![warn(clippy::doc_markdown)]
#![warn(clippy::similar_names)]
#![warn(clippy::too_many_arguments)]
#![warn(clippy::too_many_lines)]

use libc::free; // strlen
//use pkcs11::types::{CKM_DES_ECB, CKM_DES3_ECB, CKM_AES_ECB};

use std::os::raw::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::ptr::{null_mut, from_mut};
use std::slice::from_raw_parts;
use function_name::named;
use opensc_sys::opensc::{/*sc_context,*/ sc_card, sc_select_file, sc_card_ctl, SC_ALGORITHM_DES,
                         SC_ALGORITHM_3DES, SC_ALGORITHM_AES, sc_card_find_rsa_alg, sc_file_new, sc_transmit_apdu,
                         sc_file_dup, sc_delete_file, sc_check_sw, sc_update_record, SC_RECORD_BY_REC_NR, sc_get_version};

use opensc_sys::profile::sc_profile;
use opensc_sys::pkcs15::{sc_pkcs15_card, sc_pkcs15_object, sc_pkcs15_prkey, sc_pkcs15_pubkey, sc_pkcs15_skey_info,
                         SC_PKCS15_TYPE_SKEY_DES/*, SC_PKCS15_TYPE_SKEY_2DES*/, SC_PKCS15_TYPE_SKEY_3DES, SC_PKCS15_TYPE_SKEY_GENERIC,
                         sc_pkcs15_prkey_info, sc_pkcs15_pubkey_info, SC_PKCS15_TYPE_PRKEY_EC, //sc_pkcs15_prkey_rsa,
                         SC_PKCS15_TYPE_PRKEY_RSA, SC_PKCS15_TYPE_PUBKEY_RSA, sc_pkcs15_auth_info, //sc_pkcs15_id,
                         SC_PKCS15_PRKDF, SC_PKCS15_PUKDF, SC_PKCS15_SKDF, SC_PKCS15_CDF, SC_PKCS15_CDF_TRUSTED,
                         SC_PKCS15_DODF, sc_pkcs15_read_pubkey, sc_pkcs15_free_pubkey, sc_pkcs15_der,
                         SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE, SC_PKCS15_TYPE_PUBKEY_EC,
                         SC_PKCS15_PRKEY_USAGE_SIGN, SC_PKCS15_PRKEY_USAGE_DECRYPT, SC_PKCS15_TYPE_CLASS_MASK, SC_PKCS15_TYPE_SKEY,
                         SC_PKCS15_PRKEY_ACCESS_SENSITIVE, SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE,
                         SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE, SC_PKCS15_PRKEY_ACCESS_LOCAL, SC_PKCS15_TYPE_PRKEY
};
//, sc_pkcs15_bignum, sc_pkcs15_pubkey_rsa
use opensc_sys::pkcs15_init::{sc_pkcs15init_operations, sc_pkcs15init_authenticate/*, sc_pkcs15init_pubkeyargs*/};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_KEYPAD_MSG_TOO_LONG, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED,
                         SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_NOT_SUPPORTED, /*SC_ERROR_NON_UNIQUE_ID,*/
                         SC_ERROR_INCONSISTENT_PROFILE, SC_ERROR_OUT_OF_MEMORY, SC_ERROR_FILE_NOT_FOUND
                         //, SC_ERROR_NOT_IMPLEMENTED, SC_ERROR_FILE_ALREADY_EXISTS
                         //,SC_ERROR_INCONSISTENT_CONFIGURATION, SC_ERROR_UNKNOWN, SC_ERROR_FILE_NOT_FOUND
};
//use opensc_sys::sm::{sm_info};
use opensc_sys::types::{sc_file, sc_path, SC_AC_OP_CREATE_EF, SC_AC_OP_DELETE, SC_AC_OP_READ, SC_AC_OP_DELETE_SELF,//SC_AC_OP_DELETE_SELF, SC_FILE_TYPE_INTERNAL_EF,
                        SC_AC_OP_UPDATE, SC_APDU_CASE_1/*, SC_APDU_CASE_3*/, SC_PATH_TYPE_PATH, sc_acl_entry};
// SC_FILE_EF_TRANSPARENT, SC_FILE_STATUS_CREATION, SC_MAX_PATH_SIZE,  SC_PATH_TYPE_FILE_ID, SC_AC_OP_DELETE
//use opensc_sys::types::{/*SC_MAX_CRTS_IN_SE, sc_crt*/};
use opensc_sys::log::sc_dump_hex; /*sc_do_log, SC_LOG_DEBUG_NORMAL,*/


#[macro_use]
pub mod    macros; // shared file among modules acos5, acos5_pkcs15

pub mod    constants_types; // shared file among modules acos5, acos5_pkcs15
use crate::constants_types::{CARD_DRV_SHORT_NAME, DataPrivate, SC_CARDCTL_ACOS5_SDO_CREATE,
                             SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES, SC_CARD_TYPE_ACOS5_64_V3, build_apdu,
                             SC_CARDCTL_ACOS5_SANITY_CHECK, GuardFile, file_id_from_path_value,
                             SC_CARD_TYPE_ACOS5_EVO_V4};

pub mod    missing_exports; // this is NOT the same as in acos5
use crate::missing_exports::{me_profile_get_file, me_pkcs15_dup_bignum/*, my_file_dup*/};

pub mod    no_cdecl; // this is NOT the same as in acos5
use crate::no_cdecl::{rsa_modulus_bits_canonical, first_of_free_indices, construct_sym_key_entry, free_fid_asym}; /*call_dynamic_update_hashmap, call_dynamic_sm_test,*/

#[cfg(not(target_os = "windows"))]
use crate::no_cdecl::check_enlarge_prkdf_pukdf;

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        mod tasn1_pkcs15_util; // shared file among modules acos5, acos5_pkcs15
        mod tasn1_sys;         // shared file among modules acos5, acos5_pkcs15
    }
}

pub mod    wrappers; // shared file among modules acos5, acos5_pkcs15
use crate::wrappers::{wr_do_log, wr_do_log_rv, wr_do_log_sds, wr_do_log_t, wr_do_log_tu};


const BOTH : u32 = SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT;

/// A mandatory library export  It MUST BE identical for acos5 and acos5_pkcs15
///
/// @apiNote
/// If @return doesn't match the version of OpenSC binary libopensc.so/dll installed, then this library
/// will be rejected/unloaded immediately by OpenSC; depends on build.rs setup ref. "cargo:rustc-cfg=v0_??_0".
///
/// Its essential, that this doesn't merely echo, what a call to `sc_get_version` reports:
/// Its my/developers statement, that the support as reported by sc_driver_version got checked !
/// Thus, if e.g. a new OpenSC version 0.22.0 got released and if I didn't reflect that in sc_driver_version,
/// (updating opensc-sys binding and code of acos5 and acos5_pkcs15),
/// then the driver won't accidentally malfunction for a not yet supported OpenSC environment/version !
///
/// The support of not yet released OpenSC code (i.e. github/master) is somewhat experimental:
/// Its accuracy depends on how closely the opensc-sys binding and driver code has covered the possible
/// differences in API and behavior (this function mentions the last OpenSC commit covered).
/// master will be handled as an imaginary new version release:
/// E.g. while currently the latest release is 0.22.0, build OpenSC from source such that it reports imaginary
/// version 0.23.0 (change configure.ac; define(\[PACKAGE_VERSION_MINOR\], \[23\]) )
/// In this example, cfg!(v0_23_0) will then match that
///
/// @return   The OpenSC release/imaginary version, that this driver implementation supports
#[unsafe(no_mangle)]
pub extern "C" fn sc_driver_version() -> *const c_char {
    let version_ptr = sc_get_version();
    if cfg!(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1, v0_26_0/*, v0_27_0*/))  { version_ptr }
    // v0_27_0: experimental only:  Latest OpenSC gitHub master commit covered: 21ba386
    else  { c"0.0.0".as_ptr() } // will definitely cause rejection by OpenSC
}

///
/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sc_module_init(name: *const c_char) -> *mut c_void {
    if !name.is_null() && unsafe { CStr::from_ptr(name) } == CARD_DRV_SHORT_NAME {
        acos5_get_pkcs15init_ops as *mut c_void
    }
    else {
        null_mut()
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
        select_pin_reference : None, //Some(acos5_pkcs15_select_pin_reference), // does nothing
        create_pin : None, //Some(acos5_pkcs15_create_pin), // does nothing
        select_key_reference : None, // called only from src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_init_prkdf
        /* create_key :
           For generate_key (RSA) this does all of the required work before calling generate_key
         */
        create_key : Some(acos5_pkcs15_create_key),
        store_key  : Some(acos5_pkcs15_store_key),
        generate_key : Some(acos5_pkcs15_generate_key),
        encode_private_key : None, // doesn't get called by OpenSC
        encode_public_key  : None, // doesn't get called by OpenSC
        finalize_card : None, //Some(acos5_pkcs15_finalize_card), // does nothing // probably not required for ACOS5; called only from src/pkcs15init/pkcs15-lib.c:sc_pkcs15init_finalize_card
        delete_object : None, //Some(acos5_pkcs15_delete_object), // does nothing
        // how about the emu support at all? is that required? What exactly is that?
        emu_update_dir : None,
        emu_update_any_df : None,// : Some(acos5_pkcs15_emu_update_any_df), // does nothing
        emu_update_tokeninfo : None,
        emu_write_info : None,
        emu_store_data : Some(acos5_pkcs15_emu_store_data), // interceptor to correct/set data for SC_PKCS15_TYPE_PUBKEY_RSA
        /* there are rare OpenSC uses currently */
        sanity_check : Some(acos5_pkcs15_sanity_check),
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
#[named]
extern "C" fn acos5_pkcs15_erase_card(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card) -> i32
{
    if profile_ptr.is_null() || p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card_ptr).card };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    let mut rv;
    {
        let mut file = sc_file_new();
        let guard_file = GuardFile::new(&mut file);
        unsafe { (*file).path = sc_path { value: [0x3F,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], len: 2, ..sc_path::default() } };
        /* Authenticate arbitrary op that's protected by SOPIN */
        rv = unsafe { sc_pkcs15init_authenticate(profile_ptr, p15card_ptr, **guard_file, i32::try_from(SC_AC_OP_DELETE).unwrap()) };
    }
    if rv < 0 {
        log3ifr!(ctx,f,line!(), c"SOPIN verification failed", rv);
        return rv;
    }

    let mut apdu = build_apdu(ctx, &[0x80, 0x30, 0, 0], SC_APDU_CASE_1, &mut[]);
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), c"Error: ### Impossible to Zeroize Card User Data ###");
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
//    log3if!(ctx,f,line!(), c"Ready to erase card's content");
    rv
}


/*
 * Create a DF
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app  and  sc_pkcs15_create_pin_domain
 */
#[allow(dead_code)]  // no usage currently
#[cold]
#[named]
extern "C" fn acos5_pkcs15_create_dir(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                      df_ptr: *mut sc_file) -> i32
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || df_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let ctx = unsafe { &mut *card.ctx };
    let df = unsafe { & *df_ptr };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), c"called  with df.id %X", df.id);

    let create_dfs = [(SC_PKCS15_PRKDF, c"PKCS15-PrKDF"), (SC_PKCS15_PUKDF, c"PKCS15-PuKDF"),
                      (SC_PKCS15_SKDF, c"PKCS15-SKDF"),   (SC_PKCS15_DODF, c"PKCS15-DODF"),
                      (SC_PKCS15_CDF, c"PKCS15-CDF"),     (SC_PKCS15_CDF_TRUSTED, c"PKCS15-CDF-TRUSTED")];

    if df.id == /* 0x4100 0x5015*/ 0x4100_i32 {
        log3if!(ctx,f,line!(), c"Select (%X)", df.id);
        let mut rv = unsafe { sc_select_file(card, &df.path, null_mut()) };
        assert_eq!(SC_SUCCESS, rv);

        for (_key,value) in &create_dfs {
            log3if!(ctx,f,line!(), c"Create '%s'", value.as_ptr());

            let mut file = null_mut();
            let guard_file = GuardFile::new(&mut file);
            rv = me_profile_get_file(profile, value.as_ptr(), *guard_file);
            if rv != SC_SUCCESS {
                log3if!(ctx,f,line!(), c"Inconsistent profile: cannot find %s", value.as_ptr());
                return SC_ERROR_INCONSISTENT_PROFILE;//LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
            }
//            rv = sc_pkcs15init_add_object(p15card, profile_ptr, create_dfs_val[ii], NULL);

//pub fn me_pkcs15init_add_object(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile, arg2: u32, arg3: *mut sc_pkcs15_object) -> i32;

//            if (rv != SC_ERROR_FILE_ALREADY_EXISTS)
//                LOG_TEST_RET(ctx, rv, "Failed to create MyEID xDF file");
        }
    }

//    LOG_FUNC_RETURN(p15card.card.ctx, rv);

    SC_SUCCESS
} // acos5_pkcs15_create_dir


/*
 * Select a PIN reference
 *
 * Called only from   src/pkcs15init/pkcs15-lib.c:  sc_pkcs15init_add_app  and  sc_pkcs15init_create_pin
 */
#[allow(dead_code)]  // no usage currently
#[cold]
#[named]
extern "C" fn acos5_pkcs15_select_pin_reference(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                                pin_ainfo_ptr: *mut sc_pkcs15_auth_info) -> i32
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null()  || (*(*p15card_ptr).card).ctx.is_null() } || pin_ainfo_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx, f, line!());
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
#[allow(dead_code)]  // no usage currently
#[cold]
#[named]
extern "C" fn acos5_pkcs15_create_pin(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                      file_ptr: *mut sc_file,
                                      _object_ptr: *mut sc_pkcs15_object, _arg5: *const u8, _arg6: usize,
                                      _arg7: *const u8, _arg8: usize) -> i32
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } || file_ptr.is_null()  {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx, f, line!());
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
///
/// # Panics
#[named]
extern "C" fn acos5_pkcs15_create_key(profile_ptr: *mut sc_profile,
                                      p15card_ptr: *mut sc_pkcs15_card,
                                      object_ptr: *mut sc_pkcs15_object) -> i32
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
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), c"called with object_ptr: %p", object_ptr);

    if profile_ptr.is_null() || object_ptr.is_null() || unsafe { (*object_ptr).data.is_null() } {
        log3if!(ctx,f,line!(), c"called with profile_ptr: %p, object_ptr: %p", profile_ptr, object_ptr);
        if !object_ptr.is_null() {
            log3if!(ctx,f,line!(), c"called with object.data: %p", unsafe { (*object_ptr).data });
        }
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let profile = unsafe { &mut *profile_ptr };
    let object = unsafe { &mut *object_ptr };
    let mut rv;
    log3if!(ctx,f,line!(), c"object.type: %X  (SC_PKCS15_TYPE_PRKEY_EC = 0x104;)", object.type_);
// println!("acos5_pkcs15_create_key, object: {:X?}", *object);
    let object_class = object.type_ & SC_PKCS15_TYPE_CLASS_MASK;
    if SC_PKCS15_TYPE_SKEY == object_class {
        log3if!(ctx,f,line!(),c"Currently we won't create any sym. secret key file, but presume that it exists already");
        return SC_SUCCESS;
    }


    let (ax, ay) = match free_fid_asym(p15card) {
        Ok((ax, ay)) => (ax, ay),
        Err(e) => return e,
    };
    assert_eq!(SC_PKCS15_TYPE_PRKEY, object_class);
    let key_info = unsafe { &mut *object.data.cast::<sc_pkcs15_prkey_info>() };
    if ![SC_PKCS15_TYPE_PRKEY_RSA, SC_PKCS15_TYPE_PRKEY_EC].contains(&object.type_) ||
        (key_info.usage & (SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT)) == 0 {
        log3if!(ctx,f,line!(), c"Failed: Only RSA and ECC is supported");
        return SC_ERROR_NOT_SUPPORTED;
    }
    let keybits : usize;
    if SC_PKCS15_TYPE_PRKEY_RSA == object.type_ {
        key_info.modulus_length = rsa_modulus_bits_canonical(key_info.modulus_length);

        keybits = key_info.modulus_length;
        if !(512..=4096).contains(&keybits) || (keybits % 256) > 0 {
            rv = SC_ERROR_INVALID_ARGUMENTS;
            log3ifr!(ctx,f,line!(), c"Invalid RSA modulus size requested", rv);
            return rv;
        }
        /* Check that the card supports the requested modulus length */
//    if cfg!(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))
        unsafe { cfg_if::cfg_if! {
            if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
        if sc_card_find_rsa_alg(card, u32::try_from(keybits).unwrap()).is_null() {
            rv = SC_ERROR_INVALID_ARGUMENTS;
            log3if!(ctx,f,line!(), c"Failed: Unsupported RSA key size %zu", keybits);
            return rv;
        }
            }
            else {
                if sc_card_find_rsa_alg(card, keybits).is_null() {
                    rv = SC_ERROR_INVALID_ARGUMENTS;
                    log3if!(ctx,f,line!(), c"Failed: Unsupported RSA key size %zu", keybits);
                    return rv;
                }
            }
        }}
    }
    else /*SC_PKCS15_TYPE_PRKEY_EC == object.type_*/ {
        keybits = 0;
        //rv = SC_ERROR_INVALID_ARGUMENTS;
        //return log3ifr_ret!(ctx,f,line!(), c"Error: EC key pair creation not yet supported by driver", rv);
    }

    /* TODO Think about other checks or possibly refuse to generate keys if file access rights are wrong */
/* */
    /* enlarge EF.PrKDF, EF.PuKDF, if required AND check for enough memory available */
    #[cfg(not(target_os = "windows"))]
    {
        if object.session_object == 0 {
            match check_enlarge_prkdf_pukdf(profile, p15card, key_info) {
                Ok(_val) => (),
                Err(e) => return e,
            }
        }
    }
/* */
    key_info.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE |
                            SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE |
                            SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE |
                            SC_PKCS15_PRKEY_ACCESS_LOCAL;

/* * /
    if !profile.name.is_null() {
        log3if!(ctx,f,line!(), c"profile.name: %s",       profile.name);
    }
    if !profile.options[0].is_null() {
        log3if!(ctx,f,line!(), c"profile.options[0]: %s", profile.options[0]);
    }
    if !profile.options[1].is_null() {
        log3if!(ctx,f,line!(), c"profile.options[1]: %s", profile.options[1]);
    }
/* */
    let mut elem = profile.df_info;
    while !elem.is_null() {
        let df_info = unsafe { & *elem };
        if !df_info.file.is_null() {
            let file_ref = unsafe { & *df_info.file };
            log3if!(ctx,f,line!(), c"df_info file_ref.path: %s", unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) });
            log3if!(ctx,f,line!(), c"df_info file_ref.type: 0x%X", file_ref.type_);
            log3if!(ctx,f,line!(), c"df_info file_ref.id:   0x%X", file_ref.id);
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
            log3if!(ctx,f,line!(), c"ef_list file_ref.path: %s", unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) });
            log3if!(ctx,f,line!(), c"ef_list file_ref.type: 0x%X", file_ref.type_);
            log3if!(ctx,f,line!(), c"ef_list file_ref.id:   0x%X", file_ref.id);
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
                log3if!(ctx,f,line!(), c"template_list_file file_ref.path: %s",
                    unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) });
                log3if!(ctx,f,line!(), c"template_list_file file_ref.type: 0x%X", file_ref.type_);
                log3if!(ctx,f,line!(), c"template_list_file file_ref.id:   0x%X", file_ref.id);
            }
            elem = unsafe { (*elem).next };
        }
    }
/ * */
/* * /
    log3if!(ctx,f,line!(), c"profile.id_style: %u", profile.id_style);
    log3if!(ctx,f,line!(), c"object.type: 0x%X",  object.type_); // pub const SC_PKCS15_TYPE_PRKEY_RSA        : u32 =  0x101;
    log3if!(ctx,f,line!(), c"object.label: %s",   object.label.as_ptr()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
    log3if!(ctx,f,line!(), c"object.flags: 0x%X", object.flags); // 3: SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE ??
    log3if!(ctx,f,line!(), c"object.auth_id.len: %zu",     object.auth_id.len); // 1
    log3if!(ctx,f,line!(), c"object.auth_id.value[0]: %u", object.auth_id.value[0]); // 1
    log3if!(ctx,f,line!(), c"object.usage_counter: %d",    object.usage_counter); // 1
    log3if!(ctx,f,line!(), c"object.user_consent: %d",     object.user_consent); // 1
    log3if!(ctx,f,line!(), c"object.access_rules[0].access_mode: %X", object.access_rules[0].access_mode); // 1
    log3if!(ctx,f,line!(), c"object.df: %p",               object.df); // 1
    log3if!(ctx,f,line!(), c"key_info.id: %s", unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) });
    log3if!(ctx,f,line!(), c"key_info.usage: 0x%X",         key_info.usage); // 46 SC_PKCS15_PRKEY_USAGE_UNWRAP | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER | SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_DECRYPT
    log3if!(ctx,f,line!(), c"key_info.access_flags: 0x%X",  key_info.access_flags); // 29  SC_PKCS15_PRKEY_ACCESS_LOCAL | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_SENSITIVE
    log3if!(ctx,f,line!(), c"key_info.native: %d",          key_info.native); // 1
    log3if!(ctx,f,line!(), c"key_info.key_reference: 0x%X", key_info.key_reference); // 0
    log3if!(ctx,f,line!(), c"key_info.modulus_length: %zu", key_info.modulus_length); // 3072
    log3if!(ctx,f,line!(), c"key_info.algo_refs[0]: 0x%X",  key_info.algo_refs[0]); // 0
    log3if!(ctx,f,line!(), c"key_info.subject.len: %zu",    key_info.subject.len); // 0
    log3if!(ctx,f,line!(), c"key_info.params.len: %zu",     key_info.params.len); // 0
    log3if!(ctx,f,line!(), c"key_info.path: %s",
        unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }); // 3F00410041F5
/ * */
    let mut file_priv = null_mut();
    let guard_file_priv = GuardFile::new(&mut file_priv);
    rv = me_profile_get_file(profile, c"template-private-key".as_ptr(), *guard_file_priv);
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), c"Inconsistent profile: cannot find %s", c"private-key".as_ptr());
        return SC_ERROR_INCONSISTENT_PROFILE;//LOG_FUNC_RETURN(ctx, SC_ERROR_INCONSISTENT_PROFILE);
    }
    assert!(!file_priv.is_null());
    let file_priv = unsafe { &mut *file_priv };
    assert_eq!(file_priv.path.type_, SC_PATH_TYPE_PATH);
    assert!(file_priv.path.len >= 4 && file_priv.path.len<=16);
//file_priv.acl[SC_AC_OP_READ as usize] = 0x1 as *mut sc_acl_entry;
//println!("file_priv: {:02X?}", *file_priv);
    assert_eq!(file_priv.acl[SC_AC_OP_READ as usize], 0x1 as *mut sc_acl_entry); // NEVER allowed to be read
    assert_eq!(file_priv.path.len, key_info.path.len+2);
//println!("file_priv: {:02X?}", *file_priv);
//println!("key_info:  {:02X?}", *key_info);
/* */
    assert!(!ctx.app_name.is_null());
    let app_name = unsafe { CStr::from_ptr(ctx.app_name) }; // app_name: "pkcs15-init"
//    println!("app_name: {:?}", app_name);
//
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if app_name == c"acos5_gui " {
        dp.agc.do_create_files = dp.agi.do_create_files;
//      if !dp.agc.do_create_files && dp.agi.file_id_priv!=0 && dp.agi.file_id_pub!=0 {}
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
    file_priv.size =
        if SC_PKCS15_TYPE_PRKEY_RSA == object.type_
             { 5 + keybits/16 * if dp.agc.do_generate_rsa_crt {5} else {2} }
        else { 71 };
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
//
    if !file_priv.prop_attr.is_null() {
        unsafe { free(file_priv.prop_attr.cast::<c_void>()) }; // file->prop_attr = malloc(len);
        file_priv.prop_attr = null_mut();
    }

    /* The following is the possible starting value for key priv file path */
    file_priv.path.value[file_priv.path.len-2] = file_priv.path.value[file_priv.path.len-4];
//    let mut fid_priv_possible : HashSet<u16> = HashSet::with_capacity(0x30);
//    let mut fid_pub_possible  : HashSet<u16> = HashSet::with_capacity(0x30);
    {
//        let fid = u16::from_be_bytes([file_priv.path.value[file_priv.path.len-2], file_priv.path.value[file_priv.path.len-1]]);
log3if!(ctx,f,line!(), c"file_priv.path: %s",
    unsafe { sc_dump_hex(file_priv.path.value.as_ptr(), file_priv.path.len) });
//        for i in 0..0x30 { fid_priv_possible.insert(fid+i); }
//        for i in 0..0x30 { fid_pub_possible.insert( fid+i +0x30); }
    }
/*
    /* examine existing key priv file path */
    let mut _cnt_priv = 0_u8;
    let mut p15obj_list_ptr = p15card.obj_list;
    while !p15obj_list_ptr.is_null() {
        let p15obj = unsafe { &*p15obj_list_ptr };
        if SC_PKCS15_TYPE_PRKEY_RSA == p15obj.type_ && !p15obj.df.is_null() {
/* * /
            log3if!(ctx,f,line!(), c"");
            log3if!(ctx,f,line!(), c"p15obj.type_: %X",   p15obj.type_);
            log3if!(ctx,f,line!(), c"p15obj.label: %s",   p15obj.label.as_ptr()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
            log3if!(ctx,f,line!(), c"p15obj.flags: 0x%X", p15obj.flags); // 3: SC_PKCS15_CO_FLAG_PRIVATE | SC_PKCS15_CO_FLAG_MODIFIABLE ??
            log3if!(ctx,f,line!(), c"p15obj.auth_id.len: %zu",     p15obj.auth_id.len); // 1
            log3if!(ctx,f,line!(), c"p15obj.auth_id.value[0]: %u", p15obj.auth_id.value[0]); // 1
            log3if!(ctx,f,line!(), c"p15obj.usage_counter: %d",    p15obj.usage_counter); // 1
            log3if!(ctx,f,line!(), c"p15obj.user_consent: %d",     p15obj.user_consent); // 1
            log3if!(ctx,f,line!(), c"p15obj.access_rules[0].access_mode: %X", p15obj.access_rules[0].access_mode); // 1
            log3if!(ctx,f,line!(), c"p15obj.df: %p",               p15obj.df); // 1
            log3if!(ctx,f,line!(), c"p15obj.session_object: %d",   p15obj.session_object); // 1
/ * */
            _cnt_priv += 1;
            assert!(!p15obj.data.is_null());
//            let p15obj_prkey_info_path = & unsafe { &mut *(p15obj.data as *mut sc_pkcs15_prkey_info) }.path;
//            log3if!(ctx,f,line!(), c"p15obj_prkey_info_path: %s",
//                unsafe { sc_dump_hex(p15obj_prkey_info_path.value.as_ptr(), p15obj_prkey_info_path.len) });
//            let fid_priv_used = u16::from_be_bytes([p15obj_prkey_info_path.value[p15obj_prkey_info_path.len-2],
//                                                    p15obj_prkey_info_path.value[p15obj_prkey_info_path.len-1]]);
//            fid_priv_possible.remove(&fid_priv_used);
//            fid_pub_possible.remove(&fid_priv_used);
        }
        p15obj_list_ptr = p15obj.next;
    }
*/
//    let mut fid_priv_possible_min = 0xFFFF_u16;
//    for elem in &fid_priv_possible {
//        if *elem < fid_priv_possible_min && fid_pub_possible.contains(&(*elem+0x30)) { fid_priv_possible_min = *elem; }
//    }

//    println!("fid_priv_possible.len(): {}", fid_priv_possible.len());
//    println!("fid_publ_possible.len(): {}", fid_pub_possible.len());
//    println!("fid_priv_existing.len(): {}", _cnt_priv);
//    if fid_priv_possible_min == 0xFFFF {
//        println!("The maximum of 48 RSA key pairs is exceeded. First delete one for a free file id slot");
//        rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
//        log3ifr!(ctx,f,line!(),
//            b"### The maximum of 48 RSA key pairs is exceeded. First delete one for a free file id slot ###", rv);
//        return rv;
//    }
    #[cfg(key_gen_verbose)]
    { println!("This file id will be chosen for the private RSA key:  {ax:X}"); }
    /* The final values for path and fid_priv */
    // file_priv.path.value[file_priv.path.len-1] = u8::try_from(fid_priv_possible_min & 0x00FF).unwrap();
    file_priv.path.value[file_priv.path.len-2..file_priv.path.len].copy_from_slice(&ax.to_be_bytes());
    file_priv.id = i32::from(file_id_from_path_value(&file_priv.path.value[..file_priv.path.len]));
    log3if!(ctx,f,line!(), c"file_priv.path: %s",
        unsafe { sc_dump_hex(file_priv.path.value.as_ptr(), file_priv.path.len) });
    log3if!(ctx,f,line!(), c"file_priv.id: %X", file_priv.id);
//
/*
    unsafe { copy_nonoverlapping((u16::try_from(file_priv.id).unwrap()).to_be_bytes().as_ptr(),
                                 key_info.path.value.as_mut_ptr().add(key_info.path.len), 2); }
*/
    key_info.path.value[key_info.path.len..key_info.path.len+2].copy_from_slice
        (&(u16::try_from(file_priv.id).unwrap()).to_be_bytes());
    key_info.path.len += 2;
    key_info.path.type_ = SC_PATH_TYPE_PATH;
    assert_eq!(key_info.path.value, file_priv.path.value);

    let mut file_pub = null_mut();
    let guard_file_pub = GuardFile::new(&mut file_pub);
    unsafe { sc_file_dup(*guard_file_pub, file_priv) };
    // unsafe { my_file_dup(&mut **guard_file_pub, file_priv) };
    if file_pub.is_null() {
        return SC_ERROR_OUT_OF_MEMORY;
    }
    let file_pub = unsafe { &mut *file_pub };
    file_pub.size =
        if SC_PKCS15_TYPE_PRKEY_RSA == object.type_
             { 21 + keybits/8 }
        else { 72 };
    // file_pub.path.value[file_pub.path.len-1] += 0x30;
    file_pub.path.value[file_pub.path.len-2..file_pub.path.len].copy_from_slice(&ay.to_be_bytes());
    file_pub.id = i32::from(file_id_from_path_value(&file_pub.path.value[..file_pub.path.len]));
    #[cfg(key_gen_verbose)]
    { println!("This file id will be chosen for the public  RSA key:  {:X}", file_pub.id); }
    if app_name == c"acos5_gui " {
        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        dp.agi.file_id_priv = u16::try_from(file_priv.id).unwrap();
        dp.agi.file_id_pub  = u16::try_from(file_pub.id).unwrap();
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
    }
    // TODO don't leak old file_pub.acl[SC_AC_OP_READ]
    file_pub.acl[SC_AC_OP_READ as usize] = 0x2 as *mut sc_acl_entry; // ALWAYS allowed to be read
//println!("file_pub: {:02X?}", *file_pub);
//println!("key_info: {:02X?}", *key_info);

    let file_priv_has_to_be_deleted = if do_create_files {SC_SUCCESS == unsafe{sc_select_file(card, &file_priv.path, null_mut())}} else {false};
    let file_pub_has_to_be_deleted  = if do_create_files {SC_SUCCESS == unsafe{sc_select_file(card,  &file_pub.path, null_mut())}} else {false};

    /* delete potentially existing file with file_id of file_priv in card's file system */
    #[allow(non_snake_case)]
    let pathDFparent = sc_path { len: file_priv.path.len-2, ..file_priv.path };
    #[allow(non_snake_case)]
    let mut fileDFparent = null_mut();
    #[allow(non_snake_case)]
    let guard_fileDFparent = GuardFile::new(&mut fileDFparent);
    rv = unsafe { sc_select_file(card, &pathDFparent, *guard_fileDFparent) };
    if rv < 0 {
        log3ifr!(ctx,f,line!(), c"DF for the private objects not defined", rv);
        return rv;
    }

    if do_create_files {
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, fileDFparent, i32::try_from(SC_AC_OP_CREATE_EF).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"SC_AC_OP_CREATE_EF authentication failed for parent DF", rv);
            return rv;
        }
        if file_priv_has_to_be_deleted || file_pub_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, fileDFparent, i32::try_from(SC_AC_OP_DELETE).unwrap()) };
            if rv < 0 {
                log3ifr!(ctx,f,line!(), c"SC_AC_OP_CREATE_EF authentication failed for parent DF", rv);
                return rv;
            }
        }
        if file_priv_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, i32::try_from(SC_AC_OP_DELETE_SELF).unwrap()) };
            if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_delete_file(card, &file_priv.path) };
            if rv != SC_SUCCESS { return rv; }
        }
        if file_pub_has_to_be_deleted {
            rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, i32::try_from(SC_AC_OP_DELETE_SELF).unwrap()) };
            if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_delete_file(card, &file_pub.path) };
            if rv != SC_SUCCESS { return rv; }
        }
    }

    /* actual file creation on card */
/* */
    if do_create_files {
        rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_CREATE, (from_mut::<sc_file>(file_priv)).cast::<c_void>()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"create file_priv failed", rv);
            return rv;
        }
        rv = unsafe { sc_select_file(card, &file_priv.path, null_mut()) };
        if rv != SC_SUCCESS {
            return rv;
        }
        let mut apdu = build_apdu(ctx, &[0x00, 0x44, 0x00, 0x00], SC_APDU_CASE_1, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
        if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
            let fmt = c"sc_transmit_apdu failed or ### File Activation failed for private key ###";
            log3if!(ctx,f,line!(), fmt);
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }

        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, i32::try_from(SC_AC_OP_UPDATE).unwrap()) };
        if rv != SC_SUCCESS { return rv; }

        rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_CREATE, (from_mut::<sc_file>(file_pub)).cast::<c_void>()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"create file_pub failed", rv);
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
            let fmt = c"sc_transmit_apdu failed or ### File Activation failed for public key ###";
            log3if!(ctx,f,line!(), fmt);
            return SC_ERROR_KEYPAD_MSG_TOO_LONG;
        }

        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, i32::try_from(SC_AC_OP_UPDATE).unwrap()) };
        if rv != SC_SUCCESS { return rv; }
    }
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.agc.file_id_priv = u16::try_from(file_priv.id).unwrap();
    dp.agc.file_id_pub  = u16::try_from(file_pub.id).unwrap();
    dp.agc.key_len_code = u8::try_from(keybits / 128).unwrap();

    dp.agc.key_curve_code = match key_info.field_length {
        #[allow(clippy::bool_to_int_with_if)]
        224 => if card.type_ < SC_CARD_TYPE_ACOS5_EVO_V4 {0} else {1},
        256 => if card.type_ < SC_CARD_TYPE_ACOS5_EVO_V4 {0} else {2},
        384 => if card.type_ < SC_CARD_TYPE_ACOS5_EVO_V4 {0} else {3},
        521 => if card.type_ < SC_CARD_TYPE_ACOS5_EVO_V4 {0} else {4},
        _   => 0,
    };
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
    card.drv_data = Box::into_raw(dp).cast::<c_void>();

    rv = SC_SUCCESS;
    log3ifr!(ctx,f,line!(), rv);
    rv
} // acos5_pkcs15_create_key


/* e.g. pkcs15-init --store-secret-key aes_key_256.hex --secret-key-algorithm aes/256  --auth-id 01 --id 09 --verify-pin
 *      pkcs15-init --store-secret-key file            --secret-key-algorithm 3des     --auth-id 01 --id 02 --verify-pin
 *      pkcs15-init --store-secret-key file            --secret-key-algorithm 3des/128 --auth-id 01 --id 03 --verify-pin
 *
 *  file to be written by a hex-editor, i.e. containing hexadecimal values , containing probably unprintable bytes, no BOM, no line feed, carriage return etc.
 *  if 128 of des/128 is omitted, i.e. des only, it will be the default value 192=24 bytes
 *  auth-id is the pin that protects the secret key file
 *  id is the key reference==key record

00a40000024100
00a40000024114
00c0000020
00b00000ff
000e00BA00
00b00000ff

called only from pkcs15init/pkcs15-lib.c: functions
int sc_pkcs15init_store_private_key(struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15init_prkeyargs *keyargs, struct sc_pkcs15_object **res_obj)
int sc_pkcs15init_store_secret_key (struct sc_pkcs15_card *p15card, struct sc_profile *profile, struct sc_pkcs15init_skeyargs  *keyargs, struct sc_pkcs15_object **res_obj)
not called by C_GenerateKeyPair
*/
///
/// # Panics
#[named]
extern "C" fn acos5_pkcs15_store_key(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
                                     object_ptr: *mut sc_pkcs15_object, key_ptr: *mut sc_pkcs15_prkey) -> i32
{
    if p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } ||
        object_ptr.is_null() || unsafe { (*object_ptr).data.is_null() } || key_ptr.is_null() ||
        unsafe { ((*object_ptr).type_ & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_SKEY } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let p15card = unsafe { &mut *p15card_ptr };
    let card = unsafe { &mut *p15card.card };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let object = unsafe { &mut *object_ptr };
    /* key: if called from sc_pkcs15init_store_secret_key, then only key.algorithm and  key.u.secret were set  */
    let key = unsafe { &mut *key_ptr };
    let skey_algo = key.algorithm;
    let skey = unsafe { &mut key.u.secret };
    let skey_info = unsafe { &mut *object.data.cast::<sc_pkcs15_skey_info>() };
    log3ifc!(ctx,f,line!());
    if skey.data.is_null() || skey.data_len == 0 || skey_info.value_len/8 != skey.data_len {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    if object.session_object != 0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    match skey_algo {
        SC_ALGORITHM_AES  => if skey_info.key_type != 0x1F /*CKK_AES*/ || object.type_ != SC_PKCS15_TYPE_SKEY_GENERIC
                             { return SC_ERROR_INVALID_ARGUMENTS; },
        SC_ALGORITHM_3DES => if ![0x15 /*CKK_DES3*/ /*, 0x14  CKK_DES2*/].contains(&skey_info.key_type) ||
                                ![SC_PKCS15_TYPE_SKEY_3DES/*, SC_PKCS15_TYPE_SKEY_2DES*/].contains(&object.type_)
                             { return SC_ERROR_INVALID_ARGUMENTS; },
        SC_ALGORITHM_DES  => if skey_info.key_type != 0x13 /*CKK_DES*/ || object.type_ != SC_PKCS15_TYPE_SKEY_DES
                             { return SC_ERROR_INVALID_ARGUMENTS; },
        _  => return SC_ERROR_INVALID_ARGUMENTS,
    }
// println!("key.algorithm: {:X?}", skey_algo);
// println!("key.u.secret:  0x{:X?}", unsafe { from_raw_parts(skey.data, skey.data_len) });
// println!("skey_info: {:?}", *skey_info);

    if SC_PKCS15_TYPE_SKEY_GENERIC == object.type_ {
        skey_info.algo_refs[0..2].copy_from_slice(&[1_u32 /*AES ECB*/, 2 /*AES CBC*/]);
    }
    skey_info.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE |
        SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE |
        SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
    let mut file_id_sym_keys = 0_u16;
    skey_info.path.index = first_of_free_indices(p15card, &mut file_id_sym_keys);
    assert!(skey_info.path.index>0 && skey_info.path.index<=255);
    assert!(file_id_sym_keys>0);
    skey_info.key_reference = 0x80 | skey_info.path.index;
    skey_info.path.value[skey_info.path.len..skey_info.path.len+2].copy_from_slice(&file_id_sym_keys.to_be_bytes());
    skey_info.path.len += 2;
    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let mrl = dp.files[&file_id_sym_keys].1[4];
//      let nor = dp.files[&file_id_sym_keys].1[5];
    // dp.is_unwrap_op_in_progress = true;
    dp.sym_key_file_id = file_id_sym_keys;
    dp.sym_key_rec_idx = u8::try_from(skey_info.path.index).unwrap();
    dp.sym_key_rec_cnt = mrl;
    card.drv_data = Box::into_raw(dp).cast::<c_void>();

    skey_info.path.count = i32::from(mrl);//0x25;
// println!("skey_info: {:?}", *skey_info);
    assert_eq!(3, skey_info.usage & 3);
/*
    assert_eq!(3, object.flags);
    assert_eq!(1,     skey_info.id.len);
    let key_id = skey_info.id.value[0];
    if key_id == 0 || key_id > 31 {
        return SC_ERROR_NOT_SUPPORTED;
    }
*/
    let key_vec = construct_sym_key_entry(card, skey_info.path.index.try_into().unwrap(),
                                          skey_algo, skey.data_len.try_into().unwrap(),
            false, 0xFF, false, 0xFFFF,
             mrl.into(), unsafe { from_raw_parts(skey.data, skey.data_len) }).unwrap();
// println!("sym. key record content to be stored at path: {:X?}", key_vec);
    let mut file = null_mut();
    let guard_file = GuardFile::new(&mut file);
    let mut rv = unsafe { sc_select_file(card, &skey_info.path, *guard_file) };
    if rv != SC_SUCCESS {
        return SC_ERROR_FILE_NOT_FOUND;
    }
    rv = unsafe { sc_pkcs15init_authenticate(profile_ptr, p15card, file, i32::try_from(SC_AC_OP_UPDATE).unwrap()) };
    if rv != SC_SUCCESS {
        return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
    }
    cfg_if::cfg_if! {
    if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
        unsafe { sc_update_record(card, skey_info.path.index.try_into().unwrap(), key_vec.as_ptr(), key_vec.len(), SC_RECORD_BY_REC_NR) }
    }
    else {
        unsafe { sc_update_record(card, skey_info.path.index.try_into().unwrap(), 0, key_vec.as_ptr(), key_vec.len(), SC_RECORD_BY_REC_NR) }
    }}
} // acos5_pkcs15_store_key


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
///
/// # Panics
#[named]
extern "C" fn acos5_pkcs15_generate_key(profile_ptr: *mut sc_profile,
                                        p15card_ptr: *mut sc_pkcs15_card,
                                        p15object_ptr: *mut sc_pkcs15_object,
                                        p15pubkey_ptr: *mut sc_pkcs15_pubkey) -> i32
{ // TODO must handle create RSA key pair  And  generate ECC key pair
    if profile_ptr.is_null() || p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } ||
       p15object_ptr.is_null() || unsafe { (*p15object_ptr).data.is_null() } || p15pubkey_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let profile = unsafe { &mut *profile_ptr };
//    let p15card = unsafe { &mut *p15card_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let ctx = unsafe { &mut *card.ctx };
    let object_priv = unsafe { &mut *p15object_ptr};
    let key_info_priv = unsafe { &mut *object_priv.data.cast::<sc_pkcs15_prkey_info>() };
    let p15pubkey = unsafe { &mut *p15pubkey_ptr };
    let mut rv;// = SC_ERROR_UNKNOWN;
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    if   SC_PKCS15_TYPE_PRKEY_RSA != object_priv.type_ &&
        (SC_PKCS15_TYPE_PRKEY_EC  != object_priv.type_ || card.type_ != SC_CARD_TYPE_ACOS5_EVO_V4)
    {
        log3if!(ctx,f,line!(), c"Failed: Only RSA is supported");
        return SC_ERROR_NOT_SUPPORTED;
    }
//    let keybits = rsa_modulus_bits_canonical(key_info_priv.modulus_length);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let mut agc = dp.agc;
//    let is_key_pair_created_and_valid_for_generation = dp.agc.is_key_pair_created_and_valid_for_generation;
    let dp_files_value_ref = &dp.files[&dp.agc.file_id_pub];
    let path_pub = sc_path { type_: SC_PATH_TYPE_PATH, value: dp_files_value_ref.0, len: dp_files_value_ref.1[1].into(), ..sc_path::default()};
/*
    log3if!(ctx,f,line!(), c"key_info_priv.id: %s", unsafe { sc_dump_hex(key_info_priv.id.value.as_ptr(), key_info_priv.id.len) });
    log3if!(ctx,f,line!(), c"key_info_priv.usage: 0x%X", key_info_priv.usage);
    log3if!(ctx,f,line!(), c"key_info_priv.access_flags: 0x%X", key_info_priv.access_flags);
    log3if!(ctx,f,line!(), c"key_info_priv.native: %d", key_info_priv.native);
    log3if!(ctx,f,line!(), c"key_info_priv.modulus_length: 0x%X", key_info_priv.modulus_length);
    //log3if!(ctx,f,line!(), c"keybits: %zu", keybits);
    log3if!(ctx,f,line!(), c"key_info_priv.path: %s",
        unsafe { sc_dump_hex(key_info_priv.path.value.as_ptr(), key_info_priv.path.len) });

    //log3if!(ctx,f,line!(), c"dp.file_id_key_pair_priv: 0x%X", dp.file_id_key_pair_priv);
    //log3if!(ctx,f,line!(), c"dp.file_id_key_pair_pub:  0x%X", dp.file_id_key_pair_pub);
//    log3if!(ctx,f,line!(), c"is_key_pair_created_and_valid_for_generation: %d", is_key_pair_created_and_valid_for_generation);

    log3if!(ctx,f,line!(), c"dp.agc.do_generate_rsa_crt: %d", dp.agc.do_generate_rsa_crt);
    //log3if!(ctx,f,line!(), c"dp.do_generate_rsa_add_decrypt: %d", dp.do_generate_rsa_add_decrypt);
    //log3if!(ctx,f,line!(), c"dp.do_generate_rsa_standard_pub_exponent: %d", dp.do_generate_rsa_standard_pub_exponent);

    log3if!(ctx,f,line!(), c"p15pubkey.algorithm: 0x%X", p15pubkey.algorithm);
    log3if!(ctx,f,line!(), c"p15pubkey.alg_id:    %p", p15pubkey.alg_id);
*/
    let _unused = Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as *mut c_void;
/*
    if !is_key_pair_created_and_valid_for_generation {
        rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
        log3ifr!(ctx,f,line!(), c"not allowed due to is_key_pair_created_and_valid_for_generation", rv);
        return rv;
    }
*/
    //gen_keypair; the data get prepared in acos5_pkcs15_create_key
    rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES, (&raw mut agc).cast::<c_void>()) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), c"command 'Generate Key Pair' failed", rv);
        return rv;
    }

    let mut key_info_pub = sc_pkcs15_pubkey_info { path: path_pub, ..sc_pkcs15_pubkey_info::default() };
    if agc.key_curve_code == 0 {
        key_info_pub.modulus_length = key_info_priv.modulus_length;
    }
    else {
        key_info_pub.field_length = key_info_priv.field_length;   /* EC in bits */
    }
    let object_pub = sc_pkcs15_object { type_:  if agc.key_curve_code == 0 {SC_PKCS15_TYPE_PUBKEY_RSA} else {SC_PKCS15_TYPE_PUBKEY_EC},
        data: (&raw mut key_info_pub).cast::<c_void>(),  ..sc_pkcs15_object::default() };
    let mut p15pubkey2_ptr = null_mut();
    rv = unsafe { sc_pkcs15_read_pubkey(p15card_ptr, &object_pub, &mut p15pubkey2_ptr) };
    if rv != SC_SUCCESS {
        log3ifr!(ctx,f,line!(), c"sc_pkcs15_read_pubkey failed", rv);
        return rv
    }
    assert!(!p15pubkey2_ptr.is_null());
    unsafe {
        p15pubkey.algorithm = (*p15pubkey2_ptr).algorithm;
        if agc.key_curve_code == 0 {
            rv = me_pkcs15_dup_bignum(&mut p15pubkey.u.rsa.modulus,  &(*p15pubkey2_ptr).u.rsa.modulus);
            if rv != SC_SUCCESS { return rv; }
            rv = me_pkcs15_dup_bignum(&mut p15pubkey.u.rsa.exponent, &(*p15pubkey2_ptr).u.rsa.exponent);
            if rv != SC_SUCCESS { return rv; }
        }
        sc_pkcs15_free_pubkey(p15pubkey2_ptr);
    }

    rv = SC_SUCCESS;
    log3ifr!(ctx,f,line!(), rv);
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
#[allow(dead_code)]  // no usage currently
#[cold]
#[named]
extern "C" fn acos5_pkcs15_finalize_card(card_ptr: *mut sc_card) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(unsafe { &mut *card.ctx }, f, line!());
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
#[allow(dead_code)]  // no usage currently
#[cold]
#[named]
extern "C" fn acos5_pkcs15_delete_object(profile_ptr: *mut sc_profile, p15card_ptr: *mut sc_pkcs15_card,
    object_ptr: *mut sc_pkcs15_object, path_ptr: *const sc_path) -> i32
{
    if profile_ptr.is_null() ||  p15card_ptr.is_null() || unsafe { (*p15card_ptr).card.is_null() || (*(*p15card_ptr).card).ctx.is_null() } ||
        object_ptr.is_null() ||  path_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    // let profile = unsafe { &mut *profile_ptr };
    let card = unsafe { &mut *(*p15card_ptr).card };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(unsafe { &mut *card.ctx }, f, line!());
    SC_SUCCESS
}

/*
// does nothing currently, except logging CALLED
/* This function shall intercept one call to sc_pkcs15init_update_any_df:
   When a PuKDF shall be updated; anything else shall be passed to sc_pkcs15init_update_any_df directly */
extern "C" fn  acos5_pkcs15_emu_update_any_df(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card,
                                                 _op: u32, _object: *mut sc_pkcs15_object) -> i32
{ //ops->emu_update_any_df(profile, p15card, SC_AC_OP_CREATE, object);
    if p15card.is_null() || unsafe { (*p15card).card.is_null() || (*(*p15card).card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card).card };
    log3ifc!(unsafe { &mut *card.ctx }, c"acos5_pkcs15_emu_update_any_df", line!());
    SC_SUCCESS
}
*/

/* required for sc_pkcs15init_generate_key in order to do some corrections ref. public ḱey */
/* required for unwrap */
#[named]
extern "C" fn acos5_pkcs15_emu_store_data(p15card: *mut sc_pkcs15_card, profile: *mut sc_profile,
    object_ptr: *mut sc_pkcs15_object, _der_data: *mut sc_pkcs15_der, path: *mut sc_path) -> i32
{
    if profile.is_null() || p15card.is_null() || object_ptr.is_null() || unsafe { (*p15card).card.is_null() ||
        (*(*p15card).card).ctx.is_null() || (*object_ptr).data.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *(*p15card).card };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let object = unsafe { &mut *object_ptr };
    log3if!(ctx,f,line!(), c"called for object.type %X", object.type_); // SC_PKCS15_TYPE_PRKEY_RSA / SC_PKCS15_TYPE_PUBKEY_RSA
    if !path.is_null() && unsafe{ (*path).len > 0 } {
        log3if!(ctx,f,line!(), c"path: %s", unsafe { sc_dump_hex((*path).value.as_ptr(), (*path).len) }); // 0
    }

    if SC_PKCS15_TYPE_PRKEY_RSA == object.type_ {
        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        dp.last_keygen_priv_id = unsafe { (*object.data.cast::<sc_pkcs15_prkey_info>() ).id };
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
    }
    else if SC_PKCS15_TYPE_PUBKEY_RSA == object.type_ {
        let key_info = unsafe { &mut *object.data.cast::<sc_pkcs15_pubkey_info>() };
/*
    log3if!(ctx,f,line!(), c"object.label: %s",   object.label.as_ptr()); // pkcs15-init -G rsa/3072 -a 01 -i 08 -l testkey -u sign,decrypt
    log3if!(ctx,f,line!(), c"object.flags: 0x%X", object.flags); // 0x2: SC_PKCS15_CO_FLAG_MODIFIABLE
    log3if!(ctx,f,line!(), c"object.auth_id.len: %zu", object.auth_id.len); // 0
    log3if!(ctx,f,line!(), c"object.auth_id.value[0]: %u", object.auth_id.value[0]); // 0
    log3if!(ctx,f,line!(), c"object.usage_counter: %d",    object.usage_counter); // 0
    log3if!(ctx,f,line!(), c"object.user_consent: %d",     object.user_consent); // 0
    log3if!(ctx,f,line!(), c"object.access_rules[0].access_mode: %X", object.access_rules[0].access_mode); // 0
    log3if!(ctx,f,line!(), c"object.df: %p", object.df); // (nil)

    log3if!(ctx,f,line!(), c"key_info.id: %s",
            unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) }); // 08
    log3if!(ctx,f,line!(), c"key_info.usage: 0x%X", key_info.usage); // 0xD1 SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER | SC_PKCS15_PRKEY_USAGE_VERIFY | SC_PKCS15_PRKEY_USAGE_WRAP | SC_PKCS15_PRKEY_USAGE_ENCRYPT
    log3if!(ctx,f,line!(), c"key_info.access_flags: 0x%X", key_info.access_flags); // 0x0
    log3if!(ctx,f,line!(), c"key_info.native: %d", key_info.native); // 0
    log3if!(ctx,f,line!(), c"key_info.key_reference: 0x%X", key_info.key_reference); // 0x0
    log3if!(ctx,f,line!(), c"key_info.modulus_length: %zu", key_info.modulus_length); // 3071
    log3if!(ctx,f,line!(), c"key_info.algo_refs[0]: 0x%X", key_info.algo_refs[0]); // 0x0
    log3if!(ctx,f,line!(), c"key_info.subject.len: %zu", key_info.subject.len); // 0
    log3if!(ctx,f,line!(), c"key_info.params.len: %zu",  key_info.params.len); // 0
    log3if!(ctx,f,line!(), c"key_info.path: %s",
            unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) }); // empty
    log3if!(ctx,f,line!(), c"key_info.direct.raw.len: %zu",  key_info.direct.raw.len);  //398
    log3if!(ctx,f,line!(), c"key_info.direct.spki.len: %zu", key_info.direct.spki.len); //422
    if !_der_data.is_null() {
        unsafe {
            log3if!(ctx,f,line!(), c"der_length: %zu", (*_der_data).len); // 398
            (*_der_data).len = 0;
        }
    }
*/
        key_info.modulus_length = rsa_modulus_bits_canonical(key_info.modulus_length);
        key_info.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_LOCAL;
        key_info.native = 1;
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
/**/
        /* FIXME temporarily solve issue https://github.com/OpenSC/OpenSC/issues/2184 here, later improve OpenSC code */
        if key_info.id != dp.last_keygen_priv_id {
            key_info.id = dp.last_keygen_priv_id;
            log3if!(ctx,f,line!(), c"##### Warning: public key iD got corrected to match private key iD #####");
        }
/**/
        let dp_files_value_ref = &dp.files[&dp.agc.file_id_pub];
//        if dp.agc.is_key_pair_created_and_valid_for_generation {
        key_info.path = sc_path { type_: SC_PATH_TYPE_PATH, value: dp_files_value_ref.0,
            len: dp_files_value_ref.1[1] as usize, ..sc_path::default()};
//    }
//    dp.agc.is_key_pair_created_and_valid_for_generation = false; // this is the antagonist of: acos5_pkcs15_create_key: dp.is_key_pair_created_and_valid_for_generation = true;
        let _unused = Box::leak(dp);
    }
    else if SC_PKCS15_TYPE_SKEY_GENERIC == object.type_ {
        /* called from unwrapping a RSA_WRAPPED_AES_KEY */
        let key_info = unsafe { &mut *object.data.cast::<sc_pkcs15_skey_info>() };
        key_info.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE;
        // key_info.key_reference;

        log3if!(ctx,f,line!(), c"key_info.id: %s", unsafe { sc_dump_hex(key_info.id.value.as_ptr(), key_info.id.len) });
        log3if!(ctx,f,line!(), c"key_info.usage: %X", key_info.usage);
        log3if!(ctx,f,line!(), c"key_info.access_flags: %X", key_info.access_flags);
        log3if!(ctx,f,line!(), c"key_info.native: %d", key_info.native);
        log3if!(ctx,f,line!(), c"key_info.key_reference: %X", key_info.key_reference);
        log3if!(ctx,f,line!(), c"key_info.value_len: %zu", key_info.value_len);
        log3if!(ctx,f,line!(), c"key_info.key_type: %zu", key_info.key_type);
        log3if!(ctx,f,line!(), c"key_info.algo_refs[0]: %X", key_info.algo_refs[0]);
        log3if!(ctx,f,line!(), c"key_info.algo_refs[1]: %X", key_info.algo_refs[1]);
        log3if!(ctx,f,line!(), c"key_info.algo_refs[2]: %X", key_info.algo_refs[2]);
        log3if!(ctx,f,line!(), c"key_info.path: %s", unsafe { sc_dump_hex(key_info.path.value.as_ptr(), key_info.path.len) });
        if !key_info.data.value.is_null() && key_info.data.len>0 {
            log3if!(ctx,f,line!(), c"key_info.data: %s", unsafe { sc_dump_hex(key_info.data.value, key_info.data.len) });
        }
    }
    SC_SUCCESS
} // acos5_pkcs15_emu_store_data

#[named]
extern "C" fn acos5_pkcs15_sanity_check(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> i32
{
    if p15card.is_null() || unsafe { (*p15card).card.is_null() } {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    // let card_ref: &sc_card = unsafe { &*(*p15card).card };
    let card = unsafe { &mut *(*p15card).card };
    if card.ctx.is_null() {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_SANITY_CHECK, null_mut()) }
}

/*
from a run of main_RW_unwrap_AES_key_wrapped_by_RSA_key.rs:
FIXME the AES key labeled "Secret Key" doesn't actually get stored !!!
FIXME the AES key labeled "Secret Key" (shown below) has some wrong entries in SKDF
accessFlags are missing
keyReference is wrong
path.path is wrong
path.index is missing
path.length is missing


name: secretKey  type: CHOICE
  name: genericSecretKey  type: SEQUENCE
    name: commonObjectAttributes  type: SEQUENCE
      name: label  type: UTF8_STR  value: AES3
      name: flags  type: BIT_STR  value(2): c0  ->  11
      name: authId  type: OCT_STR  value: 01
    name: commonKeyAttributes  type: SEQUENCE
      name: iD  type: OCT_STR  value: 07
      name: usage  type: BIT_STR  value(2): c0  ->  11
      name: native  type: BOOLEAN
        name: NULL  type: DEFAULT  value: TRUE
      name: accessFlags  type: BIT_STR  value(4): b0  ->  1011
      name: keyReference  type: INTEGER  value: 0x0083
      name: algReference  type: SEQ_OF
        name: NULL  type: INTEGER
        name: ?1  type: INTEGER  value: 0x01
        name: ?2  type: INTEGER  value: 0x02
    name: commonSecretKeyAttributes  type: SEQUENCE
      name: keyLen  type: INTEGER  value: 0x0100
    name: genericSecretKeyAttributes  type: SEQUENCE
      name: value  type: CHOICE
        name: indirect  type: CHOICE
          name: path  type: SEQUENCE
            name: path  type: OCT_STR  value: 3f0041004102
            name: index  type: INTEGER  value: 0x03
            name: length  type: INTEGER  value: 0x25

name: secretKey  type: CHOICE
  name: genericSecretKey  type: SEQUENCE
    name: commonObjectAttributes  type: SEQUENCE
      name: label  type: UTF8_STR  value: Secret Key
      name: flags  type: BIT_STR  value(2): c0  ->  11
      name: authId  type: OCT_STR  value: 01
    name: commonKeyAttributes  type: SEQUENCE
      name: iD  type: OCT_STR  value: 09
      name: usage  type: BIT_STR  value(2): c0  ->  11
      name: native  type: BOOLEAN
        name: NULL  type: DEFAULT  value: TRUE
      name: keyReference  type: INTEGER  value: 0x00
    name: commonSecretKeyAttributes  type: SEQUENCE
      name: keyLen  type: INTEGER  value: 0x0100
    name: genericSecretKeyAttributes  type: SEQUENCE
      name: value  type: CHOICE
        name: indirect  type: CHOICE
          name: path  type: SEQUENCE
            name: path  type: OCT_STR  value: 3f004100

Content of SKDF
A4 39 30 0C 0C 03 53 4D 31 03 02 06 C0 04 01 01 30 0F 04 01 01 03 02 06 C0 03 02 04 B0 02 02 00 81 A0 04 02 02 00 C0 A1 12 30 10 30 0E 04 06 3F
00 41 00 41 02 02 01 01 80 01 25 A4 39 30 0C 0C 03 53 4D 32 03 02 06 C0 04 01 01 30 0F 04 01 02 03 02 06 C0 03 02 04 B0 02 02 00 82 A0 04 02 02
00 C0 A1 12 30 10 30 0E 04 06 3F 00 41 00 41 02 02 01 02 80 01 25 30 42 30 0D 0C 04 41 45 53 33 03 02 06 C0 04 01 01 30 17 04 01 07 03 02 06 C0
03 02 04 B0 02 02 00 83 A1 06 02 01 01 02 01 02 A0 04 02 02 01 00 A1 12 30 10 30 0E 04 06 3F 00 41 00 41 02 02 01 03 80 01 25 30 33 30 13 0C 0A
53 65 63 72 65 74 20 4B 65 79 03 02 06 C0 04 01 01 30 0A 04 01 09 03 02 06 C0 02 01 00 A0 04 02 02 01 00 A1 0A 30 08 30 06 04 04 3F 00 41 00
*/

/* Not yet ready; possibly better to be implemented in the driver and call that via sc_card_ctl
   I didn't yet check the Opensc functionality for that, but the driver probably will use libtasn1 anyway !

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
extern "C" fn acos5_pkcs15_sanity_check(_profile: *mut sc_profile, p15card: *mut sc_pkcs15_card) -> i32
{
    if p15card.is_null() || unsafe { (*p15card).card.is_null()} {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let card_ref:         &sc_card = unsafe { &    *(*p15card).card };
    let card: &mut sc_card = unsafe { &mut *(*p15card).card };
    if  card_ref.ctx.is_null() {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    let ctx = unsafe { &mut *card.ctx };
    let f   = c"acos5_pkcs15_sanity_check";
    log3ifc!(ctx,f,line!());

    /* select MF; if it doesn't exist, there's nothing to check */

    /* fill the hashmap: there are possibly not all scb8 retrieved so far and PKCS#15 file type yet unknown */
    let _dummy = call_dynamic_update_hashmap(card); // all scb8 are complete, same for the byte containing the PKCS#15 file type, i.e. the file really contains content acc. to that file type

//    let ctx = null_mut()::<sc_context>();
    let info = null_mut::<sm_info>();
    let mut out: c_char = 65u8 as c_char;
    let sm_available = false;
/* */
        match call_dynamic_sm_test(ctx, info, &mut out) {
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
    let dp = unsafe { Box::from_raw(card_ref.drv_data.cast::<DataPrivate>()) };

//    let mut path3908 = sc_path::default();
    /* DF/MF must point to existing SE-File with correct FDB==0x1C */
    for (key, val) in dp.files.iter() {
        if is_DFMF(val.1[0]) {
            let file_id_se = u16::from_be_bytes([val.1[4], val.1[5]]);
            if file_id_se == 0u16 {
                let fmt   = c"FCI of DF/MF %04X doesn't specify a mandatory SE file (tag 0x8D missing or zero content)";
                log3if!(ctx,f,line!(), fmt, *key as u32);
            }
            else if !dp.files.contains_key(&file_id_se) {
                let fmt   = c"FCI of DF/MF %04X specifies a non-existant, mandatory SE file id (file %04X is missing)";
                log3if!(ctx,f,line!(), fmt, *key as u32, file_id_se as u32);
            }
            else if dp.files[&file_id_se].1[0] != FDB_SE_FILE {
                let fmt   = c"FCI of DF/MF %04X specifies an existant, mandatory SE file id %04X that has incompatible cos5 file type (FDB != 0x1C)";
                log3if!(ctx,f,line!(), fmt, *key as u32, file_id_se as u32);
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
                    let format = c"SCB of file %04X enforces SM for 'read_binary', but the Secure Messaging library doesn't yet exist: Impossible to read that file";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }
                if val.2.unwrap()[1] & 0x40 > 0 {
                    let format = c"SCB of file %04X enforces SM for 'update_binary', but the Secure Messaging library doesn't yet exist: Impossible to modify content of that file";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }


                if val.2.unwrap()[3] & 0x40 > 0 {
                    let format = c"SCB of file %04X enforces SM for 'deactivate_file', but the Secure Messaging library doesn't yet exist: Impossible to deactivate/invalidate that file";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }
                if val.2.unwrap()[4] & 0x40 > 0 {
                    let format = c"SCB of file %04X enforces SM for 'activate_file', but the Secure Messaging library doesn't yet exist: Impossible to activate/rehabilitate that file";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }
                if val.2.unwrap()[5] & 0x40 > 0 {
                    let format = c"SCB of file %04X enforces SM for 'terminate_file', but the Secure Messaging library doesn't yet exist: Impossible to unmodifiably terminate/lock that file";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }
                if val.2.unwrap()[6] & 0x40 > 0 {
                    let format = c"SCB of file %04X enforces SM for 'delete_file', but the Secure Messaging library doesn't yet exist: Impossible to delete that file (except by 'erase_card')";
                    unsafe { sc_do_log(card_ref.ctx, SC_LOG_DEBUG_NORMAL, f_log.as_ptr(), line!() as i32, f.as_ptr(), format.as_ptr(), *key as u32) };
                }
            }
        }
    }
    card.drv_data = Box::into_raw(dp) as p_void;


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

    log3ifr!(ctx,f,line!(), SC_SUCCESS);
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
