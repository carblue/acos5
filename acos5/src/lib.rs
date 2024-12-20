//! Rust language:
//!
//! This documentation is intended to attract contributors to this software project wherever possible, but in any case to facilitate access to understanding as much as possible. Because I would have missed my main goal of making this software available as open source if no one reads the source code and thus potentially helps maintain its security
//! Diese Dokumentation soll nach Möglichkeit Beitragende zu diesem Software Projekt anziehen, in jedem Fall aber den Zugang zum Verständnis so weit wie möglich erleichtern. Denn ich hätte mein Hauptziel warum ich diese Software als open source zugänglich mache verfehlt, wenn keiner den Quelltext liest und so potentiell seine Sicherheit mit aufrecht zu erhalten hilft
//!
//! Admittedly, the source code is quite complicated:
//! Of course that depends on the material, a number of PKCS# standards, and then the not exactly simple ASN.1 and cryptography in general.
//! Furthermore, the OpenSC source code written in C is not easily accessible. In addition, I have ambitions to support several things in a source code project:
//! Different hardware versions (with different functionality), different operating systems (platforms and then also support for a variety of OpenSC releases (currently from 0.20.0 to 0.26.0-rc1)
//!
//! Zugegebenermaßen ist der Quelltext recht kompliziert:
//! Das hängt natürlich mit der Materie zusammen, eine Reihe von PKCS# Standards, und dann noch das nicht gerade simple ASN.1 und generell die Kryptographie.
//! Darüberhinaus ist der in C geschriebene OpenSC Quelltext nicht leicht zugänglich. Weiter hinzu kommen meine Ambitionen, in einem Quelltext-Projekt mehrers zu unterstützen:
//! Verschiedene Hardware-Versionen (mit unterschiedlichem Funktionsumfang), verschiedene Betriebssysteme (platforms und dann auch noch Unterstützung for eine Vielzahl von OpenSC-Releases (aktuell von 0.20.0 bis 0.26.0-rc1)
//!
//! \[`OpenSC wiki`\]\
//! \[`Rust website`\]

/*
 * lib.rs: Driver 'acos5' - main library file
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
/*
 https://www.acs.com.hk/en/products/18/cryptomate64-usb-cryptographic-tokens/

 https://www.acs.com.hk/en/products/308/acos5-64-v3.00-cryptographic-card-contact/
 https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens/

 https://www.acs.com.hk/en/products/464/acos5-evo-pki-smart-card-contact/
 https://www.acs.com.hk/en/products/494/cryptomate-evo-cryptographic-usb-tokens/

 http://acsccid.sourceforge.net/
 https://launchpad.net/~acshk/+archive/ubuntu/stable

 https://help.github.com/en/articles/changing-a-remotes-url

 Table 4 - Data within a command-response pair : APDU case
Case     Command data     Expected response data
1         No data             No data
2         No data             Data
3         Data                No data
4         Data                Data

TODO Many error returns are provisionally set to SC_ERROR_KEYPAD_MSG_TOO_LONG to be refined later
TODO Only set to anything other than SC_ERROR_KEYPAD_MSG_TOO_LONG, if that's the final setting

Note: The ACOS5-EVO supports a file hierarchy of any level but only stores security states up to the
third DF level. This means that successive DFs under the third level would not retain security states if
it has a child DF that has been selected.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
*/

//#![feature(const_fn)]
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
#![warn(missing_docs)] //     detects missing documentation for public members
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
#![warn(unnameable_types)] //     effective visibility of a type is larger than the area in which it can be named
#![expect(unreachable_pub)] //     `pub` items not reachable from crate root
#![warn(unsafe_attr_outside_unsafe)] //     detects unsafe attributes outside of unsafe
#![expect(unsafe_code)] //     usage of `unsafe` code and other potentially unsound constructs
#![warn(unsafe_op_in_unsafe_fn)] //     unsafe operations in unsafe functions without an explicit unsafe block are deprecated
#![warn(unstable_features)] //     enabling unstable features
#![warn(unused_crate_dependencies)] //     crate dependencies that are never used
#![warn(unused_extern_crates)] //     extern crates that are never used
#![warn(unused_import_braces)] //     unnecessary braces around an imported item
#![warn(unused_lifetimes)] //     detects lifetime parameters that are never used
#![warn(unused_macro_rules)] //     detects macro rules that were not used
#![warn(unused_qualifications)] //     detects unnecessarily qualified names
#![warn(unused_results)] //     unused result of an expression in a statement
#![warn(variant_size_differences)] //     detects enums with widely varying variant sizes

#![warn(clippy::all)]
#![warn(clippy::pedantic)]

#![warn(clippy::doc_lazy_continuation)]
#![warn(clippy::similar_names)]
#![warn(clippy::too_many_lines)]

use std::cmp::{min, max};
use std::os::raw::{c_char, c_ulong, c_void};
use std::ffi::{CStr, CString};
use std::ptr::{copy_nonoverlapping, null_mut, null};
use std::collections::HashMap;
use std::slice::{from_raw_parts, from_raw_parts_mut};

use function_name::named;

use opensc_sys::opensc::{sc_card, sc_card_driver, sc_card_operations, sc_security_env, sc_pin_cmd_data,
                         sc_get_iso7816_driver, sc_get_mf_path, sc_file_set_prop_attr, sc_select_file,
                         sc_read_binary, sc_transmit_apdu, sc_check_sw, sc_get_version,
                         SC_ALGORITHM_RSA_HASH_NONE, SC_ALGORITHM_ECDSA_RAW, SC_CARD_CAP_RNG,
                         SC_CARD_CAP_USE_FCI_AC, SC_READER_SHORT_APDU_MAX_SEND_SIZE,
                         SC_READER_SHORT_APDU_MAX_RECV_SIZE, SC_ALGORITHM_RSA, SC_ALGORITHM_ONBOARD_KEY_GEN,
                         SC_ALGORITHM_RSA_RAW, SC_SEC_OPERATION_SIGN, SC_SEC_OPERATION_DECIPHER,
                         SC_SEC_ENV_FILE_REF_PRESENT, SC_SEC_OPERATION_DERIVE, SC_PIN_CMD_GET_INFO,
                         SC_PIN_CMD_VERIFY, SC_PIN_CMD_CHANGE, SC_PIN_CMD_UNBLOCK, SC_ALGORITHM_RSA_PAD_PKCS1,
                         SC_ALGORITHM_RSA_PAD_ISO9796, SC_SEC_ENV_ALG_REF_PRESENT, SC_SEC_ENV_ALG_PRESENT,
                         SC_ALGORITHM_3DES, SC_ALGORITHM_DES, SC_RECORD_BY_REC_NR, SC_CARD_CAP_ISO7816_PIN_INFO,
                         SC_ALGORITHM_AES, SC_ALGORITHM_EXT_EC_NAMEDCURVE, SC_CARD_CAP_APDU_EXT, SC_ALGORITHM_EC,
                         SC_PROTO_T1, SC_ALGORITHM_EXT_EC_COMPRESS};
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
use opensc_sys::opensc::{SC_SEC_OPERATION_ENCRYPT_SYM, SC_SEC_OPERATION_DECRYPT_SYM};
//use opensc_sys::opensc::{SC_ALGORITHM_RSA_PAD_PSS};
use opensc_sys::opensc::{sc_update_record, SC_SEC_ENV_PARAM_IV, SC_SEC_ENV_PARAM_TARGET_FILE,
                         SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB, SC_SEC_OPERATION_UNWRAP,
                         SC_ALGORITHM_AES_CBC_PAD, sc_ec_parameters//, SC_CARD_CAP_UNWRAP_KEY, SC_CARD_CAP_ONCARD_SESSION_OBJECTS, SC_CARD_CAP_WRAP_KEY
//                         , SC_SEC_OPERATION_WRAP
};

use opensc_sys::types::{SC_AC_CHV, sc_aid, sc_path, sc_file, sc_serial_number, SC_MAX_PATH_SIZE,
                        SC_PATH_TYPE_FILE_ID, SC_PATH_TYPE_DF_NAME, SC_PATH_TYPE_PATH, SC_FILE_TYPE_DF,
                        SC_FILE_TYPE_INTERNAL_EF, SC_FILE_EF_TRANSPARENT, SC_APDU_FLAGS_CHAINING,
                        SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT,
                        SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT, sc_object_id, sc_lv_data};
#[cfg(target_os = "windows")]
use opensc_sys::types::SC_MAX_AID_SIZE;
use opensc_sys::errors::{SC_SUCCESS/*, SC_ERROR_INTERNAL*/, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_KEYPAD_MSG_TOO_LONG,
                         SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INCOMPATIBLE_KEY, SC_ERROR_WRONG_CARD, SC_ERROR_WRONG_PADDING,
                         SC_ERROR_INCORRECT_PARAMETERS, SC_ERROR_NOT_SUPPORTED, SC_ERROR_BUFFER_TOO_SMALL, SC_ERROR_NOT_ALLOWED,
                         SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_CARD_CMD_FAILED, SC_ERROR_FILE_ALREADY_EXISTS,
                         SC_ERROR_INVALID_CARD};

use opensc_sys::internal::{_sc_card_add_rsa_alg, _sc_card_add_ec_alg, sc_pkcs1_encode, _sc_match_atr};
use opensc_sys::log::sc_dump_hex;
use opensc_sys::cardctl::{SC_CARDCTL_GET_SERIALNR, SC_CARDCTL_LIFECYCLE_SET};
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
use opensc_sys::cardctl::SC_CARDCTL_GET_MODEL;
use opensc_sys::asn1::sc_asn1_put_tag;/*, sc_asn1_skip_tag, sc_asn1_read_tag, sc_asn1_print_tags, sc_asn1_find_tag*/
use opensc_sys::iso7816::{ISO7816_TAG_FCP_TYPE, ISO7816_TAG_FCP_LCS,  ISO7816_TAG_FCP, ISO7816_TAG_FCP_SIZE,
                          ISO7816_TAG_FCP_FID, ISO7816_TAG_FCP_DF_NAME};
use opensc_sys::pkcs15::{sc_pkcs15_pubkey_rsa, sc_pkcs15_bignum, sc_pkcs15_encode_pubkey_rsa, sc_pkcs15_bind,
                         sc_pkcs15_unbind, sc_pkcs15_auth_info, sc_pkcs15_get_objects, SC_PKCS15_TYPE_AUTH_PIN,
                         sc_pkcs15_id, sc_pkcs15_pubkey_ec, sc_pkcs15_u8, sc_pkcs15_encode_pubkey_ec
                         /*,sc_pkcs15_object, sc_pkcs15_card*/}; // , SC_PKCS15_AODF
use opensc_sys::sm::{SM_TYPE_CWA14890, SM_CMD_PIN, SM_CMD_PIN_VERIFY, SM_CMD_PIN_SET_PIN, SM_CMD_PIN_RESET,
                     SM_CMD_FILE_UPDATE, SM_CMD_FILE_DELETE};


#[macro_use]
mod macros;

/*
#[cfg(card_initialization)]
mod card_initialization;
use card_initialization::{};
*/

/// The reference manual contains a chapter "ACOS5-64/ACOS5-EVO Card Management Commands", and within
/// it subchapter "Get Card Info". This module implements all of those.
/// There is a subset of commands available from all hardware versions, the remainder only available
/// from some specific hardware
pub mod cmd_card_info;
use cmd_card_info::{cos_version, count_files_curr_df, file_info, free_space, is_fips_compliant,
                    is_ident_self_okay, is_key_authenticated, is_pin_authenticated, manufacture_date,
                    op_mode_byte, rom_sha1, serial_no};

mod constants_types; // shared file among modules acos5, acos5_pkcs15
use constants_types::{BLOCKCIPHER_PAD_TYPE_ANSIX9_23, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES,
                      BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64, BLOCKCIPHER_PAD_TYPE_PKCS7,
                      BLOCKCIPHER_PAD_TYPE_ZEROES, CARD_DRV_NAME, CARD_DRV_SHORT_NAME,
                      CardCtlArray32, CardCtlArray8, CardCtlAuthState, CardCtlSymCrypt,
                      CardCtlGenerateAsymCrypt, CardCtlGenerateAsymInject, DataPrivate,
                      FDB_CHV_EF, FDB_CYCLIC_EF, FDB_DF, FDB_ECC_KEY_EF, FDB_LINEAR_FIXED_EF,
                      FDB_LINEAR_VARIABLE_EF, FDB_MF, FDB_PURSE_EF, FDB_RSA_KEY_EF, FDB_SE_FILE,
                      FDB_SYMMETRIC_KEY_EF, FDB_TRANSPARENT_EF, ISO7816_RFU_TAG_FCP_SAC,
                      ISO7816_RFU_TAG_FCP_SEID, KeyTypeFiles, PKCS15_FILE_TYPE_NONE, PKCS15_FILE_TYPE_PIN,
                      /*PKCS15_FILE_TYPE_RSAPRIVATEKEY, PKCS15_FILE_TYPE_RSAPUBLICKEY,*/ PKCS15_FILE_TYPE_SECRETKEY,
                      RSAPUB_MAX_LEN, SC_CARDCTL_ACOS5_DECRYPT_SYM, SC_CARDCTL_ACOS5_ENCRYPT_ASYM,
                      SC_CARDCTL_ACOS5_ENCRYPT_SYM, SC_CARDCTL_ACOS5_GET_COS_VERSION,
                      SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF, SC_CARDCTL_ACOS5_GET_FILE_INFO,
                      SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE, SC_CARDCTL_ACOS5_GET_FREE_SPACE,
                      SC_CARDCTL_ACOS5_GET_IDENT_SELF, SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE,
                      SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE, SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE,
                      SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE, SC_CARDCTL_ACOS5_GET_ROM_SHA1,
                      SC_CARDCTL_ACOS5_HASHMAP_GET_FILE_INFO, SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO,
                      SC_CARDCTL_ACOS5_SDO_CREATE, SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES,
                      SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_GET,
                      SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_SET, SC_CARD_TYPE_ACOS5_64_V2,
                      SC_CARD_TYPE_ACOS5_64_V3, SC_CARD_TYPE_ACOS5_BASE, SC_CARD_TYPE_ACOS5_EVO_V4,
                      /*SC_SEC_OPERATION_DECIPHER_RSAPRIVATE, */ // SC_SEC_OPERATION_DECIPHER_SYMMETRIC,
                      SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC, // SC_SEC_OPERATION_ENCIPHER_SYMMETRIC,
                      SC_SEC_OPERATION_GENERATE_RSAPRIVATE, SC_SEC_OPERATION_GENERATE_RSAPUBLIC,
                      ValueTypeFiles, build_apdu, is_DFMF, SC_CARDCTL_ACOS5_SANITY_CHECK, GuardFile, p_void,
                      file_id_from_path_value, file_id, file_id_se, Fci,
                      SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE, CardCtlAlgoRefSymStore, CRT_TAG_DST, CRT_TAG_CT,
                      SC_SEC_OPERATION_GENERATE_ECCPRIVATE, SC_SEC_OPERATION_GENERATE_ECCPUBLIC,
                      SC_SEC_OPERATION_ENCIPHER_ECCPUBLIC, ECPUB_MAX_LEN
                      /*,PKCS15_FILE_TYPE_ECCPRIVATEKEY, PKCS15_FILE_TYPE_ECCPUBLICKEY, READ*/};

#[cfg(iup_user_consent)]
use constants_types::{ui_context, set_ui_ctx, get_ui_ctx, acos5_ask_user_consent};

mod crypto;

/// There are some functions implemented in OpenSC and available from a static libopensc.a library
/// (typically not made available by distribution packages),
/// but not available from a dynamically linked libopensc.so/.dll library.
/// The solution should be, to convince OpenSC maintainers to export those 'missing export functions'
/// as well.
/// In the meantime, I duplicated the code of valuable non-callable functions via this module.
mod missing_exports;
use missing_exports::{me_card_add_symmetric_alg, me_card_find_alg, //me_get_max_recv_size, me_get_max_send_size,
                      me_pkcs1_strip_01_padding, me_pkcs1_strip_02_padding};//, me_get_encoding_flags

mod no_cdecl;
use no_cdecl::{select_file_by_path, enum_dir,
    pin_get_policy, tracking_select_file, acos5_supported_atrs,
                      /*encrypt_public_rsa,*/ get_sec_env, set_sec_env,// get_rsa_caps,
    get_is_running_cmd_long_response, set_is_running_cmd_long_response, is_any_known_digestAlgorithm,
    generate_asym, encrypt_asym, files_hashmap_info, update_hashmap,
    /*, create_mf_file_system*/ convert_acl_array_to_bytes_tag_fcp_sac, get_sec_env_mod_len,
    ACL_CATEGORY_DF_MF, ACL_CATEGORY_EF_CHV, ACL_CATEGORY_KEY, ACL_CATEGORY_SE,
    get_is_running_compute_signature, set_is_running_compute_signature, algo_ref_sym_store,
    common_read, common_update, acos5_supported_ec_curves, logout_pin, sym_en_decrypt,
    algo_ref_mse_sedo
};

mod path;
use path::{file_id_from_cache_current_path, current_path_df};

mod sanity;
use sanity::sanity_check;

mod se;
use se::{map_scb8_to_acl, se_get_is_scb_suitable_for_sm_has_ct, se_parse_sae, se_get_sae_scb};

mod sm;
use sm::{sm_erase_binary, sm_delete_file, sm_pin_cmd, sm_pin_cmd_get_policy};

cfg_if::cfg_if! {
if #[cfg(not(target_os = "windows"))] {
    mod tasn1_pkcs15_array;
    use tasn1_pkcs15_array::tasn1_pkcs15_definitions;

    mod tasn1_pkcs15_util;
    use tasn1_pkcs15_util::{analyze_PKCS15_DIRRecord_2F00, analyze_PKCS15_PKCS15Objects_5031}; /* , analyze_PKCS15_TokenInfo_5032*/

    mod tasn1_sys;
    use tasn1_sys::{ASN1_SUCCESS, asn1_node, asn1_array2tree, asn1_delete_structure};
    // mod tasn1_wrap;
}}

mod wrappers;
use wrappers::{wr_do_log, wr_do_log_rv, wr_do_log_rv_ret, wr_do_log_sds, wr_do_log_sds_ret,
               wr_do_log_t, wr_do_log_tt, wr_do_log_tu, wr_do_log_tuv};

/*
#[cfg(test)]
#[cfg(test_v2_v3_token)]
mod   test_v2_v3;
*/


// #[no_mangle] pub extern fn  is the same as  #[no_mangle] pub extern "C" fn
//   for the time being, be explicit using  #[no_mangle] pub extern "C" fn


/// A mandatory library export.  It MUST BE identical for acos5 and `acos5_pkcs15`
///
/// @apiNote
/// If @return doesn't match the version of `OpenSC` binary libopensc.so/dll installed, then this library
/// will be rejected/unloaded immediately by `OpenSC`; depends on build.rs setup ref. "cargo:rustc-cfg=v0_??_0".
///
/// Its essential, that this doesn't merely echo, what a call to `sc_get_version` reports:
/// It is my/developers statement, that the support as reported by `sc_driver_version` got checked !
/// Thus, if e.g. a new `OpenSC` version 0.26.0 got released and if I didn't reflect that in `sc_driver_version`,
/// (updating opensc-sys binding and code of acos5 and `acos5_pkcs15`),
/// then the driver won't accidentally malfunction for a not yet supported `OpenSC` environment/version !
///
/// The support of not yet released `OpenSC` code (i.e. gitHub/master) is somewhat experimental:
/// Its accuracy depends on how closely the opensc-sys binding and driver code has covered the possible
/// differences in API and behavior (this function mentions the last `OpenSC` commit covered).
/// master will be handled as an imaginary new version release:
/// E.g. while currently the latest release is 0.25.1, build `OpenSC` from source such that it reports imaginary
/// version 0.26.0 (change configure.ac; define(\[`PACKAGE_VERSION_MINOR`\], \[26\]) )
/// In this example, `cfg!(v0_26_0`) will then match that
///
/// call site: function load_dynamic_driver, close to:
/// libopensc/ctx.c:515:    *(void **)tmodv = sc_dlsym(handle, "sc_driver_version");
/// @return   The `OpenSC` release/imaginary version, that this driver implementation supports
#[unsafe(no_mangle)]
pub extern "C" fn sc_driver_version() -> *const c_char {
    let version_ptr = sc_get_version();
    if cfg!(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1, v0_26_0/*, v0_27_0*/))  { version_ptr }
    // v0_27_0: experimental only:  Latest OpenSC gitHub master commit covered: 21ba386
    else  { c"0.0.0".as_ptr() } // will definitely cause rejection by OpenSC
}

/// A mandatory library export
/// @apiNote TODO inspect behavior in multi-threading context
/// @param   name passed in by `OpenSC` (acc. opensc.conf: assoc. `acos5_external` <-> ATR or `card_driver` `acos5_external`
/// @return  function pointer; calling that returns `acos5_external`'s `sc_card_driver` struct address
///
/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sc_module_init(name: *const c_char) -> *mut c_void {
    if !name.is_null() && unsafe { CStr::from_ptr(name) } == CARD_DRV_SHORT_NAME {
        acos5_get_card_driver as *mut c_void
    }
    else {
        null_mut()
    }
}


/**
 * What it does
 * @apiNote
 * @return
 */
extern "C" fn acos5_get_card_driver() -> *mut sc_card_driver
{
/*
static struct sc_card_operations iso_ops = {
	no_match,
	iso7816_init,	/* init   */
	NULL,			/* finish */
	iso7816_read_binary,
	iso7816_write_binary,
	iso7816_update_binary,
	NULL,			/* erase_binary */
	iso7816_read_record,
	iso7816_write_record,
	iso7816_append_record,
	iso7816_update_record,
	iso7816_select_file,
	iso7816_get_response,
	iso7816_get_challenge,
	NULL,			/* verify */
	NULL,			/* logout */
	iso7816_restore_security_env,
	iso7816_set_security_env,
	iso7816_decipher,
	iso7816_compute_signature,
	NULL,			/* change_reference_data */
	NULL,			/* reset_retry_counter   */
	iso7816_create_file,
	iso7816_delete_file,
	NULL,			/* list_files */
	iso7816_check_sw,
	NULL,			/* card_ctl */
	iso7816_process_fci,
	iso7816_construct_fci,
	iso7816_pin_cmd,
	iso7816_get_data,
	NULL,			/* put_data */
	NULL,			/* delete_record */
	NULL,			/* read_public_key */
	NULL,			/* card_reader_lock_obtained */
	NULL,			/* wrap */
	NULL,			/* unwrap */
	NULL,			/* encrypt_sym */
	NULL			/* decrypt_sym */
};
*/
    let iso_ops = unsafe { &*(*sc_get_iso7816_driver()).ops };
    let b_sc_card_operations = Box::new( sc_card_operations {
        match_card:            Some(acos5_match_card),        // no_match     is insufficient for cos5: It just doesn't match any ATR
        init:                  Some(acos5_init),              // iso7816_init is insufficient for cos5: It just returns SC_SUCCESS without doing anything
        finish:                Some(acos5_finish),            // NULL
        read_binary:           Some(acos5_read_binary),       // iso7816_read_binary
        write_binary:          Some(acos5_update_binary),     // iso7816_write_binary
        update_binary:         Some(acos5_update_binary),     // iso7816_update_binary
        erase_binary:          Some(acos5_erase_binary),      // NULL
        /* ATTENTION: calling the iso7816_something_record functions requires using flag SC_RECORD_BY_REC_NR , or it won't work as expected !!! s*/
        read_record:           Some(acos5_read_record),       // iso7816_read_record
        write_record:          None,//Some(acos5_update_record),     // iso7816_write_record
        append_record:         Some(acos5_append_record),     // iso7816_append_record
        update_record:         Some(acos5_update_record),     // iso7816_update_record
        delete_record:         Some(acos5_delete_record),     // NULL

        select_file:           Some(acos5_select_file),       // iso7816_select_file is insufficient for cos5: It will be used, but in a controlled manner only
        get_response:          Some(acos5_get_response),      // iso7816_get_response is insufficient for some cos5 commands with more than 256 bytes to fetch
            /* get_challenge:  iso7816_get_challenge  is usable, but only with P3==8, thus a wrapper is required */
        get_challenge:         Some(acos5_get_challenge),     // iso7816_get_challenge
        /* verify:                                               NULL, deprecated */
        logout:                Some(acos5_logout),            // NULL
        /* restore_security_env                                  // iso7816_restore_security_env */
        /* iso7816_set_security_env doesn't work for signing; do set CRT B6 and B8 */
        set_security_env:      Some(acos5_set_security_env),  // iso7816_set_security_env
        decipher:              Some(acos5_decipher),          // iso7816_decipher,  not suitable for cos5
        compute_signature:     Some(acos5_compute_signature), // iso7816_compute_signature,  not suitable for cos5
        /* change_reference_data:                                NULL, deprecated */
        /* reset_retry_counter:                                  NULL, deprecated */
            /* create_file: iso7816_create_file  is usable, provided that construct_fci is suitable */
        create_file:           Some(acos5_create_file),       // iso7816_create_file
            /* delete_file: iso7816_delete_file  is usable, BUT pay ATTENTION, how path.len selects among alternatives;
                        AND, even with path, it must first be selected */
        delete_file:           Some(acos5_delete_file),       // iso7816_delete_file
        list_files:            Some(acos5_list_files),        // NULL
        /* check_sw:                                          // iso7816_check_sw
            iso7816_check_sw basically is usable except that for pin_cmd cmd=SC_PIN_CMD_GET_INFO, the correct answer like
            0x63C8 (8 tries left) is interpreted as a failing pin verification trial (SC_ERROR_PIN_CODE_INCORRECT)
            thus trying to go with iso7816_check_sw, reroute that pin_cmd cmd=SC_PIN_CMD_GET_INFO to not employ check_sw
           TODO  iso7816_check_sw has an internal table to map return status to text: this doesn't match the ACOS5 mapping in some cases, THUS maybe switching on/off check_sw==iso7816_check_sw may be required
        */
        check_sw:              Some(acos5_check_sw),          // iso7816_check_sw
        card_ctl:              Some(acos5_card_ctl),          // NULL
        process_fci:           Some(acos5_process_fci),       // iso7816_process_fci is insufficient for cos5: It will be used, but more has to be done for cos5
        construct_fci:         Some(acos5_construct_fci),     // iso7816_construct_fci
        pin_cmd:               Some(acos5_pin_cmd),           // iso7816_pin_cmd
            /* pin_cmd:
            SC_PIN_CMD_GET_INFO: iso7816_pin_cmd not suitable for SC_PIN_CMD_GET_INFO (only because the status word is
                                   mis-interpreted by iso7816_check_sw as failed pin verification)
            SC_PIN_CMD_VERIFY:   iso7816_pin_cmd is okay for  SC_PIN_CMD_VERIFY
            SC_PIN_CMD_CHANGE:   iso7816_pin_cmd is okay for  SC_PIN_CMD_CHANGE
            SC_PIN_CMD_UNBLOCK:  iso7816_pin_cmd is okay for  SC_PIN_CMD_UNBLOCK
            */
        /* get_dat:                                              iso7816_get_data */
        /* put_data:                                             NULL, put a data object  write to Data Object */
        /* delete_record                                         NULL */
        read_public_key:       Some(acos5_read_public_key),   // NULL
        /* card_reader_lock_obtained:                            NULL */
        /* wrap:                                                 NULL */
        unwrap:                None, //Some(acos5_unwrap),            // NULL
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
        encrypt_sym:           Some(acos5_encrypt_sym),       // NULL
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
        decrypt_sym:           Some(acos5_decrypt_sym),       // NULL
        ..*iso_ops // untested so far whether remaining functionality from libopensc/iso7816.c is sufficient for cos5
/* from iso_ops:
    NULL,            /* verify,                deprecated */

>>  iso7816_restore_security_env,
    NULL,            /* change_reference_data, deprecated */
    NULL,            /* reset_retry_counter,   deprecated */

//>>  iso7816_check_sw,

>>  iso7816_get_data,
    NULL,            /* put_data */

    NULL,            /* card_reader_lock_obtained */
    NULL,            /* wrap */
*/
    } );

    let b_sc_card_driver = Box::new( sc_card_driver {
        name:       CARD_DRV_NAME.as_ptr(),
        short_name: CARD_DRV_SHORT_NAME.as_ptr(),
        ops:        Box::into_raw(b_sc_card_operations),
        ..sc_card_driver::default()
    } );
    Box::into_raw(b_sc_card_driver)
}


/*
match_card as other cards do,
(based on ATR from driver and/or opensc.conf? )
additionally optional:
exclude non-64K, i.e. exclude
V2: 32K mode

V3: 32K mode
V3: FIPS mode
V3: Brasil mode

additionally optional:
check cos version

additionally optional:
check operation Mode Byte Setting for V3

TODO how to set opensc.conf, such that a minimum of trials to match atr is done
*/
/**
 *  @param  `card`  `sc_card` object (treated as *const `sc_card`)
 *  @return 1 on succcess i.e. card did match, otherwise 0
 */
/*
 * Implements sc_card_operations function 'match_card'
 * @see opensc_sys::opensc struct sc_card_operations
 * @apiNote
 * @param
 * @return 1 on success (this driver will serve the card), 0 otherwise
 */
#[named]
extern "C" fn acos5_match_card(card_ptr: *mut sc_card) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return 0;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str(); // c"acos5_match_card";
    log3if!(ctx,f,line!(), c"called. Try to match card with ATR %s",
        unsafe { sc_dump_hex(card.atr.value.as_ptr(), card.atr.len) } );

    /* check whether card.atr can be found in acos5_supported_atrs[i].atr, iff yes, then
       card.type_ will be set accordingly, but not before the successful return of match_card */
    let mut type_out = 0;
    let     acos5_atrs = acos5_supported_atrs();
    let idx_acos5_atrs = unsafe { _sc_match_atr(card, acos5_atrs.as_ptr(), &mut type_out) };
////println!("reader.supported_protocols: {}, reader.active_protocol: {}\n", reader.supported_protocols, reader.active_protocol);
////println!("idx_acos5_atrs: {}, card.type_: {}, type_out: {}, &card.atr.value[..20]: {:X?}\n", idx_acos5_atrs, card.type_, type_out, &card.atr.value[..20]);
    if idx_acos5_atrs < 0 {
        return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: Differing ATR. Returning with 0 (no match)", 0);
    }
    let idx_acos5_atrs = usize::try_from(idx_acos5_atrs).unwrap();
    if idx_acos5_atrs+1 >= acos5_atrs.len() {
        return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: Differing ATR. Returning with 0 (no match)", 0);
    }

    /* check for 'Identity Self' */
    match is_ident_self_okay(card, type_out) {
        Ok(val) => if !val { return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: \
            is_ident_self_okay: SW2 different from expected! Returning with 0 (no match)", 0) },
        Err(_e) => return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: is_ident_self_okay \
            failed! Returning with 0 (no match)", 0),
    };

    /* check for 'Card OS Version' */
    let rbuf_card_os_version = match cos_version(card) {
        Ok(val) => val,
        Err(_e) => return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: cos_version failed! \
            Returning with 0 (no match)", 0),
    };

////println!("rbuf_card_os_version: {:X?}", &rbuf_card_os_version[..]);
/*
              rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05,  0x02, 0x00,  0x40]  Cryptomate64  b"ACOS___@"
              rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05,  0x03, 0x01,  0x40]  CryptoMate Nano in op mode 64 K
              rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05,  0x03, 0x00,  0x40]  CryptoMate Nano in op mode FIPS
              rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05,  0x04, 0x20,  0xC0]  CryptoMate EVO revision 2 in op mode
              rbuf_card_os_version: [0x41, 0x43, 0x4F, 0x53, 0x05,  0x04, 0x30,  0xC0]  CryptoMate EVO revision 3 in op mode */
    if rbuf_card_os_version[..=4] != [0x41, 0x43, 0x4F, 0x53, 0x05]  ||
        SC_CARD_TYPE_ACOS5_BASE + i32::from(rbuf_card_os_version[5]) != type_out  ||
        ![0x40, 0xC0].contains(&rbuf_card_os_version[7]) {
        return log3ifr_ret!(ctx,f,line!(), c"Card doesn't match: ACOS5 'Card OS Version'-check \
        failed. Returning with 0 (no match)", 0);
    }

    if SC_CARD_TYPE_ACOS5_64_V2 != type_out && cfg!(enforce_restricted_op_mode_byte) {
        let op_mode_byte = op_mode_byte(card, type_out).unwrap_or(255); /*
        if cfg!(enforce_restricted_op_mode_byte_no_fips) {
            match type_out {
                SC_CARD_TYPE_ACOS5_64_V3  => if op_mode_byte != 2 { return log3ifr_ret!(ctx,f,line!(),
                    c"EEPROM address 0xC191 is set with unsupported Operation Mode Byte. \
                    Returning with 0 (no match)", 0)},
                SC_CARD_TYPE_ACOS5_EVO_V4 => if op_mode_byte != 1 { return log3ifr_ret!(ctx,f,line!(),
                    c"EEPROM address 0xC191 is set with unsupported Operation Mode Byte. \
                    Returning with 0 (no match)", 0)},
                _ => unreachable!(),
            }
        }
        else { */
            match type_out {
                SC_CARD_TYPE_ACOS5_64_V3  => if ![0, 2, 16].contains(&op_mode_byte) { return log3ifr_ret!(ctx,f,line!(),
                    c"EEPROM address 0xC191 is set with unsupported Operation Mode Byte. \
                    Returning with 0 (no match)", 0)},
                SC_CARD_TYPE_ACOS5_EVO_V4 => if ![0, 1].contains(&op_mode_byte) { return log3ifr_ret!(ctx,f,line!(),
                    c"EEPROM address 0xC191 is set with unsupported Operation Mode Byte. \
                    Returning with 0 (no match)", 0)},
                _ => unreachable!(),
            }
//        }
    }


    /*  //optional checks
    match type_out {
        /* rbuf_card_os_version[5] is the major version */
        /* rbuf_card_os_version[6] is the minor version
           probably minor version reflects the  'Operation Mode Byte Setting',
           thus relax req. for SC_CARD_TYPE_ACOS5_64_V3, iff FIPS mode should ever be supported */
        SC_CARD_TYPE_ACOS5_64_V2  =>  { if rbuf_card_os_version[6] != 0  { return 0; } },
        SC_CARD_TYPE_ACOS5_64_V3  =>  { if rbuf_card_os_version[6] != 1  { return 0; } },
        _                         =>  { return 0; },
    }

        /* excludes any mode except 64K (no FIPS, no 32K, no NSH-1 (ICP Brasil)) */
        if type_out == SC_CARD_TYPE_ACOS5_64_V3 {

            /* check 'Operation Mode Byte Setting', must be set to  */
            let op_mode_byte = match op_mode_byte(card) {
                Ok(op_mb) => op_mb,
                Err(_err) =>  0x7FFF_FFFFu32,
            };

            if op_mode_byte != 2 {
                let fmt = c"ACOS5-64 v3.00 'Operation mode==Non-FIPS (64K)'-check failed. Trying to change the mode of operation to Non-FIPS/64K mode (no other mode is supported currently)....";
                log3if!(ctx,f,line!(), fmt);
                // FIXME try to change the operation mode byte if there is no MF
                let mf_path_ref: &sc_path = unsafe { & *sc_get_mf_path() };
                let mut file = null_mut();
                let guard_file = GuardFile::new(&mut file);
                let mut rv = unsafe { sc_select_file(card, mf_path_ref, *guard_file) };
                println!("rv from sc_select_file: {}, file: {:?}", rv, file); // rv from sc_select_file: -1200, file: 0x0
                let fmt = c"Card doesn't match: sc_transmit_apdu or 'change to operation mode 64K' failed ! Have a look into docs how to change the mode of operation to Non-FIPS/64K mode. No other mode is supported currently";
                if rv == SC_SUCCESS {
                    log3if!(ctx,f,line!(), fmt);
                    return 0;
                }
                // if sc_select_file failed, try to write value 2 to address 0xC191
                let command = [0, 0xD6, 0xC1, 0x91, 0x01, 0x02];
                let mut apdu = sc_apdu::default();
                rv = sc_bytes2apdu_wrapper(ctx, &command, &mut apdu);
                assert_eq!(rv, SC_SUCCESS);
                assert_eq!(apdu.cse, SC_APDU_CASE_3_SHORT);
                rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
                if rv != SC_SUCCESS || apdu.sw1 != 0x90 || apdu.sw2 != 0x00 {
                    log3if!(ctx,f,line!(), fmt);
                    return 0;
                }
                else {
                    let fmt = c"Card was set to Operation Mode 64K (SUCCESS) !";
                    log3if!(ctx,f,line!(), fmt);
                }
            }
        }
    / **/

    // Only now, on success, set card.type
    card.type_ = type_out;
    log3if!(ctx,f,line!(), c"'%s'  ##### card matched ! #####. Returning with 1", acos5_atrs[idx_acos5_atrs].name);
    1
}


/*
what can we rely on, when this gets called:
1. card.atr  was set
2. card.type was set by match_card, but it may still be incorrect, as a forced_card driver ignores
     a no-match on ATR and nevertheless calls init, thus rule out non-matching ATR card finally here
*/
/**
 *  @param  `card`  struct `sc_card` object
 *  @return `SC_SUCCESS` or error code from errors.rs
 */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_init(card_ptr: *mut sc_card) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || unsafe { (*card_ptr).reader.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let reader = unsafe { &mut *card.reader };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), c"called with card.type: %d, card.atr.value: %s", card.type_,
        unsafe {sc_dump_hex(card.atr.value.as_ptr(), card.atr.len) });
/* */
    let mut app_name = f;
    if !ctx.app_name.is_null() {
        app_name = unsafe { CStr::from_ptr(ctx.app_name) }; // app_name: e.g. "pkcs15-init"
        log3if!(ctx,f,line!(), c"The driver was loaded for application: %s", app_name.as_ptr());
        // println!("{}", String::from("The driver was loaded for application: ") + app_name.to_str().unwrap());
    }
/* */
    /* Undo 'force_card_driver = acos5_external;'  if match_card reports 'no match' */
    for elem in &acos5_supported_atrs() {
        if elem.atr.is_null() {
            return log3ifr_ret!(ctx,f,line!(), c"### Error, have to skip driver 'acos5_external'! Got here, \
            though match_card reported 'no match' (probably by using  'force_card_driver = acos5_external;')\
            ###. Returning with", SC_ERROR_WRONG_CARD);
        }
        if elem.type_ == card.type_ {
            card.name = elem.name;
            card.flags = elem.flags; // FIXME maybe omit here and set later
            break;
        }
    }

    card.cla  = 0x00;  // int      default APDU class (interindustry)

    /* possibly more SC_CARD_CAP_* apply, TODO clarify */
    card.caps    = SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC | SC_CARD_CAP_ISO7816_PIN_INFO;
    /* card.caps |= SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH   what exactly is this? */
    // { card.caps |=  SC_CARD_CAP_UNWRAP_KEY | SC_CARD_CAP_ONCARD_SESSION_OBJECTS; }
    /* The reader of USB CryptoMate64/CryptoMate Nano supports extended APDU, but the ACOS5-64 cards don't:
       Thus SC_CARD_CAP_APDU_EXT only for ACOS5-EVO TODO
       For many commands there is no benefit using extended, thus check whether its possible to switch often
       Maybe better solved with APDUShortExtendedSwitcher
    */
    if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 && reader.active_protocol == SC_PROTO_T1 {
        card.caps |= SC_CARD_CAP_APDU_EXT;
    }
    //println!("card.caps: {:X}\n", card.caps);
    /* max_send_size  IS  treated as a constant (won't change) after assignment here ! */
    card.max_send_size = if (card.caps & SC_CARD_CAP_APDU_EXT) == 0 {SC_READER_SHORT_APDU_MAX_SEND_SIZE} else { min(SC_READER_SHORT_APDU_MAX_SEND_SIZE, 0xFFFF) };
////println!("card.max_send_size: {}", card.max_send_size);
    //SC_READER_SHORT_APDU_MAX_SEND_SIZE; // 0x0FF; // 0x0FFFF for usb-reader, 0x0FF for chip/card;  Max Lc supported by the card

    /* max_recv_size  IS NOT  treated as a constant (it will be set temporarily to SC_READER_SHORT_APDU_MAX_RECV_SIZE
    where commands do support interpreting le byte 0 as 256 (le is 1 byte only!), like e.g. acos5_compute_signature) */
    /* some commands return 0x6100, meaning, there are 0x100==256==SC_READER_SHORT_APDU_MAX_RECV_SIZE  bytes (or more) to fetch */
    card.max_recv_size = if (card.caps & SC_CARD_CAP_APDU_EXT) == 0 {SC_READER_SHORT_APDU_MAX_SEND_SIZE} else { min(SC_READER_SHORT_APDU_MAX_SEND_SIZE, 0x1_0000) };
////println!("card.max_recv_size: {}", card.max_recv_size);

    // RSA
    /* it's possible to add SC_ALGORITHM_RSA_RAW, but then pkcs11-tool -t needs insecure
       --cfg dev_relax_signature_constraints_for_raw */
    let rsa_algo_flags = SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_RSA_PAD_PKCS1 /* | SC_ALGORITHM_RSA_RAW*/;
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_RAW; // PSS works with that only currently via acos5_decipher; declaring SC_ALGORITHM_RSA_PAD_PSS seems superfluous
//    { rsa_algo_flags |= SC_ALGORITHM_RSA_PAD_PSS; }
//    rsa_algo_flags   |= SC_ALGORITHM_RSA_PAD_ISO9796; // cos5 supports ISO9796, but don't use this, see https://www.iacr.org/archive/eurocrypt2000/1807/18070070-new.pdf
    /* SC_ALGORITHM_NEED_USAGE : Don't use that: the driver will handle that for sign internally ! */

    let is_fips_mode = match card.type_ {
        SC_CARD_TYPE_ACOS5_64_V3 |
        SC_CARD_TYPE_ACOS5_EVO_V4 => op_mode_byte(card, 0).unwrap()==0,
        _ => false,
    };
    let mut rv;
    cfg_if::cfg_if! {
    if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))] {
        let     rsa_key_len_from : u32 = if is_fips_mode { 2048 } else {  512 };
        let     rsa_key_len_step : u32 = if is_fips_mode { 1024 } else {  256 };
        let     rsa_key_len_to   : u32 = if is_fips_mode && card.type_==SC_CARD_TYPE_ACOS5_64_V3 { 3072 } else { 4096 };
    }
    else {
        let     rsa_key_len_from : usize = if is_fips_mode { 2048 } else {  512 };
        let     rsa_key_len_step : usize = if is_fips_mode { 1024 } else {  256 };
        let     rsa_key_len_to   : usize = if is_fips_mode && card.type_==SC_CARD_TYPE_ACOS5_64_V3 { 3072 } else { 4096 };
    }}
    let mut rsa_key_len = rsa_key_len_from;
    /* TODO currently there is no support for public exponents differing from 0x10001 */
    while   rsa_key_len <= rsa_key_len_to {
        rv = unsafe { _sc_card_add_rsa_alg(card, rsa_key_len,
            #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                                           rsa_algo_flags.into(),
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                                           rsa_algo_flags,
                                           0/*0x10001*/) };
        if rv != SC_SUCCESS {
            return log3ifr_ret!(ctx,f,line!(), rv);
        }
        rsa_key_len += rsa_key_len_step;
    }
// ECC
    if card.type_ == SC_CARD_TYPE_ACOS5_EVO_V4 {
        let flags = SC_ALGORITHM_ONBOARD_KEY_GEN | SC_ALGORITHM_ECDSA_RAW; /*| SC_ALGORITHM_ECDH_CDH_RAW |
                           SC_ALGORITHM_ECDSA_HASH_NONE | SC_ALGORITHM_ECDSA_HASH_SHA1*/
        let ext_flags = SC_ALGORITHM_EXT_EC_NAMEDCURVE | SC_ALGORITHM_EXT_EC_COMPRESS;
        for elem in &mut acos5_supported_ec_curves() {
            #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
            unsafe { rv = _sc_card_add_ec_alg(card, elem.size, c_ulong::from(flags), c_ulong::from(ext_flags), &mut elem.curve_oid) };
            #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
            unsafe { rv = _sc_card_add_ec_alg(card, elem.size, flags, ext_flags, &mut elem.curve_oid) };
            assert_eq!(SC_SUCCESS, rv);
        }
    }
// DES 3DES
    /* ACOS5 is capable of DES, but I think we can just skip that insecure algo; and the next, 3DES/128 with key1==key3 should NOT be used */
//    me_card_add_symmetric_alg(card, SC_ALGORITHM_DES,  64,  0);
//    me_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 128, 0);
    /* there is no DES / 3DES support from opensc-pkcs11 binary ! */
    rv = me_card_add_symmetric_alg(card, SC_ALGORITHM_3DES, 192, 0);
    assert_eq!(SC_SUCCESS, rv);

// AES
    let aes_algo_flags = SC_ALGORITHM_AES_ECB | SC_ALGORITHM_AES_CBC | SC_ALGORITHM_AES_CBC_PAD;
    rv = me_card_add_symmetric_alg(card, SC_ALGORITHM_AES, 128, aes_algo_flags);
    assert_eq!(SC_SUCCESS, rv);
    rv = me_card_add_symmetric_alg(card, SC_ALGORITHM_AES, 192, aes_algo_flags);
    assert_eq!(SC_SUCCESS, rv);
    rv = me_card_add_symmetric_alg(card, SC_ALGORITHM_AES, 256, aes_algo_flags);
    assert_eq!(SC_SUCCESS, rv);
    debug_assert!( me_card_find_alg(card, SC_ALGORITHM_AES, 256, None).is_some());
////////////////////////////////////////
cfg_if::cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        let mut pkcs15_definitions : asn1_node = null_mut();
        let mut error_description = [0x00 as c_char; 129];
        // let asn1_result = unsafe { crate::tasn1_sys::asn1_parser2tree(c"acos5_gui/source/PKCS15.asn".as_ptr(),
        //     &mut pkcs15_definitions, error_description.as_mut_ptr()) };
        let asn1_result = unsafe { asn1_array2tree(tasn1_pkcs15_definitions().as_ptr(), &mut pkcs15_definitions,
                                                   error_description.as_mut_ptr()) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
            println!("asn1_result (definitions): {asn1_result}, error_description: {c_str:?}");
        }
        debug_assert!(!pkcs15_definitions.is_null());
    }
}
    let mut files : HashMap<KeyTypeFiles, ValueTypeFiles> = HashMap::with_capacity(50);
    assert_eq!(None, files.insert(0x3F00, (
        [0; SC_MAX_PATH_SIZE],
        [0x3F, 0xFF, 0x3F, 0x00, 0x00, 0x00, 0xFF, 0xFF], // File Info, 0xFF are incorrect byte settings, corrected later
        None, //Some([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), // scb8, ditto. concerning 0xFF
        None, // Some(vec_SACinfo),
        None, // Some(vec_SAEinfo),
    )) );

    let dp = Box::new( DataPrivate {
        #[cfg(not(target_os = "windows"))]
        pkcs15_definitions,
        files,
        sec_env: sc_security_env::default(),
        agc: CardCtlGenerateAsymCrypt::default(),
        agi: CardCtlGenerateAsymInject::default(),
        time_stamp: std::time::Instant::now(),
        sm_cmd: 0,
        rsa_caps: rsa_algo_flags,
        sec_env_mod_len: 0,
        rfu_align_pad1: 0,
        does_mf_exist: true,       // just an assumption; will be set in enum_dir
        is_fips_mode,
        is_fips_compliant : false, // just an assumption; will be set in
        is_running_init: true,
        is_running_compute_signature: false,
        is_running_cmd_long_response: false,
        is_cap_apdu_ext_enabled: (card.caps & SC_CARD_CAP_APDU_EXT) != 0,
        rfu_align_pad2 : false,
        sym_key_file_id: 0,
        sym_key_rec_idx: 0,
        sym_key_rec_cnt: 0,
        last_keygen_priv_id: sc_pkcs15_id::default(),
        #[cfg(iup_user_consent)]
        ui_ctx: ui_context::default(),
    } );

/*
println!("address of dp:                    {:p}",  dp);
#[cfg(not(target_os = "windows"))]
println!("address of dp.pkcs15_definitions: {:p}", &dp.pkcs15_definitions);
println!("address of dp.files:              {:p}", &dp.files);
println!("address of dp.sec_env:            {:p}", &dp.sec_env);
//address of dp:                    0x55cb0bebc510
//address of dp.pkcs15_definitions: 0x55cb0bebc510
//address of dp.files:              0x55cb0bebc518
//address of dp.sec_env:            0x55cb0bebc548
*/

    card.drv_data = Box::into_raw(dp).cast::<c_void>();

/*
#[cfg(not(target_os = "windows"))]
println!("offset_of pkcs15_definitions:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, pkcs15_definitions),   offset_of!(DataPrivate, files)-offset_of!(DataPrivate, pkcs15_definitions), std::mem::size_of::<asn1_node>(), std::mem::align_of::<asn1_node>());

println!("offset_of files:                            {}, Δnext:   {}, size_of:   {}, align_of: {}", offset_of!(DataPrivate, files),   offset_of!(DataPrivate, sec_env)-offset_of!(DataPrivate, files), std::mem::size_of::<HashMap<KeyTypeFiles,ValueTypeFiles>>(), std::mem::align_of::<HashMap<KeyTypeFiles,ValueTypeFiles>>());
println!("offset_of sec_env:                         {}, Δnext: {}, size_of: {}, align_of: {}", offset_of!(DataPrivate, sec_env),      offset_of!(DataPrivate, agc)-offset_of!(DataPrivate, sec_env), std::mem::size_of::<sc_security_env>(), std::mem::align_of::<sc_security_env>());
println!("offset_of agc:                           {}, Δnext:  {}, size_of:  {}, align_of: {}", offset_of!(DataPrivate, agc),          offset_of!(DataPrivate, agi)-offset_of!(DataPrivate, agc), std::mem::size_of::<CardCtlGenerateAsymCrypt>(), std::mem::align_of::<CardCtlGenerateAsymCrypt>());
println!("offset_of agi:                           {}, Δnext:   {}, size_of:   {}, align_of: {}", offset_of!(DataPrivate, agi),        offset_of!(DataPrivate, time_stamp)-offset_of!(DataPrivate, agi), std::mem::size_of::<CardCtlGenerateAsymInject>(), std::mem::align_of::<CardCtlGenerateAsymInject>());
println!("offset_of time_stamp:                    {}, Δnext:   {}, size_of:   {}, align_of: {}", offset_of!(DataPrivate, time_stamp), offset_of!(DataPrivate, sm_cmd)-offset_of!(DataPrivate, time_stamp), std::mem::size_of::<std::time::Instant>(), std::mem::align_of::<std::time::Instant>());
println!("offset_of sm_cmd:                        {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, sm_cmd),     offset_of!(DataPrivate, rsa_caps)-offset_of!(DataPrivate, sm_cmd), std::mem::size_of::<u32>(), std::mem::align_of::<u32>());
println!("offset_of rsa_caps:                      {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, rsa_caps),   offset_of!(DataPrivate, sec_env_mod_len)-offset_of!(DataPrivate, rsa_caps), std::mem::size_of::<u32>(), std::mem::align_of::<u32>());

println!("offset_of sec_env_mod_len:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, sec_env_mod_len), offset_of!(DataPrivate, rfu_align_pad1)-offset_of!(DataPrivate, sec_env_mod_len), std::mem::size_of::<u16>(), std::mem::align_of::<u16>());
println!("offset_of rfu_align_pad1:                {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, rfu_align_pad1),  offset_of!(DataPrivate, does_mf_exist)-offset_of!(DataPrivate, rfu_align_pad1), std::mem::size_of::<u16>(), std::mem::align_of::<u16>());

println!("offset_of does_mf_exist:                 {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, does_mf_exist),   offset_of!(DataPrivate, is_fips_mode)-offset_of!(DataPrivate, does_mf_exist), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of is_fips_mode:                  {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, is_fips_mode),    offset_of!(DataPrivate, is_fips_compliant)-offset_of!(DataPrivate, is_fips_mode), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of is_fips_compliant:             {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, is_fips_compliant),            offset_of!(DataPrivate, is_running_init)-offset_of!(DataPrivate, is_fips_compliant), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of is_running_init:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, is_running_init),              offset_of!(DataPrivate, is_running_compute_signature)-offset_of!(DataPrivate, is_running_init), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of is_running_compute_signature:  {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, is_running_compute_signature), offset_of!(DataPrivate, is_running_cmd_long_response)-offset_of!(DataPrivate, is_running_compute_signature), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of is_running_cmd_long_response:  {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, is_running_cmd_long_response), offset_of!(DataPrivate, rfu_align_pad3)-offset_of!(DataPrivate, is_running_cmd_long_response), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of rfu_align_pad3:                {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, rfu_align_pad3),     offset_of!(DataPrivate, rfu_align_pad2)-offset_of!(DataPrivate, rfu_align_pad3), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());
println!("offset_of rfu_align_pad2:                {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, rfu_align_pad2),               offset_of!(DataPrivate, sym_key_file_id)-offset_of!(DataPrivate, rfu_align_pad2), std::mem::size_of::<bool>(), std::mem::align_of::<bool>());

println!("offset_of sym_key_file_id:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, sym_key_file_id), offset_of!(DataPrivate, sym_key_rec_idx)-offset_of!(DataPrivate, sym_key_file_id), std::mem::size_of::<u16>(), std::mem::align_of::<u16>());
println!("offset_of sym_key_rec_idx:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, sym_key_rec_idx), offset_of!(DataPrivate, sym_key_rec_cnt)-offset_of!(DataPrivate, sym_key_rec_idx), std::mem::size_of::<u8>(), std::mem::align_of::<u8>());
println!("offset_of sym_key_rec_cnt:               {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, sym_key_rec_cnt), std::mem::size_of::<DataPrivate>()-offset_of!(DataPrivate, sym_key_rec_cnt), std::mem::size_of::<u8>(), std::mem::align_of::<u8>());
#[cfg(iup_user_consent)]
println!("offset_of ui_ctx:                        {}, Δnext:    {}, size_of:    {}, align_of: {}", offset_of!(DataPrivate, ui_ctx), std::mem::size_of::<DataPrivate>()-offset_of!(DataPrivate, ui_ctx), std::mem::size_of::<ui_context>(), std::mem::align_of::<ui_context>());

println!("DataPrivate:                                                size_of: {}, align_of: {}", std::mem::size_of::<DataPrivate>(), std::mem::align_of::<DataPrivate>()); // DataPrivate: size_of: 1784, align_of: 8


offset_of pkcs15_definitions:               0, Δnext:    8, size_of:    8, align_of: 8
offset_of files:                            8, Δnext:   48, size_of:   48, align_of: 8
offset_of sec_env:                         56, Δnext: 1112, size_of: 1112, align_of: 8
offset_of agc:                           1168, Δnext:  552, size_of:  552, align_of: 8
offset_of agi:                           1720, Δnext:   24, size_of:   24, align_of: 2
offset_of time_stamp:                    1744, Δnext:   16, size_of:   16, align_of: 8
offset_of sm_cmd:                        1760, Δnext:    4, size_of:    4, align_of: 4
offset_of rsa_caps:                      1764, Δnext:    4, size_of:    4, align_of: 4
offset_of sec_env_mod_len:               1768, Δnext:    2, size_of:    2, align_of: 2
offset_of rfu_align_pad1:                1770, Δnext:    2, size_of:    2, align_of: 2
offset_of does_mf_exist:                 1772, Δnext:    1, size_of:    1, align_of: 1
offset_of is_fips_mode:                  1773, Δnext:    1, size_of:    1, align_of: 1
offset_of is_fips_compliant:             1774, Δnext:    1, size_of:    1, align_of: 1
offset_of is_running_init:               1775, Δnext:    1, size_of:    1, align_of: 1
offset_of is_running_compute_signature:  1776, Δnext:    1, size_of:    1, align_of: 1
offset_of is_running_cmd_long_response:  1777, Δnext:    1, size_of:    1, align_of: 1
offset_of rfu_align_pad3:                1778, Δnext:    1, size_of:    1, align_of: 1
offset_of rfu_align_pad2:                1779, Δnext:    1, size_of:    1, align_of: 1
offset_of sym_key_file_id:               1780, Δnext:    2, size_of:    2, align_of: 2
offset_of sym_key_rec_idx:               1782, Δnext:    1, size_of:    1, align_of: 1
offset_of sym_key_rec_cnt:               1783, Δnext:    1, size_of:    1, align_of: 1
DataPrivate:                                                size_of: 1784, align_of: 8

offset_of sym_key_rec_cnt:               1783, Δnext:    9, size_of:    1, align_of: 1
offset_of ui_ctx:                        1784, Δnext:    8, size_of:    4, align_of: 4
DataPrivate:                                                size_of: 1792, align_of: 8
*/

////////////////////////////////////////
    /* stores serialnr in card.serialnr; enum_dir currently doesn't require that */
    /* stores serialnr in card.serialnr, required for   sm_info.serialnr = card.serialnr; */
    #[cfg(ifd_serial_constrained_for_sm)]
    match serial_no(card) {
        Ok(_val) => (),
        Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
    }
// enum_dir
    let path_mf = unsafe { *sc_get_mf_path() };
    card.cache.current_path = path_mf;
    rv = enum_dir(card, &path_mf, true/*, 0*/); /* FIXME Doing to much here degrades performance, possibly for no value */
    if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); } // enum_dir returns SC_SUCCESS also for does_mf_exist==false
    {
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        let does_mf_exist = dp.does_mf_exist;
        let _unused = Box::leak(dp);
        if !does_mf_exist {
            let _rv = sanity_check(card, app_name);
            return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_CARD);
        }
    }
    // final selection in acos5_init  After the card powers up or resets, the MF is selected by default.
    rv = unsafe { sc_select_file(card, &path_mf, null_mut()) }; // acos5_select_file: if !does_mf_exist { return SC_ERROR_NOT_ALLOWED; }
    assert_eq!(SC_SUCCESS, rv);
// card.sm_ctx.info
    let sm_info = &mut card.sm_ctx.info;
/*
card.sm_ctx.module.ops  : handled by card.c:sc_card_sm_check/sc_card_sm_load
       if (card.cache.current_df)
       current_path_df                 = card.cache.current_df.path;
char[64]  config_section;  will be set from opensc.conf later by sc_card_sm_check
unsafe { copy_nonoverlapping(c"acos5_sm".as_ptr(), sm_info.config_section.as_mut_ptr(), 9); } // used to look up the block; only iasecc/authentic populate this field
uint      sm_mode;         will be set from opensc.conf later by sc_card_sm_check only for SM_MODE_TRANSMIT
 */
    sm_info.card_type = u32::try_from(card.type_).unwrap();
    sm_info.sm_type   = SM_TYPE_CWA14890;
    // sm_info.current_aid : on non-Windows (*nix) now set when required only in sm_manage_keyset, with aid read from EF.DIR, hence for SM EF.DIR must exist and be populated/correct
    #[cfg(target_os = "windows")]
    { sm_info.current_aid = sc_aid { len: SC_MAX_AID_SIZE, value: [0x41, 0x43, 0x4F, 0x53, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35, 0x76, 0x31, 0x2E, 0x30, 0x30] }; } //"ACOSPKCS-15v1.00", see PKCS#15 EF.DIR file
    unsafe {
        sm_info.session.cwa.params.crt_at.refs[0] = 0x82; // this is the selection of keyset_... ...02_... to be used !!! Currently, 24 byte keys (generate 24 byte session keys)
//      sm_info.session.cwa.params.crt_at.refs[0] = 0x81; // this is the selection of keyset_... ...01_... to be used !!!            16 byte keys (generate 16 byte session keys)
    }

cfg_if::cfg_if! {
    if #[cfg(ifd_serial_constrained_for_sm)] {
        sm_info.serialnr = card.serialnr; // enabling this instead of the following 2 lines would allow to constrain SM to a specific hardware, set in opensc.conf as ifd_serial = "byte_1:byte_2:byte_3:byte_4:byte_5:byte_6:byte_7:byte_8"; ifd_serial of SC_CARD_TYPE_ACOS5_64_V2 has 6 bytes only !
        sm_info.serialnr.len = 8;
    }
    else {
        sm_info.serialnr.len   = 8;
        sm_info.serialnr.value = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0];
    }
}

    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.files.shrink_to_fit();
    dp.is_running_init = false;

    #[cfg(iup_user_consent)]
    {
        /* read environment from configuration file */
//println!("dp.ui_ctx.user_consent_enabled: {}", dp.ui_ctx.user_consent_enabled);
        rv = set_ui_ctx(card, &mut dp.ui_ctx);
//println!("dp.ui_ctx.user_consent_enabled: {}", dp.ui_ctx.user_consent_enabled);
        if rv < SC_SUCCESS {
            log3ifr!(ctx,f,line!(), c"set_ui_ctx failed. Returning with", rv);
        }
    }
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
    log3ifr_ret!(ctx,f,line!(), rv)
} // acos5_init


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_finish(card_ptr: *mut sc_card) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
////////////////////
//     let _rv = sanity_check(card, unsafe { CStr::from_ptr(ctx.app_name) });
/* * /
    use opensc_sys::opensc::{sc_format_path};
    use no_cdecl::{sc_ac_op_name_from_idx};
    {
        let mut path_x = sc_path::default();
        let mut file_x = null_mut();
        let guard_file_x = GuardFile::new(&mut file_x);
        unsafe { sc_format_path(c"3F0041004102".as_ptr(), &mut path_x); }
        let rv = unsafe { sc_select_file(card, &path_x, *guard_file_x) };
        assert_eq!(SC_SUCCESS, rv);

        assert!(!file_x.is_null());
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        let scb8 = dp.files[&0x4102].2.unwrap();
        card.drv_data = Box::into_raw(dp) as p_void;

        let file = unsafe { &mut *file_x };
        println!("file_id: {:X?}, scb8: {:X?}", 0x4102, scb8);
        for (i, elem) in file.acl.iter().enumerate() {
            if !(*elem).is_null() {
                if unsafe { (*elem) as usize==1 || (*elem) as usize==2 || (*elem) as usize==3 } {
                    println!("i: {} {:?}, pointer: {:p}", i, sc_ac_op_name_from_idx(i), (*elem));
                }
                else {
                    let acl =  unsafe { &mut *(*elem) };
                    println!("i: {} {:?}, method: {:X}, key_ref: {:X}, next: {:p}", i, sc_ac_op_name_from_idx(i), acl.method, acl.key_ref, acl.next);
                }
            }
        }
    }
/ * */
/* * /
    let mut path_x = sc_path::default();
    unsafe { sc_format_path(c"3F0041004103".as_ptr(), &mut path_x); }
    let mut rv = unsafe { sc_select_file(card, &path_x, null_mut()) };
    assert_eq!(SC_SUCCESS, rv);
    {
        let mut tries_left = 0;
        let pin1_user: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]; // User pin, local  12345678
//        let pin2_user: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let mut pin_cmd_data = sc_pin_cmd_data {
            cmd: SC_PIN_CMD_VERIFY, // SC_PIN_CMD_GET_INFO  SC_PIN_CMD_VERIFY SC_PIN_CMD_CHANGE SC_PIN_CMD_UNBLOCK
            pin_reference: 0x81,
            pin1: sc_pin_cmd_pin {
                data: pin1_user.as_ptr(),
                len:  i32::try_from(pin1_user.len()).unwrap(),
                ..sc_pin_cmd_pin::default()
            },
            ..sc_pin_cmd_data::default()
        };
        rv = unsafe { sc_pin_cmd(card, &mut pin_cmd_data, &mut tries_left) }; // done with SM Conf
        assert_eq!(SC_SUCCESS, rv);
    }
//    rv = unsafe { sc_delete_file(card, &path_x) };

/ **/
/* * /
    let mut path_x = sc_path::default();
    unsafe { sc_format_path(c"3F00C100C200C300C304".as_ptr(), &mut path_x); }
    let mut rv = unsafe { sc_select_file(card, &path_x, null_mut()) };
    assert_eq!(SC_SUCCESS, rv);

    {
        let mut tries_left = 0;
        let pin1_user: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]; // User pin, local  12345678
        let pin2_user: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let mut pin_cmd_data = sc_pin_cmd_data {
            cmd: SC_PIN_CMD_UNBLOCK, // SC_PIN_CMD_GET_INFO  SC_PIN_CMD_VERIFY SC_PIN_CMD_CHANGE SC_PIN_CMD_UNBLOCK
            pin_reference: 0x81,
            pin1: sc_pin_cmd_pin {
                data: pin1_user.as_ptr(),
                len:  i32::try_from(pin1_user.len()).unwrap(),
                ..sc_pin_cmd_pin::default()
            },
            pin2: sc_pin_cmd_pin {
                data: pin2_user.as_ptr(),
                len:  i32::try_from(pin2_user.len()).unwrap(),
                ..sc_pin_cmd_pin::default()
            },
            ..sc_pin_cmd_data::default()
        };
        rv = unsafe { sc_pin_cmd(card, &mut pin_cmd_data, &mut tries_left) }; // done with SM Conf
        assert_eq!(SC_SUCCESS, rv);
    }
/ * */
    /* * /
        let mut path_x = sc_path::default();
        unsafe { sc_format_path(c"i3F00".as_ptr(), &mut path_x); }
        let mut rv = unsafe { sc_select_file(card, &path_x, null_mut()) };
        assert_eq!(SC_SUCCESS, rv);

        path_x = sc_path::default();
    //    let mut file_x = null_mut();
        let df_name = [b'd', b'i', b'r', b'e', b'c', b't', b'o', b'r', b'y', b'1'];
        rv = unsafe { sc_path_set(&mut path_x, SC_PATH_TYPE_DF_NAME, df_name.as_ptr(), df_name.len(), 0, -1) };
        assert_eq!(SC_SUCCESS, rv);
        rv = unsafe { sc_select_file(card, &path_x, null_mut()) };
        assert_eq!(SC_SUCCESS, rv);
    //    unsafe { sc_file_free(file_x) };
    */
/* some testing * /
    if /*false &&*/ card.type_ > SC_CARD_TYPE_ACOS5_64_V2 {
        let mut path = sc_path::default();
        /* this file requires pin verification for sc_update_binary and the DF requires SM for pin verification */
        unsafe { sc_format_path(c"3F00410045004504".as_ptr(), &mut path) };
//println!("path.len: {}, path.value: {:X?}", path.len, path.value);
        let mut rv = unsafe { sc_select_file(card, &path, null_mut()) };
        assert_eq!(rv, SC_SUCCESS);

        let mut tries_left = 0;
        let pin_user: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]; // User pin, local  12345678
        let mut pin_cmd_data = sc_pin_cmd_data {
            cmd: SC_PIN_CMD_GET_INFO, // SC_PIN_CMD_GET_INFO  SC_PIN_CMD_VERIFY
            pin_reference: 0x81,
            pin1: sc_pin_cmd_pin {
                data: pin_user.as_ptr(),
                len:  i32::try_from(pin_user.len()).unwrap(),
                ..sc_pin_cmd_pin::default()
            },
            ..sc_pin_cmd_data::default()
        };
        rv = unsafe { sc_pin_cmd(card, &mut pin_cmd_data, &mut tries_left) };
println!("Pin verification performed for DF {:X}, resulting in pin_user_verified/get_info: {}, rv: {}, tries_left: {}", 0x4500, rv == SC_SUCCESS, rv, tries_left);

        let sbuf = [0x01, 0x02];
        rv = unsafe { sc_update_binary(card, 0, sbuf.as_ptr(), sbuf.len(), 0) };
println!("sc_update_binary: rv: {}", rv);
    }
/ * */
    /*
    00a40000024100
    00c0000032
    00a40000024500
    00c0000028
    00a40000024503
    00c0000020
    00b201040b
    00b2020415
    00b203041f
    00a40000024504
    00c0000020
    00200081083132333435363738
    00d60000020102
    */
////////////////////
    assert!(!card.drv_data.is_null(), "drv_data is null");
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            let     dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        }
        else {
            let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
            if !dp.pkcs15_definitions.is_null() {
                let rv = unsafe { asn1_delete_structure(&mut dp.pkcs15_definitions) };
                assert_eq!(ASN1_SUCCESS, rv.try_into().unwrap())
            }
        }
    }
    cfg_if::cfg_if! {
        if #[cfg(finish_verbose)] {
            println!("EEPROM remaining free memory space: ~ {} of {}, in kB", f64::from(free_space(card).unwrap())/1000.,
                if card.type_ > SC_CARD_TYPE_ACOS5_64_V3 {192} else {64});
//println!("Hashmap: {:02X?}", dp.files);
        }
    }

    drop(dp);
    card.drv_data = null_mut();
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

#[named]
extern "C" fn acos5_check_sw(card_ptr: *mut sc_card, sw1: u32, sw2: u32) -> i32
//pub check_sw : Option< unsafe extern "C" fn (card: *mut sc_card, sw1: u32, sw2: u32) -> i32 >,
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    log3ifr_ret!(ctx,f,line!(), if sw1 == 0x61 {SC_SUCCESS} else
        { unsafe { (*(*sc_get_iso7816_driver()).ops).check_sw.unwrap()(card_ptr, sw1, sw2) } } )
}

/**
  Erases bytes (i.e. sets bytes to value 0x00) in a transparent file, within a chosen range of file's size
  The underlying card command does that beginning from a `start_offset` until either `end_offset` or end of file
  This `OpenSC` function has the parameter idx for `start_offset`, and a parameter `count` for how many bytes shall be cleared to zero.
  Use the special value count=0xFFFF (a value far beyond possible file sizes) in order to denote clearing bytes until the end of the file
  TODO check what happens if `end_offset` > file's size

@param `count` indicates the number of bytes to erase
@return `SC_SUCCESS` or other SC_..., NO length !
 * @return number of bytes written or an error code
@requires prior file selection

called only from `sc_erase_binary`, but that is used nowhere in `OpenSC`, except in some card drivers, tested in `acos5/src/test_v2_v3.rs`
*/
#[named]
extern "C" fn acos5_erase_binary(card_ptr: *mut sc_card, idx: u32, count: usize, flags: c_ulong) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let idx = u16::try_from(idx).unwrap();
    let mut count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    if count==0 {
        return log3ifr_ret!(ctx,f,line!(), SC_SUCCESS);
    }

    let file_id = file_id_from_cache_current_path(card);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    let dp_files_value = &dp.files[&file_id];
    let fdb = dp_files_value.1[0];
    let size = file_id_se(dp_files_value.1);
    let scb_erase = dp_files_value.2.unwrap()[1];
    let _unused = Box::leak(dp);
////println!("idx: {}, count: {}, flags: {}, fdb: {}, size: {}, scb_erase: {}", idx, count, flags, fdb, size, scb_erase);
    if ![1, 9].contains(&fdb) || idx >= size {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
    }

    if scb_erase == 0xFF {
        log3ifr_ret!(ctx,f,line!(), c"No erase_binary will be done: The file has acl NEVER ERASE. \
          Returning with", SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
    }
    else if (scb_erase & 0x40) == 0x40 {
        let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_erase & 0x0F);
        if res_se_sm.0 {
            // forward to SM processing, no P3==0
            if idx + count > size {
                count = size - idx;
            }
            card.sm_ctx.info.cmd = SM_CMD_FILE_UPDATE;
            sm_erase_binary(card, idx, count, flags, res_se_sm.1)
        }
        else {
            log3ifr_ret!(ctx,f,line!(), c"No erase_binary will be done: The file has acl \
              SM-protected ERASE. Returning with", SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
        }
    }
    else {
        let mut apdu = build_apdu(ctx, &[0, 0x0E, 0, 0,  2, 0xFF, 0xFF], SC_APDU_CASE_3_SHORT, &mut[]);
        apdu.flags = flags;

        if idx != 0 {
            let arr2 : [u8; 2] = idx.to_be_bytes();
            apdu.p1 = arr2[0]; // start_offset (included)
            apdu.p2 = arr2[1]; // dito
        }
        if idx + count >= size { // TODO what if idx (+count) >= size ?
            count = size - idx;

            apdu.cse = SC_APDU_CASE_1;
            apdu.lc = 0;
            apdu.datalen = 0;
            apdu.data = null();
        }
        else {
            let mut end_offset = [0_u8; 2];
            // end_offset (not included; i.e. byte at that address doesn't get erased)
            end_offset.copy_from_slice(&(idx + count).to_be_bytes());
            apdu.data = end_offset.as_ptr();
        }

        let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return log3ifr_ret!(ctx,f,line!(), rv); }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if rv != SC_SUCCESS {
            return log3ifr_ret!(ctx,f,line!(), c"Error: #### Failed to erase binary. Returning with", rv);
        }
        log3ifr_ret!(ctx,f,line!(), i32::from(count))
    }
}

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_card_ctl(card_ptr: *mut sc_card, command: c_ulong, data_ptr: p_void) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), c"called for command: %u", command);

    if data_ptr.is_null() && ![SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO, SC_CARDCTL_ACOS5_SANITY_CHECK].contains(&command)
    { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS); }

    match command {
//        SC_CARDCTL_GENERIC_BASE |
//        SC_CARDCTL_ERASE_CARD |
//        SC_CARDCTL_GET_DEFAULT_KEY |
//        SC_CARDCTL_LIFECYCLE_GET |
        SC_CARDCTL_LIFECYCLE_SET =>
//        SC_CARDCTL_GET_SE_INFO |
//        SC_CARDCTL_GET_CHV_REFERENCE_IN_SE |
//        SC_CARDCTL_PKCS11_INIT_TOKEN |
//        SC_CARDCTL_PKCS11_INIT_PIN |
            log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_SUPPORTED), // see sc_pkcs15init_bind
        SC_CARDCTL_GET_SERIALNR =>
            {
                let rm_serialnr = unsafe { &mut *data_ptr.cast::<sc_serial_number>() };
                *rm_serialnr = match serial_no(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
//#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))] {
        SC_CARDCTL_GET_MODEL =>
            {
                let rm_model = unsafe { &mut *data_ptr.cast::<*const c_char>() };
                *rm_model = c"PKCS#15".as_ptr();
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
//}
        SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE =>
            {
                let rm_algo_ref_sym_store = unsafe { &mut *data_ptr.cast::<CardCtlAlgoRefSymStore>() };
                rm_algo_ref_sym_store.value = match algo_ref_sym_store(rm_algo_ref_sym_store.card_type, rm_algo_ref_sym_store.algorithm, rm_algo_ref_sym_store.key_len_bytes) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_COUNT_FILES_CURR_DF =>
            {
                let rm_count_files_curr_df = unsafe { &mut *data_ptr.cast::<u16>() };
                *rm_count_files_curr_df = match count_files_curr_df(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_FILE_INFO =>
            {
                let rm_file_info = unsafe { &mut *data_ptr.cast::<CardCtlArray8>() };
                rm_file_info.value = match file_info(card, rm_file_info.reference) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_FREE_SPACE =>
            {
                let rm_free_space = unsafe { &mut *data_ptr.cast::<u32>() };
                *rm_free_space = match free_space(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_IDENT_SELF =>
            {
                let rm_is_hw_acos5 = unsafe { &mut *data_ptr.cast::<bool>() };
                *rm_is_hw_acos5 = match is_ident_self_okay(card, 0) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_COS_VERSION =>
            {
                let rm_cos_version = unsafe { &mut *data_ptr.cast::<[u8; 8]>() };
                *rm_cos_version = match cos_version(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },


        SC_CARDCTL_ACOS5_GET_ROM_MANUFACTURE_DATE =>
            {
                if card.type_ != SC_CARD_TYPE_ACOS5_64_V3 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_manufacture_date = unsafe { &mut *data_ptr.cast::<u32>() };
                *rm_manufacture_date = match manufacture_date(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_ROM_SHA1 =>
            {
                if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_rom_sha1 = unsafe { &mut *data_ptr.cast::<[u8; 20]>() };
                *rm_rom_sha1 = match rom_sha1(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_OP_MODE_BYTE =>
            {
//                if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_op_mode_byte = unsafe { &mut *data_ptr.cast::<u8>() };
                *rm_op_mode_byte = match op_mode_byte(card, 0) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_FIPS_COMPLIANCE =>
            {
                if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_is_fips_compliant = unsafe { &mut *data_ptr.cast::<bool>() };
                *rm_is_fips_compliant = match is_fips_compliant(card) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_PIN_AUTH_STATE =>
            {
                if card.type_ != SC_CARD_TYPE_ACOS5_64_V3 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_pin_auth_state = unsafe { &mut *data_ptr.cast::<CardCtlAuthState>() };
                rm_pin_auth_state.value = match is_pin_authenticated(card, rm_pin_auth_state.reference) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_GET_KEY_AUTH_STATE =>
            {
                if card.type_ != SC_CARD_TYPE_ACOS5_64_V3 { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT); }
                let rm_key_auth_state = unsafe { &mut *data_ptr.cast::<CardCtlAuthState>() };
                rm_key_auth_state.value = match is_key_authenticated(card, rm_key_auth_state.reference) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_HASHMAP_GET_FILE_INFO =>
            {
                let rm_files_hashmap_info = unsafe { &mut *data_ptr.cast::<CardCtlArray32>() };
                rm_files_hashmap_info.value = match files_hashmap_info(card, rm_files_hashmap_info.key) {
                    Ok(val) => val,
                    Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
                };
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_HASHMAP_SET_FILE_INFO =>
            {
                update_hashmap(card);
                /* */
                #[cfg(not(target_os = "windows"))]
                {
                        // let req_version = c"4.16";
                        // let tasn1_version = unsafe { crate::tasn1_sys::asn1_check_version(std::ptr::null() /*req_version.as_ptr()*/) };
                        // if !tasn1_version.is_null() {
                        //     println!("result from asn1_check_version: {:?}", unsafe { CStr::from_ptr(tasn1_version) });
                        // }
                    let mut aid = sc_aid::default();
                    let res = analyze_PKCS15_DIRRecord_2F00(card, &mut aid);
                    if res.is_err() || !res.unwrap() {
                        return log3ifr_ret!(ctx,f,line!(), -1);
                    }
                    //println!("AID: {:X?}", &aid.value[..aid.len]);
                    analyze_PKCS15_PKCS15Objects_5031(card);
                    // the only missing check is that EF.Tokeninfo is PKCS#15 compliant
                    // analyze_PKCS15_TokenInfo_5032(card);
                }
                /* */
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_SDO_CREATE =>
            log3ifr_ret!(ctx,f,line!(), acos5_create_file(card, data_ptr.cast::<sc_file>())),
        SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_GET =>
            {
                let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
                unsafe { *data_ptr.cast::<CardCtlGenerateAsymInject>() = dp.agi };
                let _unused = Box::leak(dp);
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES_INJECT_SET =>
            {
                let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
                dp.agi = unsafe { *data_ptr.cast::<CardCtlGenerateAsymInject>() };
                card.drv_data = Box::into_raw(dp).cast::<c_void>();
                log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
            },
        SC_CARDCTL_ACOS5_SDO_GENERATE_KEY_FILES =>
            /* suppose select_file, authenticate, (possibly setting MSE) etc. was done already */
            log3ifr_ret!(ctx,f,line!(), generate_asym(card, unsafe { &mut *data_ptr.cast::<CardCtlGenerateAsymCrypt>() })),
        SC_CARDCTL_ACOS5_ENCRYPT_ASYM =>
            /* suppose select_file, authenticate, (possibly setting MSE) etc. was done already */
            log3ifr_ret!(ctx,f,line!(), encrypt_asym(card, unsafe { &mut *data_ptr.cast::<CardCtlGenerateAsymCrypt>() }, false)),
        SC_CARDCTL_ACOS5_ENCRYPT_SYM |
        SC_CARDCTL_ACOS5_DECRYPT_SYM     =>
            {
                let crypt_sym_data = unsafe { &mut *data_ptr.cast::<CardCtlSymCrypt>() };
                if !((crypt_sym_data.outdata_len > 0) ^ !crypt_sym_data.outfile.is_null())  ||
                   !((crypt_sym_data.indata_len  > 0) ^ !crypt_sym_data.infile.is_null())   ||
                   ![8_u8, 16].contains(&crypt_sym_data.block_size)  ||
                   ![BLOCKCIPHER_PAD_TYPE_ZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES, BLOCKCIPHER_PAD_TYPE_ONEANDZEROES_ACOS5_64,
                        BLOCKCIPHER_PAD_TYPE_PKCS7, BLOCKCIPHER_PAD_TYPE_ANSIX9_23/*, BLOCKCIPHER_PAD_TYPE_W3C*/]
                        .contains(&crypt_sym_data.pad_type)
//                    || crypt_sym_data.iv != [0u8; 16]
                { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS); }

                log3ifr_ret!(ctx,f,line!(), if sym_en_decrypt(card, crypt_sym_data) > 0 {SC_SUCCESS} else {SC_ERROR_KEYPAD_MSG_TOO_LONG})
            },
        SC_CARDCTL_ACOS5_SANITY_CHECK =>
            {
                match sanity_check(card, unsafe {
                    if ctx.app_name.is_null() { c"" }
                    else { CStr::from_ptr(ctx.app_name) } } )
                {
                    Ok(()) => log3ifr_ret!(ctx,f,line!(), SC_SUCCESS),
                    Err(e) => log3ifr_ret!(ctx,f,line!(), e),
                }
            },
        _   => log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT)
    } // match command
} // acos5_card_ctl

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_select_file(card_ptr: *mut sc_card, path_ptr: *const sc_path, file_out_ptr: *mut *mut sc_file) -> i32
{
    if card_ptr.is_null() || path_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    let path_ref = unsafe { & *path_ptr };
    // first setting of  card.cache.current_path.len  done in acos5_init
    if card.cache.current_path.len==0 || (path_ref.type_==SC_PATH_TYPE_FILE_ID && path_ref.len!=2) ||
        !(path_ref.len>=2 && path_ref.len<=16 && (path_ref.len%2==0 || path_ref.type_==SC_PATH_TYPE_DF_NAME)) {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_INVALID_ARGUMENTS);
    }
    let target_file_id = file_id_from_path_value(&path_ref.value[..path_ref.len]); // wrong result for SC_PATH_TYPE_DF_NAME, but doesn't matter

    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    dp.sm_cmd = 0;
    let does_mf_exist = dp.does_mf_exist;
    let does_file_exist = dp.files.contains_key(&target_file_id);
    let force_process_fci = !dp.is_running_init && file_out_ptr.is_null() &&
        ( path_ref.type_==SC_PATH_TYPE_DF_NAME || (does_file_exist && dp.files[&target_file_id].2.is_none()) );
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
    if !does_mf_exist { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_ALLOWED); }
    // if !does_file_exist { return log3ifr_ret!(ctx,f,line!(), SC_ERROR_FILE_NOT_FOUND); }
    let file_opt = unsafe { file_out_ptr.as_mut() };

    match path_ref.type_ {
        SC_PATH_TYPE_PATH     => log3ifr_ret!(ctx,f,line!(), select_file_by_path(card, path_ref, file_opt, force_process_fci)),
        SC_PATH_TYPE_DF_NAME |
        SC_PATH_TYPE_FILE_ID  => log3ifr_ret!(ctx,f,line!(), tracking_select_file(card, path_ref, file_opt, force_process_fci)),
        /*SC_PATH_TYPE_PATH_PROT | SC_PATH_TYPE_FROM_CURRENT | SC_PATH_TYPE_PARENT  => log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT),*/
        _  => log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT),
    }
}

/*
Specific Return Status Code of cos5 Get Response
SW1 SW2   Definition
6b 00h    Wrong P1 or P2. Value must be 00h.
6C XXh    Incorrect P3. Value must be XXh.       actually OpenSC catches this and retransmits once with corrected XX
6A 88h    No data available
*/

/* get_response:   iso7816_get_response, limited to read max. 0xFF/(0x100 with card.max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE;) bytes, does work,
        see the impl. for more than 256 bytes: my_get_response
        get_response returns how many more bytes there are still to retrieve by a following call to get_response */
/*
 * What it does
 * @apiNote  ATTENTION SPECIAL MEANING of @return
 * @param  card
 * @param  count INOUT IN  how many bytes are expected that can be fetched;
                       OUT how many bytes actually were fetched by this call and were written to buf
 * @param  buf
 * @return how many bytes can be expected to be fetched the next time, this function gets called: It's a guess only
 */
#[named]
extern "C" fn acos5_get_response(card_ptr: *mut sc_card, count_ptr: *mut usize, buf_ptr: *mut u8) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || unsafe { (*card_ptr).reader.is_null() } || count_ptr.is_null() || buf_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let cnt_in = unsafe { *count_ptr };
    assert!(cnt_in <= 256);
    let fmt_1 = c"returning with: *count: %zu, rv: %d";
    log3if!(ctx,f,line!(), c"called with: *count: %zu", cnt_in);

    /* request at most max_recv_size bytes */
    card.max_recv_size = if (card.caps & SC_CARD_CAP_APDU_EXT) == 0 {SC_READER_SHORT_APDU_MAX_RECV_SIZE} else { min(SC_READER_SHORT_APDU_MAX_RECV_SIZE, 0x1_0000) };

    unsafe { *count_ptr = 0 }; // prepare to be an OUT variable now
    if (card.caps & SC_CARD_CAP_APDU_EXT) != 0  {
 //        is_cap_apdu_ext_enabled: (card.caps & SC_CARD_CAP_APDU_EXT) != 0,
        log3if!(ctx,f,line!(), c"eligible for a future optimized `acos5_get_response` for EVO. max_recv_size=%zu", card.max_recv_size);
    }
    let rlen = min(cnt_in, card.max_recv_size);
    //println!("### acos5_get_response rlen: {}", rlen);

    // will replace le later; the last byte is a placeholder only for sc_bytes2apdu
    let mut apdu = build_apdu(ctx, &[0, 0xC0, 0x00, 0x00, 0xFF], SC_APDU_CASE_2_SHORT, &mut[]);
    apdu.le      = rlen;
    apdu.resplen = rlen;
    apdu.resp    = buf_ptr;
    /* don't call GET RESPONSE recursively */
    apdu.flags  |= SC_APDU_FLAGS_NO_GET_RESP;

    let mut rv = unsafe { sc_transmit_apdu(card, &mut apdu) };
//    LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
    if rv != SC_SUCCESS {
        if      apdu.sw1==0x6B && apdu.sw2==0x00 {
println!("### acos5_get_response returned 0x6B00:   Wrong P1 or P2. Value must be 00h.");
        }
        else if apdu.sw1==0x6A && apdu.sw2==0x88 {
println!("### acos5_get_response returned 0x6A88:   No data available.");
        }
        else {
println!("### acos5_get_response returned apdu.sw1: {:X}, apdu.sw2: {:X}   Unknown error code", apdu.sw1, apdu.sw2);
        }
        log3if!(ctx,f,line!(), fmt_1, unsafe { *count_ptr }, rv);
        card.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    if !(apdu.sw1==0x6A && apdu.sw2==0x88) && apdu.resplen == 0 {
//    LOG_FUNC_RETURN(card->ctx, sc_check_sw(card, apdu.sw1, apdu.sw2));
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        log3if!(ctx,f,line!(), fmt_1, unsafe { *count_ptr }, rv);
        card.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
        return log3ifr_ret!(ctx,f,line!(), rv);
    }

    unsafe { *count_ptr = apdu.resplen };

    if      apdu.sw1==0x61 {
        rv = if get_is_running_cmd_long_response(card) {set_is_running_cmd_long_response(card, false); 256} else {0 /* no more data to read */};
    }
    else if apdu.sw1==0x90 && apdu.sw2==0x00 {
        /* for some cos5 commands, it's NOT necessarily true, that status word 0x9000 signals "no more data to read" */
        rv = if get_is_running_cmd_long_response(card) {set_is_running_cmd_long_response(card, false); 256} else {0 /* no more data to read */};
        /* switching off here should also work for e.g. a 3072 bit key:
           The first  invocation by sc_get_response is with *count_ptr==256 (set by sc_get_response)
           The second invocation by sc_get_response is with *count_ptr==256 (got from rv, line above), fails, as the correct rv should have been 128,
             but the failure doesn't crawl up to this function, as a retransmit with corrected value 128 will be done in the low sc_transmit layer;
             thus there should be only 1 situation when (apdu.sw1==0x6A && apdu.sw2==0x88) gets to this function: For a 2048 bit RSA  key operation with is_running_cmd_long_response==true
            */
    }
/*
    else if apdu.sw1 == 0x61 { // this never gets returned by command
        rv = if apdu.sw2 == 0 {256_i32} else {i32::try_from(apdu.sw2).unwrap()};    /* more data to read */
    }
    else if apdu.sw1 == 0x62 && apdu.sw2 == 0x82 { // this never gets returned by command
        rv = 0; /* Le not reached but file/record ended */
    }
*/
    else if apdu.sw1==0x6A && apdu.sw2==0x88 {
        rv = 0;
    }
    else {
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    }
    log3if!(ctx,f,line!(), fmt_1, unsafe { *count_ptr }, rv);

    card.max_recv_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE;
    log3ifr_ret!(ctx,f,line!(), rv)
} // acos5_get_response

/*
 * Get data from card's PRNG; as card's command supplies a fixed number of 8 bytes, some administration is required for count!= multiple of 8
 * @apiNote
 * @param count how many bytes are requested from RNG
 * @return MUST return the number of challenge bytes stored to buf
 */
#[named]
extern "C" fn acos5_get_challenge(card_ptr: *mut sc_card, buf_ptr: *mut u8, count: usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || buf_ptr.is_null() || count > 1024 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3if!(ctx,f,line!(), c"called with request for %zu bytes", count);
    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).get_challenge.unwrap() };
    // let is_count_multiple : bool;
    let cond_1 = card.type_ > SC_CARD_TYPE_ACOS5_64_V3;
    let cond_2 = cond_1 && count>8;
    let is_count_multiple = if cond_2 {count%16==0} else {count%8==0};
    // let is_count_multiple16 =  count%16 == 0;
    let chunk_size = if cond_2 {16_usize} else {8_usize};
    let loop_count = count/chunk_size + usize::from(!is_count_multiple);
    let mut len_rem = count;
    for i in 0..loop_count {
        if i+1<loop_count || is_count_multiple {
            let rv = unsafe { func_ptr(card, buf_ptr.add(i*chunk_size), chunk_size) };
            if rv != chunk_size.try_into().unwrap() { return log3ifr_ret!(ctx,f,line!(), rv); }
            len_rem -= chunk_size;
        }
        else {
            assert!(len_rem>0 && len_rem<chunk_size);
            let mut buf_temp = vec![0; chunk_size];
            let rv = unsafe { func_ptr(card, buf_temp.as_mut_ptr(), chunk_size) };
            if rv != chunk_size.try_into().unwrap() { return log3ifr_ret!(ctx,f,line!(), rv); }
            unsafe { copy_nonoverlapping(buf_temp.as_ptr(), buf_ptr.add(i*chunk_size), len_rem) };
        }
    }
//    log3if!(ctx,f,line!(), c"returning with requested %zu bytes supplied", count);
    log3ifr_ret!(ctx,f,line!(), i32::try_from(count).unwrap())
} // acos5_get_challenge

/* currently refers to pins only, but what about authenticated keys */
#[named]
extern "C" fn acos5_logout(card_ptr: *mut sc_card) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

//    let aid = null_mut();
    let mut p15card_ptr = null_mut();
    let mut rv = unsafe { sc_pkcs15_bind(card, null_mut(), &mut p15card_ptr) };
    if rv < SC_SUCCESS {
        return log3ifr_ret!(ctx,f,line!(), c"Error: sc_pkcs15_bind. Returning with", rv);
    }
    assert!(!p15card_ptr.is_null());
    let mut p15objects = [null_mut(); 10]; // TODO there should be less than 10 AUTH_PIN
    let nn_objs = usize::try_from( unsafe { sc_pkcs15_get_objects(p15card_ptr, SC_PKCS15_TYPE_AUTH_PIN,
                                                                  p15objects.as_mut_ptr(), 10) } ).unwrap();
    for &item in p15objects.iter().take(nn_objs) {
        assert!(unsafe { !item.is_null() && !(*item).data.is_null() });
        let auth_info_ref = unsafe { &* (*item).data.cast::<sc_pkcs15_auth_info>() };
//        apdu.p2 = u8::try_from(unsafe { auth_info_ref.attrs.pin.reference }).unwrap();
        rv = logout_pin(card, u8::try_from(unsafe { auth_info_ref.attrs.pin.reference }).unwrap());
        if rv != SC_SUCCESS {
            return log3ifr_ret!(ctx,f,line!(), c"Error: ACOS5 'Logout' failed. Returning with", SC_ERROR_CARD_CMD_FAILED);
        }
    }
    rv = unsafe { sc_pkcs15_unbind(p15card_ptr) }; // calls sc_pkcs15_pincache_clear
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), c"Error: sc_pkcs15_unbind failed");
//        return log3ifr_ret!(ctx,f,line!(), rv);
    }
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}


/* TODO this isn't yet completed: 1. the hashmap-entry/path+fileinfo must be set and 2. there is more to do for MF/DF */
/* expects some entries in file, see acos5_construct_fci */
#[named]
extern "C" fn acos5_create_file(card_ptr: *mut sc_card, file_ptr: *mut sc_file) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || file_ptr.is_null() || unsafe {(*file_ptr).id==0} {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let file = unsafe { &mut *file_ptr };
    log3ifc!(ctx,f,line!());

    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if dp.files.contains_key(&(u16::try_from(file.id).unwrap())) {
        let _unused = Box::leak(dp);
        return log3ifr_ret!(ctx,f,line!(),c"### Duplicate file id disallowed by the driver ! ###", SC_ERROR_NOT_ALLOWED);
    }
    let _unused = Box::leak(dp);

    if file.path.len == 0 {
        let current_path_df_slice = current_path_df(card);
        let len = current_path_df_slice.len();
        let mut path = sc_path { type_: SC_PATH_TYPE_PATH, len: len+2, ..sc_path::default() };
        path.value[..len].copy_from_slice(current_path_df_slice);
        path.value[len..len+2].copy_from_slice(&u16::try_from(file.id).unwrap().to_be_bytes());
        file.path = path;
    }

    /* iso7816_create_file calls acos5_construct_fci */
    let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).create_file.unwrap() };
    let rv = unsafe { func_ptr(card, file_ptr) };

    if rv == SC_SUCCESS {
        let file_ref : &sc_file = file;
        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        let _unused = dp.files.insert(u16::try_from(file_ref.id).unwrap(),
                        (file_ref.path.value, [0, 0, 0, 0, 0, 0, 0xFF, 1], None, None, None));
        let x = dp.files.get_mut(&(u16::try_from(file_ref.id).unwrap())).unwrap();
        x.1[0] = u8::try_from(file_ref.type_).unwrap();
        x.1[1] = u8::try_from(file_ref.path.len).unwrap();
        x.1[2] = file_ref.path.value[file_ref.path.len-2];
        x.1[3] = file_ref.path.value[file_ref.path.len-1];
        if [FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF,
            FDB_SE_FILE].contains(&x.1[0]) {
            x.1[4] =  u8::try_from(file_ref.record_length).unwrap();
            x.1[5] =  u8::try_from(file_ref.record_count).unwrap();
        }
        else if [FDB_TRANSPARENT_EF, FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&x.1[0]) {
            x.1[4..6].copy_from_slice(&u16::try_from(file_ref.size).unwrap().to_be_bytes());
        }
        else { // MF/DF
            x.1[4..6].copy_from_slice(&u16::try_from(file_ref.id+3).unwrap().to_be_bytes());
        }
        card.drv_data = Box::into_raw(dp).cast::<c_void>();

        log3if!(ctx,f,line!(), c"file_id %04X added to hashmap", file_ref.id);
    }
    else {
        log3ifr!(ctx,f,line!(), c"Error: failed with", rv);
    }
    rv
}

/* opensc-explorer doesn't select first
iso7816_delete_file: condition: (path->type == SC_PATH_TYPE_FILE_ID && (path->len == 0 || path->len == 2))
*/
/* expects a path of type SC_PATH_TYPE_FILE_ID and a path.len of 2 or 0 (0 means: delete currently selected file) */
/* even with a given path with len==2, acos expects a select_file ! */
#[named]
extern "C" fn acos5_delete_file(card_ptr: *mut sc_card, path_ref_ptr: *const sc_path) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || path_ref_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let path_ref= unsafe { &*path_ref_ptr };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
    log3if!(ctx,f,line!(), c"card.cache.current_path %s",
        unsafe{sc_dump_hex(card.cache.current_path.value.as_ptr(), card.cache.current_path.len)});
    log3if!(ctx,f,line!(), c"path_ref %s", unsafe{sc_dump_hex(path_ref.value.as_ptr(), path_ref.len)} );

    let file_id = if path_ref.len == 0 { file_id_from_cache_current_path(card) }
                        else                 { file_id_from_path_value(&path_ref.value[..path_ref.len]) };
////println!("file_id: {:X}", file_id);

    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if !dp.files.contains_key(&file_id) {
println!("file_id: {file_id:X} is not a key of hashmap dp.files");
        let _unused = Box::leak(dp);
        return -1;
    }
    let x = &dp.files[&file_id];
    let need_to_select_or_process_fci = x.2.is_none() || file_id != file_id_from_cache_current_path(card);
    let mut scb_delete_self = if need_to_select_or_process_fci {0xFF} else {x.2.unwrap()[6]};
    let _unused = Box::leak(dp);

    let mut rv;
    if need_to_select_or_process_fci {
        let mut file = null_mut();
        let guard_file = GuardFile::new(&mut file);
        rv = unsafe { sc_select_file(card, path_ref, *guard_file) };
        if rv != SC_SUCCESS {
            return rv;
        }
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        scb_delete_self = dp.files[&file_id].2.unwrap()[6];
        let _unused = Box::leak(dp);
    }

//println!("acos5_delete_file  scb_delete_self: {:X}", scb_delete_self);
    if scb_delete_self == 0xFF {
        log3if!(ctx,f,line!(), c"No delete_file will be done: The file has acl NEVER DELETE_SELF");
        rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
    }
    else if (scb_delete_self & 0x40) == 0x40 { // sc_select_file was done, as SM doesn't accept path.len==2
        let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_delete_self & 0x0F);
        if res_se_sm.0 {
            card.sm_ctx.info.cmd = SM_CMD_FILE_DELETE;
            rv = sm_delete_file(card);
        }
        else {
            log3if!(ctx,f,line!(), c"No delete_file will be done: The file has acl SM-protected DELETE_SELF");
            rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;
        }
    }
    else {
        let mut path = sc_path { type_: SC_PATH_TYPE_FILE_ID, len: min(path_ref.len, 2), ..*path_ref };
        if path.len == 2 {
            path.value[..2].copy_from_slice(&path_ref.value[path_ref.len-2..path_ref.len]);
        }
        let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).delete_file.unwrap() };
        rv = unsafe { func_ptr(card, &path) };
    }
////
    if rv == SC_SUCCESS {
        let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        let rm_result = dp.files.remove(&file_id);
        assert!(rm_result.is_some());
        card.drv_data = Box::into_raw(dp).cast::<c_void>();
        assert!(card.cache.current_path.len > 2);
        card.cache.current_path.len   -= 2;
        //println!("acos5_delete_file  card.cache.current_path: {:X?}", &card.cache.current_path.value[..card.cache.current_path.len]);
        log3if!(ctx,f,line!(), c"file_id %04X deleted from hashmap", file_id);
    }
    else {
        log3if!(ctx,f,line!(), c"acos5_delete_file failed. rv: %d", rv);
    }
    log3ifr_ret!(ctx,f,line!(), rv)
}

/*
deficiency: It's not known in advance, how many files will be reported by count_files_curr_df, but an arg
buflen must be supplied to sc_list_files. If that is to small and there are more files, then truncation occurs and
x files will not be listed by this function: TODO add a warning message

 * what's expected are the file IDs of files within the selected directory.
 * as opensc-tool provides as buf u8[SC_MAX_APDU_BUFFER_SIZE], max 130 files for each directory can be listed
 * @param  card    INOUT
 * @param  buf     INOUT
 * @param  buflen  IN
 * @return         number of bytes put into buf <= buflen
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_list_files(card_ptr: *mut sc_card, buf_ptr: *mut u8, buflen: usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || buf_ptr.is_null() || buflen<2 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let buf = unsafe { from_raw_parts_mut(buf_ptr, buflen) };
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());

    /* retrieve the number of files in the currently selected directory*/
    let numfiles = match count_files_curr_df(card) {
        Ok(val) => min(val, u16::try_from(buflen/2).unwrap()),
        Err(e) => return log3ifr_ret!(ctx,f,line!(), e),
    };
    // TODO : log if truncation occured
    if numfiles > 0 {
        let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
        let is_running_init = dp.is_running_init;
        let _unused = Box::leak(dp);

        /* collect the IDs of files in the currently selected directory, restrict to max. 255, because addressing has 1 byte only */
        for i  in 0..u8::try_from(numfiles).unwrap() {
            let idx = usize::from(i) * 2;
            let mut rbuf = match file_info(card, i) {
                Ok(val) => val,
                Err(e)    => return log3ifr_ret!(ctx,f,line!(), e),
            };
//println!("{:X?}", rbuf);
            buf[idx..idx+2].copy_from_slice(&rbuf[2..4]);
            if card.type_ > SC_CARD_TYPE_ACOS5_64_V3 && [FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF,
                FDB_CYCLIC_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF, FDB_SE_FILE].contains(&rbuf[0]) {
                if rbuf[4]>0 || rbuf[6]>0 {return log3ifr_ret!(ctx,f,line!(), c"Only 1 byte allowed for  MRL or NOR (driver constrained)", SC_ERROR_NOT_ALLOWED);}
                rbuf[4] = rbuf[5]; //  {FDB, DCB, FILE ID, FILE ID,4 SIZE or MRL,5 SIZE or NOR,6 SFI,7 LCSI};
                rbuf[5] = rbuf[7];
            }
            rbuf[6] = match rbuf[0] { // replaces the unused ISO7816_RFU_TAG_FCP_SFI
                FDB_CHV_EF           => PKCS15_FILE_TYPE_PIN,
                FDB_SYMMETRIC_KEY_EF => PKCS15_FILE_TYPE_SECRETKEY,
                //FDB_RSA_KEY_EF     => PKCS15_FILE_TYPE_RSAPRIVATEKEY, // must be corrected for public key files later on
                //FDB_ECC_KEY_EF     => PKCS15_FILE_TYPE_ECCPRIVATEKEY, // must be corrected for public key files later on
                _                    => PKCS15_FILE_TYPE_NONE, // the default: not relevant for PKCS#15; will be changed for some files later on
            };

            if is_running_init {
                let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
                let predecessor = dp.files.insert(file_id(rbuf),
                                                  ([0; SC_MAX_PATH_SIZE], rbuf, None, None, None));
                card.drv_data = Box::into_raw(dp).cast::<c_void>();
                if predecessor.is_some() {
                    return log3ifr_ret!(ctx,f,line!(), c"### Duplicate file id disallowed by the driver ! ###", SC_ERROR_FILE_ALREADY_EXISTS)
                }
            }
        } // for
    }
    log3ifr_ret!(ctx,f,line!(), i32::from(numfiles)*2 )
}


/*
 *  Evaluates file header bytes from TLV with T= ISO7816_TAG_FCI or ISO7816_TAG_FCP,
 *  provided from select_file response data (opensc calls this function only from iso7816_select_file)
 *
 *  @apiNote  iso7816_select_file positions buf by calling sc_asn1_read_tag such that the first 2 bytes (Tag 0x6F and
 *            L==buflen are skipped)
 *  @param  card    INOUT
 *  @param  file    INOUT iso7816_select_file allocates a file object, field 'path' assigned
 *  @param  buf     IN    Must point to V[0] of FCI's first TLV
 *  @param  buflen  IN    L of FCI's first TLV
 *  @return         SC_SUCCESS or error code from errors.rs
 */
#[named]
extern "C" fn acos5_process_fci(card_ptr: *mut sc_card, file_ptr: *mut sc_file,
                                buf_ref_ptr: *const u8, buflen: usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || file_ptr.is_null() || buflen==0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let file = unsafe { &mut *file_ptr };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
/*
    let mut buf_vec : Vec<u8> = Vec::with_capacity(90);
    buf_vec.extend_from_slice(unsafe { from_raw_parts(buf_ref_ptr, buflen) });
    println!("buf_vec: {:X?}", buf_vec);
*/
    /* save all the FCI data for future use */
    let mut rv = unsafe { sc_file_set_prop_attr(file, buf_ref_ptr, buflen) };
    assert_eq!(rv, SC_SUCCESS);
    assert!(file.prop_attr_len > 0);
    assert!(!file.prop_attr.is_null());
    rv = unsafe { (*(*sc_get_iso7816_driver()).ops).process_fci.unwrap()(card, file, buf_ref_ptr, buflen) };
    assert_eq!(rv, SC_SUCCESS);

    let fci = Fci::new_parsed(card, unsafe { from_raw_parts(buf_ref_ptr, buflen) });

    // perform some corrective actions
    if  file.type_ == 0 && [FDB_ECC_KEY_EF, FDB_SE_FILE].contains(&fci.fdb) {
        file.type_ = SC_FILE_TYPE_INTERNAL_EF;
    }
    debug_assert_ne!(0, file.type_);
    if file.type_ != SC_FILE_TYPE_DF && file.ef_structure != SC_FILE_EF_TRANSPARENT {
        file.record_length = fci.mrl.into();
        file.record_count  = fci.nor.into();
        file.size          = fci.size.into();
    }

    /* Map from scb8 to file.acl array */
    map_scb8_to_acl(card, file, fci.scb8, fci.fdb);

    let mut dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    assert!(dp.files.contains_key(&fci.fid));
    let dp_files_value = dp.files.get_mut(&fci.fid).unwrap();
//println!("on entry; dp_files_value: {:X?}", dp_files_value);
    /* if dp_files_value.1[0] == FDB_MF && dp_files_value.1[4..] == [0u8, 0, 0xFF, 0xFF] */  // correct the initially unknown/incorrect lcsi setting
    dp_files_value.1[7] = fci.lcsi;
    let _unused = dp_files_value.2.get_or_insert(fci.scb8);

    if  file_id(dp_files_value.1) == 0 { // assume dp_files_value.1 wasn't provided by list_files, i.e. insert by acos5_create_file
        dp_files_value.1[0] = fci.fdb;
        dp_files_value.1[2..4].copy_from_slice(&fci.fid.to_be_bytes());
        if  file.type_!= SC_FILE_TYPE_DF && file.ef_structure != SC_FILE_EF_TRANSPARENT {
            dp_files_value.1[4..6].copy_from_slice( &[u8::try_from(fci.mrl).unwrap(), u8::try_from(fci.nor).unwrap()] );
        }
        else {
            dp_files_value.1[4..6].copy_from_slice(&u16::try_from(file.size).unwrap().to_be_bytes());
        }
//      dp_files_value.1[6] = sfi;
    }
/*
    if [FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&dp_files_value.1[0]) && dp_files_value.1[6] == 0xFF {
        /* a better, more sophisticated distinction requires more info. Here, readable or not. Possibly read first byte from file */
        if  dp_files_value.1[0] == FDB_RSA_KEY_EF {
            dp_files_value.1[6] = if fci.scb8[READ] != 0xFF {PKCS15_FILE_TYPE_RSAPUBLICKEY} else {PKCS15_FILE_TYPE_RSAPRIVATEKEY};
        }
        else {
            dp_files_value.1[6] = if fci.scb8[READ] != 0xFF {PKCS15_FILE_TYPE_ECCPUBLICKEY} else {PKCS15_FILE_TYPE_ECCPRIVATEKEY};
        }
    }
*/
    if is_DFMF(fci.fdb) {
        if  dp_files_value.1[4..6] == [0_u8; 2] {
            dp_files_value.1[4..6].copy_from_slice(&fci.seid.to_be_bytes());
        }

        if  dp_files_value.4.is_none() && !fci.sae.is_empty() {
//            println!("fci.fid: {:X}, fci.sae: {:X?}", fci.fid, fci.sae);
            dp_files_value.4 = match se_parse_sae(&mut dp_files_value.3, &fci.sae) {
                Ok(val) => Some(val),
                Err(e) => { card.drv_data = Box::into_raw(dp).cast::<c_void>(); return log3ifr_ret!(ctx,f,line!(), e) },
            }
        }
    }

//println!("on exit;  dp_files_value: {:X?}", dp_files_value);
    card.drv_data = Box::into_raw(dp).cast::<c_void>();
    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
} // acos5_process_fci


// assembles the byte string/data part for file creation via command "Create File"
// TODO special treatment for DF/MF is missing: optional ISO7816_RFU_TAG_FCP_SAE
// ATTENTION : expects from file.type the fdb , but NOT what usually is in file.type like e.g. SC_FILE_TYPE_WORKING_EF
#[named]
extern "C" fn acos5_construct_fci(card_ptr: *mut sc_card, file_ref_ptr: *const sc_file,
                                  out_ptr: *mut u8, outlen_ptr: *mut usize) -> i32
{
/* file 5032 created by OpenSC  pkcs15-init  --create-pkcs15 --so-pin 87654321
30 56 02 01 00 04 06 30 AB 40 68 81 C7 0C 23 68 74 74 70 73 3A 2F 2F 67 69 74 68 75 62 2E 63 6F 6D 2F 63 61 72 62 6C 75 65 2F 61 63 6F 73 35 5F
36 34 80 0D 41 43 4F 53 35 2D 36 34 20 43 61 72 64 03 02 04 10 A5 11 18 0F 32 30 31 39 30 39 30 31 31 38 30 37 34 37 5A 00 00 00 00

SEQUENCE (6 elem)
  INTEGER 0
  OCTET STRING (6 byte) 30AB406881C7
  UTF8String https://github.com/carblue/acos5_64
  [0] ACOS5-64 Card
  BIT STRING (4 bit) 0001
  [5] (1 elem)
    GeneralizedTime 2019-09-01 18:07:47 UTC


6F 16  83 02 2F 00   82 02 01 00  80 02 00 21  8C 08 7F 01 FF 01 01 FF 01 00
6F 30  83 02 41 00 88 01 00 8A 01 05 82 02 38 00 8D 02 41 03 84 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30 8C 08 7F 03 FF 00 01 01 01 01 AB 00

6F 16  83 02 41 01   82 06 0A 00 00 15 00 01   8C 08 7F 03 FF 00 FF FF 01 FF
6F 16  83 02 41 02   82 06 0C 00 00 25 00 0C   8C 08 7F 03 FF 00 FF 01 01 FF
6F 16  83 02 41 03   82 06 1C 00 00 38 00 08   8C 08 7F 03 FF 00 FF 00 03 00

6F 16  83 02 50 31   82 02 01 00  80 02 00 6C  8C 08 7F 03 FF 00 03 FF 00 00
6F 16  83 02 41 11   82 02 01 00  80 02 00 80  8C 08 7F 03 FF 00 03 FF 00 00
6F 16  83 02 41 20   82 02 01 00  80 02 06 80  8C 08 7F 01 FF 00 01 FF 01 00

6F 16  83 02 41 31   82 02 09 00  80 02 02 15  8C 08 7F 01 FF 00 01 00 01 00
6F 16  83 02 41 F1   82 02 09 00  80 02 05 05  8C 08 7F 01 FF 00 01 01 01 FF
*/
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || file_ref_ptr.is_null() || out_ptr.is_null() ||
        outlen_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let outlen = unsafe { &mut *outlen_ptr };
    if *outlen < 2 {
        return SC_ERROR_BUFFER_TOO_SMALL;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    let file_ref = unsafe { &*file_ref_ptr };
    log3ifc!(ctx,f,line!());
    log3if!(ctx,f,line!(), c"path: %zu, %s",    file_ref.path.len,
        unsafe{sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len)} );
    log3if!(ctx,f,line!(), c"name: %zu, %s",    file_ref.namelen,
        unsafe{sc_dump_hex(file_ref.name.as_ptr(), file_ref.namelen)} );
    log3if!(ctx,f,line!(), c"type_: %u",        file_ref.type_);
    log3if!(ctx,f,line!(), c"id: 0x%X",         file_ref.id);
    log3if!(ctx,f,line!(), c"size: %zu",        file_ref.size);
    log3if!(ctx,f,line!(), c"ef_structure: %u", file_ref.ef_structure);
//    log3if!(ctx,f,line!(), c"status: %u",         file_ref.status);
//    log3if!(ctx,f,line!(), c"shareable: %u",      file_ref.shareable);
//    log3if!(ctx,f,line!(), c"sid: %d",            file_ref.sid);
//    log3if!(ctx,f,line!(), c"prop_attr_len: %zu", file_ref.prop_attr_len);
/* * /
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_SELECT]: %p", file_ref.acl[ 0]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_LOCK]: %p",   file_ref.acl[ 1]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_DELETE]: %p", file_ref.acl[ 2]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_CREATE]: %p", file_ref.acl[ 3]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_REHABILITATE]: %p", file_ref.acl[ 4]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_INVALIDATE]: %p",   file_ref.acl[ 5]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_LIST_FILES]: %p",   file_ref.acl[ 6]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_CRYPTO]: %p", file_ref.acl[ 7]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_DELETE_SELF]: %p", file_ref.acl[ 8]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_DECRYPT]: %p", file_ref.acl[ 9]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_ENCRYPT]: %p", file_ref.acl[10]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_COMPUTE_SIGNATURE]: %p", file_ref.acl[11]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_VERIFY_SIGNATURE]: %p",  file_ref.acl[12]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_COMPUTE_CHECKSUM]: %p",  file_ref.acl[13]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PSO_VERIFY_CHECKSUM]: %p",   file_ref.acl[14]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_INTERNAL_AUTHENTICATE]: %p", file_ref.acl[15]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_EXTERNAL_AUTHENTICATE]: %p", file_ref.acl[16]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PIN_DEFINE]: %p",            file_ref.acl[17]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PIN_CHANGE]: %p", file_ref.acl[18]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PIN_RESET]: %p",  file_ref.acl[19]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_ACTIVATE]: %p",   file_ref.acl[20]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_DEACTIVATE]: %p", file_ref.acl[21]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_READ]: %p",       file_ref.acl[22]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_UPDATE]: %p",     file_ref.acl[23]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_WRITE]: %p",      file_ref.acl[24]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_RESIZE]: %p",     file_ref.acl[25]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_GENERATE]: %p",   file_ref.acl[26]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_CREATE_EF]: %p",  file_ref.acl[27]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_CREATE_DF]: %p",  file_ref.acl[28]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_ADMIN]: %p",      file_ref.acl[29]);
    log3if!(ctx,f,line!(), c"acl[SC_AC_OP_PIN_USE]: %p",    file_ref.acl[30]);
/ * */

    /* file type in profile to be entered aus FDB: File Descriptor Byte */
    let acl_category = match u8::try_from(file_ref.type_).unwrap() {
        FDB_DF | FDB_MF        => ACL_CATEGORY_DF_MF,
        FDB_TRANSPARENT_EF |
        FDB_LINEAR_FIXED_EF |
        FDB_LINEAR_VARIABLE_EF |
        FDB_CYCLIC_EF |
        FDB_CHV_EF             => ACL_CATEGORY_EF_CHV,
        FDB_RSA_KEY_EF |
        FDB_ECC_KEY_EF |
        FDB_SYMMETRIC_KEY_EF   => ACL_CATEGORY_KEY,
        FDB_SE_FILE            => ACL_CATEGORY_SE,
        _                      => {
println!("Failure: Non-match in let acl_category. file_ref.type_: {}", file_ref.type_);
            return SC_ERROR_NOT_ALLOWED;
        }, // this includes FDB_PURSE_EF: unknown acl_category
    };

//println!("\nacl_category: {}, file to create: {:02X?}", acl_category, *file_ref);
    let bytes_tag_fcp_sac = match convert_acl_array_to_bytes_tag_fcp_sac(/*card,*/ &file_ref.acl, acl_category) {
        Ok(val) => val,
        Err(e) => { println!("\n\nError xyz\n\n"); return e; },
    };
//println!("bytes_tag_fcp_sac: {:X?}", bytes_tag_fcp_sac); // bytes_tag_fcp_sac: [7F, 1, FF, 1, 1, 1, 1, 1]
    let mut buf2 = [0; 2];
    let mut ptr_diff_sum = 0_usize; // difference/distance of p and out   #![feature(ptr_offset_from)]
    let mut p = out_ptr;
    unsafe { *p = ISO7816_TAG_FCP }; // *p++ = 0x6F;  p++;
    p = unsafe { p.add(2) };
    ptr_diff_sum += 2;

    /* 4 bytes will be written for tag ISO7816_TAG_FCP_FID (0x83)  MANDATORY */
    buf2.copy_from_slice(&u16::try_from(file_ref.id).unwrap().to_be_bytes());
    let mut rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_FID), buf2.as_ptr(), 2, p, *outlen-ptr_diff_sum, &mut p) };
    assert_eq!(SC_SUCCESS, rv);
    ptr_diff_sum += 4;

    /* 1 or 5 bytes will be written for tag ISO7816_TAG_FCP_TYPE (0x82) MANDATORY */
    //  e.g.  {82 06} 0A 00 00 15 00 01
    let fdb = u8::try_from(file_ref.type_).unwrap();
    if [FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF, FDB_SE_FILE].contains(&fdb) &&
        (file_ref.record_length==0 || file_ref.record_count==0) { return SC_ERROR_INVALID_ARGUMENTS; }
    if [FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF, FDB_SE_FILE].contains(&fdb) {
        let mut rec_buf = [0; 5];
//        05h    FDB+DCB+00h+MRL+NOR
        rec_buf[0] = fdb;
        rec_buf[3] = u8::try_from(file_ref.record_length).unwrap();
        rec_buf[4] = u8::try_from(file_ref.record_count).unwrap();
        rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_TYPE), rec_buf.as_ptr(), 5, p, *outlen-ptr_diff_sum, &mut p) };
        assert_eq!(SC_SUCCESS, rv);
        ptr_diff_sum += 7;
    }
    else {
        buf2[0] = fdb;
        buf2[1] = 0;
        rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_TYPE), buf2.as_ptr(), 2, p, *outlen-ptr_diff_sum, &mut p) };
        assert_eq!(SC_SUCCESS, rv);
        ptr_diff_sum += 4;
    }

    /* 3 bytes will be written for tag ISO7816_TAG_FCP_LCS (0x8A) */
    buf2[0] = 1; // skip cos5 command "Activate File" and create as activated
    rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_LCS), buf2.as_ptr(), 1, p, *outlen-ptr_diff_sum, &mut p) };
    assert_eq!(SC_SUCCESS, rv);
    ptr_diff_sum += 3;

    if [FDB_TRANSPARENT_EF, FDB_RSA_KEY_EF, FDB_ECC_KEY_EF].contains(&fdb) { // any non-record-based, non-DF/MF fdb
        /* 4 bytes will be written for tag ISO7816_TAG_FCP_SIZE (0x80) */
        assert!(file_ref.size > 0);
        buf2.copy_from_slice(&u16::try_from(file_ref.size).unwrap().to_be_bytes());
        rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_SIZE), buf2.as_ptr(), 2, p, *outlen-ptr_diff_sum, &mut p) };
        assert_eq!(SC_SUCCESS, rv);
        ptr_diff_sum += 4;
    }

    /*  bytes will be written for tag ISO7816_RFU_TAG_FCP_SAC (0x8C) MANDATORY */
    rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_RFU_TAG_FCP_SAC), bytes_tag_fcp_sac.as_ptr(), bytes_tag_fcp_sac.len(),
                             p, *outlen-ptr_diff_sum, &mut p) };
    assert_eq!(SC_SUCCESS, rv);
    ptr_diff_sum += 2+bytes_tag_fcp_sac.len();

    if is_DFMF(fdb) {
        /* 4 bytes will be written for tag ISO7816_RFU_TAG_FCP_SEID (0x8D) */
        buf2.copy_from_slice(&u16::try_from(file_ref.id+3).unwrap().to_be_bytes());
        rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_RFU_TAG_FCP_SEID), buf2.as_ptr(), 2, p, *outlen-ptr_diff_sum, &mut p) };
        assert_eq!(SC_SUCCESS, rv);
        ptr_diff_sum += 4;

        if file_ref.namelen>0 {
            /* bytes will be written for tag ISO7816_TAG_FCP_DF_NAME (0x84) */
            rv = unsafe { sc_asn1_put_tag(u32::from(ISO7816_TAG_FCP_DF_NAME), file_ref.name.as_ptr(), file_ref.namelen, p, *outlen-ptr_diff_sum, &mut p) };
            assert_eq!(SC_SUCCESS, rv);
            ptr_diff_sum += 2+file_ref.namelen;
        }
        //ISO7816_RFU_TAG_FCP_SAE
    }

    unsafe { *out_ptr.add(1) = u8::try_from(ptr_diff_sum-2).unwrap(); };
    *outlen = ptr_diff_sum;

    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[named]
extern "C" fn acos5_pin_cmd(card_ptr: *mut sc_card, data_ptr: *mut sc_pin_cmd_data, tries_left_ptr: *mut i32) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } /*|| data_ptr.is_null()*/ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    if data_ptr.is_null() {
        log3if!(ctx,f,line!(), c"called for data_ptr: %p", data_ptr);
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let pin_cmd_data = unsafe { &mut *data_ptr };
    let mut dummy_tries_left : i32 = -1;

    log3if!(ctx,f,line!(), c"called for cmd: %d", pin_cmd_data.cmd);

    if      SC_PIN_CMD_GET_INFO == pin_cmd_data.cmd { // pin1 used, pin2 unused
        if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 {
            /*let rv =*/ pin_get_policy(card, pin_cmd_data,
                             if tries_left_ptr.is_null() {
                                 &mut dummy_tries_left
                             }
                             else {
                                 unsafe { &mut *tries_left_ptr }
                             }
            )
        }
        else {
            let file_id = file_id_from_cache_current_path(card);
//println!("file_id: {:X}", file_id);
            let scb_verify = se_get_sae_scb(card, [0_u8, 0x20, 0, u8::try_from(pin_cmd_data.pin_reference).unwrap()]);
//println!("scb_verify: {:X}", scb_verify);

            if scb_verify == 0xFF {
                log3if!(ctx,f,line!(), c"SC_PIN_CMD_GET_INFO won't be done: It's not allowed by SAE");
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
            }
            else if (scb_verify & 0x40) == 0x40  &&  SC_AC_CHV == pin_cmd_data.pin_type {
                let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_verify & 0x1F);
//println!("res_se_sm: {:?}", res_se_sm);
                if res_se_sm.0 {
                    card.sm_ctx.info.cmd = SM_CMD_PIN;
                    sm_pin_cmd_get_policy(card, pin_cmd_data,
                                          if tries_left_ptr.is_null() { &mut dummy_tries_left }
                                          else { unsafe { &mut *tries_left_ptr } })
                }
                else {
                    log3if!(ctx,f,line!(),
                        c"SC_PIN_CMD_GET_INFO won't be done: It's SM protected, but the CRT template(s) don't accomplish requirements");
                    SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
                }
            }
            else {
                pin_get_policy(card, pin_cmd_data,
                                        if tries_left_ptr.is_null() {
                                            &mut dummy_tries_left
                                        }
                                        else {
                                            unsafe { &mut *tries_left_ptr }
                                        }
                )
            }
        }
    }

    else if SC_PIN_CMD_VERIFY   == pin_cmd_data.cmd { // pin1 is used, pin2 unused
        //log3if!(ctx,f,line!(), c"pin_cmd_data.pin_type:  %u", pin_cmd_data.pin_type);
        //log3if!(ctx,f,line!(), c"pin_cmd_data.pin1.len:  %lu", pin_cmd_data.pin1.len);
        //log3if!(ctx,f,line!(), c"pin_cmd_data.pin1.data: %p", pin_cmd_data.pin1.data);
        if SC_AC_CHV != pin_cmd_data.pin_type || pin_cmd_data.pin1.len == 0 || pin_cmd_data.pin1.data.is_null() {
            //log3if!(ctx,f,line!(), c"returning from here with SC_ERROR_INVALID_ARGUMENTS!");
            return SC_ERROR_INVALID_ARGUMENTS;
        }
/*
        println!("SC_PIN_CMD_VERIFY: before execution:");
        println!("pin_cmd_data.cmd:           {:X}", pin_cmd_data.cmd);
        println!("pin_cmd_data.flags:         {:X}", pin_cmd_data.flags);
        println!("pin_cmd_data.pin_type:      {:X}", pin_cmd_data.pin_type);
        println!("pin_cmd_data.pin_reference: {:X}", pin_cmd_data.pin_reference);

        println!("pin_cmd_data.apdu:          {:p}", pin_cmd_data.apdu);
        println!("pin_cmd_data.pin2.len:      {}", pin_cmd_data.pin2.len);
        println!();
        println!("pin_cmd_data.pin1.prompt:   {:p}", pin_cmd_data.pin1.prompt);
        println!("pin_cmd_data.pin1.data:     {:p}", pin_cmd_data.pin1.data);
        println!("pin_cmd_data.pin1.len:      {}", pin_cmd_data.pin1.len);
        if ! pin_cmd_data.pin1.data.is_null() {
            println!("pin_cmd_data.pin1           {:X?}", unsafe { from_raw_parts(pin_cmd_data.pin1.data, usize::try_from(pin_cmd_data.pin1.len).unwrap()) } );
        }
        println!("pin_cmd_data.pin1.min_length:      {}", pin_cmd_data.pin1.min_length);
        println!("pin_cmd_data.pin1.max_length:      {}", pin_cmd_data.pin1.max_length);
        //println!("pin_cmd_data.pin1.stored_length:   {}", pin_cmd_data.pin1.stored_length);

        println!("pin_cmd_data.pin1.encoding:        {:X}", pin_cmd_data.pin1.encoding);
        println!("pin_cmd_data.pin1.pad_length:      {}", pin_cmd_data.pin1.pad_length);
        println!("pin_cmd_data.pin1.pad_char:        {}", pin_cmd_data.pin1.pad_char);

        println!("pin_cmd_data.pin1.offset:          {}", pin_cmd_data.pin1.offset);
        //println!("pin_cmd_data.pin1.length_offset:   {}", pin_cmd_data.pin1.length_offset);

        println!("pin_cmd_data.pin1.max_tries:   {}", pin_cmd_data.pin1.max_tries);
        println!("pin_cmd_data.pin1.tries_left:  {}", pin_cmd_data.pin1.tries_left);
        println!("pin_cmd_data.pin1.logged_in:   {}", pin_cmd_data.pin1.logged_in);
//        println!("pin_cmd_data.pin1.acls:        {:?}", pin_cmd_data.pin1.acls);
        println!();
*/
/*
SC_PIN_CMD_VERIFY: before execution:
pin_cmd_data.cmd:           0
pin_cmd_data.flags:         2
pin_cmd_data.pin_type:      1
pin_cmd_data.pin_reference: 81
pin_cmd_data.apdu:          0x0
pin_cmd_data.pin2.len:      0

pin_cmd_data.pin1.prompt:   0x0
pin_cmd_data.pin1.data:     0x5558bdf12cc0
pin_cmd_data.pin1.len:      8
pin_cmd_data.pin1           [31, 32, 33, 34, 35, 36, 37, 38]
pin_cmd_data.pin1.min_length:      4
pin_cmd_data.pin1.max_length:      8
pin_cmd_data.pin1.stored_length:   0
pin_cmd_data.pin1.encoding:        0
pin_cmd_data.pin1.pad_length:      8
pin_cmd_data.pin1.pad_char:        255
pin_cmd_data.pin1.offset:          0  -> 5
pin_cmd_data.pin1.length_offset:   0
pin_cmd_data.pin1.max_tries:   0
pin_cmd_data.pin1.tries_left:  0      -> -1
pin_cmd_data.pin1.logged_in:   0      -> 1

SC_PIN_CMD_VERIFY: after execution:
pin_cmd_data.pin1.offset:          5
pin_cmd_data.pin1.length_offset:   0
pin_cmd_data.pin1.max_tries:   0
pin_cmd_data.pin1.tries_left:  -1
pin_cmd_data.pin1.logged_in:   1
*/

        if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 {
            /*let rv =*/ unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
/*
println!("SC_PIN_CMD_VERIFY: after execution:");
println!("pin_cmd_data.pin1.offset:          {}", pin_cmd_data.pin1.offset);
//println!("pin_cmd_data.pin1.length_offset:   {}", pin_cmd_data.pin1.length_offset);
println!("pin_cmd_data.pin1.max_tries:   {}", pin_cmd_data.pin1.max_tries);
println!("pin_cmd_data.pin1.tries_left:  {}", pin_cmd_data.pin1.tries_left);
println!("pin_cmd_data.pin1.logged_in:   {}", pin_cmd_data.pin1.logged_in);
println!();
            rv
*/
        }
        else {
            let file_id = file_id_from_cache_current_path(card);
//println!("file_id: {:X}", file_id);
            let scb_verify = se_get_sae_scb(card, [0_u8, 0x20, 0, u8::try_from(pin_cmd_data.pin_reference).unwrap()]);
//println!("scb_verify: {:X}", scb_verify);

            if scb_verify == 0xFF {
                log3if!(ctx,f,line!(), c"SC_PIN_CMD_VERIFY won't be done: It's not allowed by SAE");
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
            }
            else if (scb_verify & 0x40) == 0x40  &&  SC_AC_CHV == pin_cmd_data.pin_type {
                let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_verify & 0x1F);
//println!("res_se_sm: {:?}", res_se_sm);
                // TODO think about whether SM mode Confidentiality should be enforced
                if res_se_sm.0 {
                    card.sm_ctx.info.cmd = SM_CMD_PIN_VERIFY;
                    /*let rv =*/ sm_pin_cmd(card, pin_cmd_data, if tries_left_ptr.is_null() { &mut dummy_tries_left }
                    else { unsafe { &mut *tries_left_ptr } }, res_se_sm.1)
                    /*
                    println!("SC_PIN_CMD_VERIFY: after execution:");
                    println!("pin_cmd_data.pin1.offset:          {}", pin_cmd_data.pin1.offset);
                    println!("pin_cmd_data.pin1.length_offset:   {}", pin_cmd_data.pin1.length_offset);
                    println!("pin_cmd_data.pin1.max_tries:   {}", pin_cmd_data.pin1.max_tries);
                    println!("pin_cmd_data.pin1.tries_left:  {}", pin_cmd_data.pin1.tries_left);
                    println!("pin_cmd_data.pin1.logged_in:   {}", pin_cmd_data.pin1.logged_in);
                    println!();
                                        rv
                    */
                }
                else {
                    log3if!(ctx,f,line!(), c"SC_PIN_CMD_VERIFY won't be done: It's SM protected, but the CRT }\
                        template(s) don't accomplish requirements");
                    SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
                }
            }
            else {
                unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
            }
        }
    }

    else if SC_PIN_CMD_CHANGE   == pin_cmd_data.cmd { // pin1 is old pin, pin2 is new pin
        if pin_cmd_data.pin1.len == 0 || pin_cmd_data.pin1.data.is_null() ||
           pin_cmd_data.pin2.len == 0 || pin_cmd_data.pin2.data.is_null() ||
           pin_cmd_data.pin1.len != pin_cmd_data.pin2.len ||
           pin_cmd_data.pin1.len  > 8 {
            return SC_ERROR_INVALID_ARGUMENTS;
        }

        if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 {
            unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
        }
        else {
            let file_id = file_id_from_cache_current_path(card);
//println!("file_id: {:X}", file_id);
            let scb_change_code = se_get_sae_scb(card, [0_u8,0x24,0,u8::try_from(pin_cmd_data.pin_reference).unwrap()]);
//println!("scb_change_code: {:X}", scb_change_code);

            if scb_change_code == 0xFF {
                log3if!(ctx,f,line!(), c"SC_PIN_CMD_CHANGE won't be done: It's not allowed by SAE");
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
            }
            else if (scb_change_code & 0x40) == 0x40  &&  SC_AC_CHV == pin_cmd_data.pin_type {
                let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_change_code & 0x1F);
//println!("res_se_sm: {:?}", res_se_sm);
                // TODO think about whether SM mode Confidentiality should be enforced
                if res_se_sm.0 {
                    card.sm_ctx.info.cmd = SM_CMD_PIN_SET_PIN; /*let rv =*/
                    sm_pin_cmd(card, pin_cmd_data, if tries_left_ptr.is_null() { &mut dummy_tries_left }
                    else { unsafe { &mut *tries_left_ptr } }, res_se_sm.1)
                }
                else {
                    log3if!(ctx,f,line!(), c"SC_PIN_CMD_CHANGE won't be done: It's SM protected, but the CRT \
                        template(s) don't accomplish requirements");
                    SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
                }
            }
            else {
                unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
            }
        }
    }

    else if SC_PIN_CMD_UNBLOCK  == pin_cmd_data.cmd { // pin1 is PUK, pin2 is new pin for the one blocked
        if  pin_cmd_data.pin1.len == 0 || pin_cmd_data.pin1.data.is_null() ||
            pin_cmd_data.pin2.len == 0 || pin_cmd_data.pin2.data.is_null() ||
            pin_cmd_data.pin1.len != pin_cmd_data.pin2.len ||
            pin_cmd_data.pin1.len  > 8 {
            return SC_ERROR_INVALID_ARGUMENTS;
        }

        if card.type_ == SC_CARD_TYPE_ACOS5_64_V2 {
            unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
        }
        else {
            let file_id = file_id_from_cache_current_path(card);
//println!("file_id: {:X}", file_id);
            let scb_unblock_pin = se_get_sae_scb(card, [0_u8,0x24,0,u8::try_from(pin_cmd_data.pin_reference).unwrap()]);
//println!("scb_unblock_pin: {:X}", scb_unblock_pin);

            if scb_unblock_pin == 0xFF {
                log3if!(ctx,f,line!(), c"SC_PIN_CMD_CHANGE won't be done: It's not allowed by SAE");
                SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
            }
            else if (scb_unblock_pin & 0x40) == 0x40  &&  SC_AC_CHV == pin_cmd_data.pin_type {
                let res_se_sm = se_get_is_scb_suitable_for_sm_has_ct(card, file_id, scb_unblock_pin & 0x1F);
//println!("res_se_sm: {:?}", res_se_sm);
                // TODO think about whether SM mode Confidentiality should be enforced
                if res_se_sm.0 {
                    card.sm_ctx.info.cmd = SM_CMD_PIN_RESET; /*let rv =*/
                    sm_pin_cmd(card, pin_cmd_data, if tries_left_ptr.is_null() { &mut dummy_tries_left }
                    else { unsafe { &mut *tries_left_ptr } }, res_se_sm.1)
                }
                else {
                    log3if!(ctx,f,line!(), c"SC_PIN_CMD_CHANGE won't be done: It's SM protected, but the CRT \
                        template(s) don't accomplish requirements");
                    SC_ERROR_SECURITY_STATUS_NOT_SATISFIED
                }
            }
            else {
                unsafe { (*(*sc_get_iso7816_driver()).ops).pin_cmd.unwrap()(card, pin_cmd_data, tries_left_ptr) }
            }
        }
    }

    else {
        SC_ERROR_NO_CARD_SUPPORT
    }
}


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
/// Reads an RSA or EC public key file and outputs formatted as DER
/// wrong documentation
/// @param  `card`       INOUT
/// @param  `algorithm`  IN     Number of bytes available in buf from position buf onwards\
/// @param  `key_path`   OUT    Receiving address for: Class\
/// @param  `tag_out`  OUT    Receiving address for: Tag\
/// @param  `taglen`   OUT    Receiving address for: Number of bytes available in V\
/// @return          `SC_SUCCESS`  or error code\
/// On error, buf may have been set to NULL, and (except on `SC_ERROR_ASN1_END_OF_CONTENTS`) no OUT param gets set\
/// OUT `tag_out` and `taglen` are guaranteed to have values set on `SC_SUCCESS`  (`cla_out` only, if also (buf\[0\] != 0xff && buf\[0\] != 0))\
extern "C" fn acos5_read_public_key(card_ptr: *mut sc_card,
                                    algorithm: u32,
                                    key_path_ptr: *mut sc_path,
                                    key_reference: u32, /* unused */
                                    modulus_length: u32, /* bits, max. 4096 */
                                    out: *mut *mut u8,
                                    out_len: *mut usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || key_path_ptr.is_null() || out.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS; // TODO possibly check for out_len to small
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_read_public_key";
    log3ifc!(ctx,f,line!());
    #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
    let algorithm : c_ulong = algorithm.into();

    if ![SC_ALGORITHM_RSA, SC_ALGORITHM_EC].contains(&algorithm) {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT);
    }
    if SC_ALGORITHM_EC  == algorithm {
        return log3ifr_ret!(ctx,f,line!(), read_public_key_ec(card, key_path_ptr, out, out_len));
    }

    assert!((512..=4096).contains(&modulus_length));
    assert!(num_integer::Integer::is_multiple_of(&modulus_length, &8));
    let mlbyte = usize::try_from(modulus_length).unwrap()/8; /* key modulus_length in byte (expected to be a multiple of 32)*/
    let le_total = mlbyte + 21;
    log3if!(ctx,f,line!(), c"read public key(ref:%i; modulus_length:%i; modulus_bytes:%zu)", key_reference,
        modulus_length, mlbyte);

    let mut rv = unsafe { sc_select_file(card, key_path_ptr, null_mut()) };
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), c"failed to select public key file");
        return rv;
    }

    let mut rbuf = [0; RSAPUB_MAX_LEN];
    rv = unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            sc_read_binary(card, 0, rbuf.as_mut_ptr(), le_total, 0)
        }
        else {
            let mut flags : c_ulong = 0;
            sc_read_binary(card, 0, rbuf.as_mut_ptr(), le_total, &mut flags)
        }
    }};
  //};
    if rv < i32::try_from(le_total).unwrap() {
        log3if!(ctx,f,line!(), c"get key failed");
        return rv;
    }

    if    rbuf[0] != 0
       || rbuf[1] != u8::try_from((modulus_length+8)/128).unwrap() /* encode_key_RSA_ModulusBitLen(modulus_length) */
//     || rbuf[2] != key_path_ref.value[key_path_ref.len-2] /* FIXME RSAKEYID_CONVENTION */
//     || rbuf[3] != ( (key_path_ref.value[key_path_ref.len-1] as u16 +0xC0u16)       & 0xFFu16) as  /* FIXME RSAKEYID_CONVENTION */
//     || rbuf[4] != 3 // TODO the bit setting for ACOS5-EVO is different
    {
        log3if!(ctx,f,line!(), c"### failed: check the raw content of RSA pub file: \
            within the first 5 bytes there is content that indicates an invalid public key ###");
        return SC_ERROR_INCOMPATIBLE_KEY;
    }

    // skip leading zero bytes of exponent; usually only 3 of 16 bytes are used; otherwise pkcs15-tool.c:read_ssh_key doesn't work
    let mut view = &rbuf[5..21];
    while !view.is_empty() && view[0] == 0 {
        view = &view[1..];
    }
    let raw_exp_len = view.len(); // raw_exponent_len
    if  raw_exp_len == 0 {
        return SC_ERROR_INCOMPATIBLE_KEY;
    }
    let rsa_key = sc_pkcs15_pubkey_rsa {
        exponent: sc_pkcs15_bignum{ data: unsafe { rbuf.as_mut_ptr().add(21-raw_exp_len) }, len: raw_exp_len},
        modulus:  sc_pkcs15_bignum{ data: unsafe { rbuf.as_mut_ptr().add(21) }, len: mlbyte }
    };

    /* transform the raw content to der-encoded */
    rv = unsafe { sc_pkcs15_encode_pubkey_rsa(ctx, &rsa_key, out, out_len) };
    if rv < 0 {
        return log3ifr_ret!(ctx,f,line!(), c"Error: sc_pkcs15_encode_pubkey_rsa failed: returning with", rv);
    }
    SC_SUCCESS
}

fn read_public_key_ec(card: &mut sc_card,
                      key_path_ptr: *mut sc_path,
                      out: *mut *mut u8,
                      out_len: *mut usize) -> i32
{
    let ctx = unsafe { &mut *card.ctx };
    let f = c"read_public_key_ec";
    log3ifc!(ctx,f,line!());

    let mut rv = unsafe { sc_select_file(card, key_path_ptr, null_mut()) };
    if rv != SC_SUCCESS {
        log3if!(ctx,f,line!(), c"failed to select public key file");
        return rv;
    }

    let mut rbuf = [0; ECPUB_MAX_LEN];
    rv = unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            sc_read_binary(card, 0, rbuf.as_mut_ptr(), 6, 0)
        }
        else {
            let mut flags : c_ulong = 0;
            sc_read_binary(card, 0, rbuf.as_mut_ptr(), 6, &mut flags)
        }
    }};

   if rv < 6 {
        log3if!(ctx,f,line!(), c"get key failed");
        return rv;
    }
/*
1 ->     224 = 8*28  +6 = 34
2 ->     256 = 8*32  +6 = 38
3 ->     384 = 8*48  +6 = 54
4 -> 521 528 = 8*66  +6 = 72
*/
    if rbuf[0] != 0 // 00 04 12 01 0A 03   00 3C 00 B0 23 40 DD 4A 44 31 AF 1E 5E 0F 4F 7F 8F 98 02 D9 0D 7E 68 3A 89 49 71 16 F0 A3 8A 8C B6 9D 4A 85 37 12 79 4C 47 9D 6F 26 20 55 E2 5D 96 B1 0B 37 60 34 88 6D DC 55 36 C7 C3 3F 1A 7C 86 DF
        || ![1,2,3,4].contains(&rbuf[1]) // != u8::try_from((modulus_length+8)/128).unwrap() /* encode_key_RSA_ModulusBitLen(modulus_length) */
//     || rbuf[2] != key_path_ref.value[key_path_ref.len-2] /* FIXME RSAKEYID_CONVENTION */
//     || rbuf[3] != ( (key_path_ref.value[key_path_ref.len-1] as u16 +0xC0u16)       & 0xFFu16) as  /* FIXME RSAKEYID_CONVENTION */
        || rbuf[4] != 0x0A
        || ![2,3,4].contains(&rbuf[5])
    {
        log3if!(ctx,f,line!(), c"### failed: check the raw content of EC pub file: \
            within the first 5 bytes there is content that indicates an invalid public key ###");
        return SC_ERROR_INCOMPATIBLE_KEY;
    }
    let curve_indicator = rbuf[1];
//    let point_format_indicator = rbuf[5];
    let point_length_readable /* starting from position 5, not 6 !!! */ = match curve_indicator {
        1 => 28_u8+1,
        2 => 32+1,
        3 => 48+1,
        4 => 66+1,
        _ => 0,
    };
    rv = unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            sc_read_binary(card, 5, rbuf.as_mut_ptr(), point_length_readable.into(), 0)
        }
        else {
            let mut flags : c_ulong = 0;
            sc_read_binary(card, 5, rbuf.as_mut_ptr(), point_length_readable.into(), &mut flags)
        }
    }};

    if rv < point_length_readable.into() {
        log3if!(ctx,f,line!(), c"get key failed");
        return rv;
    }

    let mut ec_key = sc_pkcs15_pubkey_ec {
        params: sc_ec_parameters { named_curve: c"nistp521".as_ptr().cast_mut(), id: sc_object_id { value : [1, 3, 132, 0, 35,  -1,0,0,0,0,0,0,0,0,0,0] },
                                   der: sc_lv_data::default(), type_: 1, field_length: 521 },
        ecpointQ: sc_pkcs15_u8 { value: rbuf.as_mut_ptr(), len: point_length_readable.into() }
    };

    /* transform the raw content to der-encoded */
    rv = unsafe { sc_pkcs15_encode_pubkey_ec(ctx, &mut ec_key, out, out_len) };

    if rv < 0 {
        return log3ifr_ret!(ctx,f,line!(), c"Error: sc_pkcs15_encode_pubkey_ec failed: returning with", rv);
    }
    SC_SUCCESS
}

extern "C" fn acos5_set_security_env(card_ptr: *mut sc_card, env_ref_ptr: *const sc_security_env, _se_num: i32) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || env_ref_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_set_security_env";
    let env_ref  = unsafe { & *env_ref_ptr };
    log3if!(ctx,f,line!(), c"called  for operation %d", env_ref.operation);
//println!("set_security_env: *env_ref_ptr: sc_security_env: {:0X?}\n\n", *env_ref);
/*
Tokenunfo
30 7F 02 01 01 04 08 B0 35 00 5B A1 0A 65 00 0C 1A 41 64 76 61 6E 63 65 64 20 43 61 72 64 20 53 79 73 74 65 6D 73 20 4C 74 64 2E 80 14 4E 36 34
5F 42 30 33 35 30 30 35 42 41 31 30 41 36 35 30 30 03 02 04 20 A2 3A 30 1B 02 01 01 02 02 10 81 05 00 03 02 00 0C 06 09 60 86 48 01 65 03 04 01
29 02 01 04 30 1B 02 01 02 02 02 10 82 05 00 03 02 00 0C 06 09 60 86 48 01 65 03 04 01 2A 02 01 06

30819C0201010408B035005BA10A65000C1A416476616E63656420436172642053797374656D73204C74642E80144E36345F4230333530303542413130413635303003020420A257301B0201010202108105000302000C0609608648016503040129020104301B0201020202108205000302000C060960864801650304012A020106301B0201030202108505000302000C060960864801650304012A020106
*/
    set_sec_env(card, env_ref);
    let mut rv;

    if SC_SEC_OPERATION_DERIVE == env_ref.operation
//        || (SC_SEC_OPERATION_WRAP == env_ref.operation)
    {
        return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT);
    }

    else if [SC_SEC_OPERATION_GENERATE_RSAPRIVATE, SC_SEC_OPERATION_GENERATE_RSAPUBLIC,
             SC_SEC_OPERATION_GENERATE_ECCPRIVATE, SC_SEC_OPERATION_GENERATE_ECCPUBLIC].contains(&env_ref.operation)  &&
            (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0  &&
            (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0  &&
            [SC_ALGORITHM_RSA, SC_ALGORITHM_EC].contains(&env_ref.algorithm)
    {
        assert!(env_ref.file_ref.len >= 2);
        let path_idx = env_ref.file_ref.len - 2;

        let algo = algo_ref_mse_sedo(card.type_,
            if env_ref.algorithm==SC_ALGORITHM_RSA {SC_SEC_OPERATION_GENERATE_RSAPRIVATE}
            else {SC_SEC_OPERATION_GENERATE_ECCPRIVATE}, CRT_TAG_DST,
            env_ref.algorithm, 0, false, false).unwrap();
        let command = [0x00, 0x22, 0x01, CRT_TAG_DST, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01,
            if [SC_SEC_OPERATION_GENERATE_RSAPRIVATE, SC_SEC_OPERATION_GENERATE_ECCPRIVATE].contains(&env_ref.operation) {0x40} else {0x80}];
        let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS {
            return log3ifr_ret!(ctx,f,line!(), c"Error: 'Set Security Environment for Generate Key pair' failed. Returning with", rv);
        }
    }

    else if SC_SEC_OPERATION_SIGN == env_ref.operation  &&
        (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0  &&
        (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0  &&
        [SC_ALGORITHM_RSA, SC_ALGORITHM_EC].contains(&env_ref.algorithm)
    {
        assert!((env_ref.algorithm_flags & SC_ALGORITHM_RSA_PAD_ISO9796) == 0);
        assert!(env_ref.file_ref.len >= 2);
        let path_idx = env_ref.file_ref.len - 2;
        let mut algo = algo_ref_mse_sedo(card.type_, SC_SEC_OPERATION_SIGN, CRT_TAG_DST,
            env_ref.algorithm, 0, false, false).unwrap();
        let mut command = [0x00, 0x22, 0x01, CRT_TAG_DST, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS {
            //rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
            return log3ifr_ret!(ctx,f,line!(), c"Error: 'Set Security Environment for Sign' failed-Returning with", rv);
        }
        /* sign may need decrypt (for non-SHA1/SHA256 hashes), thus prepare for a CT as well */
        algo = algo_ref_mse_sedo(card.type_, 0, CRT_TAG_CT,
            env_ref.algorithm, 0, false, false).unwrap();
        command = [0x00, 0x22, 0x01, CRT_TAG_CT, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS {
            //rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
            return log3ifr_ret!(ctx,f,line!(), c"Error: 'Set Security Environment for Decrypt' failed. Returning with", rv);
        }
    }

    else if SC_SEC_OPERATION_DECIPHER == env_ref.operation  &&
        (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0  &&
        (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0  &&
        [SC_ALGORITHM_RSA, SC_ALGORITHM_EC].contains(&env_ref.algorithm)
    {
        assert!(env_ref.file_ref.len >= 2);
        let path_idx = env_ref.file_ref.len - 2;
        let algo = algo_ref_mse_sedo(card.type_, 0, CRT_TAG_CT,
            env_ref.algorithm, 0, false, false).unwrap();
        let command = [0x00, 0x22, 0x01, CRT_TAG_CT, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
        let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS {
            //rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
            return log3ifr_ret!(ctx,f,line!(), c"Error: 'Set Security Environment for Decrypt' failed. Returning with", rv);
        }
    }

    else if [SC_SEC_OPERATION_ENCIPHER_RSAPUBLIC, SC_SEC_OPERATION_ENCIPHER_ECCPUBLIC].contains(&env_ref.operation)  &&
        (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0  &&
        (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0  &&
        env_ref.algorithm==SC_ALGORITHM_RSA
    {
       assert!(env_ref.file_ref.len >= 2);
        let path_idx = env_ref.file_ref.len - 2;
        let algo = algo_ref_mse_sedo(card.type_, 0, CRT_TAG_CT,
            env_ref.algorithm, 0, false, false).unwrap();
        let command = [0x00, 0x22, 0x01, CRT_TAG_CT, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
            env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x80];
        let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//    println!("rv: {}, apdu: {:?}", rv, apdu);
        if rv != SC_SUCCESS {
            //rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
            return log3ifr_ret!(ctx,f,line!(), c"Error: 'Set Security Environment for encrypt_asym' failed", rv);
        }
    }

    else if cfg!(not(any(v0_20_0, v0_21_0, v0_22_0))) &&
        [SC_SEC_OPERATION_ENCRYPT_SYM, SC_SEC_OPERATION_DECRYPT_SYM].contains(&env_ref.operation)
        //&& (env_ref.flags & SC_SEC_ENV_KEY_REF_PRESENT) > 0  // FIXME relax and don't require this
        && (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0
        && (env_ref.flags & SC_SEC_ENV_ALG_REF_PRESENT) > 0
    {
        if env_ref.key_ref_len == 0 || ![SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&env_ref.algorithm) {
            return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_SUPPORTED);
        }

        let mut cbc = true;
        if (env_ref.algorithm & SC_ALGORITHM_AES) > 0 {
            if ![SC_ALGORITHM_AES_CBC_PAD, SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB].contains(&env_ref.algorithm_flags) {
                return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NOT_SUPPORTED);
            }
            cbc =  env_ref.algorithm_flags != SC_ALGORITHM_AES_ECB;
        }

//        let env_ref_algorithm_ref;
        let env_ref_algorithm_ref : u8 = if (env_ref.flags & SC_SEC_ENV_ALG_REF_PRESENT) > 0 {
                u8::try_from(env_ref.algorithm_ref).unwrap()
            }
            else {
                algo_ref_mse_sedo(card.type_,0, CRT_TAG_CT, env_ref.algorithm,
                                  0, cbc, false).unwrap()
            };

        let mut vec =   // made for cbc and blockSize == 16
            vec![0_u8,  0x22, 0x01,  CRT_TAG_CT, 0xFF,
                 0x95, 0x01, 0x40,
                 0x80, 0x01, 0xFF,
                 0x83, 0x01, 0xFF,
                 0x87, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if env_ref.algorithm == SC_ALGORITHM_AES {
            if !cbc { vec.truncate(vec.len()-18) }
        }
        else { // then it's SC_ALGORITHM_3DES | SC_ALGORITHM_DES    TODO check for EVO
            vec.truncate(vec.len()-8);
            let pos = vec.len()-9;
            vec[pos] = 8; // IV has len == 8. assuming it's CBC
            if [0, 1].contains(&env_ref_algorithm_ref) // DES/3DES (ECB)
            { vec.truncate(vec.len()-10); }
        }

        /*  transferring the iv is missing below 0.20.0 */
//        {
            for sec_env_param in &env_ref.params {
                match sec_env_param.param_type {
                    SC_SEC_ENV_PARAM_IV => {
                        assert!(vec.len() >= 16);
                        assert_eq!(sec_env_param.value_len, vec[15].into());
                        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                        let len : usize = sec_env_param.value_len.try_into().unwrap();
                        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                        let len : usize = sec_env_param.value_len;
                        assert_eq!(vec.len(), 16+ len);
                        vec[16..].copy_from_slice(unsafe { from_raw_parts(sec_env_param.value as *const u8, len) });
                    },
                    SC_SEC_ENV_PARAM_TARGET_FILE => { continue; }
                    _ => { break; },
                }
            }
/* * /

//                env_ref.algorithm_flags = if crypt_sym.cbc {if crypt_sym.pad_type==BLOCKCIPHER_PAD_TYPE_PKCS7 {SC_ALGORITHM_AES_CBC_PAD} else {SC_ALGORITHM_AES_CBC} } else {SC_ALGORITHM_AES_ECB};
//                env_ref.params[0] = sc_sec_env_param { param_type: SC_SEC_ENV_PARAM_IV, value: crypt_sym.iv.as_mut_ptr() as p_void, value_len: u32::from(crypt_sym.iv_len) };
                // for 3DES/DES use this to select CBC/ECB: with param_type: SC_SEC_ENV_PARAM_DES_ECB or SC_SEC_ENV_PARAM_DES_CBC

                if [SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&env_ref.algorithm) {
                    for i in 0..SC_SEC_ENV_MAX_PARAMS {
                        if vec.len()<=14 {break;}
                        if env_ref.params[i].param_type==SC_SEC_ENV_PARAM_DES_ECB { vec.truncate(vec.len()-10); }
                    }
                }
pub const SC_SEC_ENV_PARAM_DES_ECB           : u32 = 3;
pub const SC_SEC_ENV_PARAM_DES_CBC           : u32 = 4;
    pub params :          [sc_sec_env_param; SC_SEC_ENV_MAX_PARAMS],
/ * */
//        }

        vec[ 4] = u8::try_from(vec.len()-5).unwrap();
        vec[10] = env_ref_algorithm_ref;
        vec[13] = env_ref.key_ref[0];

        let mut apdu = build_apdu(ctx, &vec, SC_APDU_CASE_3_SHORT, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
        rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
        if rv != SC_SUCCESS {
            return log3ifr_ret!(ctx,f,line!(), rv);
        }
    }

    else {
     // the same for SC_SEC_OPERATION_UNWRAP as for SC_SEC_OPERATION_DECIPHER_RSAPRIVATE
        if SC_SEC_OPERATION_UNWRAP == env_ref.operation  &&
            (env_ref.flags & SC_SEC_ENV_FILE_REF_PRESENT) > 0  &&
            (env_ref.flags & SC_SEC_ENV_ALG_PRESENT) > 0  &&
            [SC_ALGORITHM_RSA, SC_ALGORITHM_EC].contains(&env_ref.algorithm)
        {
            /* unwrap a sym. algo key (AES), that was wrapped by an asym. algo key;  setting for decipher */
            assert!(env_ref.file_ref.len >= 2);
            let path_idx = env_ref.file_ref.len - 2;
            let algo = algo_ref_mse_sedo(card.type_, 0, CRT_TAG_CT,
                                     env_ref.algorithm, 0, false, false).unwrap();
            let command = [0x00, 0x22, 0x01, CRT_TAG_CT, 0x0A, 0x80, 0x01, algo, 0x81, 0x02,
                env_ref.file_ref.value[path_idx], env_ref.file_ref.value[path_idx+1],  0x95, 0x01, 0x40];
            let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_3_SHORT, &mut[]);
            rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
            rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
//println!("rv: {}, apdu: {:?}", rv, apdu);
            if rv != SC_SUCCESS {
                //rv = SC_ERROR_KEYPAD_MSG_TOO_LONG;
                return log3ifr_ret!(ctx,f,line!(), c"'Set SecEnv for RSA Decrypt' failed. Returning with", rv);
            }
/*
                println!("set_security_env_Unwrap: env_ref.flags: {:X?}", env_ref.flags);                            // 0x12: SC_SEC_ENV_FILE_REF_PRESENT | SC_SEC_ENV_ALG_PRESENT
                println!("set_security_env_Unwrap: env_ref.operation: {:X}", env_ref.operation);                     // 0x06: SC_SEC_OPERATION_UNWRAP
                println!("set_security_env_Unwrap: env_ref.algorithm: {:X?}", env_ref.algorithm);                    // 0x00: SC_ALGORITHM_RSA
                println!("set_security_env_Unwrap: env_ref.algorithm_flags: {:X?}", env_ref.algorithm_flags);        // 0x00:
                println!("set_security_env_Unwrap: env_ref.algorithm_ref: {:X?}", env_ref.algorithm_ref);            // 0x00:
                println!("set_security_env_Unwrap: env_ref.file_ref: {:?}", unsafe{CStr::from_ptr(sc_dump_hex(env_ref.file_ref.value.as_ptr(), env_ref.file_ref.len)).to_str().unwrap()} ); // "41A0"
                println!("set_security_env_Unwrap: env_ref.key_ref: {:X?}", env_ref.key_ref);                        // [0, 0, 0, 0, 0, 0, 0, 0]
                println!("set_security_env_Unwrap: env_ref.key_ref_len: {:X?}", env_ref.key_ref_len);                // 0
                println!("set_security_env_Unwrap: env_ref.target_file_ref: {:?}", unsafe{CStr::from_ptr(sc_dump_hex(env_ref.target_file_ref.value.as_ptr(), env_ref.target_file_ref.len)).to_str().unwrap()} ); // ""
                println!("set_security_env_Unwrap: env_ref.supported_algos[0]: {:X?}", env_ref.supported_algos[0]);  // sc_supported_algo_info { reference: 1, mechanism: 1081, parameters: 0x0, operations: 30, algo_id: sc_object_id { value: [2, 10, 348, 1, 65, 3, 4, 1, 29, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF] }, algo_ref: 4 }
                println!("set_security_env_Unwrap: env_ref.supported_algos[1]: {:X?}", env_ref.supported_algos[1]);  // sc_supported_algo_info { reference: 2, mechanism: 1082, parameters: 0x0, operations: 30, algo_id: sc_object_id { value: [2, 10, 348, 1, 65, 3, 4, 1, 2A, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFF] }, algo_ref: 6 }
*/
        }
        else {
            return log3ifr_ret!(ctx,f,line!(), SC_ERROR_NO_CARD_SUPPORT);
        }
    }

    log3ifr_ret!(ctx,f,line!(), SC_SUCCESS)
}

/* Should this be restricted by inspecting the padding for correctness ? */
/* decipher:  Engages the deciphering operation.  Card will use the
 *   security environment set in a call to set_security_env or
 *   restore_security_env.
 *
 *  Status Words while processing:
 *  While sending (flag SC_APDU_FLAGS_CHAINING set conditionally) transmit of chunks returns 0x9000 for cos5, until all data are sent. The last transmit returns e.g. SW 0x6100,
 *  meaning, there are 256 bytes or more to fetch, or a one only transmit for keylen<=2048 returns e.g. 0x61E0 or 0x6100.
 *  decrypted data for keylen<=2048 can be easily, automatically fetched with regular commands called by sc_transmit_apdu (sc_get_response, iso7816_get_response;
 *  olen  = apdu->resplen (before calling sc_single_transmit; after calling sc_single_transmit, all commands that return a SM 0x61?? set apdu->resplen to 0)
 *  olen gets passed to sc_get_response, which is the total size of output buffer offered.
 *  For keylen>2048
 00 C0 00 00 00
 */
/*
 * What it does The function currently relies on, that the crgram_len==keylen_bytes i.o. to control amount of bytes to expect from get_response (if keylen_bytes>256)
 * @apiNote
 * @param
 * @return  error code or number of bytes written into out
 */
/* see pkcs15-sec.c:sc_pkcs15_decipher This operation is dedicated to be used with RSA keys only ! */
extern "C" fn acos5_decipher(card_ptr: *mut sc_card, crgram_ref_ptr: *const u8, crgram_len: usize,
                                                       out_ptr:        *mut u8,     outlen: usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || crgram_ref_ptr.is_null() || out_ptr.is_null() {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_decipher";
    let mut rv;
    log3if!(ctx,f,line!(), c"called with: in_len: %zu, out_len: %zu", crgram_len, outlen);
    assert!(outlen >= crgram_len);
////assert_eq!(crgram_len, get_sec_env_mod_len(card));
//println!("acos5_decipher          called with: in_len: {}, out_len: {}, {}, crgram: {:X?}", crgram_len, outlen, get_is_running_compute_signature(card), unsafe {from_raw_parts(crgram_ref_ptr, crgram_len)});

    #[cfg(iup_user_consent)]
    {
        if get_ui_ctx(card).user_consent_enabled == 1 {
            /* (Requested by DGP): on signature operation, ask user consent */
            rv = acos5_ask_user_consent();
            if rv < 0 {
                log3ifr!(ctx,f,line!(), c"User consent denied", rv);
                return rv;
            }
        }
    }

    let command = [0, 0x2A, 0x80, 0x84, 2, 0xFF, 0xFF, 0xFF]; // will replace lc, cmd_data and le later; the last 4 bytes are placeholders only for sc_bytes2apdu
    let mut vec = vec![0_u8; outlen];
    let mut apdu = build_apdu(ctx, &command, SC_APDU_CASE_4_SHORT, &mut vec);
    apdu.data    = crgram_ref_ptr;
    apdu.datalen = crgram_len;
    apdu.lc      = crgram_len;
    apdu.le      = min(crgram_len, SC_READER_SHORT_APDU_MAX_RECV_SIZE);
    if apdu.lc > card.max_send_size {
        apdu.flags |= SC_APDU_FLAGS_CHAINING;
    }

    set_is_running_cmd_long_response(card, true); // switch to false is done by acos5_get_response
    rv = unsafe { sc_transmit_apdu(card, &mut apdu) }; if rv != SC_SUCCESS { return rv; }
    rv = unsafe { sc_check_sw(card, apdu.sw1, apdu.sw2) };
    if rv != SC_SUCCESS || apdu.resplen==0 {
        log3ift!(ctx,f,line!(), c"### 0x%02X%02X: decipher failed or \
            it's impossible to retrieve the answer from get_response ###", apdu.sw1, apdu.sw2);
        /* while using pkcs11-tool -l -t
        it may happen, that a sign-key gets tested with a hash algo unsupported by compute_signature, thus it must revert to use acos5_decipher,
        but the key isn't generated with decrypt capability: Then fake a success here, knowing, that a verify signature will fail
        Update: this doesn't help, check_sw kicks in and aborts on error 0x6A80 */
        if rv == SC_ERROR_INCORRECT_PARAMETERS { // 0x6A80 error code gets transformed by iso7816_check_sw to SC_ERROR_INCORRECT_PARAMETERS
            apdu.sw1 = 0x90;
            apdu.sw2 = 0x00;
            log3if!(ctx,f,line!(), c"### \
                decipher failed with error code 0x6A80: Multiple possible reasons for the failure; a likely harmless \
                one is, that the key is not capable to decipher but was used for deciphering (maybe called from \
                compute_signature, i.e. the intent was signing with a hash algo that compute_signature doesn't support \
                ; compute_signature reverts to decipher for any hash algo other than SHA-1 or SHA-256) ###");
        }
        assert!(rv<0);
        return rv;
    }
    //println!("acos5_decipher: apdu.resplen {}", apdu.resplen);
    vec.truncate(min(crgram_len, apdu.resplen));

    if get_is_running_compute_signature(card) {
        set_is_running_compute_signature(card, false);
    }
    else { // assuming plaintext was EME-PKCS1-v1_5 encoded before encipher: Now remove the padding
        // let sec_env_algo_flags = get_sec_env(card).algorithm_flags;
        // println!("\nacos5_decipher:             in_len: {}, out_len: {}, sec_env_algo_flags: 0x{:X}, input data: {:X?}", crgram_len, outlen, sec_env_algo_flags,  unsafe {from_raw_parts(crgram_ref_ptr, crgram_len)});
        // println!("\nacos5_decipher:             in_len: {}, out_len: {}, sec_env_algo_flags: 0x{:X},output data: {:X?}", crgram_len, outlen, sec_env_algo_flags,  vec);
        rv = me_pkcs1_strip_02_padding(&mut vec); // returns length of padding to be removed from vec such that net message/plain text remains
        if rv < 0 && ((SC_ALGORITHM_RSA_RAW & get_sec_env(card).algorithm_flags) == 0) {
            log3ifr!(ctx,f,line!(), c"returning with: Failed strip_02_padding !", rv);
            return rv;
        }
    }
    rv = i32::try_from(vec.len()).unwrap();
    unsafe { copy_nonoverlapping(vec.as_ptr(), out_ptr, vec.len()) };
    log3ifr!(ctx,f,line!(), rv);
    rv
} // acos5_decipher


/*
1. DO very very carefully inspect where acos5_compute_signature transfers the operation to acos5_decipher:
   It MUST NOT happen, that an attacker can use acos5_compute_signature to pass arbitrary data to acos5_decipher, except of Length hLen (HashLength which is max 64 bytes)

2. This should be the place to check, that the integer representing the 'message' is smaller than the integer representing the RSA key modulus !
   BUT, that's not possible here (there is no knowledge here about the RSA key modulus) !
   EMSA-PKCS1-v1_5:
       emLen = RSA key modulus length in bytes, e.g. for a 4096 bit key: 512
       EM starts with bytes 0x00, 0x01  (EM = 0x00 || 0x01 || PS || 0x00 || T).
       Thus, the modulus must start with bytes > 0x00, 0x01, e.g. the minimum is 0x00, 0x02:
           Check in acos5_gui when generating a key pair, that this condition is met

   EMSA-PSS:
      11. Set the leftmost 8emLen - emBits bits of the leftmost octet in
       maskedDB to zero.

      12. Let EM = maskedDB || H || 0xbc.

      emBits must be less than  int RSA_bits(const RSA *rsa); // RSA_bits() returns the number of significant bits.



   Definition :
         DigestInfo ::= SEQUENCE {
          digestAlgorithm DigestAlgorithm,
          digest OCTET STRING
      }

   In the following, digestAlgorithm includes the tag for SEQUENCE and a length byte (behind SEQUENCE)
   Input allowed: optional_padding  +  digestAlgorithm  +  digest

   For RSASSA-PKCS1-v1_5:
       Only for sha1 and sha256, as an exception, both optional_padding + digestAlgorithm, may be omitted from input, for all other digestAlgorithm is NOT optional.

   RSASSA-PSS : Only works with SC_ALGORITHM_RSA_RAW declared in acos5_init()

 * What it does
 Ideally this function should be adaptive, meaning it works for SC_ALGORITHM_RSA_RAW as well as for e.g. SC_ALGORITHM_RSA_PAD_PKCS1

 The function currently relies on, that data_len==keylen_bytes i.o. to control amount of bytes to expect from get_response (if keylen_bytes>256)
 It's not safe to use outlen as indicator for  keylen_bytes, e.g.: pkcs15-crypt --sign --key=5 --input=test_in_sha1.hex --output=test_out_sig_pkcs1.hex --sha-1 --pkcs1 --pin=12345678
 uses outlen==1024

 * @apiNote
 * @param
 * @return  error code (neg. value) or number of bytes written into out
 */
extern "C" fn acos5_compute_signature(card_ptr: *mut sc_card, data_ref_ptr: *const u8, data_len: usize,
                                                                   out_ptr:   *mut u8,   outlen: usize) -> i32
{
    if data_len == 0 || outlen == 0 {
        return 0;
    }
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || data_ref_ptr.is_null() || out_ptr.is_null() ||
        outlen < 64 { // cos5 supports RSA beginning from moduli 512 bits = 64 bytes
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(data_len <= outlen);
    assert!(data_len <= 512); // cos5 supports max RSA 4096-bit keys
//println!("acos5_compute_signature called with: in_len: {}, out_len: {}", data_len, outlen);
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_compute_signature";
    log3ift!(ctx,f,line!(), c"called with: in_len: %zu, out_len: %zu", data_len, outlen);
    set_is_running_compute_signature(card, false); // this is an info valuable only when delegating to acos5_decipher

    let mut rv; // = SC_SUCCESS;
    //   sha1     sha256  +md2/5 +sha1  +sha224  +sha256  +sha384  +sha512
    if ![20_usize, 32,     34,    35,    47,      51,      67,      83, get_sec_env_mod_len(card)].contains(&data_len) {
        rv = SC_ERROR_NOT_SUPPORTED;
        log3ifr!(ctx,f,line!(), c"returning with: Inadmissible data_len !", rv);
        return rv;
    }
    let digest_algorithm_sha1      =
    [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
    let digest_algorithm_sha256    =
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
    // #[allow(non_snake_case)]
    // let digestAlgorithm_sha512    =
    // [0x30_u8, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];

    let mut vec_in : Vec<u8> = Vec::with_capacity(512);
    /*
       if data_len==20, assume it's a SHA-1   digest and prepend digestAlgorithm
       if data_len==32, assume it's a SHA-256 digest and prepend digestAlgorithm
     */
    if      data_len == 20 {
        vec_in.extend_from_slice(&digest_algorithm_sha1[..]);
    }
    else if data_len == 32 {
        vec_in.extend_from_slice(&digest_algorithm_sha256[..]);
    }
    vec_in.extend_from_slice(unsafe { from_raw_parts(data_ref_ptr, data_len) });

    let sec_env_algo_flags = get_sec_env(card).algorithm_flags;
//println!("\nacos5_compute_signature:             in_len: {}, out_len: {}, sec_env_algo_flags: 0x{:X}, input data: {:X?}", vec_in.len(), outlen, sec_env_algo_flags,  vec_in);
    let digest_info =
        if (SC_ALGORITHM_RSA_RAW & sec_env_algo_flags) == 0 { vec_in.as_slice() } // then vec_in IS digest_info
        else {
//println!("acos5_compute_signature: (SC_ALGORITHM_RSA_RAW & sec_env_algo_flags) > 0");
            match me_pkcs1_strip_01_padding(&vec_in) { // TODO possibly also try pkcs1_strip_PSS_padding
                Ok(digest_info) => digest_info,
                Err(e) => {
                    if cfg!(dev_relax_signature_constraints_for_raw) && data_len==get_sec_env_mod_len(card) {
//println!("acos5_compute_signature: dev_relax_signature_constraints_for_raw is active");
                        set_is_running_compute_signature(card, true);
                        rv = acos5_decipher(card, data_ref_ptr, data_len, out_ptr, outlen);
                        log3ifr!(ctx,f,line!(), rv);
                        return rv;
/*
We are almost lost here (or have to reach into one's bag of tricks): We know, that we''ll have to switch to acos5_decipher and:
The "7.4.3.9. RSA Private Key Decrypt" command requires an input data length that must be the same as the RSA key length being used.
It's unknown here what is the RSA key length and we can't reliably deduce that from the parameters:
One of the tests of pkcs11-tool sends this:
acos5_compute_signature: called with: data_len: 34, outlen: 1024
Trick: cache last security env setting, retrieve file id (priv) and deduce key length from file size. The commands were:
00 22 01 B6 0A 80 01 10 81 02 41 F3 95 01 40 ."........A...@
00 22 01 B8 0A 80 01 13 81 02 41 F3 95 01 40 ."........A...@
*/
                    }
                    if [35, 51].contains(&vec_in.len()) /* TODO && &vec_in[0..15] != digestAlgorithm_ripemd160*/ {
                        if (vec_in.len() == 35 && vec_in[0..15] == digest_algorithm_sha1) ||
                           (vec_in.len() == 51 && vec_in[0..19] == digest_algorithm_sha256)
                        {
                            vec_in.as_slice()
                        }
                        else {
                            return e;
                        }
                    }
                    /* */
                    else if e != SC_ERROR_WRONG_PADDING || vec_in[vec_in.len() - 1] != 0xbc {
                        log3ifr!(ctx,f,line!(), c"Error: (input is neither EMSA-PKCS1-v1_5 nor EMSA-PSS \
                            encoded) returning with", e);
                        return e;
                    }
                    else {
                        return -1;
                        /* forward to acos5_decipher only, if this is really secure; a pss padding can't be detected unambiguously */
//                      set_is_running_compute_signature(card, true);
//                      return acos5_decipher(card, data_ref_ptr, data_len, out_ptr, outlen);
                    }
                }
            }
        };
//println!("digest_info.len(): {}, digest_info: {:X?}", digest_info.len(), digest_info);
    if digest_info.is_empty() { // if there is no content to sign, then don't sign
        return SC_SUCCESS;
    }

    // id_rsassa_pkcs1_v1_5_with_sha512_256 and id_rsassa_pkcs1_v1_5_with_sha3_256 also have a digest_info.len() == 51

    if  ( digest_info.len() == 35 /*SHA-1*/ || digest_info.len() == 51 /*SHA-256*/ /*|| digest_info.len() == 83 / *SHA-512* / */ )  && // this first condition is superfluous but get's a faster decision in many cases
        ((digest_info.len() == 35 && digest_info[..15]==digest_algorithm_sha1)   ||
         (digest_info.len() == 51 && digest_info[..19]==digest_algorithm_sha256) /* ||
         (digest_info.len() == 83 && digest_info[..19]==digestAlgorithm_sha512) */ )
    {
//println!("acos5_compute_signature: digest_info.len(): {}, digest_info[..15]==digest_algorithm_sha1[..]: {}, digest_info[..19]==digest_algorithm_sha256[..]: {}", digest_info.len(), digest_info[..15]==digest_algorithm_sha1[..], digest_info[..19]==digest_algorithm_sha256[..]);
        #[cfg(iup_user_consent)]
        {
            if get_ui_ctx(card).user_consent_enabled == 1 {
                /* (Requested by DGP): on signature operation, ask user consent */
                rv = acos5_ask_user_consent();
                if rv < 0 {
                    log3ifr!(ctx,f,line!(), c"returning with: User consent denied", rv);
                    return rv;
                }
            }
        }

        // SHA-1 and SHA-256 hashes, what the card can handle natively
        let hash = &digest_info[if digest_info.len()==35 {15} else {19} ..];
        set_is_running_cmd_long_response(card, true); // switch to false is done by acos5_get_response
        let func_ptr = unsafe { (*(*sc_get_iso7816_driver()).ops).compute_signature.unwrap() };
        rv = unsafe { func_ptr(card, hash.as_ptr(), hash.len(), out_ptr, outlen) };
        if rv <= 0 {
            log3if!(ctx,f,line!(), c"iso7816_compute_signature failed or apdu.resplen==0. rv: %d", rv);
//            return rv;
        }
        /* temporary: "decrypt" signature (out) to stdout:
           applied specifically to RSA key 0x41F3, used to inspect that the acos operation did set the
           padding and digestInfo correctly (input was a hash only) * /
        encrypt_public_rsa(card, out_ptr, data_len);
        / * */
    }
    else {   /* for other digests than SHA-1/SHA-256 */
        let fmt = c"### Switch to acos5_decipher, because \
                acos5_compute_signature can't handle the hash algo ###";
        log3if!(ctx,f,line!(), fmt);
        /* digest_info.len() is from SC_ALGORITHM_RSA_RAW or SC_ALGORITHM_RSA_PAD_PKCS1 */
        /* is_any_known_digestAlgorithm or ? could go further and compare digestAlgorithm to known ones as well
           With that done, a possible attacker can control nothing but the hash value (and signature scheme to be used)
           TODO implement delaying, if consecutive trials to sign are detected, revoke PIN verification etc.
             or enable an additional layer where user MUST accept or deny sign operation (see DNIE) */
//println!("is_any_known_digestAlgorithm(digest_info): {}", is_any_known_digestAlgorithm(digest_info));
        if (SC_ALGORITHM_RSA_PAD_PKCS1 & sec_env_algo_flags) > 0 && is_any_known_digestAlgorithm(digest_info)
        {
            /* calling me_get_encoding_flags is not necessary, it's done within sc_pkcs1_encode anyway.
               Here just for curiosity/inspection  * /
            let mut pflags = 0;
            let mut sflags = 0;
            rv = me_get_encoding_flags(ctx, sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE,
                                       get_rsa_caps(card), &mut pflags, &mut sflags);
            println!("pflags: {}, sflags: {}", pflags, sflags);
            if rv != SC_SUCCESS {
                return rv;
            }
            */
            let sec_env_mod_len = get_sec_env_mod_len(card);
            let mut vec_len = if sec_env_mod_len>0 {min(outlen, sec_env_mod_len)} else {outlen};
            let mut vec = vec![0_u8; vec_len];
            /*
              in the following,   | SC_ALGORITHM_RSA_HASH_NONE   is required for ssh for version:
              v0_17_0  (sec_env_algo_flags: 0x2, even if rsa_algo_flags |= SC_ALGORITHM_RSA_HASH_NONE;)
              v0_18_0  (sec_env_algo_flags: 0x2, even if ditto.)
              v0_19_0  (sec_env_algo_flags: 0x2, even if ditto.)

              | SC_ALGORITHM_RSA_HASH_NONE   is *NOT* required for ssh for version:
              v0_20_0  (sec_env_algo_flags: 0x102, even if there is no rsa_algo_flags |= SC_ALGORITHM_RSA_HASH_NONE;)
            */

            rv = unsafe { cfg_if::cfg_if! {
                if #[cfg(any(v0_20_0, v0_21_0, v0_22_0))] {
                    sc_pkcs1_encode(ctx, c_ulong::from(sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE), digest_info.as_ptr(),
                                                 digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len * 8)
                }
                else {
                    sc_pkcs1_encode(ctx, c_ulong::from(sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE), digest_info.as_ptr(),
                                                  digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len * 8, null_mut())
                }
            }};

            if rv != SC_SUCCESS {
                return rv;
            }
            set_is_running_compute_signature(card, true);
            rv = acos5_decipher(card, vec.as_ptr(), vec_len, out_ptr, outlen);
        }
        else if (SC_ALGORITHM_RSA_RAW  & sec_env_algo_flags) > 0 && data_len==get_sec_env_mod_len(card) &&
            (is_any_known_digestAlgorithm(digest_info) || cfg!(dev_relax_signature_constraints_for_raw))
        {
//            match me_pkcs1_strip_01_padding(&vec_in) { // TODO possibly also try pkcs1_strip_PSS_padding
//                Ok(digest_info) => digest_info,
//                Err(e) => {}
//            }
            set_is_running_compute_signature(card, true);
            rv = acos5_decipher(card, data_ref_ptr, data_len, out_ptr, outlen);
        }
/*
        else if cfg!(not(any(v0_17_0, v0_18_0))) {
        #[       cfg(not(any(v0_17_0, v0_18_0)))]
        {
            if (SC_ALGORITHM_RSA_PAD_PSS & sec_env_algo_flags) > 0 /*&& is_any_known_digestAlgorithm(digest_info.len()*/) {
                rv = 0; // do nothing
/*
sc_pkcs1_encode with SC_ALGORITHM_RSA_PAD_PSS does work only since v0.20.0
when pkcs1_strip_PSS_padding works
                    let mut vec = vec![0u8; 512];
                    let mut vec_len = min(512, outlen);
                    rv = unsafe { sc_pkcs1_encode(ctx, c_ulong::try_from(sec_env_algo_flags | SC_ALGORITHM_RSA_HASH_NONE).unwrap(), digest_info.as_ptr(),
                                                      digest_info.len(), vec.as_mut_ptr(), &mut vec_len, vec_len*8) };
                    if rv != SC_SUCCESS {
                        return rv;
                    }
                    rv = acos5_decipher(card, data_ref_ptr, data_len, out_ptr, outlen);
*/
            }
            else {
                rv = 0; // do nothing
            }
        }}
*/
        else {
            rv = 0; // do nothing and live with a verification error
        }
        /* temporary: "decrypt" signature (out) to stdout */
        if rv>0 { // EM = 0x00 || 0x02 || PS || 0x00 || M.
//            let tmp_buf = [0u8,2,   4,247,125,36,98,255,144,111,47,96,32,249,19,77,251,200,199,87,16,99,178,159,210,55,1,254,66,236,11,   0, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
//            encrypt_public_rsa(card, tmp_buf.as_ptr() /*out_ptr*/, /*data_len*/ tmp_buf.len()/*outlen*/);
        }

//        log3if!(ctx,f,line!(), c"returning from acos5_decipher with: %d", rv);
//        return rv;
    }
    log3ifr!(ctx,f,line!(), rv);
    rv
} // acos5_compute_signature

/* Implementation for RSA_WRAPPED_AES_KEY with template entries for receiving sym. key: CKA_TOKEN=TRUE and CKA_EXTRACTABLE=FALSE.
   i.e. it's assumed that the unwrapped key is of AES type ! */
// FIXME this doesn't work currently:  the SKDF entry is created already with some data missing, see also acos5_pkcs15/src/lib.rs comment in the end
// FIXME sc_pkcs15init_store_secret_key get's called, but without calling  profile->ops->store_key (keyargs->key.data_len == 0)
#[allow(dead_code)]  // no usage currently
#[cold]
extern "C" fn acos5_unwrap(card_ptr: *mut sc_card, crgram: *const u8, crgram_len: usize) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_unwrap";
    log3if!(ctx,f,line!(), c"called with crgram_len: %zu", crgram_len);

    let mut vec = vec![0; crgram_len];
    let mut rv = acos5_decipher(card, crgram, crgram_len, vec.as_mut_ptr(), vec.len());
    if rv < SC_SUCCESS {
        log3ifr!(ctx,f,line!(),c"returning with failure", rv);
        return rv;
    }
    vec.truncate(usize::try_from(rv).unwrap());
    let klen = vec.len();
    assert!([16, 24, 32].contains(&klen));
//println!("\n\nUnwrapped {} key bytes: {:X?}\n", klen, vec);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    if true /* dp.rfu_align_pad3  dp.is_unwrap_op_in_progress */ {
        assert!(usize::from(dp.sym_key_rec_cnt) >= klen+3);
        vec.reserve_exact(usize::from(dp.sym_key_rec_cnt));
        vec.insert(0, 0x80|dp.sym_key_rec_idx);
        vec.insert(1, 0);
        vec.insert(2, if klen==32 {0x22} else if klen==24 {0x12} else {2});
        while vec.len() < usize::from(dp.sym_key_rec_cnt) { vec.push(0); }
        let mut path = sc_path { len: 2, ..sc_path::default() };
        path.value[..2].copy_from_slice(&dp.sym_key_file_id.to_be_bytes());
        rv = unsafe { sc_select_file(card, &path, null_mut()) };
        assert_eq!(SC_SUCCESS, rv);
        /* TODO This only works if Login-PIN is the same as required for SC_AC_OP_UPDATE of file dp.sym_key_file_id */
        #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
        unsafe { rv = sc_update_record(card, u32::from(dp.sym_key_rec_idx), vec.as_ptr(), vec.len(), 0) };
        #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
        unsafe { rv = sc_update_record(card, u32::from(dp.sym_key_rec_idx), 0, vec.as_ptr(), vec.len(), 0) };
        assert_eq!(SC_SUCCESS, rv);
        // dp.is_unwrap_op_in_progress = false;
    }
    let _unused = Box::leak(dp);

    log3ifr!(ctx,f,line!(), rv);
    rv
}

/*
 * Implements sc_card_operations function 'delete_record'
 * @see opensc_sys::opensc struct sc_card_operations
 * In the narrower sense, deleting a record is impossible: It's part of a file that may be deleted.
 * In the broader sense, cos5 considers any record with first byte==00 as empty (see cos5 command 'append_record'),
 * thus this command will zeroize all record content
 * @apiNote
 * @param  rec_nr starting from 1
 * @return number of erasing zero bytes written to record, otherwise an error code
 */
extern "C" fn acos5_delete_record(card_ptr: *mut sc_card, rec_nr: u32) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || rec_nr==0 || rec_nr>0xFF {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card       = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_delete_record";
    log3if!(ctx,f,line!(), c"called with rec_nr: %u", rec_nr);
    assert!(rec_nr>0);
    let rec_nr = u16::try_from(rec_nr).unwrap();
    let zero_buf = [0; 0xFF];
    common_update(card, rec_nr, &zero_buf, SC_RECORD_BY_REC_NR, false)
}

extern "C" fn acos5_append_record(card_ptr: *mut sc_card, buf_ptr: *const u8, count: usize, _flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_append_record";
    log3ifc!(ctx,f,line!());
    let buf      = unsafe { from_raw_parts(buf_ptr, count) };
    common_update(card, 0, buf, 0, false)
}

/* returns how many bytes were read or an error code */
/* read_binary is also responsible for get_key and takes appropriate actions, such that get_key is NOT publicly available
   OpenSC doesn't know the difference (fdb 1 <-> 9): It always calls for transparent files: read_binary
   shall be called solely by sc_read_binary, which cares for dividing into chunks !! */
extern "C" fn acos5_read_binary(card_ptr: *mut sc_card, idx: u32,
                                buf_ptr: *mut u8, count: usize,
                                #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
                                flags:      c_ulong,
                                #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
                                flags: *mut c_ulong,
                               ) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 /* || flags.is_null() */ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let idx = u16::try_from(idx).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts_mut(buf_ptr, count) };
    //let count = u16::try_from(count).unwrap();
    common_read(card, idx, buf,
                #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
                    flags,
                #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
                    unsafe {if flags.is_null() {0} else {*flags}},
                true)
}

#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
extern "C" fn acos5_read_record(card_ptr: *mut sc_card, rec_nr: u32,
                                buf_ptr: *mut u8, count: usize, _flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 /* || count>255*/ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
////    assert!(rec_nr>0); // TODO deactivated because opensc-tool is buggy
    let rec_nr = u16::try_from(rec_nr).unwrap();
    let count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts_mut(buf_ptr, usize::from(count)) };
    common_read(card, rec_nr, buf, SC_RECORD_BY_REC_NR, false)
}
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
extern "C" fn acos5_read_record(card_ptr: *mut sc_card, rec_nr: u32, _idx: u32,
                                buf_ptr: *mut u8, count: usize, _flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 /* || count>255*/ {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
////    assert!(rec_nr>0); // TODO deactivated because opensc-tool is buggy
    let rec_nr = u16::try_from(rec_nr).unwrap();
    let count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts_mut(buf_ptr, usize::from(count)) };
    common_read(card, rec_nr, buf, SC_RECORD_BY_REC_NR, false)
}

extern "C" fn acos5_update_binary(card_ptr: *mut sc_card, idx: u32,
                                  buf_ptr: *const u8, count: usize, flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let idx = u16::try_from(idx).unwrap();
    let count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts(buf_ptr, usize::from(count)) };
    common_update(card, idx, buf, flags, true)
}

#[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))]
extern "C" fn acos5_update_record(card_ptr: *mut sc_card, rec_nr: u32,
                                  buf_ptr: *const u8, count: usize, _flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(rec_nr>0);
    let rec_nr = u16::try_from(rec_nr).unwrap();
    let count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts(buf_ptr, usize::from(count)) };
    common_update(card, rec_nr, buf, SC_RECORD_BY_REC_NR, false)
}
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
extern "C" fn acos5_update_record(card_ptr: *mut sc_card, rec_nr: u32, _idx: u32,
                                  buf_ptr: *const u8, count: usize, _flags: c_ulong) -> i32
{
    if card_ptr.is_null() || buf_ptr.is_null() || count==0 {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    assert!(rec_nr>0);
    let rec_nr = u16::try_from(rec_nr).unwrap();
    let count = u16::try_from(count).unwrap();
    let card = unsafe { &mut *card_ptr };
    let buf      = unsafe { from_raw_parts(buf_ptr, usize::from(count)) };
    common_update(card, rec_nr, buf, SC_RECORD_BY_REC_NR, false)
}

/* the return value will later be assigned to *pulDataLen in pkcs15_skey_encrypt */
// plaintext_len is allowed to be not a multiple of block_size 16 for SC_ALGORITHM_AES_CBC_PAD only
//#[allow(dead_code)] // currently unused
//#[cold]

#[named]
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
extern "C" fn acos5_encrypt_sym(card_ptr: *mut sc_card, plaintext: *const u8, plaintext_len: usize,
                                out: *mut u8, outlen: *mut usize) -> i32
//    out: *mut u8, outlen: usize, algorithm: u32, algorithm_flags: u32, _key_ref: *const [u8; 8]) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } || outlen.is_null() {
//        || algorithm != SC_ALGORITHM_AES || ![SC_ALGORITHM_AES_CBC_PAD, SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB].contains(&algorithm_flags)
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
//println!("acos5_encrypt_sym input: algorithm: {:02X}, algorithm_flags: {:02X}, key_ref[0]: {:02X}, plaintext_len: {}, plaintext: {:02X?}",
//algorithm, algorithm_flags, unsafe{ (*_key_ref)[0] }, plaintext_len, unsafe { from_raw_parts(plaintext, plaintext_len) });
    // temporarily route via sym_en_decrypt
    let mut crypt_sym_data = CardCtlSymCrypt {
        inbuf        : plaintext,
        indata_len   : plaintext_len,
        outbuf       : out,
        outdata_len  : unsafe {*outlen},
        algorithm      :0,
        algorithm_flags:0,
        pad_type     : BLOCKCIPHER_PAD_TYPE_PKCS7,
        cbc          : true,//(algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) >0 || (algorithm_flags & SC_ALGORITHM_AES_CBC) > 0,
        encrypt      : true,
        .. CardCtlSymCrypt::default()
    };
    sym_en_decrypt(card,  &mut crypt_sym_data)
}


/* the return value will later be assigned to *pulDataLen in pkcs15_skey_decrypt */
//#[allow(dead_code)] // currently unused
//#[cold]

#[named]
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0)))]
extern "C" fn acos5_decrypt_sym(card_ptr: *mut sc_card, encrypted_data: *const u8, encrypted_data_len: usize,
                                out: *mut u8, outlen: *mut usize) -> i32
 //   out: *mut u8, outlen: usize, algorithm: u32, algorithm_flags: u32, key_ref: *const [u8; 8]) -> i32
{
    if card_ptr.is_null() || unsafe { (*card_ptr).ctx.is_null() } {
//        || algorithm != SC_ALGORITHM_AES || ![SC_ALGORITHM_AES_CBC_PAD, SC_ALGORITHM_AES_CBC, SC_ALGORITHM_AES_ECB].contains(&algorithm_flags)
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    let card = unsafe { &mut *card_ptr };
    let ctx = unsafe { &mut *card.ctx };
    let f_cstr = CString::new(function_name!()).expect("CString::new failed");
    let f = f_cstr.as_c_str();
    log3ifc!(ctx,f,line!());
println!("called for decryption: encrypted_data_len  {encrypted_data_len:?}");
    if out.is_null() {
println!("called for decryption: out , outlen   {out:p} , {outlen:p}");
        if outlen.is_null() { return 3; }
        unsafe { *outlen = max(encrypted_data_len, 256) };
        return 0;
    }
    if encrypted_data_len == 0 {
        log3if!(ctx,c"acos5_decrypt_sym",line!(), c"nothing to do here: returning with 0");
        return 0;
    }

    if outlen.is_null() {
        log3ifc!(ctx,c"acos5_decrypt_sym",line!());
println!("called for decryption: outlen {outlen:p}");
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//println!("acos5_decrypt_sym input: algorithm: {:02X}, algorithm_flags: {:02X}, key_ref[0]: {:02X}, encrypted_data_len: {}, encrypted_data: {:02X?}",
//algorithm, algorithm_flags, unsafe{ (*key_ref)[0] }, encrypted_data_len, unsafe { from_raw_parts(encrypted_data, encrypted_data_len) });
    // temporarily route via sym_en_decrypt
    let mut crypt_sym_data = CardCtlSymCrypt {
        inbuf        : encrypted_data,
        indata_len   : encrypted_data_len,
        outbuf       : out,
        outdata_len  : encrypted_data_len,

        iv_len: 16, //if (algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) > 0 || (algorithm_flags & SC_ALGORITHM_AES_CBC) > 0 {16} else {0},
        algorithm      : SC_ALGORITHM_AES,
        algorithm_flags: SC_ALGORITHM_AES_CBC_PAD,

        pad_type     : BLOCKCIPHER_PAD_TYPE_PKCS7,
        cbc          : true,//(algorithm_flags & SC_ALGORITHM_AES_CBC_PAD) >0 || (algorithm_flags & SC_ALGORITHM_AES_CBC) > 0,
        encrypt      : false,
        .. CardCtlSymCrypt::default()
    };
/* this is okay, used in debug.log
00 22 01 B8 1B
95 01 40  bit 6 allows for PSO
80 01 06  AES-CBC page 43 of 129
83 01 83  local key 03
87 10 10 54 82 A9 68 8B 7B FF 8E CB B5 D7 26 AD A2 A9
*/
println!("called for decryption\n");

    let rv = sym_en_decrypt(card,  &mut crypt_sym_data);
    unsafe { *outlen = crypt_sym_data.outdata_len; }
    rv
}

/*
/* Access Control flags */
SC_AC_NONE
SC_AC_CHV              /* Card Holder Verif. */
                          util_acl_to_str prints with    key_ref: "CHV";
SC_AC_TERM             /* Terminal auth. */                                => unused in driver, *.profile
                          util_acl_to_str prints without key_ref: "TERM";
                          profile.c map: { "TERM", SC_AC_TERM }
                          no more OpenSC framework usage and card-specific usage only by: card-several.c
SC_AC_PRO              /* Secure Messaging */
                          util_acl_to_str prints without key_ref: "PROT";
                          profile.c map: { "PRO", SC_AC_PRO }
                          pkcs15-lib.c: get_pin_ident_name: "secure messaging key"
                                        sc_pkcs15init_verify_secret : pinsize = 0; "No 'verify' for secure messaging"
                          tools/pkcs15-init.c
                          tools/opensc-explorer.c

SC_AC_AUT              /* Key auth. */
                          util_acl_to_str prints with    key_ref: "AUTH";
                          profile.c map: { "AUT", SC_AC_AUT }
                          profile.c map: { "KEY", SC_AC_AUT }
                          pkcs15-lib.c: get_pin_ident_name: "authentication key"
                                        sc_pkcs15init_verify_secret : sc_card_ctl(SC_CARDCTL_GET_CHV_REFERENCE_IN_SE) ...  -> SC_AC_CHV

SC_AC_SYMBOLIC         /* internal use only */                               => unused in driver, *.profile

SC_AC_SEN              /* Security Environment. */                               => unused in driver, *.profile
                          util_acl_to_str prints with    key_ref: "Sec.Env. ";
                          profile.c map: { "SEN", SC_AC_SEN }
                          pkcs15-lib.c: get_pin_ident_name: "security environment"
                                        sc_pkcs15init_verify_secret : sc_card_ctl(SC_CARDCTL_GET_CHV_REFERENCE_IN_SE) ...  -> SC_AC_CHV
                          no more OpenSC framework usage and card-specific usage only by: pkcs15-iasecc.c, card-iasecc.c and iasecc-sdo.c
SC_AC_SCB              /* IAS/ECC SCB byte. */
                          util_acl_to_str prints with    key_ref: "Sec.ControlByte ";
                          profile.c map: { "SCB", SC_AC_SCB }
                          pkcs15-lib.c: get_pin_ident_name: "SCB byte in IAS/ECC"
                                        sc_pkcs15init_verify_secret : pinsize = 0;
                          no more OpenSC framework usage and card-specific usage only by: pkcs15-iasecc.c, card-iasecc.c and card-authentic.c
SC_AC_IDA              /* PKCS#15 authentication ID */                               => unused in driver, *.profile
                          util_acl_to_str prints with    key_ref: "PKCS#15 AuthID ";
                          profile.c map: { "IDA", SC_AC_IDA }
                          pkcs15-lib.c: get_pin_ident_name: "PKCS#15 reference"
                          no more OpenSC framework usage and card-specific usage only by: pkcs15-iasecc.c
SC_AC_SESSION          /* Session PIN */ // since opensc source release v0.17.0            => unused in driver, *.profile
SC_AC_CONTEXT_SPECIFIC /* Context specific login */ // since opensc source release v0.18.0          => unused in driver, *.profile

The driver doesn't support access control condition: 'authenticate a key' because OpenSC doesn't support that either.

*/
/*
user@host:~/workspace/acos5_gui/opensc/C/contribute_opensc/OpenSC-1/src$ grep -rnw supported_algos
user@host:~/workspace/acos5_gui/opensc/C/contribute_opensc/OpenSC-1/src$ grep -rnw algo_refs

file 4114:

name: secretKey  type: CHOICE
  name: genericSecretKey  type: SEQUENCE
    name: commonObjectAttributes  type: SEQUENCE
      name: label  type: UTF8_STR  value: AES3                                 name: label  type: UTF8_STR  value: Secret Key
      name: flags  type: BIT_STR  value(2): c0  ->  11
      name: authId  type: OCT_STR  value: 01
    name: commonKeyAttributes  type: SEQUENCE
      name: iD  type: OCT_STR  value: 07                                       name: iD  type: OCT_STR  value: 09
      name: usage  type: BIT_STR  value(2): c0  ->  11
      name: native  type: BOOLEAN
        name: NULL  type: DEFAULT  value: TRUE
      name: accessFlags  type: BIT_STR  value(4): b0  ->  1011                 missing !!!
      name: keyReference  type: INTEGER  value: 0x0083                         name: keyReference  type: INTEGER  value: 0x00
      name: algReference  type: SEQ_OF                                         missing !!!
        name: NULL  type: INTEGER
        name: ?1  type: INTEGER  value: 0x01
        name: ?2  type: INTEGER  value: 0x02
    name: commonSecretKeyAttributes  type: SEQUENCE
      name: keyLen  type: INTEGER  value: 0x0100
    name: genericSecretKeyAttributes  type: SEQUENCE
      name: value  type: CHOICE
        name: indirect  type: CHOICE
          name: path  type: SEQUENCE
            name: path  type: OCT_STR  value: 3f0041004102                     name: path  type: OCT_STR  value: 3f004100
            name: index  type: INTEGER  value: 0x03                            missing !!!
            name: length  type: INTEGER  value: 0x25                           missing !!!

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


A4 39 30 0C 0C 03 53 4D 31 03 02 06 C0 04 01 01
30 0F 04 01 01 03 02 06 C0 03 02 04 B0 02 02 00
81 A0 04 02 02 00 C0 A1 12 30 10 30 0E 04 06 3F
00 41 00 41 02 02 01 01 80 01 25 A4 39 30 0C 0C
03 53 4D 32 03 02 06 C0 04 01 01 30 0F 04 01 02
03 02 06 C0 03 02 04 B0 02 02 00 82 A0 04 02 02
00 C0 A1 12 30 10 30 0E 04 06 3F 00 41 00 41 02
02 01 02 80 01 25 30 42 30 0D 0C 04 41 45 53 33
03 02 06 C0 04 01 01 30 17 04 01 07 03 02 06 C0
03 02 04 B0 02 02 00 83 A1 06 02 01 01 02 01 02
A0 04 02 02 01 00 A1 12 30 10 30 0E 04 06 3F 00
41 00 41 02 02 01 03 80 01 25 30 33 30 13 0C 0A
53 65 63 72 65 74 20 4B 65 79 03 02 06 C0 04 01
01 30 0A 04 01 09 03 02 06 C0 02 01 00 A0 04 02
02 01 00 A1 0A 30 08 30 06 04 04 3F 00 41 00

SEQUENCE (4 elem)
  SEQUENCE (3 elem)
    UTF8String AES3
    BIT STRING (2 bit) 11
    OCTET STRING (1 byte) 01
  SEQUENCE (5 elem)
    OCTET STRING (1 byte) 07
    BIT STRING (2 bit) 11
    BIT STRING (4 bit) 1011
    INTEGER 131
    [1] (2 elem)
      INTEGER 1
      INTEGER 2
  [0] (1 elem)
    INTEGER 256
  [1] (1 elem)
    SEQUENCE (1 elem)
      SEQUENCE (3 elem)
        OCTET STRING (6 byte) 3F0041004102
        INTEGER 3
        [0] (1 byte) %



SEQUENCE (4 elem)
  SEQUENCE (3 elem)
    UTF8String Secret Key
    BIT STRING (2 bit) 11
    OCTET STRING (1 byte) 01
  SEQUENCE (3 elem)
    OCTET STRING (1 byte)
    BIT STRING (2 bit) 11

    INTEGER 0
  [0] (1 elem)
    INTEGER 256
  [1] (1 elem)
    SEQUENCE (1 elem)
      SEQUENCE (1 elem)
        OCTET STRING (4 byte) 3F004100





Beginning script execution...

Sending: 00 A4 00 00 00 00 02 3F 00
Received: 61 22
0x22 bytes of response still available.

Sending: 00 A4 00 00 00 00 02 41 00
Received: 61 32
0x32 bytes of response still available.

Sending: 00 20 00 81 00 00 08 31 32 33 34 35 36 37 38
Received: 90 00
Normal processing.

Sending: 00 22 01 B6 00 00 0A 80 01 42 81 02 11 01 95 01 80
Received: 90 00
Normal processing.

Sending: 00 22 01 B6 00 00 0A 80 01 42 81 02 12 01 95 01 40
Received: 90 00
Normal processing.

Sending: 00 46 00 00 00 00 01 04
Received: 90 00
Normal processing.

Script was executed without error...




Sending: 00 A4 00 00 02 41 00
Received: 61 32
0x32 bytes of response still available.

Sending: 00 C0 00 00 32
Received: 6F 30 83 02 41 00 88 01 00 8A 01 05 82 02 38 00
8D 02 41 03 84 10 41 43 4F 53 50 4B 43 53 2D 31
35 76 31 2E 30 30 8C 08 7F 03 FF 03 03 01 01 01
AB 00 90 00
Normal processing.

Sending: 00 A4 00 00 02 11 01
Received: 61 20
0x20 bytes of response still available.

Sending: 00 C0 00 00 20
Received: 6F 1E 83 02 11 01 88 01 01 8A 01 05 82 02 19 00
80 02 00 48 8C 08 7F FF FF 01 01 01 01 00 AB 00
90 00
Normal processing.

Sending: 80 CA 00 00 48
Received: 00 04 12 01 0A   03 00 3C 00 B0 23 40 DD 4A 44 31
AF 1E 5E 0F 4F 7F 8F 98 02 D9 0D 7E 68 3A 89 49
71 16 F0 A3 8A 8C B6 9D 4A 85 37 12 79 4C 47 9D
6F 26 20 55 E2 5D 96 B1 0B 37 60 34 88 6D DC 55
36 C7 C3 3F 1A 7C 86 DF 90 00
Normal processing.

Script was executed without error...
*/
