//! Rust language: A binding to libopensc.so/opensc.dll, reduced extend required for external modules\
//!(driver/PKCS#15 init/SM etc.)\
//! [`OpenSC wiki`]\
//! [`Rust website`]
//!
//! This binding supports OpenSC release versions 0.17.0 - 0.20.0
//!
//! The state is Work In Progress WIP, though usable.\
//! The focus is on the generic header subset, i.o. to support new driver etc. external module development.\
//! The headers covered are those that have any relation to libopensc.so/dll, but card-specific headers are excluded.\
//! The Rust files may partially contain untranslated content (comments), where it's either card-specific or not
//! accessible from the binary, (e.g. all functions of simclist are exported from libsmm-local.so/dll, which is not
//! covered here), alternatively, 'non-export' library symbols may have a private Rust declaration.\
//! Also some library symbols's accessibility may depend on the version configuration in build.rs, see below.\
//! (libsmm-local.so/dll is not usable, if a card loads an individual Secure Messagimg library: symbol name clashing).
//!
//! Basically it's a pure '-sys'-binding generated from bindgen output, with these deviations:\
//! pub type some_type_t = some_type;  most of them got removed i.o. to reduce redundancy (comments now).\
//! Controlled by cfg (explained in build.rs), a few impl got added for traits Default and Display, also a few 'new'
//! assoc. functions for struct sc_crt.\
//! The type of constants (they all originate from #define) may change during WIP to be the best fit for function
//! parameter types.\
//! The functions originating from #define are excluded currently.\
//! It's intended to once have each function covered by a unit test, i.o. to check callability from Rust,
//! and thoroughly document the API.
//!
//! OpenSSL\
//! It's debatable, whether Cargo.toml should specify a dependency on OpenSSL: Clearly, libopensc.so/opensc.dll depends
//! on libcrypto.so/dll (Windows before OpenSSL version 1.1.0: libeay32.dll) (see below: presupposed defined), but the
//! binding doesn't use any of it's headers, thus it's omitted in Cargo.toml.
//!
//! Before using this binding, carefully check how libopensc.so/dll was built (#define..., see below) by the package
//! distribution/Yourself:
//!
//! The main reason is, that some #define... (whether defined or not) modify the size of structs and/or are assumed by
//! this binding to be set  (I didn't repeat all that conditional code that the C headers provide)
//!
//! The presupposed #define or #undef used are what a typical install ala [`Compiling-and-Installing-on-Unix-flavors`],
//! same what my Ubuntu package for x86_64 provides (if You have the file config.h, most of it is in there):
//!
//! missing or #undef SIMCLIST_WITH_THREADS  (presupposed undefined)  modifies sizeof(list_t)\
//! #define ENABLE_SM 1           (presupposed defined)    modifies sizeof(sc_card)\
//! #define ENABLE_OPENSSL 1      (presupposed defined)    modifies behavior/availability of functions\
//! #define VERSION "0.??.0"      (nothing presupposed, but exactly one must be selected in all build.rs to match the
//! binary's version !)
//!
//!
//! If You don't yet have libopensc.so/.dll/.a , install it from Your distro or sources from [`OpenSC releases`]\
//! [`Windows-Quick-Start`]\
//! [`macOS-Quick-Start`]\
//! [`Compiling-and-Installing-on-Unix-flavors`]
//!
//! I propose to deviate on Ubuntu by using (--libdir=... is what Ubuntu's package opensc-pkcs11 does):\
//! `tar xfvz opensc-*.tar.gz`\
//! `cd opensc-*`\
//! `./bootstrap`\
//! `./configure --prefix=/usr --sysconfdir=/etc/opensc --libdir=/usr/lib/x86_64-linux-gnu`\
//! `make`\
//! `sudo checkinstall`
//!
//! If there is no file or symbolic link `libopensc.so` in the library search path, then create a
//! symbolic link pointing to the relevant library. It will be used by build.rs.\
//! The import library `opensc.lib` (for Windows) doesn't get provided by OpenSC. It must be created from opensc.dll.
//! For some versions they are available from the opensc-sys/windows-x86_64/lib/ directory.
//!
//! The build.rs file employs a detection of installed  libopensc.so/opensc.dll and retrieving it's version information.
//! That is designed to fail, if the version is lower than 0.17.0, the min. supported version of this binding.
//!
//! Run e.g. opensc-tool -i\
//! OpenSC 0.21.0 [gcc  9.3.0]
//! Enabled features: locking zlib readline openssl pcsc(libpcsclite.so.1)
//!
//! The important pieces of information here are:\
//! 1. The release version of my OpenSC binary is 0.21.0, thus covered by this binding.\
//! 2. A dependency on openssl is given by the binary, i.e. #define ENABLE_OPENSSL 1  was used in config.h\
//! 3. Sadly the other required info is not reported, thus run:  `cargo test test_struct_sizeof -- --nocapture`
//!    That will check the variable struct sizes of list_t and sc_card (and more) for x86_64 Linux/Windows against
//!    values known and working for me and report something.
//!    The size values are not relevant, important is, that the test passes.
//!    It will also call into libopensc, i.e. check ability to link and print the OpenSC version to be checked vs. output
//!    of opensc-tool.
//!    Once the test passes, the opensc-sys binding is ready to be used.
//!
//! Not selecting any OpenSC release versions 0.17.0 - 0.21.0, is treated as unsupported, except:
//! That's experimental only: Take OpenSC master branch, change configure.ac to read  define([PACKAGE_VERSION_MINOR], [22]) , the next/imaginary version (currently 0.22.0)
//! and build from source.
//! At irregular intervals only I check master's implications for the binding. E.g. there was a commit (effective since
//! OpenSC release versions 0.18.0), that changed parsing of
//! EF.Tokeninfo supportedAlgorithms/parameters/PKCS15ECParameters.
//!
//! Remark about functions returning i32:
//! Many functions return i32, and mostly that refers to SC_SUCCESS or some error code:
//! Carefully read about the exact meaning of the value returned, as there are inconsistencies:
//! E.g. for match_card, success is returned with value 1, while all other return success by SC_SUCCESS (value==0).
//! Functions that get/put data, return the number of bytes received/written
//!
//!
//! IN, OUT, INOUT as described in  [`IN OUT INOUT`].
//! For pointer function parameters, the occurences of `*const some_type` by far are a minority, compared to the
//! majority typed `*mut some_type`.
//! This doesn't convey much info about the purpose of `*mut some_type` parameters and dataflow (if the param_name or
//! context doesn't help either),
//! except everything can happen with that parameter and without inspecting code, it must conservatively be regarded as
//! an INOUT.
//! In order to help with that, OpenSC API documentation occasionally already uses adornments for @param like IN, OUT,
//! INOUT, but inconsistently.
//! The purpose of the following is, based on code inspection, narrow INOUT to either IN or OUT variants if applicable
//! and for\
//! 1. User: Convey as much information as possible in a compact form (without need to revert to code inspection) how
//!          to connect to a param (Rust: by *const, *mut const, &, &mut) and what the implications are,
//!          adorn with lifetime requiremnts if applicable\
//! 2. Binding maintainer: Narrow where an in-depth inspection is required for Rust memory safety and what must be
//!          warned upon towards the User
//!
//! With Rust's ownership and borrowing rules and pointer parameters passing the FFI boundary, there are some
//! considerations to be taken into account, knowing,
//! that we constantly call OpenSC code in Rust's unsafe { call opensc_function() }; manner, where the compiler is
//! off-duty, relyimg on, that memory safety won't be undermined in unsafe blocks.\
//! To cut a long story short, API documentation get's extended by additional @param adornments and text, providing
//! more info.\
//! Essential is to identify, where memory get's allocated on the Rust side that will be free'ed on the C side and
//! vice versa, as well as lifetime issues. It's not yet clear how to mark Rust-related issues other than by text.
//!
//! An example of C code:
//!
//! `void sc_format_asn1_entry(struct sc_asn1_entry *entry, void *parm, void *arg, int set_present)`\
//! `{`\
//! `    entry->parm = parm;`\
//! `    entry->arg  = arg;`\
//! `    if (set_present)`\
//! `        entry->flags |= SC_ASN1_PRESENT;`\
//! `}`
//!
//! The entry parameter, get's dereferenced unconditionally (no IF) and written to, thus it has at least OUT
//! characteristic. But it doesn't get written in all fields, some are untouched, thus no initialization.
//! An initialization may or may not have happened by the caller, thus even although entry doesn't get read in the
//! function, it implicitely also has IN characteristic, altogether it's an INOUT parameter.
//! param and arg don't get written to, thus no OUT parameters, but IN parameters that get read by value, not by
//! dereferencing them. Additionally they may be NULL,
//! thus get an IF qualification, altogether they are INIF parameters.\
//! Additionally both parameters get an = qualification, meaning, that they are used by assignment only, without being
//! dereferenced, in total they get an INIF= qualification.\
//! set_present is a simple non-pointer IN parameter.\
//! I think, alone from parameter qualifications  INOUT,  INIF=,  INIF=,  IN  it's quite clear what happens, without
//! knowing anything about types, parameter names and algorithm:\
//! INOUT get's set from values of INIF=,  INIF=,  IN\
//! The fate of INOUT must still be inspected from the Rust-perspective
//! Rust can connect to this function this way:
//! entry       INOUT: *mut or &mut; the lifetime of entry is controlled by the smaller of parm/arg\
//! parm        INIF=: *mut or &mut; the lifetime of parm must outlive entry (if it's not null/&mut used);
//!                    *parm doesn't get changed\
//! arg         INIF=: *mut or &mut; the lifetime of arg  must outlive entry (if it's not null/&mut used);
//!                    *arg  doesn't get changed\
//! set_present IN:    non-pointer value
//!
//! Here are the details, to be possibly refined and subject to WIP:
//!
//! The documented functions use these abbreviations: IN, OUT, INOUT,   INIF, OUTIF, INOUTIF and for IN/INIF possibly
//! these trailing characters '=', '!', or '?',
//! IN,   OUT,   INOUT  pointers *NEVER* are allowed to be a NULL pointer (may be called from Rust with a reference
//! parameter).
//! INIF, OUTIF, INOUTIF (always pointers) are allowed to be a NULL pointer without explicit statement ().
//!
//! IN is a 'read only' argument and must be initialised by the caller. Evem if IN is a pointer, then it shall not have
//! any retroactive effects for the caller (i.e. 'read only' refers to the dereferenced pointer value: no write there!).
//!
//!   if a pointer parameter IN or INIF is followed by characters = or ! or ?, this means, that the func signature
//!   deviates from 'pure' IN /INIF typed `*const some_type` as `*mut some_type` because of:
//!   =: the IN pointer parameter just get's passed/assigned by value to somewhere that expects non-const\
//!   !: the IN parameter was checked by me to not be used in an object-modifying way by C code (i.e. may be called with
//!      a Rust reference &). BUT, this is no warranty, it's valid
//!      only today May/June 2019: Code modification by OpenSC may invalidate the check\
//!   ?: Not yet checked which qualification for IN/INIF applies
//!
//! OUT is an uninitialized (by the caller) 'write only' argument (always a pointer), or an address, where writing
//!   consecutive bytes may start.
//!   The function is not allowed (though possible) to read anything from out passed in to the function.
//!   The function itself MUST initialize, i.e. for struct must cover all fields (and then can read that of course).
//!   The value get's returned to the caller.
//!   There is a subtle distinction from INOUT: If the function omits e.g. for struct to assign a value for each field,
//!   then it's no OUT but INOUT parameter
//!   (as part of the initialization took place on the call side already).
//!   Rust has no uninitialized memory for primitive types, but the point here is, that an OUT parameter MUST NOT rely
//!   on that.
//!
//! INOUT is both of IN and OUT. The location of initialization may be either caller or caller+function. Something get's
//! written to INOUT.
//!
//! INIF is like IN, but potentially no read occurs, thus the parameter may have no influence for the function. The
//!   condition, whether to read from INIF or not is not generally defined, but the function guarantees to first check
//!   for NULL before reading.
//!
//! OUTIF is like OUT, but potentially NO initialization takes place at all (and nothing get's returned through OUTIF
//!   to the caller, thus no influence for the caller and OUTIF's value must be treated as undefined by the caller),
//!   dependig on some condition. The function guarantees to check for a NULL pointer before writing to OUTIF.
//!
//! INOUTIF is like INOUT, but potentially NO initialization takes place at all, and potentially nothing is readable.
//!   The function guarantees to check for NULL before any action on INOUTIF
//!
//! Consequences for RUST (regarding pointer parameters):\
//!
//! IN: It's guaranteed, that the memory address passed from Rust to C by the function call get's read only.
//!   (PROBABLY WRONG, depends on lifetime??? but not stored or it's pointee modified, thus it's safe, that after the
//!   C function returns, that memory address get's invalid ???)
//!
//!   The C function is not allowed to remember the IN pointer parameter in any way
//!
//!   NO NEED TO CHECK, what the C code does with IN, because functions signature complies with IN (const type* or
//!   const type* const) !!!
//!   There are rare uses of pure IN pointer parameters, most must be qualified with = or ! or ?
//!
//!   It's safe to use a Rust immutable reference (&) for an IN pointer parameter
//!
//! IN= and\
//! IN?:\
//!   No guarantee
//!   MUST BE CHECKED carefully, what the C code does with IN !!!
//!   For IN= a Rust immutable reference (&) MAY be used; for IN? a Rust mutable reference (&mut) MUST be used
//!
//! IN!: Guarantee only valid up to master SHA ...
//!   MUST BE CHECKED carefully, what the C code does with IN !!!
//!   For IN! a Rust immutable reference (&) MAY be used, provided that the OpenSC code didn't change since the check
//!
//! All that have OUT in it's name: MUST BE CAREFULLY CHECKED, what kind of memory this is, what's it's lifetime,
//! who has to care for free'ing (if applicable)
//!
//! Summary  call param on Rust side\
//! IN       &\
//! IN!      &mut is save but & may still be correct\
//! IN?      &mut\
//! IN=      both &mut and & are correct
//!
//! INIF     *const\
//! INIF!    *mut is save but *const may still be correct\
//! INIF?    *mut\
//! INIF=    both *mut and *const are correct
//!
//! all other ...IF varants  *mut\
//! all remaining            *mut or &mut
//!
//! TODO consolidate, refine all the above about IN, OUT, INOUT etc.
//!
//! [`Rust website`]: http://www.rust-lang.org
//! [`IN OUT INOUT`]: https://www.careerride.com/oracle-db-IN-OUT-and-INOUT.aspx
//! [`OpenSC wiki`]: https://github.com/OpenSC/OpenSC/wiki
//! [`Windows-Quick-Start`]: https://github.com/OpenSC/OpenSC/wiki/Windows-Quick-Start
//! [`macOS-Quick-Start`]: https://github.com/OpenSC/OpenSC/wiki/macOS-Quick-Start
//! [`Compiling-and-Installing-on-Unix-flavors`]: https://github.com/OpenSC/OpenSC/wiki/Compiling-and-Installing-on-Unix-flavors
//! [`OpenSC releases`]: https://github.com/OpenSC/OpenSC/releases
//! [`test`]: ../../../info/README.html

#![cfg_attr(feature = "cargo-clippy", warn(clippy::all))]
#![cfg_attr(feature = "cargo-clippy", warn(clippy::pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::doc_markdown))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::module_name_repetitions))]
 

// for FILE and free
extern crate libc;

#[doc = " ASN.1 handling"]
#[allow(dead_code)]
pub mod asn1;

#[doc = " Non PKCS#15, non ISO7816 data."]
#[doc = " Used to pass auxiliary data from non PKCS#15, non ISO7816 applications (like minidriver) to card specific part through the standard PKCS#15 and ISO7816 frameworks"]
#[allow(dead_code)]
pub mod aux_data;

#[doc = " Constants for sc_card_operations.card_ctl: The generic subset"]
#[allow(dead_code)]
pub mod cardctl;

#[doc = " Error codes and it's associated texts"]
#[allow(dead_code)]
pub mod errors;

#[doc = " Miscellaneous"]
#[allow(dead_code)]
pub mod internal;

#[doc = " ISO 7816 defined tags"]
#[allow(dead_code)]
pub mod iso7816;

#[doc = " Logging facility functions"]
#[allow(dead_code)]
pub mod log;

#[doc = " Not ready for Windows"]
#[allow(dead_code)]
#[cfg(not(v0_17_0))]
pub mod notify;

#[doc = " Advanced Types, Constants and Functions"]
#[allow(dead_code)]
pub mod opensc;
/*
#[doc = " PKCS#11 Basic Types, Constants and Functions"]
#[allow(dead_code)]
pub mod pkcs11;
*/
#[doc = " PKCS#15 Basic Types, Constants and Functions"]
#[allow(dead_code)]
pub mod pkcs15;

#[doc = " PKCS#15 related to card initialization and on-card object creation"]
#[allow(dead_code)]
pub mod pkcs15_init;

#[doc = " PKCS#15 related to configuration file 'card_xyz.profile'"]
#[allow(dead_code)]
pub mod profile;

#[doc = " Functions for handling configuration files 'opensc.conf' and PKCS#15 'card_xyz.profile'"]
#[allow(dead_code)]
pub mod scconf;

//#[doc(hidden)]
#[doc = " A doubly-linked-list implementation, used i.a. for card_reader. It's functions are NOT exported by libopensc"]
#[allow(dead_code)]
pub mod simclist;

#[doc = " Secure Messaging"]
#[allow(dead_code)]
pub mod sm;

#[doc = " Default UI strings"]
#[allow(dead_code)]
#[cfg(not(v0_17_0))]
pub mod strings;

#[doc = " Basic Types and Constants"]
#[allow(dead_code)]
pub mod types;


#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use crate::opensc::sc_get_version;

    #[test]
    fn test_struct_sizeof() { // $ cargo test test_struct_sizeof -- --nocapture
        let sl   = std::mem::size_of::<crate::simclist::list_t>();
        let sc   = std::mem::size_of::<crate::opensc::sc_card>();   // has 4x c_ulong
        let sr   = std::mem::size_of::<crate::opensc::sc_reader>(); // has 2x c_ulong
        let sse  = std::mem::size_of::<crate::opensc::sc_security_env>(); // changed  // since opensc source release v0.18.0
        let sef  = std::mem::size_of::<crate::opensc::sc_ef_atr>();
        let srd  = std::mem::size_of::<crate::opensc::sc_reader_driver>();
        let pcp  = std::mem::size_of::<crate::opensc::sc_pin_cmd_pin>();
        let pcd  = std::mem::size_of::<crate::opensc::sc_pin_cmd_data>();
        let sco  = std::mem::size_of::<crate::opensc::sc_card_operations>();
        let scc  = std::mem::size_of::<crate::opensc::sc_context>();
        let spo  = std::mem::size_of::<crate::pkcs15::sc_pkcs15_object>();
        let sca  = std::mem::size_of::<crate::pkcs15::sc_pkcs15_card>();
        let sf   = std::mem::size_of::<crate::types::sc_file>();
        let sccc = std::mem::size_of::<crate::scconf::scconf_context>();
        let ip   = std::mem::size_of::<crate::pkcs15_init::sc_pkcs15init_prkeyargs>();
        let is   = std::mem::size_of::<crate::pkcs15_init::sc_pkcs15init_skeyargs>();
        let prki = std::mem::size_of::<crate::pkcs15::sc_pkcs15_prkey_info>();
        let puki = std::mem::size_of::<crate::pkcs15::sc_pkcs15_pubkey_info>();
        let ski  = std::mem::size_of::<crate::pkcs15::sc_pkcs15_skey_info>();
        let sai  = std::mem::size_of::<crate::opensc::sc_supported_algo_info>();

        assert_eq!(sl,  120);

        if cfg!(all(target_pointer_width = "64", any(unix, windows))) {
            // FIXME windows OpenSC32 <-> OpenSC64
            println!("Testing version's struct sizes actually *DOES* take place");
            if cfg!(v0_17_0) {
                // testing v0_17_0 verified with Windows 10:    ?
                // testing v0_17_0 verified with Kubuntu 18.04: yes, ok
                println!("For OpenSC 0.17.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, size_of::<sc_pkcs15_card>: {}, \
                    size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, size_of::<sc_pkcs15init_skeyargs>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, sco, scc, spo, sca, sf, sccc, ip, is);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1384); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1400); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }
                assert_eq!(sse,  744);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp, 4456);
                assert_eq!(sco,  280);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  632); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2768);
                assert_eq!(sca,  152);
                assert_eq!(sf,   448);
                assert_eq!(sccc,  32);
                assert_eq!(ip,   800);
                assert_eq!(is,   584);
            }
            else  if cfg!(v0_18_0) {
                // testing v0_18_0 verified with Windows 10:    ?
                // testing v0_18_0 verified with Kubuntu 18.04: yes, ok
                println!("For OpenSC 0.18.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, size_of::<sc_pkcs15_card>: {}, \
                    size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, size_of::<sc_pkcs15init_skeyargs>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, sco, scc, spo, sca, sf, sccc, ip, is);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1384); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1400); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }

                assert_eq!(sse,  808);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp, 4456);
                assert_eq!(sco,  280);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  632); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2768);
                assert_eq!(sca,  152);
                assert_eq!(sf,   448);
                assert_eq!(sccc,  32);
                assert_eq!(ip,   800);
                assert_eq!(is,   584);
            }
            else  if cfg!(v0_19_0) {
                // testing v0_19_0 verified with Windows 10:    ?
                // testing v0_19_0 verified with Kubuntu 18.04: yes, ok
                println!("For OpenSC 0.19.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, size_of::<sc_pkcs15_card>: {}, \
                    size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, size_of::<sc_pkcs15init_skeyargs>: {}, \
                    size_of::<sc_pkcs15_prkey_info>: {}, size_of::<sc_pkcs15_pubkey_info>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, sco, scc, spo, sca, sf, sccc, ip, is,  prki, puki);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1384); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1400); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }

                assert_eq!(sse,  808);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp, 4456);
                assert_eq!(sco,  280);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  624); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2768);
                assert_eq!(sca,  152);
                assert_eq!(sf,   448);
                assert_eq!(sccc,  32);
                assert_eq!(ip,   800);
                assert_eq!(is,   584);

                assert_eq!(prki, 440);
                assert_eq!(puki, 464);
            }
            else  if cfg!(v0_20_0) {
                // testing v0_20_0 verified with Windows 10:    yes, ok
                // testing v0_20_0 verified with Kubuntu 18.04: yes, ok
                println!("For OpenSC 0.20.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_pin_cmd_data>: {}, size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, \
                    size_of::<sc_pkcs15_card>: {}, size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, \
                    size_of::<sc_pkcs15init_skeyargs>: {}, size_of::<sc_pkcs15_prkey_info>: {}, size_of::<sc_pkcs15_pubkey_info>: {}, \
                    size_of::<sc_pkcs15_skey_info>: {}, size_of::<sc_supported_algo_info>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, pcd, sco, scc, spo, sca, sf, sccc, ip, is,  prki, puki, ski, sai);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1376); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1392); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }

                assert_eq!(sse, 1112);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp, 4456);
                assert_eq!(pcd, 8936);
                assert_eq!(sco,  296);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  624); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2776);
                assert_eq!(sca,  160);
                assert_eq!(sf,   456);
                assert_eq!(sccc,  32);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(ip,   792); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(ip,   800); }

                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(is,   584); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(is,   592); }

                assert_eq!(prki, 440);
                assert_eq!(puki, 464);
                assert_eq!(ski,  408);
                assert_eq!(sai,   88);
            }
            else  if cfg!(v0_21_0) {
                // testing v0_21_0 verified with Windows 10:    ?
                // testing v0_21_0 verified with Kubuntu 18.04: yes, ok for latest commit  0e55a34
// WARNING watch out for everything that depends on SC_MAX_SUPPORTED_ALGORITHMS, increased from 8 -> 16  sse,
// sc_pin_cmd_data pcd with new int field
// sc_pin_cmd_pin  pcp with some fields removed
                println!("For OpenSC 0.21.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_pin_cmd_data>: {}, size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, \
                    size_of::<sc_pkcs15_card>: {}, size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, \
                    size_of::<sc_pkcs15init_skeyargs>: {}, size_of::<sc_pkcs15_prkey_info>: {}, size_of::<sc_pkcs15_pubkey_info>: {}, \
                    size_of::<sc_pkcs15_skey_info>: {}, size_of::<sc_supported_algo_info>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, pcd, sco, scc, spo, sca, sf, sccc, ip, is,  prki, puki, ski, sai);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1376); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1392); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }

                assert_eq!(sse, 2712);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp,   88);
                assert_eq!(pcd,  208);

                #[cfg(not(sym_hw_encrypt))]
                assert_eq!(sco,  296);
                #[cfg(    sym_hw_encrypt)]
                assert_eq!(sco,  312);

                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  624); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2776);
                assert_eq!(sca,  160);
                assert_eq!(sf,   456);
                assert_eq!(sccc,  32);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(ip,   792); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(ip,   800); }

                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(is,   584); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(is,   592); }

                assert_eq!(prki, 472);
                assert_eq!(puki, 496);
                assert_eq!(ski,  440);
                assert_eq!(sai,  144);
            }
            else  if cfg!(v0_22_0) { // experimental only: it's git-master, Latest commit 0e55a34, defined as version 0.21.0
                // testing v0_22_0 verified with Windows 10:    ?
                // testing v0_22_0 verified with Kubuntu 18.04: ?,  for latest commit  85e08ae
                println!("For OpenSC 0.22.0 and 64bit unix/windows OS: size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_pin_cmd_data>: {}, size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, \
                    size_of::<sc_pkcs15_card>: {}, size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, \
                    size_of::<sc_pkcs15init_skeyargs>: {}, size_of::<sc_pkcs15_prkey_info>: {}, size_of::<sc_pkcs15_pubkey_info>: {}, \
                    size_of::<sc_pkcs15_skey_info>: {}, size_of::<sc_supported_algo_info>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, pcd, sco, scc, spo, sca, sf, sccc, ip, is,  prki, puki, ski, sai);
                #[cfg(any(target_pointer_width = "32", windows))]
                    { assert_eq!(sc,  1376); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                    { assert_eq!(sc,  1392); }
                #[cfg(any(target_pointer_width = "32", windows))]
                    { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                    { assert_eq!(sr,   208); }

                assert_eq!(sse, 2712);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp,   88);
                assert_eq!(pcd,  208);

                #[cfg(not(sym_hw_encrypt))]
                assert_eq!(sco,  296);
                #[cfg(    sym_hw_encrypt)]
                assert_eq!(sco,  312);

                #[cfg(any(target_pointer_width = "32", windows))]
                    { assert_eq!(scc,  624); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                    { assert_eq!(scc,  632); }

                assert_eq!(spo, 2776);
                assert_eq!(sca,  160);
                assert_eq!(sf,   456);
                assert_eq!(sccc,  32);
                #[cfg(any(target_pointer_width = "32", windows))]
                    { assert_eq!(ip,   792); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                    { assert_eq!(ip,   800); }

                #[cfg(any(target_pointer_width = "32", windows))]
                    { assert_eq!(is,   584); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                    { assert_eq!(is,   592); }

                assert_eq!(prki, 472);
                assert_eq!(puki, 496);
                assert_eq!(ski,  440);
                assert_eq!(sai,  144);
            }
            else {
                // experimental use only, this check may not be consistent with current master
                println!("For OpenSC beyond 0.22.0 (https://github.com/OpenSC/OpenSC  branch: master) and 64bit unix/windows OS: \
                    size_of::<list_t>: {}, size_of::<sc_card>: {}, size_of::<sc_reader>: {}, \
                    size_of::<sc_security_env>: {}, size_of::<sc_ef_atr>: {}, size_of::<sc_reader_driver>: {}, size_of::<sc_pin_cmd_pin>: {}, \
                    size_of::<sc_pin_cmd_data>: {}, size_of::<sc_card_operations>: {}, size_of::<sc_context>: {}, size_of::<sc_pkcs15_object>: {}, \
                    size_of::<sc_pkcs15_card>: {}, size_of::<sc_file>: {}, size_of::<scconf_context>: {}, size_of::<sc_pkcs15init_prkeyargs>: {}, \
                    size_of::<sc_pkcs15init_skeyargs>: {}, size_of::<sc_pkcs15_prkey_info>: {}, size_of::<sc_pkcs15_pubkey_info>: {}, \
                    size_of::<sc_pkcs15_skey_info>: {}, size_of::<sc_supported_algo_info>: {}",
                         sl, sc, sr, sse, sef, srd, pcp, pcd, sco, scc, spo, sca, sf, sccc, ip, is,  prki, puki, ski, sai);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sc,  1384); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sc,  1392); }
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(sr,   200); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(sr,   208); }

                assert_eq!(sse, 2712);
                assert_eq!(sef,  176);
                assert_eq!(srd,   32);
                assert_eq!(pcp,   88);
                assert_eq!(pcd,  208);
                assert_eq!(sco,  296);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(scc,  624); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(scc,  632); }

                assert_eq!(spo, 2776);
                assert_eq!(sca,  160);
                assert_eq!(sf,   456);
                assert_eq!(sccc,  32);
                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(ip,   792); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(ip,   800); }

                #[cfg(any(target_pointer_width = "32", windows))]
                { assert_eq!(is,   584); }
                #[cfg(all(target_pointer_width = "64", not(windows)))]
                { assert_eq!(is,   592); }

                assert_eq!(prki, 472);
                assert_eq!(puki, 496);
                assert_eq!(ski,  440);
                assert_eq!(sai,  144);
            }
            println!("\nTesting whether linking against the OpenSC binary works: On success, it will state the OpenSC version in the following line:");
            println!("\n### Release version of installed OpenSC binaries is  {:?}  ###\n",
                     unsafe { CStr::from_ptr(sc_get_version()) });
        }
        else { // if cfg!( not (all(target_pointer_width = "64", any(unix, windows))))
            println!("Testing version's struct sizes actually *DID NOT* take place");
            println!("For unknown OpenSC version, unknown OS: size_of::<list_t>: {}, size_of::<sc_card>: {}", sl, sc);
            assert!(false);
        }
    }
}

/*
$ grep -rnw c_ulong

pub struct sc_pkcs15_skey_info {
pkcs15.rs:700:    pub key_type : c_ulong,


pub struct sc_pkcs15init_prkeyargs {
pkcs15_init.rs:257:    pub usage : c_ulong,
pkcs15_init.rs:258:    pub x509_usage : c_ulong,

pub struct sc_pkcs15init_pubkeyargs {
pkcs15_init.rs:289:    pub usage : c_ulong,
pkcs15_init.rs:290:    pub x509_usage : c_ulong,

pub struct sc_pkcs15init_skeyargs {
pkcs15_init.rs:315:    pub usage : c_ulong,
pkcs15_init.rs:318:    pub algorithm : c_ulong, /* User requested algorithm */
pkcs15_init.rs:319:    pub value_len : c_ulong, /* User requested length */

pub struct sc_pkcs15init_certargs {
pkcs15_init.rs:335:    pub x509_usage : c_ulong,


pub struct sc_apdu {
types.rs:436:    pub flags : c_ulong, //unsigned long flags;

pub struct sc_iin {
types.rs:504:    pub issuer_id : c_ulong,        /* issuer identifier */




pub struct sc_security_env {
opensc.rs:409:    pub flags           : c_ulong,    /* e.g. SC_SEC_ENV_KEY_REF_SYMMETRIC, ... */


opensc.rs:513:    pub exponent : c_ulong,

pub struct sc_reader {
opensc.rs:690:    pub flags               : c_ulong,
opensc.rs:691:    pub capabilities        : c_ulong,

pub struct sc_card {
opensc.rs:901:    pub caps : c_ulong,
opensc.rs:902:    pub flags : c_ulong,

pub struct sc_context {
opensc.rs:1179:    pub flags : c_ulong,                // since opensc source release v0.16.0

pub struct sc_context_param_t {
opensc.rs:1356:    pub flags : c_ulong,


pub struct sc_atr_table {
internal.rs:68:    pub flags : c_ulong,

*/
