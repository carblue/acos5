/* build.rs */
extern crate libloading;

use libloading::{Library, Symbol, Error};
use std::{os::raw::c_char, ffi::CStr};

fn parse_version_string(input: &str) -> String {
    /*  What a mess/inconsistency on Windows: for OpenSC 0.20.0, sc_get_version reports 0.20.0-0.20.0 // opensc-tool -i ; OpenSC 0.20.0-0.20.0 [Microsoft 1800]
        thus strip all beginning with hyphen */
    let mut result = String::from("cargo:rustc-cfg=");
    let v: Vec<&str>;
    {
        let pos = input.find('-').or(Some(input.as_bytes().len())).unwrap();
        let input = std::str::from_utf8(&input.as_bytes()[..pos]).unwrap();
        v = input.splitn(3, '.').collect();
    }
    assert_eq!(3, v.len());
    for (i, &elem) in v.iter().enumerate() {
        if i==0 { result.push_str("v"); }
        else    { result.push('_'); }
        result.push_str(elem);
        if i==1 && (elem.parse::<u32>().is_err() || elem.parse::<u32>().unwrap()<17) {
            panic!("OpenSC version detection failed or the version is less than min. 0.17.0")
        }
    }
    println!("{}", result);
    result
}

fn main() {
    let version;
    /* OpenSC version detection */
    match unsafe { Library::new(if cfg!(unix) {"libopensc.so"}
                       else if cfg!(macos) {"libopensc.dylib"}
                       else if cfg!(windows) {"opensc"}
                       else {"unknown_library_opensc"} ) }
    {
        Ok(lib_dyn) =>
            unsafe {
                let func_dyn: Symbol<unsafe fn() -> *const c_char> = lib_dyn.get(b"sc_get_version").unwrap();
                let cargo_string = parse_version_string(CStr::from_ptr(func_dyn()).to_str().unwrap());
                version = String::from(&cargo_string.as_str()[16..]); // e.g. "0.21.0"
                println!("cargo:OPENSCVERSION={}", version);
            },
        Err(e) => {
            match &e {
                Error::DlOpen { desc: _ } => { println!("libloading DlOpen opensc: {}", e); },
                Error::DlOpenUnknown => { println!("libloading DlOpenUnknown opensc: {}", e); },
                Error::LoadLibraryExW { source: _ } => { println!("libloading LoadLibraryW opensc: {}", e); },
                Error::LoadLibraryExWUnknown => { println!("libloading LoadLibraryWUnknown opensc: {}", e); },
                _ => { println!("libloading opensc: {}", e); },
            }
            unreachable!(); // intentionally panic if OpenSC is not installed or detectable this way
        }
    }

    println!("cargo:rustc-link-lib=dylib=opensc");

    #[cfg(not(target_os = "windows"))]
    {
        // println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rerun-if-changed=/usr/lib/x86_64-linux-gnu/libopensc.so");
    }
    #[cfg(    target_os = "windows")]
    {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search={}/windows-x86_64/lib/{}", manifest_dir, version);
    }

    /* other conditional compilation settings, required only for testing (impl_default) and by driver acos5/acos5_pkcs15 */
    println!("cargo:rustc-cfg=impl_default"); // enables impl Default      for many structs, used extensively for tests
    println!("cargo:rustc-cfg=impl_display"); // enables impl fmt::Display for sc_context
    println!("cargo:rustc-cfg=acos5_impl_default"); // enables impl Default, acos5-specific for some structs
    println!("cargo:rustc-cfg=impl_newAT_newCCT_newCT"); // enables some acos5-specific ? assoc. new func. for struct sc_crt
//    println!("cargo:rustc-cfg=sym_hw_encrypt"); // experimental only: May be enabled **only** with OpenSC compiled and installed from my branch https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt ; that is current OpenSC github master 85e08ae + on top my patches
}
