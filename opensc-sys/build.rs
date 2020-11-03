/* build.rs */
extern crate libloading;

use libloading::{Library, Symbol, Error};
use std::{os::raw::c_char, ffi::CStr};

fn parse_version_string(r#in: &str) -> String {
    let mut result = String::from("cargo:rustc-cfg=");
    let v: Vec<&str> = r#in.splitn(3, '.').collect();
    assert_eq!(3, v.len());
    for (i, elem) in v.iter().enumerate() {
        if i==0 { result.push_str("v"); }
        else    { result.push('_'); }
        result.push_str(*elem);
    }
    println!("{}", result);
    result
}

fn main() {
    /* OpenSC version detection */
    match Library::new(if cfg!(unix) {"libopensc.so"}
                       else if cfg!(macos) {"libopensc.dylib"}
                       else if cfg!(windows) {"opensc"}
                       else {"unknown_library_opensc"} )
    {
        Ok(lib_dyn) =>
            unsafe {
                let func_dyn: Symbol<unsafe fn() -> *const c_char> = lib_dyn.get(b"sc_get_version").unwrap();
                let cargo_string = parse_version_string(CStr::from_ptr(func_dyn()).to_str().unwrap());
                println!("cargo:OPENSCVERSION={}", &cargo_string.as_str()[16..]);
            },
        Err(e) => {
            match &e {
                Error::DlOpen { desc: _ } => { println!("libloading DlOpen opensc: {}", e); },
                Error::DlOpenUnknown => { println!("libloading DlOpenUnknown opensc: {}", e); },
                Error::LoadLibraryW { source: _ } => { println!("libloading LoadLibraryW opensc: {}", e); },
                Error::LoadLibraryWUnknown => { println!("libloading LoadLibraryWUnknown opensc: {}", e); },
                _ => { println!("libloading opensc: {}", e); },
            }
            unreachable!(); // intentionally panic if OpenSC is not installed or detectable this way
        }
    }

    println!("cargo:rustc-link-lib=dylib=opensc");
    // println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rerun-if-changed=/usr/lib/x86_64-linux-gnu/libopensc.so");

    /* other conditional compilation settings, required only for testing (impl_default) and by driver acos5/acos5_pkcs15 */
    println!("cargo:rustc-cfg=impl_default"); // enables impl Default      for many structs, used extensively for tests
    println!("cargo:rustc-cfg=impl_display"); // enables impl fmt::Display for sc_context
    println!("cargo:rustc-cfg=acos5_impl_default"); // enables impl Default, acos5-specific for some structs
    println!("cargo:rustc-cfg=impl_newAT_newCCT_newCT"); // enables some acos5-specific ? assoc. new func. for struct sc_crt
}
