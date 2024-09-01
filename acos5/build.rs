/* build.rs, identical for driver acos5 and acos5_pkcs15 */
use std::env;

fn main() {
    if let Ok(cfg_opensc_version) = env::var("DEP_OPENSC_OPENSCVERSION") {
        println!("cargo:rustc-cfg={}", cfg_opensc_version);
    }

    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo:rustc-link-lib=dylib=crypto");
        println!("cargo:rustc-link-lib=dylib=tasn1"); // see also https://gnutls.gitlab.io/libtasn1/libtasn1.html
    }
    #[cfg(    target_os = "windows")]
    {
        println!("cargo:rustc-link-search=C:/Program Files/OpenSSL-Win64/bin");
        println!("cargo:rustc-link-lib=dylib=crypto-3-x64"); // libeay32.lib -> libcrypto.lib; Since version 1.1.0 OpenSSL have changed their library names from: libeay32.dll -> libcrypto.dll etc.
        //let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        //println!("cargo:rustc-link-search={}/windows-x86_64", manifest_dir);
        //println!("cargo:rustc-link-lib=dylib=msys-tasn1-6");  // see also https://gnutls.gitlab.io/libtasn1/libtasn1.html, dll : mingw-w64-libtasn1 from https://packages.msys2.org/base
    }

    /* other conditional compilation settings */
    println!("cargo:rustc-cfg=log"); // enables driver log output to file debug_file, set in opensc.conf (e.g. debug_file = "/tmp/opensc-debug.log";). Otherwise the driver will be almost quiet referring that
//     println("cargo:rustc-cfg=card_initialization"); // enables card initialization code
    { // in the following lines of this block ({...}), remove either all leading // if You want that feature compiled in, or none to keep that inactive
//        println!("cargo:rustc-cfg=iup_user_consent"); // enables driver to ask for user consent prior to using RSA private keys (for sign, decrypt); DO ENABLE ONLY together with the 2 following lines relating to IUP
//        println!("cargo:rustc-link-lib=dylib=iup"); // specifies linking libiup.so/dylib or compiling on Windows with import library iup.lib
//        println!("cargo:rustc-link-search=native=C:/bin"); // specifies where libiup.so/dylib/ iup.lib is located
    }
//     println!("cargo:rustc-cfg=ifd_serial_constrained_for_sm"); // if this gets activated, then only for the ifd_serial set in opensc.conf will SM commands be executed (if any at all)
//     println!("cargo:rustc-cfg=dev_relax_signature_constraints_for_raw"); // this is an insecure setting, meant to be used only temporarily for pkcs11-tool -t with  SC_ALGORITHM_RSA_RAW added to rsa_algo_flags in acos5_init
//     println!("cargo:rustc-cfg=key_gen_verbose"); // enable to print to console some info while generating RSA key pair (see function acos5_pkcs15/src/lib.rs: acos5_pkcs15_create_key)
//     println!("cargo:rustc-cfg=finish_verbose"); // enable to print to console some info short before finishing driver process (see function acos5_finish)
}
