/* build.rs, identical for driver acos5 and acos5_pkcs15 */

extern crate pkg_config;

fn main() {
/*
   IMPORTANT: changes to cargo:rustc-cfg=... MUST BE identical for driver acos5 and acos5_pkcs15 (there is no reason for differing build.rs anyway)

   General note for Linux/(macOS?) :
   The path /usr/lib/x86_64-linux-gnu used here is exemplary only: It's where my Kubuntu distro places OpenSC library files, and relative to that path other stuff as well.
   That path may be different for other distros/or following OpenSC's ./configure --prefix=/usr option, it will be /usr/lib or possibly /usr/local/lib  or whatever

   If not existing in the standard library search path, create a symbolic link there, named libopensc.so
   (Windows: opensc.lib), targeting the relevant object: With Linux, that's (depending on OpenSC version)
   something like libopensc.so.5 or libopensc.so.6 or ...
 */

/* pkg_config-based-adaption to installed OpenSC release version
   with file /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc in place:
   This will print to stdout (for (K)ubuntu) some required arguments for the linker/compiler:
   cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu
   cargo:rustc-link-lib=opensc
   cargo:rustc-cfg=v0_19_0   <= or whatever version the installed OpenSC package is. The relevant version info is taken from /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc

   Whenever the installed OpenSC package changes, be reminded of these actions required:
   1. Check that a file or symbolic link libopensc.so/opensc.lib exists in OS library search path (and points to the correct library)
   2. Adapt Version: in /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc
   3. Delete file Cargo.lock and delete directory target (/path/to/opensc-sys/target)
   4. Rebuild the driver by first deleting Cargo.lock and target (/path/to/acos5/target); this forces the changed OpenSC package version for opensc-sys
   5. Rebuild (if used) acos5_pkcs15 and sm by first deleting Cargo.lock and target
   6. Run cargo build -v and check that for both opensc-sys and e.g. driver, the changed OpenSC package version was used
   7. If that failed, remove directory target, deactivate the following match pkg_config... {...} code block and activate the required lines (see below) println!("cargo:rustc-...=... manually in all build.rs.
*/
    match pkg_config::Config::new().atleast_version("0.17.0").probe("opensc") {
        Ok(lib) => {
            match lib.version.as_str() {
                "0.17.0" => println!("cargo:rustc-cfg=v0_17_0"),
                "0.18.0" => println!("cargo:rustc-cfg=v0_18_0"),
                "0.19.0" => println!("cargo:rustc-cfg=v0_19_0"),
                "0.20.0" => println!("cargo:rustc-cfg=v0_20_0"), // experimental only: it's git-master Latest commit a8de0070fd351b56895191653bf35888d0d3ab39, defined as version 0.20.0 in config.h
//                "0.21.0" => println!("cargo:rustc-cfg=v0_21_0"), // experimental only: it's git-master, Latest commit ?, defined as version 0.21.0 in config.h
                _ => panic!("No matching version found for opensc library"),
            }
        }
        Err(_e) => panic!("No pkg-config found for opensc library") // "{}", e.description()
    };
/* in case of non-availability of pkg-config or failure of above, uncomment this block, comment-out the previous
   (possibly adapt next line for path_to of /path_to/libopensc.so|dylib|lib; for Windows, the path to import library .lib):
//  println!("cargo:rustc-link-search=native=/path/to/opensc-sys/windows-x86_64/lib/v0_19_0"); // Windows, the directory that contains opensc.lib
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");                      // Posix,   the directory that contains libopensc.so/libopensc.dylib
    println!("cargo:rustc-link-lib=opensc");
    println!("cargo:rustc-cfg=v0_19_0"); //  <= or whatever version the installed OpenSC package is
*/

    /* other conditionaĺ compilation settings */
    println!("cargo:rustc-cfg=log"); // enables driver log output to file debug_file, set in opensc.conf (e.g. debug_file = "/tmp/opensc-debug.log";). Otherwise the driver will be almost quiet referring that
//    println!("cargo:rustc-cfg=test_v2_v3_token");
//    println!("cargo:rustc-cfg=dev_relax_signature_constraints_for_raw"); // this is an insecure setting, meant to be used only temporarily for pkcs11-tool -t with  SC_ALGORITHM_RSA_RAW added to rsa_algo_flags in acos5_init
//    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libacos5.so.6"); //doesn't work currently

//    println!("cargo:rustc-cfg=enable_acos5_ui"); // enables driver to ask for user consent prior to using RSA private keys (for sign, decrypt); DO ENABLE ONLY together with the 2 following lines relating to IUP
//    println!("cargo:rustc-link-lib=iup"); // specifies linking libiup.so/dylib or compiling on Windows with import library iup.lib
//    println!("cargo:rustc-link-search=native=/usr/lib"); // specifies where libiup.so/dylib/dll is located
}
