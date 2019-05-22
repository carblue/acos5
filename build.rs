/* build.rs */

extern crate pkg_config;

fn main() {
/*
   If not existing in the standard library search path, create a symbolic link there, named libopensc.so
   (Windows: opensc.lib), targeting the relevant object: With Linux, that's (depending on OpenSC version)
   something like libopensc.so.5 or libopensc.so.6 or ...
 */

/* pkg_config-based-adaption to installed OpenSC release version
   with file /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc in place:
   This will print to stdout (for Kubuntu):
   cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu
   cargo:rustc-link-lib=opensc
   cargo:rustc-cfg=v0_19_0   <= or whatever version the installed OpenSC package is

   Whenever the installed OpenSC package changes, be reminded of these actions required:
   1. Check that a file or symbolic link libopensc.so/opensc.lib exists in OS library search path (and points to the correct library)
   2. Adapt Version: in /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc
   3. Delete file Cargo.lock and delete directory target (/path/to/opensc-sys/target)
   4. Rebuild the driver by first deleting Cargo.lock and target (/path/to/acos5_64/target); this forces the changed OpenSC package version for opensc-sys
   5. Rebuild (if used) acos5_64_pkcs15init and sm by first deleting Cargo.lock and target
   6. Run cargo build -v -v and check that for both e.g. driver and opensc-sys, the changed OpenSC package version was used
   7. If that failed, remove directory target, deactivate the following match pkg_config... {...} code block and activate the required lines println!("cargo:rustc-...=... manually in all build.rs.
*/
    match pkg_config::Config::new().atleast_version("0.17.0").probe("opensc") {
        Ok(lib) => {
            match lib.version.as_str() {
//                "0.15.0" => println!("cargo:rustc-cfg=v0_15_0"),
//                "0.16.0" => println!("cargo:rustc-cfg=v0_16_0"),
                "0.17.0" => println!("cargo:rustc-cfg=v0_17_0"),
                "0.18.0" => println!("cargo:rustc-cfg=v0_18_0"),
                "0.19.0" => println!("cargo:rustc-cfg=v0_19_0"),
                _ => ()
            }
        }
        Err(_e) => panic!("No pkg-config found for opensc library") // "{}", e.description()
    };
/* in case of non-availability of pkg-config or failure of above:
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-lib=opensc");
    println!("cargo:rustc-cfg=v0_19_0");   <= or whatever version the installed OpenSC package is
*/

    /* other conditionaĺ compilation settings */
    println!("cargo:rustc-cfg=log"); // enables acos5_64 log output to file debug_file, set in opensc.conf (e.g. debug_file = "/tmp/opensc-debug.log";). Otherwise the driver will be almost quiet referring that
//    println!("cargo:rustc-cfg=impl_default"); // enables impl Default      for some struct s
//    println!("cargo:rustc-cfg=impl_display"); // enables impl fmt::Display for some struct s
//    println!("cargo:rustc-cfg=gui"); // unused currently: enables compile additional functionality, that is required only by acos5_64_gui; see repo carblue/acos5_64_gui
}
