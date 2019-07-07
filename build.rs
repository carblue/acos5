/* build.rs */

extern crate pkg_config;

fn main() {
/*
   General note for Linux/(macOS?) :
   The path /usr/lib/x86_64-linux-gnu used here is exemplary only: It's where my Kubuntu distro places OpenSC library files, and relative to that path other stuff as well.
   That path may be different for other distros/or following OpenSC's ./configure --prefix=/usr option, it will be /usl/lib or possibly /usr/local/lib  or whatever

   If not existing in the standard library search path, create a symbolic link there, named libopensc.so
   (Windows: opensc.lib), targeting the relevant object: With Linux, that's (depending on OpenSC version)
   something like libopensc.so.5 or libopensc.so.6 or ...
 */

/* pkg_config-based-adaption to installed OpenSC release version
   with file /usr/lib/x86_64-linux-gnu/pkgconfig/opensc.pc in place:
   This will print to stdout (for (K)ubuntu) some required arguments for the linker/compiler:
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
//                "0.15.0" => println!("cargo:rustc-cfg=v0_15_0"), // an impl. will need to care for function _sc_match_atr and more
//                "0.16.0" => println!("cargo:rustc-cfg=v0_16_0"), // dito
                "0.17.0" => println!("cargo:rustc-cfg=v0_17_0"),
                "0.18.0" => println!("cargo:rustc-cfg=v0_18_0"),
                "0.19.0" => println!("cargo:rustc-cfg=v0_19_0"),
                "0.20.0" => println!("cargo:rustc-cfg=v0_20_0"), // experimental only: it's git-master, Latest commit 130e9bb068401ec78461777695f3e3273fcc4a13, defined as version 0.20.0
                _ => ()
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
    println!("cargo:rustc-cfg=log"); // enables acos5_64 log output to file debug_file, set in opensc.conf (e.g. debug_file = "/tmp/opensc-debug.log";). Otherwise the driver will be almost quiet referring that
//    println!("cargo:rustc-cfg=impl_default"); // enables impl Default      for some struct s
//    println!("cargo:rustc-cfg=impl_display"); // enables impl fmt::Display for some struct s
//    println!("cargo:rustc-cfg=gui"); // unused currently: enables compile additional functionality, that is required only by acos5_64_gui; see repo carblue/acos5_64_gui
}
