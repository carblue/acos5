/* build.rs */

extern crate pkg_config;

fn main() {
/*
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
   4. If the following fails (used by cargo test), remove directory target, deactivate the following match pkg_config... {...} code block and activate the required lines println!("cargo:rustc-...=... manually in this build.rs.
*/
    match pkg_config::Config::new().atleast_version("0.17.0").probe("opensc") {
        Ok(lib) => {
            match lib.version.as_str() {
                "0.17.0" => println!("cargo:rustc-cfg=v0_17_0"),
                "0.18.0" => println!("cargo:rustc-cfg=v0_18_0"),
                "0.19.0" => println!("cargo:rustc-cfg=v0_19_0"),
                "0.20.0" => println!("cargo:rustc-cfg=v0_20_0"),
                "0.21.0" => println!("cargo:rustc-cfg=v0_21_0"), // experimental only: it's git-master Latest commit 57a391f, defined as version 0.21.0 in config.h
//                "0.22.0" => println!("cargo:rustc-cfg=v0_22_0"), // experimental only: it's git-master, Latest commit    ?, defined as version 0.22.0 in config.h
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

    /* other conditionaĺ compilation settings, required only for testing (impl_default) and by driver acos5/acos5_pkcs15 */
    println!("cargo:rustc-cfg=impl_default"); // enables impl Default      for many struct s, used extensively for tests
    println!("cargo:rustc-cfg=impl_display"); // enables impl fmt::Display for sc_context
    println!("cargo:rustc-cfg=acos5_impl_default"); // enables impl Default, acos5-specific for some struct s
    println!("cargo:rustc-cfg=impl_newAT_newCCT_newCT"); // enables some acos5-specific ? assoc. new func. for struct sc_crt
}

/*
  Save build.rs (if build.rs was edited)  and run:

  user@host:~/path/to/opensc-sys$ cargo test test_struct_sizeof -- --nocapture

  The opensc-sys binding is usable only, if the test does pass with SUCCESS   (test tests::test_struct_sizeof ... ok)
*/
