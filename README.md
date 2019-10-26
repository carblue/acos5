This repository now empraces all "driver-related" referring to ACOS5, an ACS family of smart cards / USB cryptographic tokens, which are specifically designed to enhance the security and performance of RSA (and ECC) Public-key cryptographic operations. ECC is available only since ACOS5-EVO.

Motivation:
For platform-independent, serious use of a cryptographic token like ACOS5 from a software application, a PKCS#11 implementing library is required.<br>
There is none known to me for ACOS5 that is open source and the available ones from ACS are for Windows only, or You'll have to pay a lot more for that than for the hardware.

OpenSC offers a PKCS#11 implementing open source library if it get's augmented by a hardware specific driver, which is missing currently for ACOS5 in OpenSC v0.20.0, and the one available in earlier versions was rudimentary/incomplete.

With this repo's components 'acos5' and 'acos5_pkcs15' as plug-ins, OpenSC supports ACOS5 as well. (Fortunately OpenSC allows such plug-ins as - in OpenSC lingo - external modules/shared libraries.<br>
They got implemented in the Rust programming language, so You will need the Rust compiler and cargo build tool from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install") to build those libraries from source code).<br>
If there is anybody willing to transform the Rust code into an internal OpenSC driver, then I'll be happy to support that undertaking.
External modules need some configuration once in opensc.conf, such that they get 'registered' and used by OpenSC, explained below.

# Build state

[![Build Status](https://travis-ci.org/carblue/acos5.svg?branch=master)](https://travis-ci.org/carblue/acos5)

# acos5

Driver for Advanced Card Systems  ACOS5 Smart Card V2.00, V3.00 and V4.00 (EVO) / CryptoMate64 (V2.00) / CryptoMate Nano (V3.00), as external module operating within the OpenSC framework.<br>

External module, in this context means: You also have to "tell opensc.conf some details", such that OpenSC can find the driver library, knows about it and can load it as a known driver.
External module also has the implication, that OpenSC calls up to 3 different libraries (depending on opensc.conf configuration and functionality required): Into this mandatory driver library, into an optional library [acos5_pkcs15](https://github.com/carblue/acos5_pkcs15) and into an optional acos5-specific 'Secure Messaging' library.<br>
OpenSC also has the implication: If Your card got initialized and is not PKCS#15 compliant, it won't work (well) with OpenSC and likely requires card's re-initialization<br>
The minimal OpenSC version supported is 0.17.0<br>
The new ACOS5-EVO is not yet available to me and untested.<br>
The respective reference manual is available on request from: info@acs.com.hk


IMPORTANT renaming<br>
Since release 0.0.28 the driver starts to cover (some, work in progress) support for ACOS5-EVO, which has a 192 kB EEPROM, thus the former "_64" suffix for 64 kB EEPROM is inappropriate now.<br>
This repo's name changed, as well as the driver's name and binary name and required entries in opensc.conf


Steps towards a driver binary build libacos5.so/dll/dylib
============================================================
1. Install OpenSC (if it's not there already). The driver will call into libopensc.so (opensc.dll/libopensc.dylib), will need the configuration file opensc.conf to be adapted, and the build process will need an installed package pkgconfig in order to read from opensc.pc (You have to create that: see how the script .travis.yml constructs/adapts it from opensc-pkcs11.pc (if that is available), or copys a basic version, that must be adapted).
For details read on in opensc-sys binding.<br>
Invoke `opensc-tool --info` in order to know Your installed OpenSC version. The driver build will be tied to that specific OpenSC version.

2. Install the Rust compiler and cargo build manager (it's bundled) from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install")<br>
(If those rust tools aren't required anymore, later uninstall with: rustup self uninstall)

3. Build the driver acos5: `cargo build --release`. The binary will be built into directory target/release<br>
   Towards OpenSC, the driver's name is acos5-external, in order to make it distinguishable from a quite useless acos5 internal driver, that existed in OpenSC throughout until version 0.19.0

4. Adapt opensc.conf (see below). Also, in the beginning, switch on logging by a setting `debug=3;`<br>
   If all the above went well, the log file will have an entry within it's first 4 lines, reporting: "load_dynamic_driver: successfully loaded card driver 'acos5-external'".<br>
   Check that by reissuing: `opensc-tool --info`<br>
   The last command should have successfully loaded card driver 'acos5-external', but it didn't yet use it. The next will do so (and also check for disallowed duplicate file ids):<br>
   `opensc-tool --serial`
5. In case build errors or other errors occur:
   Only now since Rust is installed and `cargo build` has run, You have a copy of the opensc-sys binding on Your system in directory $HOME/.cargo/git/checkouts.<br>
   If there are build errors, then go to that folder and issue `cargo test test_struct_sizeof -- --nocapture`. Likely that fails then, and an error reason is found by asking why didn't that find the library libopensc.so or does the version reported differ, or ?, or as the worst case:<br>
   OpenSC was built with different settings/switches than the binding requires/assumes.<br>
   Other errors occur: Likely the opensc.conf file is incorrect.<br>
   Otherwise file an issue.

   
The required opensc.conf entries:<br>
Since recently, OpenSC installs a very short opensc.conf. The long version (that I'm using and referring to here) is in github's/tarball's etc/opensc.conf.example.in<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5.<br>
The line "card_drivers = acos5-external, npa, internal;" is just an example from OpenSC version 0.17.0 opensc.conf: It means: Just prepend<br>
acos5-external,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5 V2.00, it's also required for any OpenSC release version <= 0.19.0, to bypass the almost non-functional 'acos5' internal driver somehow, thus a painless start is by using<br>
    card_drivers = acos5-external, default;

```
app default {
.........
    #debug = 3;                           # optionally remove the leading # for temporary log output; diver's log is available with debug = 3 (only?); meaning of the number: look at https://github.com/carblue/opensc-sys/blob/master/src/log.rs
    # debug_file = /tmp/opensc-debug.log; # optionally remove the leading # for temporary log output and terminate debug_file=value with a semicolon ;  possibly path adaption required !
.........
    # card_driver customcos {
    # The location of the driver library
    # module = /usr/lib/x86_64-linux-gnu/libcard_customcos.so;
    # }
...
    card_driver acos5-external {
        # module, the (/path/to/) filename of the driver library .so/.dll/.dylib. /path/to/ is dispensable if filename is in a 'standard library search path'
        module = /something/like/path/to/acos5/target/release/libacos5.so;

        # "user-consent": Override disable / enable GUI enquiry popup when performing a signature or RSA decrypt operation with ACOS5.
        # Operational only if compiled with cfg=enable_acos5_ui and IUP installed:
        # user_consent_enabled = yes; # anything starting with letter t or y (case-insensitive) get's interpreted as true/yes, otherwise false/no
        # When the dialog window pops up: Answer with NO in order to decline the RSA key usage; YES or closing the window [X] means accepting RSA key usage
    }
...
.........
    #card_drivers = npa, internal;
...
    card_drivers = acos5-external, npa, internal; # for a painless start use  card_drivers = acos5-external, default;
...
}
```

You'll probably also want [acos5_pkcs15](https://github.com/carblue/acos5_pkcs15 "https://github.com/carblue/acos5_pkcs15"), an optional library that supplements driver 'acos5' with some specific PKCS#15 related functionality (it's mandatory for [acos5_gui](https://github.com/carblue/acos5_gui "https://github.com/carblue/acos5_gui")).<br>

You will very likely need a card (re-)initialization suitable for OpenSC (i.e. PKCS#15-compliant, see [card_initialization README](https://github.com/carblue/acos5/blob/master/info/card_initialization/README.md "https://github.com/carblue/acos5/blob/master/info/card_initialization/README.md"))
