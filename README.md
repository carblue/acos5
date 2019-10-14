# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64


If You intend to download/clone but are not willing to respect my interest (any constructive reply), then please stay away!


Driver for ACOS5-64 Smart Card / CryptoMate64 / CryptoMate Nano (Advanced Card Systems), as<br>
external module operating within the OpenSC framework (min. version 0.17.0).<br>
External module, in this context means: You also have to "tell opensc.conf some details", such that OpenSC can find the driver library, knows about it and can load it as a known driver.
External module also has the implication, that OpenSC calls up to 3 different libraries (depending on opensc.conf configuration and functionality required): Into this mandatory driver library, into an optional library [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init) and into an optional 'Secure Messaging' sm library (not available with LGPL license).
OpenSC also has the implication: If Your card got initialized and is not PKCS#15 compliant, it won't work (well) with OpenSC and likely requires card's re-initialization<br>
Hardware supported: V2.00 and V3.00. The new ACOS5-EVO is not yet available to me and untested.<br>
The respective reference manual is available on request from: info@acs.com.hk

Likely You are here because You have an ACOS5-64 card and want it to be used - based on opensc-pkcs11.so/dll/dylib - with any software that connects to Your ACOS5-64 smart card via the PKCS#11 interface, like ssh, Firefox, Thunderbird etc.. Then this is for You.<br>
But know that we entered my deferment period: The ratio of response to download/clone count is extremely disapointing: If people who downloaded/cloned are happy or unhappy, I expect a response in some way You like.<br>
For those who leave me nothing but an increased download counter: You are demolishing my willingness to share my code with the public, and after the deferment period I will reevaluate whether I should remove this repo (, dependants and opensc-sys) and save time. And You are also the reason why I'm continuously reducing any explanatory ambition, though there is a lot to say about this driver.

A word about OpenSC: This is a quite huge and complex software that provides access to a bunch of different smart cards by providing a general framework and hooks for card specific behavior.
This driver (and if installed and required, then also the acos5_64_pkcs15init) kicks in at (some of) those hooks for ACOS5-64 specific processing. With that in tow, OpenSC provides a general PKCS#11 module/library that can be used with ACOS5-64 cards as well, and it provides a bunch of tools like opensc-tool and more to work with/inspect/manipulate supported smart cards. At it's heart it's all about implementing the standards for PKCS#11/OASIS and PKCS#15/ISO/IEC 7816-15  (see also https://en.wikipedia.org/wiki/PKCS). There is a tool in progress acos5_64_gui, for fine-grained, convinient control/administration.

Steps towards a driver binary build libacos5_64.so/dll/dylib
============================================================
1. Install OpenSC (if it's not there already). The driver will call into libopensc.so (opensc.dll/libopensc.dylib), will need the configuration file opensc.conf to be adapted, and the build process will need an installed package pkgconfig in order to read from opensc.pc (You have to create that: see how the script .travis.yml constructs/adapts it from opensc-pkcs11.pc (if that is available), or copys a basic version, that must be adapted).
For details read on in opensc-sys binding.<br>
Invoke `opensc-tool --info` in order to know Your installed OpenSC version. The driver build will be tied to that specific OpenSC version.

2. Install the Rust compiler and cargo build manager (it's bundled) from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install")<br>
(If those rust tools aren't required anymore, later uninstall with: rustup self uninstall)

3. Build the driver acos5_64: `cargo build --release`. The binary will be built into directory target/release

4. Adapt opensc.conf. Also, in the beginning, switch on logging by a setting `debug=3;`<br>
   If all the above went well, the log file will have an entry within it's first 4 lines, reporting: "load_dynamic_driver: successfully loaded card driver 'acos5_64'".<br>
   Check that by reissuing: `opensc-tool --info`<br>
   The last command should have successfully loaded card driver 'acos5_64', but it didn't yet use it. The next will do so (and also check for disallowed duplicate file ids):<br>
   `opensc-tool --serial`
5. In case build errors or other errors occur:
   Only now since Rust is installed and `cargo build` has run, You have a copy of the opensc-sys binding on Your system in directory $HOME/.cargo/git/checkouts.<br>
   If there are build errors, then go to that folder and issue `cargo test test_struct_sizeof -- --nocapture`. Likely that fails then, and an error reason is found by asking why didn't that find the library libopensc.so or does the version reported differ, or ?, or as the worst case:<br>
   OpenSC was built with different setting than the binding requires/assumes.<br>
   Other errors occur: Likely the opensc.conf file is incorrect.<br>
   Otherwise file an issue.

   
The required opensc.conf entries:<br>
Since recently, OpenSC installs a very short opensc.conf. The long version (that I'm using and referring to here) is in github's/tarball's etc/opensc.conf.example.in<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_64/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5-64.<br>
The line "card_drivers = acos5_64, npa, internal;" is just an example from OpenSC version 0.17.0 opensc.conf: It means: Just prepend<br>
acos5_64,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5-64 V2.00, it's also required for any release version including 0.19.0 (but not current git-master or OpenSC-0.20.0-rc?) to bypass the almost non-functional 'acos5' internal driver somehow, thus a painless start is by using<br>
    card_drivers = acos5_64, default;

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
    card_driver acos5_64 {
        # module, the (/path/to/) filename of the driver library .so/.dll/.dylib. /path/to/ is dispensable if filename is in a 'standard library search path'
        module = /something/like/path/to/acos5_64/target/release/libacos5_64.so;

        # "user-consent": Override disable / enable GUI enquiry popup when performing a signature or RSA decrypt operation with ACOS5-64.
        # Operational only if compiled with cfg=enable_acos5_64_ui and IUP installed:
        # user_consent_enabled = yes; # anything starting with letter t or y (case-insensitive) get's interpreted as true/yes, otherwise false/no
        # When the dialog window pops up: Answer with NO in order to decline the RSA key usage; YES or closing the window [X] means accepting RSA key usage
    }
...
.........
    #card_drivers = npa, internal;
...
    card_drivers = acos5_64, npa, internal; # for a painless start use  card_drivers = acos5_64, default;
...
}
```

You'll probably also want [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init"), an optional library that supplements driver 'acos5_64' with some specific PKCS#15 related functionality (it's mandatory for [acos5_64_gui](https://github.com/carblue/acos5_64_gui "https://github.com/carblue/acos5_64_gui")).<br>

You will very likely need a card (re-)initialization suitable for OpenSC (i.e. PKCS#15-compliant, see [card_initialization README](https://github.com/carblue/acos5_64/blob/master/info/card_initialization/README.md "https://github.com/carblue/acos5_64/blob/master/info/card_initialization/README.md"))
