# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

Driver for ACS ACOS5-64 Smart Card/CryptoMate64/CryptoMate Nano; external module operating within the OpenSC framework (min. version 0.17.0).

https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/learn/get-started<br>
If Rust/cargo is not required anymore, uninstall with: rustup self uninstall

Look into build.rs first for some details about the libopensc binary (version etc.).<br>
The prerequisite required to be installed is evident: OpenSC packages (Ubuntu: opensc, which depends on opensc-pkcs11).<br>
Whether or not You intend to build the OpenSC binaries from sources, it's recommended to read the first 100 lines of [opensc-sys.lib.rs](https://github.com/carblue/opensc-sys/blob/master/src/lib.rs "https://github.com/carblue/opensc-sys/blob/master/src/lib.rs")<br>
The opensc-sys binding should be tested to be operational.

Compile as usual with Rust<br>
`user@host:~/path/to/acos5_64$ cargo build --release`<br>
`optionally, if no debug info is required for better backtrace infos: user@host:~/path/to/acos5_64$ strip --strip-all target/release/libacos5_64.so`

The required opensc.conf entries:<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_64/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5-64.<br>
The line "card_drivers = acos5_64, npa, internal;" is just an example for OpenSC version 0.17.0: It means: Just prepend<br>
acos5_64,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5-64 V2.00, it's possibly also required (any release version including 0.19.0, but not current git-master) to bypass the 'acos5' internal driver somehow, thus a painless start is by using<br>
    card_drivers = acos5_64, default;

```
app default {
.........
    #debug = 3;                           # optionally remove the leading # for temporary log output
    # debug_file = /tmp/opensc-debug.log; # optionally remove the leading # for temporary log output and terminate debug_file=value with a ;
.........
    # card_driver customcos {
    # The location of the driver library
    # module = /usr/lib/x86_64-linux-gnu/libcard_customcos.so;
    # }
...
    card_driver acos5_64 {
        # module, the (/path/to/) filename of the driver library .so/.dll/.dylib. /path/to/ is dispensable if it's in a 'standard library search path'
        module = /something/like/path/to/acos5_64/target/release/libacos5_64.so;
    }
...
.........
    #card_drivers = npa, internal;
...
    card_drivers = acos5_64, npa, internal;
...
}
```

You'll probably also want [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init"), an optional library that supplements driver 'acos5_64' with some specific PKCS#15 related functionality.<br>

The third in the trio will be acos5_64_sm, an optional library that supplements driver 'acos5_64' with Secure Messaging support.

Detailed info about what is working is in directory info/what_do_the_rust_implementations_driver_pkcs15init_sm_currently_support.

The driver should be given a chance to know the content of all Security Environment Files and it will read that content if it's allowed to.<br>
If any Security Environment File is read-protected (either readable only after some condition fulfilled like successful pin verification or never-readable), and You have a chance to change that to always readable, then do so.<br>
If not, You'll have to change source code and enter the content of Security Environment File records in source code.
Without infos from the Security Environment File likely errors with return status word sw1sw2 0x6982 will occur: "Security condition is not satisfied". In some situations that's an unrecoverable error and OpenSC will shut down.

A template how to do the source code change is function `get_known_sec_env_entry_V3_FIPS` in no_cdecl.rs, which does exactly that for V3 cards being FIPS-compliant (where the Security Environment Files mindless are required to be read-protected, but their content is known and published in the reference manual).
If there are problems with this issue, I can assist with that, provided that I can deduce that a serious attempt was made to solve that on Your own by reading the reference manual and my assistance is NOT just replacing reading that.


The driver has this peculiarity, which adds ~ 1 second to it's start-up time:<br>
It scans the card for duplicate file id s.<br>
While cos5 (card operating system of ACOS5-64) allows duplicate file id s (in differing DF s), that's a bad idea, as in rare scenarios, with cos5 "smart?" file search strategy You may end up operating on another of those duplicates than intended.
Also this could confuse tracking of currently selected file/dir position.
Therefore, the driver (in the near future) won't allow duplicate file/dir id s and stop processing/panics (visible as SIGSEGV) once it detects duplicate existence.

Testing: That's tedious as a full test for each feature may include testing 4 OpenSC versions (0.17.0-experimental_0.20.0) multiplied by 2 hardware versions multiplied by 2 main OS versions (Posix and Windows). I don't do that, but usually for 0.19.0 (or 0.20.0) with CryptoMate64 and Linux. Thus something, that doesn't work as expected for another combination may slip my testing habits.
Open an issue if You encounter any failure.

Also, the driver still has a lot of assert macros which shall catch - disregarding from code bugs - unexpected input (card content) as well. As violated assert s cause a panic as well, this isn't as user-friendly as it should be: Work in Progress to replace all assert macros regarding unexpected card content by user-friendly error handling/logging to opensc-debug.log.

What is unexpected card content ? Anything that OpenSC's code can't parse as valid PKCS#15 content/structure, e.g. non-OPTIONAL ASN.1 DER content. (that also is OpenSC version dependent, see ).<br>
Sadly OpenSC nowhere states, what is the PKCS#15 version it does support, and I don't possess any PKCS#15 standard that I would have to pay for in order to state it's this or that (if anybody considers a donation for this open source project, I would appreciate to receive any ISO/IEC 7816-15 standard document after :2004)<br>

The only way to know what OpenSC supports related to PKCS#15 is looking into the sources (it's spread over a couple of files, locate with grep -rnw sc_copy_asn1_entry and/or grep -rnw sc_format_asn1_entry) or alternatively look at [PKCS15.asn](https://github.com/carblue/acos5_64_gui/blob/master/source/PKCS15.asn "https://github.com/carblue/acos5_64_gui/blob/master/source/PKCS15.asn").<br>
That PKCS15.asn is based on a published ASN.1 module `pkcs-15v1_1.asn` tailored to what current OpenSC version 0.19.0, ACOS5-64 and [libtasn1](https://www.gnu.org/software/libtasn1 "https://www.gnu.org/software/libtasn1") support. libtasn1 doesn't support classes/parameters, thus some 'unrolling' was done in there. acos5_64_gui uses that PKCS15.asn in order to detect, what is the type of ASN.1 DER data in card files (e.g. EF.AODF or EF.PrKDF or EF.Cert or ...), whether it's PKCS#15-compliant and display/decode/encode. That works (at least for my card content).

