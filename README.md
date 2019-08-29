# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

Driver for ACOS5-64 Smart Card / CryptoMate64 / CryptoMate Nano (Advanced Card Systems); external module operating within the OpenSC framework (min. version 0.17.0).<br>
Hardware supported: V2.00 and V3.00. The new ACOS5-EVO is not yet available to me and untested.

[ACOS5-64 Smart Card](https://www.acs.com.hk/en/products/308/acos5-64-v3.00-cryptographic-card-contact "ACOS5-64 Cryptographic Card (Contact) - Advanced Card Systems Ltd.") (V3.00)<br>
[ACOS5-64 USB Token](https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens "ACOS5-64 CryptoMate Nano Cryptographic USB Token - Advanced Card Systems Ltd.") (V3.00)<br>
[ACOS5 EVO](https://www.acs.com.hk/en/press-release/2579/acs-launches-acos5-evo-cryptographic-smart-card)<br>
The reference manual for V2.00, REF-ACOS5-64-1.07.pdf, is available on request from  info@acs.com.hk<br>
The reference manual for V3.00, REF-ACOS5-64-2.07.pdf, is available on request from  info@acs.com.hk<br>
https://archive.fosdem.org/2018/schedule/event/smartcards_in_linux/attachments/slides/2265/export/events/attachments/smartcards_in_linux/slides/2265/smart_cards_slides.pdf<br>
https://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works<br>
https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/learn/get-started. If Rust/cargo is not required anymore, uninstall with: rustup self uninstall

Look into build.rs first for some details about the libopensc binary (version etc.) and pkg-config.<br>

The prerequisite required to be installed is evident: OpenSC packages (e.g. Ubuntu: opensc, which depends on (required) opensc-pkcs11).<br>
Whether or not You intend to build the OpenSC binaries from sources, it's recommended to read the first 100 lines of [opensc-sys.lib.rs](https://github.com/carblue/opensc-sys/blob/master/src/lib.rs "https://github.com/carblue/opensc-sys/blob/master/src/lib.rs")<br>
The opensc-sys binding should be tested to be operational.

Another "weak prerequisite" is pkg-config package installed. It's used in file build.rs to adapt the code to the OpenSC version installed, i.e. a driver build will always be tied to a specific OpenSC version and needs to be rebuilt whenever the OpenSC version changes (before that, change opensc.pc to the new Version). There is a way to make the adaption work without pkg-config by editing build.rs, see comments in file build.rs.
The adaption based on pkg-config needs a file opensc.pc to be created on Your system. No distro supplys that, but a file opensc-pkcs11.pc. Copy that as file opensc.pc into the same directory location and change the content (see after <- what to change where; don't change anything else e.g. if Your libdir is different from mine on Kubuntu, that's fine and specific for Your OS). The last 2 lines are what processing build.rs via pkg-config will utilize from opensc.pc:

```
prefix=/usr
exec_prefix=${prefix}
libdir=/usr/lib/x86_64-linux-gnu
includedir=${prefix}/include

Name: OpenSC smartcard framework
Description: OpenSC PKCS#11 module        <- Description: OpenSC library
Version: 0.19.0
Libs: -L${libdir} -lopensc-pkcs11         <- Libs: -L${libdir} -lopensc

```

There is an optional prerequisite: IUP installed, if You want the feature "user consent", see in the end.


Build the driver binary as usual with Rust<br>
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
        # module, the (/path/to/) filename of the driver library .so/.dll/.dylib. /path/to/ is dispensable if filename is in a 'standard library search path'
        module = /something/like/path/to/acos5_64/target/release/libacos5_64.so;

        # Disable / enable enquiry popup when performing a signature or RSA decrypt operation with ACOS5-64.
        # Operational only if compiled with cfg=enable_acos5_64_ui:
        # user_consent_enabled = yes; # anything starting with letter t or y (case-insensitive) get's interpreted as true/yes, otherwise false/no
        # When the dialog/popup window is shown: Answer with NO in order to decline the RSA key usage; YES or closing the window [X] means accepting RSA key usage
    }
...
.........
    #card_drivers = npa, internal;
...
    card_drivers = acos5_64, npa, internal; # for a painless start use  card_drivers = acos5_64, default;
...
}
```

You'll probably also want [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init"), an optional library that supplements driver 'acos5_64' with some specific PKCS#15 related functionality (it doesn't supply much currently, yet it's non-optional for [acos5_64_gui](https://github.com/carblue/acos5_64_gui "https://github.com/carblue/acos5_64_gui")).<br>

The third in the trio will be acos5_64_sm, an optional library that supplements driver 'acos5_64' with Secure Messaging support.

Detailed info about what is working is in directory info/what_do_the_rust_implementations_driver_pkcs15init_sm_currently_support.

The driver should be given a chance to know the content of all Security Environment Files and it will read that content if it's allowed to.<br>
If any Security Environment File is read-protected (either readable only after some condition fulfilled like successful pin verification or never-readable), and You have a chance to change that to always readable, then do so.<br>
If not, You'll have to change source code and enter the content of Security Environment File records in source code.
Without infos from the Security Environment File likely errors with return status word sw1sw2 0x6982 will occur: "Security condition is not satisfied". In some situations that's an unrecoverable error and OpenSC will shut down.

A template how to do the source code change is function `get_known_sec_env_entry_V3_FIPS` in no_cdecl.rs, which does exactly that for V3 cards being FIPS-compliant (where the Security Environment Files mindless are required to be read-protected, but their content is known and published in the reference manual).
If there are problems with this issue, I can assist with that, provided that I can deduce that a serious attempt was made to solve that on Your own by reading the reference manual and my assistance is NOT just replacing reading that.

Another way to tackle the "Security Environment File is read-protected" problem is: Introduce Your PINs into the code in acos5_64/src/no_cdecl.rs: function enum_dir, the block that contains is_wrong_acs_initialized.<br>
It starts with the cards serial no.and the individual pins to be adjusted and whether the card is erroneously initialized by client kit.

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

"user consent"<br>
This is a feature to constrain usage of token's RSA private keys: Only when the user allows  RSA private key usage case by case, then `acos5_64_compute_signature` and `acos5_64_decipher` are allowed to proceed operating for RSA private keys.<br>
Independent from that, the RSA private key files should be created with "never allowed to read" and "allowed to perform crypto operations only after some condition fulfilled, like verify a pin" and that pin should be the same as the one required for a User Login.<br>
I deem this feature invaluable, as many applications start asking for the User Login Pin, but never tell what they will do with that permission. Unconstrained, they could likely do everything after a Login.<br>
How this works: First the driver must be compiled with "cfg=enable_acos5_64_ui" (see file build.rs, other conditional compilation settings). This - as a default - enables this feature.
The graphical part of this feature is based on [IUP](https://www.tecgraf.puc-rio.br/iup "https://www.tecgraf.puc-rio.br/iup"), thus that must be installed and the last 3 lines in build.rs must be activated (meaning removing leading //):<br>
The one that contains cargo:rustc-cfg=enable_acos5_64_ui, the next that names the iup library to link, and the last one where to find that library. The same must be applied for acos5_64_pkcs15init's build.rs if that is installed.<br>
That's it, except via opensc.conf the enabled status can be overridden by specifying user_consent_enabled = no;

Card was initialized by ACS Client Kit?<br>
What a pity! You payed money for something that claims to create a PKCS#15 conforming file system (which is required for OpenSC and thus this driver), but it doesn't !<br>
You will have to change/edit files. Ask Advanced Card Systems if they will do that for You or how to do it.<br>
The entry in MF's Security Environment File is wrong: Thus You won't be able to use the SOPIN in that directory (and You can't change that), thus You can't read MF's Security Environment File and won't know Access rights in MF directory<br>

Even the primary file for PKCS#15 is wrong: File 0x2F00 must specify the application path as absolute path, i.e. starting from 0x3F00. I.e. 2 more bytes must be stored in file 0x2F00 but they don't fit into the available file size. Deleting the file and recreating it: No way, ACS-initialization doesn't allow deletion. End of the story, You're stuck.<br>
The ACS Client Kits that I know, do define 1 application directory 0x3F004100 and content therein like a Pin file 0x3F0041004101, a Security environment File 0x3F0041004103 (read protected), 16 RSA Key pair files, a gigantic-sized Certificate File 0x3F0041004110 and no space left for additional files to be created by Yourself.<br>
The empty file 0x3F0041005031 means, Your card has no User Pin nor SOPIN (known to PKCS#15), no keys for sym. algos, no RSA key pairs etc. but definitely Your card has those files. A lot of things can't be changed at all because they are protected to be NEVER changeable.<br>
You will very likely have to remove everything and create the file system from scratch (more details in the reference manual).<br>
[acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init") is the module dedicated to support card initialization, but currently it's limited to support:<br>
pkcs15-init --erase-card --so-pin  sopin(4..8 bytes, e.g. 12345678)<br>
This will remove everything from the card including MF and let You change the Operation Mode Byte (recommended for V3.00)<br>

In order to see what's the crap on Your freshly ACS-initialized card and puzzle about what most files are for, it's recommended to run<br>
$ opensc-tool -f<br>
or use tool [acos5_64_gui](https://github.com/carblue/acos5_64_gui "https://github.com/carblue/acos5_64_gui") (acos5_64_gui will internally simulate a correct file 0x2F00, if necessary).
