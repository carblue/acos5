# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

Driver for ACOS5-64 Smart Card / CryptoMate64 / CryptoMate Nano (Advanced Card Systems); external module operating within the OpenSC framework (min. version 0.17.0).<br>
Hardware supported: V2.00 and V3.00. The new ACOS5-EVO is not yet available to me and untested.

The driver is tolerably complete.<br>

 Installing module [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init") is required for changing card's content like 'Creating new RSA key pair' or the not yet finished implementations of 'Store key for sym. algo', 'Card Initialization' etc.<br>
'acos5_64_pkcs15init' is Work in Progress.

IMPORTANT<br>
Usability of this driver depends on a Card Initialization suitable for OpenSC.<br>
Definitely the ACS Client Kits that I know, don't initialize a card conforming to PKCS#15, and they set some file access rights non-suitable for OpenSC. It's very unlikely that You will get a card - initialized that way - working satisfyingly with OpenSC and this driver.<br>
Thus either the Card Initialization was done manually by individual APDU commands, or some - unknown to me - suitable tool was used, or very likely the card must be reinitialized (if that is possible: see reference manual: Zeroize Card User Data Disable Flag).<br>
Reinitialization means: Remove everything from the card such that it's in factory state again: Install [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init") and invoke:<br>
`pkcs15-init --erase-card --so-pin <arg>`      e.g. pkcs15-init --erase-card --so-pin 12345678<br>
Then use [acos5_64_gui](https://github.com/carblue/acos5_64_gui "https://github.com/carblue/acos5_64_gui") and click virgin-init. This will create MF, some basic files within MF and write the SOPIN and SOPUK into MF's (global) PIN file 3F000001.<br>
The next step is not yet ready implemented: Create an application directory, e.g. 3F004100 (as the client kit does) and set-up all PKCS#15 files therein and update file 3F002F00.

[ACOS5-64 Smart Card](https://www.acs.com.hk/en/products/308/acos5-64-v3.00-cryptographic-card-contact "ACOS5-64 Cryptographic Card (Contact) - Advanced Card Systems Ltd.") (V3.00)<br>
[ACOS5-64 USB Token](https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens "ACOS5-64 CryptoMate Nano Cryptographic USB Token - Advanced Card Systems Ltd.") (V3.00)<br>
[ACOS5 EVO](https://www.acs.com.hk/en/press-release/2579/acs-launches-acos5-evo-cryptographic-smart-card)<br>
The reference manuals: for V2.00: REF-ACOS5-64-1.07.pdf, for V3.00: REF-ACOS5-64-2.07.pdf, are available on request from  info@acs.com.hk<br>
https://github.com/OpenSC/OpenSC/wiki/Card-personalization<br>
https://archive.fosdem.org/2018/schedule/event/smartcards_in_linux/attachments/slides/2265/export/events/attachments/smartcards_in_linux/slides/2265/smart_cards_slides.pdf<br>
https://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works<br>
https://www.rust-lang.org/learn/get-started  for rust/cargo installation via rustup. If rust/cargo is not required anymore, uninstall with: rustup self uninstall

Look into build.rs first for some details about the libopensc binary (version etc.) and pkg-config.<br>

The prerequisite required to be installed is evident: OpenSC packages (e.g. Ubuntu: opensc, which depends on (required) opensc-pkcs11).<br>
Whether or not You intend to build the OpenSC binaries from sources, it's recommended to read the first 100 lines (before the IN, OUT, INOUT topic) of [opensc-sys.lib.rs](https://github.com/carblue/opensc-sys/blob/master/src/lib.rs "https://github.com/carblue/opensc-sys/blob/master/src/lib.rs")<br>
The opensc-sys binding should be tested to be operational, if there are errors in the following driver binary build or usage. That build will fetch and install the binding (on Linux) to<br>
/home/user/.cargo/git/checkouts/opensc-sys-........../43ac40a<br>
Read how to test that in [opensc-sys](https://github.com/carblue/opensc-sys "https://github.com/carblue/opensc-sys")<br>
Likely You won't take any notice of that binding, but if there are problems, then start here: It's the very basic building block for all acos5_64* that MUST work properly and should be tested first in any error case !!!

Another "weak prerequisite" is pkg-config package installed. It's used in file build.rs to adapt the code to the OpenSC version installed, i.e. a driver build (the same applies to all acos5_64* builds) will always be tied to a specific OpenSC version and needs to be rebuilt whenever the OpenSC version changes (before that, change opensc.pc to the new Version). OpenSC checks external drivers whether they were built for the actual/currently installed OpenSC version and refuse loading non-matching-version external drivers!<br>
There is a way to make the adaption work without pkg-config by editing build.rs, see comments in file build.rs or see also: [closed issue #3](https://github.com/carblue/acos5_64/issues/3 "https://github.com/carblue/acos5_64/issues/3").<br>
The adaption based on pkg-config needs a file opensc.pc to be created on Your system. No distro supplies that, but a file opensc-pkcs11.pc. Copy that as file opensc.pc into the same directory location and change the content (see after <- what to change where; don't change anything else e.g. if Your libdir is different from mine on Kubuntu, that's fine and specific for Your OS). The last 2 lines are what processing build.rs via pkg-config will utilize from opensc.pc:

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
Another opensc.pc file example is in acos5_64/travis/opensc.pc: It's specific for debian/Ubuntu based distros and must be adapted as well, at least for Version:

There is an optional prerequisite: IUP installed, if You want the feature "user consent", see in the end.

Possibly set Your own RSA security level:<br>
The driver (with help from acos5_64_pkcs15init module) allows generating RSA keys with modulus sizes from 512 to 3072/4096 bits (upper limit depending on FIPS operation mode, see V3.00 reference manual), i.e. that what cos5 is capable of, but it's recommended to not use a lower limit than let's say 2048 bits.
It's recommended to bake Your lower limit into the driver and change source code: Search in src/lib.rs for the line with content:<br>
`let     rsa_key_len_from : u32 = if is_v3_fips_compliant { 2048 } else {  512 };`<br>
Replace 512 by an integral number for rsa_key_len_from (in bits) greater than 512 that is divisible by 256 (within given limits) like 2048 and save src/lib.rs. See also: https://en.wikipedia.org/wiki/Key_size

Build the driver binary as usual with Rust:<br>
`user@host:~/path/to/acos5_64$ cargo build --release`<br>
(Omitting --release from the build command will result in a debug driver build in directory  target/debug. When doing so, change in opensc.conf accordingly, see below.)<br>
`optionally, if no symbol/debug info is required for better backtrace infos: user@host:~/path/to/acos5_64$ strip --strip-all target/release/libacos5_64.so`

The required opensc.conf entries:<br>
Since recently, OpenSC installs a very short opensc.conf. The long version (preprocessed, that I'm using and referring to here) is in github's/tarball's etc/opensc.conf.example.in<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_64/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5-64.<br>
The line "card_drivers = acos5_64, npa, internal;" is just an example from OpenSC version 0.17.0 opensc.conf: It means: Just prepend<br>
acos5_64,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5-64 V2.00, it's also required for any release version including 0.19.0 (but not current git-master or OpenSC-0.20.0-rc1) to bypass the almost non-functional 'acos5' internal driver somehow, thus a painless start is by using<br>
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

Basic tests whether the acos5_64 diver is working (with my example ouput (patch applied as of https://github.com/carblue/acos5_64/blob/master/info/what_do_the_rust_implementations_driver_pkcs15init_sm_currently_support/support_for_bin_opensc-tool.txt, otherwise no record content will be shown)):<br>
```
user@host~$ opensc-tool -D
Configured card drivers:
  acos5_64         'acos5_64', suitable for ACOS5-64 v2.00 and v3.00 (Smart Card / CryptoMate64 / CryptoMate Nano)
  default          Default driver for unknown cards
user@host~$ opensc-tool --serial
Using reader with a card: ACS CryptoMate64 00 00
AA BB CC DD EE FF ......
user@host~$ opensc-tool -f
Using reader with a card: ACS CryptoMate64 00 00
3f00 type: DF, size: 0
select[NONE] lock[NONE] delete[NONE] create[NONE] rehab[NONE] inval[NONE] list[NONE] 
prop: 83:02:3F:00:88:01:00:8A:01:01:82:02:3F:00:8D:02:00:03:84:00:8C:00:AB:00

  3f000001 type: iEF, ef structure: linear-fixed, size: 21
  read[NEVR] update[CHV1] erase[CHV1] write[CHV1] rehab[CHV1] inval[CHV1] 
  prop: 83:02:00:01:88:01:01:8A:01:05:82:06:0A:00:00:15:00:01:8C:08:7F:01:FF:01:01:FF:01:FF:AB:00

Record 1
  3f000002 type: iEF, ef structure: linear-variable, size: 148
  read[NEVR] update[CHV1] erase[CHV1] write[CHV1] rehab[CHV1] inval[CHV1] 
  prop: 83:02:00:02:88:01:02:8A:01:05:82:06:0C:00:00:25:00:04:8C:08:7F:01:FF:01:01:01:01:FF:AB:00

Record 1
Record 2
Record 3
Record 4
  3f000003 type: iEF, ef structure: linear-variable, size: 48
  read[NONE] update[CHV1] erase[CHV1] write[CHV1] rehab[CHV1] inval[CHV1] 
  prop: 83:02:00:03:88:01:03:8A:01:05:82:06:1C:00:00:30:00:01:8C:08:7F:01:FF:01:01:00:01:00:AB:00

Record 1
00000000: 80 01 01 A4 06 83 01 01 95 01 08 00 00 00 00 00 ................      <== This clarifies the meaning of CHV1: The SOPIN must be verified first
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
  3f002f00 type: wEF, ef structure: transparent, size: 33
  read[NONE] update[CHV1] erase[CHV1] write[CHV1] rehab[CHV1] inval[CHV1] 
  prop: 83:02:2F:00:88:01:00:8A:01:05:82:02:01:00:80:02:00:21:8C:08:7F:01:FF:01:01:FF:01:00:AB:00

00000000: 61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 a.O.ACOSPKCS-15v
00000010: 31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 1.00P.eCertQ.?.A
00000020: 00                                              .
  3f004100 [ACOSPKCS-15v1.00] type: DF, size: 0
  select[NONE] lock[NEVR] delete[CHV129] create[CHV129] rehab[NONE] inval[CHV129] list[NONE] 
  prop: 83:02:41:00:88:01:00:8A:01:05:82:02:38:00:8D:02:41:03:84:10:41:43:4F:53:50:4B:43:53:2D:31:35:76:31:2E:30:30:8C:08:7F:03:FF:00:01:01:01:01:AB:00
...truncated      <== There will be a clarification of CHV129's meaning: The USERPIN must be verified first, and that
                  <== the meaning of CHV1 in this directory still is: The SOPIN must be verified first
```

You'll probably also want [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init"), an optional library that supplements driver 'acos5_64' with some specific PKCS#15 related functionality (it's mandatory for [acos5_64_gui](https://github.com/carblue/acos5_64_gui "https://github.com/carblue/acos5_64_gui")).<br>

The third in the trio will be acos5_64_sm, an optional library that supplements driver 'acos5_64' with Secure Messaging support.

Detailed info about what is working is in https://github.com/carblue/acos5_64/tree/master/info/what_do_the_rust_implementations_driver_pkcs15init_sm_currently_support.

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
Therefore, the driver disallows duplicate file/dir id s and stops processing/panics (visible as SIGSEGV) once it detects duplicate existence.

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
What a pity! You payed money for something that doesn't give a damn about a PKCS#15 conforming file system! PKCS#15/ISO/IEC 7816-15 is an international standard that describes/organizes file system content of smart cards and a conformance required by OpenSC and thus this driver.<br>
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
