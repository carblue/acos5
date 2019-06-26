# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

Driver for ACS ACOS5-64 Smart Card/CryptoMate64/CryptoMate Nano; external module operating within the OpenSC framework (min. version 0.17.0).

https://github.com/OpenSC/OpenSC/wiki<br>
https://www.rust-lang.org/learn/get-started<br>
If Rust/cargo is not required anymore, uninstall with: rustup self uninstall

Look into build.rs first for some details about the libopensc binary (version etc.).<br>
The prerequisite required to be installed are evident: OpenSC packages (Ubuntu: opensc, which depends on opensc-pkcs11).<br>
Whether or not You intend to build the OpenSC binaries from sources, it's recommended to read the first 100 lines of [opensc-sys.lib.rs](https://github.com/carblue/opensc-sys/blob/master/src/lib.rs "https://github.com/carblue/opensc-sys/blob/master/src/lib.rs")<br>
The opensc-sys binding should be tested to be operational.

Compile as usual with Rust<br>
`user@host:~/path/to/acos5_64$ cargo build --release`<br>
`optionally user@host:~/path/to/acos5_64$ strip --strip-all target/release/libacos5_64.so`

The required opensc.conf entries:<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5_64/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5-64.<br>
The line "card_drivers = acos5_64, npa, internal;" is just an example for OpenSC version 0.17.0: It means: Just prepend<br>
acos5_64,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5-64 V2.00, it's possibly (any release version including 0.19.0, but not current git-master) also required to bypass the 'acos5' internal driver somehow, thus a painless start is by using<br>
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
        # module, the (/path/to/) filename of the driver library. /path/to/ is dispensable if it's in a 'standard library search path'
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


The driver has this peculiarity, which adds ~ 1 second to it's start-up time:<br>
It scans the card for duplicate file id s.<br>
While cos5 (card operating system of ACOS5-64) allows duplicate file id s (in differring DF s), that's a bad idea, as in rare scenarios, with cos5 "smart?" file search strategy You may end up operating on another of those duplicates than intended.
Also this could confuse tracking of currently selected file/dir position.
Therefore, the driver (in the near future) won't allow duplicate file/dir id s and stop processing/panics (visible as SIGSEGV) once it detects duplicate existance.

Also, the driver still has a lot of assert macros which shall catch - disregarding from code bugs - unexpected input (card content) as well. As violated assert s cause a panic as well, this isn't as user-friendly as it should be: Work in Progress to replace all assert macros regarding unexpected card content by user-friendly error handling/logging to opensc-debug.log.

What is unexpected card content ? Anything that OpenSC's code can't parse as valid PKCS#15 content/structure, e.g. non-OPTIONAL ASN.1 DER content. (that also is OpenSC version dependent, see ).<br>
Sadly OpenSC nowhere states, what is the PKCS#15 version it does support, and I don't possess any PKCS#15 standard that I would have to pay for in order to state it's this or that (if anybody considers a donation for this open source project, I would appreciate to receive any ISO/IEC 7816-15 standard document after :2004)<br>

The only way to know what OpenSC supports related to PKCS#15 is looking into the sources (it's spread over a couple of files, locate with grep -rnw sc_copy_asn1_entry and/or grep -rnw sc_format_asn1_entry) or alternatively look at [PKCS15.asn](https://github.com/carblue/acos5_64_gui/blob/master/source/PKCS15.asn "https://github.com/carblue/acos5_64_gui/blob/master/source/PKCS15.asn").<br>
That PKCS15.asn is based on a published ASN.1 module `pkcs-15v1_1.asn` tailored to what current OpenSC version 0.19.0, ACOS5-64 and [libtasn1](https://www.gnu.org/software/libtasn1 "https://www.gnu.org/software/libtasn1") support. libtasn1 doesn't support classes/parameters, thus some 'unrolling' was done in there. acos5_64_gui uses that PKCS15.asn in order to detect, what is the type of ASN.1 DER data in card files (e.g. EF.AODF or EF.PrKDF or EF.Cert or ...), whether it's PKCS#15-compliant and display/decode/encode. That works (at least for my card content).

<br><br><br>
PS: There is more to it if You like more details:<br>
Never before I worked on a topic where so much can (and did/does?) go wrong, there is almost no fault tolerance:<br>
Smart card software like this driver depends on a lot of other software, notably the code from OpenSC (and it's dependents like OpenSSL) and what I wrote myself AND <br>
it heavily depends on the smart card content, which MUST be PKCS#15 compliant.<br>
To cut a long story short: A single bit on the card currently may make the difference between success or failure in using this driver.

This is work in progress.

People who get here might have questions like:

I don't have ACS ACOS5-64 hardware, but do investigate to buy some. How about support?

I do have ACS ACOS5-64 hardware but no PKCS#11 library for that and do investigate to get/buy some. Is this repo's library something for me?

I do have ACS ACOS5-64 hardware and a PKCS#11 library for that and do investigate OpenSC support. Is this repo's library something for me?

TL;DR  There is no short answer for a complex topic, except: It depends, maybe this driver with current implementation state is all You need; maybe not, because some feature(s) that You require are still waiting to be implemented.

But first some introduction about what I understand by "support": A PKCS#11 library, the platform-independent API for smart card usage **is** PKCS#11.
Modern software communicates via a PKCS#11 library (or other higher level interface software) to cryptographic smart cards/usb tokens and that e.g. PKCS#11 library must
"understand"/know the specifics of the individual hardware. There is no generic one. The lower level PC/SC support for a hardware is required anyway, and a PKCS#11 library builds upon that.
So usually hardware suppliers offer a PKCS#11 library as well, ideally an open source one.<br>
Advanced Card Systems Ltd. (ACS) ACOS5-64 hardware doesn't come with an open source PKCS#11 library, even the proprietary one available for Windows(/MAC/Linux not officially but presumably on request: While I didn't get it for Linux when asking in 2014, meanwhile I know someone who got it) is not
downloadable for free, but included in their Client Kit software products, even worse, before this repo existed, users (very likely) were forced to buy a new Client Kit for every new card version.

On the other hand there is OpenSC, an initiative that i.a. implements an open source PKCS#11 library and that supports a bunch of different smart card hardware,
depending on for which a hardware-specific, so-called (internal) 'driver' does exist.
Sadly OpenSC currently has no ACOS5-64 support (ancient driver 'acos5' is not really usable and meanwhile has been removed from GitHub/master).
Also sadly, OpenSC code is poorly documented and it's a chronophage/extremely time-consuming (for me) to dive into relevant parts of ~150 TLOC and learn how things work together and how to integrate driver specifics.
Ranting done, OpenSC is smart open source code for smart cards, written, maintained and continuously advanced by experts.

In the beginning, as a novice, I started out writing an internal driver 'acos5_64' for OpenSC, but soon stopped that in favour of an external driver for OpenSC, for development speed reasons.

This repo is dedicated to such an external driver for OpenSC, supporting ACS ACOS5-64 hardware versions V2.00 and V3.00.<br>
The driver doesn't "see"/make any difference whether a smart card or usb token is connected, because they both include the same chip, but it handles (most of) the differences regarding versions V2.00 and V3.00.<br>
V2.00: Smart Card or Cryptographic USB token CryptoMate64<br>
V3.00: Smart Card or Cryptographic USB token CryptoMate Nano (reported by PC/SC as ACS CryptoMate (T2))<br>
The driver's focus is on the Operation Mode 64K (Non-FIPS) currently, one of the common to both versions V2.00 and V3.00 modes, and also Linux/Posix is a focus in that: If different OS handling is required, then
it will be first done for Posix, later for Windows (that's no issue currently).<br>
This is not my first implementation for ACOS5-64. Very old code is in v0.0.5, the recent 2 years of development with D lang unpublished, resulting in a driver that worked for me every day, but which is far from complete referring pkcs15init.
Now I'm learning Rust and have chosen driver 'acos5_64' for OpenSC as my hands-on project, putting in all knowledge gathered with opensc/crypto/ACOS5-64 and some new design decisions, writing the driver from scratch in Rust, and with the tool acos5_64_gui
in mind being a lot easier to implement, as well as being a lot easier to extract code for an internal driver 'acos5_64'.
But still this is not the most complicated, time consuming part; that still is OpenSC code. Thus I decided to first do an in-depth study of all related OpenSC code that might be useful and document that first, from a Rust-perspective (required anyway concerning unsafe Rust), such that
writing the driver needs much less OpenSC code inspection, using much more callable code.

Now answering possible reader's questions, the last 2 first:
Yes, this repo's library may be interesting for You.
It's state is WIP, work in progress, meaning, the driver doesn't yet support everything that ACS ACOS5-64 is capable of, but a reasonable subset is working (see directory info for details).
Among the things missing is card initialization, which is a problem for those with an empty/virgin card, and technically it's not the task of this library, but that of
repo [acos5_64_pkcs15init](https://github.com/carblue/acos5_64_pkcs15init "https://github.com/carblue/acos5_64_pkcs15init").<br>
Also missing is support of Secure Messaging. Don't expect this to come soon (not before everything else is completed. Most of the work is done already by figuring out what is correct/wrong in the reference manual and implemented in D language. And whether I'm going to publish that, depends on my further experience with consumers as well. Currently I think this is a dissatisfying one-way road).

Being an external driver for OpenSC has these important implications:
1. The feature of OpenSC to load external modules/libraries (during runtime) is a very nice one and comes with a split of functionality: OpenSC loads the mandatory 'driver' library and optionally other libraries:<br>
   a) driver is 'acos5_64', provided by this repo as libacos5_64.so/dll/dylib<br>
   b) pkcs15init for 'acos5_64'. This repo does exist, but doesn't supply much functionality currently, to be implemented when driver is close to completition. The functionality is dedicated to card initialization and among others generating new RSA key pair. Library's mere existance and configuration in opensc.conf is required for acos5_64_gui.<br>
   c) sm (Secure Messaging support) for 'acos5_64', provided by repo https://github.com/carblue/acos5_64_sm as libacos5_64_sm.so/dll/dylib.
      This repo doesn't yet exist and will be the last one to be implemented
2. There is repo https://github.com/carblue/opensc-sys. All of the former libraries depend on this binding to libopensc.so/dll transparently, but You should know these subtleties:
   The OpenSC versions supported by this binding are from (0.15.0) 0.17.0 up to the current 0.19.0<br>
   Not all functions covered by the binding actually are callable from libopensc.so/dll, be it version dependence or some are independent from version not callable at all:
   The binding covers that by private/public declarations or no declarations for such functions, thus technically OpenSC is supported since it's version 0.15.0, but
   practically for building a driver since 0.17.0 (a workaround for building a driver for 0.15.0/0.16.0 is to either patch OpenSC code's export and rebuild it or add missing functions to the driver code Yourself (file missing_exports.rs; IIRC the missing one is _sc_match_atr and everything about AES)
   The soname of libopensc depends on versions, thus all build.rs will link to libopensc.so/dll/dylib, which may have to be created as a symbolic link first.
   **It's highly recommended to consult that repo and test it's operational readiness, see next 3.**

3. The user should identify the OpenSC binary version installed on the system (e.g. run opensc-tool -i)
   and verify, that the installed version matches one that the binding does support
   //and must configure all software components of my repos targeting the installed OpenSC binary version
   *** automatic configuring of opensc binary ***
   Be aware, that when building a library (driver etc.), automatic configuring took place and therefore the driver etc. are bound to a specific OpenSC version.
   When the opensc/opensc-pkcs11 packages from OpenSC installed are changed/upgraded, then all external libraries like driver etc. must be rebuilt. First delete the target folders and Cargo.lock file and then rebuild.
4. The user must add a few entries to the OpenSC configuration file opensc.conf.<br>
   Each of the external libraries requires some entries.<br>
   One of the decisions with entries is: Where to place the libacos5_64* libraries. It's up to You whether to copy them to standard OS's .so/dll search path and save specifying the path component or
   e.g. specify the location where they sit after building them (the libraries don't require root privileges).

Contributions are welcome, possibly a common repo starting to convert the Rust code to an internal C code driver. If You are new to all that but know enough about Rust and C and interested in crypto, I think I can give a lot of guidance/mentoring if requested.

As far as I know, this repo is the only one existing, devoted to support ACOS5-64 via PKCS#11 in an open source manner.<br>
It's also devoted to support OpenSC, which implies the PKCS#15 compliance requirement.<br>
The only other currently available PKCS#11 implementation for ACOS5-64 - I know about - is from ACS, which doesn't seem to support  PKCS#15 compliance (at least I couldn't detect presence of all
required files or useful file contents for PKCS#15 compliance, after initializing my CryptoMate64 with ACS client kit).<br>
Setting up a FIPS compliant CryptoMate Nano: No success for me, having all required ACS software, all accessible documentation. I wonder if anybody else succeeded and I'm keen on knowing how to do that.
Thus I had to modify the file system manually based on the client kit initialization, retaining everything I deemed necessary to keep the ACS software continuing to work.

If You don't have ACS ACOS5-64 hardware, but do investigate to buy some. How about support?
If You don't want to rely on this repo (or when/which feature will be supported) then You depend solely on ACS proprietary software and let me say it this way:
Under these conditions I personally wouldn't buy ACS ACOS5-64 hardware as a single user:
When I compare the price of e.g. the CryptoMate Nano Client Kit software (1 CryptoMate Nano hardware included) to alternatives, then I'm better off with alternatives existing, that charge less, do support both RSA and ECC and are supported by OpenSC.
My decision was some years ago buying several CryptoMate64 + Client Kit for my company and a single special task only, thus the balance was different with almost no 4096 bit RSA alternatives at that time.
Probably I would decide differently today:
I would investigate about Elliptic-curve cryptography and possibly shift to ECC, not supported by ACOS5-64, and for sure, I never again would like to depend on ACS Client Kit software. That also is suggestive of being an SDK: The client kit definitely is no SDK (for old acos5 hardware there was an SDK product worth that name).<br>
The ACS Client Kit software isn't much more then the price You have to pay in order to get a OS-Windows PKCS#11 module for ACOS5-64 from ACS, closed source. See also [2015:first-steps-with-smartcards-under-linux](https://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works#comments "https://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works#comments"))

But this is my personal view, I'm strongly biased, as I got to know some dark corners of ACS ACOS5-64 (first and foremost relating to it's software), but I don't know any other crypto products and software and their possible dark corners.
For example, the crypto algorithms that ship with ACS ACOS5-64 internal card operating system: Almost unchanged since about 10 years (apart from introducing 192/256 bit for AES, and SHA-256), has AES and RSA up to 4096 bit, but the remaining is old-fashioned SHA1, DES
or nowadays less used SHA256 and 3DES.
What i heard about 3DES and can read here https://www.cryptomathic.com/news-events/blog/3des-is-officially-being-retired "According to draft guidance published by NIST on July 19, 2018, the Triple Data Encryption Algorithm (TDEA or 3DES) is officially being retired.
The guidelines propose that, after a period of public consultation, 3DES is deprecated for all new applications and usage is disallowed after 2023. ... The two-key variant of 3DES was retired in 2015".<br>
3DES is still the only algo usable for Secure Messaging with ACOS5-64. The implementation for the SM module does/will use the 3-key based 3DES (k1!=k3).
The card's signing command is almost useless, as it is bound to either SHA1 or SHA256 hashes, but e.g. Firefox or GitHub use SHA512 hashes to be signed. The driver code must revert
to the decrypt command to solve that, which is impossible if the key is generated with sign-only capability. Thus a security feature, being able to separate responsibility of RSA keys for either signing or decrypting
(but not both) is almost thwarted, at least for signing keys, that must handle modern hash functions and when You can't control which one. Also, for block cipher CBC deciphering, the driver must compensate for a cos5 bug (for V2, not yet tested for V.3), which boils down to a slow-down in deciphering.
Good news is that my tests of the internal cos5 crypto library didn't show a ROCA vulnerability.

Another negative point is: V2.00 isn't sold anymore (officially by ACS, but still in stock of resellers), but it's remarkably faster than the successor V3.00.<br>
V2.00 is able to generate RSA keys 4096 bit, while the same with V3.00 (op mode 64K) never succeeded (ACS told me to 'get' the Client Kit v4.5,
initialize with that and then it should work: No it didn't, I never was able to generate a key larger than 3328 bit with V3.00, but occasionally the generate 4096 bit key malfunction shuffled some bytes and bad things happened:
I was glad to be able to reinitialize the token, but in the end, the generate 4096 bit key malfunction byte shuffling caused my token to be lost, because irreversibly disallowing card's reinitialization).
Successor V3.00 comes with slightly expanded functionality, one of which should be: Encrypted Pin verification: I never succeeded with that. It should have been done by Client Kit's initialization, that the created application directory is set to force
Secure Messaging when doing pin verification. No it didn't, thus I should remove the app DF and repeat DF creation manually? No, I didn't dare any faults here and possibly exclude myself from my last token left.
And what is the value of FIPS, when the reference manual is either vague or wrongly explaining how to put a card's file system to FIPS compliance, such that a person like me who studied the reference manual extensively, is unable to succeed?
And believe me, I don't forfeit quickly. Maybe, once I'll contact ACS what's the meaning of undocumented error code 6F59. For the time being, I lost interest in FIPS compliance verification, while the rules of FIPS definitely make sense.<br>
If Your choice is between V2/CryptoMate64 and V3/CryptoMate Nano, then I would prefer V2.<br>
What makes ACOS5-64 interesting IMO is it's low hardware price e.g. ~18€/CryptoMate64_or_CryptoMateNano USB token +VAT +shipping cost combined with an open source driver for OpenSC like this one.

I'm fascinated by smart card crypto chips: You have a mini-computer at hand: It has an Operating System and some crypto library, some kBytes of EEPROM for a file system. It's about protecting Your credentials/private keys and if You care for that,
I propose to know, what the driver is doing on Your behalf by at least requesting the reference manual for Your hardware (in this case from info@acs.com.hk, it's/should be free of charge), possibly before a purchase.
If You arn't a developer, You won't read much of it, but get a far better impression of Your options than from any other ACS marketing flyer. If You don't get it, my recommendation is: Don't buy.
