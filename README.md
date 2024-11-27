Help wanted from users of an EVO card or CryptoMate EVO:
As I stated several times, my hardware, a CryptoMate EVO cryptographic USB Token seems to be buggy, or the underlying software: Recurrent it stops to work, seems to need a reset?
Reports from EVO users might help to isolate the problem.


# acos5  
[![Build Status](https://travis-ci.org/carblue/acos5.svg?branch=master)](https://travis-ci.org/carblue/acos5)

Driver for Advanced Card Systems (ACS)  ACOS5 Smart Card<br>
  V2.00 ([CryptoMate64](https://www.acs.com.hk/en/products/18/cryptomate64-usb-cryptographic-tokens/ " https://www.acs.com.hk/en/products/18/cryptomate64-usb-cryptographic-tokens/"))<br>
  V3.00 ([CryptoMate Nano (T2)](https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens/ "https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens/")),<br>
  V4.X0 EVO ([CryptoMate EVO](https://www.acs.com.hk/en/products/494/cryptomate-evo-cryptographic-usb-tokens/ "https://www.acs.com.hk/en/products/494/cryptomate-evo-cryptographic-usb-tokens/"))<br>
as external modules, operating within the [OpenSC](https://github.com/OpenSC/OpenSC/wiki "https://github.com/OpenSC/OpenSC/wiki") smartcard software framework (versions supported: 0.20.0 - 0.26.0).


Motivation:
For OS/platform-independent, serious use of a cryptographic hardware/token from software like Firefox, Thunderbird, ssh etc., a [PKCS#11](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11 "https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11") implementing library is required.
There is none known to me for ACOS5 that is open-source, nothing in this regard downloadable from ACS for free, instead, one has to pay a lot more for a proprietary ACS PKCS#11 library (bundled with some other software) than for a single hardware token. They even have a proprietary ACS PKCS#11 library for Linux, but don't advertise that, and probably it also needs to be paid.

The only open-source software downloadable from ACS is [acsccid](https://github.com/acshk/acsccid "https://github.com/acshk/acsccid"), a PC/SC driver for Linux/Mac OS X. PC/SC or WinSCard (Windows) is just the basic layer on which a PKCS#11 implementing library can build upon. I never installed acsccid for production use of my CryptoMate64 and CryptoMate Nano, hence the debian/ubuntu-supplied [ccid](https://ccid.apdu.fr/ "https://ccid.apdu.fr/") seems to be sufficient (if it's new enough to list those cards as supported ones: [shouldwork](https://ccid.apdu.fr/ccid/shouldwork.html "https://ccid.apdu.fr/ccid/shouldwork.html")).
So be careful what You get from ACS when it's called driver. Perhaps You get something that is behind the "File Upon Request" barrier.

[OpenSC](https://github.com/OpenSC/OpenSC/wiki "https://github.com/OpenSC/OpenSC/wiki") supplies i.a. a PKCS#11 implementing open-source library (onepin-opensc-pkcs11.so/opensc-pkcs11.so) if it get's augmented by a hardware specific driver, which is missing currently for ACOS5 smart cards in OpenSC v0.26.0, and the one available in previous versions was rudimentary/incomplete; hence excluded for good reasons.

With this repo's components 'acos5' and 'acos5_pkcs15' as plug-ins, OpenSC now supports some ACOS5 hardware as well. (Fortunately OpenSC allows such plug-ins as - in OpenSC lingo - external modules/shared libraries/DLL).
External modules need some configuration once in opensc.conf, such that they get 'registered' and used by OpenSC software, explained below.

For some reason (that I don't recall now) I didn't decide for [openCryptoki](https://www.ibm.com/docs/en/linux-on-systems?topic=stack-opencryptoki-overview "https://www.ibm.com/docs/en/linux-on-systems?topic=stack-opencryptoki-overview") (which also consists of an implementation of the PKCS #11 API), but it looks like it would have been an eligible alternative for me to implement ACOS5 hardware specific stuff for an open-source PKCS#11 library [github/opencryptoki](https://github.com/opencryptoki/opencryptoki "https://github.com/opencryptoki/opencryptoki").


Support for the EVO chip is given partially, work in progress to be completed. By default, this hardware is operated in protocol T=1 (different from the other supported hardware, T=0). OpenSC wants to handle the APDU case 'SC_APDU_CASE_4_SHORT' differently for T=0/T=1 protocols, but that's not how the ACOS5 EVO behaves. Thus, currently, for the EVO card only, patching OpenSC source code is required (use file diff_apdu_c.txt) like that:<br>

user@host:~/path/to/opensc-0.26.0$ patch -b src/libopensc/apdu.c diff_apdu_c.txt

The respective reference manual for Your hardware is available on request from: info@acs.com.hk

Platforms supported: Those that the Rust compiler targets: [rustc platform-support](https://doc.rust-lang.org/nightly/rustc/platform-support.html "https://doc.rust-lang.org/nightly/rustc/platform-support.html").
Platforms tested: Those that I use:  
Linux/Kubuntu 24.04 LTS (extensively tested, everything implemented works as expected),
Windows 11 (sparsely tested and questionable: my opensc.dll doesn't show any dependency on OpenSSL; the driver seems to be blocking when it needs to access files opensc.conf or .profile files, thus anything related doesn't work currently: Secure Messaging (SM) and everything that needs acos5_pkcs15.dll: e.g. main_RW_create_key_pair doesn't work; all the remaining read-only operations seem to work as expected. Seems to be a privileges/access right issue. Note that, for the time being, after all this annoying, time consuming hassle with Windows, I don't plan to let this build participate in the goodies that libtasn1 will allow i.a. for sanity-check).

In the future, I'll test only Linux and the latest OpenSC version supported, which is 0.26.0 currently. It's advised to install that OpenSC version.
Also, testing will be limited to 1 hardware version, which is CryptoMate64 currently.

Release tags get added irregularly, mainly i.o. to refer to something from `acos5_gui` (as a minimum driver release requirement). In any case, master's HEAD has the best driver code for You.


Prerequisite installations  
Mandatory:  
- Rust compiler rustc and cargo build manager (it's bundled) from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install")  
- OpenSC  (requires OpenSSL, the driver will use that as well; *nix OS: requires pcscd and libpcsclite1 and libccid)  
- [Libtasn1](https://www.gnu.org/software/libtasn1/ "https://www.gnu.org/software/libtasn1/") only for non-Windows (*nix) OS  

Recommended:  
- [pcsc-tools](http://ludovic.rousseau.free.fr/softwares/pcsc-tools/ "http://ludovic.rousseau.free.fr/softwares/pcsc-tools/"), provides `scriptor` for card initialization as a batch run of commands, see [info/card_initialization/README.md](https://github.com/carblue/acos5/blob/master/info/card_initialization/README.md "https://github.com/carblue/acos5/blob/master/info/card_initialization/README.md")<br>
`gscriptor` is nice in order to communicate with Your crypto hardware without any PKCS#11 software, i.e. only PC/SC layer (on byte level, and definitely not without the reference manual)
```
$ sudo apt-get update
$ sudo apt-get upgrade
$ sudo apt-get install opensc opensc-pkcs11 openssl libssl-dev libtasn1-6-dev pcscd build-essential pcsc-tools
```
**If that doesn't install a symbolic link libopensc.so, then this must be done manually, followed by a sudo ldconfig. See also file travis.yml**

Optional:  
- [IUP](https://webserver2.tecgraf.puc-rio.br/iup/en/download.html "https://webserver2.tecgraf.puc-rio.br/iup/en/download.html") from [pre-build binaries](https://sourceforge.net/projects/iup/files/ "https://sourceforge.net/projects/iup/files/") in ...Libraries sub-folder   

The driver may be "configured" to include code for: User consent to use an RSA private key: A dialog window (provided by IUP)
pops up every time when an RSA private key is requested to be used for sign, decrypt, unwrap. I recommend to use this feature for enhanced security, more in file   [conditional_compile_options](https://github.com/carblue/acos5/tree/master/conditional_compile_options.md "https://github.com/carblue/acos5/tree/master/conditional_compile_options.md"), referring to 'iup_user_consent'.
It's just not mandatory due to the required additional installation, required editing of acos5_external/acos5/build.rs and editing opensc.conf: iup_user_consent_enabled = yes; the latter allows to have that feature compiled in, but disable it temporarily e.g. for pkcs11-tool --test  where it would be tedious to approve each single RSA key usage. The pre-built IUP binaries are easy to install on Linux via sudo ./install (check for all dependencies satisfied with ldd libiup.so), or as usual, compile from sources.

This repo builds 2 dll/shared object libraries:  
- libacos5.so/dylib/dll, which is a mandatory one, the driver in the narrow sense, and
- libacos5_pkcs15.so/dylib/dll, which is theoretically optional, but very likely required if the token isn't used read-only; e.g. storing/generating keys on-card requires this.  
In the following I won't make any distinction anymore and call both 'the driver' for ACOS5.

This repo also builds a library from the included opensc-sys binding for internal use. It's the basic building block for the driver components in order to be able to call into the libopensc.so/.dll library, the backbone/workhorse of OpenSC.  
There is also a complete binding included towards libtasn1 and a binding to a small subset of OpenSSL functions used.  
The minimal OpenSC version supported is 0.20.0 now. Former support of 0.17.0 - 0.19.0 was dropped.

All these builds will be tied to the OpenSC version installed on Your pc, so that installation must be done first. Then, for all 3 builds there are files build.rs which get processed prior to the remaining build and control how that will be done (conditional compilation, see [conditional_compile_options](https://github.com/carblue/acos5/tree/master/conditional_compile_options.md "https://github.com/carblue/acos5/tree/master/conditional_compile_options.md")). The first one will detect the OpenSC version installed, adapt the opensc_sys binding to that version and pass the version info to the other builds.
Upon loading external modules, OpenSC will check, that driver's version matches the one of the installed OpenSC version, rejecting the external modules in case of version mismatch.  
OpenSC also has the implication: If Your card got initialized by an ACS tool and is not [PKCS#15](https://stackoverflow.com/questions/33792095/what-does-it-mean-for-a-smart-card-to-be-pkcs15-compatible "https://stackoverflow.com/questions/33792095/what-does-it-mean-for-a-smart-card-to-be-pkcs15-compatible") compliant (this is true for all that I've run into), then it won't work (well) with OpenSC and likely requires card's re-initialization, see [card_initialization README](https://github.com/carblue/acos5/tree/master/info/card_initialization "https://github.com/carblue/acos5/tree/master/info/card_initialization"))  


IMPORTANT behavior  
There is a huge number of "limits" and "rules" that apply, many originate from standards like PKCS#15 or OpenSC, others from this driver, far more than I'm willing to describe expressly other than in code (and I hope having covered all by checks).
Common usage won't exceed these limits and the driver will "just work". E.g. probably You won't have a file in Your file system that will be addressed by such a long 18-byte path, e.g.
0x3F00_4100_4200_4300_4400_4500_4600_4700_4710  
An 18-byte path length won't work, as OpenSC data structures are limited to a path length of 16 bytes.  
File ids 0x5000 - 0x5FFF are reserved for the driver and PKCS#15 files 0x5031, 0x5032 and 0x5033. The driver will place generated RSA files (in case of EVO also ECC files) into this range of file ids and will delete - if necessary - any other types of files in this range of file ids (and even RSA files that are not listed in PrKDF/PuKDF).
And a driver rule to name explicitly: In case of manually adding (e.g. with tool `gscriptor`) records to 'PIN file', 'Symmetric Key file' or 'Security Environment file': These are record-based file types, i.e. content gets addressed by a record no. **and** store inside that record an ID (of pin, sym. key or SE condition): Record no. and ID always must be the same ! This can be checked only for readable files, and 'PIN file' / 'Symmetric Key file' never are readable.
If a manually added 'Symmetric Key' (e.g. by using `gscriptor` or `scriptor`) is not listed in SKDF, then it does not exist for OpenSC/driver and the record/key will be overwritten next time a 'key store' or 'unwrap' operation occurs !

So this is the point: It would be graceful to react upon limits/rules violations with error returns and respective error messages in opensc-debug.log, but all too often the driver isn't yet that polite and just deliberately aborts ("panic" in Rust lingo, due to an assert violation).
So, if anybody wants to contribute, removing these rough edges is an easy way to start.  
And if the driver is "impolite" currently, it's most likely something about card content, that is different from expected according to PKCS#15 / ISO/IEC 7816-15 / OpenSC. It's tough for outsiders to spot from OpenSC code: What is the exact requirement for ASN.1 content of PKCS#15 files. Maybe it's easier to read from [PKCS15.asn](https://github.com/carblue/acos5_gui/blob/master/source/PKCS15.asn "https://github.com/carblue/acos5_gui/blob/master/source/PKCS15.asn"), which is specifically crafted/modified from a module pkcs-15v1_1.asn found by a web search, for compatibility with OpenSC, libtasn1 and ACOS5. It's also internally used by the driver in non-Windows builds.

Akin to the www with it's broken links phenomenon, that may happen with a smart card as well: A lot in PKCS#15 and ACOS5 depends on "pointing to", and that may easily be broken by software bugs or ?. Thus I plan to integrate detection code for this kind of card content errors and more, for '$ pkcs15-init --sanity-check'
Thus a sanity-check without any errors found should prevent the driver from becoming "impolite" or reporting errors. [Work in progress]

## Steps towards driver binary builds and setup

1. Prerequisite installations are done, optionally read   [conditional_compile_options](https://github.com/carblue/acos5/tree/master/conditional_compile_options.md "https://github.com/carblue/acos5/tree/master/conditional_compile_options.md").  
   If Your OS is different from debian/Ubuntu, then I recommend to inspect all 3 build.rs files once (in folders acos5, acos5_pkcs15 and opensc-sys), whether the lines starting with `println!("cargo:rustc-link` are correct: Maybe for other OS the library names might differ or the path specified there. If libraries aren't located in linkers 'standard' directory search list, then lines println!("cargo:rustc-link-search=native=path"); might need to be added and path adapted.
   
   and then build the driver acos5:  
   `user@host:~/path/to/acos5_root_downloaded$  cargo build --release`. The 2 shared object binaries will be built into directory target/release  
   Towards OpenSC, the driver's name is `acos5_external`, in order to make it distinguishable from a quite useless acos5 internal driver, that existed in OpenSC throughout until version 0.19.0

2. Copy acos5_pkcs15/acos5_external.profile to the directory where all the other .profile files installed by OpenSC are located, for Linux probably in /usr/share/opensc/ or /usr/local/share/opensc/, for Windows something like C:/Program Files/OpenSC Project/OpenSC/profiles.  

3. Adapt opensc.conf (see below). Also, in the beginning, switch on logging by a setting `debug=3;` and for debug_file set the file name receiving the logging output.  
   If all the above went well, the log file will have an entry within it's first 5 lines, reporting: "load_dynamic_driver: successfully loaded card driver 'acos5_external'".  
   Check that by issuing (in a shell; $ is the Linux shell prompt for a user without admin rights, not part of the command): `$ opensc-tool --info`  
   The last command should have successfully loaded card driver 'acos5_external', but it didn't yet use it. The next will do so (and also check for disallowed duplicate file ids):  
   `$ opensc-tool --serial`
4. In case build errors or other errors occur:
   You have a copy of the opensc-sys binding on Your system in directory opensc-sys.  
   If there are build errors, then issue
   `$ cargo test test_struct_sizeof -- --nocapture`  
   Likely that fails then, and an error reason is found by asking why didn't that find the library libopensc.so or does the version reported differ, or ?, or as the worst case:  
   OpenSC was built with different settings/switches than the binding requires/assumes.  
   Other errors occur: Likely the opensc.conf file is incorrect.  
   Otherwise file an issue.
5. Documentation
   I have resumed my efforts to let the 'rustdoc' tool produce good documentation. Also out of my own interest, especially with regard to the 'opensc-sys' binding:
   That is poorly documented by OpenSC.
   I hope, the doc helps understanding what goes on in driver's source code.
   Build it, if You like:<br>
   `user@host:~/path/to/acos5_root_downloaded$  cargo doc --open --document-private-items`  
   The doc will be built into directory target/doc/acos5, file index.html

When You change/update Your OpenSC installation: Only step 1 (and 5: rebuilding the driver, adapted to the new version und it's documentation) needs to be redone, and as I don't know whether Rust's rerun feature is reliable, I first delete folder target and file Cargo.lock, then (re-)build the driver.

The required opensc.conf entries:  
The location of opensc.conf on Linux: /etc/opensc/opensc.conf.  
The location of opensc.conf on Windows: C:\Program Files\OpenSC Project\OpenSC\opensc.conf.  
Since recently, OpenSC installs a very short opensc.conf. The long version (that I'm using and referring to here) is in github's/tarball's etc/opensc.conf.example.in  
......... just denotes, there is/might be other opensc.conf content before this line  
Content within ... (excluded) must be adapted (/something/like/path/to/acos5/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5.  
The line "card_drivers = acos5_external, npa, internal;" is just an example from OpenSC version 0.17.0 opensc.conf: It means: Just prepend  
acos5_external,  
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.  


```
app default {
.........
	#debug = 3;                          # optionally remove the leading # for temporary log output; driver's log is available with debug = 3 (or 6); meaning of the number: look at https://github.com/carblue/acos5/blob/master/opensc-sys/src/log.rs
	#debug_file = /tmp/opensc-debug.log; # optionally remove the leading # for temporary log output and terminate debug_file=value with a semicolon ;  possibly path adaption required !
.........
	# card_driver customcos {
	# The location of the driver library
	# module = /usr/lib/x86_64-linux-gnu/libcard_customcos.so;
	# }
...
	card_driver acos5_external {
		# module, the (/path/to/) filename of the driver library .so/.dll/.dylib. /path/to/ is dispensable if filename is in a 'standard library search path'
		module = /something/like/path/to/acos5/target/release/libacos5.so;

		# "user-consent": Override disable / enable IUP GUI enquiry dialog window when performing an RSA signature, unwrap or decrypt operation with ACOS5.
		# When the iup dialog/popup window is shown: Answer with NO in order to decline the RSA key usage; YES or closing the window [X] means accepting RSA key usage
		# iup_user_consent_enabled value:  anything starting with letter t or y (case-insensitive) get's interpreted as true/yes, otherwise false/no
		iup_user_consent_enabled = yes; # in order for true/yes to take effect: Needs compiler switch --cfg iup_user_consent and IUP installed (lib.iup.so/iup.dll)        

		# secure messaging settings:
		ifd_serial = "11:22:33:44:55:66:77:88"; # changing this "match all" default value to Your actual hardware serialnr (8 bytes, for ACOS5 V2.00 append zero bytes) needs compiler switch --cfg ifd_serial_constrained_for_sm
		keyset_41434F53504B43532D313576312E3030_02_mac = "F1:E0:D0:C1:B0:A1:89:08:07:16:45:04:13:02:01:F1:89:FE:B3:C8:37:45:16:94"; # corresponds to record# 1/key_reference 0x81 (external auth. key host kh in EF 0x4102); this will be authenticated
		keyset_41434F53504B43532D313576312E3030_02_enc = "F1:01:02:13:04:85:16:07:08:49:A1:B0:C1:D0:E0:F1:45:89:B3:16:FE:94:37:C8"; # corresponds to record# 2/key_reference 0x82 (internal auth. key card kc in EF 0x4102)
	}
...
.........
	#card_drivers = npa, internal;
...
	card_drivers = acos5_external, npa, internal; # for a painless start use  card_drivers = acos5_external, default;
...
.........
	# PKCS #15
	framework pkcs15 {
.........
		# emulate custom {
		# The location of the driver library
		# module = /usr/lib/x86_64-linux-gnu/libp15emu_custom.so;
		# }
...
		pkcs15init acos5_external {
			# The location of the pkcs15init library that supplements driver 'acos5': /path/to/libacos5_pkcs15.so/dll/dylib;
			# /path/to/ may be omitted, if it's located in a standard library search path of the OS
			module = /something/like/path/to/acos5/target/release/libacos5_pkcs15.so;
		}
...
	}
}
```

When You're ready with Your personalized opensc.conf: Keep a backup, as some OpenSC-installers just overwrite without asking!

### Appetizer: Using SSH with keys from Your cryptographic smart card/USB token with GitHub  
Its assumed You have a local git repository, and want to push to Your or other's remote repository hosted at github,
and haven’t yet done that via SSH.  
Also, to be explicit, its assumed You don't yet have an RSA keypair for authentication with GitHub,
so let's create that first:  
I like the max. modulus bit length that my CryptoMate64 allows: 4096 bit, and use the 'standard' public exponent 0x10001.
We need to specify some more info for PKCS#15: The key pair will have the (new unique, hex.) iD 01, be protected by authId 01
(i.e. there is an authentication object defined in my EF.AODF with iD 01; in my case it refers to the user pin, that must be verified before RSA
private key usage gets allowed for cryptographic operations, or key file allowed to be updated; reading of the newly created private key file will 
never be allowed, but be allowed without any constraint for the public key file).
The key pair will be labeled  github_key.
This is a complex operation, as observable in the opensc-debug.log file, if that's enabled in opensc.conf, and it may take several minutes to complete.  
Note, that there will be 2 calls load_dynamic_driver:   
successfully loaded card driver 'acos5_external'   
successfully loaded pkcs15init driver 'acos5_external'   
and 2 sc_profile_load:   
profile /usr/share/opensc/pkcs15.profile loaded ok   
profile /usr/share/opensc/acos5_external.profile loaded ok

```
$ pkcs15-init --generate-key rsa/4096 --auth-id 01 --id 01 --label github_key --key-usage sign
Using reader with a card: ACS CryptoMate64 00 00
optionally printed: This file id will be chosen for the private RSA key:  5000
optionally printed: This file id will be chosen for the public  RSA key:  5001
User PIN [User] required.
Please enter User PIN [User]: 
$

Let's visualize what OpenSC appended to our EF.PrKDF file:

name: privateRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: github_key
    name: flags  type: BIT_STR  value(2): c0  ->  11
    name: authId  type: OCT_STR  value: 01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: 01
    name: usage  type: BIT_STR  value(4): 30  ->  0011
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): b8  ->  10111
    name: keyReference  type: INTEGER  value: 0x00
  name: privateRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f0041005000
    name: modulusLength  type: INTEGER  value: 0x1000
    
and appended to our EF.PuKDF file:

name: publicRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: github_key
    name: flags  type: BIT_STR  value(2): 40  ->  01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: 01
    name: usage  type: BIT_STR  value(8): 03  ->  00000011
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): 48  ->  01001
    name: keyReference  type: INTEGER  value: 0x00
  name: publicRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f0041005001
    name: modulusLength  type: INTEGER  value: 0x1000


```
So, everything is okay with those entries, though OpenSC did include the optional keyReference field with invalid value 0:
It is irrelevant for the ACOS5 card, which references RSA keys by file id/path.

We need a representation of our github_key (the public part of the key pair), that we will present to/store at GitHub:
```
$ pkcs15-tool --read-ssh-key 01
Using reader with a card: ACS CryptoMate64 00 00
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCHaxU2k3N0IFepLCbpSisoTEeUpGAx1UD7ENYis1wzrR5v3qvrkVhleoDQZnQWAAhu66bGm35Cyz8QnWN5MTtVqtgdeEQbR55EJI57ODw3LAN+z7S7OzQX42phigTCyKPlBcpfXygmJyeWDv33YpUFXDoxo874dwvyVX39sIgY+RZwqzoGF6UwX2cRDgGuPMtM2DmGbr27BVAVGP4rDBlxACJtsbknQYiR9jwdrIQg40P/0JSKFtvxnDIW8QPgY6CRC09FcwKaXZ+rFnp78rHHdP7Kik5g4e2jeduQfaVD8Wp4jZpiEEJElXBoyjKG1x0eF9Z+U2GR8kfqVDtftKgro4YrjO+qYRKsEOZ87fzlSjqF5e1iqJt9hp2lAphb3ge6WwUgPyPt4ckswlmGufPhlfbx2AXRlmXnF4S3Mex1bBIU7ydosZ1FcBF5Wh7+ySIYHkfi1AX2/jCAxEmDnPpL+I7slMJJBO9moQK7gzFBEDysZXbzdVRAQPNzQFFBw+FiZHApExHeLie3Z/cZSKsE+rpu9aza7DVA3ztIswmTkGng4MfzvLdskkMSTipJjzLJSlPIHsxWf5dx1Eqznjc7r3zICCpRLvVi0tiY6IfapWW20ShPCO3Anf1oOtaPctkTl/Y+Hp6o/eNPeoQ89b1kJyQ2XCfTgK1vJyg1QPXzOw== github_key
```
If You don't have a GitHub account, get one for free (for public repos): [GitHub](https://github.com/ "https://github.com/")   
Sign into GitHub, 
in the upper-right corner of any page, click your profile photo, then click Settings / SSH and GPG keys  
click New SSH key and copy/paste Your key content.  

Then test whether You "could" establish an ssh connection with Your github_key:  
```
$ ssh -T -I/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so  git@github.com
```
On success, GitHub will reply:<br>
Hi your_github_user_name! You've successfully authenticated, but GitHub does not provide shell access.

With this ssh config file I can even abbreviate:<br>
$ cat ~/.ssh/config<br>
#PKCS11Provider /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so<br>
PKCS11Provider /usr/lib/x86_64-linux-gnu/libp11-kit.so<br>

It reveals, that I've p11-kit installed (and configured), which actually points to opensc-pkcs11.so (in lack of a proprietary libacospkcs11.so - which knows how to handle ACOS5 hardware as well - it wouldn't work for ACOS5 hardware otherwise).

$ ssh -T git@github.com

If You like to push from current local git repo  to github via being authenticated by Your github_key: [changing-a-remotes-url](https://docs.github.com/en/free-pro-team@latest/github/using-git/changing-a-remotes-url "https://docs.github.com/en/free-pro-team@latest/github/using-git/changing-a-remotes-url")

Recommended info:  
[Linux and smart cards for PKI - Overview](http://cedric.dufour.name/blah/IT/SmartCardsOverview.html "http://cedric.dufour.name/blah/IT/SmartCardsOverview.html")  
[Linux and smart cards (OpenSC) - How-to](http://cedric.dufour.name/blah/IT/SmartCardsHowto.html "http://cedric.dufour.name/blah/IT/SmartCardsHowto.html")  
[OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/ "https://jamielinux.com/docs/openssl-certificate-authority/") with adaptions from info/howto/HOWTO_Create_Your_own_CA_root_hierarchy_on_Linux

< not yet:[changelog.md](https://github.com/carblue/acos5/tree/master/changelog.md "https://github.com/carblue/acos5/tree/master/changelog.md"): Recent commits (notable ones that deserve some verbosity) >


In it's card header block there is a byte at EEPROM address 0xC191 called "Compatibility Byte" or "Operation Mode Byte" or "Configuration Mode Byte". It may be changed only as long as the card is virgin.
This driver is usable/defined only for specific "Compatibility Byte" settings, not for any arbitrary setting:

ACOS5 Smart Card V2.00 (CryptoMate64): Only the default byte setting 0x00 is supported, which is the ordinary ACOS5-64 mode. Any other byte setting would trigger the ACOS5-32 backward compatibility mode, which is *NOT* supported. There is no software function to query the byte setting, thus it's the users responsibility to make sure, that value zero is set!


ACOS5 Smart Card V3.00 (CryptoMate Nano): Only the non-default byte setting 0x02 (64K Mode) is safely supported. The "Emulated 32K Mode" (byte setting 0x01) is *NOT* supported. Whether this software works for the "NSH-1 Mode": I don't know, the reference manual tells absolutely nothing about that mode (and what is different/characteristic). Again for the "FIPS 140-2 Level 3–Compliant Mode": The reference manual is unable to instruct exactly, how to fulfill all the requirements for FIPS mode: The card supports a command "Verify FIPS Compliance". It returns 0x9000, if the card file system and settings are FIPS140-2 Level 3 compliant. I never succeeded to receive a success return !! Thus I couldn't test for a statement of support for this mode: You are at Your own risk in this mode.

ACOS5 Smart Card V4.X0 EVO (CryptoMate EVO): Only the default byte setting 0x01 is supported, because the only other mode, "FIPS 140-2 Level 3" wasn't yet tested.

Currently, the above statement "This driver is usable/defined only for specific "Compatibility Byte" settings"
is enforced in a way that excludes the "Emulated 32K Mode" for ACOS5 Smart Card V3.00 and V4.X0 EVO.
Those hardware versions support a function to query the byte setting.
