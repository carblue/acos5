# Build state

[![Build Status](https://travis-ci.org/carblue/acos5.svg?branch=master)](https://travis-ci.org/carblue/acos5)

# acos5

Driver for Advanced Card Systems (ACS)  ACOS5 Smart Card V2.00 and V3.00 / CryptoMate64 (V2.00) / CryptoMate Nano (V3.00), as external modules operating within the OpenSC framework.<br>
Platforns supported: Those that the Rust compiler targets (https://doc.rust-lang.org/nightly/rustc/platform-support.html).

Motivation:<br>
For platform-independent, serious use of a cryptographic token from software like Firefox, Thunderbird, ssh etc., a [PKCS#11](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11 "https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11") implementing library is required.<br>
There is none known to me for ACOS5 that is open-source, nothing in this regard downloadable from ACS for free, instead, one has to pay a lot more for a proprietary ACS PKCS#11 library (bundled with some other software) than for a single hardware token.<br>
The only open-source software downloadable from ACS is [acsccid](https://github.com/acshk/acsccid "https://github.com/acshk/acsccid"), a PC/SC driver for Linux/Mac OS X. PC/SC or WinSCard (Windows) is just the basic layer on which a PKCS#11 library can build upon. I never installed acsccid for production use of my CryptoMate64 and CryptoMate Nano, hence the debian/Ubuntu-supplied [ccid](https://ccid.apdu.fr/ "https://ccid.apdu.fr/") seems to be sufficient (if it's new enough to list those cards as supported ones).<br>
So be careful what You get from ACS when it's called driver. Perhaps You get something that is behind the "File Upon Request" barrier.

[OpenSC](https://github.com/OpenSC/OpenSC/wiki "https://github.com/OpenSC/OpenSC/wiki") supplies i.a. a PKCS#11 implementing open-source library if it get's augmented by a hardware specific driver, which is missing currently for ACOS5 in OpenSC v0.20.0, and the one available in earlier versions was rudimentary/incomplete.

With this repo's components 'acos5' and 'acos5_pkcs15' as plug-ins, OpenSC supports some ACOS5 hardware as well. (Fortunately OpenSC allows such plug-ins as - in OpenSC lingo - external modules/shared libraries/DLL).<br>
External modules need some configuration once in opensc.conf, such that they get 'registered' and used by OpenSC software, explained below.

Prerequisite installations<br>
There are mandatory and an optional one:<br>
Mandatory:<br>
- Rust compiler rustc and cargo build manager (it's bundled) from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install") <br>
- OpenSC  (requires OpenSSL, the driver will use that as well; *nix: requires libpcsclite1) <br>
- Libtasn1 https://www.gnu.org/software/libtasn1/

Recommended:<br>
- pcsc-tools from http://ludovic.rousseau.free.fr/softwares/pcsc-tools/, provides scriptor for card initialization, see info/
```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install opensc opensc-pkcs11 libtasn1-6-dev pcsc-tools
```
If that doesn't install a symbolic link libopensc.so, then this must be done manually

Optional:<br>
- IUP from https://webserver2.tecgraf.puc-rio.br/iup/en/download.html <br>
The driver may be "configured" to include code for:

This repo builds 2 dll/shared object libraries:<br>
- libacos5.so/dylib/dll, which is a mandatory one, the driver in the narrow sense, and
- libacos5_pkcs15.so/dylib/dll, which is theoretically optional, but very likely required when the token isn't used read-only; e.g. storing keys on-card requires this.<br>
In the following I won't make any distinction anymore and call both 'the driver' for ACOS5.

This repo also builds a library from the included opensc-sys binding for internal use. It's the basic building block for the driver components such that they are able to call into the libopensc library.

All these builds will be tied to the OpenSC version installed, so this must be done first. Then, for all 3 builds there are files build.rs which get processed prior to the remaining build and control how that will be done. It's the location, where 


External module, in this context means: You also have to "tell opensc.conf some details", such that OpenSC can find the driver library, knows about it's name and can load it as a known driver.
External module also has the implication, that OpenSC calls up to 2(3) different libraries (depending on opensc.conf configuration and functionality required): Into the mandatory driver library, into an optional pkcs15init library acos5_pkcs15 and into an optional acos5-specific 'Secure Messaging' (SM) library (which does not exist though for ACOS5, as the 'Secure Messaging' support is integrated into the mandatory driver library).<br>
The driver builds are bound to one specific OpenSC version and upon loading the external modules, OpenSC will check, that this version matches the one of the installed OpenSC version, rejecting the external modules in case of mismatch.<br>
OpenSC also has the implication: If Your card got initialized by an ACS tool and is not [PKCS#15](https://stackoverflow.com/questions/33792095/what-does-it-mean-for-a-smart-card-to-be-pkcs15-compatible "https://stackoverflow.com/questions/33792095/what-does-it-mean-for-a-smart-card-to-be-pkcs15-compatible") compliant (this is true for all that I've run into), then it won't work (well) with OpenSC and likely requires card's re-initialization, see [card_initialization README](https://github.com/carblue/acos5/tree/master/info/card_initialization "https://github.com/carblue/acos5/tree/master/info/card_initialization"))
The minimal OpenSC version supported is 0.17.0<br>
The new ACOS5-EVO (ACOS5 V4.00, V4.10, V4.20?): Meanwhile available, but I don't have it, thus untested/unknown what works or doesn't, when serving that card by this driver. Therefore, as matching those cards got activated, please file any issues/problems.<br>

The respective reference manual for Your hardware is available on request from: info@acs.com.hk


IMPORTANT renaming<br>
Since release 0.0.28 the driver starts to cover (some, work in progress; UPDATE: no more work on EVO until I received an ACOS5-EVO USB crypto token to test with) support for ACOS5-EVO, which has a 192 kB EEPROM, thus the former "_64" suffix for 64 kB EEPROM is inappropriate now.<br>
This repo's name changed from acos5_64 to acos5, as well as the driver's name and binary names and required entries in opensc.conf

IMPORTANT behavior<br>
There is a huge number of "limits" and "rules" that apply, many originate from OpenSC, others from this driver, far more than I'm willing to declare expressly other than in code (and I hope having covered all by checks).
Common usage won't exceed these limits and the driver will "just work". E.g. probably You won't have a file in Your file system that will be addressed with such a long path, e.g.
0x3F00_4100_4200_4300_4400_4500_4600_4700_4710<br>
An 18-byte path length won't work, as OpenSC data structures are limited to a path length of 16 bytes.<br>
So this is the point: It would be graceful reacting upon such limits/rules violations with error returns and respective error messages in opensc-debug.log, but often the driver isn't yet that polite and just deliberately aborts ("panic" in Rust lingo, due to an assert violation).
So, if anybody wants to contribute, removing these rough edges is an easy way to start.
And if the driver is "impolite" currently, it's most likely something about card content, that is different from expected according to PKCS#15/ISO/IEC 7816-15.
 

Steps towards driver binary builds libacos5.so/dll/dylib and libacos5_pkcs15.so/dll/dylib
=========================================================================================
1. Install OpenSC (if it's not there already; with debian and derivatives, it comprises packages opensc and opensc-pkcs11). The driver will call into libopensc.so (opensc.dll/libopensc.dylib), will need the configuration file opensc.conf to be adapted, and the build process will need an installed package pkgconfig in order to read from opensc.pc (You have to create the opensc.pc file: see how the script .travis.yml constructs/adapts it from opensc-pkcs11.pc (if that is available), or copies a basic version, that must be adapted). The build dependency may be removed by editing all 3 build.rs files accordingly:
For details about OpenSC read on in the opensc-sys binding.<br>
Same as OpenSC's libraries, also this driver will depend on OpenSSL's crypto library.<br>
Invoke `opensc-tool --info` in order to know Your installed OpenSC version. The driver build will be tied to that specific OpenSC version.
By default, the following installations are not required, but may be, depending on conditional compilation attributes (cfg):<br>
cargo:rustc-cfg=enable_acos5_ui requires an installation of [IUP](https://webserver2.tecgraf.puc-rio.br/iup "https://webserver2.tecgraf.puc-rio.br/iup"), [Download IUP sources/binaries](https://sourceforge.net/projects/iup/files/, "https://sourceforge.net/projects/iup/files/")

2. Install the Rust compiler and cargo build manager (it's bundled) from [Rust, cargo](https://www.rust-lang.org/tools/install "https://www.rust-lang.org/tools/install")<br>
   The version of Rust compiler rustc required is : 1.47.0 (released October 8th 2020) and upwards.<br>
(If those rust tools aren't required anymore, later uninstall with: rustup self uninstall)

3. Optionally read conditional_compile_options.md and then build the driver acos5: `user@host:~/path/to/acos5_root_downloaded$  cargo build --release`. The 2 shared object binaries will be built into directory target/release<br>
   `optionally user@host:~/path/to/acos5_root_downloaded$  strip --strip-unneeded target/release/libacos5.so`<br>
   `optionally user@host:~/path/to/acos5_root_downloaded$  strip --strip-unneeded target/release/libacos5_pkcs15.so`<br><br>
   Towards OpenSC, the driver's name is acos5_external, in order to make it distinguishable from a quite useless acos5 internal driver, that existed in OpenSC throughout until version 0.19.0

4. Copy acos5_pkcs15/acos5_external.profile to the directory where all the other .profile files installed by OpenSC are located, for Linux probably in /usr/share/opensc/ or /usr/local/share/opensc/, for Windows something like C:/Program Files/OpenSC Project/OpenSC/profiles.<br>

5. Adapt opensc.conf (see below). Also, in the beginning, switch on logging by a setting `debug=3;`<br>
   If all the above went well, the log file will have an entry within it's first 4 lines, reporting: "load_dynamic_driver: successfully loaded card driver 'acos5_external'".<br>
   Check that by reissuing: `opensc-tool --info`<br>
   The last command should have successfully loaded card driver 'acos5_external', but it didn't yet use it. The next will do so (and also check for disallowed duplicate file ids):<br>
   `opensc-tool --serial`
6. In case build errors or other errors occur:
   You have a copy of the opensc-sys binding on Your system in directory opensc-sys.<br>
   If there are build errors, then go to that folder and issue `cargo test test_struct_sizeof -- --nocapture`. Likely that fails then, and an error reason is found by asking why didn't that find the library libopensc.so or does the version reported differ, or ?, or as the worst case:<br>
   OpenSC was built with different settings/switches than the binding requires/assumes.<br>
   Other errors occur: Likely the opensc.conf file is incorrect.<br>
   Otherwise file an issue.


The required opensc.conf entries:<br>
The location of opensc.conf on Linux: /etc/opensc/opensc.conf.<br>
The location of opensc.conf on Windows: C:\Program Files\OpenSC Project\OpenSC\opensc.conf.<br>
Since recently, OpenSC installs a very short opensc.conf. The long version (that I'm using and referring to here) is in github's/tarball's etc/opensc.conf.example.in<br>
......... just denotes, there is other opensc.conf content before this line<br>
Content within ... (excluded) must be adapted (/something/like/path/to/acos5/target/releaseORdebug/) and added, otherwise there will be no support for ACOS5.<br>
The line "card_drivers = acos5_external, npa, internal;" is just an example from OpenSC version 0.17.0 opensc.conf: It means: Just prepend<br>
acos5_external,<br>
to the list of drivers specified by default and remove a leading comment character # in this line, if there is any.<br>
When using ACOS5 V2.00, it's also required for any OpenSC release version <= 0.19.0, to bypass the almost non-functional 'acos5' internal driver somehow, thus a painless start is by using<br>
    card_drivers = acos5_external, default;

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

		# "user-consent": Override disable / enable GUI enquiry popup when performing a signature, unwrap or RSA decrypt operation with ACOS5.
		# Operational only if compiled with cfg=enable_acos5_ui and IUP installed:
		user_consent_enabled = no; # anything starting with letter t or y (case-insensitive) get's interpreted as true/yes, otherwise false/no
		# When the dialog window pops up: Answer with NO in order to decline the RSA key usage; YES or closing the window [X] means accepting RSA key usage
		# secure messaging settings:
		ifd_serial = "11:22:33:44:55:66:77:88";
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
