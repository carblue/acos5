# acos5_64

Work in progress:

ACS ACOS5-64/CryptoMate64 driver and SM module (shared library/DLL) for the OpenSC framework

The library will be limited to OS Windows and POSIX (excluding Mac OSX; I've neither access to nor knowledge of Mac OSX. But if it doesn't work out of the box, it should be quite easy to support Mac OS X as well, if someone interested in will assist/test).

The module (driver) now is operational for linux (and almost for Windows as 32bit build; it does the job, but crashes while unloading) for some basic, read-only operations, e.g. opensc-tool and alike.

An early tester will find the opensc.conf (i.e. my diff-file to what gets installed by opensc, working for me on linux/Kubuntu and Windows8.1) in directory config.<br>
Adapt "/path/to" or place binary in OS's shared object/DLL search path.<br>

Forcing driver acos5_64 seems to be essential at the moment, as there is another driver (rudimentary acos5 internal driver), that will "serve" Your card/token otherwíse.<br>

As long as DMD for linux doesn't obey visibility of symbols declared [http://wiki.dlang.org/Access_specifiers_and_visibility], the script for the linker 'libacos5_64.ver' ("managed" by dub.json) does the job as well.

Building with DUB is a pleasure and DMD is blazingly fast ;-) . After installing prerequisite binaries: Within (downloaded/cloned) directory e.g. 'acos5_64-master', execute: $ dub build<br>
The binary will be compiled/linked/placed to sub-directory lib, if You go with DUB/my dub.json.

Soon to come: More code and SM to be integrated, as review of existing code goes on:

This topic climbed rapidly on my priority ladder: Reinitialization of a card/token. Presumably, most cards/token out there, such as mine, got initialized with vendors client kit, what makes Secure Messaging (SM) with session key infeasible (SE-file NEVER update protected, but no session key usage provided).
There are some more reasons to reinitialize. Users with some knowledge in this regard and not afraid of source code, will be able to reinitialize exactly to their needs. Still my settings are compatible with ACSCMU and the proprietary PKCS#11 module.<br>
In turn SM working is my prerequisite for publishing operations relevant to security/crypto operations.
Though sadly, all pin related operations have no SM support by ACOS5-64 (at least reference manual says so, but perhaps it is wrong in this regard too?).
Pins will always be in plain text commands. I've to make my mind how to deal with that if it proves true. Then, pins are but a transient shadow.



Steps to compile/install
========================

<br> are line breaks, only used for presenting text here, not to be part of any copying or command.

Prerequisites:

- I assume, the required basic reader software is installed (for MS-Windows this is winscard, for unix-flavours pcscd which pulls libpcsclite; for linux, CryptoMate64 additionally needs 
	(libccid or a newer) libacsccid:	PC/SC Driver (Package for Linux includes e.g. Ubuntu and others) from http://www.acs.com.hk/en/products/18/cryptomate64-cryptographic-usb-tokens/  Downloads
- Install or build libsodium (a fork of libnacl; my preferred crypto library)  https://download.libsodium.org/doc/
- If not already there, install or build openssl (e.g. https://wiki.openssl.org/index.php/Binaries, for now, for Windows the 32bit version light is sufficient) or, with Linux package managers, the next step will pull it anyway

- Install opensc-pkcs11 (and optionally/recommended opensc for utilities like opensc-tool), if not already there. Check the opensc version by running $ opensc-tool -i<br>
	user@host:~$ opensc-tool -i<br>
	OpenSC 0.15.0 [gcc  4.9.2]<br>
	Enabled features: zlib readline openssl pcsc(libpcsclite.so.1)     <-- THAT'S WHAT WE EXPECTED, OTHERWISE if pcsc (for linux) or openssl is missing, build opensc with appropriate options<br>
                                                                           <-- not shown here but also essential: opensc was compiled with #define ENABLE_SM  1<br>

- now for this library:

Concerning Windows, the required DMD download is "self-contained" for building 32bit-executables (x86) only. Stick with that for now.
(For building 64bit-executables (x86_64), it relies on the Microsoft linker.
If not installed, FIRST download and INSTALL e.g. free "Visual Studio Community" AND ONLY AFTERWARDS INSTALL DMD (so that DMD install-script can look-up paths to the Microschrott-tools and set-up everything)).

- Get a recent D-compiler DMD and runtime library libphobos2 (i.e. DMD 2.070.2 as of now or higher from https://dlang.org/download.html; so far, I've tested and support DMD only)
- Get DUB - The D package registry... (https://code.dlang.org/download or for Ubuntu users: http://d-apt.sourceforge.net/ ; there is DMD too and more).
	This step is optional but highly recommended, as it eases compiling the D source code and any of it's prerequisites (D-bindings to libopensc, libsodium and the later required libcrypto/libeay32):
	it automatically downloads/compiles/links everything defined in my dub.json file; otherwise have a look in file dub.json for compiler/linker settings etc.; (DUB website, subject: Package file format JSON)

- Download (zip and extract)/git clone code from https://github.com/carblue/acos5_64; within the extracted/cloned folder run $ dub build<br>
	  This command takes all it needs to know (potentially for different compilers, OSes, configurations) from file dub.json and the resulting libacos5_64.so/.dll driver executable will be in folder /lib<br>
- Optional: Making shure, that all dependencies are resolved is always a good idea (Linux): ldd lib/libacos5_64.so (Windows: use e.g. dependancy walker)<br>

- Optionally place the resulting libacos5_64.so/.dll exexutable to a directory, where Your OS will look for it when it's searching/loading .so/.dll files (thus we can optionally omit the /path/to in the following step and use it for whatever;  (sudo ldconfig  for posix user's required?)

HOWTO edit opensc configuration files (s.a. folder config)
- Edit the OpenSC configuration file opensc.conf (my linux distro places the general/'anyuser' config file at /etc/opensc)<br>
    Details about the config file are beyond the scope of this doc and may perhaps be found in the OpenSC documentation.
    The following 2 changes in opensc.conf are essential to make OpenSC aware of the (new) external ACOS5-64/CryptoMate64 driver (acos5_64):<br>
    
(1) Locate the line:  	# card_drivers = customcos, internal;<br>
      and copy the following line just one line below, or adapt: essential: It's no comment (no # in the beginning) and it includes acos5_64; internal must be the last entry.<br>
	card_drivers = acos5_64, internal;
  
(2) Locate the line:  # For card drivers loaded from an external shared library/DLL,<br>
	    and replace (or even better paste after):<br>
	# card_driver customcos {<br>
		# The location of the driver library<br>
		# module = /usr/lib/x86_64-linux-gnu/card_customcos.so;<br>
	# }<br>
	by:<br>
	 card_driver acos5_64 {<br>
		# The location of the driver library, e.g. /usr/local/lib/libacos5_64.so or c:\windows\system32\libacos5_64.dll<br>
		 module = /path/to/libacos5_64.so/.dll;<br>
	 }<br>


The following third change in opensc.conf is essential as long as internal driver acos5 (ACS ACOS5 card) captures "our" ATR; we force OpenSC to skip the "greedy" acos5 driver;
There may be some ways to do that, but as long as You use only CryptoMate64, this way will do:<br>

(3) Locate the line:    # force_card_driver = customcos;<br>
      and copy the following line just one line below:<br>
	force_card_driver = acos5_64;<br>

(4) You may instruct opensc to output log messages to any extend such as level 9, which is very informative for the curious user. This driver library adheres to that logging facility and uses 
		logging quite extensively, at least during implementation.<br>
		BUT do this on YOUR OWN RISK OF LOOSING SECURITY, as passwords and other sensitive data will be revealed in any log file as long as I haven't completed SM implementation!!!<br>
		Lines in D code containing sc_do_log are responsible for that<br>
		
		If something doesn't work as expected, this is the source to reveal what happened/failed and often why (on source code line level; for my part, search for acos5_64 (acos5_64_sm));<br>
		direct logging output to /tmp, thus it gets deleted on shutdown; the setting is right in the beginning of opensc.conf "Amount of debug info to print"<br>
		It get's even better: There is an opensc library pkcs11-spy.so that hook's in and may be instructed/configured by environment variables to log all calls to pkcs#11 functions to a separate file<br>
		https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC<br>
		You can even get logging from the lower PC/SC-level if the pcscd daemon is instructed to do so; found that on one of the alioth web pages;<br>
		http://ludovicrousseau.blogspot.de/2011/07/pcscd-debug-output.html<br>
		but don't run pcscd in debugging output mode a long time:<br>
		There is a polling thread running that will flood the logfile.<br>
		If pcscd is running: Close/disconnect any possible clients of pcsc/opensc: Client apps (PCSC and PKCS#11-aware ones) like gscriptor, scriptor, XCA, maybe Firefox/Thunderbird etc. and shut them down:<br>
                sudo service pcscd stop<br>
                Now we start pcscd again manually with other options like debug output at apdu level, to be directed to stdout and file pcscd_log.txt.<br>
		sudo pcscd --foreground --debug --apdu --color | tee pcscd_log.txt &<br>
		Now let's log e.g. a call to program opensc-tool (You'll get a log of all apdu commands sent and responses received from the token; far more, than I/opensc decided to be logged, everything, thus pins etc. too:<br>
		LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libpcscspy.so opensc-tool --serial<br>
                Finally, kill the pcscd process or find the right way to quit pcscd<br>
                sudo service pcscd start<br>
                pcscd should run from now on on request only as before, with it's usual options as daemon (mine are --foreground --auto-exit).<br>
                If this went wrong, nothing depending on pcscd will work any more until repair or reboot.<br>
                (e.g. this was the only method to figure out, how (re-)initialization of token is done by ACS "Certificate Management Utility"; it wasn't documented even in the reference manual.<br>
		
		
Test, that opensc does load our driver:<br>
user@host:~$ opensc-tool -D<br>
  Configured card drivers:<br>
  acos5_64         ACS ACOS5-64 (CryptoMate64)     <-- THAT'S WHAT WE EXPECTED, OTHERWISE THERE IS A MALFORMED opensc.conf OR SOME .so/.dll PROBLEM !!!<br>
  cardos           Siemens CardOS<br>
  flex             Schlumberger Multiflex/Cryptoflex<br>
  ...<br>
  incrypto34       Incard Incripto34<br>
  acos5            ACS ACOS5 card<br>
  ...  <br>
	
  This library got tested as version "0.15.0" (D code constant "module_version") with OS Kubuntu 15.10 and Windows 8.1 to work as intended to the extend supported with OpenSC package release version "0.15.0", https://github.com/OpenSC/OpenSC/wiki.<br>
  Older opensc versions will probably do as well but I didn't check that AND FAKE_OPENSC_VERSION must be used then; to get users of acos5_64 going in the first place and demonstrate where it's done, this is incorporated a priori in dub.json, despite it's not the long-term way to handle this versioning issue: Prefer to update opensc to the latest version 0.15.0 (if linux distros are behind, install prerequisites and follow the "Typical Installation" described in https://github.com/OpenSC/OpenSC/wiki/Compiling-and-Installing-OpenSC-on-Unix-flavors; I replace command sudo make install by sudo checkinstall), and update this library as well, thus version no.s match in fact and omit FAKE_OPENSC_VERSION from dub.json. Usage of FAKE_OPENSC_VERSION is intended on an interim basis only, mainly for the meantime since a new opensc release version is out and on Your box and I'm not ready with my updated homonymous version;<br>FAKE_OPENSC_VERSION may hide API discrepancies and You/this driver may be screwed by ignoring this issue.<br>
  
  IMPORTANT: Installed opensc version and the version, this library reports to opensc, MUST match (even though faked-wise), OTHERWISE, this external library will be REJECTED by opensc !<br>
  IMPORTANT: Remove FAKE_OPENSC_VERSION from dub.json as soon as possible !

TODO explain a lot of details/usage/version identifiers/etc.


Remaining text: Some example output:

user@host:~/workspace/libacos5_64$ ldd lib/libacos5_64.so<br>
        linux-vdso.so.1 =>  (0x00007fff9ab15000)<br>
        libssl.so.1.0.0 => /lib/x86_64-linux-gnu/libssl.so.1.0.0 (0x00007f452257c000)<br>
        libcrypto.so.1.0.0 => /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 (0x00007f4522138000)<br>
        libsodium.so.18 => /usr/local/lib/libsodium.so.18 (0x00007f4521ed9000)<br>
        libopensc.so.3 => /usr/lib/libopensc.so.3 (0x00007f4521b31000)<br>
        libphobos2.so.0.70 => /usr/lib/x86_64-linux-gnu/libphobos2.so.0.70 (0x00007f45212f9000)<br>
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f45210db000)<br>
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f4520dd3000)<br>
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f4520bcb000)<br>
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f45209c7000)<br>
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f45207b0000)<br>
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f45203e6000)<br>
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f45201cc000)<br>
        /lib64/ld-linux-x86-64.so.2 (0x00007f4522a09000)<br>


$ opensc-tool -f<br>
...
    3f0041005031 type: wEF, ef structure: transparent, size: 80                               <= EF(ODF) 
    read[NONE] update[CHV3] erase[CHV3] write[N/A] rehab[CHV3] inval[CHV3] 

00000000: A8 0A 30 08 04 06 3F 00 41 00 12 34 00 00 00 00 ..0...?.A..4....
00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
...
    3f0041004135 type: iEF, ef structure: transparent, size: 533                              <= public key RSA 4096 bit
    read[NONE] update[CHV1] erase[CHV1] write[NONE] rehab[CHV1] inval[CHV1] 

    3f00410041f5 type: iEF, ef structure: transparent, size: 1285                  <= private key RSA 4096 bit, CRT
    read[NEVR] update[CHV1] erase[CHV1] write[NONE] rehab[CHV1] inval[CHV1] 

    3f0041001234 type: wEF, ef structure: transparent, size: 128                   <= EF(AODF)
    read[NONE] update[CHV3] erase[CHV3] write[N/A] rehab[CHV3] inval[CHV3] 

00000000: 30 37 30 0D 0C 07 55 73 65 72 50 49 4E 03 02 06 070...UserPIN...
00000010: C0 30 03 04 01 01 A1 21 30 1F 03 02 02 CC 0A 01 .0.....!0.......
00000020: 01 02 01 04 02 01 08 02 01 08 80 02 00 81 04 01 ................
00000030: FF 30 06 04 04 3F 00 41 00 00 00 00 00 00 00 00 .0...?.A........
00000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
    3f0041003901 type: wEF, ef structure: transparent, size: 16                               <= file for tests on secure messaging
    read[NONE] update[SecOx5] erase[SecOx5] write[N/A] rehab[CHV3] inval[CHV3] 

00000000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................


Debug file content (opensc.conf: debug set to 9) after running on linux: $ opensc-tool -f<br>
0x7ff198613700 19:26:18.078 [opensc-tool] ctx.c:726:sc_context_create: ===================================<br>
0x7ff198613700 19:26:18.078 [opensc-tool] ctx.c:727:sc_context_create: opensc version: 0.15.0<br>
0x7ff198613700 19:26:18.079 [opensc-tool] reader-pcsc.c:668:pcsc_init: PC/SC options: connect_exclusive=0 disconnect_action=1 transaction_end_action=0 reconnect_action=0 enable_pinpad=1 enable_pace=1<br>
0x7ff198613700 19:26:18.086 [opensc-tool] ctx.c:382:load_dynamic_driver: successfully loaded card driver 'acos5_64'<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:956:pcsc_detect_readers: called<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:970:pcsc_detect_readers: Probing PC/SC readers<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:999:pcsc_detect_readers: Establish PC/SC context<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:1047:pcsc_detect_readers: Found new PC/SC reader 'ACS CryptoMate64 00 00'<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:309:refresh_attributes: current  state: 0x00000022<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:310:refresh_attributes: previous state: 0x00000000<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:364:refresh_attributes: card present, changed<br>
0x7ff198613700 19:26:18.086 [opensc-tool] reader-pcsc.c:1078:pcsc_detect_readers: Requesting reader features ... <br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:1092:pcsc_detect_readers: ACS CryptoMate64 00 00:SCardConnect(SHARED): 0x00000000<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:831:detect_reader_features: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:852:detect_reader_features: Reader feature 12 found<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:852:detect_reader_features: Reader feature 13 found<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:872:detect_reader_features: Reader feature 13 is not supported<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:1122:pcsc_detect_readers: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.374 [opensc-tool] sc.c:251:sc_detect_card_presence: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:372:pcsc_detect_card_presence: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:377:pcsc_detect_card_presence: returning with: 1<br>
0x7ff198613700 19:26:18.374 [opensc-tool] sc.c:256:sc_detect_card_presence: returning with: 1<br>
0x7ff198613700 19:26:18.374 [opensc-tool] sc.c:251:sc_detect_card_presence: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:372:pcsc_detect_card_presence: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:377:pcsc_detect_card_presence: returning with: 1<br>
0x7ff198613700 19:26:18.374 [opensc-tool] sc.c:256:sc_detect_card_presence: returning with: 1<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:148:sc_connect_card: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:452:pcsc_connect: called<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:481:pcsc_connect: Initial protocol: T=0<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:923:match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:934:match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:401:check_forced_protocol: force_protocol: t0<br>
0x7ff198613700 19:26:18.374 [opensc-tool] reader-pcsc.c:493:pcsc_connect: Final protocol: T=0<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:169:sc_connect_card: matching configured ATRs<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:178:sc_connect_card: trying driver 'acos5_64'<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:923:match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:934:match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.374 [opensc-tool] card.c:183:sc_connect_card: matched driver 'ACS ACOS5-64 (CryptoMate64)'<br>
0x7ff198613700 19:26:18.374 [opensc-tool] acos5_64:405:acos5_64_match_card: try to match card with ATR 3BBE9600004105200000000000000000 009000<br>
0x7ff198613700 19:26:18.375 [opensc-tool] acos5_64:255:missing_match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.375 [opensc-tool] acos5_64:266:missing_match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7ff198613700 19:26:18.375 [opensc-tool] acos5_64:273:missing_match_atr_table: ATR mask: FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF<br>
0x7ff198613700 19:26:18.375 [opensc-tool] acos5_64:323:acos5_64_match_card_checks: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] apdu.c:563:sc_transmit_apdu: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] card.c:352:sc_lock: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] reader-pcsc.c:519:pcsc_lock: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] apdu.c:530:sc_transmit: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] apdu.c:384:sc_single_transmit: called<br>
0x7ff198613700 19:26:18.375 [opensc-tool] apdu.c:389:sc_single_transmit: CLA:80, INS:14, P1:5, P2:0, data(0) (nil)<br>
0x7ff198613700 19:26:18.375 [opensc-tool] reader-pcsc.c:251:pcsc_transmit: reader 'ACS CryptoMate64 00 00'<br>
0x7ff198613700 19:26:18.375 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Outgoing APDU data [    5 bytes] =====================================<br>
80 14 05 00 00 .....<br>
======================================================================<br>
0x7ff198613700 19:26:18.375 [opensc-tool] reader-pcsc.c:184:pcsc_internal_transmit: called<br>
0x7ff198613700 19:26:18.383 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Incoming APDU data [    2 bytes] =====================================<br>
95 40 .@<br>
======================================================================<br>
0x7ff198613700 19:26:18.383 [opensc-tool] apdu.c:399:sc_single_transmit: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.383 [opensc-tool] apdu.c:552:sc_transmit: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.383 [opensc-tool] card.c:392:sc_unlock: called<br>
0x7ff198613700 19:26:18.383 [opensc-tool] reader-pcsc.c:556:pcsc_unlock: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] acos5_64:977:acos5_64_check_sw: called for: sw1 = 0x95, sw2 = 0x40<br>
0x7ff198613700 19:26:18.387 [opensc-tool] acos5_64:982:acos5_64_check_sw: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.387 [opensc-tool] apdu.c:563:sc_transmit_apdu: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] card.c:352:sc_lock: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] reader-pcsc.c:519:pcsc_lock: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] apdu.c:530:sc_transmit: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] apdu.c:384:sc_single_transmit: called<br>
0x7ff198613700 19:26:18.387 [opensc-tool] apdu.c:389:sc_single_transmit: CLA:80, INS:14, P1:6, P2:0, data(0) (nil)<br>
0x7ff198613700 19:26:18.387 [opensc-tool] reader-pcsc.c:251:pcsc_transmit: reader 'ACS CryptoMate64 00 00'<br>
0x7ff198613700 19:26:18.387 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Outgoing APDU data [    5 bytes] =====================================<br>
80 14 06 00 08 .....<br>
======================================================================<br>
0x7ff198613700 19:26:18.387 [opensc-tool] reader-pcsc.c:184:pcsc_internal_transmit: called<br>
0x7ff198613700 19:26:18.400 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Incoming APDU data [   10 bytes] =====================================<br>
41 43 4F 53 05 02 00 40 90 00 ACOS...@..<br>
======================================================================<br>
0x7ff198613700 19:26:18.400 [opensc-tool] apdu.c:399:sc_single_transmit: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.400 [opensc-tool] apdu.c:552:sc_transmit: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.400 [opensc-tool] card.c:392:sc_unlock: called<br>
0x7ff198613700 19:26:18.400 [opensc-tool] reader-pcsc.c:556:pcsc_unlock: called<br>
0x7ff198613700 19:26:18.407 [opensc-tool] acos5_64:326:acos5_64_match_card_checks: returning with: 0 (Success)<br>
0x7ff198613700 19:26:18.407 [opensc-tool] acos5_64:414:acos5_64_match_card: card matched (acos5_64)<br>
0x7ff198613700 19:26:18.407 [opensc-tool] acos5_64:427:acos5_64_init: called<br>
0x7ff198613700 19:26:18.408 [opensc-tool] acos5_64:474:acos5_64_init: This module initialized libsodium version: 1.0.8<br>
0x7ff198613700 19:26:18.408 [opensc-tool] acos5_64:182:acos5_64_get_serialnr: called<br>
...<br>


Same on Windows:<br>
Output of dependancy walker for LIBACOS5_64.DLL:<br>
c:\bin\LIBSODIUM.DLL<br>
c:\bin\OPENSC.DLL<br>
c:\bin\LIBACOS5_64.DLL<br>
c:\windows\system32\ADVAPI32.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-APIQUERY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-APPCOMPAT-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-APPINIT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-ATOMS-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-BEM-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-COMM-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-CONSOLE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-CONSOLE-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-CRT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-CRT-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-DATETIME-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-DATETIME-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-DEBUG-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-DEBUG-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-DELAYLOAD-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-ERRORHANDLING-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-ERRORHANDLING-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FIBERS-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FILE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FILE-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FILE-L1-2-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FILE-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-FILE-L2-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-HANDLE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-HEAP-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-HEAP-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-HEAP-OBSOLETE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-INTERLOCKED-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-INTERLOCKED-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-IO-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-JOB-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-JOB-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-KERNEL32-LEGACY-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LIBRARYLOADER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LIBRARYLOADER-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-L1-2-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-OBSOLETE-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-LOCALIZATION-PRIVATE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-MEMORY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-MEMORY-L1-1-2.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-NAMEDPIPE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-NAMEDPIPE-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-NAMESPACE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-NORMALIZATION-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PATH-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSENVIRONMENT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSENVIRONMENT-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSTHREADS-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSTHREADS-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSTHREADS-L1-1-2.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROCESSTOPOLOGY-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PROFILE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PSAPI-ANSI-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PSAPI-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-PSAPI-OBSOLETE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-REALTIME-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-REGISTRY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-REGISTRYUSERSPECIFIC-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-RTLSUPPORT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-RTLSUPPORT-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SHLWAPI-LEGACY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SHLWAPI-OBSOLETE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SIDEBYSIDE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-STRING-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-STRING-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-STRING-OBSOLETE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-STRINGANSI-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SYNCH-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SYNCH-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SYSINFO-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SYSINFO-L1-2-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-SYSTEMTOPOLOGY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-THREADPOOL-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-THREADPOOL-LEGACY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-THREADPOOL-PRIVATE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-TIMEZONE-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-URL-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-UTIL-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-VERSION-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-VERSIONANSI-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WINDOWSERRORREPORTING-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WINRT-ERROR-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WINRT-ERRORPRIVATE-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WINRT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WINRT-REGISTRATION-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-WOW64-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CORE-XSTATE-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-CONVERT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-HEAP-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-STDIO-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-STRING-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-CRT-TIME-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-EVENTING-CLASSICPROVIDER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-EVENTING-CONSUMER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-EVENTING-CONTROLLER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-EVENTING-PROVIDER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-APPCONTAINER-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-AUDIT-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-BASE-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-BASE-PRIVATE-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-LSALOOKUP-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-SECURITY-LSAPOLICY-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SERVICE-CORE-L1-1-1.DLL<br>
c:\windows\system32\API-MS-WIN-SERVICE-MANAGEMENT-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SERVICE-MANAGEMENT-L2-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SERVICE-WINSVC-L1-2-0.DLL<br>
c:\windows\system32\API-MS-WIN-SHELL-SHELLCOM-L1-1-0.DLL<br>
c:\windows\system32\API-MS-WIN-SHELL-SHELLFOLDERS-L1-1-0.DLL<br>
c:\windows\system32\BCRYPTPRIMITIVES.DLL<br>
c:\windows\system32\CRYPTBASE.DLL<br>
c:\windows\system32\GDI32.DLL<br>
c:\windows\system32\KERNEL32.DLL<br>
c:\windows\system32\KERNELBASE.DLL<br>
c:\windows\system32\MSVCRT.DLL<br>
c:\windows\system32\NSI.DLL<br>
c:\windows\system32\NTDLL.DLL<br>
c:\windows\system32\RPCRT4.DLL<br>
c:\windows\system32\SECHOST.DLL<br>
c:\windows\system32\SHELL32.DLL<br>
c:\windows\system32\SHLWAPI.DLL<br>
c:\windows\system32\SSPICLI.DLL<br>
c:\windows\system32\UCRTBASE.DLL<br>
c:\windows\system32\USER32.DLL<br>
c:\windows\system32\VCRUNTIME140.DLL<br>
c:\windows\system32\WS2_32.DLL<br>
c:\windows\syswow64\downlevel\API-MS-WIN-CORE-KERNEL32-PRIVATE-L1-1-1.DLL<br>
c:\windows\syswow64\downlevel\API-MS-WIN-CORE-PRIVATEPROFILE-L1-1-1.DLL<br>
c:\windows\syswow64\downlevel\API-MS-WIN-SERVICE-PRIVATE-L1-1-1.DLL<br>


C:\Users\carblue>opensc-tool -i<br>
OpenSC 0.15.0 [Microsoft 1600]<br>
Enabled features:pcsc openssl zlib<br>

C:\Users\carblue>opensc-tool -a<br>
Using reader with a card: ACS CryptoMate64 0<br>
3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>

C:\Users\carblue>opensc-tool -n<br>
Using reader with a card: ACS CryptoMate64 0<br>
acos5_64<br>

C:\Users\carblue>opensc-tool -l<br>
# Detected readers (pcsc)<br>
Nr.  Card  Features  Name<br>
0    Yes             ACS CryptoMate64 0<br>

C:\Users\carblue>opensc-tool -D<br>
Configured card drivers:<br>
  acos5_64         ACS ACOS5-64 (CryptoMate64)<br>
  cardos           Siemens CardOS<br>
  flex             Schlumberger Multiflex/Cryptoflex<br>
  ...<br>
  incrypto34       Incard Incripto34<br>
  acos5            ACS ACOS5 card<br>
  ...  <br>
