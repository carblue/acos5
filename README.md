# acos5_64

Work in progress:

ACS ACOS5-64/CryptoMate64 driver and SM module (shared library/DLL) for the OpenSC framework

The library will be limited to OS Windows and POSIX (excluding Mac OSX; I've neither access to nor knowledge of Mac OSX. But if it doesn't work out of the box, it should be quite easy to support Mac OS X as well, if someone interested in will assist/test); in the order linux, other OSes.

The module (driver) now is operational on linux for some basic, read-only operations, e.g. opensc-tool and alike (Windows needs some dub.json changes I didn't figure out so far; hassle with -m32/-m64/linker as well as import libs for openssl's dlls, sodium.dll and opensc.dll)

An early tester will find the opensc.conf (i.e. my diff-file to what gets installed by opensc, working for me on linux/Kubuntu) in directory config.<br>
Adapt "/path/to" or place binary in OS's shared object/DLL search path.<br>

Forcing driver acos5_64 seems to be essential at the moment, as there is another driver (acos5 internal driver), that will serve Your card/token otherwíse.<br>

As long as DMD doesn't obey visibility of symbols declared [http://wiki.dlang.org/Access_specifiers_and_visibility], the script for the linker 'libacos5_64.ver' ("managed" by dub.json) does the job as well.

Building with DUB is a pleasure and DMD is blazingly fast ;-) . After installing prerequisites: Within (downloaded/cloned) directory e.g. 'acos5_64-master', execute: $ dub build<br>
The binary will be compiled/linked/placed to sub-directory lib, if You go with DUB/my dub.json.

Soon to come: More code to be integrated, as review of existing code goes on:

This topic climbed rapidly on my priority ladder: Reinitialization of a card/token. Presumably, most cards/token out there, such as mine, got initialized with vendors client kit, what makes Secure Messaging (SM) with session key infeasible (SE-file NEVER update protected, but no session key usage provided).
There are some more reasons to reinitialize. Users with some knowledge in this regard and not afraid of source code, will be able to reinitialize exactly to their needs. Still my settings are compatible with ACSCMU.<br>
In turn SM working is my prerequisite for publishing operations relevant to security/crypto operations.
Though sadly, all pin related operations have no SM support by ACOS5-64 (at least reference manual says so, but perhaps it is wrong in this regard too?).
Pins will always be in plain text commands. I've to make my mind how to deal with that if it proves true. Then, pins are but a transient shadow.



Steps to compile/install
========================
Prerequisites:

- I assume, the required basic reader software is installed (on MS-Windows this is winscard, on unix-flavours pcscd which pulls libpcsclite; CryptoMate64 additionally needs 
	(libccid or a newer) libacsccid:	PC/SC Driver (Package for Linux includes e.g. Ubuntu and others) from http://www.acs.com.hk/en/products/18/cryptomate64-cryptographic-usb-tokens/  Downloads
- Install or build libsodium (a fork of libnacl; my preferred crypto library)  https://download.libsodium.org/doc/
- If not already there, install or build libssl (openssl, e.g. https://wiki.openssl.org/index.php/Binaries) or, with Linux package managers, the next step will pull it anyway

- Install opensc-pkcs11 (and optionally/recommended opensc for utilities like opensc-tool), if not already there. Check the opensc version by running (in a shell/cmd.exe) opensc-tool -i<br>
	user@host:~$ opensc-tool -i<br>
	OpenSC 0.15.0 [gcc  4.9.2]<br>
	Enabled features: zlib readline openssl pcsc(libpcsclite.so.1)     <-- THAT'S WHAT WE EXPECTED, OTHERWISE if pcsc or openssl is missing, build opensc with appropriate options<br>
                                                                           <-- not shown here but also essential: opensc was compiled with #define ENABLE_SM  1<br>

- now for this library in narrower sense:
- Get a recent D-compiler like dmd and runtime library libphobos2 (i.e. DMD 2.070.2 as of now or higher from https://dlang.org/download.html; so far, I've tested with DMD only)
- Get DUB - The D package ... (https://code.dlang.org/download or for Ubuntu users: http://d-apt.sourceforge.net/).
	This step is optional but highly recommended, as it eases compiling the D source code and any of it's prerequisites:
	it automatically downloads/compiles/links everything defined in my dub.json file; otherwise have a look in file dub.json for compiler/linker settings etc.; (DUB website, subject: Package file format (JSON))

- Download (as zip and extract)/clone my code from https://github.com/carblue/acos5_64; within the extracted/cloned folder run (in shell/cmd.exe user@host:/extracted/folder$) dub build<br>
	  This command takes all it needs to know (potentially for different compilers, OSes, configurations) from file dub.json and the resulting libacos5_64.so/.dll driver exexutable will be in folder /lib<br>
- Optional: Making shure, that all dependencies are resolved is always a good idea (Linux): ldd lib/libacos5_64.so (Windows: use e.g. dependancy walker)<br>

- Optionally place the resulting libacos5_64.so/.dll exexutable to a directory, where Your OS will look for it when it's searching/loading .so/.dll files (thus we can optionally omit the /path/to in the following step and use it for whatever;  (sudo ldconfig  for posix user's required?)

HOWTO edit opensc configuration files (s.a. folder config)
- Edit the OpenSC configuration file opensc.conf (my linux distro places the general/'anyuser' config file at /etc/opensc;<br>
    Details about the config file are out of the scope of this doc and may perhaps be found in the OpenSC documentation.
    The following 2 changes in opensc.conf are essential to make OpenSC aware of the (new) external CryptoMate64 driver (acos5_64):<br>
    
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
		# The location of the driver library, e.g. /usr/local/lib/libacos5_64.so or C:\windows\system32\libacos5_64.dll<br>
		 module = /path/to/libacos5_64.so;<br>
	 }<br>

    The following third change in opensc.conf is essential as long as acos5 (ACS ACOS5 card)	captures "our" ATR; we force OpenSC to skip the "greedy" acos5 driver;
      There may be some ways to do that, but as long as You use only CryptoMate64, this way will do:<br>
      
(3) Locate the line:    # force_card_driver = customcos;<br>
      and copy the following line just one line below:<br>
	force_card_driver = acos5_64;<br>

(4) You may instruct opensc to output log messages to any extend such as level 9, which is very informative for the curious user. This driver library adheres to that logging facility and uses 
		logging quite extensively, at least during implementation phase.<br>
		BUT do this on YOUR OWN RISK OF LOOSING SECURITY, as passwords and other sensitive data will be revealed in any log file as long as I haven't completed SM implementation!!!<br>
		Lines in my code containing sc_do_log are responsible for that<br>
		
		If something doesn't work as expected, this is the source to reveal what happened/failed and often why (on source code line level; for my part, search for acos5_64 (acos5_64_sm));<br>
		direct logging output to /tmp, thus it gets deleted on shutdown; the setting is right in the beginning of opensc.conf "Amount of debug info to print"
		It get's even better: There is an opensc library pkcs11-spy.so that hook's in and may be instructed/configured by environment variables to log all calls to pkcs#11 functions to a separate file<br>
		https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC<br>
		You can even get logging from the lower PC/SC-level if the pcscd daemon is instructed to do so; found that on one of the alioth web pages;<br>
		http://ludovicrousseau.blogspot.de/2011/07/pcscd-debug-output.html<br>
		but don't run pcscd in debugging output mode over a long time:<br>
		There is a polling thread running that will flood the logfile.<br>
		If pcscd is running: Close/disconnect any possible clients of pcsc/opensc: Client apps (PCSC and PKCS#11-aware ones) like gscriptor, scriptor, XCA, maybe Firefox/Thunderbird etc. and shut it down:<br>
                sudo service pcscd stop<br>
                Now we start pcscd again manually with other options like debug output at apdu level, to be directed to stdout and file pcscd_log.txt.<br>
		sudo pcscd --foreground --debug --apdu --color | tee pcscd_log.txt &<br>
		Now let's log e.g. a call to program opensc-tool (You'll get a log of all apdu commands sent and responses received from the token; far more, than I/opensc decided to be logged, everything, thus pins etc. too:<br>
		LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libpcscspy.so opensc-tool --serial<br>
                kill the pcscd process or find the right way to quit pcscd<br>
                sudo service pcscd start<br>
                pcscd should run from now on on request only as before, with it's usual options as daemon (mine are --foreground --auto-exit).<br>
                If this went wrong, nothing depending on pcscd will work any more until repair or reboot.<br>
                This was the only method to figure out, how (re-)initialization of token is done by ACS "Certificate Management Utility"; it wasn't documented even in the reference manual.<br>
		
		
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
	
  This library got tested as version "0.15.0" with OS Kubuntu 15.10 (and not yet Windows 8.1/10) to work as intended to the extend supported with OpenSC package release version "0.15.0", https://github.com/OpenSC/OpenSC/wiki<br>
  (older opensc versions will probably do as well but I didn't check that AND FAKE_OPENSC_VERSION must be used; to get users going, this is incorporated a priori in dub.json, despite it's not the long-term way to handle this versioning issue: Prefer to update opensc to the latest version, as well as this library, thus version no.s match in fact and omit FAKE_OPENSC_VERSION from dub.json<br>
  Installed opensc version and this library's version MUST match (even though faked-wise), OTHERWISE, this external library will be REJECTED by opensc !<br>

TODO explain a lot of details/usage/version identifiers/etc.


Some example output (opensc.conf: debug set to 9):<br>

user@host:~/workspace/libacos5_64$ ldd lib/libacos5_64.so<br>
        linux-vdso.so.1 =>  (0x00007ffeda1ba000)<br>
        libssl.so.1.0.0 => /lib/x86_64-linux-gnu/libssl.so.1.0.0 (0x00007f725a7de000)<br>
        libcrypto.so.1.0.0 => /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 (0x00007f725a39a000)<br>
        libsodium.so.13 => /usr/lib/x86_64-linux-gnu/libsodium.so.13 (0x00007f725a147000)<br>
        librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f7259f3f000)<br>
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f7259d21000)<br>
        libopensc.so.3 => /usr/lib/libopensc.so.3 (0x00007f7259979000)<br>
        libphobos2.so.0.70 => /usr/lib/x86_64-linux-gnu/libphobos2.so.0.70 (0x00007f7259141000)<br>
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f7258e39000)<br>
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f7258c35000)<br>
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f7258a1e000)<br>
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7258654000)<br>
        /lib64/ld-linux-x86-64.so.2 (0x00007f725ac6a000)<br>
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f725843a000)<br>

e.g. $ opensc-tool -f<br>
0x7fb2c69d5700 12:16:26.414 [opensc-tool] ctx.c:726:sc_context_create: ===================================<br>
0x7fb2c69d5700 12:16:26.414 [opensc-tool] ctx.c:727:sc_context_create: opensc version: 0.15.0<br>
0x7fb2c69d5700 12:16:26.414 [opensc-tool] reader-pcsc.c:668:pcsc_init: PC/SC options: connect_exclusive=0 disconnect_action=1 transaction_end_action=0 reconnect_action=0 enable_pinpad=1 enable_pace=1<br>
0x7fb2c69d5700 12:16:26.422 [opensc-tool] ctx.c:382:load_dynamic_driver: successfully loaded card driver 'acos5_64'<br>
0x7fb2c69d5700 12:16:26.422 [opensc-tool] reader-pcsc.c:956:pcsc_detect_readers: called<br>
0x7fb2c69d5700 12:16:26.422 [opensc-tool] reader-pcsc.c:970:pcsc_detect_readers: Probing PC/SC readers<br>
0x7fb2c69d5700 12:16:26.422 [opensc-tool] reader-pcsc.c:999:pcsc_detect_readers: Establish PC/SC context<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:1047:pcsc_detect_readers: Found new PC/SC reader 'ACS CryptoMate64 00 00'<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:309:refresh_attributes: current  state: 0x00000022<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:310:refresh_attributes: previous state: 0x00000000<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:364:refresh_attributes: card present, changed<br>
0x7fb2c69d5700 12:16:26.907 [opensc-tool] reader-pcsc.c:1078:pcsc_detect_readers: Requesting reader features ... <br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:1092:pcsc_detect_readers: ACS CryptoMate64 00 00:SCardConnect(SHARED): 0x00000000<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:831:detect_reader_features: called<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:852:detect_reader_features: Reader feature 12 found<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:852:detect_reader_features: Reader feature 13 found<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:872:detect_reader_features: Reader feature 13 is not supported<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:1122:pcsc_detect_readers: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] sc.c:251:sc_detect_card_presence: called<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:372:pcsc_detect_card_presence: called<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] reader-pcsc.c:377:pcsc_detect_card_presence: returning with: 1<br>
0x7fb2c69d5700 12:16:26.919 [opensc-tool] sc.c:256:sc_detect_card_presence: returning with: 1<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] sc.c:251:sc_detect_card_presence: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:372:pcsc_detect_card_presence: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:377:pcsc_detect_card_presence: returning with: 1<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] sc.c:256:sc_detect_card_presence: returning with: 1<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:148:sc_connect_card: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:452:pcsc_connect: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:285:refresh_attributes: ACS CryptoMate64 00 00 check<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:301:refresh_attributes: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:481:pcsc_connect: Initial protocol: T=0<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:923:match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:934:match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:401:check_forced_protocol: force_protocol: t0<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:493:pcsc_connect: Final protocol: T=0<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:169:sc_connect_card: matching configured ATRs<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:178:sc_connect_card: trying driver 'acos5_64'<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:923:match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:934:match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:183:sc_connect_card: matched driver 'ACS ACOS5-64 (CryptoMate64)'<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] acos5_64:396:acos5_64_match_card: try to match card with ATR 3BBE9600004105200000000000000000 009000<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] acos5_64:246:missing_match_atr_table: ATR     : 3b:be:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] acos5_64:257:missing_match_atr_table: ATR try : 3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] acos5_64:264:missing_match_atr_table: ATR mask: FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] acos5_64:314:acos5_64_match_card_checks: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] apdu.c:563:sc_transmit_apdu: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] card.c:352:sc_lock: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:519:pcsc_lock: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] apdu.c:530:sc_transmit: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] apdu.c:384:sc_single_transmit: called<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] apdu.c:389:sc_single_transmit: CLA:80, INS:14, P1:5, P2:0, data(0) (nil)<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:251:pcsc_transmit: reader 'ACS CryptoMate64 00 00'<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Outgoing APDU data [    5 bytes] =====================================<br>
80 14 05 00 00 .....<br>
======================================================================<br>
0x7fb2c69d5700 12:16:26.920 [opensc-tool] reader-pcsc.c:184:pcsc_internal_transmit: called<br>
0x7fb2c69d5700 12:16:26.922 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Incoming APDU data [    2 bytes] =====================================<br>
95 40 .@<br>
======================================================================<br>
0x7fb2c69d5700 12:16:26.922 [opensc-tool] apdu.c:399:sc_single_transmit: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.922 [opensc-tool] apdu.c:552:sc_transmit: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.922 [opensc-tool] card.c:392:sc_unlock: called<br>
0x7fb2c69d5700 12:16:26.922 [opensc-tool] reader-pcsc.c:556:pcsc_unlock: called<br>
0x7fb2c69d5700 12:16:26.924 [opensc-tool] acos5_64:965:acos5_64_check_sw: called for: sw1 = 0x95, sw2 = 0x40<br>
0x7fb2c69d5700 12:16:26.924 [opensc-tool] acos5_64:970:acos5_64_check_sw: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.924 [opensc-tool] apdu.c:563:sc_transmit_apdu: called<br>
0x7fb2c69d5700 12:16:26.924 [opensc-tool] card.c:352:sc_lock: called<br>
0x7fb2c69d5700 12:16:26.924 [opensc-tool] reader-pcsc.c:519:pcsc_lock: called<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] apdu.c:530:sc_transmit: called<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] apdu.c:384:sc_single_transmit: called<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] apdu.c:389:sc_single_transmit: CLA:80, INS:14, P1:6, P2:0, data(0) (nil)<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] reader-pcsc.c:251:pcsc_transmit: reader 'ACS CryptoMate64 00 00'<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Outgoing APDU data [    5 bytes] =====================================<br>
80 14 06 00 08 .....<br>
======================================================================<br>
0x7fb2c69d5700 12:16:26.925 [opensc-tool] reader-pcsc.c:184:pcsc_internal_transmit: called<br>
0x7fb2c69d5700 12:16:26.926 [opensc-tool] apdu.c:187:sc_apdu_log: <br>
Incoming APDU data [   10 bytes] =====================================<br>
41 43 4F 53 05 02 00 40 90 00 ACOS...@..<br>
======================================================================<br>
0x7fb2c69d5700 12:16:26.926 [opensc-tool] apdu.c:399:sc_single_transmit: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.926 [opensc-tool] apdu.c:552:sc_transmit: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.926 [opensc-tool] card.c:392:sc_unlock: called<br>
0x7fb2c69d5700 12:16:26.926 [opensc-tool] reader-pcsc.c:556:pcsc_unlock: called<br>
0x7fb2c69d5700 12:16:26.928 [opensc-tool] acos5_64:317:acos5_64_match_card_checks: returning with: 0 (Success)<br>
0x7fb2c69d5700 12:16:26.928 [opensc-tool] acos5_64:405:acos5_64_match_card: card matched (acos5_64)<br>
0x7fb2c69d5700 12:16:26.928 [opensc-tool] acos5_64:418:acos5_64_init: called<br>
0x7fb2c69d5700 12:16:26.928 [opensc-tool] acos5_64:465:acos5_64_init: This module initialized libsodium version: 1.0.3<br>
0x7fb2c69d5700 12:16:26.928 [opensc-tool] acos5_64:173:acos5_64_get_serialnr: called<br>
...<br>
