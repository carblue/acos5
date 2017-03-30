# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=v0.0.2)](https://travis-ci.org/carblue/acos5_64)
[![Build status](https://ci.appveyor.com/api/projects/status/1l5v35trn2ypx815?svg=true)](https://ci.appveyor.com/project/carblue/acos5-64-vr8gx)
[![Coverage Status](https://coveralls.io/repos/github/carblue/acos5_64/badge.svg?branch=master)](https://coveralls.io/github/carblue/acos5_64?branch=master)

The coverage is shown much worse than it actually is (didn't manage so far to get those lines counted as well, that are called indirectly (by OpenSC)).

# acos5_64

Driver `acos5_64`, an external modul .so/.dll for the PKCS#11,15 OpenSC framework.<br>
Compiles with DMD, LDC, GDC; shared phobos/druntime must be provided, which currently aren't included in released binaries of LDC and GDC.

Sorry, if anybody got trouble using RSA keys greater than 2048 bits with this driver; I forgot that OpenSC issue, it just hit me again when switching OpenSC releases:
  Current OpenSC releases are not prepared to use RSA keys greater than 2048 bit ! It's required to patch a release and build OpenSC from source: The patch is the closed/merged Pull Request #814  https://github.com/OpenSC/OpenSC/pull/814, also as .diff files 'framework-pkcs15_c.diff' and 'pkcs11-tool_c.diff' in folder patch_diff_for_OpenSC_upto_0.16.0.

The driver is suitable for<br>
ACS ACOS5-64 v2.00 Smart Card/CryptoMate64 USB token, and also since v0.0.5 for<br>
ACS ACOS5-64 v3.00 Smart Card/CryptoMate Nano USB token **in operation mode Non-FIPS/64K**.<br>
My interest currently is not that much in modes 'FIPS 140-2 Level 3–Compliant' or 'NSH-1', more in first completing everything for the already supported hardware and operation mode.<br>
The driver is NOT designed for ACS ACOS5 32KB (though this is one of the possible operation modes of ACOS5-64 V2/3, but this driver doesn't/won't ever support that); there is the skinny OpenSC internal driver acos5 for that and it is outdated, CryptoMate even not supported by ccid anymore.

If Your interest is in ACOS5-64 V2 Smart card/CryptoMate64, I recommend to ask ACS for the reference manual REF-ACOS5-64-1.07.pdf (or a newer version?)<br>
If Your interest is in ACOS5-64 V3 Smart card/CryptoMate Nano, I recommend to ask ACS for the reference manual REF-ACOS5-64-2.07.pdf (or a newer version?) and perhaps ACOS5-64_v3.00_Backward_Compatibility_Guide-1.00.pdf (which refers to backward compatibility with ACOS5-64 V2.<br>
Even if You don't want to go into it's details, I recommend warmly some read; and it's indispensable if You intend to customize the driver/SM/PKCS#15.

The driver currently expects, that the Security Environment files are readable without any authentication method (FIPS mode won't allow that).
Since v0.0.5: If the card is virgin from factory, it will be initialized automatically, otherwise, change SO PIN to 87654321 (hex 3837363534333231) and issue:<br>
pkcs11-tool --so-pin 87654321 --label someLabel --init-token

This is still work in progress (sadly, not all is correct or documented in ref. manuals, the comments/explanations in OpenSC's source code are quite rare, and the hardest/time consuming part is to filter driver operations into the stream of OpenSC code flow and structures), and currently there is not yet continuous Secure Messaging support implemented, though I put SM into operation in function sm_acos5_64_card_open for testing ['vi' TRY_SM may be used to check if keyset (steps b), c) ) is setup appropriately, ready for SM (You will find a log entry from function sm_acos5_64_card_open about that), then also the 'vi' SESSIONKEYSIZE24 set or not (24 or 16 byte keys) must match what is set in steps b) and c); TRY_SM_MORE may only be set if TRY_SM was successfull and if there is a transparent file 3901 created, size at least 6 bytes, with Security Condition SM for write/update (or change appropriately in source code); this actually uses SM_for_authenticity to eraze the file's contents beginning with byte 6]. Next to publish will be (re-)initialize_token, which shall significantly ease step c) and then ACOS5-64 V3 support and  C_GenerateKeyPair.

In case anybody wants to donate, I'm still in need of the latest PKCS#15 standard document ISO/IEC 7816-15:2016.

A list of functions (in terms of PKCS#11 naming), for which this card driver can/has to implement supporting code (to be called by OpenSC (OSC), aside from those that are implemented purely by OpenSC or OpenSC's implementation is sufficient for ACS ACOS5-64), stating, which are YES/NO/NOT implemented/implementable.<br>
After going through the following list (summarily: all token read-only operations should work, support of operations writing to the token is very limited though), the next step is outlined in directory [info](https://github.com/carblue/acos5_64/tree/master/info) file [compile_install_configure](https://github.com/carblue/acos5_64/blob/master/info/compile_install_configure). There is mutch info I collected and deem usefull, all in directory `info` but not yet well and finally organized/presented while still a lot is changing.

General-purpose functions:<br>
YES     C_Initialize<br>
YES     C_Finalize<br>
OpenSC  C_GetInfo<br>
OpenSC  C_GetFunctionList

Slot and token management functions:<br>
YES     C_GetSlotList<br>
OpenSC  C_GetSlotInfo<br>
YES     C_GetTokenInfo<br>
NOT     C_WaitForSlotEvent (not reasonably usable; 'blocking' unsupported by OpenSC)<br>
YES/OSC C_GetMechanismList (for RSA; howto for sym. keys?)<br>
YES/OSC C_GetMechanismInfo<br>

NO      C_InitToken       pkcs11-tool --so-pin 87654321 --label thistoken --init-token<br>
NO      C_InitPIN<br>
NO   C_SetPIN

Session management functions:<br>
     C_OpenSession (opensc only)<br>
     C_CloseSession (opensc only)<br>
     C_CloseAllSessions (opensc only)<br>
     C_GetSessionInfo (opensc only)<br>
NOT  C_GetOperationState (not supported by ACS ACOS5-64)<br>
NOT  C_SetOperationState (not supported by ACS ACOS5-64)<br>
YES  C_Login<br>
YES  C_Logout

Object management functions:<br>
??   C_CreateObject<br>
NOT  C_CopyObject (not supported by ACS ACOS5-64)<br>
NO   C_DestroyObject<br>
     C_GetObjectSize (opensc only)<br>
     C_GetAttributeValue (opensc only)<br>
??   C_SetAttributeValue<br>
     C_FindObjectsInit (opensc only)<br>
     C_FindObjects (opensc only)<br>
     C_FindObjectsFinal (opensc only)<br>

Encryption functions:<br>
C_EncryptInit (opensc only)<br>
C Encrypt (opensc only)<br>
C_EncryptUpdate (opensc only)<br>
C_EncryptFinal (opensc only)<br>

Decryption functions:<br>
     C_DecryptInit (opensc only)<br>
YES  C_Decrypt<br>
     C_DecryptUpdate (opensc only)<br>
     C_DecryptFinal (opensc only)<br>

Message digesting functions:<br>
     C_DigestInit (opensc only)<br>
     C_Digest (opensc only; ACS ACOS5-64 is capable too, but opensc is faster)<br>
     C_DigestUpdate (opensc only)<br>
NOT  C_DigestKey (not supported by ACS ACOS5-64)<br>
     C_DigestFinal (opensc only)<br>

Signing and MACing functions:<br>
     C_SignInit (opensc only)<br>
YES  C_Sign (YES for RSA, NO for computing cryptographic checksum (HMAC), though ACS ACOS5-64 is capable of)<br>
NOT  C_SignUpdate (not supported by ACS ACOS5-64)<br>
NOT  C_SignFinal (not supported by ACS ACOS5-64)<br>
?? C_SignRecoverInit<br>
?? C_SignRecover<br>

Functions for verifying signatures and MACs:<br>
<!-- C_VerifyInit (opensc only) --><br>
C_Verify (opensc only)<br>
NOT  C_VerifyUpdate (not supported by ACS ACOS5-64)<br>
NOT  C_VerifyFinal (not supported by ACS ACOS5-64)<br>
     C_VerifyRecoverInit (opensc only)<br>
     C_VerifyRecover (opensc only)<br>

Dual-function cryptographic functions:<br>
NOT supported by ACS ACOS5-64

Key management functions:<br>
yes by opensc? C_GenerateKey<br>
NO   C_GenerateKeyPair<br>
     C_WrapKey (opensc only)<br>
     C_UnwrapKey (opensc only)<br>
NOT  C_DeriveKey (not supported by ACS ACOS5-64)


Random number generation functions:<br>
NOT  C_SeedRandom (not explicitely callable to ACS ACOS5-64 but stated to be done internally)<br>
YES  C_GenerateRandom

Parallel function management functions:<br>
NOT supported by ACS ACOS5-64

Callback functions:<br>
NOT supported by ACS ACOS5-64



	C_GenerateKeyPair isn't ready, due to the complexity involved (Creating, Deleting files etc.)

	Once the files are in place, the commands to issue are akin to those:

	00A4000000         <- required: select MF
	00A40000024100     <- required: select the DF of the RSA files; also these selects make sure, SE is cleared
	00C0000032         <- optional: perhaps 32 may have to be adapted; get the File Control Information FCI
	00A40000024131     <- optional: select the RSA public  key file, just to make sure it exists and how it is sized (5+16+ NumberOfModulusBytes)
	00C0000020         <- perhaps 20 may have to be adapted
	00A400000241F1     <- optional: select the RSA private key file, just to make sure it exists and how it is sized (5+2.5*NumberOfModulusBytes), CRT style
	00C0000020         <- perhaps 20 may have to be adapted
	00200081083132333435363738       <- local/user pin verification, probably required by access conditions of RSA files
	002201B60A80011081024131950180   <- MSE for RSA public  key file
	002201B60A800110810241F1950140   <- MSE for RSA private key file
	00460000021804                   <- Generate as 3072-bit key pair, priv. for Signing    only         (last 2 bytes are 1804)
	                                 <- Generate as 3584-bit key pair, priv. for Decrypting only: replace last 2 bytes by  1C05
	                                 <- Generate as 4096-bit key pair, priv. for Sign + Decrypt:  replace last 2 bytes by  2006

If key files are created + keypair generated manually, files PrKDF and PuKDF (public key directory file) will also have to be adapted, otherwise OpenSC won't know about the newly existing key pair. Currently I'm investigating how to turn off OpenSC's (unwished) storing modulus bytes in PuKDF, which extremly blows up file size for large keys.

The driver expects RSA public  key file(s) in File IDs 413x<br>
The driver expects RSA private key file(s) in File IDs 41Fx, x hex digit being the same for pub and priv.

Be prepared, that the largest bit sizes take several minutes to be generated.<br>
Generating keys (for manual creation I use pcsc-tools) always was somewhat instable, for whatever reasons, i.e. sometimes the operation didn't succeed:<br>
With CryptoMate64, generate a 4096-bit key pair (incl. trial enc-, decryption) takes 2.5 - 3 minutes; if it takes much less, the key pair is invalid/unusable.<br>
In the end, key pair generation always succeeded with CryptoMate64 (ACOS5-64 V2.00).

Different with CryptoMateNano (ACOS5-64 V3.00):<br>
I only managed to generate key pairs up to 3328-bits in operation mode NonFips/64K. Obove that limit, the operation never succeeded and worse,<br>
sometimes did destroy some card content, leaving the card e.g. without SOPIN or files disappeared etc., MF gone, very uncomfortable.<br>
Fortunately I always got back control but a newcomer may be lost in this situation.<br>
My assumption is, it's some problem with the ccid driver and/or PC/SC? Or maybe some timeout problem, but of course there should be no run riot on the card but worst case a cancel of operation 'generate key pair'.
And another weird action occured with ACOS5-64 V3.00: Simply plugging off the CryptoMateNano started the Linux KDE sign off dialog. This disappeared now, probably because I deinstalled libccid and have libacsccid only installed or even more probable because I removed the p11-kit module for opensc-pkcs11.so (I never installed libpam-pkcs11 or alike and wouldn't dare that dependency until my driver is ready and I put everything related to the acid test).


Related to ACS ACOS5-64 I found [this](http://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works) blog, I replied to recently<br>



It will take some time to read in this repo's directory info, 'configure' the local environment including card/token next to driver compilation, as the driver's silent, uncomplaining working within the OpenSC framework depends on some things to setup once and know about some rules, the driver is following [in the following, the essential related D language conditional compilation version identifier/s (vi, vis) are included in brackets]:<br>
  a) The summary to get the driver operational on Linux/Ubuntu is in file .travis.yml (for Win32 in appveyor.yml ; less complete than for Linux, refer to info/compile_install_configure), but this omits the recommanded OpenSC patch as testing there is limited (no token present).<br>
  ---
  b) The libopensc.so|opensc.dll it can rely on, it's version  (version=OPENSC_VERSION_LATEST set or not (default is set in package 'opensc'; note, that only OpenSC v0.16.0 and v0.15.0 are supported; both should do equally well) and some other vis to check; all vis are in [info/options](https://github.com/carblue/acos5_64/blob/master/info/options))<br>
     This is mentioned first explicitly because of the tight dependancy on package https://github.com/carblue/opensc; downloading/updating the driver should be done from tagged versions only (i.e. not from master), as only those are guaranteed to be always in sync. with a dedicated opensc package version.<br>
  c) Settings in /etc/opensc/opensc.conf suitable for the driver and the features desired [e.g. ENABLE_ACOS5_64_UI, *_SM].<br>
  d) Setting up the card/token's file system/required files/contents. If it's already PKCS#15-compliant, only the keyset for SM (secure messaging) needs to be written, matching what is set in opensc.conf b).<br>
  e) Installing some build requirements (supporting libraries openssl, opensc etc., and the D build environment DUB and DMD.<br>
  f) DMD should be used in the beginning; the other compilers LDC/GDC are possible too if built from source with appropriate settings (meanwhile they also cope with building shared objects, but - as of now - compiler binary releases don't ship the required shared druntime and phobos, thus require building from source; check dub.json if adjustments are required concerning 'vis', and for compilers other than DMD: path to shared default libs for link and run (druntime and phobos)!<br>
  g) Compile and possibly, optionally place the drivers binary(s) libacos5_64.so in some OS standard library location in accordance with b).<br>
  h) Test, that the driver is recognized: opensc-tool -D, possibly switch on logging via b), e.g. debug=3, and where to log to (search in log file for load_dynamic_driver and what it reports)).<br>
  i) If You have a GitHub account and a SSH key from token associated with your account, test this: ssh -I /path/to/opensc-pkcs11.so -T git@github.com <br>
  j) More testing (with RSA keys) may be done: pkcs11-tool -l -t [temporarily only use 'vis' FAKE_SUCCESS_FOR_SIGN_VERIFY_TESTS and TRY_SUCCESS_FOR_SIGN_VERIFY_TESTS in order to get less errors or the test running at all; 5 errors I drilled-down are acceptable IMHO, as the driver can't or intentionally doesn't blindly forward everything for signing by the card's keys it get's submitted; there is more to read about details ref. signing, including the window pop-up to accept or refuse signing, if ENABLE_ACOS5_64_UI is set on Linux].<br>
  ---
  k) There are more 'vis' for refining/customizing the drivers working/features to explore later; only a few are implemented as of now.<br>
  l) Later when I'm done with writing operations, possibly customize file acos5_64.profile, but there are some rules/conventions to know about
