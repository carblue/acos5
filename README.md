# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=v0.0.2)](https://travis-ci.org/carblue/acos5_64)
[![Build status](https://ci.appveyor.com/api/projects/status/1l5v35trn2ypx815?svg=true)](https://ci.appveyor.com/project/carblue/acos5-64-vr8gx)

# acos5_64

Driver `acos5_64` (shared library/DLL) for the PKCS#11,15 OpenSC framework.<br>
Compiles with DMD, LDC, GDC; shared phobos/druntime must be provided, which currently aren't included in released binaries of LDC and GDC.

Sorry, if anybody got trouble using RSA keys greater than 2048 bits with this driver. I forgot this OpenSC issue, it just hit me again:
  Current OpenSC releases are not prepared to use RSA keys greater than 2048 bit ! It's required to patch and build OpenSC from source: The patch is the closed/merged Pull Request #814  https://github.com/OpenSC/OpenSC/pull/814, also as .diff files 'framework-pkcs15_c.diff' and 'pkcs11-tool_c.diff' in folder patch_diff_for_OpenSC_upto_0.16.0.

The driver currently expects, that the Security Environment files are readable without any authentication method, otherwise search 3132333435363738 in source code and follow instructions.

It will take some time to read in directory info, 'configure' the local environment including card/token next to driver compilation, as the driver's silent, uncomplaining working within the OpenSC framework depends on some things to setup once and know about some rules, the driver is following [in the following, the essential related D language conditional compilation version identifier/s (vi, vis) are included in brackets]:<br>
  a) The summary to get the driver operational on Linux/Ubuntu is in file .travis.yml (for Win32 in appveyor.yml ; basic building, not complete, refer to info/compile_install_configure)<br>
  ---
  b) The libopensc.so|opensc.dll it can rely on, it's version  [version=OPENSC_VERSION_LATEST set or not (default is set in package 'opensc'; note, that only OpenSC v0.16.0 and v0.15.0 are supported; both should do equally well) and some other vis to check]<br>
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

The driver is currently suitable for the ACS ACOS5-64 v2.00 Smart Card and CryptoMate64 USB token, soon also for the announced ACS ACOS5-64 v3.00 (I'm still waiting on availability for tests with a CryptoMate Nano). ACS ACOS5-64 v3.00 will require more 'vis' to distinguish different modes the card/token may be set to. Therefore currently vi ACOSMODE_V2 is set (which will also serve ACS ACOS5-64 v3.00 in the non-factory-default-setting operation mode "ACOS5-64 v2.00 backward compatibility")<br>
The driver is NOT designed for ACS ACOS5 32KB; there is the skinny OpenSC internal driver acos5 for that.


This is still work in progress (sadly, not all is correct or documented in ref. manuals, the comments in OpenSC's source code are quite rare, and the hardest/time consuming part is to filter driver operations into the stream of OpenSC code flow and structures), and currently there is not yet continuous Secure Messaging support implemented, though I put SM into operation in function sm_acos5_64_card_open for testing ['vi' TRY_SM may be used to check if keyset (steps b), c) ) is setup appropriately, ready for SM (You will find a log entry from function sm_acos5_64_card_open about that), then also the 'vi' SESSIONKEYSIZE24 set or not (24 or 16 byte keys) must match what is set in steps b) and c); TRY_SM_MORE may only be set if TRY_SM was successfull and if there is a transparent file 3901 created, size at least 6 bytes, with Security Condition SM for write/update (or change appropriately in source code); this actually uses SM_for_authenticity to eraze the file's contents beginning with byte 6]. Next to publish - after SM is finalized - will be reinitialize_token, which shall significantly ease step c)

In case anybody wants to donate, I'm still in need of the latest PKCS#15 standard document ISO/IEC 7816-15:2016.

A list of functions (in terms of PKCS#11 naming), for which this card driver can/has to implement supporting code (to be called by OpenSC (OSC), aside from those that are implemented purely by OpenSC or OpenSC's implementation is sufficient for ACS ACOS5-64), stating, which are YES/NO/NOT implemented/implementable.<br>
After going through the following list (summarily: all token read-only operations should work, support of operations writing to the token is very limited though), the next step is outlined in directory `info` file `compile_install_configure`. There is mutch info I collected and deem usefull, all in directory `info` but not yet well and finally organized/presented while still a lot is changing.

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

I found [this](http://changelog.complete.org/archives/9358-first-steps-with-smartcards-under-linux-and-android-hard-but-it-works)<br>

