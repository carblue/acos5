# acos5_64

Driver `acos5_64` (shared library/DLL) for the PKCS#11,15 OpenSC framework.<br>

Not suitable for ACS ACOS5 32KB (Product Codes: ACOS5-B, ACOS5T-A (CryptoMate)); that is different hardware (I don't have this outdated one and it isn't targeted here, but by opensc internal driver acos5).
Also, none of the following cards/tokens is supported if set to Mode "Emulated 32K Mode"! (Generally, with ACS ACOS5-64 v2.00 it's not detectable by the driver, if this mode is set, but for the ACOS5-64 v3.00, the driver won't work for that mode).

Suitable for ACS ACOS5-64 v2.00:<br>
Smart Card and USB token CryptoMate64 (Product Codes: ACOS5-C1, ACOS5-C2 and ACOS5T-B2 [this is the USB token's P/N I have]); both Smart Card and USB CryptoMate64 share the same chip with 64k EEPROM and the same card operating system, both henceforth shortened to 'token' in order to denominate the hardware, opposed to 'acos' denominating the token's internal Advanced Cards Operating System.<br>
http://www.acs.com.hk/en/products/18/cryptomate64-cryptographic-usb-tokens/

Suitable for ACS ACOS5-64 v3.00, the latest version in ACS ACOS5-64 'family':<br>
Smart Card and USB Token CryptoMate Nano (Nano Product Code: ACOS5T2-B), again share a same chip (also 64k EEPROM) and acos, slightly different from ACOS5-64 v2.00.
This has several modes to select from: 1. FIPS 140-2 mode (default factory setting), 2. Non-FIPS mode (backward compatibility mode ACOS5-64 v2.00), 3. NSH-1 mode (, 4. "Emulated 32K Mode").<br>
The differences are going to be controlled by D language version identifiers: ACOSMODE_V2, ACOSMODE_V3_FIPS_140_2L3 and ACOSMODE_V3_NSH_1. Must be set according to Your token.
The debug logfile will tell You, which mode is currently set.

dub.json currently defaults to ACOSMODE_V2 (i.e. ACS ACOS5-64 v2.00  or ACS ACOS5-64 v3.00 set to Non-FIPS mode).
Currently it's not possible to operate an ACOS5-64 v2 and another ACOS5-64 v3 token at the same time (requires to differently compiled libs).

My recommendation ref. buying a crypto-card/token: First request the product's reference manual (a document that tells e.g. how to do Secure Messaging SM on byte level, even if You won't mess with those details; the overview sections may be enough to learn more about the token than from marketing flyers) and/or be shure about availability of required intermediate software (e.g. ref. PKCS#11, token being supported by OpenSC). Don't buy a black box, or You might regret that later, especially if Your OS is not Windows.

A highlight of ACOS5-64 are 4096 bit RSA keys as many as the usable EEPROM size allows for if You like, some SM possibility, and an acceptable price around $22 (v3.00 USB)+shipping cost.
As downside, it lacks direct cos support of EMSA-PSS (same as OpenSC) and it's compute_signature operation is limited to SHA1 and SHA256 for EMSA-PKCS1-v1_5, accepting hash values 20/32 bytes only (e.g. Thunderbird employs SHA512 for digesting, which can be served by the card driver only by falling back to raw RSA calculation, if the key is created for sign+decypt (AFAIK it's not advised to generate such keys)). There is no Elliptic Curve Cryptography with ACOS5-64. Half of the on-token crypto mechanisms are outdated (SHA1, DES, TDES (won't be supported by openssl anymore begining with v.1.1.0). What remains are SHA256, AES and RSA, not mutch, but sufficient for what the token is designed for. If choosing among ACOS5-64 v2.00 and ACOS5-64 v3.00, go with ACOS5-64 v3.00, which has SM-protected pin verification.

Why this driver?
The primary reason: It happend, that I got a CryptoMate64, but no Linux middleware support (at that time?) and still official Linux support ends with PC/SC which is just the very basics.
The second: It's my firm conviction, that security related software must be open source, in order to be trustable, and, my 'give back' to the open source community.
The third: To bring out the best in CryptoMate64/Nano, which no other driver known to me does, and it's fun.

OS support: Essentially limited to druntime's and dependency package opensc's limits (refer to the README of that package), though I don't know/have MAC OSX.

Some decisions had to be made while mapping PKCS#11 to this cos/token, amongst others based on the reference manual REF-ACOS5-64-1.07.pdf (ACS ACOS5-64 v2.00) and REF-ACOS5-64-2.07.pdf (ACS ACOS5-64 v3.00), available on request from http://www.acs.com.hk/en/technical-enquiry/); in other words, You will probably need a reference manual if You want to customize anything.

Like opensc (when omitting emulation), the driver expects to operate on a fully PKCS#15 compliant file structure/contents (which - to my knowledge - no token is, virgin shipped by the manufacturer [only the very basics]). Unfortunately the function to (re-) initialize the token is the most complicated one and isn't published currently, thus maybe You're going to face a hard time correcting for PKCS#15 compliance on Your token manually for interesting functionality like signing to work.<br>

The driver "requires" the latest OpenSC installation (or more precisely, the functionality available from this binary), that's version 0.16.0 currently, otherwise You won't get but the very basics from the driver and no real fun. Users with version 0.15.0 installation, who don't want to upgrade to 0.16.0, must either way make available to the driver functions sc_pkcs1_strip_01_padding and sc_pkcs1_strip_02_padding (patch OpenSC source to export them or implement them) and also patch this code in some places where version(OPENSC_VERSION_LATEST) is involved.

This is still work in progress (sadly, not all is correct in ref. manuals and comments in opensc's source code (if any at all), and the hardest/time consuming part is to filter cos operations into the stream of opensc code flow and structures) and currently there is not yet continuous Secure Messaging support implemented, though I put SM into operation in function acos5_64_init for testing.

In case anybody wants to donate, I'm still in need of the latest PKCS#15 standard document ISO/IEC 7816-15:2016.

A list of functions (in terms of PKCS#11 naming), for which this card driver can/has to implement supporting code (to be called by opensc, aside from those that are implemented purely by opensc or opensc's implementation is sufficient for ACS ACOS5-64), stating, which are YES/NO/NOT implemented/implementable.<br>
After going through the following list (summarily: all token read-only operations should work, support of operations writing to the token is very limited though), the next step is outlined in directory `info` file `compile_install_configure`. There is mutch info I collected and deem usefull, all in directory `info`

General-purpose functions:<br>
YES  C_Initialize<br>
YES  C_Finalize<br>
<!-- C_GetInfo (opensc only) --><br>
YES  C_GetFunctionList
 
Slot and token management functions:<br>
<!-- C_GetSlotList (opensc only) --><br>
<!-- C_GetSlotInfo (opensc only) --><br>
YES  C_GetTokenInfo<br>
NOT  C_WaitForSlotEvent (not supported by ACS ACOS5-64)<br>
YES  C_GetMechanismList (for RSA; howto for sym. keys?)<br>
YES  C_GetMechanismInfo (for RSA; howto for sym. keys?)<br>
NO   C_InitToken<br>
NO   C_InitPIN<br>
NO   C_SetPIN

Session management functions:<br>
<!-- C_OpenSession (opensc only) --><br>
<!-- C_CloseSession (opensc only) --><br>
<!-- C_CloseAllSessions (opensc only) --><br>
<!-- C_GetSessionInfo (opensc only) --><br>
NOT  C_GetOperationState (not supported by ACS ACOS5-64)<br>
NOT  C_SetOperationState (not supported by ACS ACOS5-64)<br>
YES  C_Login<br>
YES  C_Logout

Object management functions:<br>
??   C_CreateObject<br>
NOT  C_CopyObject (not supported by ACS ACOS5-64)<br>
NO   C_DestroyObject<br>
<!-- C_GetObjectSize (opensc only) --><br>
<!-- C_GetAttributeValue (opensc only) --><br>
??   C_SetAttributeValue<br>
<!-- C_FindObjectsInit (opensc only) --><br>
<!-- C_FindObjects (opensc only) --><br>
<!-- C_FindObjectsFinal (opensc only) --><br>

Encryption functions:<br>
<!-- C_EncryptInit (opensc only) --><br>
<!-- C Encrypt (opensc only) --><br>
<!-- C_EncryptUpdate (opensc only) --><br>
<!-- C_EncryptFinal (opensc only) --><br>

Decryption functions:<br>
<!-- C_DecryptInit (opensc only) --><br>
YES  C_Decrypt<br>
<!-- C_DecryptUpdate (opensc only) --><br>
<!-- C_DecryptFinal (opensc only) --><br>

Message digesting functions:<br>
<!-- C_DigestInit (opensc only) --><br>
<!-- C_Digest (opensc only; ACS ACOS5-64 is capable too, but opensc is faster) --><br>
<!-- C_DigestUpdate (opensc only) --><br>
NOT  C_DigestKey (not supported by ACS ACOS5-64)<br>
<!-- C_DigestFinal (opensc only) --><br>

Signing and MACing functions:<br>
<!-- C_SignInit (opensc only) --><br>
YES  C_Sign (YES for RSA, NO for computing cryptographic checksum (HMAC), though ACS ACOS5-64 is capable of)<br>
NOT  C_SignUpdate (not supported by ACS ACOS5-64)<br>
NOT  C_SignFinal (not supported by ACS ACOS5-64)<br>
?? C_SignRecoverInit<br>
?? C_SignRecover<br>

Functions for verifying signatures and MACs:<br>
<!-- C_VerifyInit (opensc only) --><br>
<!-- C_Verify (opensc only) --><br>
NOT  C_VerifyUpdate (not supported by ACS ACOS5-64)<br>
NOT  C_VerifyFinal (not supported by ACS ACOS5-64)<br>
<!-- C_VerifyRecoverInit (opensc only) --><br>
<!-- C_VerifyRecover (opensc only) --><br>

Dual-function cryptographic functions:<br>
NOT supported by ACS ACOS5-64

Key management functions:<br>
yes by opensc? C_GenerateKey<br>
NO   C_GenerateKeyPair<br>
<!-- C_WrapKey (opensc only) --><br>
<!-- C_UnwrapKey (opensc only) --><br>
NOT  C_DeriveKey (not supported by ACS ACOS5-64)
 

Random number generation functions:<br>
NOT  C_SeedRandom (not explicitely callable to ACS ACOS5-64 but stated to be done internally)<br>
YES  C_GenerateRandom
 
Parallel function management functions:<br>
NOT supported by ACS ACOS5-64

Callback functions:<br>
NOT supported by ACS ACOS5-64
