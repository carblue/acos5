# acos5_64

Driver `acos5_64` (shared library/DLL) for the OpenSC framework.<br>

Suitable for ACS ACOS5-64 v2.00:<br>
Smart Card and USB token CryptoMate64 (Product Codes: ACOS5-C1, ACOS5-C2 and ACOS5T-B2 [this is the USB token's P/N I have]); both Smart Card and USB CryptoMate64 share the same chip with card operating system ACOS5-64 v2.00 and a 64k EPROM, both henceforth shortened to 'token' in order to denominate the hardware, opposed to 'cos' denominating the token's internal card operating system.<br>
http://www.acs.com.hk/en/products/18/cryptomate64-cryptographic-usb-tokens/

The brand-new ACS ACOS5-64 V3.00: Smart Card and USB token CryptoMate Nano (Product Code: ACOS5T2-B), again share a same chip with a 64k EEPROM, but I've no clue if the driver is suitable (but those at least have backward compatibility mode to ACOS5-64 v2.00).<br>
If someone has this new version token, wants to try this driver in regular (non-backward-compatibility-mode) and it doesn't work out of the box (i.e. the logfile shows function acos5_64_match_card_checks returning with error), do the following and PLEASE communicate Your results here: https://github.com/carblue/acos5_64/issues :<br>
Search in file source/acos5_64.d for the string (inside quotes) "call 7.3.1. Get Card Info" and follow the instructions given there.

A highlight of CryptoMate64 are 4096 bit RSA keys as many as the EEPROM size allows for, SM possibility, and an acceptable price below 30€.
As downside, it lacks cos support of EMSA-PSS and it's compute_signature operation is limited to SHA1 and SHA256 for EMSA-PKCS1-v1_5, accepting hash values 20/32 bytes only (e.g. Thunderbird employs SHA512 for digesting, which can be served by the card driver only by falling back to raw RSA calculation, if key is created for sign+decypt).
 
Some decisions had to be made while mapping PKCS#11 to this cos/token, amongst others based on the reference manual REF-ACOS5-64-1.07.pdf (this or a successor is available on request from http://www.acs.com.hk/en/technical-enquiry/); in other words, You will probably need the reference manual if You want to customize anything.

Like opensc (when omitting emulation), the driver expects to operate on a fully PKCS#15 compliant file structure/contents (which - to my knowledge - no token is, virgin shipped by the manufaturer [only the very basics]). Unfortunately the function to (re-) initialize the token is the most complicated one and isn't implemented currently, thus maybe You're going to face a hard time correcting PKCS#15 on Your token manually for interesting functionality like signing to work.<br>

This is still work in progress (sadly, the hardest/time consuming part is to filter cos operations into the stream of opensc code flow and structures) and currently there is no Secure Messaging support, though planned to be implemented later.

In case anybody wants to donate, I'm still in need of the latest PKCS#15 standard document ISO/IEC 7816-15:2016.

A list of functions (in terms of PKCS#11 naming), for which this card driver can/has to implement supporting code (to be called by opensc, aside from those that are implemented purely by opensc or opensc's implementation is sufficient for ACS ACOS5-64), stating, which are YES/NO/NOT implemented/implementable.<br>
After going through the following list (summarily: all read-only operations should work, writing support is limited though), the next step is outlined in directory `info` file `compile_install_configure`.

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
NO?  C_GenerateKeyPair<br>
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
