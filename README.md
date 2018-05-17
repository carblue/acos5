# Build state

[![Build Status](https://travis-ci.org/carblue/acos5_64.svg?branch=master)](https://travis-ci.org/carblue/acos5_64)

# acos5_64

ACS ACOS5-64/CryptoMate64/CryptoMateNano driver/SM/PKCS#15 external module for the OpenSC framework.<br>

Linux binaries from recent sources are available at:<br>
https://github.com/carblue/acos5_64_gui/tree/master/opensc_0.18.0<br>
https://github.com/carblue/acos5_64_gui/tree/master/opensc_0.17.0<br>

Releasing source code to anonymous recipients got discontinued since April 2017.<br>
Thus part of what's here get's increasingly outdated.

---

Restricted to Non-FIPS/64K operation mode setting !<br>
If the card/token is virgin from factory (no MF), it will be switched to Non-FIPS/64K mode and initialized (by any tool, that invokes acos5_64_init, e.g. opensc-tool --serial). Initial "CODES PINS" to be looked up in source code.<br>
For tweaking init/reinit/zeroize card/token, search for CHANGE_HERE_FOR_  in source code.<br>
FIPS mode (if at all) won't be supported before full SM implementation is done and the final Non-FIPS/64K mode will be close to FIPS mode, but e.g. not exclude 4096 bit keys.<br>
Bear in mind to copy opensc/source/pkcs15init/acos5_64.profile to /usr/share/opensc for C_GenerateKeyPair to work (file locations are restricted as per acos5_64.profile).<br>
Fine-tuning the kind of priv. key to be generated doesn't seem to be possible through OpenSC. CRT_for_* enum members are usable for that.<br>
Creating RSA key pairs may take (depending on bit size) several minutes, typically 3-4 minutes for 4096 bit with ACOS5-64 V2.00; ACOS5-64 V3.00 takes longer and doesn't succeed with the largest key sizes (probably some timeout-related problem within the PC/SC layer)<br>
Currently I can't control, what OpenSC writes to PuKDF (file 4113) and thus requires some manual post-processing of the associated entry:<br>
1. Storing the modulus and public exponent inside PuKDF is undesirable, as a freely accessible public key file 3F004100413x does exist, providing that information (apart from that the modulus written is wrong): replace by path to public key file.<br>
2. CommonKeyAttributes.native is wrong; it should read TRUE<br>
3. keyReference is wrong; it's value should be the same as choosen by --id<br>
As an example: 303530110C0B446563727970745369676E03020640300E0401010302018203020348020101A110300E300804063F004100413102021000

Work in progress.

Contributions like writing docmentation/code, borrow latest PKCS#15 standard document ISO/IEC 7816-15:2016 are welcome.

A list of functions (in terms of PKCS#11 naming), for which this card driver can/has to implement supporting code (to be called by OpenSC, aside from those that are implemented by OpenSC), stating, which are YES/NO/NOT implemented/implementable.<br>

	General-purpose functions:
	YES         C_Initialize
	YES         C_Finalize
	OpenSC      C_GetInfo
	OpenSC      C_GetFunctionList

	Slot and token management functions:
	YES         C_GetSlotList
	OpenSC      C_GetSlotInfo
	YES         C_GetTokenInfo
	NOT         C_WaitForSlotEvent (not reasonably usable; 'blocking' unsupported by OpenSC)
	YES/OpenSC  C_GetMechanismList (for RSA; howto for sym. keys?)
	YES/OpenSC  C_GetMechanismInfo
	YES         C_InitToken   usage e.g.: pkcs11-tool --init-token --so-pin 8BYTESOPIN --label LABEL_NOT_PROCESSED (requires source code uncommenting at CHANGE_HERE_FOR_REINIT)
	NO          C_InitPIN
	NO          C_SetPIN

	Session management functions:
	OpenSC      C_OpenSession
	OpenSC      C_CloseSession
	OpenSC      C_CloseAllSessions
	OpenSC      C_GetSessionInfo
	NOT         C_GetOperationState (not supported by ACS ACOS5-64)
	NOT         C_SetOperationState (not supported by ACS ACOS5-64)
	YES         C_Login
	YES         C_Logout

	Object management functions:
	??/NO       C_CreateObject
	NOT         C_CopyObject (not supported by ACS ACOS5-64)
	NO          C_DestroyObject
	OpenSC      C_GetObjectSize
	OpenSC      C_GetAttributeValue
	??          C_SetAttributeValue
	OpenSC      C_FindObjectsInit
	OpenSC      C_FindObjects
	OpenSC      C_FindObjectsFinal

	Encryption functions:
	OpenSC      C_EncryptInit
	OpenSC      C Encrypt
	OpenSC      C_EncryptUpdate
	OpenSC      C_EncryptFinal

	Decryption functions:
	OpenSC      C_DecryptInit
	YES         C_Decrypt
	OpenSC      C_DecryptUpdate
	OpenSC      C_DecryptFinal

	Message digesting functions:
	OpenSC      C_DigestInit
	OpenSC      C_Digest (opensc only; ACS ACOS5-64 is capable too, but opensc is faster)
	OpenSC      C_DigestUpdate
	NOT         C_DigestKey (not supported by ACS ACOS5-64)
	OpenSC      C_DigestFinal

	Signing and MACing functions:
	OpenSC      C_SignInit (opensc only)
	OpenSC      C_Sign (YES for RSA, NO for computing cryptographic checksum (HMAC), though ACS ACOS5-64 is capable of)
	NOT         C_SignUpdate (not supported by ACS ACOS5-64)
	NOT         C_SignFinal  (not supported by ACS ACOS5-64)
	??          C_SignRecoverInit
	??          C_SignRecover

	Functions for verifying signatures and MACs:
	OpenSC      C_VerifyInit
	OpenSC      C_Verify
	NOT         C_VerifyUpdate (not supported by ACS ACOS5-64)
	NOT         C_VerifyFinal  (not supported by ACS ACOS5-64)
	??/OpenSC   C_VerifyRecoverInit
	??/OpenSC   C_VerifyRecover

	Dual-function cryptographic functions:
	NOT supported by ACS ACOS5-64

	Key management functions:
	??/OpenSC   C_GenerateKey
	YES         C_GenerateKeyPair   usage e.g.: pkcs11-tool -l --keypairgen --key-type rsa:4096 --id 01 --label "someLabel" (due to some CCID/ACS CCID PC/SC driver? problem, currently limit keybits to max. 3072(3328) for new ACOS5-64 V3.00, yet max. 4096 is okay for ACOS5-64 V2.00)
	??/OpenSC   C_WrapKey
	??/OpenSC   C_UnwrapKey
	NOT         C_DeriveKey (not supported by ACS ACOS5-64)

	Random number generation functions:
	NOT         C_SeedRandom (not explicitely callable; ACS ACOS5-64 states to do that internally (non-deterministic))
	YES         C_GenerateRandom

	Parallel function management functions:
	NOT supported by ACS ACOS5-64

	Callback functions:
	NOT supported by ACS ACOS5-64
