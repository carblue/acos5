The procedure of card initialization
====================================

To be explicit: Card initialization removes all user data from the card such that it will be virgin afterwards,
and then installs the basic file structure required by PKCS#15. Many file ids are inspired by what the ACS tool does,
also some file content, e.g. content of EF.DIR.

If Your card was initialized already by other means, then that was probably done by an ACS tool. I don't recall all
reasons for a need to re-initialization (except i.a. a catch-22), but instead will provide a sanity-check (accessible via
pkcs15-init --sanity-check). This will print to stdout everything notable about Your card's content.
The catch-22 with ACS tool card initialization is, that any (Security Environment) SE-file (which provides information
i.a. about how to do PIN verification) is readable only after PIN verification has been completed.

Note, that the philosophy of OpenSC is to have free access (reading always allowed or SM constraints satisfiable without
any PIN entry) to PKCS#15 directory file EF.DIR and PKCS#15 object directory file EF.ODF and to all what they point to.
Also to EF.TokenInfo. The driver requires free access to all SE-files.

OpenSC in general has provisions for card initialization, but I didn't implement this (so far, and havn't made up my
mind if I ever will do).<br>
Instead I provide script `card_initialization.scriptor` to initialize Your ACOS5-64 V2.00 or ACOS5-64 V3.00 card/token:
It allows the ultimate control over what will be done. (Or, if You want to do card initialization manually, invoke
pkcs15-init --erase-card  and continue on Your own).<br>
With knowledge from the reference manual You can adapt everything in the script to Your heart's content, but I recommend
to start with what is provided: With incorrect commands it's easy to render Your card unusable, in the worst case
exclude Yourself from the card.

In order to enable secured pin entry with ACOS5-64 V3.00 card/token: There is a special
V3_00_card_initialization_secured_pin.scriptor. It differs from card_initialization.scriptor only in that it uses the
SAE tag 0xAB for directories in which pin commands are forced to use Secure Messaging (SM) in order to send pins
encrypted to the card for commands 'pin verify', 'pin change' and 'pin unblock'.
Note that the keys written to file 0x3F0041004102 Local Symmetric Key file and within opensc.conf under
keyset_41434F53504B43532D313576312E3030_02_* MUST MATCH. Any mistake with that entails impossibility to verify pins.

Note, that current card_initialization.scriptor *DOES NOT* force anything to happen protected by SM, though there are
records #5 and #6 in file 0x3F0041004103 that may be used for SM inside PKCS#15 Application DF 0x3F004100.
I recommend to use SM gradually and get used to it, e.g. by removing comment characters from lines 131-134 in
card_initialization.scriptor.
This will then create a test file sized 16 bytes, that i.a. forces read_binary to use SM as specified in record #6,
i.e. transmit response encrypted, the driver will then decrypt and e.g. opensc-tool -f will display that plain text.
If opensc-tool -f doesn't display any content, then SM is not setup correctly (keys in file 0x4102 and/or keyset* in
opensc.conf; see details in opensc-debug.log).

But, don't rely too much on 'Secure' Messaging if Your crypto card/token is plugged into a hostile environment: An
attacker, that controls the computer can eavedrop the card <-> terminal communication and can read the opensc.conf
file and hence reconstruct the generated session keys. Well, I can think of ways to enhance SM's security for ACOS5,
but thats not disclosable publicly.

scriptor from package pcsc-tools (see https://pcsc-tools.apdu.fr/) or some equivalent tool
that can send APDUs to a smart card in batch mode will be required.

The bulk of initialization will be done by script `card_initialization.scriptor`:
1. Adapt the script referring to old SOPIN and whether the line for V2.00 or for V3.00 has to be executed (see
   explanation inside the script: comments).
2. With Linux: Make sure that a tool like scriptor is available (in the following I will assume scriptor) and that the
   file's access rigths are set to 'executable'. Invoke<br>
   ./card_initialization.scriptor

The remaining is optional but recommended adaption to Your specific settings. Invoke<br>
opensc-tool --serial

Some adjustion will be done for file 0x3F0041005032 PKCS#15 EF.TokenInfo by one of the
V?_00_TokenInfo_file_customization.scriptor<br>
The adaption is related to Your individual card's harware serial no. and token label, that will be part of how
OpenSC refers to this hardware when communicating with You (e.g. asking for a User PIN)<br>
1. Adapt the script referring to content (see explanation inside the script: comments).
2. With Linux: Invoke for Your V2_00 or V3_00 hardware either ./V2_00_TokenInfo_file_customization.scriptor or
   ./V3_00_TokenInfo_file_customization.scriptor

Some adjustion will be done for file 0x3F0041005031 PKCS#15 EF.ODF by ODF_file_customization.scriptor<br>
The adaption is related to: Some performance gain can be achieved, if OpenSC doesn't need to analyse all PKCS#15
directory files, because e.g. Your card has no Data Object files or no PUKDF_TRUSTED asym. keys etc.
1. Adapt the script referring to content (see explanation inside the script: comments).
2. With Linux: Invoke ./ODF_file_customization.scriptor

Set new PINs (e.g. with opensc-explorer)

Add new content, e.g. RSA key pair (either with tool acos5_gui or the following command) and<br>
read public RSA file content for e.g. placing that in Your GitHub settings and then test the ssh connection:<br>
```
pkcs15-init --generate-key rsa/4096 --auth-id 01 --id 09 --label testkey --key-usage sign,decrypt
pkcs15-tool --read-ssh-key 09
-- GitHub settings --
ssh -T -I /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so git@github.com

Response on success: Hi your_github_name! You've successfully authenticated, but GitHub does not provide shell access.
```

Add new content, e.g. sym. key (either with tool acos5_gui or the following command).  
With a hex editor, craft a file e.g. aes_key_256.hex with exactly as many key bytes as required for the specified key
type (32 bytes in this example). Invoke e.g.<br>
$ pkcs15-init --store-secret-key aes_key_256.hex --secret-key-algorithm aes/256  --auth-id 01 --id 02 --verify-pin

Import a certificate for Your RSA key pair (not yet tested)  
$ pkcs15-init --store-certificate some.cert.pem --auth-id ?? --id ?? --format pem --pin ??

Besides what You always can do manually with a card with tools like scriptor or gscriptor, referring to secret keys
(symmetric or asymmetric algorithm keys), the tandem of `card_initialization.scriptor` and acos5_external driver
won't let You get out of the card (export) any secret key material.
Getting secret key material into the card (import) is limited to symmetric algorithm keys, either by command  
pkcs15-init --store-secret-key   or  
unwrap an AES key into Your card (which was wrapped by one of Your public keys). That one (the latter) currently will be stored permanently,
though there are plans to allow that temporarily as well (OpenSC has a flag for that: SC_CARD_CAP_ONCARD_SESSION_OBJECTS, since OpenSC version 0.20.0

The difference is, that with CKA_TOKEN=FALSE (== SC_CARD_CAP_ONCARD_SESSION_OBJECTS enabled) OpenSC won't add an SKDF entry while unwrapping that key, but the driver will still write that key to card. That key effectively exists on card until the next symmetric algorithm key import occurs, which will overwrite into the record no. occupied before "temporarily".

Foresight
=========

Basically I want a backup/clone of my CryptoMate64 (content) to be placed e.g. in a safe. Therefore there are plans,
that acos5_gui will have an import/export feature.
Then, card initialization will also be possible as import from such an archive/export.
This will be tricky though, as I don't plan to have secrets on card (RSA private keys, sym. keys) ever be readable.
