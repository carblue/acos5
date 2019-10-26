The procedure of card initialization
====================================
OpenSC in general has provisions for this task, but I didn't implemement this (so far, and havn't made up my mind if I ever will do).<br>
Instead I provide this way based on scripts to initialize Your ACOS5-64 V2.00 or ACOS5-64 V3.00 card/token: It allows the ultimate control over what will be done.<br>
With knowledge from the reference manual You can adapt everything to Your heart's content, but I recommend to start with what is provided: With incorrect commands it's easy to render Your card unusable, in the worst case exclude Yourself from the card.

scriptor from package pcsc-tools (see http://ludovic.rousseau.free.fr/softwares/pcsc-tools/) or some equivalent tool that can send APDUs to a smart card will be required.

The bulk of initialization will be done by script card_initialization.scriptor:
1. Adapt the script referring to old SOPIN and whether the line for V2.00 or for V3.00 has to be executed (see explanation inside the script: comments).
2. With Linux: Make sure that a tool like scriptor is available (in the following I will assume scriptor) and that the file's access rigths are set to 'executable'. Invoke<br>
./card_initialization.scriptor

The remaining is optional but recommended adaption to Your specific settings. Invoke<br>
opensc-tool --serial

Some adjustion will be done for file 0x3F0041005032 PKCS#15 EF.TokenInfo by one of the V?_00_TokenInfo_file_customization.scriptor<br>
1. Adapt the script referring to content (see explanation inside the script: comments).
2. With Linux: Invoke for Your V2_00 or V3_00 hardware either ./V2_00_TokenInfo_file_customization.scriptor or ./V3_00_TokenInfo_file_customization.scriptor

Some adjustion will be done for file 0x3F0041005031 PKCS#15 EF.ODF by ODF_file_customization.scriptor<br>
1. Adapt the script referring to content (see explanation inside the script: comments).
2. With Linux: Invoke ./ODF_file_customization.scriptor

Set new PINs (e.g. with opensc-explorer)

Add new content, e.g. RSA key pair (either with tool acos5_gui or the following command) and<br>
read public RSA file content for e.g. placing that in Your GitHub settings:<br>
```
pkcs15-init --generate-key rsa/3072 --auth-id 01 --id 01 --label testkey --key-usage sign,decrypt
pkcs15-tool --read-ssh-key 01
-- GitHub settings --
ssh -T git@github.com
```

Add new content, e.g. sym. key (either with tool acos5_gui or the following command).Invoke<br>
TODO not yet ready

Import a certificate for Your RSA key pair (not yet tested how to do that)


Foresight
=========

Basically I want a backup/clone of my CryptoMate64 (content) to be placed e.g. in a safe. Therefore there are plans, that acos5_gui will have an import/export feature.
Then, card initialization will also be possible as import from such an archive/export.
This will be tricky though, as I don't plan to have secrets on card (RSA private keys, sym. keys) ever be readable.
