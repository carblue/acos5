This is meant to be used as a separate cargo project.
If You don't have installed the Rust compiler rustc and build tool cargo, get it bundled from
https://www.rust-lang.org/tools/install

It uses crate pkcs11, which encapsulates all calls to cryptoki, thus You won't see any calls like C_Initialize etc.
in the first place.
Currently I'm about to change from crate pkcs11 to crate cryptoki.
We need to name the cryptoki library - here opensc-pkcs11.so - or it's alternate namings for other OS: 
let ctx = Ctx::new_and_initialize("opensc-pkcs11.so")?;

It's assumed that driver components libacos5.so *AND* libacos5_pkcs15.so are installed and opensc.conf updated to use them.
But, the code may be used as well for any card supported by OpenSC.

All applications "C_Login" into Your card as User with PIN 12345678:
Either change Your card's User PIN temporarily to "12345678" or change the source code with Your actual User PIN.


The src/ directory contains several main_* files, each for a different application, some don't change card content
(main_RO*), while others do so, ReadWrite (main_RW*). Currently:

main.rs == main_RO_inspect_keys.rs  
main_RW_create_key_pair.rs  
main_RO_sym_decrypt.rs  
main_RO_sym_encrypt.rs  

Rename the main_* file You are interested in (only 1 at a time) to main.rs and run it via  
$ cd project_pkcs11_example_apps  
$ cargo run


**Notes referring to  main_RW_create_key_pair.rs** (ref. driver acos5_external):  
It will change Your cards contents:
New public and private key files will be created, sized to exactly match the requirements and with file ids selected 
by the driver, something like 0x5000, 0x5001 or higher values.
modulus_bits : CK_ULONG = 1024; This is not recommended for production use; used here just to demonstrate that it works
and to save time. For high modulus_bits, generation takes considerable time, up to ~ 5 min for 4096 bit !

Note that PKCS#11/OpenSC doesn't allow to individually set all options for RSA key pair generation that ACOS5 provides.
Therefore the driver defaults to create the private RSA key with CRT data and the key capable to sign **and** decrypt.
(the tool acos5_gui allows to set those options).

With ACOS5 V2.00 we can generate a keypair with bitLen 4096, while ACOS5 V3.00 must be in operation mode "64K (backward compatibility with V2.00"),
otherwise allows max. 3072 bit only.
Occasionally the ACOS5 chip fails to generate the keys for large moduli (I assume, its a timing issue when generation and
trial encryption/decryption takes to much time), but in general it should work (just retry).
The same can be achieved by invoking  
pkcs15-init -G rsa/1024 -a 01 -i a1 -l mykey -u sign,decrypt,unwrap


**Notes referring to  main_RO_sym_decrypt.rs:**  


**Notes referring to  main_RO_sym_encrypt.rs:**  

