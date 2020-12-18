Design rationale for `symmetric on-card/hardware crypto support in OpenSC` and comments  
This file is now identically also within:  
repo at https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt  

1. Its implemented in an imaginary OpenSC version  0.22.0-sym_hw_encrypt (which is my driver's way to address  OpenSC github master, i.e. all not yet released).

2. The implementation is limited to support only  
   - AES, as its the only sym. algo registered with PKCS#11 currently.  
     (e.g. the blocksize 16 is hardcoded),  and impl. is limited to  
   - C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt.   (C_WrapKey, C_UnwrapKey are already supported by OpenSC, thanks to Hannu Honkanen)

   Actually the code was copied from existing code in same file(s), adapted as I deemed required.

3. struct sc_card_operations got extended by functions `encrypt_sym` and `decrypt_sym` (assuming, that decipher is reserved for asym. algos)

4. currently these algorithm_flags are defined for AES in OpenSC
```
/* symmetric algorithm flags. More algorithms to be added when implemented. */
#define SC_ALGORITHM_AES_ECB           0x01000000
#define SC_ALGORITHM_AES_CBC           0x02000000
#define SC_ALGORITHM_AES_CBC_PAD       0x04000000
#define SC_ALGORITHM_AES_FLAGS         0x0F000000
```
   All 3 mechanisms CKM_AES_ECB, CKM_AES_CBC and SC_ALGORITHM_AES_CBC_PAD are supported and a card driver willing to support symmetric on-card crypto must declare at least 1 of them with _sc_card_add_symmetric_alg.  
   Nothing (in the impl.) precludes us from adding more  SC_ALGORITHM_AES_*, if required (it's just my card not supporting more), except that requires slight adaptions in mapping to  CKM_AES_*  back and forth.

5. The implementation was done with extensibility for other sym. algorithms in mind

6. The implementation supports setting struct sc_security_env field algorithm_ref from TokenInfo.supportedAlgorithms and field flags |= SC_SEC_ENV_ALG_REF_PRESENT (if applicable), i.e. the card specific algorithm/algorithm_flags encoding)

7. The (essential) call stacks:
```
pkcs11/pkcs11-object.c    C_EncryptInit  
pkcs11/mechanism.c          sc_pkcs11_encr_init  
pkcs11/misc.c                 session_start_operation  
pkcs11/mechanism.c            sc_pkcs11_encrypt_init  
                                can_do            currently its NULL

pkcs11/pkcs11-object.c    C_Encrypt  
pkcs11/mechanism.c          sc_pkcs11_encr  
pkcs11/mechanism.c            sc_pkcs11_encrypt  
pkcs11/framework-pkcs15.c       pkcs15_skey_encrypt  
libopensc/pkcs15-sec.c            sc_pkcs15_encrypt_sym  
                                    format_senv  
libopensc/padding.c                 sc_get_encoding_flags  
libopensc/pkcs15-sec.c              use_key_sym(p15card, obj, &senv, sc_encrypt_sym, in, inlen, out, outlen)  
                                      select_key_file  
                                      sc_set_security_env  
libopensc/sec.c                         sc_encrypt_sym  
libopensc/card_driver                     card->ops->encrypt_sym

pkcs11/pkcs11-object.c    C_DecryptInit  
pkcs11/mechanism.c          sc_pkcs11_decr_init  
pkcs11/misc.c                 session_start_operation  
pkcs11/mechanism.c            sc_pkcs11_decrypt_init  
                                can_do            currently its NULL

pkcs11/pkcs11-object.c    C_Decrypt  
pkcs11/mechanism.c          sc_pkcs11_decr  
pkcs11/mechanism.c            sc_pkcs11_decrypt  
pkcs11/framework-pkcs15.c       pkcs15_skey_decrypt  
libopensc/pkcs15-sec.c            sc_pkcs15_decrypt_sym  
                                    format_senv  
libopensc/padding.c                 sc_get_encoding_flags  
libopensc/pkcs15-sec.c              use_key_sym(p15card, obj, &senv, sc_decrypt_sym, in, inlen, out, outlen)  
                                      select_key_file  
                                      sc_set_security_env  
libopensc/sec.c                         sc_decrypt_sym  
libopensc/card_driver                     card->ops->decrypt_sym  

==============================================================  
pkcs11/pkcs11-object.c    C_UnwrapKey  
                            sc_create_object_int  
pkcs11/mechanism.c          sc_pkcs11_unwrap  
pkcs11/misc.c                 session_start_operation  
pkcs11/mechanism.c            sc_pkcs11_unwrap_operation  
pkcs11/framework-pkcs15.c       pkcs15_prkey_unwrap      pkcs15_skey_unwrap  
libopensc/pkcs15-sec.c            sc_pkcs15_unwrap  
                                    format_senv  
libopensc/padding.c                 sc_get_encoding_flags  
libopensc/pkcs15-sec.c              use_key(p15card, obj, &senv, sc_unwrap, in, inlen, out, outlen)  
                                      select_key_file  
                                      sc_set_security_env  
libopensc/sec.c                         sc_unwrap  
libopensc/card_driver                     card->ops->unwrap  
==============================================================
```


8.
# There is this issue, solved, but I'm not happy with the code duplication use_key/use_key_sym: #  
Acc. to http://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html  
2.10.4 AES-ECB  
2.10.5 AES-CBC  
2.10.6 AES-CBC with PKCS padding  

the latter is special: A card driver that declares to support SC_ALGORITHM_AES_CBC_PAD, must do the padding before encrypt and padding-removal after decrypt, but not for any other (AES-ECB, AES-CBC); for those, the calling PKCS#11 application is responsible to care for trailing padding to block_size and padding removal.  
So the card driver functions implementing sc_card_operations:encrypt_sym/decrypt_sym must receive the parameter sc_security_env:algorithm_flags (and I added param. algorithm for future use, for possibly other algorithms to be added later)  
Except for codeline  r = card_command(...  use_key/use_key_sym are identical. I don't know C well enough to avoid this code duplication, the difference is the function signature of 'card_command' being called. Any ideas?

9. The impl. works as expected (at least for me), but needs more testing and care for error conditions (a little bit disregarded so far).


10.
# pkcs11-tool: testing sym. encrypt/decrypt was included, to be used with $ pkcs11-tool --test --login --pin ******** #  
  Testing symmetric on-card/hardware crypto with pkcs11-tool --test  might not be the best idea, but for some inscrutable
  reason I started to implement that first (possibly I didn't want to fiddle with program options):  
  The reason is: Both the card and the  pkcs11-tool application must know the same AES key material, and that's not
  solvable in a generic way, so the user must do something here prior to invocation of pkcs11-tool --test:  
  Currently pkcs11-tool.c knows a hardcoded AES key, 32 content bytes with values 1..32 for any of AES/128, AES/192, AES/256 use cases:  
  In the beginning of functions `encrypt_decrypt_sym_1` and `encrypt_decrypt_sym_2`: unsigned char	aes_key_256[32] = {0x01, 0x02 ... 0x1F, 0x20};
  
  There are 2 options:
  1. Change pkcs11-tool.c source code's aes_key_256 to Your specific, actual AES key in those 2 locations.
  2. If Your card/driver allows that, then import file aes_key_256.hex (it's located in sym_hw_encrypt's root folder) with something similar to  
     $ pkcs15-init --store-secret-key aes_key_256.hex --secret-key-algorithm aes/256  --auth-id 01 --id 02 --verify-pin  
     (--auth-id  and  --id  need to be adapted, possibly more options used or e.g. --secret-key-algorithm aes/192)


  With that preparation, it works for me:  It should report something behind "Decryption (currently only for RSA)":  
  Encryption: card/hardware encrypts, OpenSSL decrypts  
  Decryption: OpenSSL encrypts, card/hardware decrypts  
```
$ pkcs11-tool --test --login --pin ********
  ...
  Decryption (currently only for RSA)
  ...
  Encryption (currently only for AES)
    testing key 0 (AES3) 256 bit
      AES-ECB: OK
      AES-CBC: OK
      AES-CBC-PAD: OK
  Decryption (currently only for AES)
    testing key 0 (AES3) 256 bit
   -- mechanism can't be used to decrypt, skipping
      AES-ECB: OK
      AES-CBC: OK
      AES-CBC-PAD: OK
  No errors
```

  The impl. was done ad-hoc, may certainly need refinement, but it works (at least for me).  
  There are many printf statements that may be activated/un-commented by a developer and allow good insight what's going on.  
  Also the console output "Error Return some_unique_number" lets devs easily spot where something goes wrong.  
  The original plaintext length is set to 481; /* cards with short APDU syntax should prove correct chaining handling with >= 240 */  
  That's where my acos5_external driver did fail, solved now:
  It turned out, that my ACOS5 V2.00 hardware claims to be capable of sym. decrypt, CBC in **chaining mode**, but actually it's not, and
  ACOS5 V3.00 doesn't even claim that capability, so my driver needs to workaroung and call sc_set_security_env from within card->ops->decrypt_sym.
  Thus `decrypt_sym` needs one more parameter from struct sc_security_env: field key_ref.

  Option --decrypt_sym --input file          to be added by someone ?  
         --encrypt_sym --input file          to be added by someone ?

pkcs15-crypt: Not yet adapted for sym. encrypt/decrypt; to be added by someone ? With the testing code for pkcs11-tool --test   that should be easy to do ?


11. There is Rust code as well, usable by any OpenSC supported card (capable of sym. encrypt/decrypt). I used that for testing:  
https://github.com/carblue/acos5/tree/master/project_pkcs11_example_apps  
src/main_RO_sym_encrypt.rs  and  
src/main_RO_sym_decrypt.rs  

It just relies on finding 1 AES key on card (may need slight adaption to find a specific one, e.g. by CKA_LABEL).
The iv, plaintext_data etc. are arbitrarily assigned. Exchange mechanism CKM_AES_CBC_PAD in the mechanism struct by CKM_AES_CBC or CKM_AES_ECB for testing those.


11. For OpenSC users,  
who want to try `symmetric on-card/hardware crypto support in OpenSC`:  
My OpenSC's fork, branch sym_hw_encrypt gets regularly rebased on current upstream OpenSC github master and presumably updated with refinements.  
https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt  
After release 0.21.0 is done, I treat everything from OpenSC github master as an imaginary version v0_22_0 in acos5 driver's sources.  
So, first You need to compile OpenSC from sources in my branch sym_hw_encrypt, and install:  
I, personally on Kubuntu, deviate from https://github.com/OpenSC/OpenSC/wiki/Compiling-and-Installing-on-Unix-flavors like this in the last 3 lines:  
```
cd into the opensc root folder that has script bootstrap
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc/opensc --libdir=/usr/lib/x86_64-linux-gnu
make -j4
sudo checkinstall
```

opensc-tool -i will report:  OpenSC 0.22.0-sym_hw_encrypt

Any card driver capable/willing to support sym. hw crypto needs to implement struct sc_card_operations 's functions `encrypt_sym` and `decrypt_sym`, otherwise they are NULL (no support) from libopensc/iso7816.c: iso_ops / sc_get_iso7816_driver

ACOS5 card / driver acos5_external users:  
The compiler switch --cfg sym_hw_encrypt must be activated in the following 3 files (i.e. remove leading // in respective line):  
opensc-sys/build.rs  
acos5/build.rs  
acos5_pkcs15/build.rs

Delete (acos_root_downloaded/) folder target and file Cargo.lock, finally re-build the driver
