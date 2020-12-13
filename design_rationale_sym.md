Design rationale for `symmetric on-card/hardware crypto support in OpenSC` and comments

Its implemented in an imaginary OpenSC version  0.22.0-sym_hw_encrypt (which is my driver's way to address  OpenSC github master, i.e. all not yet released).


1. The implementation is limited to support only
   - AES, as its the only sym. algo registered with PKCS#11 currently.
     (e.g. the blocksize 16 is hardcoded),  and impl. is limited to
   - C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt.   (C_UnwrapKey, C_UnwrapKey are already supported by OpenSC, thanks to Hannu Honkanen)

   Actually the code was copied from existing code in same file(s), adapted as I deemed required.

2. struct sc_card_operations got extended by functions `encrypt_sym` and `decrypt_sym` (assuming, that decipher is reserved for asym. algos)

3. currently these algorithm_flags are defined for AES in OpenSC
```
/* symmetric algorithm flags. More algorithms to be added when implemented. */
#define SC_ALGORITHM_AES_ECB           0x01000000
#define SC_ALGORITHM_AES_CBC           0x02000000
#define SC_ALGORITHM_AES_CBC_PAD       0x04000000
#define SC_ALGORITHM_AES_FLAGS         0x0F000000

(#define SC_ALGORITHM_ONBOARD_KEY_GEN  0x80000000)
```
   All 3 mechanisms CKM_AES_ECB, CKM_AES_CBC and SC_ALGORITHM_AES_CBC_PAD are supported and a card driver willing to support symmetric on-card crypto must declare at least 1 of them with _sc_card_add_symmetric_alg.
   Nothing (in the impl.) precludes us from adding more  SC_ALGORITHM_AES_*, if required (it's just my card not supporting more), except that requires slight adaptions in mapping to  CKM_AES_*  back and forth.

   The implementation was done with extensibilit for other sym. aalgorithms in mind
4. The implementation supports setting struct sc_security_env field algorithm_ref from TokenInfo.supportedAlgorithms and field flags |= SC_SEC_ENV_ALG_REF_PRESENT (if applicable), i.e. the card secific algorithm/algorithm_flags encoding)


The (essential) call stacks:

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
libopensc/pkcs15-sec.c              use_key(p15card, obj, &senv, sc_encrypt_sym, in, inlen, out, outlen)
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
libopensc/pkcs15-sec.c              use_key(p15card, obj, &senv, sc_decrypt_sym, in, inlen, out, outlen)
                                      select_key_file
                                      sc_set_security_env
libopensc/sec.c                         sc_decrypt_sym
libopensc/card_driver                     card->ops->decrypt_sym



# There is this not-generally-solved issue: #
Acc. to http://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/pkcs11-curr-v3.0.html
2.10.4 AES-ECB  
2.10.5 AES-CBC  
2.10.6 AES-CBC with PKCS padding  

the latter is special: A card driver that declares to support SC_ALGORITHM_AES_CBC_PAD, must do the padding for encrypt and padding-removal after decrypt:  
But how

There is Rust code that I used for testing at https://github.com/carblue/acos5/tree/master/project_pkcs11_example_apps  
src/main_RO_sym_encrypt.rs  and  
src/main_RO_sym_decrypt.rs  

which may be used by any card: It just relies on finding 1 AES key on card (may need slight adaption to find a specific one).
The iv, plaintext_data etc. are arbitrarily assigned. Exchange


For OpenSC users,  
who want to try `symmetric on-card/hardware crypto support in OpenSC` with driver acos5_external:
My OpenSC's fork, branch sym_hw_encrypt gets regularly rebased on current upstream OpenSC github master and possibly updated with refinements.
https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt  
After release 0.21.0 is done, I treat everything from OpenSC github master as an imaginary version v0_22_0 in driver's sources.
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

Any non-ACOS5 card driver needs to implement struct sc_card_operations 's functions `encrypt_sym` and `decrypt_sym`, otherwise they are NULL from libopensc/iso7816.c: iso_ops / sc_get_iso7816_driver

ACOS5 card users:
The compiler switch --cfg sym_hw_encrypt must be activated in the following 3 files (i.e. remove leading // in respective line):  
opensc-sys/build.rs  
acos5/build.rs  
acos5_pkcs15/build.rs

Delete folder target and file Cargo.lock, finally re-build the driver
