Design rationale for `symmetric on-card/hardware crypto support in OpenSC` and comments

Its implemented in an imaginary OpenSC version  0.22.0-sym_hw_encrypt (which is my driver's way to address  OpenSC github master).

1. The implementation is limited to support only 
   - AES, as its the only sym. algo registered with PKCS#11 currently.
     (e.g. the blocksize 16 is hardcoded) and limited to
   - C_EncryptInit, C_Encrypt, C_DecryptInit, C_Decrypt (C_UnwrapKey, C_UnwrapKey are supported by OpenSC already)


2. Actually the code was copied from existing code in same file(s), adapted as I deemed required.


3. currently these algorithm_flags are defined for AES in OpenSC
```
/* symmetric algorithm flags. More algorithms to be added when implemented. */
#define SC_ALGORITHM_AES_ECB           0x01000000
#define SC_ALGORITHM_AES_CBC           0x02000000
#define SC_ALGORITHM_AES_CBC_PAD       0x04000000
#define SC_ALGORITHM_AES_FLAGS         0x0F000000

(#define SC_ALGORITHM_ONBOARD_KEY_GEN  0x80000000)
```
All 3 mechanisms CKM_AES_ECB, CKM_AES_CBC and SC_ALGORITHM_AES_CBC_PAD are supported.  

The implementation supports setting struct sc_security_env field algorithm_ref from TokenInfo.supportedAlgorithms and field flags |= SC_SEC_ENV_ALG_REF_PRESENT (if applicable), i.e. the card secific algorithm encoding

For ACOS5 card users,  
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
Then, the compiler switch --cfg sym_hw_encrypt must be activated in the following 3 files (i.e. remove leading // in respective line):  
opensc-sys/build.rs  
acos5/build.rs  
acos5_pkcs15/build.rs

Delete folder target and file Cargo.lock, finally re-build the driver
