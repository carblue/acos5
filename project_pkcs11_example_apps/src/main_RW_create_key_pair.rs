/* main_RW_create_key_pair.rs */
/* This example implements "3.6 Example 2: Generating a key pair", page 16, from https://www.nlnetlabs.nl/downloads/publications/hsm/hsm.pdf
   main_RO_CKO_PRIVATE_KEY.rs: show some information about private keys in a read-only session
   Functions used:
   C_Initialize
   C_GetSlotList
   C_OpenSession
   C_Login
   C_GenerateKeyPair
   C_Logout
   C_CloseSession
   C_Finalize
 */

use pkcs11::{Ctx};
use pkcs11::errors::{Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKU_USER, CK_SESSION_HANDLE, CK_ATTRIBUTE,
                    CK_VOID_PTR, CK_OBJECT_HANDLE, CKA_LABEL, CKA_ID,
                    CKA_DECRYPT, CK_BBOOL, CKA_SIGN, CKA_UNWRAP,
                    CKA_SENSITIVE, CKF_RW_SESSION, CK_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN, CK_VOID,
                    CK_ULONG, CK_BYTE, CK_TRUE, CKA_MODULUS_BITS,
                    CKA_PUBLIC_EXPONENT, CKA_LOCAL, CKA_KEY_TYPE, CK_KEY_TYPE, CKA_EXTRACTABLE,
                    CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE, CKA_COPYABLE,
                    CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_ENCRYPT, CKA_VERIFY, CKA_SIGN_RECOVER,
                    CKA_VERIFY_RECOVER, CKA_WRAP};
use std::mem::size_of;
use std::convert::TryInto;
use std::ptr::null_mut;

fn show_key_info(ctx: &Ctx, session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> Result<(), Error> {
    let mut label = [0_u8; 80]; //CK_UTF8CHAR *label = (CK_UTF8CHAR *) malloc(80);
    let mut id = [0_u8; 10]; //CK_BYTE *id = (CK_BYTE *) malloc(10);
    let mut key_type: CK_KEY_TYPE = 0xFFFFFFFF;
    /* CKA_LOCAL is true only if key was either
     * generated locally (i.e., on the token) with a C_GenerateKey or C_GenerateKeyPair call
     * created with a C_CopyObject call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE

     Different from that is field native in PKCS#15 CommonKeyAttributes:
     The native field identifies whether the card is able to use the key for hardware computations or not
     (e.g. this field is by default true for all RSA keys stored in special RSA key files on an RSA capable IC card,
     and does not apply in the soft-token case).

     CKA_TOKEN  CK_BBOOL  CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE.
     */
    let mut is_token_object : CK_BBOOL = 0xAA;
    let mut is_private : CK_BBOOL = 0xAA;
    let mut is_modifiable : CK_BBOOL = 0xAA;
    let mut is_copyable : CK_BBOOL = 0xAA;

    let mut is_sensitive : CK_BBOOL = 0xAA;
    let mut is_extractable : CK_BBOOL = 0xAA;
    let mut is_always_sensitive : CK_BBOOL = 0xAA;
    let mut is_never_extractable : CK_BBOOL = 0xAA;
    let mut is_local : CK_BBOOL = 0xAA;

    let mut can_encrypt : CK_BBOOL = 0xAA;
    let mut can_decrypt : CK_BBOOL = 0xAA;
    let mut can_sign    : CK_BBOOL = 0xAA;
    let mut can_verify  : CK_BBOOL = 0xAA;
    let mut can_signrecover    : CK_BBOOL = 0xAA;
    let mut can_verifyrecover  : CK_BBOOL = 0xAA;
    let mut can_wrap    : CK_BBOOL = 0xAA;
    let mut can_unwrap  : CK_BBOOL = 0xAA;

    let mut template = vec![
        CK_ATTRIBUTE { attrType: CKA_LABEL,
                       pValue: label.as_mut_ptr() as CK_VOID_PTR,
                       ulValueLen: label.len().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_ID,
                       pValue: id.as_mut_ptr() as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_KEY_TYPE,
                       pValue: &mut key_type as *mut _ as CK_VOID_PTR,
                       ulValueLen: size_of::<CK_KEY_TYPE>().try_into().unwrap() },

        CK_ATTRIBUTE { attrType: CKA_TOKEN,
                       pValue: &mut is_token_object as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_PRIVATE,
                       pValue: &mut is_private as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_MODIFIABLE,
                       pValue: &mut is_modifiable as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_COPYABLE,
                       pValue: &mut is_copyable as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },

        CK_ATTRIBUTE { attrType: CKA_SENSITIVE,
                       pValue: &mut is_sensitive as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_EXTRACTABLE,
                       pValue: &mut is_extractable as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_ALWAYS_SENSITIVE,
                       pValue: &mut is_always_sensitive as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_NEVER_EXTRACTABLE,
                       pValue: &mut is_never_extractable as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_LOCAL,
                       pValue: &mut is_local as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },

        CK_ATTRIBUTE { attrType: CKA_ENCRYPT,
                       pValue: &mut can_encrypt as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_DECRYPT,
                       pValue: &mut can_decrypt as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_SIGN,
                       pValue: &mut can_sign as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_VERIFY,
                       pValue: &mut can_verify as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_SIGN_RECOVER,
                       pValue: &mut can_signrecover as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_VERIFY_RECOVER,
                       pValue: &mut can_verifyrecover as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_WRAP,
                       pValue: &mut can_wrap as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_UNWRAP,
                       pValue: &mut can_unwrap as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
    ];

    ctx.get_attribute_value(session, key, &mut template)?;

    print!("Found a key:  ");
    let label_len : usize = template[0].ulValueLen.try_into().unwrap();

    if label_len > 0 {
        // let label_str = String::from_utf8(unsafe {std::slice::from_raw_parts(vec[0].pValue as *const u8, label_len.try_into().unwrap()).to_vec()}).unwrap();
        // let label_str = unsafe { std::ffi::CStr::from_ptr(vec[0].pValue as *const i8) };
        print!("Key label: {}  ", std::str::from_utf8(&label[..label_len]).unwrap());// unsafe { std::ffi::CStr::from_ptr(template[0].pValue as *const i8) });
    }
    else {
        print!("Key label too large, or not found  ");
    }

    if template[1].ulValueLen > 0 {
        print!("\tKey ID: 0x{:02X}", id[0]);
    }
    else {
        print!("\tKey ID too large, or not found");
    }

    if template[2].ulValueLen > 0 {
        print!("\tKey type: {} (0 == CKK_RSA, 3==CKK_EC)", key_type);
    }
    else {
        print!("\tKey type too large, or not found");
    }

    if template[3].ulValueLen > 0 { print!("\t is_token_object: {}", is_token_object==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[4].ulValueLen > 0 { print!("\t is_private: {}", is_private==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[5].ulValueLen > 0 { print!("\t is_modifiable: {}", is_modifiable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[6].ulValueLen > 0 { print!("\t is_copyable: {}", is_copyable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }

    if template[7].ulValueLen > 0 { print!("\t is_sensitive: {}", is_sensitive==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[8].ulValueLen > 0 { print!("\t is_extractable: {}", is_extractable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[9].ulValueLen > 0 { print!("\t is_always_sensitive: {}", is_always_sensitive==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[10].ulValueLen > 0 { print!("\t is_never_extractable: {}", is_never_extractable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[11].ulValueLen > 0 { print!("\t is_local: {}", is_local==1); }
    else { print!("\tKey is_token_object too large, or not found"); }

    if template[12].ulValueLen > 0 { print!("\t can_encrypt: {}", can_encrypt==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[13].ulValueLen > 0 { print!("\t can_decrypt: {}", can_decrypt==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[14].ulValueLen > 0 { print!("\t can_sign: {}", can_sign==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[15].ulValueLen > 0 { print!("\t can_verify: {}", can_verify==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[16].ulValueLen > 0 { print!("\t can_signRecover: {}", can_signrecover==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[17].ulValueLen > 0 { print!("\t can_verifyRecover: {}", can_verifyrecover==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[18].ulValueLen > 0 { print!("\t can_wrap: {}", can_wrap==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[19].ulValueLen > 0 { println!("\t can_unwrap: {}", can_unwrap==1); }
    else { println!("\tKey is_token_object too large, or not found"); }

    Ok(())
}

fn create_key_pair(ctx: &Ctx, session: CK_SESSION_HANDLE) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
    let mechanism = CK_MECHANISM {
        mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, pParameter: null_mut::<CK_VOID>(), ulParameterLen: 0
    };
    let modulus_bits : CK_ULONG = 1024;
    let public_exponent : [CK_BYTE; 3] = [ 1, 0, 1];
    let subject = b"mykey\0";
    let id : CK_BYTE = 0xa1;
    let true_ : CK_BBOOL = CK_TRUE;
    let bool_size : CK_ULONG = size_of::<CK_BBOOL>().try_into().unwrap();
    let public_key_template = [
        CK_ATTRIBUTE { attrType: CKA_ID, pValue: &id as *const _ as CK_VOID_PTR, ulValueLen: 1},
        CK_ATTRIBUTE { attrType: CKA_LABEL, pValue: subject  as *const _ as CK_VOID_PTR, ulValueLen: 5},
        CK_ATTRIBUTE { attrType: CKA_MODIFIABLE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_TOKEN, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },

        CK_ATTRIBUTE { attrType: CKA_EXTRACTABLE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_LOCAL, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },

        CK_ATTRIBUTE { attrType: CKA_ENCRYPT, pValue: &true_ as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_VERIFY,pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_WRAP,  pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_MODULUS_BITS, pValue: &modulus_bits as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_ULONG>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_PUBLIC_EXPONENT, pValue: public_exponent.as_ptr() as *const _ as CK_VOID_PTR, ulValueLen: 3 }
    ];

    let private_key_template = [
        CK_ATTRIBUTE { attrType: CKA_ID, pValue: &id as *const _ as CK_VOID_PTR, ulValueLen: 1},
        CK_ATTRIBUTE { attrType: CKA_LABEL,   pValue: subject  as *const _ as CK_VOID_PTR, ulValueLen: 5},
        CK_ATTRIBUTE { attrType: CKA_MODIFIABLE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_TOKEN,   pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },

        CK_ATTRIBUTE { attrType: CKA_PRIVATE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_SENSITIVE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_ALWAYS_SENSITIVE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_NEVER_EXTRACTABLE, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_LOCAL, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },

        CK_ATTRIBUTE { attrType: CKA_DECRYPT, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_SIGN, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
        CK_ATTRIBUTE { attrType: CKA_UNWRAP, pValue: &true_   as *const _ as CK_VOID_PTR, ulValueLen: bool_size },
    ];

    match ctx.generate_key_pair(session, &mechanism, &public_key_template, &private_key_template) {
        Ok(val) => Ok(val), // (pubOh, privOh)
        Err(e) => Err(e)
    }
}

fn main() -> Result<(), Error> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            let ctx = Ctx::new_and_initialize("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll")?;
        }
        else {
            // let ctx = Ctx::new_and_initialize("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")?;
            let ctx = Ctx::new_and_initialize("opensc-pkcs11.so")?;
        }
    }

    let slot_list = ctx.get_slot_list(true)?;
    if slot_list.is_empty() {
        eprintln!("Error; could not find any slots");
        return Err(Error::UnavailableInformation);
    }
    let slot = slot_list[0]; // = get_slot();
    println!("slot count: {}. Selected slotId: {}", slot_list.len(), slot);

    let session = ctx.open_session(slot, CKF_SERIAL_SESSION |  CKF_RW_SESSION, None, None)?;
    ctx.login(session, CKU_USER, Some("12345678"))?;
    let (pub_oh, priv_oh) = create_key_pair(&ctx, session)?;
    println!("CKO_PUBLIC_KEY:");
    show_key_info(&ctx, session, pub_oh)?;
    println!("CKO_PRIVATE_KEY:");
    show_key_info(&ctx, session, priv_oh)?;
    ctx.logout(session)?;
    ctx.close_session(session)
}
/*
$ cargo run
   Compiling project_pkcs11_example_apps v0.0.30 (/home/user/RustProjects/acos5_external/project_pkcs11_example_apps)
    Finished dev [unoptimized + debuginfo] target(s) in 0.41s
     Running `target/debug/project_pkcs11_example_apps`
slot count: 1. Selected slotId: 0
This file id will be chosen for the private RSA key:  41A1
This file id will be chosen for the public  RSA key:  41D1
CKO_PUBLIC_KEY:
Found a key:  Key label: mykey          Key ID: 0xA1    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: false       is_modifiable: false    is_copyable: false      is_sensitive: false     is_extractable: false   is_always_sensitive: false     is_never_extractable: false     is_local: true  can_encrypt: true       can_decrypt: false      can_sign: false   can_verify: true        can_signRecover: false  can_verifyRecover: true         can_wrap: true    can_unwrap: false
CKO_PRIVATE_KEY:
Found a key:  Key label: mykey          Key ID: 0xA1    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: true        is_modifiable: false    is_copyable: false      is_sensitive: true      is_extractable: false   is_always_sensitive: true      is_never_extractable: true      is_local: true  can_encrypt: false      can_decrypt: true       can_sign: true    can_verify: false       can_signRecover: true   can_verifyRecover: false        can_wrap: false   can_unwrap: true
$

name: publicRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: mykey
    name: flags  type: BIT_STR  value(2): 40  ->  01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: a1
    name: usage  type: BIT_STR  value(8): 8b  ->  10001011
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): 48  ->  01001
    name: keyReference  type: INTEGER  value: 0x00
  name: publicRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f00410041d1
    name: modulusLength  type: INTEGER  value: 0x0400


name: privateRSAKey  type: SEQUENCE
  name: commonObjectAttributes  type: SEQUENCE
    name: label  type: UTF8_STR  value: mykey
    name: flags  type: BIT_STR  value(2): c0  ->  11
    name: authId  type: OCT_STR  value: 01
  name: commonKeyAttributes  type: SEQUENCE
    name: iD  type: OCT_STR  value: a1
    name: usage  type: BIT_STR  value(6): 74  ->  011101
    name: native  type: BOOLEAN
      name: NULL  type: DEFAULT  value: TRUE
    name: accessFlags  type: BIT_STR  value(5): b8  ->  10111
    name: keyReference  type: INTEGER  value: 0x00
  name: privateRSAKeyAttributes  type: SEQUENCE
    name: value  type: CHOICE
      name: indirect  type: CHOICE
        name: path  type: SEQUENCE
          name: path  type: OCT_STR  value: 3f00410041a1
    name: modulusLength  type: INTEGER  value: 0x0400
*/
