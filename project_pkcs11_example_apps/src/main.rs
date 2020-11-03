/* main_RO_inspect_keys.rs : show some information about keys in a read-only session */
/* This example implements "3.5  Example 1: Reading keys", page 13,
   from https://www.nlnetlabs.nl/downloads/publications/hsm/hsm.pdf
   and got extended to also cover public and secret keys.
   Functions used:
   C_Initialize
   C_GetSlotList
   C_OpenSession
   C_Login
   C_GetAttributeValue
   C_FindObjectsInit
   C_FindObjects
   C_FindObjectsFinal
   C_Logout
   C_CloseSession
   C_Finalize
 */

use pkcs11::{Ctx};
use pkcs11::errors::{Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKU_USER, CK_SESSION_HANDLE, CK_OBJECT_CLASS, CK_ATTRIBUTE, CKO_PRIVATE_KEY,
                    CK_VOID_PTR, CKA_CLASS, CK_OBJECT_HANDLE/*, CK_UTF8CHAR, CK_BYTE*/, CKA_LABEL, CKA_ID, CKA_KEY_TYPE,
                    CK_KEY_TYPE, CKA_DECRYPT, CK_BBOOL, CKA_SIGN, CKA_UNWRAP, CKO_SECRET_KEY, CKA_LOCAL,
                    CKA_EXTRACTABLE, CKA_SENSITIVE, CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE, CKA_COPYABLE,
                    CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_ENCRYPT, CKA_VERIFY, CKA_SIGN_RECOVER,
                    CKA_VERIFY_RECOVER, CKA_WRAP, CKO_PUBLIC_KEY};
use std::mem::size_of;
use std::convert::TryInto;

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
        print!("Key label: {}  ", std::str::from_utf8(&label[..label_len]).unwrap());
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

fn read_keys(ctx: &Ctx, session: CK_SESSION_HANDLE, key_class: CK_OBJECT_CLASS) -> Result<(), Error> {
    let template = [
        CK_ATTRIBUTE { attrType: CKA_CLASS,
                       pValue: &key_class as *const _ as CK_VOID_PTR,
                       ulValueLen: size_of::<CK_OBJECT_CLASS>().try_into().unwrap() }
    ];
    ctx.find_objects_init(session, &template)?;

    let mut res : Vec<CK_OBJECT_HANDLE> = ctx.find_objects(session, 1)?;
    while !res.is_empty() {
        show_key_info(ctx, session, res[0])?;
        res = ctx.find_objects(session, 1)?;
        // println!("object_count: {}", res.len());
    }
    ctx.find_objects_final(session)
}

fn main() -> Result<(), Error> {
    // let ctx = Ctx::new_and_initialize("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")?;
    let ctx = Ctx::new_and_initialize("opensc-pkcs11.so")?;

    let slot_list = ctx.get_slot_list(true)?;
    if slot_list.is_empty() {
        eprintln!("Error; could not find any slots");
        return Err(Error::UnavailableInformation);
    }
    let slot = slot_list[0];
    println!("slot count: {}. Selected slotId: {}", slot_list.len(), slot);

    let session = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)?;
    ctx.login(session, CKU_USER, Some("12345678"))?;
    println!("CKO_PUBLIC_KEY:");
    read_keys(&ctx, session, CKO_PUBLIC_KEY)?;
    println!("CKO_PRIVATE_KEY:");
    read_keys(&ctx, session, CKO_PRIVATE_KEY)?;
    println!("CKO_SECRET_KEY:");
    read_keys(&ctx, session, CKO_SECRET_KEY)?;
    ctx.logout(session)?;
    ctx.close_session(session)
}

/*
$ cargo run
...
slot count: 1. Selected slotId: 0
CKO_PUBLIC_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: false       is_modifiable: false    is_copyable: false      is_sensitive: false     is_extractable: false   is_always_sensitive: false     is_never_extractable: false     is_local: true   can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: false       is_modifiable: false    is_copyable: false      is_sensitive: false     is_extractable: false   is_always_sensitive: false     is_never_extractable: false     is_local: true   can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: true          can_unwrap: false
CKO_PRIVATE_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: true        is_modifiable: false    is_copyable: false      is_sensitive: true      is_extractable: false   is_always_sensitive: true      is_never_extractable: true      is_local: true   can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)    is_token_object: true   is_private: true        is_modifiable: false    is_copyable: false      is_sensitive: true      is_extractable: false   is_always_sensitive: true      is_never_extractable: true      is_local: true   can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: true
CKO_SECRET_KEY:
Found a key:  Key label: AES3           Key ID: 0x07    Key type: 31 (0 == CKK_RSA, 3==CKK_EC)   is_token_object: true   is_private: true        is_modifiable: true     is_copyable: false      is_sensitive: true      is_extractable: true    is_always_sensitive: true      is_never_extractable: true      is_local: false  can_encrypt: true       can_decrypt: true       can_sign: false         can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
*/
