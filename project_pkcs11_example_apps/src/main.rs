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

use cryptoki::context::{Pkcs11, CInitializeArgs};
use cryptoki::session::{UserType, Session};
use cryptoki::types::AuthPin;
use cryptoki::object::{ObjectClass, Attribute, ObjectHandle, AttributeType};
use cryptoki::error::Error;


fn show_key_info(/*_ctx: &Pkcs11,*/ session: &Session, key: ObjectHandle) -> Result<(), Error> {
    println!("key {:?}", key);
/*
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
    // let mut is_copyable : CK_BBOOL = 0xAA;

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
/*
        CK_ATTRIBUTE { attrType: CKA_COPYABLE,
                       pValue: &mut is_copyable as *mut _ as CK_VOID_PTR,
                       ulValueLen: 1 },
*/
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
    //ctx.get_attribute_value(session, key, &mut template)?;
*/
    let template = [
        AttributeType::Label,
        AttributeType::Id,
        AttributeType::KeyType,
        AttributeType::Token,
        AttributeType::Private,
        AttributeType::Modifiable,
        //AttributeType::,
        AttributeType::Sensitive,
        AttributeType::Extractable,
        AttributeType::AlwaysSensitive,
        AttributeType::NeverExtractable,
        AttributeType::Local,
        AttributeType::Encrypt,
        AttributeType::Decrypt,
        AttributeType::Sign,
        AttributeType::Verify,
        AttributeType::SignRecover,
        AttributeType::VerifyRecover,
        AttributeType::Wrap,
        AttributeType::Unwrap,
    ];
    let attributes_vec = session.get_attributes(key, &template)?;
    for elem in attributes_vec {
        match elem {
            Attribute::Label(vec) => println!("attrib {:?}", unsafe { std::str::from_utf8_unchecked(&vec) } ),
            _ => println!("attrib {:?}", elem),
        }
    }
    /*
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
        print!("\tKey type: {} (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))", key_type);
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
    // if template[6].ulValueLen > 0 { print!("\t is_copyable: {}", is_copyable==1); }
    // else { print!("\tKey is_token_object too large, or not found"); }

    if template[6].ulValueLen > 0 { print!("\t is_sensitive: {}", is_sensitive==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[7].ulValueLen > 0 { print!("\t is_extractable: {}", is_extractable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[8].ulValueLen > 0 { print!("\t is_always_sensitive: {}", is_always_sensitive==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[9].ulValueLen > 0 { print!("\t is_never_extractable: {}", is_never_extractable==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[10].ulValueLen > 0 { print!("\t is_local: {}", is_local==1); }
    else { print!("\tKey is_token_object too large, or not found"); }

    if template[11].ulValueLen > 0 { print!("\t can_encrypt: {}", can_encrypt==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[12].ulValueLen > 0 { print!("\t can_decrypt: {}", can_decrypt==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[13].ulValueLen > 0 { print!("\t can_sign: {}", can_sign==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[14].ulValueLen > 0 { print!("\t can_verify: {}", can_verify==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[15].ulValueLen > 0 { print!("\t can_signRecover: {}", can_signrecover==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[16].ulValueLen > 0 { print!("\t can_verifyRecover: {}", can_verifyrecover==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[17].ulValueLen > 0 { print!("\t can_wrap: {}", can_wrap==1); }
    else { print!("\tKey is_token_object too large, or not found"); }
    if template[18].ulValueLen > 0 { println!("\t can_unwrap: {}", can_unwrap==1); }
    else { println!("\tKey is_token_object too large, or not found"); }
*/
    Ok(())
}

fn read_keys(/*ctx: &Pkcs11,*/ session: &Session, key_class: ObjectClass) -> Result<(), Error> {
    let template = [ Attribute::Class(key_class) ];
    for elem in session.find_objects(&template)? {
        show_key_info(/*ctx,*/ session, elem)?;
    }
    Ok(())
}

fn main() -> Result<(), Error> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            let ctx = Pkcs11::new("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll")?;
        }
        else {
            //let ctx = Pkcs11::new("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")?;
            /* if p11-kit installed and opensc-pkcs11.so configured with highest priority */
            let ctx = Pkcs11::new("/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so")?;
        }
    }
    ctx.initialize(CInitializeArgs::OsThreads)?;

    let slot = ctx.get_slots_with_initialized_token()?.remove(0);
    let session = ctx.open_ro_session(slot)?;
    session.login(UserType::User, Some(&AuthPin::new("12345678".into())))?;
    println!("CKO_PUBLIC_KEY:");
    read_keys(/*&ctx,*/ &session, ObjectClass::PUBLIC_KEY)?;
    println!("CKO_PRIVATE_KEY:");
    read_keys(/*&ctx,*/ &session, ObjectClass::PRIVATE_KEY)?;
    println!("CKO_SECRET_KEY:");
    read_keys(/*&ctx,*/ &session, ObjectClass::SECRET_KEY)?;
    session.logout()
}

/*
$ cargo run
...
slot count: 1. Selected slotId: 0

after merge of PR #2176

CKO_PUBLIC_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))      is_token_object: true   is_private: false       is_modifiable: true     is_sensitive: false     is_extractable: true    is_always_sensitive: false      is_never_extractable: false   is_local: true  can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))      is_token_object: true   is_private: false       is_modifiable: true     is_sensitive: false     is_extractable: true    is_always_sensitive: false      is_never_extractable: false   is_local: true  can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: true  can_unwrap: false
CKO_PRIVATE_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))      is_token_object: true   is_private: true        is_modifiable: true     is_sensitive: true      is_extractable: false   is_always_sensitive: true       is_never_extractable: true    is_local: true  can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))      is_token_object: true   is_private: true        is_modifiable: true     is_sensitive: true      is_extractable: false   is_always_sensitive: true       is_never_extractable: true    is_local: true  can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: true
CKO_SECRET_KEY:
Found a key:  Key label: AES3           Key ID: 0x07    Key type: 31 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))     is_token_object: true   is_private: true        is_modifiable: true     is_sensitive: true      is_extractable: false   is_always_sensitive: true       is_never_extractable: true    is_local: false  can_encrypt: true      can_decrypt: true       can_sign: false         can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false


before merge of PR #2176

CKO_PUBLIC_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)                    is_token_object: true   is_private: false       is_modifiable: false    is_sensitive: false     is_extractable: false   is_always_sensitive: false     is_never_extractable: false     is_local: true   can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)                    is_token_object: true   is_private: false       is_modifiable: false    is_sensitive: false     is_extractable: false   is_always_sensitive: false     is_never_extractable: false     is_local: true   can_encrypt: true       can_decrypt: false      can_sign: false         can_verify: true        can_signRecover: false  can_verifyRecover: false        can_wrap: true          can_unwrap: false
CKO_PRIVATE_KEY:
Found a key:  Key label: arcor          Key ID: 0x06    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)                    is_token_object: true   is_private: true        is_modifiable: false    is_sensitive: true      is_extractable: false   is_always_sensitive: true      is_never_extractable: true      is_local: true   can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false
Found a key:  Key label: dummy          Key ID: 0x08    Key type: 0 (0 == CKK_RSA, 3==CKK_EC)                    is_token_object: true   is_private: true        is_modifiable: false    is_sensitive: true      is_extractable: false   is_always_sensitive: true      is_never_extractable: true      is_local: true   can_encrypt: false      can_decrypt: true       can_sign: true          can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: true
CKO_SECRET_KEY:
Found a key:  Key label: AES3           Key ID: 0x07    Key type: 31 (0 == CKK_RSA, 3==CKK_EC)                   is_token_object: true   is_private: true        is_modifiable: true     is_sensitive: true      is_extractable: true    is_always_sensitive: true      is_never_extractable: true      is_local: false  can_encrypt: true       can_decrypt: true       can_sign: false         can_verify: false       can_signRecover: false  can_verifyRecover: false        can_wrap: false         can_unwrap: false

*/
