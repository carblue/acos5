/* main_RW_unwrap_AES_key_wrapped_by_RSA_key.rs */
/* This example is an extract of some code from Hannu Honkanen (hhonkanen) in https://github.com/hhonkanen/WrapTest

implemented is RSA_WRAPPED_AES_KEY which needs some preparation, as driver acos5 doesn't yer implement wrap:
  1. Choose some AES key bytes, e.g. 32 for AES/256
  2. Encrypt that with a public RSA key from card

   Functions used:
   C_Initialize
   C_GetSlotList
   C_OpenSession
   C_Login
   C_GetAttributeValue
   C_FindObjectsInit
   C_FindObjects
   C_FindObjectsFinal

   C_UnwrapKey

   C_Logout
   C_CloseSession
   C_Finalize
 */

use pkcs11::{Ctx};
use pkcs11::errors::{Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKF_RW_SESSION, CKU_USER, CK_OBJECT_CLASS, CK_ATTRIBUTE, CK_ULONG,
                    CK_VOID_PTR, CKA_CLASS, CK_OBJECT_HANDLE, CK_BYTE, CKA_LABEL, CKA_KEY_TYPE,
                    CK_KEY_TYPE, CKA_DECRYPT, CK_BBOOL, CKO_SECRET_KEY, CKA_TOKEN, CKA_ENCRYPT,
                    CK_MECHANISM, CKK_AES, CK_TRUE, CK_FALSE, CK_SESSION_HANDLE, CKM_RSA_PKCS, CKA_VALUE_LEN,
                    CKA_ID, CKA_PRIVATE, CKA_MODIFIABLE, CKA_COPYABLE,
                    CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE, CKA_LOCAL,
                    CKA_SIGN, CKA_VERIFY, CKA_SIGN_RECOVER, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_UNWRAP,
                    CKO_PRIVATE_KEY, CKK_RSA
};
use std::mem::size_of;
use std::convert::TryInto;
use std::ptr::null_mut;


fn show_key_info(ctx: &Ctx, session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> Result<(), Error> {
    if key == 0 {
        return Err(Error::InvalidInput("Invalid object handle"));
    }
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


fn find_object_by_class_type_id(ctx: &Ctx, session: CK_SESSION_HANDLE,
                                key_class: CK_OBJECT_CLASS,
                                key_type: CK_KEY_TYPE,
                                rsa_key_id: CK_BYTE) -> Result<Vec<CK_OBJECT_HANDLE>, Error>
{
    let template = [
        CK_ATTRIBUTE { attrType: CKA_CLASS,    pValue: &key_class  as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_OBJECT_CLASS>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_KEY_TYPE, pValue: &key_type   as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_KEY_TYPE>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_ID,       pValue: &rsa_key_id as *const _ as CK_VOID_PTR, ulValueLen: 1 }
    ];
    ctx.find_objects_init(session, &template)?;
    let res : Vec<CK_OBJECT_HANDLE> = ctx.find_objects(session, 1)?;
    ctx.find_objects_final(session)?;
    Ok(res)
}


fn unwrap_aes_key_wrapped_by_rsa_key(ctx: &Ctx, session: CK_SESSION_HANDLE) -> Result<CK_OBJECT_HANDLE, Error> {
    let crgram_rsa_wrapped_aes_key = [
        0x3B_u8, 0x0B, 0x59, 0x2A, 0x3E, 0xBE, 0x64, 0x3C, 0x09, 0x00, 0x2E, 0x3E, 0xF0, 0x97, 0x7A, 0x5A,
        0xB8, 0x7F, 0x47, 0x59, 0x70, 0x69, 0xFD, 0x3F, 0x65, 0xEE, 0x54, 0x36, 0x0F, 0xD5, 0x06, 0x1B,
        0x17, 0x96, 0x39, 0xF2, 0xDB, 0x53, 0xD0, 0x12, 0xE4, 0xAB, 0x4B, 0x3C, 0x50, 0x31, 0x96, 0x68,
        0xA6, 0x66, 0x1F, 0x72, 0x52, 0x13, 0xBF, 0xC8, 0xBF, 0xB3, 0x7C, 0x6D, 0x37, 0xC5, 0xD4, 0xC5
    ];
    /* mechanism for unwrap operation */
    let mech_rsa_pkcs = CK_MECHANISM { mechanism: CKM_RSA_PKCS, pParameter: null_mut(), ulParameterLen: 0 };
    /* RSA key used for wrap/unwrap operation
       in my case id==8 specifies a RSA/512 key pair residing on my card, so crgram_rsa_wrapped_aes_key.len()== 64 byte== 512 bit is correct */
    let rsa_key_id : CK_BYTE = 8;

    /* Attributes for the to-be-unwrapped AES key */
    let key_class = CKO_SECRET_KEY;
    let key_type = CKK_AES;
    let true_ = CK_TRUE;
    let false_ = CK_FALSE;
    /* FIXME can the 2 following be set by te unwrap operation ? */
    let value_len : CK_ULONG = 32;
    let aes_key_id : CK_BYTE = 9;

    /* AES, non extractable, non-session object */
    let template_aes_key =  [
        CK_ATTRIBUTE { attrType: CKA_CLASS,       pValue: &key_class as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_OBJECT_CLASS>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_KEY_TYPE,    pValue: &key_type  as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_KEY_TYPE>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_VALUE_LEN,   pValue: &value_len as *const _ as CK_VOID_PTR, ulValueLen: size_of::<CK_ULONG>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_ID,          pValue: &aes_key_id as *const _ as CK_VOID_PTR, ulValueLen: 1 },

        CK_ATTRIBUTE { attrType: CKA_TOKEN,       pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_PRIVATE,     pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_MODIFIABLE,  pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },

        /* due to a bug in OpenSC. explicitly set these, but opensc-pkcs11 will still erroneously report true for CKA_EXTRACTABLE */
        CK_ATTRIBUTE { attrType: CKA_SENSITIVE,         pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_EXTRACTABLE,       pValue: &false_ as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_ALWAYS_SENSITIVE,  pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_NEVER_EXTRACTABLE, pValue: &true_  as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_LOCAL,             pValue: &false_ as *const _ as CK_VOID_PTR, ulValueLen: 1 },
        /* omit the crypto attributes: OpenSC will set reasonable defaults for AES: true for CKA_ENCRYPT and CKA_DECRYPT, all the other: false */
    ];

    let unwrapping_rsa_key : CK_OBJECT_HANDLE =
        match find_object_by_class_type_id(ctx, session, CKO_PRIVATE_KEY, CKK_RSA, rsa_key_id) {
        Ok(vec) if vec.len()==1 => vec[0],
        Ok(_) => return Err(Error::UnavailableInformation),
        Err(_e) => return Err(Error::UnavailableInformation),
    };

    ctx.unwrap_key(session, &mech_rsa_pkcs, unwrapping_rsa_key, &crgram_rsa_wrapped_aes_key, &template_aes_key)
}

fn main() -> Result<(), Error> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            let ctx = Ctx::new_and_initialize("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll")?;
        }
        else {
            // let ctx = Ctx::new_and_initialize("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")?;
            let ctx = Ctx::new_and_initialize("opensc-pkcs11.so")?;
            /* if p11-kit installed and opensc-pkcs11.so configured with highest priority */
            //let ctx = Ctx::new_and_initialize("p11-kit-proxy.so")?;
        }
    }

    let slot_list = ctx.get_slot_list(true)?;
    if slot_list.is_empty() {
        eprintln!("Error; could not find any slots");
        return Err(Error::UnavailableInformation);
    }
    let slot = slot_list[0];
    println!("slot count: {}. Selected slotId: {}", slot_list.len(), slot);

    let session = ctx.open_session(slot, CKF_SERIAL_SESSION |  CKF_RW_SESSION, None, None)?;
    ctx.login(session, CKU_USER, Some("12345678"))?;

    let sec_oh = unwrap_aes_key_wrapped_by_rsa_key(&ctx, session)?;

    println!("CKO_SECRET_KEY:");
    match show_key_info(&ctx, session, sec_oh) {
        Ok(_val) => (),
        Err(Error::InvalidInput(msg)) => println!("{}", msg),
        _  => (),
    }

    ctx.logout(session)?;
    ctx.close_session(session)
}

/*
user@host:~/RustProjects/acos5_external/project_pkcs11_example_apps$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.01s
     Running `target/debug/project_pkcs11_example_apps`
slot count: 1. Selected slotId: 0

acos5_decipher:             in_len: 64, out_len: 64, sec_env_algo_flags: 0x0, input data: [3B, B, 59, 2A, 3E, BE, 64, 3C, 9, 0, 2E, 3E, F0, 97, 7A, 5A, B8, 7F, 47, 59, 70, 69, FD, 3F, 65, EE, 54, 36, F, D5, 6, 1B, 17, 96, 39, F2, DB, 53, D0, 12, E4, AB, 4B, 3C, 50, 31, 96, 68, A6, 66, 1F, 72, 52, 13, BF, C8, BF, B3, 7C, 6D, 37, C5, D4, C5]

acos5_decipher:             in_len: 64, out_len: 64, sec_env_algo_flags: 0x0,output data: [0, 2, 4, F7, 7D, 24, 62, FF, 90, 6F, 2F, 60, 20, F9, 13, 4D, FB, C8, C7, 57, 10, 63, B2, 9F, D2, 37, 1, FE, 42, EC, B, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, A, B, C, D, E, F, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 1A, 1B, 1C, 1D, 1E, 1F, 20]
CKO_SECRET_KEY:
Found a key:  Key label: Secret Key     Key ID: 0x09    Key type: 31 (0 (CKK_RSA), 3 (CKK_EC), 31 (CKK_AES))     is_token_object: true   is_private: true        is_modifiable: true     is_copyable: false      is_sensitive: false  is_extractable: true    is_always_sensitive: false      is_never_extractable: false     is_local: false         can_encrypt: true       can_decrypt: true       can_sign: false         can_verify: false       can_signRecover: false       can_verifyRecover: false        can_wrap: false         can_unwrap: false

user@host:~/RustProjects/acos5_external/project_pkcs11_example_apps$
*/
