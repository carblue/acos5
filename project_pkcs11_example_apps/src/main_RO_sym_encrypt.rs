/* main_RO_sym_encrypt.rs : do hardware/on-card symmetric decryption with an AES key */
/* This example requires existence of an AES key on card and listed in SKDF **AND**
    requires OpenSC code from my dev branch (it's on top of current OpenSC master)  at https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt
    and requires compiler switch --cfg sym_hw_encrypt  in opensc_sys and acos5 build.rs
   Functions used:
   C_Initialize
   C_GetSlotList
   C_OpenSession
   C_Login
   C_GetAttributeValue
   C_FindObjectsInit
   C_FindObjects
   C_FindObjectsFinal

   C_EncryptInit
   C_Encrypt

   C_Logout
   C_CloseSession
   C_Finalize
 */

use pkcs11::{Ctx};
use pkcs11::errors::{Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKU_USER,CK_OBJECT_CLASS, CK_ATTRIBUTE,
                    CK_VOID_PTR, CKA_CLASS, CK_OBJECT_HANDLE, CKA_KEY_TYPE,
                    CK_KEY_TYPE, CKO_SECRET_KEY,
                    CK_MECHANISM, CKK_AES, CKM_AES_ECB
//                    , CKA_LABEL, CKA_DECRYPT, CKM_AES_CBC, CKA_TOKEN, CKA_ENCRYPT, CK_BBOOL, CK_TRUE, CK_BYTE
};
use std::mem::size_of;
use std::convert::TryInto;
//use std::ffi::CStr;
use std::ptr::null_mut;

/*
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
*/

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

    let session = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)?;
    ctx.login(session, CKU_USER, Some("12345678"))?;
    // println!("CKO_PUBLIC_KEY:");

    /* find AES key labeled AES3 */
    let mut key_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let mut key_type: CK_KEY_TYPE = CKK_AES;
//    let mut true_ : CK_BBOOL = CK_TRUE;
//    let label = CStr::from_bytes_with_nul(b"AES3\0").unwrap().as_ptr();

    let template = [
        CK_ATTRIBUTE { attrType: CKA_CLASS,
            pValue: &mut key_class as *mut _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_OBJECT_CLASS>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_KEY_TYPE,
            pValue: &mut key_type as *mut _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_KEY_TYPE>().try_into().unwrap() },
/*
        CK_ATTRIBUTE { attrType: CKA_TOKEN,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_LABEL,
            pValue: label as *mut u8 as CK_VOID_PTR,
            ulValueLen: 4 },
        CK_ATTRIBUTE { attrType: CKA_ENCRYPT,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_DECRYPT,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
*/
        // CK_ATTRIBUTE { attrType: CKA_ID,
        //     pValue: id.as_mut_ptr() as CK_VOID_PTR,
        //     ulValueLen: 1 },
/*
    CK_UTF8CHAR label[] = “An AES secret key object”;
    CK_ATTRIBUTE template[] = {
        {CKA_LABEL, label, sizeof(label)-1},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_ENCRYPT, &true, sizeof(true)},
*************

    let mut template = vec![
        CK_ATTRIBUTE { attrType: CKA_LABEL,
                       pValue: label.as_mut_ptr() as CK_VOID_PTR,
                       ulValueLen: label.len().try_into().unwrap() },
*/
    ];
    ctx.find_objects_init(session, &template)?;

    let skeys : Vec<CK_OBJECT_HANDLE> = ctx.find_objects(session, 1)?;
    assert_eq!(1, skeys.len());
    ctx.find_objects_final(session)?;

//    let mut iv : [CK_BYTE; 16] = [0_u8; 16];
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_ECB, pParameter: null_mut() as CK_VOID_PTR, ulParameterLen: 0 };
        // mechanism: CKM_AES_CBC, pParameter: iv.as_mut_ptr() as CK_VOID_PTR, ulParameterLen: 16 };
/*
    let mut data : [CK_BYTE; PLAINTEXT_BUF_SZ];
    let mut encryptedData : [CK_BYTE; CIPHERTEXT_BUF_SZ];
    // CK_ULONG ulData1Len, ulData2Len, ulData3Len;
    // CK_RV rv;
    // .
    // .
    // firstEncryptedPieceLen = 90;
    // secondEncryptedPieceLen = CIPHERTEXT_BUF_SZ - firstEncryptedPieceLen;

plain text
Cryptoki has a terrible API. RIP\0

00 DC 03 04 25 83 00 22
key bytes (AES/256)
98 47 2C 6D A2 33 50 46 55 3F C3 91 52 AD 63 85 FE EF C3 B0 77 28 58 62 31 CA 34 FB 1E 85 80 32
00 00

ciphertext
36 fb 93 97 7c 07 65 4a 8e cb b5 d7 26 ad a2 a9
10 54 82 a9 68 8b 7b ff be 49 9b 97 44 48 36 2c
*/
    let plaintext_data = [
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c
    ];
    ctx.encrypt_init(session, &mechanism, skeys[0])?;
    let encrypted = ctx.encrypt(session, &plaintext_data)?; // -> Result<Vec<CK_BYTE>, Error>
println!("{:02X?}", encrypted);

    ctx.logout(session)?;
    ctx.close_session(session)
}
