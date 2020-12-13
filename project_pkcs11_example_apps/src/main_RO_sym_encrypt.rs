/* main_RO_sym_encrypt.rs : do hardware/on-card symmetric encryption with an AES key */
/* This example requires existence of an AES key on card and listed in SKDF **AND**
    requires OpenSC code from my dev branch (it's on top of current OpenSC master)  at
    https://github.com/carblue/OpenSC-1/tree/sym_hw_encrypt
    and requires compiler switch --cfg sym_hw_encrypt  in opensc_sys and acos5 and acos5_pkcs15 build.rs
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

use std::mem::size_of;
use std::convert::{TryInto, TryFrom};

use pkcs11::{Ctx, errors::Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKU_USER,CK_OBJECT_CLASS, CK_ATTRIBUTE, CK_TRUE, CK_BBOOL,
                    CK_VOID_PTR, CKA_CLASS, CK_OBJECT_HANDLE, CKA_KEY_TYPE, CKA_TOKEN, // CKA_LABEL,
                    CK_KEY_TYPE, CKO_SECRET_KEY, CKA_ENCRYPT, CKA_DECRYPT,
                    CK_MECHANISM, CKK_AES, CK_BYTE, CKM_AES_CBC_PAD, CKM_AES_CBC, CKM_AES_ECB
};


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

    /* find AES key (adapt if there is more than one existing) */
    let mut key_class: CK_OBJECT_CLASS = CKO_SECRET_KEY;
    let mut key_type: CK_KEY_TYPE = CKK_AES;
    let mut true_ : CK_BBOOL = CK_TRUE;
    // let cstring = std::ffi::CStr::from_bytes_with_nul(b"AES3\0").unwrap();

    let template = [
        CK_ATTRIBUTE { attrType: CKA_CLASS,
            pValue: &mut key_class as *mut _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_OBJECT_CLASS>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_KEY_TYPE,
            pValue: &mut key_type as *mut _ as CK_VOID_PTR,
            ulValueLen: size_of::<CK_KEY_TYPE>().try_into().unwrap() },
        CK_ATTRIBUTE { attrType: CKA_TOKEN,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_ENCRYPT,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
        CK_ATTRIBUTE { attrType: CKA_DECRYPT,
            pValue: &mut true_ as *mut _ as CK_VOID_PTR,
            ulValueLen: 1 },
/*
        CK_ATTRIBUTE { attrType: CKA_LABEL,
            pValue: cstring.as_ptr() as *mut u8 as CK_VOID_PTR,
            ulValueLen: 4 },
        CK_ATTRIBUTE { attrType: CKA_ID,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: 1 },
*/
    ];
    ctx.find_objects_init(session, &template)?;

    let skeys : Vec<CK_OBJECT_HANDLE> = ctx.find_objects(session, 1)?;
    assert_eq!(1, skeys.len());
    ctx.find_objects_final(session)?;

    let mut iv : [CK_BYTE; 16] = [0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff,
                                  0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9];
    let mechanism = CK_MECHANISM {
        mechanism: CKM_AES_CBC_PAD, //CKM_AES_CBC, // CKM_AES_ECB
        pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
        ulParameterLen: 16
    };
    ctx.encrypt_init(session, &mechanism, skeys[0])?;

    let mut plaintext_data = vec![
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c, 0xfe, 0x13 
    ];

    // add padding PKCS#7, if mechanism != CKM_AES_CBC_PAD
    if mechanism.mechanism != CKM_AES_CBC_PAD /* && plaintext_data.len()%16 != 0*/ {
        // BLOCKCIPHER_PAD_TYPE_PKCS#7
        let pad_num = 16 - plaintext_data.len()%16;
        plaintext_data.resize(plaintext_data.len()+pad_num, u8::try_from(pad_num).unwrap());
    }

    let encrypted : Vec<CK_BYTE> = ctx.encrypt(session, &plaintext_data)?;
println!("{:02X?}", encrypted);

    ctx.logout(session)?;
    ctx.close_session(session)
}

/*
Running `target/debug/project_pkcs11_example_apps`
slot count: 1. Selected slotId: 0
acos5_encrypt_sym  ECB 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E]
[B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0,  D8, 4B, 6D, 51, 69, 0C, F6, 5C, 99, D1, E5, 61, 1A, B6, C3, 9F]

acos5_encrypt_sym  CBC 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A,  24, FC, B3, DA, DF, 3F, 4D, E4, 9F, 0F, F1, 2D, F4, E9, E3, 6C]

acos5_encrypt_sym  CBC:PAD 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13]
acos5_encrypt_sym 
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A,  24, FC, B3, DA, DF, 3F, 4D, E4, 9F, 0F, F1, 2D, F4, E9, E3, 6C]

*/
