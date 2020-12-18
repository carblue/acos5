/* mmain_RO_sym_decrypt.rs : do hardware/on-card symmetric decryption with an AES key */
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

   C_DecryptInit
   C_Decrypt

   C_Logout
   C_CloseSession
   C_Finalize
 */

use std::mem::size_of;
use std::convert::TryInto;

use pkcs11::{Ctx, errors::Error};
use pkcs11::types::{CKF_SERIAL_SESSION, CKU_USER,CK_OBJECT_CLASS, CK_ATTRIBUTE, CKA_ENCRYPT,
                    CKA_DECRYPT, CK_VOID_PTR, CKA_CLASS, CK_OBJECT_HANDLE, CK_BYTE, CKA_KEY_TYPE,
                    CK_KEY_TYPE, CK_BBOOL, CKO_SECRET_KEY, CKA_TOKEN, CKR_ENCRYPTED_DATA_LEN_RANGE,
                    CK_MECHANISM, CKK_AES, CK_TRUE, CKM_AES_CBC_PAD, CKM_AES_CBC, CKM_AES_ECB
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

    /* find AES key labeled AES3 */
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
        mechanism: CKM_AES_CBC_PAD, pParameter: iv.as_mut_ptr() as CK_VOID_PTR, ulParameterLen: 16 };
    ctx.decrypt_init(session, &mechanism, skeys[0])?;

    // let encrypted_data_was_padded = true;
    let encrypted_data = [
/* * /
        0xB2, 0x72, 0x1A, 0x53, 0xA4, 0xE2, 0xA4, 0x0B, 0x5C, 0x6B, 0x80, 0x8B, 0x0A, 0x7A, 0xD3, 0xF5,
        0x38, 0x2E, 0x9D, 0xBE, 0x6B, 0x31, 0x14, 0x14, 0x3B, 0x89, 0x49, 0x4A, 0xCF, 0x06, 0x79, 0xB0,
        0xD8, 0x4B, 0x6D, 0x51, 0x69, 0x0C, 0xF6, 0x5C, 0x99, 0xD1, 0xE5, 0x61, 0x1A, 0xB6, 0xC3, 0x9F
/ * */
/* */
        0x2B, 0x30, 0x7D, 0x2F, 0x7D, 0x32, 0x5B, 0xFF, 0xB2, 0x96, 0x8A, 0x01, 0x8F, 0x27, 0x09, 0x96,
        0x38, 0xCB, 0x94, 0xAE, 0xC9, 0x06, 0x34, 0x7F, 0x40, 0xEB, 0xF7, 0x8E, 0xE8, 0xFE, 0xDD, 0x3A,
        0x24, 0xFC, 0xB3, 0xDA, 0xDF, 0x3F, 0x4D, 0xE4, 0x9F, 0x0F, 0xF1, 0x2D, 0xF4, 0xE9, 0xE3, 0x6C
/* */
    ];
    let mut decrypted = ctx.decrypt(session, &encrypted_data)?; // -> Result<Vec<CK_BYTE>, Error>

    // remove padding PKCS#7
    if !decrypted.is_empty() && mechanism.mechanism != CKM_AES_CBC_PAD /* && encrypted_data_was_padded*/ {
        // BLOCKCIPHER_PAD_TYPE_PKCS7
        let pad_byte = decrypted[decrypted.len()-1];
        if pad_byte > 16 || pad_byte == 0  { return Err(Error::Pkcs11(CKR_ENCRYPTED_DATA_LEN_RANGE)) }
        let mut count_pad_byte : usize = 0;
        for &b in decrypted.iter().rev() {
            if b == pad_byte { count_pad_byte += 1 } else { break }
            if count_pad_byte == 16 { break }
        }
        if count_pad_byte != pad_byte.into() { return Err(Error::Pkcs11(CKR_ENCRYPTED_DATA_LEN_RANGE)) }
        decrypted.truncate(decrypted.len()-count_pad_byte);
    }

println!("{:02X?}", decrypted);

    ctx.logout(session)?;
    ctx.close_session(session)
}

/*
Running `target/debug/project_pkcs11_example_apps`
slot count: 1. Selected slotId: 0
acos5_encrypt_sym  ECB 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E]
[B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0,  D8, 4B, 6D, 51, 69, 0C, F6, 5C, 99, D1, E5, 61, 1A, B6, C3, 9F]
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13]

acos5_encrypt_sym  CBC 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E, 0E]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A,  24, FC, B3, DA, DF, 3F, 4D, E4, 9F, 0F, F1, 2D, F4, E9, E3, 6C]
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13]

acos5_encrypt_sym  CBC:PAD 34
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A,  24, FC, B3, DA, DF, 3F, 4D, E4, 9F, 0F, F1, 2D, F4, E9, E3, 6C]
[36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C,  FE, 13]

*/
