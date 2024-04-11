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
    // let cstring = c"AES3";

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
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
        0x10, 0x54, 0x82, 0xa9, 0x68, 0x8b, 0x7b, 0xff, 0xbe, 0x49, 0x9b, 0x97, 0x44, 0x48, 0x36, 0x2c,
        0x36, 0xfb, 0x93, 0x97, 0x7c, 0x07, 0x65, 0x4a, 0x8e, 0xcb, 0xb5, 0xd7, 0x26, 0xad, 0xa2, 0xa9,
    ];

    // add padding PKCS#7, if mechanism != CKM_AES_CBC_PAD
    if mechanism.mechanism != CKM_AES_CBC_PAD {
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
/*
     Running `target/debug/project_pkcs11_example_apps`
slot count: 1. Selected slotId: 0

ECB 240
acos5_encrypt_sym input: algorithm: 43, algorithm_flags: 1000000, key_ref[0]: 83, plaintext_len: 256, plaintext: [36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
[B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, 38, 2E, 9D, BE, 6B, 31, 14, 14, 3B, 89, 49, 4A, CF, 06, 79, B0, B2, 72, 1A, 53, A4, E2, A4, 0B, 5C, 6B, 80, 8B, 0A, 7A, D3, F5, D4, 5D, 7C, 5A, A2, 6B, CA, 9D, 6B, 1D, 5D, DB, F6, 8F, 9E, F6]

CBC 240
acos5_encrypt_sym input: algorithm: 43, algorithm_flags: 2000000, key_ref[0]: 83, plaintext_len: 256, plaintext: [36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A, 17, 9F, AC, E7, 68, BD, DE, 6F, 29, DB, 6A, C1, 36, 75, 40, 0B, FE, 5D, 01, 57, BC, A7, DD, 5E, 84, D9, 51, 1D, 5A, F2, F8, A4, 39, 52, 0B, FC, 93, 61, 16, 50, 6A, CA, 55, AF, 3B, 93, A8, 16, 7D, 13, E4, 25, D0, 20, F9, AF, 85, A5, A3, 95, B6, FF, D3, 6C, 2B, 1F, E2, F6, EB, C5, 1E, CA, 0B, 21, 3B, A2, 7A, 2B, 66, 33, 47, C7, FE, 4A, 77, E1, 27, 8C, DD, 7A, DE, 80, 43, 3D, AB, C2, 84, 7B, 52, 66, 0E, F0, 74, D0, 01, EB, 7D, AD, BE, CF, 0A, 32, 37, B4, 82, C5, 45, 83, 47, A3, 37, D2, 28, 94, B3, B4, EF, 92, E3, E1, B2, 6B, DD, D5, 39, 92, 38, 89, 86, 96, 30, 03, 04, 41, 0E, 5A, F9, 8E, 03, D0, 83, B3, 0F, 30, 0E, C9, B3, DC, 95, 5C, 01, 84, 06, D3, F9, 18, ED, 6D, 1F, F7, 2A, F0, 67, 8D, 37, 19, 8A, DD, 7F, 69, E4, 04, 2A, 6A, 3D, 4A, 52, 10, 95, 2F, C4, 36, 09, 36, A6, CD, 02, E3, CA, 03, 4C, 37, 7C, 63, 5B, 22, 13, C4, C2, DC, B0, 66, 74, A9, 27, 63, C5, 74, 66, F7, EB, 1B, 49, 0F]


CBC_PAD 240
acos5_encrypt_sym input: algorithm: 43, algorithm_flags: 4000000, key_ref[0]: 83, plaintext_len: 240, plaintext: [36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9, 10, 54, 82, A9, 68, 8B, 7B, FF, BE, 49, 9B, 97, 44, 48, 36, 2C, 36, FB, 93, 97, 7C, 07, 65, 4A, 8E, CB, B5, D7, 26, AD, A2, A9]
[2B, 30, 7D, 2F, 7D, 32, 5B, FF, B2, 96, 8A, 01, 8F, 27, 09, 96, 38, CB, 94, AE, C9, 06, 34, 7F, 40, EB, F7, 8E, E8, FE, DD, 3A, 17, 9F, AC, E7, 68, BD, DE, 6F, 29, DB, 6A, C1, 36, 75, 40, 0B, FE, 5D, 01, 57, BC, A7, DD, 5E, 84, D9, 51, 1D, 5A, F2, F8, A4, 39, 52, 0B, FC, 93, 61, 16, 50, 6A, CA, 55, AF, 3B, 93, A8, 16, 7D, 13, E4, 25, D0, 20, F9, AF, 85, A5, A3, 95, B6, FF, D3, 6C, 2B, 1F, E2, F6, EB, C5, 1E, CA, 0B, 21, 3B, A2, 7A, 2B, 66, 33, 47, C7, FE, 4A, 77, E1, 27, 8C, DD, 7A, DE, 80, 43, 3D, AB, C2, 84, 7B, 52, 66, 0E, F0, 74, D0, 01, EB, 7D, AD, BE, CF, 0A, 32, 37, B4, 82, C5, 45, 83, 47, A3, 37, D2, 28, 94, B3, B4, EF, 92, E3, E1, B2, 6B, DD, D5, 39, 92, 38, 89, 86, 96, 30, 03, 04, 41, 0E, 5A, F9, 8E, 03, D0, 83, B3, 0F, 30, 0E, C9, B3, DC, 95, 5C, 01, 84, 06, D3, F9, 18, ED, 6D, 1F, F7, 2A, F0, 67, 8D, 37, 19, 8A, DD, 7F, 69, E4, 04, 2A, 6A, 3D, 4A, 52, 10, 95, 2F, C4, 36, 09, 36, A6, CD, 02, E3, CA, 03, 4C, 37, 7C, 63, 5B, 22, 13, C4, C2, DC, B0, 66, 74, A9, 27, 63, C5, 74, 66, F7, EB, 1B, 49, 0F]


*/
