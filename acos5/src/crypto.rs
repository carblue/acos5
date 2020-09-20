
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

use num_integer::Integer;

use std::os::raw::{c_char, c_ulong, c_long};
use std::convert::TryFrom;

//from openssl  des.h and rand.h
#[allow(non_upper_case_globals)]
pub const DES_KEY_SZ_u8 : u8    = 8; // sizeof(DES_cblock)
pub const DES_KEY_SZ    : usize = 8; // sizeof(DES_cblock)

pub const Encrypt: i32 = 1;
pub const Decrypt: i32 = 0;

pub type DES_cblock       = [u8; DES_KEY_SZ];
pub type const_DES_cblock = [u8; DES_KEY_SZ];
pub type DES_LONG = c_ulong;

pub const OPENSSL_VERSION:     i32 =  0;
pub const OPENSSL_CFLAGS:      i32 =  1;
pub const OPENSSL_BUILT_ON:    i32 =  2;
pub const OPENSSL_PLATFORM:    i32 =  3;
pub const OPENSSL_DIR:         i32 =  4;
pub const OPENSSL_ENGINES_DIR: i32 =  5;

#[repr(C)]
#[derive(Default, Debug)]
pub struct DES_key_schedule {
    ks: [DES_cblock; 16],
}

// TODO is this portable ?
#[link(name = "crypto")]
extern {
    pub fn OpenSSL_version_num() -> c_ulong;
    pub fn OpenSSL_version(type_: i32) -> *const c_char;
    pub fn RAND_bytes(buf: *mut u8, num: i32) -> i32; // RAND_bytes() returns 1 on success, 0 otherwise

    #[allow(dead_code)]
    fn DES_set_key_checked  (block_key: *const u8, ks: *mut DES_key_schedule) -> i32;
    fn DES_set_key_unchecked(block_key: *const u8, ks: *mut DES_key_schedule);
    fn DES_ecb3_encrypt(input: *const u8, output: *mut u8,
                        ks1: *const DES_key_schedule,
                        ks2: *const DES_key_schedule,
                        ks3: *const DES_key_schedule,
                        enc: i32);
    /* DES_ede3_cbc_encrypt encrypts (or decrypts, if enc is DES_DECRYPT) len bytes from in to out with 3DES in CBC mode.
       3DES uses three keys, thus the function takes three different DES_key_schedules.*/
    fn DES_ede3_cbc_encrypt(input: *const u8, output: *mut u8,
                            length: c_long,
                            ks1: *const DES_key_schedule,
                            ks2: *const DES_key_schedule,
                            ks3: *const DES_key_schedule,
                            ivec: *mut DES_cblock,
                            enc: i32);
}

/*
//  from https://gist.github.com/vincascm/fda1cff664fa027937a53446ba8ef605
//! triple des(3des) ecb pkcs5 padding encrypt/decrypt function for rust, use openssl crypto
//! library.
//! refer to <http://blog.csdn.net/lyjinger/article/details/1722570>
//! coded by vinoca.
//! 2017.11.24
pub fn des_ecb3_pad_pkcs5(data: &[u8], key: &str, mode: i32) -> Vec<u8> {

    // pad data
    let mut data = data.to_vec();
    let mut pad = 8 - data.len() % 8;
    if pad == 8 {
        pad = 0;
    }
    for _ in 0..pad {
        data.push(pad as u8);
    }

    // pad key
    let mut key = key.as_bytes().to_vec();
    key.truncate(24);
    for _ in 0..24 - key.len() {
        key.push(0);
    }

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut out_block = vec![0u8; 8];
    let mut output = Box::new(Vec::with_capacity(data.len()));
    unsafe {
        for (i, item) in key.chunks(8).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        for i in data.chunks(8) {
            DES_ecb3_encrypt(i.as_ptr(), out_block.as_mut_ptr(), &ks[0], &ks[1], &ks[2], mode);
            output.extend_from_slice(out_block.as_slice());
        }
    }
    if mode == Decrypt {
        let pad = *output.last().unwrap();
        (*output).truncate(data.len() - pad as usize);
        *output
    } else {
        *output
    }
}
*/

/* this gets used currently only for Encrypt and data known to be multiple of DES_KEY_SZ */
pub fn des_ecb3_unpadded_8(data: &[u8], key: &[u8], mode: i32) -> Vec<u8> { // -> [u8; DES_KEY_SZ] {
    assert!(data.len().is_multiple_of(&DES_KEY_SZ));
    assert_eq!(24, key.len());

    let key = key.to_vec();

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut out_block = vec![0_u8; DES_KEY_SZ];
    let mut output = Vec::with_capacity(data.len());
    unsafe {
        for (i, item) in key.chunks(DES_KEY_SZ).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        for i in data.chunks(DES_KEY_SZ) {
            DES_ecb3_encrypt(i.as_ptr(), out_block.as_mut_ptr(), &ks[0], &ks[1], &ks[2], mode);
            output.extend_from_slice(out_block.as_slice());
        }
    }
    output
}

/*
acos5 applies padding only if !data.len().is_multiple_of(&DES_KEY_SZ)
acos5 sets a padding indicator byte pi while encrypting:
pi is relevant here only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added (padding was applied and must be stripped in mode == Decrypt)
if pi==00, then it's known, that no 0x80 byte was added
*/
pub fn des_ede3_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut DES_cblock, mode: i32, pi: u8) -> Vec<u8> {
    assert_eq!(3*DES_KEY_SZ, key.len());
    assert!(mode==Encrypt || data.len().is_multiple_of(&DES_KEY_SZ));

    let mut data = data.to_vec();
    // mode==Encrypt: pad data, if necessary
    if !data.len().is_multiple_of(&DES_KEY_SZ) {
        data.push(0x80);
        while !data.len().is_multiple_of(&DES_KEY_SZ) { data.push(0); }
    }

    let key = key.to_vec();

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut output = vec![0_u8; data.len()];
    unsafe {
        for (i, item) in key.chunks(DES_KEY_SZ).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        DES_ede3_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), c_long::try_from(output.len()).unwrap(),
                             &ks[0], &ks[1], &ks[2], ivec, mode);
    }

    if mode == Decrypt && pi==1 {
        while output.last().is_some() && *output.last().unwrap()==0  { output.pop(); }
        if    output.last().is_some() {
            if *output.last().unwrap()==0x80  { output.pop(); }
            else { panic!("Incorrect padding detected!") }
        }
    }
    output
}

pub fn des_ede3_cbc_pad_80_mac(data: &[u8], key: &[u8], ivec: &mut DES_cblock) -> Vec<u8> {
    let mut result = des_ede3_cbc_pad_80(data, key, ivec, Encrypt, 0);
    assert!(result.len() >= DES_KEY_SZ);
    while result.len()>DES_KEY_SZ { result.remove(0); }
    result
}

#[cfg(test)]
mod tests {
    use num_integer::Integer;
    use super::{Encrypt, Decrypt, DES_KEY_SZ, DES_cblock, des_ecb3_unpadded_8, des_ede3_cbc_pad_80,
                des_ede3_cbc_pad_80_mac /*, des_ecb3_pad_pkcs5*/};
/*
    #[test]
    fn test_des_ecb3_pad_pkcs5() {
        let data = "hello world!";
        let key = "01234567899876543210";
        let e = des_ecb3_pad_pkcs5(&data.as_bytes(), &key, Encrypt);
        let d = des_ecb3_pad_pkcs5(&e, &key, Decrypt);
        println!("{:X?}", d);
        //println!("{:?}", std::str::from_utf8(&d).unwrap());
    }
*/
    #[test]
    fn test_des_ecb3_unpadded_8() {
        let data = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let key  = [0x32, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x33, 0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x34, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38];
        let e = des_ecb3_unpadded_8(&data, &key, Encrypt);
        let d = des_ecb3_unpadded_8(&e, &key, Decrypt);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
    }

    #[test]
    fn test_des_ede3_cbc_pad_80() {
        let data = [
            0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
            0x66, 0x6F, 0x72, 0x20, 0x00, 0x31, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33
        ];
        let key  = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let mut ivec : DES_cblock = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80(&data, &key, &mut ivec, Encrypt, 0);
        assert!(e.len().is_multiple_of(&DES_KEY_SZ));
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = des_ede3_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());

        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(e.len().is_multiple_of(&DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
//println!("{:X?}", e);
    }
}
