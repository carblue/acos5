
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case, clippy::upper_case_acronyms)]

use std::os::raw::{/*c_char, c_ulong,*/ c_long, c_int};

//from openssl  des.h and rand.h
#[allow(non_upper_case_globals)]
pub const DES_KEY_SZ_u8 : u8    = 8; // sizeof(DES_cblock)
pub const DES_KEY_SZ    : usize = 8; // sizeof(DES_cblock)
#[allow(dead_code)]
const AES_BLOCK_SIZE: usize = 16;

pub const Encrypt: i32 = 1;
pub const Decrypt: i32 = 0;

pub type DES_cblock       = [u8; DES_KEY_SZ];
//pub type const_DES_cblock = [u8; DES_KEY_SZ];
//pub type DES_LONG = c_ulong;

// pub const OPENSSL_VERSION:     i32 =  0;
// pub const OPENSSL_CFLAGS:      i32 =  1;
// pub const OPENSSL_BUILT_ON:    i32 =  2;
// pub const OPENSSL_PLATFORM:    i32 =  3;
// pub const OPENSSL_DIR:         i32 =  4;
// pub const OPENSSL_ENGINES_DIR: i32 =  5;

#[repr(C)]
#[derive(Default, Debug)]
struct DES_key_schedule {
    ks: [DES_cblock; 16],
}

#[repr(C)]
struct AES_KEY {
    rd_key: [u32; 60],
    rounds: c_int,
}

impl Default for AES_KEY {
    fn default() -> Self {
        Self {
            rd_key: [0; 60],
            rounds: 0
        }
    }
}

extern "C" {
//    pub fn OpenSSL_version_num() -> c_ulong;
//    pub fn OpenSSL_version(type_: i32) -> *const c_char;
    pub fn RAND_bytes(buf: *mut u8, num: i32) -> i32; // RAND_bytes() returns 1 on success, 0 otherwise

    pub fn DES_set_odd_parity(key: *mut DES_cblock);
    fn DES_set_key_checked  (block_key: *const u8, ks: *mut DES_key_schedule) -> i32;
//  fn DES_set_key_unchecked(block_key: *const u8, ks: *mut DES_key_schedule);
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
    // return 0 for success, -1 if userKey or key is NULL, or -2 if the number of bits is unsupported.
    #[allow(dead_code)]
    fn AES_set_encrypt_key(userKey: *const u8, bits: i32, key: *mut AES_KEY) -> i32;
    #[allow(dead_code)]
    fn AES_set_decrypt_key(userKey: *const u8, bits: i32, key: *mut AES_KEY) -> i32;

    #[allow(dead_code)]
    fn AES_ecb_encrypt(in_: *const u8, out: *mut u8, key: *const AES_KEY, enc: i32);
    #[allow(dead_code)]
    fn AES_cbc_encrypt(in_: *const u8, out: *mut u8, length: usize, key: *const AES_KEY, ivec: *mut u8, enc: i32);
}

/*
from https://github.com/tkaitchuck/aHash/blob/master/src/operations.rs
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes", not(miri)))]
#[allow(unused)]
#[inline(always)]
pub(crate) fn aesenc(value: u128, xor: u128) -> u128 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    use core::mem::transmute;
    unsafe {
        let value = transmute(value);
        transmute(_mm_aesenc_si128(value, transmute(xor)))
    }
}
*/

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
            output.extend_from_slice(&out_block);
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

/* this gets used currently only for Encrypt and data.len() known to be multiple of DES_KEY_SZ */
#[must_use]
pub fn des_ecb3_unpadded_8(data: &[u8], key: &[u8], mode: i32) -> Vec<u8> { // -> [u8; DES_KEY_SZ] {
    assert!(num_integer::Integer::is_multiple_of(&data.len(), &DES_KEY_SZ));
    assert_eq!(24, key.len());

    let mut ks = [DES_key_schedule::default(), DES_key_schedule::default(), DES_key_schedule::default()];
    let mut output = vec![0_u8; data.len()];
    unsafe {
        for (i, item) in key.chunks_exact(DES_KEY_SZ).enumerate() {
            let rv = DES_set_key_checked(item.as_ptr(), &mut ks[i]);
            if rv != 0 {
                return output;
            }
        }

        for (i, chunk) in data.chunks_exact(DES_KEY_SZ).enumerate() {
            DES_ecb3_encrypt(chunk.as_ptr(), output.as_mut_ptr().add(i*DES_KEY_SZ), &ks[0], &ks[1], &ks[2], mode);
        }
    }
    output
}

/*
acos5 applies padding only if !num_integer::Integer::is_multiple_of(&data.len(), &DES_KEY_SZ)
acos5 sets a padding indicator byte pi while encrypting:
pi is relevant here only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added (padding was applied and must be stripped in mode == Decrypt)
if pi==00, then it's known, that no 0x80 byte was added
*/
pub fn des_ede3_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut DES_cblock, mode: i32, pi: u8) -> Vec<u8> {
    assert_eq!(3*DES_KEY_SZ, key.len());
    assert!(mode==Encrypt || num_integer::Integer::is_multiple_of(&data.len(), &DES_KEY_SZ));

    let mut data = data.to_vec();
    // mode==Encrypt: pad data, if necessary
    if !num_integer::Integer::is_multiple_of(&data.len(), &DES_KEY_SZ) {
        data.push(0x80);
        while !num_integer::Integer::is_multiple_of(&data.len(), &DES_KEY_SZ) { data.push(0); }
    }

    let mut ks = [DES_key_schedule::default(), DES_key_schedule::default(), DES_key_schedule::default()];
    let mut output = vec![0_u8; data.len()];
    unsafe {
        for (i, item) in key.chunks_exact(DES_KEY_SZ).enumerate() {
            // DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
            let rv = DES_set_key_checked(item.as_ptr(), &mut ks[i]);
            if rv != 0 {
                return output;
            }
        }

        DES_ede3_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), c_long::try_from(data.len()).unwrap(),
                             &ks[0], &ks[1], &ks[2], ivec, mode);
    }

    if mode == Decrypt && pi==1 {
        while output.last().unwrap_or(&1) == &0  { let _unused = output.pop(); }
        if let Some(&b) = output.last() {
            if b == 0x80  { let _unused = output.pop(); }
            else { panic!("Incorrect padding detected!") }
        }
    }
    output
}

pub fn des_ede3_cbc_pad_80_mac(data: &[u8], key: &[u8], ivec: &mut DES_cblock) -> Vec<u8> {
    let mut result = des_ede3_cbc_pad_80(data, key, ivec, Encrypt, 0);
    assert!(result.len() >= DES_KEY_SZ);
    while result.len()>DES_KEY_SZ { let _unused = result.remove(0); }
    result
}

// AES
/* this will be used by EVO only for Encrypt and data known to be a multiple of AES_BLOCK_SIZE */
#[allow(dead_code)]
#[must_use]
fn aes_ecb_unpadded_16(data: &[u8], key: &[u8], mode: i32) -> Vec<u8> {
    assert!(num_integer::Integer::is_multiple_of(&data.len(), &AES_BLOCK_SIZE));
    assert!([16, 24, 32].contains(&key.len()));
    // assert_eq!(Encrypt, mode); // TODO missing AES_set_decrypt_key

    let mut aes_key = AES_KEY::default();
    let mut out_block = [0_u8; AES_BLOCK_SIZE];
    let mut output = Vec::with_capacity(data.len());
    let res;
    unsafe {
        if mode == Encrypt {
            res = AES_set_encrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &mut aes_key);
        }
        else {
            res = AES_set_decrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &mut aes_key);
        }
        assert_eq!(0, res);

        for chunk in data.chunks_exact(AES_BLOCK_SIZE) {
            AES_ecb_encrypt(chunk.as_ptr(), out_block.as_mut_ptr(), &aes_key, mode);
            output.extend_from_slice(&out_block[..]);
        }
    }
    output
}

/*
acos5 applies padding only if !num_integer::Integer::is_multiple_of(&data.len(), &AES_BLOCK_SIZE)
acos5 sets a padding indicator byte pi while encrypting:
pi is relevant here only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added (padding was applied and must be stripped in mode == Decrypt)
if pi==00, then it's known, that no 0x80 byte was added
*/
#[allow(dead_code)]
fn aes_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut [u8; AES_BLOCK_SIZE], mode: i32, pi: u8) -> Vec<u8> {
    assert!(mode==Encrypt || num_integer::Integer::is_multiple_of(&data.len(), &AES_BLOCK_SIZE));
    assert!([16, 24, 32].contains(&key.len()));

    let mut data = data.to_vec();
    // mode==Encrypt: pad data, if necessary
    if !num_integer::Integer::is_multiple_of(&data.len(), &AES_BLOCK_SIZE) {
        data.push(0x80);
        while !num_integer::Integer::is_multiple_of(&data.len(), &AES_BLOCK_SIZE) { data.push(0); }
    }

    let mut aes_key = AES_KEY::default();
    let mut output = vec![0_u8; data.len()];
    let res;
    unsafe {
        if mode == Encrypt {
            res = AES_set_encrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &mut aes_key);
        }
        else {
            res = AES_set_decrypt_key(key.as_ptr(), 8* i32::try_from(key.len()).unwrap(), &mut aes_key);
        }
        assert_eq!(0, res);

        AES_cbc_encrypt(data.as_ptr(), output.as_mut_ptr(), data.len(), &aes_key, ivec.as_mut_ptr(), mode);
    }

    if mode == Decrypt && pi==1 {
        while output.last().unwrap_or(&1) == &0  { let _unused = output.pop(); }
        if let Some(&b) = output.last() {
            if b == 0x80  { let _unused = output.pop(); }
            else { panic!("Incorrect padding detected!") }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use num_integer::Integer;
    use super::{Encrypt, Decrypt, DES_KEY_SZ, DES_cblock, des_ecb3_unpadded_8, des_ede3_cbc_pad_80,
                des_ede3_cbc_pad_80_mac /*, des_ecb3_pad_pkcs5*/,
                AES_BLOCK_SIZE, aes_ecb_unpadded_16, aes_cbc_pad_80, DES_set_odd_parity, };
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
    fn test_multiple() {
        assert_eq!(16, Integer::prev_multiple_of(&22, &8)); // equivalent: (integral_number / integral_step_size) * integral_step_size
        assert_eq!(24, 22.next_multiple_of(&8)); // if integral_number % integral_step_size == 0 {integral_number}
                                                       // else { (integral_number / integral_step_size +1) * integral_step_size }

        assert_eq!(24, Integer::prev_multiple_of(&24, &8)); // no selection of smaller multiple !!
        assert_eq!(24, 24.next_multiple_of(&8)); // no selection of larger  multiple !!
    }

    #[test]
    fn test_des_ecb3_unpadded_8() {
        let data = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let mut key  = [0x32, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x33, 0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x38,
                             0x34, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38];
        for i in 0..3 {
            unsafe { DES_set_odd_parity(key.as_mut_ptr().add(i*8) as *mut DES_cblock); }
        }
        let e = des_ecb3_unpadded_8(&data, &key, Encrypt);
        let d = des_ecb3_unpadded_8(&e, &key, Decrypt);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
    }

    #[test]
    fn test_aes_ecb_unpadded_16() {// $ cargo test test_aes_ecb_unpadded_16 -- --nocapture
        let data = [
            0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x20,
            0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
            0x68, 0x65, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x20,
            0x66, 0x6F, 0x72, 0x20, 0x00, 0x31, 0x00, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xf1, 0xe0, 0xd3, 0xc2, 0xb5, 0xa4, 0x97, 0x86
        ];
        let key  = [
            0x32, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x33, 0x31, 0x32, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x34, 0x31, 0x32, 0x33, 0x35, 0x36, 0x37, 0x38,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ];
        let e = aes_ecb_unpadded_16(&data, &key, Encrypt);
        let d = aes_ecb_unpadded_16(&e, &key, Decrypt);
// println!("{:X?}", e);
// println!("{:X?}", d);
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
        assert!(Integer::is_multiple_of(&e.len(), &DES_KEY_SZ));
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = des_ede3_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());

        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(Integer::is_multiple_of(&e.len(), &DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
//println!("{:X?}", e);
    }

    #[test]
    fn test_aes_cbc_pad_80() {
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
        let mut ivec : [u8; AES_BLOCK_SIZE] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = aes_cbc_pad_80(&data, &key, &mut ivec, Encrypt, 0);
        assert!(Integer::is_multiple_of(&e.len(), &AES_BLOCK_SIZE));
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = aes_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());
/*
        ivec = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(num_integer::Integer::is_multiple_of(&e.len(), &DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
*/
//println!("{:X?}", e);
    }
}
