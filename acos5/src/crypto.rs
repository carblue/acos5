
#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case)]

use num_integer::Integer;

use std::os::raw::{c_uchar, c_int, c_ulong, c_long};
//use std::ptr::{copy_nonoverlapping};

//from openssl  des.h and rand.h
pub const DES_KEY_SZ : usize = 8; // sizeof(DES_cblock)
#[allow(non_upper_case_globals)]
pub const DES_KEY_SZ_u8 : c_uchar = DES_KEY_SZ as c_uchar;

pub const Encrypt: c_int = 1;
pub const Decrypt: c_int = 0;

pub type DES_cblock       = [c_uchar; DES_KEY_SZ];
pub type const_DES_cblock = [c_uchar; DES_KEY_SZ];
pub type DES_LONG = c_ulong;

#[repr(C)]
#[derive(Default, Debug)]
pub struct DES_key_schedule {
    ks: [DES_cblock; 16],
}

// TODO is this portable ?
#[link(name = "crypto")]
extern {
    pub fn RAND_bytes(buf: *mut c_uchar, num: c_int) -> c_int; // RAND_bytes() returns 1 on success, 0 otherwise

    #[allow(dead_code)]
    fn DES_set_key_checked  (block_key: *const c_uchar, ks: *mut DES_key_schedule) -> c_int;
    fn DES_set_key_unchecked(block_key: *const c_uchar, ks: *mut DES_key_schedule);
    fn DES_ecb3_encrypt(input: *const c_uchar, output: *mut c_uchar,
                        ks1: *const DES_key_schedule,
                        ks2: *const DES_key_schedule,
                        ks3: *const DES_key_schedule,
                        enc: c_int);
    /* DES_ede3_cbc_encrypt encrypts (or decrypts, if enc is DES_DECRYPT) len bytes from in to out with 3DES in CBC mode.
       3DES uses three keys, thus the function takes three different DES_key_schedules.*/
    fn DES_ede3_cbc_encrypt(input: *const c_uchar, output: *mut c_uchar,
                            length: c_long,
                            ks1: *const DES_key_schedule,
                            ks2: *const DES_key_schedule,
                            ks3: *const DES_key_schedule,
                            ivec: *mut DES_cblock,
                            enc: c_int);
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

/* pi is acos5 padding indicator, relevant only for Decrypt:
if pi==01, then it's known, that  a 0x80 byte was added
if pi==00, then it's known, that no 0x80 byte was added
*/
/* pi is relevant only for Decrypt:
   The 0x80 padding is
*/
pub fn des_ede3_cbc_pad_80(data: &[u8], key: &[u8], ivec: &mut DES_cblock, mode: c_int, pi: u8) -> Vec<u8> {
    assert_eq!(3*DES_KEY_SZ, key.len());
    assert!(mode==Encrypt || data.len().is_multiple_of(&DES_KEY_SZ));

    // pad data
    let mut data = data.to_vec();
    if !data.len().is_multiple_of(&DES_KEY_SZ) {
        data.push(0x80);
        while !data.len().is_multiple_of(&DES_KEY_SZ) { data.push(0); }
    }

    let key = key.to_vec();

    let mut ks = Vec::new();
    for _ in 0..3 {
        ks.push(DES_key_schedule::default());
    }
    let mut out_block = vec![0_u8; data.len()];
//    let mut output = /*Box::new(*/Vec::with_capacity(data.len())/*)*/;
    unsafe {
        for (i, item) in key.chunks(DES_KEY_SZ).enumerate() {
            DES_set_key_unchecked(item.as_ptr(), &mut ks[i]);
        }

        DES_ede3_cbc_encrypt(data.as_ptr(), out_block.as_mut_ptr(), out_block.len() as c_long,
                             &ks[0], &ks[1], &ks[2], ivec, mode);
    }

    if mode == Decrypt && pi==1 {
        while out_block.last().is_some() && *out_block.last().unwrap()==0     { out_block.pop(); }
        if    out_block.last().is_some() && *out_block.last().unwrap()==0x80  { out_block.pop(); }
    }
    out_block
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
        let mut ivec : DES_cblock = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let d = des_ede3_cbc_pad_80(&e, &key, &mut ivec, Decrypt, 1);
//println!("{:X?}", e);
//println!("{:X?}", d);
        assert_eq!(&data[..], d.as_slice());

        let mut ivec : DES_cblock = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let e = des_ede3_cbc_pad_80_mac(&data, &key, &mut ivec);
        assert!(e.len().is_multiple_of(&DES_KEY_SZ));
        assert_eq!(&[0xBF, 0x59, 0xFF, 0x28, 0xE3, 0x23, 0xB9, 0xF4][..], e.as_slice());
//println!("{:X?}", e);
    }
}
