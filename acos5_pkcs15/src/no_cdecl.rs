/*
 * no:cdecl.rs: Driver 'acos5_pkcs15' -
 *
 * Copyright (C) 2019-  Carsten Blüggel <bluecars@posteo.eu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110  USA
 */

//use libc::strlen;
//use std::ffi::CStr;
use std::os::raw::c_void;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0)))]
use std::os::raw::c_ulong;
use std::collections::HashSet;
use std::ptr::addr_of_mut;
#[cfg(not(target_os = "windows"))]
use std::ptr::null_mut;
use std::cmp::Ordering;
// use std::slice::from_raw_parts;

use opensc_sys::opensc::{SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES, sc_card_ctl, sc_card};
#[cfg(not(target_os = "windows"))]
use opensc_sys::opensc::{sc_select_file, sc_read_binary,
                         sc_delete_file, sc_create_file, sc_update_binary, sc_transmit_apdu};

#[cfg(not(target_os = "windows"))]
use opensc_sys::types::{SC_AC_OP_DELETE, SC_AC_OP_DELETE_SELF, SC_AC_OP_CREATE_EF, SC_AC_OP_UPDATE, SC_APDU_CASE_1};
use opensc_sys::pkcs15::{sc_pkcs15_card, SC_PKCS15_SKDF, SC_PKCS15_TYPE_SKEY, sc_pkcs15_skey_info,
                         SC_PKCS15_SEARCH_CLASS_PRKEY, SC_PKCS15_SEARCH_CLASS_PUBKEY,
                         sc_pkcs15_prkey_info, sc_pkcs15_pubkey_info, sc_pkcs15_parse_df};
#[cfg(not(target_os = "windows"))]
use opensc_sys::pkcs15::{SC_PKCS15_PRKDF, SC_PKCS15_PUKDF};
#[cfg(not(target_os = "windows"))]
use opensc_sys::pkcs15_init::sc_pkcs15init_authenticate;
#[cfg(not(target_os = "windows"))]
use opensc_sys::profile::sc_profile;
use opensc_sys::errors::{SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_CARD_CMD_FAILED, SC_SUCCESS, SC_ERROR_INTERNAL};
#[cfg(not(target_os = "windows"))]
use opensc_sys::errors::SC_ERROR_NOT_ENOUGH_MEMORY;
use opensc_sys::log::sc_dump_hex;

use crate::constants_types::{SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3, SC_CARD_TYPE_ACOS5_EVO_V4,
                             file_id_from_path_value, CardCtlAlgoRefSymStore, SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE //, FCI
};
#[cfg(not(target_os = "windows"))]
use crate::constants_types::{GuardFile, DataPrivate, file_id_se, SC_CARDCTL_ACOS5_GET_FREE_SPACE, build_apdu};
use crate::wrappers::{wr_do_log, wr_do_log_t, wr_do_log_rv};
#[cfg(not(target_os = "windows"))]
use crate::wrappers::wr_do_log_sds;
use crate::missing_exports::find_df_by_type;
#[cfg(not(target_os = "windows"))]
use crate::tasn1_pkcs15_util::DirectoryRange;

#[cfg(not(target_os = "windows"))]
const INC : usize = 0x100;

#[must_use]
pub fn rsa_modulus_bits_canonical(rsa_modulus_bits: usize) -> usize { ((rsa_modulus_bits + 8) /256) *256 }

///
/// # Panics
pub fn first_of_free_indices(p15card: &mut sc_pkcs15_card, file_id_sym_keys: &mut u16) -> i32
{
    if p15card.card.is_null() || unsafe { (*p15card.card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
    // let card = unsafe { &mut *p15card.card };
    let ctx = unsafe { &mut *(*p15card.card).ctx };
    let f = c"first_of_free_indices";
    log3ifc!(ctx,f,line!());

    let df_path = match find_df_by_type(p15card, SC_PKCS15_SKDF) {
        Ok(df) => if df.enumerated==1 {&df.path} else {return -1},
        Err(e) => return e,
    };
    log3if!(ctx,f,line!(), c"df_list.path of SC_PKCS15_SKDF: %s",
        unsafe { sc_dump_hex(df_path.value.as_ptr(), df_path.len) });
    let mut obj_list_ptr = p15card.obj_list;
    if obj_list_ptr.is_null() {
        return -1;
    }
    let mut index_possible : HashSet<u8> = HashSet::with_capacity(255);
    for i in 0..255 { let _unused = index_possible.insert(i+1); }

    while !obj_list_ptr.is_null() {
        let obj_list = unsafe { &*obj_list_ptr };
        if (obj_list.type_ & SC_PKCS15_TYPE_SKEY) == SC_PKCS15_TYPE_SKEY {
            assert!(!obj_list.data.is_null());
            // log3if!(ctx,f,line!(), c"obj_list.type_: %X",        obj_list.type_);
            // log3if!(ctx,f,line!(), c"obj_list.label: %s",        obj_list.label.as_ptr());
            // log3if!(ctx,f,line!(), c"obj_list.flags: %X",        obj_list.flags);
            // log3if!(ctx,f,line!(), c"obj_list.content.len: %zu", obj_list.content.len);
            let skey_info = unsafe { &*obj_list.data.cast::<sc_pkcs15_skey_info>() };
            // log3if!(ctx,f,line!(), c"skey_info.id.len: %zu",       skey_info.id.len);
            // log3if!(ctx,f,line!(), c"skey_info.id: %s",
            //     unsafe { sc_dump_hex(skey_info.id.value.as_ptr(), skey_info.id.len) });
            log3if!(ctx,f,line!(), c"skey_info.key_reference: %d", skey_info.key_reference);
            log3if!(ctx,f,line!(), c"skey_info.key_type: %lu",     skey_info.key_type);
            // log3if!(ctx,f,line!(), c"skey_info.path: %s",
            //     unsafe { sc_dump_hex(skey_info.path.value.as_ptr(), skey_info.path.len) });
            // log3if!(ctx,f,line!(), c"skey_info.path.index: %d",    skey_info.path.index);
            // log3if!(ctx,f,line!(), c"skey_info.path.count: %d",    skey_info.path.count);
            assert!(skey_info.path.index >= 0 && skey_info.path.index <= 255);
            let _unused = index_possible.remove(& u8::try_from(skey_info.path.index).unwrap());
            if  *file_id_sym_keys == 0 {
                *file_id_sym_keys = file_id_from_path_value(&skey_info.path.value[..skey_info.path.len]);
            }
        }
        obj_list_ptr = obj_list.next;
    }
    let mut index_possible_min = 256_u16;
    for &elem in &index_possible {
        if  index_possible_min > u16::from(elem) {
            index_possible_min = u16::from(elem);
        }
    }
    i32::from(u8::try_from(index_possible_min).unwrap())
}

/* find unused file id s, i.e. not listed in EF.PrKDF, EF.PuKDF (, EF.PuKDF_TRUSTED) */
///
/// # Panics
///
/// # Errors
pub fn free_fid_asym(p15card: &mut sc_pkcs15_card) -> Result<(u16, u16), i32>
{
    if p15card.card.is_null() || unsafe { (*p15card.card).ctx.is_null() } {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }
    let ctx = unsafe { &mut *(*p15card.card).ctx };
    let f = c"free_fid_asym";
    log3ifc!(ctx,f,line!());

    let mut df = p15card.df_list;
    while !df.is_null() {
        let df_ref = unsafe { &*df };
        if (3 & (1 << df_ref.type_)) == 0 {
            df = df_ref.next;
            continue;
        }
        if df_ref.enumerated != 0 {
            df = df_ref.next;
            continue;
        }
        /* Enumerate the DF's, so p15card->obj_list is populated. */
        unsafe {
            let _unused =
            if p15card.ops.parse_df.is_some() { p15card.ops.parse_df.unwrap()(p15card, df) }
            else                              { sc_pkcs15_parse_df(p15card, df) }
        ;}
        df = df_ref.next;
    }

    let mut vec : Vec<u16> = (0x5000..0x6000).collect();
    vec.retain(|&x|  x != 0x5030 && x != 0x5031 && x != 0x5032 && x != 0x5033 && x != 0x5154 && x != 0x5155);
//println!("{:X?}", vec);

    /* for SC_PKCS15_PRKDF */
    // let df_path = match find_df_by_type(p15card, SC_PKCS15_PRKDF) {
    //     Ok(df) => if df.enumerated==1 {&df.path} else {return Err(-1)},
    //     Err(e) => return Err(e),
    // };
//log3if!(ctx,f,line!(), c"df_list.path of SC_PKCS15_PRKDF: %s",
//    unsafe { sc_dump_hex(df_path.value.as_ptr(), df_path.len) });
    let mut obj_list_ptr = p15card.obj_list;
    if obj_list_ptr.is_null() {
        return Err(-1);
    }
    while !obj_list_ptr.is_null() {
        let obj_list = unsafe { &*obj_list_ptr };
        if (1 << (obj_list.type_ >> 8)) == SC_PKCS15_SEARCH_CLASS_PRKEY {
            assert!(!obj_list.data.is_null());
//log3if!(ctx,f,line!(), c"obj_list.type_: %X",        obj_list.type_);
//log3if!(ctx,f,line!(), c"obj_list.label: %s",        obj_list.label.as_ptr());
            let prkey_info = unsafe { &*obj_list.data.cast::<sc_pkcs15_prkey_info>() };
//log3if!(ctx,f,line!(), c"prkey_info.path: %s",
//    unsafe { sc_dump_hex(prkey_info.path.value.as_ptr(), prkey_info.path.len) });
            let y = file_id_from_path_value(&prkey_info.path.value[..prkey_info.path.len]);
            vec.retain(|&x|  x != y);
        }
        obj_list_ptr = obj_list.next;
    }

    /* same for SC_PKCS15_PUKDF */
    // let df_path = match find_df_by_type(p15card, SC_PKCS15_PUKDF) {
    //     Ok(df) => if df.enumerated==1 {&df.path} else {return Err(-1)},
    //     Err(e) => return Err(e),
    // };
//log3if!(ctx,f,line!(), c"df_list.path of SC_PKCS15_PUKDF: %s",
//    unsafe { sc_dump_hex(df_path.value.as_ptr(), df_path.len) });
    obj_list_ptr = p15card.obj_list;
/*
    if obj_list_ptr.is_null() {
        return Err(-1);
    }
*/
    while !obj_list_ptr.is_null() {
        let obj_list = unsafe { &*obj_list_ptr };
        if (1 << (obj_list.type_ >> 8)) == SC_PKCS15_SEARCH_CLASS_PUBKEY {
            assert!(!obj_list.data.is_null());
//log3if!(ctx,f,line!(), c"obj_list.type_: %X",        obj_list.type_);
//log3if!(ctx,f,line!(), c"obj_list.label: %s",        obj_list.label.as_ptr());
            let pukey_info = unsafe { &*obj_list.data.cast::<sc_pkcs15_pubkey_info>() };
//log3if!(ctx,f,line!(), c"pukey_info.path: %s",
//    unsafe { sc_dump_hex(pukey_info.path.value.as_ptr(), pukey_info.path.len) });
            let y = file_id_from_path_value(&pukey_info.path.value[..pukey_info.path.len]);
            vec.retain(|&x|  x != y);
        }
        obj_list_ptr = obj_list.next;
    }
/*
    let df_path = match find_df_by_type(p15card, SC_PKCS15_PUKDF_TRUSTED) {
        Ok(df) => if df.enumerated==1 {&df.path} else {return Err(-1)},
        Err(e) => return Err(e),
    };
    log3if!(ctx,f,line!(), c"df_list.path of SC_PKCS15_PUKDF_TRUSTED: %s",
        unsafe { sc_dump_hex(df_path.value.as_ptr(), df_path.len) });
    let mut obj_list_ptr = p15card.obj_list;
    if obj_list_ptr.is_null() {
        return Err(-1);
    }
    while !obj_list_ptr.is_null() {
        let obj_list = unsafe { &*obj_list_ptr };
        if (1 << (obj_list.type_ >> 8)) == SC_PKCS15_SEARCH_CLASS_PUBKEY {
            assert!(!obj_list.data.is_null());
            log3if!(ctx,f,line!(), c"obj_list.type_: %X",        obj_list.type_);
            log3if!(ctx,f,line!(), c"obj_list.label: %s",        obj_list.label.as_ptr());
            let pukey_info = unsafe { &*(obj_list.data as *mut sc_pkcs15_pubkey_info) };
            log3if!(ctx,f,line!(), c"pukey_info.path: %s",
                unsafe { sc_dump_hex(pukey_info.path.value.as_ptr(), pukey_info.path.len) });
            let y = file_id_from_path_value(&pukey_info.path.value[..pukey_info.path.len]);
            vec.retain(|&x|  x != y);
        }
        obj_list_ptr = obj_list.next;
    }
*/

    if vec.len() >= 2 { log3ifr!(ctx,f,line!(), SC_SUCCESS); Ok((vec[0], vec[1])) }
    else              { log3ifr!(ctx,f,line!(), SC_ERROR_INTERNAL); Err(SC_ERROR_INTERNAL) }
} // free_fid_asym

///
/// # Panics
///
/// # Errors
//#[allow(dead_code)]  // no usage currently
//#[cold]
#[cfg(not(target_os = "windows"))]
pub fn check_enlarge_prkdf_pukdf(profile: &mut sc_profile, p15card: &mut sc_pkcs15_card, key_info: &sc_pkcs15_prkey_info) -> Result<(), i32>
{
    if p15card.card.is_null() || unsafe { (*p15card.card).ctx.is_null() } {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }
    let card = unsafe { &mut *p15card.card };
    let ctx = unsafe { &mut *(*p15card.card).ctx };
    let f = c"check_enlarge_prkdf_pukdf";
    log3ifc!(ctx,f,line!());

    let df_path_priv = match find_df_by_type(p15card, SC_PKCS15_PRKDF) {
        Ok(df) => if df.enumerated==1 {df.path} else {return Err(-1)},
        Err(e) => return Err(e),
    };
    let df_path_pub = match find_df_by_type(p15card, SC_PKCS15_PUKDF) {
        Ok(df) => if df.enumerated==1 {df.path} else {return Err(-1)},
        Err(e) => return Err(e),
    };
    assert!(df_path_priv.len >= 4);
    assert!(df_path_pub.len >= 4);
    let mut df_path_parent = df_path_priv;
    df_path_parent.len -= 2;
    let file_priv_id = file_id_from_path_value(&df_path_priv.value[..df_path_priv.len]);
    let file_pub_id  = file_id_from_path_value( &df_path_pub.value[..df_path_pub.len]);
//    let file_parent_id = file_id_from_path_value(&df_path_parent.value[..df_path_parent.len]);
    let dp = unsafe { Box::from_raw(card.drv_data.cast::<DataPrivate>()) };
    // let dp_files_value = &dp.files[&file_priv_id];
    let size_priv : usize = file_id_se(dp.files[&file_priv_id].1).into();
    let size_pub  : usize = file_id_se(dp.files[&file_pub_id].1).into();
    let _unused = Box::leak(dp);

    let mut file_parent = null_mut();
    let guard_file_parent = GuardFile::new(&mut file_parent);
    let mut rv = unsafe { sc_select_file(card, &df_path_parent, *guard_file_parent) };
    if rv != SC_SUCCESS { return Err(-1); }

    let mut file_priv = null_mut();
    let guard_file_priv = GuardFile::new(&mut file_priv);
    rv = unsafe { sc_select_file(card, &df_path_priv, *guard_file_priv) };
    if rv != SC_SUCCESS { return Err(-1); }
    let mut rbuf_priv = vec![0_u8; size_priv];

    rv = unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            sc_read_binary(card, 0, rbuf_priv.as_mut_ptr(), rbuf_priv.len(), 0)
        }
        else {
            let mut flags : c_ulong = 0;
            sc_read_binary(card, 0, rbuf_priv.as_mut_ptr(), rbuf_priv.len(), &mut flags)
        }
    }};
    if rv != size_priv.try_into().unwrap()  { return Err(-1); }
    let unused_len = DirectoryRange::new(&rbuf_priv).unused_len();
//println!("SC_PKCS15_PRKDF: unused_len: {} of available {},\nfile_priv: {:X?}", unused_len, rv, unsafe {*file_priv});
    let mut card_free_space : u32 = 0;
    rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_GET_FREE_SPACE, addr_of_mut!(card_free_space).cast::<c_void>()) };
    assert_eq!(SC_SUCCESS, rv);
    let key_pair_size_req = key_info.modulus_length/16 * 7 + 26; // min. is 250 bytes for RSA/512
    if  key_pair_size_req > card_free_space.try_into().unwrap() { return Err(SC_ERROR_NOT_ENOUGH_MEMORY); }
    if unused_len < 80  &&  key_pair_size_req + INC <= card_free_space.try_into().unwrap() {
        /* TODO any enlargement only if it makes sense : get_free_space; in any case it MUST BE AVOIDED that EF.PrKDF gets deleted without being able to re-create it enlarged !!! */
        let file_priv = unsafe { &mut *file_priv };
//        let mut fci = FCI::new_parsed(unsafe { from_raw_parts(file_priv.prop_attr, file_priv.prop_attr_len) });
        file_priv.size += INC;
//        fci.size       += INC;
//println!("Need to  enlarge file {:04X?} in DF {:04X?}, fci: {:02X?}", file_priv.id, file_parent_id, fci );
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_parent, i32::try_from(SC_AC_OP_DELETE).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_parent, i32::try_from(SC_AC_OP_CREATE_EF).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, i32::try_from(SC_AC_OP_DELETE_SELF).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_priv, i32::try_from(SC_AC_OP_UPDATE).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }

        rv = unsafe { sc_delete_file(card, &df_path_priv) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File deletion failed", rv);
            return Err(rv);
        }
        rv = unsafe { sc_create_file(card, file_priv) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File creation failed", rv);
            return Err(rv);
        }
        rv = unsafe { sc_update_binary(card, 0, rbuf_priv.as_ptr(), rbuf_priv.len(), 0/*flags: c_ulong*/) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File update failed", rv);
            return Err(rv);
        }
        let mut apdu = build_apdu(ctx, &[0, 0x44, 0, 0], SC_APDU_CASE_1, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { /*return Err(rv);*/ }
    }


    let mut file_pub = null_mut();
    let guard_file_pub = GuardFile::new(&mut file_pub);
    rv = unsafe { sc_select_file(card, &df_path_pub, *guard_file_pub) };
    if rv != SC_SUCCESS { return Err(-1); }
    let mut rbuf_pub = vec![0_u8; size_pub];
    rv = unsafe { cfg_if::cfg_if! {
        if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
            sc_read_binary(card, 0, rbuf_pub.as_mut_ptr(), rbuf_pub.len(), 0)
        }
        else {
            let mut flags : c_ulong = 0;
            sc_read_binary(card, 0, rbuf_pub.as_mut_ptr(), rbuf_pub.len(), &mut flags)
        }
    }};
    if rv != size_pub.try_into().unwrap()  { return Err(-1); }
    let unused_len = DirectoryRange::new(&rbuf_pub).unused_len();
//println!("SC_PKCS15_PUKDF: unused_len: {} of available {},\nfile_pub: {:X?}", unused_len, rv, unsafe {*file_pub});
    rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_GET_FREE_SPACE, addr_of_mut!(card_free_space).cast::<c_void>()) };
    assert_eq!(SC_SUCCESS, rv);
    if  key_pair_size_req > card_free_space.try_into().unwrap() { return Err(SC_ERROR_NOT_ENOUGH_MEMORY); }
    if unused_len < 80  &&  key_pair_size_req + INC <= card_free_space.try_into().unwrap() {
        /* TODO any enlargement only if it makes sense : get_free_space; in any case it MUST BE AVOIDED that EF.PuKDF gets deleted without being able to re-create it enlarged !!! */
        let file_pub = unsafe { &mut *file_pub };
//        let mut fci = FCI::new_parsed(unsafe { from_raw_parts(file_pub.prop_attr, file_pub.prop_attr_len) });
        file_pub.size += INC;
//        fci.size      += INC;
//println!("Need to  enlarge file {:04X?} in DF {:04X?}, fci: {:02X?}", file_pub.id, file_parent_id, fci );
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_parent, i32::try_from(SC_AC_OP_DELETE).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_parent, i32::try_from(SC_AC_OP_CREATE_EF).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, i32::try_from(SC_AC_OP_DELETE_SELF).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }
        /* Authenticate  */
        rv = unsafe { sc_pkcs15init_authenticate(profile, p15card, file_pub, i32::try_from(SC_AC_OP_UPDATE).unwrap()) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"PIN verification failed", rv);
            return Err(rv);
        }

        rv = unsafe { sc_delete_file(card, &df_path_pub) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File deletion failed", rv);
            return Err(rv);
        }
        rv = unsafe { sc_create_file(card, file_pub) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File creation failed", rv);
            return Err(rv);
        }
        rv = unsafe { sc_update_binary(card, 0, rbuf_pub.as_ptr(), rbuf_pub.len(), 0/*flags: c_ulong*/) };
        if rv < 0 {
            log3ifr!(ctx,f,line!(), c"File update failed", rv);
            return Err(rv);
        }
        let mut apdu = build_apdu(ctx, &[0, 0x44, 0, 0], SC_APDU_CASE_1, &mut[]);
        rv = unsafe { sc_transmit_apdu(card, &mut apdu) };  if rv != SC_SUCCESS { /*return Err(rv);*/ }
    }
    Ok(())
} // check_enlarge_prkdf_pukdf


/* creates the first part of a sym key record entry; only 'key_len_bytes' key bytes need to be appended */
///
/// # Panics
///
/// # Errors
fn prefix_sym_key(card: &mut sc_card,
                  rec_nr: u8,
                  #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                  algorithm: u32, // e.g. SC_ALGORITHM_AES
                  #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                  algorithm: c_ulong, // e.g. SC_ALGORITHM_AES
                  key_len_bytes: u8,
                  ext_auth: bool,
                  count_err_ext_auth: u8,
                  int_auth: bool,
                  count_use_int_auth: u16
) -> Result<Vec<u8>, i32>
{
    let mut res = Vec::with_capacity(38);
    if ![SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3, SC_CARD_TYPE_ACOS5_EVO_V4].contains(&card.type_) {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }
    if rec_nr==0 || rec_nr>30 {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }
    if ![SC_ALGORITHM_AES, SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&algorithm) {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }
    if ![8_u8, 16, 24, 32].contains(&key_len_bytes) {
        return Err(SC_ERROR_INVALID_ARGUMENTS);
    }

    res.push(0x80 | rec_nr);
    let mut key_type = 0;
    if [SC_ALGORITHM_3DES, SC_ALGORITHM_DES].contains(&algorithm) || card.type_==SC_CARD_TYPE_ACOS5_EVO_V4 {
        if int_auth { key_type += 2; }
        if ext_auth { key_type += 1; }
    }
    res.push(key_type);
    if key_type > 0 {
        // This order of "key info" data was tested to work as intended !
        if int_auth { res.extend_from_slice(&count_use_int_auth.to_be_bytes()); }
        if ext_auth { res.push(count_err_ext_auth); }
    }

    let mut card_ctl_algo_ref_sym_store = CardCtlAlgoRefSymStore { card_type: card.type_, algorithm, key_len_bytes, value: 0 };
    let rv = unsafe { sc_card_ctl(card, SC_CARDCTL_ACOS5_ALGO_REF_SYM_STORE, addr_of_mut!(card_ctl_algo_ref_sym_store).cast::<c_void>()) };
    assert_eq!(SC_SUCCESS, rv);
    res.push(card_ctl_algo_ref_sym_store.value);
/*
    match algorithm {
        SC_ALGORITHM_AES => {
            if ![16, 24, 32].contains(&key_len_bytes) { return Err(-1); }
            match key_len_bytes {
                16 => res.push(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x22} else {0x02}),
                24 => res.push(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x24} else {0x12}),
                32 => res.push(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x28} else {0x22}),
                _  => unreachable!(),
            }
        },
        SC_ALGORITHM_3DES => {
            if ![16, 24].contains(&key_len_bytes) { return Err(-1); }
            match key_len_bytes {
                16 => res.push(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x12} else {0x04}),
                24 => res.push(0x14),
                _  => unreachable!(),
            }
        },
        SC_ALGORITHM_DES => {
            if 8 != key_len_bytes { return Err(-1); }
            res.push(if card_type==SC_CARD_TYPE_ACOS5_EVO_V4 {0x11} else {0x05});
        },
        _ => unreachable!(),
    }
*/
    Ok(res)
} // prefix_sym_key

///
/// # Errors
pub fn construct_sym_key_entry(card: &mut sc_card, rec_nr: u8,
                      #[cfg(    any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0))]
                      algorithm: u32,
                      #[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0)))]
                      algorithm: c_ulong,
                      key_len_bytes: u8,
                      ext_auth: bool, count_err_ext_auth: u8,
                      int_auth: bool, count_use_int_auth: u16,
                      mrl: usize, key_bytes: &[u8]) -> Result<Vec<u8>, i32>
{
    let mut vec = prefix_sym_key(card, rec_nr, algorithm, key_len_bytes,
                   ext_auth, count_err_ext_auth,
                   int_auth, count_use_int_auth)?;
    vec.extend_from_slice(key_bytes);
    match mrl.cmp(&vec.len()) {
        Ordering::Less    => return Err(SC_ERROR_CARD_CMD_FAILED),
        Ordering::Greater => vec.resize_with(mrl, Default::default),
        Ordering::Equal   => (),
    }
    Ok(vec)
}


#[cfg(dont_test__this_signature_changed)]
#[cfg(test)]
mod tests {
    use super::*; /*{prefix_sym_key, SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3, SC_CARD_TYPE_ACOS5_EVO_V4}*/

    # [test]
    fn test_prefix_sym_key() -> Result<(), i32> {
        assert_eq!(&[0x81_u8, 0, 0x22], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V2, 1,
            SC_ALGORITHM_AES, 32, false, 0, false, 0)?.as_slice() );
        assert_eq!(&[0x83_u8, 0, 0x12], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V3, 3,
            SC_ALGORITHM_AES, 24, false, 0, false, 0)?.as_slice() );
        assert_eq!(&[0x9E_u8, 0, 0x22], prefix_sym_key(SC_CARD_TYPE_ACOS5_EVO_V4, 30,
            SC_ALGORITHM_AES, 16, false, 0, false, 0)?.as_slice() );

        assert_eq!(&[0x81_u8, 0, 0x22], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V3, 1,
            SC_ALGORITHM_AES, 32, false, 0, true, 256)?.as_slice() );
        assert_eq!(&[0x83_u8, 2, 0x01, 0, 0x24], prefix_sym_key(SC_CARD_TYPE_ACOS5_EVO_V4, 3,
            SC_ALGORITHM_AES, 24, false, 0, true, 256)?.as_slice() );
        assert_eq!(&[0x9E_u8, 0, 0x02], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V2, 30,
            SC_ALGORITHM_AES, 16, false, 0, true, 256)?.as_slice() );

        assert_eq!(&[0x81_u8, 3, 1, 0, 0x33, 0x28], prefix_sym_key(SC_CARD_TYPE_ACOS5_EVO_V4, 1,
            SC_ALGORITHM_AES, 32, true, 0x33, true, 256)?.as_slice() );
        assert_eq!(&[0x83_u8, 0, 0x12], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V2, 3,
            SC_ALGORITHM_AES, 24, true, 0x33, true, 256)?.as_slice() );
        assert_eq!(&[0x9E_u8, 0, 0x02], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V3, 30,
            SC_ALGORITHM_AES, 16, true, 0x33, true, 256)?.as_slice() );

        assert_eq!(&[0x81_u8, 2, 0x01, 0, 0x14], prefix_sym_key(SC_CARD_TYPE_ACOS5_64_V2, 1,
            SC_ALGORITHM_3DES, 24, false, 0, true, 256)?.as_slice() );
        assert_eq!(&[0x9E_u8, 2, 0x01, 0, 0x12], prefix_sym_key(SC_CARD_TYPE_ACOS5_EVO_V4, 30,
            SC_ALGORITHM_3DES, 16, false, 0, true, 256)?.as_slice() );
        Ok(())
    }
}

/*
/**
 * find library module for provided driver in configuration file
 * if not found assume library name equals to module name
 */
fn me_find_library_driver/*<'a>*/(ctx: &/*'a*/ mut sc_context, name: &CStr) -> String //&'a CStr
{
    let mut module_path_name : *const c_char = null_mut();
    for elem in ctx.conf_blocks.iter() {
        if (*elem).is_null() {
            break;
        }
        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem,
            CARD_DRIVER.as_ptr(), name.as_ptr()) };
        if blocks.is_null() {
            continue;
        }
        let blk = unsafe { *blocks };
//        free(blocks);
        if blk.is_null() {
            continue;
        }
        module_path_name = unsafe { scconf_get_str(blk, MODULE.as_ptr(),
        LIB_DRIVER_NIX.as_ptr()) }; // TODO is OS specific Linux/Unix/MAC?
    }
    let mut vec : Vec<u8> = Vec::with_capacity(64);
    for i in 0.. unsafe {  strlen(module_path_name) } {
        vec.push(unsafe { *module_path_name.add(i) as u8 } );
    }
    String::from_utf8(vec).unwrap()
}

fn me_find_library_sm(ctx: &mut sc_context, name: &CStr) -> Result<String, i32>
{
    let f = c"me_find_library_sm";
    /* * /
    //    const char *sm = NULL, *module_name = NULL, *module_path = NULL, *module_data = NULL, *sm_mode = NULL;
    //    struct sc_context *ctx = card->ctx;
    //    scconf_block *atrblock = NULL, *sm_conf_block = NULL;
    //    int rv, ii;
    //
    //    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
    //    sc_log(ctx, "card->sm_ctx.ops.open %p", card->sm_ctx.ops.open);
    //
    //    /* get the name of card specific SM configuration section */
    //    atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
    //    if (atrblock == NULL)
    //        LOG_FUNC_RETURN(ctx, SC_SUCCESS);
    //    sm = scconf_get_str(atrblock, "secure_messaging", NULL);
    //    if (!sm)
    //        LOG_FUNC_RETURN(ctx, SC_SUCCESS);

        /* get SM configuration section by the name */
    //    sc_log(ctx, "secure_messaging configuration block '%s'", sm); // sm == "acos5_sm"
    / * */
    let mut sm_conf_block = null_mut() as *mut scconf_block;
    for elem in ctx.conf_blocks.iter() {
//        scconf_block **blocks;
        if (*elem).is_null() {
            break;
        }
//        blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm);
        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem,
            SECURE_MESSAGING.as_ptr(), name.as_ptr()) };

        if !blocks.is_null() {
            sm_conf_block = unsafe { *blocks }; //= blocks[0];
//            free(blocks);
        }
        if !sm_conf_block.is_null() {
            break;
        }
    }

    if sm_conf_block.is_null() {
//        LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "SM configuration block not present");
        return Err(SC_ERROR_INCONSISTENT_CONFIGURATION);
    }

    /* check if an external SM module has to be used */
    let module_path : *const c_char = unsafe { scconf_get_str(sm_conf_block, SM_MODULE_PATH.as_ptr(),
                                                              null() as *const c_char) };
    let module_name : *const c_char = unsafe { scconf_get_str(sm_conf_block, SM_MODULE_NAME.as_ptr(),
                                                              null() as *const c_char) };
    log3ift!(ctx,f,line!(), c"SM module '%s' in  '%s'", module_name, module_path);

    if module_name.is_null() {
//        LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "Invalid SM configuration: module not defined");
        return Err(SC_ERROR_INCONSISTENT_CONFIGURATION);
    }
    let mut vec : Vec<u8> = Vec::with_capacity(64);
    for i in 0.. unsafe {  strlen(module_path) } {
        vec.push(unsafe { *module_path.add(i) as u8 } );
    }
    if vec.len()>0 && unsafe{strlen(module_name)}>0 { vec.push(47); } // '/'
    for i in 0.. unsafe {  strlen(module_name) } {
        vec.push(unsafe { *module_name.add(i) as u8 } );
    }
    Ok(String::from_utf8(vec).unwrap())
//    Ok(String::from("$HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so"))
}

/* call into the driver library */
pub fn call_dynamic_update_hashmap(card: &mut sc_card) -> lib::Result<()> {
    let ctx : &mut sc_context = unsafe { &mut *card.ctx };
    let drv_module_path_name = me_find_library_driver(ctx, CARD_DRV_SHORT_NAME);
//    println!("driver's module_path_name: {}", drv_module_path_name);
//              driver's module_path_name: "$HOME/RustProjects/acos5/target/debug/libacos5.so"
    let lib = lib::Library::new(OsStr::new(&drv_module_path_name))?;
    unsafe {
        let func: lib::Symbol<unsafe extern fn(*mut sc_card)> = lib.get(b"acos5_update_hashmap")?;
        Ok(func(card))
    }
}

/* call into the SM library (whether it's existent/usable) */
pub fn call_dynamic_sm_test(ctx: &mut sc_context, info: *mut sm_info, out: *mut c_char) -> lib::Result<i32> {
//    let ctx : &mut sc_context = unsafe { &mut *card.ctx };
    let sm_module_path_name = me_find_library_sm(ctx, CARD_SM_SHORT_NAME);
//    println!("sm module_path_name: {}", sm_module_path_name);
//            sm module_path_name: $HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so
//    me_find_library_sm: SM module 'libacos5_sm.so' in  '$HOME/RustProjects/acos5_sm/target/debug'
//    println!("driver's module_path_name: {:?}", me_find_library_driver(ctx, CARD_DRV_SHORT_NAME) );
//    "$HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so"
    /*
    app default {
        framework pkcs15 {
        pkcs15init "acos5-external" {
            # The location of the pkcs15init driver library: /path/to/libacos5....so...;
            #module = "/usr/lib/x86_64-linux-gnu/libacos5.so.5";
            module = "$HOME/RustProjects/acos5_pkcs15/target/debug/libacos5_pkcs15.so";
        }
        }
    }
    */
    let lib = lib::Library::new(OsStr::new(&sm_module_path_name))?;
    unsafe {
        let func: lib::Symbol< unsafe extern fn(*mut sc_context, *mut sm_info, *mut c_char) -> i32 > = lib.get(b"test")?;
        Ok(func(ctx, info, out))
    }
}
*/

/*
/*
 * Allocate a file
 */
pub fn acos5_pkcs15_new_file(profile: &mut sc_profile, card: &mut sc_card,
                             type_: u32, num: i32, out: *mut *mut sc_file) -> i32
{
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = c"acos5_pkcs15_new_file";
    log3ifc!(ctx,f,line!());
    log3if!(ctx,f,line!(), c"type %X; num %i", type_, num);

    let rv : i32;
    let t_name = match type_ {
        SC_PKCS15_TYPE_PRKEY_RSA   => c"template-private-key",
        SC_PKCS15_TYPE_PUBKEY_RSA  => c"template-public-key",
        SC_PKCS15_TYPE_CERT        => c"template-certificate",
        SC_PKCS15_TYPE_DATA_OBJECT => c"template-public-data",
        _  => {
            rv = SC_ERROR_NOT_SUPPORTED;
            log3ifr!(ctx,f,line!(), c"Profile template not supported", rv);
            return rv;
        },
    };

//sc_log(ctx, "df_info path '%s'", sc_print_path(&profile->df_info->file->path));
    let mut file : *mut sc_file = null_mut();
    let rv = me_profile_get_file(profile, t_name.as_ptr(), &mut file);
    if rv < 0 {
        log3ifr!(ctx,f,line!(), c"Error when getting file from template", rv)};
//        return rv;
        file = unsafe { sc_file_new() };
    }
    assert!(!file.is_null());
    let file_rm = unsafe { &mut *file };

    log3if!(ctx,f,line!(), c"file(type:%X), path(type:%X,path:%s)", file_rm.type_, file_rm.path.type_,
        unsafe { sc_print_path(&file_rm.path) } );
    file_rm.id = (file_rm.id & 0xFF00) | (num & 0xFF);

    if file_rm.type_ != SC_FILE_TYPE_BSO {
        if file_rm.path.len == 0 {
            file_rm.path.type_ = SC_PATH_TYPE_FILE_ID;
            file_rm.path.len = 2;
        }
        file_rm.path.value[file_rm.path.len - 2] = ((file_rm.id >> 8) as u8) & 0xFF;
        file_rm.path.value[file_rm.path.len - 1] = (file_rm.id & 0xFF) as u8;
        file_rm.path.count = -1;
    }

//    sc_log(ctx, "file(size:%"SC_FORMAT_LEN_SIZE_T"u,type:%i/%i,id:%04X), path(type:%X,'%s')",
//        file_rm.size, file_rm.type_, file_rm.ef_structure, file_rm.id,
//        file_rm.path.type_, sc_print_path(&file_rm.path));
    unsafe {
        if !out.is_null() {
            *out = file;
        }
        else {
            sc_file_free(file);
        }
    }
    SC_SUCCESS
}
 */
