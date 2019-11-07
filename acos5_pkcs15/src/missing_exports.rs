use libc::{strcasecmp, calloc, memcpy/*, memcmp,*/};

use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ffi::{CStr};

use opensc_sys::opensc::{sc_file_dup};
use opensc_sys::profile::{sc_profile, file_info};
use opensc_sys::types::{sc_path, sc_file/*, SC_AC_OP_CREATE_EF, SC_PATH_TYPE_FILE_ID, SC_AC_OP_DELETE*/};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_FILE_NOT_FOUND, SC_ERROR_OUT_OF_MEMORY, SC_ERROR_INVALID_ARGUMENTS};
use opensc_sys::pkcs15::{sc_pkcs15_bignum, sc_pkcs15_card, sc_pkcs15_df};
//use opensc_sys::log::{sc_dump_hex};

use crate::constants_types::CRATE;
use crate::wrappers::*;

fn me_profile_find_file(profile: &mut sc_profile, _path: *const sc_path, name: *const c_char) -> *mut file_info
{
    assert!(!profile.card.is_null());
    assert!(unsafe { (*profile.card).ctx.is_null() });
//    let card = unsafe { &mut *profile.card };
    let card_ctx = unsafe { &mut *(*profile.card).ctx };
    let mut fi = profile.ef_list;

    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"me_profile_find_file\0").unwrap();
    if cfg!(log) {
        wr_do_log_t(card_ctx, f_log, line!(), fun, profile.ef_list, CStr::from_bytes_with_nul(b"called  with profile.ef_list: %p\0").unwrap());
    }

//    let len = if !path.is_null() { unsafe{(*path).len} } else {0};
    while !fi.is_null() {
        let fi_ref = unsafe { &*fi };
        assert!(!fi_ref.file.is_null());
//        let file_ref = unsafe { &*fi_ref.file };
/*
        wr_do_log_tuv(card_ctx, f_log, line!(), fun, file_ref.id,
                      unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, fi_ref.ident,
                      CStr::from_bytes_with_nul(b"file_ref.id: 0x%X, file_ref.path: %s, fi_ref.ident: %s\0").unwrap());
*/
/* * /
        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, CStr::from_bytes_with_nul(b"file_ref.path: %s\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.type_, CStr::from_bytes_with_nul(b"file_ref.type_: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.ef_structure, CStr::from_bytes_with_nul(b"file_ref.ef_structure: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.status, CStr::from_bytes_with_nul(b"file_ref.status: %u\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.size, CStr::from_bytes_with_nul(b"file_ref.size: %zu\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.id, CStr::from_bytes_with_nul(b"file_ref.id: 0x%X\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.acl[22], CStr::from_bytes_with_nul(b"file_ref.acl[SC_AC_OP_READ]: %p\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.record_length, CStr::from_bytes_with_nul(b"file_ref.record_length: %zu\0").unwrap());
        wr_do_log_t(card_ctx, f_log, line!(), fun, file_ref.record_count, CStr::from_bytes_with_nul(b"file_ref.record_count: %zu\0").unwrap());

        if file_ref.prop_attr_len>0 && !file_ref.prop_attr.is_null() {
            wr_do_log_tu(card_ctx, f_log, line!(), fun, file_ref.prop_attr_len, unsafe { sc_dump_hex(file_ref.prop_attr, file_ref.prop_attr_len) }, CStr::from_bytes_with_nul(b"file_ref.prop_attr: %zu  %s\0").unwrap());
            for i in 0..file_ref.prop_attr_len {
                wr_do_log_tu(card_ctx, f_log, line!(), fun, i, unsafe{*file_ref.prop_attr.add(i)}, CStr::from_bytes_with_nul(b"file_ref.prop_attr[%zu]: %X\0").unwrap());
            }
        }
//        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.dont_free, CStr::from_bytes_with_nul(b"fi_ref.dont_free: %u\0").unwrap());
//        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.parent, CStr::from_bytes_with_nul(b"fi_ref.parent: %p\0").unwrap());
//        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.instance, CStr::from_bytes_with_nul(b"fi_ref.instance: %p\0").unwrap());
  //        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.base_template, CStr::from_bytes_with_nul(b"fi_ref.base_template: %p\0").unwrap());
  //        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.inst_index, CStr::from_bytes_with_nul(b"fi_ref.inst_index: %u\0").unwrap());
  //        wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(fi_ref.inst_path.value.as_ptr(), fi_ref.inst_path.len) }, CStr::from_bytes_with_nul(b"fi_ref.inst_path: %s\0").unwrap());
  //        wr_do_log_t(card_ctx, f_log, line!(), fun, fi_ref.profile_extension, CStr::from_bytes_with_nul(b"fi_ref.profile_extension: %p\0").unwrap());
/ * */
        if unsafe { strcasecmp(fi_ref.ident, name) == 0 } /*&& file_ref.path.len >= len && !path.is_null() &&
            unsafe { memcmp(file_ref.path.value.as_ptr() as *const c_void, (*path).value.as_ptr() as *const c_void, len) == 0 }*/ {
            return fi;
        }
        fi = fi_ref.next;
    }
    std::ptr::null_mut()
}


pub fn me_profile_get_file(profile: &mut sc_profile, name: *const c_char, ret: &mut *mut sc_file) -> c_int
{
    if name.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
    let fi = me_profile_find_file(profile, std::ptr::null(), name);
    if fi.is_null() {
        return SC_ERROR_FILE_NOT_FOUND;
    }
    let fi = unsafe { & *fi};
    assert!(!fi.file.is_null());
    unsafe { sc_file_dup(ret, fi.file) };
    if (*ret).is_null() {
        return SC_ERROR_OUT_OF_MEMORY;
    }
    SC_SUCCESS
}


pub fn me_pkcs15_dup_bignum(dst: &mut sc_pkcs15_bignum, src: &sc_pkcs15_bignum) -> c_int
{
     if !src.data.is_null() && src.len > 0  {
        dst.data = unsafe { calloc(1, src.len) } as *mut c_uchar;
        if dst.data.is_null() {
            return SC_ERROR_OUT_OF_MEMORY;
        }
        unsafe { memcpy(dst.data as *mut c_void, src.data as *mut c_void, src.len) };
        dst.len = src.len;
    }

    0
}


pub fn find_df_by_type(p15card: &mut sc_pkcs15_card, type_: c_uchar) -> Result<&mut sc_pkcs15_df, c_int>
{
    let mut df  = p15card.df_list;
    unsafe {
        while !df.is_null() && (*df).type_ != u32::from(type_) {
            df = (*df).next;
        }
        if df.is_null() {
            Err(-1)
        }
        else {
            Ok(&mut *df)
        }
    }
}
