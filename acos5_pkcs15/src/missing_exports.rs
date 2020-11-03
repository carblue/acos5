use libc::{strcmp, calloc, memcpy/*, memcmp,*/};

use std::os::raw::{c_char};
//use std::ffi::{CStr};

use opensc_sys::opensc::{sc_file_dup};
use opensc_sys::profile::{sc_profile, file_info};
use opensc_sys::types::{sc_path, sc_file/*, SC_AC_OP_CREATE_EF, SC_PATH_TYPE_FILE_ID, SC_AC_OP_DELETE*/};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_FILE_NOT_FOUND, SC_ERROR_OUT_OF_MEMORY, SC_ERROR_INVALID_ARGUMENTS};
use opensc_sys::pkcs15::{sc_pkcs15_bignum, sc_pkcs15_card, sc_pkcs15_df};
//use opensc_sys::log::{sc_dump_hex};

use crate::constants_types::p_void;
//use crate::wrappers::*;

fn me_profile_find_file(profile: &mut sc_profile, _path: *const sc_path, name: *const c_char) -> *mut file_info
{
/*
    assert!(!profile.card.is_null());
    assert!(unsafe { (*profile.card).ctx.is_null() });
    // let card = unsafe { &mut *profile.card };
    let ctx = unsafe { &mut *(*profile.card).ctx };
    let f = cstru!(b"me_profile_find_file\0");
*/
    let mut fi = profile.ef_list;
//    log3if!(ctx,f,line!(), cstru!(b"called  with profile.ef_list: %p\0"), profile.ef_list);

//    let len = if !path.is_null() { unsafe{(*path).len} } else {0};
    while !fi.is_null() {
        let fi_ref = unsafe { &*fi };
        assert!(!fi_ref.file.is_null());
//        let file_ref = unsafe { &*fi_ref.file };
/*
        log3if!(ctx,f,line!(), cstru!(b"file_ref.id: 0x%X, file_ref.path: %s, fi_ref.ident: %s\0"),  file_ref.id,
            unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, fi_ref.ident);

*/
/* * /
        log3if!(ctx,f,line!(), cstru!(b"file_ref.path: %s\0"), unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) });
        log3if!(ctx,f,line!(), cstru!(b"file_ref.type_: 0x%X\0"), file_ref.type_);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.ef_structure: 0x%X\0"), file_ref.ef_structure);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.status: %u\0"), file_ref.status);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.size: %zu\0"),  file_ref.size);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.id: 0x%X\0"),   file_ref.id);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.acl[SC_AC_OP_READ]: %p\0"), file_ref.acl[22]);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.record_length: %zu\0"),     file_ref.record_length);
        log3if!(ctx,f,line!(), cstru!(b"file_ref.record_count: %zu\0"),      file_ref.record_count);

        if file_ref.prop_attr_len>0 && !file_ref.prop_attr.is_null() {
            log3if!(ctx,f,line!(), cstru!(b"file_ref.prop_attr: %zu  %s\0"),  file_ref.prop_attr_len,
                unsafe { sc_dump_hex(file_ref.prop_attr, file_ref.prop_attr_len) });
            for i in 0..file_ref.prop_attr_len {
                log3if!(ctx,f,line!(), cstru!(b"file_ref.prop_attr[%zu]: %X\0"), i, unsafe{*file_ref.prop_attr.add(i)});
            }
        }
//        log3if!(ctx,f,line!(), cstru!(b"fi_ref.dont_free: %u\0"), fi_ref.dont_free);
//        log3if!(ctx,f,line!(), cstru!(b"fi_ref.parent: %p\0"),    fi_ref.parent);
//        log3if!(ctx,f,line!(), cstru!(b"fi_ref.instance: %p\0"),  fi_ref.instance);
  //        log3if!(ctx,f,line!(), cstru!(b"fi_ref.base_template: %p\0"), fi_ref.base_template);
  //        log3if!(ctx,f,line!(), cstru!(b"fi_ref.inst_index: %u\0"),    fi_ref.inst_index);
  //        log3if!(ctx,f,line!(), cstru!(b"fi_ref.inst_path: %s\0"),     unsafe { sc_dump_hex(fi_ref.inst_path.value.as_ptr(), fi_ref.inst_path.len) });
  //        log3if!(ctx,f,line!(), cstru!(b"fi_ref.profile_ext: %p\0"),   fi_ref.profile_extension);
/ * */
        // strcasecmp
        if unsafe { strcmp(fi_ref.ident, name) == 0 } /*&& file_ref.path.len >= len && !path.is_null() &&
            unsafe { memcmp(file_ref.path.value.as_ptr() as *const c_void, (*path).value.as_ptr() as *const c_void, len) == 0 }*/ {
            return fi;
        }
        fi = fi_ref.next;
    }
    std::ptr::null_mut()
}


pub fn me_profile_get_file(profile: &mut sc_profile, name: *const c_char, ret: *mut *mut sc_file) -> i32
{
    if name.is_null() || ret.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
    let fi = me_profile_find_file(profile, std::ptr::null(), name);
    if fi.is_null() {
        return SC_ERROR_FILE_NOT_FOUND;
    }
    let fi = unsafe { & *fi};
    assert!(!fi.file.is_null());
    unsafe { sc_file_dup(ret, fi.file) };
    if unsafe { (*ret).is_null() } {
        return SC_ERROR_OUT_OF_MEMORY;
    }
    SC_SUCCESS
}


pub fn me_pkcs15_dup_bignum(dst: &mut sc_pkcs15_bignum, src: &sc_pkcs15_bignum) -> i32
{
     if !src.data.is_null() && src.len > 0  {
        dst.data = unsafe { calloc(1, src.len) } as *mut u8;
        if dst.data.is_null() {
            return SC_ERROR_OUT_OF_MEMORY;
        }
        unsafe { memcpy(dst.data as p_void, src.data as p_void, src.len) };
        dst.len = src.len;
    }

    0
}

#[allow(clippy::missing_errors_doc)]
pub fn find_df_by_type(p15card: &mut sc_pkcs15_card, type_: u8) -> Result<&mut sc_pkcs15_df, i32>
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
