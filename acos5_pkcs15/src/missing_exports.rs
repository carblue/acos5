/*
 * missing_exports.rs: Driver 'acos5_pkcs15' - OpenSC code duplicated
 *
 * card.c: General smart card functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *
 * padding.c: miscellaneous padding functions
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003 - 2007  Nils Larsch <larsch@trustcenter.de>
 *
 * missing_exports.rs:
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

use libc::{strcmp, calloc, memcpy};

use std::os::raw::{c_char, c_void};

use opensc_sys::opensc::sc_file_dup; // sc_file_valid, sc_file_new
use opensc_sys::profile::{sc_profile, file_info};
use opensc_sys::types::{sc_path, sc_file}; //, sc_acl_entry, SC_MAX_AID_SIZE, SC_MAX_AC_OPS
                        /*, SC_AC_OP_CREATE_EF, SC_PATH_TYPE_FILE_ID, SC_AC_OP_DELETE*/
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_FILE_NOT_FOUND, SC_ERROR_OUT_OF_MEMORY, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_PKCS15INIT};
use opensc_sys::pkcs15::{sc_pkcs15_bignum, sc_pkcs15_card, sc_pkcs15_df};
//use opensc_sys::log::{sc_dump_hex};

use std::ptr::null_mut;
//use crate::constants_types::p_void;
//use crate::wrappers::*;

fn me_profile_find_file(profile: &mut sc_profile, _path: *const sc_path, name: *const c_char) -> *mut file_info
{
/*
    assert!(!profile.card.is_null());
    assert!(unsafe { (*profile.card).ctx.is_null() });
    // let card = unsafe { &mut *profile.card };
    let ctx = unsafe { &mut *(*profile.card).ctx };
    let f = c"me_profile_find_file";
*/
    let mut fi = profile.ef_list;
//    log3if!(ctx,f,line!(), c"called  with profile.ef_list: %p", profile.ef_list);

//    let len = if !path.is_null() { unsafe{(*path).len} } else {0};
    while !fi.is_null() {
        let fi_ref = unsafe { &*fi };
        assert!(!fi_ref.file.is_null());
//        let file_ref = unsafe { &*fi_ref.file };
/*
        log3if!(ctx,f,line!(), c"file_ref.id: 0x%X, file_ref.path: %s, fi_ref.ident: %s",  file_ref.id,
            unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) }, fi_ref.ident);

*/
/* * /
        log3if!(ctx,f,line!(), c"file_ref.path: %s", unsafe { sc_dump_hex(file_ref.path.value.as_ptr(), file_ref.path.len) });
        log3if!(ctx,f,line!(), c"file_ref.type_: 0x%X", file_ref.type_);
        log3if!(ctx,f,line!(), c"file_ref.ef_structure: 0x%X", file_ref.ef_structure);
        log3if!(ctx,f,line!(), c"file_ref.status: %u", file_ref.status);
        log3if!(ctx,f,line!(), c"file_ref.size: %zu",  file_ref.size);
        log3if!(ctx,f,line!(), c"file_ref.id: 0x%X",   file_ref.id);
        log3if!(ctx,f,line!(), c"file_ref.acl[SC_AC_OP_READ]: %p", file_ref.acl[22]);
        log3if!(ctx,f,line!(), c"file_ref.record_length: %zu",     file_ref.record_length);
        log3if!(ctx,f,line!(), c"file_ref.record_count: %zu",      file_ref.record_count);

        if file_ref.prop_attr_len>0 && !file_ref.prop_attr.is_null() {
            log3if!(ctx,f,line!(), c"file_ref.prop_attr: %zu  %s",  file_ref.prop_attr_len,
                unsafe { sc_dump_hex(file_ref.prop_attr, file_ref.prop_attr_len) });
            for i in 0..file_ref.prop_attr_len {
                log3if!(ctx,f,line!(), c"file_ref.prop_attr[%zu]: %X", i, unsafe{*file_ref.prop_attr.add(i)});
            }
        }
//        log3if!(ctx,f,line!(), c"fi_ref.dont_free: %u", fi_ref.dont_free);
//        log3if!(ctx,f,line!(), c"fi_ref.parent: %p",    fi_ref.parent);
//        log3if!(ctx,f,line!(), c"fi_ref.instance: %p",  fi_ref.instance);
  //        log3if!(ctx,f,line!(), c"fi_ref.base_template: %p", fi_ref.base_template);
  //        log3if!(ctx,f,line!(), c"fi_ref.inst_index: %u",    fi_ref.inst_index);
  //        log3if!(ctx,f,line!(), c"fi_ref.inst_path: %s",     unsafe { sc_dump_hex(fi_ref.inst_path.value.as_ptr(), fi_ref.inst_path.len) });
  //        log3if!(ctx,f,line!(), c"fi_ref.profile_ext: %p",   fi_ref.profile_extension);
/ * */
        // strcasecmp
        if unsafe { strcmp(fi_ref.ident, name) == 0 } /*&& file_ref.path.len >= len && !path.is_null() &&
            unsafe { memcmp(file_ref.path.value.as_ptr() as *const c_void, (*path).value.as_ptr() as *const c_void, len) == 0 }*/ {
            return fi;
        }
        fi = fi_ref.next;
    }
    null_mut()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn me_profile_get_file(profile: &mut sc_profile, name: *const c_char, ret: *mut *mut sc_file) -> i32
{
    if name.is_null() || ret.is_null() { return SC_ERROR_INVALID_ARGUMENTS; }
    let fi = me_profile_find_file(profile, std::ptr::null(), name);
    if fi.is_null() {
        return SC_ERROR_FILE_NOT_FOUND;
    }
    if unsafe { *fi }.file.is_null() {
        return SC_ERROR_FILE_NOT_FOUND;
    }
    let file = unsafe { & *(*fi).file};
    // who cares for deleting ret ? GuardFile !
    unsafe { sc_file_dup(ret, file) };
    // unsafe { my_file_dup(&mut *ret, file) };
    if unsafe { (*ret).is_null() } {
        return SC_ERROR_OUT_OF_MEMORY;
    }
    SC_SUCCESS
}

/*
/* How this differs from sc_file_dup:
   field acl       doesn't get duplicated, but set to all: SC_AC_NONE, as internal/virtual  pointer encoding,
                   see sc_file_add_acl_entry
   field sec_attr         no copy
   field prop_attr        no copy
   field type_attr        no copy
   field encoded_content  no copy
 */
#[allow(dead_code)]  // no usage currently
#[cold]
pub fn my_file_dup(dest: &mut *mut sc_file, src: &sc_file) {
    *dest = null_mut();
    if sc_file_valid(src) != 1  { return; }
    let newf = sc_file_new(); // initializes all its bits to zero, then file.magic = SC_FILE_MAGIC;
    if  newf.is_null() { return; }
    *dest = newf;
    let newf = unsafe { &mut *newf };

    unsafe {
        // memcpy(&newf->path, &src->path, sizeof(struct sc_path));
        copy_nonoverlapping(&src.path, &mut newf.path, 1 /*std::mem::size_of::<sc_path>()*/);
        // memcpy(&newf->name, &src->name, sizeof(src->name));
        copy_nonoverlapping(src.name.as_ptr(), newf.name.as_mut_ptr(), SC_MAX_AID_SIZE);
    }
    newf.namelen = src.namelen;

    newf.type_        = src.type_;
    newf.ef_structure = src.ef_structure;
    newf.status       = src.status;
    newf.shareable    = src.shareable;
    newf.size         = src.size;
    newf.id           = src.id;
    // newf.sid         = src.sid;
    newf.acl     = [2 as *mut sc_acl_entry; SC_MAX_AC_OPS]; // this is SC_AC_NONE, corrected later on
/*
    for (unsigned int op = 0; op < SC_MAX_AC_OPS; op++) {
        newf.acl[op] = NULL;
        const sc_acl_entry_t *e = sc_file_get_acl_entry(src, op);
        if (e != NULL) {
            if (sc_file_add_acl_entry(newf, op, e.method, e.key_ref) < 0)
            goto err;
        }
    }
*/
    newf.record_length = src.record_length;
    newf.record_count  = src.record_count;
// return;
    // if (sc_file_set_sec_attr(newf, src.sec_attr, src.sec_attr_len) < 0)
    // goto err;
    // if (sc_file_set_prop_attr(newf, src.prop_attr, src.prop_attr_len) < 0)
    // goto err;
    // if (sc_file_set_type_attr(newf, src.type_attr, src.type_attr_len) < 0)
    // goto err;
    // if (sc_file_set_content(newf, src.encoded_content, src.encoded_content_len) < 0)
    // goto err;
// return;
    // err:
    //     sc_file_free(newf);
    // *dest = NULL;

    // unsafe { opensc_sys::opensc::sc_file_dup(dest, src) }
/*
$ grep -rnw sc_file_dup
opensc-sys/src/opensc.rs:1990:pub fn sc_file_dup(dest: *mut *mut sc_file, src: *const sc_file);

acos5_pkcs15/src/missing_exports.rs:6:use opensc_sys::opensc::{sc_file_dup};
acos5_pkcs15/src/missing_exports.rs:84:    unsafe { sc_file_dup(ret, fi.file) };

acos5_pkcs15/src/lib.rs:91: sc_file_dup, sc_delete_file, sc_check_sw, sc_update_record, SC_RECORD_BY_REC_NR, sc_get_version};
acos5_pkcs15/src/lib.rs:685:    unsafe { sc_file_dup(*guard_file_pub, file_priv) };
*/
}
*/

pub fn me_pkcs15_dup_bignum(dst: &mut sc_pkcs15_bignum, src: &sc_pkcs15_bignum) -> i32
{
     if !src.data.is_null() && src.len > 0  {
        dst.data = unsafe { calloc(1, src.len) }.cast::<u8>();
        if dst.data.is_null() {
            return SC_ERROR_OUT_OF_MEMORY;
        }
        let _unused = unsafe { memcpy(dst.data.cast::<c_void>(), src.data as *const c_void, src.len) };
        dst.len = src.len;
    }

    0
}

///
/// # Errors
pub fn find_df_by_type(p15card: &mut sc_pkcs15_card, type_: u8) -> Result<&mut sc_pkcs15_df, i32>
{
    let mut df  = p15card.df_list;
    unsafe {
        while !df.is_null() && (*df).type_ != u32::from(type_) {
            df = (*df).next;
        }
        if df.is_null() {
            Err(SC_ERROR_PKCS15INIT)
        }
        else {
            Ok(&mut *df)
        }
    }
}
