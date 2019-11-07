/*
 * path.rs: Driver 'acos5' - Some helper functions referring to sc_path or sc_path.value
 *
 * Copyright (C) 2019  Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110-1335  USA
 */

use std::os::raw::{c_void, c_int};
use std::ffi::{CStr};

use opensc_sys::opensc::{sc_card};
use opensc_sys::types::{sc_path, SC_MAX_PATH_SIZE};
use opensc_sys::log::{sc_dump_hex};
use opensc_sys::errors::{SC_SUCCESS};

use crate::constants_types::*;
use crate::wrappers::*;

/* The following 2 functions take the file id from the last valid path component */
pub fn file_id_from_path_value(path_value: &[u8]) -> u16
{
    let len = path_value.len();
    assert!(len>=2);
    u16::from_be_bytes([path_value[len-2], path_value[len-1]])
}

pub fn file_id_from_cache_current_path(card: &sc_card) -> u16
{
    file_id_from_path_value(&card.cache.current_path.value[..card.cache.current_path.len])
}

/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn current_path_df(card: &mut sc_card) -> &[u8]
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let len = card.cache.current_path.len;
    assert!(len>=2);
    let file_id = file_id_from_cache_current_path(card);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    assert!(dp.files.contains_key(&file_id));
    let fdb = dp.files[&file_id].1[0];
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    if cfg!(log) && ![FDB_MF, FDB_DF, FDB_TRANSPARENT_EF, FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_SE_FILE,
        FDB_RSA_KEY_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF, FDB_ECC_KEY_EF].contains(&fdb) {
        let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
        let fun   = CStr::from_bytes_with_nul(b"current_path_df\0").unwrap();
        let fmt   = CStr::from_bytes_with_nul(b"### fdb: %d is incorrect ##################################\0").unwrap();
        wr_do_log_t(card_ctx, f_log, line!(), fun, fdb, fmt);
    }
    &card.cache.current_path.value[..card.cache.current_path.len - if is_DFMF(fdb) {0} else {2}]
}

/* If one of the 'is_search_ruleX_match()' functions returns true, it's sufficient for cos5 to just select the file_id
   These functions represent the built-in search strategy of cos5 for target: "File ID":

   Search Sequence for Target "File ID" is:
   current DF ->
   current DF's children ->
   current DF’s parent ->
   current DF’s siblings ->
   MF ->
   MF’s children

   There is another built-in search strategy for DF
*/

/* select_file target is what is currently selected already (potentially superfluous select) */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule0_match(path_target: &[u8], current_path_ef: &[u8]) -> bool {
    path_target == current_path_ef
}

/* select_file target is the currently selected DF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule1_match(path_target: &[u8], current_path_df: &[u8]) -> bool
{
    if path_target.len()==2 && path_target==&[0x3F_u8, 0xFF][..] { return true; }
    path_target == current_path_df
}

/* select_file target is a EF/DF located (directly) within currently selected DF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule2_match(path_target: &[u8], current_path_df: &[u8]) -> bool
{
    let len_current_path_df = current_path_df.len();
    assert!(len_current_path_df+2<=SC_MAX_PATH_SIZE);
    path_target.len() == len_current_path_df+2 && &path_target[..len_current_path_df] == current_path_df
}

/* select_file target is the parent DF of currently selected DF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule3_match(path_target: &[u8], current_path_df: &[u8]) -> bool
{
    assert!(current_path_df.len()>=2);
    let len_current_path_parent_df= current_path_df.len()-2;
    let current_path_parent_df = &current_path_df[..len_current_path_parent_df];
    path_target.len() == len_current_path_parent_df && &path_target[..len_current_path_parent_df]==current_path_parent_df
}

/* select_file target is a EF/DF located (directly) within the parent DF of currently selected DF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule4_match(path_target: &[u8], current_path_df: &[u8]) -> bool
{
    assert!(current_path_df.len()>=2);
    let len_current_path_parent_df= current_path_df.len()-2;
    let current_path_parent_df = &current_path_df[..len_current_path_parent_df];
    path_target.len()==len_current_path_parent_df+2 && &path_target[..len_current_path_parent_df]==current_path_parent_df
}

/* select_file target is MF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule5_match(path_target: &[u8]) -> bool
{
    path_target.len() == 2 && path_target == &[0x3F_u8, 0][..]
}

/* select_file target is a EF/DF located (directly) within MF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule6_match(path_target: &[u8]) -> bool
{
    path_target.len() == 4 && path_target[..2] == [0x3F_u8, 0][..]
}

/* select_file target is known to be non-selectable (reserved or erroneous file id) */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_impossible_file_match(path_target: &sc_path) -> bool {
    let len = path_target.len;
    assert!(len>=2);
    let file_id = u16::from_be_bytes([path_target.value[len-2], path_target.value[len-1]]);
    match file_id {
        0 | 0xFFFF => true,
        _ => false,
    }
}

/*
The task of cut_path:
Truncate as much as possible from the path to be selected for performance reasons (less select s issued)

It's rarely called and implements just those remaining cases that came across so far, otherwise it does nothing
*/
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn cut_path(card: &mut sc_card, path: &mut sc_path) -> c_int
{
    assert!(!card.ctx.is_null());
    let card_ctx = unsafe { &mut *card.ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun     = CStr::from_bytes_with_nul(b"cut_path\0").unwrap();
    let fmt_1   = CStr::from_bytes_with_nul(b"                     called.   in_type: %d,   in_value: %s\0").unwrap();
    let fmt_3   = CStr::from_bytes_with_nul(b"                  returning:  out_type: %d,  out_value: %s\0").unwrap();
    if cfg!(log) {
        wr_do_log_tu(card_ctx, f_log, line!(), fun, path.type_, unsafe{sc_dump_hex(path.value.as_ptr(), path.len)}, fmt_1);
    }

    assert!(card.cache.current_path.len>=2);
    assert!(path.len>=4);
    let c_path = &card.cache.current_path.value[..card.cache.current_path.len];
    let t_path = &mut path.value[..path.len];
    if c_path == t_path {
        t_path[0] = t_path[t_path.len()-2];
        t_path[1] = t_path[t_path.len()-1];
        path.len = 2;
        return SC_SUCCESS;
    }

    if c_path.len()>=4 && t_path.len()>=4 && c_path[0..4] == t_path[0..4] {
        if c_path.len() < t_path.len() { // In principle it's_search_rule6_match: true, but path_target.len() > 4
            for i in 4..path.len { // shift left in path.value
                t_path[i-4] = t_path[i];
            }
            t_path[path.len-4] = 0;
            t_path[path.len-3] = 0;
            t_path[path.len-2] = 0;
            t_path[path.len-1] = 0;
            path.len -= 4;
        }
        else {
            for i in 2..path.len { // shift left in path.value
                t_path[i-2] = t_path[i];
            }
            t_path[path.len-2] = 0;
            t_path[path.len-1] = 0;
            path.len -= 2;
        }
    }
    else if  c_path[0..2] == t_path[0..2] {
        for i in 2..path.len { // shift left in path.value
            t_path[i-2] = t_path[i];
        }
        t_path[path.len-2] = 0;
        t_path[path.len-1] = 0;
        path.len -= 2;
    }

    if cfg!(log) {
        wr_do_log_tu(card_ctx, f_log, line!(), fun, path.type_, unsafe{sc_dump_hex(path.value.as_ptr(), path.len)}, fmt_3);
    }
    SC_SUCCESS
}


#[cfg(test)]
mod tests {
    use super::{is_search_rule1_match, is_search_rule2_match, is_search_rule3_match,
                is_search_rule4_match, is_search_rule5_match, is_search_rule6_match};

    /* select_file target is the currently selected DF */
    #[test]
    fn test_is_search_rule1_match() {
        let path_target            = &[0x3Fu8, 0, 0x41, 0, 0x43, 0, 0x43, 5];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0, 0x43, 0];
        assert_eq!(is_search_rule1_match(path_target, path_current_df), false);
    }

    /* select_file target is a EF/DF located (directly) within currently selected DF */
    #[test]
    fn test_is_search_rule2_match() {
        let path_target            = &[0x3Fu8, 0, 0x41, 0, 0x43, 0, 0x43, 5];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0, 0x43, 0];
        assert_eq!(is_search_rule2_match(path_target, path_current_df), true);

        let path_current_df        = &[0x3Fu8, 0, 0x41, 0];
        assert_eq!(is_search_rule2_match(path_target, path_current_df), false);
    }

    /* select_file target is the parent DF of currently selected DF */
    #[test]
    fn test_is_search_rule3_match() {
        let path_target            = &[0x3Fu8, 0, 0x41, 0];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0, 0x43, 0];
        assert_eq!(is_search_rule3_match(path_target, path_current_df), true);

        let path_target            = &[0x3Fu8, 0, 0x41, 0, 0x41, 1];
        assert_eq!(is_search_rule3_match(path_target, path_current_df), false);

        let path_target            = &[0x3Fu8, 0];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0];
        assert_eq!(is_search_rule3_match(path_target, path_current_df), true);
    }

    /* select_file target is a EF/DF located (directly) within the parent DF of currently selected DF */
    #[test]
    fn test_is_search_rule4_match() {
        let path_target            = &[0x3Fu8, 0, 0x41, 0, 0x41, 1];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0, 0x43, 0];
        assert_eq!(is_search_rule4_match(path_target, path_current_df), true);
    }

    /* select_file target is MF */
    #[test]
    fn test_is_search_rule5_match() {
        assert_eq!(is_search_rule5_match(&[0x3Fu8, 0]), true);
        assert_eq!(is_search_rule5_match(&[0x3Fu8, 0, 0x41, 0]), false);
    }

    /* select_file target is a EF/DF located (directly) within MF */
    #[test]
    fn test_is_search_rule6_match() {
        assert_eq!(is_search_rule6_match(&[0x3Fu8, 0, 0x41, 0]), true);
        assert_eq!(is_search_rule6_match(&[0x3Fu8, 0, 0x41, 0, 0x41, 1]), false);
    }
}
