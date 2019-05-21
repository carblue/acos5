/*
 * path.rs: Driver 'acos5_64' - Some helper functions referring to sc_path or sc_path.value
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
use opensc_sys::log::{sc_do_log, sc_dump_hex, SC_LOG_DEBUG_NORMAL};
use opensc_sys::errors::{SC_SUCCESS};

use crate::constants_types::*;


/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn current_path_df(card: &mut sc_card) -> &[u8]
{
    let len = card.cache.current_path.len; // crash location TODO How it's possible to get here with  0==card.cache.current_path.len
    assert!(len>=2);
    let file_id = u16_from_array_begin(&card.cache.current_path.value[len-2..len]);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    assert!(dp.files.contains_key(&file_id));
    let fdb = (&dp.files[&file_id]).1[0];
    card.drv_data = Box::into_raw(dp) as *mut c_void;

    if fdb & FDB_DF == FDB_DF {
        &card.cache.current_path.value[..len]
    }
    else {
        &card.cache.current_path.value[..len-2]
    }
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

/* select_file target is the currently selected DF */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
pub fn is_search_rule1_match(path_target: &[u8], current_path_df: &[u8]) -> bool
{
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
    path_target.len() == 2 && path_target == &[0x3Fu8, 0][..]
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
    path_target.len() == 4 && &path_target[..2] == &[0x3Fu8, 0][..]
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
pub fn cut_path(card: &mut sc_card, path_in: &sc_path, path_out: &mut sc_path) -> c_int
{
    let file_str = CStr::from_bytes_with_nul(CRATE).unwrap();
    let func     = CStr::from_bytes_with_nul(b"cut_path\0").unwrap();
    let format_1   = CStr::from_bytes_with_nul(b"                    called.    in_type: %d,   in_value: %s\0").unwrap();
    let format_3   = CStr::from_bytes_with_nul(b"                 returning:   out_type: %d,  out_value: %s\0").unwrap();
    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_1.as_ptr(), path_in.type_,
                       sc_dump_hex(path_in.value.as_ptr(), path_in.len) ) };

    assert!(path_out.len>=4);
    let c_path = &card.cache.current_path.value[..card.cache.current_path.len];
    let t_path = &mut path_out.value[..path_out.len];

    if  c_path[0..2] == t_path[0..2] &&
        c_path[2..4] != t_path[2..4] { // In principle it's_search_rule6_match: true, but path_target.len() > 4
        for i in 2..path_out.len { // shift left in path.value
            t_path[i-2] = t_path[i];
        }
        t_path[path_out.len-2] = 0;
        t_path[path_out.len-1] = 0;
        path_out.len -= 2;
    }

    #[cfg(log)]
    unsafe { sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, file_str.as_ptr(), line!() as i32, func.as_ptr(),
                       format_3.as_ptr(), path_out.type_,
                       sc_dump_hex(path_out.value.as_ptr(), path_out.len) ) };
    SC_SUCCESS
}


// TODO tests for other 'is_search_ruleX_match()' functions
#[cfg(test)]
mod tests {
    use super::{is_search_rule1_match};

    /* select_file target is the currently selected DF */
    #[test]
    fn test_is_search_rule1_match() {
        let path_target            = &[0x3Fu8, 0, 0x41, 0, 0x43, 0, 0x43, 5];
        let path_current_df        = &[0x3Fu8, 0, 0x41, 0, 0x43, 0];
        assert_eq!(is_search_rule1_match(path_target, path_current_df), false);
    }
}
