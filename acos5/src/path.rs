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

use opensc_sys::opensc::{sc_card};
use opensc_sys::types::{sc_path/*, SC_MAX_PATH_SIZE*/};
//use opensc_sys::log::{sc_dump_hex};
//use opensc_sys::errors::{SC_SUCCESS};

use crate::constants_types::{DataPrivate, FDB_CHV_EF, FDB_CYCLIC_EF, FDB_DF, FDB_ECC_KEY_EF, FDB_LINEAR_FIXED_EF,
                             FDB_LINEAR_VARIABLE_EF, FDB_MF, FDB_PURSE_EF, FDB_RSA_KEY_EF, FDB_SE_FILE,
                             FDB_SYMMETRIC_KEY_EF, FDB_TRANSPARENT_EF, is_DFMF, p_void};
use crate::wrappers::wr_do_log_t;

/* The following 2 functions take the file id from the last valid path component */
#[must_use]
pub fn file_id_from_path_value(path_value: &[u8]) -> u16
{
    let len = path_value.len();
    assert!(len>=2);
    u16::from_be_bytes([path_value[len-2], path_value[len-1]])
}

#[must_use]
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
    let len = card.cache.current_path.len;
    assert!(len>=2);
    debug_assert_eq!(card.cache.current_path.value[0], 0x3F);
    debug_assert_eq!(card.cache.current_path.value[1], 0);
    let file_id = u16::from_be_bytes([card.cache.current_path.value[len-2], card.cache.current_path.value[len-1]]);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    assert!(dp.files.contains_key(&file_id));
    let fdb = dp.files[&file_id].1[0];
    card.drv_data = Box::into_raw(dp) as p_void;

    if ![FDB_MF, FDB_DF, FDB_TRANSPARENT_EF, FDB_LINEAR_FIXED_EF, FDB_LINEAR_VARIABLE_EF, FDB_CYCLIC_EF, FDB_SE_FILE,
        FDB_RSA_KEY_EF, FDB_CHV_EF, FDB_SYMMETRIC_KEY_EF, FDB_PURSE_EF, FDB_ECC_KEY_EF].contains(&fdb) {
        assert!(!card.ctx.is_null());
        log3if!(unsafe { &mut *card.ctx }, cstru!(b"current_path_df\0"), line!(),
            cstru!(b"Error: ### fdb: %d is incorrect ########################\0"), fdb);
        panic!();
    }
    assert!(is_DFMF(fdb) || len>=4);
    &card.cache.current_path.value[..len - if is_DFMF(fdb) {0} else {2}]
}

/* select_file target is known to be non-selectable (reserved or erroneous file id) */
/*
 * What it does
 * @apiNote
 * @param
 * @return
 */
#[must_use]
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
Truncate as much as possible from the path to be selected for performance reasons (less select s issued),
based on acos5 search rules for files
*/
pub fn cut_path(path_target: &mut [u8], path_target_len: &mut usize, current_path_df: &[u8])
{
    /*
    Search Sequence for Target File ID is:
       current DF
    -> current DF's children
    -> current DF’s parent
    -> current DF’s siblings
    -> MF
    -> MF’s children
    */
    let c_len = current_path_df.len();
    let t_len = path_target.len();
//  assert!(c_len>=2);
//  assert!(t_len>=2);
//println!("path from: {:X?},  {}", current_path_df, current_path_df.len());
//println!("path to:   {:X?},  {}", path_target,     path_target.len());

    if c_len <= t_len {
        for i in 0..c_len/2 {
            let j = c_len - i*2; // min j is 2
            if path_target.starts_with(&current_path_df[..j]) && (j<=4 || i<=1) {
                let rot = if t_len==j || (i>1 && j==4) {j-2} else if j==2 {2} else {j};
                path_target.rotate_left(rot);
                *path_target_len = t_len - rot;
//println!("path to:   {:X?},  {}", &path_target[..*path_target_len], *path_target_len);
//println!("path:   i: {}, j: {}, rot: {}", i, j, rot);
//println!();
                break;
            }
        }
    }
    else { // t_len < c_len
        let k = (c_len - t_len)/2; // min k is 1
        for i in 0..t_len/2 {
            let j = t_len - i*2; // min j is 2
            if path_target.starts_with(&current_path_df[..j]) && (j<=4 || i+k<=1) {
                let rot = if j==2 && t_len>2 {2} else {j-2};
                path_target.rotate_left(rot);
                *path_target_len = t_len - rot;
//println!("path to:   {:X?},  {}", &path_target[..*path_target_len], *path_target_len);
//println!("path:   i: {}, j: {}, rot: {}, k: {}", i, j, rot, k);
//println!();
                break;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{cut_path};

    #[test]
    fn test1_cut_path() { // $ cargo test test_cut_path1 -- --nocapture
        // c_len <= t_len
        let current_path_df= &[0x3F, 0, 0xC0, 0, 0xC1, 0][..];
        let mut path_target = [0x3F, 0, 0xC0, 0, 0xAB, 0];
        let mut path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 6);
        assert_eq!(path_target, [0xAB, 0, 0x3F, 0, 0xC0, 0]);
        assert_eq!(path_target_len, 2);
////
        let current_path_df= &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        let mut path_target= [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 10);
        assert_eq!(path_target, [0xC3, 0, 0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0]);
        assert_eq!(path_target_len, 2);

//        let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target=             [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xAB, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xAB, 0, 0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0]);
        assert_eq!(path_target_len, 2);
////
//         let current_path_df      = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        let mut path_target = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 14);
        assert_eq!(path_target, [0xC4, 0, 0xC5, 0, 0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0]);
        assert_eq!(path_target_len, 4);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xAB, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xAB, 0, 0xC4, 0, 0xC5, 0, 0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0]);
        assert_eq!(path_target_len, 6);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xAB, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xC0, 0, 0xC1, 0, 0xAB, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 12);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xAB, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xC0, 0, 0xAB, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 12);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target     = [0x3F, 0, 0xAB, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xAB, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 12);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target     = [0xAB, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target, [0xAB, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0]);
        assert_eq!(path_target_len, 14);
    }

    #[test]
    fn test2_cut_path() { // $ cargo test test_cut_path2 -- --nocapture
        // t_len < c_len
        let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        let mut path_target = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0];
        let mut path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xC4, 0, 0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0]);
        assert_eq!(path_target_len, 2);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xAB, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xAB, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 10);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xAB, 0, 0xC4, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xC0, 0, 0xC1, 0, 0xC2, 0, 0xAB, 0, 0xC4, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 10);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xC1, 0, 0xAB, 0, 0xC3, 0, 0xC4, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xC0, 0, 0xC1, 0, 0xAB, 0, 0xC3, 0, 0xC4, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 10);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0, 0xAB, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xC0, 0, 0xAB, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 10);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0xC5, 0][..];
        path_target     = [0x3F, 0, 0xAB, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 12);
        assert_eq!(path_target, [0xAB, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0, 0xC4, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 10);

        let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0][..];
        let mut path_target = [0x3F, 0, 0xAB, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 4);
        assert_eq!(path_target, [0xAB, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 2);

// let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0][..];
        path_target     = [0x3F, 0, 0xC0, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 4);
        assert_eq!(path_target, [0xC0, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 2);

        let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0][..];
        let mut path_target = [0x3F, 0, 0xC0, 0, 0xC1, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 6);
        assert_eq!(path_target, [0xC1, 0, 0x3F, 0, 0xC0, 0]);
        assert_eq!(path_target_len, 2);

        let current_path_df = &[0x3F, 0, 0xC0, 0, 0xC1, 0, 0xC2, 0, 0xC3, 0][..];
        path_target                = [0x3F, 0, 0xC0, 0, 0xC1, 0];
        path_target_len = path_target.len();
        cut_path(&mut path_target[..], &mut path_target_len, current_path_df);
        assert_eq!(path_target.len(), 6);
        assert_eq!(path_target, [0xC0, 0, 0xC1, 0, 0x3F, 0]);
        assert_eq!(path_target_len, 4);
    }
}
