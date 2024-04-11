/*
 * wrapper.rs: Driver 'acos5' - Some wrapping functions
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

/* naming: replace sc to wr, e.g. sc_do_log -> wr_do_log */

//TODO overhaul this interface (with macro_rules?)
// make it as readable as the C code's logging is !


use std::ffi::CStr;

use opensc_sys::opensc::{sc_context};
use opensc_sys::log::{sc_do_log, SC_LOG_DEBUG_NORMAL};
use opensc_sys::log::{sc_do_log_color, SC_COLOR_FG_RED};
use opensc_sys::errors::{sc_strerror};


const CRATE               : &CStr = c"acos5"; // search acos5 mention in debug log file; each function should at least log CALLED, except small helpers or code that is clearly covered by only one possible surrounding function's called
//const RETURNING_INT       : &[u8;  20] = b"returning with: %d\n\0";
const RETURNING_INT_CSTR  : &CStr = c"returning with: %d (%s)\n";
const CSTR_INT_CSTR       : &CStr =             c"%s: %d (%s)\n";


#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log        (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr()) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_t<T>   (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg: T)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_tt<T>  (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: T)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_ttt<T> (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: T, arg3: T)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_tttt<T>(ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: T, arg3: T, arg4: T)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3, arg4) };
    }
}



#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_tu<T,U>      (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: U)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_tuv<T,U,V>   (ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: U, arg3: V)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3) };
    }
}

#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_tuvw<T,U,V,W>(ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, arg1: T, arg2: U, arg3: V, arg4: W)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3, arg4) };
    }
}




/*
pub fn wr_do_log_8u8_i32(ctx: &mut sc_context, f: &CStr, line: u32, fmt: &CStr, a: [u8; 8], i: i32)
{
    if cfg!(log) {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), fmt.as_ptr(),
                           u32::from(a[0]), u32::from(a[1]), u32::from(a[2]), u32::from(a[3]), u32::from(a[4]), u32::from(a[5]), u32::from(a[6]), u32::from(a[7]), i) };
    }
}
*/

// usage for error return (<0) with: LOG_TEST_RET, LOG_TEST_GOTO_ERR
#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_sds(ctx: &mut sc_context, f: &CStr, line: u32, arg1: &CStr, rv: i32/*, arg3: &CStr*/)
{
    if cfg!(log) {
//        let fmt = CSTR_INT_CSTR.as_ptr();
        //                  c"%s: %d (%s)\n")
        //, c"%s rv: %d (%s)\n"
//        #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
//        unsafe {       sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(),
//                                   CSTR_INT_CSTR.as_ptr(), arg1.as_ptr(), rv, sc_strerror(rv)); }
//        #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
        unsafe { sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), SC_COLOR_FG_RED,
                                 CSTR_INT_CSTR.as_ptr(), arg1.as_ptr(), rv, sc_strerror(rv)); }
    }
}

// usage for ordinary return with: LOG_FUNC_RETURN
#[allow(clippy::missing_panics_doc)]
pub fn wr_do_log_rv(ctx: &mut sc_context, f: &CStr, line: u32, rv: i32)
{
    if cfg!(log) {
        if rv <= 0 {
//            #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
//                unsafe {       sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(),
//                                    RETURNING_INT_CSTR.as_ptr(), rv, sc_strerror(rv)); }
//            #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
                unsafe { sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(), SC_COLOR_FG_RED,
                                         RETURNING_INT_CSTR.as_ptr(), rv, sc_strerror(rv)); }
        }
        else {
            unsafe {            sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, CRATE.as_ptr(), i32::try_from(line).unwrap(), f.as_ptr(),
                                          c"returning with: %d\n".as_ptr(), rv); }
        }
    }
}
