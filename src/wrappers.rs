/*
 * wrapper.rs: Driver 'acos5_64' - Some wrapping functions
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

use std::os::raw::{c_uint, c_int, c_uchar, c_char};
use std::ffi::CStr;

use opensc_sys::opensc::{sc_context};
use opensc_sys::log::{sc_do_log, SC_LOG_DEBUG_NORMAL};
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
use opensc_sys::log::{sc_do_log_color, SC_COLOR_FG_RED};
use opensc_sys::errors::{sc_strerror};

pub fn wr_do_log(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr()) };
}

pub fn wr_do_log_t<T>(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg: T, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg) };
}

pub fn wr_do_log_tt<T>(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg1: T, arg2: T, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg1, arg2) };
}

pub fn wr_do_log_ttt<T>(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg1: T, arg2: T, arg3: T, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3) };
}

pub fn wr_do_log_tu<T,U>(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg1: T, arg2: U, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg1, arg2) };
}

pub fn wr_do_log_tuv<T,U,V>(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg1: T, arg2: U, arg3: V, fmt: &CStr)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3) };
}

pub fn wr_do_log_8u8_i32(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, fmt: &CStr, a: [c_uchar; 8], i:i32)
{
    unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(),
                       a[0] as u32, a[1] as u32, a[2] as u32, a[3] as u32, a[4] as u32, a[5] as u32, a[6] as u32, a[7] as u32, i) };
}

// usage for error return (<0) with: LOG_TEST_RET, LOG_TEST_GOTO_ERR
pub fn wr_do_log_sds(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, arg1: *const c_char, arg2: c_int, arg3: *const c_char, fmt: &CStr)
{
    #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
    {unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), fmt.as_ptr(), arg1, arg2, arg3) }; }
    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    {unsafe { sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), SC_COLOR_FG_RED, fmt.as_ptr(), arg1, arg2, arg3) }; }
}

// usage for ordinary return with: LOG_FUNC_RETURN
pub fn wr_do_log_rv(ctx: *mut sc_context, file: &CStr, line: c_uint, fun: &CStr, rv: c_int)
{
    if rv <= 0 {
        #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
        {unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(),
                            CStr::from_bytes_with_nul(b"returning with: %d (%s)\n\0").unwrap().as_ptr(), rv, sc_strerror(rv)) }; }
        #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
        {unsafe { sc_do_log_color(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(), SC_COLOR_FG_RED,
                                  CStr::from_bytes_with_nul(b"returning with: %d (%s)\n\0").unwrap().as_ptr(), rv, sc_strerror(rv)) }; }
    }
    else {
        unsafe { sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, file.as_ptr(), line as c_int, fun.as_ptr(),
                            CStr::from_bytes_with_nul(b"returning with: %d\n\0").unwrap().as_ptr(), rv) };
    }
}
