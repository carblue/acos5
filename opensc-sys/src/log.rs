/*
 * log.h: Logging functions header file
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 * Copyright (C) 2019-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/


use libc::FILE;
use std::os::raw::c_char;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1)))]
use std::os::raw::c_int;


use crate::opensc::sc_context;
use crate::types::sc_object_id;
                                        /* 0            will suppress any debug log */
pub const SC_LOG_DEBUG_VERBOSE_TOOL: i32 = 1;        /* tools only: verbose */
pub const SC_LOG_DEBUG_VERBOSE     : i32 = 2;        /* helps users */
pub const SC_LOG_DEBUG_NORMAL      : i32 = 3;        /* helps developers */
pub const SC_LOG_DEBUG_RFU1        : i32 = 4;        /* RFU */
pub const SC_LOG_DEBUG_SM          : i32 = 5;        /* secure messaging */  // since opensc source release v0.20.0
pub const SC_LOG_DEBUG_ASN1        : i32 = 6;        /* asn1.c */
pub const SC_LOG_DEBUG_MATCH       : i32 = 7;        /* card matching */
cfg_if::cfg_if! {
    if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1))] {
        pub const SC_LOG_DEBUG_PIN         : i32 = 8;        /* PIN commands */  // since opensc source release v0.21.0
    }
    else {
        pub const SC_LOG_DEBUG_DEPS        : i32 = 8;        /* debugging of dependencies, e.g. OpenSSL */
        pub const SC_LOG_DEBUG_PIN         : i32 = 9;        /* PIN commands */  // since opensc source release v0.21.0
    }
}
pub const SC_COLOR_FG_RED          : i32 = 0x0001;
pub const SC_COLOR_FG_GREEN        : i32 = 0x0002;
pub const SC_COLOR_FG_YELLOW       : i32 = 0x0004;
pub const SC_COLOR_FG_BLUE         : i32 = 0x0008;
pub const SC_COLOR_FG_MAGENTA      : i32 = 0x0010;
pub const SC_COLOR_FG_CYAN         : i32 = 0x0020;
pub const SC_COLOR_BG_RED          : i32 = 0x0100;
pub const SC_COLOR_BG_GREEN        : i32 = 0x0200;
pub const SC_COLOR_BG_YELLOW       : i32 = 0x0400;
pub const SC_COLOR_BG_BLUE         : i32 = 0x0800;
pub const SC_COLOR_BG_MAGENTA      : i32 = 0x1000;
pub const SC_COLOR_BG_CYAN         : i32 = 0x2000;
pub const SC_COLOR_BOLD            : i32 = 0x8080;

extern "C" {
/*
/* You can't do #ifndef __FUNCTION__ */
#if !defined(__GNUC__) && !defined(__IBMC__) && !(defined(_MSC_VER) && (_MSC_VER >= 1300))
#define __FUNCTION__ NULL
#endif

#if defined(__GNUC__)
#define sc_debug(ctx, level, format, args...)    sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#define sc_log(ctx, format, args...)   sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __FILE__, __LINE__, __FUNCTION__, format , ## args)
#else
#define sc_debug _sc_debug
#define sc_log _sc_log
#endif

#if defined(__GNUC__)
#if defined(__MINGW32__) && defined (__MINGW_PRINTF_FORMAT)
#define SC_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#else
#define SC_PRINTF_FORMAT printf
#endif

/* GCC can check format and param correctness for us */
void sc_do_log(struct sc_context *ctx, int level, const char *file, int line,
           const char *func, const char *format, ...)
    __attribute__ ((format (SC_PRINTF_FORMAT, 6, 7)));
void sc_do_log_color(struct sc_context *ctx, int level, const char *file, int line,
           const char *func, int color, const char *format, ...)
    __attribute__ ((format (SC_PRINTF_FORMAT, 7, 8)));
void sc_do_log_noframe(sc_context_t *ctx, int level, const char *format,
               va_list args) __attribute__ ((format (SC_PRINTF_FORMAT, 3, 0)));
void _sc_debug(struct sc_context *ctx, int level, const char *format, ...)
    __attribute__ ((format (SC_PRINTF_FORMAT, 3, 4)));
void _sc_log(struct sc_context *ctx, const char *format, ...)
    __attribute__ ((format (SC_PRINTF_FORMAT, 2, 3)));
int sc_color_fprintf(int colors, struct sc_context *ctx, FILE * stream, const char * format, ...)
    __attribute__ ((format (SC_PRINTF_FORMAT, 4, 5)));
#else
*/
pub fn sc_do_log(ctx: *mut sc_context, level: i32, file: *const c_char, line: i32, func: *const c_char,
                 format: *const c_char, ...);
pub fn sc_do_log_color(ctx: *mut sc_context, level: i32, file: *const c_char, line: i32, func: *const c_char,
                       color: i32, format: *const c_char, ...);
//void sc_do_log_noframe(sc_context_t *ctx, int level, const char *format, va_list args);
//pub fn sc_do_log_noframe(ctx: *mut sc_context_t, level: i32, format: *const c_char, args: *mut __va_list_tag);
pub fn _sc_debug(ctx: *mut sc_context, level: i32, format: *const c_char, ...);
pub fn _sc_log(ctx: *mut sc_context, format: *const c_char, ... );
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1)))]
pub fn _sc_log_openssl(ctx: *mut sc_context);
pub fn sc_color_fprintf(colors: i32, ctx: *mut sc_context, stream: *mut FILE, format: *const c_char, ...) -> i32;
#[cfg(not(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0, v0_24_0, v0_25_0, v0_25_1)))]
pub fn sc_do_log_openssl(ctx: *mut sc_context, level: c_int, file: *const c_char, line: c_int, func: *const c_char);
}
/*
#endif  // #if defined(__GNUC__)

/**
 * @brief Log binary data to a sc context
 *
 * @param\[in\] ctx   Context for logging
 * @param\[in\] level
 * @param\[in\] label Label to prepend to the buffer
 * @param\[in\] data  Binary data
 * @param\[in\] len   Length of \a data
 */
#define sc_debug_hex(ctx, level, label, data, len) \
    _sc_debug_hex(ctx, level, __FILE__, __LINE__, __FUNCTION__, label, data, len)
#define sc_log_hex(ctx, label, data, len) \
    sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, label, data, len)
*/

extern "C" {
/// @brief Log binary data
///
/// @param\[in\] ctx    Context for logging
/// @param\[in\] level  Debug level
/// @param\[in\] file   File name to be prepended
/// @param\[in\] line   Line to be prepended
/// @param\[in\] func   Function to be prepended
/// @param\[in\] label  label to prepend to the buffer
/// @param\[in\] data   binary data
/// @param\[in\] len    length of \a data
pub fn _sc_debug_hex(ctx: *mut sc_context, level: i32, file: *const c_char, line: i32,
                     func: *const c_char, label: *const c_char, data: *const u8, len: usize);

pub fn sc_hex_dump(                                  buf: *const u8, len: usize, out: *mut c_char, outlen: usize);

/*
@return A pointer to statically 'allocated' array. sizeof(array)==4096,
        truncation occurs ! Special formating (blocks of 16 bytes, space delimited etc.) get's applied
*/
pub fn sc_dump_hex(in_: *const u8, count: usize) -> *const c_char;

fn sc_dump_oid(oid: *const sc_object_id) -> *const c_char;
}

/*
#define SC_FUNC_CALLED(ctx, level) do { \
     sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, "called\n"); \
} while (0)
#define LOG_FUNC_CALLED(ctx) SC_FUNC_CALLED((ctx), SC_LOG_DEBUG_NORMAL)

#define SC_FUNC_RETURN(ctx, level, r) do { \
    int _ret = r; \
    if (_ret <= 0) { \
        sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
            "returning with: %d (%s)\n", _ret, sc_strerror(_ret)); \
    } else { \
        sc_do_log(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
            "returning with: %d\n", _ret); \
    } \
    return _ret; \
} while(0)
#define LOG_FUNC_RETURN(ctx, r) SC_FUNC_RETURN((ctx), SC_LOG_DEBUG_NORMAL, (r))

#define SC_TEST_RET(ctx, level, r, text) do { \
    int _ret = (r); \
    if (_ret < 0) { \
        sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
            "%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
        return _ret; \
    } \
} while(0)
#define LOG_TEST_RET(ctx, r, text) SC_TEST_RET((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))

#define SC_TEST_GOTO_ERR(ctx, level, r, text) do { \
    int _ret = (r); \
    if (_ret < 0) { \
        sc_do_log_color(ctx, level, __FILE__, __LINE__, __FUNCTION__, \
            "%s: %d (%s)\n", (text), _ret, sc_strerror(_ret)); \
        goto err; \
    } \
} while(0)
#define LOG_TEST_GOTO_ERR(ctx, r, text) SC_TEST_GOTO_ERR((ctx), SC_LOG_DEBUG_NORMAL, (r), (text))
*/
