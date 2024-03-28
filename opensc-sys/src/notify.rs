/*
 * notify.h: OpenSC library header file
 *
 * Copyright (C) 2017 Frank Morgner <frankmorgner@gmail.com>
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

use std::os::raw::c_char;

use crate::types::sc_atr;
use crate::opensc::sc_context;
use crate::strings::ui_str;
use crate::pkcs15::sc_pkcs15_card;

extern "C" {
pub fn sc_notify_init();
pub fn sc_notify_close();
pub fn sc_notify(title: *const c_char, text: *const c_char);
pub fn sc_notify_id(ctx: *mut sc_context, atr: *mut sc_atr, p15card: *mut sc_pkcs15_card, id: ui_str);
}

/*
#ifdef _WIN32  //#[cfg(windows)]
#include <windows.h>  //extern crate winapi;  pub enum HINSTANCE__ {};  type HINSTANCE = *mut HINSTANCE__;
/* If the code executes in a DLL, `sc_notify_instance_notify` should be
 * initialized before calling `sc_notify_init()`. If not initialized, we're
 * using the HINSTANCE of the EXE */
extern HINSTANCE sc_notify_instance;
/* This is the message created when the user clicks on "exit". */
#define WMAPP_EXIT (WM_APP + 2) //pub const WMAPP_EXIT : u32 = (/*WM_APP*/ 0x8000 + 2);
#endif
*/
