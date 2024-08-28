/*
 * cardctl.h: card_ctl command numbers
 *
 * Copyright (C) 2003  Olaf Kirch <okir@lse.de>
 * Copyright (C) 2018-2019 GSMK - Gesellschaft für Sichere Mobile Kommunikation mbH
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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110-1335  USA
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

use std::os::raw::{c_char, c_ulong};
#[cfg(not(v0_20_0))]
use crate::pkcs15::sc_pkcs15_tokeninfo;

//#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

/*
 * Generic card_ctl calls
 */
pub const SC_CARDCTL_GENERIC_BASE            : c_ulong =  0x0000_0000;
pub const SC_CARDCTL_ERASE_CARD              : c_ulong =  0x0000_0001;
pub const SC_CARDCTL_GET_DEFAULT_KEY         : c_ulong =  0x0000_0002;
pub const SC_CARDCTL_LIFECYCLE_GET           : c_ulong =  0x0000_0003;
pub const SC_CARDCTL_LIFECYCLE_SET           : c_ulong =  0x0000_0004;
pub const SC_CARDCTL_GET_SERIALNR            : c_ulong =  0x0000_0005;
cfg_if::cfg_if! {
    if #[cfg(any(v0_20_0, v0_21_0, v0_22_0, v0_23_0))] {
pub const SC_CARDCTL_GET_SE_INFO             : c_ulong =  0x0000_0006;
pub const SC_CARDCTL_GET_CHV_REFERENCE_IN_SE : c_ulong =  0x0000_0007;
pub const SC_CARDCTL_PKCS11_INIT_TOKEN       : c_ulong =  0x0000_0008;
pub const SC_CARDCTL_PKCS11_INIT_PIN         : c_ulong =  0x0000_0009;
    }
    else {
pub const SC_CARDCTL_GET_CHANGE_COUNTER      : c_ulong =  0x0000_0006; // since opensc-0.24.0
pub const SC_CARDCTL_GET_SE_INFO             : c_ulong =  0x0000_0007;
pub const SC_CARDCTL_GET_CHV_REFERENCE_IN_SE : c_ulong =  0x0000_0008;
pub const SC_CARDCTL_PKCS11_INIT_TOKEN       : c_ulong =  0x0000_0009;
pub const SC_CARDCTL_PKCS11_INIT_PIN         : c_ulong =  0x0000_000A;
    }
}

pub const SC_CARDCTRL_LIFECYCLE_ADMIN : c_ulong = 0;
pub const SC_CARDCTRL_LIFECYCLE_USER  : c_ulong = 1;
pub const SC_CARDCTRL_LIFECYCLE_OTHER : c_ulong = 2;

/*
 * Generic cardctl - check if the required key is a default
 * key (such as the GPK "TEST KEYTEST KEY" key, or the Cryptoflex AAK)
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_cardctl_default_key {
    pub method : i32,           /* SC_AC_XXX */
    pub key_ref : i32,          /* key reference */

    pub len : usize,              /* in: max size, out: actual size */
    pub key_data : *mut u8,  /* out: key data */
}

/*
 * Generic cardctl - initialize token using PKCS#11 style
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_cardctl_pkcs11_init_token {
    pub so_pin : *const u8,
    pub so_pin_len : usize,
    pub label : *const c_char,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_cardctl_pkcs11_init_token_t = sc_cardctl_pkcs11_init_token;
*/

/*
 * Generic cardctl - set pin using PKCS#11 style
 */
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_cardctl_pkcs11_init_pin {
    pub pin : *const u8,
    pub pin_len : usize,
}
/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type sc_cardctl_pkcs11_init_pin_t = sc_cardctl_pkcs11_init_pin;
*/

/*
 * Generic cardctl - card driver can examine token info
 */
#[cfg(not(v0_20_0))]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_cardctl_parsed_token_info {
    pub flags : u32,
    pub tokeninfo : *mut sc_pkcs15_tokeninfo,
}
