/*
 * internal.h: Internal definitions for libopensc
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 *               2005        The OpenSC project
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
 */

use std::os::raw::{c_char, c_ulong};

use crate::opensc::{sc_context, sc_card, sc_algorithm_info};
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
use crate::opensc::{sc_card_driver};
use crate::types::{sc_object_id};
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
use crate::types::{sc_atr};
use crate::scconf::{scconf_block};

/*
#ifdef ENABLE_OPENSSL
#include "libopensc/sc-ossl-compat.h"
#endif
*/
pub const SC_FILE_MAGIC : u32 =  0x1442_6950;
/*
#ifndef _WIN32
#define msleep(t) usleep((t) * 1000)
#else
#define msleep(t) Sleep(t)
#define sleep(t) Sleep((t) * 1000)
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif
*/


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sc_atr_table {
    /* The atr fields are required to
     * be in aa:bb:cc hex format. */
    pub atr : *const c_char,
    /* The atrmask is logically AND'd with an
     * card atr prior to comparison with the
     * atr reference value above. */
    pub atrmask : *const c_char,
    pub name : *const c_char,
    pub type_ : i32,
    pub flags : c_ulong,
    /* Reference to card_atr configuration block,
     * available to user configured card entries. */
    pub card_atr : *mut scconf_block,
}

#[cfg(impl_default)]
impl Default for sc_atr_table {
    fn default() -> Self {
        Self {
            atr      :  std::ptr::null(),
            atrmask  :  std::ptr::null(),
            name     :  std::ptr::null(),
            type_    :  0,
            flags    :  0,
            card_atr :  std::ptr::null_mut(),
        }
    }
}

#[allow(non_snake_case)]
#[must_use]
pub fn BYTES4BITS(num: u32) -> u32 { (num + 7) / 8 }    /* number of bytes necessary to hold 'num' bits */

extern "C" {

/*
/* Internal use only */
int _sc_add_reader(struct sc_context *ctx, struct sc_reader *reader);
int _sc_parse_atr(struct sc_reader *reader);

/* Add an ATR to the card driver's struct sc_atr_table */
int _sc_add_atr(struct sc_context *ctx, struct sc_card_driver *driver, struct sc_atr_table *src);
int _sc_free_atr(struct sc_context *ctx, struct sc_card_driver *driver);

/**
 * Convert an unsigned long into 4 bytes in big endian order
 * @param  buf   the byte array for the result, should be 4 bytes long
 * @param  x     the value to be converted
 * @return       the buffer passed, containing the converted value
 */
u8 *ulong2bebytes(u8 *buf, unsigned long x);
/**
 * Convert an unsigned long into 2 bytes in big endian order
 * @param  buf   the byte array for the result, should be 2 bytes long
 * @param  x     the value to be converted
 * @return       the buffer passed, containing the converted value
 */
u8 *ushort2bebytes(u8 *buf, unsigned short x);
/**
 * Convert 4 bytes in big endian order into an unsigned long
 * @param  buf   the byte array of 4 bytes
 * @return       the converted value
 */
unsigned long bebytes2ulong(const u8 *buf);
/**
 * Convert 2 bytes in big endian order into an unsigned short
 * @param  buf   the byte array of 2 bytes
 * @return       the converted value
 */
unsigned short bebytes2ushort(const u8 *buf);

/**
 * Convert 2 bytes in little endian order into an unsigned short
 * @param  buf   the byte array of 2 bytes
 * @return       the converted value
 */
unsigned short lebytes2ushort(const u8 *buf); // added since opensc source release v0.17.0
/**
 * Convert 4 bytes in little endian order into an unsigned long
 * @param  buf   the byte array of 4 bytes
 * @return       the converted value
 */
unsigned long lebytes2ulong(const u8 *buf);

/* Usable for setting string elements of token info, which
 * are either initialized to NULL or we need to clean
 * previous value.
 *
 * @param   strp   The pointer where to store string
 * @param   value  The string to store (is strdupped)
 */
void set_string(char **strp, const char *value);

#define BYTES4BITS(num)  (((num) + 7) / 8)    /* number of bytes necessary to hold 'num' bits */
*/

/* Returns an scconf_block entry with matching ATR/ATRmask to the ATR specified,
 * NULL otherwise. Additionally, if card driver is not specified, search through
 * all card drivers user configured ATRs. */
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn _sc_match_atr_block(ctx: *mut sc_context, driver: *mut sc_card_driver, atr: *mut sc_atr) -> *mut scconf_block;


/* Returns an index number if a match was found, -1 otherwise. table has to
 * be null terminated. */
// @param table  wont be changed though
#[cfg(    any(v0_17_0, v0_18_0))]
pub fn _sc_match_atr(card: *mut sc_card, table: *mut   sc_atr_table, type_out: *mut i32) -> i32; // exported since opensc source release v0.17.0
#[cfg(not(any(v0_17_0, v0_18_0)))]
pub fn _sc_match_atr(card: *mut sc_card, table: *const sc_atr_table, type_out: *mut i32) -> i32; // API change since opensc source release v0.19.0

fn _sc_card_add_algorithm(card: *mut sc_card, info: *const sc_algorithm_info) -> i32;
fn _sc_card_add_symmetric_alg(card: *mut sc_card, algorithm: u32, key_length: u32, flags: c_ulong) -> i32; // added since opensc source release v0.17.0, but still not exported

pub fn _sc_card_add_rsa_alg(card: *mut sc_card, key_length: u32, flags: c_ulong, exponent: c_ulong) -> i32;
pub fn _sc_card_add_ec_alg(card: *mut sc_card, key_length: u32, flags: c_ulong, ext_flags: c_ulong,
                           curve_oid: *mut sc_object_id) -> i32;

/********************************************************************/
/*                 pkcs1 padding/encoding functions                 */
/********************************************************************/

fn sc_pkcs1_strip_01_padding(ctx: *mut sc_context, in_dat: *const u8, in_len: usize,
                             out_dat: *mut u8, out_len: *mut usize) -> i32;

/*
int sc_pkcs1_strip_02_padding(struct sc_context *ctx, const u8 *data, size_t len,
  u8 *out_dat, size_t *out_len);
int sc_pkcs1_strip_digest_info_prefix(unsigned int *algorithm,
  const u8 *in_dat, size_t in_len, u8 *out_dat, size_t *out_len);
*/

/// PKCS1 encodes the given data.
/// @apiNote only OpenSC (except card-atrust-acos.c and card-starcos.c) calls this in libopensc/pkcs15-sec.c.
///          It may be useful for compute_signature
///          SC_ALGORITHM_RSA_PAD_*, SC_ALGORITHM_RSA_HASH_NONE, SC_ALGORITHM_RSA_HASHES, SC_ALGORITHM_AES*
///          code: ident in 0.17, 0.18 and 0.19; massive changes in 0.20, the first that does PSS padding
/// @param  ctx     IN    sc_context object
/// @param  flags   IN    the algorithm to use
/// @param  in      IN    input buffer
/// @param  inlen   IN    length of the input
/// @param  out     OUT   output buffer (in == out is allowed)
/// @param  outlen  INOUT length of the output buffer; IN: available, OUT: used
/// @param  modlen  IN    length of the modulus in bytes
/// @return         SC_SUCCESS or error code
/// @test available
#[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
pub fn sc_pkcs1_encode(ctx: *mut sc_context, flags: c_ulong, in_: *const u8, inlen: usize,
                       out: *mut u8, outlen: *mut usize, modlen: usize) -> i32;

/// PKCS1 encodes the given data.
/// @param  ctx       IN    sc_context object
/// @param  flags     IN    the algorithm to use
/// @param  in        IN    input buffer
/// @param  inlen     IN    length of the input
/// @param  out       OUT   output buffer (in == out is allowed)
/// @param  outlen    INOUT length of the output buffer; IN: available, OUT: used
/// @param  mod_bits  IN    length of the modulus in bits
/// @return           SC_SUCCESS or error code
/// @test available
#[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
pub fn sc_pkcs1_encode(ctx: *mut sc_context, flags: c_ulong, in_: *const u8, inlen: usize,
                       out: *mut u8, outlen: *mut usize, mod_bits: usize) -> i32;


/**
 * Get the necessary padding and sec. env. flags.
 * @apiNote only OpenSC calls this in libopensc/pkcs15-sec.c. It's vital to understand SC_ALGORITHM_RSA_RAW,
 *          SC_ALGORITHM_RSA_PAD_*, SC_ALGORITHM_RSA_HASH_NONE, SC_ALGORITHM_RSA_HASHES, SC_ALGORITHM_AES*
 *          code: ident in 0.17 and 0.18; 0.19 is the first to consider SC_ALGORITHM_RSA_PAD_PSS; massive changes in 0.20
 * @param  ctx     IN  sc_contex_t object
 * @param  iflags  IN  the desired algorithms flags
 * @param  caps    IN  the card / key capabilities
 * @param  pflags  OUT the padding flags to use
 * @param  sflags  OUT the security env. algorithm flag to use
 * @return SC_SUCCESS on success and an error code otherwise
 */
fn sc_get_encoding_flags(ctx: *mut sc_context, iflags: c_ulong, caps: c_ulong,
                         pflags: *mut c_ulong, sflags: *mut c_ulong) -> i32;
/*
/********************************************************************/
/*             mutex functions                                      */
/********************************************************************/

/**
 * Creates a new sc_mutex object. Note: unless sc_mutex_set_mutex_funcs()
 * this function does nothing and always returns SC_SUCCESS.
 * @param  ctx    sc_context object with the thread context
 * @param  mutex  pointer for the newly created mutex object
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_create(const sc_context *ctx, void **mutex);
/**
 * Tries to acquire a lock for a sc_mutex object. Note: Unless
 * sc_mutex_set_mutex_funcs() has been called before this
 * function does nothing and always returns SUCCESS.
 * @param  ctx    sc_context object with the thread context
 * @param  mutex  mutex object to lock
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_lock(const sc_context *ctx, void *mutex);
/**
 * Unlocks a sc_mutex object. Note: Unless sc_mutex_set_mutex_funcs()
 * has been called before this function does nothing and always returns
 * SC_SUCCESS.
 * @param  ctx    sc_context object with the thread context
 * @param  mutex  mutex object to unlock
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_unlock(const sc_context *ctx, void *mutex);
/**
 * Destroys a sc_mutex object. Note: Unless sc_mutex_set_mutex_funcs()
 * has been called before this function does nothing and always returns
 * SC_SUCCESS.
 * @param  ctx    sc_context object with the thread context
 * @param  mutex  mutex object to be destroyed
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_mutex_destroy(const sc_context *ctx, void *mutex);
/**
 * Returns a unique id for every thread.
 * @param  ctx  sc_context object with the thread context
 * @return unsigned long with the unique id or 0 if not supported
 */
unsigned long sc_thread_id(const sc_context *ctx);

/********************************************************************/
/*             internal APDU handling functions                     */
/********************************************************************/

/**
 * Returns the encoded APDU in newly created buffer.
 * @param  ctx     sc_context object
 * @param  apdu    sc_apdu_t object with the APDU to encode
 * @param  buf     pointer to the newly allocated buffer
 * @param  len     length of the encoded APDU
 * @param  proto   protocol to be used
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_apdu_get_octets(sc_context *ctx, const sc_apdu_t *apdu, u8 **buf,
  size_t *len, unsigned int proto);
/**
 * Sets the status bytes and return data in the APDU
 * @param  ctx     sc_context object
 * @param  apdu    the apdu to which the data should be written
 * @param  buf     returned data
 * @param  len     length of the returned data
 * @return SC_SUCCESS on success and an error code otherwise
 */
int sc_apdu_set_resp(sc_context *ctx, sc_apdu_t *apdu, const u8 *buf,
  size_t len);
/**
 * Logs APDU
 * @param  ctx          sc_context_t object
 * @param  buf          buffer with the APDU data
 * @param  len          length of the APDU
 * @param  is_outgoing  != 0 if the data is send to the card
 */
#define sc_apdu_log(ctx, data, len, is_outgoing) \
    sc_debug_hex(ctx, SC_LOG_DEBUG_NORMAL, is_outgoing != 0 ? "Outgoing APDU" : "Incoming APDU", data, len)

extern struct sc_reader_driver *sc_get_pcsc_driver(void);
extern struct sc_reader_driver *sc_get_ctapi_driver(void);
extern struct sc_reader_driver *sc_get_openct_driver(void);
extern struct sc_reader_driver *sc_get_cryptotokenkit_driver(void);
*/
} // extern "C"


#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SC_SUCCESS;
    use crate::opensc::{SC_ALGORITHM_RSA_PAD_PKCS1, SC_ALGORITHM_RSA_HASH_SHA256};

    #[cfg(    any(v0_17_0, v0_18_0, v0_19_0))]
    #[test]
    fn test_sc_pkcs1_encode() {
        let mut ctx : sc_context = Default::default();
        let flags = SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_PAD_PKCS1;
        let hash = [1u8, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
        let mut out = [0u8; 96];
        let mut outlen = out.len();
        let rv = unsafe { sc_pkcs1_encode(&mut ctx, c_ulong::from(flags), hash.as_ptr(), hash.len(), out.as_mut_ptr(), &mut outlen, out.len()) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(outlen, out.len());
        assert_eq!(out[ 0..32], [0u8, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(out[32..64], [255u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]);
        assert_eq!(out[64..96], hash);
        /*
        SEQUENCE (2 elem)
          SEQUENCE (2 elem)
            OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
            NULL
          OCTET STRING (32 byte) 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20

         30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
        */
    }

    #[cfg(not(any(v0_17_0, v0_18_0, v0_19_0)))]
    #[test]
    fn test_sc_pkcs1_encode() {
        let mut ctx : sc_context = Default::default();
        let flags = SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_PAD_PKCS1;
        let hash = [1u8, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32];
        let mut out = [0u8; 96];
        let mut outlen = out.len();
        let rv = unsafe { sc_pkcs1_encode(&mut ctx, c_ulong::from(flags), hash.as_ptr(), hash.len(), out.as_mut_ptr(), &mut outlen, out.len()*8) };
        assert_eq!(rv, SC_SUCCESS);
        assert_eq!(outlen, out.len());
        assert_eq!(out[ 0..32], [0u8, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(out[32..64], [255u8, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]);
        assert_eq!(out[64..96], hash);
        /*
        SEQUENCE (2 elem)
          SEQUENCE (2 elem)
            OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1 sha-256 (NIST Algorithm)
            NULL
          OCTET STRING (32 byte) 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20

         30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
        */
    }

}
