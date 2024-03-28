/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 * Copyright (C) 2019-  for the binding: Carsten Blüggel <bluecars@posteo.eu>
 *
 * Originally based on source by Timo Sirainen <tss@iki.fi>
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

use std::os::raw::{c_char, c_void};

pub const SCCONF_BOOLEAN : u32 = 11;
pub const SCCONF_INTEGER : u32 = 12;
pub const SCCONF_STRING  : u32 = 13;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct scconf_list {
    pub next : *mut scconf_list,
    pub data : *mut c_char,
}

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type _scconf_list = scconf_list; // scconf_list and _scconf_list got swapped
*/

pub const SCCONF_ITEM_TYPE_COMMENT : u32 = 0; /* key = NULL, comment */
pub const SCCONF_ITEM_TYPE_BLOCK   : u32 = 1; /* key = key, block */
pub const SCCONF_ITEM_TYPE_VALUE   : u32 = 2; /* key = key, list */

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub union scconf_item__union {
    pub comment : *mut c_char,
    pub block   : *mut scconf_block,
    pub list    : *mut scconf_list,
//  scconf_item__union_align : u64 ,
}

#[repr(C)]
#[derive(/*Debug,*/ Copy, Clone)]
pub struct scconf_item {
    pub next  : *mut scconf_item,
    pub type_ : i32,
    pub key   : *mut c_char,
    pub value : scconf_item__union,
}

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type _scconf_item = scconf_item; // scconf_item and _scconf_item got swapped
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct scconf_block {
    pub parent : *mut scconf_block,
    pub name   : *mut scconf_list,
    pub items  : *mut scconf_item,
}

/*
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub type _scconf_block = scconf_block; // scconf_block and _scconf_block got swapped
*/

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct scconf_context {
    pub filename : *mut c_char,
    pub debug    : i32,
    pub root     : *mut scconf_block,
    pub errmsg   : *mut c_char,
}


extern "C" {
    /* Allocate scconf_context
     * The filename can be NULL
     * field filename get's strdup'ed if non-NULL
     * field root get's heap-allocated
     */
    pub fn scconf_new(filename: *const c_char) -> *mut scconf_context;

    /* Free scconf_context
     */
    pub fn scconf_free(config: *mut scconf_context);

    /* Parse configuration
     * Returns 1 = ok, 0 = error, -1 = error opening config file
     */
    pub fn scconf_parse(config : *mut scconf_context) -> i32;

    /* Parse a static configuration string
     * Returns 1 = ok, 0 = error
     */
    pub fn scconf_parse_string(config: *mut scconf_context, string: *const c_char) -> i32;

    /* Write config to a file
     * If the filename is NULL, use the config->filename
     * Returns 0 = ok, else = errno
     */
    pub fn scconf_write(config: *mut scconf_context, filename: *const c_char) -> i32;

    /* Find a block by the item_name
     * If the block is NULL, the root block is used
     */
    pub fn scconf_find_block(config: *const scconf_context, block: *const scconf_block, item_name: *const c_char)
        -> *const scconf_block;

    /* Find blocks by the item_name
     * If the block is NULL, the root block is used
     * The key can be used to specify what the blocks first name should be
     */
    pub fn scconf_find_blocks(config: *const scconf_context, block: *const scconf_block, item_name: *const c_char,
                              key: *const c_char) -> *mut *mut scconf_block;

    /* Get a list of values for option
     */
    pub fn scconf_find_list(block: *const scconf_block, option: *const c_char) -> *const scconf_list;

    /* Return the first string of the option
     * If no option found, return def
     */
    pub fn scconf_get_str(block: *const scconf_block, option: *const c_char, def: *const c_char) -> *const c_char;

    /* Return the first value of the option as integer
     * If no option found, return def
     */
    pub fn scconf_get_int(block: *const scconf_block, option: *const c_char, def: i32) -> i32;

    /* Return the first value of the option as boolean
     * If no option found, return def
     */
    pub fn scconf_get_bool(block: *const scconf_block, option: *const c_char, def: i32) -> i32;

    /* Write value to a block as a string
     */
    pub fn scconf_put_str(block: *mut scconf_block, option: *const c_char, value: *const c_char) -> *const c_char;

    /* Write value to a block as an integer
     */
    pub fn scconf_put_int( block: *mut scconf_block, option: *const c_char, value: i32) -> i32;

    /* Write value to a block as a boolean
     */
    pub fn scconf_put_bool(block: *mut scconf_block, option: *const c_char, value: i32) -> i32;

    /* Add block structure
     * If the block is NULL, the root block is used
     */
    pub fn scconf_block_add(config: *mut scconf_context, block: *mut scconf_block, key: *const c_char,
                            name: *const scconf_list) -> *mut scconf_block;

    /* Copy block structure (recursive)
     */
    pub fn scconf_block_copy(src: *const scconf_block, dst: *mut *mut scconf_block) -> *mut scconf_block;

    /* Free block structure (recursive)
     */
    pub fn scconf_block_destroy(block: *mut scconf_block);

    /* Add item to block structure
     * If the block is NULL, the root block is used
     */
    pub fn scconf_item_add(config: *mut scconf_context, block: *mut scconf_block, item: *mut scconf_item, type_: i32,
                           key: *const c_char, data: *const c_void) -> *mut scconf_item;

    /* Copy item structure (recursive)
     */
    pub fn scconf_item_copy(src: *const scconf_item, dst: *mut *mut scconf_item) -> *mut scconf_item;

    /* Free item structure (recursive)
     */
    pub fn scconf_item_destroy(item: *mut scconf_item);

    /* Add a new value to the list
     */
    pub fn scconf_list_add(list: *mut *mut scconf_list, value: *const c_char) -> *mut scconf_list;

    /* Copy list structure
     */
    pub fn scconf_list_copy(src: *const scconf_list, dst: *mut *mut scconf_list) -> *mut scconf_list;

    /* Free list structure
     */
    pub fn scconf_list_destroy(list: *mut scconf_list);

    /* Return the length of an list array
     */
    pub fn scconf_list_array_length(list: *const scconf_list) -> i32;

    /* Return the combined length of the strings on all arrays
     */
    pub fn scconf_list_strings_length(list: *const scconf_list) -> i32;

    /* Return an allocated string that contains all
     * the strings in a list separated by the filler
     * The filler can be NULL
     */
    pub fn scconf_list_strdup(list: *const scconf_list, filler: *const c_char) -> *mut c_char;

    /* Returns an allocated array of const char *pointers to
     * list elements.
     * Last pointer is NULL
     * Array must be freed, but pointers to strings belong to scconf_list
     */
    pub fn scconf_list_toarray(list: *const scconf_list) -> *mut *const c_char;
}


#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use super::*;

    #[test]
    fn test_scconf_new() {
        let filename = CStr::from_bytes_with_nul(b"some_name\0").unwrap().as_ptr();
        let ctx = unsafe { scconf_new(filename) };
        assert!(!ctx.is_null());
        unsafe { scconf_free(ctx) };
    }

    #[test]
    fn test_scconf_parse() {
        let filename = CStr::from_bytes_with_nul(b"test_files/scconf_1.txt\0").unwrap().as_ptr();
        let ctx = unsafe { scconf_new(filename) };
        assert!(!ctx.is_null());
        let ctx_mr = unsafe { &mut *ctx };
        let rv = unsafe { scconf_parse(ctx_mr) };
        assert_eq!(rv, 1);
        println!("ctx.errmsg:   {:?}", ctx_mr.errmsg);                                   // a null value
        if !ctx_mr.errmsg.is_null() { println!("ctx.errmsg: {:?}", unsafe { CStr::from_ptr(ctx_mr.errmsg) }); }
        println!("ctx.debug:    {}",   ctx_mr.debug);                                    // 0
        println!("ctx.filename: {:?}", unsafe { CStr::from_ptr(ctx_mr.filename) }); // "test_files/scconf_1.txt"
        println!("ctx.root:     {:?}", ctx_mr.root);                                     // a non-null value
        if !ctx_mr.root.is_null() {
            let root_mr = unsafe { &mut *ctx_mr.root };
            println!("ctx.root.parent: {:?}", root_mr.parent);                           // a null value
            println!("ctx.root.name:   {:?}", root_mr.name);                             // a null value
            println!("ctx.root.items:  {:?}", root_mr.items);                            // a non-null value
            if !root_mr.items.is_null() {
                let root_items_mr = unsafe { &mut *root_mr.items };
                println!("ctx.root.items.next:  {:?}", root_items_mr.next);              // a null value
                println!("ctx.root.items.type:  {}",   root_items_mr.type_);             // 1 => SCCONF_ITEM_TYPE_BLOCK
//                println!("ctx.root.items.key:   {:?}", root_items_mr.key);               // a non-null value
                if !root_items_mr.key.is_null() {
                    println!("ctx.root.items.key:   {:?}", unsafe { CStr::from_ptr(root_items_mr.key) }); // "transport_stream"
                }
                println!("ctx.root.items.value.block: {:?}", unsafe { root_items_mr.value.block }); // a non-null value
                if unsafe { !root_items_mr.value.block.is_null() } {
                    let root_items_value_block_mr = unsafe { &mut *root_items_mr.value.block };
                    println!("ctx.root.items.value.block.parent: {:?}", root_items_value_block_mr.parent); // a non-null value equal to ctx.root
                    println!("ctx.root.items.value.block.name:   {:?}", root_items_value_block_mr.name);   // a non-null value
                    println!("ctx.root.items.value.block.items:  {:?}", root_items_value_block_mr.items);  // a non-null value

                    if !root_items_value_block_mr.name.is_null() { // scconf_list *
                        let root_items_value_block_name_mr = unsafe { &mut *root_items_value_block_mr.name };
                        println!("ctx.root.items.value.block.name.next: {:?}", root_items_value_block_name_mr.next);   // a null value
                        println!("ctx.root.items.value.block.name.data: {:?}", root_items_value_block_name_mr.data);   // a non-null value
                        if !root_items_value_block_name_mr.data.is_null() {
                            println!("ctx.root.items.value.block.name.data: {:?}",  unsafe { CStr::from_ptr(root_items_value_block_name_mr.data) }); // ""
                        }
                    }
                    if !root_items_value_block_mr.items.is_null() { // scconf_item *
                        let root_items_value_block_items_mr = unsafe { &mut *root_items_value_block_mr.items };
                        println!("ctx.root.items.value.block.items.next:  {:?}", root_items_value_block_items_mr.next);  // a non-null value
                        println!("ctx.root.items.value.block.items.type:  {}",   root_items_value_block_items_mr.type_); // 2 => SCCONF_ITEM_TYPE_VALUE
//                        println!("ctx.root.items.value.block.items.key:   {:?}", root_items_value_block_items_mr.key);   // a non-null value
                        if !root_items_value_block_items_mr.key.is_null() {
                            println!("ctx.root.items.value.block.items.key:   {:?}", unsafe { CStr::from_ptr(root_items_value_block_items_mr.key) }); // "id"
                        }
                        println!("ctx.root.items.value.block.items.value.list: {:?}", unsafe { root_items_value_block_items_mr.value.list }); // a non-null value
                        if unsafe { !root_items_value_block_items_mr.value.list.is_null() } {
                            let root_items_value_block_items_value_list_mr =  unsafe { &mut *root_items_value_block_items_mr.value.list };
                            println!("ctx.root.items.value.block.items.value.list.next: {:?}", root_items_value_block_items_value_list_mr.next);   // a null value
                            println!("ctx.root.items.value.block.items.value.list.data: {:?}", root_items_value_block_items_value_list_mr.data);   // a non-null value
                            if !root_items_value_block_items_value_list_mr.data.is_null() {
                                println!("ctx.root.items.value.block.items.value.list.data: {:?}",  unsafe { CStr::from_ptr(root_items_value_block_items_value_list_mr.data) }); // "0x0009"
                            }
                        }
                        if !root_items_value_block_items_mr.next.is_null() {
                            let next_item_mr = unsafe { &mut *root_items_value_block_items_mr.next };
                            println!("ctx.root.items.value.block.items.next.next:  {:?}", next_item_mr.next);  // a non-null value
                            println!("ctx.root.items.value.block.items.next.type:  {}",   next_item_mr.type_); // 2 => SCCONF_ITEM_TYPE_VALUE
//                            println!("ctx.root.items.value.block.items.next.key:   {:?}", next_item_mr.key);   // a non-null value
                            if !next_item_mr.key.is_null() {
                                println!("ctx.root.items.value.block.items.next.key:   {:?}", unsafe { CStr::from_ptr(next_item_mr.key) }); // "original_network_id"
                            }
                            println!("ctx.root.items.value.block.items.next.value.list: {:?}", unsafe { next_item_mr.value.list }); // a non-null value
                            // won't follow next_item_mr.value.list here

                            if !next_item_mr.next.is_null() {
                                let next_next_item_mr = unsafe { &mut *next_item_mr.next };
                                println!("ctx.root.items.value.block.items.next.next.next:  {:?}", next_next_item_mr.next);  // a non-null value
                                println!("ctx.root.items.value.block.items.next.next.type:  {}",   next_next_item_mr.type_); // 1 => SCCONF_ITEM_TYPE_BLOCK
//                                println!("ctx.root.items.value.block.items.next.next.key:   {:?}", next_next_item_mr.key);   // a non-null value
                                if !next_next_item_mr.key.is_null() {
                                    println!("ctx.root.items.value.block.items.next.next.key:   {:?}", unsafe { CStr::from_ptr(next_next_item_mr.key) }); // "sat_tuning_info"
                                }
                                println!("ctx.root.items.value.block.items.next.next.value.list: {:?}", unsafe { next_next_item_mr.value.list }); // a non-null value
                                // won't follow next_item_mr.value.list here
                            }
                        }
                    }
                }
            }
        }
        unsafe { scconf_free(ctx) };
    }

}
