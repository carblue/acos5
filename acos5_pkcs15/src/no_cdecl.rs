use std::os::raw::{c_int /*, c_char, c_uint, c_void, c_uchar*/};
use std::ffi::{CStr/*, OsStr*/};
use std::collections::{HashSet};

//use libc::strlen;

//use opensc_sys::opensc::{sc_context, sc_card/*, sc_print_path, sc_file_free, sc_file_new*/};

use opensc_sys::pkcs15::{sc_pkcs15_card, SC_PKCS15_SKDF, SC_PKCS15_TYPE_SKEY, sc_pkcs15_skey_info /*, sc_pkcs15_object*/};
use opensc_sys::errors::{SC_ERROR_INVALID_ARGUMENTS };
use opensc_sys::log::{sc_dump_hex};

use crate::constants_types::*;
use crate::wrappers::*;

use crate::missing_exports::{find_df_by_type};


pub fn rsa_modulus_bits_canonical(rsa_modulus_bits: usize) -> usize { ((rsa_modulus_bits + 8) /256) *256 }

#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_sign_loss))]
#[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_possible_truncation))]
pub fn first_of_free_indices(p15card: &mut sc_pkcs15_card, file_id_sym_keys: &mut u16) -> c_int
{
    if p15card.card.is_null() || unsafe { (*p15card.card).ctx.is_null() } {
        return SC_ERROR_INVALID_ARGUMENTS;
    }
//    let card = unsafe { &mut *p15card.card };
    let card_ctx = unsafe { &mut *(*p15card.card).ctx };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun  = CStr::from_bytes_with_nul(b"first_of_free_indices\0").unwrap();
    if cfg!(log) {
        wr_do_log(card_ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
    }
    let df_path = match find_df_by_type(p15card, SC_PKCS15_SKDF) {
        Ok(df) => if df.enumerated==1 {&df.path} else {return -1},
        Err(e) => return e,
    };
    wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(df_path.value.as_ptr(), df_path.len) }, CStr::from_bytes_with_nul(b"df_list.path of SC_PKCS15_SKDF: %s\0").unwrap());
    let mut obj_list_ptr = p15card.obj_list;
    if obj_list_ptr.is_null() {
        return -1;
    }
    let mut index_possible : HashSet<u8> = HashSet::with_capacity(255);
    for i in 0..255 { index_possible.insert(i+1); }

    /*
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:156:first_of_free_indices: obj_list.type_: 304
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:157:first_of_free_indices: obj_list.label: SM1
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:158:first_of_free_indices: obj_list.flags: 3
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:159:first_of_free_indices: obj_list.content.len: 0
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:161:first_of_free_indices: skey_info.id.len: 1
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:162:first_of_free_indices: skey_info.id: 01
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:163:first_of_free_indices: skey_info.key_reference: 129
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:164:first_of_free_indices: skey_info.key_type: 0
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:165:first_of_free_indices: skey_info.path: 3F0041004102
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:166:first_of_free_indices: skey_info.path.index: 1
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:167:first_of_free_indices: skey_info.path.count: 37

    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:156:first_of_free_indices: obj_list.type_: 304
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:157:first_of_free_indices: obj_list.label: SM2
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:158:first_of_free_indices: obj_list.flags: 3
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:159:first_of_free_indices: obj_list.content.len: 0
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:161:first_of_free_indices: skey_info.id.len: 1
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:162:first_of_free_indices: skey_info.id: 02
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:163:first_of_free_indices: skey_info.key_reference: 130
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:164:first_of_free_indices: skey_info.key_type: 0
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:165:first_of_free_indices: skey_info.path: 3F0041004102
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:166:first_of_free_indices: skey_info.path.index: 2
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:167:first_of_free_indices: skey_info.path.count: 37

    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:156:first_of_free_indices: obj_list.type_: 301
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:157:first_of_free_indices: obj_list.label: AES3
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:158:first_of_free_indices: obj_list.flags: 3
    P:4411; T:0x140611560458048 22:28:26.288 [opensc-pkcs11] acos5:159:first_of_free_indices: obj_list.content.len: 0
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:161:first_of_free_indices: skey_info.id.len: 1
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:162:first_of_free_indices: skey_info.id: 07
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:163:first_of_free_indices: skey_info.key_reference: 131
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:164:first_of_free_indices: skey_info.key_type: 31
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:165:first_of_free_indices: skey_info.path: 3F0041004102
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:166:first_of_free_indices: skey_info.path.index: 3
    P:4411; T:0x140611560458048 22:28:26.289 [opensc-pkcs11] acos5:167:first_of_free_indices: skey_info.path.count: 37
    */
    while !obj_list_ptr.is_null() {
        let obj_list = unsafe { &*obj_list_ptr };
        if (obj_list.type_ & SC_PKCS15_TYPE_SKEY) == SC_PKCS15_TYPE_SKEY {
            assert!(!obj_list.data.is_null());
            wr_do_log_t(card_ctx, f_log, line!(), fun, obj_list.type_, CStr::from_bytes_with_nul(b"obj_list.type_: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, obj_list.label.as_ptr(), CStr::from_bytes_with_nul(b"obj_list.label: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, obj_list.flags, CStr::from_bytes_with_nul(b"obj_list.flags: %X\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, obj_list.content.len, CStr::from_bytes_with_nul(b"obj_list.content.len: %zu\0").unwrap());
            let skey_info = unsafe { &*(obj_list.data as *mut sc_pkcs15_skey_info) };
            wr_do_log_t(card_ctx, f_log, line!(), fun, skey_info.id.len, CStr::from_bytes_with_nul(b"skey_info.id.len: %zu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(skey_info.id.value.as_ptr(), skey_info.id.len) }, CStr::from_bytes_with_nul(b"skey_info.id: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, skey_info.key_reference, CStr::from_bytes_with_nul(b"skey_info.key_reference: %d\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, skey_info.key_type, CStr::from_bytes_with_nul(b"skey_info.key_type: %lu\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, unsafe { sc_dump_hex(skey_info.path.value.as_ptr(), skey_info.path.len) }, CStr::from_bytes_with_nul(b"skey_info.path: %s\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, skey_info.path.index, CStr::from_bytes_with_nul(b"skey_info.path.index: %d\0").unwrap());
            wr_do_log_t(card_ctx, f_log, line!(), fun, skey_info.path.count, CStr::from_bytes_with_nul(b"skey_info.path.count: %d\0").unwrap());
            assert!(skey_info.path.index >= 0 && skey_info.path.index <= 255);
            //TODO temporarily allow cast_sign_loss
            //TODO temporarily allow cast_possible_truncation
            index_possible.remove(&(skey_info.path.index as u8));
            if *file_id_sym_keys == 0 {
                assert!(skey_info.path.len>=2);
                *file_id_sym_keys = u16::from_be_bytes([skey_info.path.value[skey_info.path.len-2],
                                                        skey_info.path.value[skey_info.path.len-1]]);
            }
        }
        obj_list_ptr = obj_list.next;
    }
    let mut index_possible_min = 256_u16;
    for elem in &index_possible {
        if  index_possible_min > u16::from(*elem) {
            index_possible_min = u16::from(*elem);
        }
    }
    //TODO temporarily allow cast_possible_truncation
    i32::from(index_possible_min as u8)
}

/*
/**
 * find library module for provided driver in configuration file
 * if not found assume library name equals to module name
 */
fn me_find_library_driver/*<'a>*/(ctx: &/*'a*/ mut sc_context, name: &CStr) -> String //&'a CStr
{
    let mut module_path_name : *const c_char = std::ptr::null_mut();
    for elem in ctx.conf_blocks.iter() {
        if (*elem).is_null() {
            break;
        }
        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem,
            CStr::from_bytes_with_nul(CARD_DRIVER).unwrap().as_ptr(), name.as_ptr()) };
        if blocks.is_null() {
            continue;
        }
        let blk = unsafe { *blocks };
//        free(blocks);
        if blk.is_null() {
            continue;
        }
        module_path_name = unsafe { scconf_get_str(blk, CStr::from_bytes_with_nul(MODULE).unwrap().as_ptr(),
        CStr::from_bytes_with_nul(LIB_DRIVER_NIX).unwrap().as_ptr()) }; // TODO is OS specific Linux/Unix/MAC?
    }
    let mut vec : Vec<u8> = Vec::with_capacity(64);
    for i in 0.. unsafe {  strlen(module_path_name) } {
        vec.push(unsafe { *module_path_name.add(i) as u8 } );
    }
    String::from_utf8(vec).unwrap()
}

fn me_find_library_sm(ctx: &mut sc_context, name: &CStr) -> Result<String, c_int>
{
    /* * /
    //    const char *sm = NULL, *module_name = NULL, *module_path = NULL, *module_data = NULL, *sm_mode = NULL;
    //    struct sc_context *ctx = card->ctx;
    //    scconf_block *atrblock = NULL, *sm_conf_block = NULL;
    //    int rv, ii;
    //
    //    SC_FUNC_CALLED(ctx, SC_LOG_DEBUG_NORMAL);
    //    sc_log(ctx, "card->sm_ctx.ops.open %p", card->sm_ctx.ops.open);
    //
    //    /* get the name of card specific SM configuration section */
    //    atrblock = _sc_match_atr_block(ctx, card->driver, &card->atr);
    //    if (atrblock == NULL)
    //        LOG_FUNC_RETURN(ctx, SC_SUCCESS);
    //    sm = scconf_get_str(atrblock, "secure_messaging", NULL);
    //    if (!sm)
    //        LOG_FUNC_RETURN(ctx, SC_SUCCESS);

        /* get SM configuration section by the name */
    //    sc_log(ctx, "secure_messaging configuration block '%s'", sm); // sm == "acos5_sm"
    / * */
    let mut sm_conf_block = std::ptr::null_mut() as *mut scconf_block;
    for elem in ctx.conf_blocks.iter() {
//        scconf_block **blocks;
        if (*elem).is_null() {
            break;
        }
//        blocks = scconf_find_blocks(ctx->conf, ctx->conf_blocks[ii], "secure_messaging", sm);
        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem,
            CStr::from_bytes_with_nul(SECURE_MESSAGING).unwrap().as_ptr(), name.as_ptr()) };

        if !blocks.is_null() {
            sm_conf_block = unsafe { *blocks }; //= blocks[0];
//            free(blocks);
        }
        if !sm_conf_block.is_null() {
            break;
        }
    }

    if sm_conf_block.is_null() {
//        LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "SM configuration block not present");
        return Err(SC_ERROR_INCONSISTENT_CONFIGURATION);
    }

    /* check if an external SM module has to be used */
    let module_path : *const c_char = unsafe { scconf_get_str(sm_conf_block, CStr::from_bytes_with_nul(MODULE_PATH).unwrap().as_ptr(),
                                                              std::ptr::null() as *const c_char) };
    let module_name : *const c_char = unsafe { scconf_get_str(sm_conf_block, CStr::from_bytes_with_nul(MODULE_NAME).unwrap().as_ptr(),
                                                              std::ptr::null() as *const c_char) };
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"me_find_library_sm\0").unwrap();
    let fmt   = CStr::from_bytes_with_nul(b"SM module '%s' in  '%s'\0").unwrap();
    if cfg!(log) {
        wr_do_log_tt(ctx, f_log, line!(), fun, module_name, module_path, fmt);
    }

    if module_name.is_null() {
//        LOG_TEST_RET(ctx, SC_ERROR_INCONSISTENT_CONFIGURATION, "Invalid SM configuration: module not defined");
        return Err(SC_ERROR_INCONSISTENT_CONFIGURATION);
    }
    let mut vec : Vec<u8> = Vec::with_capacity(64);
    for i in 0.. unsafe {  strlen(module_path) } {
        vec.push(unsafe { *module_path.add(i) as u8 } );
    }
    if vec.len()>0 && unsafe{strlen(module_name)}>0 { vec.push(47); } // '/'
    for i in 0.. unsafe {  strlen(module_name) } {
        vec.push(unsafe { *module_name.add(i) as u8 } );
    }
    Ok(String::from_utf8(vec).unwrap())
//    Ok(String::from("$HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so"))
}

/* call into the driver library */
pub fn call_dynamic_update_hashmap(card: &mut sc_card) -> lib::Result<()> {
    let card_ctx : &mut sc_context = unsafe { &mut *card.ctx };
    let drv_module_path_name = me_find_library_driver(card_ctx, CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap());
//    println!("driver's module_path_name: {}", drv_module_path_name);
//              driver's module_path_name: "$HOME/RustProjects/acos5/target/debug/libacos5.so"
    let lib = lib::Library::new(OsStr::new(&drv_module_path_name))?;
    unsafe {
        let func: lib::Symbol<unsafe extern fn(*mut sc_card)> = lib.get(b"acos5_update_hashmap")?;
        Ok(func(card))
    }
}

/* call into the SM library (whether it's existent/usable) */
pub fn call_dynamic_sm_test(ctx: &mut sc_context, info: *mut sm_info, out: *mut c_char) -> lib::Result<c_int> {
//    let card_ctx : &mut sc_context = unsafe { &mut *card.ctx };
    let sm_module_path_name = me_find_library_sm(ctx, CStr::from_bytes_with_nul(CARD_SM_SHORT_NAME).unwrap()).unwrap();
//    println!("sm module_path_name: {}", sm_module_path_name);
//            sm module_path_name: $HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so
//    me_find_library_sm: SM module 'libacos5_sm.so' in  '$HOME/RustProjects/acos5_sm/target/debug'
//    println!("driver's module_path_name: {:?}", me_find_library_driver(card_ctx, CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap() ) );
//    "$HOME/RustProjects/acos5_sm/target/debug/libacos5_sm.so"
    /*
    app default {
        framework pkcs15 {
        pkcs15init "acos5-external" {
            # The location of the pkcs15init driver library: /path/to/libacos5....so...;
            #module = "/usr/lib/x86_64-linux-gnu/libacos5.so.5";
            module = "$HOME/RustProjects/acos5_pkcs15/target/debug/libacos5_pkcs15.so";
        }
        }
    }
    */
    let lib = lib::Library::new(OsStr::new(&sm_module_path_name))?;
    unsafe {
        let func: lib::Symbol< unsafe extern fn(*mut sc_context, *mut sm_info, *mut c_char) -> c_int > = lib.get(b"test")?;
        Ok(func(ctx, info, out))
    }
}
*/

/*
/*
 * Allocate a file
 */
pub fn acos5_pkcs15_new_file(profile: &mut sc_profile, card: &mut sc_card,
                                type_: c_uint, num: c_int, out: *mut *mut sc_file) -> c_int
{
    let f_log = CStr::from_bytes_with_nul(CRATE).unwrap();
    let fun   = CStr::from_bytes_with_nul(b"acos5_pkcs15_new_file\0").unwrap();
    let rv : c_int;
    if cfg!(log) {
        wr_do_log(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(CALLED).unwrap());
        wr_do_log_tu(card.ctx, f_log, line!(), fun, type_, num,
                     CStr::from_bytes_with_nul(b"type %X; num %i\0").unwrap());
    }

    let t_name = match type_ {
        SC_PKCS15_TYPE_PRKEY_RSA   => CStr::from_bytes_with_nul(b"template-private-key\0").unwrap(),
        SC_PKCS15_TYPE_PUBKEY_RSA  => CStr::from_bytes_with_nul(b"template-public-key\0").unwrap(),
        SC_PKCS15_TYPE_CERT        => CStr::from_bytes_with_nul(b"template-certificate\0").unwrap(),
        SC_PKCS15_TYPE_DATA_OBJECT => CStr::from_bytes_with_nul(b"template-public-data\0").unwrap(),
        _  => {
            rv = SC_ERROR_NOT_SUPPORTED;
            if cfg!(log) {
                wr_do_log_sds(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Profile template not supported\0").
                    unwrap().as_ptr(), rv, unsafe { sc_strerror(rv) },
                    CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap());
            }
            return rv;
        },
    };

//sc_log(ctx, "df_info path '%s'", sc_print_path(&profile->df_info->file->path));
    let mut file : *mut sc_file = std::ptr::null_mut();
    let rv = me_profile_get_file(profile, t_name.as_ptr(), &mut file);
    if rv < 0 {
        if cfg!(log) {
            wr_do_log_sds(card.ctx, f_log, line!(), fun, CStr::from_bytes_with_nul(b"Error when getting file from template\0").
                unwrap().as_ptr(), rv, unsafe { sc_strerror(rv) },
                CStr::from_bytes_with_nul(b"%s: %d (%s)\n\0").unwrap());
        }
//        return rv;
        file = unsafe { sc_file_new() };
    }
    assert!(!file.is_null());
    let file_rm = unsafe { &mut *file };

    if cfg!(log) {
        wr_do_log_tuv(card.ctx, f_log, line!(), fun, file_rm.type_, file_rm.path.type_, unsafe { sc_print_path(&file_rm.path) },
                      CStr::from_bytes_with_nul(b"file(type:%X), path(type:%X,path:%s)\0").unwrap());
    }
    file_rm.id = (file_rm.id & 0xFF00) | (num & 0xFF);

    if file_rm.type_ != SC_FILE_TYPE_BSO {
        if file_rm.path.len == 0 {
            file_rm.path.type_ = SC_PATH_TYPE_FILE_ID;
            file_rm.path.len = 2;
        }
        file_rm.path.value[file_rm.path.len - 2] = ((file_rm.id >> 8) as u8) & 0xFF;
        file_rm.path.value[file_rm.path.len - 1] = (file_rm.id & 0xFF) as u8;
        file_rm.path.count = -1;
    }

//    sc_log(ctx, "file(size:%"SC_FORMAT_LEN_SIZE_T"u,type:%i/%i,id:%04X), path(type:%X,'%s')",
//        file_rm.size, file_rm.type_, file_rm.ef_structure, file_rm.id,
//        file_rm.path.type_, sc_print_path(&file_rm.path));
    unsafe {
        if !out.is_null() {
            *out = file;
        }
        else {
            sc_file_free(file);
        }
    }
    SC_SUCCESS
}
*/
