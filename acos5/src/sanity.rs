use std::ptr::{/*null,*/ null_mut};
use std::ffi::CStr;
use std::collections::HashSet;

use opensc_sys::opensc::{sc_card, sc_get_mf_path/*, sc_format_path*/, sc_select_file};
use opensc_sys::types::{sc_crt};
//#[cfg(not(target_os = "windows"))]
//use opensc_sys::types::{sc_aid};
use opensc_sys::errors::{/*SC_SUCCESS,*/ SC_ERROR_NOT_ALLOWED, SC_ERROR_FILE_NOT_FOUND};
// /*, SC_ERROR_INTERNAL*/, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_KEYPAD_MSG_TOO_LONG,
//                          SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INCOMPATIBLE_KEY, SC_ERROR_WRONG_CARD, SC_ERROR_WRONG_PADDING,
//                          SC_ERROR_INCORRECT_PARAMETERS, SC_ERROR_NOT_SUPPORTED, SC_ERROR_BUFFER_TOO_SMALL, SC_ERROR_NOT_ALLOWED,
//                          SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_CARD_CMD_FAILED


use crate::wrappers::{wr_do_log, wr_do_log_ttt};
use crate::cmd_card_info::{get_card_life_cycle_byte_eeprom, get_op_mode_byte_eeprom, get_zeroize_card_disable_byte_eeprom};
use crate::no_cdecl::{update_hashmap};
use crate::constants_types::{DataPrivate, p_void, is_DFMF, FDB_SE_FILE, READ};
use crate::path::{/*file_id,*/ file_id_se, is_child_of};
use crate::se::se_get_references;
/*
cfg_if::cfg_if! {
    if #[cfg(not(target_os = "windows"))] {
        use crate::tasn1_sys::{asn1_check_version};
        use crate::tasn1_pkcs15_util::{analyze_PKCS15_DIRRecord_2F00,/* analyze_PKCS15_PKCS15Objects_5031, analyze_PKCS15_TokenInfo_5032*/};
    }
}
*/
/* route onlY MF doesn't exist to Err ! */
fn select_mf(card: &mut sc_card) -> Result<i32, i32> {
    let rv = unsafe { sc_select_file(card, sc_get_mf_path(), null_mut()) };
    match rv {
        SC_ERROR_NOT_ALLOWED | SC_ERROR_FILE_NOT_FOUND => Err(rv),
        _ => Ok(rv),
    }
}

#[cold]
pub fn sanity_check(card: &mut sc_card, app_name: &CStr) -> Result<(), i32> {
    assert!(!card.ctx.is_null());
    let ctx = unsafe { &mut *card.ctx };
    let f = cstru!(b"sanity_check\0");
    log3ifc!(ctx,f,line!());
    let printable = app_name != unsafe { CStr::from_bytes_with_nul_unchecked(b"opensc-pkcs11\0") };
    if printable {
        println!();
        println!("The following sanity checks are implemented [X] or planned []. Some or all may depend on prior check(s)");
        println!("to be successful. Indentation will indicate such dependency.");
        println!();
        println!("[X] Does MF exist? If no, then the following (indented) checks are possible but nothing else remains to be done.");
        println!("   [] TODO : all what is meaningful to check with access to card's header block bytes");
        println!();
        println!("File system, Security Access Conditions (SAC) and Security Attributes Expanded (SAE) etc.");
        println!("[X] Does each DF/MF specify the mandatory security environment (SE) file and it does exist and is accessible?");
        println!("[X] Check whether all references to SE file are satisfied; list unused SE file record(s)");
        println!("[] PIN files are required for at least MF and each appDF, with max. 1 such file existing there. Is that okay?");
        println!("[] Sym. key file(s) are required only if Secure Messaging (SM) is involved in a DF/MF, with max. 1 such file existing there. Is that okay?");
        println!("[] Are the PIN files and Sym. key file(s) constrained to: Never readable, and files activated such that the constraint will be upheld by the cos (card operating system?");
        println!("[] List all SE file record entries, that are unused (and might be deleted), and list all that refer to SM");
        println!("[] Are the SE file record entries (if used) meaningful, i.e. don't refer to something that doesn't exist?");
        println!("[] TODO check other recommended access rights, e.g. for RSA key pair files");
        println!("  [] List all DF/MF that specify SAE and try a plain explanation of constraints");
        println!("[] Warn about non-security-activated files");
        println!("TODO more to test here");
        println!();
        println!("Issues, that can't be checked, i.e. just be careful or ?");
        println!("PIN record entries: TODO check whether all ACOS5 options can be used/set by opensc tools, or whether the first time they should be written with APDU command for Update Record; be careful here; see how it's done in info/card_initialization.scriptor");
        println!("Sym. key file record entries: TODO check whether all ACOS5 options can be used/set by opensc tools, or whether the first time they should be written with APDU command for Update Record; be careful here; see how it's done in info/card_initialization.scriptor");
        println!("If a sym. key file record is to be used for SM and its Usage or Error Counter is not set to unlimited, then it will/may become invalid in the future, and when it happens, Y'll probably have forgotten this limit");
        println!("There is no way to unblock an invalid key: The complete record must be updated, which may be impossible, if the command for Update Record is forced to use SM for this file, thus SM won't work any more, until You re-initialize the card.");
        println!("It's inadvisable to block Your emergency exit door: Make sure - by all means -, that Access Control always allows to issue command 'Zeroize Card' (part of re-initialization)");
        println!();
        println!("PKCS#15 related checks");
        println!("[] Does EF.DIR 3F002F00 exist, is accessible and has appropriate content, specifying at least 1 appDF and it's aid?");
        println!("   [] List for all appDF(s) the information encoded in EF.DIR");
        println!("   [] Do appDF's path exist in file system and are accessible?");
        println!("      [] Does EF.ODF exist in each appDF and is accessible?");
        println!("[TODO more to test here]");
        println!("-------------------------------------------------------------------------------------------------------");
        println!();
        println!();
    }
    if select_mf(card).is_err() {
        if printable { println!("[X] Does MF exist?  No") }

        /* Try to read EEPROM addresses: If successful, card is uninitialized */
        let card_life_cycle_byte = match get_card_life_cycle_byte_eeprom(card) {
            Ok(val) => val,
            Err(error) => { return Err(error) },
        };
        let operation_mode_byte = match get_op_mode_byte_eeprom(card) {
            Ok(val) => val,
            Err(error) => { return Err(error) },
        };
        let zeroize_card_disable_byte =  match get_zeroize_card_disable_byte_eeprom(card) {
            Ok(val) => val,
            Err(error) => { return Err(error) },
        };

        if printable { println!("### There is no MF: The card is uninitialized/virgin/in factory state ### (Card Life Cycle Byte is 0x{:X}, Operation Mode Byte is 0x{:X}, Zeroize Card Disable Byte is 0x{:X})", card_life_cycle_byte, operation_mode_byte, zeroize_card_disable_byte) }
        log3ift!(ctx,f,line!(), cstru!(
                b"### There is no MF: The card is uninitialized/virgin/in factory state ### (Card Life Cycle Byte is 0x%02X, Operation Mode Byte is 0x%02X, Zeroize Card Disable Byte is 0x%02X)\0"),
                card_life_cycle_byte, operation_mode_byte, zeroize_card_disable_byte);
        return Ok(());
    }
    if printable { println!("[X] Does MF exist?  Yes") }
    update_hashmap(card);
    /* * /
    #[cfg(not(target_os = "windows"))]
    {
        // let req_version = unsafe { CStr::from_bytes_with_nul_unchecked(b"4.16\0") };
        let tasn1_version = unsafe { asn1_check_version(std::ptr::null() /*req_version.as_ptr()*/) };
        if !tasn1_version.is_null() {
            println!("result from asn1_check_version: {:?}", unsafe { CStr::from_ptr(tasn1_version) });
        }
        let mut aid = sc_aid::default();
        analyze_PKCS15_DIRRecord_2F00(card, &mut aid);
println!("AID: {:X?}", &aid.value[..aid.len]);
        // analyze_PKCS15_PKCS15Objects_5031(card);
        // analyze_PKCS15_TokenInfo_5032(card);
    }
    / * */
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    for (&key_dfmf, val) in &dp.files {
        if is_DFMF(val.1[0]) {
            let child_id = file_id_se(val.1);
            assert!(dp.files.contains_key(&child_id)); // or it doesn't exist
            let dpfv_child = &dp.files[&child_id];
            if  dpfv_child.1[0] != FDB_SE_FILE || !is_child_of(dpfv_child, val) {
                println!("DF {:04X} does declare SE file id {:04X}, but either this is no SE-file or is not a child", key_dfmf, child_id);
            }
            else if dpfv_child.2.is_none() || dpfv_child.2.unwrap()[READ] != 0 {
                println!("WARNING: Security Access Condition of SE file id {:04X} is different from 'ALWAYS READABLE'. \
                Hence, OpenSC and this driver won't know any file related Security Access Constraint in directory \
                {:04X} and You may run into all sorts of errors related to Access Control", child_id, key_dfmf);
            }
            else {
                println!("\n[X] DF/MF {:04X} mandatory security environment (SE) file {:04X} seems to be okay (content checked next).", key_dfmf, child_id);
                let mut index_used : HashSet<u8> = HashSet::with_capacity(14);
                for &b in val.2.unwrap().iter() {
                    if ![0, 255].contains(&b) {
                        index_used.insert(b);
                    }
                }
                for (_key_child, val_child) in &dp.files {
                    if is_DFMF(val_child.1[0]) || val_child.1[1] != val.1[1]+2  {
                        continue;
                    }
                    if is_child_of(val_child, val) {
                        for &b in val_child.2.unwrap().iter() {
                            if ![0, 255].contains(&b) {
                                index_used.insert(b);
                            }
                        }
                    }
                }
println!("[X] DF/MF {:04X} references found: {:X?} ", key_dfmf, index_used);
                let mut vec_add_to_set = Vec::with_capacity(8);
                for &index in &index_used {
                    if (index & 0x30) > 0 {
println!("[X] DF/MF {:04X} reference {:X} has bit(s) set that are unused", key_dfmf, index);
                        vec_add_to_set.push(index & 0x0F);
                    }
                    if (index & 0x40) > 0 {
println!("[X] DF/MF {:04X} reference {:X} has bit 'Secure Messaging' set", key_dfmf, index);
                        vec_add_to_set.push(index & 0x0F);
                    }
                    if (index & 0x80) > 0 {
println!("[X] DF/MF {:04X} reference {:X} has MSB bit set: TODO check whether OpenSC/driver supports logical conjunction of constraints", key_dfmf, index);
                        vec_add_to_set.push(index & 0x0F);
                    }
                }
                index_used.retain(|&k| (k & 0xB0) == 0);
                index_used.extend(vec_add_to_set);
println!("[X] DF/MF {:04X} references (reduced set) found: {:X?} ", key_dfmf, index_used);
                let mut once = false;
                for &index in &index_used {
                    if index & 0x40 > 0 &&
                        se_get_references(card, key_dfmf, index & 0x0F, &sc_crt::new_CCT(0x30), false).is_empty() &&
                        se_get_references(card, key_dfmf, index & 0x0F, &sc_crt::new_CCT(0x70), false).is_empty()
                    {
                        once = true;
                        println!("[X] ERROR: The record #{} in SE-file {} shall be used for SM, but it has no suitable CCT template", index & 0x0F, child_id);
                    }
                    if se_get_references(card, key_dfmf, index & 0x0F, &sc_crt::new_AT(0x88), true).is_empty() {
                        once = true;
                        println!("[X] ERROR: There is no record #{} in SE-file {}, but it gets referenced for Access Control", index & 0x0F, child_id);
                    }
                }
                if !once {
                    println!("[X] DF/MF {:04X} mandatory security environment (SE) file {:04X} content satisfies all references).", key_dfmf, child_id);
                }

// if val.3.is_some() {
// println!("[X] DF/MF {:04X}    {:X?} ", key_dfmf, val.3.as_ref().unwrap());
// }

                /*
                for key_dfmf and all its children, collect the SE-records used
                x references to SE-record 1 (PIN verification)
                x references to SE-record 2 (KEY authorization)
                x references to SE-record 3 (SM authenticate)
                x references to SE-record 4 (SM encrypt)
                x references to SE-record 5 (empty)
                */
            }
        }
    }
    // for (_key, val) in &dp.files {
    //     if FDB_SE_FILE == val.1[0] {
    //         println!("val is_SE  : {:X?}", *val);
    //     }
    // }
    card.drv_data = Box::into_raw(dp) as p_void;
    Ok(())
}

#[allow(dead_code)]
#[cold]
fn explain_the_driver() {
    println!("The most prominent feature of the driver design is that it maintains state of the file system, stored in");
    println!("a hashmap. By key=file_id some assorted information about files/directories is stored as value.");
    println!("As collecting the value information is critical for performance, this will be done gradually only");
    println!("(as required) and some information only applies to DF/MF.");
    println!();
    println!("As imposed by a hashmap and required for other reasons, file ids must be unique within the file system.");
    println!("Thus if Your card has more than 1 file id e.g. 0x5031 EF.ODF in different directories (while allowed by");
    println!("acos5, the operating system of ACOS5 cards), the driver doesn't allow that and bail out of acos5_init");
    println!("with an error SC_ERROR_NOT_ALLOWED.");
    println!("Another restriction is, that there may be not more than 255 files witin a DF/MF/directory.");
    println!("There are a lot of other restrictions referring to 'limits', e.g. max. file size, range of allowed ids");
    println!("for e.g. security environment entries, most of them are hardware specific and must be looked up in the");
    println!("reference manual, though common use won't exceed those limits.");
    println!("Violations of these restrictins result in either refusing to support the card or in a process abort.");
    println!("There is 1 other important, notable restriction: Beginning from depth=4 in the file system hierarchy,");
    println!("acos5 stops to enforce the access control, i.e. e.g. PINs are readable, thus, avoid deep nesting");
    println!();
    println!("There is a minimum set of information, that is always present in the hashmap:");

//        ACOS5 allows duplicate file ids, but in corner cases might select among duplicate file ids different than intended. Thus the driver disallows duplicate file ids.


    println!("1. all files and directories of the file system are represented.");
    println!("2. The absolute file/directory path always is present.");
    println!("3. The 8 'File Info' bytes always are present: This is what card's command 'Get Card Info:");
    println!("   File Information' returns for the P2th file in the DF. The 8 bytes are:");
    println!("   [ FDB, DCB, FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI ]; see reference manual");
    println!("   The slots of bytes DCB, SFI and possibly also the 2 byte slot of 'SIZE or MRL, SIZE or NOR' will be");
    println!("   used differently by the driver:");
    println!("   DCB originally is unused (always==0), thus now used for absolute file path length.");
    println!("   SFI is used by acos5, but not by the driver. Instead it will hold an encoding of the PKCS#15 file type,");
    println!("   which will be relevant for a tool like acos5_gui. Currently, the driver does no such detection and");
    println!("   assignment other than for RSA files were an easy identification is possible via FDB (also for EC files");
    println!("   of EVO card type).");
    println!("   DF/MF by definition have no size, mrl or nor info, thus for those the SE file id will be stored in");
    println!("   this slot.");
    println!("4. The Security Condition Bytes (SCB) collected as 8 bytes and named scb8:");
    println!("   The retrieval is expensive: Needs to select the file, get the FCI response and process FCI, thus");
    println!("   collecting this info will be deferred until the file actually needs to be selected.");
    println!("   Nevertheless it's always available for DF/MF and security environment (SE) file.");
    println!("   DF/MF always has complete information about SAC (Security Attributes Compact) from the responsible");
    println!("   SE file, i.e. how to interpret the SCB, and complete information about SAE (Security Attributes");
    println!("   Extended). SAC refers to files/directories, SAE refers to instructions and is responsible for all");
    println!("   children of a DF/MF, whereas SCB/SAC refers to a single file/directory only.");
    println!();
    println!("Another outstanding feature of the driver is the management of select_file and process_fci:");
    println!("Once sc_select_file is invoked, it will perform the minimum of selections required to select the target");
    println!("file and suppress superfluous calls to process_fci (which might entail creating and destroying sc_file");
    println!("structs). cos5 maintains a pointer to currently selected file/directory, so does the driver.");
    println!("cos5 implements a preassigned 'search sequence', a kind of fast search in current file's 'neighborhood'.");
    println!("If the target file is located in that 'neighborhood', 1 single file id selection is sufficient, and the");
    println!("driver uses that efficiently.");
    println!("The selection of target file never gets dropped, as select_file may have side effects: It may change User");
    println!("PIN login status to NOT LOGGED IN and may clear the SE CRT stored/accumulated in cos memory.");
    println!("The driver implements a copy of iso7816_select_file with a single code line change, just to avoid  apdu.p2 = 0x0C; /* first record, return nothing */");
    println!();
    println!("Other of driver's complexity is due to ACOS5 deficiencies:");
    println!("acos5_get_response: Short APDUS allow a 1-byte le only");
    println!("acos5_compute_signature");
}
