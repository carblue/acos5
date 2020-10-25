use std::ptr::null_mut;
use std::ffi::CStr;

use opensc_sys::opensc::{sc_card, sc_get_mf_path/*, sc_format_path*/, sc_select_file};
// use opensc_sys::types::{sc_path,/* sc_file*/};
use opensc_sys::errors::{/*SC_SUCCESS,*/ SC_ERROR_NOT_ALLOWED, SC_ERROR_FILE_NOT_FOUND};
// /*, SC_ERROR_INTERNAL*/, SC_ERROR_INVALID_ARGUMENTS, SC_ERROR_KEYPAD_MSG_TOO_LONG,
//                          SC_ERROR_NO_CARD_SUPPORT, SC_ERROR_INCOMPATIBLE_KEY, SC_ERROR_WRONG_CARD, SC_ERROR_WRONG_PADDING,
//                          SC_ERROR_INCORRECT_PARAMETERS, SC_ERROR_NOT_SUPPORTED, SC_ERROR_BUFFER_TOO_SMALL, SC_ERROR_NOT_ALLOWED,
//                          SC_ERROR_SECURITY_STATUS_NOT_SATISFIED, SC_ERROR_CARD_CMD_FAILED


use crate::wrappers::{wr_do_log, wr_do_log_ttt};
use crate::cmd_card_info::{get_card_life_cycle_byte_eeprom, get_op_mode_byte_eeprom, get_zeroize_card_disable_byte_eeprom};
// use crate::no_cdecl::{update_hashmap};

/* route onlY MF doesn't exist to Err ! */
fn select_mf(card: &mut sc_card) -> Result<i32, i32> {
    let rv = unsafe { sc_select_file(card, unsafe { &*sc_get_mf_path() }, null_mut()) };
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
        println!("[] Does each DF/MF specify the mandatory security environment (SE) file and it does exist and is accessible?");
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
    // update_hashmap(card);
    Ok(())
// $ grep -rni sanity
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
    println!("file. ");
    println!();
}
