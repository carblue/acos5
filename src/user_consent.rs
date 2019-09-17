
use libc::{free};

use std::os::raw::{c_int, c_char, c_void};
use std::ffi::{CStr};

use opensc_sys::opensc::{sc_card/*, SC_CTX_FLAG_DISABLE_POPUPS*/};
use opensc_sys::errors::{SC_SUCCESS, SC_ERROR_KEYPAD_MSG_TOO_LONG, SC_ERROR_NOT_ALLOWED/*, SC_ERROR_INTERNAL, SC_ERROR_INVALID_ARGUMENTS*/};
use opensc_sys::scconf::{/*scconf_block,*/ scconf_find_blocks, scconf_get_bool/*, scconf_get_str*/};
use crate::constants_types::{DataPrivate, CARD_DRV_SHORT_NAME/*, CALLED, CRATE, USER_CONSENT_CMD_NIX*/};
//use crate::wrappers::*;


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ui_context {
//    pub user_consent_app : *const c_char,
    pub user_consent_enabled : c_int,
}// ui_context_t;


impl Default for ui_context {
    fn default() -> ui_context {
        ui_context {
//            user_consent_app: std::ptr::null(),
            user_consent_enabled: 0
        }
    }
}


pub fn get_ui_ctx(card: &mut sc_card) -> ui_context
{
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let ui_ctx = dp.ui_ctx;
    card.drv_data = Box::into_raw(dp) as *mut c_void;
    ui_ctx
}


/* IUP Interface */
pub enum Ihandle {}
extern {
    pub fn IupOpen(argc: *const c_int, argv: *const *const *const c_char) -> c_int;
    pub fn IupClose();
    pub fn IupMessageDlg() -> *mut Ihandle; // https://webserver2.tecgraf.puc-rio.br/iup/en/dlg/iupmessagedlg.html
    pub fn IupDestroy(ih: *mut Ihandle);
    pub fn IupPopup(ih: *mut Ihandle, x: c_int, y: c_int) -> c_int;
//    pub fn IupSetAttributes(ih: *mut Ihandle, str: *const c_char) -> *mut Ihandle;
    pub fn IupSetAttribute(ih: *mut Ihandle, name: *const c_char, value: *const c_char);
    pub fn IupGetAttribute(ih: *mut Ihandle, name: *const c_char) -> *mut c_char;
}

/* called once only from acos5_64_init */
pub fn set_ui_ctx(card: &mut sc_card, ui_ctx: &mut ui_context) -> c_int
{
    if card.ctx.is_null() {
        return SC_ERROR_KEYPAD_MSG_TOO_LONG;
    }
    /* set default values */
//    ui_ctx.user_consent_app = CStr::from_bytes_with_nul(USER_CONSENT_CMD_NIX).unwrap().as_ptr();
    ui_ctx.user_consent_enabled = 1;

    /* look for sc block in opensc.conf */
    let ctx = unsafe { &mut *card.ctx };
    for elem in &ctx.conf_blocks {
        if elem.is_null() { break; }

        let blocks = unsafe { scconf_find_blocks(ctx.conf, *elem,
                                                 CStr::from_bytes_with_nul(b"card_driver\0").unwrap().as_ptr(),
                                         CStr::from_bytes_with_nul(CARD_DRV_SHORT_NAME).unwrap().as_ptr()) };
        if blocks.is_null() { continue; }
        let blk = unsafe { *blocks };

        unsafe { free(blocks as *mut c_void) };
        if blk.is_null() { continue; }
        /* fill private data with configuration parameters */
//        ui_ctx.user_consent_app =    /* def user consent app is "pinentry" */
//            /*(char *)*/ unsafe { scconf_get_str(blk, CStr::from_bytes_with_nul(b"user_consent_app\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(USER_CONSENT_CMD_NIX).unwrap().as_ptr()) };
        ui_ctx.user_consent_enabled =    /* user consent is enabled by default */
            unsafe { scconf_get_bool(blk, CStr::from_bytes_with_nul(b"user_consent_enabled\0").unwrap().as_ptr(), 1) };
    }
    /* possibly read disable_popups; this then may disable as well */
    if ui_ctx.user_consent_enabled == 1 { unsafe { IupOpen(std::ptr::null(), std::ptr::null()) }; }
    SC_SUCCESS
}

/**
 * Ask for user consent.
 *
 * Check for user consent configuration,
 * Invoke proper gui app and check result
 *
 * @param card pointer to sc_card structure
 * @param title Text to appear in the window header
 * @param text Message to show to the user
 * @return SC_SUCCESS on user consent OK , else error code
 */
//#[cfg(not(any(v0_15_0, v0_16_0)))]
#[cfg(enable_acos5_64_ui)]
pub fn acos5_64_ask_user_consent() -> c_int
{
    unsafe {
        let dlg = IupMessageDlg();
        IupSetAttribute(dlg, CStr::from_bytes_with_nul(b"DIALOGTYPE\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"QUESTION\0").unwrap().as_ptr());
        IupSetAttribute(dlg, CStr::from_bytes_with_nul(b"TITLE\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"RSA private key usage\0").unwrap().as_ptr());
        IupSetAttribute(dlg, CStr::from_bytes_with_nul(b"BUTTONS\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"YESNO\0").unwrap().as_ptr());
        IupSetAttribute(dlg, CStr::from_bytes_with_nul(b"VALUE\0").unwrap().as_ptr(), CStr::from_bytes_with_nul(b"Got a request to use an RSA private key (e.g. for a sign operation).\nDo You accept ?\n(Use 'Yes' only if this makes sense at this point)\0").unwrap().as_ptr());
        IupPopup(dlg, 0xFFFF, 0xFFFF);
        let b_response = IupGetAttribute(dlg, CStr::from_bytes_with_nul(b"BUTTONRESPONSE\0").unwrap().as_ptr()); // BUTTONRESPONSE: Number of the pressed button. Can be "1", "2" or "3". Default: "1".
        assert!(!b_response.is_null());
        let result_ok = *b_response == 49;
        IupDestroy(dlg);
        /* IupClose();  can't be used here, otherwise - using acos5_64_gui - this would close the acos5_64_gui application and crash that */
        if !result_ok { SC_ERROR_NOT_ALLOWED }
        else          { SC_SUCCESS }
    }
}
