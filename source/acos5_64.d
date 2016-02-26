module acos5_64;

import core.stdc.config : c_ulong;
import core.stdc.locale : setlocale, LC_ALL;
import core.stdc.string : memset, memcpy, strlen;
import core.stdc.stdlib : realloc, free;
/*
import core.runtime;
import core.sys.posix.dlfcn : dlsym;
import core.vararg;
import core.thread;

import std.file;
*/
import std.stdio : stdout, stderr, writeln, File;
import std.string : toStringz, fromStringz, lastIndexOf, CaseSensitive;
import std.exception : enforce; //, assumeUnique;
import std.format : format;
import std.algorithm.comparison: min, equal;
import std.conv : to;
import std.array;

version(USE_SODIUM) {
/*
import sodium;
import sodium.randombytes : randombytes_buf;
*/
	import sodium.core : sodium_init;
	import sodium.utils : sodium_malloc, sodium_free, sodium_mlock, sodium_mprotect_noaccess, sodium_mprotect_readwrite;
	import sodium.version_ : sodium_version_string;
}
import libopensc.asn1 : sc_asn1_find_tag;
import libopensc.cardctl;
import libopensc.internal : sc_atr_table;
import libopensc.log; // : sc_do_log, SC_LOG_DEBUG_NORMAL;
import libopensc.opensc;
/+
import acos5_64_h : /*libopenscLoader,*/ SC_CARD_TYPE_ACOS5_64, acos5_64_private_data, DES_KEY_SZ;

version(ENABLE_SM)
	import acos5_64_sm : SM_MODE_TRANSMIT, SM_MODE_ACL, SM_TYPE_CWA14890, SM_SMALL_CHALLENGE_LEN, acos5_64_open, acos5_64_get_wrapped_apdu, acos5_64_free_wrapped_apdu, initialize;
+/
// temporaryly as long as preceeding statements are comments 
import libopensc.cards : SC_CARD_TYPE_ACOS5_64/*, SC_CARD_TYPE_ACOS5_BASE*/;
import libopensc.sm;
import deimos.openssl.des : DES_cblock, const_DES_cblock, DES_KEY_SZ, DES_key_schedule, DES_SCHEDULE_SZ /* is not fixed length, as dep. on DES_LONG */, DES_LONG /*c_ulong*/;
//////////////////////////////////////////////////

immutable sc_path MF = sc_path(
	cast(immutable(ubyte)[SC_MAX_PATH_SIZE]) x"3F00 0000000000000000000000000000",
		2, 0, 0, SC_PATH_TYPE_PATH /*all following bytes of aid: zero*/); 

private immutable(char)[28]  chip_name      = "ACS ACOS5-64 (CryptoMate64)"; // C-style null-terminated string equivalent
private immutable(char)[ 9]  chip_shortname = "acos5_64";                    // C-style null-terminated string equivalent
private immutable(ubyte)[SC_MAX_ATR_SIZE]  ATR       = cast(immutable(ubyte)[SC_MAX_ATR_SIZE]) x"3B BE 96 00 00 41 05 20 00 00 00 00 00 00 00 00 00 90 00";
private immutable(char )[57]               ATR_colon =                                          "3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00"; // FIXME get rid of this, calc from ATR 

/* ATR Table list. */
private immutable(sc_atr_table)[2] acos5_64_atrs = [
	sc_atr_table(
		ATR_colon.ptr,//"3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00",
		"FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		chip_shortname.ptr,
		SC_CARD_TYPE_ACOS5_64,
		SC_CARD_FLAG_RNG, // flags
		null), // _sc_match_atr_block(sc_context_t *ctx, struct sc_card_driver *driver, struct sc_atr *atr)
	sc_atr_table(null, null, null, 0, 0, null) // list end marker
];

				__gshared sc_card_operations*  iso_ops_ptr;
private __gshared sc_card_operations  acos5_64_ops;

/* Module definition for card driver */ 
private __gshared sc_card_driver  acos5_64_drv = sc_card_driver(
	chip_name.ptr,      /**< Full name for acos5_64 card driver */
	chip_shortname.ptr, /**< Short name for acos5_64 card driver */
	null,               /**< pointer to acos5_64_ops (acos5_64 card driver operations) */
	acos5_64_atrs.ptr,  /**< List of card ATR's handled by this driver */
	1,    /**< (natrs) number of atr's to check for this driver */
	null  /**< (dll) Card driver module  (seems to be unused) */
);

// the OpenSC version, this driver implementation is based on.
private immutable(char)[7] module_version = "0.15.0";  // uint major = 0, minor = 15, fix = 0;  // C-style null-terminated string equivalent


/* The 3 module exports: */

export extern (C) __gshared immutable(char)* sc_module_version   = module_version.ptr;
export extern (C) __gshared immutable(char)* sc_driver_version() {
	version(FAKE_OPENSC_VERSION) return sc_get_version();
	else                         return module_version.ptr; 
}
export extern (C) __gshared immutable(void)* sc_module_init(const(char)* name) { return &sc_get_acos5_64_driver; }


private sc_card_driver* sc_get_acos5_64_driver() {
	enforce(DES_KEY_SZ == SM_SMALL_CHALLENGE_LEN && DES_KEY_SZ== 8,
		"For some reason size [byte] of DES-block and challenge-rsponse (card/host) is not equal and/or not 8 bytes!");

	sc_card_driver* iso_drv  = sc_get_iso7816_driver();
	iso_ops_ptr         = iso_drv.ops; // iso_ops_ptr for initialization and casual use

	// initialize all ops with iso7816_driver's implementations
	acos5_64_ops        = *iso_ops_ptr; 
	// reassign what must be handled in a special way for acos5_64
/*
	with (acos5_64_ops) {
		match_card        = &acos5_64_match_card;
		acos5_64_ops.init = &acos5_64_init;
		finish            = &acos5_64_finish;
		erase_binary      = &acos5_64_erase_binary;
		select_file       = &acos5_64_select_file;
		get_challenge     = &acos5_64_get_challenge;
//	verify            = null; // like in *iso_ops_ptr
		logout            = &acos5_64_logout;
		list_files        = &acos5_64_list_files;
//	check_sw          = &acos5_64_check_sw; // switch on/off in some cases only

		card_ctl          = &acos5_64_card_ctl;
		pin_cmd           = &acos5_64_pin_cmd;
		process_fci       = &acos5_64_process_fci;
	}
*/
	acos5_64_drv.ops = &acos5_64_ops;
	return &acos5_64_drv; 
}
