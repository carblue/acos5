/**
Copyright etc.
*/

module acos5_64;

import core.stdc.config : c_ulong;
import core.stdc.locale : setlocale, LC_ALL;
import core.stdc.string : memset, memcpy, memcmp, strlen/*, strcasecmp*/;
import core.stdc.stdlib : realloc, free, malloc, calloc;
/*
import core.sys.posix.dlfcn : dlsym;
import core.vararg;
import core.thread;
import std.file;
*/
import std.stdio : stdout, stderr, writeln, File;
import std.string : toStringz, fromStringz, lastIndexOf, CaseSensitive;
import std.exception : enforce; //, assumeUnique;
import std.format;
import std.range : take, retro;
import std.conv : to;
import std.array;
import std.regex;
import std.traits : EnumMembers;

version (GNU) { // gdc compiler
	import std.algorithm : min, equal, find;
//	import gcc.attribute;
}
else { // DigitalMars or LDC compiler
	import std.algorithm.comparison : min, max, equal;
	import std.algorithm.searching : find, count, canFind, any /*,all*/;
}

import libopensc.asn1 : sc_asn1_find_tag, sc_asn1_put_tag;
import libopensc.cardctl : SC_CARDCTL, SC_CARDCTL_GENERIC_BASE, SC_CARDCTL_ERASE_CARD, SC_CARDCTL_GET_DEFAULT_KEY, SC_CARDCTL_LIFECYCLE_GET,
					SC_CARDCTL_GET_SE_INFO, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, SC_CARDCTL_PKCS11_INIT_TOKEN, SC_CARDCTL_PKCS11_INIT_PIN,
					SC_CARDCTL_LIFECYCLE_SET, SC_CARDCTL_GET_SERIALNR,
					SC_CARDCTRL_LIFECYCLE, SC_CARDCTRL_LIFECYCLE_ADMIN, SC_CARDCTRL_LIFECYCLE_USER, SC_CARDCTRL_LIFECYCLE_OTHER;

import libopensc.internal : sc_atr_table;

version(FAKE_OPENSC_VERSION) {}
else
	import libopensc.internal : sc_pkcs1_strip_01_padding, sc_pkcs1_strip_02_padding, _sc_card_add_rsa_alg, _sc_match_atr;

import libopensc.log : sc_dump_hex, sc_do_log, SC_LOG_DEBUG_NORMAL, log;
import libopensc.opensc; // sc_format_path, SC_ALGORITHM_RSA, sc_print_path, sc_file_get_acl_entry
import libopensc.types;// : sc_path, sc_atr, sc_file, sc_serial_number, SC_MAX_PATH_SIZE, SC_PATH_TYPE_PATH, sc_apdu, SC_AC_OP_GENERATE;
import libopensc.errors;

/+
import acos5_64_h : /*libopenscLoader,*/ SC_CARD_TYPE_ACOS5_64, acos5_64_private_data, DES_KEY_SZ;

version(ENABLE_SM)
	import acos5_64_sm : SM_MODE_TRANSMIT, SM_MODE_ACL, SM_TYPE_CWA14890, SM_SMALL_CHALLENGE_LEN, acos5_64_open, acos5_64_get_wrapped_apdu, acos5_64_free_wrapped_apdu, initialize;
+/
// temporarily as long as preceeding statements are comments :
import libopensc.cards : SC_CARD_TYPE_ACOS5_64;
import libopensc.sm;

import libopensc.pkcs15 : sc_pkcs15_card, sc_pkcs15_object, sc_pkcs15_pubkey, SC_PKCS15_TOKEN_PRN_GENERATION, sc_pkcs15_prkey_info, sc_pkcs15_print_id, SC_PKCS15_TYPE_PRKEY_RSA, SC_PKCS15_TYPE_PUBKEY_RSA,
	sc_pkcs15_prkey, sc_pkcs15_der, sc_pkcs15_auth_info, SC_PKCS15_PRKEY_USAGE_SIGN, SC_PKCS15_TYPE_CLASS_MASK, sc_pkcs15_prkey_rsa;
import pkcs15init.pkcs15init : /*sc_profile,*/ sc_pkcs15init_operations, sc_pkcs15init_authenticate, sc_pkcs15init_delete_by_path, sc_pkcs15init_create_file, SC_PKCS15INIT_SO_PIN, SC_PKCS15INIT_USER_PIN;
import pkcs15init.profile : file_info, sc_profile/*, sc_profile_get_file*/;


version(USE_SODIUM) {
	import deimos.sodium.core : sodium_init;
	import deimos.sodium.utils : sodium_malloc, sodium_free, sodium_mlock, sodium_munlock, sodium_mprotect_noaccess, sodium_mprotect_readwrite, sodium_mprotect_readonly;
	import deimos.sodium.version_ : sodium_version_string;
}

import deimos.openssl.des : DES_cblock, const_DES_cblock, DES_KEY_SZ; //, DES_key_schedule, DES_SCHEDULE_SZ /* is not fixed length, as dep. on DES_LONG */, DES_LONG /*c_ulong*/;
import deimos.openssl.bn;

//aus acos5_64_h
	enum ACOS5_64_OBJECT_REF_FLAG_LOCAL = 0x80; // von authentic.h
	enum ACOS5_64_CRYPTO_OBJECT_REF_MIN	= 0x01; // 0x81;
	enum ACOS5_64_CRYPTO_OBJECT_REF_MAX	= 0x0F; // 0xFF;

	enum ERSA_Key_type : ubyte {
		Public_Key                          = 0, // Public Key

		Standard_for_Signing_and_Decrypting = 1, // Private non-CRT key capable of RSA Private Key Sign and Decrypt
		Standard_for_Decrypting             = 2, // Private non-CRT key capable of RSA Private Key Decrypt (only)
		CRT_for_Signing_and_Decrypting      = 4, // Private     CRT key capable of RSA Private Key Sign and Decrypt
		CRT_for_Decrypting_only             = 5, // Private     CRT key capable of RSA Private Key Decrypt (only)
	}

	enum EFDB : ubyte {
	// Working EF:
		Transparent_EF     = SC_FILE_EF.SC_FILE_EF_TRANSPARENT, //1,
		Linear_Fixed_EF    = SC_FILE_EF.SC_FILE_EF_LINEAR_FIXED,// 2,
		Linear_Variable_EF = SC_FILE_EF.SC_FILE_EF_LINEAR_VARIABLE, // 4,
		Cyclic_EF          = SC_FILE_EF.SC_FILE_EF_CYCLIC,// 6, // rarely used		
	// Internal EF:
		RSA_Key_EF         = 0x09,     // ==  8+Transparent_EF,  not record based ( Update Binary )		
			// There can be a maximum of 0x1F Global PINs, 0x1F Local PINs, 0x1F Global Keys, and 0x1F Local Keys at a given time. (1Fh==31)
		CHV_EF             = 0x0A,  // ==  8+Linear_Fixed_EF,     record based ( Update Record ) DF or MF shall contain only one CHV file. Every record in the CHV file will have a fixed length of 21 bytes each
		Symmetric_key_EF   = 0x0C,  // ==  8+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall contain only one sym file. Every record in the symmetric key file shall have a maximum of 37 bytes
		// Proprietary EF:
		SE_EF    	         = 0x1C,  // ==18h+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall use only one SE File. An SE file can have up to 0x0F identifiable records. (0Fh==15)
	// DF types:
		DF                 = 0x38,  // == 0b0011_1000; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
		MF                 = 0x3F,  // == 0b0011_1111; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
	}
	mixin FreeEnumMembers!EFDB;

	ubyte iEF_FDB_to_structure(EFDB FDB) { auto result = cast(ubyte)(FDB & 7); if (result>0 && result<7) return result; else return 0; } 

version(ENABLE_TOSTRING)
/*shared*/ auto writer = appender!string();

BN_CTX* bn_ctx;

version(Posix) {
	private shared static this() {
		setlocale (LC_ALL, "C"); // char* currentlocale =
		version(ENABLE_TOSTRING)
			writer.put("private shared static  this() was called\n\n");
		version(RSA_PKCS_PSS)
			bn_ctx = BN_CTX_new();
	}

	private shared static ~this() {
		version(RSA_PKCS_PSS)
			BN_CTX_free(bn_ctx);
		version(ENABLE_TOSTRING) {
			writer.put("\nprivate shared static ~this() was called\n");
			File f = File("/tmp/test.txt", "w");
			f.write(writer.data);
		}
	}
}

version(Windows)
{
	import core.sys.windows.dll : SimpleDllMain;

	mixin SimpleDllMain;
}

// we'll often deal with ubyte[8]; thus it's worth an alias; don't mix up opensc's  typedef unsigned char u8;
//ias  DES_cblock = ubyte[8];
alias  ub8        = ubyte[8];
//ias iub8        = immutable(ubyte)[8];

struct acos5_64_private_data {
//	sm_cwa_keyset				cwa_keyset;
//uint                sdo_reference;
	ubyte[2*DES_KEY_SZ] card_key2;
	ubyte[2*DES_KEY_SZ] host_key1;
//	sm_cwa_token_data		ifd;
	ubyte[  DES_KEY_SZ] cwa_session_ifd_sn;
	ubyte[  DES_KEY_SZ] cwa_session_ifd_rnd;
	ubyte[4*DES_KEY_SZ]	cwa_session_ifd_k;

	ubyte[  DES_KEY_SZ]	card_challenge; // cwa_session.card_challenge.ptr
	/* it's necessary to know, whether a call to function acos5_64_decipher originated from function acos5_64_compute_signature or not.
	 * call_to_compute_signature_in_progress is set to true, when function acos5_64_compute_signature is entered, and reset to false when returning.
	 */
	bool call_to_compute_signature_in_progress;

	sc_security_env         security_env; // gesetzt in int acos5_64_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num), genutzt z.B. für iasecc_compute_signature*
	acos5_64_se_info*       se_info;      // gesetzt in int acos5_64_se_cache_info/iasecc_se_cache_info(sc_card* card, acos5_64_se_info* se)

version(ENABLE_ACOS5_64_UI)
	 ui_context_t           ui_ctx;
}

//////////////////////////////////////////////////

immutable sc_path MF_path = sc_path( cast(immutable(ubyte)[SC_MAX_PATH_SIZE]) x"3F00 0000000000000000000000000000", 2, 0, 0, SC_PATH_TYPE_PATH /*all following bytes of aid: zero*/);

private immutable(char)[28]  chip_name      = "ACS ACOS5-64 (CryptoMate64)"; // C-style null-terminated string equivalent, +1 for literal-implicit \0
private immutable(char)[ 9]  chip_shortname = "acos5_64";
private immutable(char)[57]               ATR_colon =                                          "3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00";
//ivate immutable(ubyte)[SC_MAX_ATR_SIZE] ATR       = cast(immutable(ubyte)[SC_MAX_ATR_SIZE]) x"3B BE 96 00 00 41 05 20 00 00 00 00 00 00 00 00 00 90 00"; // FIXME get rid of this, calc from ATR_colon if req.
private immutable(char)[57]               ATR_mask  =                                          "FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF";

/* ATR Table list. */
private __gshared sc_atr_table[2] acos5_64_atrs = [ // immutable(sc_atr_table)[2]
	sc_atr_table(
		ATR_colon.ptr,
		ATR_mask.ptr, // "FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		chip_shortname.ptr,
		SC_CARD_TYPE_ACOS5_64,
		SC_CARD_FLAG_RNG, // flags
		null
	),
	sc_atr_table(null, null, null, 0, 0, null) // list end marker all zero
];

__gshared sc_card_operations*  iso_ops_ptr;
private __gshared sc_card_operations        acos5_64_ops;
private __gshared sc_pkcs15init_operations  acos5_64_pkcs15init_ops;

/* Module definition for card driver */
private __gshared sc_card_driver  acos5_64_drv = sc_card_driver(
	chip_name.ptr,      /**< Full  name for acos5_64 card driver */
	chip_shortname.ptr, /**< Short name for acos5_64 card driver */
	null,               /**< pointer to acos5_64_ops (acos5_64 card driver operations) */
	acos5_64_atrs.ptr,  /**< List of card ATR's handled by this driver */
	1,    /**< (natrs) number of atr's to check for this driver */
	null  /**< (dll) Card driver module  (seems to be unused) */
);

// the OpenSC version, this driver implementation is based on.
private __gshared const(char[7]) module_version = "0.16.0";  // uint major = 0, minor = 16, fix = 0;

/* The 3 module exports: */
export extern(C) __gshared const(char)* sc_module_version   = module_version.ptr;
export extern(C) const(char)* sc_driver_version() {
	version(FAKE_OPENSC_VERSION) return sc_get_version;
	else                         return module_version.ptr;
}

extern(C) int rt_init();
extern(C) int rt_term();


export extern(C) void* sc_module_init(const(char)* name)
{
	static int cnt_call;
	++cnt_call;
	if (cnt_call == 1) {
		if (! rt_init())
			return null;
		version(ENABLE_TOSTRING)
			writer.formattedWrite("void* sc_module_init(const(char)* name) was called with argument name: %s and cnt_call: %s\n", name.fromStringz, cnt_call);
		return &sc_get_acos5_64_driver;
	}
	version(ENABLE_TOSTRING)
		writer.formattedWrite("void* sc_module_init(const(char)* name) was called with argument name: %s and cnt_call: %s\n", name.fromStringz, cnt_call);
	return &sc_get_acos5_64_pkcs15init_ops;
}

private sc_card_driver* sc_get_acos5_64_driver()
{
	enforce(DES_KEY_SZ == SM_SMALL_CHALLENGE_LEN && DES_KEY_SZ == 8,
		"For some reason size [byte] of DES-block and challenge-response (card/host) is not equal and/or not 8 bytes!");
	version(ENABLE_TOSTRING)
		writer.put("sc_card_driver* sc_get_acos5_64_driver() was called\n");

//	sc_card_driver* iso_drv  = sc_get_iso7816_driver;
	iso_ops_ptr         = sc_get_iso7816_driver.ops; // iso_ops_ptr for initialization and casual use
	acos5_64_ops        = *iso_ops_ptr; // initialize all ops with iso7816_driver's implementations

	with (acos5_64_ops) {
		match_card        = &acos5_64_match_card; // called from libopensc/card.c:186 int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out) // grep -rnw -e 'acos5_\(64_\)\{0,1\}match_card' 2>/dev/null 
		acos5_64_ops.init = &acos5_64_init;       // called from libopensc/card.c:186 int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out)
		finish            = &acos5_64_finish;
		read_binary       = &acos5_64_read_binary;
		erase_binary      = &acos5_64_erase_binary; // stub

		read_record       = &acos5_64_read_record;
//	iso7816_write_record,
//	iso7816_append_record,
//	iso7816_update_record,

		select_file       = &acos5_64_select_file;
		get_challenge     = &acos5_64_get_challenge;
//	verify            = null; // like in *iso_ops_ptr  this is deprecated
		logout            = &acos5_64_logout;
		set_security_env  = &acos5_64_set_security_env;
version(FAKE_OPENSC_VERSION) {} // due to missing exports sc_pkcs1_strip_01_padding, sc_pkcs1_strip_02_padding
else {
		decipher          = &acos5_64_decipher;
		compute_signature = &acos5_64_compute_signature;
}
////		create_file       = &acos5_64_create_file;
////		delete_file       = &acos5_64_delete_file;
		list_files        = &acos5_64_list_files;
	check_sw          = &acos5_64_check_sw; // NO external use
		card_ctl          = &acos5_64_card_ctl;
		process_fci       = &acos5_64_process_fci;
		construct_fci     = &acos5_64_construct_fci;
		pin_cmd           = &acos5_64_pin_cmd;
// some stubs
		read_public_key   = &acos5_64_read_public_key;
	}
	acos5_64_drv.ops = &acos5_64_ops;
	return &acos5_64_drv;
}

private sc_pkcs15init_operations* sc_get_acos5_64_pkcs15init_ops()
{
// all sc_pkcs15init_operations functions of acos5_64 initially are null, the .init property of 
	version(ENABLE_TOSTRING)
		writer.put("sc_pkcs15init_operations* sc_get_acos5_64_pkcs15init_ops() was called\n");
	with (acos5_64_pkcs15init_ops) {
//		erase_card
		init_card            = &acos5_64_pkcs15_init_card;     // doesn't get called so far
//		create_dir
//		create_domain
		select_pin_reference = &acos5_64_pkcs15_select_pin_reference; // does nothing
//		create_pin
		select_key_reference = &acos5_64_pkcs15_select_key_reference; // does nothing
		create_key           = &acos5_64_pkcs15_create_key;           // does nothing
		store_key            = &acos5_64_pkcs15_store_key;            // does nothing
////		generate_key         = &acos5_64_pkcs15_generate_key;     //   not complete, issues with key-id and acl (check what has preference: profile or new_file etc.) and reading of new pub key, but overall it works
		encode_private_key   = &acos5_64_pkcs15_encode_private_key;   // does nothing
		encode_public_key    = &acos5_64_pkcs15_encode_public_key;    // does nothing
//		finalize_card
		delete_object        = &acos5_64_pkcs15_delete_object;        // does nothing
//		emu_update_dir
//		emu_update_any_df
//		emu_update_tokeninfo
//		emu_write_info
		emu_store_data       = &acos5_64_pkcs15_emu_store_data;       // does nothing ; (otherwise, after acos5_64_pkcs15_generate_key, sc_pkcs15init_store_data wouuld try to delete the publik key file, written nicely on card) 
		sanity_check         = &acos5_64_pkcs15_sanity_check;         // does nothing
	}
	return &acos5_64_pkcs15init_ops;
}


mixin template transmit_apdu(alias functionName) {
	int transmit_apdu_do() {
		int rv_priv;
		if ((rv_priv=sc_transmit_apdu(card, &apdu)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, functionName,
				"APDU transmit failed\n");
		}
		return rv_priv;
	}
}

mixin template transmit_apdu_strerror(alias functionName) {
	int transmit_apdu_strerror_do() {
		int rv_priv;
		if ((rv_priv=sc_transmit_apdu(card, &apdu)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, functionName,
				"APDU transmit failed: %d (%s)\n", rv_priv, sc_strerror(rv_priv));
		}
		return rv_priv;
	}
}

mixin template log_scope_exit(alias functionName) {
	void log_scope_exit_do() {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, functionName,
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, functionName,
				"returning with: %d\n", rv);
	}
}

/**
 * Retrieve hardware identifying serial number (6 bytes) from card and cache it
 *
 * @param card pointer to card description
 * @param serial where to store data retrieved
 * @return SC_SUCCESS if ok; else error code
 */
private int acos5_64_get_serialnr(sc_card* card, sc_serial_number* serial) {
	if (card == null || card.ctx == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_get_serialnr"}, q{"called"}));
	int rv;
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_serialnr",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_serialnr",
				"returning with: %d  (Serial Number is cached)\n", rv);
	}

	if (card.type != SC_CARD_TYPE_ACOS5_64)
		return rv=SC_ERROR_INS_NOT_SUPPORTED;

	/* if serial number is cached, use it */
	with (card.serialnr)
	if (serial && value.ptr && len==6) {
		serial.len           = len;
		serial.value[0..len] = value[0..len];
		return rv=SC_SUCCESS;
	}

	/* not cached, retrieve serial number using GET CARD INFO. */
	sc_apdu apdu;
	ubyte[SC_MAX_APDU_BUFFER_SIZE] rbuf;
	/* Case 2 short APDU, 5 bytes: ins=14 p1=00 p2=00 lc=0000 le=0006 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x00, 0x00);
	with (apdu) {
		cla     = 0x80;
		le      = 6;
		resp    = rbuf.ptr;
		resplen = rbuf.sizeof;
	}

	mixin transmit_apdu_strerror!("acos5_64_get_serialnr");  if ((rv=transmit_apdu_strerror_do)<0) return rv;

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen!=6)
		return rv=SC_ERROR_INTERNAL;

	/* cache serial number */
	with (card.serialnr) {
		len           = 6;
		value         = value.init;
		value[0..len] = rbuf[0..len];
		if (serial) {
			serial.len     = len;
			serial.value[] = value[];
		}
	}
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_serialnr",
		"Serial Number of Card (EEPROM): '%s'", sc_dump_hex(card.serialnr.value.ptr, card.serialnr.len));
	return rv=SC_SUCCESS;
}


/* a workaround, opensc doesn't handle ACOS keys > 2048 bit properly, so far */
private int acos5_64_get_response_large(sc_card* card, sc_apdu* apdu, size_t outlen, size_t minlen)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_get_response_large"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
				"returning with: %d\n", rv);
	}

	/* this should _never_ happen */
	if (!card.ops.get_response)
		return rv=SC_ERROR_NOT_SUPPORTED;
//		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "no GET RESPONSE command");

	/* call GET RESPONSE until we have read all data requested or until the card retuns 0x9000,
	 * whatever happens first. */

	/* if there are already data in response append new data to the end of the buffer */
	ubyte* buf = apdu.resp + apdu.resplen;

	/* read as much data as fits in apdu.resp (i.e. min(apdu.resplen, amount of data available)). */
	size_t buflen = outlen - apdu.resplen;

	/* 0x6100 means at least 256 more bytes to read */
	size_t le = apdu.sw2 != 0 ? apdu.sw2 : 256;
	/* we try to read at least as much as bytes as promised in the response bytes */
//  	minlen = crgram_len;

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
		"buflen: %lu\n", buflen);
	do {
		ubyte[256] resp;
		size_t     resp_len = le;

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"le: %lu\n", le);
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"minlen: %lu\n", minlen);
		/* call GET RESPONSE to get more date from the card;
		 * note: GET RESPONSE returns the left amount of data (== SW2) */
		resp = resp.init;//memset(resp, 0, resp.length);
		rv = card.ops.get_response(card, &resp_len, resp.ptr);
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"result from card.ops.get_response(card, &resp_len, resp): %d\n", rv);
		if (rv < 0)   {
version(ENABLE_SM)
{
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
				"Here I am");
			if (resp_len)   {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
					"SM response data %s", sc_dump_hex(resp.ptr, resp_len));
				sc_sm_update_apdu_response(card, resp.ptr, resp_len, rv, apdu);
			}
}
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
				"GET RESPONSE error");
			return rv;
		}

		le = resp_len;
		/* copy as much as will fit in requested buffer */
		if (buflen < le)
			le = buflen;

		memcpy(buf, resp.ptr, le);
		buf    += le;
		buflen -= le;
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"buflen: %lu\n", buflen);

		/* we have all the data the caller requested even if the card has more data */
		if (buflen == 0)
			break;

		minlen = (minlen>le ? minlen - le :  0);
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"minlen: %lu\n", minlen);
		if (rv != 0)
			le = minlen = rv;
		else
			/* if the card has returned 0x9000 but we still expect data ask for more
			 * until we have read enough bytes */
			le = minlen;
	} while (rv != 0 || minlen != 0);
	if (rv < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_response_large",
			"cannot get all data with 'GET RESPONSE'");
		return rv;
	}

	/* we've read all data, let's return 0x9000 */
	apdu.resplen = buf - apdu.resp;
	apdu.sw1 = 0x90;
	apdu.sw2 = 0x00;

	return rv=SC_SUCCESS;
}

version(FAKE_OPENSC_VERSION) // for some reason, this usefull function is not exported from libopensc's version 0.15.0
private int missingExport_match_atr_table(sc_context* ctx, sc_atr_table* table, sc_atr* atr)
{ // c source function 'match_atr_table' copied, translated to D
	ubyte* card_atr_bin;
	size_t card_atr_bin_len;
	char[3 * SC_MAX_ATR_SIZE] card_atr_hex;
	size_t                    card_atr_hex_len;
	uint i = 0;

	if (ctx == null || table == null || atr == null)
		return -1;
	card_atr_bin     = atr.value.ptr;
	card_atr_bin_len = atr.len;
	sc_bin_to_hex(card_atr_bin, card_atr_bin_len, card_atr_hex.ptr, card_atr_hex.sizeof, ':');
	card_atr_hex_len = strlen(card_atr_hex.ptr);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missingExport_match_atr_table", "ATR     : %s", card_atr_hex.ptr);

	for (i = 0; table[i].atr != null; i++) {
		const(char)* tatr = table[i].atr;
		const(char)* matr = table[i].atrmask;
		size_t tatr_len = strlen(tatr);
		ubyte[SC_MAX_ATR_SIZE] mbin, tbin;
		size_t mbin_len, tbin_len, s, matr_len;
		size_t fix_hex_len = card_atr_hex_len;
		size_t fix_bin_len = card_atr_bin_len;

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missingExport_match_atr_table", "ATR try : %s", tatr);

		if (tatr_len != fix_hex_len) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missingExport_match_atr_table", "ignored - wrong length");
			continue;
		}
		if (matr != null) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missingExport_match_atr_table", "ATR mask: %s", matr);

			matr_len = strlen(matr);
			if (tatr_len != matr_len)
				continue;
			tbin_len = tbin.sizeof;
			sc_hex_to_bin(tatr, tbin.ptr, &tbin_len);
			mbin_len = mbin.sizeof;
			sc_hex_to_bin(matr, mbin.ptr, &mbin_len);
			if (mbin_len != fix_bin_len) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missingExport_match_atr_table",
					"length of atr and atr mask do not match - ignored: %s - %s", tatr, matr);
				continue;
			}
			for (s = 0; s < tbin_len; s++) {
				/* reduce tatr with mask */
				tbin[s] = (tbin[s] & mbin[s]);
				/* create copy of card_atr_bin masked) */
				mbin[s] = (card_atr_bin[s] & mbin[s]);
			}
			if (memcmp(tbin.ptr, mbin.ptr, tbin_len) != 0)
				continue;
		}
		else {
			if (!equal(fromStringz(tatr), card_atr_hex[])) //(strncasecmp(tatr, card_atr_hex, tatr_len) != 0)
				continue;
		}
		return i;
	}
	return -1;
}


private int acos5_64_match_card_checks(sc_card *card) { // regular return value: 0==SUCCESS
	int rv = SC_ERROR_INVALID_CARD;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_match_card_checks"}, q{"called"}));
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
				"returning with: %d\n", rv);
	}

	/* call 7.3.1. Get Card Info Identify Self. SW1 SW2 = 95 40h for ACOS5-64 ; make shure we really deal with a ACOS5-64 card */
	/* brand-new ACS ACOS5-64 V3.00 check: send the following sequence of bytes (APDU command as hex) to Your token with a tool like gscriptor (in window "Script") and run:
80140500

Probably the answer is: Received: 95 40, which is expected and okay (though gscriptor believes it is an error)
If the answer is different, You will have to add an "else if" in function acos5_64_check_sw too:
	else if (sw1 == 0x??U && sw2 == 0x??U) // this is a response to "Identify Self" and is okay for Version ACS ACOS5-64 v3.00/no error
		return rv=SC_SUCCESS;
	*/
	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x05, 0x00); 
	apdu.cla = 0x80;

/*
	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
*/
	mixin transmit_apdu_strerror!("acos5_64_match_card_checks");  if ((rv=transmit_apdu_strerror_do) < 0) return rv;
	if ((rv=acos5_64_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"SW1SW2 doesn't match 0x9540: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	/* call 7.3.1. Get Card Info Card OS Version */
	/* brand-new ACS ACOS5-64 V3.00 check: send the following sequence of bytes (APDU command as hex) to Your token with a tool like gscriptor (in window "Script") and run:
8014060008

"41434F5305 02 00 40"
Probably the answer is: Received: 41 43 4F 53 05 02 00 40 90 00, which is expected and okay (though gscriptor believes it is an error)
If the answer is different, You will have to add an "else if" in function acos5_64_check_sw too:
	else if (sw1 == 0x??U && sw2 == 0x??U) // this is a response to "Identify Self" and is okay for Version ACS ACOS5-64 v3.00/no error
		return rv=SC_SUCCESS;
	*/
	immutable(ubyte)[8] vbuf_2 = cast(immutable(ubyte)[8]) x"41434F5305 02 00 40"; // "ACOS 0x05 ...", major vers.=2,   minor=0,   0x40 kBytes user EEPROM capacity
	immutable(ubyte)[8] vbuf_3 = cast(immutable(ubyte)[8]) x"41434F5305 03 00 40"; // "ACOS 0x05 ...", major vers.=3,   minor=0,   0x40 kBytes user EEPROM capacity
	immutable(ubyte)[8] vbuf_M = cast(immutable(ubyte)[8]) x"41434F5305 FF FF 40"; // "ACOS 0x05 ...", major vers.=any, minor=any, 0x40 kBytes user EEPROM capacity
	ub8 rbuf;
//	apdu = apdu.init; // apdu = sc_apdu.init;
	sc_apdu sc_apdu_init;
	apdu = sc_apdu_init;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x14, 0x06, 0x00);
	with (apdu) {
		cla          = 0x80;
		le = resplen = rbuf.sizeof;
		resp         = rbuf.ptr;
	}

	if ((rv=transmit_apdu_strerror_do) < 0) return rv;
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return rv=SC_ERROR_INTERNAL;
	// equality of vbuf_2 and rbuf ==> 0==SC_SUCCESS, 	inequality==> 1*SC_ERROR_NO_CARD_SUPPORT
	if ((rv=SC_ERROR_INVALID_CARD*(!(equal(rbuf[0..5], vbuf_2[0..5]) && rbuf[7] == vbuf_2[7]))) < 0) { // equal(rbuf[], vbuf_2[])
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"Card OS Version doesn't match: major(%d), minor(%d), EEPROM user capacity in kilobytes (0x%02X)\n", rbuf[5], rbuf[6], rbuf[7]);
		return rv;
	}
	card.version_.hw_major = rbuf[5];
	card.version_.hw_minor = rbuf[6];

	return rv;
}

/** checked against card-acos5_64.c  OPENSC_loc
 * Check if provided card can be handled.
 *
 * Called in sc_connect_card().  Must return 1, if the current
 * card can be handled with this driver, or 0 otherwise.  ATR field
 * of the sc_card struct is filled in before calling this function.
 *
 * do not declare static, if pkcs15-acos5_64 module should be necessary
 *
 * @param card Pointer to card structure
 * @returns 1 on card matched, 0 if no match (or error)
 *
 * Returning 'no match' still doesn't stop opensc-pkcs11 using this driver, when forced to use acos5_64
 * Thus for case "card not matched", another 'killer argument': set card.type to impossible one and rule out in acos5_64_init
 */
private extern(C) int acos5_64_match_card(sc_card *card) { // irregular/special return value: 0==FAILURE
	int rv;
	sc_context* ctx = card.ctx;
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card",
		"try to match card with ATR %s", sc_dump_hex(card.atr.value.ptr, card.atr.len));
	scope(exit) {
		if (rv == 0) { // FAILURE, then stall acos5_64_init !!! (a FAILURE in 'match_card' is skipped e.g. when force_card_driver is active, but a FAILURE in 'init' is adhered to)
			card.type = -1;
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card",
				"card not matched");
		}
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card",
				"card matched (%s)", acos5_64_atrs[0].name);
	}

version(FAKE_OPENSC_VERSION) // for some reason, this usefull function is not exported from libopensc's version 0.15.0
	int missingExport_sc_match_atr(sc_card* card, sc_atr_table* table, int* type_out)
	{ // c source _sc_match_atr copied, translated to D
		int res;

		if (card == null)
			return -1;
		res = missingExport_match_atr_table(card.ctx, table, &card.atr);
		if (res < 0)
			return res;
		if (type_out != null)
			*type_out = table[res].type;
		return res;
	}

version(FAKE_OPENSC_VERSION) {
	if ((rv=missingExport_sc_match_atr(card, acos5_64_atrs.ptr, &card.type)) < 0)
		return rv=0;
}
else {
	if ((rv=             _sc_match_atr(card, acos5_64_atrs.ptr, &card.type)) < 0)
		return rv=0;
}

	return rv=!cast(bool)acos5_64_match_card_checks(card);
}

// TODO write content of card to file at begin and end of this function
private extern(C) int acos5_64_init(sc_card *card) {
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_init"}, q{"called"}));
	int rv = SC_ERROR_INVALID_CARD; // SC_ERROR_NO_CARD_SUPPORT
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"returning with: %d\n", rv);
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_init(sc_card *card) is returnung with no argument *card:\n");
//			writer.formattedWrite("%s", *card);
		}
	}
	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_init(sc_card *card) was called\n");
//		writer.formattedWrite("%s", *card);
	}

	int ii;
	for (ii=0; acos5_64_atrs[ii].atr; ++ii) {
		if (card.type  == acos5_64_atrs[ii].type) {
			card.name   = acos5_64_atrs[ii].name; // the only card settings within this function, that aren't done in/called from the section: 'with(card)...'
			card.flags  = acos5_64_atrs[ii].flags;
			break;
		}
	}
	// if no card.type match in previous for loop, ii is at list end marker all zero
	if (!acos5_64_atrs[ii].atr) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "about to stall this driver (some matching problem)\n");
		return rv=SC_ERROR_INVALID_CARD;
	}
	acos5_64_private_data* private_data;

version(none) // FIXME activate this again for Posix, investigate for Windows, when debugging is done
{
version(Posix)
{
	import core.sys.posix.sys.resource : RLIMIT_CORE, rlimit, setrlimit;
	rlimit core_limits; // = rlimit(0, 0);
	if ((rv=setrlimit(RLIMIT_CORE, &core_limits)) != 0) { // inhibit core dumps, https://download.libsodium.org/doc/helpers/memory_management.html
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "Setting rlimit failed !\n");
		return rv;
	}
}
}

	private_data = cast(acos5_64_private_data*) malloc(acos5_64_private_data.sizeof);
	if (private_data == null)
		return rv=SC_ERROR_MEMORY_FAILURE;

version(USE_SODIUM)
{
	synchronized { // check for need to synchronize sinceversion 1.0.11
		if (sodium_init == -1) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "sodium_init() returned indicating a failure)\n");
			return rv=SC_ERROR_CARD_CMD_FAILED;
		}
	}
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
		"This module initialized libsodium version: %s\n", sodium_version_string);
////	private_data = cast(acos5_64_private_data*) sodium_malloc(acos5_64_private_data.sizeof);
////	if (private_data == null)
////		return rv=SC_ERROR_MEMORY_FAILURE;
////	if ((rv=sodium_mlock(private_data, acos5_64_private_data.sizeof)) < 0) // inhibit swapping sensitive data to disk
////		return rv;
////	if ((rv=sodium_mprotect_noaccess(private_data)) <0)                    // inhibit access to private_data other than controled one by this library
////		return rv;
/+
////version(ENABLE_SM)  randombytes_buf(card.sm_ctx.info.session.cwa.host_challenge.ptr, SM_SMALL_CHALLENGE_LEN);
/*		
		immutable(ubyte)* message = cast(immutable(ubyte)*) "test".ptr;
		const message_len = 4;

		ubyte[crypto_hash_sha256_BYTES] result;

		crypto_hash_sha256(result.ptr, message, message_len);
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
			"SHA-256-hash: %s\n", sc_dump_hex(result.ptr, crypto_hash_sha256_BYTES));
*/			
+/
} // version(USE_SODIUM)

// RSA algRef: Decrypt=13, GenKeyPair=10; Sign/Verify with PKCS#1 Padding=10; Sign/Verify with ISO 9796-2 scheme 1 Padding=11; Encrypt=12
	c_ulong algoflags =   SC_ALGORITHM_ONBOARD_KEY_GEN   // 0x8000_0000
// the next's group flags may be set by the framework as well if SC_ALGORITHM_NEED_USAGE is defined (pkcs15-sec.c:sc_pkcs15_compute_signature)
						| SC_ALGORITHM_RSA_RAW           // 0x0000_0001  /* RSA raw support */
/* If the card is willing to produce a cryptogram (i.e. compute_signature) padded with the following
 * SC_ALGORITHM_RSA_HASH_* methods, set these flags accordingly.
ACOS5_64 can do for SHA-1 and SHA-256 only (look at comment for acos5_54_compute_signature !!): both PAD_PKCS1 and PAD_ISO9796
SC_ALGORITHM_RSA_PAD_ISO9796: Leave out this, it's not used in the opensc framework.
SC_ALGORITHM_RSA_PAD_PKCS1:   Setting the flag assumably entails, that the in_len for acos5_54_compute_signature will be shorter than the keyModulusLength.
This results in 2 problems:
1. Retrieving the keyModulusLength to apply in compute_signature, i.e. knowing how many bytes to ask for in get_response
   (currently, for SC_ALGORITHM_RSA_RAW only) it's identical to in_len.
2. Okay for SHA-1 and SHA-256, but all other hashes must be forwarded to acos5_64_decipher (if possible) and
   sc_pkcs1_add_01_padding must be invoked before performing raw RSA calculation
 */
						| SC_ALGORITHM_RSA_PAD_NONE //   CHANGED, but makes no difference; it means: the card/driver doesn't do the padding, but opensc does it
//						| SC_ALGORITHM_RSA_PAD_PKCS1     // 0x0000_0002  if this is defined, the framework will do sc_pkcs1_strip_02_padding() on deciphered message; entfernt, weil der Test encrypt_decrypt erwartet, dass das padding nach Entschlüsselung entfernt wird
//						| SC_ALGORITHM_RSA_PAD_ISO9796   // 0x0000_0008  ggf. nur für card-interne Nutzung; das opensc-framework nutzt SC_ALGORITHM_RSA_PAD_ISO9796 nicht!
/* If the card is willing to produce a cryptogram with the following
 * hash values, set these flags accordingly. 
Check if the setting of SC_ALGORITHM_RSA_HASH_NONE is correct: acos5_54_compute_signature always expects a hash input, except ACOS5_64 memory already knows a hash from a preceding hash calculation on token
 */
//						| SC_ALGORITHM_RSA_HASH_NONE     // 0x0000_0010  CHANGED  what exactly is the meaning?
						| SC_ALGORITHM_RSA_HASH_SHA1     // sign: the driver will not use RSA raw  0x0000_0020
						| SC_ALGORITHM_RSA_HASH_SHA256   // sign: the driver will not use RSA raw  0x0000_0200

//						| SC_ALGORITHM_RSA_HASH_SHA384   // sign: the driver MUST use RSA raw, if allowed by the key, otherwise failure
//						| SC_ALGORITHM_RSA_HASH_SHA512   // sign: the driver MUST use RSA raw, if allowed by the key
//						| SC_ALGORITHM_RSA_HASH_SHA224   // sign: the driver MUST use RSA raw, if allowed by the key

//						| SC_ALGORITHM_NEED_USAGE        // 0x4000_0000
                     ;                       // 0x8000_0231

	with (*card) {
	  // SC_CARD_CAP_USE_FCI_AC : There is only 1 usage in sc_pkcs15init_authenticate pkcs15init/pkcs15-lib.c:3492
		caps   = SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC; // SC_CARD_CAP_ONLY_RAW_HASH.... only used for card-cardos.c in cardos_compute_signature and for fixing "cardos": fix_starcos_pkcs15_card()
/* SC_CARD_CAP_ONLY_RAW_HASH_STRIPPED when: cards, which always add SHA1 prefix itself */
/* SC_CARD_CAP_ONLY_RAW_HASH          when: cards working with all types of hashes and no addition of prefix */
		cla           = 0x00;  // int      default APDU class (interindustry)
		max_send_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; //0x0FF; // size_t,  Max Lc supported by the card
		max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE; //0x100; // size_t,  Max Le supported by the card, decipher (in chaining mode) with a 4096-bit key returns 2 chunks of 256 bytes each !!

version(FAKE_OPENSC_VERSION)
		int missingExport_sc_card_add_rsa_alg(sc_card* card, uint key_length, c_ulong flags, c_ulong exponent)
		{ // same as in opensc, but combined with _sc_card_add_algorithm; both are not exported by libopensc
			sc_algorithm_info info;
//		memset(&info, 0, info.sizeof);
			info.algorithm = SC_ALGORITHM_RSA;
			info.key_length = key_length;
			info.flags = cast(uint)flags;
			info.u._rsa.exponent = exponent;
			sc_algorithm_info* p = cast(sc_algorithm_info*) realloc(card.algorithms, (card.algorithm_count + 1) * info.sizeof);
			if (!p) {
				if (card.algorithms)
					free(card.algorithms);
				card.algorithms = null;
				card.algorithm_count = 0;
				return SC_ERROR_OUT_OF_MEMORY;
			}
			card.algorithms = p;
			p += card.algorithm_count;
			card.algorithm_count++;
			*p = info;
			return SC_SUCCESS;
		}

		for (uint key_len = 0x0200; key_len <= 0x1000; key_len += 0x0100) {
version(FAKE_OPENSC_VERSION)
			 missingExport_sc_card_add_rsa_alg(card, key_len, algoflags, 0x10001);
else
										_sc_card_add_rsa_alg(card, key_len, algoflags, 0x10001);
		}
		drv_data = private_data; // void*, null if NOT version=USE_SODIUM, garbage collector (GC) not involved
		max_pin_len = 8; // int
		with (cache) { // sc_card_cache
		  // on reset, MF is automatically selected
			current_df = sc_file_new;
			if (current_df == null)
				return rv=SC_ERROR_MEMORY_FAILURE;

			current_df.path = MF_path; // TODO do more than .path, e.g. ubyte* sec_attr, sc_acl_entry[SC_MAX_AC_OPS]* acl  etc.
			valid = 1; // int
		} // with (cache)
		if ((rv=acos5_64_get_serialnr(card, null)) < 0) { // card.serialnr will be stored/cached
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"Retrieving ICC serial# failed: %d (%s)\n", rv, sc_strerror(rv));
			return rv;
		}
version(RESTRICTED_SN_TOKEN)
{
/+
	// D0AE406881C7  441
		immutable(sc_serial_number) my_token_01_serial_number = sc_serial_number(
			[0xC0, 0xC6, 0x40, 0x68, 0x81, 0xC7, 0x00, 0x00, // ubyte[32] value, here the first 6 bytes only are relevant for CryptoMate64, other zero
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
			6, // len
			sc_iin( // iin
				0, // ubyte mii;          /* industry identifier */
				0, // uint country;       /* country identifier */
				0) // c_ulong issuer_id;  /* issuer identifier */
		);
		// card.serialnr.value[] is the result of get_serialnr applied to the token plugged in; at this point in code it is known already
		rv = !equal(card.serialnr.value[], my_token_01_serial_number.value[]);
		if ((rv=-rv*SC_ERROR_NO_CARD_SUPPORT) < 0) {
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"Token/card differs from 'my_token_01_serial_number': %d (%s)\n", rv, sc_strerror(rv));
			return rv;
		}
+/
}

		with (version_) { // sc_version
			fw_major = hw_major; // ubyte
			fw_minor = hw_minor; // ubyte
		}
version(ENABLE_SM)
{
		with (sm_ctx) { // sm_context
		} // with (sm_ctx)
} // version(ENABLE_SM)
	} // with (*card)


version(ENABLE_ACOS5_64_UI) {
	/* read environment from configuration file */
	if ((rv=acos5_64_get_environment(card, &(get_acos5_64_ui_ctx(card)))) != SC_SUCCESS) { // get_acos5_64_ui_ctx(card) is not an lvalue
		free(card.drv_data);
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "Failure reading DNIe environment.");
		return rv;
	}
}

	return rv=SC_SUCCESS;
} // acos5_64_init

/**
 * De-initialization routine.
 *
 * Called when the card object is being freed.  finish() has to
 * deallocate all possible private data.
 *
 * @param card Pointer to card driver data structure
 * @return SC_SUCCESS if ok; else error code
 */
private extern(C) int acos5_64_finish(sc_card *card) {
//  import core.thread;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_finish"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_finish",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_finish",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_finish(sc_card *card) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
////		rt_term();
	}

////version(USE_SODIUM)
////{
////	rv = sodium_mprotect_readwrite(card.drv_data);
/*
	acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
	acos5_64_se_info*      se_info      = private_data.se_info;
	acos5_64_se_info*      next;

	while (se_info)   {
		if (se_info.df)
			sc_file_free(se_info.df);
		next = se_info.next;
		free(se_info);
		se_info = next;
	}
*/
////	sodium_munlock(card.drv_data, acos5_64_private_data.sizeof);
////	sodium_free(card.drv_data);
	free(card.drv_data);
	card.drv_data = null;
////}
	return rv = SC_SUCCESS;
}

private extern(C) int acos5_64_read_binary(sc_card* card, uint idxORrec_nr, ubyte* buf, size_t count, c_ulong flags)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_read_binary"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_binary",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_binary",
				"returning with: %d\n", rv);
	}
	
	return rv=iso_ops_ptr.read_binary(card, idxORrec_nr, buf, count, flags);
}


private extern(C) int acos5_64_erase_binary(sc_card *card, uint idx, size_t count, c_ulong flags)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(q{"acos5_64_erase_binary"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_erase_binary",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_erase_binary",
				"returning with: %d\n", rv);
	}
	return rv;
}

/**
opensc-tool doesn't communicate the length of data to be read, only the length of accepting buffer is specified (ubyte[256] buf is sufficient, as cos MRL is 255)
1 trial and error is sufficient, asking for 0xFF bytes: In the likely case of wrong length, cos will respond with 6C XXh where XXh is the maximum bytes
available in the record and opensc automatically issues the corrected APDU once more
*/
private extern(C) int acos5_64_read_record(sc_card* card, uint rec_nr,
	ubyte* buf, size_t buf_len, c_ulong flags) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_read_record"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_record",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_record",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_read_record(sc_card* card, uint rec_nr, ubyte* buf, size_t buf_len, c_ulong flags) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_record",
		"called with rec_nr(%u), buf_len(%lu), flags(%lu)\n", rec_nr, buf_len, flags);

//	return rv=iso_ops_ptr.read_record(card, rec_nr, buf, buf_len, flags);
	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xB2, 1+rec_nr, 0x04); // opensc/cos indexing differ by 1

//	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3; // SC_RECORD_EF_ID_MASK = 0x000_1FUL
//	if (flags & SC_RECORD_BY_REC_NR)               // SC_RECORD_BY_REC_NR  = 0x001_00UL,
//		apdu.p2 |= 0x04;
	with (apdu) {
		le = 0xFF;
		resplen = buf_len;
		resp = buf;
	}
	mixin transmit_apdu!("acos5_64_read_record");  if ((rv=transmit_apdu_do) < 0) return rv;

	if (apdu.resplen == 0)
		return rv=sc_check_sw(card, apdu.sw1, apdu.sw2);

	return rv=cast(int)apdu.resplen;
}

private int acos5_64_select_file_by_path(sc_card* card, const(sc_path) *in_path, sc_file **file_out)
{
/*
ACOS Select File has (possible several) side effect(s) (thus it may be necessary to issue the command and not drop it, even if not straight reasonable,  like:
It clears the accumulated CRTs in the internal system memory.
Access rights achieved will be invalidated, when a new DF is selected (same as Logout(Pin) AND? De-authenticate(Symkey))

After the card powers up or resets, the MF is selected by default.
There are some reserved File IDs, that are not createble/selectable

If it is called with an address file_out!=null, opensc may want file's acl
TODO consolidate this
ACOS's Search Sequence for Target File ID is: current DF -> current DF's children -> current DF's parent ->
current DF's siblings -> MF -> MF's children.
This can be used, if it's reliably known where we are actually before selecting the new path.
Otherwise, take the path as is, and decompose it.
While looping (if necessary), no interest in analyzing FCI, except when we get to the target.
We can't assume, that in_path always starts with 3F00 */
	size_t          in_len = in_path.len;
	const(ubyte) *  in_pos = in_path.value.ptr;
	ubyte*          p = null;
	ubyte[]         p_arr;
	int  /*result = -1,*/ in_path_complete = 1, diff = 2;
//	sc_path path;
	sc_path path_substitute;
	sc_path* p_path = cast(sc_path*)in_path;  /*pointing to in_path or path_substitute*/

	uint file_type = SC_FILE_TYPE_WORKING_EF;

	sc_context* ctx = card.ctx;
//	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path", "called\n");
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_select_file_by_path"}, q{"called"}));
	scope(exit) {
		if (rv <= 0) {
			if (rv == 0 && file_out && *file_out == null /* are there any cases where *file_out != null ? */) {
				*file_out = sc_file_new();
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
					"sc_file_new() was called\n");
			}
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		}
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
				"returning with: %d\n", rv);
	}

	/* Check parameters. */
	with (*in_path) {
		if (len % 2 != 0 || len < 2) {
			return rv=SC_ERROR_INVALID_ARGUMENTS;
		}
		if (type==SC_PATH_TYPE_FROM_CURRENT || type==SC_PATH_TYPE_PARENT)
			return rv=SC_ERROR_UNKNOWN;
	}

	if (!sc_compare_path_prefix(&MF_path, in_path)) /*incomplete path given for in_path */
		in_path_complete = 0;
	with (*in_path) with (card.cache)  sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
		"starting with card->cache.current_df->path=%s, card->cache.valid=%d, searching: path->len=%lu, path->index=%d, path->count=%d, path->type=%d, file_out=%p",
			sc_print_path(&current_df.path), valid, len, index, count, type, file_out);
	if (card.cache.valid) {
		if (!in_path_complete) {
			p_arr = find(card.cache.current_df.path.value[], take(in_path.value[], 2));
			p = p_arr.empty? null : p_arr.ptr;
//			with (card.cache)  p = cast(ubyte*)memmem(current_df.path.value.ptr, current_df.path.len, in_path.value.ptr, 2);
			if (p && ((p-card.cache.current_df.path.value.ptr) % 2 == 0)) {
				sc_path path_prefix;
				memset(&path_prefix, 0, sc_path.sizeof);
				path_prefix.len = p-card.cache.current_df.path.value.ptr;
				memcpy(&path_prefix, &card.cache.current_df.path, path_prefix.len);
				sc_concatenate_path(&path_substitute, &path_prefix, in_path);
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
					"starting with path_substitute=%s (memmem)\n", sc_print_path(&path_substitute));
				p_path = &path_substitute;
				in_len = path_substitute.len;
				in_pos = path_substitute.value.ptr;
			}
			/*if card->cache.current_df->path==MF_path and card->cache.valid and in_path->len ==2*/
			else if (sc_compare_path(&card.cache.current_df.path, &MF_path) /*&& in_path->len == 2*/) {
				sc_concatenate_path(&path_substitute, &MF_path, in_path);
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
					"starting with path_substitute=%s (MFprefix)\n", sc_print_path(&path_substitute));
				p_path = &path_substitute;
				in_len = path_substitute.len;
				in_pos = path_substitute.value.ptr;
			}
		}

		with (card.cache) {
		/* Don't need to select if it's other than MF_path ? */
			if (sc_compare_path(&current_df.path, p_path) &&
				!sc_compare_path(&current_df.path, &MF_path)) { /*check current DF*/
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
					"Don't need to select! ending with card->cache.current_df->path=%s, card->cache.valid=%d",	sc_print_path(&current_df.path), valid);
				rv=SC_SUCCESS;
				return rv;
			}
			/* shorten the path based on card->cache.current_df->path */
			if (in_len>2) {
//			if (sc_compare_path(&card->cache.current_df->path, p_path)) { /*check current DF*/
//				in_pos += in_len-2;
//				in_len = 2;
//			}
				if (sc_compare_path_prefix(&current_df.path, p_path)) { /* check current DF's children*/
					in_len -= current_df.path.len;
					in_pos += current_df.path.len;
				}
				else if (current_df.path.len > 2) { /* check current DF's parent and it's children*/
					sc_path path_parent;
					sc_path_set(&path_parent, /*SC_PATH_TYPE.*/SC_PATH_TYPE_FILE_ID, current_df.path.value.ptr, current_df.path.len-2, 0, -1);
					if ( sc_compare_path(&path_parent, p_path) ||
							(sc_compare_path_prefix(&path_parent, p_path) && current_df.path.len==in_len)) {
						in_pos += in_len-2;
						in_len = 2;
					}
				}
				/*check MF's children */
				else if (sc_compare_path_prefix(&MF_path, p_path) && 4==in_len) {
					in_pos += in_len-2;
					in_len = 2;
				}
			}
		} // with (card.cache)
	} // if (card.cache.valid)

	if (cast(ptrdiff_t)in_len<=0 || in_len%2)
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	/* process path components
	   iso_ops_ptr.select_file can do it, iff it get's a special set of arguments */
	sc_path path;
//	path = 0; // redundant dispensable memset(&path, 0, sc_path.sizeof);
	path.type = /*SC_PATH_TYPE.*/SC_PATH_TYPE_FILE_ID;
	path.len = 2;		/* one path component at a time */
	do {
		if (in_len>=4) {
			sc_apdu apdu;
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
			with (apdu) {
				lc = datalen = 2;
				data = /*cast(ubyte*)*/in_pos;
				flags |= SC_APDU_FLAGS_NO_GET_RESP; // prevent get_response and process_fci
			}
			rv = sc_transmit_apdu(card, &apdu) || apdu.sw1 != 0x61;
			/*sc_log(ctx, "rv=%d, apdu.sw1: 0x%02X", rv, apdu.sw1);*/
		}
		else if (in_len==2 || rv) {
			path.value[0..2] = in_pos[0..2]; //memcpy(path.value.ptr, in_pos, 2);
			if (file_out) {
				rv = iso_ops_ptr.select_file(card, &path, file_out);
				if (file_out && *file_out)
					file_type = (**file_out).type;
			}
			else {
				sc_file* file = sc_file_new();
				file.path = path;
			  rv = iso_ops_ptr.select_file(card, &path, &file /*null ?*/);
				file_type = file.type;
				sc_file_free(file);
			}
			diff = (file_type == SC_FILE_TYPE_DF ? 0 : 2);
			/*sc_log(ctx, "file->type detected: %u", file_type);*/
		}
		in_len -= 2;
		in_pos += 2;
	} while (in_len && rv == SC_SUCCESS);

	/* adapt card->cache.current_df->path */
	if (rv==SC_SUCCESS) with (card.cache) {
		memset(&current_df.path, 0, sc_path.sizeof);
		if (in_path_complete) {
			current_df.path.len = (in_path.len      == 2 ? 2 : in_path.len-diff);
			memcpy(current_df.path.value.ptr, in_path.value.ptr, current_df.path.len);
			valid = 1;
		}
		else if (p_path != in_path) { /* we have path_substitute */
			current_df.path.len = (path_substitute.len == 2 ? 2 : path_substitute.len-diff);
			memcpy(current_df.path.value.ptr, path_substitute.value.ptr, current_df.path.len);
			valid = 1;
		}
		else
			valid = 0;
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
			"ending with card->cache.current_df->path=%s, card->cache.valid=%d",	sc_print_path(&current_df.path), valid);
	}
	else with (card.cache) { // sc_card_cache
		current_df.path = MF_path;
		valid = 1; // int
	}

	return rv;
}


private extern(C) int acos5_64_select_file(sc_card* card, const(sc_path)* path, sc_file** file_out)
{
/* acos can handle path->type SC_PATH_TYPE_FILE_ID (P1=0) and SC_PATH_TYPE_DF_NAME (P1=4) only.
Other values for P1 are not supported.
We have to take care for SC_PATH_TYPE_PATH and (maybe those are used too)
SC_PATH_TYPE_FROM_CURRENT as well as SC_PATH_TYPE_PARENT */
/* FIXME if path is SC_PATH_TYPE_DF_NAME, card->cache.current_df->path is not adapted */
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_INS_NOT_SUPPORTED;
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file",
		"called with path->type: %d\n", path.type);
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file",
				"returning with: %d\n", rv);
	}

	final switch (cast(SC_PATH_TYPE)path.type) {
		case SC_PATH_TYPE_FILE_ID:
			goto case SC_PATH_TYPE_PATH;
		case SC_PATH_TYPE_DF_NAME:
			rv = iso_ops_ptr.select_file(card, path, file_out);
			if (file_out && *file_out && (**file_out).path.len > 0) {
				/* TODO test this */
				card.cache.current_df.path = (**file_out).path;
				card.cache.valid = 1; /* maybe not starting with 3F00 */
			}
			else
				card.cache.valid = 0;
			return rv;
		case SC_PATH_TYPE_PATH:
			return rv=acos5_64_select_file_by_path(card, path, file_out);
		case SC_PATH_TYPE_PATH_PROT:
			return rv;
		case SC_PATH_TYPE_FROM_CURRENT, SC_PATH_TYPE_PARENT:
			goto case SC_PATH_TYPE_PATH;
	}
}


/**
 *  The iso7816.c -version get_challenge get's wrapped to have RNDc known by terminal/host in sync with card's last SM_SMALL_CHALLENGE_LEN challenge handed out
 *  len is restricted to be a multiple of 8 AND 8<=len
 */
private extern(C) int acos5_64_get_challenge(sc_card *card, ubyte * rnd, size_t len)
{
	int rv = SC_ERROR_UNKNOWN;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_get_challenge"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
				"returning with: %d\n", rv);
		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_get_challenge(sc_card *card, ubyte * rnd, size_t len) is returnung with argument *card:\n");
//			writer.formattedWrite("%s", *card);
		}
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
		"len: %lu\n", len);
	if (len==0)
		return rv=SC_SUCCESS;
	if (len<SM_SMALL_CHALLENGE_LEN /*|| (len%SM_SMALL_CHALLENGE_LEN)*/) {
		rv = -1;
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
			"called with inappropriate len arument: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if ((rv=iso_ops_ptr.get_challenge(card, rnd, len)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
			"iso_ops_ptr.get_challenge failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	
version(ENABLE_SM)
{
	card.sm_ctx.info.session.cwa.card_challenge = rnd[(len-SM_SMALL_CHALLENGE_LEN) .. len]; // SM_SMALL_CHALLENGE_LEN);
	card.sm_ctx.info.session.cwa.ssc            = rnd[(len-SM_SMALL_CHALLENGE_LEN) .. len]; // SM_SMALL_CHALLENGE_LEN);
}

	return rv;
}

private extern(C) int acos5_64_logout(sc_card *card)
{
/* ref. manual:  7.2.2. Logout
Logout command is used to de-authenticate the user's global or local PIN access condition status.
The user controls PIN rights without resetting the card and interrupting the flow of events.
[The same may be achieved simply be selecting a different DF(/MF)]
7.2.7.
 De-authenticate
This command allows ACOS5-64 to de-authenticate the authenticated key without resetting the card.

TODO Check if 'Logout' does all we want or if/when we need 'De-authenticate' too
 */
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_logout"}, q{"called"})); //
	int rv;
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_logout",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_logout",
			"returning with: %d\n", rv);
	}

	sc_apdu apdu; //                           CLAINSP1 P2
	bytes2apdu(ctx, cast(immutable(ubyte)[4])x"80 2E 00 81", apdu);
//	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x81);
//	apdu.cla = 0x80;

	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_logout",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	
	return rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
}

private extern(C) int acos5_64_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num)
{
/*
if env.operation==SC_SEC_OPERATION_SIGN then
we will prepare a CT template as well, as it may be necessary to switch from SC_SEC_OPERATION_SIGN to SC_SEC_OPERATION_DECIPHER for SHA-512 (acos5_64_compute_signature can't cope with SHA-512 itself, but has to delegate)
*/
	assert(card != null && env != null);

	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_set_security_env"}, q{"called"})); //
	scope(exit) {
		(cast(acos5_64_private_data*) card.drv_data).security_env = *env;
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num) is returning with argument *env:\n");
			writer.formattedWrite("%s", *env);
		}
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"returning with: %d\n", rv);
	}
/* */
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
		"env.operation: %d\n", env.operation);
//	sc_log(card.ctx, "env.algorithm: %lu\n", env.algorithm); // 0
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
		"env.algorithm_flags: 0x%02X\n", env.algorithm_flags);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
		"env.file_ref.value: %s\n", sc_dump_hex(env.file_ref.value.ptr, env.file_ref.len));

/* */
	sc_apdu apdu;
	ubyte[SC_MAX_APDU_BUFFER_SIZE] sbuf;
	ubyte* p;
	int locked = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x01, 0);
	p = sbuf.ptr;
	*p++ = 0x95;
	*p++ = 0x01;
	*p++ = (env.operation==6 ? 0x80 : 0x40); /* 0x80: public key usage; 0x40 : priv. key usage */

	if (env.flags & SC_SEC_ENV_FILE_REF_PRESENT) {
		*p++ = 0x81;
		*p++ = cast(ubyte)env.file_ref.len;
		assert(sbuf.length - (p - sbuf.ptr) >= env.file_ref.len);
		memcpy(p, env.file_ref.value.ptr, env.file_ref.len);
		p += env.file_ref.len;
	}

	*p++ = 0x80; /* algorithm reference */
	*p++ = 0x01;
	
//	sc_apdu apdu2;
	switch (env.operation) {
	case SC_SEC_OPERATION_DECIPHER:
		*p++ = 0x13;
		apdu.p2 = 0xB8;
		break;
	case SC_SEC_OPERATION_SIGN:
		*p++ = 0x10;
		apdu.p2 = 0xB6;
		break;
	case 5: // my encoding for SC_SEC_GENERATE_RSAKEYS_PRIVATE
		goto case SC_SEC_OPERATION_SIGN;
	case 6: // my encoding for SC_SEC_GENERATE_RSAKEYS_PUBLIC
		goto case SC_SEC_OPERATION_SIGN;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

/*
	if (env.flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	 algorithm reference
		*p++ = 0x01;
		*p++ = env.algorithm_ref & 0xFF;
	}
*/
/* page 47
	if (env.flags & SC_SEC_ENV_KEY_REF_PRESENT) {
		if (env.flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
		else
			*p++ = 0x84;
		*p++ = env.key_ref_len;
		assert(sizeof(sbuf) - (p - sbuf) >= env.key_ref_len);
		memcpy(p, env.key_ref, env.key_ref_len);
		p += env.key_ref_len;
	}
*/
	rv = cast(int)(p - sbuf.ptr);
	apdu.lc = rv;
	apdu.datalen = rv;
	apdu.data = sbuf.ptr;
	if (se_num > 0) {
//	  rv = ; sc_unlock(card);

		if ((rv=sc_lock(card)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"sc_lock() failed");
			return rv;		
		}
		locked = 1;
	}
	if (apdu.datalen != 0) {
		rv = sc_transmit_apdu(card, &apdu);
		if (rv) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"%s: APDU transmit failed", sc_strerror(rv));
			goto err;
		}
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (rv) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"%s: Card returned error", sc_strerror(rv));
			goto err;
		}
		if (env.operation==SC_SEC_OPERATION_SIGN) {
			ubyte[SC_MAX_APDU_BUFFER_SIZE] sbuf2;
			sc_apdu apdu2 = apdu;
			ulong apduLenM1 = apdu2.lc-1;
			sbuf2[0..apduLenM1] = sbuf[0..apduLenM1];
			sbuf2[apduLenM1] = 0x13;
			apdu2.p2 = 0xB8;
			apdu2.data = sbuf2.ptr;

			rv = sc_transmit_apdu(card, &apdu2);
			if (rv) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
					"%s: APDU transmit failed", sc_strerror(rv));
				goto err;
			}
			rv = sc_check_sw(card, apdu2.sw1, apdu2.sw2);
			if (rv) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
					"%s: Card returned error", sc_strerror(rv));
				goto err;
				}
		}
	}
	if (se_num <= 0)
		return rv=SC_SUCCESS;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xF2, se_num); // Store Security Environment ?
	rv = sc_transmit_apdu(card, &apdu);

	sc_unlock(card);
	if (rv < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
			"APDU transmit failed");
		return rv;
	}

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);
	return rv;
}

/+ + /
int pkcs1_check_01_padding(const(ubyte)* in_dat, size_t in_len,
		ubyte* out_, size_t* out_len)
{ // based on padding.c:sc_pkcs1_strip_01_padding
// no stripping, just checking if padding is conformant to PKCS#1v1.15; block type 01
	const(ubyte)* tmp = in_dat;
	size_t        len;

	if (in_dat == null || in_len < 10 || *tmp != 0x00) // FIXME
		return SC_ERROR_INTERNAL;
	/* skip leading zero byte */
	tmp++;
	in_len--;
	len = in_len;
	if (*tmp != 0x01)
		return SC_ERROR_WRONG_PADDING;
	tmp++;
	len--;
	for (; *tmp == 0xff && len != 0; tmp++, len--)
		;
	if (!len || (in_len - len) < 9 || *tmp++ != 0x00)
		return SC_ERROR_WRONG_PADDING;
	len--;
	if (out == NULL)
		/* just check the padding */
		return SC_SUCCESS;
	if (*out_len < len)
		return SC_ERROR_INTERNAL;
	memmove(out, tmp, len);
	*out_len = len;
	return SC_SUCCESS;
}
/ + +/

version(FAKE_OPENSC_VERSION) {}
else
/** This function doesn't slavishly perform Decipher (RSA public key encrypted) content: Some conditions must be fulfilled:
    Of course, the in_len must match the keyModulus_length.
    Also, the padding must be according to PKCS#1v1.5 for Decryption (BT=01), except it is a delegate call from compute_signature.
    TODO include symKey Decryption?
 */
private extern(C) int acos5_64_decipher(sc_card* card, const(ubyte)* in_, /*in*/ size_t in_len, ubyte* out_, /*in*/ size_t out_len)
{ // check in_len, out_len, they aren't constant any more, but treat them as if they are constant
// For RSA, it's an error, if the in_len is not modulusbits/8 (multiples of 32 bytes), for symetric: multiples of 8 (for DES) or 16 (for AES) 
// how to know, whether symetric or asymetric key involved?
//	Regex!char r = regex("^\x00\x01\xFF{8,}\x00(.*)$");

//Fixme currently it is for RSA only, but must take care of symkey decrypt as well
	assert(card != null && in_ != null && out_ != null);
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_decipher"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
				"returning with: %d\n", rv);
	}
	bool call_to_compute_signature_in_progress = (cast(acos5_64_private_data*) card.drv_data).call_to_compute_signature_in_progress;
/* */
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"in_len:  %llu\n", in_len);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"out_len: %llu\n", out_len);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.algorithms.algorithm: %u\n", card.algorithms.algorithm); // SC_ALGORITHM_RSA = 0
//	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
//		"card.algorithms.key_length: %u\n", card.algorithms.key_length); // 512
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.algorithms.flags: 0x%08X\n", card.algorithms.flags); // 0x80000_23B  

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.algorithms.u._rsa.exponent: %lu\n", card.algorithms.u._rsa.exponent);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.algorithm_count: %d\n", card.algorithm_count);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.caps:  %d\n", card.caps);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.flags: %d\n", card.flags);

//	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
//		"call_to_compute_signature_in_progress: %s\n", call_to_compute_signature_in_progress ? "true".toStringz : "false".toStringz);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"Input to decipher len: '%d' bytes:\n%s\n============================================================",
		in_len, sc_dump_hex(in_, in_len));
/* */
	if (in_len > out_len)
		return rv=SC_ERROR_NOT_SUPPORTED;
	if (in_len > 0x0200) // FIXME stimmt nur für RSA
		return rv=SC_ERROR_NOT_SUPPORTED;
	// TODO check for "the in_len must match the keyModulus_length"

version(ENABLE_ACOS5_64_UI) {
	/* (Requested by DGP): on signature operation, ask user consent */
	if (call_to_compute_signature_in_progress && (rv=acos5_64_ask_user_consent(card, user_consent_title, user_consent_message)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher", "User consent denied\n");
		return rv;
	}
}

	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80, 0x84);
	apdu.flags = SC_APDU_FLAGS_NO_GET_RESP;
	apdu.data  = in_;
	apdu.lc    = apdu.datalen = in_len;
//	apdu.resp    = out_;
//	apdu.resplen = out_len;

	if (in_len > 0xFF)
		apdu.flags  |= SC_APDU_FLAGS_CHAINING;

//	else
//		apdu.le      = in_len; 
	
	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) { // able to apply chaining properly with flag SC_APDU_FLAGS_CHAINING
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
			"APDU transmit failed\n");
//		if (apdu.sw1 == 0x6A && apdu.sw2 == 0x80) {
//			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
//				"This occured probably after redirection and the key isn't capable to decipher. The length of deciphered data will be indicated as 0\n");
//			rv=0;
//		}
		return rv;
	}
		
//	if ((in_len > 0xFF && !(apdu.sw1 == 0x61 && apdu.sw2 == 0x00)) || (in_len <= 0xFF && !(apdu.sw1 == 0x90 && apdu.sw2 == 0x00))) {
	if (!(apdu.sw1 == 0x61 && apdu.sw2 == (in_len>0xFF? 0x00 : in_len & 0x00FF))) {	
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
			"Didn't get clearance to call get_response: sw1: %X, sw2: %X\n", apdu.sw1, apdu.sw2);
		return rv=SC_ERROR_UNKNOWN;
	}

	size_t received;
	ubyte[0x200] parr;
//	if (in_len > 0xFF) {
		size_t count;
		ubyte* p = parr.ptr;
		do { // emulate kind of 'chaining' of get_response; acos doesn't tell properly for keys>2048 bits how much to request, thus we have to fall back to in_len==keyLength
			count = in_len - received; // here count is: 'not_received'
			if ((rv=iso_ops_ptr.get_response(card, &count, p)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
					"rv: %d, count:%lu , \n", rv, count);
				return rv;
			}
			received += count; // now count is what actually got received
			p        += count;
		} while (in_len > received && count>0);
//	}
//	else
//		received = in_len;
	
/* */
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"Output from decipher len: '%d' bytes:\n%s\n============================================================",
	       received, sc_dump_hex(parr.ptr, received));
	if (in_len != received)
		return rv=SC_ERROR_UNKNOWN;

	size_t out_len_new = received;
version(RSA_PKCS_PSS) {
		if (call_to_compute_signature_in_progress)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__,   "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: No checking of padding for PKCS_PPS took place currently (other than last byte = 0xbc)\n"); //
		else {
		  
		}
}
else {
	if      (card.algorithms.flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if ((rv=sc_pkcs1_strip_02_padding(ctx, parr.ptr, received, out_, &out_len_new)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
				"MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_PAD_PKCS1 is defined; padding of cryptogram is wrong (NOT BT=02  or other issue)\n");
			return rv;
		}
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
			"MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_PAD_PKCS1 is defined; the cryptogram was padded correctly (BT=02); padding got stripped\n");
	}
	else if (card.algorithms.flags & SC_ALGORITHM_RSA_RAW) {
		if (call_to_compute_signature_in_progress)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__,   "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: The digestInfo(prefix+hash) was padded correctly for signing (BT=01)\n"); //
		else {
			rv = sc_pkcs1_strip_02_padding(ctx, parr.ptr, received, null, &out_len_new); // this is a check only, out_len_new doesn't get changed
			if (rv==SC_SUCCESS)
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_RAW is defined (NOTHING has to be stripped); the cryptogram was padded correctly (BT=02)\n");
			else {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_RAW is defined (NOTHING has to be stripped); the cryptogram was NOT padded correctly for deciphering (BT=02)\n");
				return rv;
			}
		}
//		if (in_len > 0xFF) memcpy(out_, parr.ptr, out_len_new);
		out_[0..out_len_new] = parr[0..out_len_new];
	}
	else 
		return rv=SC_ERROR_NOT_SUPPORTED;
}
/* */
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"MESSAGE FROM PRIVATE KEY USAGE: Private key was successfully applied for decryption");
	return rv=cast(int)out_len_new;
}

version(RSA_PKCS_PSS) {
/* requires my yet unpublished:
	"dependencies" : {
		"pkcs11": "~>2.20.3"
	},
	"subConfigurations": {
		"pkcs11": "deimos"
	},
*/
import pkcs11.types;

/**
as long as PSS support for RSA-SSA-PKCS is missing in opensc, required parameters are based on PKCS#11 header's structs, constants

mechanism: CKM_RSA_PKCS_PSS is generic, there are more specific ones that include digesting with a denoted digest algorithm
CK_RSA_PKCS_PSS_PARAMS pss_params = e.g. CK_RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32 sLen==hLen);
*/
private extern(C) int pkcs1_add_PSS_padding(const(ubyte)*in_/* data_hashed */, size_t in_len /* data_hashedLen*/,
	ubyte* out_/*EM*/, size_t* out_len/* in: *out_len>=rsa_size_bytes_modulus; out: rsa_size_bytes_modulus==emLen*/,
	size_t	rsa_size_bytes_modulus, size_t	bn_num_bits_modulus, CK_RSA_PKCS_PSS_PARAMS_PTR pss_params) {
	import std.stdio;
	import std.digest.digest;
	import std.digest.sha;
	import deimos.openssl.rand : RAND_bytes;
//	import std.random; // doesn't work so far:   Random rng = rndGen(); salt = cast(ubyte[]) rng.take(sLen).array;

	ubyte[] MGF1(ubyte[] mgfSeed, size_t maskLen, CK_RSA_PKCS_MGF_TYPE hashAlg_mgf1) {
		ubyte[] T = new ubyte[0];
		size_t  hLen_mgf1;
		ubyte[] hash_mgfSeed;

		switch (hashAlg_mgf1) {
			case CKG_MGF1_SHA1:   hLen_mgf1=20; hash_mgfSeed = digest!SHA1  (mgfSeed); break;
			case CKG_MGF1_SHA256: hLen_mgf1=32; hash_mgfSeed = digest!SHA256(mgfSeed); break;
			case CKG_MGF1_SHA384: hLen_mgf1=48; hash_mgfSeed = digest!SHA384(mgfSeed); break;
			case CKG_MGF1_SHA512: hLen_mgf1=64; hash_mgfSeed = digest!SHA512(mgfSeed); break;
			case CKG_MGF1_SHA224: hLen_mgf1=28; hash_mgfSeed = digest!SHA224(mgfSeed); break;
			default:
				return T.dup;
		}

		if (maskLen > 0x1_0000_0000UL*hLen_mgf1)
			return T.dup; // output "mask too long" and stop.

		foreach (i; 0..(maskLen / hLen_mgf1 + (maskLen % hLen_mgf1 != 0)))
			T ~= hash_mgfSeed.dup ~ integralLastFour2ub4(i);

		assert(T.length>=maskLen);
		T.length = maskLen;
		return T.dup;
	} // MGF1

	if (*out_len<rsa_size_bytes_modulus)
		return SC_ERROR_INTERNAL;

	size_t emBits = bn_num_bits_modulus-1; /* (intended) length in bits of an encoded message EM */
	size_t emLen  = emBits/8 + (emBits % 8 != 0);
	ubyte hLen;
	switch (pss_params.hashAlg) {
		case CKM_SHA_1:  hLen=20; break;
		case CKM_SHA256: hLen=32; break;
		case CKM_SHA384: hLen=48; break;
		case CKM_SHA512: hLen=64; break;
		case CKM_SHA224: hLen=28; break;
		default:
			return SC_ERROR_INTERNAL;
	}

	int sLen  = cast(int)pss_params.sLen;

//      3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
	if (emLen < hLen + sLen + 2)
		return SC_ERROR_INTERNAL; // output "encoding error" and stop.
/+
//      2.   Let mHash = Hash(M), an octet string of length hLen.
	ubyte[]  mHash;
	switch (pss_params.hashAlg) {
		case CKM_SHA_1:  mHash = digest!SHA1  (in_[0..in_len]); break;
		case CKM_SHA256: mHash = digest!SHA256(in_[0..in_len]); break;
		case CKM_SHA384: mHash = digest!SHA384(in_[0..in_len]); break;
		case CKM_SHA512: mHash = digest!SHA512(in_[0..in_len]); break;
		case CKM_SHA224: mHash = digest!SHA224(in_[0..in_len]); break;
		default:
			return SC_ERROR_INTERNAL;
	}
	assert(mHash.length==hLen);
+/
//      4.   Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string.
	ubyte[] salt  = new ubyte[sLen];
	if (sLen>0 && RAND_bytes(salt.ptr, sLen) != 1)
		return SC_ERROR_INTERNAL;
//writefln("salt: 0x [ %(%x %) ]", salt);

//      5.   Let  M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;  M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
	ubyte[] M1 = cast(ubyte[])x"00 00 00 00 00 00 00 00" ~ /*mHash*/ in_[0..in_len] ~ salt;
	assert(M1.length == 8+hLen+sLen);

//      6.   Let H = Hash(M'), an octet string of length hLen.
	ubyte[]  H; // H.length == hLen == mHash.length;
	switch (pss_params.hashAlg) {
		case CKM_SHA_1:  H = digest!SHA1  (M1); break;
		case CKM_SHA256: H = digest!SHA256(M1); break;
		case CKM_SHA384: H = digest!SHA384(M1); break;
		case CKM_SHA512: H = digest!SHA512(M1); break;
		case CKM_SHA224: H = digest!SHA224(M1); break;
		default:
			return SC_ERROR_INTERNAL;
	}
	assert(H.length==hLen);

//      7.   Generate an octet string PS consisting of emLen - sLen - hLen - 2
//           zero octets.  The length of PS may be 0.
	ubyte[] PS = new ubyte[emLen - sLen - hLen - 2];
	assert(PS.length==emLen - sLen - hLen - 2);
	assert(!any(PS));

//      8.   Let DB = PS || 0x01 || salt;  DB is an octet string of length emLen - hLen - 1.
	ubyte[] DB = PS ~ ubyte(0x01) ~ salt;
//	writefln("    : generated DB   of Len %s: 0x [ %(%x %) ]", DB.length, DB);
	assert(DB.length==emLen - hLen - 1);
	
//      9.   Let dbMask = MGF(H, emLen - hLen - 1).
	ubyte[] dbMask = MGF1(H, emLen - hLen - 1, pss_params.mgf);
//	writefln("MGF1: generated mask of Len %s: 0x [ %(%x %) ]", dbMask.length, dbMask);
	assert(dbMask.length==DB.length);

//      10.  Let maskedDB = DB \xor dbMask.
	ubyte[] maskedDB = new ubyte[DB.length];
	maskedDB[] = DB[] ^ dbMask[];
//	writefln("    : xor'd maskedDB of Len %s: 0x [ %(%x %) ]", maskedDB.length, maskedDB);
	assert(maskedDB.length==DB.length);

//      11.  Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
	int rem = emBits % 8;
	if (rem)
		maskedDB[0] &=  2^^rem -1;

//      12.  Let EM = maskedDB || H || 0xbc.
	ubyte[] EM = maskedDB ~ H ~ 0xbc;
	assert(EM.length==emLen);

//      13.  Output EM.
	size_t  emLenOffset = rsa_size_bytes_modulus - emLen;
	assert(emLenOffset+EM.length == rsa_size_bytes_modulus);
	if (emLenOffset)
		out_[0..emLenOffset] = 0;
	out_[emLenOffset..emLenOffset+EM.length] = EM[0..EM.length];
	*out_len = rsa_size_bytes_modulus;
	return 0;
}

unittest {
	import std.stdio;
	import deimos.openssl.rsa : RSA;
//	import deimos.openssl.rsa : RSA_padding_add_PKCS1_PSS_mgf1, RSA_size;
//	import deimos.openssl.bn : BN_num_bits;
	immutable(ubyte)[16] Message = cast(immutable(ubyte)[16])x"0f0e0d0c0b0a09080706050403020100";
	ubyte[] EM = new ubyte[128];
	size_t  EMLen = EM.length;
//	RSA* rsa;
	CK_RSA_PKCS_PSS_PARAMS pss_params = CK_RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32);

	assert(pkcs1_add_PSS_padding(Message.ptr, Message.length, EM.ptr, &EMLen, EMLen, 8*EMLen-(1), &pss_params) == 0);

	assert(EMLen == EM.length);
  writefln("EM: 0x [%(%x %)]", EM);
  writeln("PASSED: pkcs1_add_PSS_padding");
}

} // version(RSA_PKCS_PSS)

/*
   DigestInfo ::= SEQUENCE {
     digestAlgorithm DigestAlgorithmIdentifier,
     digest Digest
   }
In the following naming, digestInfoPrefix is everything from the ASN1 representaion of DigestInfo, except the trailing digest bytes
*/
enum : ubyte /*DigestInfo_Algo_RSASSA_PKCS1_v1_5 : ubyte*/ { // contents from RFC 8017 are examples, some not recommended for new apps, some in specific schemes; SHA3 not yet mentioned in RFC 8017 
//id_rsassa_pkcs1_v1_5_with_md2,        // md2WithRSAEncryption, // id_md2, not recommended
//id_rsassa_pkcs1_v1_5_with_md5,        // md5WithRSAEncryption, // id_md5, not recommended
	id_rsassa_pkcs1_v1_5_with_sha1,       // sha1WithRSAEncryption,       // id_sha1, not recommended, backwards compatibility only

	id_rsassa_pkcs1_v1_5_with_sha224,     // sha224WithRSAEncryption,     // id_sha224
	id_rsassa_pkcs1_v1_5_with_sha256,     // sha256WithRSAEncryption,     // id_sha256
	id_rsassa_pkcs1_v1_5_with_sha384,
	id_rsassa_pkcs1_v1_5_with_sha512,
	id_rsassa_pkcs1_v1_5_with_sha512_224,
	id_rsassa_pkcs1_v1_5_with_sha512_256,
//
	id_rsassa_pkcs1_v1_5_with_sha3_224,
	id_rsassa_pkcs1_v1_5_with_sha3_256,
	id_rsassa_pkcs1_v1_5_with_sha3_384,
	id_rsassa_pkcs1_v1_5_with_sha3_512,

//version(D_LP64) {
//id_rsassa_pkcs1_v1_5_with_blake2b160, // https://tools.ietf.org/html/rfc7693
//id_rsassa_pkcs1_v1_5_with_blake2b256,
//id_rsassa_pkcs1_v1_5_with_blake2b384,
//id_rsassa_pkcs1_v1_5_with_blake2b512,
//}
//else {
//id_rsassa_pkcs1_v1_5_with_blake2s128,
//id_rsassa_pkcs1_v1_5_with_blake2s160,
//id_rsassa_pkcs1_v1_5_with_blake2s224,
//id_rsassa_pkcs1_v1_5_with_blake2s256,
//}
}

struct DI_data {
  string             hashAlgorithmOID;
  ubyte              hashAlgorithmName; // it's enum value is the index in DI_table
  ubyte              hashLength;
  ubyte              digestInfoLength;
  bool               allow;
  bool               compute_signature_possible_without_rawRSA;
  immutable(ubyte)[] digestInfoPrefix;
}

immutable(DI_data[]) DI_table = [
//DI_data("1.2.840.113549.2.2",      id_rsassa_pkcs1_v1_5_with_md2,        16, 34, false, false, cast(immutable(ubyte)[]) x"30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10"),
//DI_data("1.2.840.113549.2.5",      id_rsassa_pkcs1_v1_5_with_md5,        16, 34, false, false, cast(immutable(ubyte)[]) x"30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10"),
	DI_data("1.3.14.3.2.26",           id_rsassa_pkcs1_v1_5_with_sha1,       20, 35, true,  true,  cast(immutable(ubyte)[]) x"30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14"),

	DI_data("2.16.840.1.101.3.4.2.4",  id_rsassa_pkcs1_v1_5_with_sha224,     28, 47, true,  false, cast(immutable(ubyte)[]) x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c"),
	DI_data("2.16.840.1.101.3.4.2.1",  id_rsassa_pkcs1_v1_5_with_sha256,     32, 51, true,  true,  cast(immutable(ubyte)[]) x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"),
	DI_data("2.16.840.1.101.3.4.2.2",  id_rsassa_pkcs1_v1_5_with_sha384,     48, 67, true,  false, cast(immutable(ubyte)[]) x"30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30"),
	DI_data("2.16.840.1.101.3.4.2.3",  id_rsassa_pkcs1_v1_5_with_sha512,     64, 83, true,  false, cast(immutable(ubyte)[]) x"30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40"),
	DI_data("2.16.840.1.101.3.4.2.5",  id_rsassa_pkcs1_v1_5_with_sha512_224, 28, 47, true,  false, cast(immutable(ubyte)[]) x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 05 05 00 04 1c"),
	DI_data("2.16.840.1.101.3.4.2.6",  id_rsassa_pkcs1_v1_5_with_sha512_256, 32, 51, true,  false, cast(immutable(ubyte)[]) x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 06 05 00 04 20"),

	DI_data("2.16.840.1.101.3.4.2.7",  id_rsassa_pkcs1_v1_5_with_sha3_224,   28, 47, true,  false, cast(immutable(ubyte)[]) x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 07 05 00 04 1c"),
	DI_data("2.16.840.1.101.3.4.2.8",  id_rsassa_pkcs1_v1_5_with_sha3_256,   32, 51, true,  false, cast(immutable(ubyte)[]) x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 08 05 00 04 20"),
	DI_data("2.16.840.1.101.3.4.2.9",  id_rsassa_pkcs1_v1_5_with_sha3_384,   48, 67, true,  false, cast(immutable(ubyte)[]) x"30 41 30 0d 06 09 60 86 48 01 65 03 04 02 09 05 00 04 30"),
	DI_data("2.16.840.1.101.3.4.2.10", id_rsassa_pkcs1_v1_5_with_sha3_512,   64, 83, true,  false, cast(immutable(ubyte)[]) x"30 51 30 0d 06 09 60 86 48 01 65 03 04 02 0a 05 00 04 40"),

//version(D_LP64) { //Blak2s is not mentioned in PKCS#2.2
//data("1.3.6.1.4.1.1722.12.2.1.5",  id_rsassa_pkcs1_v1_5_with_blake2b160, 20, 41, true,  false, cast(immutable(ubyte)[]) x"30 27 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 05 05 00 04 14"),
//data("1.3.6.1.4.1.1722.12.2.1.8",  id_rsassa_pkcs1_v1_5_with_blake2b256, 32, 53, true,  false, cast(immutable(ubyte)[]) x"30 33 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 08 05 00 04 20"),
//data("1.3.6.1.4.1.1722.12.2.1.12", id_rsassa_pkcs1_v1_5_with_blake2b384, 48, 69, true,  false, cast(immutable(ubyte)[]) x"30 43 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 0c 05 00 04 30"),
//data("1.3.6.1.4.1.1722.12.2.1.16", id_rsassa_pkcs1_v1_5_with_blake2b512, 64, 85, true,  false, cast(immutable(ubyte)[]) x"30 53 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 10 05 00 04 40"),
//}
//else {
//data("1.3.6.1.4.1.1722.12.2.2.4",  id_rsassa_pkcs1_v1_5_with_blake2s128, 16, 41, true,  false, cast(immutable(ubyte)[]) x"30 23 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 04 05 00 04 10"),
//data("1.3.6.1.4.1.1722.12.2.2.5",  id_rsassa_pkcs1_v1_5_with_blake2s160, 20, 41, true,  false, cast(immutable(ubyte)[]) x"30 27 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 05 05 00 04 14"),
//data("1.3.6.1.4.1.1722.12.2.2.7",  id_rsassa_pkcs1_v1_5_with_blake2s224, 28, 41, true,  false, cast(immutable(ubyte)[]) x"30 2F 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 07 05 00 04 1c"),
//data("1.3.6.1.4.1.1722.12.2.2.8",  id_rsassa_pkcs1_v1_5_with_blake2s256, 32, 41, true,  false, cast(immutable(ubyte)[]) x"30 33 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 08 05 00 04 20"),
//}
];


version(FAKE_OPENSC_VERSION) {}
else
/** This function doesn't slavishly perform Computing RSA Signature: Some conditions must be fulfilled, except,
 * it gets either 20 or 32 (, or 0) bytes which are assumed to be a hash from sha1 or sha256 (or a pkcs11-tool test case), but this may result in a verification error due to false assumption.

 * The ACOS function for computing a signature is somewhat special/recuded in capabilitiy:
 * It doesn't accept data well-prepared for signing (padding, digestinfo including hash),
 * but accepts only a hash value (20 bytes=SHA-1 or 32 bytes=SHA-256 or 0 bytes for a hash value
 * already present by an immediate preceding hash calculation by the token; nothing else).
 * The digestInfo and padding (BT=01) is generated by cos before signing automatically, depending on hashLength (20/32 bytes). 
 * In order to mitigate the shortcoming, this function will try (if it can detect {also: does accept} the hash algorithm used)
 * to delegate to raw hash computation,
 * which is possible only, if the RSA key is capabale for decrypting, additional to signing as well!
 * Though this dual key capability is not recommended.
 * THUS ALL HASH ALGORITHMS OTHER THAN SHA1 AND SHA256 MAY CAUSE AN ERROR CONDITION !!!
 * The aforesaid raw hash computation is available as ACOS's RSA Private Key Decrypt operation, which shall be
 * given a padding different from padding for signing. Correctness of padding is always checked (except for 20/32 byte input), thus
 * "decipher" also has to know about if it is a delegate call from "compute_signature", in order to allow the "unexpected" padding for signing in this case.
 * If enabled, also a user_consent must be answered affirmatively.
 * In corner cases, this complicated procedure may fail.

This function serves RSA_PKCS_PSS only. RSA_PKCS_PSS isn't supportrd yet by opensc
TODO record and update the current state of SecEnv to know about prKey about to be used: (FID,) KeyModulusLength, capability (Sign/Decipher)
Knowing that, no need to try raw RSA if it's known, the key is not capable of
 
 https://msdn.microsoft.com/en-us/library/ff635603.aspx
 https://msdn.microsoft.com/en-us/library/aa375534(VS.85).aspx

If SC_ALGORITHM_RSA_PAD_PKCS1 is used as alterative to SC_ALGORITHM_RSA_PAD_NONE, the difference is then:
in_len no more reflects the modulus_len, but the len of digestInfo (no padding), which is the input then; opposed to in_len=modulusByteLen and padded input including digestInfo

The setting of SC_ALGORITHM_RSA_HASH_NONE doesn't seem to make a difference for sign/verify

This function will benefit from knowledge about:
keyModulusBytesLength (in order to allow SC_ALGORITHM_RSA_PAD_PKCS1)
RSA file byte 1:       Key Type (whether decipher is allowed for private key: is unretrievable ! maintain a bookkeeping file or rely on settings in PrKDF?) 
RSA file byte 2:       Key Length encoded
RSA file byte 3 and 4: Key partner File ID

Task: make acos5_64_compute_signature ready to deal with PSS Signing Scheme
How is this indicated <-> RSA_PKCS
 */
private extern(C) int acos5_64_compute_signature(sc_card* card, const(ubyte)* in_, /*in*/ size_t in_len, ubyte* out_, /*in*/ size_t out_len)
{ // check in_len, out_len, they aren't constant any more, but treat them as if they are constant
	// we got a SHA-512 hash value and this function can not deal with that. Hopefully, the prkey is allowed to decrypt as well, as we will delegate to acos5_64_decipher (raw RSA)
	// There is a signing test, which pads properly, but has no digestinfo(no hash). If the key is capable to decipher as well, we can delegate to acos5_64_decipher. Let's try it.
/*
Test data issued by pkcs11-tool, that are wrong:

This padding is for RSA-decipher ?

This will leave acos5_64_compute_signature with faked success, if version=FAKE_SUCCESS_FOR_SIGN_VERIFY_TESTS is set; won't delegate to acos5_64_decipher in this case.
But setting TRY_SUCCESS_FOR_SIGN_VERIFY_TESTS will delegate to acos5_64_decipher.

C_SeedRandom() and C_GenerateRandom():
  seeding (C_SeedRandom) not supported
  seems to be OK
Digests:
  all 4 digest functions seem to work
  MD5: OK
  SHA-1: OK
  RIPEMD160: OK
Signatures (currently only RSA signatures)
  testing key 0 (key_1) 
ERR: signatures returned by C_SignFinal() different from C_Sign()
  testing signature mechanisms:
    RSA-X-509: OK
    RSA-PKCS: OK
  testing key 1 (4096 bits, label=key_2) with 1 signature mechanism
    RSA-X-509: OK
  testing key 2 (4096 bits, label=key_3) with 1 signature mechanism -- can't be used to sign/verify, skipping  (<- it's declared to decrypt only in PrKDF)
  testing key 3 (4096 bits, label=key_4) with 1 signature mechanism
    RSA-X-509: OK
  testing key 4 (1792 bits, label=key_5) with 1 signature mechanism
    RSA-X-509: OK
Verify (currently only for RSA):
  testing key 0 (key_1)
    RSA-X-509:   ERR: verification failed  ERR: C_Verify() returned CKR_SIGNATURE_INVALID (0xc0)

  testing key 1 (key_2) with 1 mechanism
    RSA-X-509:   ERR: verification failed  ERR: C_Verify() returned CKR_SIGNATURE_INVALID (0xc0)

  testing key 2 (key_3) with 1 mechanism
 -- can't be used to sign/verify, skipping
  testing key 3 (key_4) with 1 mechanism
    RSA-X-509: OK
  testing key 4 (key_5) with 1 mechanism
    RSA-X-509: OK
Unwrap: not implemented

Decryption (RSA)
  testing key 0 (key_1)  -- can't be used to decrypt, skipping  (<- it's declared to sign only in PrKDF)
  testing key 1 (key_2)  -- can't be used to decrypt, skipping  (<- it's declared to sign only in PrKDF)
  testing key 2 (key_3)
    RSA-X-509: OK
    RSA-PKCS: OK
  testing key 3 (key_4)
    RSA-X-509: OK
    RSA-PKCS: OK
  testing key 4 (key_5)
    RSA-X-509: OK
    RSA-PKCS: OK
5 errors
*/
	if (card == null || in_ == null || out_ == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;

	acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
	mixin (log!(q{"acos5_64_compute_signature"}, q{"called"}));
	scope(exit) {
		private_data.call_to_compute_signature_in_progress = false;
		mixin log_scope_exit!("acos5_64_compute_signature");  log_scope_exit_do;
/* */
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_compute_signature(sc_card* card, const(ubyte)* in_, in size_t in_len, ubyte* out_, in size_t out_len) is returnung with argument *card\n");
//			writer.formattedWrite("%s", *card);
		}
/* */
	}
	private_data.call_to_compute_signature_in_progress = true;

/+ +/
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"in_len:  %llu\n", in_len);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"out_len: %llu\n", out_len);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.algorithms.algorithm: %u\n", card.algorithms.algorithm); // SC_ALGORITHM_RSA = 0
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.algorithms.key_length: %u\n", card.algorithms.key_length); // 512
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.algorithms.flags: 0x%08X\n", card.algorithms.flags); // 0x80000_23B  

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.algorithms.u._rsa.exponent: %lu\n", card.algorithms.u._rsa.exponent);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.algorithm_count: %d\n", card.algorithm_count);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.caps:  %d\n", card.caps);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.flags: %d\n", card.flags);
/+ +/
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"Input to compute_signature len: '%d' bytes:\n%s\n============================================================",
		in_len, sc_dump_hex(in_, in_len));


	if (in_len > out_len)
		return rv=SC_ERROR_NOT_SUPPORTED;
	if (in_len > 0x0200) // FIXME if this function has to decrypt for symkeys as well; currently it's for RSA only
		return rv=SC_ERROR_NOT_SUPPORTED;

	ubyte[] tmp_arr = new ubyte[in_len]; // ubyte[0x200] tmp_arr; //	size_t       in_len_new = in_len;
	bool hash_algo_detected;

	if (in_len>=64 /*the min. Modulus*/ && !(cast(int)(in_len%32/*modulusStepSize*/))) { // this must be true (but may depend on SC_ALGORITHM_RSA_PAD_*; check this),  assuming in_len==keyLength
		// padding must exist, be the correct one, possible to be removed, otherwise it's an error
		// the remainder after applying sc_pkcs1_strip_01_padding must be a recognized digestInfo, and this must be allowed to eventually succeed
		{
			size_t  digestInfoLen = in_len; // unfortunately, tmp_arr.length is no lvalue, can't be set by sc_pkcs1_strip_01_padding directly, therfore the scope to get rid of digestInfoLen soon
			// TODO the following is for EMSA-PKCS1-v1_5-ENCODE only, but ther is also EMSA-PSS
			if ((rv=sc_pkcs1_strip_01_padding(ctx, in_, in_len, tmp_arr.ptr, &digestInfoLen)) < 0) { // what remains, should (for RSASSA-PKCS1-v1_5) be a valid ASN.1 DigestInfo with either SHA-1 or SHA-256 digestAlgorithm, otherwise we have to handle that with another function
				//stripp padding BT=01 failed: refuse to sign !
				bool maybe_PSS = in_[in_len-1]==0xbc;
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"MESSAGE FROM PRIVATE KEY USAGE: Refused to sign because padding is not correct according EMSA-PKCS1-v1_5 (NOT BT=01 or other issue); maybe_PSS: %d", maybe_PSS);
version(FAKE_SUCCESS_FOR_SIGN_VERIFY_TESTS) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"MESSAGE FROM PRIVATE KEY USAGE: Nevertheless, in order to proceed in pkcs11-tool's tests, we fake a success here, knowing, that a verifification of signature will fail !");
				return rv=SC_SUCCESS; // the appropriate SC_ERROR_NOT_SUPPORTED here would stop test procedure in pkcs11-tool, thus we fake a success here and will get a failing verify
}
else version(RSA_PKCS_PSS) {
				if (!maybe_PSS) // TODO possibly more checks before doing Raw RSA
					return rv=SC_ERROR_NOT_SUPPORTED;
				else {
					sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
						"MESSAGE FROM PRIVATE KEY USAGE: RSA_PKCS_PSS is active and we'll try to sign");
					if ((rv=acos5_64_decipher(card, in_, in_len, out_, out_len)) < 0) {
						sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
							"The reason for the error probably is: The key is not capable to decrypt, just sign (every cos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by cos (established when creating a key pair in token) !");
					}
					return rv;
				}
}
else		return rv=SC_ERROR_NOT_SUPPORTED;
			}
			tmp_arr.length = digestInfoLen;
		} // tmp_arr content is now in_ content without padding; now do the detection
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
			"The in_len got reduced by sc_pkcs1_strip_01_padding from %lu to %lu", in_len, tmp_arr.length);

// what to do with tmp_arr if e.g. only zeros or length to short for hash or digestInfo
		if (!any(tmp_arr)) { // hash algo not retrievable; sc_pkcs1_strip_01_padding succeeded, but the remaining bytes are zeros only; shall we sign? It's worth nothing
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
				"Got a digestInfo (includeing hash) consisting of %lu zeros only!!", tmp_arr.length);
			if (tmp_arr.length<20)
				return rv=SC_ERROR_NOT_ALLOWED;
			
version(TRY_SUCCESS_FOR_SIGN_VERIFY_TESTS) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
				"MESSAGE FROM PRIVATE KEY USAGE: TRY_SUCCESS_FOR_SIGN_VERIFY_TESTS is active and some IMHO unsave steps are taken to try to sign");
			if ((rv=acos5_64_decipher(card, in_, in_len, out_, out_len)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"The reason for the error probably is: The key is not capable to decrypt, just sign (every cos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by cos (established when creating a key pair in token) !");
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"As a last resort, it's assumed, that a SHA1 hash 20 zero bytes was given");
				tmp_arr.length = 20;
				goto matched_SHA1_or_SHA256;
			}
			return rv;
}
else
			return rv=SC_ERROR_NOT_ALLOWED;
		}

		foreach (ref elem; DI_table[id_rsassa_pkcs1_v1_5_with_sha1..1+id_rsassa_pkcs1_v1_5_with_sha3_512]) // foreach (elem; EnumMembers!DigestInfo_Algo_RSASSA_PKCS1_v1_5)
		with (elem) { // a match will leave this function, except for SHA1 and SHA256
			assert(digestInfoPrefix[$-1]              == hashLength);
			assert(digestInfoPrefix.length+hashLength == digestInfoLength);

			if (tmp_arr.length==digestInfoLength && equal(tmp_arr[0..digestInfoPrefix.length], digestInfoPrefix)) { //was memcmp...
				hash_algo_detected = true;

				if (!any(tmp_arr[digestInfoPrefix.length..$])) { // hash algo known, but we got a hash with zeros only; shall we sign a zeroed hash? It's worth nothing
					sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
						"Got a hash with zeros only! Will refuse to sign!");
					return rv=SC_ERROR_NOT_ALLOWED;
				}

				if (!allow) {
					sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
						"I condider hash algorithm %s to be weak and don't allow it !", hashAlgorithmOID.toStringz);
					return rv=SC_ERROR_NOT_ALLOWED;
				}
				if (!compute_signature_possible_without_rawRSA) {
					if ((rv=acos5_64_decipher(card, in_, in_len, out_, out_len)) < 0)
						sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
							"The reason for the error probably is: The key is not capable to decrypt, just sign (every cos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by cos (established when creating a key pair in token) !");
					return rv;
				}
				// only SHA1 and SHA256, after sc_pkcs1_strip_01_padding and successful detection get to this point
				tmp_arr = tmp_arr[digestInfoPrefix.length..$]; // keep the hash only
				break;
			}
		} // foreach with
		// not yet detected: could still be a hash value without digestInfo
		if (!hash_algo_detected) {
			if (tmp_arr.length!=20 && tmp_arr.length!=32) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"Unknown hash algorithm used: Check whether to add to DI_table digestInfoPrefix: %s", sc_dump_hex(tmp_arr.ptr, max(0,tmp_arr.length-tmp_arr[$-1])));
				return rv=SC_ERROR_NOT_IMPLEMENTED;
			}
		}
		//matched SHA1 or SHA256
	} // if (in_len>=64 && !(cast(int)in_len%32))
	else { // (or 20/32 bytes pure hash)
version(RSA_PKCS_PSS) {
		if (in_len==20/* || in_len==32*/) {
/* */
			tmp_arr.length = 512;
			size_t out_len_tmp = 512;
			CK_RSA_PKCS_PSS_PARAMS pss_params = CK_RSA_PKCS_PSS_PARAMS(CKM_SHA_1, CKG_MGF1_SHA1, in_len);
			rv = pkcs1_add_PSS_padding(in_, in_len, tmp_arr.ptr, &out_len_tmp, tmp_arr.length, tmp_arr.length*8, &pss_params);
			assert(rv==0);
			assert(out_len_tmp==512);
			if ((rv=acos5_64_decipher(card, tmp_arr.ptr, tmp_arr.length, out_, out_len)) < 0)
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"The reason for the error probably is: The key is not capable to decrypt, just sign (every cos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by cos (established when creating a key pair in token) !");
			return rv;
/* */
		}
		else
			tmp_arr.length = 0;
}
else {
		if (in_len==20 || in_len==32) {
			tmp_arr.length = in_len;
			tmp_arr[] = in_[0..tmp_arr.length]; 
		}
		else
			tmp_arr.length = 0;
}
	}

matched_SHA1_or_SHA256: // or everything unknown is mapped to zero length, which entails, that cos will try to use an existing internal hash

version(ENABLE_ACOS5_64_UI)  /* (Requested by DGP): on signature operation, ask user consent */
	if ((rv=acos5_64_ask_user_consent(card, user_consent_title, user_consent_message)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature", "User consent denied\n");
		return rv;
	}

	sc_apdu apdu; //                          CLAINSP1 P2               lc            apdu.data
	bytes2apdu(ctx, cast(immutable(ubyte)[])x"00 2A 9E 9A" ~ cast(ubyte)tmp_arr.length ~ tmp_arr,     apdu);
	apdu.flags = SC_APDU_FLAGS_NO_GET_RESP | (tmp_arr.length > 0xFF ? SC_APDU_FLAGS_CHAINING : 0LU);
	mixin transmit_apdu!("acos5_64_compute_signature");  if ((rv=transmit_apdu_do)<0) return rv;

	if (apdu.sw1 != 0x61) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
			"Didn't get clearance to call get_response\n");
		return rv=SC_ERROR_UNKNOWN;
	}

	uint received;
	size_t count;
	ubyte* p = out_;
	do {
		count = in_len - received; // here count is: 'not_received', what remains to be received; get_response truncates to max_recv_length 0X100
		if ((rv=iso_ops_ptr.get_response(card, &count, p)) < 0) { // 
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
				"get_response failed: rv: %d, count:%lu , \n", rv, count);
			return rv;
		}
		received += count; // now count is what actually got received
		p        += count;
	} while (in_len > received && count>0); // receiving more than in_lenmax==512 would cause a crash here
/*
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"Output from compute_signature len: '%d' bytes:\n%s\n============================================================",
			received, sc_dump_hex(out_, received));
*/
	if (in_len != received)
		return rv=SC_ERROR_UNKNOWN;
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"MESSAGE FROM PRIVATE KEY USAGE: Private key was successfully applied for signatur generation");

	return rv=cast(int)received;
}


private extern(C) int acos5_64_list_files(sc_card* card, ubyte* buf, size_t buflen)
{
  sc_apdu apdu;
  int rv;
  size_t count;
  ubyte* bufp = buf;
  int fno = 0;    /* current file index */

	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_list_files"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_list_files",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_list_files",
				"returning with: %d\n", rv);
	}

  /* Check parameters. */
  if (!buf || (buflen < 8))
    return SC_ERROR_INVALID_ARGUMENTS;

  /*
   * Use CARD GET INFO to fetch the number of files under the
   * curently selected DF.
   */
  sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x01, 0x00);
  apdu.cla = 0x80;
	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_list_files",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	if (apdu.sw1 != 0x90)
		return rv=SC_ERROR_INTERNAL;
	count = apdu.sw2;

	while (count--) {
		ub8 info; // cos will deliver 8 bytes: [FDB, DCB(always 0), FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI]

		/* Truncate the scan if no more room left in output buffer. */
		if (buflen == 0)
			break;

//		apdu = sc_apdu.init;
		sc_apdu sc_apdu_init;
		apdu = sc_apdu_init;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x02, fno++);
		with (apdu) {
			cla = 0x80;
			resp         = info.ptr;
			resplen = le = info.sizeof;
		}
		if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_list_files",
				"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
			return rv;
		}

		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
			return rv=SC_ERROR_INTERNAL;

		*bufp++ = info[2];
		*bufp++ = info[3];
		buflen -= 2;
	}

	return  rv=cast(int)(bufp - buf);
}

private extern(C) int acos5_64_check_sw(sc_card *card, uint sw1, uint sw2)
{
	/* intercept SW of pin_cmd ? */
	/* intercept SW 7.3.1. Get Card Info Identify Self? */
	int rv = SC_ERROR_UNKNOWN;
	sc_context* ctx = card.ctx;
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_check_sw",
		"called for: sw1 = 0x%02x, sw2 = 0x%02x\n", sw1, sw2);
//	mixin (log!(q{"acos5_64_check_sw"}, q{"called"})); //
	scope(exit) { 
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_check_sw",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_check_sw",
				"returning with: %d\n", rv);
	}

	if (sw1 == 0x90)
		return rv=SC_SUCCESS;
/*
	else if (sw1 == 0x63 && (sw2 & 0xFFFFFFF0U) == 0xC0 ) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_check_sw",
			"Verification failed (remaining tries: %d)\n", (sw2 & 0x0f));
		return rv=SC_ERROR_PIN_CODE_INCORRECT;
	}
*/
	else if (sw1 == 0x95U && sw2 == 0x40U) // this is a response to "Identify Self" and is okay for Version ACS ACOS5-64 v2.00/no error
		return rv=SC_SUCCESS;
	else if (sw1 == 0x61U /*&& sw2 == 0x40U*/)
		return rv=SC_SUCCESS;
//	else if (sw1 == 0x00U && sw2 == 0x00U)
//		return rv=SC_SUCCESS;
	/* iso error */
	return rv=iso_ops_ptr.check_sw(card, sw1, sw2);
}

struct acos5_64_se_info {
////	iasecc_sdo_docp            docp;
	int                        reference;

	sc_crt[SC_MAX_CRTS_IN_SE]  crts;

	sc_file*                   df;
	acos5_64_se_info*          next;

	uint                       magic;
}

private int acos5_64_se_cache_info(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_se_cache_info"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_cache_info",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_cache_info",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_se_cache_info(sc_card* card, acos5_64_se_info* se) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}

	acos5_64_private_data* prv = cast(acos5_64_private_data*) card.drv_data;
	acos5_64_se_info* se_info  = cast(acos5_64_se_info*)calloc(1, acos5_64_se_info.sizeof);

	if (!se_info) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_cache_info", "SE info allocation error");
		return rv=SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(se_info, se, acos5_64_se_info.sizeof);

	if (card.cache.valid && card.cache.current_df) {
		sc_file_dup(&se_info.df, card.cache.current_df);
		if (se_info.df == null) {
			free(se_info);
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_cache_info", "Cannot duplicate current DF file");
			return rv=SC_ERROR_OUT_OF_MEMORY;
		}
	}

////	if ((rv=acos5_64_docp_copy(ctx, &se.docp, &se_info.docp)) < 0) {
////		free(se_info.df);
////		free(se_info);
////		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_cache_info", "Cannot make copy of DOCP");
////		return rv;
////	}

	if (!prv.se_info)
		prv.se_info = se_info;
	else {
		acos5_64_se_info* si;
		for (si = prv.se_info; si.next; si = si.next)
		{}
		si.next = se_info;
	}

	return rv;
}

private int acos5_64_se_get_info_from_cache(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_se_get_info_from_cache"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info_from_cache",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info_from_cache",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_se_get_info_from_cache(sc_card* card, acos5_64_se_info* se) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}

	acos5_64_private_data* prv = cast(acos5_64_private_data*)card.drv_data;
	acos5_64_se_info* si;

	for (si = prv.se_info; si; si = si.next) {
		if (si.reference != se.reference)
			continue;
		if (!(card.cache.valid && card.cache.current_df) && si.df)
			continue;
		if (card.cache.valid && card.cache.current_df && !si.df)
			continue;
		if (card.cache.valid && card.cache.current_df && si.df)
			if (memcmp(&card.cache.current_df.path, &si.df.path, sc_path.sizeof))
				continue;
		break;
	}

	if (!si)
		return rv=SC_ERROR_OBJECT_NOT_FOUND;

	memcpy(se, si, acos5_64_se_info.sizeof);

	if (si.df) {
		sc_file_dup(&se.df, si.df);
		if (se.df == null) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info_from_cache", "Cannot duplicate current DF file");
			return rv=SC_ERROR_OUT_OF_MEMORY;
		}
	}

////	if ((rv=acos5_64_docp_copy(ctx, &si.docp, &se.docp)) < 0) {
////		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info_from_cache", "Cannot make copy of DOCP");
////		return rv;
////	}
	return rv;
}

private int acos5_64_se_get_info(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_se_get_info"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_se_get_info(sc_card* card, acos5_64_se_info* se) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}
	

	if (se.reference > 0x0F/*IASECC_SE_REF_MAX*/)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if ((rv=acos5_64_se_get_info_from_cache(card, se)) == SC_ERROR_OBJECT_NOT_FOUND)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info",
			"No SE#%X info in cache, try to use 'GET DATA'", se.reference);
		if (rv == SC_ERROR_OBJECT_NOT_FOUND)
  		return rv;
		
		if ((rv=acos5_64_se_cache_info(card, se)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_info", "failed to put SE data into cache");
			return rv;
		}
	} // if ((rv=acos5_64_se_get_info_from_cache(card, se)) == SC_ERROR_OBJECT_NOT_FOUND)

	return rv;
}

private int acos5_64_se_get_crt(sc_card* card, acos5_64_se_info* se, sc_crt* crt) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_se_get_crt"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_crt",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_crt",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_finish(sc_card *card) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}

	if (!se || !crt)
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_crt",
		"CRT search template: %X:%X:%X, refs %X:%X:...", crt.tag, crt.algo, crt.usage, crt.refs[0], crt.refs[1]);

	for (int ii=0; ii<SC_MAX_CRTS_IN_SE && se.crts[ii].tag; ii++)   {
		if (crt.tag != se.crts[ii].tag)
			continue;
		if (crt.algo && crt.algo != se.crts[ii].algo)
			continue;
		if (crt.usage && crt.usage != se.crts[ii].usage)
			continue;
		if (crt.refs[0] && crt.refs[0] != se.crts[ii].refs[0])
			continue;

		memcpy(crt, &se.crts[ii], sc_crt.sizeof);

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_crt",
			"acos5_64_se_get_crt() found CRT with refs %X:%X:...", se.crts[ii].refs[0], se.crts[ii].refs[1]);
		return rv=SC_SUCCESS;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_get_crt", "iasecc_se_get_crt() CRT is not found");
	return rv=SC_ERROR_DATA_OBJECT_NOT_FOUND;
}

private int acos5_64_get_chv_reference_from_se(sc_card* card, int* se_reference) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_get_chv_reference_from_se"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_chv_reference_from_se",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_chv_reference_from_se",
				"returning with: %d\n", rv);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_get_chv_reference_from_se(sc_card* card, int* se_reference) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
//		}
	}

	if (!se_reference)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	acos5_64_se_info  se;
	se.reference = *se_reference;

	if ((rv=acos5_64_se_get_info(card, &se)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_chv_reference_from_se", "get SE info error\n");
		return rv;
	}

	sc_crt crt;
	crt.tag   = 0xA4; // IASECC_CRT_TAG_AT;
	crt.usage = 0x08; // IASECC_UQB_AT_USER_PASSWORD;

	if ((rv=acos5_64_se_get_crt(card, &se, &crt)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_chv_reference_from_se", "Cannot get 'USER PASSWORD' authentication template\n");
		return rv;
	}

	if (se.df)
		sc_file_free(se.df);
	return rv=crt.refs[0];
}

/**
 * Implementation for Card_Ctl() card driver operation.
 *
 * This command provides access to non standard functions provided by
 * this card driver, as defined in cardctl.h
 *
 * @param card Pointer to card driver structure
 * @param request Operation requested
 * @param data where to get data/store response
 * @return SC_SUCCESS if ok; else error code
 * @see cardctl.h
 *
 * TODO: wait for GET_CARD_INFO generic cardctl to be implemented in opensc
 */
private extern(C) int acos5_64_card_ctl(sc_card* card, c_ulong request, void* data) {
	if (card == null || card.ctx == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(q{"acos5_64_card_ctl"}, q{"called"})); //
//	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl", "request=%lu\n", request);
	scope(exit) {
		if (rv <= 0)
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"returning with: %d\n", rv);
	}

	if (data == null)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	final switch (cast(SC_CARDCTL)request) {
		case SC_CARDCTL_GENERIC_BASE, SC_CARDCTL_ERASE_CARD, SC_CARDCTL_GET_DEFAULT_KEY, SC_CARDCTL_LIFECYCLE_GET
				, SC_CARDCTL_PKCS11_INIT_TOKEN, SC_CARDCTL_PKCS11_INIT_PIN:
			return rv; // SC_ERROR_NOT_SUPPORTED
		case SC_CARDCTL_LIFECYCLE_SET:
			SC_CARDCTRL_LIFECYCLE lcsi =  cast(SC_CARDCTRL_LIFECYCLE)(*cast(int*)data); // Life Cycle Status Integer
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"request=SC_CARDCTL_LIFECYCLE_SET with *data: %d\n", lcsi);
			final switch (lcsi) {
				case SC_CARDCTRL_LIFECYCLE_ADMIN:
				{
					sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
						"### FAKING SO LOGIN ### request=SC_CARDCTL_LIFECYCLE_SET with *data==SC_CARDCTRL_LIFECYCLE_ADMIN\n");
					sc_pin_cmd_data data_so;
					with (data_so) {
						cmd           = SC_PIN_CMD.SC_PIN_CMD_VERIFY;
						flags         = SC_PIN_CMD_NEED_PADDING;
						pin_type      = SC_AC_CHV;
						pin_reference = 0x0333;
/*
						sc_pin_cmd_pin pin1;
						sc_pin_cmd_pin pin2;
						sc_apdu* apdu;
*/
					}
					int tries_left;
					if ((rv=acos5_64_pin_cmd(card, &data_so, &tries_left)) != SC_SUCCESS)
						return rv;
					else
						return rv=SC_ERROR_NOT_SUPPORTED;//SC_SUCCESS;
				}
				case SC_CARDCTRL_LIFECYCLE_USER, SC_CARDCTRL_LIFECYCLE_OTHER:
					return rv; // SC_ERROR_NOT_SUPPORTED
			}
		case SC_CARDCTL_GET_SERIALNR: /* call card to obtain serial number */
			return rv=acos5_64_get_serialnr(card, cast(sc_serial_number*) data);
		case SC_CARDCTL_GET_SE_INFO:
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"CMD SC_CARDCTL_GET_SE_INFO: sdo_class prozentX"/*, sdo.sdo_class*/);
			return rv=acos5_64_se_get_info(card, cast(acos5_64_se_info*)data);
		case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"CMD SC_CARDCTL_GET_CHV_REFERENCE_IN_SE");
			return rv=acos5_64_get_chv_reference_from_se(card, cast(int*)data);
	}
}

private extern(C) int acos5_64_create_file(sc_card* card, sc_file* file)
{
	ubyte acos5_64_acl_to_security_condition_byte(const(sc_acl_entry)* entry)
	{
		if (!entry)
			return 0x00;
		switch(entry.method) {
			case SC_AC_CHV:
				return 0x90;
			case SC_AC_NEVER:
				return 0xFF;
			case SC_AC_NONE:
			default:
				return 0x00;
		}
	}

	int rv = SC_SUCCESS;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_create_file"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_create_file",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_create_file",
				"returning with: %d\n", rv);
	}

	if (file.sec_attr_len == 0) {
		ub8 access_buf;
		int[8] idx = [
			0, /* Reserved. */
			SC_AC_OP.SC_AC_OP_DELETE_SELF, /* b6 */
			SC_AC_OP.SC_AC_OP_LOCK,        /* b5   (Terminate) */
			SC_AC_OP.SC_AC_OP_ACTIVATE,    /* b4 */
			SC_AC_OP.SC_AC_OP_DEACTIVATE,  /* b3 */
			0, /* Preliminary */  /* b2 */
			0, /* Preliminary */  /* b1 */
			0  /* Preliminary */  /* b0 */
		];

		if (file.type == SC_FILE_TYPE_DF) {
			const(int)[3] df_idx = [ /* These are the SC operations. */
				SC_AC_OP.SC_AC_OP_CREATE_DF,   /* b2 */
				SC_AC_OP.SC_AC_OP_CREATE_EF,   /* b1 */
				SC_AC_OP.SC_AC_OP_DELETE       /* b0   (Delete Child) */
			];
			idx[5..8] = df_idx[];
		}
		else {  /* EF */
			const(int)[3] ef_idx = [
				SC_AC_OP.SC_AC_OP_WRITE,       /* b2 */ // file.type == ? 0: 
				SC_AC_OP.SC_AC_OP_UPDATE,      /* b1 */
				SC_AC_OP.SC_AC_OP_READ         /* b0 */
			];
			idx[5..8] = ef_idx[];
		}
		/* Now idx contains the operation identifiers.
		 * We now search for the OPs. */
		access_buf[0] = 0xFF; /* A security condition byte is present for every OP. (Table 19) */
		for (int i=1; i<8; ++i) {
			const(sc_acl_entry)* entry;
			entry = sc_file_get_acl_entry(file, idx[i]);
			access_buf[i] = acos5_64_acl_to_security_condition_byte(entry);
		}

		if ((rv=sc_file_set_sec_attr(file, access_buf.ptr, 8)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_create_file", "Error adding security attribute.");
			return rv;
		}
	}

	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_create_file(sc_card* card, sc_file* file) with argument *file:\n");
		if (file)
			writer.formattedWrite("%s", *file);
	}

	return rv=iso_ops_ptr.create_file(card, file);
}

/** iso7816_delete_file should be sufficient
private extern(C) int acos5_64_delete_file(sc_card* card, const(sc_path)* path) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_delete_file"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_delete_file",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_delete_file",
				"returning with: %d\n", rv);
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_delete_file(sc_card* card, const(sc_path)* path) is returning with argument *card:\n");
//			writer.formattedWrite("%s", *card);
		}
	}
	int r;
	ubyte[2] sbuf;
	sc_apdu apdu;

	if ((rv=sc_select_file(card, path, null)) != SC_SUCCESS)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	sbuf = path.value[(path.len - 2)..path.len];
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE4, 0x00, 0x00);
	apdu.lc = apdu.datalen = sbuf.length;
	apdu.data              = sbuf.ptr;

	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_delete_file", "APDU transmit failed");
			return rv;
	}
	if ((rv=rv = sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_delete_file", "Delete file failed");
			return rv;
	}

	return rv;
}
*/

/**
 * This function first calls the iso7816.c process_fci() for any other FCI
 * information and then updates the ACL of the OpenSC file struct according
 * to the FCI (from the isoapplet.
 */
private extern(C) int acos5_64_process_fci(sc_card* card, sc_file* file, const(ubyte)* buf, size_t buflen)
{

	void file_add_acl_entry(sc_file *file, int op, uint SCB) // checked against card-acos5_64.c  OPENSC_loc
	{
		uint method, keyref = SC_AC_KEY_REF_NONE;

		switch (SCB) {
			case 0x00:
				method = SC_AC.SC_AC_NONE;
				break;
			case 0xFF:
				method = SC_AC.SC_AC_NEVER;
				break;
			case 0x41: .. case 0x4E: // Force the use of Secure Messaging and at least one condition specified in the SE-ID of b3-b0
				// TODO
				method = SC_AC.SC_AC_SCB;
				keyref = SCB & 0x0F;
				break;
			case 0x01: .. case 0x0C: // cos allows 0x0E, but opensc is limited to 0x0C==SC_MAX_CRTS_IN_SE;  At least one condition specified in the SE ID of b3-b0
				goto case;  // continues to the next case
			case 0x81: .. case 0x8C: // cos allows 0x0E, but opensc is limited to 0x0C==SC_MAX_CRTS_IN_SE;  All conditions         specified in the SE ID of b3-b0
				method = SC_AC.SC_AC_SEN; //SC_AC.SC_AC_CHV;
				keyref = SCB & 0x0F;
				break;
			default:
				method = SC_AC.SC_AC_UNKNOWN;
				break;
		}
		sc_file_add_acl_entry(file, op, method, keyref);
	}

	import core.cpuid : hasPopcnt;
	import core.bitop : /* _popcnt, */ popcnt; // GDC doesn't know _popcnt

	size_t taglen, plen = buflen;
	const(ubyte)* tag = null, p = buf;
	int rv;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_process_fci"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci",
				"returning with: %d\n", rv);
	}

	// iso_ops_ptr.process_fci does a nice job, leaving some refinements etc. for this function
	if ((rv = iso_ops_ptr.process_fci(card, file, buf, buflen)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci",
			"error parsing fci: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (!file)
		return rv=SC_SUCCESS;

	file.sid = 0;
//	file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_SELECT,						SC_AC_NONE);
	ubyte FDB;
	/* catch up on everything, iso_ops_ptr.process_fci did omit: SE-file FDB (0x1C), tags 0x8C and 0xAB */
	/* correct/add/refine   File Descriptor Byte (FDB) for
		 Security Environment file (proprietary) has FDB : 1C 
	int record_length; // In case of fixed-length or cyclic EF
	int record_count;  // Valid, if not transparent EF or DF
	 */
//	if (file.type == 0 || file.type == SC_FILE_TYPE_INTERNAL_EF) {
	tag = sc_asn1_find_tag(ctx, p, plen, 0x82, &taglen);
	if (tag && taglen > 0 && taglen <= 6 /*&& file.type!=SC_FILE_TYPE_WORKING_EF*/ && file.type!=SC_FILE_TYPE_DF) {
		if (!canFind(/*[0x3F, 0x38, 0x01, 0x02, 0x04, 0x06, 0x09, 0x0A, 0x0C, 0x1C]*/ [EnumMembers!EFDB], tag[0]))
			return rv=SC_ERROR_INVALID_ASN1_OBJECT;
		FDB = tag[0]; // 82 06  1C 00 00 30 00 05
		switch (FDB) {
			case CHV_EF, Symmetric_key_EF:
//				file.type = SC_FILE_TYPE_BSO;
//				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci", "  type (corrected): BSO EF CHV or Symmetric-key");
				break;
			case RSA_Key_EF:
				if ((integralLastTwo2ub2(file.id)[1] & 0xF0) == 0xF0) { // privat? the public key is no BSO
//					file.type = SC_FILE_TYPE_BSO;
//					sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci", "  type (corrected): BSO EF RSA private");
				}
				break;
			case SE_EF:
//				type = "internal EF";
				file.type = SC_FILE_TYPE_INTERNAL_EF; // refinement might be SC_FILE_TYPE_INTERNAL_SE_EF
				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci", "  type (corrected): proprietary EF SecurityEnvironment"); // SE-file  // FDB == 0x1C
				break;
			default:	
				break;
		}
		if (taglen>=5 /*&& taglen <= 6*/) {//FDB+DCB+00h+MRL+NOR or FDB+DCB+00h+MRL+00h+NOR;  MRL:maximum record length (<=255); in case of linear variable, there may be less bytes in a record than MRL
			file.record_length = tag[3];        // ubyte MRL // In case of fixed-length or cyclic EF
			file.record_count  = tag[taglen-1]; // ubyte NOR // Valid, if not transparent EF or DF
		}
	}

	tag = sc_asn1_find_tag(ctx, p, plen, 0x8C, &taglen); // e.g. 8C 08 7F FF FF 01 01 01 01 FF; taglen==8, x"7F FF FF 01 01   01 01 FF"
//	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci",
//		"1sc_asn1_find_tag(ctx, p, plen, 0x8C, &taglen): 0x8C %d    %s\n", taglen, sc_dump_hex(tag, taglen));
/+ +/
	ubyte AM; // Access Mode Byte (AM) 
	ub8   SC; // initialized with SC_AC_NONE;

	if (tag && taglen > 0) {
		AM = *tag++;
		if (1+ (/*hasPopcnt? _popcnt(AM) :*/ popcnt(AM)) != taglen)
			return rv=SC_ERROR_INVALID_ASN1_OBJECT;

		foreach (i, ref b; SC)
			if (AM & (0b1000_0000 >> i))
				b = *tag++;
	}
/+ +/
//		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_process_fci",
//			"2sc_asn1_find_tag(ctx, p, plen, 0x8C, &taglen): 0x8C %d %02X %s\n", taglen, AM, sc_dump_hex(SC.ptr, 8));
	file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DELETE_SELF,     SC[1]);
	file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_LOCK,            SC[2]); // Terminate
	file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_REHABILITATE,    SC[3]); // Activate
//file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_ACTIVATE,        SC[3]);
	file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_INVALIDATE,      SC[4]); // Deactivate
//file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DEACTIVATE,      SC[4]);

	final switch (cast(SC_FILE_TYPE)file.type) {
		case SC_FILE_TYPE_DF:
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CREATE_DF,   SC[5]);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CREATE_EF,   SC[6]);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CREATE,      SC[6]); // What to specify here? CREATE_EF or CREATE_DF? Currently return CREATE_EF
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DELETE,      SC[7]); // Delete Child 
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_SELECT,      SC_AC_NONE);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_LIST_FILES,  SC_AC_NONE);
			break;
		case SC_FILE_TYPE_INTERNAL_EF:
			final switch (cast(EFDB)FDB) {
				case SE_EF:  // potentially as own SC_FILE_TYPE in case SC_FILE_TYPE_INTERNAL_SE_EF:
					file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CRYPTO,                     SC[5]); //  MSE Restore
					break;
				case CHV_EF:
					break;
				case RSA_Key_EF, Symmetric_key_EF:
					file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CRYPTO,                     SC[5]); //  MSE/PSO Commands
					if (FDB==Symmetric_key_EF) {
						file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_DECRYPT,              SC[5]);
						file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_ENCRYPT,              SC[5]);
						file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_COMPUTE_CHECKSUM,     SC[5]);
						file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_VERIFY_CHECKSUM,      SC[5]);
					}
					else if (FDB==RSA_Key_EF) {
						file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_GENERATE,                 SC[5]);
						if (SC[7]==0xFF) { // then assume it's the private key
							file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_DECRYPT,            SC[5]);
							file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_COMPUTE_SIGNATURE,  SC[5]);
						}
						else {
							file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_ENCRYPT,            SC[5]);
							file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_PSO_VERIFY_SIGNATURE,   SC[5]);
						}
					}
					break;
				// all other non-internal_EF FDBs are not involved, just mentioned for final switch usage
				case Transparent_EF, Linear_Fixed_EF, Linear_Variable_EF, Cyclic_EF, DF, MF: break;
			}
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_UPDATE,          SC[6]);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_WRITE,           SC[6]); //###
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DELETE,          SC[1]); //### synonym SC_AC_OP_ERASE, points to SC_AC_OP_DELETE_SELF
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_READ,            SC[7]);
			break;
		case SC_FILE_TYPE_WORKING_EF:
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_UPDATE,  SC[6]);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_WRITE,   SC[6]); //###
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DELETE,  SC[1]); // synonym SC_AC_OP_ERASE, points to SC_AC_OP_DELETE_SELF
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_READ,    SC[7]);
			break;
		case SC_FILE_TYPE_BSO: // BSO (Base Security Object) BSO contains data that must never go out from the card, but are essential for cryptographic operations, like PINs or Private Keys
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_CRYPTO,          SC[5]); //  MSE/PSO Commands
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_UPDATE,          SC[6]);
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_WRITE,           SC[6]); //###
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_DELETE,          SC[1]); //### synonym SC_AC_OP_ERASE, points to SC_AC_OP_DELETE_SELF
			file_add_acl_entry (file, SC_AC_OP.SC_AC_OP_READ,            SC[7]);
			break;
	} // final switch (cast(SC_FILE_TYPE)file.type)
/+ +/
/+
	if (tag && taglen > 0 && FDB && file.id) {
		abc[SC_AC_OP] aa_acls = SACmap_SCBs2sc_acl_entry(FDB, integralLastTwo2ub2(file.id), tag[0], tag[1..taglen]);
		foreach (k, ref v; aa_acls)
			sc_file_add_acl_entry(file, k, v.acle.method, v.acle.key_ref);
	}
+/
	/* do some post processing, if file.size if record based files determined by iso7816_process_fci is zero; read from tag 0x82, if available */
	if (file.size == 0) {
		tag = sc_asn1_find_tag(ctx, p, plen, 0x82, &taglen);
		if (tag != null && taglen >= 5 && taglen <= 6) {
			ubyte MRL = tag[3], NOR = tag[taglen-1];
			file.size = MRL * NOR;
		}
	}

	return rv=SC_SUCCESS;
}

private extern(C) int acos5_64_construct_fci(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen) {

	int acl_to_ac_byte(sc_card* card, const(sc_acl_entry)* e) {
		if (e == null)
			return SC_ERROR_OBJECT_NOT_FOUND;

		switch (e.method) {
		case SC_AC.SC_AC_NONE:
			return 0x00; // LOG_FUNC_RETURN(card.ctx, EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_EVERYONE);
		case SC_AC.SC_AC_NEVER:
			return 0xFF; // LOG_FUNC_RETURN(card.ctx, EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_NOONE);
//		case SC_AC.SC_AC_SCB:
//			return 0x02;
		case SC_AC.SC_AC_CHV:
			return 0x01;
//		case SC_AC.SC_AC_SEN:
//			return 0x03;
		default:
			return 0x00; // LOG_FUNC_RETURN(card.ctx, EPASS2003_AC_MAC_NOLESS | EPASS2003_AC_USER);
		}
	//	return SC_ERROR_INCORRECT_PARAMETERS; // LOG_FUNC_RETURN(card.ctx, SC_ERROR_INCORRECT_PARAMETERS);
	}

	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_construct_fci"}, q{"called"}));
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci",
				"returning with: %d\n", rv);
/* */
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_construct_fci(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen) is returning with argument *out_:\n");
			writer.formattedWrite("[%(%#X, %)]\n", out_[0..*outlen]);
		}
/* */
	}

version(ENABLE_TOSTRING) {
	writer.put("int acos5_64_construct_fci(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen) called with argument *file:\n");
	writer.formattedWrite("%s", *file);
}

	ubyte* p = out_;
	ubyte[64] buf;

	if (*outlen < 2)
		return rv=SC_ERROR_BUFFER_TOO_SMALL;

	*p++ = 0x62;
	++p;
	if ((file.type == SC_FILE_TYPE.SC_FILE_TYPE_WORKING_EF  && file.ef_structure == SC_FILE_EF_TRANSPARENT) ||
	    (file.type == SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF && file.ef_structure == EFDB.RSA_Key_EF)) {
		buf[0..2] = integralLastTwo2ub2(file.size);
		sc_asn1_put_tag(0x80, buf.ptr, 2, p, *outlen - (p - out_), &p); // 80h 02h  Transparent File Size in bytes
	}
//	int sc_asn1_put_tag(uint tag, const(ubyte)* data, size_t datalen, ubyte* out_, size_t outlen, ubyte** ptr);

	if (file.type == SC_FILE_TYPE.SC_FILE_TYPE_DF) {
		buf[0] = 0x38;
		buf[1] = 0x00;
		sc_asn1_put_tag(0x82, buf.ptr, 2, p, *outlen - (p - out_), &p); // 82h 02h  FDB + DCB
	}
	else if (file.type == SC_FILE_TYPE.SC_FILE_TYPE_WORKING_EF) {
		buf[0] = file.ef_structure & 7;
		if (file.ef_structure == SC_FILE_EF_TRANSPARENT) {
			buf[1] = 0x00;
			sc_asn1_put_tag(0x82, buf.ptr, 2, p, *outlen - (p - out_), &p); // 82h 02h  FDB + DCB
		}
/+
		else if (file.ef_structure == SC_FILE_EF_LINEAR_FIXED
			   || file.ef_structure == SC_FILE_EF_LINEAR_VARIABLE) {
			buf[1] = 0x00;
			buf[2] = 0x00;
			buf[3] = 0x40;	/* record length */
			buf[4] = 0x00;	/* record count */
			sc_asn1_put_tag(0x82, buf, 5, p, *outlen - (p - out), &p);
		}
		else {
			return SC_ERROR_NOT_SUPPORTED;
		}
+/
	}
	else if (file.type == SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF) {
		if (file.ef_structure == EFDB.RSA_Key_EF) {
			buf[0] = 0x09;
			buf[1] = 0x00;
		}
/+
		else if (file.ef_structure == SC_CARDCTL_OBERTHUR_KEY_RSA_PUBLIC) {
			buf[0] = 0x12;
			buf[1] = 0x00;
		}
+/
		else
			return SC_ERROR_NOT_SUPPORTED;
		sc_asn1_put_tag(0x82, buf.ptr, 2, p, *outlen - (p - out_), &p);
	}/+
	else if (file.type == SC_FILE_TYPE_BSO) {
		buf[0] = 0x10;
		buf[1] = 0x00;
		sc_asn1_put_tag(0x82, buf.ptr, 2, p, *outlen - (p - out_), &p);
	}
+/
	buf[0] = (file.id >> 8) & 0xFF;
	buf[1] = file.id & 0xFF;
	sc_asn1_put_tag(0x83, buf.ptr, 2, p, *outlen - (p - out_), &p);

	buf[0] = 0x01;
	sc_asn1_put_tag(0x8A, buf.ptr, 1, p, *outlen - (p - out_), &p);

	ub8 ops = [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ];/+
	if (file.sec_attr_len) {
		memcpy(buf.ptr, file.sec_attr, file.sec_attr_len);
		sc_asn1_put_tag(0x86, buf.ptr, file.sec_attr_len, p, *outlen - (p - out_), &p);
	}
	else +/{
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci", "SC_FILE_ACL");
		if (file.type == SC_FILE_TYPE_DF) {
			ops[0] = SC_AC_OP.SC_AC_OP_LIST_FILES;
			ops[1] = SC_AC_OP.SC_AC_OP_CREATE;
			ops[3] = SC_AC_OP.SC_AC_OP_DELETE;
		}
		else if (file.type == SC_FILE_TYPE_WORKING_EF) {
			if (file.ef_structure == SC_FILE_EF_TRANSPARENT) {
				ops[0] = SC_AC_OP.SC_AC_OP_READ;
				ops[1] = SC_AC_OP.SC_AC_OP_UPDATE;
//				ops[3] = SC_AC_OP_DELETE;
			}
			else if (file.ef_structure == SC_FILE_EF_LINEAR_FIXED
					|| file.ef_structure == SC_FILE_EF_LINEAR_VARIABLE) {
				ops[0] = SC_AC_OP.SC_AC_OP_READ;
				ops[1] = SC_AC_OP.SC_AC_OP_UPDATE;
				ops[2] = SC_AC_OP.SC_AC_OP_WRITE;
//				ops[3] = SC_AC_OP_DELETE;
			}
			else {
				return SC_ERROR_NOT_SUPPORTED;
			}
		}
		else if (file.type == SC_FILE_TYPE_BSO) {
			ops[0] = SC_AC_OP.SC_AC_OP_UPDATE;
			ops[3] = SC_AC_OP.SC_AC_OP_DELETE;
		}
		else if (file.type == SC_FILE_TYPE_INTERNAL_EF) {
			if (file.ef_structure == EFDB.RSA_Key_EF) {
				ops[0] = SC_AC_OP.SC_AC_OP_READ;
				ops[1] = SC_AC_OP.SC_AC_OP_UPDATE;
//				ops[2] = SC_AC_OP.SC_AC_OP_GENERATE;
				ops[3] = SC_AC_OP.SC_AC_OP_INVALIDATE;
				ops[4] = SC_AC_OP.SC_AC_OP_REHABILITATE;
//				ops[5] = SC_AC_OP.SC_AC_OP_LOCK;
//				ops[6] = SC_AC_OP.SC_AC_OP_DELETE;
			}
		}
		else {
			return SC_ERROR_NOT_SUPPORTED;
		}

		for (uint ii = 0; ii < ops.length-1; ++ii) {
			const(sc_acl_entry)* entry;

			buf[ii] = 0xFF;
			if (ops[ii] == 0xFF)
				continue;
			entry = sc_file_get_acl_entry(file, ops[ii]);

			if ((rv=acl_to_ac_byte(card, entry)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci", "Invalid ACL");
				return rv;
			}

			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci",
				"entry(%p), entry.method(%#X), rv(%#X) \n", entry, entry.method, rv);

			buf[ii] = cast(ubyte)rv;
			if (ii==0 && file.type == SC_FILE_TYPE_INTERNAL_EF && file.ef_structure == EFDB.RSA_Key_EF && (integralLastTwo2ub2(file.id)[1] & 0xF0)==0x30)
				buf[ii] = SC_AC_NONE;
		}

		buf[ops.length-1] = 0x7F;
		ub8 buf2 = array(retro(buf[0..8]));
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_construct_fci",
			"AM +7 SC bytes: %p\n", sc_dump_hex(buf2.ptr, buf2.length));
		sc_asn1_put_tag(0x8C, buf2.ptr, buf2.length, p, *outlen - (p - out_), &p);

	}
	out_[1] = cast(ubyte)(p - out_ - 2);

	*outlen = p - out_;

	return rv=SC_SUCCESS;
}


private extern(C) int acos5_64_pin_cmd(sc_card *card, sc_pin_cmd_data *data, int *tries_left) {
	sc_context* ctx = card.ctx;
	int rv;
	mixin (log!(q{"acos5_64_pin_cmd"}, q{"called"}));
	scope(exit) {
		if (rv <= 0)
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"returning with: %d\n", rv);
	}

/* */
	with (*data)
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"sc_pin_cmd_data 1-4: cmd(%u), flags(%u), pin_type(%u), pin_reference(0x%02X)\n", cmd, flags, pin_type, pin_reference);
	if (data.pin1.prompt && strlen(data.pin1.prompt))
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"prompt: %s\n", data.pin1.prompt);
	with (data.pin1)	
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"sc_pin_cmd_data.pin1: min_length(%lu), max_length(%lu), stored_length(%lu), encoding(%u)\n", min_length, max_length, stored_length, encoding);
/* */

	final switch (cast(SC_PIN_CMD)data.cmd) {
	case SC_PIN_CMD_VERIFY: /*0*/
		final switch (cast(SC_AC)data.pin_type) {
		case SC_AC_CHV:
			if (data.pin_reference == 0x0333 ) {
			}
			else {
				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
					"Next:     Call   to   iso7816.c:iso7816_pin_cmd\n");
				data.pin_reference |= 0x80;
				/* ISO7816 implementation works */
				rv = iso_ops_ptr.pin_cmd(card, data, tries_left);
				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
					"Previous: Return from iso7816.c:iso7816_pin_cmd\n");
			}
			break;
		case SC_AC_AUT:
		/* 'AUT' key is the transport PIN and should have reference '0' */
			rv = (data.pin_reference ? SC_ERROR_INVALID_ARGUMENTS : iso_ops_ptr.pin_cmd(card, data, tries_left));
			break;
		case SC_AC_NONE, SC_AC_TERM, SC_AC_PRO, SC_AC_SYMBOLIC, SC_AC_SEN, SC_AC_SCB, SC_AC_IDA, SC_AC_UNKNOWN, SC_AC_NEVER:
			rv = SC_ERROR_INVALID_ARGUMENTS;
			break;
		}
		break;
	case SC_PIN_CMD_CHANGE: /*1*/
		if (data.pin_type == SC_AC_AUT)
			rv = SC_ERROR_INS_NOT_SUPPORTED;
		else
			rv = acos5_64_pin_change(card, data, tries_left);
		break;
	case SC_PIN_CMD_UNBLOCK: /*2*/
		if (data.pin_type != SC_AC_CHV)
			rv = SC_ERROR_INS_NOT_SUPPORTED;
		else {
			/* 1. step: verify the puk */
			/* ISO7816 implementation works */
//			if ((rv = iso_ops_ptr.pin_cmd(card, data, tries_left)) < 0)
//				return rv;

//			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd", "We are about to call acos5_64_pin_unblock_change\n");
			/* 2, step: unblock and change the pin */
			rv = acos5_64_pin_unblock_change(card, data, tries_left);
		}
		break;
	case SC_PIN_CMD_GET_INFO: /*3*/
		rv = acos5_64_pin_get_policy(card, data);//iasecc_pin_get_policy(card, data);
		break;
	}
	
	return rv;//acos5_64_check_sw(card, apdu.sw1, apdu.sw2);
}

private int acos5_64_pin_get_policy(sc_card *card, sc_pin_cmd_data *data)
{
	sc_context* ctx = card.ctx;
	int rv;
	mixin (log!(q{"acos5_64_pin_get_policy"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_get_policy",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_get_policy",
			"returning with: %d\n", rv);
	}
//		data->flags=0;// what shall be done here? Ask for the remaining tries of User PIN
	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, data.pin_reference | 0x80);
	/* send apdu */
	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_get_policy",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (apdu.sw1 != 0x63 || (apdu.sw2 & 0xFFFFFFF0U) != 0xC0)
		return rv=SC_ERROR_INTERNAL;
	rv = SC_SUCCESS;
	if (data.pin_reference < 0x80) {
		data.pin1.len           = 8; /* set to -1 to get pin from pin pad FIXME Must be changed if user has installed a pin pad and wants to use this instead of keyboard */
		data.pin1.min_length    = 4; /* min length of PIN */
		data.pin1.max_length    = 8; /* max length of PIN */
		data.pin1.stored_length = 8; /* stored length of PIN */
		data.pin1.encoding      = SC_PIN_ENCODING_ASCII; /* ASCII-numeric, BCD, etc */
		data.pin1.pad_length    = 0; /* filled in by the card driver */
		data.pin1.pad_char      = 0xFF;
		data.pin1.offset = 5; /* PIN offset in the APDU */
		data.pin1.length_offset = 5;
		data.pin1.length_offset = 0; /* Effective PIN length offset in the APDU */

		data.pin1.max_tries  =  8; /* Used for signaling back from SC_PIN_CMD_GET_INFO */ /* assume: 8 as factory setting; max allowed number of retries is unretrievable with proper file access condition NEVER read */
		data.pin1.tries_left =  apdu.sw2 & 0x0F; /* Used for signaling back from SC_PIN_CMD_GET_INFO */
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_get_policy",
			"Tries left for User PIN : %d\n", data.pin1.tries_left);
	}
	return rv;
}

private int acos5_64_pin_change(sc_card *card, sc_pin_cmd_data *data, int *tries_left)
{
	sc_context* ctx = card.ctx;
	sc_apdu apdu;
	uint reference = data.pin_reference;
	ubyte[0x100] pin_data;
	int rv;

	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change", "called\n");
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
		"Change PIN(ref:%i,type:0x%X,lengths:%i/%i)", reference, data.pin_type, data.pin1.len, data.pin2.len);

	if (!data.pin1.data && data.pin1.len) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"Invalid PIN1 arguments: %d (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (!data.pin2.data && data.pin2.len) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"Invalid PIN2 arguments: %d (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	rv = iso_ops_ptr.pin_cmd(card, data, tries_left); // verifies pin1
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
		"(SC_PIN_CMD_CHANGE) old pin (pin1) verification returned %i", rv);
	if (rv < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"PIN verification error: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (data.pin2.data)
		memcpy(pin_data.ptr /* + data.pin1.len*/, data.pin2.data, data.pin2.len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, reference);
	apdu.data = pin_data.ptr;
	apdu.datalen = /*data.pin1.len + */data.pin2.len;
	apdu.lc = apdu.datalen;

	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	if ((rv = sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"PIN cmd failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (rv <= 0)
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"returning with: %d (%s)\n", rv, sc_strerror(rv));
	else
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"returning with: %d\n", rv);

	return rv;
}

private int acos5_64_pin_unblock_change(sc_card *card, sc_pin_cmd_data *data, int *tries_left)
{
	sc_context* ctx = card.ctx;
	sc_apdu apdu;
	uint reference = data.pin_reference;
	ubyte[0x100] pin_data;
	int rv = SC_SUCCESS;//SC_ERROR_INS_NOT_SUPPORTED;

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change", "called\n");
	if (!data.pin1.data || data.pin1.len==0) { // no puk available or empty
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Invalid PUK arguments: %d (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}
	
	if (data.pin2.data && data.pin2.len>0 && (data.pin2.len < 4 || data.pin2.len > 8)) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Invalid PIN2 length: %d (%s)\n", SC_ERROR_INVALID_PIN_LENGTH, sc_strerror(SC_ERROR_INVALID_PIN_LENGTH));
		return SC_ERROR_INVALID_PIN_LENGTH; 
	}	

	/* Case 3 short APDU, 5 bytes+?: ins=2C p1=00/01 p2=pin-reference lc=? le=00 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, 0x00, reference);
	memcpy(pin_data.ptr, data.pin1.data, data.pin1.len);
	if (!data.pin2.data || data.pin2.len==0) { // do solely unblocking
		apdu.p1 = 0x01;
		apdu.lc = data.pin1.len;
	}
	else { // do unblocking + changing pin (new-pin is in pin2)
//	apdu.p1 = 0x00;
		apdu.lc = data.pin1.len + data.pin2.len;
		memcpy(pin_data.ptr+data.pin1.len, data.pin2.data, data.pin2.len);
	}
	apdu.datalen = apdu.lc;
	apdu.data = pin_data.ptr;

	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	if ((rv = sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Unblock pin cmd failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	
	if (rv <= 0)
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"returning with: %d (%s)\n", rv, sc_strerror(rv));
	else
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"returning with: %d\n", rv);

	return rv;
}

private extern(C) int acos5_64_read_public_key(sc_card* card, uint algorithm, sc_path* path, uint key_reference, uint modulus_length, ubyte** buf, size_t* buflen)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(q{"acos5_64_read_public_key"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_public_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_public_key",
				"returning with: %d\n", rv);
	}

	sc_apdu      apdu;
	immutable(uint)  N = modulus_length/8; /* key modulus_length in byte */
	immutable(ubyte) MHB = cast(ubyte) (N>>8); /* with modulus length N as 2 byte value: Modulus High Byte of N, or its the zero byte for MLB with MSB set */
	immutable(ubyte) MLB = N & 0xFF; /* with modulus length N as 2 byte value: Modulus Low Byte of N */
	ubyte* key_in,  pkey_in;  /* key_in  keeps position; length of internal format:	 5 + 16(e) + N(n/8) */
	ubyte* key_out, pkey_out; /* key_out keeps position; length of asn.1 format:		11 + 16(e) + N(n/8) */
	immutable(uint) le_accumul = N + 21;
	immutable(uint) len_out    = N + 27;
	uint count = 0;

	assert(path != null && buf != null);
	if (algorithm != SC_ALGORITHM_RSA)
		return rv=SC_ERROR_NOT_SUPPORTED;

	rv = sc_select_file(card, path, null);

	/* Case 2 short APDU, 5 bytes: ins=CA p1=xx p2=yy lc=0000 le=00zz */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xCA, 0x00, 0x00);
	apdu.cla = 0x80;
	apdu.resplen = le_accumul;
	apdu.le = le_accumul>SC_READER_SHORT_APDU_MAX_SEND_SIZE ? SC_READER_SHORT_APDU_MAX_SEND_SIZE : le_accumul;
	pkey_in = key_in = cast(ubyte*)malloc(le_accumul);

	while (le_accumul > count && count <= 0xFFFF-apdu.le) {
		apdu.p1   = cast(ubyte) (count>>8);
		apdu.p2   = count & SC_READER_SHORT_APDU_MAX_SEND_SIZE;
		apdu.resp = key_in + count;
		/*sc_log(ctx, "apdu chunk count=%u, p1=%u, p2=%u, le=%lu, apdu.resplen=%lu", count, apdu.p1, apdu.p2, apdu.le, apdu.resplen);*/
		/* send apdu */
		rv = sc_transmit_apdu(card, &apdu);
		if (rv < 0) {
			free(key_in);
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_read_public_key",
				"APDU transmit failed");
			return rv;
		}
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00) {
			free(key_in);
			return rv=SC_ERROR_INTERNAL;
		}
		count += apdu.le;
		if (le_accumul-count < SC_READER_SHORT_APDU_MAX_SEND_SIZE)
			apdu.le = le_accumul-count;
	}

	pkey_out = key_out = cast(ubyte*) malloc(len_out);
	if (key_out == null) {
		free(key_in);
		return rv=SC_ERROR_OUT_OF_MEMORY;
	}

	*pkey_out++ = 0x30;
	*pkey_out++ = 0x82;
	*pkey_out++ = MHB;
	*pkey_out++ = cast(ubyte) (MLB + 23); /*always is < 0xFF */

	*pkey_out++ = 0x02;
	*pkey_out++ = 0x82;
	*pkey_out++ = MHB;
	*pkey_out++ = cast(ubyte) (MLB + 1);
	*pkey_out++ = 0x00; /* include zero byte */

	pkey_in = key_in + 21;
	memcpy(pkey_out, pkey_in, N);
	pkey_out += N;
	*pkey_out++ = 0x02;
	*pkey_out++ = 0x10;
	pkey_in = key_in + 5;
	memcpy(pkey_out, pkey_in, 16);

	*buflen = len_out;
	*buf = key_out;
	rv = SC_SUCCESS;

	free(key_in);
	return rv;
}

private extern(C) int acos5_64_pkcs15_init_card(sc_profile* profile, sc_pkcs15_card* p15card)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_pkcs15_init_card"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_init_card",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_init_card",
				"returning with: %d\n", rv);
	}

	sc_path    path;
	sc_file*   file;
	ubyte[256] rbuf;

	p15card.tokeninfo.flags = SC_PKCS15_TOKEN_PRN_GENERATION /*0| SC_PKCS15_TOKEN_EID_COMPLIANT*/;

	rv = sc_card_ctl(p15card.card, SC_CARDCTL_GET_SERIALNR, rbuf.ptr);

	sc_format_path("3F00", &path);
	rv = sc_select_file(p15card.card, &path, &file);

	if (file)
		sc_file_free(file);

	return rv;
}

private extern(C) int acos5_64_pkcs15_select_pin_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_auth_info*)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_select_pin_reference"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_select_pin_reference",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_select_pin_reference",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_select_pin_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_auth_info*) was called\n");
	return rv; 
}

/*
 * Select a key reference
 */
private extern(C) int acos5_64_pkcs15_select_key_reference(sc_profile*, sc_pkcs15_card* p15card,
			sc_pkcs15_prkey_info* key_info)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_select_key_reference"}, q{"called"})); //
	scope(exit) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_select_key_reference",
			"returning (key reference %i) with: %d (%s)\n", key_info.key_reference, rv, sc_strerror(rv));
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_pkcs15_select_key_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_prkey_info*) returning with argument *key_info:\n");
			writer.formattedWrite("%s", *key_info);
		}
	}
	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_pkcs15_select_key_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_prkey_info*) was called with argument *key_info:\n");
		writer.formattedWrite("%s", *key_info);
	}
	
	/* In authentic PKCS#15 all crypto objects are locals */
//	key_info.key_reference |= ACOS5_64_OBJECT_REF_FLAG_LOCAL;

	if (key_info.key_reference > ACOS5_64_CRYPTO_OBJECT_REF_MAX)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if (key_info.key_reference < ACOS5_64_CRYPTO_OBJECT_REF_MIN)
		key_info.key_reference = ACOS5_64_CRYPTO_OBJECT_REF_MIN;

	return rv=SC_SUCCESS; 
}

/* Generate the private key on card */
private extern(C) int acos5_64_pkcs15_create_key(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_object*)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_create_key"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_create_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_create_key",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_create_key(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_object*) was called\n");
	return rv; 
}

private extern(C) int acos5_64_pkcs15_store_key(sc_profile*, sc_pkcs15_card* p15card,
			sc_pkcs15_object*,
			sc_pkcs15_prkey*)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_store_key"}, q{"called"}));
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_store_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_store_key",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_store_key(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_object*, sc_pkcs15_prkey*) was called\n");
	return rv; 
}

private ubyte encodedRSAbitLen(const uint bitLenDec) pure nothrow @nogc @safe
{
	import std.algorithm.comparison : clamp;
  return  cast(ubyte)((clamp(bitLenDec+8,512U,4096U)/256U)*2U);
}

@safe
unittest {
  import std.stdio;
  writeln("Hallo");
  assert(encodedRSAbitLen( 511) == 0x04);
  assert(encodedRSAbitLen( 512) == 0x04); // defined, lowerLimit
  assert(encodedRSAbitLen( 759) == 0x04);
  assert(encodedRSAbitLen( 767) == 0x06);
  assert(encodedRSAbitLen( 768) == 0x06); // defined
// for each increment in by 256 -> increment by 0x02
  assert(encodedRSAbitLen(3840) == 0x1E); // defined
  assert(encodedRSAbitLen(4095) == 0x20);
  assert(encodedRSAbitLen(4096) == 0x20); // defined, upperLimit
  assert(encodedRSAbitLen(4100) == 0x20);
  writeln("PASSED: encodedRSAbitLen");
}

private int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"new_file"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "new_file",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "new_file",
				"returning with: %d\n", rv);
		version(ENABLE_TOSTRING) {
			writer.put("int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_) is returning with argument **out_:\n");
			if (out_ && *out_)
				writer.formattedWrite("%s", **out_);
		}
	}

	assert(p15object.type == SC_PKCS15_TYPE_PRKEY_RSA);
	assert(otype == SC_PKCS15_TYPE_PRKEY_RSA || otype == SC_PKCS15_TYPE_PUBKEY_RSA);

		version(ENABLE_TOSTRING) {
			writer.put("int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_) called with argument *p15object:\n");
				writer.formattedWrite("%s", *p15object);
		}
	sc_pkcs15_prkey_info* key_info = cast(sc_pkcs15_prkey_info*)p15object.data;
	uint keybits = ((cast(uint)key_info.modulus_length+8U)/256)*256;

	uint structure = 0xFFFFFFFF;
	structure = EFDB.RSA_Key_EF;

	uint modulusBytes = keybits/8; //                                        Read
	sc_file* file = sc_file_new();
	with (file) {
		path = key_info.path;
		if (otype == SC_PKCS15_TYPE_PUBKEY_RSA)
			path.value[path.len-1] &= 0x3F;
		type = SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF;
		ef_structure = EFDB.RSA_Key_EF;
		size = 5 + (otype == SC_PKCS15_TYPE_PRKEY_RSA? modulusBytes/2*5 : modulusBytes+16); // CRT for SC_PKCS15_TYPE_PRKEY_RSA
		id = ub22integral(path.value[path.len-2..path.len]);
	}

	if      (otype == SC_PKCS15_TYPE_PRKEY_RSA)
		rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_READ,       SC_AC_NEVER, SC_AC_KEY_REF_NONE);
	else if (otype == SC_PKCS15_TYPE_PUBKEY_RSA)
		rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_READ,       SC_AC_NONE,  SC_AC_KEY_REF_NONE);

	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_UPDATE,       SC_AC_CHV,   SC_AC_KEY_REF_NONE);
	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_CRYPTO,       SC_AC_CHV,   SC_AC_KEY_REF_NONE);
	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_GENERATE,     SC_AC_CHV,   SC_AC_KEY_REF_NONE);

	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_INVALIDATE,   SC_AC_CHV/*SC_AC_TERM*/,  SC_AC_KEY_REF_NONE);
	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_REHABILITATE, SC_AC_CHV/*SC_AC_PRO*/,   SC_AC_KEY_REF_NONE);
	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_LOCK,         SC_AC_CHV/*SC_AC_SEN*/,   SC_AC_KEY_REF_NONE);
	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_DELETE,       SC_AC_CHV/*SC_AC_SCB*/,   SC_AC_KEY_REF_NONE);

	rv=sc_file_add_acl_entry(file, SC_AC_OP.SC_AC_OP_GENERATE,     SC_AC_CHV,   SC_AC_KEY_REF_NONE);
// The remaining positions are the same for all SAC_table_*
// position 3:  SC_AC_OP_INVALIDATE   //  Deactivate , set by ADMIN
// position 4:  SC_AC_OP_REHABILITATE //  Activate   , set by ADMIN
// position 5:  SC_AC_OP_LOCK         //  Terminate  , set to NEVER
// position 6:  SC_AC_OP_DELETE_SELF  //  Delete Self, set to NEVER

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "new_file",
		"file size %i; ef type %i/%i; id %04X; path_len %i; file path: %s\n",
		file.size, file.type, file.ef_structure, file.id, file.path.len, sc_print_path(&(file.path)));

	*out_ = file;
	return rv=SC_SUCCESS;
}

/** TODO NOT YET FINISHED

pkcs11-tool --module opensc-pkcs11.so -l --keypairgen --key-type rsa:4096 --id 06 --label "Bourne"
Key pair generated:
Private Key Object; RSA 
  label:      Bourne
  ID:         06
  Usage:      decrypt, sign, unwrap
Public Key Object; RSA 4096 bits
  label:      Bourne
  ID:         06
  Usage:      encrypt, verify, wrap

to be used like this, e.g. from p11tool:
user@host:~$ p11tool --generate-rsa --outfile=pbl.txt --label=sunny --bits=4096 --login pkcs11:model=PKCS%2315;manufacturer=Advanced%20Card%20Systems%20Ltd.;serial=YOURSERIALNO;token=CryptoMate64_YOURSERIALNO%20%28User%29
Token 'CryptoMate64_YOURSERIALNO (User)' with URL 'pkcs11:model=PKCS%2315;manufacturer=Advanced%20Card%20Systems%20Ltd.;serial=YOURSERIALNO;token=CryptoMate64_YOURSERIALNO%20%28User%29' requires user PIN
Enter PIN: 
user@host:~$ 


and y'll receive the keypair as per token file location specified in acos5_64.profile and an outfile pbl.txt containing e.g. (TODO content read and shown is wrong, but the new key on card is operational):

-----BEGIN PUBLIC KEY-----
MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgB4O1ymkX8AAHg7XKaRfwAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAABAQAAAAAAAGg8XKaRfwAAaDxcppF/AAA1IDAxIDgwIDgxIDAyIDQx
IDM2IDgwIDAxIDEwIC4iLi4uLi4uLi5BNi4uLgoAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAABBAAAAAAAAAIDdDQEAAAAAqDtcppF/AADw1A4BAAAAACEAAAAAAAAA
eDtcppF/AAB4O1ymkX8AAAIDAQAB
-----END PUBLIC KEY-----

There is a tool to get an outfile=pbl.txt formated for ssh too, TODO which one was it?

opensc does update PrKDF and PukDF accordingly, but requires immense size (~ 0x0250 bytes per public key in PukDF !)

Fill existing internal EF's of RSA priv and pub key with contents by ACOS5-64 command 7.4.4. Generate RSA Key Pair (includes internal testing of gen key pair; if test fails, usage of priv (and pub) key should be prohibited by acos)
and do populate sc_pkcs15_pubkey* p15pubkey
Implementation does omit (complicated way like all other internal drivers do): Routing command and data via function (acos5_64_)card_ctl

*/
private extern(C) int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)
{
	sc_card* card   = p15card.card;
	sc_context* ctx = card.ctx;
	sc_file* file;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_pkcs15_generate_key"}, q{"called"}));
	scope(exit) {
		if (file)
			sc_file_free(file);
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"returning with: %d\n", rv);
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)  is returnung\n");
//			writer.formattedWrite("%s", *profile);
		}
	}
//////////
//	sc_epass2003_gen_key_data gendat;
//	uint                  usage    = key_info.usage; // 14 = SC_PKCS15_PRKEY_USAGE_DECRYPT = 2 | SC_PKCS15_PRKEY_USAGE_SIGN = 4 | SC_PKCS15_PRKEY_USAGE_SIGNRECOVER = 8
//	int fidl = 0;
//  rsa_access_flags  (uint) : 29 from profile: SC_PKCS15_PRKEY_ACCESS_LOCAL | SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE | SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE | SC_PKCS15_PRKEY_ACCESS_SENSITIVE
	sc_pkcs15_prkey_info* key_info = cast(sc_pkcs15_prkey_info*)p15object.data;
	uint keybits = ((cast(uint)key_info.modulus_length+8U)/256)*256;

	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)  called with argument *profile, *p15card, *p15object\n");
		writer.formattedWrite("%s", *profile);
		writer.formattedWrite("%s", *p15card);
		writer.formattedWrite("%s", *p15object); // sc_pkcs15_object* p15object
	}
/////////
	if (p15object.type != SC_PKCS15_TYPE_PRKEY_RSA) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key", "Failed: Only RSA is supported");
		return rv=SC_ERROR_NOT_SUPPORTED;
	}
	/* Check that the card supports the requested modulus length */
	if (sc_card_find_rsa_alg(card, keybits) == null) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key", "Failed: Unsupported RSA key size");
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	}
/* TODO Think about other checks or possibly refuse to genearate keys if file access rights are wrong */

	/* allocate key object */
	if ((rv=new_file(profile, p15card, p15object, SC_PKCS15_TYPE_PRKEY_RSA, &file)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key", "create key: failed to allocate new key object");
		if (file)
			sc_file_free(file);
		return rv;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"private key path: %s", sc_print_path(&file.path));

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"private key_info path: %s", sc_print_path(&(key_info.path)));

	/* delete, if existant */
	if ((rv=sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_DELETE)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key", "generate key: pkcs15init_authenticate(SC_AC_OP_DELETE) failed");
		if (rv == SC_ERROR_FILE_NOT_FOUND) {}
		else {
			if (file)
				sc_file_free(file);
			return rv;
		}
	}
	if (rv != SC_ERROR_FILE_NOT_FOUND)
		rv = sc_delete_file(card, &file.path);

	/* create */
	if ((rv=sc_pkcs15init_create_file(profile, p15card, file)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key", "create key: failed to create private key file on card");
		if (file)
			sc_file_free(file);
		return rv;
	}
/* */
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"Have to generate RSA key pair with keybits %i; ID: %s and path: %s", keybits, sc_pkcs15_print_id(&key_info.id), sc_print_path(&key_info.path));

	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)  with argument *file, *key_info\n");
		writer.formattedWrite("%s", *file);
		writer.formattedWrite("%s", *key_info);
	}

	sc_file* tfile;
	sc_path path = key_info.path;
	path.len -= 2;

	if ((rv=sc_select_file(card, &path, &tfile)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"generate key: no private object DF");
		if (file)
			sc_file_free(file);
		if (tfile)
			sc_file_free(tfile);
		return rv;
	}
	sc_file* pukf;
	if ((rv=new_file(profile, p15card, p15object, SC_PKCS15_TYPE_PUBKEY_RSA, &pukf)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"generate key: create temporary pukf failed\n");
		if (pukf)
			sc_file_free(pukf);
		if (file)
			sc_file_free(file);
		if (tfile)
			sc_file_free(tfile);
		return rv;
	}

//	pukf.size = keybits;
//	pukf.id = pukf.path.value[pukf.path.len - 2] * 0x100
//	    + pukf.path.value[pukf.path.len - 1];

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"public key size %i; ef type %i/%i; id %04X; path: %s",
		 pukf.size, pukf.type, pukf.ef_structure, pukf.id,
		 sc_print_path(&pukf.path));

	/* if exist, delete */
	if ((rv=sc_select_file(p15card.card, &pukf.path, null)) == SC_SUCCESS) {
		if ((rv=sc_pkcs15init_authenticate(profile, p15card, pukf, SC_AC_OP_DELETE)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"generate key - pubkey: pkcs15init_authenticate(SC_AC_OP_DELETE) failed");
			if (pukf)
				sc_file_free(pukf);
			if (file)
				sc_file_free(file);
			if (tfile)
				sc_file_free(tfile);
			return rv;
		}

		if ((rv=sc_pkcs15init_delete_by_path(profile, p15card, &pukf.path)) != SC_SUCCESS) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"generate key: failed to delete existing key file\n");
			if (pukf)
				sc_file_free(pukf);
			if (file)
				sc_file_free(file);
			if (tfile)
				sc_file_free(tfile);
			return rv;
		}
	}
	/* create */
	if ((rv=sc_pkcs15init_create_file(profile, p15card, pukf)) != SC_SUCCESS) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"generate key: pukf create file failed\n");
		if (pukf)
			sc_file_free(pukf);
		if (file)
			sc_file_free(file);
		if (tfile)
			sc_file_free(tfile);
		return rv;
	}

	if ((rv=sc_pkcs15init_authenticate(profile, p15card, pukf, SC_AC_OP_UPDATE)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"generate key - pubkey: pkcs15init_authenticate(SC_AC_OP_UPDATE) failed");
		if (pukf)
			sc_file_free(pukf);
		if (file)
			sc_file_free(file);
		if (tfile)
			sc_file_free(tfile);
		return rv;
	}

//acos5_64_logout(p15card.card);
//acos5_64_finish(p15card.card);


///////////////////
/* TODO file is selected twice (in sc_pkcs15init_authenticate as well) */
	if ((rv=sc_select_file(card, &key_info.path, &file)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"Cannot generate key: failed to select key file");
		return rv;
	}
	if ((rv=sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_GENERATE)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"No authorisation to generate private key");
		if (file)
			sc_file_free(file);
		return rv;
	}
/* Do generate here: */
	{ // set SE for private key usage
		sc_security_env env;
		env.flags = SC_SEC_ENV_FILE_REF_PRESENT;
		env.operation = 5; /*SC_SEC_OPERATION_SIGN*/ // case 5: // my encoding for SC_SEC_GENERATE_RSAKEYS_PRIVATE
		assert(key_info.path.len >= 2);
		env.file_ref.len = 2;
		env.file_ref.value[0..2] = key_info.path.value[key_info.path.len-2..key_info.path.len];
//		env.file_ref.value[1] = key_info.path[key_info.path.len-1];
		if ((rv=acos5_64_set_security_env(card, &env, 0)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"Cannot generate key: failed to set SE for private key file");
			return rv;
		}
	}
	{ // set SE for public key usage; by convention prkey file id's are 41Fx and corresponding pubkey file id's are 413x 
		sc_security_env env;
		env.flags = SC_SEC_ENV_FILE_REF_PRESENT;
		env.operation = 6; /*SC_SEC_OPERATION_SIGN*/ // case 6: // my encoding for SC_SEC_GENERATE_RSAKEYS_PUBLIC
/* TODO how to get public key file id for known private key file id ? */
		env.file_ref.len = 2;
		env.file_ref.value[0..2] = key_info.path.value[key_info.path.len-2..key_info.path.len];
		env.file_ref.value[1] &= 0x3F;
		if ((rv=acos5_64_set_security_env(card, &env, 0)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
				"Cannot generate key: failed to set SE for public key file");
			return rv;
		}
	}

	// 00 46 00 00  02 2004
	ubyte[2] sbuf = [encodedRSAbitLen(keybits), ERSA_Key_type.CRT_for_Decrypting_only]; // always CRT
	if (key_info.usage & SC_PKCS15_PRKEY_USAGE_SIGN)
		sbuf[1] = ERSA_Key_type.CRT_for_Signing_and_Decrypting;

	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0, 0);
	apdu.lc = apdu.datalen = sbuf.length;
	apdu.data = sbuf.ptr;

	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"%s: APDU transmit failed", sc_strerror(rv));
		return rv;
	}

	if ((rv=sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"%s: Card returned error", sc_strerror(rv));
		return rv;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"p15object.type: %04x\n", p15object.type);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"p15object.label: %s\n", p15object.label.ptr);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"p15object.flags: %08x\n", p15object.flags);
	if (p15object.auth_id.value.ptr != null)
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
			"p15object.auth_id.value: %s\n", sc_dump_hex(p15object.auth_id.value.ptr, p15object.auth_id.len));
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_generate_key",
		"keybits: %u\n", keybits);

	/* Keypair generation -> collect public key info */
		if (p15pubkey != null) with (p15pubkey) {
			algorithm = SC_ALGORITHM_RSA;
			u.rsa.modulus.len = keybits / 8;
			u.rsa.modulus.data = cast(ubyte*)malloc(u.rsa.modulus.len);
			ubyte[3] DEFAULT_PUBEXPONENT = [0x01, 0x00, 0x01];
			u.rsa.exponent.len = DEFAULT_PUBEXPONENT.length;
			u.rsa.exponent.data = cast(ubyte*)malloc(DEFAULT_PUBEXPONENT.length);
			memcpy(u.rsa.exponent.data, DEFAULT_PUBEXPONENT.ptr, DEFAULT_PUBEXPONENT.length);

			/* Get public key modulus * /
			r = sc_select_file(card, &file.path, null);
			LOG_TEST_RET(ctx, r, "Cannot get key modulus: select key file failed");

			struct sc_cardctl_myeid_data_obj data_obj;
			data_obj.P1 = 0x01;
			data_obj.P2 = 0x01;
			data_obj.Data = raw_pubkey;
			data_obj.DataLen = sizeof (raw_pubkey);

			r = sc_card_ctl(card, SC_CARDCTL_MYEID_GETDATA, &data_obj);
			LOG_TEST_RET(ctx, r, "Cannot get RSA key modulus: 'MYEID_GETDATA' failed");

			if ((data_obj.DataLen * 8) != key_info.modulus_length)
				LOG_TEST_RET(ctx, SC_ERROR_PKCS15INIT, "Cannot get RSA key modulus: invalid key-size");

			memcpy(pubkey.u.rsa.modulus.data, raw_pubkey, pubkey.u.rsa.modulus.len); */
		}

	return rv=SC_SUCCESS; 
}

/*
 * Encode private/public key
 * These are used mostly by the Cryptoflex/Cyberflex drivers.
 */
private extern(C) int acos5_64_pkcs15_encode_private_key(sc_profile* profile, sc_card* card,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_encode_private_key"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_encode_private_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_encode_private_key",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_encode_private_key(sc_profile* profile, sc_card* card, sc_pkcs15_prkey_rsa*, ubyte* , size_t*, int) was called\n");
	return rv; 
}

private extern(C) int acos5_64_pkcs15_encode_public_key(sc_profile* profile, sc_card* card,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_encode_public_key"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_encode_public_key",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_encode_public_key",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_encode_public_key(sc_profile* profile, sc_card* card, sc_pkcs15_prkey_rsa*, ubyte* , size_t*, int) was called\n");
	return rv; 
}

private extern(C) int acos5_64_pkcs15_delete_object(sc_profile* profile, sc_pkcs15_card* p15card,
			sc_pkcs15_object*, const(sc_path)* path) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_delete_object"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_delete_object",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_delete_object",
				"returning with: %d\n", rv);
	}
	return rv=sc_pkcs15init_delete_by_path(profile, p15card, path);
}

private extern(C) int acos5_64_pkcs15_emu_store_data(sc_pkcs15_card* p15card, sc_profile* profile, sc_pkcs15_object*,
				sc_pkcs15_der*, sc_path*) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_emu_store_data"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_emu_store_data",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_emu_store_data",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_emu_store_data(sc_pkcs15_card* p15card, sc_profile* profile, sc_pkcs15_object*, sc_pkcs15_der*, sc_path*) was called\n");
	return rv; 
}

/**
 * There are a lot of checks that might be tought of as reasonable
 Check reasonable access rights, depending on file type
 Check, that for every pin record, there is a sym key record as well, because they might be forced to cooperate in usage (e.g. in CRT AT, usage 0x88
 Check, that for every sym key record, there is a pin record as well, because they might be forced to cooperate in usage (e.g. in CRT AT, usage 0x88
 Check, if there are non-activated files
 Check, that popcnt of AM equals number of SC bytes, that follow: AM 0x07 and !=3 bytes following is illegal !
 Check if all files (except CHV 0001, 4101, ? SKEY 0002, 4102,  are mentioned in DFs: 
 IMHO, TERMINATE/LOCK doesn't make sense, better DELETE and reuse file space, thus check, that TERMINATE/LOCK is always NEVER
 Check if what the PKCS#15 "managing files" like PrKDF etc. tell about file existance etc, is actually correct:
 E.g. scan card, detect for each DF: PIN file, Sym. Key file, SE file
 Mandatory: EF(Dir) 2F00
  
 Some of the checks are essential, others are my convention: How to handle that, where to put the log?
 etc.
 cards that do sanity check:
 src/pkcs15init/pkcs15-entersafe.c
 src/pkcs15init/pkcs15-epass2003.c
*/
private extern(C) int acos5_64_pkcs15_sanity_check(sc_profile* profile, sc_pkcs15_card* p15card) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_sanity_check"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_sanity_check",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_sanity_check",
				"returning with: %d\n", rv);
	}
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_sanity_check(sc_profile* profile, sc_pkcs15_card* p15card) was called\n");
	return rv; 
}



ubyte[2] integralLastTwo2ub2(size_t integral) {
	ubyte[2] result;
	result[0] = cast(ubyte)((integral >> 8) & 0xFF);
	result[1] = cast(ubyte)( integral       & 0xFF);
	return result;
}

ubyte[4] integralLastFour2ub4(size_t integral) {
	ubyte[4] result;
	result[0] = cast(ubyte)((integral >> 24) & 0xFF);
	result[1] = cast(ubyte)((integral >> 16) & 0xFF);
	result[2] = cast(ubyte)((integral >>  8) & 0xFF);
	result[3] = cast(ubyte)( integral        & 0xFF);
	return result;
}

/** Take a byte stream as coming form the token and convert to an integral value
Most often, the byte stream has to be interpreted as big-endian (The most significant byte (MSB) value, is at the lowest address (position in stream). The other bytes follow in decreasing order of significance)
*/
ushort ub22integral(ubyte[] ub2) { // formerly ub22integralLastTwo
/* TODO make this general : 
ushort ubyte_arr2ushort
uint   ubyte_arr2uint
ulong  ubyte_arr2ulong
auto ubyte_arr2integral(ubyte size)(ubyte[size] ubyte_arr) // allowed sizes: 2,4,8
*/
	if (ub2.length!=2)
		return 0;
	return  (ub2[0] << 8) | ub2[1];
}

//@safe
unittest {
	import std.stdio;
	const integer = 0x01070D13;
	assert(integer == 17_239_315);
//	ubyte[2] integralLastTwo2ub2 (size_t integral)
//	ubyte[4] integralLastFour2ub4(size_t integral)
	ubyte[2] ub2 = [0x41, 0x03];
	assert(ub22integral([0x41, 0x03]) == 16_643);
	writeln("PASSED: ub22integral");

}

version(ENABLE_ACOS5_64_UI/*ENABLE_DNIE_UI*/) {
	/**
	 * To handle user interface routines
	 */
	struct ui_context_t {
		int     user_consent_enabled;
		string  user_consent_app;
	}
//	alias  ui_context_t = ui_context;

	ref ui_context_t get_acos5_64_ui_ctx(sc_card* card) {
		return (cast(acos5_64_private_data*)card.drv_data).ui_ctx;
	}

/** default user consent program (if required) */
string USER_CONSENT_CMD = "/usr/bin/pinentry";

/**
 * Messages used on user consent procedures
 */
immutable(char)* user_consent_title   = "Query for clearance to generate digital signature"; // 
//immutable(char)* user_consent_title   = "Erlaubnisanfrage zur Erstellung digitale Signatur/Unterschrift"; // 

////#ifdef linux
immutable(char)* user_consent_message ="A private RSA-key shall be used for digital signature generation! Do You agree?";
//immutable(char)* user_consent_message ="Ein privater RSA-Schlüssel soll zur Erstellung digitale Signatur/Unterschrift benutzt werden! Stimmen Sie zu?";
//immutable(char)* user_consent_message ="Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?";
////#else
////const char *user_consent_message="Esta a punto de realizar una firma digital\ncon su clave de FIRMA del DNI electronico.\nDesea permitir esta operacion?";
////#endif

private int acos5_64_get_environment(sc_card* card, ui_context_t* ui_context) {
	import scconf.scconf : scconf_block, scconf_find_blocks, scconf_get_str, scconf_get_bool;

	scconf_block** blocks;
	scconf_block*  blk;
	sc_context*    ctx = card.ctx;
	/* set default values */
	ui_context.user_consent_app = USER_CONSENT_CMD;
	ui_context.user_consent_enabled = 1;
	/* look for sc block in opensc.conf */
//	for (int i = 0; ctx.conf_blocks[i]; ++i)
	foreach (elem; ctx.conf_blocks) { // scconf_block*[3] conf_blocks;
		if (elem == null)
			break;
		blocks = scconf_find_blocks(ctx.conf, elem, "card_driver", "acos5_64");
		if (!blocks)
			continue;
		blk = blocks[0];
		free(blocks);
		if (blk == null)
			continue;
		/* fill private data with configuration parameters */
		ui_context.user_consent_app =	/* def user consent app is "pinentry" */
			scconf_get_str (blk, "user_consent_app", USER_CONSENT_CMD.toStringz /*the default*/).fromStringz.idup;
		ui_context.user_consent_enabled =	/* user consent is enabled by default */
			scconf_get_bool(blk, "user_consent_enabled", 1);
	}
	return SC_SUCCESS;
} // acos5_64_get_environment

/**
 * Messages used on pinentry protocol
 */
const(char)*[] user_consent_msgs = ["SETTITLE", "SETDESC", "CONFIRM", "BYE" ];


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
private int acos5_64_ask_user_consent(sc_card* card, const(char)* title, const(char)* message) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_INTERNAL;	/* by default error :-( */
	mixin (log!(q{"acos5_64_ask_user_consent"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent",
				"returning with: %d\n", rv);
	}
// TODO it's currently for Linux only
version(Posix) { // should be for Linux only  #include <sys/stat.h>
	import core.sys.posix.sys.types;
	import core.sys.posix.sys.stat;
	import core.sys.posix.unistd;
	import core.sys.posix.stdio : fdopen;
	import core.stdc.stdio;
	import core.stdc.string : strstr;
//	import core.sys.linux.fcntl;
	pid_t   pid;
	FILE*   fin;
	FILE*   fout;	/* to handle pipes as streams */
	stat_t  st_file;	/* to verify that executable exists */
	int[2]  srv_send;	/* to send data from server to client */
	int[2]  srv_recv;	/* to receive data from client to server */
	char[1024] outbuf;	/* to compose and send messages */
	char[1024] buf;		/* to store client responses */
	int n = 0;		/* to iterate on to-be-sent messages */
}

	string msg;	/* to mark errors */

	if (card == null || card.ctx == null)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if (title==null || message==null)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if (get_acos5_64_ui_ctx(card).user_consent_enabled == 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent", "User Consent is disabled in configuration file");
		return rv=SC_SUCCESS;
	}

	/* check that user_consent_app exists. TODO: check if executable */
	rv = stat(get_acos5_64_ui_ctx(card).user_consent_app.toStringz, &st_file);
	if (rv != 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent",
			"Invalid pinentry application: %s\n", get_acos5_64_ui_ctx(card).user_consent_app.toStringz);
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	}
	/* just a simple bidirectional pipe+fork+exec implementation */
	/* In a pipe, xx[0] is for reading, xx[1] is for writing */
	if (pipe(srv_send) < 0) {
		msg = "pipe(srv_send)";
		goto do_error;
	}
	if (pipe(srv_recv) < 0) {
		msg = "pipe(srv_recv)";
		goto do_error;
	}

	pid = fork();
	switch (pid) {
	case -1:		/* error  */
		msg = "fork()";
		goto do_error;
	case 0:		/* child  */
		/* make our pipes, our new stdin & stderr, closing older ones */
		dup2(srv_send[0], STDIN_FILENO);	/* map srv send for input */
		dup2(srv_recv[1], STDOUT_FILENO);	/* map srv_recv for output */
		/* once dup2'd pipes are no longer needed on client; so close */
		close(srv_send[0]);
		close(srv_send[1]);
		close(srv_recv[0]);
		close(srv_recv[1]);
		/* call exec() with proper user_consent_app from configuration */
		/* if ok should never return */
		execlp(get_acos5_64_ui_ctx(card).user_consent_app.toStringz, get_acos5_64_ui_ctx(card).user_consent_app.toStringz, cast(char*)null);

		rv = SC_ERROR_INTERNAL;
		msg = "execlp() error";	/* exec() failed */
		goto do_error;
	default:		/* parent */
		/* Close the pipe ends that the child uses to read from / write to
		 * so when we close the others, an EOF will be transmitted properly.
		 */
		close(srv_send[0]);
		close(srv_recv[1]);
		/* use iostreams to take care on newlines and text based data */
		fin = fdopen(srv_recv[0], "r");
		if (fin == null) {
			msg = "fdopen(in)";
			goto do_error;
		}
		fout = fdopen(srv_send[1], "w");
		if (fout == null) {
			msg = "fdopen(out)";
			goto do_error;
		}
		/* read and ignore first line */
		fflush(stdin);
		for (n = 0; n<4; n++) {
			char* pt;
			memset(outbuf.ptr, 0, outbuf.sizeof);
			if (n==0) snprintf(outbuf.ptr,1023,"%s %s\n",user_consent_msgs[0],title);
			else if (n==1) snprintf(outbuf.ptr,1023,"%s %s\n",user_consent_msgs[1],message);
			else snprintf(outbuf.ptr,1023,"%s\n",user_consent_msgs[n]);
			/* send message */
			fputs(outbuf.ptr, fout);
			fflush(fout);
			/* get response */
			memset(buf.ptr, 0, buf.sizeof);
			pt=fgets(buf.ptr, buf.sizeof - 1, fin);
			if (pt==null) {
				rv = SC_ERROR_INTERNAL;
				msg = "fgets() Unexpected IOError/EOF";
				goto do_error;
			}
			if (strstr(buf.ptr, "OK") == null) {
				rv = SC_ERROR_NOT_ALLOWED;
				msg = "fail/cancel";
				goto do_error;
			}
		}
	}			/* switch */
	/* arriving here means signature has been accepted by user */
	rv = SC_SUCCESS;
	msg = null;

do_error:
	/* close our channel to force client receive EOF and also die */
	if (fout != null) fclose(fout);
	if (fin != null) fclose(fin);
	if (msg != null)
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent", "%s\n", msg.toStringz);

	return rv;
} // acos5_64_ask_user_consent


} // version(ENABLE_ACOS5_64_UI)

/**
OS2IP converts an octet string to a nonnegative integer.
   Input:  X octet string to be converted

   Output:  x corresponding nonnegative integer

This is usually done by cos for RSA operations
The interpretation of OS2IP's input is that of big-endian 
cos operates the same, expects an octet string `OctetString` where OctetString[0] is the most significant byte (highest importance for value of resulting BIGNUM)
*/
BIGNUM* OS2IP(ubyte[] OctetStringBigEndian)
out (result) { assert(!BN_is_negative(result)); }
body {
	BIGNUM* res = BN_new();
	BIGNUM* a   = BN_new();
	BIGNUM* b   = BN_new();
	if (res == null || a == null || b == null)
		return null;

	BN_zero(res);
	int xLen = cast(int)OctetStringBigEndian.length;
	foreach (i; 0..xLen) {
		/*int*/ BN_set_word(a, OctetStringBigEndian[i]);
		/*int*/ BN_lshift  (b, a, 8*(xLen-1 -i));
		/*int*/ BN_add     (res, res, b);
	}
	BN_free(b);
	BN_free(a);
	return res;
}

/**
OS2IP converts an octet string to a nonnegative integer.
   Input:  X octet string to be converted

   Output:  x corresponding nonnegative integer

This is usually done by cos for RSA operations
The interpretation of OS2IP's input is that of big-endian 
cos operates the same, expects an octet string `OctetString` where OctetString[0] is the most significant byte (highest importance for value of resulting BIGNUM)
*/
ubyte[] /* <-OctetStringBigEndian*/ I2OSP(BIGNUM* x, int xLen /* intended length of the resulting octet string */)

in { assert(!BN_is_negative(x)); }
body {
	ubyte[] res;
	if (BN_num_bytes(x) > xLen)
		return res; //, output "integer too large" and stop.
	foreach (i_chunk; 0..x.top)
		res ~= integralLastFour2ub4(x.d[i_chunk]);

  return res;
}

unittest {
	import std.stdio;
	ubyte[4] os = [0x0A, 0x0B, 0xC0, 0xD0];
	BIGNUM* res = OS2IP(os);
	BN_ULONG dword = BN_get_word(res);
	assert(dword==0x0A0BC0D0);

	writeln("PASSED: OS2IP");
	ubyte[] os2 = I2OSP(res, 4);
	BN_free(res);
	assert(equal(os2, os[]));
	writeln("PASSED: I2OSP");
}
