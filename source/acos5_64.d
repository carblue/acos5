module acos5_64;

import core.stdc.config : c_ulong;
import core.stdc.locale : setlocale, LC_ALL;
import core.stdc.string : memset, memcpy, memcmp, strlen;
import core.stdc.stdlib : realloc, free;
import core.runtime : Runtime;
/*
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
	import sodium.core : sodium_init;
	import sodium.utils : sodium_malloc, sodium_free, sodium_mlock, sodium_mprotect_noaccess, sodium_mprotect_readwrite, sodium_mprotect_readonly;
	import sodium.version_ : sodium_version_string;
}

import libopensc.asn1 : sc_asn1_find_tag;
import libopensc.cardctl : SC_CARDCTL, SC_CARDCTL_GENERIC_BASE, SC_CARDCTL_ERASE_CARD, SC_CARDCTL_GET_DEFAULT_KEY, SC_CARDCTL_LIFECYCLE_GET,
					SC_CARDCTL_GET_SE_INFO, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, SC_CARDCTL_PKCS11_INIT_TOKEN, SC_CARDCTL_PKCS11_INIT_PIN,
					SC_CARDCTL_LIFECYCLE_SET, SC_CARDCTL_GET_SERIALNR;
import libopensc.internal : sc_atr_table;
import libopensc.log : sc_dump_hex, sc_do_log, SC_LOG_DEBUG_NORMAL, log;
import libopensc.opensc;
/+
import acos5_64_h : /*libopenscLoader,*/ SC_CARD_TYPE_ACOS5_64, acos5_64_private_data, DES_KEY_SZ;

version(ENABLE_SM)
	import acos5_64_sm : SM_MODE_TRANSMIT, SM_MODE_ACL, SM_TYPE_CWA14890, SM_SMALL_CHALLENGE_LEN, acos5_64_open, acos5_64_get_wrapped_apdu, acos5_64_free_wrapped_apdu, initialize;
+/
// temporarily as long as preceeding statements are comments :
import libopensc.cards : SC_CARD_TYPE_ACOS5_64;
import libopensc.sm;

import deimos.openssl.des : DES_cblock, const_DES_cblock, DES_KEY_SZ; //, DES_key_schedule, DES_SCHEDULE_SZ /* is not fixed length, as dep. on DES_LONG */, DES_LONG /*c_ulong*/;

struct acos5_64_private_data {
//	sm_cwa_keyset				cwa_keyset;
//uint                sdo_reference;
	ubyte[2*DES_KEY_SZ] card_key2;
	ubyte[2*DES_KEY_SZ] host_key1;
//	sm_cwa_token_data		ifd;
	ubyte[1*DES_KEY_SZ] cwa_session_ifd_sn;
	ubyte[1*DES_KEY_SZ] cwa_session_ifd_rnd;
	ubyte[4*DES_KEY_SZ]	cwa_session_ifd_k;

	ubyte[1*DES_KEY_SZ]	card_challenge; // cwa_session.card_challenge.ptr
}

//////////////////////////////////////////////////

immutable sc_path MF = sc_path( cast(immutable(ubyte)[SC_MAX_PATH_SIZE]) x"3F00 0000000000000000000000000000",
	2, 0, 0, SC_PATH_TYPE_PATH /*all following bytes of aid: zero*/);

private immutable(char)[28]  chip_name      = "ACS ACOS5-64 (CryptoMate64)"; // C-style null-terminated string equivalent, +1 for literal-implicit \0
private immutable(char)[ 9]  chip_shortname = "acos5_64";
private immutable(char)[57]               ATR_colon =                                          "3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00";
//ivate immutable(ubyte)[SC_MAX_ATR_SIZE] ATR       = cast(immutable(ubyte)[SC_MAX_ATR_SIZE]) x"3B BE 96 00 00 41 05 20 00 00 00 00 00 00 00 00 00 90 00"; // FIXME get rid of this, calc from ATR_colon if req.

/* ATR Table list. */
private immutable(sc_atr_table)[2] acos5_64_atrs = [
	sc_atr_table(
		ATR_colon.ptr,
		"FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		chip_shortname.ptr,
		SC_CARD_TYPE_ACOS5_64,
		SC_CARD_FLAG_RNG, // flags
		null),
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
private immutable(char)[7] module_version = "0.15.0";  // uint major = 0, minor = 15, fix = 0;


/* The 3 module exports: */

export extern (C) __gshared immutable(char)* sc_module_version   = module_version.ptr;
export extern (C) __gshared immutable(char)* sc_driver_version() {
	version(FAKE_OPENSC_VERSION) return sc_get_version;
	else                         return module_version.ptr;
}
export extern (C) __gshared immutable(void)* sc_module_init(const(char)* name) { return &sc_get_acos5_64_driver; }


private sc_card_driver* sc_get_acos5_64_driver() {
	enforce(DES_KEY_SZ == SM_SMALL_CHALLENGE_LEN && DES_KEY_SZ== 8,
		"For some reason size [byte] of DES-block and challenge-response (card/host) is not equal and/or not 8 bytes!");

	sc_card_driver* iso_drv  = sc_get_iso7816_driver;
	iso_ops_ptr         = iso_drv.ops; // iso_ops_ptr for initialization and casual use

	acos5_64_ops        = *iso_ops_ptr; // initialize all ops with iso7816_driver's implementations
	with (acos5_64_ops) {
		match_card        = &acos5_64_match_card;
		acos5_64_ops.init = &acos5_64_init;
		finish            = &acos5_64_finish;
/*
		erase_binary      = &acos5_64_erase_binary;
*/
		select_file       = &acos5_64_select_file;
		get_challenge     = &acos5_64_get_challenge;
//	verify            = null; // like in *iso_ops_ptr  this is deprecated
		logout            = &acos5_64_logout;
		list_files        = &acos5_64_list_files;
//	check_sw          = &acos5_64_check_sw; // switch on/off in some cases only
		card_ctl          = &acos5_64_card_ctl;
/*
		pin_cmd           = &acos5_64_pin_cmd;
		process_fci       = &acos5_64_process_fci;
*/
	}
	acos5_64_drv.ops = &acos5_64_ops;
	return &acos5_64_drv;
}

private shared static this() {
	Runtime.initialize;
	setlocale (LC_ALL, "C"); // char* currentlocale =
}

private shared static ~this() {
	Runtime.terminate;
}

// TODO eliminate dep. on memmem in the D way: peel off front
//This function is a GNU extension in glibc: void* memmem(const(void)* haystack, size_t haystacklen, const(void) *needle, size_t needlelen);
extern (C) void* memmem(const(void)* l, size_t l_len, const(void)* s, size_t s_len);

/**
 * Retrieve serial number (6 bytes) from card.
 *
 * @param card pointer to card description
 * @param serial where to store data retrieved
 * @return SC_SUCCESS if ok; else error code
 */
private int acos5_64_get_serialnr(sc_card* card, sc_serial_number* serial) {
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

	if (card == null || card.ctx == null)
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	if (card.type != SC_CARD_TYPE_ACOS5_64)
		return rv=SC_ERROR_INS_NOT_SUPPORTED;

	/* if serial number is cached, use it */
	if (serial && card.serialnr.value.ptr && card.serialnr.len==6) {
		serial.value[0..6] = card.serialnr.value[0..6];
		serial.len    = 6;
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

	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_serialnr",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00 || apdu.resplen!=6)
		return rv=SC_ERROR_INTERNAL;
	/* cache serial number */
	with (card.serialnr) {
		value       = value.init;
		value[0..6] = rbuf[0..6];
		len         = 6;
		if (serial) {
			serial.value[] = value[];
			serial.len     = len;
		}
	}
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_serialnr",
		"Serial Number of Card (EEPROM): '%s'", sc_dump_hex(card.serialnr.value.ptr, card.serialnr.len));
	return rv=SC_SUCCESS;
}

private int missing_match_atr_table(sc_context* ctx, immutable(sc_atr_table)* table, sc_atr* atr)
{ // c source match_atr_table copied, translated to D
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

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missing_match_atr_table", "ATR     : %s", card_atr_hex.ptr);

	for (i = 0; table[i].atr != null; i++) {
		const(char)* tatr = table[i].atr;
		const(char)* matr = table[i].atrmask;
		size_t tatr_len = strlen(tatr);
		ubyte[SC_MAX_ATR_SIZE] mbin, tbin;
		size_t mbin_len, tbin_len, s, matr_len;
		size_t fix_hex_len = card_atr_hex_len;
		size_t fix_bin_len = card_atr_bin_len;

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missing_match_atr_table", "ATR try : %s", tatr);

		if (tatr_len != fix_hex_len) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missing_match_atr_table", "ignored - wrong length");
			continue;
		}
		if (matr != null) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missing_match_atr_table", "ATR mask: %s", matr);

			matr_len = strlen(matr);
			if (tatr_len != matr_len)
				continue;
			tbin_len = tbin.sizeof;
			sc_hex_to_bin(tatr, tbin.ptr, &tbin_len);
			mbin_len = mbin.sizeof;
			sc_hex_to_bin(matr, mbin.ptr, &mbin_len);
			if (mbin_len != fix_bin_len) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "missing_match_atr_table",
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


private int missing_sc_match_atr(sc_card* card, immutable(sc_atr_table)* table, int* type_out)
{ // c source _sc_match_atr copied, translated to D
	int res;

	if (card == null)
		return -1;
	res = missing_match_atr_table(card.ctx, table, &card.atr);
	if (res < 0)
		return res;
	if (type_out != null)
		*type_out = table[res].type;
	return res;
}

private int acos5_64_match_card_checks(sc_card *card) { // regular return value: 0==SUCCESS
	int rv = SC_ERROR_UNKNOWN;
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
	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x05, 0x00);
	apdu.cla = 0x80;

	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	if ((rv=acos5_64_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"SW1SW2 doesn't match 0x9540: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	/* call 7.3.1. Get Card Info Card OS Version */
	immutable(ubyte)[8] vbuf = cast(immutable(ubyte)[8]) x"41434F5305 02 00 40"; // "ACOS 0x05 ...", major vers.=2, minor=0, 0x40 kBytes user EEPROM capacity
	ubyte[8] rbuf;
	apdu = apdu.init;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0x14, 0x06, 0x00);
	with (apdu) {
		cla = 0x80;
		le  =    8;
		resp    = rbuf.ptr;
		resplen = rbuf.sizeof;
	}

	/* send apdu */
	if ((rv=sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return rv=SC_ERROR_INTERNAL;
/*
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
		"rbuf: '%s'", sc_dump_hex(rbuf.ptr, rbuf.sizeof));
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_match_card_checks",
		"vbuf: '%s'", sc_dump_hex(vbuf.ptr, vbuf.sizeof));
*/
	// equality of vbuf and rbuf ==> 0==SC_SUCCESS, 	inequality==> 1*SC_ERROR_NO_CARD_SUPPORT
	if ((rv=SC_ERROR_NO_CARD_SUPPORT*(!equal(rbuf[], vbuf[]))) < 0) {
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
 * @return on card matching 0 if no match; negative return means error
 *
 * Returning error still doesn't stop using this driver.
 * Thus for case "card not matched" another 'killer argument': set card.type to impossible one and rule out in acos5_64_init
 */
private extern (C) int acos5_64_match_card(sc_card *card) { // irregular/special return value: 0==FAILURE
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

	if ((rv=missing_sc_match_atr(card, acos5_64_atrs.ptr, &card.type)) < 0)
		return rv=0;

	return rv=!cast(bool)acos5_64_match_card_checks(card);
}


private extern (C) int acos5_64_init(sc_card *card) {
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_init"}, q{"called"}));
	int rv = SC_ERROR_NO_CARD_SUPPORT;
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"returning with: %d\n", rv);
	}

	int ii;
	for (ii=0; acos5_64_atrs[ii].atr; ++ii)   {
		if (card.type == acos5_64_atrs[ii].type)   {
			card.name    = acos5_64_atrs[ii].name;
			card.flags   = acos5_64_atrs[ii].flags;
			break;
		}
	}

	if (!acos5_64_atrs[ii].atr) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "about to stall this driver (some matching problem)\n");
		return rv=SC_ERROR_NO_CARD_SUPPORT;
	}
	acos5_64_private_data* private_data; // = null;

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

version(USE_SODIUM)
{
	synchronized {
		if (sodium_init == -1) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "sodium_init() returned indicating a failure)\n");
			return rv=SC_ERROR_CARD_CMD_FAILED;
		}
	}
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
		"This module initialized libsodium version: %s\n", sodium_version_string);
	private_data = cast(acos5_64_private_data*) sodium_malloc(acos5_64_private_data.sizeof);
	if (private_data == null)
		return rv=SC_ERROR_MEMORY_FAILURE;
	if ((rv=sodium_mlock(private_data, acos5_64_private_data.sizeof)) < 0) // inhibit swapping sensitive data to disk
		return rv;
	if ((rv=sodium_mprotect_noaccess(private_data)) <0)                    // inhibit access to private_data other than controled one by this library
		return rv;
} // version(USE_SODIUM)

	c_ulong algoflags = 0
						| SC_ALGORITHM_RSA_RAW  /* RSA support */
						| SC_ALGORITHM_RSA_PAD_ISO9796
						| SC_ALGORITHM_RSA_PAD_PKCS1
						| SC_ALGORITHM_RSA_HASH_NONE
						| SC_ALGORITHM_RSA_HASH_SHA1
						| SC_ALGORITHM_RSA_HASH_SHA256
						| SC_ALGORITHM_ONBOARD_KEY_GEN;

	with (*card) {
		caps   = SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC; // c_ulong   we have a random number generator
		cla           = 0x00;  // int      default APDU class (interindustry)
		max_send_size = 0x0FF; // size_t,  Max Lc supported by the card
		max_recv_size = 0x100; // size_t,  Max Le supported by the card, decipher (in chaining mode) with a 4096-bit key returns 2 chunks of 256 bytes each !!

		int missingExport_sc_card_add_rsa_alg(sc_card* card, uint key_length, c_ulong flags, c_ulong exponent)
		{ // same as in opensc, but combined with _sc_card_add_algorithm; both are not exported by libopensc
			sc_algorithm_info info;
//		memset(&info, 0, info.sizeof);
			info.algorithm = SC_ALGORITHM_RSA;
			info.key_length = key_length;
			info.flags = cast(uint)flags;
			info.u._rsa.exponent = exponent;

			sc_algorithm_info* p;
//		assert(info != null);
			p = cast(sc_algorithm_info*) realloc(card.algorithms, (card.algorithm_count + 1) * info.sizeof);
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

		for (uint key_len = 0x0200; key_len <= 0x1000; key_len += 0x0100)
			missingExport_sc_card_add_rsa_alg(card, key_len, algoflags, 0x10001);

		drv_data = private_data; // void*, null if NOT version=USE_SODIUM, garbage collector (GC) not involved
		max_pin_len = 8; // int
		with (cache) { // sc_card_cache
		  // on reset, MF is automatically selected
			current_df = sc_file_new;
			if (current_df == null)
				return rv=SC_ERROR_MEMORY_FAILURE;

			current_df.path = MF;
			valid = 1; // int
		} // with (cache)
		if ((rv=acos5_64_get_serialnr(card, null)) < 0) { // card.serialnr will be stored/cached
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
				"Retrieving ICC serial# failed: %d (%s)\n", rv, sc_strerror(rv));
			return rv;
		}
version(RESTRICTED_SN_TOKEN)
{

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
private extern (C) int acos5_64_finish(sc_card *card) {
	int rv = SC_ERROR_UNKNOWN;
	sc_context* ctx = card.ctx;
	mixin (log!(q{"acos5_64_finish"}, q{"called"})); //
	scope(exit) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_finish",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_finish",
				"returning with: %d\n", rv);
	}

version(USE_SODIUM)
{
	rv = sodium_mprotect_readonly(card.drv_data);
/+
	acos5_64_private_data* private_data = cast(acos5_64_private_data*)card.drv_data;
	acos5_64_se_info*  se_info = private_data.se_info, next;

	while (se_info)   {
		if (se_info->df)
			sc_file_free(se_info->df);
		next = se_info->next;
		free(se_info);
		se_info = next;
	}
+/
	sodium_free(card.drv_data);
	card.drv_data = null;
}
	return rv = SC_SUCCESS;
}

private int acos5_64_select_file_by_path(sc_card* card, const(sc_path) *in_path, sc_file **file_out)
{
/* TODO consolidate this
ACOS's Search Sequence for Target File ID is: current DF -> current DF's children -> current DF's parent ->
current DF's siblings -> MF -> MF's children.
This can be used, if it's reliably known where we are actually before selecting the new path.
Otherwise, take the path as is, and decompose it.
While looping (if necessary), no interest in analyzing FCI, except when we get to the target.
We can't assume, that in_path always starts with 3F00 */
	size_t          in_len = in_path.len;
	const(ubyte) *  in_pos = in_path.value.ptr;
	ubyte *        p = null;
	int  /*result = -1,*/ in_path_complete = 1, diff = 2;
	sc_path path;
	sc_path path_substitute;
	sc_path* p_path = cast(sc_path*)in_path;  /*pointing to in_path or path_substitute*/

	uint file_type = SC_FILE_TYPE_WORKING_EF;

	sc_context* ctx = card.ctx;
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path", "called\n");
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_select_file_by_path"}, q{"called"}));
	scope(exit) { 
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
				"returning with: %d (%s)\n", rv, sc_strerror(rv));
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

	if (!sc_compare_path_prefix(&MF, in_path)) /*incomplete path given for in_path */
		in_path_complete = 0;
	with (*in_path) with (card.cache)  sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
		"starting with card->cache.current_df->path=%s, card->cache.valid=%d, searching: path->len=%lu, path->index=%d, path->count=%d, path->type=%d, file_out=%p",
			sc_print_path(&current_df.path), valid, len, index, count, type, file_out);
	if (card.cache.valid) {
		if (!in_path_complete) {
			with (card.cache)  p = cast(ubyte*)memmem(current_df.path.value.ptr, current_df.path.len, in_path.value.ptr, 2);
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
			/*if card->cache.current_df->path==MF and card->cache.valid and in_path->len ==2*/
			else if (sc_compare_path(&card.cache.current_df.path, &MF) /*&& in_path->len == 2*/) {
				sc_concatenate_path(&path_substitute, &MF, in_path);
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_select_file_by_path",
					"starting with path_substitute=%s (MFprefix)\n", sc_print_path(&path_substitute));
				p_path = &path_substitute;
				in_len = path_substitute.len;
				in_pos = path_substitute.value.ptr;
			}
		}

		with (card.cache) {
		/* Don't need to select if it's other than MF ? */
			if (sc_compare_path(&current_df.path, p_path) &&
				!sc_compare_path(&current_df.path, &MF)) { /*check current DF*/
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
				else if (sc_compare_path_prefix(&MF, p_path) && 4==in_len) {
					in_pos += in_len-2;
					in_len = 2;
				}
			}
		} // with (card.cache)
	} // if (card.cache.valid)

	/* process path components */
	memset(&path, 0, sc_path.sizeof);
	path.type = /*SC_PATH_TYPE.*/SC_PATH_TYPE_FILE_ID;
	path.len = 2;		/* one path component at a time */
	do {
		if (in_len>=4) {
			sc_apdu apdu;
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0, 0);
			with (apdu){
				lc = datalen = 2;
				data = cast(ubyte*)in_pos;
				flags |= SC_APDU_FLAGS_NO_GET_RESP;
			}
			rv = sc_transmit_apdu(card, &apdu) || apdu.sw1 != 0x61;
			/*sc_log(ctx, "rv=%d, apdu.sw1: 0x%02X", rv, apdu.sw1);*/
		}
		if (in_len==2 || rv) {
			memcpy(path.value.ptr, in_pos, 2);
			if (file_out) {
				rv = iso_ops_ptr.select_file(card, &path, file_out);
				if (file_out && *file_out)
					file_type = (**file_out).type;
			}
			else {
				sc_file *file = sc_file_new();
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

	return rv;
}


private extern (C) int acos5_64_select_file(sc_card *card, const(sc_path)* path, sc_file **file_out)
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
private extern (C) int acos5_64_get_challenge(sc_card *card, ubyte * rnd, size_t len)
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
	}
	
	if (len<SM_SMALL_CHALLENGE_LEN || (len%SM_SMALL_CHALLENGE_LEN)) {
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
	memcpy(card.sm_ctx.info.session.cwa.card_challenge.ptr, &rnd[len-SM_SMALL_CHALLENGE_LEN], SM_SMALL_CHALLENGE_LEN);
	memcpy(card.sm_ctx.info.session.cwa.ssc.ptr,            &rnd[len-SM_SMALL_CHALLENGE_LEN], SM_SMALL_CHALLENGE_LEN);
}

	return rv;
}

private extern (C) int acos5_64_logout(sc_card *card)
{
/* ref. manual:
7.2.2.
 Logout
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

	sc_apdu apdu;
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2E, 0x00, 0x81);
	apdu.cla = 0x80;

	if ((rv = sc_transmit_apdu(card, &apdu)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_logout",
			"APDU transmit failed: %d (%s)\n", rv, sc_strerror(rv));
		return rv;
	}	
	
	return rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
}

private extern (C) int acos5_64_list_files(sc_card* card, ubyte* buf, size_t buflen)
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
    ubyte[8] info;

    /*
     * Truncate the scan if no more room left in output buffer.
     */
    if (buflen == 0)
      break;

		apdu = apdu.init;
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

private int acos5_64_check_sw(sc_card *card, uint sw1, uint sw2)
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
	else if (sw1 == 0x95U && sw2 == 0x40U)
		return rv=SC_SUCCESS;
	/* iso error */
	return rv=iso_ops_ptr.check_sw(card, sw1, sw2);
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
private extern (C) int acos5_64_card_ctl(sc_card* card, c_ulong request, void* data) {
	if (card == null || card.ctx == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_INS_NOT_SUPPORTED;
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
				,SC_CARDCTL_GET_SE_INFO, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, SC_CARDCTL_PKCS11_INIT_TOKEN, SC_CARDCTL_PKCS11_INIT_PIN:
		break;
	case SC_CARDCTL_LIFECYCLE_SET: // SC_CARDCTRL_LIFECYCLE_ADMIN int lcycle
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
			"request=SC_CARDCTL_LIFECYCLE_SET with *data: %d\n", *(cast(int*)data));
		rv = SC_ERROR_NOT_SUPPORTED; // FIXME change that when known, what is the intent/meaning; there are some commands to manage life cycle:
		/*
		7.3.4.  Change Life Cycle; This command changes the cards life cycle. See Section 3.1. (otherwise undocumented)
		7.3.5.  Activate Card;     This command changes activates the card. The life cycle stage will be the User Stage.
		7.3.6.  Deactivate Card;   This command changes deactivates the card. The life cycle stage will go back to the Personalization Stage. See Section 3.1 for card life cycle stages.

		I assume:
enum {
	SC_CARDCTRL_LIFECYCLE_ADMIN,  <- refers to Personalization Stage
	SC_CARDCTRL_LIFECYCLE_USER,   <- refers to User Stage
	SC_CARDCTRL_LIFECYCLE_OTHER   <- refers to all the other stages (Manufacturer Stage || Transport Stage 1 || Issuer Stage || Transport Stage 2)
};
		*/
		break;
	case SC_CARDCTL_GET_SERIALNR: /* call card to obtain serial number */
		rv = acos5_64_get_serialnr(card, cast(sc_serial_number*) data);
		break;
	}

	return rv;
}


version(REINITIALIZE)
{
	struct reinit_entry {
		immutable(c_ulong)  flags;
		immutable(int)      cse;
		immutable(ubyte)    cmd_len; // temporarily, to check correct length of apdu
		immutable(ubyte)[]  cmd;
		immutable(ubyte)[]  sw1sw2Response; //expected_response;
		//immutable bool      no_expectation;
		@disable this(this);  // disabling makes reinit_entry non-copyable
	}

} // version(REINITIALIZE)

