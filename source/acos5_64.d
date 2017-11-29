/*
 *   acos5_64.d  OpenSC support for ACOS5-64 smart cards/USB token.
 *
 *   Copyright (C) 2017  Carsten Blüggel <carblue@geekmail.de>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation,
 *   version 2.1 of the License.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.

 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1335
 *   USA
 */


module acos5_64;

import core.stdc.config : c_ulong;
import core.stdc.locale : setlocale, LC_ALL;
import core.stdc.string : memset, memcpy, memcmp, memmove, strlen/*, strcasecmp*/;
import core.stdc.stdlib : realloc, free, malloc, calloc;//, strtol;

import std.conv : to;
import core.exception : AssertError;
import std.exception : enforce, assumeUnique, assertNotThrown, assertThrown;
import std.stdio : stdout, stderr, writeln, writefln, File, snprintf, fprintf, printf;
import std.string : toStringz, fromStringz, lastIndexOf, CaseSensitive, representation, strip;
import std.format;
import std.range : take, retro, dropExactly, repeat, iota;
import std.array;
import std.regex;
import std.traits : EnumMembers;
import std.typecons : Tuple;


version(GNU) { // gdc compiler
	import std.algorithm : min, max, clamp, equal, find, canFind, countUntil, any, mismatch, commonPrefix;
//import gcc.attribute;
}
else { // DigitalMars or LDC compiler
	import std.algorithm.iteration : fold;
	import std.algorithm.comparison : min, max, clamp, equal, mismatch;
	import std.algorithm.searching : /*count,*/ find, canFind, countUntil, any /*,all*/, commonPrefix;
	import std.algorithm.mutation: reverse;
}

version(Windows)  {
version(unittest) {}
else {
	import core.sys.windows.dll : SimpleDllMain;
	mixin SimpleDllMain;
}
}


/* import OpenSC */
import libopensc.asn1 : sc_asn1_find_tag, sc_asn1_put_tag, sc_asn1_entry, sc_copy_asn1_entry, SC_ASN1_OCTET_STRING, SC_ASN1_CTX, SC_ASN1_OPTIONAL,
	sc_format_asn1_entry, sc_asn1_decode, SC_ASN1_PRESENT, SC_ASN1_UNI;
import libopensc.cardctl : SC_CARDCTL, SC_CARDCTL_GENERIC_BASE, SC_CARDCTL_ERASE_CARD, SC_CARDCTL_GET_DEFAULT_KEY, SC_CARDCTL_LIFECYCLE_GET,
					SC_CARDCTL_GET_SE_INFO, SC_CARDCTL_GET_CHV_REFERENCE_IN_SE, SC_CARDCTL_PKCS11_INIT_TOKEN, SC_CARDCTL_PKCS11_INIT_PIN,
					SC_CARDCTL_LIFECYCLE_SET, SC_CARDCTL_GET_SERIALNR,
					SC_CARDCTRL_LIFECYCLE, SC_CARDCTRL_LIFECYCLE_ADMIN, SC_CARDCTRL_LIFECYCLE_USER, SC_CARDCTRL_LIFECYCLE_OTHER, sc_cardctl_pkcs11_init_token,
					sc_cardctl_pkcs11_init_pin, SC_CARDCTL_ACS_BASE, SC_CARDCTL_ACS_GENERATE_KEY;

import libopensc.internal : sc_atr_table;

import libopensc.log : sc_dump_hex, sc_do_log, SC_LOG_DEBUG_NORMAL, log;
import libopensc.opensc; // sc_format_path, SC_ALGORITHM_RSA, sc_print_path, sc_file_get_acl_entry
import libopensc.types; // : sc_path, sc_atr, sc_file, sc_serial_number, SC_MAX_PATH_SIZE, SC_PATH_TYPE_PATH, sc_apdu, SC_AC_OP_GENERATE;
import libopensc.errors;
import scconf.scconf : scconf_block, scconf_find_blocks, scconf_get_str, scconf_get_bool;
import libopensc.iso7816;

import libopensc.cards : SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3;
import libopensc.sm;

import libopensc.pkcs15 : sc_pkcs15_card, sc_pkcs15_object, sc_pkcs15_pubkey, SC_PKCS15_TOKEN_PRN_GENERATION, sc_pkcs15_prkey_info, sc_pkcs15_print_id, SC_PKCS15_TYPE_PRKEY_RSA, SC_PKCS15_TYPE_PUBKEY_RSA,
	sc_pkcs15_prkey, sc_pkcs15_der, sc_pkcs15_auth_info, SC_PKCS15_PRKEY_USAGE, SC_PKCS15_TYPE_CLASS_MASK, sc_pkcs15_prkey_rsa, sc_pkcs15_pubkey_rsa,
	sc_pkcs15_bignum, sc_pkcs15_encode_pubkey_rsa;
import pkcs15init.pkcs15init : /*sc_profile,*/ sc_pkcs15init_operations, sc_pkcs15init_authenticate, sc_pkcs15init_delete_by_path, sc_pkcs15init_create_file, SC_PKCS15INIT_SO_PIN, SC_PKCS15INIT_USER_PIN;
import pkcs15init.profile : file_info, sc_profile/*, sc_profile_get_file*/;


import deimos.openssl.des : DES_cblock, const_DES_cblock, DES_KEY_SZ; //, DES_key_schedule, DES_SCHEDULE_SZ /* is not fixed length, as dep. on DES_LONG */, DES_LONG /*c_ulong*/;
import deimos.openssl.bn;
import deimos.openssl.conf;
import deimos.openssl.evp;
import deimos.openssl.err : ERR_free_strings;
import deimos.openssl.rand : RAND_bytes;


//from acos5_64_h
// default/factory setting values are 0, i.e. eACOSV2MODE_V2 for card.type==SC_CARD_TYPE_ACOS5_64_V2; eACOSV3MODE_V3_FIPS_140_2L3 for card.type==SC_CARD_TYPE_ACOS5_64_V3
enum EACOSV2MODE : ubyte {      // see Reference Manual
		 eACOSV2MODE_V2,              // = 0, V2: 64K Mode is the Version 2 ACOS5-64 default mode; card.type and mode together determine cos's capabilities, e.g. SC_CARD_TYPE_ACOS5_64_V3 can SM pin_verify, SC_CARD_TYPE_ACOS5_64_V2 can't
		 eACOSV2MODE_V1_Emulated_32K, // = 1, V2: 32K Mode is very similar to the ACOS5 (V1?); just for completeness, not supported here
}
mixin FreeEnumMembers!EACOSV2MODE;

enum EACOSV3MODE : ubyte {      // see Reference Manual
		 eACOSV3MODE_V3_FIPS_140_2L3, // = 0  V3: FIPS 140-2 Level 3–Compliant Mode
		 eACOSV3MODE_V1_Emulated_32K, // = 1, V3: Emulated 32K Mode is very similar to the ACOS5 (V1?); just for completeness, not supported here
		 eACOSV3MODE_V2,              // = 2, V3: Non-FIPS 64K Mode is very similar to the Version 2 ACOS5-64 default mode; card.type and mode together determine cos's capabilities, e.g. SC_CARD_TYPE_ACOS5_64_V3 can SM pin_verify, SC_CARD_TYPE_ACOS5_64_V2 can't
		 eACOSV3MODE_V3_NSH_1 = 16,   //      V3: NSH-1 Mode
}
mixin FreeEnumMembers!EACOSV3MODE;


enum ACOS5_64_OBJECT_REF_FLAG_LOCAL = 0x80; // from authentic.h
enum ACOS5_64_CRYPTO_OBJECT_REF_MIN	= 0x01; // 0x81;
enum ACOS5_64_CRYPTO_OBJECT_REF_MAX	= 0x0F; // 0xFF;

enum ERSA_Key_type : ubyte {
	Public_Key                          = 0, // Public Key

	Standard_for_Signing_only           = 1, // Private non-CRT key capable of RSA Private Key Sign (only)       // not for FIPS
	Standard_for_Decrypting_only        = 2, // Private non-CRT key capable of RSA Private Key Decrypt (only)    // not for FIPS
	Standard_for_Signing_and_Decrypting = 3, // Private non-CRT key capable of RSA Private Key Sign and Decrypt  // not for FIPS

	CRT_for_Signing_only                = 4, // Private     CRT key capable of RSA Private Key Sign (only)
	CRT_for_Decrypting_only             = 5, // Private     CRT key capable of RSA Private Key Decrypt (only)
	CRT_for_Signing_and_Decrypting      = 6, // Private     CRT key capable of RSA Private Key Sign and Decrypt
}

enum EFDB : ubyte {
// Working EF:
	Transparent_EF     = SC_FILE_EF.SC_FILE_EF_TRANSPARENT,     // 1,
	Linear_Fixed_EF    = SC_FILE_EF.SC_FILE_EF_LINEAR_FIXED,    // 2,
	Linear_Variable_EF = SC_FILE_EF.SC_FILE_EF_LINEAR_VARIABLE, // 4,
	Cyclic_EF          = SC_FILE_EF.SC_FILE_EF_CYCLIC,          // 6,  rarely used
	// Internal EF:
	RSA_Key_EF         = 0x09,  // ==  8+Transparent_EF,  not record based ( Update Binary )
	// There can be a maximum of 0x1F Global PINs, 0x1F Local PINs, 0x1F Global Keys, and 0x1F Local Keys at a given time. (1Fh==31)
	CHV_EF             = 0x0A,  // ==  8+Linear_Fixed_EF,     record based ( Update Record ) DF or MF shall contain only one CHV file. Every record in the CHV file will have a fixed length of 21 bytes each
	Sym_Key_EF         = 0x0C,  // ==  8+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall contain only one sym file. Every record in the symmetric key file shall have a maximum of 37 bytes
	Purse_EF           = 0x0E,
	// Proprietary EF:
	SE_EF    	         = 0x1C,  // ==18h+Linear_Variable_EF,  record based ( Update Record ) DF or MF shall use only one SE File. An SE file can have up to 0x0F identifiable records. (0Fh==15)
	// DF types:
	DF                 = ISO7816_FILE_TYPE_DF, //0x38,  // == 0b0011_1000; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
	MF                 = 0x3F,  // == 0b0011_1111; common DF type mask == DF : (file_type_in_question & DF) == DF for this enum
}
mixin FreeEnumMembers!EFDB;

ubyte iEF_FDB_to_structure(EFDB FDB) { auto result = cast(ubyte)(FDB & 7); if (result>0 && result<7) return result; else return 0; }

/*
   DigestInfo ::= SEQUENCE {
     digestAlgorithm DigestAlgorithmIdentifier,
     digest Digest
   }
In the following naming, digestInfoPrefix is everything from the ASN1 representaion of DigestInfo, except the trailing digest bytes
*/
enum DigestInfo_Algo_RSASSA_PKCS1_v1_5 : ubyte  { // contents from RFC 8017 are examples, some not recommended for new apps, some in specific schemes; SHA3 not yet mentioned in RFC 8017
/*
	id_rsassa_pkcs1_v1_5_with_md2,        // md2WithRSAEncryption, // id_md2, not recommended
	id_rsassa_pkcs1_v1_5_with_md5,        // md5WithRSAEncryption, // id_md5, not recommended
*/
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
/*
version(X86_64) {
id_rsassa_pkcs1_v1_5_with_blake2b160, // https://tools.ietf.org/html/rfc7693
id_rsassa_pkcs1_v1_5_with_blake2b256,
id_rsassa_pkcs1_v1_5_with_blake2b384,
id_rsassa_pkcs1_v1_5_with_blake2b512,
}
else {
id_rsassa_pkcs1_v1_5_with_blake2s128,
id_rsassa_pkcs1_v1_5_with_blake2s160,
id_rsassa_pkcs1_v1_5_with_blake2s224,
id_rsassa_pkcs1_v1_5_with_blake2s256,
}
*/
	id_rsassa_pkcs1_v1_5_maxcount_unused // usefull as excluded limit in .min .. .max
}
mixin FreeEnumMembers!DigestInfo_Algo_RSASSA_PKCS1_v1_5;

enum Usage {
	/* HT */
	None,
	/* AT 1*/
	Pin_Verify_and_SymKey_Authenticate,
	SymKey_Authenticate,
	Pin_Verify,
	/* DST 4*/
	Sign_PKCS1_priv,  // algo (10) can be infered; the key type RSA priv. must match what is stored in FileID parameter
	Verify_PKCS1_pub, // algo (10) can be infered; the key type RSA publ. must match what is stored in FileID parameter
	Sign_9796_priv,   // algo (11) can be infered; the key type RSA priv. must match what is stored in FileID parameter
	Verify_9796_pub,  // algo (11) can be infered; the key type RSA publ. must match what is stored in FileID parameter
	/* CT_asym 8*/
	Decrypt_PSO_priv,
	Decrypt_PSO_SMcommand_priv,
	Decrypt_PSO_SMresponse_priv,
	Decrypt_PSO_SMcommandResponse_priv,
	Encrypt_PSO_pub,
	Encrypt_PSO_SMcommand_pub,
	Encrypt_PSO_SMresponse_pub,
	Encrypt_PSO_SMcommandResponse_pub,
//		CT_asym: UQB_Possible(0xFF, [0x40/*PSO*/, 0x50/*PSO+SM in Command Data*/, 0x60/*PSO+SM in Response Data*/, 0x70/*PSO+SM in Command and Response Data*/]),
	/* CT_sym */

	/* CCT 16*/
	Session_Key_SM,
	Session_Key,
	Local_Key1_SM,
	Local_Key1,
}
mixin FreeEnumMembers!Usage;

struct cache_current_df_se_info {
	ub8       sac;     /* SAC as preprocessed by read_8C_SAC_Bytes_to_ub8SC, always 8 bytes sac_len */
	ubyte[32] sae;     /* SAE Security Attributes Expanded */
	uint      sae_len; /* sae length used */
	int       fdb;     /* FileDescriptorByte */
	ub2       fid;
	ub2       seid;
	ubyte     NOR; /* if applicable: Number Of Records */
	ubyte     MRL; /* if applicable: Max. Record Length */
}

struct acos5_64_private_data {
	acos5_64_se_info*   pse_info;      // gesetzt in int acos5_64_se_set_cached_info/iasecc_se_cache_info(sc_card* card, acos5_64_se_info* se)
	ubyte[2*DES_KEY_SZ] card_key2;
	ubyte[2*DES_KEY_SZ] host_key1;
//	sm_cwa_token_data		ifd;
	ubyte[  DES_KEY_SZ] cwa_session_ifd_sn;
	ubyte[  DES_KEY_SZ] cwa_session_ifd_rnd;
	ubyte[4*DES_KEY_SZ]	cwa_session_ifd_k;

	ubyte[  DES_KEY_SZ]	card_challenge; // cwa_session.card_challenge == cwa_session.icc.rnd
	/* it's necessary to know, whether a call to function acos5_64_decipher originated from function acos5_64_compute_signature or not.
	 * call_to_compute_signature_in_progress is set to true, when function acos5_64_compute_signature is entered, and reset to false when returning.
	 */
	bool call_to_compute_signature_in_progress;

	sc_security_env              security_env; // gesetzt in int acos5_64_set_security_env(struct sc_card *card, const struct sc_security_env *env, int se_num), genutzt z.B. für iasecc_compute_signature*

	cache_current_df_se_info  current_df_se_info; /* Holds information about the current security environment, depending on valid sc_file*: cache.current_df*/

version(ENABLE_ACOS5_64_UI)
	 ui_context_t           ui_ctx;
}

enum /*BlockCipherModeOfOperation*/ {
	ECB,
	CBC,
	DAC, /* usage in encrypt_algo must pass DAC and desired DAC_length;  acos does CBC-MAC like in withdrawn FIPS PUB 113, but with TDES instead of DES, with an IV!=0 and DAC-length is 4 bytes  */
	// more? ,
	blockCipherModeOfOperation_maxcount_unused // usefull as excluded limit in .min .. .max
}

enum SubDO_Tag : ubyte {
	Algorithm                = 0x80, /* L=1 */

	KeyFile_RSA              = 0x81, /* L=2 */
	// or
	ID_Pin_Key_Local_Global  = 0x83, /* L=1 */
	HP_Key_Session           = 0x84, /* L=0;  High Priority: If this is present, ID_Pin_Key_Local_Global will be ignored (if present too) */
	Initial_Vector           = 0x87, /* L=8 or 16 (CBC !) */

	UQB                      = 0x95, /* L=1;  Usage Qualifier Byte */
}
mixin FreeEnumMembers!SubDO_Tag;

ubyte SubDO_Tag_len(SubDO_Tag tag /*, int algo=0*/) {
	final switch (tag) {
		case Algorithm:                return 1;
		case KeyFile_RSA:              return 2;
		case ID_Pin_Key_Local_Global:  return 1;
		case HP_Key_Session:           return 0;
		case Initial_Vector:           return 8;
		case UQB:                      return 1;
	}
}

struct CRT_Tags {
	SubDO_Tag[] mandatory_And;
	SubDO_Tag[] mandatory_OneOf;
	SubDO_Tag[] optional_SymKey; // only for sym.Key, i.e. ID_Pin_Key_Local_Global or HP_Key_Session: the Initial_Vector may be required or not
}

struct Algorithm_Possible {
	uba list;
}
struct UQB_Possible {
	ubyte   mask;
	uba list;
}
struct ID_Pin_Key_Local_Global_Possible {
	ubyte   mask;
	uba list;
}

enum CRT_TAG : ubyte {
	HT      = 0xAA,   // Hash Template                 : AND:      Algorithm
	AT      = 0xA4,   // Authentication Template       : AND: UQB, Pin_Key,
	DST     = 0xB6,   // Digital Signature Template    : AND: UQB, Algorithm, KeyFile_RSA
	CT_asym = 0xB8+1, // Confidentiality Template      : AND: UQB, Algorithm       OR: KeyFile_RSA
	CT_sym  = 0xB8+0, // Confidentiality Template      : AND: UQB, Algorithm       OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
	CCT     = 0xB4,   // Cryptographic Checksum Templ. : AND: UQB, Algorithm  ;    OR: ID_Pin_Key_Local_Global, HP_Key_Session  ; OPT: Initial_Vector
	NA      = 0x00,   // N/A unknown
}
mixin FreeEnumMembers!CRT_TAG;

enum SMDO_Tag : ubyte { // Secure Messaging Data Object Tags
	Plain_Value                                           = 0x81, // Length variable
	Padding_content_indicator_byte_followed_by_cryptogram = 0x87, // Length variable
	Command_header_SMCLA_INS_P1_P2                        = 0x89, // Length = 4
	Cryptographic_Checksum                                = 0x8E, // Length = 4
	Original_P3_in_an_ISO_OUT_command                     = 0x97, // Length = 1
	Processing_status_word_SW1SW2_of_the_command          = 0x99, // Length = 2
}
mixin FreeEnumMembers!SMDO_Tag;

enum SM_Extend {
	SM_CCT,
	SM_CCT_AND_CT_sym
}
mixin FreeEnumMembers!SM_Extend;

enum {
//ACS_ACOS5____V1, // v1.00: Smart Card/CryptoMate
	ACS_ACOS5_64_V2, // v2.00: Smart Card/CryptoMate64
	ACS_ACOS5_64_V3, // v3.00: Smart Card/CryptoMate Nano
	// insert here
	ATR_zero,
	ATR_maxcount_unused,
}

alias  uba        = ubyte[];
alias  ub2        = ubyte[2];
alias  ub4        = ubyte[4];
alias  ub8        = ubyte[8];
alias  ub16       = ubyte[16];
alias  ub24       = ubyte[24];
//ias iub8        = immutable(ubyte)[8];
alias iuba        = immutable(ubyte)[];

alias TSMarguments = Tuple!(
	 int,       "cse_plain"     /* APDU case before wrapping*/
	,SM_Extend, "sm_extend"     /*  */
	,uba,       "cla_ins_p1_p2" /*  */
	,ubyte*,    "key_enc"
	,ubyte*,    "key_mac"
	,ub8,       "ssc_iv"
	,ubyte,     "p3"
	,uba,       "cmdData"
);


//////////////////////////////////////////////////
/*
 * Attention: All mixin templates expect "some" symbol(s) to be available when instantiating, like e.g. for transmit_apdu: ctx, card, apdu
*/
mixin template transmit_apdu(alias functionName) {
	int transmit_apdu_do(int line=__LINE__) {
		int rv_priv;
		if ((rv_priv=sc_transmit_apdu(card, &apdu)) < 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"APDU transmit failed\n");
		return rv_priv;
	}
}

mixin template transmit_apdu_strerror(alias functionName) {
	int transmit_apdu_strerror_do(int line=__LINE__) {
		int rv_priv;
		if ((rv_priv=sc_transmit_apdu(card, &apdu)) < 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"APDU transmit failed: %i (%s)\n", rv_priv, sc_strerror(rv_priv));
		return rv_priv;
	}
}

mixin template transmit_rapdu_strerror(alias functionName) {
	int transmit_rapdu_strerror_do(int line=__LINE__) {
		int rv_priv;
		if ((rv_priv=sc_transmit_apdu(card, &rapdu.apdu)) < 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"r-APDU transmit failed: %i (%s)\n", rv_priv, sc_strerror(rv_priv));
		return rv_priv;
	}
}

mixin template alloc_rdata_rapdu(alias functionName) {
	int alloc_rdata_rapdu_do(int line=__LINE__) {
		int rv_priv;
		if ((rv_priv=rdata.alloc(rdata, &rapdu)) < 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"cannot allocate remote APDU");
		return rv_priv;
	}
}

mixin template log_scope_exit(alias functionName) {
	void log_scope_exit_do(int line=__LINE__) {
		if (rv <= 0)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"returning with: %i (%s)\n", rv, sc_strerror(rv));
		else
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, functionName,
				"returning with: %i\n", rv);
	}
}

mixin template file_add_acl_entry() {
	void file_add_acl_entry_do(int offs, int line=__LINE__) {
		if (op == 0xFF) {}
		else if ( info.sac[offs] == 0)
			sc_file_add_acl_entry(file, op, SC_AC.SC_AC_NONE, 0);
		else if ( info.sac[offs] == 0xFF)
			sc_file_add_acl_entry(file, op, SC_AC.SC_AC_NEVER, 0);
		else if ( canFind(iota(1,15), info.sac[offs] & 0x0F))     { // [1, 14]
			if      (info.sac[offs] & 0x40) // SM
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_PRO, 0);
			else if (info.sac[offs] & 0x80) {} // FIXME
			int Ref;
			if      ((Ref=acos5_64_se_get_reference(card, info.sac[offs] & 0x0F, sc_crt(CRT_TAG.AT, 0x08))) > 0)
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_CHV, Ref);
			else if ((Ref=acos5_64_se_get_reference(card, info.sac[offs] & 0x0F, sc_crt(CRT_TAG.AT, 0x80))) > 0)
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_AUT, Ref);
			else if ((Ref=acos5_64_se_get_reference(card, info.sac[offs] & 0x0F, sc_crt(CRT_TAG.AT, 0x88))) > 0) {
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_CHV, Ref);
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_AUT, Ref);
			}
			else {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, "acos5_64_process_fci",
					"Warning: A SE-record without Authentication Template AT is referenced: %X; SC_AC_NEVER was set", info.sac[offs]);
				sc_file_add_acl_entry(file, op, SC_AC.SC_AC_NEVER, 0);
			}
			version(none /*ENABLE_TOSTRING*/) {
				sc_acl_entry* e = cast(sc_acl_entry*)sc_file_get_acl_entry(file, op);
				e.crts = /*(sc_crt[SC_MAX_CRTS_IN_SE])*/ e.crts.init; // there seems to be garbage in crts
				while (e.next) {
					e = e.next;
					e.crts = e.crts.init;
				}
			}
		}
		else {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, line, "acos5_64_process_fci",
				"Warning: non supported SCB method: %X", info.sac[offs]);
			sc_file_add_acl_entry(file, op, SC_AC.SC_AC_NEVER, 0);
		}
	} // file_add_acl_entry_do
}

//////////////////////////////////////////////////

struct DI_data { // DigestInfo_data
	string  hashAlgorithmOID;
	ubyte   hashAlgorithmName; // it's enum value is the index in DI_table
	ubyte   hashLength;
	ubyte   digestInfoLength;
	bool    allow;
	bool    compute_signature_possible_without_rawRSA;
	iuba    digestInfoPrefix;
}

immutable(DI_data[]) DI_table = [ // DigestInfo_table
/*
	{ "1.2.840.113549.2.2",      id_rsassa_pkcs1_v1_5_with_md2,        16, 34, false, false, representation(x"30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10")},
	{ "1.2.840.113549.2.5",      id_rsassa_pkcs1_v1_5_with_md5,        16, 34, false, false, representation(x"30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10")},
*/
	{ "1.3.14.3.2.26",           id_rsassa_pkcs1_v1_5_with_sha1,       20, 35, true,  true,  representation(x"30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14")},

	{ "2.16.840.1.101.3.4.2.4",  id_rsassa_pkcs1_v1_5_with_sha224,     28, 47, true,  false, representation(x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04 05 00 04 1c")},
	{ "2.16.840.1.101.3.4.2.1",  id_rsassa_pkcs1_v1_5_with_sha256,     32, 51, true,  true,  representation(x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")},
	{ "2.16.840.1.101.3.4.2.2",  id_rsassa_pkcs1_v1_5_with_sha384,     48, 67, true,  false, representation(x"30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30")},
	{ "2.16.840.1.101.3.4.2.3",  id_rsassa_pkcs1_v1_5_with_sha512,     64, 83, true,  false, representation(x"30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40")},
	{ "2.16.840.1.101.3.4.2.5",  id_rsassa_pkcs1_v1_5_with_sha512_224, 28, 47, true,  false, representation(x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 05 05 00 04 1c")},
	{ "2.16.840.1.101.3.4.2.6",  id_rsassa_pkcs1_v1_5_with_sha512_256, 32, 51, true,  false, representation(x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 06 05 00 04 20")},

	{ "2.16.840.1.101.3.4.2.7",  id_rsassa_pkcs1_v1_5_with_sha3_224,   28, 47, true,  false, representation(x"30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 07 05 00 04 1c")},
	{ "2.16.840.1.101.3.4.2.8",  id_rsassa_pkcs1_v1_5_with_sha3_256,   32, 51, true,  false, representation(x"30 31 30 0d 06 09 60 86 48 01 65 03 04 02 08 05 00 04 20")},
	{ "2.16.840.1.101.3.4.2.9",  id_rsassa_pkcs1_v1_5_with_sha3_384,   48, 67, true,  false, representation(x"30 41 30 0d 06 09 60 86 48 01 65 03 04 02 09 05 00 04 30")},
	{ "2.16.840.1.101.3.4.2.10", id_rsassa_pkcs1_v1_5_with_sha3_512,   64, 83, true,  false, representation(x"30 51 30 0d 06 09 60 86 48 01 65 03 04 02 0a 05 00 04 40")},
/*
version(X86_64) { //Blak2s is not mentioned in PKCS#2.2
	{ "1.3.6.1.4.1.1722.12.2.1.5",  id_rsassa_pkcs1_v1_5_with_blake2b160, 20, 41, true,  false, representation(x"30 27 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 05 05 00 04 14")},
	{ "1.3.6.1.4.1.1722.12.2.1.8",  id_rsassa_pkcs1_v1_5_with_blake2b256, 32, 53, true,  false, representation(x"30 33 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 08 05 00 04 20")},
	{ "1.3.6.1.4.1.1722.12.2.1.12", id_rsassa_pkcs1_v1_5_with_blake2b384, 48, 69, true,  false, representation(x"30 43 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 0c 05 00 04 30")},
	{ "1.3.6.1.4.1.1722.12.2.1.16", id_rsassa_pkcs1_v1_5_with_blake2b512, 64, 85, true,  false, representation(x"30 53 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 01 10 05 00 04 40")},
}
else {
	{ "1.3.6.1.4.1.1722.12.2.2.4",  id_rsassa_pkcs1_v1_5_with_blake2s128, 16, 41, true,  false, representation(x"30 23 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 04 05 00 04 10")},
	{ "1.3.6.1.4.1.1722.12.2.2.5",  id_rsassa_pkcs1_v1_5_with_blake2s160, 20, 41, true,  false, representation(x"30 27 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 05 05 00 04 14")},
	{ "1.3.6.1.4.1.1722.12.2.2.7",  id_rsassa_pkcs1_v1_5_with_blake2s224, 28, 41, true,  false, representation(x"30 2F 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 07 05 00 04 1c")},
	{ "1.3.6.1.4.1.1722.12.2.2.8",  id_rsassa_pkcs1_v1_5_with_blake2s256, 32, 41, true,  false, representation(x"30 33 30 0F 06 0B 2b 06 01 04 01 8D 3A 0c 02 02 08 05 00 04 20")},
}
*/
];



immutable ubyte[1]  ubZero = cast(ubyte)0;
immutable ubyte[1]  ubOne  = cast(ubyte)1;
immutable ubyte[1]  ubTwo  = cast(ubyte)2;

immutable(const(EVP_CIPHER)*[blockCipherModeOfOperation_maxcount_unused]) cipher_TDES; // TODO TDES won't be included in openssl any more beginning with version 1.1.0
immutable enum MAX_FCI_GET_RESPONSE_LEN = 86; //[EnumMembers!ISO7816_TAG_FCP_    ].fold!((a, b) => a + 2+TAG_FCP_len(b))(-12) +
																							//[EnumMembers!ISO7816_RFU_TAG_FCP_].fold!((a, b) => a + 2+TAG_FCP_len(b))(0); // Σ:86 //2(6F) [+4(80)] +8(82)+4(83) [+18(84)]+3(88)+3(8A)+10(8C)  [+4(8D) +34(AB)]
//pragma(msg, "compiling...MAX_FCI_GET_RESPONSE_LEN is: ", MAX_FCI_GET_RESPONSE_LEN);
immutable sc_path MF_path   = { [0x3F, 0], 2,  0, -1,  SC_PATH_TYPE_PATH }; // all following bytes of aid: zero

version(ACOSMODE_V2)
	private immutable(char)[98]  chip_name  = "ACS ACOS5-64 (v2: Smart Card/CryptoMate64 or v3: Smart Card/CryptoMate Nano in mode Non-FIPS/64K)"; // C-style null-terminated string equivalent, +1 for literal-implicit \0
else
	private immutable(char)[49]  chip_name  = "ACS ACOS5-64 (v3: Smart Card/CryptoMate Nano)";

private immutable(char)[9]  chip_shortname = "acos5_64";

private immutable(char)[57]  ATR_V2_colon =          "3B:BE:96:00:00:41:05:20:00:00:00:00:00:00:00:00:00:90:00";
private immutable(char)[57]  ATR_V3_colon =          "3B:BE:96:00:00:41:05:30:00:00:00:00:00:00:00:00:00:90:00";

private immutable(char)[57]  ATR_mask  =    "FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:FF:00:00";

/* ATR Table list. */
__gshared sc_atr_table[3]  acos5_64_atrs = [
	{
		ATR_V2_colon.ptr,               // atr
		ATR_mask.ptr,                   // atrmask "FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		chip_shortname.ptr,             // name
		SC_CARD_TYPE_ACOS5_64_V2,       // type
		SC_CARD_FLAG_RNG,               // flags
		null                            // card_atr  scconf_block*  fill this in acos5_64_init, or done by opensc d?
	},
	{
		ATR_V3_colon.ptr,               // atr
		ATR_mask.ptr,                   // atrmask "FF:FF:FF:FF:FF:FF:FF:FF:00:00:00:00:00:00:00:00:00:FF:FF",
		chip_shortname.ptr,             // name
		SC_CARD_TYPE_ACOS5_64_V3,       // type
		SC_CARD_FLAG_RNG,               // flags
		null                            // card_atr  scconf_block*  fill this in acos5_64_init, or done by opensc d?
	},
	{ } //null, null, null, 0, 0, null) // list end marker all zero
];

__gshared         sc_card_operations*       iso_ops_ptr;
private __gshared sc_card_operations        acos5_64_ops;
private __gshared sc_pkcs15init_operations  acos5_64_pkcs15init_ops;

/* Module definition for card driver */
private __gshared sc_card_driver  acos5_64_drv = sc_card_driver(
	chip_name.ptr,      /**< (name):       Full name for acos5_64 card driver */
	chip_shortname.ptr, /**< (short_name): Short name for acos5_64 card driver */
	null,               /**< (ops):        Pointer to acos5_64_ops (acos5_64 card driver operations), assigned later by sc_get_acos5_64_driver */
	acos5_64_atrs.ptr,  /**< (atr_map):    Pointer to list of card ATR's handled by this driver */
	2,                  /**< (natrs):      Number of atr's to check for this driver */
	null                /**< (dll):        Card driver module  (seems to be unused) */
);

// the OpenSC version, this driver implementation is based on/does support.
private __gshared const(char[7]) module_version = "0.16.0";  // uint major = 0, minor = 16, fix = 0;

version(ENABLE_TOSTRING)
auto writer = appender!string();

BN_CTX*  bn_ctx;

bool do_zeroize_token;    // = false;
bool do_initialize_token; // = false;
//bool do_re_initialize_token; // = false;  the same as do_zeroize_token && do_initialize_token


/* Information Structures for Building CRT Templates (which Tags for what type of Template; for SE-File, ManageSecurityEnvironment MSE and acos5_64_set_security_env) */
immutable(                        CRT_Tags[CRT_TAG]) aa_crt_tags;
immutable(              Algorithm_Possible[CRT_TAG]) aa_alg_poss;
immutable(                    UQB_Possible[CRT_TAG]) aa_uqb_poss;
immutable(ID_Pin_Key_Local_Global_Possible[CRT_TAG]) aa_idpk_poss;

//////////////////////////////////////////////////


private uba construct_SMcommand(int SC_APDU_CASE, SM_Extend sm_extend, in uba CLA_INS_P1_P2, in ubyte* key_enc, in ubyte* key_mac, ref ubyte[8] ssc_iv,  ubyte P3=0, uba cmdData=null)
{
	uba result; // = new ubyte[0];
	uba cmdDataNew;
	uba cmdDataEncrypted;

	assert(4==CLA_INS_P1_P2.length);
	assert(P3<=240);
	assert(canFind([SC_APDU_CASE_1, SC_APDU_CASE_2_SHORT, SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT], SC_APDU_CASE));

	ub4  SMCLA_INS_P1_P2 = CLA_INS_P1_P2[];
	SMCLA_INS_P1_P2[0] |= 0x0C;
	result = SMCLA_INS_P1_P2 ~ ubZero;

	uba mac_indataPadded = [ubyte(SMDO_Tag.Command_header_SMCLA_INS_P1_P2), ubyte(4)] ~ SMCLA_INS_P1_P2;

	sm_incr_ssc(ssc_iv); // ready for SM-mac'ing // The sequence number (seq#) n is used as the initial vector in the CBC calculation

	switch (SC_APDU_CASE) {
		case SC_APDU_CASE_2_SHORT:
			result           ~= [ubyte(SMDO_Tag.Original_P3_in_an_ISO_OUT_command), ubyte(1) , P3];
			mac_indataPadded ~= [ubyte(SMDO_Tag.Original_P3_in_an_ISO_OUT_command), ubyte(1) , P3];
			break;
		case SC_APDU_CASE_3_SHORT, SC_APDU_CASE_4_SHORT:
			if (sm_extend==SM_CCT_AND_CT_sym) {
				cmdDataNew = cmdData.dup;
				cmdDataEncrypted = new ubyte[cmdData.length];
				ubyte padByte = (cmdDataNew.length%8? 1 : 0);
				if (padByte) {
					cmdDataNew ~= ubyte(0x80);
					while (cmdDataNew.length%8)
						cmdDataNew ~= ubyte(0x00);
					cmdDataEncrypted.length = cmdDataNew.length;
				}

				if (cmdDataEncrypted.length!=encrypt_algo(cmdDataNew, key_enc, ssc_iv.ptr, cmdDataEncrypted.ptr, cipher_TDES[CBC], false) )
					return null;
				result           ~= [ubyte(SMDO_Tag.Padding_content_indicator_byte_followed_by_cryptogram), cast(ubyte)(cmdDataEncrypted.length+1), padByte] ~ cmdDataEncrypted;
				mac_indataPadded ~= [ubyte(SMDO_Tag.Padding_content_indicator_byte_followed_by_cryptogram), cast(ubyte)(cmdDataEncrypted.length+1), padByte] ~ cmdDataEncrypted;
			}
			else {
				result           ~= [ubyte(SMDO_Tag.Plain_Value), P3] ~ cmdData;
				mac_indataPadded ~= [ubyte(SMDO_Tag.Plain_Value), P3] ~ cmdData;
			}
			break;
		default:
			break;
	}

	ub8 mac_outdataPadded;
	if (mac_indataPadded.length%8)
		mac_indataPadded ~= ubyte(0x80);
	while (mac_indataPadded.length%8)
		mac_indataPadded ~= ubyte(0x00);// assert(equal(5.repeat().take(4), [ 5, 5, 5, 5 ]));

	if (8!=encrypt_algo_cbc_mac(mac_indataPadded, key_mac, ssc_iv.ptr, mac_outdataPadded.ptr, cipher_TDES[DAC], false))
		return null;

	result ~= [ubyte(SMDO_Tag.Cryptographic_Checksum), ubyte(4)] ~ mac_outdataPadded[0..4];
	result[4] = cast(ubyte)(result.length-5);

	return result;
}


private int check_SMresponse(sc_apdu* apdu, sm_card_response* sm_resp, int SC_APDU_CASE, SM_Extend sm_extend,
	in uba CLA_INS_P1_P2, in ubyte* key_enc, in ubyte* key_mac, ref ubyte[8] ssc_iv,  ubyte P3=0) {
	assert(4==CLA_INS_P1_P2.length);
	int   rv;
	bool  sm_resp_usable;
	if (sm_resp && sm_resp.sw1 && sm_resp.mac_len && sm_resp.data_len) {
			sm_resp_usable = true;
	}
	uba mac_indataPadded = [ubyte(SMDO_Tag.Command_header_SMCLA_INS_P1_P2), ubyte(4)] ~ CLA_INS_P1_P2 ~
		[ubyte(SMDO_Tag.Processing_status_word_SW1SW2_of_the_command), ubyte(2), cast(ubyte)apdu.sw1, cast(ubyte)apdu.sw2];
	mac_indataPadded[2] |= 0x0C;

	if (canFind([SC_APDU_CASE_2_SHORT, SC_APDU_CASE_4_SHORT], SC_APDU_CASE)) {
		if (sm_extend==SM_Extend.SM_CCT)
			mac_indataPadded ~= [ubyte(SMDO_Tag.Plain_Value), P3] ~ apdu.resp[0..apdu.resplen];
		else if (sm_resp_usable) {
			if (SC_APDU_CASE==2)
				mac_indataPadded ~= [ubyte(SMDO_Tag.Padding_content_indicator_byte_followed_by_cryptogram), cast(ubyte)sm_resp.data_len] ~ sm_resp.data[0..sm_resp.data_len];
			else
				mac_indataPadded ~= [ubyte(SMDO_Tag.Padding_content_indicator_byte_followed_by_cryptogram), ubyte(0), ubyte(0)] ~ apdu.resp[0..apdu.resplen];
		}
	}

	if (mac_indataPadded.length%8)
		mac_indataPadded ~= ubyte(0x80);
	while (mac_indataPadded.length%8)
		mac_indataPadded ~= ubyte(0x00);

	ub8 mac_outdataPadded;
	sm_incr_ssc(ssc_iv);
	if (sm_extend==SM_Extend.SM_CCT_AND_CT_sym && sm_resp_usable && key_enc && canFind([SC_APDU_CASE_2_SHORT, SC_APDU_CASE_4_SHORT], SC_APDU_CASE)) {
		ubyte PI      = sm_resp.data[0];
		uba encrypted = sm_resp.data[1..sm_resp.data_len].dup;
		if (encrypted.length>8 && (encrypted.length%8)==0 && PI==0 && equal(encrypted[$-8..$],[0,0,0,0,0,0,0,0][]))
			encrypted = encrypted[0..$-8];
		sm_resp.data = sm_resp.data.init;
		assert((encrypted.length%8)==0);
		assert(encrypted.length==decrypt_algo(encrypted, key_enc, ssc_iv.ptr, sm_resp.data.ptr, cipher_TDES[CBC], false));
		sm_resp.data_len = encrypted.length;
		if (PI==1)
			while (sm_resp.data[sm_resp.data_len-- -1] != 0x80) {}
	}
	if (8!=encrypt_algo_cbc_mac(mac_indataPadded, key_mac, ssc_iv.ptr, mac_outdataPadded.ptr, cipher_TDES[DAC], false))
		return SC_ERROR_SM_ENCRYPT_FAILED;
	return SC_ERROR_SM_INVALID_CHECKSUM* !(equal(mac_outdataPadded[0..4], apdu.mac[0..4]) && 4==apdu.mac_len);
}


unittest {
	version(SESSIONKEYSIZE24)
		ub24 random_key;
	else
		ub16 random_key;
	assert(1==RAND_bytes(random_key.ptr, random_key.length));
	ub8  random_iv;
	assert(1==RAND_bytes(random_iv.ptr, random_iv.length));

	ub4  CLA_INS_P1_P2 = [0x00, 0x0E, 0x00, 0x00];
	TSMarguments smArguments;
	smArguments = TSMarguments(SC_APDU_CASE_1, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, 0, null);

	uba  SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..7], [0x0C, 0x0E, 0x00, 0x00, 0x06, 0x8E, 0x04][0..7]));

	ubyte P3 = 2;
	ubyte[2] offset = [0, 5];
	SMcommand = construct_SMcommand(SC_APDU_CASE_3_SHORT, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, P3, offset);
	assert(equal(SMcommand[0..11], [0x0C, 0x0E, 0x00, 0x00, 0x0A, 0x81, P3, 0x00, 0x05, 0x8E, 0x04][0..11]));

	CLA_INS_P1_P2 = [0x00, 0x84, 0x00, 0x00];
	P3 = 8;
	SMcommand = construct_SMcommand(SC_APDU_CASE_2_SHORT, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, P3);
	assert(equal(SMcommand[0..10], [0x0C, 0x84, 0x00, 0x00, 0x09, 0x97, 0x01, P3, 0x8E, 0x04][0..10]));

	CLA_INS_P1_P2 = [0x00, 0x2A, 0x9E, 0x9A];
	P3 = 20;
	ubyte[20] hash = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20];
	SMcommand = construct_SMcommand(SC_APDU_CASE_4_SHORT, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, P3, hash);
	assert(equal(SMcommand[0..29], [0x0C, 0x2A, 0x9E, 0x9A, 0x1C, 0x81, P3, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20, 0x8E, 0x04][0..29]));

	CLA_INS_P1_P2 = [0x00, 0xB0, 0x00, 0x00];
	random_iv[6] = 0xFF;
	random_iv[7] = 0xFF;
	smArguments = TSMarguments(SC_APDU_CASE_2_SHORT, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, 16, null);
	ushort ssc0 = ub22integral(smArguments.ssc_iv[$-2..$]);
	SMcommand = construct_SMcommand(smArguments[]);
	ushort ssc1 = ub22integral(smArguments.ssc_iv[$-2..$]);
	assert(ssc0+1==ssc1 || (ssc0==0xFFFF && ssc1==0x0000));
	assert(equal(SMcommand[0..10], [0x0C, 0xB0, 0x00, 0x00, 0x09, 0x97, 0x01, 0x10, 0x8E, 0x04][0..10]));

	CLA_INS_P1_P2 = [0x00, 0xD6, 0x00, 0x00];
	ub16 ubin = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
	smArguments = TSMarguments(SC_APDU_CASE_3_SHORT, SM_Extend.SM_CCT, CLA_INS_P1_P2, random_key.ptr, random_key.ptr, random_iv, 16, ubin);
	SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..25], [0x0C, 0xD6, 0x00, 0x00, 0x18, 0x81, 0x10,  1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,  0x8E, 0x04][]));

	smArguments = TSMarguments(SC_APDU_CASE_1, SM_CCT, [0x00, 0x44, 0x00, 0x00], random_key.ptr, random_key.ptr, random_iv, 0, null);
	SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..7], [0x0C, 0x44, 0x00, 0x00, 0x06, 0x8E, 0x04][]));

	smArguments = TSMarguments(SC_APDU_CASE_3_SHORT, SM_CCT_AND_CT_sym, [0x00, 0xD6, 0x00, 0x00], random_key.ptr, random_key.ptr, random_iv, 16, [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
	SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..8], [0x0C, 0xD6, 0x00, 0x00, 0x19, 0x87, 0x11, 0x00][]));

	smArguments = TSMarguments(SC_APDU_CASE_3_SHORT, SM_CCT, [0x00, 0x0E, 0x00, 0x00], random_key.ptr, random_key.ptr, random_iv, 2, [0,5]);
	SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..11], [0x0C, 0x0E, 0x00, 0x00, 0x0A, 0x81, 0x02, 0x00, 0x05, 0x8E, 0x04][]));
	writeln("PASSED: construct_SMcommand");
	sc_apdu apdu;
	assert(SC_ERROR_SM_INVALID_CHECKSUM == check_SMresponse(&apdu, null, smArguments[0..$-2]));

	sm_cwa_session cwa;
	smArguments = TSMarguments(SC_APDU_CASE_2_SHORT, SM_Extend.SM_CCT, [0x00, 0xB0, 0x00, 0x00], get_cwa_session_enc(cwa).ptr, random_key.ptr, random_iv, ubyte(16), null);
	SMcommand = construct_SMcommand(smArguments[]);
	assert(equal(SMcommand[0..10], [0x0C, 0xB0, 0x00, 0x00, 0x09, 0x97, 0x01, 0x10, 0x8E, 0x04][]));
	smArguments.sm_extend = SM_Extend.SM_CCT_AND_CT_sym;
	apdu.resp    = ubin.ptr;
	apdu.resplen = ubin.length;
	sm_card_response sm_resp;
	sm_resp.data[0..17] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
	sm_resp.data_len    = 17;
	sm_resp.mac         = [7,8,9,10,11,12,13,14];
	sm_resp.mac_len     = 8;
	sm_resp.sw1         = 0x90;
	assert(SC_ERROR_SM_INVALID_CHECKSUM == check_SMresponse(&apdu, &sm_resp, smArguments[0..$-2]));
	writeln("PASSED: check_SMresponse");
	get_cwa_session_enc(cwa);
	set_cwa_session_enc(cwa, random_key);
	get_cwa_session_mac(cwa);
	set_cwa_session_mac(cwa, random_key);
	get_cwa_keyset_enc(cwa);
	writeln("PASSED: get/set: cwa_session_enc/cwa_session_mac, cwa_keyset_enc/cwa_keyset_mac");
} // unittest


uba  get_cwa_session_enc(ref const sm_cwa_session cwa) {
	uba result = cwa.session_enc.dup;
version(SESSIONKEYSIZE24)
	result ~= cwa.icc.k[8..16];
	return result;
}


void set_cwa_session_enc(ref sm_cwa_session cwa, uba key) {
	cwa.session_enc  = key[ 0..16];
version(SESSIONKEYSIZE24)
	cwa.icc.k[8..16] = key[16..24];
}


uba  get_cwa_session_mac(ref const sm_cwa_session cwa) {
	uba result = cwa.session_mac.dup;
version(SESSIONKEYSIZE24)
	result ~= cwa.ifd.k[8..16];
	return result;
}


void set_cwa_session_mac(ref sm_cwa_session cwa, uba key) {
	cwa.session_mac  = key[ 0..16];
version(SESSIONKEYSIZE24)
	cwa.ifd.k[8..16] = key[16..24];
}

///////////////
uba  get_cwa_keyset_enc(ref const sm_cwa_session cwa) {
	uba result = cwa.cwa_keyset.enc.dup;
version(SESSIONKEYSIZE24)
	result ~= cwa.icc.k[0..8];
	return result;
}


void set_cwa_keyset_enc(ref sm_cwa_session cwa, uba key) {
	cwa.cwa_keyset.enc  = key[ 0..16];
version(SESSIONKEYSIZE24)
	cwa.icc.k[0..8]     = key[16..24];
}


uba  get_cwa_keyset_mac(ref const sm_cwa_session cwa) {
	uba result = cwa.cwa_keyset.mac.dup;
version(SESSIONKEYSIZE24)
	result ~= cwa.ifd.k[0..8];
	return result;
}


void set_cwa_keyset_mac(ref sm_cwa_session cwa, uba key) {
	cwa.cwa_keyset.mac  = key[ 0..16];
version(SESSIONKEYSIZE24)
	cwa.ifd.k[0..8]     = key[16..24];
}


extern(C) int rt_init(); // in Windows, a DLL_PROCESS_ATTACH calls rt_init(); what is the equivalent in Linux?
extern(C) int rt_term(); // in Windows, a DLL_PROCESS_DETACH calls rt_term(); what is the equivalent in Linux?

// http://stackoverflow.com/questions/12463718/linux-equivalent-of-dllmain
// the contract is that functions with __attribute__((constructor)) will execute before dlopen() returns.
// presumably shared static this() will run after rt_init() is called ! This is invoked by sc_module_init
//version(all/*Posix*/) { }
shared static this() {
	setlocale (LC_ALL, "C"); // char* currentlocale =
	/* Initialize the openssl library */
	ERR_load_CRYPTO_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(null);
	bn_ctx = BN_CTX_new();

	version(SESSIONKEYSIZE24)
		const(EVP_CIPHER)*[blockCipherModeOfOperation_maxcount_unused] local_cipher_TDES = [EVP_des_ede3(), EVP_des_ede3_cbc(), EVP_des_ede3_cbc()];
	else
		const(EVP_CIPHER)*[blockCipherModeOfOperation_maxcount_unused] local_cipher_TDES = [EVP_des_ede(),  EVP_des_ede_cbc(),  EVP_des_ede_cbc()];
	cipher_TDES = assumeUnique(local_cipher_TDES);

	CRT_Tags[CRT_TAG] local_aa_crt_tags = [// mandatory_And    mandatory_OneOf                              optional
		HT     : CRT_Tags([      Algorithm ]),
		AT     : CRT_Tags([ UQB,            ID_Pin_Key_Local_Global ]),
		DST    : CRT_Tags([ UQB, Algorithm, KeyFile_RSA ]),
		CT_asym: CRT_Tags([ UQB, Algorithm, KeyFile_RSA ]),
		CT_sym : CRT_Tags([ UQB, Algorithm ],                         [ ID_Pin_Key_Local_Global, HP_Key_Session ], [ Initial_Vector ]),
		CCT    : CRT_Tags([ UQB, Algorithm ],                         [ ID_Pin_Key_Local_Global, HP_Key_Session ], [ Initial_Vector ]),
	];
	aa_crt_tags = assumeUnique(local_aa_crt_tags);

	Algorithm_Possible[CRT_TAG] local_aa_alg_poss = [ // defaults shall be the first entry
		HT     : Algorithm_Possible([       0x21 /*SHA256*/   ,      ubyte(0x20) /*SHA1*/ ]),
		AT     : Algorithm_Possible([]),
		DST    : Algorithm_Possible([ ubyte(0x10) /*PKCS#1 Padding generated by card for Sign; or removed for verify; also for generate key pair; all RSA*/
																															,  ubyte(0x11)/* ISO 9796-2 scheme 1 Padding*/ ]),
		CT_asym: Algorithm_Possible([ ubyte(0x13) /*Decrypt */, cast(ubyte)0x12 /*Encrypt, both RSA */ ]),
		CT_sym : Algorithm_Possible([ ubyte(0x06) /* AES-CBC*/, cast(ubyte)0x04 /* AES-ECB*/
																 ,ubyte(0x07) /* AES-CBC*/, cast(ubyte)0x05 /* AES-ECB*/
																 ,ubyte(0x02) /*TDES-CBC*/, cast(ubyte)0x00 /*TDES-ECB*/
																 ,ubyte(0x03) /* DES-CBC*/, cast(ubyte)0x01 /* DES-ECB*/ ]),
		CCT    : Algorithm_Possible([ ubyte(0x02) /*TDES-CBC*/, cast(ubyte)0x03 /* DES-CBC; NOT SECURE !*/ ]),
	];
	aa_alg_poss = assumeUnique(local_aa_alg_poss);

	UQB_Possible[CRT_TAG] local_aa_uqb_poss = [
		HT     : UQB_Possible(0xFF, []),
		AT     : UQB_Possible(0x88, [0x88/*Pin_Verify_and_SymKey_Authenticate*/, 0x80/*SymKey_Authenticate*/, 0x08/*Pin_Verify*/]),
		DST    : UQB_Possible(0xC0, [0x40/*private*/, 0x80/*public*/,  0x40, 0x80]),
		CT_asym: UQB_Possible(0x70, [0x40/*PSO*/, 0x50/*PSO+SM in Command Data*/, 0x60/*PSO+SM in Response Data*/, 0x70/*PSO+SM in Command and Response Data*/, 0x40, 0x50, 0x60, 0x70]),
		CT_sym : UQB_Possible(0x70, [0x30/*SM*/, 0x40/*PSO*/]),
		CCT    : UQB_Possible(0x70, [0x30/*SM*/, 0x40/*PSO*/]),
	];
	aa_uqb_poss = assumeUnique(local_aa_uqb_poss);


//immutable(ID_Pin_Key_Local_Global_Possible[CRT_TAG]) aa_idpk_poss;
	ID_Pin_Key_Local_Global_Possible[CRT_TAG] local_aa_idpk_poss = [
		HT     : ID_Pin_Key_Local_Global_Possible(0xFF, []),
		// not all possible keys/pins may exist and files holding keys and pins can't be queried, thus always obey this rule: Assign a key/pin with ID #x to exactly a record No.#x;
		// This should allow to query numer of records and infer the available IDs now, before assigning in  local_aa_idpk_poss TODO
		AT     : ID_Pin_Key_Local_Global_Possible(0x9F, [0x81/*User's (local) Pin/1. symKey*/, 0x82/*2. local symKey*/, 0x83/*3. local symKey*/, 0x01/*Admin's (global) Pin/1. symKey*/, 0x02]),
		DST    : ID_Pin_Key_Local_Global_Possible(0xFF, [] /*[cast(ubyte)0x41, cast(ubyte)0x31, cast(ubyte)0x41, cast(ubyte)0xF1]*/ ),
		CT_asym: ID_Pin_Key_Local_Global_Possible(0xFF, []),
		CT_sym : ID_Pin_Key_Local_Global_Possible(0xFF, [0x84, 0x81, 0x82, 0x83] ),
		CCT    : ID_Pin_Key_Local_Global_Possible(0xFF, [0x84, 0x81, 0x82, 0x83] ),
	];
	aa_idpk_poss = assumeUnique(local_aa_idpk_poss);

	version(ENABLE_TOSTRING)
		writer.put("private shared static  this() was called\n\n");
}


shared static ~this() {
	BN_CTX_free(bn_ctx);
  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();
	version(ENABLE_TOSTRING)
	{
		writer.put("\nprivate shared static ~this() was called\n");
		version(Windows)
			File f = File( r"C:\test.txt", "w");
		else
			File f = File("/tmp/test.txt", "w");
		f.write(writer.data);
	}
}


/* The 2 required exports of the 'card_driver': */

////export extern(C) __gshared const(char)* sc_module_version   = module_version.ptr; // actually not required, even if "src/libopensc/ctx.c:399" says so, but instead, the next is required
export extern(C) const(char)* sc_driver_version() {
	version(OPENSC_VERSION_LATEST) return module_version.ptr; // when private __gshared const(char[7]) 'module_version' and the libopensc.so version are the same==0.16.0
	else                           return sc_get_version();   // otherwise they fall apart, but difference may be 1 version only (only the last 2 opensc versions are supported)!
}

export extern(C) void* sc_module_init(const(char)* name) {
	static int cnt_call;
	try {
		++cnt_call;
		if (cnt_call == 1) {
			if (! rt_init())
				return null;
			version(ENABLE_TOSTRING)
				writer.formattedWrite("sc_module_init '&sc_get_acos5_64_driver' was called with argument name: %s and cnt_call: %s\n", name.fromStringz, cnt_call);
			return &sc_get_acos5_64_driver;
		}
		version(ENABLE_TOSTRING)
			writer.formattedWrite("sc_module_init '&sc_get_acos5_64_pkcs15init_ops' was called with argument name: %s and cnt_call: %s\n", name.fromStringz, cnt_call);
		return &sc_get_acos5_64_pkcs15init_ops;
	}
	catch (Exception e) {
		return null;
	}
}

private sc_card_driver* sc_get_acos5_64_driver() {
	try {
		enforce(DES_KEY_SZ == SM_SMALL_CHALLENGE_LEN && DES_KEY_SZ == 8, "For some reason size [byte] of DES-block and challenge-response (card/host) is not equal and/or not 8 bytes!");
		version(ENABLE_TOSTRING)
			writer.put("sc_card_driver* sc_get_acos5_64_driver() was called\n");

		iso_ops_ptr         = sc_get_iso7816_driver.ops; // iso_ops_ptr for initialization and casual use
		acos5_64_ops        = *iso_ops_ptr; // initialize all ops with iso7816_driver's implementations

		with (acos5_64_ops) {
			/* Called in sc_connect_card().  Must return 1, if the current
			 * card can be handled with this driver, or 0 otherwise.  ATR
			 * field of the sc_card struct is filled in before calling
			 * this function. */
			match_card        = &acos5_64_match_card; // called from libopensc/card.c:186 int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out) // grep -rnw -e 'acos5_\(64_\)\{0,1\}match_card' 2>/dev/null
			/* Called when ATR of the inserted card matches an entry in ATR
			 * table.  May return SC_ERROR_INVALID_CARD to indicate that
			 * the card cannot be handled with this driver. */
			acos5_64_ops.init = &acos5_64_init;       // called from libopensc/card.c:186 int sc_connect_card(sc_reader_t *reader, sc_card_t **card_out)
			/* Called when the card object is being freed.  finish() has to
			 * deallocate all possible private data. */
			finish            = &acos5_64_finish;

			/* ISO 7816-4 functions */
			//TODO replace iso7816_read_binary: this also should try the command get_key for public RSA files
//	iso7816_read_binary                       // = &acos5_64_read_binary; // SC_AC_OP_READ
//	iso7816_write_binary
//	iso7816_update_binary                          // SC_AC_OP_UPDATE
//	null or erase_binary = &acos5_64_erase_binary; // stub

			read_record       = &acos5_64_read_record; // SC_AC_OP_READ
//	iso7816_write_record,
//	iso7816_append_record,
//	iso7816_update_record,                       // SC_AC_OP_UPDATE

			/* select_file: Does the equivalent of SELECT FILE command specified
			 *   in ISO7816-4. Stores information about the selected file to
			 *   <file>, if not NULL. */
			select_file       = &acos5_64_select_file; // SC_AC_OP_SELECT
//	iso7816_get_response
			get_challenge     = &acos5_64_get_challenge;

			/* ISO 7816-8 functions */
			//	null  deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") verify_tf verify;
			/* logout: Resets all access rights that were gained. */
			logout            = &acos5_64_logout;
			/* restore_security_env:  Restores a previously saved security
			 *   environment, and stores information about the environment to
			 *   <env_out>, if not NULL. */
//	iso7816_restore_security_env                                        // SC_AC_OP_READ
			/* set_security_env:  Initializes the security environment on card
			 *   according to <env>, and stores the environment as <se_num> on the
			 *   card. If se_num <= 0, the environment will not be stored. */ // if se_num >0: SC_AC_OP_UPDATE
			set_security_env  = &acos5_64_set_security_env;
			/* decipher:  Engages the deciphering operation.  Card will use the
			 *   security environment set in a call to set_security_env or
			 *   restore_security_env. */
			decipher          = &acos5_64_decipher;
			/* compute_signature:  Generates a digital signature on the card.  Similiar
			 *   to the function decipher. */
			compute_signature = &acos5_64_compute_signature;
			//	null  deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") change_reference_data_tf change_reference_data;
			//	null  deprecated("Don't use this: It's old style and not necessary if pin_cmd is supported") reset_retry_counter_tf reset_retry_counter;

			/* ISO 7816-9 functions */
////	iso7816_create_file		create_file       = &acos5_64_create_file; // SC_AC_OP_CREATE, applied in DF/MF
/* iso7816_delete_file */		delete_file       = &acos5_64_delete_file; // SC_AC_OP_DELETE, applied for file/path in ParenDF: sc_delete_file(sc_card_t *card, const sc_path_t *path)
			/* list_files:  Enumerates all the files in the current DF, and
			 *   writes the corresponding file identifiers to <buf>.  Returns
			 *   the number of bytes stored. */
			list_files        = &acos5_64_list_files; // SC_AC_OP_LIST_FILES
		check_sw          = &acos5_64_check_sw; // NO external use; not true: sc_check_sw calls this
			card_ctl          = &acos5_64_card_ctl;
			process_fci       = &acos5_64_process_fci;
			construct_fci     = &acos5_64_construct_fci;
			/* pin_cmd: verify/change/unblock command; optionally using the
			 * card's pin pad if supported.
			 */
			pin_cmd           = &acos5_64_pin_cmd;
//	iso7816_get_data
//	null  put_data_tf         put_data;
//	null  delete_record_tf    delete_record;
			read_public_key   = &acos5_64_read_public_key;
		} // with (acos5_64_ops)
	}
	catch (Exception e) {
		acos5_64_ops = sc_card_operations();
	}
	acos5_64_drv.ops = &acos5_64_ops;
	return &acos5_64_drv;
}

private sc_pkcs15init_operations* sc_get_acos5_64_pkcs15init_ops() {
	try {
		version(ENABLE_TOSTRING)
			writer.put("sc_pkcs15init_operations* sc_get_acos5_64_pkcs15init_ops() was called\n");
		with (acos5_64_pkcs15init_ops) {
			/* Erase everything that's on the card */
//			erase_card

		/* New style API */

			/*
			 * Card-specific initialization of PKCS15 meta-information.
			 * Currently used by the cflex driver to read the card's
			 * serial number and use it as the pkcs15 serial number.
			 */
			init_card            = &acos5_64_pkcs15_init_card;     // doesn't get called so far
			/* Create a DF */
//			create_dir
			/*
			 * Create a "pin domain". This is for cards such as
			 * the cryptoflex that need to put their pins into
			 * separate directories
			 */
//			create_domain
			/* Select a PIN reference */
			select_pin_reference = &acos5_64_pkcs15_select_pin_reference; // does nothing
			/*
			 * Create a PIN object within the given DF.
			 *
			 * The pin_info object is completely filled in by the caller.
			 * The card driver can reject the pin reference; in this case
			 * the caller needs to adjust it.
			 */
//			create_pin
			/* Select a reference for a private key object */
//			select_key_reference = &acos5_64_pkcs15_select_key_reference; // does nothing
			/*
			 * Create an empty key object.
			 * @index is the number key objects already on the card.
			 * @pin_info contains information on the PIN protecting
			 *		the key. NULL if the key should be
			 *		unprotected.
			 * @key_info should be filled in by the function
			 */
			create_key           = &acos5_64_pkcs15_create_key;           // does nothing
			/* Store a key on the card */
			store_key            = &acos5_64_pkcs15_store_key;            // does nothing
			/* Generate key */
			generate_key         = &acos5_64_pkcs15_generate_key;
			/*
			 * Encode private/public key
			 * These are used mostly by the Cryptoflex/Cyberflex drivers.
			 */
			encode_private_key   = &acos5_64_pkcs15_encode_private_key;   // does nothing
			encode_public_key    = &acos5_64_pkcs15_encode_public_key;    // does nothing
			/*
			 * Finalize card
			 * Ends the initialization phase of the smart card/token
			 * (actually this command is currently only for starcos spk 2.3
			 * cards).
			 */
//			finalize_card
			/* Delete object */
			delete_object        = &acos5_64_pkcs15_delete_object;        // does nothing
			/* Support of pkcs15init emulation */
//			emu_update_dir
//			emu_update_any_df
//			emu_update_tokeninfo
//			emu_write_info
			emu_store_data       = &acos5_64_pkcs15_emu_store_data;       // does nothing ; (otherwise, after acos5_64_pkcs15_generate_key, sc_pkcs15init_store_data wouuld try to delete the publik key file, written nicely on card)

			sanity_check         = &acos5_64_pkcs15_sanity_check;         // does nothing
		} // with (acos5_64_pkcs15init_ops)
	}
	catch (Exception e) {
		acos5_64_pkcs15init_ops = sc_pkcs15init_operations();
	}
	return &acos5_64_pkcs15init_ops;
}

/**
 * Retrieve hardware identifying serial number (cardType_serial_len bytes) from card and cache it
 * The serial no. retrieved from card will be cached in any case, even if the regular
 * variable to receive the result (serial) is null
 * For ACOS5-64 V2.00, only the first 6 bytes are meaningful
 *
 * @param card pointer to card description
 * @param serial where to store data retrieved, may be null
 * @return SC_SUCCESS if ok; else error code
 */
private int acos5_64_get_serialnr(sc_card* card, sc_serial_number* serial) {
	if (card == null || card.ctx == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	int rv;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_get_serialnr"`, `"called"`));
	mixin transmit_apdu_strerror!("acos5_64_get_serialnr");
	mixin log_scope_exit!("acos5_64_get_serialnr");
	scope(exit) {
		if (serial !is null) {
			serial.value                = 0;
			serial.len                  = clamp(card.serialnr.len, 0, SC_MAX_SERIALNR);
			serial.value[0..serial.len] = card.serialnr.value[0..serial.len];
		}
		log_scope_exit_do(__LINE__);
	}
	try {
		ubyte cardType_serial_len = (card.type==SC_CARD_TYPE_ACOS5_64_V2? 6 : 8);
		/* if serial number is cached, use it */
		with (card.serialnr) {
			if (len)
				return rv=SC_SUCCESS;
		/* not cached, retrieve serial number using GET CARD INFO, and cache serial number */
			value = 0;
			bytes2apdu(ctx, representation(x"80 14 00 00")~cardType_serial_len, apdu);
			apdu.resp    = value.ptr;
			apdu.resplen = value.length;
			if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
			if (sc_check_sw(card, apdu.sw1, apdu.sw2) || apdu.resplen!=cardType_serial_len)
				return rv=SC_ERROR_INTERNAL;
			len = cardType_serial_len;

version(ENABLE_SM)
			card.sm_ctx.info.session.cwa.icc.sn = value[0..8];

			mixin (log!(`"acos5_64_get_serialnr"`, `"Serial Number of Card (EEPROM): '%s'"`, "sc_dump_hex(value.ptr, cardType_serial_len)"));
		} // with (card.serialnr)
		return rv=SC_SUCCESS;
	}
	catch(Throwable)
		return rv=SC_ERROR_CARD_UNRESPONSIVE;
}


// for some reason, this usefull function is not exported from libopensc's version 0.15.0
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
	mixin (log!(`"missingExport_match_atr_table"`, `"ATR     : %s"`, "card_atr_hex.ptr"));

	for (i = 0; table[i].atr != null; i++) {
		const(char)*  tatr = table[i].atr;
		const(char)*  matr = table[i].atrmask;
		size_t        tatr_len = strlen(tatr);
		ubyte[SC_MAX_ATR_SIZE]  mbin, tbin;
		size_t        mbin_len, tbin_len, s, matr_len;
		size_t        fix_hex_len = card_atr_hex_len;
		size_t        fix_bin_len = card_atr_bin_len;
		mixin (log!(`"missingExport_match_atr_table"`, `"ATR try : %s"`, "tatr"));

		if (tatr_len != fix_hex_len) {
			mixin (log!(`"missingExport_match_atr_table"`, `"ignored - wrong length"`));
			continue;
		}
		if (matr != null) {
			mixin (log!(`"missingExport_match_atr_table"`, `"ATR mask: %s"`, "matr"));

			matr_len = strlen(matr);
			if (tatr_len != matr_len)
				continue;
			tbin_len = tbin.sizeof;
			sc_hex_to_bin(tatr, tbin.ptr, &tbin_len);
			mbin_len = mbin.sizeof;
			sc_hex_to_bin(matr, mbin.ptr, &mbin_len);
			if (mbin_len != fix_bin_len) {
				mixin (log!(`"missingExport_match_atr_table"`, `"length of atr and atr mask do not match - ignored: %s - %s"`, "tatr", "matr"));
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


private int acos5_64_match_card_checks(sc_card* card) { // regular return value: 0==SUCCESS
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_INVALID_CARD;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_match_card_checks"`, `"called"`));
	mixin transmit_apdu_strerror!("acos5_64_match_card_checks");
	mixin log_scope_exit!("acos5_64_match_card_checks");
	scope(exit)
		log_scope_exit_do(__LINE__);

	bytes2apdu(ctx, representation(x"80 14 05 00"), apdu);
	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if ((rv=acos5_64_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		mixin (log!(`"acos5_64_match_card_checks"`, `"SW1SW2 doesn't match 0x9540: %i (%s)\n"`, "rv", "sc_strerror(rv)"));
		return rv;
	}

	/* call 7.3.1. Get Card Info Card OS Version */
	immutable(ubyte)[8][3] vbuf = [ cast(immutable(ubyte)[8]) x"41434F5305 02 00 40",  // "ACOS 0x05 ...", major vers.=2,   minor=0,   0x40 kBytes user EEPROM capacity
	                                cast(immutable(ubyte)[8]) x"41434F5305 03 00 40",  // "ACOS 0x05 ...", major vers.=3,   minor=0,   0x40 kBytes user EEPROM capacity
	                                cast(immutable(ubyte)[8]) x"41434F5305 03 01 40"]; // "ACOS 0x05 ...", major vers.=3,   minor=1,   0x40 kBytes user EEPROM capacity
	bytes2apdu(ctx, representation(x"80 14 06 00 08"), apdu);
	ub8 rbuf;
	apdu.resp    = rbuf.ptr;
	apdu.resplen = rbuf.length;

	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		return rv=SC_ERROR_INTERNAL;

	assert(card.type>=SC_CARD_TYPE_ACOS5_64_V2 && card.type<=SC_CARD_TYPE_ACOS5_64_V3);
	size_t x;
version(ACOSMODE_V2) {
	if (card.type==SC_CARD_TYPE_ACOS5_64_V3)
		x = 1;
}
else {
	card.type = -1;
	return rv=SC_ERROR_INVALID_CARD; // ACOSMODE_V3_FIPS_140_2L3  ACOSMODE_V3_NSH_1
}
	// equality of vbuf_2 and rbuf ==> 0==SC_SUCCESS, 	inequality==> 1*SC_ERROR_NO_CARD_SUPPORT
	if ((rv=SC_ERROR_INVALID_CARD* !equal(rbuf[], vbuf[x+card.type-SC_CARD_TYPE_ACOS5_64_V2][])) < 0) {
		mixin (log!(`"acos5_64_match_card_checks"`,
			`"Card OS Version doesn't match expected data! Current data: major(%i), minor(%i), EEPROM user capacity in kilobytes (0x%02X)\n"`, "rbuf[5]", "rbuf[6]", "rbuf[7]"));
		mixin (log!(`"acos5_64_match_card_checks"`,
			`"For ACOS5-64 V3.00 card/token, a possible reason is: It's set to an unsupportrd operation mode (unsupported FIPS is the default setting by ACS)"`));
		mixin (log!(`"acos5_64_match_card_checks"`,
			`"If the card/token is virgin (no MF), this will be corrected by (1) switching to non-FIPS/64K here and (2) an initialization with operation mode non-FIPS/64K in acos5_64_init"`));
		mixin (log!(`"acos5_64_match_card_checks"`,
			`"If the card/token is not virgin (MF exists), then nothing will be done at the moment"`));
		if (card.type==SC_CARD_TYPE_ACOS5_64_V3 && equal(rbuf[], vbuf[card.type-SC_CARD_TYPE_ACOS5_64_V2][])) {
			bytes2apdu(ctx, representation(x"80 14 09 00"), apdu);
			if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
			if (apdu.sw1 != 0x90)  return rv;
			if (apdu.sw2 == 0x02)  return rv;
			bytes2apdu(ctx, representation(x"00 A4 00 00"), apdu);
			apdu.flags = SC_APDU_FLAGS_NO_GET_RESP;
			if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
			if (apdu.sw1 != 0x69 || apdu.sw2 != 0x86)  return rv;
			/* okay, card is virgin: Set operation mode Non-FIPS/64K now, and acos5_64_init will invoke card/token initialization */
			bytes2apdu(ctx, representation(x"00 D6  C191  01 02"), apdu);
			if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
			bytes2apdu(ctx, representation(x"80 14 09 00"), apdu);
			if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
			if (apdu.sw1 != 0x90 || apdu.sw2 != 0x02)  return rv;
			return rv=SC_SUCCESS;
		}
		else
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
private extern(C) int acos5_64_match_card(sc_card* card) { // irregular/special return value: 0==FAILURE
	int rv;
	sc_context* ctx = card.ctx;
	mixin (log!(`"acos5_64_match_card"`, `"called. Try to match card with ATR %s"`, "sc_dump_hex(card.atr.value.ptr, card.atr.len)"));
	scope(exit) {
		if (rv == 0) { // FAILURE, then stall acos5_64_init !!! (a FAILURE in 'match_card' is skipped e.g. when force_card_driver is active, but a FAILURE in 'init' is adhered to)
			card.type = -1;
			mixin (log!(`"acos5_64_match_card"`, `"card not matched"`));
		}
		else
			mixin (log!(`"acos5_64_match_card"`, `"card matched (%s)"`, "acos5_64_atrs[0].name"));
	}

	// for some reason, this usefull function is not exported from libopensc's version 0.15.0
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
	if ((rv=missingExport_sc_match_atr(card, acos5_64_atrs.ptr, &card.type)) < 0)
		return rv=0;

	return rv=!/*cast(bool)*/acos5_64_match_card_checks(card);
}


void handleErrors(int i) {
	version(ENABLE_TOSTRING) {
		writer.put("handleErrors(int i) called\n");
		writer.formattedWrite("%s", i);
	}
}

int encrypt_algo(in uba plaintext,  in ubyte* key, in ubyte* iv, ubyte* ciphertext, const(EVP_CIPHER)* algo, bool pad=true,
	uint macOut_len = DES_KEY_SZ /* this is for CMAC only and may be given to reduce number of MAC bytes (starting at last ub8 block) written to ciphertext*/) {
// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
// http://etutorials.org/Programming/secure+programming/Chapter+5.+Symmetric+Encryption/5.17+Performing+Block+Cipher+Setup+for+CBC+CFB+OFB+and+ECB+Modes+in+OpenSSL/
	EVP_CIPHER_CTX* evp_ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if ((evp_ctx = EVP_CIPHER_CTX_new()) == null)
		handleErrors(1);

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(evp_ctx, algo, null, key, iv))
		handleErrors(2);

	if (!pad)
		EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(evp_ctx, ciphertext, &len, plaintext.ptr, cast(int)plaintext.length))
		handleErrors(3);
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(evp_ctx, ciphertext + len, &len))
		handleErrors(4);
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(evp_ctx);

	return ciphertext_len;
}


int decrypt_algo(in uba ciphertext, in ubyte* key, in ubyte* iv, ubyte* plaintext,  const(EVP_CIPHER)* algo, bool pad=true) {
	EVP_CIPHER_CTX* evp_ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
//	if (!(evp_ctx = EVP_CIPHER_CTX_new()))
	if ((evp_ctx = EVP_CIPHER_CTX_new()) == null)
		handleErrors(11);

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_DecryptInit_ex(evp_ctx, algo, /*EVP_aes_256_cbc()*/ null, key, iv))
		handleErrors(12);

	if (!pad)
		EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(evp_ctx, plaintext, &len, ciphertext.ptr, cast(int)ciphertext.length))
		handleErrors(13);
	plaintext_len = len;

	/* Finalizee the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(evp_ctx, plaintext + len, &len))
		handleErrors(14);
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(evp_ctx);

	return plaintext_len;
}

/** swallow all ciphertext except last DES_KEY_SZ-sized block, ouput first out_len bytes of this
 * CBC-MAC  based on des_ede3_cbc/des_ede_cbc, 24/16 byte key,
 * adapted for convinience as ACOS5_64 takes a 4 byte out_len MAC only
 * not strictly necessary, if des3_encrypt_cbc is applied correctly (last 8 byte block !); advantage: less (fixed) memory alloc; simple building block
 */
int encrypt_algo_cbc_mac(in uba plaintext, in ubyte* key, in ubyte* iv, ubyte* ciphertext, const(EVP_CIPHER)* algo, bool pad=true, uint dac=DAC, uint out_len = DES_KEY_SZ)
{
	DES_cblock    res    = iv[0..8];
	ub24 /*DES_cblock*/ iv2;
	const(ubyte)* in_p   = plaintext.ptr;
	size_t        in_len = plaintext.length;
	int           rv     = SC_ERROR_SM_INVALID_CHECKSUM;

	if (/*input-*/in_len==0 || in_len % DES_KEY_SZ || out_len>8 || !canFind([EVP_des_ede3_cbc, EVP_des_ede_cbc], algo))
		return rv;

	while (in_len>0) {
		iv2 = ub24.init;
		iv2[0..8] = res[];
		if ((rv=encrypt_algo(in_p[0..8], key, iv2.ptr, res.ptr, algo, false)) != DES_KEY_SZ)
			return rv;
		in_p   += DES_KEY_SZ;
		in_len -= DES_KEY_SZ;
	}
	ciphertext[0..out_len] = res[0..out_len];
	return out_len;
}

unittest {
	version(SESSIONKEYSIZE24) {
		ub24 random_bytes;
		assert(1==RAND_bytes(random_bytes.ptr, random_bytes.length));
		immutable(ub24) key = random_bytes[];//(representation(x"0102030405060708090A0B0C0D0E0F101112131415161718"))[];
	}
	else {
		ub16 random_bytes;
		assert(1==RAND_bytes(random_bytes.ptr, random_bytes.length));
		immutable(ub16) key = random_bytes[];//(representation(x"0102030405060708090A0B0C0D0E0F10"))[];
	}

	immutable(ubyte[72]) plaintext_pre = representation("###Victor jagt zwölf Boxkämpfer quer über den großen Sylter Deich###")[]; // includes 4 2-byte german unicode code points
	ubyte[72]            ciphertext;
	ubyte[72]            plaintext_post;
	ub8                  mac;
	ub8                  iv; // for TripleDES usage only
	int                  rv;
	writefln("plaintext_pre:  0x [%(%02x %)]", plaintext_pre);
	assert(plaintext_pre.length==encrypt_algo(plaintext_pre,  key.ptr, iv.ptr, ciphertext.ptr,     cipher_TDES[CBC], false));
	assert(plaintext_pre.length==decrypt_algo(ciphertext,     key.ptr, iv.ptr, plaintext_post.ptr, cipher_TDES[CBC], false));
	assert(equal(plaintext_pre[], plaintext_post[]));
	writefln("plaintext_post: 0x [%(%02x %)]", plaintext_post);
	assert(  mac.length==encrypt_algo_cbc_mac(plaintext_pre,  key.ptr, iv.ptr, mac.ptr,            cipher_TDES[DAC], false, DAC));
	writefln("ciphertext:     0x [%(%02x %)]", ciphertext);
	writefln("mac:            0x [                                                                                                                                                                                                %(%02x %)]", mac);
	mac = mac.init;
	iv = [1,2,3,4,5,6,7,8];
	assert(           4==encrypt_algo_cbc_mac(plaintext_pre,  key.ptr, iv.ptr, mac.ptr,            cipher_TDES[DAC], false, DAC, 4));
	writefln("mac4:           0x [%(%02x %)]", mac);
	writeln("PASSED: encrypt_algo, decrypt_algo, encrypt_algo_cbc_mac, without padding");
}

private int check_weak_DES_key(sc_card* card, in uba key) {
	return SC_SUCCESS;
}


private extern(C) int acos5_64_init(sc_card* card) {
	sc_context* ctx = card.ctx;
	int         rv  = SC_ERROR_INVALID_CARD;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_init"`, `"called"`));
	mixin log_scope_exit!("acos5_64_init");
	mixin transmit_apdu_strerror!("acos5_64_init");
	scope(exit)
		log_scope_exit_do(__LINE__);

	{ // local ii
		int ii;
		for (ii=0; acos5_64_atrs[ii].atr; ++ii)
			if (card.type == acos5_64_atrs[ii].type)
				break;

		// if no card.type match in previous for loop, ii is at list end marker all zero
		if (!acos5_64_atrs[ii].atr) {
			mixin (log!(`"acos5_64_init"`, `"about to stall this driver (some matching problem)"`));
			return rv=SC_ERROR_INVALID_CARD;
		}
	}


	static int once;
	bytes2apdu(ctx, representation(x"00 A4 00 00"), apdu);
	apdu.flags = SC_APDU_FLAGS_NO_GET_RESP;
	if ((rv=transmit_apdu_strerror_do(__LINE__))<0)  return rv;
	if ( !(apdu.sw1 == 0x69 && apdu.sw2 == 0x86)) {
//		do_zeroize_token = true; // CHANGE_HERE_FOR_ZEROIZE : remove leading //
		if (do_zeroize_token) {
			re_initialize_token(card, representation(x"38 37 36 35 34 33 32 31" /* SO_PIN */), null);
			return rv=SC_ERROR_INVALID_CARD;
		}
	}
	else {
		++once;
		if (once==1) {
			do_initialize_token = true; // CHANGE_HERE_FOR_INIT : remove leading //
			if ((rv=re_initialize_token(card, representation(x"38 37 36 35 34 33 32 31" /* SO_PIN */), null)) < 0)
				return rv;
			bytes2apdu(ctx, representation(x"00 A4 00 00"), apdu);
			apdu.flags = SC_APDU_FLAGS_NO_GET_RESP;
			if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
			if (apdu.sw1 == 0x69 && apdu.sw2 == 0x86)  return rv=SC_ERROR_INVALID_CARD; // MF still doesn't exist
		}
	}

	if (card.type==SC_CARD_TYPE_ACOS5_64_V2)  { // the Operation Mode Byte Setting cab't be retrieved from card; it must be assumed that the card is set to ACOSMODE_V2
	}
	else { // (card.type==SC_CARD_TYPE_ACOS5_64_V3)
		// the Operation Mode Byte Setting retrievable from card and the dlang version specifier must match
		bytes2apdu(ctx, representation(x"80 14 09 00"), apdu);
		if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
		if (apdu.sw1 != 0x90 || !canFind([ EnumMembers!EACOSV3MODE ], apdu.sw2))
			return rv=SC_ERROR_INVALID_CARD;
		mixin (log!(`"acos5_64_init"`, `"Operation Mode Byte is set to: %i (ACOSMODE_V3_FIPS_140_2L3(0),'Emulated 32K Mode'(1), ACOSMODE_V2(2), ACOSMODE_V3_NSH_1(16))"`,"apdu.sw2"));
version (ACOSMODE_V3_FIPS_140_2L3) {
		if (EACOSV3MODE.eACOSV3MODE_V3_FIPS_140_2L3 != apdu.sw2) {
			mixin (log!(`"acos5_64_init"`, `"Operation Mode Byte set doesn't match %u (version identifier ACOSMODE_V3_FIPS_140_2L3, this code was compiled with)"`, "EACOSV3MODE.eACOSV3MODE_V3_FIPS_140_2L3"));
			return rv=SC_ERROR_INVALID_CARD;
		}
		// check FIPS 140_2L3 compliance: card file system and settings
		bytes2apdu(ctx, representation(x"80 14 0A 00"), apdu);
		if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
		if ((rv=sc_check_sw(card, apdu.sw1, apdu.sw2))<0) return rv;
		return rv=SC_ERROR_INVALID_CARD;
}
else version (ACOSMODE_V2) {
		if (     EACOSV3MODE.eACOSV3MODE_V2 != apdu.sw2) {
			mixin (log!(`"acos5_64_init"`, `"Operation Mode Byte set doesn't match %u (version identifier ACOSMODE_V2, this code was compiled with)"`, "EACOSV3MODE.eACOSV3MODE_V2"));
			return rv=SC_ERROR_INVALID_CARD;
		}
}
else version(ACOSMODE_V3_NSH_1) {
		if (    EACOSV3MODE.eACOSV3MODE_V3_NSH_1 != apdu.sw2) {
			mixin (log!(`"acos5_64_init"`, `"Operation Mode Byte set doesn't match %u (version identifier ACOSMODE_V3_NSH_1, this code was compiled with)"`, "EACOSV3MODE.eACOSV3MODE_V3_NSH_1"));
			return rv=SC_ERROR_INVALID_CARD;
		}
		return rv=SC_ERROR_INVALID_CARD;
}
else
		static assert(0); // exactly one of ACOSMODE_V2, ACOSMODE_V3_FIPS_140_2L3, ACOSMODE_V3_NSH_1 must be used
	} // (card.type==SC_CARD_TYPE_ACOS5_64_V3)


version(none) // FIXME activate this again for Posix, investigate for Windows, when debugging is done
{
version(Posix)
{
	import core.sys.posix.sys.resource : RLIMIT_CORE, rlimit, setrlimit;
	rlimit core_limits; // = rlimit(0, 0);
	if ((rv=setrlimit(RLIMIT_CORE, &core_limits)) != 0) { // inhibit core dumps, https://download.libsodium.org/doc/helpers/memory_management.html
		mixin (log!(`"acos5_64_init"`, `"Setting rlimit failed !"`));
		return rv;
	}
}
}

	c_ulong algoflags =   SC_ALGORITHM_ONBOARD_KEY_GEN   // 0x8000_0000
						| SC_ALGORITHM_RSA_RAW           // 0x0000_0001  /* RSA raw support */
						| SC_ALGORITHM_RSA_PAD_NONE //   CHANGED, but makes no difference; it means: the card/driver doesn't do the padding, but opensc does it
						| SC_ALGORITHM_RSA_HASH_SHA1     // sign: the driver will not use RSA raw  0x0000_0020
						| SC_ALGORITHM_RSA_HASH_SHA256   // sign: the driver will not use RSA raw  0x0000_0200
				;                       // 0x8000_0231

	with (card) {
		caps =  SC_CARD_CAP_RNG | SC_CARD_CAP_USE_FCI_AC;
		cla           = 0x00;  // int      default APDU class (interindustry)
		max_send_size = SC_READER_SHORT_APDU_MAX_SEND_SIZE; //0x0FF; // 0x0FFFF for usb-reader, 0x0FF for chip/card;  Max Lc supported by the card
		max_recv_size = SC_READER_SHORT_APDU_MAX_RECV_SIZE; //0x100; // 0x10000 for usb-reader, 0x100 for chip/card;  Max Le supported by the card, decipher (in chaining mode) with a 4096-bit key returns 2 chunks of 256 bytes each !!
	} // with (card)

	int missingExport_sc_card_add_rsa_alg(sc_card* card, uint key_length, c_ulong flags, c_ulong exponent)
	{ // same as in opensc, but combined with _sc_card_add_algorithm; both are not exported by libopensc
		sc_algorithm_info info;
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

version(ACOSMODE_V3_FIPS_140_2L3)
	immutable uint key_len_from = 0x800, key_len_to = 0x0C00, key_len_step = 0x400;
else
	immutable uint key_len_from = 0x200, key_len_to = 0x1000, key_len_step = 0x100;

	for (uint key_len = key_len_from; key_len <= key_len_to; key_len += key_len_step)
		missingExport_sc_card_add_rsa_alg(card, key_len, algoflags, 0x10001);

	card.max_pin_len = 8;
	{
	/* reason for df_dummy: currently the functions calld by sc_select_file need a card.cache.current_df "before the initial card.cache.current_df get's returned ! */
		sc_file*  file, df_dummy = sc_file_new();
		scope(exit)
			sc_file_free(df_dummy);
		with (df_dummy) {
			path = MF_path;
			type = SC_FILE_TYPE.SC_FILE_TYPE_DF;
			id   = 0x3F00;
		}
		card.cache.valid = 1;
		card.cache.current_df = df_dummy;

		acos5_64_private_data*  private_data = cast(acos5_64_private_data*) calloc(1, acos5_64_private_data.sizeof);
		if (private_data == null)
			return rv=SC_ERROR_MEMORY_FAILURE;

		with (private_data.current_df_se_info) {
			fdb       = EFDB.MF;
			fid       = integral2ub!2(0x3F00);
			seid      = integral2ub!2(0x0003);
		}
		card.drv_data = private_data;

		// on reset, MF is automatically (internally) selected, but card* still doesn't know abaout that
		if ((rv=sc_select_file(card, &MF_path, &file)) < 0) {
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init", "select MF failed");
			return rv=SC_ERROR_FILE_NOT_FOUND;
		}
		card.cache.valid = card.cache.current_df? 1 : 0;
		card.cache.current_df = file;
	}

	if ((rv=acos5_64_get_serialnr(card, null)) < 0) { // card.serialnr will be stored/cached
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_init",
			"Retrieving ICC serial# failed: %i (%s)", rv, sc_strerror(rv));
		return rv;
	}

	with (card) {
		with (version_) {
			fw_major = hw_major;
			fw_minor = hw_minor;
		}
version(ENABLE_SM)
{
		with (sm_ctx) { // sm_context
			info.serialnr                       = card.serialnr;
			with (card.sm_ctx.info) {
				config_section                    = "acos5_64_sm";
				card_type                         = card.type;
				sm_type                           = SM_TYPE_CWA14890;
version(SESSIONKEYSIZE24)
				session.cwa.params.crt_at.refs[0] = 0x82; // this is the selection of keyset_... ...02_... to be used !!! Currently 24 byte keys (generate 24 byte session keys)
else
				session.cwa.params.crt_at.refs[0] = 0x81; // this is the selection of keyset_... ...01_... to be used !!!           16 byte keys (generate 16 byte session keys)

				if (card.cache.current_df)
					current_path_df                 = card.cache.current_df.path;
				current_aid                       = sc_aid(); // ubyte[SC_MAX_AID_SIZE==16] value; size_t len;
				current_aid.len                   = SC_MAX_AID_SIZE; // = "ACOSPKCS-15v1.00".length
				current_aid.value                 = representation("ACOSPKCS-15v1.00")[];
			}
			ops.open          = &sm_acos5_64_card_open;
			ops.close         = &sm_acos5_64_card_close;
			ops.get_sm_apdu   = &sm_acos5_64_card_get_apdu;
			ops.free_sm_apdu  = &sm_acos5_64_card_free_apdu;
//			ops.read_binary   = &sm_acos5_64_card_read_binary;   // SC_AC_OP_READ
//			ops.update_binary = &sm_acos5_64_card_update_binary; // SC_AC_OP_UPDATE
		} // with (sm_ctx)
} // version(ENABLE_SM)
	} // with (card)

version(ENABLE_ACOS5_64_UI) {
	/* read environment from configuration file */
	if ((rv=acos5_64_get_environment(card, &(get_acos5_64_ui_ctx(card)))) != SC_SUCCESS) {
		free(card.drv_data);
		mixin (log!(`"acos5_64_init"`, `"Failure reading acos5_64 environment."`));
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
private extern(C) int acos5_64_finish(sc_card* card) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(`"acos5_64_finish"`, `"called"`));
	mixin log_scope_exit!("acos5_64_finish");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if (card.drv_data) {
		free(card.drv_data);
		card.drv_data = null;
	}
	return rv=SC_SUCCESS;
}


private extern(C) int acos5_64_erase_binary(sc_card* card, uint idx, size_t count, c_ulong flags)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"acos5_64_erase_binary"`, `"called"`));
	mixin log_scope_exit!("acos5_64_erase_binary");
	scope(exit)
		log_scope_exit_do(__LINE__);

	return rv;
}

/**
opensc-tool doesn't communicate the length of data to be read, only the length of accepting buffer is specified (ubyte[256] buf is sufficient, as acos MRL is 255)
1 trial and error is sufficient, asking for 0xFF bytes: In the likely case of wrong length, acos will respond with 6C XXh where XXh is the maximum bytes
available in the record and opensc automatically issues the corrected APDU once more
*/
private extern(C) int acos5_64_read_record(sc_card* card, uint rec_nr,
	ubyte* buf, size_t buf_len, c_ulong flags) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_read_record"`, `"called"`));
	mixin transmit_apdu!("acos5_64_read_record");
	mixin log_scope_exit!("acos5_64_read_record");
	scope(exit)
		log_scope_exit_do(__LINE__);

	mixin (log!(`"acos5_64_read_record"`, `"called with rec_nr(%u), buf_len(%lu), flags(%lu)"`,"rec_nr","buf_len","flags"));

	bytes2apdu(ctx, representation(x"00 B2 00 04 FF"), apdu); // opensc/acos indexing differ by 1
	apdu.p1 = cast(ubyte)(1+rec_nr);
	apdu.resp    = buf;
	apdu.resplen = buf_len;

	if ((rv=transmit_apdu_do(__LINE__)) < 0) return rv;
	if (apdu.resplen == 0)
		return rv=sc_check_sw(card, apdu.sw1, apdu.sw2);

	return rv=cast(int)apdu.resplen;
}

/** Helps manipulating arrays of ubyte with a subrange used/valid; implicitely converts to ubyte[]
	it's usefull especially for path changing operations */
struct UByteArray(size_t granularity=1) {
	private uba    rep;
	private size_t rep_len_valid;
	private size_t ever_dropped;

	@property size_t len_valid() { return rep_len_valid; }

	invariant() {
		assert(rep.length == rep_len_valid + ever_dropped);
	}

	alias rep this; // alias this enables the specific (implicit) conversion from UByteArray!? type to uba type


	this(uba val) {
		rep           = val.dup;
		rep_len_valid = val.length;
	}
	this(uba val, size_t len_valid) {
		rep           = val.dup;
		rep_len_valid = clamp(len_valid, 0, val.length);
		ever_dropped  = rep.length - rep_len_valid;
	}
	this(this) {
		writefln("rep has been copy-constructed. postblitting now");
		rep           = rep.dup;
	}

	UByteArray opAssign(UByteArray rhs) {
		writefln("rep is being changed from 0x [%(%02X %)] to 0x [%(%02X %)]", this.rep, rhs.rep);
		this.rep           = rhs.rep.dup;
		this.rep_len_valid = rhs.rep_len_valid;
		this.ever_dropped  = rhs.ever_dropped;
		return this;
	}

	UByteArray opAssign(uba rhs) {
		writefln("rep is being replaced by an uba");
		this.rep           = rhs.dup;
		this.rep_len_valid = rhs.length;
		this.ever_dropped  = 0;
		return this;
	}

	bool opEquals()(auto ref const UByteArray rhs) {
		return this.rep_len_valid==rhs.rep_len_valid && equal(this.rep, rhs.rep);
	}

	bool opEquals()(in uba rhs) {
		return rep_len_valid==rhs.length && equal(rep[0..rep_len_valid], rhs);
	}

	UByteArray opBinary(string op)(in size_t rhs)
		if (op == "<<")
	{
		writefln(`x.opBinary!"<<"(y) called`);
		UByteArray  new_one = this;
		size_t cutLen = clamp(rhs*granularity, 0, new_one.rep_len_valid);

		new_one.rep_len_valid -= cutLen;
		new_one.ever_dropped  += cutLen;
		new_one.rep = dropExactly(new_one.rep, cutLen) ~ repeat(ubyte(0)).take(cutLen).array; // cutLen bytes to shift left and append cutLen bytes of zero-valued bytes
		return new_one;
	}

	ref UByteArray opOpAssign(string op)(in size_t rhs)
		if (op == "<<")
	{
		size_t cutLen = clamp(rhs*granularity, 0, rep_len_valid);
		rep_len_valid -= cutLen;
		ever_dropped  += cutLen;
		rep = dropExactly(rep, cutLen) ~ repeat(ubyte(0)).take(cutLen).array; // a new rep array
		return this;
	}

	void popBackN(size_t n) {
		if (n<=rep_len_valid) {
			rep[rep_len_valid-n..rep_len_valid] = 0;
			rep_len_valid -= n;
			ever_dropped  += n;
		}
		else {
			rep[0..min(n,rep.length)] = 0;
			rep_len_valid  = 0;
			ever_dropped   = rep.length;
		}
	}
}

unittest {
	import std.range.primitives;
	auto UBA1 = UByteArray!2( x"3F00 4100 1000 1234".representation.dup, 8 );
	auto UBA2 = UByteArray!2( x"1000 1234 0000 0000".representation.dup, 4 );
	assert((UBA1<<=2) == UBA2);
	auto UBA3 = UByteArray!1( x"3F00 4100 1000 1234".representation.dup, 8 );
	auto UBA4 = UByteArray!1( x"1000 1234 0000 0000".representation.dup, 4 );
	assert((UBA3<<=4) == UBA4);
	auto UBA5 = UByteArray!1( x"3F00 4100 1000 1234".representation.dup, 8 );
	UBA5.popBackN(2);
	assert(UBA5==x"3F00 4100 1000".representation);
	writeln("PASSED: testing UByteArray");
}

struct SelectSupport {
	sc_card*      card;
	sc_path*      path;
	const size_t  plen;
	size_t*       pclen;
	this(sc_card* in_card, sc_path* in_path) {
		card  = in_card;
		path  = in_path;
		plen  = in_path.len;
		if (in_card.cache.valid && in_card.cache.current_df)
			pclen = &in_card.cache.current_df.path.len;
	}

	int run(bool* prestore_cache_current_df, bool force_select_prefix=false) {
		sc_context*      ctx = card.ctx;
		int              rv;
		bool             seid_changed;
		bool             skip_some_seid_retrieval;

// First cut
		assert(plen>=2);
		if (!card.cache.valid) {
			skip_some_seid_retrieval = false;
		}
		else {
			auto  m = mismatch    (card.cache.current_df.path.value[0..*pclen], path.value[0..plen]);
			auto CP = commonPrefix(card.cache.current_df.path.value[0..*pclen], path.value[0..plen]); // 3F00
			assert(equal(CP~m[0],  card.cache.current_df.path.value[0..*pclen]));                     // 4100
			assert(equal(CP~m[1],  path.value[0..plen]));                                             // 50154946

			if (force_select_prefix || plen==2 || CP.length==0) {
				if (!sc_compare_path(&MF_path, path))
					return -1;
				seid_changed             = (*pclen==2? false : true);
				skip_some_seid_retrieval = false; //plen>4;
				*pclen = 0;
				card.cache.valid = 0;
			}
			else { // !force_select_prefix && plen>=4 && CP.length>=2 and at least CP.length-2 are DFs
				if (empty(m[1])) { // plen==CP.length
					*pclen = CP.length - 2;
					seid_changed =             (empty(m[0])? false : true);
					skip_some_seid_retrieval = (empty(m[0])? true  : *pclen>2);
				}
				else { // plen>CP.length
					*pclen = CP.length;
					seid_changed =             (empty(m[0])? true /*don't know*/ : true);
					skip_some_seid_retrieval =                       m[1].length>4; // CHANGED from *pclen>2
				}

				with (path) {
					len           -= *pclen;
					value[0..plen] = (UByteArray!1(value[0..plen]) <<= *pclen)[];
				}
			}
		}

		size_t  cutLen = path.len - 2;
		if (cutLen)   {
			sc_apdu  apdu;
			mixin transmit_apdu_strerror!("struct SelectSupport:run");
			scope(exit)
				card.cache.valid = rv<0 && !*prestore_cache_current_df? 0 : card.cache.valid;
			foreach (j; 0..cutLen/2) {
				assert(path.len>=2);
				ubyte[MAX_FCI_GET_RESPONSE_LEN]  rbuf;
				bytes2apdu(ctx, representation(x"00 A4 00 00 02") ~ path.value[0..2] ~ ubyte(MAX_FCI_GET_RESPONSE_LEN) /*le estimated*/, apdu);
				apdu.resp    = rbuf.ptr;
				apdu.resplen = rbuf.length;
				if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
				if ((rv=sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
					if (j==0)
						*prestore_cache_current_df = true;
					return rv;
				}
				card.cache.valid = 1;
				if (!skip_some_seid_retrieval || j+1>=cutLen/2)
					if ((rv=process_fci_sac_se(card, rbuf[0..apdu.resplen],null,/*enveloped=*/true,/*skip_seid_retrieval=*/false,/*sacNONE=*/false)) < 0)  return rv; // communicate potential change of Security Environment

				auto UBA  = UByteArray!1(path.value[0..plen]);
				with (path) {
					value[0..plen] = (UBA <<= 2)[];
					len           -= 2;
				}
			}
		} // if (cutLen)
		return rv= SC_SUCCESS;
	} // run
} // struct SelectSupport

/* designed to always select the last path component, but potentially discard selecting it's prefix components; assumes we always get a complete path beginning at MF */
private int acos5_64_select_file_by_path(sc_card* card, const(sc_path)* in_path, sc_file** file_out, bool force_select_prefix=false)
{
	assert(in_path.len%2==0);
	sc_context*  ctx  = card.ctx;
	int          rv   = SC_ERROR_UNKNOWN;
	sc_path      path = *in_path;
	acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
	auto  info = &private_data.current_df_se_info;
	bool restore_cache_current_df;
/* */
	if (!card.cache.current_df)
		mixin (log!(`"acos5_64_select_file_by_path"`, `"called with card.cache.valid: %i, force: %i"`, "card.cache.valid", "force_select_prefix"));
	else {
		mixin (log!(`"acos5_64_select_file_by_path"`, `"called with card.cache.current_df.path.value: %s, valid: %i, force_select_prefix: %i"`,
			"sc_dump_hex(card.cache.current_df.path.value.ptr, card.cache.current_df.path.len)", "card.cache.valid", "force_select_prefix"));
//		mixin (log!(`"acos5_64_select_file_by_path"`, `"called with                        path_fid : %s"`, "sc_dump_hex(info.path_fid.value.ptr,  info.path_fid.len)"));
		sc_path  path_seid = card.cache.current_df.path; sc_append_path_id(&path_seid, private_data.current_df_se_info.seid.ptr, 2);
		mixin (log!(`"acos5_64_select_file_by_path"`, `"called with                        path_seid: %s"`, "sc_dump_hex(path_seid.value.ptr, path_seid.len)"));
	}
/* */
	mixin (log!(`"acos5_64_select_file_by_path"`, `"called with                          in_path: %s, &(sc_file*): %p"`,
		"sc_dump_hex(in_path.value.ptr, in_path.len)", "file_out"));
	mixin log_scope_exit!("acos5_64_select_file_by_path");
	scope(exit) {
		card.cache.valid = ((rv<0 && !restore_cache_current_df)  || (card.cache.current_df && card.cache.current_df.path.len==0)) ?
			0 : card.cache.valid; // refers only to card.cache.current_df
		if (card.cache.current_df) {
			mixin (log!(`"acos5_64_select_file_by_path"`, `"returning card.cache.current_df.path.value: %s, valid: %i"`,
				"sc_dump_hex(card.cache.current_df.path.value.ptr, card.cache.current_df.path.len)", "card.cache.valid"));
			mixin (log!(`"acos5_64_select_file_by_path"`, `"returning                             fid : %s"`, "sc_dump_hex(info.fid.ptr, 2)"));
			sc_path  path_seid = card.cache.current_df.path; sc_append_path_id(&path_seid, private_data.current_df_se_info.seid.ptr, 2);
			mixin (log!(`"acos5_64_select_file_by_path"`, `"returning                        path_seid: %s"`, "sc_dump_hex(path_seid.value.ptr, path_seid.len)"));
		}
/* */
		log_scope_exit_do(__LINE__);
	}

	sc_path  cccdf_path_saved = card.cache.current_df.path;
	int      ccv_saved        = card.cache.valid;

	if ((!file_out) && (!force_select_prefix && ccv_saved && cccdf_path_saved.len==in_path.len && cccdf_path_saved.value==in_path.value))  return rv=SC_SUCCESS;
	if ((rv=  SelectSupport(card, &path).run(&restore_cache_current_df, force_select_prefix)) < 0) { // run: maybe does nothing or path gets shortened, prefix selections done, cache.current_df adapted
		mixin (log!(`"acos5_64_select_file_by_path"`, `"selecting/discarding prefix path components returned an error"`));
		if (restore_cache_current_df) {
			card.cache.current_df.path = cccdf_path_saved;
			card.cache.valid           = ccv_saved;
		}
		return rv;
	}

	path.type = SC_PATH_TYPE_FILE_ID;
	if ((rv=  iso_ops_ptr.select_file(card, &path, file_out)) == SC_SUCCESS)   {
		card.cache.valid = 1;
		if (!file_out) {
			ubyte[MAX_FCI_GET_RESPONSE_LEN] arr;
			size_t count = MAX_FCI_GET_RESPONSE_LEN;
			if ((rv=  iso_ops_ptr.get_response(card, &count, arr.ptr)) < 0)      return rv;
			if ((rv=  process_fci_sac_se(card, arr[0..count], null,/*enveloped=*/true,/*skip_seid_retrieval=*/false,/*sacNONE=*/false)) < 0)
				return rv;
		}
	}
	return rv;
}


private extern(C) int acos5_64_select_file(sc_card* card, const(sc_path)* path, sc_file** file_out)
{
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_INS_NOT_SUPPORTED;
	mixin (log!(`"acos5_64_select_file"`, `"called"`));
	mixin log_scope_exit!("acos5_64_select_file");
	scope(exit)
		log_scope_exit_do(__LINE__);

	final switch (cast(SC_PATH_TYPE)path.type) {
		case  SC_PATH_TYPE_PATH_PROT:
			return rv=SC_ERROR_INS_NOT_SUPPORTED;
		case  SC_PATH_TYPE_DF_NAME:
			rv = iso_ops_ptr.select_file(card, path, file_out);
			if (file_out && *file_out && (**file_out).path.len > 0) {
				/* TODO test this */
				card.cache.current_df.path = (**file_out).path;
				card.cache.valid = 1; /* maybe not starting with 3F00 */
			}
			else
				card.cache.valid = 0;
			return rv;
		case  SC_PATH_TYPE_FILE_ID,  SC_PATH_TYPE_FROM_CURRENT,  SC_PATH_TYPE_PARENT:
			goto case  SC_PATH_TYPE_PATH;

		case  SC_PATH_TYPE_PATH:
			return rv=acos5_64_select_file_by_path(card, path, file_out);
	}
}


/**
 *  The iso7816.c -version get_challenge get's wrapped to have RNDc known by terminal/host in sync with card's last SM_SMALL_CHALLENGE_LEN challenge handed out
 *  len is restricted to be a multiple of 8 AND 8<=len
 */
private extern(C) int acos5_64_get_challenge(sc_card* card, ubyte* rnd, size_t len)
{
	int rv = SC_ERROR_UNKNOWN;
	sc_context* ctx = card.ctx;
	mixin (log!(`"acos5_64_get_challenge"`, `"called"`));
	mixin log_scope_exit!("acos5_64_get_challenge");
	scope(exit)
		log_scope_exit_do(__LINE__);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
		"len: %lu\n", len);
	if (len==0)
		return rv=SC_SUCCESS;
	if (len<SM_SMALL_CHALLENGE_LEN /*|| (len%SM_SMALL_CHALLENGE_LEN)*/) {
		rv = -1;
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
			"called with inappropriate len arument: %i (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	ubyte* p_rnd = rnd;
	size_t p_len = len;
version(ENABLE_SM)
	with (card.sm_ctx.info.session.cwa)
	if (p_rnd == null) {
		p_rnd = icc.rnd.ptr;
		p_len = icc.rnd.length;
	}

	if ((rv=iso_ops_ptr.get_challenge(card, p_rnd, p_len)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_get_challenge",
			"iso_ops_ptr.get_challenge failed: %i (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

version(ENABLE_SM)
	with (card.sm_ctx.info.session.cwa) {
		if (p_rnd != icc.rnd.ptr)
			icc.rnd        = p_rnd[(p_len-SM_SMALL_CHALLENGE_LEN) .. p_len]; // SM_SMALL_CHALLENGE_LEN==8;
		card_challenge   = icc.rnd;
		ssc              = icc.rnd;
	} // version(ENABLE_SM)

	return rv;
}

private extern(C) int acos5_64_logout(sc_card* card)
{
	sc_context* ctx = card.ctx;
	int rv;
	sc_apdu apdu;
	mixin (log!(q{"acos5_64_logout"}, q{"called"}));
	mixin transmit_apdu_strerror!("acos5_64_logout");
	mixin log_scope_exit!("acos5_64_logout");
	scope(exit)
		log_scope_exit_do(__LINE__);

	bytes2apdu(ctx, representation(x"80 2E 00 81"), apdu);
	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;

	return rv=sc_check_sw(card, apdu.sw1, apdu.sw2);
}

enum {
	from_env,   //0
	from_usage, //1
}


/** constructs the "ubyte-string" for set security environment beginning with CRT template tag
 *  2 modes: 'from_env' taking input from sc_security_env or 'from_usage' taking input from the other parameters */
uba construct_sc_security_env (int mode, const(sc_security_env)* psec_env, CRT_TAG crtt, Usage usage=None,
	ubyte id_pin_key_local_global_or_key_session=0xFF/*None*/, ubyte algo=0xFF/*None, or infer*/, uba keyFile_RSA=null, uba iv=null)
{
	uba result;

	if (mode==from_env) {
		if (!psec_env)
			return result;
		with (*psec_env)   {
			if (!(flags & SC_SEC_ENV_ALG_PRESENT) || algorithm != SC_ALGORITHM_RSA /*|| algorithm_flags != SC_ALGORITHM_RSA_RAW*/)
				return result;
			if (!(flags & (SC_SEC_ENV_FILE_REF_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT)))
				return result;
			final switch (cast(SC_SEC_OPERATION)operation) {
				case SC_SEC_OPERATION_DECIPHER:
					crtt  = CRT_TAG.CT_asym;
					usage = Usage.Decrypt_PSO_priv; // Decrypt_PSO_priv, Decrypt_PSO_SMcommand_priv, Decrypt_PSO_SMresponse_priv, Decrypt_PSO_SMcommandResponse_priv,
					break;
				case SC_SEC_OPERATION_SIGN:
					crtt  = CRT_TAG.DST;
					usage = Usage.Sign_PKCS1_priv;
					break;
				case SC_SEC_OPERATION_AUTHENTICATE:  break;
				case SC_SEC_OPERATION_DERIVE:        break;
			}
			if (flags & SC_SEC_ENV_FILE_REF_PRESENT) {
				if (file_ref.len<2)
					return result;
				with (file_ref) keyFile_RSA = value[len-2..len].dup;
			}
			else {
				sc_path path;
				sc_format_path("41F0", &path);
				path.value[1] |= key_ref[0];
				with (path) keyFile_RSA = value[len-2..len].dup;
			}
		} // with (*psec_env) {
	} // if (mode==from_env)

	if (keyFile_RSA !is null && keyFile_RSA.length!=2)
		return result;

	result = [crtt==CT_asym? cast(ubyte)(crtt-1) : cast(ubyte)crtt] ~ ubZero; // length not known yet: 0 to be replaced later
	ubyte res_uqb, res_algo, res_idpk;
	ubyte uqb;

	switch (crtt) {
		case HT :     assert(aa_uqb_poss[crtt].list.length==0); uqb = 0xFF;                          break;
		case AT :     assert(aa_uqb_poss[crtt].list.length >0); uqb = aa_uqb_poss[crtt].list[usage-1]; break;
		case DST:     assert(aa_uqb_poss[crtt].list.length >0); uqb = aa_uqb_poss[crtt].list[usage-4]; algo=(usage -4<2? 0x10 : 0x11); break;
		case CT_asym: assert(aa_uqb_poss[crtt].list.length >0); uqb = aa_uqb_poss[crtt].list[usage-8]; algo=(usage -8<4? 0x13 : 0x12); break;
		case CT_sym:  assert(aa_uqb_poss[crtt].list.length >0); break;
		case CCT:     assert(aa_uqb_poss[crtt].list.length>=2);                                      algo=0x02; // SM: always algo 02
									uqb =  aa_uqb_poss[crtt].list[(usage-16)%2]; break;//(usage-16<2? aa_uqb_poss[crtt].list[0] : aa_uqb_poss[crtt].list[1]); break;
		default:
			break;
	}

	// .mandatory_And
	// has crtt an UQB requirement? if required, SubDO_Tag.UQB always is in .mandatory_And
	if (canFind(aa_crt_tags[crtt].mandatory_And, SubDO_Tag.UQB)) {
		result ~= [cast(ubyte)SubDO_Tag.UQB, ubyte(1)];
		if (aa_uqb_poss[crtt].list.length) { // otherwise aa_uqb_poss[crtt].list is ill-defined and the APDU command will fail
			res_uqb = canFind(aa_uqb_poss[crtt].list, uqb)? uqb : aa_uqb_poss[crtt].list[0];
			result ~= res_uqb;
		}
	}
	// has crtt an algo requirement? if required, SubDO_Tag.Algorithm always is in .mandatory_And
	if (canFind(aa_crt_tags[crtt].mandatory_And, SubDO_Tag.Algorithm)) {
		result ~= [cast(ubyte)SubDO_Tag.Algorithm, ubyte(1)];
		if (aa_alg_poss[crtt].list.length) { // otherwise aa_alg_poss[crtt].list is ill-defined and the APDU command will fail
			res_algo = canFind(aa_alg_poss[crtt].list, algo)? algo : aa_alg_poss[crtt].list[0];
			result ~= res_algo;
		}
	}
	// has crtt an KeyFile_RSA requirement? if required, SubDO_Tag.KeyFile_RSA always is in .mandatory_And
	if (canFind(aa_crt_tags[crtt].mandatory_And, SubDO_Tag.KeyFile_RSA)) {
		if (keyFile_RSA.length<2)
			keyFile_RSA = [ubyte(0),ubyte(0)];
		result ~= [cast(ubyte)SubDO_Tag.KeyFile_RSA, ubyte(2)] ~ keyFile_RSA;
	}

	// has crtt an ID_Pin_Key_Local_Global requirement in .mandatory_And? must be AT
	if (canFind(aa_crt_tags[crtt].mandatory_And, SubDO_Tag.ID_Pin_Key_Local_Global)) {
		result ~= [cast(ubyte)SubDO_Tag.ID_Pin_Key_Local_Global, ubyte(1)];
		if (aa_idpk_poss[crtt].list.length) { // otherwise aa_idpk_poss[crtt].list is ill-defined and the APDU command will fail
			res_idpk = canFind(aa_idpk_poss[crtt].list, id_pin_key_local_global_or_key_session)? id_pin_key_local_global_or_key_session : aa_idpk_poss[crtt].list[0];
			result ~= res_idpk;
		}
	}
	// has crtt
	if (canFind(aa_crt_tags[crtt].mandatory_OneOf, SubDO_Tag.HP_Key_Session)) {
		if (crtt==CCT && (usage-16)/2 == 0)
			result ~= [cast(ubyte)SubDO_Tag.HP_Key_Session, ubyte(0)];
		else {
			result ~= [cast(ubyte)SubDO_Tag.ID_Pin_Key_Local_Global, ubyte(1)];
			if (aa_idpk_poss[crtt].list.length) { // otherwise aa_idpk_poss[crtt].list is ill-defined and the APDU command will fail
				res_idpk = canFind(aa_idpk_poss[crtt].list, id_pin_key_local_global_or_key_session)? id_pin_key_local_global_or_key_session : aa_idpk_poss[crtt].list[(usage-16)/2];
				result ~= res_idpk;
			}
		}
	}
	// has crtt an optional Initial_Vector in .optional_SymKey? must be CT_sym or CCT
	if (canFind(aa_crt_tags[crtt].optional_SymKey, SubDO_Tag.Initial_Vector) && iv !is null && iv.length==8)
		result ~= [cast(ubyte)SubDO_Tag.Initial_Vector, ubyte(8)] ~ iv;

	if (result.length>1)
		result[1] = cast(ubyte)(result.length-2);
	return result;
}

unittest {
	assert(equal(construct_sc_security_env(1, null,     HT                  ), [0xAA, 0x03, 0x80, 0x01, 0x21][]));
	assert(equal(construct_sc_security_env(1, null,     HT, None, 0xFF, 0xFF), [0xAA, 0x03, 0x80, 0x01, 0x21][]));
	assert(equal(construct_sc_security_env(1, null,     HT, None, 0xFF, 0x20), [0xAA, 0x03, 0x80, 0x01, 0x20][]));
	assert(equal(construct_sc_security_env(1, null,     AT, Pin_Verify_and_SymKey_Authenticate), [AT, 0x06, 0x95, 0x01, 0x88, 0x83, 0x01, 0x81][]));
	assert(equal(construct_sc_security_env(1, null,     AT, SymKey_Authenticate),                [AT, 0x06, 0x95, 0x01, 0x80, 0x83, 0x01, 0x81][]));
	assert(equal(construct_sc_security_env(1, null,     AT, Pin_Verify),                         [AT, 0x06, 0x95, 0x01, 0x08, 0x83, 0x01, 0x81][]));
	assert(equal(construct_sc_security_env(1, null,     AT, Pin_Verify, 0x82),                   [AT, 0x06, 0x95, 0x01, 0x08, 0x83, 0x01, 0x82][]));
	assert(equal(construct_sc_security_env(1, null,     AT, SymKey_Authenticate, 0x82),          [AT, 0x06, 0x95, 0x01, 0x80, 0x83, 0x01, 0x82][]));
	assert(equal(construct_sc_security_env(1, null,DST,Sign_PKCS1_priv, 0xFF,0xFF,[ubyte(0x41), ubyte(0xF1)]), [0xB6, 0x0A, 0x95, 0x01, 0x40, 0x80, 0x01, 0x10, 0x81, 0x02, 0x41, 0xF1][]));
	assert(equal(construct_sc_security_env(1, null,DST,Verify_PKCS1_pub,0xFF,0xFF,[ubyte(0x41), ubyte(0x31)]), [0xB6, 0x0A, 0x95, 0x01, 0x80, 0x80, 0x01, 0x10, 0x81, 0x02, 0x41, 0x31][]));
	assert(equal(construct_sc_security_env(1, null,DST,Sign_9796_priv,  0xFF,0xFF,[ubyte(0x41), ubyte(0xF2)]), [0xB6, 0x0A, 0x95, 0x01, 0x40, 0x80, 0x01, 0x11, 0x81, 0x02, 0x41, 0xF2][]));
	assert(equal(construct_sc_security_env(1, null,DST,Verify_9796_pub, 0xFF,0xFF,[ubyte(0x41), ubyte(0x32)]), [0xB6, 0x0A, 0x95, 0x01, 0x80, 0x80, 0x01, 0x11, 0x81, 0x02, 0x41, 0x32][]));
	assert(equal(construct_sc_security_env(1, null,CT_asym,Usage.Decrypt_PSO_priv, 0xFF,0xFF,[ubyte(0x41), ubyte(0xF1)]),             [CT_sym, 0x0A, 0x95, 0x01, 0x40, 0x80, 0x01, 0x13, 0x81, 0x02, 0x41, 0xF1][]));
	assert(equal(construct_sc_security_env(1, null,CT_asym,Decrypt_PSO_SMcommandResponse_priv, 0xFF,0xFF,[ubyte(0x41), ubyte(0xF1)]), [CT_sym, 0x0A, 0x95, 0x01, 0x70, 0x80, 0x01, 0x13, 0x81, 0x02, 0x41, 0xF1][]));
	assert(equal(construct_sc_security_env(1, null,CT_asym,Encrypt_PSO_pub, 0xFF,0xFF,[ubyte(0x41), ubyte(0x31)]),                    [CT_sym, 0x0A, 0x95, 0x01, 0x40, 0x80, 0x01, 0x12, 0x81, 0x02, 0x41, 0x31][]));
	assert(equal(construct_sc_security_env(1, null,CT_asym,Encrypt_PSO_SMcommandResponse_pub, 0xFF,0xFF,[ubyte(0x41), ubyte(0x31)]),  [CT_sym, 0x0A, 0x95, 0x01, 0x70, 0x80, 0x01, 0x12, 0x81, 0x02, 0x41, 0x31][]));

	assert(equal(construct_sc_security_env(1, null,CCT,Session_Key_SM), [CCT, 0x08, 0x95, 0x01, 0x30, 0x80, 0x01, 0x02, 0x84, 0x00][]));
	assert(equal(construct_sc_security_env(1, null,CCT,Local_Key1, 0xFF, 0xFF, null, [8,7,6,5,4,3,2,1]), [CCT, 0x13, 0x95, 0x01, 0x40, 0x80, 0x01, 0x02, 0x83, 0x01, 0x81, 0x87, 0x08, 0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01][]));

	sc_security_env sec_enc;
	with (sec_enc) {
		flags     = SC_SEC_ENV_ALG_PRESENT | SC_SEC_ENV_KEY_REF_PRESENT | SC_SEC_ENV_FILE_REF_PRESENT;
		operation = SC_SEC_OPERATION_DECIPHER;
		algorithm = SC_ALGORITHM_RSA;
		algorithm_flags = SC_ALGORITHM_RSA_RAW;
		algorithm_ref   = 0;
		sc_format_path("41F3", &file_ref);
		key_ref[0]      = 3;
		key_ref_len     = 1;
	}
	assert(equal(construct_sc_security_env(0, &sec_enc, CRT_TAG.HT, Usage.None), [CT_sym, 0x0A, 0x95, 0x01, 0x40, 0x80, 0x01, 0x13, 0x81, 0x02, 0x41, 0xF3][]));

	writeln("PASSED: construct_sc_security_env"); // Decrypt_RSA_priv
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
	sc_apdu apdu;
	mixin (log!(q{"acos5_64_set_security_env"}, q{"called"}));
	mixin transmit_apdu_strerror!("acos5_64_set_security_env");
	mixin log_scope_exit!("acos5_64_set_security_env");
	scope(exit) {
		acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
		private_data.security_env = *env;
		log_scope_exit_do(__LINE__);
//		version(ENABLE_TOSTRING) {
//			writer.put("int acos5_64_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num) is returning with argument *env:\n");
//			writer.formattedWrite("%s", *env);
//		}
	}
/* */
	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_set_security_env(sc_card* card, const(sc_security_env)* env, int se_num) called with argument se_num, *env:\n");
		writer.formattedWrite("%s\n", se_num);
		writer.formattedWrite("%s", *env);
	}

	ubyte[SC_MAX_APDU_BUFFER_SIZE] sbuf;
	ubyte* p;
	int locked = 0;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x01, 0);
	p = sbuf.ptr;
	if (env.algorithm==SC_ALGORITHM_RSA &&
			(env.operation==SC_SEC_OPERATION_DECIPHER || env.operation==SC_SEC_OPERATION_SIGN)) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
			"about to call construct_sc_security_env with env.operation(%i), env.flags(%u), env.key_ref[0](%02X)\n", env.operation, env.flags, env.key_ref[0]);
		uba res = construct_sc_security_env (from_env, env, CRT_TAG.NA);
		if (res.length>1) {
			apdu.p2 = res[0];
			res = res [2..$];
			p[0..res.length] = res[];
			p += res.length;
		}
	}
	else {
	*p++ = 0x95;
	*p++ = 0x01;
	*p++ = (env.operation==6 ? 0x80 : (env.operation==3 ? 0xC0 : 0x40)); /* 0x80: public key usage; 0x40 : priv. key usage */

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
		apdu.p2 = CT_sym;
		break;
	case SC_SEC_OPERATION_SIGN:
		*p++ = 0x10;
		apdu.p2 = 0xB6;
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		*p++ = cast(ubyte)(env.flags & SC_SEC_ENV_ALG_REF_PRESENT? env.algorithm_ref & 0xFF : 0x00);
		apdu.p2 = CT_sym;
		break;
	case 5: // my encoding for SC_SEC_GENERATE_RSAKEYS_PRIVATE
		goto case SC_SEC_OPERATION_SIGN;
	case 6: // my encoding for SC_SEC_GENERATE_RSAKEYS_PUBLIC
		goto case SC_SEC_OPERATION_SIGN;
	default:
		return SC_ERROR_INVALID_ARGUMENTS;
	}

/+
	if (env.flags & SC_SEC_ENV_ALG_REF_PRESENT) {
		*p++ = 0x80;	 algorithm reference
		*p++ = 0x01;
		*p++ = env.algorithm_ref & 0xFF;
	}
+/
/* page 47 */
	if (env.operation!=SC_SEC_OPERATION_SIGN && (env.flags & SC_SEC_ENV_KEY_REF_PRESENT)) {
//		if (env.flags & SC_SEC_ENV_KEY_REF_ASYMMETRIC)
			*p++ = 0x83;
//		else
//			*p++ = 0x84;
		*p++ = cast(ubyte)env.key_ref_len;
		assert(sbuf.sizeof - (p - sbuf.ptr) >= env.key_ref_len);
		memcpy(p, env.key_ref.ptr, env.key_ref_len);
		p += env.key_ref_len;
	}
/* */
	} //else
	rv = cast(int)(p - sbuf.ptr);
	apdu.lc = rv;
	apdu.datalen = rv;
	apdu.data = sbuf.ptr;
	if (se_num > 0) {

		if ((rv=sc_lock(card)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"sc_lock() failed");
			return rv;
		}
		locked = 1;
	}
	if (apdu.datalen != 0) {
		if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) goto err;
		if ((rv=sc_check_sw(card, apdu.sw1, apdu.sw2))!=SC_SUCCESS) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_set_security_env",
				"%s: Card returned error", sc_strerror(rv));
			goto err;
		}
		if (env.operation==SC_SEC_OPERATION_SIGN) {
			ubyte[SC_MAX_APDU_BUFFER_SIZE] sbuf2;
//			sc_apdu apdu2 = apdu;
			sc_apdu apdu2;
			with (env.file_ref)
			bytes2apdu(card.ctx, representation(x"00 22 01")~construct_sc_security_env(1, null, CT_asym, Usage.Decrypt_PSO_priv, 0xFF, 0xFF, value[len-2..len].dup), apdu2);
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
	rv = transmit_apdu_strerror_do(__LINE__);
	sc_unlock(card);
	if (rv < 0)
		return rv;

	return sc_check_sw(card, apdu.sw1, apdu.sw2);
err:
	if (locked)
		sc_unlock(card);

	return rv;
}


private extern(C) int acos5_64_decipher(sc_card* card, const(ubyte)* in_, /*in*/ size_t in_len, ubyte* out_, /*in*/ size_t out_len)
{ // check in_len, out_len, they aren't constant any more, but treat them as if they are constant
	assert(card != null && in_ != null && out_ != null);
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	sc_apdu apdu;
	mixin (log!(q{"acos5_64_decipher"}, q{"called"}));
	mixin transmit_apdu_strerror!("acos5_64_decipher");
	mixin log_scope_exit!("acos5_64_decipher");
	scope(exit)
		log_scope_exit_do(__LINE__);
	acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
	bool call_to_compute_signature_in_progress = private_data.call_to_compute_signature_in_progress;
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
		"card.algorithm_count: %i\n", card.algorithm_count);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.caps:  %i\n", card.caps);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"card.flags: %i\n", card.flags);

//	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
//		"call_to_compute_signature_in_progress: %s\n", call_to_compute_signature_in_progress ? "true".toStringz : "false".toStringz);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"Input to decipher len: '%i' bytes:\n%s\n============================================================",
		in_len, sc_dump_hex(in_, in_len));
/* */
	if (in_len > out_len)
		return rv=SC_ERROR_NOT_SUPPORTED;
	if (in_len > 0x0200) // FIXME stimmt nur für RSA
		return rv=SC_ERROR_NOT_SUPPORTED;
	// TODO check for "the in_len must match the keyModulus_length"

version(ENABLE_ACOS5_64_UI)
version(Posix) {
	/* (Requested by DGP): on signature operation, ask user consent */
	if (call_to_compute_signature_in_progress && (rv=acos5_64_ask_user_consent(card, user_consent_title, user_consent_message)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher", "User consent denied\n");
		return rv;
	}
}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x80, 0x84);
	apdu.flags = SC_APDU_FLAGS_NO_GET_RESP;
	apdu.data  = in_;
	apdu.lc    = apdu.datalen = in_len;
//	apdu.resp    = out_;
//	apdu.resplen = out_len;

	if (in_len > 0xFF)
		apdu.flags  |= SC_APDU_FLAGS_CHAINING;

	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;

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
					"rv: %i, count:%lu , \n", rv, count);
				return rv;
			}
			received += count; // now count is what actually got received
			p        += count;
		} while (in_len > received && count>0);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
		"Output from decipher len: '%i' bytes:\n%s\n============================================================",
			received, sc_dump_hex(parr.ptr, received));
	if (in_len != received)
		return rv=SC_ERROR_UNKNOWN;

	size_t out_len_new = received;
version(RSA_PKCS_PSS) {
		if (call_to_compute_signature_in_progress)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__,   "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: No checking of padding for PKCS_PPS took place currently (other than last byte = 0xbc)\n");
		else {

		}
}
else {
	if      (card.algorithms.flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		if ((rv=missingExport_sc_pkcs1_strip_02_padding(ctx, parr.ptr, received, out_, &out_len_new)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
				"MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_PAD_PKCS1 is defined; padding of cryptogram is wrong (NOT BT=02  or other issue)\n");
			return rv;
		}
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_decipher",
			"MESSAGE FROM PRIVATE KEY USAGE: SC_ALGORITHM_RSA_PAD_PKCS1 is defined; the cryptogram was padded correctly (BT=02); padding got stripped\n");
	}
	else if (card.algorithms.flags & SC_ALGORITHM_RSA_RAW) {
		if (call_to_compute_signature_in_progress)
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__,   "acos5_64_decipher", "MESSAGE FROM PRIVATE KEY USAGE: The digestInfo(prefix+hash) was padded correctly for signing (BT=01)\n");
		else {
			rv = missingExport_sc_pkcs1_strip_02_padding(ctx, parr.ptr, received, null, &out_len_new); // this is a check only, out_len_new doesn't get changed
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
import pkcs11.types;

private extern(C) int pkcs1_add_PSS_padding(const(ubyte)*in_/* data_hashed */, size_t in_len /* data_hashedLen*/,
	ubyte* out_/*EM*/, size_t* out_len/* in: *out_len>=rsa_size_bytes_modulus; out: rsa_size_bytes_modulus==emLen*/,
	size_t	rsa_size_bytes_modulus, size_t	bn_num_bits_modulus, CK_RSA_PKCS_PSS_PARAMS_PTR pss_params) {
	import std.stdio;
	import std.digest.digest;
	import std.digest.sha;
	import deimos.openssl.rand : RAND_bytes;
//	import std.random; // doesn't work so far:   Random rng = rndGen(); salt = cast(ubyte[]) rng.take(sLen).array; used openssl's random instead

	uba MGF1(in uba mgfSeed, size_t maskLen, CK_RSA_PKCS_MGF_TYPE hashAlg_mgf1) {
		uba T = new ubyte[0];
		size_t  hLen_mgf1;
		uba hash_mgfSeed;

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
			T ~= hash_mgfSeed.dup ~ integral2ub!4(i);

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

//      2.   Let mHash = Hash(M), an octet string of length hLen.

//      4.   Generate a random octet string salt of length sLen; if sLen = 0, then salt is the empty string.
	uba salt  = new ubyte[sLen];
	if (sLen>0 && RAND_bytes(salt.ptr, sLen) != 1)
		return SC_ERROR_INTERNAL;
//writefln("salt: 0x [ %(%x %) ]", salt);

//      5.   Let  M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;  M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
	uba M1 = cast(uba)x"00 00 00 00 00 00 00 00" ~ /*mHash*/ in_[0..in_len] ~ salt;
	assert(M1.length == 8+hLen+sLen);

//      6.   Let H = Hash(M'), an octet string of length hLen.
	uba  H; // H.length == hLen == mHash.length;
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
	uba PS = new ubyte[emLen - sLen - hLen - 2];
	assert(PS.length==emLen - sLen - hLen - 2);
	assert(!any(PS));

//      8.   Let DB = PS || 0x01 || salt;  DB is an octet string of length emLen - hLen - 1.
	uba DB = PS ~ ubyte(0x01) ~ salt;
//	writefln("    : generated DB   of Len %s: 0x [ %(%x %) ]", DB.length, DB);
	assert(DB.length==emLen - hLen - 1);

//      9.   Let dbMask = MGF(H, emLen - hLen - 1).
	uba dbMask = MGF1(H, emLen - hLen - 1, pss_params.mgf);
//	writefln("MGF1: generated mask of Len %s: 0x [ %(%x %) ]", dbMask.length, dbMask);
	assert(dbMask.length==DB.length);

//      10.  Let maskedDB = DB \xor dbMask.
	uba maskedDB = new ubyte[DB.length];
	maskedDB[] = DB[] ^ dbMask[];
//	writefln("    : xor'd maskedDB of Len %s: 0x [ %(%x %) ]", maskedDB.length, maskedDB);
	assert(maskedDB.length==DB.length);

//      11.  Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero.
	int rem = emBits % 8;
	if (rem)
		maskedDB[0] &=  2^^rem -1;

//      12.  Let EM = maskedDB || H || 0xbc.
	uba EM = maskedDB ~ H ~ 0xbc;
	assert(EM.length==emLen);

//      13.  Output EM.
	size_t  emLenOffset = rsa_size_bytes_modulus - emLen;
	assert(emLenOffset+EM.length == rsa_size_bytes_modulus);
	if (emLenOffset)
		out_[0..emLenOffset] = 0;
	out_[emLenOffset..emLenOffset+EM.length] = EM[0..EM.length];
	*out_len = rsa_size_bytes_modulus;
	return SC_SUCCESS;
}


unittest {
	import std.stdio;
	import deimos.openssl.rsa : RSA;
	immutable(ubyte)[16] Message = cast(immutable(ubyte)[16])x"0f0e0d0c0b0a09080706050403020100";
	uba     EM = new ubyte[128];
	size_t  EMLen = EM.length;
	CK_RSA_PKCS_PSS_PARAMS pss_params = CK_RSA_PKCS_PSS_PARAMS(CKM_SHA256, CKG_MGF1_SHA256, 32);

	assert(pkcs1_add_PSS_padding(Message.ptr, Message.length, EM.ptr, &EMLen, EMLen, 8*EMLen-(1), &pss_params) == 0);
	assert(EMLen == EM.length);
	writefln("EM: 0x [%(%02x %)]", EM);
	writeln("PASSED: pkcs1_add_PSS_padding");
}

} // version(RSA_PKCS_PSS)



private extern(C) int acos5_64_compute_signature(sc_card* card, const(ubyte)* in_, /*in*/ size_t in_len, ubyte* out_, /*in*/ size_t out_len)
{ // check in_len, out_len, they aren't constant any more, but treat them as if they are constant
	// we got a SHA-512 hash value and this function can not deal with that. Hopefully, the prkey is allowed to decrypt as well, as we will delegate to acos5_64_decipher (raw RSA)
	// There is a signing test, which pads properly, but has no digestinfo(no hash). If the key is capable to decipher as well, we can delegate to acos5_64_decipher. Let's try it.

	if (card == null || in_ == null || out_ == null)
		return SC_ERROR_INVALID_ARGUMENTS;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	sc_apdu apdu;
	acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
	mixin (log!(q{"acos5_64_compute_signature"}, q{"called"}));
	mixin transmit_apdu!("acos5_64_compute_signature");
	mixin log_scope_exit!("acos5_64_compute_signature");
	scope(exit) {
		private_data.call_to_compute_signature_in_progress = false;
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_compute_signature(sc_card* card, const(ubyte)* in_, in size_t in_len, ubyte* out_, in size_t out_len) is returnung with argument *card\n");
//			writer.formattedWrite("%s", *card);
		}
		log_scope_exit_do(__LINE__);
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
		"card.algorithm_count: %i\n", card.algorithm_count);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.caps:  %i\n", card.caps);
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"card.flags: %i\n", card.flags);
/+ +/
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"Input to compute_signature len: '%i' bytes:\n%s\n============================================================",
		in_len, sc_dump_hex(in_, in_len));


	if (in_len > out_len)
		return rv=SC_ERROR_NOT_SUPPORTED;
	if (in_len > 0x0200) // FIXME if this function has to decrypt for symkeys as well; currently it's for RSA only
		return rv=SC_ERROR_NOT_SUPPORTED;

	uba tmp_arr = new ubyte[in_len]; // ubyte[0x200] tmp_arr; //	size_t       in_len_new = in_len;
	bool hash_algo_detected;

	if (in_len>=64 /*the min. Modulus*/ && !(cast(int)(in_len%32/*modulusStepSize*/))) { // this must be true (but may depend on SC_ALGORITHM_RSA_PAD_*; check this),  assuming in_len==keyLength
		// padding must exist, be the correct one, possible to be removed, otherwise it's an error
		// the remainder after applying sc_pkcs1_strip_01_padding must be a recognized digestInfo, and this must be allowed to eventually succeed
		{
			size_t  digestInfoLen = in_len; // unfortunately, tmp_arr.length is no lvalue, can't be set by sc_pkcs1_strip_01_padding directly, therfore the scope to get rid of digestInfoLen soon
			// TODO the following is for EMSA-PKCS1-v1_5-ENCODE only, but ther is also EMSA-PSS
			if ((rv=missingExport_sc_pkcs1_strip_01_padding(ctx, in_, in_len, tmp_arr.ptr, &digestInfoLen)) < 0) { // what remains, should (for RSASSA-PKCS1-v1_5) be a valid ASN.1 DigestInfo with either SHA-1 or SHA-256 digestAlgorithm, otherwise we have to handle that with another function
				//stripp padding BT=01 failed: refuse to sign !
				bool maybe_PSS = in_[in_len-1]==0xbc;
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
					"MESSAGE FROM PRIVATE KEY USAGE: Refused to sign because padding is not correct according EMSA-PKCS1-v1_5 (NOT BT=01 or other issue); maybe_PSS: %i", maybe_PSS);
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
							"The reason for the error probably is: The key is not capable to decrypt, just sign (every acos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by acos (established when creating a key pair in token) !");
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
					"The reason for the error probably is: The key is not capable to decrypt, just sign (every acos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by acos (established when creating a key pair in token) !");
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

		foreach (ref elem; DI_table[DigestInfo_Algo_RSASSA_PKCS1_v1_5.min .. DigestInfo_Algo_RSASSA_PKCS1_v1_5.max]) /*id_rsassa_pkcs1_v1_5_with_sha1..1+id_rsassa_pkcs1_v1_5_with_sha3_512*/ // foreach (elem; EnumMembers!DigestInfo_Algo_RSASSA_PKCS1_v1_5)
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
							"The reason for the error probably is: The key is not capable to decrypt, just sign (every acos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by acos (established when creating a key pair in token) !");
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
					"The reason for the error probably is: The key is not capable to decrypt, just sign (every acos RSA-key may sign, but only keys with a flag set for decrypt are allowed to decrypt by acos (established when creating a key pair in token) !");
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

matched_SHA1_or_SHA256: // or everything unknown is mapped to zero length, which entails, that acos will try to use an existing internal hash

version(ENABLE_ACOS5_64_UI)  /* (Requested by DGP): on signature operation, ask user consent */
version(Posix) {
	if ((rv=acos5_64_ask_user_consent(card, user_consent_title, user_consent_message)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature", "User consent denied\n");
		return rv;
	}
}
	 //                              CLAINSP1 P2                lc            apdu.data
	bytes2apdu(ctx, representation(x"00 2A 9E 9A") ~ cast(ubyte)tmp_arr.length ~ tmp_arr,     apdu);
	apdu.flags = SC_APDU_FLAGS_NO_GET_RESP | (tmp_arr.length > 0xFF ? SC_APDU_FLAGS_CHAINING : 0LU);
	if ((rv=transmit_apdu_do(__LINE__))<0) return rv;

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
		if ((rv=iso_ops_ptr.get_response(card, &count, p)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
				"get_response failed: rv: %i, count:%lu , \n", rv, count);
			return rv;
		}
		received += count; // now count is what actually got received from the preceding get_response call
		p        += count;
	} while (in_len > received && count>0); // receiving more than in_lenmax==512 would cause a crash here
/*
	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_compute_signature",
		"Output from compute_signature len: '%i' bytes:\n%s\n============================================================",
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
	mixin (log!(q{"acos5_64_list_files"}, q{"called"}));
	mixin transmit_apdu_strerror!("acos5_64_list_files");
	mixin log_scope_exit!("acos5_64_list_files");
	scope(exit)
		log_scope_exit_do(__LINE__);

	/* Check parameters. */
	if (!buf || (buflen < 8))
		return SC_ERROR_INVALID_ARGUMENTS;

	/*
	 * Use CARD GET INFO to fetch the number of files under the
	 * curently selected DF.
	 */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x14, 0x01, 0x00);
	apdu.cla = 0x80;
	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if (apdu.sw1 != 0x90)
		return rv=SC_ERROR_INTERNAL;
	count = apdu.sw2;

	while (count--) {
		ub8 info; // acos will deliver 8 bytes: [FDB, DCB(always 0), FILE ID, FILE ID, SIZE or MRL, SIZE or NOR, SFI, LCSI]

		/* Truncate the scan if no more room left in output buffer. */
		if (buflen == 0)
			break;

		apdu = sc_apdu(); // apdu = apdu.init;
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x14, 0x02, fno++);
		with (apdu) {
			cla = 0x80;
			resp         = info.ptr;
			resplen = le = info.sizeof;
		}
		if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
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
	int rv = SC_ERROR_UNKNOWN;
	sc_context* ctx = card.ctx;
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_check_sw",
		"called for: sw1 = 0x%02x, sw2 = 0x%02x\n", sw1, sw2);
	mixin log_scope_exit!("acos5_64_check_sw");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if (sw1 == 0x90)
		return rv= (sw2==0x00 ? SC_SUCCESS : SC_ERROR_CARD_CMD_FAILED);
	else if (sw1 == 0x95U && sw2 == 0x40U) // this is a response to "Identify Self" and is okay for Version ACS ACOS5-64 v2.00/no error
		return rv=SC_SUCCESS;
	else if (sw1 == 0x61U /*&& sw2 == 0x40U*/)
		return rv=SC_SUCCESS;
	/* iso error */
	return rv=iso_ops_ptr.check_sw(card, sw1, sw2);
}


struct acos5_64_se_info {
	int                        reference;
	uint                       crts_len; /* what is used actually in crts */
	acos5_64_se_info*          next;

	sc_crt[SC_MAX_CRTS_IN_SE]  crts; // align(8)

	uint                       magic;
}

private int acos5_64_se_set_cached_info(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(`"acos5_64_se_set_cached_info"`, `"called"`));
	mixin log_scope_exit!("acos5_64_se_set_cached_info");
	scope(exit)
		log_scope_exit_do(__LINE__);

	acos5_64_se_info*  se_info = cast(acos5_64_se_info*)calloc(1, acos5_64_se_info.sizeof);
	if (!se_info) {
		mixin (log!(`"acos5_64_se_set_cached_info"`, `"SE info allocation error"`));
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_se_set_cached_info", "SE info allocation error");
		return rv=SC_ERROR_OUT_OF_MEMORY;
	}
	memcpy(se_info, se, acos5_64_se_info.sizeof);

	acos5_64_private_data*  private_data = cast(acos5_64_private_data*) card.drv_data;
	if (!private_data.pse_info) {
		private_data.pse_info = se_info;
		mixin (log!(`"acos5_64_se_set_cached_info"`, `"SE info was empty"`));
	}
	else {
		acos5_64_se_info* si;
		for (si = private_data.pse_info; si.next; si = si.next) {}
		si.next = se_info;
	}

	return rv;
}


private int acos5_64_se_get_cached_info(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	if (se==null)
		return rv=SC_ERROR_OBJECT_NOT_FOUND;

	acos5_64_private_data* private_data = cast(acos5_64_private_data*) (card.drv_data);
	if (private_data is null)
		return rv=SC_ERROR_OBJECT_NOT_FOUND;

	acos5_64_se_info*  si;
	for ( si = private_data.pse_info ; si !is null; si = si.next) {
		if (si.reference != se.reference)
			continue;
		else
			break;
	}

	if (!si) {
		mixin (log!(`"acos5_64_se_get_cached_info"`, `"acos5_64_se_info* si  %p"`,"si"));
		return rv=SC_ERROR_OBJECT_NOT_FOUND;
	}

	memcpy(se, si, acos5_64_se_info.sizeof);
	se.next = null;

	return rv;
}

private int acos5_64_se_get_info(sc_card* card, acos5_64_se_info* se) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;//SC_ERROR_UNKNOWN;
	if (!se || se.reference<=0 || se.reference > 0x0E )
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if ((rv=acos5_64_se_get_cached_info(card, se)) != SC_SUCCESS)
		mixin (log!(`"acos5_64_se_get_info"`, `"No SE#%X info in cache"`, "se.reference"));
	return rv;
}


private int acos5_64_se_get_reference(sc_card* card, int se_reference, sc_crt search_template) {
/*
	search_template  = { CRT_TAG.AT, 0x08 }; // 'USER PASSWORD' authentication  search/result template
	search_template  = { CRT_TAG.AT, 0x80 }; // 'SYMMETRIC KEY' authentication  search/result template
	search_template  = { CRT_TAG.AT, 0x88 }; // both 'USER PASSWORD' and 'SYMMETRIC KEY' authentication  search/result template
*/
	sc_context*       ctx = card.ctx;
	int               rv = SC_ERROR_UNKNOWN;
	acos5_64_se_info  se;
	mixin (log!(`"acos5_64_se_get_reference"`, `""`));
	mixin (log!(`"acos5_64_se_get_reference"`, `"called for se_reference %i"`, "se_reference"));
	mixin log_scope_exit!("acos5_64_se_get_reference");
	scope(exit) {
		version(ENABLE_TOSTRING) {
			if (se_reference==5) {
				writer.put("acos5_64_se_get_reference with argument acos5_64_se_info se, sc_crt search_template:\n");
				writer.formattedWrite("%s", se);
				writer.formattedWrite("%s", search_template);
			}
		}
		log_scope_exit_do(__LINE__);
	}

	if (se_reference<=0 || se_reference>0x0E)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	se.reference = se_reference;
	if ((rv=acos5_64_se_get_info(card, &se)) < SC_SUCCESS) {
		mixin (log!(`"acos5_64_se_get_reference"`, `"get SE info error"`));
		return rv;
	}

	mixin (log!(`"acos5_64_se_get_reference"`, `"CRT search_template (tag:usage:algo): %02X:%02X:%02X, refs %02X:%02X:..."`,
		"search_template.tag","search_template.usage","search_template.algo","search_template.refs[0]","search_template.refs[1]"));

	rv = SC_ERROR_DATA_OBJECT_NOT_FOUND;
	for (int ii=0; (ii<SC_MAX_CRTS_IN_SE) && se.crts[ii].tag; ii++)   {
		if (search_template.tag != se.crts[ii].tag)
			continue;
		if (search_template.tag != 0xA4 && search_template.algo && (search_template.algo != se.crts[ii].algo))
			continue;
		if (search_template.usage && ((search_template.usage & se.crts[ii].usage)!=search_template.usage) )
			continue;

		search_template = se.crts[ii];
		mixin (log!(`"acos5_64_se_get_crt"`, `"found CRT with refs %X:%X:..."`,"se.crts[ii].refs[0]","se.crts[ii].refs[1]"));
		rv=SC_SUCCESS;
		break;
	}

	if (rv==SC_ERROR_DATA_OBJECT_NOT_FOUND) {
		mixin (log!(`"acos5_64_se_get_crt"`, `"      CRT not found"`));
		switch (search_template.usage) {
			case 0x08:  mixin (log!(`"acos5_64_se_get_reference"`, `"Cannot get 'USER PASSWORD' authentication template"`)); break;
			case 0x80:  mixin (log!(`"acos5_64_se_get_reference"`, `"Cannot get 'SYMMETRIC KEY' authentication template"`)); break;
			case 0x88:  mixin (log!(`"acos5_64_se_get_reference"`, `"Cannot get both 'USER PASSWORD' and 'SYMMETRIC KEY' authentication template"`)); break;
			default:   	mixin (log!(`"acos5_64_se_get_reference"`, `"Cannot get 'DONT KNOW KIND' authentication template"`)); break;
		}
		return rv;
	}
	return rv=search_template.refs[0];
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
	mixin (log!(`"acos5_64_card_ctl"`, `"called with request %lu"`, "request"));
	mixin log_scope_exit!("acos5_64_card_ctl");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if (data == null)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	final switch (cast(SC_CARDCTL)request) {
		case SC_CARDCTL_GENERIC_BASE,
				 SC_CARDCTL_ERASE_CARD,
				 SC_CARDCTL_GET_DEFAULT_KEY,
				 SC_CARDCTL_LIFECYCLE_GET,
				 SC_CARDCTL_ACS_BASE,
				 SC_CARDCTL_ACS_GENERATE_KEY:
			return rv; // SC_ERROR_NOT_SUPPORTED

		case SC_CARDCTL_PKCS11_INIT_TOKEN:
			with (cast(sc_cardctl_pkcs11_init_token*)data) {
				mixin (log!(`"acos5_64_card_ctl"`, `"so_pin (%s), label (%s)"`, "sc_dump_hex(so_pin, so_pin_len)", "label"));
				if (so_pin_len!=8) {
					mixin (log!(`"acos5_64_card_ctl"`, `"so_pin_len must be 8 !"`));
					return  rv=SC_ERROR_NOT_SUPPORTED;
				}
//				do_zeroize_token       = true; // CHANGE_HERE_FOR_REINIT : remove leading //
//				do____initialize_token = true; // CHANGE_HERE_FOR_REINIT : remove leading //
				return rv=re_initialize_token(card, so_pin[0..so_pin_len], label);
			}

		case SC_CARDCTL_PKCS11_INIT_PIN:
		{
			sc_pin_cmd_pin   cmd_pin;
			sc_pin_cmd_data  cmd_data;
			int              tries_left;
			with (cast(sc_cardctl_pkcs11_init_pin*)data) {
				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
					"pin (%s)", sc_dump_hex(pin, pin_len));
				with (cmd_pin) {
				}
				with (cmd_data) {

				}
			} // with (cast(sc_cardctl_pkcs11_init_pin*)data)
			return rv=SC_ERROR_NOT_SUPPORTED;//return rv=acos5_64_pin_change(card, &cmd_data, &tries_left);
		}
		case SC_CARDCTL_LIFECYCLE_SET:
			SC_CARDCTRL_LIFECYCLE lcsi =  *cast(SC_CARDCTRL_LIFECYCLE*)data;
			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_card_ctl",
				"request=SC_CARDCTL_LIFECYCLE_SET with *data: %i\n", lcsi);
			final switch (lcsi) {
				case SC_CARDCTRL_LIFECYCLE_ADMIN,  SC_CARDCTRL_LIFECYCLE_USER, SC_CARDCTRL_LIFECYCLE_OTHER:
					return rv; // SC_ERROR_NOT_SUPPORTED
			}

		case SC_CARDCTL_GET_SERIALNR: /* call card to obtain serial number */
			return rv=acos5_64_get_serialnr(card, cast(sc_serial_number*) data);

		case SC_CARDCTL_GET_SE_INFO:
			mixin (log!(`"acos5_64_card_ctl"`, `"CMD SC_CARDCTL_GET_SE_INFO: sdo_class prozentX"`/*, sdo.sdo_class*/));
			if (!data)
				return rv=SC_ERROR_CARD_CMD_FAILED;
			return rv=acos5_64_se_get_info(card, cast(acos5_64_se_info*)data);

		case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
			mixin (log!(`"acos5_64_card_ctl"`, `"CMD SC_CARDCTL_GET_CHV_REFERENCE_IN_SE"`));
			if (!data)
				return rv=SC_ERROR_CARD_CMD_FAILED;
//			int se_reference = *(cast(int*)data);
			return rv=acos5_64_se_get_reference(card, *(cast(int*)data), sc_crt(CRT_TAG.AT, 0x08));
	}
}


/*
 * read_8C_SAC_Bytes_to_ub8SC expands the "compressed" 8C_SAC_Bytes from card/token to a 'standard' 8 byte SC array, interpreting the AM byte;
 * SC's byte positions are assigned values matching the AM bit-representation in reference manual, i.e. it is reversed to what many other cards do:
 * Bit 7 of AM byte indicates what is stored to byte-index 7 of SC ( Not Used by ACOS )
 * Bit 0 of AM byte indicates what is stored to byte-index 0 of SC ( EF: READ, DF/MF:  Delete_Child )
 * Bits 0,1,2 may have different meaning depending on file type, from bits 3 to 6/7 (unused) meanings are the same for all file types
 * Maybe later integrate this in acos5_64_process_fci
 */
int read_8C_SAC_Bytes_to_ub8SC(out ub8 SC, in uba _8C_SAC_Bytes) {
	import core.bitop : popcnt; //, _popcnt; : GDC doesn't know _popcnt //	import core.cpuid : hasPopcnt;
	int  rv;
	try {
		scope(exit)
			SC[7] = 0xFF; // though not expected to be accidentally set, it get's overriden to NEVER: it's not used by ACOS
		if (empty(_8C_SAC_Bytes))
			return rv=SC_SUCCESS;
		assert(_8C_SAC_Bytes.length<=8);
		const(ubyte)*    p  = _8C_SAC_Bytes.ptr;
		immutable ubyte  AM = *p++;
		if (popcnt(AM) != _8C_SAC_Bytes.length-1) // the count of 1-valued bits of AM Byte must equal (taglen-1), the count of bytes following AM
			return rv=SC_ERROR_INVALID_ASN1_OBJECT;
		foreach (i, unused; SC)
			if (AM & (0b1000_0000 >>> i))
				SC[7-i] = *p++;
	}
	catch(Throwable)
		rv=SC_ERROR_CARD_UNRESPONSIVE;
	return rv;
}


unittest {
	auto a_SCexpect =  cast(immutable(ubyte)[8])x"01 03 01 03 03 FF FF FF"; // assume: Not used -> Never allow
	auto b_SCexpect =  cast(immutable(ubyte)[8])x"00 01 00 00 00 05 06 FF";
	auto c_SCexpect =  cast(immutable(ubyte)[8])x"45 01 00 03 00 05 00 FF";
	auto d_SCexpect =  cast(immutable(ubyte)[8])x"00 00 00 00 00 00 00 FF";
	auto e_SCexpect =  cast(immutable(ubyte)[8])x"02 00 FF FF 04 03 02 FF";
	uba  x          = (cast(immutable(ubyte)[ ])x"7F FF FF 03 03 01 03 01").dup;
	ub8  SC;
	read_8C_SAC_Bytes_to_ub8SC(SC,   x);
	assert(                equal(SC[], a_SCexpect[]));
	x = (cast(immutable(ubyte)[4])x"62 06 05 01").dup;
	read_8C_SAC_Bytes_to_ub8SC(SC,   x);
	assert(                equal(SC[], b_SCexpect[]));
	x = (cast(immutable(ubyte)[5])x"2B 05 03 01 45").dup;
	read_8C_SAC_Bytes_to_ub8SC(SC,   x);
	assert(                equal(SC[], c_SCexpect[]));
	x = (cast(immutable(ubyte)[1])x"00").dup;
	read_8C_SAC_Bytes_to_ub8SC(SC,   x);
	assert(                equal(SC[], d_SCexpect[]));
	x = (cast(immutable(ubyte)[7])x"7D 02 03 04 FF FF 02").dup;
	read_8C_SAC_Bytes_to_ub8SC(SC,   x);
	assert(                equal(SC[], e_SCexpect[]));
	writeln("PASSED: read_8C_SAC_Bytes_to_ub8SC");
}


private int process_fci_sac_se(sc_card* card, in uba fci_carrier, cache_current_df_se_info* info_out, bool enveloped=false, bool skip_seid_retrieval=false, bool sacNONE=false/*, bool append=false*/) {
	sc_context*      ctx = card.ctx;
	const(ubyte)*    tag;
	size_t           taglen;
	cache_current_df_se_info  info;

	if (enveloped) {
		tag = sc_asn1_find_tag(ctx, fci_carrier.ptr, fci_carrier.length, ISO7816_TAG_FCI /*0x6F*/, &taglen);
		if (!tag || !taglen || 2+taglen>fci_carrier.length || (tag-fci_carrier.ptr != 2))
			return SC_ERROR_ASN1_END_OF_CONTENTS;
	}
	const(uba)  fci = enveloped? fci_carrier[2..2+taglen] : fci_carrier;

	tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_TAG_FCP_FID /*0x83*/, &taglen);
	if (!tag ||                taglen != TAG_FCP_len(ISO7816_TAG_FCP_FID))
		return SC_ERROR_ASN1_END_OF_CONTENTS;
	info.fid = tag[0..taglen]; // e.g. [0x41, 0x00]

	tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_RFU_TAG_FCP_SAC /*0x8C*/, &taglen);
	if (!tag ||                 taglen > TAG_FCP_len(ISO7816_RFU_TAG_FCP_SAC) || read_8C_SAC_Bytes_to_ub8SC(info.sac, tag[0..taglen]) < 0)
		return SC_ERROR_ASN1_END_OF_CONTENTS;

	tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_TAG_FCP_TYPE /*0x82*/, &taglen); // e.g.  82 06  1C 00 00 30 00 05
	if (!tag || !taglen ||      taglen > TAG_FCP_len(ISO7816_TAG_FCP_TYPE))
		return SC_ERROR_ASN1_END_OF_CONTENTS;
	if (!canFind([EnumMembers!EFDB], tag[0]))
		return SC_ERROR_INVALID_ASN1_OBJECT;
	info.fdb = tag[0];
	if (info.fdb==SE_EF && sacNONE)
		info.sac = ub8.init;
	if (info.fdb!=MF && (info.fdb&6) && taglen >= 5) {//FDB+DCB+00h+MRL+NOR or FDB+DCB+00h+MRL+00h+NOR;  MRL:maximum record length (<=255); in case of linear variable, there may be less bytes in a record than MRL
		info.MRL = tag[3];        // ubyte MRL // In case of fixed-length or cyclic EF
		info.NOR = tag[taglen-1]; // ubyte NOR // Valid, if not transparent EF or DF
	}

	acos5_64_private_data*  private_data = cast(acos5_64_private_data*) card.drv_data;

	if ((info.fdb & ISO7816_FILE_TYPE_DF) == ISO7816_FILE_TYPE_DF)  { // DF/MF
	//tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_TAG_FCP_DF_NAME /*0x84*/, &taglen);
		tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_RFU_TAG_FCP_SAE /*0xAB*/, &taglen);
		if (!tag ||                 taglen > TAG_FCP_len(ISO7816_RFU_TAG_FCP_SAE))
			return SC_ERROR_ASN1_END_OF_CONTENTS;
		info.sae_len        = cast(uint)taglen;
		info.sae[0..taglen] = tag[0..taglen];

		tag = sc_asn1_find_tag(ctx, fci.ptr, fci.length, ISO7816_RFU_TAG_FCP_SEID /*0x8D*/, &taglen);
		if (!tag ||                taglen != TAG_FCP_len(ISO7816_RFU_TAG_FCP_SEID))
			return SC_ERROR_ASN1_END_OF_CONTENTS;
		info.seid      = tag[0..taglen];

		private_data.current_df_se_info = info;

		if (!skip_seid_retrieval) { // do cache the new SE-Files information, discarding previous content; possibly later switch to a on-demand solution
			if (equal(info.seid[], info.fid[])) {
				mixin (log!(`"process_fci_sac_se"`, `"Something went wrong retrieving seid and fid: The values would incur 'infinite' recursion !!!"`));
				return SC_ERROR_ASN1_END_OF_CONTENTS;
			}

			if (card.cache.current_df /*&& card.cache.valid && (append || card.cache.current_df.path.len==0 || !sc_compare_path(&card.cache.current_df.path, &MF_path) )*/ ) {
				sc_append_path_id(&card.cache.current_df.path, info.fid.ptr, 2);
			}


			ubyte[255] rbuf;
			sc_apdu apdu;
			int rv;
			mixin transmit_apdu_strerror!("process_fci_sac_se");
			bytes2apdu(ctx, representation(x"00 A4 00 00 02")~info.seid~ubyte(MAX_FCI_GET_RESPONSE_LEN), apdu);
			apdu.resp    = rbuf.ptr;
			apdu.resplen = rbuf.length;
			if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
			if (sc_check_sw(card, apdu.sw1, apdu.sw2)) return SC_ERROR_INTERNAL;
			cache_current_df_se_info  info_seid; // required for NOR and MRL
			if ((rv= process_fci_sac_se(card, rbuf[0..apdu.resplen], &info_seid,/*enveloped=*/true,/*skip_seid_retrieval=*/false,/*sacNONE=*/true)) < 0) return rv;

		version(all) {
			acos5_64_se_info*  se_info = private_data.pse_info; // acos5_64_se_info*
			acos5_64_se_info*  next;

			if (se_info) // delete private_data.se_info
				while (se_info)   {
					next = se_info.next;
					free(se_info);
					se_info = next;
				}
			private_data.pse_info = null;
		} // version(all)

/+
		if (equal(info.seid[], [0,3][])) {
			bytes2apdu(ctx, representation(x"00 20 00 01  08 3837363534333231"), apdu);
		}
		else
			bytes2apdu(ctx, representation(x"00 20 00 81  08 3132333435363738"), apdu);
		if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
		if (sc_check_sw(card, apdu.sw1, apdu.sw2)) return SC_ERROR_INTERNAL;
+/
			foreach (rec_no; iota(ubyte(1), cast(ubyte)(1+info_seid.NOR))) {
				bytes2apdu(ctx, representation(x"00 B2 00 04") ~ info_seid.MRL, apdu);
				apdu.p1 = rec_no;
				rbuf = rbuf.init;
				apdu.resp    = rbuf.ptr;
				apdu.resplen = rbuf.length;
				if ((rv=transmit_apdu_strerror_do(__LINE__))<0) return rv;
				if (sc_check_sw(card, apdu.sw1, apdu.sw2)) return SC_ERROR_INTERNAL;
				tag = sc_asn1_find_tag(ctx, rbuf.ptr, apdu.resplen, 0x80, &taglen);
				if (!tag || tag!=rbuf.ptr+2 || taglen!=1)
					continue;
				acos5_64_se_info  se;
				se.reference = tag[0];

				int parse_len = acos5_64_crt_parse(ctx, rbuf[3..apdu.resplen], &se);
				assert(!any(apdu.resp[3+parse_len..apdu.resplen]));
/* * /
				mixin (log!(`"process_fci_sac_se"`, `"se.reference:       %i"`,   "se.reference"));
				mixin (log!(`"process_fci_sac_se"`, `"se.crts_len:        %u"`,   "se.crts_len"));
				mixin (log!(`"process_fci_sac_se"`, `"se.crts[0].tag:     %02X"`, "se.crts[0].tag"));
				mixin (log!(`"process_fci_sac_se"`, `"se.crts[0].usage:   %02X"`, "se.crts[0].usage"));
				mixin (log!(`"process_fci_sac_se"`, `"se.crts[0].algo:    %02X"`, "se.crts[0].algo"));
				mixin (log!(`"process_fci_sac_se"`, `"se.crts[0].refs[0]: %02X"`, "se.crts[0].refs[0]"));
/ * */
				if ((rv= acos5_64_se_set_cached_info(card, &se)) < 0) {
					mixin (log!(`"acos5_64_se_get_info"`, `"failed to put SE data into cache"`));
					return rv;
				}
			} // foreach (i; iota(ubyte(1), cast(ubyte)(1+info_seid.NOR)))
		} // if (!skip_seid_retrieval)
	} // if (((info.fdb & ISO7816_FILE_TYPE_DF) == ISO7816_FILE_TYPE_DF))

	if (info_out)
		*info_out = info;
	return SC_SUCCESS;
}


private extern(C) int acos5_64_process_fci(sc_card* card, sc_file* file, const(ubyte)* buf, size_t buflen)
{
	const(ubyte)* tag;
	size_t        taglen;
	int           rv;
	sc_context*   ctx = card.ctx;
	mixin (log!(`"acos5_64_process_fci"`, `"called"`));
	mixin log_scope_exit!("acos5_64_process_fci");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if ((rv = iso_ops_ptr.process_fci(card, file, buf, buflen)) < 0) {
		mixin (log!(`"acos5_64_process_fci"`, `"error parsing fci: %i (%s)"`, "rv", "sc_strerror(rv)"));
		return rv;
	}
	file.sid = -1; // though acos stores sid, they are quite meaningless as not being distinct, the driver won't use it; don't want any decision taken depending on sid !

	cache_current_df_se_info info; // tag 0x8C and maybe more
	if ((rv=process_fci_sac_se(card, buf[0..buflen], &info,/*enveloped=*/false,/*skip_seid_retrieval=*/true,/*sacNONE=*/false)) < 0)  return rv; // communicate potential change of Security Environment
	EFDB  FDB = cast(EFDB)info.fdb;
	final switch (FDB) {
		case RSA_Key_EF:
			break;
		case Purse_EF:
			file.type = SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF;
			mixin (log!(`"acos5_64_process_fci"`, `"  type (corrected): proprietary EF SecurityEnvironment"`));
			break;
		case EFDB.SE_EF:
			file.type = SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF; // refinement might be SC_FILE_TYPE_INTERNAL_SE_EF
			mixin (log!(`"acos5_64_process_fci"`, `"  type (corrected): proprietary EF SecurityEnvironment"`));
			goto case Linear_Fixed_EF;
		case Linear_Fixed_EF, Linear_Variable_EF, Cyclic_EF:
			if (file.size == 0) {
				file.record_length = info.MRL;
				file.record_count  = info.NOR;
				file.size          = info.MRL * info.NOR;
			}
			break;
		case DF, MF,  Transparent_EF,  CHV_EF, Sym_Key_EF:
			break;
	}

	info = cache_current_df_se_info.init; // tag 0x8C and maybe more
	if ((rv=process_fci_sac_se(card, buf[0..buflen], &info,/*enveloped=*/false,/*skip_seid_retrieval=*/false,/*sacNONE=*/false)) < 0)  return rv; // communicate potential change of Security Environment

	if (equal(info.fid[], [0x39, 0x02])) {
		mixin (log!(`"acos5_64_process_fci"`, `"sac:  %s"`, "sc_dump_hex(info.sac.ptr, info.sac.length)"));
		mixin (log!(`"acos5_64_process_fci"`, `"fdb:  %i"`, "info.fdb"));
		mixin (log!(`"acos5_64_process_fci"`, `"fid:  %s"`, "sc_dump_hex(info.fid.ptr, 2)"));
		mixin (log!(`"acos5_64_process_fci"`, `"seid: %s"`, "sc_dump_hex(info.seid.ptr, 2)"));
		mixin (log!(`"acos5_64_process_fci"`, `"NOR:  %i"`, "info.NOR"));
	}
	mixin (log!(`"acos5_64_process_fci"`, `"ACLs[0..7] '%s'"`, "sc_dump_hex(info.sac.ptr, info.sac.length)"));
	ubyte[7] ops_DF_MF  = [ SC_AC_OP_DELETE_SELF, SC_AC_OP_CREATE_EF, SC_AC_OP_CREATE_DF, SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE ];
	ubyte[7] ops_EF_CHV = [ SC_AC_OP_READ,        SC_AC_OP_UPDATE,    0xFF,               SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE ];
	ubyte[7] ops_Key_SE = [ SC_AC_OP_READ,        SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE ];

	ubyte  op;
	mixin file_add_acl_entry;
	sc_file_add_acl_entry(  file, SC_AC_OP_SELECT,     SC_AC.SC_AC_NONE, 0);
	if (canFind([DF,MF], FDB)) {
		sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC.SC_AC_NONE, 0);
		op = SC_AC_OP.SC_AC_OP_CREATE;
		file_add_acl_entry_do(1, __LINE__);
		file_add_acl_entry_do(2, __LINE__);
	}
	else {
		op = SC_AC_OP.SC_AC_OP_WRITE;
		file_add_acl_entry_do(1, __LINE__);
	}
	if (EFDB.RSA_Key_EF==FDB) {
		op = SC_AC_OP.SC_AC_OP_GENERATE;
		file_add_acl_entry_do(1, __LINE__);
	}

	foreach (ii; 0..7) {
		op = canFind([EFDB.DF,MF],                    FDB)? ops_DF_MF [ii] :
				(canFind([RSA_Key_EF, Sym_Key_EF, SE_EF], FDB)? ops_Key_SE[ii] : ops_EF_CHV[ii]);
		if (ii>0)
			mixin (log!(`"acos5_64_process_fci"`, `"offs %i, op 0x%02X, SC 0x%02X"`, "ii", "op", "info.sac[ii]"));
		else
			mixin (log!(`"acos5_64_process_fci"`, `"offs %i, op 0x%02X, SC 0x%02X  [op 0x16==SC_AC_OP_READ/op 0x08==SC_AC_OP_DELETE_SELF for DF_MF(Delete Child)]"`, "ii", "op", "info.sac[ii]"));
		file_add_acl_entry_do(ii, __LINE__);
	}
	return rv=SC_SUCCESS;
} // acos5_64_process_fci


private extern(C) int acos5_64_pin_cmd(sc_card *card, sc_pin_cmd_data *data, int *tries_left) {
	sc_context* ctx = card.ctx;
	int rv;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_pin_cmd"`, `"called"`));
	mixin transmit_apdu_strerror!("acos5_64_pin_cmd");
	mixin log_scope_exit!("acos5_64_pin_cmd");
	scope(exit)
		log_scope_exit_do(__LINE__);

	with (*data)
		mixin (log!(`"acos5_64_pin_cmd"`, `"sc_pin_cmd_data 1-4: cmd(%u), flags(0x%X), pin_type(0x%02X), pin_reference(0x%02X)"`,"cmd","flags","pin_type","pin_reference"));
	if (data.pin1.prompt && strlen(data.pin1.prompt))
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"prompt: %s\n", data.pin1.prompt);
	with (data.pin1)
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_cmd",
			"sc_pin_cmd_data.pin1: min_length(%lu), max_length(%lu), stored_length(%lu), encoding(%u)\n", min_length, max_length, stored_length, encoding);

	final switch (cast(SC_PIN_CMD)data.cmd) {
	case SC_PIN_CMD_VERIFY: /*0*/
		final switch (cast(SC_AC)data.pin_type) {
		case SC_AC_CHV:
			rv = iso_ops_ptr.pin_cmd(card, data, tries_left);
			break;
		case SC_AC_AUT:
		/* 'AUT' key is the transport PIN and should have reference '0' */
			rv = (data.pin_reference ? SC_ERROR_INVALID_ARGUMENTS : iso_ops_ptr.pin_cmd(card, data, tries_left));
			break;
		case SC_AC_NONE, SC_AC_UNKNOWN, SC_AC_NEVER, SC_AC_TERM, SC_AC_PRO, SC_AC_SYMBOLIC, SC_AC_SEN, SC_AC_SCB, SC_AC_IDA:
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
			rv = acos5_64_pin_unblock_change(card, data, tries_left);
		}
		break;
	case SC_PIN_CMD_GET_INFO: /*3*/
		rv = acos5_64_pin_get_policy(card, data);//iasecc_pin_get_policy(card, data);
		break;
	}

	return rv;
}

private int acos5_64_pin_get_policy(sc_card *card, sc_pin_cmd_data *data)
{
	sc_context* ctx = card.ctx;
	int rv;
	sc_apdu apdu;
	mixin (log!(q{"acos5_64_pin_get_policy"}, q{"called"}));
	mixin transmit_apdu_strerror!("acos5_64_pin_get_policy");
	mixin log_scope_exit!("acos5_64_pin_get_policy");
	scope(exit)
		log_scope_exit_do(__LINE__);
//		data->flags=0;// what shall be done here? Ask for the remaining tries of User PIN
	sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0x00, data.pin_reference | 0x80);
	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;

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
			"Tries left for User PIN : %i\n", data.pin1.tries_left);
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
	mixin transmit_apdu_strerror!("acos5_64_pin_change");

	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change", "called\n");
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
		"Change PIN(ref:%i,type:0x%X,lengths:%i/%i)", reference, data.pin_type, data.pin1.len, data.pin2.len);

	if (!data.pin1.data && data.pin1.len) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"Invalid PIN1 arguments: %i (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (!data.pin2.data && data.pin2.len) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"Invalid PIN2 arguments: %i (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	rv = iso_ops_ptr.pin_cmd(card, data, tries_left); // verifies pin1
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
		"(SC_PIN_CMD_CHANGE) old pin (pin1) verification returned %i", rv);
	if (rv < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"PIN verification error: %i (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (data.pin2.data)
		memcpy(pin_data.ptr /* + data.pin1.len*/, data.pin2.data, data.pin2.len);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0x01, reference);
	apdu.data = pin_data.ptr;
	apdu.datalen = /*data.pin1.len + */data.pin2.len;
	apdu.lc = apdu.datalen;

	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if ((rv = sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"PIN cmd failed: %i (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (rv <= 0)
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"returning with: %i (%s)\n", rv, sc_strerror(rv));
	else
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_change",
			"returning with: %i\n", rv);

	return rv;
}

private int acos5_64_pin_unblock_change(sc_card *card, sc_pin_cmd_data *data, int *tries_left)
{
	sc_context* ctx = card.ctx;
	sc_apdu apdu;
	uint reference = data.pin_reference;
	ubyte[0x100] pin_data;
	int rv = SC_SUCCESS;//SC_ERROR_INS_NOT_SUPPORTED;
	mixin transmit_apdu_strerror!("acos5_64_pin_unblock_change");

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change", "called\n");
	if (!data.pin1.data || data.pin1.len==0) { // no puk available or empty
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Invalid PUK arguments: %i (%s)\n", SC_ERROR_INVALID_ARGUMENTS, sc_strerror(SC_ERROR_INVALID_ARGUMENTS));
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	if (data.pin2.data && data.pin2.len>0 && (data.pin2.len < 4 || data.pin2.len > 8)) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Invalid PIN2 length: %i (%s)\n", SC_ERROR_INVALID_PIN_LENGTH, sc_strerror(SC_ERROR_INVALID_PIN_LENGTH));
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
		apdu.lc = data.pin1.len + data.pin2.len;
		memcpy(pin_data.ptr+data.pin1.len, data.pin2.data, data.pin2.len);
	}
	apdu.datalen = apdu.lc;
	apdu.data = pin_data.ptr;

	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if ((rv = sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"Unblock pin cmd failed: %i (%s)\n", rv, sc_strerror(rv));
		return rv;
	}

	if (rv <= 0)
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"returning with: %i (%s)\n", rv, sc_strerror(rv));
	else
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pin_unblock_change",
			"returning with: %i\n", rv);

	return rv;
}


private extern(C) int acos5_64_read_public_key(sc_card* card, uint algorithm, sc_path* path,
	uint key_reference, uint modulus_length, ubyte** response, size_t* responselen)
{
	sc_pkcs15_pubkey_rsa  rsa_key;
	sc_apdu               apdu;
	immutable(uint) N            = modulus_length/8; /* key modulus_length in byte */
	immutable(uint) le_accumul   =   N + 21;
	immutable(uint) RSApubMaxLen = 512 + 21;
	ubyte[RSApubMaxLen] buffer;
	uint count = 0;

	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"acos5_64_read_public_key"`, `"called"`));
	mixin transmit_apdu_strerror!("acos5_64_read_public_key");
	mixin log_scope_exit!("acos5_64_read_public_key");
	scope(exit)
		log_scope_exit_do(__LINE__);

	assert(path != null && path.len>=2 && response != null);
	mixin (log!(`"acos5_64_read_public_key"`, `"Got args: algorithm=%x, modulus_length=%x, key_reference=%x, response=%x, responselen=%d, path=%s"`,
		"algorithm", "modulus_length", "key_reference","response","responselen ? *responselen : 0", "sc_dump_hex(path.value.ptr, path.len)"));
	if (algorithm != SC_ALGORITHM_RSA)
		return rv=SC_ERROR_NOT_SUPPORTED;

	if ((rv=sc_select_file(card, path, null))<0) {
		mixin (log!(`"acos5_64_read_public_key"`, `"failed to select public key file"`));
		return rv;
	}

	bytes2apdu(ctx, representation(x"80 CA 00 00 00"), apdu);
	apdu.le = le_accumul>SC_READER_SHORT_APDU_MAX_SEND_SIZE ? SC_READER_SHORT_APDU_MAX_SEND_SIZE : le_accumul;

	while (count < le_accumul && count <= 0xFFFF-apdu.le) {
		apdu.p1      = cast(ubyte) (count>>>8 & 0xFF);
		apdu.p2      = count & SC_READER_SHORT_APDU_MAX_SEND_SIZE;
		apdu.resp    = buffer.ptr    + count;
		apdu.resplen = buffer.length - count;
		if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0)  return rv;
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)  return rv=SC_ERROR_INTERNAL;

		count += apdu.resplen;
		if (le_accumul-count < SC_READER_SHORT_APDU_MAX_SEND_SIZE)
			apdu.le = le_accumul-count;
	}

	if (count!=le_accumul || buffer[0] || buffer[1]!=encodedRSAbitLen(modulus_length))
		return rv=SC_ERROR_INCOMPATIBLE_KEY;
	if (buffer[2] != path.value[path.len-2])
		return rv=SC_ERROR_INCOMPATIBLE_KEY;
	if (buffer[3] != path.value[path.len-1]+0xC0)
		return rv=SC_ERROR_INCOMPATIBLE_KEY;
	if ((buffer[4] & 3) != 3)
		return rv=SC_ERROR_INCOMPATIBLE_KEY;

	rsa_key.exponent = sc_pkcs15_bignum(buffer.ptr +  5, 16);
	rsa_key.modulus  = sc_pkcs15_bignum(buffer.ptr + 21,  N);

	if (rsa_key.exponent.len && rsa_key.modulus.len) {
		if((rv=sc_pkcs15_encode_pubkey_rsa(ctx, &rsa_key, response, responselen)) < 0) {
			mixin (log!(`"acos5_64_read_public_key"`, `"failed to read public key: cannot encode RSA public key"`));
			return rv;
		}
	}
	else {
		mixin (log!(`"acos5_64_read_public_key"`, `"it's not a known public key"`));
		return rv=SC_ERROR_INTERNAL;
	}

	return rv=SC_SUCCESS;
} // acos5_64_read_public_key


private int missingExport_sc_pkcs1_strip_01_padding(sc_context* ctx, const(ubyte)* in_dat, size_t in_len, ubyte* out_, size_t* out_len)
{
	const(ubyte)* tmp = in_dat;
	size_t    len;

	if (in_dat == null || in_len < 10)
		return SC_ERROR_INTERNAL;
	/* skip leading zero byte */
	if (*tmp == 0) {
		tmp++;
		in_len--;
	}
	len = in_len;
	if (*tmp != 0x01)
		return SC_ERROR_WRONG_PADDING;
	for (tmp++, len--; *tmp == 0xff && len != 0; tmp++, len--)
	{}
	if (!len || (in_len - len) < 9 || *tmp++ != 0x00)
		return SC_ERROR_WRONG_PADDING;
	len--;
	if (out_ == null)
		/* just check the padding */
		return SC_SUCCESS;
	if (*out_len < len)
		return SC_ERROR_INTERNAL;
	memmove(out_, tmp, len);
//	out_[0..len] = tmp[0..len];
	*out_len = len;
	return SC_SUCCESS;
}


/* remove pkcs1 BT02 padding (adding BT02 padding is currently not needed/implemented) */
private int missingExport_sc_pkcs1_strip_02_padding(sc_context* ctx, const(ubyte)* data, size_t len, ubyte* out_, size_t* out_len)
{
	uint	n = 0;

	if (data == null || len < 3)
		return SC_ERROR_INTERNAL;

	/* skip leading zero byte */
	if (*data == 0) {
		data++;
		len--;
	}
	if (data[0] != 0x02)
		return SC_ERROR_WRONG_PADDING;
	/* skip over padding bytes */
	for (n = 1; n < len && data[n]; n++)
	{}
	/* Must be at least 8 pad bytes */
	if (n >= len || n < 9)
		return SC_ERROR_WRONG_PADDING;
	n++;
	if (out_ == null)
		/* just check the padding */
		return SC_SUCCESS;

	/* Now move decrypted contents to head of buffer */
	if (*out_len < len - n)
		return SC_ERROR_INTERNAL;
	*out_len = len - n;
	memmove(out_, data + n, *out_len);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sc_pkcs1_strip_02_padding",
		"stripped output(%i): %s", len - n, sc_dump_hex(out_, len - n));
	return cast(uint)len - n;
}


private extern(C) int acos5_64_pkcs15_init_card(sc_profile* profile, sc_pkcs15_card* p15card)
{
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"acos5_64_pkcs15_init_card"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_init_card");
	scope(exit)
		log_scope_exit_do(__LINE__);

	sc_path    path;
	sc_file*   file;
	ubyte[256] rbuf;

	p15card.tokeninfo.flags = SC_PKCS15_TOKEN_PRN_GENERATION;

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
	mixin (log!(q{"acos5_64_pkcs15_select_pin_reference"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_select_pin_reference");
	scope(exit)
		log_scope_exit_do(__LINE__);
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
	mixin (log!(q{"acos5_64_pkcs15_select_key_reference"}, q{"called"}));
	scope(exit) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_pkcs15_select_key_reference",
			"returning (key reference %i) with: %i (%s)\n", key_info.key_reference, rv, sc_strerror(rv));
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_pkcs15_select_key_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_prkey_info*) returning with argument *key_info:\n");
			writer.formattedWrite("%s", *key_info);
		}
	}
	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_pkcs15_select_key_reference(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_prkey_info*) was called with argument *key_info:\n");
		writer.formattedWrite("%s", *key_info);
	}

	if (key_info.key_reference > ACOS5_64_CRYPTO_OBJECT_REF_MAX)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	if (key_info.key_reference < ACOS5_64_CRYPTO_OBJECT_REF_MIN)
		key_info.key_reference = ACOS5_64_CRYPTO_OBJECT_REF_MIN;

	return rv=SC_SUCCESS;
}

/* Generate the private key on card */
private extern(C) int acos5_64_pkcs15_create_key(sc_profile*, sc_pkcs15_card* p15card, sc_pkcs15_object*)
{ // does nothing !!!
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_create_key"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_create_key");
	scope(exit)
		log_scope_exit_do(__LINE__);
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
	mixin log_scope_exit!("acos5_64_pkcs15_store_key");
	scope(exit)
		log_scope_exit_do(__LINE__);
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
	assert(encodedRSAbitLen( 511) == 0x04);
	assert(encodedRSAbitLen( 512) == 0x04); // defined, lowerLimit
	assert(encodedRSAbitLen( 759) == 0x04);
	assert(encodedRSAbitLen( 767) == 0x06);
	assert(encodedRSAbitLen( 768) == 0x06); // defined
// for each increment of 256 -> increment by 0x02
	assert(encodedRSAbitLen(3840) == 0x1E); // defined
	assert(encodedRSAbitLen(4095) == 0x20);
	assert(encodedRSAbitLen(4096) == 0x20); // defined, upperLimit
	assert(encodedRSAbitLen(4100) == 0x20);
	writeln("PASSED: encodedRSAbitLen");
}


private extern(C) int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)
{
	sc_card* card   = p15card.card;
	sc_context* ctx = card.ctx;
	sc_file* file;
	sc_file* tfile;
	sc_file* pukf;
	int rv = SC_ERROR_UNKNOWN;
	sc_apdu apdu;
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"called"`));
	mixin transmit_apdu_strerror!("acos5_64_pkcs15_generate_key");
	mixin log_scope_exit!("acos5_64_pkcs15_generate_key");
	scope(exit) {
		version(ENABLE_TOSTRING) {
			writer.put("int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)  is returnung\n");
//			writer.formattedWrite("%s", *profile);
		}
		log_scope_exit_do(__LINE__);
	}

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
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"Failed: Only RSA is supported"`));
		return rv=SC_ERROR_NOT_SUPPORTED;
	}
	/* Check that the card supports the requested modulus length */
	if (sc_card_find_rsa_alg(card, keybits) == null) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"Failed: Unsupported RSA key size"`));
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	}
/* TODO Think about other checks or possibly refuse to genearate keys if file access rights are wrong */

	/* allocate key object */
	if ((rv=new_file(profile, p15card, p15object, SC_PKCS15_TYPE_PRKEY_RSA, &file)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"create key: failed to allocate new key object"`));
		return rv;
	}

	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"private key path:       %s"`, "sc_print_path(&file.path)"));
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"private key_info path:  %s"`, "sc_print_path(&key_info.path)"));
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"private key_info usage: %u"`, "key_info.usage"));

	/* delete, if existant */
	if ((rv=sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP.SC_AC_OP_DELETE)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"generate key: pkcs15init_authenticate(SC_AC_OP_DELETE) failed (okay, if file didn't exist)"`));
		if (rv != SC_ERROR_FILE_NOT_FOUND)
			return rv;
	}
	if (rv != SC_ERROR_FILE_NOT_FOUND)
		rv = sc_delete_file(card, &file.path);

	/* create */
	if ((rv=sc_pkcs15init_create_file(profile, p15card, file)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"create key: failed to create private key file on card"`));
		return rv;
	}

	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"Have to generate RSA key pair with keybits %i; ID: %s and path: %s"`,
		"keybits", "sc_pkcs15_print_id(&key_info.id)", "sc_print_path(&key_info.path)"));

	version(ENABLE_TOSTRING) {
		writer.put("int acos5_64_pkcs15_generate_key(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, sc_pkcs15_pubkey* p15pubkey)  with argument *file, *key_info\n");
		writer.formattedWrite("%s", *file);
		writer.formattedWrite("%s", *key_info);
	}

	sc_path path = key_info.path;
	path.len -= 2;

	if ((rv=sc_select_file(card, &path, &tfile)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"generate key: no private object DF"`));
		return rv;
	}

	if ((rv=new_file(profile, p15card, p15object, SC_PKCS15_TYPE_PUBKEY_RSA, &pukf)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"pubkey: create temporary pukf failed"`));
		return rv;
	}

	if (pukf)
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"public key size %i; ef type %i/%i; id %04X; path: %s"`,
			"pukf.size", "pukf.type", "pukf.ef_structure", "pukf.id", "sc_print_path(&pukf.path)"));

	/* if exist, delete */
	if ((rv=sc_select_file(p15card.card, &pukf.path, null)) == SC_SUCCESS) {
		if ((rv=sc_pkcs15init_authenticate(profile, p15card, pukf, SC_AC_OP_DELETE)) < 0) {
			mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"pubkey: pkcs15init_authenticate(SC_AC_OP_DELETE) failed"`));
			return rv;
		}

		if ((rv=sc_pkcs15init_delete_by_path(profile, p15card, &pukf.path)) != SC_SUCCESS) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"pubkey: sc_pkcs15init_delete_by_path faile"`));
			return rv;
		}
	}
	/* create */
	if ((rv=sc_pkcs15init_create_file(profile, p15card, pukf)) != SC_SUCCESS) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"pubkey: sc_pkcs15init_create_file failed\n"`));
		return rv;
	}

///////////////////

/* Do generate here */
	{ // set SE for private key usage
		sc_security_env env;
		env.flags = SC_SEC_ENV_FILE_REF_PRESENT;
		env.operation = 5; /*SC_SEC_OPERATION_SIGN*/ // case 5: // my encoding for SC_SEC_GENERATE_RSAKEYS_PRIVATE
		assert(key_info.path.len >= 2);
		env.file_ref.len = 2;
		env.file_ref.value[0..2] = key_info.path.value[key_info.path.len-2..key_info.path.len];
//		env.file_ref.value[1] = key_info.path[key_info.path.len-1];
		if ((rv=acos5_64_set_security_env(card, &env, 0)) < 0) {
			mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"acos5_64_set_security_env(SC_SEC_GENERATE_RSAKEYS_PRIVATE) failed"`));
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
			mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"acos5_64_set_security_env(SC_SEC_GENERATE_RSAKEYS_PUBLIC) failed"`));
			return rv;
		}
	}

	ubyte[2] sbuf = [encodedRSAbitLen(keybits), ERSA_Key_type.CRT_for_Signing_only]; // always CRT
	if (key_info.usage & SC_PKCS15_PRKEY_USAGE.SC_PKCS15_PRKEY_USAGE_DECRYPT)
		sbuf[1] = ERSA_Key_type.CRT_for_Signing_and_Decrypting;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0, 0);
	apdu.lc = apdu.datalen = sbuf.length;
	apdu.data = sbuf.ptr;

	if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
	if ((rv=sc_check_sw(card, apdu.sw1, apdu.sw2)) < 0) {
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"%s: Card returned error"`, "sc_strerror(rv)"));
		return rv;
	}

	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"p15object.type:  %04x"`, "p15object.type"));
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"p15object.label: %s"`, "p15object.label.ptr"));
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"p15object.flags: %08x"`, "p15object.flags"));
	if (p15object.auth_id.value.ptr != null)
		mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"p15object.auth_id.value: %s"`, "sc_dump_hex(p15object.auth_id.value.ptr, p15object.auth_id.len)"));
	mixin (log!(`"acos5_64_pkcs15_generate_key"`, `"keybits: %u"`, "keybits"));

	/* Keypair generation -> collect public key info */
		if (p15pubkey != null) with (p15pubkey) {
			algorithm = SC_ALGORITHM_RSA;
			u.rsa.modulus.len = keybits / 8;
			u.rsa.modulus.data = cast(ubyte*)malloc(u.rsa.modulus.len);
			ubyte[3] DEFAULT_PUBEXPONENT = [0x01, 0x00, 0x01];
			u.rsa.exponent.len = DEFAULT_PUBEXPONENT.length;
			u.rsa.exponent.data = cast(ubyte*)malloc(DEFAULT_PUBEXPONENT.length);
			memcpy(u.rsa.exponent.data, DEFAULT_PUBEXPONENT.ptr, DEFAULT_PUBEXPONENT.length);

		}

	return rv=SC_SUCCESS;
} // acos5_64_pkcs15_generate_key


/*
 * Encode private/public key
 * These are used mostly by the Cryptoflex/Cyberflex drivers.
 */
private extern(C) int acos5_64_pkcs15_encode_private_key(sc_profile* profile, sc_card* card,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_encode_private_key"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_encode_private_key");
	scope(exit)
		log_scope_exit_do(__LINE__);
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_encode_private_key(sc_profile* profile, sc_card* card, sc_pkcs15_prkey_rsa*, ubyte* , size_t*, int) was called\n");
	return rv;
}

private extern(C) int acos5_64_pkcs15_encode_public_key(sc_profile* profile, sc_card* card,
				sc_pkcs15_prkey_rsa*,
				ubyte* , size_t*, int) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_encode_public_key"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_encode_public_key");
	scope(exit)
		log_scope_exit_do(__LINE__);
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_encode_public_key(sc_profile* profile, sc_card* card, sc_pkcs15_prkey_rsa*, ubyte* , size_t*, int) was called\n");
	return rv;
}

private extern(C) int acos5_64_pkcs15_delete_object(sc_profile* profile, sc_pkcs15_card* p15card,
			sc_pkcs15_object*, const(sc_path)* path) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_delete_object"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_delete_object");
	scope(exit)
		log_scope_exit_do(__LINE__);
	return rv=sc_pkcs15init_delete_by_path(profile, p15card, path);
}

private extern(C) int acos5_64_pkcs15_emu_store_data(sc_pkcs15_card* p15card, sc_profile* profile, sc_pkcs15_object*,
				sc_pkcs15_der*, sc_path*) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(`"acos5_64_pkcs15_emu_store_data"`, `"called"`));
	mixin log_scope_exit!("acos5_64_pkcs15_emu_store_data");
	scope(exit)
		log_scope_exit_do(__LINE__);
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_emu_store_data(sc_pkcs15_card* p15card, sc_profile* profile, sc_pkcs15_object*, sc_pkcs15_der*, sc_path*) was called\n");
	return rv;
}

/**
 * There are a lot of checks that might be tought of as reasonable
*/
private extern(C) int acos5_64_pkcs15_sanity_check(sc_profile* profile, sc_pkcs15_card* p15card) {
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(q{"acos5_64_pkcs15_sanity_check"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_pkcs15_sanity_check");
	scope(exit)
		log_scope_exit_do(__LINE__);
	version(ENABLE_TOSTRING)
		writer.put("int acos5_64_pkcs15_sanity_check(sc_profile* profile, sc_pkcs15_card* p15card) was called\n");
	return rv;
}

//version(all/*REINITIALIZE*/) {

struct TriBool { //similar to std.typecons : Ternary; but no algebra required, just the states
	@safe @nogc nothrow pure:

	private ubyte value = 2; // yes
	private static TriBool make(ubyte b) {
		TriBool r = void;
		r.value = b;
		return r;
	}

	alias value this; // different from std.typecons.Ternary  // gdc seems to ignore it

	/** The possible states of the `TriBool` */
	enum no      = make(0);
	enum yes     = make(2);
	enum unknown = make(6);
}

struct reinit_entry {
	c_ulong  flags;
	int      cse;
	ubyte    cmd_len; // temporarily, to check correct length of apdu
	iuba                cmd;
	iuba                sw1sw2Response; //expected_response;
	TriBool   must_match_expected_response; // = TriBool.yes;
}

immutable(reinit_entry[])  Zeroize8030_entries;
immutable(reinit_entry[])  E0_entries;
immutable(reinit_entry[])  A444DC_entries;


private int re_initialize_token(sc_card* card, in uba so_pin, const(char)* label) {
/* currently, re_initialize_token doesn't process label ! Later, label will be stored in file 4100 5032 */
	import std.string : toStringz, fromStringz, stripRight;
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	sc_apdu apdu;
	mixin (log!(`"re_initialize_token"`, `"called"`));
	mixin transmit_apdu_strerror!("re_initialize_token");
	mixin log_scope_exit!("re_initialize_token");
	scope(exit) {
		do_zeroize_token    = false;
		do_initialize_token = false;
		log_scope_exit_do(__LINE__);
	}

	version(REINIT_ACOSMODE_V2) {}
	else return rv=SC_ERROR_NOT_SUPPORTED; // SC_ERROR_INVALID_CARD // REINIT_ACOSMODE_V3_FIPS_140_2L3  REINIT_ACOSMODE_V3_NSH_1

	if (so_pin.length!=8)
		return rv=SC_ERROR_NOT_SUPPORTED;
	if (acos5_64_get_serialnr(card, null) < 0)
		return rv=SC_ERROR_NOT_SUPPORTED;

	ubyte[256] rbuf;


	void do_logs_dry_run(in ulong i, const ref reinit_entry e) {
		switch (e.cmd_len) { // minimum is 4, max. >13
			case 0, 1, 2, 3:
				break;
			case 4:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3]);
				break;
			case 5:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4]);
				break;
			case 6:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5]);
				break;
			case 7:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6]);
				break;
			case 8:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7]);
				break;
			case 9:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8]);
				break;
			case 10:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8], e.cmd[9]);
				break;
			case 11:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8], e.cmd[9], e.cmd[10]);
				break;
			case 12:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8], e.cmd[9], e.cmd[10], e.cmd[11]);
				break;
			case 13:
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X %02X %02X %02X %02X\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8], e.cmd[9], e.cmd[10], e.cmd[11], e.cmd[12]);
				break;
			default: // >13
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"(%2i) dry-run 'reinit' command: %02X %02X %02X %02X  %02X  %02X %02X %02X %02X %02X %02X %02X %02X  more data ...\n", i, e.cmd[0], e.cmd[1], e.cmd[2], e.cmd[3], e.cmd[4], e.cmd[5], e.cmd[6], e.cmd[7], e.cmd[8], e.cmd[9], e.cmd[10], e.cmd[11], e.cmd[12]);
				break;
		}
	} // do_logs_dry_run

	int  perform_hot_run(in ulong i, const ref reinit_entry e) { // do_action_effectively
		int rval = SC_SUCCESS;
		rbuf = rbuf.init;
		bytes2apdu(ctx, e.cmd, apdu);
		apdu.flags = (apdu.flags & ~(SC_APDU_FLAGS_NO_GET_RESP | SC_APDU_FLAGS_NO_RETRY_WL)) | e.flags;

		if (e.cse==SC_APDU_CASE_2_SHORT ||e.cse==SC_APDU_CASE_4_SHORT) {
			apdu.resplen = rbuf.length;
			apdu.resp    = rbuf.ptr;
		}

		if ((rv=transmit_apdu_strerror_do(__LINE__)) < 0) return rv;
		switch (e.sw1sw2Response.length) {
			case 0, 1:
				sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
				"(%2i) Didn't get expected response from command: %i (%s)\n", i, rval, sc_strerror(rval));
				return rval= -1;
//				break;
			case 2:
				switch (e.must_match_expected_response.value) { // gdc seems to ignore alias this
					case TriBool.no:
						break;
					case TriBool.yes:
						if ((rval = -1* (apdu.sw1!=e.sw1sw2Response[0] || apdu.sw2!=e.sw1sw2Response[1])) < 0) {
							sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
							"(%2i) Didn't get expected response (mostly 0x9000 or 0x61??) from command: %i (%s), but intead sw1: %02X and sw2: %02X", i, rval, sc_strerror(rval), apdu.sw1, apdu.sw2);
							return rval;
						}
						break;
					case TriBool.unknown:
						if ((rval = -1* (apdu.sw1!=e.sw1sw2Response[0])) < 0) {
							sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
							"(%2i) Didn't get expected response (mostly 0x9000 or 0x61??) from command: %i (%s)\n", i, rval, sc_strerror(rval));
							return rval;
						}
						break;
					default:
						assert(0);
				}
				break;
			default:
				switch (e.must_match_expected_response.value) { // gdc seems to ignore alias this
					case TriBool.no,
							 TriBool.unknown:
						break;
					case TriBool.yes:
						if ((rval = -1*(apdu.sw1!=e.sw1sw2Response[$-2] || apdu.sw2!=e.sw1sw2Response[$-1])) < 0) {
							sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
							"(%2i) Didn't get expected response=0x9000 from command: %i (%s)\n", i, rval, sc_strerror(rval));
							return rval;
						}
						if ((rval=SC_ERROR_UNKNOWN_DATA_RECEIVED*(!equal(rbuf[0..apdu.resplen][], e.sw1sw2Response[0..$-2][]))) < 0) {
							sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
								"(%2i) Received data don't match expected ones !\n(%i) Response: %s\n(%i) Expected: %s", i, apdu.resplen,
								sc_dump_hex(rbuf.ptr, apdu.resplen), e.sw1sw2Response.length-2, sc_dump_hex(e.sw1sw2Response.ptr, e.sw1sw2Response.length-2));
							return rval;
						}
						break;
					default:
						assert(0);
				}
				break;
		} // switch (e.sw1sw2Response.length)
		return rval;
	} // perform_hot_run


	foreach (i, const ref e; get_Zeroize8030_entries(card, so_pin)) {
		enforce(e.cmd_len == e.cmd.length, "Something went wrong when checking Zeroize8030_entries"~" on index: "~to!string(i)); // temporarily
		switch (e.cse) {
			case SC_APDU_CASE_1,
					 SC_APDU_CASE_2_SHORT:
				enforce(e.cmd.length == 3+e.cse, "Something went wrong when checking Zeroize8030_entries on index: "~to!string(i)); // temporarily
				break;
			case SC_APDU_CASE_3_SHORT:
				enforce(e.cmd_len == 2+e.cse+e.cmd[4], "Something went wrong when checking Zeroize8030_entries on index: "~to!string(i)); // temporarily
				break;

			default:
				break;
		}
		if (e.cse==SC_APDU_CASE_3_SHORT || e.cse==SC_APDU_CASE_4_SHORT)
			enforce(e.cmd_len == e.cmd[4] + 5, "Something went wrong when checking Zeroize8030_entries on index: "~to!string(i)); // temporarily
		do_logs_dry_run(i+1, e);

		if (do_zeroize_token)
			if ((rv=perform_hot_run(i, e)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"perform_hot_run for an Zeroize8030_entry failed: %i (%s)\n", rv, sc_strerror(rv));
				return rv;
			}
	} // foreach (i, const ref e; Zeroize8030_entries)

	foreach (i, const ref e; get_E0_entries()) { // all entries have the INS E0 and cmd_len>=11
		enforce(e.cmd_len == e.cmd.length, "Something went wrong when checking E0_entries"~" on index: "~to!string(i)); // temporarily
		enforce(e.cmd_len == e.cmd[4] + 5, "Something went wrong when checking E0_entries"~" on index: "~to!string(i)); // temporarily
		do_logs_dry_run(i+1, e);

		if (do_initialize_token)
			if ((rv=perform_hot_run(i, e)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"perform_hot_run for an E0_entry failed: %i (%s)\n", rv, sc_strerror(rv));
				return rv;
			}
	}

	foreach (i, const ref e; get_A444DC_entries(card, so_pin, label)) {
		enforce(e.cmd_len == e.cmd.length, "Something went wrong when checking A444DC_entries"~" on index: "~to!string(i)); // temporarily
		if (e.cse==SC_APDU_CASE_3_SHORT || e.cse==SC_APDU_CASE_4_SHORT)
			enforce(e.cmd_len == e.cmd[4] + 5, "Something went wrong when checking A444DC_entries"~" on index: "~to!string(i)); // temporarily
		do_logs_dry_run(i+1, e);

		if (do_initialize_token)
			if ((rv=perform_hot_run(i, e)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "re_initialize_token",
					"perform_hot_run for an A444DC_entry failed: %i (%s)\n", rv, sc_strerror(rv));
				return rv;
			}
	}

	return rv;
} // re_initialize_token


immutable(reinit_entry[]) get_Zeroize8030_entries(sc_card* card, in uba so_pin) {
	reinit_entry[] result = [
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4100"), representation(x"61 32"), TriBool.no), //  DF(PKCS #15) 4100
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4129"), representation(x"61 20"), TriBool.no),

		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT, 13,(representation(x"00 20 00 01 08")~so_pin).idup, representation(x"90 00"), TriBool.yes), // SOPIN FOR RE_INITIALIZE
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT, 13, representation(x"00 A4 00 00 08  4102  4102  4102  4102"), representation(x"6A 87"), TriBool.yes), // strange, undocumented
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4100"), representation(x"61 32"), TriBool.no), //  DF(PKCS #15) 4100
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4129"), representation(x"61 20"), TriBool.no),

		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  3F00"), representation(x"61 1A"), TriBool.no),
		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  3F00"), representation(x"61 1A"), TriBool.no),
		reinit_entry(0, SC_APDU_CASE_1,        4, representation(x"80 30 00 00"),        representation(x"90 00"), TriBool.yes), // Zeroize Card Command
		reinit_entry(0, SC_APDU_CASE_1,        4, representation(x"80 30 00 00"),        representation(x"90 00"), TriBool.yes), // Zeroize Card Command Sequence, undocumented
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  6, representation(x"00 D6  C191 01  02"/*eACOSV3MODE_V2*/), representation(x"90 00"), TriBool.yes), // Compatibility Byte/Operation Mode : SET TO ZERO, OKAY for a factory default
		reinit_entry(0, SC_APDU_CASE_1,        4, representation(x"80 30 00 00"),        representation(x"90 00"), TriBool.yes), // Continue Zeroize Card Command Sequence, undocumented
		reinit_entry(0, SC_APDU_CASE_1,        4, representation(x"80 30 00 FF"),        representation(x"90 00"), TriBool.yes), // End Zeroize Card Command Sequence, undocumented
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  6, representation(x"00 D6  C191 01  02"/*eACOSV3MODE_V2*/), representation(x"90 00"), TriBool.yes), // Changed, to be issued again here
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  6, representation(x"00 D6  C192 01  00"), representation(x"90 00"), TriBool.yes), // Zeroize Card User Data/Deactivate Card Disable Flag : SET TO ZERO, OKAY
	];
	if (card.type==SC_CARD_TYPE_ACOS5_64_V2)
		result[10] = result[13] = reinit_entry(0, SC_APDU_CASE_3_SHORT,  6, representation(x"00 D6  C191  01 00"/*eACOSV2MODE_V2*/), representation(x"90 00"), TriBool.yes);

	return assumeUnique(result);

/+
Description																						EEPROM Area									Update Access Stage		Default Value
TA1 of ATR																						0xC183											0											0x96
Card Life Cycle Byte																	0xC184											N/A										0

SC_CARD_TYPE_ACOS5_64_V2: Compatibility Byte					0xC191											0											0  possible values: see enum EACOSV2MODE
SC_CARD_TYPE_ACOS5_64_V3: Operation Mode Byte					0xC191											0											0  possible values: see enum EACOSV3MODE

Zeroize Card User Data/Deactivate Card Disable Flag		0xC192											0,2,4									0
EEPROM Key (Transport Key?), 8 bytes									0xC197 - 0xC19E							0,2										0
Card Life Cycle Byte Complement												0xC19F											N/A										0xFF
EEPROM Key Error Counter															0xC1A0											0,2										0xFF
+/
}

immutable(reinit_entry[]) get_E0_entries() {
/*                                                                                                                            FDB==0x?? 38/3F           01/02/04/06/0A						09/0C							1C
                                                                                                                                        DF/MF					 	EF_CHV										Key File					SE File

                                                                                                                                          Delete Child	  Read										  Get Key					  Read
                                                                                                                                         Create EF			 Update/Append Record			 Put Key					 MSE Store/Delete
                                                                                                                                                         Update/Erase Binary
                                                                                                                                        Create DF				N/A												MSE/PSO Commands	MSE Restore
                                                                                                                                       Deactivate
                                                                                                                                      Activate
                                                                                                                                     Terminate  (are always FF, except for MF)
                                                                                                                                    Delete Self (are always FF, except for MF))
                                                                                                                                   Not Used
                                                                                                                                   MSB(7)  LSB(0)
                                                                                                                      HI LO      0b0111_1111==0x7F==AM (only AM==7F is used, except nothing which is 00 for MF)   */
	reinit_entry[] result = [ //         FID (File ID)                           FID  |       FDB       MRL   NOR |      SFI      LCSI     AM b6 b5 b4 b3 b2 b1 b0
		reinit_entry(0,3,32, /*§§ 3F00 MF         */representation(x"00 E0 00 00 1B 62 19 83 02  3F00  82 02  3F  00   8D 02 00 03          8A 01 01 8C 08 7F FF FF 01 01 01 01 01"), representation(x"90 00")), // AB 07 8C 02 80 30 9E 01 01
		reinit_entry(0,3,35, /*   0001 CHVFile SO */representation(x"00 E0 00 00 1E 62 1C 83 02  0001  82 06  0A  00 00 15 00 01   88 01 00 8A 01 01 8C 08 7F 01 FF 01 01 FF 01 FF"), representation(x"90 00")),
		reinit_entry(0,3,35, /*§§ 0002 SymKeyF SO */representation(x"00 E0 00 00 1E 62 1C 83 02  0002  82 06  0C  00 00 25 00 02   88 01 00 8A 01 01 8C 08 7F FF FF 01 01 01 01 FF"), representation(x"90 00")),
		reinit_entry(0,3,35, /*§§ 0003 SEFile SO  */representation(x"00 E0 00 00 1E 62 1C 83 02  0003  82 06  1C  00 00 30 00 02   88 01 00 8A 01 01 8C 08 7F FF FF 01 01 01 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$$ 2F00  EF.DIR    */representation(x"00 E0 00 00 1E 62 1C 83 02  2F00  82 02  01  00   80 02 00 21 88 01 00 8A 01 01 8C 08 7F 01 FF 01 01 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,55, /*§§ 4100  DF.PKCS#15*/representation(x"00 E0 00 00 32 62 30 83 02  4100  82 02  38  00   8D 02 41 03 88 01 00 8A 01 01 8C 08 7F FF FF 01 01 01 01 01   AB 00 84 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30"), representation(x"90 00")),
		reinit_entry(0,3,35, /*§§ 4101 CHVFile USR*/representation(x"00 E0 00 00 1E 62 1C 83 02  4101  82 06  0A  00 00 15 00 01   88 01 01 8A 01 01 8C 08 7F 03 FF 00 FF FF 01 FF"), representation(x"90 00")),
		reinit_entry(0,3,35, /*4102               */representation(x"00 E0 00 00 1E 62 1C 83 02  4102  82 06  0C  00 00 25 00 0C   88 01 02 8A 01 01 8C 08 7F 03 FF 00 FF 01 01 FF"), representation(x"90 00")),
		reinit_entry(0,3,35, /*§§ 4103 SEFile USER*/representation(x"00 E0 00 00 1E 62 1C 83 02  4103  82 06  1C  00 00 38 00 08   88 01 03 8A 01 01 8C 08 7F 03 FF 00 FF 00 03 00"), representation(x"90 00")),

		reinit_entry(0,3,35, /*$X 4111 AODF       */representation(x"00 E0 00 00 1E 62 1C 83 02  4111  82 02  01  00   80 02 00 80 88 01 11 8A 01 01 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4112 PrKDF      */representation(x"00 E0 00 00 1E 62 1C 83 02  4112  82 02  01  00   80 02 03 00 88 01 12 8A 01 01 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4113 PuKDF      */representation(x"00 E0 00 00 1E 62 1C 83 02  4113  82 02  01  00   80 02 06 00 88 01 13 8A 01 01 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4114 SKDF       */representation(x"00 E0 00 00 1E 62 1C 83 02  4114  82 02  01  00   80 02 01 00 88 01 14 8A 01 01 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4115 CDF        */representation(x"00 E0 00 00 1E 62 1C 83 02  4115  82 02  01  00   80 02 01 00 88 01 15 8A 01 05 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4116 DODF       */representation(x"00 E0 00 00 1E 62 1C 83 02  4116  82 02  01  00   80 02 01 00 88 01 16 8A 01 05 8C 08 7F 03 FF 00 03 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*$X 4120 EF.Cert    */representation(x"00 E0 00 00 1E 62 1C 83 02  4120  82 02  01  00   80 02 20 00 88 01 20 8A 01 05 8C 08 7F 01 FF 00 01 FF 01 00"), representation(x"90 00")),

		reinit_entry(0,3,35, /*5032  EF.TokInf */representation(x"00 E0 00 00 1E 62 1C 83 02  5032  82 02  01  00   80 02 00 C0 88 01 22 8A 01 01 8C 08 7F 03 FF 00 03 FF 00 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*5031  EF.ODF    */representation(x"00 E0 00 00 1E 62 1C 83 02  5031  82 02  01  00   80 02 00 6C 88 01 21 8A 01 01 8C 08 7F 03 FF 00 03 FF 00 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*5155  EF.AODF ? */representation(x"00 E0 00 00 1E 62 1C 83 02  5155  82 06  04  00 00 82 00 02   88 01 55 8A 01 01 8C 08 7F 01 FF 00 01 01 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*4110  EF.Cert ? */representation(x"00 E0 00 00 1E 62 1C 83 02  4110  82 02  01  00   80 02 10 00 88 01 10 8A 01 01 8C 08 7F 01 FF 00 01 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*4129 cacheFriend*/representation(x"00 E0 00 00 1E 62 1C 83 02  4129  82 06  02  00 00 14 00 02   88 01 1D 8A 01 01 8C 08 7F 00 00 00 00 00 00 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*4151  ???       */representation(x"00 E0 00 00 1E 62 1C 83 02  4151  82 02  01  00   80 02 02 00 88 01 51 8A 01 01 8C 08 7F 01 FF 00 01 FF 01 00"), representation(x"90 00")),
		reinit_entry(0,3,35, /*4152  ???       */representation(x"00 E0 00 00 1E 62 1C 83 02  4152  82 02  01  00   80 02 02 00 88 01 52 8A 01 01 8C 08 7F 01 FF 00 01 FF 01 00"), representation(x"90 00")),

		reinit_entry(0,3,35, /*3901 Test File  */representation(x"00 E0 00 00 1E 62 1C 83 02  3901  82 02  01  00   80 02 00 10 88 01 00 8A 01 01 8C 08 7F 01 FF 45 45 FF 45 45"), representation(x"90 00")),
		reinit_entry(0,3,35, /*3902 Test File  */representation(x"00 E0 00 00 1E 62 1C 83 02  3902  82 02  01  00   80 02 00 10 88 01 00 8A 01 01 8C 08 7F 01 FF 46 46 FF 46 46"), representation(x"90 00")),
	];
	return assumeUnique(result);
}

immutable(reinit_entry[]) get_A444DC_entries(sc_card* card, in uba so_pin, const(char)* label) { // (use after creation commands E0)
	reinit_entry[] result = [
/* */
		reinit_entry(2,3, 7, representation(x"00 A4 00 00 02  3F00"), representation(x"61 22"), TriBool.unknown),
		reinit_entry(2,3, 7, representation(x"00 A4 00 00 02  0001"), representation(x"61 20")), // CHV-file within MF
		reinit_entry(0,3,26,(representation(x"00 DC 01 04 15 C1 88 08")~so_pin~representation(x"88 08 61 63 6F 73 35 5F 36 34")).idup, representation(x"90 00")), // 8 tries
		reinit_entry(0,3, 7, representation(x"00 44 00 00 02  0001"), representation(x"90 00")),

		reinit_entry(2,3, 7, representation(x"00 A4 00 00 02  0002"), representation(x"61 20")), // sym. key-file within MF
		reinit_entry(0,3, 7, representation(x"00 44 00 00 02  0002"), representation(x"90 00")),

/*
  "CODES PINS"
  ALL (except Transport code; I won't touch that here) TO BE CHANGED LATER by the user; Following are the code/pin/password (defaults) set here:
  (a) Transport code : 00 00 00 00 00 00 00 00   has no representation in ascii; set by Zeroize Card ; without PUK
  (b) USER_PIN       : 31 32 33 34 35 36 37 38   in ascii: 12345678  ; with PUK (unblocking key) same as SO_PIN                     ; 8 tries each before being blocked
if automatic initialization is done:
  (c) SO_PIN         : 38 37 36 35 34 33 32 31   in ascii: 87654321  ; with PUK (unblocking key) same as SO_PUK, in ascii: acos5_64 ; 8 tries each before being blocked
if called by e.g. pkcs11-tool --init-token --so-pin ...
  (c) SO_PIN         : acc. to param so_pin                          ; with PUK (unblocking key) same as SO_PUK, in ascii: acos5_64 ; 8 tries each before being blocked
  (d) SO_PUK         : 61 63 6F 73 35 5F 36 34   in ascii: acos5_64
*/
		reinit_entry(2,3, 7, representation(x"00 A4 00 00 02  0003"), representation(x"61 20")), // SE-file within MF
		reinit_entry(0,3,16, representation(x"00 DC 01 04 0B 80 01 01 A4 06 83 01 01 95 01 08"), representation(x"90 00")), // rec #1, verify lokal pin #1==81
		reinit_entry(0,3, 7, representation(x"00 44 00 00 02  0003"), representation(x"90 00")),


		reinit_entry(2,3, 7, representation(x"00 A4 00 00 02  2F00"), representation(x"61 20")), //  EF(DIR) 2F00
		reinit_entry(0,3,38, representation(x"00 D6 00 00 21 61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00"), representation(x"90 00")),  // EF(DIR) 2F00 -> 3F00/4100
		reinit_entry(0,3, 7, representation(x"00 44 00 00 02  2F00"), representation(x"90 00")),
////
		reinit_entry(2,3,  7, representation(x"00 A4 00 00 02  4100"), representation(x"61 32"), TriBool.unknown), //  DF(PKCS #15) 4100
		reinit_entry(2,3,  7, representation(x"00 A4 00 00 02  5032"), representation(x"61 20")), //  EF(TokenInfo) 5032
		reinit_entry(0,3,192, (representation(x"00 D6 00 00 BB 3081B80201000408")~card.serialnr.value[0..8]~
				representation(x"0C1A416476616E63656420436172642053797374656D73204C74642EA0210C1F")~
				TokenInfoLabel_default(card)~
				representation(x"03020420A266300F020101020100050003020001020110300F02010202010105000302005C020110300F020103020106050003020050020110300F020104020140050003020050020110300F020105020103050003020040020110300F020106020103050003020004020113")).idup, representation(x"90 00")),
		reinit_entry(0,3,  7, representation(x"00 44 00 00 02  5032"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4101"), representation(x"61 20")), // CHV-file within DF
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 26, (representation(x"00 DC 01 04 15 C1 88 08 31 32 33 34 35 36 37 38 88 08")~so_pin).idup, representation(x"90 00")),  // 8 tries
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4101"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4102"), representation(x"61 20")), // sym. key file within PKCS#15 application DF
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 42, representation(x"00 DC 01 04 25 8101FF14F1E0D0C1B0A1890807164504130201F189FEB3C837451694000000000000000000"), representation(x"90 00")), // no resetting code for key !
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 42, representation(x"00 DC 02 04 25 8202FFFF14F1010213048516070849A1B0C1D0E0F14589B316FE9437C80000000000000000"), representation(x"90 00")), // no resetting code for key ! think about using SO_PIN or just update record with new key?
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4102"), representation(x"90 00")),

		reinit_entry(SC_APDU_FLAGS_NO_GET_RESP, SC_APDU_CASE_3_SHORT,  7U, representation(x"00 A4 00 00 02  4103"), representation(x"61 20")), // SE-file within PKCS#15 application DF
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 61, representation(x"00 DC 01 04 38 80 01 01 A4 06 83 01 81 95 01 08 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), cast(immutable(ubyte)[])x"90 00"), // rec #1-#4, verify lokal pin #1==81
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 61, representation(x"00 DC 02 04 38 80 01 02 B4 09 83 01 01 95 01 08 80 01 02 B8 09 83 01 01 95 01 08 80 01 02 A4 06 83 01 81 95 01 08 0000000000000000000000000000000000000000000000"), cast(immutable(ubyte)[])x"90 00"), // rec #1-#4, verify lokal pin #1==81
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 61, representation(x"00 DC 03 04 38 80 01 03 A4 06 83 01 01 95 01 08 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), cast(immutable(ubyte)[])x"90 00"), // rec #1-#4, verify lokal pin #1==81
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 61, representation(x"00 DC 04 04 38 80 01 04 A4 09 83 01 01 83 01 81 95 01 08 000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), cast(immutable(ubyte)[])x"90 00"), // rec #1-#4, verify lokal pin #1==81

		reinit_entry(0, SC_APDU_CASE_3_SHORT, 26, representation(x"00 DC 05 04 15 80 01 05   B4 08 84 00 95 01 30 80 01 02                                   A4 06 83 01 81 95 01 80"), cast(immutable(ubyte)[])x"90 00"),
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 36, representation(x"00 DC 06 04 1F 80 01 06   B4 08 84 00 95 01 30 80 01 02   B8 08 84 00 95 01 30 80 01 02   A4 06 83 01 81 95 01 80"), cast(immutable(ubyte)[])x"90 00"),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4103"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  4111"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  59, representation(x"00 D6 00 00 36 3034300A0C0455736572030206403003040101A121301F030202CC0A0101020104020108020108800200810401FF300604043F004100"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  4111"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  4112"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  4112"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  4113"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  4113"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  4114"), representation(x"61 20")),
//wrong content ?
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  47, representation(x"00 D6 00 00 2A 302830100C076B657943617264030206C0040101300F0401010303062040030203B80201013003020118"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  4114"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  3901"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  21, representation(x"00 D6 00 00 10 FFFFFFFF80808080FFFFFFFF40404040"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  3901"), representation(x"90 00")),
		reinit_entry(2, SC_APDU_CASE_3_SHORT,   7, representation(x"00 A4 00 00 02  3902"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  21, representation(x"00 D6 00 00 10 FFFFFFFF80808080FFFFFFFF40404040"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,   7, representation(x"00 44 00 00 02  3902"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  5031"), representation(x"61 20")), //  EF.ODF 5031
		reinit_entry(0, SC_APDU_CASE_3_SHORT,113, representation(x"00 D6 00 00 6C A80A300804063F0041004111A00A300804063F0041004112A10A300804063F0041004113A30A300804063F0041004114A40A300804063F0041004120A70A300804063F0041004116000000000000000000000000000000000000000000000000000000000000000000000000"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  5031"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  5155"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 66, representation(x"00 DC 02 04 3D 30 3B 30 08 0C 02 30 32 03 02 07 80 30 03 03 01 82 A1 2A 30 28 03 03 07 CB 80 0A 01 01 02 01 04 02 01 08 02 01 08 A0 03 02 01 08 04 01 00 18 0D 31 32 33 34 35 36 37 38 39 30 31 32 33"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 66, representation(x"00 DC 01 04 3D 30 3B 30 08 0C 02 30 31 03 02 07 80 30 03 03 01 81 A1 2A 30 28 03 03 07 CB 80 0A 01 01 02 01 04 02 01 08 02 01 08 A0 03 02 01 08 04 01 00 18 0D 31 32 33 34 35 36 37 38 39 30 31 32 33"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  5155"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4110"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4110"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  413B"), representation(x"6A 82")),
		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4100"), representation(x"61 32"), TriBool.unknown),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  41FB"), representation(x"6A 82")),
		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4100"), representation(x"61 32"), TriBool.unknown),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4151"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4151"), representation(x"90 00")),
		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4152"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4152"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, representation(x"00 A4 00 00 02  4129"), representation(x"61 20")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 25, representation(x"00 DC 01 04 14 00 00 00 00 4A 97 4A 97 72 49 72 49 C0 C6 40 68 81 C7 01 00"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT, 25, representation(x"00 DC 02 04 14 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, representation(x"00 44 00 00 02  4129"), representation(x"90 00")),

		reinit_entry(2, SC_APDU_CASE_3_SHORT,  7, /*3F00*/representation(x"00 A4 00 00 02  3F00"), representation(x"61 22"), TriBool.unknown),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, /*4100*/representation(x"00 44 00 00 02  4100"), representation(x"90 00")),
		reinit_entry(0, SC_APDU_CASE_3_SHORT,  7, /*4100*/representation(x"00 44 00 00 02  3F00"), representation(x"90 00")),
	];
	return assumeUnique(result);
}


uba /* <-OctetStringBigEndian*/ integral2ub(uint storage_bytes)(size_t integral)
	if (storage_bytes<=size_t.sizeof)
{
	uba result;
	foreach (i; 0..storage_bytes)
		result ~= cast(ubyte)(integral >>> 8*(storage_bytes-1-i) & 0xFF); // precedence: () *  >>>  &
	return result;
}

/** Take a byte stream as coming form the token and convert to an integral value
Most often, the byte stream has to be interpreted as big-endian (The most significant byte (MSB) value, is at the lowest address (position in stream). The other bytes follow in decreasing order of significance)
currently used in new_file and unittest only
*/
ushort ub22integral(in uba ub2) { // formerly ub22integralLastTwo
	if (ub2.length!=2)
		return 0;
	return  (ub2[0] << 8) | ub2[1];
}

uba TokenInfoLabel_default(sc_card* card) {
	uba result;
	result = (card.type==SC_CARD_TYPE_ACOS5_64_V2? representation("CryptoMate64_") : representation("CryptoMateNano_")).dup;
	foreach (b; card.serialnr.value[0..8]) { // 80 DD 00 5B A1 0A 65 00
		ubyte x = b>>>4;
		if (x>9) result ~= cast(ubyte)(x+55);
		else     result ~= cast(ubyte)(x+48);
		x = b & 0x0F;
		if (x>9) result ~= cast(ubyte)(x+55);
		else     result ~= cast(ubyte)(x+48);
	}
	while (result.length<31) result ~= ubyte(0x30);
	return result;
}

//@safe
unittest {
	import std.stdio;
//	writeln("size_t.sizeof: ", size_t.sizeof);
	ubyte[2] ub2 = [0x41, 0x03];
	assert(ub22integral([0x41, 0x03]) == 0x4103);
	writeln("PASSED: ub22integral");
version(X86_64) {
	const integralVal = 0xFFEEDDCCBBAA9988UL;
	assert(equal(integral2ub!8(integralVal), [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88][]));
	writeln("PASSED: integral2ub!8");
version(LittleEndian) {
	assert(equal(integral2ub!4(integralVal),                         [0xBB, 0xAA, 0x99, 0x88][]));
	writeln("PASSED: integral2ub!4");
}
}
else version(X86) {
	const integralVal = 0xFFEEDDCCUL;
	assert(equal(integral2ub!4(integralVal), [0xFF, 0xEE, 0xDD, 0xCC][]));
	writeln("PASSED: integral2ub!4");
}
else
	static assert(0);
}


version(ENABLE_ACOS5_64_UI) {
	/**
	 * To handle user interface routines
	 */
	struct ui_context_t {
		int     user_consent_enabled;
		string  user_consent_app;
	}

	ref ui_context_t get_acos5_64_ui_ctx(sc_card* card) {
		acos5_64_private_data* private_data = cast(acos5_64_private_data*) card.drv_data;
		return private_data.ui_ctx;
	}
//               #define GET_DNIE_UI_CTX(card)       ((    (dnie_private_data_t*)((card)->drv_data) )->ui_ctx)

/** default user consent program (if required) */
string USER_CONSENT_CMD = "/usr/bin/pinentry";

/** Messages used on user consent procedures */
immutable(char)* user_consent_title   = "Request for permit: Generation of digital signature";
//immutable(char)* user_consent_title   = "Erlaubnisanfrage zur Erstellung digitale Signatur/Unterschrift";

////#ifdef linux
immutable(char)* user_consent_message ="A token's secret/private RSA-key shall be used to generate and hand over Your digital signature!\nDo You agree?\n\n(Don't agree if You didn't expect this!)";
//immutable(char)* user_consent_message ="Ein geheimer/privater RSA-Schlüssel des Token soll zur Erstellung/Aushändigung Ihrer digitalen Signatur/Unterschrift benutzt werden! Stimmen Sie zu?";
//immutable(char)* user_consent_message ="Está a punto de realizar una firma electrónica con su clave de FIRMA del DNI electrónico. ¿Desea permitir esta operación?";
////#else
////const char *user_consent_message="Esta a punto de realizar una firma digital\ncon su clave de FIRMA del DNI electronico.\nDesea permitir esta operacion?";
////#endif

private int acos5_64_get_environment(sc_card* card, ui_context_t* ui_context) {
	scconf_block** blocks;
	scconf_block*  blk;
	sc_context*    ctx = card.ctx;
	/* set default values */
	ui_context.user_consent_app = USER_CONSENT_CMD;
	ui_context.user_consent_enabled = 1;
	/* look for sc block in opensc.conf */
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

version(Posix) {
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
	mixin (log!(q{"acos5_64_ask_user_consent"}, q{"called"}));
	mixin log_scope_exit!("acos5_64_ask_user_consent");
	scope(exit)
		log_scope_exit_do(__LINE__);

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
		execlp(get_acos5_64_ui_ctx(card).user_consent_app.toStringz, get_acos5_64_ui_ctx(card).user_consent_app.toStringz, cast(char*)null);

		rv = SC_ERROR_INTERNAL;
		msg = "execlp() error";	/* exec() failed */
		goto do_error;
	default:		/* parent */
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
	/* close out channel to force client receive EOF and also die */
	if (fout != null) fclose(fout);
	if (fin != null) fclose(fin);
/+
#else
#error "Don't know how to handle user consent in this (rare) Operating System"
#endif
+/
	if (msg != null)
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "acos5_64_ask_user_consent", "%s\n", msg.toStringz);

	return rv;
} // acos5_64_ask_user_consent
} // version(Posix)

} // version(ENABLE_ACOS5_64_UI)

/**
OS2IP converts an octet string to a nonnegative integer.
   Input:  X octet string to be converted

   Output:  x corresponding nonnegative integer

This is usually done by acos for RSA operations
The interpretation of OS2IP's input is that of big-endian
acos operates the same, expects an octet string `OctetString` where OctetString[0] is the most significant byte (highest importance for value of resulting BIGNUM)
*/
BIGNUM* OS2IP(uba OctetStringBigEndian)
out (result) { assert(!BN_is_negative(result)); }
body {
	BIGNUM* res = BN_new();
	BIGNUM* a   = BN_new();
	BIGNUM* b   = BN_new();
	if (res == null || a == null || b == null)
		return null;

	BN_zero(res);
	const int xLen = cast(int)OctetStringBigEndian.length;
	foreach (i; 0..xLen) {
		/*int*/ BN_set_word(a, OctetStringBigEndian[i]);
		/*int*/ BN_lshift  (b, a, 8*(xLen-1 -i));
		/*int*/ BN_add     (res, res, b);
	}
	BN_free(b);
	BN_free(a);
	return res;
}

version(PATCH_OPENSSL_BINDING_BN_ULONG) {
/**
I2OSP converts a nonnegative integer to an octet string of a specified length.
   Input:

      x        nonnegative integer to be converted

      xLen     intended length of the resulting octet string

   Output:

         X corresponding octet string of length xLen

This is usually done by acos for RSA operations
The interpretation of I2OSP's output is that of big-endian
acos operates the same, writes an octet string `OctetString` where OctetString[0] is the most significant byte
*/
uba /* <-OctetStringBigEndian*/ I2OSP(BIGNUM* x, int xLen /* intended length of the resulting octet string */)
in { assert(!BN_is_negative(x)); }
body {
	uba res; // = new ubyte[0];
	if (BN_num_bytes(x) > xLen)
		return res; //, output "integer too large" and stop.
//assert(4*x.top==BN_num_bytes(x));
	foreach (i_chunk; 0..x.top)
		res ~= integral2ub!(BN_ULONG.sizeof)(x.d[i_chunk]);

	return res;
}
} // version(PATCH_OPENSSL_BINDING_BN_ULONG)

unittest {
	import std.stdio;
	ubyte[4] zeros = [0x00, 0x00, 0x00, 0x00];
	ubyte[4] os    = [0x0A, 0x0B, 0xC0, 0xD0];
	BIGNUM* res = OS2IP(os);
//	BN_ULONG word = BN_get_word(res);   // ATTENTION: the openssl D binding currently is wrong here, defining BN_ULONG as uint on 64 bit systems as well (whereas in the 64 bit binary it's treated as ulong)!
	assert(BN_get_word(res)==0x0A0BC0D0); // thus unpatched, don't use this externally for more than ubyte[4], and use it for version(LittleEndian) only
	writeln("PASSED: OS2IP");

version(PATCH_OPENSSL_BINDING_BN_ULONG) {
	uba os2 = I2OSP(res, cast(int)BN_ULONG.sizeof);
	BN_free(res);
version(X86)
	assert(equal(os2, os[]));
else // X86_64 or more general any (64 bit processor) system where openssl defines BIGNUM's storage array underlying type (ulong) as having BN_BITS2 = 64
	assert(equal(os2, (zeros~os)[]));
	writeln("PASSED: I2OSP");
	import deimos.openssl.bio : BIO_snprintf;
	import deimos.openssl.bn;
//import std.conv : to;
//int BIO_snprintf(char* buf, size_t n, const(char)* format, ...);
	ulong num = 285212672; //FYI: fits in 29 bits
	int normalInt = 5;
	char[120] buf;
	BIO_snprintf(buf.ptr, buf.length, "My number is %i bytes wide and its value is %lu. A normal number is %i.", num.sizeof, num, normalInt);
//	printf("My number is %i bytes wide and its value is %ul. A normal number is %i.\n", sizeof(num.sizeof), num, normalInt);
//buf[strlen(buf.ptr)] = '\0';
	writeln("BIO_snprintf buf first:  ", buf.ptr.fromStringz);
	buf = buf.init;
	num = 0xFFEEDDCCBBAA9988;
	BIO_snprintf(buf.ptr, buf.length, BN_DEC_FMT1, num);
//buf[strlen(buf.ptr)] = '\0';
	writeln("BIO_snprintf buf second: ", buf.ptr.fromStringz);

	buf = buf.init;
	BIO_snprintf(buf.ptr, buf.length, BN_DEC_FMT2, num);
//buf[strlen(buf.ptr)] = '\0';
	writeln("BIO_snprintf buf third:  ", buf.ptr.fromStringz);
	stdout.flush();
}
}

immutable sc_asn1_entry[4]  c_asn1_sm_response = [
	immutable sc_asn1_entry("statusWord",    SC_ASN1_OCTET_STRING,                       SC_ASN1_CTX | 0x19, /*0x0000_0000*/  SC_ASN1_UNI,      null, null), // 99
	immutable sc_asn1_entry("mac",           SC_ASN1_OCTET_STRING,                       SC_ASN1_CTX | 0x0E, /*0x0000_0000*/  SC_ASN1_UNI,      null, null), // 8E
	immutable sc_asn1_entry("encryptedData", SC_ASN1_OCTET_STRING/*4*/, /*0x2000_0000*/  SC_ASN1_CTX | 0x07, /*0x0000_0002*/  SC_ASN1_OPTIONAL, null, null), // 87
	immutable sc_asn1_entry()
];

const(sc_asn1_entry)[4]  c_asn1_acos5_64_sm_data_object = [
	sc_asn1_entry( "encryptedData", SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 7,   SC_ASN1_OPTIONAL),
	sc_asn1_entry( "commandStatus", SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x19 ),
	sc_asn1_entry( "ticket",        SC_ASN1_OCTET_STRING,	SC_ASN1_CTX | 0x0E ),
	sc_asn1_entry()
];

void sm_incr_ssc(ref ub8 ssc) {
	if(ssc[7] == 0xFF && ssc[6] == 0xFF) {
		ssc[6] = 0x00;
		ssc[7] = 0x00;
		return;
	}
	if(ssc[7] == 0xFF) {
		ssc[6]++;
		ssc[7] = 0x00;
	}
	else
		ssc[7]++;
}

int changedExport_sc_sm_parse_answer(sc_card* card, ubyte* resp_data, size_t resp_len, sm_card_response* out_) {
	sc_asn1_entry[4]                asn1_sm_response = [sc_asn1_entry(), sc_asn1_entry(), sc_asn1_entry(), sc_asn1_entry()]; //GDC-issue with init
	ubyte[2]                        status;// = {0, 0};
	size_t                          status_len = status.length;
	ubyte[8]                        mac;
	size_t                          mac_len = mac.length;
	ubyte[SC_MAX_APDU_BUFFER_SIZE]  data;
	size_t                          data_len = data.length;
	int                             rv;

	if (!resp_data || !resp_len || !out_)
		return SC_ERROR_INVALID_ARGUMENTS;

	sc_copy_asn1_entry(c_asn1_sm_response.ptr, asn1_sm_response.ptr); //asn1_sm_response[0..4] = c_asn1_sm_response[0..4];

	sc_format_asn1_entry(asn1_sm_response.ptr + 0, status.ptr, &status_len, 0);
	sc_format_asn1_entry(asn1_sm_response.ptr + 1, mac.ptr,    &mac_len,    0);
	sc_format_asn1_entry(asn1_sm_response.ptr + 2, data.ptr,   &data_len,   0);

	rv = sc_asn1_decode(card.ctx, asn1_sm_response.ptr, resp_data, resp_len, null, null);

	if (rv)
		return rv;

	if (asn1_sm_response[0].flags & SC_ASN1_PRESENT)   {
		if (!status[0])
			return SC_ERROR_INVALID_DATA;
		out_.sw1 = status[0];
		out_.sw2 = status[1];
	}
	if (asn1_sm_response[1].flags & SC_ASN1_PRESENT)   {
		out_.mac[0..mac_len] = mac[0..mac_len];
		out_.mac_len         = mac_len;
	}
	if (asn1_sm_response[2].flags & SC_ASN1_PRESENT)   {
		if (data_len > out_.data.length)
			return SC_ERROR_BUFFER_TOO_SMALL;
		out_.data[0..data_len] = data[0..data_len];
		out_.data_len          = data_len;
	}

	return SC_SUCCESS;
}


/**  parse answer of SM protected APDU returned by APDU or by 'GET RESPONSE'
 *  @param  card 'sc_card' smartcard object
 *  @param  resp_data 'raw data returned by SM protected APDU
 *  @param  resp_len 'length of raw data returned by SM protected APDU
 *  @param  ref_rv 'status word returned by APDU or 'GET RESPONSE' (can be different from status word encoded into SM response date)
 *  @param  apdu 'sc_apdu' object to update
 *  @return SC_SUCCESS on success and an error code otherwise
 */
int changedExport_sc_sm_update_apdu_response(sc_card* card, ubyte* resp_data, size_t resp_len, int ref_rv, sc_apdu* apdu, sm_card_response* sm_response=null)
{
	sm_card_response sm_resp;
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(`"changedExport_sc_sm_update_apdu_response"`, `"called"`));
	mixin log_scope_exit!("changedExport_sc_sm_update_apdu_response");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if (!apdu)
		return rv=SC_ERROR_INVALID_ARGUMENTS;
	else if (!resp_data || !resp_len)
		return rv=SC_SUCCESS;

//	memset(&sm_resp, 0, sm_resp.sizeof);
	if ((rv=changedExport_sc_sm_parse_answer(card, resp_data, resp_len, &sm_resp)) < 0)
		return rv;

	if (sm_resp.mac_len)   {
		if (sm_resp.mac_len > apdu.mac.length)
			return rv=SC_ERROR_INVALID_DATA;
		memcpy(apdu.mac.ptr, sm_resp.mac.ptr, sm_resp.mac_len);
		apdu.mac_len = sm_resp.mac_len;
	}

	apdu.sw1 = sm_resp.sw1;
	apdu.sw2 = sm_resp.sw2;

	if (sm_response)
		*sm_response = sm_resp;

	return rv=SC_SUCCESS;
}


int sm_acos5_64_decode_card_data(sc_context* ctx, sm_info* info, sc_remote_data *rdata, ubyte* out_, size_t out_len) {
	sm_cwa_session*   session_data = &info.session.cwa;
	sc_asn1_entry[4]  asn1_acos5_64_sm_data_object = [sc_asn1_entry(), sc_asn1_entry(), sc_asn1_entry(), sc_asn1_entry()]; //GDC-issue with init
	sc_remote_apdu*   rapdu;// = null;
	int               rv, offs;// = 0;

//	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(q{"sm_acos5_64_decode_card_data"}, q{"called"}));
	mixin log_scope_exit!("sm_acos5_64_decode_card_data");
	scope(exit)
		log_scope_exit_do(__LINE__);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
		"decode answer() rdata length %i, out_ length %i", rdata.length, out_len);
	for (rapdu = rdata.data; rapdu; rapdu = rapdu.next)   {
		ubyte[2*SC_MAX_APDU_BUFFER_SIZE] decrypted;
		size_t decrypted_len = decrypted.length;
		ubyte[SC_MAX_APDU_BUFFER_SIZE] resp_data;
		size_t resp_len = resp_data.length;
		ubyte[2] status;// = {0, 0};
		size_t status_len = status.length;
		ub8 ticket;
		size_t ticket_len = ticket.length;

		with (rapdu.apdu) sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
			"decode response(%i) %s", resplen, sc_dump_hex(resp, resplen));

		sc_copy_asn1_entry(c_asn1_acos5_64_sm_data_object.ptr, asn1_acos5_64_sm_data_object.ptr);
		sc_format_asn1_entry(asn1_acos5_64_sm_data_object.ptr + 0, resp_data.ptr, &resp_len,   0);
		sc_format_asn1_entry(asn1_acos5_64_sm_data_object.ptr + 1, status.ptr,    &status_len, 0);
		sc_format_asn1_entry(asn1_acos5_64_sm_data_object.ptr + 2, ticket.ptr,    &ticket_len, 0);

		if ((rv=sc_asn1_decode(ctx, asn1_acos5_64_sm_data_object.ptr, rapdu.apdu.resp, rapdu.apdu.resplen, null, null)) < 0) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data", "decode answer(s): ASN1 decode error");
			return rv;
		}

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
			"decode response() SW:%02X%02X, MAC:%s", status[0], status[1], sc_dump_hex(ticket.ptr, ticket_len));
		if (status[0] != 0x90 || status[1] != 0x00)
			continue;

		if (asn1_acos5_64_sm_data_object[0].flags & SC_ASN1_PRESENT)   {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data", "decode answer() object present");
			if (resp_data[0] != 0x01) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
					"decode answer(s): invalid encrypted data format");
				return rv=SC_ERROR_INVALID_DATA;
			}

			if ((decrypted_len=decrypt_algo(resp_data[1..$], get_cwa_session_enc(*session_data).ptr, session_data.ssc.ptr, decrypted.ptr, cipher_TDES[CBC], false))%8 != 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
					"decode answer(s): cannot decrypt card answer data");
				return rv=SC_ERROR_DECRYPT_FAILED;
			}
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
				"decrypted data(%i) %s", decrypted_len, sc_dump_hex(decrypted.ptr, decrypted_len));
			while(*(decrypted.ptr + decrypted_len - 1) == 0x00)
				decrypted_len--;
			if   (*(decrypted.ptr + decrypted_len - 1) != 0x80) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
					"decode answer(s): invalid card data padding ");
				return rv=SC_ERROR_INVALID_DATA;
			}
			decrypted_len--;

			if (out_ && out_len)   {
				if (out_len < offs + decrypted_len) {
					sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
						"decode answer(s): insufficient output buffer size");
					return rv=SC_ERROR_BUFFER_TOO_SMALL;
				}

				memcpy(out_ + offs, decrypted.ptr, decrypted_len);

				offs += decrypted_len;
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_decode_card_data",
					"decode card answer(s): out_len/offs %i/%i", out_len, offs);
			}

//			free(decrypted);
		}
	} // for (rapdu = rdata.data; rapdu; rapdu = rapdu.next)

	return rv=offs;
}


private int sm_acos5_64_transmit_apdus(sc_card* card, sc_remote_data* rdata, ubyte* out_, size_t* out_len /*, size_t* out_cnt=null*/) {
	sc_context*     ctx   = card.ctx;
	sc_remote_apdu* rapdu = rdata.data;
	int             rv    = SC_SUCCESS, offs;// = 0;
	mixin (log!(q{"sm_acos5_64_transmit_apdus"}, q{"called"}));
	mixin transmit_rapdu_strerror!("sm_acos5_64_transmit_apdus");
	mixin log_scope_exit!("sm_acos5_64_transmit_apdus");
	scope(exit)
		log_scope_exit_do(__LINE__);

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_transmit_apdus",
		"rdata-length %i", rdata.length);

	while (rapdu)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_transmit_apdus",
			"r-APDU flags 0x%X", rapdu.apdu.flags);
		if ((rv=transmit_rapdu_strerror_do(__LINE__)) < 0) return rv;
		rv = sc_check_sw(card, rapdu.apdu.sw1, rapdu.apdu.sw2);
		if (rv < 0 && !(rapdu.flags & SC_REMOTE_APDU_FLAG_NOT_FATAL)) {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_transmit_apdus",
				"fatal error");
			return rv;
		}

		if (out_ && out_len && (rapdu.flags & SC_REMOTE_APDU_FLAG_RETURN_ANSWER))   {
			size_t len = rapdu.apdu.resplen > (*out_len - offs) ? (*out_len - offs) : rapdu.apdu.resplen;

			memcpy(out_ + offs, rapdu.apdu.resp, len);
			offs += len;
			/* TODO: decode and gather data answers */
		}

		rapdu = rapdu.next;
/*		if (out_cnt) ++*out_cnt; */
	}

	if (out_len)
		*out_len = offs;

	return rv;
}


private int sm_acos5_64_initialize(sc_card* card, uint se_num, uint cmd) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(`"sm_acos5_64_initialize"`, `"called"`));
	mixin log_scope_exit!("sm_acos5_64_initialize");
	scope(exit)
		log_scope_exit_do(__LINE__);

version(ENABLE_SM) {
	sm_info*         sm_info = &card.sm_ctx.info;
	sm_cwa_session*  cwa_session = &sm_info.session.cwa;
//	sc_remote_data   rdata;
	sc_remote_data   remote_data;
	sc_remote_data*  rdata = &remote_data;

////	strlcpy(sm_info.config_section, card.sm_ctx.config_section, sizeof(sm_info.config_section));
	sm_info.cmd       = cmd;
	sm_info.serialnr  = card.serialnr;
	sm_info.card_type = card.type;
	sm_info.sm_type   = SM_TYPE_CWA14890;

	if ((rv=acos5_64_get_challenge(card, null /* .icc.rnd.ptr*/, SM_SMALL_CHALLENGE_LEN)) != SC_SUCCESS)  {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize", "GET CHALLENGE failed\n");
		return rv;
	}

	sc_remote_data_init(rdata);

////	rv = sm_save_sc_context(card, sm_info);
////	LOG_TEST_RET(ctx, rv, "iasecc_sm_initialize() cannot save current context");

	if (!card.sm_ctx.module_.ops.initialize) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize", "No SM module");
		return rv=SC_ERROR_SM_NOT_INITIALIZED;
	}
	if ((rv=initialize(ctx, &card.sm_ctx.info, rdata)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize", "SM: INITIALIZE failed");
		return rv;
	}


	if (rdata.length == 2)   {
		rdata.data.flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;
		rdata.data.apdu.flags &= ~SC_APDU_FLAGS_NO_GET_RESP;
	}
	else {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize", "TODO: SM init with more then two APDUs");
		return rv=SC_ERROR_NOT_SUPPORTED;
	}

	size_t host_challenge_encrypted_tdesecb_with_key_card_done_by_card_len = 8;
	ub8    host_challenge_encrypted_tdesecb_with_key_card_done_by_card;
	ub8    host_challenge_encrypted_tdesecb_with_key_card_done_by_host; // both this and previous to be compared later

	if ((rv=sm_acos5_64_transmit_apdus (card, rdata, host_challenge_encrypted_tdesecb_with_key_card_done_by_card.ptr,
																									&host_challenge_encrypted_tdesecb_with_key_card_done_by_card_len)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize",
			"external/internal authentication: transmit APDUs failed");
		return rv;
	}
	rdata.free(rdata);

	with (card.sm_ctx.info.session)
		if (encrypt_algo(cwa.ifd.rnd, get_cwa_keyset_enc(cwa).ptr, null, host_challenge_encrypted_tdesecb_with_key_card_done_by_host.ptr,
				cipher_TDES[ECB], false) != host_challenge_encrypted_tdesecb_with_key_card_done_by_host.length)
			return rv=SC_ERROR_KEYPAD_TIMEOUT;

	if (!equal(host_challenge_encrypted_tdesecb_with_key_card_done_by_card[],
						 host_challenge_encrypted_tdesecb_with_key_card_done_by_host[])) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize",
		"        ### Card/Token and Host sym. keys configured are NOT suitable for Secure Messaging. The Mutual Authentication procedure failed ! ###");
		return rv=SC_ERROR_INTERNAL;
	}

		/* session keys generation */
		with (card.sm_ctx.info.session) {
//			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize",
//				"cwa.icc.rnd: %s", sc_dump_hex(cwa.icc.rnd.ptr, cwa.icc.rnd.length));
//			sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize",
//				"cwa.ifd.rnd: %s", sc_dump_hex(cwa.ifd.rnd.ptr, cwa.ifd.rnd.length));
version(SESSIONKEYSIZE24)
			ub24  deriv_data = cwa.icc.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[0..4] ~ cwa.ifd.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[4..8];
else
			ub16  deriv_data = cwa.icc.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[0..4] ~ cwa.ifd.rnd[4..8];

			ub24  enc_buf, mac_buf;
//		writefln("deriv_data_plain:     0x [ %(%x %) ]", deriv_data);
			if ((rv=encrypt_algo(deriv_data, get_cwa_keyset_enc(cwa).ptr, null/*iv*/, enc_buf.ptr, cipher_TDES[ECB], false)) != enc_buf.length)
				return rv=SC_ERROR_KEYPAD_TIMEOUT;
			if ((rv=encrypt_algo(deriv_data, get_cwa_keyset_mac(cwa).ptr, null/*iv*/, mac_buf.ptr, cipher_TDES[ECB], false)) != mac_buf.length)
				return rv=SC_ERROR_KEYPAD_TIMEOUT;
			set_cwa_session_enc(cwa, enc_buf);
			set_cwa_session_mac(cwa, mac_buf);
		}

	return rv=SC_SUCCESS;
}
else {
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_initialize", "built without support of Secure-Messaging");
	return rv=SC_ERROR_NOT_SUPPORTED;
}
}

private extern(C) int sm_acos5_64_card_open(sc_card* card) {
/* used only once after init to test SM; will finally switch to mode acl */
	sc_context*      ctx = card.ctx;
	sc_remote_apdu*  rapdu;
	sc_remote_data   remote_data;
	sc_remote_data*  rdata = &remote_data;
	int rv = SC_SUCCESS;
	mixin (log!(`"sm_acos5_64_card_open"`, `"called"`));
	mixin alloc_rdata_rapdu!("sm_acos5_64_card_open");
	mixin log_scope_exit!("sm_acos5_64_card_open");
	scope(exit)
		log_scope_exit_do(__LINE__);

/**********************/
version(TRY_SM) {
	rv = SC_ERROR_UNKNOWN;
	version(ENABLE_TOSTRING) {
		writer.put("int sm_acos5_64_card_open() before setting some data  with argument card.sm_ctx.info:\n");
		writer.formattedWrite("%s", card.sm_ctx.info);
	}

//immutable(sc_path)  test_EF = { [0x3F, 0x00, 0x41, 0x00, 0x39, 0x01], 6,  0, -1, SC_PATH_TYPE_PATH }; // test file for erase  (binary) some bytes with SM_CCT; SC = 0x45
	immutable(sc_path)  test_EF = { [0x3F, 0x00, 0x41, 0x00, 0x39, 0x02], 6,  0, -1, SC_PATH_TYPE_PATH }; // test file for update (binary) some bytes with SM_CCT_AND_CT_sym; SC = 0x46
	if ((rv=acos5_64_select_file_by_path(card, &test_EF,  null)) != SC_SUCCESS)
		return rv=SC_ERROR_KEYPAD_CANCELLED;

	card.sm_ctx.info.serialnr = card.serialnr;

	if ((rv=acos5_64_get_challenge(card, null /* .icc.rnd.ptr*/, SM_SMALL_CHALLENGE_LEN)) != SC_SUCCESS)  {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
			"initialize: get_challenge failed\n");
		return rv;
	}

	sc_remote_data_init(rdata);

	if (!card.sm_ctx.module_.ops.initialize) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "No SM module");
		return rv=SC_ERROR_SM_NOT_INITIALIZED;
	}
	if ((rv=initialize(ctx, &card.sm_ctx.info, rdata)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "SM: INITIALIZE failed");
		return rv;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
		"external_authentication(): rdata length %i\n", rdata.length);

	size_t host_challenge_encrypted_tdesecb_with_key_card_done_by_card_len = 8;
	ub8    host_challenge_encrypted_tdesecb_with_key_card_done_by_card;
	ub8    host_challenge_encrypted_tdesecb_with_key_card_done_by_host; // both this and previous to be compared later

	if ((rv=sm_acos5_64_transmit_apdus (card, rdata, host_challenge_encrypted_tdesecb_with_key_card_done_by_card.ptr,
																									&host_challenge_encrypted_tdesecb_with_key_card_done_by_card_len)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
			"external_authentication(): execute failed");
		return rv;
	}
	rdata.free(rdata);

	with (card.sm_ctx.info.session)
		if (encrypt_algo(cwa.ifd.rnd, get_cwa_keyset_enc(cwa).ptr, null, host_challenge_encrypted_tdesecb_with_key_card_done_by_host.ptr,
				cipher_TDES[ECB], false) != host_challenge_encrypted_tdesecb_with_key_card_done_by_host.length)
			return rv=SC_ERROR_KEYPAD_TIMEOUT;

	if (!equal(host_challenge_encrypted_tdesecb_with_key_card_done_by_card[],
						 host_challenge_encrypted_tdesecb_with_key_card_done_by_host[])) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
		"        ### Card/Token and Host sym. keys configured are NOT suitable for Secure Messaging. The Mutual Authentication procedure failed ! ###");
		return rv=SC_ERROR_INTERNAL;
	}
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
		"        ### Card/Token and Host sym. keys configured are     suitable for Secure Messaging. The Mutual Authentication procedure succeeded ! ###");

version(TRY_SM_MORE) {
	/* session keys generation */
	with (card.sm_ctx.info.session) {
version(SESSIONKEYSIZE24)
			ub24  deriv_data = cwa.icc.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[0..4] ~ cwa.ifd.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[4..8];
else
			ub16  deriv_data = cwa.icc.rnd[4..8] ~ cwa.ifd.rnd[0..4] ~ cwa.icc.rnd[0..4] ~ cwa.ifd.rnd[4..8];

			ub24  enc_buf, mac_buf;
//		writefln("deriv_data_plain:     0x [ %(%x %) ]", deriv_data);
			if ((rv=encrypt_algo(deriv_data, get_cwa_keyset_enc(cwa).ptr, null/*iv*/, enc_buf.ptr, cipher_TDES[ECB], false)) != enc_buf.length)
				return rv=SC_ERROR_KEYPAD_TIMEOUT;
			if ((rv=encrypt_algo(deriv_data, get_cwa_keyset_mac(cwa).ptr, null/*iv*/, mac_buf.ptr, cipher_TDES[ECB], false)) != mac_buf.length)
				return rv=SC_ERROR_KEYPAD_TIMEOUT;
			set_cwa_session_enc(cwa, enc_buf);
			set_cwa_session_mac(cwa, mac_buf);
	}
//////////////
		/* Testing usability of 	card.sm_ctx.info.session.cwa.session_mac in an SM-Authenticity operation (erase some test file's contents (binary 3901, selected previously)
			 multiple calls to MSE  Set Security Environment accumulate the CRTs in system memory until they get erased by a select different DF/MF?
			 alternative: use MSE Restore of record #5, which exists, but currently requires Pin-Authentication on my token; mimic this now: */
	sc_remote_data_init(rdata);
	if ((rv=alloc_rdata_rapdu_do(__LINE__))<0) return rv;
//bytes2apdu(card.ctx, representation(x"00 22 F3 05"), rapdu.apdu);
	bytes2apdu(card.ctx, representation(x"00 22 F3 06"), rapdu.apdu);
	mixin (log!(`"sm_acos5_64_card_open"`, `"ssc: %s"`, "sc_dump_hex(card.sm_ctx.info.session.cwa.ssc.ptr, 8)"));
	TSMarguments smArguments;
	with (card.sm_ctx.info.session)
//	smArguments = TSMarguments(SC_APDU_CASE_3_SHORT, SM_CCT,            [0x00, 0x0E, 0x00, 0x00], get_cwa_session_enc(cwa).ptr, get_cwa_session_mac(cwa).ptr, cwa.ssc, 2, [0,5]);
		smArguments = TSMarguments(SC_APDU_CASE_3_SHORT, SM_CCT_AND_CT_sym, [0x00, 0xD6, 0x00, 0x00], get_cwa_session_enc(cwa).ptr,
			get_cwa_session_mac(cwa).ptr, cwa.ssc, 16, representation(x"0102030405060708090A0B0C0D0E0F10").dup);

//	smArguments = TSMarguments(SC_APDU_CASE_1, SM_CCT, [0x00, 0x44, 0x00, 0x00], get_cwa_session_mac(cwa).ptr, cwa.ssc, 0, null);
//	mixin (log!(`"sm_acos5_64_card_open"`, `"smArg.ssc_iv: %s"`, "sc_dump_hex(smArguments.ssc_iv.ptr, 8)"));

	if ((rv=alloc_rdata_rapdu_do(__LINE__))<0) return rv;
	bytes2apdu(card.ctx, construct_SMcommand(smArguments[]) ~ ubyte(10)/*le*/, rapdu.apdu);
	mixin (log!(`"sm_acos5_64_card_open"`, `"smArg.ssc_iv: %s"`, "sc_dump_hex(smArguments.ssc_iv.ptr, 8)"));
	rapdu.flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;
	rapdu.apdu.resp    = rapdu.rbuf.ptr;
	rapdu.apdu.resplen = rapdu.rbuf.length;

	ub16    SM_response;
	size_t  SM_response_len;
	if ((rv=sm_acos5_64_transmit_apdus (card, rdata, SM_response.ptr, &SM_response_len)) < 0) {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "sm_acos5_64_transmit_apdus failed");
		return rv;
	}
	rdata.free(rdata);

	/*      changedExport_sc_sm_update_apdu_response updates:  mac, maclen, sw1 and sw2 but no more */
	if ((rv=changedExport_sc_sm_update_apdu_response(card, rapdu.apdu.resp, rapdu.apdu.resplen, 0, &rapdu.apdu))<0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "empty apdu.resp or sc_sm_parse_answer failed");
		return rv; // the response SW1SW2 got unwrapped and is now ready to be checked
	}
//	writefln("rapdu.apdu.mac: 0x [ %(%x %) ]", rapdu.apdu.mac[0..rapdu.apdu.mac_len]);
//	writefln("rapdu.apdu.sw1: 0x%02X", rapdu.apdu.sw1);
//	writefln("rapdu.apdu.sw2: 0x%02X", rapdu.apdu.sw2);
	if ((rv=sc_check_sw(card, rapdu.apdu.sw1, rapdu.apdu.sw2)) < 0) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "The SM command failed");
		return rv;
	}

	if ((rv=check_SMresponse(&rapdu.apdu, null, smArguments[0..$-2])) != SC_SUCCESS) {
		sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open", "    ### check_SMresponse failed! ###");
		return rv;
	}
//	mixin (log!(`"sm_acos5_64_card_open"`, `"smArg.ssc_iv: %s"`, "sc_dump_hex(smArguments.ssc_iv.ptr, 8)"));
	sc_do_log(card.ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_card_open",
		"        ##### SM Response Successfully Verified. Operation was performed as requested #####\n");
	card.sm_ctx.info.session.cwa.ssc = smArguments.ssc_iv;
	mixin (log!(`"sm_acos5_64_card_open"`, `"ssc: %s"`, "sc_dump_hex(card.sm_ctx.info.session.cwa.ssc.ptr, 8)"));
} // version(TRY_SM_MORE)

	version(ENABLE_TOSTRING) {
		writer.put("int sm_acos5_64_card_open after setting some data  with argument card.sm_ctx.info:\n");
		writer.formattedWrite("%s", card.sm_ctx.info);
	}
} // version(TRY_SM)
/**********************/

	with (card.sm_ctx) {
		sm_mode           = SM_MODE_ACL;
		ops.open          = null;
		ops.close         = null;
		ops.get_sm_apdu   = null;
		ops.free_sm_apdu  = null;
		ops.read_binary   = null;
		ops.update_binary = null;
	}
	return rv=SC_SUCCESS;
}


private extern(C) int sm_acos5_64_card_close(sc_card* card) {
	sc_context* ctx = card.ctx;
	int rv = SC_SUCCESS;
	mixin (log!(`"sm_acos5_64_card_close"`, `"called"`));
	mixin log_scope_exit!("sm_acos5_64_card_close");
	scope(exit)
		log_scope_exit_do(__LINE__);
	return rv;
}

private extern(C) int sm_acos5_64_card_get_apdu (sc_card* card, sc_apdu* apdu, sc_apdu** sm_apdu) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_SM_NOT_APPLIED; // this is no error !
	mixin (log!(`"sm_acos5_64_card_get_apdu"`, `"called"`));
	mixin log_scope_exit!("sm_acos5_64_card_get_apdu");
	scope(exit)
		log_scope_exit_do(__LINE__);
	return rv;
}

private extern(C) int sm_acos5_64_card_free_apdu(sc_card* card, sc_apdu* apdu, sc_apdu** sm_apdu) {
	return 0;
}



/**
 * missing export; code duplicate from smm-local.c
 */
private int sm_acos5_64_cwa_config_get_keyset(sc_context* ctx, sm_info* info)
{
	sm_cwa_session* cwa_session = &info.session.cwa;
	sm_cwa_keyset*  cwa_keyset  = &info.session.cwa.cwa_keyset;
	sc_crt*         cwa_crt_at  = &info.session.cwa.params.crt_at;
	scconf_block*   sm_conf_block;
	scconf_block**  blocks;
	const(char)*    value;
	char[128] name;
	ubyte[48] hex;
	size_t hex_len = hex.sizeof;
	int rv, ii, ref_ = cwa_crt_at.refs[0] & 0x1F /*IASECC_OBJECT_REF_MAX*/;

	mixin (log!(`"sm_acos5_64_cwa_config_get_keyset"`, `"called"`));
	mixin log_scope_exit!("sm_acos5_64_cwa_config_get_keyset");
	scope(exit)
		log_scope_exit_do(__LINE__);

	for (ii = 0; ctx.conf_blocks[ii]; ii++) {
		blocks = scconf_find_blocks(ctx.conf, ctx.conf_blocks[ii], "secure_messaging", info.config_section.ptr);
		if (blocks) {
			sm_conf_block = blocks[0];
			free(blocks);
		}

		if (sm_conf_block)
			break;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
		"CRT_AT(algo: 0x%02X, ref:0x%02X)", cwa_crt_at.algo, cwa_crt_at.refs[0]);
	/* Keyset ENC */
	if (info.current_aid.len && (cwa_crt_at.refs[0] & 0x80 /*IASECC_OBJECT_REF_LOCAL*/))
		snprintf(name.ptr, name.sizeof, "keyset_%s_%02i_enc",
				sc_dump_hex(info.current_aid.value.ptr, info.current_aid.len), ref_);
	else
		snprintf(name.ptr, name.sizeof, "keyset_%02i_enc", ref_);
	value = scconf_get_str(sm_conf_block, name.ptr, null);
	if (!value)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"No %s value in OpenSC config", name.ptr); // No keyset_00_enc value in OpenSC config
		return rv=SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
		"keyset::enc(%i) %s", strlen(value), value);

version(SESSIONKEYSIZE24)
	immutable sessionkeyLen = 24;
else
	immutable sessionkeyLen = 16;

/* only hex values, no ASCII
	if (strlen(value) == sessionkeyLen)
		memcpy(cwa_keyset.enc.ptr, value, sessionkeyLen);
	else*/ {
		hex_len = hex.sizeof;
		if ((rv=sc_hex_to_bin(value, hex.ptr, &hex_len))!=0)   {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
				"SM get %s: hex to bin failed for '%s'; error %i", name.ptr, value, rv);
			return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"ENC(%i) %s", hex_len, sc_dump_hex(hex.ptr, hex_len));
		if (hex_len != sessionkeyLen)
			return rv=SC_ERROR_INVALID_DATA;

		set_cwa_keyset_enc(info.session.cwa, hex);
	}

	/* Keyset MAC */
	if (info.current_aid.len && (cwa_crt_at.refs[0] & 0x80 /*IASECC_OBJECT_REF_LOCAL**/))
		snprintf(name.ptr, name.sizeof, "keyset_%s_%02i_mac",
				sc_dump_hex(info.current_aid.value.ptr, info.current_aid.len), ref_);
	else
		snprintf(name.ptr, name.sizeof, "keyset_%02i_mac", ref_);
	value = scconf_get_str(sm_conf_block, name.ptr, null);
	if (!value)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"No %s value in OpenSC config", name.ptr);
		return rv=SC_ERROR_SM_KEYSET_NOT_FOUND;
	}

	sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
		"keyset::mac(%i) %s", strlen(value), value);
/* only hex values, no ASCII
	if (strlen(value) == sessionkeyLen)
		memcpy(cwa_keyset.mac.ptr, value, sessionkeyLen);
	else*/ {
		hex_len = hex.sizeof;
		if ((rv=sc_hex_to_bin(value, hex.ptr, &hex_len))!=0)   {
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
				"SM get '%s': hex to bin failed for '%s'; error %i", name.ptr, value, rv);
			return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"MAC(%i) %s", hex_len, sc_dump_hex(hex.ptr, hex_len));
		if (hex_len != sessionkeyLen)
			return rv=SC_ERROR_INVALID_DATA;

		set_cwa_keyset_mac(info.session.cwa, hex);
	}

	cwa_keyset.sdo_reference = cwa_crt_at.refs[0];


	/* IFD parameters */
	value = scconf_get_str(sm_conf_block, "ifd_serial", null);
	if (!value)
		return rv=SC_ERROR_SM_IFD_DATA_MISSING;
	hex_len = hex.sizeof;
	if ((rv=sc_hex_to_bin(value, hex.ptr, &hex_len))!=0)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"SM get 'ifd_serial': hex to bin failed for '%s'; error %i", value, rv);
		return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	if (hex_len != cwa_session.ifd.sn.sizeof)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"SM get 'ifd_serial': invalid IFD serial length: %i", hex_len);
		return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
	}

	memcpy(cwa_session.ifd.sn.ptr, hex.ptr, hex_len);
	if (!equal(cwa_session.ifd.sn[], representation("acos5_64")) && !equal(cwa_session.ifd.sn[], cwa_session.icc.sn[]))
		return rv=SC_ERROR_NO_READERS_FOUND;
//// randombytes_buf(cwa_session.ifd.rnd.ptr, 8);
	if ((rv=RAND_bytes(cwa_session.ifd.rnd.ptr, cwa_session.ifd.rnd.length))==0)   {
		sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "sm_acos5_64_cwa_config_get_keyset",
			"Generate random error: %i", rv);
		return rv=SC_ERROR_SM_RAND_FAILED;
	}
	cwa_session.host_challenge = cwa_session.ifd.rnd;

	mixin (log!(`"sm_acos5_64_cwa_config_get_keyset"`, `"IFD.Serial: %s"`, "sc_dump_hex(cwa_session.ifd.sn.ptr, cwa_session.ifd.sn.sizeof)"));
	mixin (log!(`"sm_acos5_64_cwa_config_get_keyset"`, `"IFD.Rnd:    %s"`, "sc_dump_hex(cwa_session.ifd.rnd.ptr, cwa_session.ifd.rnd.sizeof)"));
	mixin (log!(`"sm_acos5_64_cwa_config_get_keyset"`, `"IFD.K:      %s"`, "sc_dump_hex(cwa_session.ifd.k.ptr, cwa_session.ifd.k.sizeof)"));

	return rv=SC_SUCCESS;
}


int sm_acos5_64_cwa_initialize(sc_context* ctx, sm_info* info, sc_remote_data* rdata) {
	int              rv;
	sc_remote_apdu*  rapdu;
	mixin (log!(`"sm_acos5_64_cwa_initialize"`, `"called"`));
	mixin alloc_rdata_rapdu!("sm_acos5_64_cwa_initialize");
	mixin log_scope_exit!("sm_acos5_64_cwa_initialize");
	scope(exit)
		log_scope_exit_do(__LINE__);

	mixin (log!(`"sm_acos5_64_cwa_initialize"`, `"serial           %s"`, "sc_dump_hex(info.serialnr.value.ptr, info.serialnr.len)"));
	mixin (log!(`"sm_acos5_64_cwa_initialize"`, `"card challenge   %s"`, "sc_dump_hex(info.session.cwa.icc.rnd.ptr, 8)"));
	mixin (log!(`"sm_acos5_64_cwa_initialize"`, `"current_df_path  %s"`, "sc_print_path(&info.current_path_df)"));
	mixin (log!(`"sm_acos5_64_cwa_initialize"`, `"CRT_AT reference 0x%02X"`, "info.session.cwa.params.crt_at.refs[0]"));

	if (!rdata || !rdata.alloc)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	ub8  card_challenge_encrypted_tdesecb_with_key_host_done_by_host;

	with (info.session)
		if ((rv=encrypt_algo(cwa.icc.rnd, get_cwa_keyset_mac(cwa).ptr, null, card_challenge_encrypted_tdesecb_with_key_host_done_by_host.ptr,
				cipher_TDES[ECB], false)) != card_challenge_encrypted_tdesecb_with_key_host_done_by_host.length)
			return rv=SC_ERROR_KEYPAD_TIMEOUT;

	if ((rv=alloc_rdata_rapdu_do(__LINE__))<0) return rv;
	// SC_APDU_CASE_3_SHORT,le=0               CLAINSP1 P2 lc    Ext. Auth.; if this succeeds, key_host/get_cwa_keyset_mac(card.sm_ctx.info.session.cwa) is authenticated from card's point of view
	bytes2apdu(ctx, representation(x"00 82 00 81 08") ~ card_challenge_encrypted_tdesecb_with_key_host_done_by_host, rapdu.apdu);

	if ((rv=alloc_rdata_rapdu_do(__LINE__))<0) return rv;
	// SC_APDU_CASE_4_SHORT,le=8               CLAINSP1 P2 lc   Int. Auth.; this doesn't authenticate key_card/get_cwa_keyset_enc(card.sm_ctx.info.session.cwa) seen from card's point of view
	bytes2apdu(ctx, representation(x"00 88 00 82 08") ~ info.session.cwa.ifd.rnd ~ ubyte(8)/*le*/, rapdu.apdu);
	rapdu.flags |= SC_REMOTE_APDU_FLAG_RETURN_ANSWER;
	rapdu.apdu.resp    = rapdu.rbuf.ptr;    // host_challenge_encrypted_tdesecb_with_key_card_done_by_card.ptr;
	rapdu.apdu.resplen = rapdu.rbuf.length; // host_challenge_encrypted_tdesecb_with_key_card_done_by_card.length;

	return rv=SC_SUCCESS;
}


/* API of the external SM module */

/**
 * Initialize
 *
 * Read keyset from the OpenSC configuration file,
 * get and return the APDU(s) to initialize SM session.
 */
export extern(C) int initialize (sc_context* ctx, sm_info* info, sc_remote_data* rdata)
{
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"initialize"`, `"called"`));
	mixin log_scope_exit!("initialize");
	scope(exit)
		log_scope_exit_do(__LINE__);

	if (!info)
		return rv=SC_ERROR_INVALID_ARGUMENTS;

	with (info.current_aid) sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "initialize",
		"Current AID: %s", sc_dump_hex(value.ptr, len));
	final switch (cast(SM_TYPE)info.sm_type) {
/*
		case SM_TYPE_GP_SCP01:
			rv = sm_gp_config_get_keyset(ctx, info);
			LOG_TEST_RET(ctx, rv, "SM gp configuration error");

			rv = sm_gp_initialize(ctx, info, rdata);
			LOG_TEST_RET(ctx, rv, "SM gp initializing error");
			break;
*/
		case SM_TYPE_CWA14890:
			if ((rv=sm_acos5_64_cwa_config_get_keyset(ctx, info)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "initialize",
				"SM acos5_64 configuration error: %i (%s)\n", rv, sc_strerror(rv));
				return rv;
			}

			if ((rv=sm_acos5_64_cwa_initialize(ctx, info, rdata)) < 0) {
				sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "initialize",
					"SM acos5_64 initializing error: %i (%s)\n", rv, sc_strerror(rv));
				return rv;
			}
			break;
		case SM_TYPE.SM_TYPE_GP_SCP01, SM_TYPE_DH_RSA:
			rv = SC_ERROR_NOT_SUPPORTED;
			sc_do_log(ctx, SC_LOG_DEBUG_NORMAL, __MODULE__, __LINE__, "initialize",
				"unsupported SM type: %i (%s)\n", rv, sc_strerror(rv));
			return rv;
	}

	return rv=SC_SUCCESS;
}


/**
 * Get APDU(s)
 *
 * Get securized APDU(s) corresponding
 * to the asked command.
 */
export extern(C) int /*sm_acos5_64_*/ get_apdus(sc_context* ctx, sm_info* info, ubyte* init_data, size_t init_len, sc_remote_data* rdata)
{
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"get_apdus"`, `"called"`));
	mixin log_scope_exit!("get_apdus");
	scope(exit)
		log_scope_exit_do(__LINE__);

	return rv;
}

/**
 * Finalize
 *
 * Decode card answer(s)
 */
export extern(C) int /*sm_acos5_64_*/ finalize(sc_context* ctx, sm_info* info, sc_remote_data* rdata, ubyte* out_, size_t out_len) {
	int rv = SC_ERROR_INTERNAL;
	mixin (log!(`"finalize"`, `"called"`));
	mixin log_scope_exit!("finalize");
	scope(exit)
		log_scope_exit_do(__LINE__);

	mixin (log!(`"finalize"`, `"SM finalize: out buffer(%u) %p"`, "out_len", "out_"));
	if (!info || !rdata)
		return rv=SC_SUCCESS;

	if (canFind([SC_CARD_TYPE_ACOS5_64_V2, SC_CARD_TYPE_ACOS5_64_V3], info.card_type))
		rv = sm_acos5_64_decode_card_data(ctx, info, rdata, out_, out_len);
	else {
		mixin (log!(`"finalize"`, `"SM finalize: cannot decode card response(s)"`));
		return rv=SC_ERROR_NOT_SUPPORTED;
	}

	return rv;
}

export extern(C) int /*sm_acos5_64_*/ module_init(sc_context* ctx, const(char)* data/*module_data*/) {
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"module_init"`, `"called"`));
	mixin log_scope_exit!("module_init");
	scope(exit)
		log_scope_exit_do(__LINE__);
	return rv=SC_SUCCESS;
}

export extern(C) int /*sm_acos5_64_*/ module_cleanup(sc_context* ctx) {
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"module_cleanup"`, `"called"`));
	mixin log_scope_exit!("module_cleanup");
	scope(exit) {
		log_scope_exit_do(__LINE__);
//	version(Windows) {} else { version(unittest) {} else rt_term(); }
	}
	return rv=SC_SUCCESS;
}


export extern(C) int test(sc_context* ctx, sm_info* info, char* out_) {
	int rv = SC_ERROR_NOT_SUPPORTED;
	mixin (log!(`"test"`, `"called"`));
	mixin log_scope_exit!("test");
	scope(exit)
		log_scope_exit_do(__LINE__);
	return rv=SC_SUCCESS;
}


private int is_string_valid_atr(const(char)* atr_str)
{ // copy of tools/is_string_valid_atr
	ubyte[SC_MAX_ATR_SIZE]  atr;
	size_t atr_len = atr.sizeof;

	if (sc_hex_to_bin(atr_str, atr.ptr, &atr_len))
		return 0;
	if (atr_len < 2)
		return 0;
	if (atr[0] != 0x3B && atr[0] != 0x3F)
		return 0;
	return 1;
}


/* All singing all dancing card connect routine */
private int util_connect_card(sc_context* ctx, sc_card** cardp, const(char)* reader_id, int do_wait, int verbose)
{ // copy of tools/util.c:util_connect_card
	import core.stdc.errno;
	import core.stdc.stdlib : strtol;
	sc_reader*  reader, found;
	sc_card*    card;
	int r;

	if (do_wait) {
		uint event;

		if (sc_ctx_get_reader_count(ctx) == 0) {
			/*fprintf(stderr.getFP(),*/ writeln("Waiting for a reader to be attached...");
			r = sc_wait_for_event(ctx, SC_EVENT_READER_ATTACHED, &found, &event, -1, null);
			if (r < 0) {
				fprintf(stderr.getFP(), "Error while waiting for a reader: %s\n", sc_strerror(r));
				return 3;
			}
			r = sc_ctx_detect_readers(ctx);
			if (r < 0) {
				fprintf(stderr.getFP(), "Error while refreshing readers: %s\n", sc_strerror(r));
				return 3;
			}
		}
		fprintf(stderr.getFP(), "Waiting for a card to be inserted...\n");
		r = sc_wait_for_event(ctx, SC_EVENT_CARD_INSERTED, &found, &event, -1, null);
		if (r < 0) {
			fprintf(stderr.getFP(), "Error while waiting for a card: %s\n", sc_strerror(r));
			return 3;
		}
		reader = found;
	}
	else if (sc_ctx_get_reader_count(ctx) == 0) {
		fprintf(stderr.getFP(), "No smart card readers found.\n");
		return 1;
	}
	else   {
		if (!reader_id) {
			uint i;
			/* Automatically try to skip to a reader with a card if reader not specified */
			for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
				reader = sc_ctx_get_reader(ctx, i);
				if (sc_detect_card_presence(reader) & SC_READER_CARD_PRESENT) {
					fprintf(stderr.getFP(), "Using reader with a card: %s\n", reader.name);
					goto autofound;
				}
			}
			/* If no reader had a card, default to the first reader */
			reader = sc_ctx_get_reader(ctx, 0);
		}
		else {
			/* If the reader identifier looks like an ATR, try to find the reader with that card */
			if (is_string_valid_atr(reader_id))   {
				ubyte[SC_MAX_ATR_SIZE * 3]  atr_buf;
				size_t atr_buf_len = atr_buf.sizeof;
				uint i;

				sc_hex_to_bin(reader_id, atr_buf.ptr, &atr_buf_len);
				/* Loop readers, looking for a card with ATR */
				for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
					sc_reader* rdr = sc_ctx_get_reader(ctx, i);

					if (!(sc_detect_card_presence(rdr) & SC_READER_CARD_PRESENT))
						continue;
					else if (rdr.atr.len != atr_buf_len)
						continue;
					else if (memcmp(rdr.atr.value.ptr, atr_buf.ptr, rdr.atr.len))
						continue;

					fprintf(stderr.getFP(), "Matched ATR in reader: %s\n", rdr.name);
					reader = rdr;
					goto autofound;
				}
			}
			else   {
				char* endptr = null;
				uint num;

				errno = 0;
				num = cast(uint)strtol(reader_id, null/*&endptr*/, 0);
				if (!errno && endptr && *endptr == '\0')
					reader = sc_ctx_get_reader(ctx, num);
				else
					reader = sc_ctx_get_reader_by_name(ctx, reader_id);
			}
		}
autofound:
		if (!reader) {
			fprintf(stderr.getFP(), "Reader \"%s\" not found (%i reader(s) detected)\n",
					reader_id, sc_ctx_get_reader_count(ctx));
			return 1;
		}

		if (sc_detect_card_presence(reader) <= 0) {
			fprintf(stderr.getFP(), "Card not present.\n");
			return 3;
		}
	}

	if (verbose)
		printf("Connecting to card in reader %s...\n", reader.name);
	r = sc_connect_card(reader, &card);
	if (r < 0) {
		fprintf(stderr.getFP(), "Failed to connect to card: %s\n", sc_strerror(r));
		return 1;
	}

	if (verbose)
		printf("Using card driver %s.\n", card.driver.name);

	r = sc_lock(card);
	if (r < 0) {
		fprintf(stderr.getFP(), "Failed to lock card: %s\n", sc_strerror(r));
		sc_disconnect_card(card);
		return 1;
	}

	*cardp = card;
	return 0;
}

/*
The following unittest (in parts) heavyly depends on interpreting /tmp/opensc-debug.log, thus debuging should be switched on; level=3, see also string debug_file = "/tmp/opensc-debug.log"
*/
version(ENABLED_DEBUG_FILE) { // this, or parts may depend on : debug_file = /tmp/opensc-debug.log; and a sufficient debug = 3; set, as well as dependancy deimos.pkcs11
unittest {
	import core.stdc.stdlib : exit, malloc, EXIT_FAILURE;
	import std.stdio;
	import std.algorithm.searching;
	import std.algorithm.comparison;
//import std.string;
	import pkcs11;

version(Posix) {
	import std.process,
				 std.conv;
//				 std.file;
	string debug_file = "/tmp/opensc-debug.log";
	{
		auto f = File(debug_file, "w"); // open for writing, i.e. Create an empty file for output operations. If a file with the same name already exists, its contents are discarded and the file is treated as a new empty file.
	}
	auto opensc_tool_i = executeShell("opensc-tool -i");
	if (opensc_tool_i.status) {
		writeln("FAILED: PKCS#11 functions: opensc_tool_i; the opensc tools (sudo apt-get install opensc) or the pkcs#11 module (sudo apt-get install opensc-pkcs11) seem to be missing");
		return;
	}
	else {
		writeln("opensc-tool -i   Prints information about OpenSC, such as the OpenSC version and parameters it was build with.");
		writeln("opensc-tool -i   Must show one of the two latest OpenSC versions, otherwise it fails prerequisites of dependancy package opensc and all bets are off (crash, undefined behaviour etc..)");
		writeln(opensc_tool_i.output);
		writeln("PASSED: PKCS#11 functions: opensc_tool_i");
	}
	auto grep_load_dynamic_driver_acos5_64 = executeShell(`grep -c "load_dynamic_driver: successfully loaded card driver 'acos5_64'"` ~ ' ' ~ debug_file);
	if (grep_load_dynamic_driver_acos5_64.status)
		writeln("FAILED: PKCS#11 functions: grep_load_dynamic_driver_acos5_64. There are many reasons why OpenSC might fail to load libacos5_64.so, miss-configured opensc.conf, missing or unknown location of libacos5_64.so being likely ones");
	else {
		assert(strip(grep_load_dynamic_driver_acos5_64.output).to!int==1);
		writeln("PASSED: PKCS#11 functions: grep_load_dynamic_driver_acos5_64");
	}
version(none) {
	{
		sc_context*         ctx;
		sc_context_param_t  ctx_param = { 0, "unittest" };
		if (sc_context_create(&ctx, &ctx_param))
			return;
version(OPENSC_VERSION_LATEST)
		ctx.flags |= SC_CTX_FLAG_ENABLE_DEFAULT_DRIVER;
//	if (verbose > 1) {
		ctx.debug_ = SC_LOG_DEBUG_NORMAL/*verbose*/;
		sc_ctx_log_to_file(ctx, toStringz(debug_file));
//	}

//		if (sc_set_card_driver(ctx, "acos5_64"))
//			return;


		acos5_64_se_info  se1;
		se1.reference     = 1;
		uba  indata = representation(x"A4 06 83 01 81 95 01 08").dup;
		assert(indata.length==acos5_64_crt_parse(ctx, indata, &se1));
		assert(se1.crts[0] == sc_crt(CRT_TAG.AT, 0x08, 0, [0x81U,0U,0U,0U,0U,0U,0U,0U]));
//	writeln("se1.crts[0]: ", se1.crts[0]);

		acos5_64_se_info  se2;
		se2.reference     = 2;
		se1.next = &se2;
		indata      = representation(x"B4 09 83 01 01 95 01 08 80 01 02   B8 09 83 01 01 95 01 08 80 01 02   A4 06 83 01 81 95 01 08").dup;
		assert(indata.length==acos5_64_crt_parse(ctx, indata, &se2));
		assert(se2.crts[0] == sc_crt(CRT_TAG.CCT,    0x08, 0x02, [0x01U,0U,0U,0U,0U,0U,0U,0U]));
		assert(se2.crts[1] == sc_crt(CRT_TAG.CT_sym, 0x08, 0x02, [0x01U,0U,0U,0U,0U,0U,0U,0U]));
		assert(se2.crts[2] == sc_crt(CRT_TAG.AT,     0x08, 0x00, [0x81U,0U,0U,0U,0U,0U,0U,0U]));
//	writeln("se2.crts[0..3]: ", se2.crts[0..3]);

		acos5_64_se_info  se3;
		se3.reference     = 3;
		se2.next = &se3;
		indata      = representation(x"A4 06 83 01 01 95 01 08").dup;
		assert(indata.length==acos5_64_crt_parse(ctx, indata, &se3));
		assert(se3.crts[0] == sc_crt(CRT_TAG.AT, 0x08, 0x00, [0x01U,0U,0U,0U,0U,0U,0U,0U]));
//	writeln("se3.crts[0]: ", se3.crts[0]);

		acos5_64_se_info  se4;
		se4.reference     = 4;
		se3.next = &se4;
		indata      = representation(x"A4 09 83 01 01 83 01 81 95 01 08").dup;
		assert(indata.length==acos5_64_crt_parse(ctx, indata, &se4));
		assert(se4.crts[0] == sc_crt(CRT_TAG.AT, 0x08, 0x00, [0x01U,0x81U,0U,0U,0U,0U,0U,0U]));
//	writeln("These are 'AND' conditions in  se4.crts[0]: ", se4.crts[0]);

		acos5_64_se_info  se5;
		se5.reference     = 5;
		se4.next = &se5;
		indata      = representation(x"B4 08 84 00 95 01 30 80 01 02   B8 08 84 00 95 01 30 80 01 02   A4 06 83 01 82 95 01 80").dup;
		assert(indata.length==acos5_64_crt_parse(ctx, indata, &se5));
		assert(se5.crts[0] == sc_crt(CRT_TAG.CCT,    0x30, 0x02, [0x84U,0U,0U,0U,0U,0U,0U,0U]));
		assert(se5.crts[1] == sc_crt(CRT_TAG.CT_sym, 0x30, 0x02, [0x84U,0U,0U,0U,0U,0U,0U,0U]));
		assert(se5.crts[2] == sc_crt(CRT_TAG.AT,     0x80, 0x00, [0x82U,0U,0U,0U,0U,0U,0U,0U]));
//	writeln("se5.crts[0..3]: ", se5.crts[0..3]);
		writeln("PASSED: acos5_64_crt_parse");
/+ +/
		sc_card* card;
		int err;

		err = util_connect_card(ctx, &card, null/*opt_reader*/, 0/*opt_wait*/, SC_LOG_DEBUG_NORMAL/*verbose*/); // does: sc_lock(card) including potentially card.sm_ctx.ops.open
		scope(exit) {
			if (card) {
				sc_unlock(card);
				sc_disconnect_card(card);
			}
			if (ctx)
				sc_release_context(ctx);
			{
				auto f = File(debug_file, "w"); // open for writing, i.e. Create an empty file for output operations. If a file with the same name already exists, its contents are discarded and the file is treated as a new empty file.
			}
		}
		if (err)
			return;
		if (!card)
			return;
	} // invoke scope(exit) to quit card and context
} // version(none)
} // version(Posix)

	void check_return_value(CK_RV rv, string message) {
		if (rv != CKR_OK) {
			writefln("Error at %s: %s", message, rv);
			stdout.flush();
		}
	}

	CK_SLOT_ID get_slot() {
		CK_RV           rv;
		CK_SLOT_ID[10]  slotIds;
		CK_ULONG        slotCount = slotIds.length;

		rv = C_GetSlotList(CK_TRUE, slotIds.ptr, &slotCount);
		check_return_value(rv, "get slot list");

		if (slotCount < 1) {
			stderr.writeln("STOPED: PKCS#11 functions: No slots with a present token found!");
			return cast(CK_ULONG)-1;//exit(EXIT_FAILURE);
		}

		CK_SLOT_ID  slotId = slotIds[0];
		writefln("slot count: %s", slotCount);
		return slotId;
	}

	extern(C) CK_RV notify_me(
		CK_SESSION_HANDLE hSession,     /* the session's handle */
		CK_NOTIFICATION   event,
		CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
	) nothrow @nogc @system {
		return CKR_OK;
	}

	CK_SESSION_HANDLE start_session(CK_SLOT_ID slotId, CK_FLAGS flags=CKF_SERIAL_SESSION) {
		CK_RV              rv;
		CK_SESSION_HANDLE  session;
		rv = C_OpenSession(slotId,
			flags,
			null,
			null,//&notify_me,
			&session);
		check_return_value(rv, "open session");
		return session;
	}
/////////////
	PKCS11.load("opensc-pkcs11.so");
	CK_RV rv;
	if ((rv=C_Initialize(NULL_PTR)) != CKR_OK) {
		writeln("Failed to initialze Cryptoki");
		return;
	}
	scope(exit)
		C_Finalize(NULL_PTR);

	CK_INFO info;
	rv = C_GetInfo(&info);
	check_return_value(rv, "get info");
	writeln("cryptokiVersion.major: ", info.cryptokiVersion.major);
	writeln("cryptokiVersion.minor: ", info.cryptokiVersion.minor);
	writeln("PASSED: PKCS#11 functions that don't require a present token");

version(all) {
	CK_SLOT_ID  slotID = get_slot(); // OpenSC does a lot for a present token now on C_GetSlotList
	if (slotID == cast(CK_ULONG)-1)
		return;
	writeln("slotID: ", slotID);

version(Posix) {
version(TRY_SM_MORE) {
	auto grep_try_sm_more = executeShell("grep -c '##### SM Response Successfully Verified. Operation was performed as requested #####'" ~ ' ' ~ debug_file);
	if (grep_try_sm_more.status != 0)
		writeln("FAILED: PKCS#11 functions: grep_try_sm_more");
	else {
		assert(strip(grep_try_sm_more.output).to!int>=1);
		writeln("PASSED: PKCS#11 functions: grep_try_sm_more");
	}
}
}

	CK_SLOT_INFO  slotInfo;
	rv = C_GetSlotInfo(slotID, &slotInfo);
	check_return_value(rv, "get slot info");
	ptrdiff_t pos = clamp(countUntil(slotInfo.slotDescription[], [ubyte(32),ubyte(32)]), 0,64);
	writeln ("slotDescription: ", (cast(char*)slotInfo.slotDescription.ptr)[0..pos]);
	pos = clamp(/*countUntil(slotInfo.manufacturerID[], [ubyte(32),ubyte(32)])*/32, 0,32);
	writeln ("manufacturerID:  ", (cast(char*)slotInfo.manufacturerID.ptr)[0..pos]);
	writeln ("flags:           ", slotInfo.flags);
	writefln("hardwareVersion: %s.%s", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
	writefln("firmwareVersion: %s.%s", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);

	CK_TOKEN_INFO tokenInfo;
	rv = C_GetTokenInfo(slotID, &tokenInfo);
	check_return_value(rv, "get token info");
	pos = clamp(/*countUntil(tokenInfo.label[], [ubyte(32),ubyte(32)])*/32, 0,32);
	writeln ("token.label: 	", (cast(char*)tokenInfo.label.ptr)[0..pos]);

	CK_FLAGS flags = CKF_DONT_BLOCK;
	CK_SLOT_ID  slotID_waiton;
	/* Don't Block and don't wait for a slot event */
	rv = C_WaitForSlotEvent(flags, &slotID_waiton, NULL_PTR);
	check_return_value(rv, "wait for slot event");
	writeln ("Didn't wait on slot ", slotID_waiton);

	CK_MECHANISM_TYPE[]  mechanismList;
	CK_ULONG             mechanismListCount;
	CK_MECHANISM_INFO    mechanismInfo;
	rv =   C_GetMechanismList(slotID, cast(CK_MECHANISM_TYPE_PTR)NULL_PTR, &mechanismListCount);

	if ((rv == CKR_OK) && (mechanismListCount > 0))  {
		//	check_return_value(rv, "get mechanism list count");
		mechanismList.length = mechanismListCount;
		rv = C_GetMechanismList(slotID, mechanismList.ptr, &mechanismListCount);
		if (rv == CKR_OK)
			foreach (i, mt; mechanismList) {
				mechanismInfo = CK_MECHANISM_INFO.init;
				/*rv =*/ C_GetMechanismInfo(slotID, mt, &mechanismInfo);
				// CKF_HW 	0x0001 	TRUE if the mechanism is performed by the device; FALSE if the mechanism is performed in software
				writefln("mechanismList[%s]: 0x%04X; mInfo: MinKeySize: %s, MaxKeySize: %s, flags: 0x%04X", i, mt, mechanismInfo.ulMinKeySize, mechanismInfo.ulMaxKeySize, mechanismInfo.flags); // CKM_*
			}
	}
	CK_SESSION_HANDLE  hSession = start_session(slotID, CKF_RW_SESSION | CKF_SERIAL_SESSION);
	CK_OBJECT_HANDLE   hPublicKey, hPrivateKey;
	CK_MECHANISM       mechanism = CK_MECHANISM(CKM_RSA_PKCS_KEY_PAIR_GEN);
	CK_BBOOL           yes = CK_TRUE;
	CK_BBOOL           no  = CK_FALSE;
	CK_ULONG           modulusBits = 3072; // 4096 doesn't work for ACOS-64 V3.00 so far ! For that, max. 3072!
	CK_BYTE[3]         publicExponent = [0x01, 0x00, 0x01];
	CK_BYTE[10]        subject = "privateKey".representation;
	CK_BYTE[1]         id = [ 0x04 ];


	CK_ATTRIBUTE[] publicKeyTemplate = [
		CK_ATTRIBUTE(CKA_MODULUS_BITS, &modulusBits, modulusBits.sizeof),
		CK_ATTRIBUTE(CKA_PUBLIC_EXPONENT, publicExponent.ptr, publicExponent.sizeof),

		CK_ATTRIBUTE(CKA_TOKEN,     &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_SENSITIVE, &no,  no.sizeof),
		CK_ATTRIBUTE(CKA_PRIVATE,   &no,  no.sizeof),

		CK_ATTRIBUTE(CKA_ENCRYPT,   &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_VERIFY,    &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_WRAP,      &no,  no.sizeof),
	];

	CK_ATTRIBUTE[] privateKeyTemplate = [
		CK_ATTRIBUTE(CKA_ID,        id.ptr,      id.sizeof),
		CK_ATTRIBUTE(CKA_SUBJECT,   subject.ptr, subject.sizeof),

		CK_ATTRIBUTE(CKA_TOKEN,     &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_SENSITIVE, &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_PRIVATE,   &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_NEVER_EXTRACTABLE, &yes, yes.sizeof),

		CK_ATTRIBUTE(CKA_DECRYPT,   &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_SIGN,      &yes, yes.sizeof),
		CK_ATTRIBUTE(CKA_UNWRAP,    &no,  no.sizeof),
	];
/+ + /
	rv = C_GenerateKeyPair(hSession, &mechanism,
		publicKeyTemplate.ptr, publicKeyTemplate.length,
		privateKeyTemplate.ptr, privateKeyTemplate.length, &hPublicKey, &hPrivateKey);

	if (rv != CKR_OK)
		writeln("C_GenerateKeyPair failed as expected");
/ + +/
	writeln("PASSED: PKCS#11 functions that do require a present token");
} // version(all)


/*
 * The final goal for testing coverage is, to have covergage information about functions too, that get called by opensc-pkcs11.so.
 * For this to work, the correct setup has to be ckecked.
 * In the meantime, manually call some functions:
*/
	assert(iEF_FDB_to_structure(Transparent_EF) == SC_FILE_EF.SC_FILE_EF_TRANSPARENT);
	assert(equal(sc_driver_version.fromStringz, sc_get_version.fromStringz));

	sc_module_init("acos5_64");
	sc_get_acos5_64_driver();
	sc_get_acos5_64_pkcs15init_ops();

	writeln("PASSED: Call some functions for coverage");

	stdout.flush();
} // unittest
} // version(ENABLED_DEBUG_FILE)

private int acos5_64_crt_parse(sc_card* card,   in ubyte[] data, acos5_64_se_info* se) {
	return acos5_64_crt_parse(card.ctx, data, se);
}

private int acos5_64_crt_parse(sc_context* ctx, in ubyte[] data, acos5_64_se_info* se)
{ // changed copy from libopensc/iasecc-sdo.c:iasecc_crt_parse; *data e.g.  A4 06 83 01 81 95 01 08
	// might be enhanced by checking with aa_* infos
	int          jj;
	int          accu_lenP2;
	int          rv;
	mixin (log!(`"acos5_64_crt_parse"`, `"(0x%X) called"`, "*data.ptr"));
	mixin log_scope_exit!("acos5_64_crt_parse");
	scope(exit)
		log_scope_exit_do(__LINE__);

	for (jj=0; jj<SC_MAX_CRTS_IN_SE; jj++) // with SC_MAX_CRTS_IN_SE==12 opensc allows less than ACOS (==14)
		if (!se.crts[jj].tag)  // find first free "slot" for storage
			break;

	mixin (log!(`"acos5_64_crt_parse"`, `"first free 'slot' for storage: %i"`, "jj"));
	do {
		if (jj==SC_MAX_CRTS_IN_SE) {
			mixin (log!(`"acos5_64_crt_parse"`, `"error: too much CRTs in SE"`));
			return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
		}

		sc_crt       crt = { *(data.ptr + accu_lenP2 + 0) /*tag*/};
		if (!canFind([EnumMembers!CRT_TAG], crt.tag) || CRT_TAG.NA==crt.tag)
			break;
		const lenP2  =       *(data.ptr + accu_lenP2 + 1) + 2;
		bool         block_SubDO_Tag_ID_Pin_Key_Local_Global;
		bool         HaveSome_SubDO_Tag_ID_Pin_Key_Local_Global;
		SubDO_Tag    tag;

		for (int offs = 2; offs < lenP2; offs += 2+SubDO_Tag_len(tag /* as processed in loop body*/)) {
//			mixin (log!(`"acos5_64_crt_parse"`, `"(0x%X) CRT %X -> %X"`, "*(data.ptr + accu_lenP2)", "*(data.ptr + accu_lenP2 + offs)", "*(data.ptr + accu_lenP2 + offs + 2)"));
			ubyte  utag = *(data.ptr + accu_lenP2 + offs);
			if (!canFind([EnumMembers!SubDO_Tag], utag))
				return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
			tag = cast(SubDO_Tag)utag;

			final switch (tag) {
				case UQB:
					crt.usage = *(data.ptr + accu_lenP2 + offs + 2);
					break;
				case ID_Pin_Key_Local_Global:
					if (block_SubDO_Tag_ID_Pin_Key_Local_Global)
						break;
					{
						int  ii;
						for (ii=0; ii<crt.refs.length && crt.refs[ii]; ii++) {} // search first crt.refs entry with no (==0) data.ptr + accu_lenP2
						if (ii == crt.refs.length)
							return rv=SC_ERROR_INVALID_DATA;
						HaveSome_SubDO_Tag_ID_Pin_Key_Local_Global = true;
						crt.refs[ii] = *(data.ptr + accu_lenP2 + offs + 2);
					}
					break;
				case Algorithm:
					crt.algo = *(data.ptr + accu_lenP2 + offs + 2);
					break;
				case SubDO_Tag.HP_Key_Session:
					if (*(data.ptr + accu_lenP2 + offs + 1)!=0)
						return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
					block_SubDO_Tag_ID_Pin_Key_Local_Global = true;
					if (HaveSome_SubDO_Tag_ID_Pin_Key_Local_Global)
						crt.refs = (uint[8]).init;
					crt.refs[0] = SubDO_Tag.HP_Key_Session;
					break;
				case Initial_Vector:
					return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
				case KeyFile_RSA:
					return rv=SC_ERROR_UNKNOWN_DATA_RECEIVED;
			} // final switch (tag)
		} // for
		se.crts[jj++] = crt;
		accu_lenP2   += lenP2;
		++se.crts_len;
	} while (accu_lenP2 < data.length);
	return rv=accu_lenP2;
}


ubyte TAG_FCP_len (ISO7816_TAG_FCP_  tag) { // for those with varying length and known max it returns the max. length, otherwise 0
	final switch (tag) {
		case ISO7816_TAG_FCP :             return 0;
		case ISO7816_TAG_FCP_SIZE,                    // not to be included for the max(MF/DF) fold; seed:-4
				 ISO7816_TAG_FCP_SIZE_FULL,               // not used by ACOS;                      fold.seed:-4
				 ISO7816_TAG_FCP_FID :         return 2;
		case ISO7816_TAG_FCP_TYPE :        return 6;  // 4 max, for ACOS it is 6
		case ISO7816_TAG_FCP_DF_NAME :     return 16; // max
		case ISO7816_TAG_FCP_PROP_INFO,               // unknown max; not used by ACOS;         fold.seed:-2
				 ISO7816_TAG_FCP_ACLS :        return 0;  // unknown max; not used by ACOS;         fold.seed:-2
		case ISO7816_TAG_FCP_LCS :         return 1;
	}
}

/*
	Example DF:
		6F 30
		83 02 41 00
		88 01 00
		8A 01 05
		82 02 38 00
		8D 02 41 03
		84 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30
		8C 08 7F FF FF 03 03 03 03 03
		AB 00

	Example EF:
		6F 1E
		83 02 41 03
		88 01 03
		8A 01 05
		82 06 1C 00 00 30 00 05
		8C 08 7F FF FF 03 03 01 03 01
		AB 00
*/

ubyte TAG_FCP_len (ISO7816_RFU_TAG_FCP_  tag) { // for those with varying length and known max it returns the max. length, otherwise 0
	final switch (tag) {
		case ISO7816_RFU_TAG_FCP_SFI:      return 1;
		case ISO7816_RFU_TAG_FCP_SAC:      return 8;
		case ISO7816_RFU_TAG_FCP_SEID:     return 2;
		case ISO7816_RFU_TAG_FCP_SAE:      return 32;
	}
}

private int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_)
{
	sc_card* card   = p15card.card;
	sc_context* ctx = p15card.card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	sc_file* file;
	mixin (log!(`"new_file"`, `"called"`));
	mixin log_scope_exit!("new_file");
	scope(exit) {
		version(ENABLE_TOSTRING) {
			writer.put("int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_) is returning with argument **out_:\n");
			if (out_ && *out_)
				writer.formattedWrite("%s", **out_);
		}
		if (rv<0 && file) {
			sc_file_free(file);
			file = null;
		}
		log_scope_exit_do(__LINE__);
	}

	assert(p15object.type == SC_PKCS15_TYPE_PRKEY_RSA);
	assert(otype == SC_PKCS15_TYPE_PRKEY_RSA || otype == SC_PKCS15_TYPE_PUBKEY_RSA);

		version(ENABLE_TOSTRING) {
			writer.put("int new_file(sc_profile* profile, sc_pkcs15_card* p15card, sc_pkcs15_object* p15object, uint otype, sc_file** out_) called with argument *p15object:\n");
//			if (out_ && *out_)
				writer.formattedWrite("%s", *p15object);
		}
	sc_pkcs15_prkey_info* key_info = cast(sc_pkcs15_prkey_info*)p15object.data;
	uint keybits = ((cast(uint)key_info.modulus_length+8U)/256)*256;

	uint structure = 0xFFFFFFFF;
	structure = EFDB.RSA_Key_EF;

	uint modulusBytes = keybits/8;
	file = sc_file_new();
	with (file) {
		path = key_info.path;

		if (otype == SC_PKCS15_TYPE_PUBKEY_RSA)
			path.value[path.len-1] &= 0x3F;
		type = SC_FILE_TYPE.SC_FILE_TYPE_INTERNAL_EF;
		ef_structure = EFDB.RSA_Key_EF;

		size = 5 + (otype == SC_PKCS15_TYPE_PRKEY_RSA? modulusBytes/2*5 : modulusBytes+16); // CRT for SC_PKCS15_TYPE_PRKEY_RSA
		id = ub22integral(path.value[path.len-2..path.len]);
	}

	cache_current_df_se_info info; // tag 0x8C and maybe more
	info.sac = [ubyte(0),ubyte(0),ubyte(0),ubyte(0),ubyte(0),ubyte(0),ubyte(0),ubyte(0xFF)];
	ubyte[7] ops_Key_SE = [ SC_AC_OP_READ,        SC_AC_OP_UPDATE,    SC_AC_OP_CRYPTO,    SC_AC_OP_INVALIDATE, SC_AC_OP_REHABILITATE, SC_AC_OP_LOCK, SC_AC_OP_DELETE ];

	ubyte  op;
	mixin file_add_acl_entry;
	sc_file_add_acl_entry(  file, SC_AC_OP_SELECT,     SC_AC.SC_AC_NONE, 0);
	op = SC_AC_OP.SC_AC_OP_WRITE;
	file_add_acl_entry_do(1, __LINE__);

	op = SC_AC_OP.SC_AC_OP_GENERATE;
	file_add_acl_entry_do(1, __LINE__);

	foreach (ii; 0..7) {
		op = ops_Key_SE[ii];
		if (ii>0)
			mixin (log!(`"acos5_64_process_fci"`, `"offs %i, op 0x%02X, SC 0x%02X"`, "ii", "op", "info.sac[ii]"));
		else
			mixin (log!(`"acos5_64_process_fci"`, `"offs %i, op 0x%02X, SC 0x%02X  [op 0x16==SC_AC_OP_READ/op 0x08==SC_AC_OP_DELETE_SELF for DF_MF(Delete Child)]"`, "ii", "op", "info.sac[ii]"));
		file_add_acl_entry_do(ii, __LINE__);
	}

	mixin (log!(`"new_file"`, `"file size %i; ef type %i/%i; id %04X; path_len %i; file path: %s"`,
		"file.size", "file.type", "file.ef_structure", "file.id", "file.path.len", "sc_print_path(&file.path)"));

	if (out_)
		*out_ = file;
	return rv=SC_SUCCESS;
} // new_file

private extern(C) int acos5_64_delete_file(sc_card* card, const(sc_path)* path) {
	sc_context* ctx = card.ctx;
	int rv = SC_ERROR_UNKNOWN;
	mixin (log!(`"acos5_64_delete_file"`, `"called"`));
	mixin log_scope_exit!("acos5_64_delete_file");
	scope(exit)
		log_scope_exit_do(__LINE__);

	sc_path new_path = *path;
	if (path.type != SC_PATH_TYPE_FILE_ID)
	with (new_path)	{
		type = SC_PATH_TYPE_FILE_ID;
		value[0..len] = (UByteArray!1(value[0..len]) <<= len-2)[];
		len = 2;
	}
	return rv=iso_ops_ptr.delete_file(card, &new_path);
}

/* this is limited currently to serve acos5_64_pkcs15_generate_key */
private extern(C) int acos5_64_construct_fci(sc_card* card, const(sc_file)* file, ubyte* out_, size_t* outlen) {
	*outlen = 30;
	if      ((file.id >>> 4) == 0x41F) { //            4                           12
		out_[0..*outlen] = representation(x"62 1C 83 02  41F1  82 02  09  00   80 02 05 15 88 01 00 8A 01 05 8C 08 7F 01 FF 00 01 01 01 FF").dup;
		out_[ 4.. 6] = integral2ub!2(file.id)[];
		out_[12..14] = integral2ub!2(file.size)[];
	}
	else if ((file.id >>> 4) == 0x413) {
		out_[0..*outlen] = representation(x"62 1C 83 02  4131  82 02  09  00   80 02 02 15 88 01 00 8A 01 05 8C 08 7F 01 FF 00 01 00 01 00").dup;
		out_[ 4.. 6] = integral2ub!2(file.id)[];
		out_[12..14] = integral2ub!2(file.size)[];
	}
	else {
		*outlen = 0;
		return SC_ERROR_CARD_CMD_FAILED;
	}
	return SC_SUCCESS;
}
