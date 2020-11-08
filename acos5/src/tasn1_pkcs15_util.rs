use std::os::raw::{c_char, c_int, c_void};
use std::ptr::{null_mut};
use std::ffi::{CStr};
use std::convert::{TryFrom, TryInto};
use std::ops::{Deref, DerefMut, Range};

use opensc_sys::opensc::{sc_card, sc_format_path, sc_select_file, sc_read_binary};
use opensc_sys::types::{sc_path, sc_aid, SC_MAX_AID_SIZE, SC_MAX_PATH_SIZE};
use opensc_sys::errors::SC_SUCCESS;

use crate::constants_types::{DataPrivate, p_void, PKCS15_FILE_TYPE_APPDF, PKCS15_FILE_TYPE_DIR, PKCS15_FILE_TYPE_ODF,
                             PKCS15_FILE_TYPE_TOKENINFO,
                             PKCS15_FILE_TYPE_PRKDF,
                             PKCS15_FILE_TYPE_PUKDF,
                             PKCS15_FILE_TYPE_PUKDF_TRUSTED,
                             PKCS15_FILE_TYPE_SKDF,
                             PKCS15_FILE_TYPE_CDF,
                             PKCS15_FILE_TYPE_CDF_TRUSTED,
                             PKCS15_FILE_TYPE_CDF_USEFUL,
                             PKCS15_FILE_TYPE_DODF,
                             PKCS15_FILE_TYPE_AODF, GuardFile
};
use crate::path::{file_id_from_path_value, file_id_se, is_child_of};

use crate::tasn1_sys::{asn1_node_st, asn1_node, asn1_delete_structure, asn1_parser2tree, ASN1_SUCCESS,
                       asn1_create_element, asn1_der_decoding, asn1_read_value, asn1_strerror, asn1_get_length_der};

// #[derive(Debug, Eq, PartialEq)]
pub struct GuardAsn1Node(*mut *mut asn1_node_st);

impl GuardAsn1Node {
    /// Creates a guard for the specified element.
    pub fn new(inner: *mut *mut asn1_node_st) -> Self {
// println!("GuardAsn1Node");
        GuardAsn1Node(inner)
    }
    /*
        /// Forgets this guard and unwraps out the contained element.
        pub fn unwrap(self) -> E {
            let inner = self.0;
            forget(self);   // Don't drop me or I'll destroy `inner`!
            inner
        }
    */
}

impl Drop for GuardAsn1Node {
    fn drop(&mut self) {
        if !self.0.is_null() && unsafe { !(*self.0).is_null() } {
// println!("Drop for ...");
            unsafe { asn1_delete_structure(self.0) };
        }
    }
}

/// Be careful on deferecing so you don't store another copy of the element somewhere.
impl Deref for GuardAsn1Node {
    type Target = *mut *mut asn1_node_st;
    // fn deref(&self) -> &Self::Target;
    fn deref(&self) -> & *mut *mut asn1_node_st {
        &self.0
    }
}

/// Be careful on deferecing so you don't store another copy of the element somewhere.
impl DerefMut for GuardAsn1Node {
    // fn deref_mut(&mut self) -> &mut Self::Target;
    fn deref_mut(&mut self) -> &mut *mut *mut asn1_node_st {
        &mut self.0
    }
}


/* Used for AODF, SKDF etc. which store sequences of logically separate DER data
   The iterator returns RangeInclusive of those separate DER data within the provided buffer.
   The provided buffer usually is from sc_read_binary, which may retrieve "excessive" bytes that
   are not part of any DER data, usually zero bytes. These "excessive" bytes will be ignored */
pub struct DirectoryRange<'a> {
    last_end_exclusive: i32,
    rem: &'a [u8],
}

impl<'a> DirectoryRange<'a> {
    // #[must_use]
    pub fn new(input: &'a[u8]) -> Self {
        Self { last_end_exclusive: 0, rem: input }
    }
}

impl<'a> Iterator for DirectoryRange<'a> {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rem.is_empty() || self.rem[0] == 0 || (self.rem.len()>=2 && self.rem[1] == 0) {
            None
        }
        else {
            #[allow(non_upper_case_globals)]
            const   T_len : i32 = 1;
            #[allow(non_snake_case)]
            let mut L_len = 0;
            #[allow(non_snake_case)]
            let     V_len : i32 = unsafe { asn1_get_length_der(self.rem.as_ptr().add(1),
                                    (self.rem.len()-1).try_into().unwrap(), &mut L_len).try_into().unwrap() };
//println!("self.rem.len(): {}, V_len: {}, L_len: {}", self.rem.len(), V_len, L_len);
            let tlv_len = T_len + L_len + V_len;
            if V_len<0 || L_len<1 || L_len>4 || self.rem.len() < tlv_len.try_into().unwrap() {
                return None;
            }
            let new_end_exclusive = self.last_end_exclusive + tlv_len;
            let result = Range { start: self.last_end_exclusive.try_into().unwrap(), end: new_end_exclusive.try_into().unwrap() };
            self.last_end_exclusive = new_end_exclusive;
            self.rem = &self.rem[tlv_len.try_into().unwrap()..];
            Some(result)
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct FidPkcs15Type(u16, u8);

#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn analyze_PKCS15_DIRRecord_2F00(card: &mut sc_card, aid: &mut sc_aid) {
    /* this will mark the file 3F002F00 as PKCS15_FILE_TYPE_DIR (after check that it contains valid data for "PKCS15.DIRRecord")
       and mark the appDF as PKCS15_FILE_TYPE_APPDF (appDF=="path" extracted from EF.DIR)
result from asn1_check_version: "4.13"
ready to inspect
path of application directory: 0x[3F, 0, 41, 0], fid: 0x4100
aid of application directory: 0x[41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30]
aid of application directory: ACOSPKCS-15v1.00
label of application directory: eCert
    */
    if card.app_count>0 && !card.app[0].is_null() {
// println!("card.app[0]: {:X?}", unsafe { *card.app[0] });
/*
card.app[0]: sc_app_info {
  label: 0x55c703e25810,
  aid: sc_aid { value: [41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30], len: 10 },
  ddo: sc_ddo { aid: sc_aid { value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 0 }, iid: sc_iid { value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 0 }, oid: sc_object_id { value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }, len: 0, value: 0x0 },
  path: sc_path { value: [3F, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 4, index: 0, count: 0, type_: 2, aid: sc_aid { value: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], len: 0 } },
  rec_nr: FFFFFFFF
}
*/
    }
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let pkcs15_definitions = dp.pkcs15_definitions;
    let size : usize = file_id_se(dp.files[&0x2F00].1).into();
    card.drv_data = Box::into_raw(dp) as p_void;
    if pkcs15_definitions.is_null() { return; }
    // else { /*ASN1_SUCCESS asn1_parser2tree */
        /* do bytes of file 0x2f00 represent DER-encoded "DIRRecord" information (see PKCS#15) ?
           if yes, then this requirement from PKCS#15 is met and we can extract info about aid and path of PKCS#15 application DF
61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76
31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00
           */
    let mut structure : asn1_node = null_mut();
    let guard_structure = GuardAsn1Node::new(&mut structure);
    let mut asn1_result = unsafe { asn1_create_element(pkcs15_definitions, cstru!(b"PKCS15.DIRRecord\0").as_ptr(),
                                                           *guard_structure) };
    if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
        println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
        return;
    }
    // else { /*ASN1_SUCCESS asn1_create_element  structure */
    let mut path_2f00 = sc_path::default();
    unsafe { sc_format_path(cstru!(b"3F002F00\0").as_ptr(), &mut path_2f00); } // type = SC_PATH_TYPE_PATH;
    let mut file = null_mut();
    let guard_file = GuardFile::new(&mut file);
    let mut rv = unsafe { sc_select_file(card, &path_2f00, *guard_file) };
    if rv != SC_SUCCESS { return; }
    let mut rbuf = vec![0_u8; size];
    rv = unsafe { sc_read_binary(card, 0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
    if rv <= 0  {  return; }
    for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap()]) {
        let rbuf2 = &rbuf[range];
        let mut error_description = [0x00 as c_char; 129];
        /* decode DER data from file 0x3F002F00 (first DirectoryRange) into structure "PKCS15.DIRRecord" */
        asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                                                 rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            return;
        }
        // else {
// println!("ready to inspect");
        let mut name = cstru!(b"path\0"); // OCTET STRING
        let mut buf = [0_u8; SC_MAX_PATH_SIZE];
        let mut outlen = buf.len() as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("asn1_result (asn1_read_value  path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            return;
        }
        else {
            let outlen = usize::try_from(outlen).unwrap();
            let buf_slice = &buf[..outlen];
            if outlen < 2 { return; }
            let file_id_app = file_id_from_path_value(buf_slice);
// println!("path of application directory: 0x{:X?}, fid: 0x{:X}", buf_slice, file_id_app);

            let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
            let dp_files_value_2F00 = dp.files.get_mut(&0x2F00).unwrap();
            dp_files_value_2F00.1[6] = PKCS15_FILE_TYPE_DIR;
            if file_id_app > 0 {
                let dp_files_value = dp.files.get_mut(&file_id_app).unwrap();
                dp_files_value.1[6] = PKCS15_FILE_TYPE_APPDF;
                let dp_files_value = &dp.files[&file_id_app];
                let path_app = &dp_files_value.0[0..dp_files_value.1[1].into()];
                assert_eq!(buf_slice, path_app);
                if path_app.len() >= 16 { return; }
                let dp_files_value_5031 = &dp.files[&0x5031];
                assert!(is_child_of(dp_files_value_5031, dp_files_value));
                let dp_files_value_5032 = &dp.files[&0x5032];
                assert!(is_child_of(dp_files_value_5032, dp_files_value));

                let dp_files_value_5031 = dp.files.get_mut(&0x5031).unwrap();
                dp_files_value_5031.1[6] = PKCS15_FILE_TYPE_ODF;
                let dp_files_value_5032 = dp.files.get_mut(&0x5032).unwrap();
                dp_files_value_5032.1[6] = PKCS15_FILE_TYPE_TOKENINFO;
            }
            card.drv_data = Box::into_raw(dp) as p_void;
        }

        name = cstru!(b"aid\0"); // OCTET STRING
        // buf = [0_u8; 16];
        outlen = SC_MAX_AID_SIZE as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), aid.value.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("asn1_result (asn1_read_value  aid): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
        }
        else {
            aid.len = outlen.try_into().unwrap();
//                    let buf_slice = &aid.value[..aid.len];
// println!("aid of application directory: 0x{:X?}", buf_slice);
// println!("aid of application directory: {}", String::from_utf8(buf_slice.to_vec()).unwrap_or_default());
        }

        name = cstru!(b"label\0"); // label is OPTIONAL   UTF8String
        let mut buf_str = [0_u8; 64];
        outlen = buf_str.len() as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), buf_str.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("asn1_result (asn1_read_value  label): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
        }
        else {
//                     let x = &buf_str[..outlen.try_into().unwrap()];
// println!("label of application directory: {}", String::from_utf8(x.to_vec()).unwrap_or_default());
        }
    }
}

#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn analyze_PKCS15_PKCS15Objects_5031(card: &mut sc_card) {
/* This relies on function analyze_PKCS15_DIRRecord_2F00 having marked as PKCS15_FILE_TYPE_ODF
   any EF.ODF specified by EF.DIR, so we can iterate over hashmah dp.files and search byte dp_files_value.1[6]
    [ "EF(ODF)",          "PKCS15.PKCS15Objects",      "",                              "PKCS15.PKCS15ObjectsChoice", "pkcs15Objects"],
    PKCS15_FILE_TYPE_ODF are set but file(s) not yet checked
 */

    fn get_arr<'a>(idx: u8) -> &'a CStr {
        match idx {
            PKCS15_FILE_TYPE_PRKDF => cstru!(b"privateKeys.path.path\0"),
            PKCS15_FILE_TYPE_PUKDF => cstru!(b"publicKeys.path.path\0"),
            PKCS15_FILE_TYPE_PUKDF_TRUSTED => cstru!(b"trustedPublicKeys.path.path\0"),
            PKCS15_FILE_TYPE_SKDF => cstru!(b"secretKeys.path.path\0"),
            PKCS15_FILE_TYPE_CDF => cstru!(b"certificates.path.path\0"),
            PKCS15_FILE_TYPE_CDF_TRUSTED => cstru!(b"trustedCertificates.path.path\0"),
            PKCS15_FILE_TYPE_CDF_USEFUL => cstru!(b"usefulCertificates.path.path\0"),
            PKCS15_FILE_TYPE_DODF => cstru!(b"dataObjects.path.path\0"),
            PKCS15_FILE_TYPE_AODF => cstru!(b"authObjects.path.path\0"),
            _ => cstru!(b"noObject\0"),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct FidPath<'a>(u16, &'a [u8]);

    let mut vec_appdf : Vec<FidPath> = Vec::with_capacity(4);
    let mut vec_FidPkcs15Type : Vec<FidPkcs15Type> = Vec::with_capacity(9);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    // let fmt1  = cstru!(b"key: %04X, val.1: %s\0");
    for (&key, val) in &dp.files {
        if val.1[6] == PKCS15_FILE_TYPE_APPDF {
            vec_appdf.push(FidPath(key, &val.0[..val.1[1].into()]));
            // log3if!(ctx,f,line!(), fmt1, *key, unsafe { sc_dump_hex(val.1.as_ptr(), 8) });
        }
    }
println!("{} PKCS#15 application(s) is/are specified. File ids:  {:X?}", vec_appdf.len(), vec_appdf);

    for FidPath(fid, path_app) in vec_appdf {
println!("fid:  {:X}", fid);
println!("len: {}",  path_app.len());
println!("path_app: {:X?}", path_app);
        for (_, val) in &dp.files {
            if val.1[6] == PKCS15_FILE_TYPE_ODF && path_app.len()+2 == val.1[1].into() && path_app == &val.0[..path_app.len()] {
println!("dp.files entry with PKCS15_FILE_TYPE_ODF:  {:X?}", val);
                /* this will mark the file 3F002F00 as PKCS15_FILE_TYPE_DIR (after check that it contains valid data for "PKCS15.DIRRecord")
                   and mark the appDF as PKCS15_FILE_TYPE_APPDF (appDF=="path" extracted from EF.DIR)
            result from asn1_check_version: "4.13"
            ready to inspect
            path of application directory: 0x[3F, 0, 41, 0], fid: 0x4100
            aid of application directory: 0x[41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30]
            aid of application directory: ACOSPKCS-15v1.00
            label of application directory: eCert
                */
                let mut pkcs15 = null_mut();
let guard_definitions = GuardAsn1Node::new(&mut pkcs15);
                let mut error_description /*: [c_char; 129]*/ = [0x00 as c_char; 129];
                let mut asn1_result = unsafe {
                    asn1_parser2tree(cstru!(b"workspace/acos5_gui/source/PKCS15.asn\0").as_ptr(),
                                     *guard_definitions, error_description.as_mut_ptr()) };
                if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                    let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
                    println!("asn1_result (definitions): {}, error_description: {:?}", asn1_result, c_str);
                }
                else { /*ASN1_SUCCESS asn1_parser2tree */
                    /* do bytes of file 0x2f00 represent DER-encoded "DIRRecord" information (see PKCS#15) ?
                       if yes, then this requirement from PKCS#15 is met and we can extract info about aid and path of PKCS#15 application DF
            61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76
            31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00
                       */

                    /*ASN1_SUCCESS asn1_create_element  structure */
                    // let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
                    let dp_files_value = &dp.files[&0x5031];
                    let size: usize = file_id_se(dp_files_value.1).into();
                    // card.drv_data = Box::into_raw(dp) as p_void;

                    let mut path_5031 = sc_path::default();
                    unsafe { sc_format_path(cstru!(b"3F0041005031\0").as_ptr(), &mut path_5031); } // type = SC_PATH_TYPE_PATH;
                    unsafe { sc_select_file(card, &path_5031, null_mut()) };
                    let mut rbuf = vec![0_u8; size];
                    let rv = unsafe { sc_read_binary(card, 0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
                    assert!(rv>0);

                    // for i in 0..=8_usize {
                    for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap()]) {
                        let mut structure = null_mut();
let guard_structure = GuardAsn1Node::new(&mut structure);
                        let source_name = cstru!(b"PKCS15.PKCS15Objects\0");
                        asn1_result = unsafe { asn1_create_element(pkcs15, source_name.as_ptr(), *guard_structure) };
                        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                            println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                        }
                        else {
                            let rbuf2 = &rbuf[range];
// println!("range: {:?}, rbuf2: {:X?}", range, rbuf2);
                            asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                                rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

                            if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                                println!("Not ready to inspect");
                                let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
                                println!("asn1_result (asn1_der_decoding): {}, error_description: {:?}", asn1_result, c_str);
                            }
                            else {

                                for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF {
                                    // println!("ready to inspect");
                                    // println!("ready to inspect");
                                    let mut buf = [0_u8; 16];
                                    let mut outlen = buf.len() as c_int;
                                    asn1_result = unsafe { asn1_read_value(structure, get_arr(type_).as_ptr(),
                                                                           buf.as_mut_ptr() as *mut c_void, &mut outlen) };
                                    if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                                        // println!("asn1_result (asn1_read_value  path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                                    }
                                    else {
                                        let outlen = usize::try_from(outlen).unwrap();
                                        let buf_slice = &buf[..outlen];
                                        let mut file_id = 0;
                                        if outlen >= 2 {
                                            file_id = file_id_from_path_value(buf_slice);
                                        }
println!("path of {}_DF: 0x{:X?}, fid: 0x{:X}", type_, buf_slice, file_id);
                                        // let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
                                        if file_id > 0 {
                                            let dp_files_value = dp.files.get(&file_id).unwrap();
                                            let path_obj = &dp_files_value.0[0..dp_files_value.1[1].into()];
                                            assert_eq!(buf_slice, path_obj);
                                            // dp_files_value.1[6] = type_;
                                            // struct FidPkcs15Type(u16, u8);
                                            vec_FidPkcs15Type.push(FidPkcs15Type(file_id, type_));// : Vec<FidPkcs15Type> = Vec::with_capacity(9);
                                        }
                                        break;
                                    } // if ASN1_SUCCESS for asn1_read_value
                                } // for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF
                            } // if ASN1_SUCCESS for asn1_der_decoding
                        } // if ASN1_SUCCESS for asn1_create_element
                    } // for range in DirectoryRange
                } // if ASN1_SUCCESS for asn1_parser2tree
// println!("One more drop GuardAsn1Node will follow ...");
            } //  if val.1[6] == PKCS15_FILE_TYPE_ODF // for each PKCS15_FILE_TYPE_ODF
        } // for (_, val) in &dp.files
    } // for FidPath(fid, path_app) in vec_appdf      // for each application
    card.drv_data = Box::into_raw(dp) as p_void;

    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    for FidPkcs15Type(fid, pkcs15_type) in &vec_FidPkcs15Type {
        let mut dp_files_value = dp.files.get_mut(fid).unwrap();
        dp_files_value.1[6] = *pkcs15_type;
    }
    card.drv_data = Box::into_raw(dp) as p_void;
    for elem in vec_FidPkcs15Type {
        analyze_PKCS15_PKCS15Objects(card, elem)
    }
}

#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn analyze_PKCS15_PKCS15Objects(_card: &mut sc_card, _type_: FidPkcs15Type) {
    println!("TODO");
}

// [ "EF(TokenInfo)",    "PKCS15.TokenInfo",          "",                              "PKCS15.TokenInfoChoice", "tokenInfo"],
#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn analyze_PKCS15_TokenInfo_5032(card: &mut sc_card) {
    /* This relies on function analyze_PKCS15_DIRRecord_2F00 having marked as PKCS15_FILE_TYPE_ODF
       any EF.ODF specified by EF.DIR, so we can iterate over hashmah dp.files and search byte dp_files_value.1[6]
        [ "EF(ODF)",          "PKCS15.PKCS15Objects",      "",                              "PKCS15.PKCS15ObjectsChoice", "pkcs15Objects"],
        PKCS15_FILE_TYPE_ODF are set but file(s) not yet checked
     */
    #[derive(Debug, Eq, PartialEq)]
    struct FidPath<'a>(u16, &'a [u8]);
    // #[derive(Debug, Eq, PartialEq)]
    // struct FidPkcs15Type(u16, u8);

    let mut vec_appdf : Vec<FidPath> = Vec::with_capacity(4);
    // let mut vec_FidPkcs15Type : Vec<FidPkcs15Type> = Vec::with_capacity(9);

    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    // let fmt1  = cstru!(b"key: %04X, val.1: %s\0");
    for (&key, val) in &dp.files {
        if val.1[6] == PKCS15_FILE_TYPE_APPDF {
            vec_appdf.push(FidPath(key, &val.0[..val.1[1].into()]));
            // log3if!(ctx,f,line!(), fmt1, *key, unsafe { sc_dump_hex(val.1.as_ptr(), 8) });
        }
    }
    println!("{} PKCS#15 application(s) is/are specified. File ids:  {:X?}", vec_appdf.len(), vec_appdf);

    for FidPath(fid, path_app) in vec_appdf {
        println!("fid:  {:X}", fid);
        println!("len: {}",  path_app.len());
        println!("path_app: {:X?}", path_app);
        for (_, val) in &dp.files {
            if val.1[6] == PKCS15_FILE_TYPE_TOKENINFO && path_app.len()+2 == val.1[1].into() && path_app == &val.0[..path_app.len()] {
                println!("dp.files entry with PKCS15_FILE_TYPE_TOKENINFO:  {:X?}", val);
                /* this will mark the file 3F002F00 as PKCS15_FILE_TYPE_DIR (after check that it contains valid data for "PKCS15.DIRRecord")
                   and mark the appDF as PKCS15_FILE_TYPE_APPDF (appDF=="path" extracted from EF.DIR)
            result from asn1_check_version: "4.13"
            ready to inspect
            path of application directory: 0x[3F, 0, 41, 0], fid: 0x4100
            aid of application directory: 0x[41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30]
            aid of application directory: ACOSPKCS-15v1.00
            label of application directory: eCert
                */
                let mut pkcs15 = null_mut();
                let guard_definitions = GuardAsn1Node::new(&mut pkcs15);
                let mut error_description /*: [c_char; 129]*/ = [0x00 as c_char; 129];
                let mut asn1_result = unsafe {
                    asn1_parser2tree(cstru!(b"workspace/acos5_gui/source/PKCS15.asn\0").as_ptr(),
                                     *guard_definitions, error_description.as_mut_ptr()) };
                if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                    let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
                    println!("asn1_result (definitions): {}, error_description: {:?}", asn1_result, c_str);
                }
                else { /*ASN1_SUCCESS asn1_parser2tree */
                    let dp_files_value = &dp.files[&0x5032];
                    let size: usize = file_id_se(dp_files_value.1).into();

                    let mut path_5032 = sc_path::default();
                    unsafe { sc_format_path(cstru!(b"3F0041005032\0").as_ptr(), &mut path_5032); } // type = SC_PATH_TYPE_PATH;
                    unsafe { sc_select_file(card, &path_5032, null_mut()) };
                    let mut rbuf = vec![0_u8; size];
                    let rv = unsafe { sc_read_binary(card, 0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
                    assert!(rv>0);

                    // this "loops" only once !
                    for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap()]) {
                        let mut structure = null_mut();
                        let guard_structure = GuardAsn1Node::new(&mut structure);
                        let source_name = cstru!(b"PKCS15.TokenInfo\0");
                        asn1_result = unsafe { asn1_create_element(pkcs15, source_name.as_ptr(), *guard_structure) };
                        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                            println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                        }
                        else {
                            let rbuf2 = &rbuf[range];
// println!("range: {:?}, rbuf2: {:X?}", range, rbuf2);
                            asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                                rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

                            if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                                println!("Not ready to inspect");
                                let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
                                println!("asn1_result (asn1_der_decoding): {}, error_description: {:?}", asn1_result, c_str);
                            }
                            else {

                                // for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF {
                                //     println!("ready to inspect");
                                //     println!("ready to inspect");
                                let name = cstru!(b"label\0"); // UTF8String
                                    let mut buf_str = [0_u8; 64];
                                    let mut outlen = buf_str.len() as c_int;
                                    asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(),
                                                               buf_str.as_mut_ptr() as *mut c_void, &mut outlen) };
                                    if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                                        println!("asn1_result (asn1_read_value  label): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                                    }
                                    else {
                                        let outlen = usize::try_from(outlen).unwrap();
                                        // let buf_slice = &buf_str[..outlen];
                                        // let mut file_id = 0;
                                        // if outlen >= 2 {
                                        //     file_id = file_id_from_path_value(buf_slice);
                                        // }
                                        // println!("buf_str of EF(TokenInfo): 0x{:X?}", buf_slice);
                                        let x = &buf_str[..outlen.try_into().unwrap()];
                                        println!("label EF(TokenInfo): {}", String::from_utf8(x.to_vec()).unwrap_or_default());
                                        // let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
                                        // if file_id > 0 {
                                        //     let dp_files_value = dp.files.get(&file_id).unwrap();
                                        //     let path_obj = &dp_files_value.0[0..dp_files_value.1[1].into()];
                                        //     assert_eq!(buf_slice, path_obj);
                                        //     // dp_files_value.1[6] = type_;
                                        //     // struct FidPkcs15Type(u16, u8);
                                        //     // vec_FidPkcs15Type.push(FidPkcs15Type(file_id, type_));// : Vec<FidPkcs15Type> = Vec::with_capacity(9);
                                        // }
                                        break;
                                    } // if ASN1_SUCCESS for asn1_read_value
                                // } // for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF
                            } // if ASN1_SUCCESS for asn1_der_decoding
                        } // if ASN1_SUCCESS for asn1_create_element
                    } // for range in DirectoryRange
                } // if ASN1_SUCCESS for asn1_parser2tree
// println!("One more drop GuardAsn1Node will follow ...");
            } //  if val.1[6] == PKCS15_FILE_TYPE_ODF // for each PKCS15_FILE_TYPE_ODF
        } // for (_, val) in &dp.files
    } // for FidPath(fid, path_app) in vec_appdf      // for each application
    card.drv_data = Box::into_raw(dp) as p_void;
/*
    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    for FidPkcs15Type(fid, pkcs15_type) in vec_FidPkcs15Type {
        let mut dp_files_value = dp.files.get_mut(&fid).unwrap();
        dp_files_value.1[6] = pkcs15_type;
    }
    card.drv_data = Box::into_raw(dp) as p_void;
*/
}


#[cfg(test)]
mod tests {
    use super::{DirectoryRange};

    #[test]
    fn test_directory_range() { // $ cargo test test_directory_range -- --nocapture
        let buf = [
            0x61, 0x1F, 0x4F, 0x10, 0x41, 0x43, 0x4F, 0x53, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35, 0x76,
            0x31, 0x2E, 0x30, 0x30, 0x50, 0x05, 0x65, 0x43, 0x65, 0x72, 0x74, 0x51, 0x04, 0x3F, 0x00, 0x41, 0x00,
            0x00, 0x00
        ];
        assert_eq!(0..33, DirectoryRange::new(&buf).next().unwrap());

        let buf = [
            0xA8, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x11,
            0xA0, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x12,
            0xA1, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x13,
            0xA3, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x14,
            0xA4, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x15,
            0xA5, 0x0A, 0x30, 0x08, 0x04, 0x06, 0x3F, 0x00, 0x41, 0x00, 0x41, 0x16,

            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ];
        let mut iter = DirectoryRange::new(&buf);
        assert_eq!( 0..12, iter.next().unwrap());
        assert_eq!(12..24, iter.next().unwrap());
        assert_eq!(24..36, iter.next().unwrap());
        assert_eq!(36..48, iter.next().unwrap());
        assert_eq!(48..60, iter.next().unwrap());
        assert_eq!(60..72, iter.next().unwrap());
        assert_eq!(None, iter.next());
    }
}
