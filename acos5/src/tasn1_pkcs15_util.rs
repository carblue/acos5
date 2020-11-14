/*
 * tasn1_pkcs15_util.rs: Driver 'acos5' - PKCS#15 related functions, based on Libtasn1
 *
 * Copyright (C) 2020  Carsten Blüggel <bluecars@posteo.eu>
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
 * Foundation, 51 Franklin Street, Fifth Floor  Boston, MA 02110-1335  USA
 */

use std::os::raw::{c_char, c_int, c_void};
use std::ptr::{null_mut};
use std::ffi::{CStr};
use std::convert::{TryFrom, TryInto};
use std::ops::{Deref, DerefMut, Range};

use opensc_sys::opensc::{sc_card, sc_format_path, sc_path_set, sc_select_file, sc_read_binary};
use opensc_sys::types::{sc_path, sc_aid, SC_PATH_TYPE_PATH, SC_MAX_AID_SIZE, SC_MAX_PATH_SIZE};
use opensc_sys::errors::SC_SUCCESS;

use crate::constants_types::{DataPrivate, p_void, PKCS15_FILE_TYPE_APPDF, PKCS15_FILE_TYPE_DIR,
                             PKCS15_FILE_TYPE_TOKENINFO,
                             PKCS15_FILE_TYPE_ODF,
                             PKCS15_FILE_TYPE_PRKDF,
                             PKCS15_FILE_TYPE_PUKDF,
                             PKCS15_FILE_TYPE_PUKDF_TRUSTED,
                             PKCS15_FILE_TYPE_SKDF,
                             PKCS15_FILE_TYPE_CDF,
                             PKCS15_FILE_TYPE_CDF_TRUSTED,
                             PKCS15_FILE_TYPE_CDF_USEFUL,
                             PKCS15_FILE_TYPE_DODF,
                             PKCS15_FILE_TYPE_AODF,

                             PKCS15_FILE_TYPE_RSAPRIVATEKEY,
                             PKCS15_FILE_TYPE_ECCPRIVATEKEY,
                             PKCS15_FILE_TYPE_RSAPUBLICKEY,
                             PKCS15_FILE_TYPE_ECCPUBLICKEY,
                             PKCS15_FILE_TYPE_SECRETKEY,
                             PKCS15_FILE_TYPE_CERT,
                             PKCS15_FILE_TYPE_DATA,
                             PKCS15_FILE_TYPE_PIN,
                             PKCS15_FILE_TYPE_BIOMETRIC,
                             PKCS15_FILE_TYPE_AUTHKEY,
                             PKCS15_FILE_TYPE_NONE,
                             GuardFile, is_DFMF};
use crate::path::{file_id_from_path_value, file_id_se, is_child_of};

use crate::tasn1_sys::{asn1_node_st, asn1_node, asn1_delete_structure, ASN1_SUCCESS,
                       asn1_create_element, asn1_der_decoding, asn1_read_value, asn1_strerror, asn1_get_length_der};

pub struct GuardAsn1Node(*mut *mut asn1_node_st);

impl GuardAsn1Node {
    pub fn new(inner: *mut *mut asn1_node_st) -> Self {
// println!("GuardAsn1Node");
        GuardAsn1Node(inner)
    }
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
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Be careful on deferecing so you don't store another copy of the element somewhere.
impl DerefMut for GuardAsn1Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
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

/* this will mark the file 3F002F00 as PKCS15_FILE_TYPE_DIR (after check that it contains valid data for "PKCS15.DIRRecord")
   and mark the appDF as PKCS15_FILE_TYPE_APPDF (appDF=="path" extracted from EF.DIR)
result from asn1_check_version: "4.13"
ready to inspect
path of application directory: 0x[3F, 0, 41, 0], fid: 0x4100
aid of application directory: 0x[41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30]
aid of application directory: ACOSPKCS-15v1.00
label of application directory: eCert
*/
/* do bytes of file 0x2f00 represent DER-encoded "DIRRecord" information (see PKCS#15) ? if yes, then this
  requirement from PKCS#15 is met and we can extract info about aid and path of PKCS#15 application DF */
/*
if the loop completes, then it has set these file types:
PKCS15_FILE_TYPE_DIR          for file 0x3F002F00
PKCS15_FILE_TYPE_APPDF        for whatever application directory DF specified
PKCS15_FILE_TYPE_ODF          for whatever file specified (or default) within APPDF (i.e. it's a child); the default is 0x5031
PKCS15_FILE_TYPE_TOKENINFO    for whatever file specified (or default) within APPDF (i.e. it's a child); the default is 0x5032

and returns first aid found
*/
#[allow(non_snake_case)]
pub fn analyze_PKCS15_DIRRecord_2F00(card: &mut sc_card, aid: &mut sc_aid) {
    if card.app_count>0 && !card.app[0].is_null() {
// println!("card.app[0]: {:X?}", unsafe { *card.app[0] });
    }
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let pkcs15_definitions = dp.pkcs15_definitions;
    let size : usize = file_id_se(dp.files[&0x2F00].1).into();
    Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as p_void;
    if pkcs15_definitions.is_null() { return; }

    let mut aid_buf = [0_u8; SC_MAX_AID_SIZE];
    let mut aid_len = SC_MAX_AID_SIZE as c_int;
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
//println!("for range in DirectoryRange: {:?}", range);
        let mut structure : asn1_node = null_mut();
        let guard_structure = GuardAsn1Node::new(&mut structure);
        let mut asn1_result = unsafe { asn1_create_element(pkcs15_definitions, cstru!(b"PKCS15.DIRRecord\0").as_ptr(), *guard_structure) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            return;
        }
        let rbuf2 = &rbuf[range];
        let mut error_description = [0x00 as c_char; 129];
        /* decode DER data from file 0x3F002F00 into structure "PKCS15.DIRRecord" */
        asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                                                 rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("error while decoding DIRRecord data: {:?}", rbuf2);
            continue;
        }
//println!("ready to inspect");
        let mut name = cstru!(b"aid\0"); // OCTET STRING  MANDATORY
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), aid_buf.as_mut_ptr() as *mut c_void, &mut aid_len) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("asn1_result (asn1_read_value  aid): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            continue;
        }

        let mut buf_slice;
//buf_slice = &aid_buf[..aid_len.try_into().unwrap()];
//println!("aid of application directory: 0x{:X?}", buf_slice);
//println!("aid of application directory: {}", String::from_utf8(buf_slice.to_vec()).unwrap_or_default());

        name = cstru!(b"path\0"); // OCTET STRING  MANDATORY
        let mut buf = [0_u8; SC_MAX_PATH_SIZE];
        let mut outlen = buf.len() as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("asn1_result (asn1_read_value  path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            continue;
        }
        if outlen < 2 { continue; }
        buf_slice = &buf[..usize::try_from(outlen).unwrap()];

        let file_id_app = file_id_from_path_value(buf_slice);
//println!("path of application directory: 0x{:X?}, fid: 0x{:X}", buf_slice, file_id_app);

        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        let dp_files_value_2F00 = dp.files.get_mut(&0x2F00).unwrap();
        dp_files_value_2F00.1[6] = PKCS15_FILE_TYPE_DIR;
        let dp_files_value_app = &dp.files[&file_id_app];
        assert!(is_DFMF(dp_files_value_app.1[0]));
        assert_eq!(buf_slice, &dp_files_value_app.0[..dp_files_value_app.1[1].into()]);
        card.drv_data = Box::into_raw(dp) as p_void;

        name = cstru!(b"label\0"); // UTF8String  OPTIONAL
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

        let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
        name = cstru!(b"ddo.odfPath.path\0"); // OCTET STRING  OPTIONAL
        outlen = buf.len() as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            //println!("asn1_result (asn1_read_value  ddo.odfPath.path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            let dp_files_value_5031 = &dp.files[&0x5031];
            if !is_child_of(dp_files_value_5031, &dp.files[&file_id_app]) {
                Box::leak(dp);
                continue;
            }
            let dp_files_value_5031 = dp.files.get_mut(&0x5031).unwrap();
            dp_files_value_5031.1[6] = PKCS15_FILE_TYPE_ODF;
        }
        else {
            buf_slice = &buf[..usize::try_from(outlen).unwrap()];
            let file_id_odf = file_id_from_path_value(buf_slice);
//println!("ddo.odfPath.path:       0x{:X?}, fid: 0x{:X}", buf_slice, file_id_odf); // ddo.odfPath.path: 0x[3F, 0, 41, 0, 50, 31], fid: 0x5031
            let dp_files_value_5031 = &dp.files[&file_id_odf];
            if !is_child_of(dp_files_value_5031, &dp.files[&file_id_app]) {
                Box::leak(dp);
                continue;
            }
            let dp_files_value_5031 = dp.files.get_mut(&file_id_odf).unwrap();
            dp_files_value_5031.1[6] = PKCS15_FILE_TYPE_ODF;
        }

        name = cstru!(b"ddo.tokenInfoPath.path\0"); // OCTET STRING  OPTIONAL
        outlen = buf.len() as c_int;
        asn1_result = unsafe { asn1_read_value(structure, name.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut outlen) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            //println!("asn1_result (asn1_read_value  ddo.tokenInfoPath.path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            let dp_files_value_5032 = &dp.files[&0x5032];
            if !is_child_of(dp_files_value_5032, &dp.files[&file_id_app]) {
                Box::leak(dp);
                continue;
            }
            let dp_files_value_5032 = dp.files.get_mut(&0x5032).unwrap();
            dp_files_value_5032.1[6] = PKCS15_FILE_TYPE_TOKENINFO;
        }
        else {
            buf_slice = &buf[..usize::try_from(outlen).unwrap()];
            let file_id_cia = file_id_from_path_value(buf_slice);
//println!("ddo.tokenInfoPath.path: 0x{:X?}, fid: 0x{:X}", buf_slice, file_id_cia); // ddo.tokenInfoPath.path: 0x[3F, 0, 41, 0, 50, 32], fid: 0x5032
            let dp_files_value_5032 = &dp.files[&file_id_cia];
            if !is_child_of(dp_files_value_5032, &dp.files[&file_id_app]) {
                Box::leak(dp);
                continue;
            }
            let dp_files_value_5032 = dp.files.get_mut(&file_id_cia).unwrap();
            dp_files_value_5032.1[6] = PKCS15_FILE_TYPE_TOKENINFO;
        }

        let dp_files_value_app = dp.files.get_mut(&file_id_app).unwrap();
        dp_files_value_app.1[6] = PKCS15_FILE_TYPE_APPDF;
        card.drv_data = Box::into_raw(dp) as p_void;
        /* return the first detected aid */
        if aid.len == 0   &&  aid.value == [0_u8; SC_MAX_AID_SIZE] &&
           aid_len != 0   &&  aid_buf   != [0_u8; SC_MAX_AID_SIZE]
        {
            aid.value = aid_buf;
            aid.len   = aid_len.try_into().unwrap();
        }
//println!("loop completed: for range in DirectoryRange::new");
    }
}

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
    let pkcs15_definitions = dp.pkcs15_definitions;
    if pkcs15_definitions.is_null() { Box::leak(dp); return; }

    for (&key, val) in &dp.files {
        if val.1[6] == PKCS15_FILE_TYPE_APPDF {
            vec_appdf.push(FidPath(key, &val.0[..val.1[1].into()]));
            // log3if!(ctx,f,line!(), fmt1, *key, unsafe { sc_dump_hex(val.1.as_ptr(), 8) });
        }
    }
//println!("{} PKCS#15 application(s) is/are specified. File ids:  {:X?}", vec_appdf.len(), vec_appdf);

    for FidPath(_fid, path_app) in vec_appdf {
//println!("_fid:  {:X}", fid);
//println!("len: {}",  path_app.len());
//println!("path_app: {:X?}", path_app);
    for (_, val) in &dp.files {
    if val.1[6] == PKCS15_FILE_TYPE_ODF && path_app.len()+2 == val.1[1].into() && path_app == &val.0[..path_app.len()] {
//println!("dp.files entry with PKCS15_FILE_TYPE_ODF:  {:X?}", val);
                /* this will mark the file 3F002F00 as PKCS15_FILE_TYPE_DIR (after check that it contains valid data for "PKCS15.DIRRecord")
                   and mark the appDF as PKCS15_FILE_TYPE_APPDF (appDF=="path" extracted from EF.DIR)
            result from asn1_check_version: "4.13"
            ready to inspect
            path of application directory: 0x[3F, 0, 41, 0], fid: 0x4100
            aid of application directory: 0x[41, 43, 4F, 53, 50, 4B, 43, 53, 2D, 31, 35, 76, 31, 2E, 30, 30]
            aid of application directory: ACOSPKCS-15v1.00
            label of application directory: eCert
                */
                    /* do bytes of file 0x2f00 represent DER-encoded "DIRRecord" information (see PKCS#15) ?
                       if yes, then this requirement from PKCS#15 is met and we can extract info about aid and path of PKCS#15 application DF
            61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76
            31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00
                       */
        let size: usize = file_id_se(val.1).into();

        let mut path_5031 = sc_path::default();
        unsafe { sc_path_set(&mut path_5031, SC_PATH_TYPE_PATH, val.0.as_ptr(), val.1[1].into(), 0, -1) };
        unsafe { sc_select_file(card, &path_5031, null_mut()) };
        let mut rbuf = vec![0_u8; size];
        let rv = unsafe { sc_read_binary(card, 0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
        assert!(rv>0);

        for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap()]) {
            let mut structure = null_mut();
            let guard_structure = GuardAsn1Node::new(&mut structure);
            let mut asn1_result = unsafe { asn1_create_element(pkcs15_definitions,
                cstru!(b"PKCS15.PKCS15Objects\0").as_ptr(), *guard_structure) };
            if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                Box::leak(dp);
                return;
            }
            let rbuf2 = &rbuf[range];
// println!("range: {:?}, rbuf2: {:X?}", range, rbuf2);
            let mut error_description = [0x00 as c_char; 129];
            asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

            if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
                println!("asn1_result (asn1_der_decoding): {}, error_description: {:?}", asn1_result, c_str);
                continue;
            }
            for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF {
                let mut buf = [0_u8; SC_MAX_PATH_SIZE];
                let mut outlen = buf.len() as c_int;
                asn1_result = unsafe { asn1_read_value(structure, get_arr(type_).as_ptr(),
                                                       buf.as_mut_ptr() as *mut c_void, &mut outlen) };
                if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                    //println!("asn1_result (asn1_read_value  path): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                    continue;
                }
                let outlen = usize::try_from(outlen).unwrap();
                if outlen < 4 {
                    continue;
                }
                let buf_slice = &buf[..outlen];
                let file_id = file_id_from_path_value(buf_slice);
//println!("path of {}_DF: 0x{:X?}, fid: 0x{:X}", type_, buf_slice, file_id);
                let dp_files_value = &dp.files[&file_id];
                let path_obj = &dp_files_value.0[0..dp_files_value.1[1].into()];
                assert_eq!(buf_slice, path_obj);
                vec_FidPkcs15Type.push(FidPkcs15Type(file_id, type_));
                break;
            } // for type_ in PKCS15_FILE_TYPE_PRKDF..=PKCS15_FILE_TYPE_AODF
        } // for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap()])
// println!("One more drop GuardAsn1Node will follow ...");
    } //  if val.1[6] == PKCS15_FILE_TYPE_ODF && path_app.len()+2 == val.1[1].into() && path_app == &val.0[..path_app.len()]  // for each PKCS15_FILE_TYPE_ODF
    } // for (_, val) in &dp.files
    } // for FidPath(_fid, path_app) in vec_appdf     // for each application
    Box::leak(dp);
    // card.drv_data = Box::into_raw(dp) as p_void;

    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    for FidPkcs15Type(fid, pkcs15_type) in &vec_FidPkcs15Type {
        let mut dp_files_value = dp.files.get_mut(fid).unwrap();
        dp_files_value.1[6] = *pkcs15_type;
    }
    card.drv_data = Box::into_raw(dp) as p_void;
    for elem in vec_FidPkcs15Type {
        if does_pkcs15type_need_filemarking(elem.1) {
            analyze_PKCS15_PKCS15Objects(card, elem)
        }
    }
}


fn does_pkcs15type_need_filemarking(pkcs15_type: u8) -> bool {
    match pkcs15_type {
        PKCS15_FILE_TYPE_PRKDF => true,
        PKCS15_FILE_TYPE_PUKDF => true,
        PKCS15_FILE_TYPE_PUKDF_TRUSTED => true,
        PKCS15_FILE_TYPE_SKDF => false /*false*/,
        PKCS15_FILE_TYPE_CDF => true,
        PKCS15_FILE_TYPE_CDF_TRUSTED => true,
        PKCS15_FILE_TYPE_CDF_USEFUL => true,
        PKCS15_FILE_TYPE_DODF => true,
        PKCS15_FILE_TYPE_AODF => false /*false*/,
        _ => false
    }
}


#[allow(non_snake_case)]
pub fn analyze_PKCS15_PKCS15Objects(card: &mut sc_card, elem: FidPkcs15Type) {

    fn get_arr0<'a>(idx_0: u8) -> &'a CStr {
        match idx_0 {
            PKCS15_FILE_TYPE_PRKDF => cstru!(b"PKCS15.PrivateKeyType\0"),
            PKCS15_FILE_TYPE_PUKDF => cstru!(b"PKCS15.PublicKeyType\0"),
            PKCS15_FILE_TYPE_PUKDF_TRUSTED => cstru!(b"PKCS15.PublicKeyType\0"),
            PKCS15_FILE_TYPE_SKDF => cstru!(b"PKCS15.SecretKeyType\0"),
            PKCS15_FILE_TYPE_CDF => cstru!(b"PKCS15.CertificateType\0"),
            PKCS15_FILE_TYPE_CDF_TRUSTED => cstru!(b"PKCS15.CertificateType\0"),
            PKCS15_FILE_TYPE_CDF_USEFUL => cstru!(b"PKCS15.CertificateType\0"),
            PKCS15_FILE_TYPE_DODF => cstru!(b"PKCS15.DataType\0"),
            PKCS15_FILE_TYPE_AODF => cstru!(b"PKCS15.AuthenticationType\0"),
            _ => cstru!(b"no_type\0"),
        }
    }

    fn get_size(idx_0: u8) -> u8 {
        match idx_0 {
            PKCS15_FILE_TYPE_PRKDF          => 2,
            PKCS15_FILE_TYPE_PUKDF       |
            PKCS15_FILE_TYPE_PUKDF_TRUSTED  => 2,
            PKCS15_FILE_TYPE_SKDF           => 4,
            PKCS15_FILE_TYPE_CDF         |
            PKCS15_FILE_TYPE_CDF_TRUSTED |
            PKCS15_FILE_TYPE_CDF_USEFUL     => 1,
            PKCS15_FILE_TYPE_DODF           => 1,
            PKCS15_FILE_TYPE_AODF           => 3,
            _                               => 1,
        }
    }

    fn get_type(idx_0: u8, idx_1: u8) -> u8 {
        match (idx_0, idx_1) {
            (PKCS15_FILE_TYPE_PRKDF, 0)          => PKCS15_FILE_TYPE_RSAPRIVATEKEY,
            (PKCS15_FILE_TYPE_PRKDF, 1)          => PKCS15_FILE_TYPE_ECCPRIVATEKEY,

            (PKCS15_FILE_TYPE_PUKDF, 0)       |
            (PKCS15_FILE_TYPE_PUKDF_TRUSTED, 0)  => PKCS15_FILE_TYPE_RSAPUBLICKEY,
            (PKCS15_FILE_TYPE_PUKDF, 1)       |
            (PKCS15_FILE_TYPE_PUKDF_TRUSTED, 1)  => PKCS15_FILE_TYPE_ECCPUBLICKEY,

            (PKCS15_FILE_TYPE_SKDF, 0)        |
            (PKCS15_FILE_TYPE_SKDF, 1)        |
            (PKCS15_FILE_TYPE_SKDF, 2)        |
            (PKCS15_FILE_TYPE_SKDF, 3)           => PKCS15_FILE_TYPE_SECRETKEY,

            (PKCS15_FILE_TYPE_CDF, 0)         |
            (PKCS15_FILE_TYPE_CDF_TRUSTED, 0) |
            (PKCS15_FILE_TYPE_CDF_USEFUL, 0)     => PKCS15_FILE_TYPE_CERT,

            (PKCS15_FILE_TYPE_DODF, 0)           => PKCS15_FILE_TYPE_DATA,

            (PKCS15_FILE_TYPE_AODF, 0)           => PKCS15_FILE_TYPE_PIN,
            (PKCS15_FILE_TYPE_AODF, 1)           => PKCS15_FILE_TYPE_BIOMETRIC,
            (PKCS15_FILE_TYPE_AODF, 2)           => PKCS15_FILE_TYPE_AUTHKEY,
            _                                    => PKCS15_FILE_TYPE_NONE,
        }
    }

fn get_arr1<'a>(idx_0: u8, idx_1: u8) -> &'a CStr {
    match (idx_0, idx_1) {
        (PKCS15_FILE_TYPE_PRKDF, 0) => cstru!(b"privateRSAKey.privateRSAKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_PRKDF, 1) => cstru!(b"privateECKey.privateECKeyAttributes.value.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_PUKDF, 0) => cstru!(b"publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_PUKDF, 1) => cstru!(b"publicECKey.publicECKeyAttributes.value.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_PUKDF_TRUSTED, 0) => cstru!(b"publicRSAKey.publicRSAKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_PUKDF_TRUSTED, 1) => cstru!(b"publicECKey.publicECKeyAttributes.value.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_SKDF, 0) => cstru!(b"genericSecretKey.genericSecretKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_SKDF, 1) => cstru!(b"desKey.genericSecretKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_SKDF, 2) => cstru!(b"des2Key.genericSecretKeyAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_SKDF, 3) => cstru!(b"des3Key.genericSecretKeyAttributes.value.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_CDF, 0) => cstru!(b"x509Certificate.x509CertificateAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_CDF_TRUSTED, 0) => cstru!(b"x509Certificate.x509CertificateAttributes.value.indirect.path.path\0"),
        (PKCS15_FILE_TYPE_CDF_USEFUL, 0)  => cstru!(b"x509Certificate.x509CertificateAttributes.value.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_DODF, 0) => cstru!(b"opaqueDO.opaque.indirect.path.path\0"),

        (PKCS15_FILE_TYPE_AODF, 0) => cstru!(b"pinAuthObj.pinAttributes.path.path\0"),
        (PKCS15_FILE_TYPE_AODF, 1) => cstru!(b"biometricAuthObj.biometricAttributes.path.path\0"),
        (PKCS15_FILE_TYPE_AODF, 2) => cstru!(b"authKeyAuthObj.authKeyAttributes.authKeyId\0"), // TODO the buffer [0_u8; SC_MAX_PATH_SIZE] may be too small, needed: [0_u8; 255]
        (_, _) => cstru!(b"no_path\0"),
    }
}

//println!("elem: FidPkcs15Type: {:X?}", elem);
    let dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    let pkcs15_definitions = dp.pkcs15_definitions;
    if pkcs15_definitions.is_null() { Box::leak(dp); return; }
    let mut vec_FidPkcs15Type : Vec<FidPkcs15Type> = Vec::with_capacity(32);

    let mut path_prkdf = sc_path::default();
    let dp_files_value = &dp.files[&elem.0];
    let size : usize = file_id_se(dp_files_value.1).into();
    let path_slice = &dp_files_value.0[..dp_files_value.1[1].into()];
    unsafe { sc_path_set(&mut path_prkdf, SC_PATH_TYPE_PATH, path_slice.as_ptr(), path_slice.len(), 0, -1) };
    unsafe { sc_select_file(card, &path_prkdf, null_mut()) };
    let mut rbuf = vec![0_u8; size];
    let rv = unsafe { sc_read_binary(card, 0, rbuf.as_mut_ptr(), rbuf.len(), 0) };
    assert!(rv>0);

    for range in DirectoryRange::new(&rbuf[..rv.try_into().unwrap() ] ) {
        let mut structure = null_mut();
        let guard_structure = GuardAsn1Node::new(&mut structure);
        let mut asn1_result = unsafe { asn1_create_element(pkcs15_definitions,
            get_arr0(elem.1).as_ptr(), *guard_structure) };
        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
            continue;
        }
        let rbuf2 = &rbuf[range.clone()];
// println!("range: {:?}, rbuf2: {:X?}", range, rbuf2);
        let mut error_description = [0x00 as c_char; 129];
        asn1_result = unsafe { asn1_der_decoding(*guard_structure, rbuf2.as_ptr() as *const c_void,
                               rbuf2.len().try_into().unwrap(), error_description.as_mut_ptr()) };

        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
            let c_str = unsafe { CStr::from_ptr(error_description.as_ptr()) };
            println!("asn1_result (asn1_der_decoding): {}, error_description: {:?}", asn1_result, c_str);
            continue;
        }
        for idx_1 in 0..get_size(elem.1) {
            let mut buf = [0_u8; SC_MAX_PATH_SIZE];
            let mut outlen = buf.len() as c_int;
            asn1_result = unsafe { asn1_read_value(structure, get_arr1(elem.1, idx_1).as_ptr(),
                                                   buf.as_mut_ptr() as *mut c_void, &mut outlen) };
            if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                //println!("asn1_result (asn1_read_value  get_arr1()): {}, error_description: {:?}", asn1_result, unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                continue;
            }
            let buf_slice = &buf[..outlen.try_into().unwrap()];
//println!("KeyAttributes.value.indirect.path.path: 0x{:02X?}", buf_slice);
            vec_FidPkcs15Type.push(FidPkcs15Type(file_id_from_path_value(buf_slice), get_type(elem.1, idx_1)) );
            break;
        }
    }
    Box::leak(dp);
//println!("vec_FidPkcs15Type: {:X?}", vec_FidPkcs15Type);
    let mut dp = unsafe { Box::from_raw(card.drv_data as *mut DataPrivate) };
    for FidPkcs15Type(fid, pkcs15_type) in &vec_FidPkcs15Type {
        let mut dp_files_value = dp.files.get_mut(fid).unwrap();
        dp_files_value.1[6] = *pkcs15_type;
    }
    card.drv_data = Box::into_raw(dp) as p_void;
}

/*
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
    let pkcs15_definitions = dp.pkcs15_definitions;
    if pkcs15_definitions.is_null() { Box::leak(dp); return; }
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
                        let mut asn1_result = unsafe { asn1_create_element(pkcs15_definitions, source_name.as_ptr(), *guard_structure) };
                        if ASN1_SUCCESS != asn1_result.try_into().unwrap() {
                            println!("### Error in structure creation: {:?}", unsafe { CStr::from_ptr(asn1_strerror(asn1_result)) });
                        }
                        else {
                            let rbuf2 = &rbuf[range];
// println!("range: {:?}, rbuf2: {:X?}", range, rbuf2);
                            let mut error_description = [0x00 as c_char; 129];
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
*/

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
/*
Header/meta infos (FCI):
6F 1E 83 02 2F 00 88 01 00 8A 01 05 82 02 01 00 80 02 00 21 8C 08 7F 01 FF 01 01 FF 01 00 AB 00

Content:
61 1F 4F 10 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30 50 05 65 43 65 72 74 51 04 3F 00 41 00

name: dirRecord  type: SEQUENCE
  name: aid  type: OCT_STR  value: 41434f53504b43532d313576312e3030
  name: label  type: UTF8_STR  value: eCert
  name: path  type: OCT_STR  value: 3f004100
*/
