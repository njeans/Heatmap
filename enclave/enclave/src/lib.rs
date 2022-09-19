// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "heatmapenclave"]
#![crate_type = "staticlib"]
#![no_std]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_types;
extern crate sgx_rand;
extern crate sgx_tseal;

#[macro_use]
extern crate lazy_static;

extern crate serde;
extern crate serde_json;
extern crate rand_hc;
extern crate rand_core;
extern crate aligned_cmov;

extern crate mc_oblivious_ram;
extern crate mc_oblivious_traits;
extern crate mc_fog_ocall_oram_storage_trusted;
extern crate rustc_hex as hex;

mod user_db;
mod heatmap;
mod crypto;
mod types;
mod traits;
mod storage;
mod multipart_data;

use std::{slice};
use std::path::{Path, PathBuf};
use std::string::{String, ToString};

use sgx_tse::rsgx_create_report;
use sgx_types::{
    sgx_status_t,
    sgx_report_t,
    sgx_target_info_t,
    sgx_report_data_t
};


use user_db::{init_user_db, load_user_db, get_enclave_data};
use heatmap::{add_personal_data_internal, retrieve_heatmap_oram, reset_heatmap, get_audit_data};
use crypto::asymmetric;
use types::{EnclaveReturn, EnclaveError, EnclaveErrorType::{CryptoErrorType, SgxError}, CryptoError};
use types::{PubKey, DhKey};
use traits::{EthereumAddress, SliceCPtr};


lazy_static! {
    pub(crate) static ref SIGNING_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper("sign".to_string());
    pub(crate) static ref ENCRYPT_KEY: asymmetric::KeyPair = get_sealed_keys_wrapper("encrypt".to_string());
}

#[no_mangle]
pub extern "C" fn ecall_get_registration_quote(target_info: &sgx_target_info_t, real_report: &mut sgx_report_t) -> sgx_status_t {
    create_report_with_data(&target_info, real_report, &SIGNING_KEY.get_pubkey())
}

#[no_mangle]
pub extern "C" fn ecall_get_signing_address(pubkey: &mut [u8; 20]) { pubkey.copy_from_slice(&SIGNING_KEY.get_pubkey().address()); }

#[no_mangle]
pub extern "C" fn ecall_get_encryption_pubkey(sig: &mut [u8; 65], pubkey: &mut [u8; 64]) -> EnclaveReturn {
    let signature = match SIGNING_KEY.sign(&ENCRYPT_KEY.get_pubkey()) {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_get_encryption_pubkey SIGNING_KEY.sign err {:?}", e);
            return e.into();
        },
    };
    sig.copy_from_slice(&signature);
    pubkey.copy_from_slice(&ENCRYPT_KEY.get_pubkey());
    EnclaveReturn::Success
}


#[no_mangle]
extern "C" {
    fn ocall_save_to_memory(ptr: *mut u64, data_ptr: *const u8, data_len: usize) -> sgx_status_t;
    fn allocate_oram_storage(count: u64, data_size: u64, meta_size: u64, id_out: *mut u64) -> sgx_status_t;
    fn release_oram_storage(id: u64) -> sgx_status_t;
    fn checkout_oram_storage( id: u64, idx: *const u64, idx_len: usize, databuf: *mut u64,
        databuf_len: usize, metabuf: *mut u64, metabuf_len: usize) -> sgx_status_t;
    fn checkin_oram_storage( id: u64, idx: *const u64, idx_len: usize, databuf: *const u64,
                                databuf_len: usize, metabuf: *const u64, metabuf_len: usize) -> sgx_status_t;
}

fn get_sealed_keys_wrapper(name: String) -> asymmetric::KeyPair {
    let mut path_buf = PathBuf::new();
    // add the filename to the path: `keypair.sealed`
    path_buf.push(name);
    path_buf.push(".keypair.sealed");
    let sealed_path = path_buf.to_str().unwrap();

    // TODO: Decide what to do if failed to obtain keys.
    match storage::get_sealed_keys(sealed_path) {
        Ok(key) => key,
        Err(err) => panic!("Failed obtaining keys: {:?}", err),
    }
}


#[no_mangle]
pub unsafe extern "C" fn ecall_init_user_db(
    database_ptr: *const u8,
    database_len: usize) -> EnclaveReturn {
    println!("ecall_init_user_db");

    if database_len == 0 {
        println!("ecall_init_user_db load_user_db");
        return match load_user_db() {
            Ok(_) => EnclaveReturn::Success,
            Err(e) => {
                println!("ecall_init_user_db load_user_db err {:?}", e);
                e.into()
            }
        };
    }

    let database = slice::from_raw_parts(database_ptr, database_len);
    println!("ecall_init_user_db database {:?}",database);

    let user_info = match init_user_db(database) {
        Ok(x) => x,
        Err(e) =>  {
            println!("ecall_init_user_db init_user_db(database) err {:?}", e);
            return e.into();
        },
    };
    println!("ecall_init_user_db user_info {:?}",user_info);

    match heatmap::reset_heatmap(){
        Ok(_) => {},
        Err(e) => {
            println!("ecall_init_user_db heatmap::reset_heatmap() err {:?}", e);
            return e.into();
        },
    };

    EnclaveReturn::Success
}

fn get_io_key(userid: [u8; 5]) -> Result<(String, DhKey), EnclaveError> {
    let user_keys = match user_db::USER_KEYS.read() {
        Ok(x)=>x,
        Err(e)=>{
            return Err(EnclaveError{trace:"lib.get_io_key  user_db::USER_KEYS.read()".to_string(), err:SgxError{description:e.to_string()}});

        }
    };
    let (pubkey, io_key) = match user_keys.get(&userid) {
        Some(x) => x,
        None => {
            return Err(EnclaveError{trace:"lib.get_io_key  user_db::USER_KEYS.read()".to_string(), err:CryptoErrorType{err:CryptoError::MissingKeyError{ key_type: "DH Key"}}});
        }
    };
    Ok((pubkey.clone(),*io_key))
}

#[no_mangle]
pub unsafe extern "C" fn ecall_add_personal_data(
    user_id_ptr: *const u8,
    user_id_len: usize,
    encrypted_data_ptr: *const u8,
    encrypted_data_len: usize) -> EnclaveReturn {
    println!("ecall_add_personal_data");

    if user_id_len != 5 {
        println!("ecall_add_personal_data wrong user_id_len {:?}",user_id_len);
        return EnclaveReturn::InputError;
    }
    let userid = slice::from_raw_parts(user_id_ptr, user_id_len);
    let encrypted_data = slice::from_raw_parts(encrypted_data_ptr, encrypted_data_len);
    println!("ecall_add_personal_data userid {:?}", userid);

    let mut uid = [0;5];
    uid.copy_from_slice(&userid[0..5]);

    let (pubkey,io_key)= match get_io_key(uid) {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_add_personal_data get_io_key err {:?}",e);
            return e.into()
        },
    };

    match add_personal_data_internal(encrypted_data, &io_key, pubkey){
        Ok(_) => EnclaveReturn::Success,
        Err(e) => {
            println!("ecall_add_personal_data add_personal_data_internal err {:?}",e);
            e.into()
        }
    }

}

#[no_mangle]
pub unsafe extern "C" fn ecall_retrieve_heatmap(
    sig: &mut [u8; 65],
    serialized_ptr: *mut u64,
    out_ptr_size: *mut usize) -> EnclaveReturn {

    // Initialize the pointer, in case we error out, it points somewhere,
    // otherwise we get a segmentation fault when we throw an error
    let empty = [0u8];
    *serialized_ptr = match save_to_untrusted_memory(&empty) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_retrieve_heatmap save_to_untrusted_memory err {:?}", e);
            return e.into();
        },
    };

    let heatmap = match retrieve_heatmap_oram() {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_retrieve_heatmap load_user_db err {:?}", e);
            return e.into();
        },
    };
    let heatmap_len = heatmap.len();
    unsafe { std::ptr::copy( &heatmap_len, out_ptr_size, 1) }
    *serialized_ptr = match save_to_untrusted_memory(&heatmap[..]) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_retrieve_heatmap save_to_untrusted_memory err {:?}", e);
            return e.into();
        },
    };

    let signature = match ENCRYPT_KEY.sign(&heatmap) {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_retrieve_heatmap ENCRYPT_KEY.sign(&heatmap) err {:?}", e);
            return e.into();
        },
    };
    sig.copy_from_slice(&signature);

    EnclaveReturn::Success
}


#[no_mangle]
pub unsafe extern "C" fn ecall_get_enclave_data(
    sig: &mut [u8; 65],
    serialized_ptr: *mut u64,
    out_ptr_size: *mut usize) -> EnclaveReturn {

    // Initialize the pointer, in case we error out, it points somewhere,
    // otherwise we get a segmentation fault when we throw an error
    let empty = [0u8];
    *serialized_ptr = match save_to_untrusted_memory(&empty) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_get_enclave_data save_to_untrusted_memory err {:?}", e);
            return e.into();
        },
    };

    let data = match get_enclave_data() {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_get_enclave_data get_enclave_data() err {:?}",e);
            return e.into()
        }
    };

    let data_len = data.len();
    unsafe { std::ptr::copy( &data_len, out_ptr_size, 1) }
    *serialized_ptr = match save_to_untrusted_memory(&data[..]) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_get_enclave_data save_to_untrusted_memory err {:?}",e);
            return e.into()
        }
    };
    println!("ecall_get_enclave_data signing {:?}", data);
    let signature = match ENCRYPT_KEY.sign_eth(&data) {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_get_enclave_data ENCRYPT_KEY.sign(&data) err {:?}",e);
            return e.into()
        }
    };
    sig.copy_from_slice(&signature);
    println!("signature={:?}",&signature);
    println!("ecall_get_enclave_data signature {:?}", &signature);

    EnclaveReturn::Success
}


#[no_mangle]
pub unsafe extern "C" fn ecall_get_audit_data(
    sig: &mut [u8; 65],
    serialized_ptr: *mut u64,
    out_ptr_size: *mut usize) -> EnclaveReturn {
    // Initialize the pointer, in case we error out, it points somewhere,
    // otherwise we get a segmentation fault when we throw an error
    let empty = [0u8];
    *serialized_ptr = match save_to_untrusted_memory(&empty) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_get_audit_data save_to_untrusted_memory err {:?}", e);
            return e.into();
        },
    };

    let data = match get_audit_data() {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_get_audit_data get_audit_data() err {:?}",e);
            return e.into()
        }
    };

    let data_len = data.len();
    unsafe { std::ptr::copy( &data_len, out_ptr_size, 1) }
    *serialized_ptr = match save_to_untrusted_memory( &data[..]) {
        Ok(ptr) => ptr,
        Err(e) => {
            println!("ecall_get_audit_data save_to_untrusted_memory err {:?}",e);
            return e.into()
        }
    };
    println!("ecall_get_audit_data signing {:?}", data);
    let signature = match ENCRYPT_KEY.sign_eth(&data) {
        Ok(x) => x,
        Err(e) => {
            println!("ecall_get_audit_data ENCRYPT_KEY.sign err {:?}",e);
            return e.into()
        }
    };
    sig.copy_from_slice(&signature);
    println!("signature={:?}",&signature);
    println!("ecall_get_audit_data signature {:?}", &signature);

    match heatmap::reset_heatmap(){
        Ok(_) => {},
        Err(e) => {
            println!("ecall_get_audit_data reset_heatmap err {:?}",e);
            return e.into()
        }
    };

    EnclaveReturn::Success
}


pub fn create_report_with_data(target_info: &sgx_target_info_t, out_report: &mut sgx_report_t, sign_key: &PubKey) -> sgx_status_t {
    let mut report_data = sgx_report_data_t::default();

    report_data.d[..64].copy_from_slice(sign_key);

    match rsgx_create_report(&target_info, &report_data) {
        Ok(r) => {
            *out_report = r;
            sgx_status_t::SGX_SUCCESS
        }
        Err(r) => {
            println!("[-] Enclave: error creating report");
            sgx_status_t::SGX_SUCCESS
        }
    }
}

pub fn save_to_untrusted_memory(data: &[u8]) -> Result<u64, EnclaveError> {
    let mut ptr = 0u64;
    match unsafe { ocall_save_to_memory(&mut ptr as *mut u64, data.as_c_ptr(), data.len()) } {
        sgx_status_t::SGX_SUCCESS => Ok(ptr),
        e => Err(e.into()),
    }
}