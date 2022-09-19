use std::vec::Vec;
use std::string::{String, ToString};
use std::collections::HashMap;
use std::borrow::ToOwned;


use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use aligned_cmov::{A64Bytes, ArrayLength};
use aligned_cmov::typenum::{U8192, U2048, U4096, U64};
use rand_hc::Hc128Rng;
use rand_core::SeedableRng;

use mc_oblivious_ram::PathORAM4096Z4Creator;
use mc_oblivious_traits::{rng_maker,ORAMCreator,ORAMStorageCreator,ORAM};
use mc_fog_ocall_oram_storage_trusted::OcallORAMStorageCreator;

use crate::types::{PubKey, DhKey};
use crate::types::{EnclaveError, EnclaveErrorType::{SgxError, CryptoErrorType, InvalidInput}, CryptoError};
use crate::traits::EthereumAddress;
use crate::crypto::symmetric::decrypt;
use crate::multipart_data::MultipartDatabase;

pub const USER_DATA_NAME: &str = "data";
pub const AUDIT_DATA_NAME: &str = "audit";

pub const MAX_DATA_SIZE: usize = 13;       // Manually calculated max dependent on SEAL_LOG_SIZE
pub const MAX_AUDIT_DATA_SIZE: usize = 36;       // Manually calculated max dependent on SEAL_LOG_SIZE

//Beijing numbers
pub const LONG_MIN: f64 = 116.0;
pub const LONG_MAX: f64 = 116.75;
pub const LAT_MIN: f64 = 39.5;
pub const LAT_MAX: f64 = 40.25;
pub const HEATMAP_GRANULARITY: u64 = 50;
pub const HEATMAP_COUNT_THRESHOLD: u16 = 2;

pub const TIMEFRAME_GRANULARITY: f64 = 10.0; // this is in minutes
const STASH_SIZE: usize = 16;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: f64,
    lng: f64,
    startTS: u64,
    endTS: u64,
    testResult: bool
}

pub fn decrypt_data(data: &[u8], key: &DhKey) -> Result<Vec<u8>, EnclaveError> {
    if data.is_empty() {
        Err(EnclaveError{trace: "heatmap.decrypt_data data.is_empty()".to_string(),err:CryptoErrorType{err:CryptoError::DecryptionError}})
    } else {
        Ok(decrypt(data, key)?)
    }
}

pub fn geo_time_index(geo_time: &GeolocationTime) -> Result<u64, EnclaveError>{
    if geo_time.lat < LAT_MIN || geo_time.lat > LAT_MAX || geo_time.lng < LONG_MIN || geo_time.lng > LONG_MAX{
        let description = format!("geo_time is out of bounds lat {:?} lng {:?}",geo_time.lat,geo_time.lng);
        return Err(EnclaveError{trace:"heatmap.geo_time_index if geo_time.lat < LAT_MIN || ...".to_string(), err:InvalidInput{description}});
    }
    let side_length_lat = HEATMAP_GRANULARITY as f64/(LAT_MAX- LAT_MIN);
    let side_length_long = HEATMAP_GRANULARITY as f64/(LONG_MAX- LONG_MIN);
    let lat: u64 = ((geo_time.lat - LAT_MIN)*side_length_lat).round() as u64;
    let lng: u64 = ((geo_time.lng - LONG_MIN)*side_length_long).round() as u64;
    Ok(lat*HEATMAP_GRANULARITY + lng)
}

pub fn strip_heatmap(x: HashMap<String, u16>) -> HashMap<String, u16> {
    return x.into_iter()
        .filter(|&(_, v)| v > HEATMAP_COUNT_THRESHOLD)
        .collect();
}

pub fn reset_heatmap() -> Result<(), EnclaveError> {
    let data: Vec<GeolocationTime> = Vec::new();
    match MultipartDatabase::<GeolocationTime>::create(String::from(USER_DATA_NAME),MAX_DATA_SIZE, true, data).save() {
        Ok(_) => {}
        Err(mut e) => {
            let trace = format!("{} || heatmap.reset_heatmap MultipartDatabase::<GeolocationTime>::create(USER_DATA_NAME).save()",e.trace);
            e.trace = trace;
            return Err(e)
        }
    }

    let audit_data: Vec<String> = Vec::new();
    match MultipartDatabase::<String>::create(String::from(AUDIT_DATA_NAME), MAX_AUDIT_DATA_SIZE, true, audit_data).save() {
        Ok(_) => {}
        Err(mut e) => {
            let trace = format!("{} || heatmap.reset_heatmap MultipartDatabase::<GeolocationTime>::create(AUDIT_DATA_NAME).save()",e.trace);
            e.trace = trace;
            return Err(e)
        }
    }

    Ok(())
}

pub fn add_personal_data_internal(encrypted_data: &[u8], dhKey: &DhKey, publickey: String)  -> Result<(), EnclaveError> {
    let decrypted_data = match decrypt_data(encrypted_data, dhKey) {
        Ok(v) => v,
        Err(mut e) => {
            let trace = format!("{} || heatmap.add_personal_data_internal decrypt_data(encrypted_data, dhKey)",e.trace);
            e.trace = trace;
            return Err(e);
        }
    };

    let mut audit_db = MultipartDatabase::<String>::load(String::from(AUDIT_DATA_NAME))?;
    let audit_data:Vec<String> = Vec::from([publickey]);
    match audit_db.append(audit_data) {
        Ok(_) => {}
        Err(mut e) => {
            let trace = format!("{} || heatmap.add_personal_data_internal audit_db.append(audit_data)",e.trace);
            e.trace = trace;
            return Err(e)
        }
    };
    let input_data: Vec<GeolocationTime> = serde_json::from_slice(&decrypted_data).unwrap();
    let mut data_db = MultipartDatabase::<GeolocationTime>::load(String::from(USER_DATA_NAME))?;
    match data_db.append(input_data) {
        Ok(_) => {}
        Err(mut e) => {
            let trace = format!("{} || heatmap.add_personal_data_internal data_db.append(input_data)",e.trace);
            e.trace = trace;
            return Err(e)
        }
    };

    Ok(())
}

pub fn retrieve_heatmap_oram() -> Result<Vec<u8>, EnclaveError> {
    println!("heatmap.retrieve_heatmap_oram");

    let mut data_db = MultipartDatabase::<GeolocationTime>::load(String::from(USER_DATA_NAME))?;

    let mut maker = rng_maker(get_seeded_rng());
    let oram_size = get_next_power_2(HEATMAP_GRANULARITY.pow(2));
    let mut oram = PathORAM4096Z4Creator::<RngType, OcallORAMStorageCreator>::create(
        oram_size,
        STASH_SIZE,
        &mut maker,
    );

    for i in 0..data_db.len(){
        let data = data_db.get(i)?;
        for geo_time in data.iter(){
            let oram_index = match geo_time_index(geo_time) {
                Ok(v) => v,
                Err(mut e) => {
                    let trace = format!("{} || heatmap.retrieve_heatmap_oram geo_time_index(geo_time)",e.trace);
                    e.trace = trace;
                    return Err(e)
                }
            };
            let mut bin_count = u64_a64(oram.read(oram_index))+1;
            println!("retrieve_heatmap_oram oram_index {:?} bin_count {:?}",oram_index, bin_count);
            oram.write(oram_index, &a64_u64(bin_count));
        }
    }


    let oram_len = oram.len();
    let mut heatmap:HashMap<String,u64> = HashMap::new();
    for oram_index in 0..oram_len{
        let count = u64_a64(oram.read(oram_index));
        let bin_str = format!("{},{}",oram_index/HEATMAP_GRANULARITY,oram_index%HEATMAP_GRANULARITY);
        // println!("retrieve_heatmap_oram add oram_index {:?} bin_str {:?} count {:?}",oram_index, bin_str, count);
        if count >= HEATMAP_COUNT_THRESHOLD.into() {
            let bin_str = format!("{},{}",oram_index/HEATMAP_GRANULARITY,oram_index%HEATMAP_GRANULARITY);
            println!("\tretrieve_heatmap_oram add bin_str {:?} count {:?}",bin_str, count);
            heatmap.insert(bin_str,count);
        }
    }

    let serialized_results = serde_json::to_string(&heatmap).map_err(|e| EnclaveError{trace: "heatmap.retrieve_heatmap_oram serde_json::to_string(&heatmap)".to_string(), err: SgxError{description:format!("error serializing heatmap {:?}", e)}})?;
    let vec_u8_results:Vec<u8> = serialized_results.into();

    Ok(vec_u8_results)
}

pub fn get_audit_data() -> Result<Vec<u8>, EnclaveError>{
    let mut audit_data_db = MultipartDatabase::<String>::load(String::from(AUDIT_DATA_NAME))?;
    let audit_data: Vec<String> = audit_data_db.get_all()?;

    let user_addresses = audit_data.iter().map(|x| x.address_string()).collect::<Vec<_>>();
    println!("heatmap.get_audit_data {:?} {:?}", user_addresses.len(),user_addresses);
    let serialized_results = serde_json::to_string(&user_addresses).map_err(|e| EnclaveError{trace: "heatmap.get_audit_data serde_json::to_string(&user_addresses)".to_string(), err: SgxError{description:format!("error serializing user_addresses {:?}", e)}})?;
    let mut results:Vec<u8> = serialized_results.into();
    let mut vec_u8_results:Vec<u8>  = "AUDIT_DATA:".as_bytes().to_vec();
    vec_u8_results.append(&mut results);
    Ok(vec_u8_results)
}

fn get_next_power_2(x: u64) -> u64 {
    let mut exp: u32 = 0;
    let two: u64 = 2;
    let mut val: u64 = two.pow(exp);
    while val < x {
        exp += 1;
        val = two.pow(exp);
    }
    val
}

fn a64_u64<N: ArrayLength<u8>>(val: u64) -> A64Bytes<N> {
    let mut result = A64Bytes::<N>::default();
    let val = val.to_be_bytes();
    // let mut i = 0;
    for i in 0..8 {
        result[i] = val[i];
    }
    result
}

fn u64_a64<N: ArrayLength<u8>>(val: A64Bytes<N>) -> u64 {
    let mut val_slice: [u8; 8] = [0;8];
    // println!("u64_a64 len {:?} val {:?}",val.len(), val);
    val_slice.copy_from_slice(&val.as_slice()[0..8]);
    u64::from_be_bytes(val_slice)
}

pub type RngType = Hc128Rng;
pub fn get_seeded_rng() -> RngType {
    RngType::from_seed([7u8; 32])
}