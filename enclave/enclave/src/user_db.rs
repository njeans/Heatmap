use std::string::{String,ToString};
use std::vec::Vec;
use std::sync::{SgxRwLock, SgxRwLockWriteGuard};
use std::collections::HashMap;
use hex::FromHex;

use crate::serde::{Serialize, Deserialize};
use crate::lazy_static::lazy_static;

use crate::{SIGNING_KEY,ENCRYPT_KEY};
use crate::types::{PubKey, DhKey};

use crate::types::{EnclaveError, EnclaveErrorType::SgxError};

use crate::traits::EthereumAddress;
use crate::multipart_data::MultipartDatabase;
use crate::crypto;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserInfo {
    pub publickey: String,
    pub userid: String,
}

pub const USER_DB_NAME: &str = "users";
pub const MAX_USER_SIZE: usize = 7; //manually calculated based on Seal size and size of userinfo struct
pub const USERID_SIZE: usize = 5;
pub const PUBLICKEY_SIZE: usize = 128;

lazy_static! { pub static ref USER_KEYS: SgxRwLock<HashMap<[u8; 5], (String, DhKey)>> = SgxRwLock::new(HashMap::new()); }

pub fn init_user_db(database_str: &[u8]) -> Result<(), EnclaveError> {
    println!("user_db.init_user_db");
    let user_info: Vec<UserInfo> = match serde_json::from_slice(&database_str) {
        Ok(x) => x,
        Err(e) => {
            let trace = format!("user_db.init_user_db serde_json::from_slice(&database_str)");
            return Err(EnclaveError{trace, err:SgxError{description: e.to_string()}});
        }
    };
    println!("user_db.init_user_db user_info.len() {:?}", user_info.len());

    for ui in &user_info {
        if ui.userid.len() != USERID_SIZE {
            let description = format!("wrong user id size {:?} != {:?}", ui.userid.len(), USERID_SIZE);
            let trace = format!("user_db.init_user_db ui.userid.len() != USERID_SIZE");
            return Err(EnclaveError{trace, err:SgxError{description}});
        }
        if ui.publickey.len() != PUBLICKEY_SIZE {
            let description = format!("wrong publickey size {:?} != {:?}", ui.publickey.len(), PUBLICKEY_SIZE);
            let trace = format!("user_db.init_user_db ui.publickey.len() != PUBLICKEY_SIZE");
            return Err(EnclaveError{trace, err:SgxError{description}});
        }
    }

    let mut user_db = MultipartDatabase::<UserInfo>::create(String::from(USER_DB_NAME), MAX_USER_SIZE, false, user_info.clone());
    match user_db.save() {
        Ok(_) => {},
        Err(e) => {
            return Err(e);
        }
    }
    setup_user_key_internal(user_info)
}

pub fn load_user_db() -> Result<(), EnclaveError> {
    println!("user_db.load_user_db");
    let mut user_db = MultipartDatabase::<UserInfo>::load(String::from(USER_DB_NAME))?;
    let user_info = user_db.get_all()?;
    setup_user_key_internal(user_info)
}

pub fn get_enclave_data() -> Result<Vec<u8>, EnclaveError>{
    println!("user_db.get_enclave_data");
    let mut data_db = MultipartDatabase::<UserInfo>::load(String::from(USER_DB_NAME))?;
    let user_info = data_db.get_all()?;
    let user_addresses = user_info.iter().map(|x| x.publickey.address_string() ).collect::<Vec<_>>();
    let serialized_results = serde_json::to_string(&user_addresses).map_err(|err| EnclaveError{ trace: "user_db.get_enclave_data serde_json::to_string(&user_addresses)".to_string(), err:SgxError{description:err.to_string()}})?;
    let mut results:Vec<u8> = serialized_results.into();
    let mut vec_u8_results:Vec<u8>  = "ENCLAVE_DATA:".as_bytes().to_vec();
    vec_u8_results.append(&mut results);
    Ok(vec_u8_results)
}

pub fn setup_user_key_internal(user_info: Vec<UserInfo>) -> Result<(), EnclaveError>{
    let mut user_info_lock = match USER_KEYS.write(){
        Ok(x) => x,
        Err(e) => {
            let trace = format!("user_db.setup_user_key_internal USER_KEYS.write()");
            return Err(EnclaveError{ trace, err:SgxError{description:e.to_string()}});
        }
    };
    for u in user_info {
        let pubkey_bytes = hex_to_bytes(&u.publickey);
        let userid_bytes = u.userid.as_bytes();
        let mut pubkey:PubKey= [0;64];
        pubkey.copy_from_slice(&pubkey_bytes[0..64]);
        let mut userid:[u8;5] = [0;5];
        userid.copy_from_slice(&userid_bytes[0..5]);

        let enc_key = ENCRYPT_KEY.derive_key(&pubkey)?;
        user_info_lock.insert(userid, (u.publickey, enc_key));
    }
    Ok(())
}

pub fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    let input_chars: Vec<_> = hex_string.chars().collect();

    input_chars
        .chunks(2)
        .map(|chunk| {
            let first_byte = chunk[0].to_digit(16).unwrap();
            let second_byte = chunk[1].to_digit(16).unwrap();
            ((first_byte << 4) | second_byte) as u8
        })
        .collect()
}