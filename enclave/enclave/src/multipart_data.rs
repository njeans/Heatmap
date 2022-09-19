use std::string::{String,ToString};
use std::vec::Vec;
use std::str;
use std::cmp;

use std::untrusted::fs::File;
use std::untrusted::path::PathEx;
use std::path::{Path, PathBuf};
use std::io::{Read, Write};

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};

use crate::serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::types::{EnclaveError, EnclaveErrorType::{SgxError, UnsealError}};
use crate::storage::SEAL_LOG_SIZE;

#[derive(Serialize, Deserialize, Clone)]
pub struct MultipartDatabase<T> {
    name: String,
    mutable: bool,
    max_size: usize,
    saved: bool,
    len: usize,
    parts: Vec<Part<T>>
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Part<T> {
    index: usize,
    data: Vec<T>,
}

impl <T: Serialize+ for<'de> Deserialize<'de> + Clone> MultipartDatabase<T> {
    pub fn create(name: String, max_size: usize, mutable:bool, data: Vec<T>) -> MultipartDatabase<T> {
        println!("multipart_data.create name {:?} max_size {:?} mutable {:?} data.len {:?}",
                 &name, max_size, mutable, data.len());
        let mut num_parts = data.len() / max_size;
        if data.len() % max_size != 0 {
            num_parts+=1
        }
        let mut parts = Vec::new();
        for i in 0..num_parts {
            let start_i = i * max_size;
            let end_i = cmp::min(start_i + max_size, data.len());

            let new_part = Part{index: i, data:(&data[start_i..end_i]).to_vec()};
            parts.push(new_part);
        }
        MultipartDatabase::<T>{name, mutable, max_size, saved: false, len: parts.len(), parts}
    }

    pub fn load(name: String) -> Result<MultipartDatabase<T>, EnclaveError> {
        println!("multipart_data.load name {:?}", name);
        let sealed_path = MultipartDatabase::<T>::_get_path(name);
        if !sealed_path.exists() {
            let description = format!("sealed_path for {:?} does not exist",sealed_path);
            return Err(EnclaveError{trace:"multipart_data.load !sealed_path.exists()".to_string(),err:SgxError{description}});
        }
        let sealed_path = match sealed_path.to_str() {
            Some(x) => x,
            None => {
                let description = format!("could not convert sealed_path {:?} to str",sealed_path);
                return Err(EnclaveError{trace:"multipart_data.load sealed_path.to_str()".to_string(), err: SgxError{description}});
            }
        };
        let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
        match load_sealed_data(&sealed_path, &mut sealed_log_out) {
            Ok(_) => {

            },
            Err(e) => {
                let trace = format!("{} || multipart_data.load load_sealed_data(&sealed_path, &mut sealed_log_out)", e.trace);
                return Err(EnclaveError{trace, err:e.err});
            }
        };

        let sealed_log = sealed_log_out.as_mut_ptr();
        let db_info:MultipartDatabase<T> = match recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE as u32) {
            Ok(x) => x,
            Err(e) => {
                let trace = format!("{} || multipart_data.load recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE)", e.trace);
                return Err(EnclaveError{trace, err:e.err});
            }
        };

        let db = MultipartDatabase{name: db_info.name, mutable: db_info.mutable, max_size:db_info.max_size, saved: db_info.saved, len: db_info.len, parts: Vec::new()};
        return Ok(db);
    }

    pub fn save(&mut self) -> Result<(),EnclaveError> {
        println!("multipart_data.save {:?}", self.name);
        if self.saved && !self.mutable {
            let description = format!("database {:?} was already saved and is not mutable saved {:?} mutable {:?}", self.name, self.saved, self.mutable);
            return Err(EnclaveError{trace:"multipart_data.save self.saved && !self.mutable".to_string(), err: SgxError{description}});
        }
        for part in &self.parts {
            match self.save_part(part) {
                Ok(_) => {},
                Err(e) => {
                    let trace = format!("{} || multipart_data.save self.save_part(part)", e.trace);
                    return Err(EnclaveError{trace, err:e.err});
                }
            }
        }

        self.saved = true;
        match self.save_db() {
            Ok(_) => {},
            Err(e) => {
                self.saved = false;
                let trace = format!("{} || multipart_data.save self.save_db()", e.trace);
                return Err(EnclaveError{trace, err:e.err});
            }
        }

        Ok(())
    }

    pub fn append(&mut self, data:Vec<T>) -> Result<(),EnclaveError>{
        println!("multipart_data.append name {:?} data.len {:?}", self.name, data.len());
        if self.saved && !self.mutable {
            let description = format!("database {:?} was already saved and is not mutable saved {:?} mutable {:?}", self.name, self.saved, self.mutable);
            return Err(EnclaveError{trace:"multipart_data.append self.saved && !self.mutable".to_string(), err: SgxError{description}});
        }
        let mut num_append = 0;
        let mut next_part_index = 0;
        if self.len > 0 {
            let last_part_index = self.len - 1;
            next_part_index = self.len;
            let sealed_path = self.get_part_path(last_part_index as usize);
            let sealed_path: &str = match sealed_path.to_str() {
                Some(x) => x,
                None => {
                    let description = format!("could not convert sealed_path {:?} to str",sealed_path);
                    return Err(EnclaveError{err:SgxError {description},trace:"multipart_data.append sealed_path.to_str()".to_string()});
                }
            };
            let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
            match load_sealed_data(&sealed_path, &mut sealed_log_out) {
                Ok(_) => {},
                Err(e) => {
                    let trace = format!("{} || multipart_data.append load_sealed_data(&sealed_path, &mut sealed_log_out)", e.trace);
                    return Err(EnclaveError{trace, err:e.err});
                }
            };

            let sealed_log = sealed_log_out.as_mut_ptr();
            let mut last_part = match recover_sealeddata_for_serializable_part(sealed_log, SEAL_LOG_SIZE as u32) {
                Ok(x) => x,
                Err(e) => {
                    let trace = format!("{} || multipart_data.append recover_sealeddata_for_serializable(sealed_log, SEAL_LOG_SIZE)", e.trace);
                    return Err(EnclaveError{trace, err:e.err});
                }
            };

            num_append = cmp::min(data.len(), self.max_size - last_part.data.len());
            if num_append > 0 {//can add at least one entry to this part
                for i in 0..num_append {
                    last_part.data.push(data[i].clone());
                }
                match self.save_part(&last_part) {
                    Ok(_) => {},
                    Err(e) => {
                        let trace = format!("{} || multipart_data.append self.save_part(&last_part)", e.trace);
                        return Err(EnclaveError{trace, err:e.err});
                    }
                }
            }
        }

        let num_left = data.len()-num_append;
        let mut num_new_parts = num_left / self.max_size;
        if num_left % self.max_size != 0 {
            num_new_parts+=1
        }
        if num_new_parts > 0 {
            for i in 0..num_new_parts {
                let index = next_part_index+i as usize;

                let start_i = num_append + (i * self.max_size);
                let end_i =cmp::min(start_i + self.max_size, data.len());

                let new_part = Part{index, data:(&data[start_i..end_i]).to_vec()};
                match self.save_part(&new_part) {
                    Ok(_) => {},
                    Err(e) => {
                        let trace = format!("{} || multipart_data.append self.save_part(&new_part)", e.trace);
                        return Err(EnclaveError{trace, err:e.err});
                    }
                }
            }

            let old_len = self.len;
            let old_saved = self.saved;
            self.saved = true;
            self.len += num_new_parts;
            match self.save_db() {
                Ok(_) => {},
                Err(e) => {
                    self.saved = old_saved;
                    self.len = old_len;
                    let trace = format!("{} || multipart_data.append self.save_db()", e.trace);
                    return Err(EnclaveError{trace, err:e.err});
                }
            }
        }
        Ok(())
    }

    pub fn get(&mut self, index: usize) -> Result<Vec<T>,EnclaveError>  {
        println!("multipart_data.get name {:?} index {:?} self.len {:?}", self.name, index, self.len);
        if index >= self.len {
            let description = format!("index out of bounds index {:?} self.len {:?}",index, self.len);
            return Err(EnclaveError{trace: "multipart_data.get index >= self.len".to_string(), err:SgxError{description}});
        }
        for p in &self.parts {
            if p.index == index {
                return Ok(p.data.clone());
            }
        }
        match self.load_part(index) {
            Ok(x) => Ok(x.data),
            Err(e) => {
                let trace = format!("{} || multipart_data.get self.load_part(index)", e.trace);
                Err(EnclaveError{trace, err:e.err})
            }
        }
    }

    pub fn get_all(&mut self) -> Result<Vec<T>,EnclaveError>  {
        println!("multipart_data.get_all {:?}", self.name);
        let mut all = Vec::new();
        for index in 0..self.len {
            match self.load_part(index) {
                Ok(mut x) => all.append(&mut x.data),
                Err(e) => {
                    let trace = format!("{} || multipart_data.get_all self.load_part(index)", e.trace);
                    return Err(EnclaveError{trace, err:e.err});
                },
            }
        }
        Ok(all)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    fn save_db(&self) -> Result<(), EnclaveError> {
        let sealed_path = self.get_path();
        if sealed_path.exists() && !self.mutable {
            let description = format!("sealed_path {:?} exists and db is not mutable, can't change",sealed_path );
            return Err(EnclaveError{trace:"multipart_data.save_db sealed_path.exists()".to_string(), err: SgxError{description}});
        }
        let sealed_path = match sealed_path.to_str() {
            Some(x) => x,
            None => {
                let description = format!("could not convert sealed_path {:?} to str",sealed_path);
                return Err(EnclaveError{err:SgxError {description},trace:"multipart_data.save_db sealed_path.to_str()".to_string()});
            }
        };
        let db_info:MultipartDatabase<T> = MultipartDatabase{name: self.name.clone(), mutable: self.mutable, max_size: self. max_size, saved: self.saved, len: self.len, parts: Vec::new()};
        let encoded_vec = serde_json::to_vec(&db_info).unwrap();
        println!("encoded_vec len {:?} {:?}",encoded_vec.len(), encoded_vec);
        let encoded_slice = encoded_vec.as_slice();
        let aad: [u8; 0] = [0_u8; 0];
        let result = SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice);
        let sealed_data = match result {
            Ok(x) => x,
            Err(e) => {
                return Err(EnclaveError{trace:"multipart_data.save_db SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice)".to_string(), err: SgxError{description: e.to_string()}});
            },
        };
        let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];

        let sealed_log = sealed_log_out.as_mut_ptr();
        let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, SEAL_LOG_SIZE as u32);

        if opt.is_none() {
            let description = format!("to_sealed_log_for_slice failed for sealed_path {:?}", sealed_path);
            return Err(EnclaveError{trace: "multipart_data.save_db opt.is_none()".to_string(), err:SgxError{description}});
        }
        match save_sealed_data(sealed_path, &sealed_log_out){
            Ok(_) => {},
            Err(e) => {
                let trace = format!("{} || multipart_data.save_db save_sealed_data", e.trace);
                return Err(EnclaveError{trace, err: e.err});
            }
        }
        Ok(())
    }

    fn save_part(&self, part:&Part<T>) -> Result<(),EnclaveError> {
        let sealed_path = self.get_part_path(part.index);
        if sealed_path.exists() && !self.mutable {
            let description = format!("sealed_part {:?} exists and db is not mutable, can't change",sealed_path);
            return Err(EnclaveError{trace:"multipart_data.save_part sealed_path.exists()".to_string(), err: SgxError{description}});
        }
        let sealed_path:&str = match sealed_path.to_str() {
            Some(x) => x,
            None => {
                let description = format!("could not convert sealed_path {:?} to str",sealed_path);
                return Err(EnclaveError{trace: "multipart_data.save_part sealed_path.to_str()".to_string(), err:SgxError{description}});
            }
        };

        let encoded_part_vec = serde_json::to_vec(&part).unwrap();
        let encoded_part_slice = encoded_part_vec.as_slice();
        let part_aad: [u8; 0] = [0_u8; 0];
        let part_result = SgxSealedData::<[u8]>::seal_data(&part_aad, encoded_part_slice);
        let sealed_part_data = match part_result {
            Ok(x) => x,
            Err(e) => {
                return Err(EnclaveError{trace:"multipart_data.save_part SgxSealedData::<[u8]>::seal_data(&aad, encoded_slice)".to_string(), err:SgxError{description: e.to_string()}});
            },
        };
        let mut sealed_part_log_out = [0u8; SEAL_LOG_SIZE];

        let sealed_part_log = sealed_part_log_out.as_mut_ptr();
        use std;
        // println!("part.data.len {:?}", part.data.len());
        // println!("encoded_part_vec len {:?} {:?} {:?}",encoded_part_vec.len(), SEAL_LOG_SIZE as u32,  std::str::from_utf8(&encoded_part_vec).unwrap());
        let part_opt = to_sealed_log_for_slice(&sealed_part_data, sealed_part_log, SEAL_LOG_SIZE as u32);
        if part_opt.is_none() {
            let description = format!("to_sealed_log_for_slice failed for sealed_path {:?}", sealed_path);
            return Err(EnclaveError{trace: "multipart_data.save_part part_opt.is_none()".to_string(), err:SgxError{description}});
        }

        match save_sealed_data(sealed_path, &sealed_part_log_out) {
            Ok(_) => {
                return Ok(());
            },
            Err(e) => {
                let trace = format!("{} || multipart_data.save_part save_sealed_data(sealed_path, &sealed_part_log_out)", e.trace);
                return Err(EnclaveError{trace, err: e.err});
            }
        }
    }

    fn load_part(&mut self, index: usize) -> Result<Part<T>, EnclaveError> {
        let sealed_path = self.get_part_path(index);
        if !sealed_path.exists() {
            let description = format!("sealed_path for {:?} does not exist",sealed_path);
            return Err(EnclaveError{err:SgxError {description}, trace:"multipart_data.load_part !sealed_path.exists()".to_string()});
        }
        let sealed_path:&str = match sealed_path.to_str() {
            Some(x) => x,
            None => {
                let description = format!("could not convert sealed_path {:?} to str",sealed_path);
                return Err(EnclaveError{err:SgxError {description},trace:"multipart_data.load_part sealed_path.to_str()".to_string()});
            }
        };

        let mut sealed_log_out = [0u8; SEAL_LOG_SIZE];
        match load_sealed_data(&sealed_path, &mut sealed_log_out) {
            Ok(_) => {},
            Err(e) => {
                let trace = format!("{} || multipart_data.load_part load_sealed_data(&sealed_path, &mut sealed_log_out)", e.trace);
                return Err(EnclaveError{trace, err: e.err});
            }
        };
        let sealed_log = sealed_log_out.as_mut_ptr();
        let part = match recover_sealeddata_for_serializable_part(sealed_log, SEAL_LOG_SIZE as u32) {
            Ok(x) => x,
            Err(e) => {
                let trace = format!("{} || multipart_data.load_part recover_sealeddata_for_serializable_part(sealed_log, SEAL_LOG_SIZE)", e.trace);
                return Err(EnclaveError{trace, err: e.err});
            }
        };
        println!("load_part part.data.len {:?}", part.data.len());
        let p = part.clone();
        self.parts.push(part);
        Ok(p)
    }

    fn get_part_path(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}.database.sealed", self.name, index))
    }

    fn get_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.database.sealed", self.name))
    }

    fn _get_path(name: String) -> PathBuf {
        PathBuf::from(format!("{}.database.sealed", name))
    }
}

// Save sealed data to disk
pub fn save_sealed_data(path: &str, sealed_data: &[u8]) -> Result<(), EnclaveError>  {
    let opt = File::create(path);
    if opt.is_ok() {
        let mut file = opt.unwrap();
        match file.write_all(&sealed_data) {
            Ok(_) => {},
            Err(e) => {
                let description = format!("error writing to file {:?} {:?}", path, file.write_all(&sealed_data));
                return Err(EnclaveError{err:SgxError {description}, trace: "multipart_data.save_sealed_data file.write_all(&sealed_data)".to_string() });
            }
        }
    } else {
        let description = format!("error creating to file {:?} {:?}",path, opt);
        return Err(EnclaveError{err:SgxError {description}, trace:"multipart_data.save_sealed_data file.create(path)".to_string()});
    }
    Ok(())
}

pub fn load_sealed_data(path: &str, sealed_data: &mut [u8]) -> Result<(), EnclaveError> {
    let mut file = match File::open(path) {
        Err(e) => {
            let description = format!("error opening to file {:?} {:?}", path, e);
            return Err(EnclaveError{err:SgxError {description}, trace: "multipart_data.load_sealed_data File::open(path)".to_string() });
        }
        Ok(file) => file,
    };

    let result = file.read(sealed_data);
    if result.is_ok() {
        return Ok(());
    } else {
        let description = format!("error reading to file {:?} {:?}",path, result);
        return Err(EnclaveError{err:SgxError {description}, trace:"multipart_data.load_sealed_data file.read(path)".to_string()});

    }
}

pub fn recover_sealeddata_for_serializable<T: DeserializeOwned>(sealed_log: * mut u8, sealed_log_size: u32) -> Result<MultipartDatabase<T>, EnclaveError> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(EnclaveError{err:UnsealError, trace:"multipart_data.recover_sealeddata_for_serializable from_sealed_log_for_slice".to_string()})?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| EnclaveError{trace: "multipart_data.recover_sealeddata_for_serializable sealed_data.unseal_data()".to_string(), err:SgxError{description: err.to_string()}})?;
    let encoded_slice = unsealed_data.get_decrypt_txt();
    let data: MultipartDatabase<T> = serde_json::from_slice(encoded_slice).unwrap();

    Ok(data)
}

pub fn recover_sealeddata_for_serializable_part<T: DeserializeOwned>(sealed_log: * mut u8, sealed_log_size: u32) -> Result<Part<T>, EnclaveError> {

    let sealed_data = from_sealed_log_for_slice::<u8>(sealed_log, sealed_log_size).ok_or(EnclaveError{err:UnsealError, trace:"multipart_data.recover_sealeddata_for_serializable_part from_sealed_log_for_slice".to_string()})?;
    let unsealed_data = sealed_data.unseal_data().map_err(|err| EnclaveError{trace: "multipart_data.recover_sealeddata_for_serializable_part sealed_data.unseal_data()".to_string(), err:SgxError{description: err.to_string()}})?;
    let encoded_slice = unsealed_data.get_decrypt_txt();

    let data: Part<T> = serde_json::from_slice(encoded_slice).unwrap();

    Ok(data)
}

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}
