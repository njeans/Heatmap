use crate::networking::messages::*;
use sgx_types::sgx_enclave_id_t;
use futures::{Future, Stream};
use std::sync::Arc;
use tokio_zmq::prelude::*;
use tokio_zmq::{Error, Multipart, Rep};


pub struct IpcListener {
    _context: Arc<zmq::Context>,
    rep_future: Box<dyn Future<Item = Rep, Error = Error>>,
}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let _context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(_context.clone()).bind(conn_str).build();
        println!("Binded to socket: {}", conn_str);
        IpcListener { _context, rep_future }
    }

    pub fn run<F>(self, f: F) -> impl Future<Item = (), Error = Error>
    where F: FnMut(Multipart) -> Multipart {
        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f).forward(sink).map(|(_stream, _sink)| ())
        })
    }
}

pub fn handle_message(request: Multipart, spid: &str, api_key: &str, eid: sgx_enclave_id_t, retries: u32) -> Multipart {
    let mut responses = Multipart::new();
    for msg in request {
        let msg: IpcMessageRequest = msg.into();
        let id = msg.id.clone();
        let response_msg = match msg.request {
            IpcRequest::GetEnclaveReport => handling::get_enclave_report(eid, spid, api_key, retries),
            IpcRequest::GetEnclavePublicKey => handling::get_enclave_publickey(eid),
            IpcRequest::GetEnclaveData => handling::get_enclave_data(eid),
            IpcRequest::GetAuditData => handling::get_audit_data(eid),
            IpcRequest::InitUserDB { user_db } => handling::init_user_db(&user_db, eid),
            IpcRequest::AddPersonalData { input } => handling::add_personal_data(input, eid),
            IpcRequest::RetrieveHeatmap => handling::retrieve_heatmap(eid),
            IpcRequest::Error => {Ok(IpcResponse::Error{msg: msg.id})}
        };
        let msg = IpcMessageResponse::from_response(response_msg.unwrap_or_error(), id);
        responses.push_back(msg.into());
    }
    responses
}


pub(self) mod handling {
    use crate::networking::messages::*;
    use crate::attestation::{service::AttestationService, constants::ATTESTATION_SERVICE_URL};
    use crate::esgx::equote;
    #[macro_use]  use failure::Error;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    use hex::{FromHex, ToHex};
    use std::str;
    use rmp_serde::Deserializer;
    use serde::Deserialize;
    use serde_json::Value;

    extern {
        fn ecall_init_user_db(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            db: *const u8,
            db_len: usize) -> sgx_status_t;
    }


    extern {
        fn ecall_get_encryption_pubkey(
            eid: sgx_enclave_id_t,
            sig: *mut [u8; 65usize],
            arr: *mut [u8; 64usize]) -> sgx_status_t;
    }



    extern {
        fn ecall_add_personal_data(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            userid: *const u8,
            userid_len: usize,
            encrypted_data: *const u8,
            encrypted_data_len: usize
        ) -> sgx_status_t;
    }

    extern {
        fn ecall_retrieve_heatmap(
                eid: sgx_enclave_id_t,
                ret: *mut sgx_status_t,
                sig: *mut [u8; 65usize],
                serialized_ptr: *mut u64,
                out_len: *mut usize
            ) -> sgx_status_t;
    }

    extern {
        fn ecall_get_enclave_data(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            sig: *mut [u8; 65usize],
            serialized_ptr: *mut u64,
            out_len: *mut usize
        ) -> sgx_status_t;
    }


    extern {
        fn ecall_get_audit_data(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            sig: *mut [u8; 65usize],
            serialized_ptr: *mut u64,
            out_len: *mut usize
        ) -> sgx_status_t;
    }

    type ResponseResult = Result<IpcResponse, Error>;

    #[derive(Serialize, Deserialize)]
    struct PubkeyResult {
        pubkey: Vec<u8>
    }

    //#[logfn(TRACE)]
    pub fn get_enclave_report(eid: sgx_enclave_id_t, spid: &str, api_key: &str, retries: u32) -> ResponseResult {
        println!("get_enclave_report");
        let signing_key = equote::get_register_signing_address(eid)?;
        let enc_quote = match equote::retry_quote(eid, spid, 18) {
            Ok(x) => x,
            Err(e) => {
                return Err(format_err!("{:?}",e));
            }
        };
        println!("get_enclave_report enc_quote {:?}", enc_quote);

        // *Important* `option_env!()` runs on *Compile* time.
        // This means that if you want Simulation mode you need to run `export SGX_MODE=SW` Before compiling.
        let (signature, report_hex) = if option_env!("SGX_MODE").unwrap_or_default() == "SW" { // Simulation Mode
            let report =  enc_quote.as_bytes().to_hex();
            let sig = String::new();
            (sig, report)
        } else { // Hardware Mode
            let service: AttestationService = AttestationService::new_with_retries(ATTESTATION_SERVICE_URL, retries);
            // get report from Intel's attestation service (IAS)
            let response = service.get_report(enc_quote, api_key)?;

            // TODO print statements is there to help troubleshoot issue with
            // signature validation failing
            // see https://github.com/sbellem/SafeTrace/tree/ias-dev/enclave/safetrace/app/src/attestation#known-issues
            // println!("result of verify report: {:#?}", response.result.verify_report().unwrap());

            let report = response.result.report_string.as_bytes().to_hex();
            let sig = response.result.signature;
            (sig, report)
        };
        println!("get_enclave_report report_hex {:?}", report_hex);
        println!("get_enclave_report signing_key {:?}", signing_key);
        // let signing_key = String::new();//signing_key.to_hex();
        let result = IpcResults::EnclaveReport { signing_key: signing_key.to_hex(), report: report_hex, signature };

        // println!("get_enclave_report signing_key {:?}", signing_key);

        Ok(IpcResponse::GetEnclaveReport { result })
    }

    pub fn get_enclave_publickey(eid: sgx_enclave_id_t) -> ResponseResult {
        let mut pubkey = [0u8; 64];
        let mut sig = [0u8; 65];

        let status = unsafe { ecall_get_encryption_pubkey(eid, &mut sig, &mut pubkey) };
        let result;
        if status == sgx_status_t::SGX_SUCCESS {
            let datahex = pubkey.to_hex();
            let signature = sig.to_hex();
            result = IpcResults::EnclavePublicKey{ status: Status::Passed, encryption_key: datahex, signature};
        } else {
            result = IpcResults::EnclavePublicKey{ status: Status::Failed, encryption_key: "".to_string(), signature: "".to_string()};
        }

        Ok(IpcResponse::GetEnclavePublicKey { result })
    }

    //#[logfn(TRACE)]
    pub fn get_enclave_data(eid: sgx_enclave_id_t) -> ResponseResult {
        println!("app.get_enclave_data");

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let mut serialized_ptr = 0u64;
        let mut size: usize = 4096;
        let mut size_ptr: *mut usize = &mut size;
        let mut sig = [0u8; 65];
        let status = unsafe {
            ecall_get_enclave_data(
                eid,
                &mut ret as *mut sgx_status_t,
                &mut sig,
                &mut serialized_ptr as *mut u64,
                size_ptr
            )
        };

        let box_ptr = serialized_ptr as *mut Box<[u8]>;
        let part = unsafe { Box::from_raw(box_ptr) };
        let data_size = unsafe { *size_ptr };
        let result;
        if ret == sgx_status_t::SGX_SUCCESS {
            let datahex = part.to_hex();
            //TODO delete
            println!("datahex {:?} {:?}",datahex.len(),datahex);
            let signature = sig.to_hex();
            result = IpcResults::EnclaveData{ status: Status::Passed, data: datahex, signature};
        } else {
            result = IpcResults::EnclaveData{ status: Status::Failed, data: "".to_string(), signature: "".to_string() };
        }

        Ok(IpcResponse::GetEnclaveData { result })
    }

    //#[logfn(TRACE)]
    pub fn get_audit_data(eid: sgx_enclave_id_t) -> ResponseResult {
        println!("app.get_audit_data");

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let mut serialized_ptr = 0u64;
        let mut size: usize = 4096;
        let mut size_ptr: *mut usize = &mut size;
        let mut sig = [0u8; 65];

        let status = unsafe {
            ecall_get_audit_data(
                eid,
                &mut ret as *mut sgx_status_t,
                &mut sig,
                &mut serialized_ptr as *mut u64,
                size_ptr
            )
        };

        let box_ptr = serialized_ptr as *mut Box<[u8]>;
        let part = unsafe { Box::from_raw(box_ptr) };
        let data_size = unsafe { *size_ptr };
        let result;
        if ret == sgx_status_t::SGX_SUCCESS {
            let datahex = part.to_hex();
            //TODO delete
            println!("datahex {:?} {:?}",datahex.len(),datahex);
            let signature = sig.to_hex();

            result = IpcResults::AuditData{ status: Status::Passed, data: datahex, signature };
        } else {
            result = IpcResults::AuditData{ status: Status::Failed, data: "".to_string(), signature: "".to_string()};
        }

        Ok(IpcResponse::GetAuditData { result })
    }

    //#[logfn(DEBUG)]
    pub fn init_user_db(input: &str, eid: sgx_enclave_id_t) -> ResponseResult {
        println!("app.init_user_db");

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let db = input.from_hex()?;
        println!("app.init_user_db {:?} {:?}",db.len(),db);

        unsafe { ecall_init_user_db(eid,
                                         &mut ret as *mut sgx_status_t,
                                         db.as_ptr() as * const u8,
                                         db.len()) };

        let result;
        if ret == sgx_status_t::SGX_SUCCESS {
            result = IpcResults::InitUserDB { status: Status::Passed };
        } else {
            result = IpcResults::InitUserDB { status: Status::Failed };
        }
        Ok(IpcResponse::InitUserDB { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn add_personal_data(input: IpcInputData, eid: sgx_enclave_id_t) -> ResponseResult {
        println!("app.add_personal_data");

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let userid = input.userid;
        let encrypted_data = input.encrypted_data.from_hex()?;
        // let mut user_pub_key = [0u8; 64];
        // user_pub_key.clone_from_slice(&input.user_pub_key.from_hex()?);

        unsafe { ecall_add_personal_data(eid,
                                         &mut ret as *mut sgx_status_t,
                                         userid.as_ptr() as * const u8,
                                         userid.len(),
                                         encrypted_data.as_ptr() as * const u8,
                                         encrypted_data.len(),
                                         // &user_pub_key
                                        ) };

        let result;
        if(ret == sgx_status_t::SGX_SUCCESS) {
            result = IpcResults::AddPersonalData { status: Status::Passed };
        } else {
            result = IpcResults::AddPersonalData { status: Status::Failed };
        }
        Ok(IpcResponse::AddPersonalData { result })
    }

    pub fn retrieve_heatmap( eid: sgx_enclave_id_t) -> ResponseResult {
        println!("app.retrieve_heatmap");

         let mut ret = sgx_status_t::SGX_SUCCESS;
         let mut serialized_ptr = 0u64;

        let mut size: usize = 4096;
        let mut size_ptr: *mut usize = &mut size;
        let mut sig = [0u8; 65];

         let status = unsafe {
             ecall_retrieve_heatmap(
                 eid,
                 &mut ret as *mut sgx_status_t,
                 &mut sig,
                 &mut serialized_ptr as *mut u64,
                 size_ptr
             )
         };

         let box_ptr = serialized_ptr as *mut Box<[u8]>;
         let part = unsafe { Box::from_raw(box_ptr) };
         let hm_size = unsafe { *size_ptr };
         let result;
         if ret == sgx_status_t::SGX_SUCCESS {
             let hmhex = part.to_hex();
             println!("hmhex {:?} {:?}",hmhex.len(),hmhex);
             let signature = sig.to_hex();
             result = IpcResults::RetrieveHeatmap { status: Status::Passed, heatmap: hmhex, signature};
         } else {
             result = IpcResults::RetrieveHeatmap { status: Status::Failed, heatmap: "".to_string(), signature: "".to_string() };
         }
         Ok(IpcResponse::RetrieveHeatmap { result })
     }

}
