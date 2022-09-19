use std::str;
use std::{self, time};
use std::thread::sleep;

use sgx_types::*;

use failure::Error;
use hex::FromHex;


#[no_mangle]
extern "C" {
    pub fn ecall_get_signing_address(eid: sgx_enclave_id_t, arr: *mut [u8; 20usize]) -> sgx_status_t;

    pub fn ecall_get_registration_quote(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                                        target_info: *const sgx_target_info_t, report: *mut sgx_report_t) -> sgx_status_t;

    pub fn sgx_init_quote(p_target_info: *mut sgx_target_info_t, p_gid: *mut sgx_epid_group_id_t) -> sgx_status_t;

    pub fn sgx_calc_quote_size(p_sig_rl: *const uint8_t, sig_rl_size: uint32_t, p_quote_size: *mut uint32_t) -> sgx_status_t;

    pub fn sgx_get_quote(p_report: *const sgx_report_t, quote_type: sgx_quote_sign_type_t,
                         p_spid: *const sgx_spid_t, p_nonce: *const sgx_quote_nonce_t, p_sig_rl: *const uint8_t,
                         sig_rl_size: uint32_t, p_qe_report: *mut sgx_report_t, p_quote: *mut sgx_quote_t,
                         quote_size: uint32_t) -> sgx_status_t;
}

// this struct is returned during the process registration back to the surface.
// quote: the base64 encoded quote
// address : the clear text public key for ecdsa signing and registration
#[derive(Serialize, Deserialize, Debug)]
pub struct GetRegisterResult {
    pub errored: bool,
    pub quote: String,
    pub address: String,
}

// wrapper function for getting the enclave public sign key (the one attached with produce_quote())
//#[logfn(TRACE)]
pub fn get_register_signing_address(eid: sgx_enclave_id_t) -> Result<[u8; 20], Error> {
    let mut pubkey = [0u8; 20];
    let status = unsafe { ecall_get_signing_address(eid, &mut pubkey) };
    if status == sgx_status_t::SGX_SUCCESS {
        Ok(pubkey)
    } else {
        Err(format_err!("{}",String::from("error in get_register_signing_key")))
    }
}

pub fn retry_quote(eid: sgx_enclave_id_t, spid: &str, times: usize) -> Result<String, String> {
    let mut quote = String::new();
    for _ in 0..times {
        quote = match produce_quote(eid, spid) {
            Ok(q) => q,
            Err(e) => {
                println!("problem with quote, trying again: {:?}", e);
                continue;
            }
        };

        if !quote.chars().all(|cur_c| cur_c == 'A') {
            return Ok(quote);
        } else {
            sleep(time::Duration::new(5, 0));
        }
    }
    Err(quote)
}

fn check_busy<T, F>(func: F) -> (sgx_status_t, T)
    where F: Fn() -> (sgx_status_t, T) {
    loop {
        let (status, rest) = func();
        if status != sgx_status_t::SGX_ERROR_BUSY {
            return (status, rest);
        }
        sleep(time::Duration::new(1, 500_000_000));
    }
}

#[logfn(TRACE)]
pub fn produce_quote(eid: sgx_enclave_id_t, spid: &str) -> Result<String, String> {
    let spid = match spid.from_hex() {
        Ok(x) => x,
        Err(e) => {
            println!("spid.from_hex() ");
            return Err(e.to_string());
        }
    };
    let mut id = [0; 16];
    id.copy_from_slice(&spid);
    let spid: sgx_spid_t = sgx_spid_t { id };

    // create quote
    let (status, (target_info, _gid)) = check_busy(|| {
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        let status = unsafe { sgx_init_quote(&mut target_info, &mut gid) };
        (status, (target_info, gid))
    });
    if status != sgx_status_t::SGX_SUCCESS {
        println!("sgx_init_quote");
        return Err("sgx_init_quote".to_string());
    }

    // create report
    let (status, (report, retval)) = check_busy(move || {
        let mut report = sgx_report_t::default();
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let status = unsafe { ecall_get_registration_quote(eid, &mut retval, &target_info, &mut report) };
        (status, (report, retval))
    });
    if status != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
        println!("ecall_get_registration_quote");
        return Err("ecall_get_registration_quote".to_string() );
    }


    // calc quote size
    let (status, quote_size) = check_busy(|| {
        let mut quote_size: u32 = 0;
        let status = unsafe { sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size) };
        (status, quote_size)
    });
    if status != sgx_status_t::SGX_SUCCESS || quote_size == 0 {
        return Err("sgx_calc_quote_size".to_string());
    }

    // get the actual quote
    let (status, the_quote) = check_busy(|| {
        let mut the_quote = vec![0u8; quote_size as usize].into_boxed_slice();
        // all of this is according to this: https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-get-quote
        // the `p_qe_report` is null together with the nonce because we don't have an ISV enclave that needs to verify this
        // and we don't care about replay attacks because the signing key will stay the same and that's what's important.
        let status = unsafe {
            sgx_get_quote(&report,
                          sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                          &spid,
                          std::ptr::null(),
                          std::ptr::null(),
                          0,
                          std::ptr::null_mut(),
                          the_quote.as_mut_ptr() as *mut sgx_quote_t,
                          quote_size,
            )
        };
        (status, the_quote)
    });
    if status != sgx_status_t::SGX_SUCCESS {
        return Err("sgx_get_quote".to_string());
    }

    let encoded_quote = base64::encode(&the_quote);
    Ok(encoded_quote)
}