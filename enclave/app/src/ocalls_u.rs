use std::slice;

use sgx_types::{sgx_enclave_id_t, sgx_status_t, sgx_target_info_t, sgx_report_t, uint8_t, uint32_t};
// use sgx_types::*;


#[no_mangle]
pub unsafe extern "C" fn ocall_save_to_memory(data_ptr: *const u8, data_len: usize) -> u64 {
    let data = slice::from_raw_parts(data_ptr, data_len).to_vec();
    let ptr = Box::into_raw(Box::new(data.into_boxed_slice())) as *const u8;
    ptr as u64
}


#[no_mangle]
extern "C" {
    pub fn ecall_get_signing_address(eid: sgx_enclave_id_t, arr: *mut [u8; 20usize]) -> sgx_status_t;

}

#[no_mangle]
extern "C" {
    pub fn ecall_get_registration_quote(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                                        target_info: *const sgx_target_info_t, report: *mut sgx_report_t) -> sgx_status_t;

    // pub fn sgx_init_quote(p_target_info: *mut sgx_target_info_t, p_gid: *mut sgx_epid_group_id_t) -> sgx_status_t;
    //
    // pub fn sgx_calc_quote_size(p_sig_rl: *const uint8_t, sig_rl_size: uint32_t, p_quote_size: *mut uint32_t) -> sgx_status_t;
    //
    // pub fn sgx_get_quote(p_report: *const sgx_report_t, quote_type: sgx_quote_sign_type_t,
    //                      p_spid: *const sgx_spid_t, p_nonce: *const sgx_quote_nonce_t, p_sig_rl: *const uint8_t,
    //                      sig_rl_size: uint32_t, p_qe_report: *mut sgx_report_t, p_quote: *mut sgx_quote_t,
    //                      quote_size: uint32_t) -> sgx_status_t;
}