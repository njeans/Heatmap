//! # Attestation service.
//! Taken from enigmampc/enigma-core/enigma-tools-u/attestation_service/service.rs
//! and adapted to work with Intel's Attestation Service.

use base64;
// use enigma_tools_u::common_u::errors;
use failure::Error;
use hex::{FromHex, ToHex};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::x509::{X509VerifyResult, X509};
use reqwest::{self, Client, header::HeaderMap};
use serde_json;
use serde_json::Value;
use std::io::Read;
use std::mem;
use std::string::ToString;

const ATTESTATION_SERVICE_DEFAULT_RETRIES: u32 = 10;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ASReport {
    pub id: String,
    pub timestamp: String,
    pub version: usize,
    #[serde(rename = "isvEnclaveQuoteStatus")]
    pub isv_enclave_quote_status: String,
    #[serde(rename = "isvEnclaveQuoteBody")]
    pub isv_enclave_quote_body: String,
    #[serde(rename = "revocationReason")]
    pub revocation_reason: Option<String>,
    #[serde(rename = "pseManifestStatus")]
    pub pse_manifest_satus: Option<String>,
    #[serde(rename = "pseManifestHash")]
    pub pse_manifest_hash: Option<String>,
    #[serde(rename = "platformInfoBlob")]
    pub platform_info_blob: Option<String>,
    pub nonce: Option<String>,
    #[serde(rename = "epidPseudonym")]
    pub epid_pseudonym: Option<String>,
    #[serde(rename = "advisoryIDs")]
    pub advisory_ids: Option<Vec<String>>,
    #[serde(rename = "advisoryURL")]
    pub advisory_url: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResult {
    pub ca: String,
    pub certificate: String,
    pub report: ASReport,
    pub report_string: String,
    pub signature: String,
    pub validate: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ASResponse {
    pub id: i64,
    pub jsonrpc: String,
    pub result: ASResult,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Params {
    pub quote: String,
    pub production: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Params,
    pub id: i32,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct IASRequest {
    #[serde(rename = "isvEnclaveQuote")]
    isv_enclave_quote: String,
}

#[derive(Default)]
pub struct Quote {
    pub body: QBody,
    pub report_body: QReportBody,
}

pub struct QBody {
    // size: 48
    pub version: [u8; 2],
    pub signature_type: [u8; 2],
    pub gid: [u8; 4],
    pub isv_svn_qe: [u8; 2],
    pub isv_svn_pce: [u8; 2],
    pub reserved: [u8; 4],
    pub base_name: [u8; 32],
}

pub struct QReportBody {
    // size: 384
    pub cpu_svn: [u8; 16],
    pub misc_select: [u8; 4],
    pub reserved: [u8; 28],
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    pub reserved3: [u8; 96],
    pub isv_prod_id: [u8; 2],
    pub isv_svn: [u8; 2],
    pub reserved4: [u8; 60],
    pub report_data: [u8; 64],
}

pub struct AttestationService {
    connection_str: String,
    /// amount of attempts per network call
    retries: u32,
}

impl AttestationService {
    pub fn new(conn_str: &str) -> AttestationService {
        AttestationService { connection_str: conn_str.to_string(), retries: ATTESTATION_SERVICE_DEFAULT_RETRIES }
    }

    pub fn new_with_retries(conn_str: &str, retries: u32) -> AttestationService {
        AttestationService { connection_str: conn_str.to_string(), retries }
    }

    /* NOTE: Functions to interact with Intel's Attestation Service (IAS) for SGX.
     *
     * As opposed to sending requests to enigma's server, requests are sent to
     * https://api.trustedservices.intel.com/sgx/dev, and the request payload is
     * constructed according to the specification found at
     * https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf.
     * The response is also processed according to the specification.
     */
    #[logfn(TRACE)]
    pub fn get_report(&self, quote: String, api_key: &str) -> Result<ASResponse, Error> {
        let request: IASRequest = IASRequest {
            isv_enclave_quote: quote,
        };
        println!("sending IAS request {:#?}: ", request);
        let response: ASResponse = self.send_request(&request, api_key)?;
        Ok(response)
    }


    // request the report object
    pub fn send_request(&self, quote_req: &IASRequest, api_key: &str) -> Result<ASResponse, Error> {
        let client = reqwest::Client::new();
        self.attempt_request(&client, quote_req, api_key).or_else(|mut res_err| {
            for _ in 0..self.retries {
                match self.attempt_request(&client, quote_req, api_key) {
                    Ok(response) => return Ok(response),
                    Err(e) => res_err = e,
                }
            }
            return Err(res_err)
        })
    }

    fn attempt_request(&self, client: &Client, quote_req: &IASRequest, api_key: &str) -> Result<ASResponse, Error> {
        let mut res = client.post(self.connection_str.as_str())
            .header("Content-type", "application/json")
            .header("Ocp-Apim-Subscription-Key", api_key)
            .json(&quote_req)
            .send()?;

        if res.status().is_success() {
            let json_response: Value = res.json()?;
            let headers: &HeaderMap = res.headers();
            let response: ASResponse = self.unwrap_response(&headers, &json_response);
            Ok(response)
        }
        else {
            let message = format!("[-] AttestationService: Invalid quote. \
                                            Status code: {:?}\n", res.status());
            Err(format_err!( "{}", message ))
        }
    }

    #[logfn(TRACE)]
    fn unwrap_result(&self, headers: &HeaderMap, json_response: &Value) -> ASResult {
        let (ca, certificate) = self.get_signing_certs(headers).unwrap();
        let signature = self.get_signature(headers).unwrap();
        let validate = true;    // TODO see whether this is needed, or how it is used
        let report_string = json_response.to_string();
        let report: ASReport = serde_json::from_str(&report_string).unwrap();
        ASResult { ca, certificate, signature, validate, report, report_string }
    }

    fn unwrap_response(&self, headers: &HeaderMap, r: &Value) -> ASResponse {
        let result: ASResult = self.unwrap_result(headers, r);
        let id: i64 = 12345; // dummy id - not sure what this is supposed to be
        let jsonrpc = String::from("2.0"); // dummy - not sure what this is for
        ASResponse { id, jsonrpc, result }
    }

    fn get_signing_certs(&self, headers: &HeaderMap) -> Result<(String, String), Error> {
        let signing_cert_header = "X-IASReport-Signing-Certificate";
        let signature_cert = headers.get(signing_cert_header).unwrap().to_str().unwrap();
        let decoded_cert = percent_encoding::percent_decode_str(signature_cert).decode_utf8().unwrap();
        let certs = X509::stack_from_pem(decoded_cert.as_bytes())?;
        let cert_obj = &certs[0];
        let ca_obj = &certs[1];
        let certificate = String::from_utf8(cert_obj.to_pem().unwrap()).unwrap();
        let ca = String::from_utf8(ca_obj.to_pem().unwrap()).unwrap();
        Ok((ca, certificate))
    }

    fn get_signature(&self, headers: &HeaderMap) -> Result<String, Error> {
        let signature_header = "X-IASReport-Signature";
        // NOTE SIGNATURE (in hex)
        //let message = format!("[-] AttestationService: missing header {:?}", signature_header);
        let signature_b64 = headers.get(signature_header).unwrap();
            //.ok_or_else(|| errors::AttestationServiceErr { message }.into())?;
        //println!("signature: {:#?}", signature_b64);
        let signature_bytes = base64::decode(signature_b64)?;
        let signature = signature_bytes.to_hex();
        //println!("signature base64 decoded in hex fmt: {:#?}", signature);
        Ok(signature)
    }
}

impl ASResponse {
    pub fn get_quote(&self) -> Result<Quote, Error> { Quote::from_base64(&self.result.report.isv_enclave_quote_body) }
}

impl ASResult {
    /// This function verifies the report and the chain of trust.
    #[logfn(TRACE)]
    pub fn verify_report(&self) -> Result<bool, Error> {
        let ca = X509::from_pem(&self.ca.as_bytes())?;
        let cert = X509::from_pem(&self.certificate.as_bytes())?;
        println!("ca.issued(&cert): {:#?}", ca.issued(&cert));
        match ca.issued(&cert) {
            X509VerifyResult::OK => (),
            _ => return Ok(false),
        };
        let pubkey = cert.public_key()?;
        let sig: Vec<u8> = self.signature.from_hex()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)?;
        verifier.update(&self.report_string.as_bytes())?;
        println!("verify sig: {:#?}", verifier.verify(&sig)?);
        Ok(verifier.verify(&sig)?)
    }
}

impl Quote {
    pub fn from_base64(encoded_quote: &str) -> Result<Quote, Error> {
        let quote_bytes = base64::decode(encoded_quote)?;

        Ok(Quote {
            body: QBody::from_bytes_read(&mut &quote_bytes[..48])?,
            report_body: QReportBody::from_bytes_read(&mut &quote_bytes[48..432])?,
        })
    }
}

impl QBody {

    /// This will read the data given to it and parse it byte by byte just like the API says
    /// The exact sizes of the field in `QBody` are extremley important.
    /// also the order in which `read_exact` is executed (filed by field just like the API) is also important
    /// because it reads the bytes sequentially.
    /// if the Reader is shorter or longer then the size of QBody it will return an error.
    pub fn from_bytes_read<R: Read>(body: &mut R) -> Result<QBody, Error> {
        let mut result: QBody = Default::default();

        body.read_exact(&mut result.version)?;
        body.read_exact(&mut result.signature_type)?;
        body.read_exact(&mut result.gid)?;
        body.read_exact(&mut result.isv_svn_qe)?;
        body.read_exact(&mut result.isv_svn_pce)?;
        body.read_exact(&mut result.reserved)?;
        body.read_exact(&mut result.base_name)?;

        if body.read(&mut [0u8])? != 0 {
            // return Err(errors::QuoteErr { message: "String passed to QBody is too big".to_string() }.into());
            return Err(format_err!("{}", "String passed to QBody is too big".to_string() ))
        }
        Ok(result)
    }
}

impl Default for QBody {
    // Using `mem::zeroed()` here should be safe because all the fields are [u8]
    // *But* this isn't good practice. because if you add a Box/Vec or any other complex type this *will* become UB(Undefined Behavior).
    fn default() -> QBody { unsafe { mem::zeroed() } }
}

impl QReportBody {
    /// This will read the data given to it and parse it byte by byte just like the API says
    /// The exact sizes of the field in `QBody` are extremley important.
    /// also the order in which `read_exact` is executed (filed by field just like the API) is also important
    /// because it reads the bytes sequentially.
    /// if the Reader is shorter or longer then the size of QBody it will return an error.
    /// Overall Size: 384
    pub fn from_bytes_read<R: Read>(body: &mut R) -> Result<QReportBody, Error> {
        let mut result: QReportBody = Default::default();

        body.read_exact(&mut result.cpu_svn)?;
        body.read_exact(&mut result.misc_select)?;
        body.read_exact(&mut result.reserved)?;
        body.read_exact(&mut result.attributes)?;
        body.read_exact(&mut result.mr_enclave)?;
        body.read_exact(&mut result.reserved2)?;
        body.read_exact(&mut result.mr_signer)?;
        body.read_exact(&mut result.reserved3)?;
        body.read_exact(&mut result.isv_prod_id)?;
        body.read_exact(&mut result.isv_svn)?;
        body.read_exact(&mut result.reserved4)?;
        body.read_exact(&mut result.report_data)?;

        if body.read(&mut [0u8])? != 0 {
            // return Err(errors::QuoteErr { message: "String passed to QReportBody is too big".to_string() }.into());
            return Err(format_err!("{}", "String passed to QReportBody is too big".to_string() ))
        }
        Ok(result)
    }
}

impl Default for QReportBody {
    // Using `mem::zeroed()` here should be safe because all the fields are [u8]
    // *But* this isn't good practice. because if you add a Box/Vec or any other complex type this *will* become UB(Undefined Behavior).
    fn default() -> QReportBody { unsafe { mem::zeroed() } }
}
