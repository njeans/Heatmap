use serde_json;
use serde_repr::{Serialize_repr, Deserialize_repr};
use zmq::Message;


// These attributes enable the status to be casted as an i8 object as well
#[derive(Serialize_repr, Deserialize_repr, Clone, Debug)]
#[repr(i8)]
pub enum Status {
    Failed = -1,
    Passed = 0,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GeolocationTime {
    lat: f32,
    lng: f32,
    start_ts: i32,
    end_ts: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageRequest {
    pub id: String,
    #[serde(flatten)]
    pub request: IpcRequest
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcMessageResponse {
    pub id: String,
    #[serde(flatten)]
    pub response: IpcResponse
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcResponse {
    GetEnclaveReport { #[serde(flatten)] result: IpcResults },
    GetEnclavePublicKey { #[serde(flatten)] result: IpcResults },
    GetEnclaveData { #[serde(flatten)] result: IpcResults },
    GetAuditData { #[serde(flatten)] result: IpcResults },
    InitUserDB { #[serde(flatten)] result: IpcResults },
    AddPersonalData { #[serde(flatten)] result: IpcResults },
    RetrieveHeatmap { #[serde(flatten)] result: IpcResults },
    Error { msg: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde( rename = "result")]
pub enum IpcResults {
    Errors(Vec<IpcStatusResult>),
    EnclaveReport { signing_key: String, report: String, signature: String },
    EnclavePublicKey { status: Status, encryption_key: String, signature: String },
    EnclaveData { status: Status, data: String, signature: String },
    AuditData { status: Status, data: String, signature: String },
    InitUserDB { status: Status },
    AddPersonalData { status: Status },
    RetrieveHeatmap { status: Status, heatmap: String, signature: String},
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum IpcRequest {
    GetEnclaveReport,
    GetEnclavePublicKey,
    GetEnclaveData,
    GetAuditData,
    InitUserDB { user_db : String },
    AddPersonalData { input: IpcInputData },
    RetrieveHeatmap,
    Error,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcInputData {
    pub userid: String,
    pub encrypted_data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpcStatusResult {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<i64>,
    pub status: Status,
}

impl IpcMessageResponse {
    pub fn from_response(response: IpcResponse, id: String) -> Self {
        Self { id, response }
    }
}

impl IpcMessageRequest {
    pub fn from_request(request: IpcRequest, id: String) -> Self {
        Self { id, request }
    }
}

impl From<Message> for IpcMessageRequest {
    fn from(msg: Message) -> Self {
        let msg_str = msg.as_str().unwrap_or("");
        let req: Self = serde_json::from_str(msg_str).unwrap_or(IpcMessageRequest{id: "failed to parse messasge".to_string(), request: IpcRequest::Error});
        req
    }
}

impl Into<Message> for IpcMessageResponse {
    fn into(self) -> Message {
        let msg = serde_json::to_vec(&self).unwrap();
        Message::from(&msg)
    }
}

pub(crate) trait UnwrapError<T> {
    fn unwrap_or_error(self) -> T;
}

impl<E: std::fmt::Display> UnwrapError<IpcResponse> for Result<IpcResponse, E> {
    fn unwrap_or_error(self) -> IpcResponse {
        match self {
            Ok(m) => m,
            Err(e) => {
                error!("Unwrapped Message failed: {}", e);
                IpcResponse::Error {msg: format!("{}", e)}
            }
        }
    }
}
