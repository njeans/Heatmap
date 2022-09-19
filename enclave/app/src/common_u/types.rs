
/// This enum is used to return from an ecall/ocall to represent if the operation was a success and if not then what was the error.
/// The goal is to not reveal anything sensitive
/// `#[repr(C)]` is a Rust feature which makes the struct be aligned just like C structs.
/// See [`Repr(C)`][https://doc.rust-lang.org/nomicon/other-reprs.html]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveReturn {
    /// Success, the function returned without any failure.
    Success,
    /// TaskFailure, the task(Deploy/Compute) has failed
    TaskFailure,
    /// KeysError, There's a key missing or failed to derive a key.
    KeysError,
    /// Failure in Encryption, couldn't decrypt the variable / failed to encrypt the results.
    EncryptionError,
    // TODO: I'm not sure this error is used anywhere.
    /// SigningError, for some reason it failed on signing the results.
    SigningError,
    // TODO: Also don't think this is needed.
    /// RecoveringError, Something failed in recovering the public key.
    RecoveringError,
    ///PermissionError, Received a permission error from an ocall, (i.e. opening the signing keys file or something like that)
    PermissionError,
    /// SgxError, Error that came from the SGX specific stuff (i.e DRAND, Sealing etc.)
    SgxError,
    /// StateError, an Error in the State. (i.e. failed applying delta, failed deserializing it etc.)
    StateError,
    /// OcallError, an error from an ocall.
    OcallError,
    /// OcallDBError, an error from the Database in the untrusted part, couldn't get/save something.
    OcallDBError,
    /// MessagingError, a message that received couldn't be processed (i.e. KM Message, User Key Exchange etc.)
    MessagingError,
    /// WorkerAuthError, Failed to authenticate the worker, this is specific to the KM node.
    WorkerAuthError,
    // TODO: should consider merging with a different error.
    /// Missing StateKeys in the KM node.
    KeyProvisionError,
    /// Something went really wrong.
    Other
}