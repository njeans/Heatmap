//! # Hash Module
//! This module provides Keccak256 and Sha256 implementations as traits for all slices.
//! I think we should consider removing the Sha256 implementation to make sure we use the same hash function always.

use std::string::String;
use std::vec::Vec;
use core::ops::{Deref, DerefMut};
use hex::{FromHex, FromHexError};

use tiny_keccak::Keccak;
use sha2;
use arrayvec::ArrayVec;
use serde::{Serialize, Deserialize};

/// This struct is basically a wrapper over `[u8; 32]`, and is meant to be returned from whatever hashing functions we use.
/// `#[repr(C)]` is a Rust feature which makes the struct be aligned just like C structs.
/// See [`Repr(C)`][https://doc.rust-lang.org/nomicon/other-reprs.html]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord, Hash, Default)]
#[serde(crate = "crate::serde")]
#[repr(C)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// This method exposes rust's built in [`copy_from_slice`][https://doc.rust-lang.org/std/primitive.slice.html#method.copy_from_slice]
    /// Copies the elements from `src` into `self`.
    ///
    /// The length of `src` must be the same as `self`.
    ///
    /// # Panics
    ///
    /// This function will panic if the two slices have different lengths.
    ///
    /// This might not be needed since we implement `Deref` and `DerefMut` for the inner array.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        self.0.copy_from_slice(src)
    }

    /// This function converts a hex string into `Hash256` type.
    /// the hex must not contain `0x` (as is usually the case in hexs in rust)
    /// if the hex length isn't 64 (which will be converted into the 32 bytes) it will return an error.
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        if hex.len() != 64 {
            return Err(FromHexError::InvalidHexLength);
        }
        let hex_vec: ArrayVec<[u8; 32]> = hex.from_hex()?;
        let mut result = Self::default();
        result.copy_from_slice(&hex_vec);
        Ok(result)
    }

    /// Checks if the struct contains only zeroes or not.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8;32]
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(arr: [u8; 32]) -> Self {
        Hash256(arr)
    }
}

impl Into<[u8; 32]> for Hash256 {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

impl Deref for Hash256 {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl DerefMut for Hash256 {
    fn deref_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Hash256 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

/// Takes a list of variables and concat them together with lengths in between.
/// What this does is appends the length of the messages before each message and makes one big slice from all of them.
/// e.g.: `S(H(len(a)+a, len(b)+b...))`
/// # Examples
/// ```
/// use enigma_crypto::hash;
/// let msg = b"sign";
/// let msg2 = b"this";
/// let ready = hash::prepare_hash_multiple(&[msg, msg2]);
/// ```
#[cfg(any(feature = "sgx", feature = "std"))]
#[allow(unused_imports)]
pub fn prepare_hash_multiple<B: AsRef<[u8]>>(messages: &[B]) -> crate::localstd::vec::Vec<u8> {
    use crate::localstd::{vec::Vec, mem};

    // The length field is always a u64.
    // On 16/32 bit platforms we pad the type to 64 bits.
    // On platforms with bigger address spaces (which don't currently exist)
    // we do not expect such ridiculously big slices.
    let length_width = mem::size_of::<u64>();
    // Pre-allocate the vector once instead of reallocating as we build it.
    let mut res = Vec::with_capacity(
        // This is the exact size of the final vector.
        length_width * messages.len() + messages.iter().map(|message| message.as_ref().len()).sum::<usize>()
    );
    for msg in messages {
        let msg = msg.as_ref();
        // See wall of text above :)
        let len = (msg.len() as u64).to_be_bytes();
        res.extend_from_slice(&len);
        res.extend_from_slice(&msg);
    }
    res
}

/// A trait that will hash using Keccak256 the object it's implemented on.
pub trait Keccak256<T> {
    /// This will return a sized object with the hash
    fn keccak256(&self) -> T where T: Sized;
}

/// A trait that will hash using Sha256 the object it's implemented on.
pub trait Sha256<T> {
    /// This will return a sized object with the hash
    fn sha256(&self) -> T where T: Sized;
}

impl Keccak256<Hash256> for [u8] {
    fn keccak256(&self) -> Hash256 {
        let mut keccak = Keccak::new_keccak256();
        let mut result = Hash256::default();
        keccak.update(self);
        keccak.finalize(result.as_mut());
        result
    }
}


impl Keccak256<Hash256> for String {//for hex public key
    fn keccak256(&self) -> Hash256 {
        let mut keccak = Keccak::new_keccak256();
        let mut result = Hash256::default();
        let val: Vec<u8> = self.from_hex().unwrap();
        keccak.update(&val);
        keccak.finalize(result.as_mut());
        result
    }
}

impl Sha256<Hash256> for [u8] {
    fn sha256(&self) -> Hash256 {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&self);
        let mut result = Hash256::default();
        result.copy_from_slice(&hasher.finalize());
        result
    }
}