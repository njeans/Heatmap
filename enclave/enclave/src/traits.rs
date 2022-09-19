use std::sync::{SgxMutex as Mutex, SgxMutexGuard as MutexGuard};
use std::string::{String,ToString};
use std::str;

use hex::ToHex;

use crate::crypto::hash::Keccak256;

/// A trait that is basically a shortcut for `mutex.lock().expect(format!("{} mutex is posion", name))`
/// you instead call `mutex.lock_expect(name)` and it will act the same.
pub trait LockExpectMutex<T> {
    /// See trait documentation. a shortcut for `lock()` and `expect()`
    fn lock_expect(&self, name: &str) -> MutexGuard<T>;
}

impl<T> LockExpectMutex<T> for Mutex<T> {
    fn lock_expect(&self, name: &str) -> MutexGuard<T> { self.lock().unwrap_or_else(|_| panic!("{} mutex is poison", name)) }
}

/// A trait to convert an object into an Ethereum Address
pub trait EthereumAddress<T, P> {
    /// This should convert the object(by hashing and slicing) into a String type 40 characters Ethereum address.
    fn address_string(&self) -> T
        where T: Sized;
    /// This should convert the object(by hashing and slicing) into a 20 byte Ethereum address.
    fn address(&self) -> P
        where P: Sized;
}

impl EthereumAddress<String, [u8; 20]> for [u8; 64] {
    // TODO: Maybe add a checksum address
    fn address_string(&self) -> String {
        let mut result: String = String::from("0x");
        let hex: String = self.keccak256()[12..32].to_hex();
        result.push_str(&hex);
        result
    }

    fn address(&self) -> [u8; 20] {
        let mut result = [0u8; 20];
        result.copy_from_slice(&self.keccak256()[12..32]);
        result
    }
}


impl EthereumAddress<String, [u8; 20]> for String {
    fn address_string(&self) -> String {
        let mut result: String = String::from("0x");
        let hex: String = self.keccak256()[12..32].to_hex();
        result.push_str(&hex);
        result
        // let address_hash:String = address.as_bytes().keccak256().to_hex();
        //
        //     .char_indices()
        //     .fold(String::from("0x"), |mut acc, (index, address_char)| {
        //         let n = u16::from_str_radix(&address_hash[index..index + 1], 16).unwrap();
        //         if n > 7 {
        //             acc.push_str(&address_char.to_uppercase().to_string())
        //         } else {
        //             acc.push(address_char);
        //         }
        //         acc
        //     })

    }

    fn address(&self) -> [u8; 20] {
        let mut result = [0u8; 20];
        result.copy_from_slice(&self.keccak256()[12..32]);
        result
    }
}

static EMPTY: [u8; 1] = [0];

/// This trait provides an interface into `C` like pointers.
/// in Rust if you try to get a pointer to an empty vector you'll get:
/// 0x0000000000000001 OR 0x0000000000000000, although bear in mind this *isn't* officially defined.
/// this behavior is UB in C's `malloc`, passing an invalid pointer with size 0 to `malloc` is implementation defined.
/// in the case of Intel's + GCC what we observed is a Segmentation Fault.
/// this is why if the vec/slice is empty we use this trait to pass a pointer to a stack allocated static `[0]` array.
/// this will make the pointer valid, and when the len is zero
/// `malloc` won't allocate anything but also won't produce a SegFault
pub trait SliceCPtr {
    /// The Target for the trait.
    /// this trait can't be generic because it should only be implemented once per type
    /// (See [Associated Types][https://doc.rust-lang.org/rust-by-example/generics/assoc_items/types.html])
    type Target;
    /// This function is what will produce a valid C pointer to the target
    /// even if the target is 0 sized (and rust will produce a C *invalid* pointer for it )
    fn as_c_ptr(&self) -> *const Self::Target;
}

impl<T> SliceCPtr for [T] {
    type Target = T;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}

impl SliceCPtr for str {
    type Target = u8;
    fn as_c_ptr(&self) -> *const Self::Target {
        if self.is_empty() {
            EMPTY.as_ptr() as *const _
        } else {
            self.as_ptr()
        }
    }
}