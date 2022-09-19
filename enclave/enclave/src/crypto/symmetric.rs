use std::borrow::ToOwned;
use std::option::Option;
use std::vec::Vec;

use ring::{aead, error};

use crate::crypto::rand;
use crate::types::{SymmetricKey, CryptoError};

static AES_MODE: &aead::Algorithm = &aead::AES_256_GCM;

/// The IV key byte size
const IV_SIZE: usize = 96/8;
/// Type alias for the IV byte array
type IV = [u8; IV_SIZE];

/// `OneNonceSequence` is a Generic Nonce sequence
pub struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

/// This function get's a key and a slice of data and encrypts the data using the key.
/// the IV/nonce is appended to the cipher text after the MAC tag.
pub fn encrypt(message: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> { encrypt_with_nonce(message, key, None) }

//#[deprecated(note = "This function shouldn't be called directly unless you're implementing the Encryption trait, please use `encrypt()` instead")]
/// This function does the same as [`self::encrypt`] but accepts an IV.
/// it *shouldn't* be called directly. only from tests or [`crate::Encryption::encrypt_with_nonce`] implementations.
pub fn encrypt_with_nonce(message: &[u8], key: &SymmetricKey, _iv: Option<IV>) -> Result<Vec<u8>, CryptoError> {
    let iv = match _iv {
        Some(x) => x,
        None => {
            let mut _tmp_iv = [0; 12];
            rand::random(&mut _tmp_iv)?;
            _tmp_iv
        }
    };

    let aes_encrypt = aead::UnboundKey::new(&AES_MODE, key)
        .map_err(|_| CryptoError::KeyError{ key_type: "Encryption", err: None })?;

    let mut in_out = message.to_owned();
    let tag_size = AES_MODE.tag_len();
    in_out.extend(vec![0u8; tag_size]);
    println!("\tiv={:?}",iv);
    let _seal_size = {
        let iv = aead::Nonce::assume_unique_for_key(iv);
        let nonce_sequence = OneNonceSequence::new(iv);
        let mut seal_key: aead::SealingKey<OneNonceSequence> = aead::BoundKey::new(aes_encrypt, nonce_sequence);
        seal_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionError)
    }?;
    println!("in_out len {:?} tag_size {:?}",in_out.len(), tag_size);
    println!("\tin_out={:?}",in_out);
    // in_out.truncate(seal_size);
    in_out.extend_from_slice(&iv);
    println!("in_out after len {:?} {:?}",in_out.len(),in_out);
    Ok(in_out)
}

/// This function will decrypt a cipher text only if it was encrypted with the `encrypt` function above.
/// Because it will try to get the IV from the last 12 bytes in the cipher text,
/// then ring will take the last 16 bytes as a MAC to check the integrity of the cipher text.
pub fn decrypt(cipheriv: &[u8], key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
    if cipheriv.len() < IV_SIZE {
        return Err(CryptoError::ImproperEncryption);
    }
    let aes_decrypt = aead::UnboundKey::new(&AES_MODE, key)
        .map_err(|_| CryptoError::KeyError { key_type: "Decryption", err: None })?;

    let (ciphertext, iv) = cipheriv.split_at(cipheriv.len()-12);
    let nonce = aead::Nonce::try_assume_unique_for_key(&iv).unwrap(); // This Cannot fail because split_at promises that iv.len()==12
    let nonce_sequence = OneNonceSequence::new(nonce);
    let mut ciphertext = ciphertext.to_owned();
    let mut open_key: aead::OpeningKey<OneNonceSequence>  = aead::BoundKey::new(aes_decrypt, nonce_sequence);
    let decrypted_data = match open_key.open_in_place(aead::Aad::empty(), &mut ciphertext) {
        Ok(x) => x,
        Err(e) => {
            println!("symmetric:decrypt open_in_place err {:?}",e);
            return Err(CryptoError::DecryptionError);
        }
    };
    // let decrypted_data = decrypted_data.map_err(|_| CryptoError::DecryptionError)?;

    Ok(decrypted_data.to_vec())
}