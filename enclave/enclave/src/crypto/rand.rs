use crate::types::CryptoError;

pub fn random(rand: &mut [u8]) -> Result<(), CryptoError> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| CryptoError::RandomError { err: e } )
}