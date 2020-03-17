use super::xor;
use openssl::symm;
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct EncryptionError;

impl Error for EncryptionError {}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Encryption error")
    }
}

pub trait Cipher {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError>;
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError>;
}

pub struct Xor;

impl Xor {
    fn repeating_xor(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

        plaintext.chunks(key.len()).for_each(|b| {
            ciphertext.append(&mut xor(b, &key[..b.len()]));
        });

        ciphertext
    }
}

impl Cipher for Xor {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        Ok(self.repeating_xor(plaintext, key))
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        Ok(self.repeating_xor(ciphertext, key))
    }
}

pub struct AesEcb {
    cipher: symm::Cipher,
}

impl AesEcb {
    pub fn new() -> AesEcb {
        AesEcb {
            cipher: symm::Cipher::aes_128_ecb(),
        }
    }
}

impl Cipher for AesEcb {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        match symm::encrypt(self.cipher, key, None, plaintext) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(_) => Err(EncryptionError),
        }
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        match symm::decrypt(self.cipher, key, None, ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err(EncryptionError),
        }
    }
}

pub struct AesCbc {
    cipher: symm::Cipher,
}

impl AesCbc {
    pub fn new() -> AesCbc {
        AesCbc {
            cipher: symm::Cipher::aes_128_ecb(),
        }
    }
}

impl Cipher for AesCbc {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != 16 || iv.is_none() || (iv.is_some() && iv.unwrap().len() != 16) {
            return Err(EncryptionError);
        }

        if let Some(iv) = iv {
            let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

            let mut c = iv.to_vec();
            for p in plaintext.chunks(16) {
                c = match symm::encrypt(self.cipher, key, None, &xor(p, &c)) {
                    Ok(b) => b,
                    Err(_) => return Err(EncryptionError),
                };

                ciphertext.extend(&c);
            }

            return Ok(ciphertext);
        }

        Err(EncryptionError)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != 16 || iv.is_none() || (iv.is_some() && iv.unwrap().len() != 16) {
            return Err(EncryptionError);
        }

        if let Some(iv) = iv {
            let mut plaintext = Vec::<u8>::with_capacity(ciphertext.len());

            let previous_c = iv.to_vec();
            for c in ciphertext.chunks(16) {
                let decrypted_current_c = match symm::decrypt(self.cipher, key, None, c) {
                    Ok(b) => b,
                    Err(_) => return Err(EncryptionError),
                };

                plaintext.extend(&xor(&previous_c, &decrypted_current_c));
            }

            return Ok(plaintext);
        }

        Err(EncryptionError)
    }
}
