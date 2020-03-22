use super::{padding::*, xor};
use aes::{
    block_cipher_trait::{generic_array::GenericArray, BlockCipher},
    Aes128,
};
use rand::prelude::*;
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

pub struct AesEcb;

impl Cipher for AesEcb {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != 16 || plaintext.len() % 16 != 0 {
            return Err(EncryptionError);
        }

        let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

        let cipher = Aes128::new(&GenericArray::from_slice(key));

        for b in plaintext.chunks(16) {
            let mut block = GenericArray::clone_from_slice(b);
            cipher.encrypt_block(&mut block);
            ciphertext.append(&mut block.to_vec());
        }

        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        _: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != 16 || ciphertext.len() % 16 != 0 {
            return Err(EncryptionError);
        }

        let mut plaintext = Vec::<u8>::with_capacity(ciphertext.len());

        let cipher = Aes128::new(&GenericArray::from_slice(key));

        for b in ciphertext.chunks(16) {
            let mut block = GenericArray::clone_from_slice(b);
            cipher.decrypt_block(&mut block);
            plaintext.append(&mut block.to_vec());
        }

        Ok(plaintext)
    }
}

pub struct AesCbc;

impl Cipher for AesCbc {
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != 16
            || plaintext.len() % 16 != 0
            || iv.is_none()
            || (iv.is_some() && iv.unwrap().len() != 16)
        {
            return Err(EncryptionError);
        }

        if let Some(iv) = iv {
            let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

            let cipher = Aes128::new(&GenericArray::from_slice(key));

            let mut c = iv.to_vec();
            for b in plaintext.chunks(16) {
                let mut block = GenericArray::clone_from_slice(&xor(b, &c));
                cipher.encrypt_block(&mut block);
                c = block.to_vec();
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
        if key.len() != 16
            || ciphertext.len() % 16 != 0
            || iv.is_none()
            || (iv.is_some() && iv.unwrap().len() != 16)
        {
            return Err(EncryptionError);
        }

        if let Some(iv) = iv {
            let mut plaintext = Vec::<u8>::with_capacity(ciphertext.len());

            let cipher = Aes128::new(&GenericArray::from_slice(key));

            let mut c = iv.to_vec();
            for b in ciphertext.chunks(16) {
                let mut block = GenericArray::clone_from_slice(b);
                let current_c = block.to_vec();
                cipher.decrypt_block(&mut block);

                plaintext.append(&mut xor(&c, &block.to_vec()));

                c = current_c;
            }

            return Ok(plaintext);
        }

        Err(EncryptionError)
    }
}

fn random_block(size: usize) -> Vec<u8> {
    (0..size).map(|_| random::<u8>()).collect()
}

fn random_key() -> Vec<u8> {
    random_block(16)
}

pub fn encryption_oracle(plaintext: &[u8]) -> Vec<u8> {
    let key = random_key();

    let mut rng = thread_rng();
    let mut p = random_block(rng.gen_range(5, 11));
    p.extend_from_slice(plaintext);
    p.extend(random_block(rng.gen_range(5, 11)));

    if let Some(b) = p.chunks(16).last() {
        if b.len() == 16 {
            p.append(&mut PKCS7::pad(&Vec::<u8>::new(), 16));
        } else {
            let padded_block = &PKCS7::pad(b, 16)[b.len()..];
            p.extend_from_slice(padded_block);
        }
    }

    if random() {
        return AesEcb.encrypt(&p, &key, None).unwrap();
    }

    let iv = random_key();
    AesCbc.encrypt(&p, &key, Some(&iv)).unwrap()
}
