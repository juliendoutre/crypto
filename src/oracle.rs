use super::{
    cipher::{self, Cipher},
    padding::{self, Padder},
};
use base64;
use rand::prelude::*;

pub trait Oracle {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
}

pub struct AesMode;

impl Oracle for AesMode {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let key = cipher::random_key();

        let mut rng = thread_rng();
        let mut p = cipher::random_block(rng.gen_range(5, 11));
        p.extend_from_slice(plaintext);
        p.extend(cipher::random_block(rng.gen_range(5, 11)));

        if let Some(b) = p.chunks(16).last() {
            if b.len() == 16 {
                p.append(&mut padding::PKCS7::pad(&Vec::<u8>::new(), 16));
            } else {
                let padded_block = &padding::PKCS7::pad(b, 16)[b.len()..];
                p.extend_from_slice(padded_block);
            }
        }

        if random() {
            return cipher::AesEcb.encrypt(&p, &key, None).unwrap();
        }

        let iv = cipher::random_key();
        cipher::AesCbc.encrypt(&p, &key, Some(&iv)).unwrap()
    }
}

pub struct EcbSimple {
    key: Vec<u8>,
}

impl EcbSimple {
    pub fn new() -> EcbSimple {
        EcbSimple {
            key: cipher::random_key(),
        }
    }
}

impl Oracle for EcbSimple {
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut p = Vec::from(plaintext);
        p.append(&mut base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap());

        if let Some(b) = p.chunks(16).last() {
            if b.len() == 16 {
                p.append(&mut padding::PKCS7::pad(&Vec::<u8>::new(), 16));
            } else {
                let padded_block = &padding::PKCS7::pad(b, 16)[b.len()..];
                p.extend_from_slice(padded_block);
            }

            return cipher::AesEcb.encrypt(&p, &self.key, None).unwrap();
        }

        vec![0; 0]
    }
}
