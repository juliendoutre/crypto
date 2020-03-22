use super::{
    cipher::{self, Cipher},
    padding::{self, Padder},
};
use rand::prelude::*;

pub trait Oracle {
    fn encrypt(plaintext: &[u8]) -> Vec<u8>;
}

pub struct AesMode;

impl Oracle for AesMode {
    fn encrypt(plaintext: &[u8]) -> Vec<u8> {
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
