use std::{cmp, error::Error, fmt};

#[derive(Debug)]
pub struct InvalidPaddingError;

impl Error for InvalidPaddingError {}

impl fmt::Display for InvalidPaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid padding")
    }
}

pub trait Padder {
    fn pad(block: &[u8], padding_length: usize) -> Vec<u8>;
    fn unpad(block: &[u8]) -> Result<Vec<u8>, InvalidPaddingError>;
}

pub struct PKCS7;

impl Padder for PKCS7 {
    fn pad(block: &[u8], padding_length: usize) -> Vec<u8> {
        let mut padded_block = Vec::<u8>::with_capacity(padding_length);

        for i in 0..cmp::min(padding_length, block.len()) {
            padded_block.push(block[i]);
        }

        let missing_bytes = padding_length - padded_block.len();
        if missing_bytes > 0 {
            for _ in 0..missing_bytes {
                padded_block.push(missing_bytes as u8);
            }
        }

        padded_block
    }

    fn unpad(block: &[u8]) -> Result<Vec<u8>, InvalidPaddingError> {
        if block.len() == 0 {
            return Err(InvalidPaddingError {});
        }

        let padding_byte = block[block.len() - 1];

        if (block.len() as i32 - padding_byte as i32) < 0 {
            return Err(InvalidPaddingError {});
        }

        for i in 2..(padding_byte + 1) as usize {
            if block[block.len() - i] != padding_byte {
                return Err(InvalidPaddingError {});
            }
        }

        return Ok(Vec::from(&block[..block.len() - padding_byte as usize]));
    }
}
