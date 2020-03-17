use std::{cmp, error::Error, fmt};

#[derive(Debug)]
pub struct InvalidPaddingError;

impl Error for InvalidPaddingError {}

impl fmt::Display for InvalidPaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid padding")
    }
}

pub struct PKCS7;

impl PKCS7 {
    pub fn pad(&self, block: &[u8], padding_length: usize) -> Vec<u8> {
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

    pub fn unpad(&self, block: &[u8]) -> Result<Vec<u8>, InvalidPaddingError> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple_padding() {
        assert_eq!(
            &PKCS7 {}.pad("YELLOW SUBMARINE".as_bytes(), 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn simple_unpadding() {
        assert_eq!(
            &PKCS7 {}
                .unpad("ICE ICE BABY\x04\x04\x04\x04".as_bytes())
                .unwrap(),
            b"ICE ICE BABY"
        );
    }

    #[test]
    fn unpadding_error() {
        assert_eq!(
            PKCS7 {}
                .unpad("ICE ICE BABY\x05\x05\x05\x05".as_bytes())
                .is_err(),
            true
        );
    }

    #[test]
    fn unpadding_error_2() {
        assert_eq!(
            PKCS7 {}
                .unpad("ICE ICE BABY\x01\x02\x03\x04".as_bytes())
                .is_err(),
            true
        );
    }

    #[test]
    fn single_unpadding() {
        assert_eq!(PKCS7 {}.unpad("\x01".as_bytes()).unwrap(), b"");
    }
}
