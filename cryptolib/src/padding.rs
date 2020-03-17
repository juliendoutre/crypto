use std::cmp;

pub fn pkcs7(block: &[u8], padding_length: usize) -> Vec<u8> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn simple_padding() {
        assert_eq!(
            pkcs7("YELLOW SUBMARINE".as_bytes(), 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }
}
