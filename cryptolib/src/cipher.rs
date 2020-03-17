use super::xor;

pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

    plaintext.chunks(key.len()).for_each(|b| {
        ciphertext.append(&mut xor(b, &key[..b.len()]));
    });

    ciphertext
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn repeating_xor_encrypting() {
        let plaintext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";

        let expected_ciphertext = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

        assert_eq!(repeating_xor(plaintext, key), expected_ciphertext);
    }
}
