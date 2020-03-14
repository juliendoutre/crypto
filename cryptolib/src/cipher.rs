use super::xor;

pub fn repeating_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ciphertext = Vec::<u8>::with_capacity(plaintext.len());

    plaintext.chunks(key.len()).for_each(|b| {
        ciphertext.append(&mut xor(b, &key[..b.len()]).unwrap());
    });

    ciphertext
}
