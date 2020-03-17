use super::xor;
use openssl::symm;

pub trait Cipher {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8>;
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
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        self.repeating_xor(plaintext, key)
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        self.repeating_xor(ciphertext, key)
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
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        symm::encrypt(self.cipher, key, None, plaintext).unwrap()
    }

    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
        symm::decrypt(self.cipher, key, None, ciphertext).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn xor_encryption() {
        let plaintext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";

        let expected_ciphertext = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

        assert_eq!(Xor {}.encrypt(plaintext, key), expected_ciphertext);
    }

    #[test]
    fn xor_decryption() {
        let ciphertext = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
        let key = b"ICE";

        let expected_plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes();

        assert_eq!(Xor {}.decrypt(&ciphertext, key), expected_plaintext);
    }
}
