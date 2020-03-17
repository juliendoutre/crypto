use cryptolib::cipher::*;
use hex;

#[test]
fn xor_encryption() {
    let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let expected_ciphertext = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();

    assert_eq!(
        Xor {}.encrypt(plaintext, key, None).unwrap(),
        expected_ciphertext
    );
}

#[test]
fn xor_decryption() {
    let ciphertext = hex::decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
    let key = b"ICE";

    let expected_plaintext =
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();

    assert_eq!(
        Xor {}.decrypt(&ciphertext, key, None).unwrap(),
        expected_plaintext
    );
}
