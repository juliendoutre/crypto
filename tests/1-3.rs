use cryptolib::cracker;
use hex;

#[test]
fn crack_single_byte_xor_cipher() {
    let ciphertext =
        hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .unwrap();

    let expected_key = 'X';
    let expected_plaintext = "Cooking MC\'s like a pound of bacon".as_bytes();

    let (key, plaintext, _) = cracker::crack_single_xor(&ciphertext).unwrap();
    assert_eq!((key, &plaintext[..]), (expected_key, expected_plaintext));
}
