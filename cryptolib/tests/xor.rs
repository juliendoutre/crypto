use cryptolib::cipher;
use cryptolib::text;
use cryptolib::xor;
use hex;

#[test]
fn xor_blocks() {
    let first_block = "1c0111001f010100061a024b53535009181c";
    let second_block = "686974207468652062756c6c277320657965";
    let first_block = hex::decode(first_block).unwrap();
    let second_block = hex::decode(second_block).unwrap();

    let expected_output = "746865206b696420646f6e277420706c6179";
    let expected_output = hex::decode(expected_output).unwrap();

    assert_eq!(xor(&first_block, &second_block), expected_output);
}

#[test]
fn repeating_xor() {
    let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";

    let expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let expected_ciphertext = hex::decode(expected_ciphertext).unwrap();

    assert_eq!(cipher::repeating_xor(plaintext, key), expected_ciphertext)
}

#[test]
fn hamming_distance() {
    assert_eq!(
        text::hamming_distance(b"this is a test", b"wokka wokka!!!"),
        37
    )
}
