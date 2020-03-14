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

    assert_eq!(xor(&first_block, &second_block).unwrap(), expected_output);
}
