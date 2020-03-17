use cryptolib::xor;
use hex;

#[test]
fn xor_blocks() {
    let first_block = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let second_block = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let expected_output = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

    assert_eq!(xor(&first_block, &second_block), expected_output);
}
