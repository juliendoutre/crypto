pub mod cipher;
pub mod cracker;
pub mod english;
pub mod padding;
pub mod text;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(i, j)| i ^ j).collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hex_to_base64() {
        let input = hex::decode("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(base64::encode(input), expected_output);
    }

    #[test]
    fn xor_blocks() {
        let first_block = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let second_block = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let expected_output = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(xor(&first_block, &second_block), expected_output);
    }
}
