pub mod cipher;
pub mod cracker;
pub mod english;
pub mod padding;
pub mod text;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(i, j)| i ^ j).collect()
}
