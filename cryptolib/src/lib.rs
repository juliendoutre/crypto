use std::{error::Error, fmt};

#[derive(Debug)]
pub struct BlockSizeError;

impl Error for BlockSizeError {}

impl fmt::Display for BlockSizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Blocks do not have the same size")
    }
}

pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>, BlockSizeError> {
    if a.len() != b.len() {
        return Err(BlockSizeError);
    }

    Ok(a.iter().zip(b.iter()).map(|(i, j)| i ^ j).collect())
}
