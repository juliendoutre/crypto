use cryptolib::{cracker, oracle::*};

#[test]
fn test_block_size_detection() {
    assert_eq!(cracker::detect_block_size(&EcbSimple::new()), 16);
}
