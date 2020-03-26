use cryptolib::{cracker, oracle::*};

#[test]
fn test_block_size_detection() {
    assert_eq!(cracker::detect_block_size(&EcbSimple::new()), 16);
}

#[test]
fn test_message_recovery() {
    println!("{:?}", cracker::decrypt_ecb_simple(&EcbSimple::new()));
}
