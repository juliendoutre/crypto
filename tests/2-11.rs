use cryptolib::{cracker, oracle::*};

#[test]
fn test_aes_mode_detection() {
    cracker::detect_aes_mode(&AesMode {});
}
