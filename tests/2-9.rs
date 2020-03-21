use cryptolib::padding::*;

#[test]
fn simple_padding() {
    assert_eq!(
        PKCS7::pad("YELLOW SUBMARINE".as_bytes(), 20),
        b"YELLOW SUBMARINE\x04\x04\x04\x04"
    );
}
