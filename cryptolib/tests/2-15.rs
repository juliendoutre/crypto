use cryptolib::padding::*;

#[test]
fn simple_unpadding() {
    assert_eq!(
        PKCS7 {}
            .unpad("ICE ICE BABY\x04\x04\x04\x04".as_bytes())
            .unwrap(),
        b"ICE ICE BABY"
    );
}

#[test]
fn unpadding_error() {
    assert_eq!(
        PKCS7 {}
            .unpad("ICE ICE BABY\x05\x05\x05\x05".as_bytes())
            .is_err(),
        true
    );
}

#[test]
fn unpadding_error_2() {
    assert_eq!(
        PKCS7 {}
            .unpad("ICE ICE BABY\x01\x02\x03\x04".as_bytes())
            .is_err(),
        true
    );
}

#[test]
fn single_unpadding() {
    assert_eq!(PKCS7 {}.unpad("\x01".as_bytes()).unwrap(), b"");
}
