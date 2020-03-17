use cryptolib::text::*;

#[test]
fn test_hamming_distance() {
    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)
}
