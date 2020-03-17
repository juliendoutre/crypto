use cryptolib;
use hex;
use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

#[test]
fn detect_single_character_xor() {
    // let path = Path::new("./data/1-4.txt");

    // let file = File::open(&path).unwrap();
    // let reader = BufReader::new(file);

    // let (mut best_key, mut best_plaintext, mut best_score, mut best_line) =
    //     (' ', Vec::<u8>::new(), 0.0, 0);

    // for (i, line) in reader.lines().enumerate() {
    //     let ciphertext = hex::decode(line.unwrap()).unwrap();
    //     if let Some((key, plaintext, score)) = cryptolib::cracker::crack_single_xor(&ciphertext) {
    //         if score > best_score {
    //             best_key = key;
    //             best_plaintext = plaintext;
    //             best_score = score;
    //             best_line = i;
    //         }
    //     }
    // }

    // assert_eq!(best_line, 0);
    // assert_eq!(best_key, ' ');
    // assert_eq!(best_plaintext, "".as_bytes());
}
