use cryptolib;
use hex;
use std::{
    env,
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Please provide a path to a file to parse");
    }

    let path = Path::new(&args[1]);

    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);

    let (mut best_key, mut best_plaintext, mut best_score, mut best_line) =
        (' ', Vec::<u8>::new(), 0.0, 0);

    for (i, line) in reader.lines().enumerate() {
        let ciphertext = hex::decode(line.unwrap()).unwrap();
        if let Some((key, plaintext, score)) = cryptolib::cracker::crack_single_xor(&ciphertext) {
            if score > best_score {
                best_key = key;
                best_plaintext = plaintext;
                best_score = score;
                best_line = i;
            }
        }
    }

    println!(
        "Detected a possibly single byte xor encoded line {} with key {} giving {:?} with score {}",
        best_line,
        best_key,
        String::from_utf8(best_plaintext).unwrap(),
        best_score,
    );
}
