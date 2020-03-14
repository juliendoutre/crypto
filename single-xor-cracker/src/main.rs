use cryptolib;
use hex;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Please provide a ciphertext to decrypt");
    }

    let ciphertext = &args[1];
    let ciphertext = hex::decode(ciphertext).unwrap();

    if let Some((key, plaintext, score)) = cryptolib::cracker::crack_single_xor(&ciphertext) {
        println!(
            "Best guessed key is {} giving: {:?} with score: {} ",
            key,
            String::from_utf8(plaintext).unwrap(),
            score
        );
    } else {
        println!("Could not find a single valid plaintext");
    }
}
