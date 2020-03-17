use base64;
use cryptolib::{self, cipher::Cipher};
use std::{
    env,
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Please provide a path to a file to read");
    }

    if args.len() < 3 {
        panic!("Please provide a key to decrypt the file with");
    }

    let path = Path::new(&args[1]);

    let mut contents = Vec::<u8>::new();

    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        contents.append(&mut base64::decode(line).unwrap());
    }

    let key = &args[2].as_bytes();

    let plaintext = cryptolib::cipher::AesEcb::new()
        .decrypt(&contents, key, None)
        .unwrap();

    println!("{:?}", String::from_utf8(plaintext).unwrap());
}
