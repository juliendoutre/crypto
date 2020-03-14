use base64;
use cryptolib;
use std::{
    env, f32,
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Please provide a path to a file to read");
    }

    let path = Path::new(&args[1]);

    let mut contents = Vec::<u8>::new();

    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        contents.append(&mut base64::decode(line).unwrap());
        contents.push('\n' as u8);
    }

    let (mut best_edit_distance, mut best_key_size) = (f32::MAX, 0);
    for key_size in 2..41 {
        let edit_distance = cryptolib::text::hamming_distance(
            &contents[..key_size],
            &contents[key_size..2 * key_size],
        ) as f32
            / key_size as f32;
        if edit_distance < best_edit_distance {
            best_edit_distance = edit_distance;
            best_key_size = key_size;
        }
    }

    println!("{}", best_key_size);
}
