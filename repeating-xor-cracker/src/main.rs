use base64;
use cryptolib::{self, cipher::*};
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

    let mut transposed_blocks = vec![Vec::<u8>::new(); best_key_size];

    contents.chunks(best_key_size).for_each(|b| {
        b.iter()
            .enumerate()
            .for_each(|(i, c)| transposed_blocks[i].push(*c))
    });

    let mut key = Vec::<u8>::with_capacity(best_key_size);

    transposed_blocks.iter().for_each(|b| {
        if let Some((k, _, _)) = cryptolib::cracker::crack_single_xor(&b) {
            key.push(k as u8);
        } else {
            println!("Could not find a single valid plaintext");
        }
    });

    println!(
        "{:?}",
        String::from_utf8(
            cryptolib::cipher::Xor {}
                .decrypt(&contents, &key, None)
                .unwrap()
        )
        .unwrap()
    );
}
