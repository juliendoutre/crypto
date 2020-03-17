use hex;
use std::{
    collections::HashMap,
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

    let (mut guessed_line, mut counter) = (0, 0);

    for (i, line) in reader.lines().enumerate() {
        let c = count_repetitions(&hex::decode(line.unwrap()).unwrap());
        if c > counter {
            counter = c;
            guessed_line = i;
        }
    }

    println!(
        "Detected a possibly single byte AES-ECB encoded line {} with {} repeated blocks",
        guessed_line, counter,
    );
}

fn count_repetitions(array: &[u8]) -> u32 {
    let mut counter = HashMap::<Vec<u8>, u32>::new();

    array.chunks(16).for_each(|b| {
        *counter.entry((*b).to_vec()).or_insert(0) += 1;
    });

    println!("{:?}", counter);

    counter.iter().fold(0, |m, (_, c)| {
        if *c > m {
            return *c;
        }
        m
    })
}
