use cryptolib;
use hex;
use std::collections::HashMap;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Please provide a ciphertext to decrypt");
    }

    let ciphertext = &args[1];
    let ciphertext = hex::decode(ciphertext).unwrap();

    let mut scores = HashMap::<u8, f32>::new();

    for k in 0..=255 as u8 {
        let plaintext = cryptolib::xor(&ciphertext, &vec![k; ciphertext.len()]).unwrap();
        if let Some(plaintext) = match String::from_utf8(plaintext) {
            Ok(m) => Some(m.to_lowercase()),
            Err(_) => None,
        } {
            scores.insert(k, score(&plaintext));
        }
    }

    let mut results: Vec<(&u8, &f32)> = scores.iter().collect();
    results.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

    for i in 0..4 {
        println!(
            "{} (with score: {}) giving: {:?}",
            results[i].0,
            results[i].1,
            String::from_utf8(
                cryptolib::xor(&ciphertext, &vec![*results[i].0; ciphertext.len()]).unwrap()
            )
            .unwrap()
        );
    }
}

fn english_frequencies() -> HashMap<u8, f32> {
    let mut frequencies = HashMap::<u8, f32>::new();

    frequencies.insert(97, 8.55);
    frequencies.insert(98, 1.6);
    frequencies.insert(99, 3.16);
    frequencies.insert(100, 3.87);
    frequencies.insert(101, 12.1);
    frequencies.insert(102, 2.18);
    frequencies.insert(103, 2.09);
    frequencies.insert(104, 4.96);
    frequencies.insert(105, 7.33);
    frequencies.insert(106, 0.22);
    frequencies.insert(107, 0.81);
    frequencies.insert(108, 4.21);
    frequencies.insert(109, 2.53);
    frequencies.insert(110, 7.17);
    frequencies.insert(111, 7.47);
    frequencies.insert(112, 2.07);
    frequencies.insert(113, 0.1);
    frequencies.insert(114, 6.33);
    frequencies.insert(115, 6.73);
    frequencies.insert(116, 8.94);
    frequencies.insert(117, 2.68);
    frequencies.insert(118, 1.06);
    frequencies.insert(119, 1.83);
    frequencies.insert(120, 0.19);
    frequencies.insert(121, 1.72);
    frequencies.insert(122, 0.11);

    frequencies
}

fn frequencies(plaintext: &str) -> HashMap<u8, f32> {
    let mut freq = HashMap::<u8, f32>::new();
    let bytes = plaintext.as_bytes();

    bytes.iter().for_each(|b| {
        *freq.entry(*b).or_insert(0.0) += 1.0;
    });

    freq.iter_mut().for_each(|i| *i.1 /= bytes.len() as f32);

    freq
}

fn dot(x: &HashMap<u8, f32>, y: &mut HashMap<u8, f32>) -> f32 {
    x.iter()
        .fold(0.0, |s, i| s + *i.1 * *y.entry(*i.0).or_insert(0.0))
}

fn score(plaintext: &str) -> f32 {
    dot(&english_frequencies(), &mut frequencies(plaintext))
}
