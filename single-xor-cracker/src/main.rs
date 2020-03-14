use cryptolib;
use hex;
use std::collections::HashMap;
use std::env;

mod english;

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
            Ok(m) => Some(m),
            Err(_) => None,
        } {
            scores.insert(k, score(&plaintext));
        }
    }

    let mut results: Vec<(&u8, &f32)> = scores.iter().collect();
    results.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

    println!(
        "Best guessed key is {} giving: {:?} with score: {} ",
        *results[0].0 as char,
        String::from_utf8(
            cryptolib::xor(&ciphertext, &vec![*results[0].0; ciphertext.len()]).unwrap()
        )
        .unwrap(),
        results[0].1,
    );
}

fn monogramic_frequencies(plaintext: &str) -> HashMap<char, f32> {
    let mut freq = HashMap::<char, f32>::new();

    plaintext.chars().for_each(|b| {
        *freq.entry(b).or_insert(0.0) += 1.0;
    });

    freq.iter_mut().for_each(|i| *i.1 /= plaintext.len() as f32);

    freq
}

fn bigramic_frequencies(plaintext: &str) -> HashMap<String, f32> {
    let mut freq = HashMap::<String, f32>::new();

    let mut word = String::with_capacity(2);
    let mut bigram_counters = 0;

    for c in plaintext.chars() {
        if c.is_alphabetic() {
            if word.len() == 2 {
                word.remove(0);
            }

            word.push(c);

            if word.len() == 2 {
                *freq.entry(word.clone()).or_insert(0.0) += 1.0;
                bigram_counters += 1;
            }
        } else {
            word.drain(..);
        }
    }

    freq.iter_mut().for_each(|i| *i.1 /= bigram_counters as f32);

    freq
}

fn score(plaintext: &str) -> f32 {
    let mut score = 0.0;

    let mut mon_freq = monogramic_frequencies(plaintext);
    let mut bi_freq = bigramic_frequencies(plaintext);

    score += english::monogramic_frequencies()
        .iter()
        .fold(0.0, |s, i| s + i.1 * *mon_freq.entry(*i.0).or_insert(0.0));

    score += english::bigramic_frequencies().iter().fold(0.0, |s, i| {
        let entry = i.0.clone();
        s + i.1 * *bi_freq.entry(entry).or_insert(0.0)
    });

    score
}
