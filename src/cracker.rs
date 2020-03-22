use super::{
    english,
    oracle::{self, Oracle},
    text, xor,
};
use std::collections::HashMap;

pub fn score(plaintext: &str) -> f32 {
    let mut score = 0.0;

    let mut mon_freq = text::monogramic_frequencies(plaintext);
    let mut bi_freq = text::bigramic_frequencies(plaintext);

    score += english::monogramic_frequencies()
        .iter()
        .fold(0.0, |s, i| s + i.1 * *mon_freq.entry(*i.0).or_insert(0.0));

    score += english::bigramic_frequencies().iter().fold(0.0, |s, i| {
        let entry = i.0.clone();
        s + i.1 * *bi_freq.entry(entry).or_insert(0.0)
    });

    score
}

pub fn crack_single_xor(ciphertext: &[u8]) -> Option<(char, Vec<u8>, f32)> {
    let mut scores = HashMap::<u8, f32>::new();

    for k in 0..=255 as u8 {
        let plaintext = xor(&ciphertext, &vec![k; ciphertext.len()]);
        if let Some(plaintext) = match String::from_utf8(plaintext) {
            Ok(m) => Some(m),
            Err(_) => None,
        } {
            scores.insert(k, score(&plaintext));
        }
    }

    let mut results: Vec<(&u8, &f32)> = scores.iter().collect();
    results.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap());

    if results.len() > 0 {
        return Some((
            *results[0].0 as char,
            xor(&ciphertext, &vec![*results[0].0; ciphertext.len()]),
            *results[0].1,
        ));
    } else {
        return None;
    }
}

pub enum AesMode {
    ECB,
    CBC,
}

pub fn detect_aes_mode() -> AesMode {
    let payload: Vec<u8> = vec![0; 43];

    let ciphertext = oracle::AesMode::encrypt(&payload);

    for b in ciphertext.chunks(16) {
        println!("{:?}", b);
    }

    if ciphertext[16..32] == ciphertext[32..48] {
        return AesMode::ECB;
    }

    AesMode::CBC
}
