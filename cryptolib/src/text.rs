use std::collections::HashMap;

pub fn monogramic_frequencies(plaintext: &str) -> HashMap<char, f32> {
    let mut freq = HashMap::<char, f32>::new();

    plaintext.chars().for_each(|b| {
        *freq.entry(b).or_insert(0.0) += 1.0;
    });

    freq.iter_mut().for_each(|i| *i.1 /= plaintext.len() as f32);

    freq
}

pub fn bigramic_frequencies(plaintext: &str) -> HashMap<String, f32> {
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
