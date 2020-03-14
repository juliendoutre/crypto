use std::collections::HashMap;

// The frequecies are taken from http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/

pub fn monogramic_frequencies() -> HashMap<char, f32> {
    let mut frequencies = HashMap::<char, f32>::new();

    frequencies.insert('a', 8.55);
    frequencies.insert('b', 1.6);
    frequencies.insert('c', 3.16);
    frequencies.insert('d', 3.87);
    frequencies.insert('e', 12.1);
    frequencies.insert('f', 2.18);
    frequencies.insert('g', 2.09);
    frequencies.insert('h', 4.96);
    frequencies.insert('i', 7.33);
    frequencies.insert('j', 0.22);
    frequencies.insert('k', 0.81);
    frequencies.insert('l', 4.21);
    frequencies.insert('m', 2.53);
    frequencies.insert('n', 7.17);
    frequencies.insert('o', 7.47);
    frequencies.insert('p', 2.07);
    frequencies.insert('q', 0.1);
    frequencies.insert('r', 6.33);
    frequencies.insert('s', 6.73);
    frequencies.insert('t', 8.94);
    frequencies.insert('u', 2.68);
    frequencies.insert('v', 1.06);
    frequencies.insert('w', 1.83);
    frequencies.insert('x', 0.19);
    frequencies.insert('y', 1.72);
    frequencies.insert('z', 0.11);

    frequencies
}

pub fn bigramic_frequencies() -> HashMap<String, f32> {
    let mut frequencies = HashMap::<String, f32>::new();

    frequencies.insert(String::from("th"), 2.71);
    frequencies.insert(String::from("he"), 2.33);
    frequencies.insert(String::from("in"), 2.03);
    frequencies.insert(String::from("er"), 1.78);
    frequencies.insert(String::from("an"), 1.61);
    frequencies.insert(String::from("re"), 1.41);
    frequencies.insert(String::from("es"), 1.32);
    frequencies.insert(String::from("on"), 1.32);
    frequencies.insert(String::from("st"), 1.25);
    frequencies.insert(String::from("nt"), 1.17);
    frequencies.insert(String::from("en"), 1.13);
    frequencies.insert(String::from("at"), 1.12);
    frequencies.insert(String::from("ed"), 1.08);
    frequencies.insert(String::from("nd"), 1.07);
    frequencies.insert(String::from("to"), 1.07);
    frequencies.insert(String::from("or"), 1.06);
    frequencies.insert(String::from("ea"), 1.00);
    frequencies.insert(String::from("ti"), 0.99);
    frequencies.insert(String::from("ar"), 0.98);
    frequencies.insert(String::from("te"), 0.98);
    frequencies.insert(String::from("ng"), 0.89);
    frequencies.insert(String::from("al"), 0.88);
    frequencies.insert(String::from("it"), 0.88);
    frequencies.insert(String::from("as"), 0.87);
    frequencies.insert(String::from("is"), 0.86);
    frequencies.insert(String::from("ha"), 0.83);
    frequencies.insert(String::from("et"), 0.76);
    frequencies.insert(String::from("se"), 0.73);
    frequencies.insert(String::from("ou"), 0.72);
    frequencies.insert(String::from("of"), 0.71);

    frequencies
}
