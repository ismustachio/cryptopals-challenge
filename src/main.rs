use std::i64;
use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::io::Read;
extern crate base64;

fn hexs_to_bytes(v: &Vec<char>) -> Vec<u8> {
    let mut buffer = vec![];
    for i in (0..v.len()).step_by(2) {
        let mut a = v[i].to_string();
        let b = v[i+1].to_string();
        a.push_str(&b);
        let t = i64::from_str_radix(&a, 16);
        match t {
            Ok(n) => buffer.push(n.to_le_bytes()[0]),
            Err(_) => panic!("invalid hex string"),
        }
    }
    return buffer;
}

// https://cryptopals.com/sets/1/challenges/1
fn s1ch1(input: &str) -> String {
    let chars : Vec<_> = input.chars().collect();
    let buffer = hexs_to_bytes(&chars);
    return base64::encode(buffer);
}

#[test]
fn set1_challenge1() {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let want = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert!(s1ch1(input) == want);
}

// https://cryptopals.com/sets/1/challenges/2
fn s1ch2(input: &str, xor_str: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let xor_chars: Vec<char> = xor_str.chars().collect();
    let input_bytes = hexs_to_bytes(&chars);
    let xor_bytes = hexs_to_bytes(&xor_chars);
    let mut output = vec![];
    for i in 0..input_bytes.len() {
       output.push(input_bytes[i] ^ xor_bytes[i]); 
    }
    return String::from_utf8(output).unwrap();
}

#[test]
fn set1_challenge2() {
    let input = "1c0111001f010100061a024b53535009181c";
    let xor_str = "746865206b696420646f6e277420706c6179";
    let want = "hit the bull's eye";
    let got = s1ch2(input, xor_str);
    println!("{}", got);
    assert!(got == want);
}

// not the best way to determine valid letters and symbols
// but beats keeping a percentage of frequency of words and
// all the nerd stuff that comes with that.
// Caveat: this might not always work...
fn is_wanted_ascii(n: u8) -> bool {
    n == 10 || n == 32 || (n >= 64 && n <= 90) || (n >= 97 && n <= 122)
}

// https://cryptopals.com/sets/1/challenges/3
fn s1ch3(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let buffer = hexs_to_bytes(&chars);
    let mut max_size = 0;
    let mut key: u8 = 0;
    let mut current_size = 0;
    for i in 0..255 {
        let tmp: Vec<_> = buffer.iter().map(|x| x ^ i).collect();
        for n in tmp {
            if is_wanted_ascii(n) {
                current_size += 1;
            }
        }
        if current_size > max_size {
            max_size = current_size;
            key = i;
        }
        current_size = 0;
    }
    return String::from_utf8(buffer.into_iter().map(|x| x ^ key).collect()).unwrap();
}

#[test]
fn set1_challenge3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let got = s1ch3(input);
    let want = "Cooking MC's like a pound of bacon";
    assert!(got == want);
}

// https://cryptopals.com/sets/1/challenges/4
fn s1ch4(filename: &str) -> String {
    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);
    let mut max_size = 0;
    let mut key: u8 = 0;
    let mut current_size = 0;
    let mut max_index = 0;
    let mut lines = vec![];
    for (index, line) in reader.lines().enumerate() {
        let line = line.unwrap().clone();
        for i in 0..255 {
            let lines = line.chars().collect();
            let buffer: Vec<_> = hexs_to_bytes(&lines);
            let tmp: Vec<_> = buffer.iter().map(|x| x ^ i).collect();
            for n in tmp {
                if is_wanted_ascii(n) {
                    current_size = current_size + 1;
                }
            }
            if current_size > max_size {
                max_size = current_size;
                key = i;
                max_index = index;
            }
            current_size = 0;
        }
        lines.push(line.clone());
    }
    let last_line: Vec<char> = lines[max_index].chars().collect();
    let line = String::from_utf8(hexs_to_bytes(&last_line).iter().map(|x| x ^ key).collect()).unwrap();
    return line;
}

#[test]
fn set1_challenge4() {
    let filename = "./resources/4.txt";
    let got = s1ch4(filename);
    let want = "Now that the party is jumping\n";
    assert!(got == want);
}

// https://cryptopals.com/sets/1/challenges/5
fn s1ch5(input: &str) -> String {
    let buffer: Vec<char> = input.chars().collect();
    let mut want: String = "".to_owned();
    let key: Vec<_> = "ICE".chars().collect();
    let mut key_index = 0;
    let pad: &str = "0";
    for byte in buffer {
        let xor = &format!("{:x}", (byte as u8) ^ (key[key_index] as u8)).to_owned();
        if xor.chars().count() == 1 {
            want.push_str(&(pad.to_owned() + xor));
        } else {
            want.push_str(xor); 
        }
        key_index = (key_index + 1) % 3;
    }
    return want.to_string();
}

#[test]
fn set1_challenge5() {
    let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let want = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let got = s1ch5(input);
    assert!(got == want);
}

fn hamming_distance(raw_str1: String, raw_str2: String) -> usize {
    let str1 : Vec<_> = raw_str1.as_bytes().iter().collect();
    let str2 : Vec<_> = raw_str2.as_bytes().iter().collect();
    let mut distance = 0;
    for j in 0..str1.len() {
        // by byte
        for i in 0..8 {
            // right shift byte j by bit index i
            // check the union against 1: 0000 0001
            // if the last bit do not match then we know
            // they are different.
            if (str1[j] >> i & 1) != (str2[j] >> i & 1) {
                distance += 1;
            }
        }
    }
    distance
}

#[test]
fn hamming_distance_test() {
    let str1 = "this is a test";
    let str2 = "wokka wokka!!!";
    let w = 37;
    let g = hamming_distance(str1.to_string(), str2.to_string());
    assert!(w == g);
}


struct Block {
    pub blocks: Vec<u8>,
}

struct Key {
    pub key_size: usize,
    pub distances: Vec<usize>,
}

// https://cryptopals.com/sets/1/challenges/6
// TODO
fn s1ch6(filename: &str) -> String {
    let file = File::open(filename).unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    let mut keys = Vec::<Key>::new();
    println!("{:?}", buffer[buffer.len()-1]);
    buffer = base64::decode(String::from_utf8(buffer).unwrap()).unwrap();
    for keysize in 2..=40 {
        let mut key = Key {
            key_size: keysize,
            distances: Vec::new(),
        };
        for i in (0..=(buffer.len() - (keysize * 4))).step_by(keysize * 4) {
            let first = &buffer[i..i+keysize];
            let second = &buffer[i+keysize..(i+keysize*2)];
            let third = &buffer[i+keysize..(i+keysize*3)];
            let fourth = &buffer[i+keysize..(i+keysize*4)]; 
            let distance1 = hamming_distance(String::from_utf8(first.to_vec()).unwrap(),String::from_utf8(second.to_vec()).unwrap());
            let distance2 = hamming_distance(String::from_utf8(third.to_vec()).unwrap(),String::from_utf8(fourth.to_vec()).unwrap());
            key.distances.push((distance1 + distance2) / 2);
        }
        key.distances.sort();
        keys.push(key);
    }
    let mut min_key = 0;
    let mut min_distance = 0;
    let mut current_distance = 0;
    let mut key_index = 0;
    for (i, k) in keys.iter().enumerate() {
        current_distance = k.distances[0];
        if current_distance < min_distance {
            key_index = i;
            min_distance = current_distance;
        }
    }
    let mut blocks = Vec::<Block>::new();
    let mut blocks_index = 0;
    for i in (0..=(buffer.len() - keys[key_index].key_size)).step_by(keys[key_index].key_size) {
        let block = Block {
            blocks: Vec::new(),
        };
        blocks.push(block);
        blocks[blocks_index].blocks.extend_from_slice(&buffer[i..(i+keys[key_index].key_size)]);
        blocks_index = blocks_index + 1;
    }
    let mut transpose_blocks = Vec::<Block>::new();
    for h in 0..blocks.len() {
        for i in 0..blocks[h].blocks.len() {
            transpose_blocks.push(Block{ blocks: vec![] });
            for j in 0..blocks.len() {
                transpose_blocks[h].blocks.push(blocks[j].blocks[i]);
            }
        }
    }

    let mut current_size = 0;
    let mut max_size = 0;
    let mut max_key = 0;
    let mut keys = vec![];
    println!("{:?}", transpose_blocks.len());
    for i in 0..transpose_blocks.len() {
        for xor_key in 0..255 {
            let tmp: Vec<_> = transpose_blocks[i].blocks.iter().map(|x| x ^ xor_key).collect();
            for n in tmp {
                if is_wanted_ascii(n) {
                    current_size += 1;
                }
            }
            if current_size > max_size {
                max_size = current_size;
                max_key = xor_key;
                println!("{:?}", max_size);
                println!("{:?}", max_key);
            }
            current_size = 0;
        }
        keys.push(max_key);
        max_size = 0;
        max_key = 0;
    }
    return filename.to_string();
}

#[test]
fn set1_challenge6() {
    let filename = "./resources/6.txt";
    let want = "!";
    let got = s1ch6(filename);
    assert!(got == want);
}

fn main() {
    println!("Hello, world!");
}
