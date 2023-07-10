use sha1::{Digest, Sha1};

use super::Length;

const OUTER_PADDING: u8 = 0x5c;
const INNER_PADDING: u8 = 0x36;
const BLOCK_SIZE: usize = 64;

fn sha1_hmac(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();

    // the padded key is padded to the right by 0s
    let mut padded_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        hasher.update(&key);
        padded_key[..20].copy_from_slice(&hasher.finalize()[..]);
    } else {
        padded_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_hmac_hasher = Sha1::new();

    // xor the key by inner padding
    for p in padded_key.iter_mut() {
        *p ^= INNER_PADDING;
    }

    inner_hmac_hasher.update(padded_key);
    inner_hmac_hasher.update(message);
    let inner_hash = inner_hmac_hasher.finalize();

    // xor the key again by inner padding ^ outer padding
    for p in padded_key.iter_mut() {
        *p ^= OUTER_PADDING ^ INNER_PADDING;
    }

    let mut hmac_hasher = Sha1::new();
    hmac_hasher.update(padded_key);
    hmac_hasher.update(inner_hash);

    let mut res = [0u8; 20];
    res.copy_from_slice(hmac_hasher.finalize().as_slice());

    res
}

fn convert_counter_to_slice(mut counter: u64) -> [u8; 8] {
    let mut slice = [0u8; 8];

    for b in (0..slice.len()).rev() {
        slice[b] = (counter & 0xff) as u8;
        counter >>= 8;
    }

    slice
}

fn extract31(mac: &[u8; 20], offset: u8) -> u32 {
    let mut acc = 0;
    for i in 0..31 / 8 + 1 {
        acc <<= 8;
        acc += mac[offset as usize + i] as u32;
    }

    acc & 0x7fffffff
}

pub fn get_hotp(key: &[u8], counter: u64, length: &Length) -> u32 {
    let mac = sha1_hmac(key, &convert_counter_to_slice(counter));

    let offset = mac[mac.len() - 1] & 0b1111;
    let truncated = extract31(&mac, offset);

    truncated % 10u32.pow(length.get() as u32)
}
