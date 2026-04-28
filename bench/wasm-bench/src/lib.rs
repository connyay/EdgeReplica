//! Wasm-bindgen exports for hashing a 4 KiB SQLite page under V8.
//!
//! Each function takes a borrowed slice and returns a u32 derived from the
//! digest so the JS caller's timing loop can't be optimized away as dead
//! code. The JS runner in `run.mjs` calls these in tight loops and times
//! them with `performance.now()`.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Blake2s256};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

type Blake2b256 = Blake2b<U32>;

fn first_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> u32 {
    first_u32(&Sha256::digest(data))
}

#[wasm_bindgen]
pub fn hash_blake2b256(data: &[u8]) -> u32 {
    first_u32(&Blake2b256::digest(data))
}

#[wasm_bindgen]
pub fn hash_blake2b512(data: &[u8]) -> u32 {
    first_u32(&Blake2b512::digest(data))
}

#[wasm_bindgen]
pub fn hash_blake2s256(data: &[u8]) -> u32 {
    first_u32(&Blake2s256::digest(data))
}

#[wasm_bindgen]
pub fn hash_blake3(data: &[u8]) -> u32 {
    first_u32(blake3::hash(data).as_bytes())
}
