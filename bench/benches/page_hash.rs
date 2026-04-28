//! Compare SHA-256, BLAKE2b, and BLAKE3 throughput on a SQLite-sized 4 KiB page.
//!
//! Run with `cargo bench -p edgereplica-bench`. Open
//! `target/criterion/report/index.html` for the pretty version.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Blake2s256};
use blake3;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};
use std::hint::black_box;

type Blake2b256 = Blake2b<U32>;

const PAGE_SIZE: usize = 4096;

fn make_page() -> Vec<u8> {
    // Deterministic seed so reruns hash identical bytes — keeps criterion's
    // run-over-run comparison meaningful.
    let mut rng = StdRng::seed_from_u64(0xED9E_5EBA);
    let mut buf = vec![0u8; PAGE_SIZE];
    rng.fill_bytes(&mut buf);
    buf
}

fn bench_page_hash(c: &mut Criterion) {
    let page = make_page();
    let mut group = c.benchmark_group("page_hash_4kb");
    group.throughput(Throughput::Bytes(PAGE_SIZE as u64));

    group.bench_function(BenchmarkId::new("sha256", PAGE_SIZE), |b| {
        b.iter(|| {
            let digest = Sha256::digest(black_box(&page[..]));
            black_box(digest);
        });
    });

    group.bench_function(BenchmarkId::new("blake2b256", PAGE_SIZE), |b| {
        b.iter(|| {
            let digest = Blake2b256::digest(black_box(&page[..]));
            black_box(digest);
        });
    });

    group.bench_function(BenchmarkId::new("blake2b512", PAGE_SIZE), |b| {
        b.iter(|| {
            let digest = Blake2b512::digest(black_box(&page[..]));
            black_box(digest);
        });
    });

    group.bench_function(BenchmarkId::new("blake2s256", PAGE_SIZE), |b| {
        b.iter(|| {
            let digest = Blake2s256::digest(black_box(&page[..]));
            black_box(digest);
        });
    });

    group.bench_function(BenchmarkId::new("blake3", PAGE_SIZE), |b| {
        b.iter(|| {
            let digest = blake3::hash(black_box(&page[..]));
            black_box(digest);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_page_hash);
criterion_main!(benches);
