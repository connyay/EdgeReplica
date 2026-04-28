// Bench runner for the wasm hash module under V8 (Node).
//
// Build first:  wasm-pack build --release --target nodejs bench/wasm-bench
// Then run:     node bench/wasm-bench/run.mjs
//
// V8 is the same engine that runs Cloudflare Workers, so these numbers are
// a reasonable proxy for production worker performance — closer than
// wasmtime (Cranelift) would be.

import {
  hash_sha256,
  hash_blake2b256,
  hash_blake2b512,
  hash_blake2s256,
  hash_blake3,
} from "./pkg/edgereplica_wasm_bench.js";

const PAGE_SIZE = 4096;
const WARMUP_ITERS = 10_000;
const MEASURE_ITERS = 200_000;

// Deterministic page bytes — same idea as the native bench's seeded RNG.
function makePage() {
  const buf = new Uint8Array(PAGE_SIZE);
  let x = 0xed9e5eba >>> 0;
  for (let i = 0; i < PAGE_SIZE; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    buf[i] = x & 0xff;
  }
  return buf;
}

function bench(name, fn, page) {
  // Warmup so V8's TurboFan tier promotes the call site before we measure.
  let acc = 0;
  for (let i = 0; i < WARMUP_ITERS; i++) acc ^= fn(page);

  const start = process.hrtime.bigint();
  for (let i = 0; i < MEASURE_ITERS; i++) acc ^= fn(page);
  const elapsedNs = Number(process.hrtime.bigint() - start);

  // Print acc so V8 can't elide the loop entirely.
  const nsPerOp = elapsedNs / MEASURE_ITERS;
  const gibPerSec = (PAGE_SIZE * MEASURE_ITERS) / elapsedNs / 1.073741824;
  console.log(
    `${name.padEnd(12)}  ${nsPerOp.toFixed(0).padStart(6)} ns/page   ` +
      `${gibPerSec.toFixed(2)} GiB/s   (acc=${acc})`,
  );
}

const page = makePage();
console.log(`page=${PAGE_SIZE}B  iters=${MEASURE_ITERS.toLocaleString()}\n`);

bench("sha256", hash_sha256, page);
bench("blake2b256", hash_blake2b256, page);
bench("blake2b512", hash_blake2b512, page);
bench("blake2s256", hash_blake2s256, page);
bench("blake3", hash_blake3, page);
