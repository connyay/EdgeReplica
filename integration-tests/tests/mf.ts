import { Miniflare } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const buildDir = resolve(__dirname, "..", "..", "worker", "build");

const jsCode = readFileSync(resolve(buildDir, "index.js"), "utf-8");
const wasmBytes = readFileSync(resolve(buildDir, "index_bg.wasm"));

// Deterministic 32-byte test key, base64-encoded. Used as SESSION_KEY so
// the macaroon root is stable across worker reloads inside a test run.
const TEST_SESSION_KEY = Buffer.alloc(32, "k").toString("base64");

export const mf = new Miniflare({
  workers: [
    {
      name: "edgereplica",
      modules: [
        { type: "ESModule", path: "index.js", contents: jsCode },
        {
          type: "CompiledWasm",
          path: "index_bg.wasm",
          contents: wasmBytes,
        },
      ],
      compatibilityDate: "2026-04-22",
      d1Databases: ["DB"],
      durableObjects: {
        EDGE_REPLICA: { className: "EdgeReplica", useSQLite: true },
      },
      bindings: {
        SESSION_KEY: TEST_SESSION_KEY,
        SESSION_TTL_SECONDS: "86400",
        SYNC_TOKEN_TTL_SECONDS: "3600",
        MAX_SYNC_TOKEN_TTL_SECONDS: "86400",
        OAUTH_STATE_TTL_SECONDS: "600",
        OAUTH_REDIRECT_BASE: "",
        GITHUB_CLIENT_ID: "",
        GITHUB_CLIENT_SECRET: "",
        GOOGLE_CLIENT_ID: "",
        GOOGLE_CLIENT_SECRET: "",
        AUTO_MIGRATE: "true",
      },
    },
  ],
});

export const mfUrl = (await mf.ready).toString().replace(/\/$/, "");
