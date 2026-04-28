import { describe, it, expect } from "vitest";
import { mf, mfUrl } from "./mf";

describe("non-RPC routes", () => {
  it("GET /healthz returns 200 + plaintext body", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.text()).toMatch(/ok/i);
  });

  it("GET /oauth/<provider>/callback echoes code + state", async () => {
    const res = await mf.dispatchFetch(
      `${mfUrl}/oauth/github/callback?code=abc123&state=xyz`,
    );
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("abc123");
    expect(body).toContain("xyz");
  });

  it("GET /oauth/<provider>/callback without code/state is 400", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/oauth/github/callback`);
    expect(res.status).toBe(400);
  });

  it("unknown /oauth/* path is 404", async () => {
    const res = await mf.dispatchFetch(`${mfUrl}/oauth/unknown`);
    expect(res.status).toBe(404);
  });
});
