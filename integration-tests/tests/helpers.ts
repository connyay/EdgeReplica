import { createClient, type Client, type Transport } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";

import { mf, mfUrl } from "./mf";

import { AdminService } from "../gen/edgereplica/admin/v1/admin_pb.js";

export const TEST_PASSWORD = "verylong-password-is-fine";

export interface TransportOptions {
  sessionToken?: string;
  useBinaryFormat?: boolean;
}

export function makeTransport(opts: TransportOptions = {}): Transport {
  return createConnectTransport({
    baseUrl: mfUrl,
    useBinaryFormat: opts.useBinaryFormat ?? true,
    fetch: ((input: RequestInfo | URL, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      if (opts.sessionToken && !headers.has("authorization")) {
        headers.set("authorization", `Bearer ${opts.sessionToken}`);
      }
      // dispatchFetch expects miniflare's own Request type, not the DOM
      // one. connect-web only ever calls fetch() with a string URL, so
      // normalizing to a string here is sound and avoids the cross-type
      // Request mismatch.
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      // The Node DOM RequestInit and miniflare's RequestInit disagree on
      // BodyInit (Blob/ReadableStream variance). The runtime values are
      // compatible — this cast is the seam.
      return mf.dispatchFetch(url, {
        ...init,
        headers,
      } as unknown as Parameters<typeof mf.dispatchFetch>[1]);
    }) as unknown as typeof globalThis.fetch,
  });
}

export const adminClient = (opts?: TransportOptions) =>
  createClient(AdminService, makeTransport(opts));

// Unique per test so the shared miniflare D1 instance stays clean across the run.
let counter = 0;
export function uniqueEmail(prefix = "user") {
  counter += 1;
  return `${prefix}+${Date.now()}-${counter}@example.com`;
}

export async function signupAndGetToken(
  email = uniqueEmail(),
  password = TEST_PASSWORD,
): Promise<{ email: string; password: string; sessionToken: string }> {
  const admin = adminClient();
  const resp = await admin.signup({ email, password });
  return { email, password, sessionToken: resp.sessionToken };
}

export async function authedAdminClient(): Promise<{
  client: Client<typeof AdminService>;
  email: string;
  password: string;
  sessionToken: string;
}> {
  const session = await signupAndGetToken();
  return { client: adminClient({ sessionToken: session.sessionToken }), ...session };
}
