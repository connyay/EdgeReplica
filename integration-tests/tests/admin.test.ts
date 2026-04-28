import { describe, it, expect } from "vitest";
import { Code, ConnectError } from "@connectrpc/connect";
import { Direction } from "../gen/edgereplica/admin/v1/admin_pb.js";
import {
  TEST_PASSWORD,
  adminClient,
  authedAdminClient,
  signupAndGetToken,
  uniqueEmail,
} from "./helpers";

describe("AdminService.Signup", () => {
  it("creates user + personal org and returns a session", async () => {
    const admin = adminClient();
    const email = uniqueEmail("ada");
    const resp = await admin.signup({ email, password: TEST_PASSWORD });
    expect(resp.sessionToken).toBeTruthy();
    const w = resp.whoami!;
    expect(w.email).toBe(email);
    expect(w.role).toBe("admin");
    expect(w.orgId).toBeTruthy();
    expect(w.userId).toBeTruthy();
  });

  it("rejects malformed emails with InvalidArgument", async () => {
    const admin = adminClient();
    await expect(
      admin.signup({ email: "not-an-email", password: TEST_PASSWORD }),
    ).rejects.toMatchObject({
      name: "ConnectError",
      code: Code.InvalidArgument,
    });
  });

  it("rejects duplicate emails (case-insensitive)", async () => {
    const admin = adminClient();
    const email = uniqueEmail("dup");
    await admin.signup({ email, password: TEST_PASSWORD });
    await expect(
      admin.signup({ email: email.toUpperCase(), password: TEST_PASSWORD }),
    ).rejects.toBeInstanceOf(ConnectError);
  });
});

describe("AdminService.Login", () => {
  it("returns a session for correct credentials", async () => {
    const { email, password } = await signupAndGetToken();
    const resp = await adminClient().login({ email, password });
    expect(resp.sessionToken).toBeTruthy();
    expect(resp.whoami?.email).toBe(email);
  });

  it("rejects wrong password with Unauthenticated", async () => {
    const { email } = await signupAndGetToken();
    await expect(
      adminClient().login({ email, password: "wrong-password" }),
    ).rejects.toMatchObject({ code: Code.Unauthenticated });
  });

  it("rejects unknown email with Unauthenticated", async () => {
    await expect(
      adminClient().login({
        email: uniqueEmail("ghost"),
        password: "irrelevant",
      }),
    ).rejects.toMatchObject({ code: Code.Unauthenticated });
  });
});

describe("AdminService.Whoami", () => {
  it("requires a session token", async () => {
    await expect(adminClient().whoami({})).rejects.toMatchObject({
      code: Code.Unauthenticated,
    });
  });

  it("echoes the verified session", async () => {
    const { client, email } = await authedAdminClient();
    const resp = await client.whoami({});
    expect(resp.whoami?.email).toBe(email);
    expect(resp.whoami?.role).toBe("admin");
  });
});

describe("AdminService databases", () => {
  it("create → list → delete round trip", async () => {
    const { client } = await authedAdminClient();

    const created = await client.createDatabase({ name: "main" });
    expect(created.name).toBe("main");
    expect(created.id).toBeTruthy();

    const list = await client.listDatabases({});
    expect(list.databases.map((d) => d.id)).toContain(created.id);

    await client.deleteDatabase({ databaseId: created.id });
    const after = await client.listDatabases({});
    expect(after.databases.map((d) => d.id)).not.toContain(created.id);
  });

  it("rejects names with spaces (InvalidArgument)", async () => {
    const { client } = await authedAdminClient();
    await expect(
      client.createDatabase({ name: "bad name with spaces" }),
    ).rejects.toMatchObject({ code: Code.InvalidArgument });
  });

  it("requires a session", async () => {
    await expect(
      adminClient().createDatabase({ name: "nope" }),
    ).rejects.toMatchObject({ code: Code.Unauthenticated });
  });

  it("delete on unknown id is NotFound", async () => {
    const { client } = await authedAdminClient();
    await expect(
      client.deleteDatabase({ databaseId: "does-not-exist" }),
    ).rejects.toMatchObject({ code: Code.NotFound });
  });
});

describe("AdminService.IssueSyncToken", () => {
  it("issues a token bound to a database + direction", async () => {
    const { client } = await authedAdminClient();
    const db = await client.createDatabase({ name: "syncdb" });

    const resp = await client.issueSyncToken({
      databaseId: db.id,
      direction: Direction.PUSH,
      ttlSeconds: 60n,
    });
    expect(resp.token).toBeTruthy();
    expect(resp.expUnix).toBeGreaterThan(0n);
  });

  it("rejects unknown database with NotFound", async () => {
    const { client } = await authedAdminClient();
    await expect(
      client.issueSyncToken({
        databaseId: "missing",
        direction: Direction.PUSH,
        ttlSeconds: 60n,
      }),
    ).rejects.toMatchObject({ code: Code.NotFound });
  });
});

describe("AdminService.StartOAuth", () => {
  // GITHUB_CLIENT_ID/SECRET are blank in mf.ts, so StartOAuth must refuse
  // rather than emit a useless redirect.
  it("returns Unimplemented when no provider creds are configured", async () => {
    await expect(
      adminClient().startOAuth({ provider: "github" }),
    ).rejects.toBeInstanceOf(ConnectError);
  });
});
