import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { admin, organization } from "better-auth/plugins";
import { beforeAll, describe, expect, it } from "vitest";
import { createSignedClient } from "../../test/signed-client";
import { SIGNATURE_HEADER, TIMESTAMP_HEADER } from "../auth/protocol";
import { runqora } from "./index";

const SECRET = "a-shared-secret-that-is-long-enough-123";
const AUTH_URL = "https://app.example.com/api/auth";
const PASSWORD = "correct-horse-battery";

interface UserBody {
  banned: boolean | null;
  email: string;
  id: string;
  name: string;
  role: string | null;
}

/**
 * A real Better Auth instance, as a customer would run it, with the plugin
 * installed, called through `auth.handler` with requests signed as Runqora
 * signs them.
 */
function createCustomerApp(options: { withAdmin: boolean }) {
  const rows = (): Record<string, unknown>[] => [];
  const database = {
    account: rows(),
    invitation: rows(),
    member: rows(),
    organization: rows(),
    session: rows(),
    user: rows(),
    verification: rows(),
  };

  const auth = betterAuth({
    baseURL: "https://app.example.com",
    database: memoryAdapter(database),
    emailAndPassword: { enabled: true },
    plugins: options.withAdmin
      ? [admin(), organization(), runqora({ secret: SECRET })]
      : [runqora({ secret: SECRET })],
    secret: "customer-app-secret-that-is-long-enough",
  });

  const call = createSignedClient({
    baseUrl: `${AUTH_URL}/runqora`,
    handler: (request) => auth.handler(request),
    secret: SECRET,
  });

  async function signUp(name: string) {
    const result = await auth.api.signUpEmail({
      body: {
        email: `${name.toLowerCase()}@example.com`,
        name,
        password: PASSWORD,
      },
    });
    return result.user.id;
  }

  return { auth, call, database, signUp };
}

describe("runqora plugin with admin and organization plugins", () => {
  const app = createCustomerApp({ withAdmin: true });
  const { call } = app;
  let ada: string;
  let grace: string;

  async function user(id: string) {
    return (await call<{ user: UserBody }>("GET", ["users", id])).body.user;
  }

  async function sessionsOf(userId?: string) {
    const query: Record<string, string> = userId ? { userId } : {};
    const { body } = await call<{ sessions: { id: string; userId: string }[] }>(
      "GET",
      ["sessions"],
      query
    );
    return body.sessions;
  }

  beforeAll(async () => {
    ada = await app.signUp("Ada");
    grace = await app.signUp("Grace");
    await app.signUp("Linus");
    app.database.organization.push({
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
      id: "org-1",
      name: "Acme",
      slug: "acme",
    });
  });

  it("reports every capability", async () => {
    const { body, headers } = await call("GET", []);

    expect(body).toEqual({
      capabilities: {
        bans: true,
        impersonation: false,
        organizations: true,
        roles: true,
        sessions: true,
      },
      protocol: 1,
      provider: "better-auth",
    });
    expect(headers.get("cache-control")).toBe("no-store");
  });

  it("counts users, sessions and organizations", async () => {
    const { body } = await call("GET", ["stats"]);

    expect(body).toEqual({ activeSessions: 3, organizations: 1, users: 3 });
  });

  it("lists users with a total and pages", async () => {
    const first = await call<{ total: number; users: UserBody[] }>(
      "GET",
      ["users"],
      { limit: "2" }
    );
    const second = await call<{ total: number; users: UserBody[] }>(
      "GET",
      ["users"],
      { limit: "2", offset: "2" }
    );

    expect(first.body.total).toBe(3);
    expect(first.body.users).toHaveLength(2);
    expect(second.body.users).toHaveLength(1);
    expect(
      [...first.body.users, ...second.body.users]
        .map((entry) => entry.name)
        .sort()
    ).toEqual(["Ada", "Grace", "Linus"]);
  });

  it("searches by email or name, ignoring case", async () => {
    const names = async (search: string) => {
      const { body } = await call<{ users: UserBody[] }>("GET", ["users"], {
        search,
      });
      return body.users.map((entry) => entry.name);
    };

    expect(await names("GRACE@")).toEqual(["Grace"]);
    expect(await names("lin")).toEqual(["Linus"]);
    expect(await names("nobody")).toEqual([]);
  });

  it("returns one user with admin fields", async () => {
    const missing = await call("GET", ["users", "missing"]);

    expect(await user(ada)).toMatchObject({
      banned: false,
      email: "ada@example.com",
      emailVerified: false,
      id: ada,
      name: "Ada",
      role: "user",
    });
    expect(missing.status).toBe(404);
  });

  it("lists sessions without ever exposing a session token", async () => {
    const { body } = await call("GET", ["sessions"]);
    const all = await sessionsOf();
    const mine = await sessionsOf(ada);

    expect(all).toHaveLength(3);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ userId: ada });

    const tokens = app.database.session.map((session) => session.token);
    expect(tokens.length).toBeGreaterThan(0);
    for (const token of tokens) {
      expect(JSON.stringify(body)).not.toContain(String(token));
    }
  });

  it("revokes a session by id", async () => {
    const target = (await sessionsOf(grace))[0]?.id ?? "";

    const revoked = await call("POST", ["sessions", target, "revoke"]);
    const again = await call("POST", ["sessions", target, "revoke"]);

    expect(revoked.body).toEqual({ ok: true });
    expect(await sessionsOf(grace)).toEqual([]);
    expect(again.status).toBe(404);
  });

  it("bans a user and ends their sessions, then unbans", async () => {
    await call("POST", ["users", ada, "ban"]);

    expect(await user(ada)).toMatchObject({ banned: true });
    expect(await sessionsOf(ada)).toEqual([]);
    // Better Auth itself now refuses the sign-in.
    await expect(
      app.auth.api.signInEmail({
        body: { email: "ada@example.com", password: PASSWORD },
      })
    ).rejects.toThrow();

    await call("POST", ["users", ada, "unban"]);
    expect(await user(ada)).toMatchObject({ banned: false });
    await expect(
      app.auth.api.signInEmail({
        body: { email: "ada@example.com", password: PASSWORD },
      })
    ).resolves.toBeTruthy();
  });

  it("reports a missing user when banning", async () => {
    const response = await call("POST", ["users", "missing", "ban"]);

    expect(response.status).toBe(404);
  });

  it("lists organizations", async () => {
    const { body } = await call("GET", ["organizations"]);

    expect(body).toEqual({
      organizations: [
        {
          createdAt: "2026-01-01T00:00:00.000Z",
          id: "org-1",
          name: "Acme",
          slug: "acme",
        },
      ],
    });
  });
});

describe("runqora plugin on a minimal Better Auth setup", () => {
  const app = createCustomerApp({ withAdmin: false });
  const { call } = app;

  beforeAll(async () => {
    await app.signUp("Solo");
  });

  it("only offers what the setup supports", async () => {
    const info = await call("GET", []);
    const stats = await call("GET", ["stats"]);

    expect(info.body.capabilities).toEqual({
      bans: false,
      impersonation: false,
      organizations: false,
      roles: false,
      sessions: true,
    });
    expect(stats.body).toEqual({
      activeSessions: 1,
      organizations: null,
      users: 1,
    });
  });

  it("leaves admin fields empty and refuses admin actions", async () => {
    const { body } = await call<{ users: UserBody[] }>("GET", ["users"]);
    const id = body.users[0]?.id ?? "";

    const ban = await call("POST", ["users", id, "ban"]);
    const organizations = await call("GET", ["organizations"]);

    expect(body.users[0]).toMatchObject({ banned: null, role: null });
    expect(ban.status).toBe(501);
    expect(organizations.status).toBe(501);
  });
});

describe("runqora plugin security", () => {
  const app = createCustomerApp({ withAdmin: true });

  it("refuses to start with a short secret", () => {
    expect(() => runqora({ secret: "short" })).toThrow(
      /at least 32 characters/
    );
  });

  it.each([
    ["without a signature", {}],
    [
      "with a forged signature",
      {
        [SIGNATURE_HEADER]: `v1=${"0".repeat(64)}`,
        [TIMESTAMP_HEADER]: String(Math.floor(Date.now() / 1000)),
      },
    ],
  ])("rejects requests %s", async (_label, headers) => {
    for (const [method, path] of [
      ["GET", "/runqora"],
      ["GET", "/runqora/users"],
      ["POST", "/runqora/users/anyone/ban"],
    ]) {
      const response = await app.auth.handler(
        new Request(`${AUTH_URL}${path}`, { headers, method })
      );
      expect(response.status).toBe(401);
    }
  });

  it("rejects requests signed with a different secret", async () => {
    const stranger = createSignedClient({
      baseUrl: `${AUTH_URL}/runqora`,
      handler: (request) => app.auth.handler(request),
      secret: "another-secret-that-is-also-long-enough",
    });

    const response = await stranger("GET", ["users"]);

    expect(response.status).toBe(401);
  });
});
