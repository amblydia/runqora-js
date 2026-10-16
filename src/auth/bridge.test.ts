import { describe, expect, it, vi } from "vitest";
import { createSignedClient } from "../../test/signed-client";
import { type AuthSource, createBridge } from "./bridge";
import { createAuthBridge } from "./index";
import {
  type BridgeSession,
  type BridgeUser,
  SIGNATURE_HEADER,
  signRequest,
  TIMESTAMP_HEADER,
} from "./protocol";

const SECRET = "a-shared-secret-that-is-long-enough-123";
const BASE_URL = "https://app.example.com/api/runqora";

function createApplication() {
  const users: BridgeUser[] = [
    {
      banned: false,
      createdAt: "2026-01-02T03:04:05.000Z",
      email: "ada@example.com",
      emailVerified: true,
      id: "user 1/ä",
      name: "Ada",
      role: "admin",
    },
    { email: "grace@example.com", id: "user-2", name: "Grace" },
    { email: "linus@example.com", id: "user-3", name: "Linus" },
  ];
  const sessions: BridgeSession[] = [
    {
      createdAt: "2026-02-01T00:00:00.000Z",
      expiresAt: "2026-03-01T00:00:00.000Z",
      id: "session-1",
      ipAddress: "203.0.113.7",
      userAgent: "Firefox",
      userId: "user 1/ä",
    },
    { id: "session-2", userId: "user-2" },
  ];

  const source: AuthSource = {
    organizations: {
      list: () =>
        Promise.resolve([{ id: "org-1", name: "Acme", slug: "acme" }]),
    },
    roles: true,
    sessions: {
      list: ({ limit, offset, userId }) =>
        Promise.resolve(
          sessions
            .filter((session) => !userId || session.userId === userId)
            .slice(offset, offset + limit)
        ),
      revoke: (id) => {
        const index = sessions.findIndex((session) => session.id === id);
        if (index >= 0) {
          sessions.splice(index, 1);
        }
        return Promise.resolve();
      },
    },
    stats: () =>
      Promise.resolve({ activeSessions: sessions.length, users: users.length }),
    users: {
      ban: (id) => {
        const user = users.find((candidate) => candidate.id === id);
        if (user) {
          user.banned = true;
        }
        return Promise.resolve();
      },
      get: (id) =>
        Promise.resolve(users.find((user) => user.id === id) ?? null),
      list: ({ limit, offset, search }) => {
        const matches = users.filter(
          (user) => !search || user.email?.includes(search)
        );
        return Promise.resolve({
          total: matches.length,
          users: matches.slice(offset, offset + limit),
        });
      },
      unban: (id) => {
        const user = users.find((candidate) => candidate.id === id);
        if (user) {
          user.banned = false;
        }
        return Promise.resolve();
      },
    },
  };

  return { sessions, source, users };
}

/** The application's handler, called with requests signed as Runqora signs them. */
function connect(source: AuthSource, secret = SECRET) {
  const handler = createAuthBridge({
    basePath: "/api/runqora",
    secret: SECRET,
    ...source,
  });
  return createSignedClient({ baseUrl: BASE_URL, handler, secret });
}

describe("auth bridge, over HTTP", () => {
  it("reports what the application supports", async () => {
    const call = connect(createApplication().source);

    const { body, headers, status } = await call("GET", []);

    expect(status).toBe(200);
    expect(headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual({
      capabilities: {
        bans: true,
        impersonation: false,
        organizations: true,
        roles: true,
        sessions: true,
      },
      protocol: 1,
      provider: "custom",
    });
  });

  it("derives capabilities from the functions that exist", async () => {
    const { users } = createApplication().source;
    const call = connect({ users: { get: users.get, list: users.list } });

    const info = await call("GET", []);
    const sessions = await call("GET", ["sessions"]);
    const ban = await call("POST", ["users", "user-2", "ban"]);

    expect(info.body.capabilities).toEqual({
      bans: false,
      impersonation: false,
      organizations: false,
      roles: false,
      sessions: false,
    });
    expect(sessions.status).toBe(501);
    expect(sessions.body).toMatchObject({ error: { code: "unsupported" } });
    expect(ban.status).toBe(501);
  });

  it("lists users with paging and search", async () => {
    const call = connect(createApplication().source);

    const first = await call("GET", ["users"], { limit: "2" });
    const second = await call("GET", ["users"], { limit: "2", offset: "2" });
    const search = await call("GET", ["users"], { search: "grace" });

    expect(first.body).toMatchObject({ total: 3 });
    expect(first.body.users).toHaveLength(2);
    expect(second.body.users).toEqual([
      { email: "linus@example.com", id: "user-3", name: "Linus" },
    ]);
    expect(search.body).toMatchObject({
      total: 1,
      users: [{ id: "user-2" }],
    });
  });

  it("returns one user, with ids that need encoding", async () => {
    const call = connect(createApplication().source);

    const found = await call("GET", ["users", "user 1/ä"]);
    const missing = await call("GET", ["users", "nobody"]);

    expect(found.body).toMatchObject({
      user: { email: "ada@example.com", id: "user 1/ä", name: "Ada" },
    });
    expect(missing.status).toBe(404);
    expect(missing.body).toMatchObject({ error: { code: "not_found" } });
  });

  it("lists and revokes sessions", async () => {
    const application = createApplication();
    const call = connect(application.source);

    const [first] = application.sessions;
    const mine = await call("GET", ["sessions"], { userId: "user 1/ä" });
    const revoked = await call("POST", ["sessions", "session-1", "revoke"]);

    expect(mine.body).toEqual({ sessions: [first] });
    expect(revoked.body).toEqual({ ok: true });
    expect(application.sessions.map((session) => session.id)).toEqual([
      "session-2",
    ]);
  });

  it("bans and unbans a user", async () => {
    const application = createApplication();
    const call = connect(application.source);

    await call("POST", ["users", "user-2", "ban"]);
    expect(application.users[1]?.banned).toBe(true);
    await call("POST", ["users", "user-2", "unban"]);
    expect(application.users[1]?.banned).toBe(false);
  });

  it("returns statistics and organizations", async () => {
    const call = connect(createApplication().source);

    const stats = await call("GET", ["stats"]);
    const organizations = await call("GET", ["organizations"]);

    expect(stats.body).toEqual({
      activeSessions: 2,
      organizations: null,
      users: 3,
    });
    expect(organizations.body).toEqual({
      organizations: [{ id: "org-1", name: "Acme", slug: "acme" }],
    });
  });

  it("rejects another secret without revealing anything", async () => {
    const call = connect(
      createApplication().source,
      "another-secret-that-is-also-long-enough"
    );

    const list = await call("GET", ["users"]);
    // Even a request for something that does not exist only learns "unauthorized".
    const missing = await call("GET", ["users", "nobody"]);

    expect(list.status).toBe(401);
    expect(missing.status).toBe(401);
    expect(missing.body).toMatchObject({ error: { code: "unauthorized" } });
  });
});

describe("createBridge", () => {
  const NOW = 1_800_000_000_000;
  const timestamp = NOW / 1000;

  function setup() {
    const application = createApplication();
    const bridge = createBridge(application.source, {
      now: () => NOW,
      provider: "custom",
      secret: SECRET,
    });
    return { application, bridge };
  }

  async function signed(
    method: "GET" | "POST",
    segments: string[],
    query: Record<string, string> = {},
    at = timestamp
  ) {
    return {
      method,
      query,
      segments,
      signature: await signRequest({
        method,
        query,
        secret: SECRET,
        segments,
        timestamp: at,
      }),
      timestamp: String(at),
    };
  }

  it("refuses a short secret at startup", () => {
    expect(() =>
      createBridge(createApplication().source, {
        provider: "custom",
        secret: "too-short",
      })
    ).toThrow(/at least 32 characters/);
  });

  it.each([
    ["no signature", { signature: null }],
    ["no timestamp", { timestamp: null }],
    ["a signature for another secret", { signature: `v1=${"0".repeat(64)}` }],
  ])("rejects a request with %s", async (_label, override) => {
    const { bridge } = setup();

    const response = await bridge.handle({
      ...(await signed("GET", ["users"])),
      ...override,
    });

    expect(response.status).toBe(401);
  });

  it("rejects a replayed request outside the time window", async () => {
    const { bridge } = setup();

    const stale = await bridge.handle(
      await signed("GET", ["users"], {}, timestamp - 301)
    );
    const fresh = await bridge.handle(
      await signed("GET", ["users"], {}, timestamp - 299)
    );

    expect(stale.status).toBe(401);
    expect(fresh.status).toBe(200);
  });

  it("binds the signature to the method, path and query", async () => {
    const { bridge } = setup();
    const request = await signed("GET", ["users", "user-2"], { limit: "1" });

    const otherPath = await bridge.handle({
      ...request,
      segments: ["users", "user-3"],
    });
    const otherQuery = await bridge.handle({
      ...request,
      query: { limit: "100" },
    });
    const otherMethod = await bridge.handle({ ...request, method: "POST" });

    expect(otherPath.status).toBe(401);
    expect(otherQuery.status).toBe(401);
    expect(otherMethod.status).toBe(401);
  });

  it("caps the page size", async () => {
    const { application, bridge } = setup();
    const list = vi.spyOn(application.source.users, "list");

    await bridge.handle(await signed("GET", ["users"], { limit: "5000" }));

    expect(list).toHaveBeenCalledWith({
      limit: 100,
      offset: 0,
      search: undefined,
    });
  });

  it.each([
    ["an unknown resource", "GET", ["secrets"]],
    ["an extra path segment", "GET", ["users", "user-2", "password"]],
    ["an unknown action", "POST", ["users", "user-2", "delete"]],
  ] as const)("answers 404 for %s", async (_label, method, segments) => {
    const { bridge } = setup();

    const response = await bridge.handle(await signed(method, [...segments]));

    expect(response.status).toBe(404);
  });

  it("hides the application's own errors", async () => {
    const { application, bridge } = setup();
    vi.spyOn(application.source.users, "list").mockRejectedValue(
      new Error("connection string postgres://user:hunter2@db")
    );

    const response = await bridge.handle(await signed("GET", ["users"]));

    expect(response.status).toBe(500);
    expect(JSON.stringify(response.body)).not.toContain("hunter2");
  });
});

describe("createAuthBridge", () => {
  it("ignores requests outside its base path", async () => {
    const handler = createAuthBridge({
      basePath: "/api/runqora/",
      secret: SECRET,
      ...createApplication().source,
    });

    const response = await handler(
      new Request("https://app.example.com/api/runqora-other/users")
    );

    expect(response.status).toBe(404);
  });

  it("answers unsigned requests with 401 and no caching", async () => {
    const handler = createAuthBridge({
      basePath: "/api/runqora",
      secret: SECRET,
      ...createApplication().source,
    });

    const response = await handler(
      new Request(`${BASE_URL}/users`, {
        headers: { [SIGNATURE_HEADER]: "v1=nope", [TIMESTAMP_HEADER]: "1" },
      })
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});
