/**
 * @runqora/sdk/better-auth
 *
 * A Better Auth plugin that lets Runqora read and manage the users of your
 * application. Your users stay in your database: the plugin answers signed
 * requests from Runqora with data it reads through Better Auth itself.
 *
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { runqora } from "@runqora/sdk/better-auth";
 *
 * export const auth = betterAuth({
 *   plugins: [runqora({ secret: process.env.RUNQORA_AUTH_SECRET! })],
 * });
 * ```
 *
 * Banning users and showing roles need Better Auth's `admin` plugin;
 * organizations need its `organization` plugin. Without them, Runqora simply
 * hides those features.
 */

import type { Auth, BetterAuthPlugin, Session, User, Where } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import {
  type AuthSource,
  BridgeNotFoundError,
  createBridge,
  readBridgeHeaders,
} from "../auth/bridge";
import type {
  BridgeMethod,
  BridgeOrganization,
  BridgeSession,
  BridgeUser,
} from "../auth/protocol";

export interface RunqoraOptions {
  /** Shared with Runqora when connecting. At least 32 characters; keep it in an environment variable. */
  secret: string;
}

type AuthContext = Awaited<Auth["$context"]>;

interface OrganizationRow {
  createdAt?: Date | null;
  id: string;
  name: string;
  slug?: string | null;
}

/** Fields the admin plugin adds to users. */
type AdminUser = User & { banned?: boolean | null; role?: string | null };

const MAX_ORGANIZATIONS = 100;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_REQUESTS = 600;

function toIso(value: Date | string | null | undefined): string | null {
  return value ? new Date(value).toISOString() : null;
}

/** Reads through Better Auth's own adapters, so custom table and field names keep working. */
function createSource(context: AuthContext): AuthSource {
  const { adapter, internalAdapter } = context;
  const plugins = new Set(
    (context.options.plugins ?? []).map((plugin) => plugin.id)
  );
  const hasAdmin = plugins.has("admin");
  const notExpired: Where = {
    field: "expiresAt",
    operator: "gt",
    value: new Date(),
  };

  function toUser(user: AdminUser): BridgeUser {
    return {
      banned: hasAdmin ? Boolean(user.banned) : null,
      createdAt: toIso(user.createdAt),
      email: user.email,
      emailVerified: user.emailVerified,
      id: user.id,
      image: user.image ?? null,
      name: user.name,
      role: hasAdmin ? (user.role ?? null) : null,
    };
  }

  /** Deliberately leaves out `token`, which is the session credential. */
  function toSession(session: Session): BridgeSession {
    return {
      createdAt: toIso(session.createdAt),
      expiresAt: toIso(session.expiresAt),
      id: session.id,
      ipAddress: session.ipAddress ?? null,
      userAgent: session.userAgent ?? null,
      userId: session.userId,
    };
  }

  async function requireUser(id: string): Promise<void> {
    if (!(await internalAdapter.findUserById(id))) {
      throw new BridgeNotFoundError();
    }
  }

  const source: AuthSource = {
    roles: hasAdmin,

    sessions: {
      async list({ limit, offset, userId }) {
        const sessions = await adapter.findMany<Session>({
          limit,
          model: "session",
          offset,
          sortBy: { direction: "desc", field: "createdAt" },
          where: userId
            ? [notExpired, { field: "userId", value: userId }]
            : [notExpired],
        });
        return sessions.map(toSession);
      },
      async revoke(id) {
        const session = await adapter.findOne<Session>({
          model: "session",
          where: [{ field: "id", value: id }],
        });
        if (!session) {
          throw new BridgeNotFoundError();
        }
        await internalAdapter.deleteSession(session.token);
      },
    },

    async stats() {
      const [users, activeSessions, organizations] = await Promise.all([
        internalAdapter.countTotalUsers(),
        adapter.count({ model: "session", where: [notExpired] }),
        plugins.has("organization")
          ? adapter.count({ model: "organization" })
          : null,
      ]);
      return { activeSessions, organizations, users };
    },

    users: {
      async get(id) {
        const user = await internalAdapter.findUserById(id);
        return user ? toUser(user) : null;
      },
      async list({ limit, offset, search }) {
        const where: Where[] | undefined = search
          ? [
              {
                connector: "OR",
                field: "email",
                mode: "insensitive",
                operator: "contains",
                value: search,
              },
              {
                connector: "OR",
                field: "name",
                mode: "insensitive",
                operator: "contains",
                value: search,
              },
            ]
          : undefined;

        const [users, total] = await Promise.all([
          internalAdapter.listUsers(
            limit,
            offset,
            { direction: "desc", field: "createdAt" },
            where
          ),
          internalAdapter.countTotalUsers(where),
        ]);
        return { total, users: users.map(toUser) };
      },
    },
  };

  if (hasAdmin) {
    source.users.ban = async (id) => {
      await requireUser(id);
      await internalAdapter.updateUser(id, { banned: true });
      // A banned user must not keep working through an existing session.
      await internalAdapter.deleteUserSessions(id);
    };
    source.users.unban = async (id) => {
      await requireUser(id);
      await internalAdapter.updateUser(id, {
        banExpires: null,
        banned: false,
        banReason: null,
      });
    };
  }

  if (plugins.has("organization")) {
    source.organizations = {
      async list() {
        const organizations = await adapter.findMany<OrganizationRow>({
          limit: MAX_ORGANIZATIONS,
          model: "organization",
          sortBy: { direction: "desc", field: "createdAt" },
        });
        return organizations.map(
          (organization): BridgeOrganization => ({
            createdAt: toIso(organization.createdAt),
            id: organization.id,
            name: organization.name,
            slug: organization.slug ?? null,
          })
        );
      },
    };
  }

  return source;
}

/**
 * Typed as a plain `BetterAuthPlugin`: its endpoints are for Runqora's servers,
 * not the application's own code, and naming their exact types would tie this
 * package to the Better Auth version it was built with.
 */
export function runqora(options: RunqoraOptions): BetterAuthPlugin {
  // Fails when the auth instance is created, not on Runqora's first request.
  createBridge(
    { users: { get: async () => null, list: async () => ({ users: [] }) } },
    { provider: "better-auth", secret: options.secret }
  );

  async function respond(
    ctx: { context: AuthContext; request: Request },
    method: BridgeMethod,
    segments: string[]
  ): Promise<Response> {
    const bridge = createBridge(createSource(ctx.context), {
      provider: "better-auth",
      secret: options.secret,
    });
    const result = await bridge.handle({
      method,
      query: Object.fromEntries(new URL(ctx.request.url).searchParams),
      segments,
      ...readBridgeHeaders(ctx.request.headers),
    });
    // A `Response` is returned as-is, which keeps the bridge's status code.
    return Response.json(result.body, {
      headers: { "Cache-Control": "no-store" },
      status: result.status,
    });
  }

  // Called by Runqora's servers only, so they are left out of the auth client.
  const get = {
    metadata: { isAction: false },
    method: "GET",
    requireRequest: true,
  } as const;
  const post = { ...get, method: "POST" } as const;

  return {
    endpoints: {
      runqoraBanUser: createAuthEndpoint(
        "/runqora/users/:id/ban",
        post,
        (ctx) => respond(ctx, "POST", ["users", ctx.params.id, "ban"])
      ),
      runqoraGetUser: createAuthEndpoint("/runqora/users/:id", get, (ctx) =>
        respond(ctx, "GET", ["users", ctx.params.id])
      ),
      runqoraInfo: createAuthEndpoint("/runqora", get, (ctx) =>
        respond(ctx, "GET", [])
      ),
      runqoraListOrganizations: createAuthEndpoint(
        "/runqora/organizations",
        get,
        (ctx) => respond(ctx, "GET", ["organizations"])
      ),
      runqoraListSessions: createAuthEndpoint("/runqora/sessions", get, (ctx) =>
        respond(ctx, "GET", ["sessions"])
      ),
      runqoraListUsers: createAuthEndpoint("/runqora/users", get, (ctx) =>
        respond(ctx, "GET", ["users"])
      ),
      runqoraRevokeSession: createAuthEndpoint(
        "/runqora/sessions/:id/revoke",
        post,
        (ctx) => respond(ctx, "POST", ["sessions", ctx.params.id, "revoke"])
      ),
      runqoraStats: createAuthEndpoint("/runqora/stats", get, (ctx) =>
        respond(ctx, "GET", ["stats"])
      ),
      runqoraUnbanUser: createAuthEndpoint(
        "/runqora/users/:id/unban",
        post,
        (ctx) => respond(ctx, "POST", ["users", ctx.params.id, "unban"])
      ),
    },
    id: "runqora",
    rateLimit: [
      {
        max: RATE_LIMIT_MAX_REQUESTS,
        pathMatcher: (path: string) => path.startsWith("/runqora"),
        window: RATE_LIMIT_WINDOW_SECONDS,
      },
    ],
  };
}
