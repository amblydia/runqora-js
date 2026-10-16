/**
 * runqora/auth
 *
 * Connect any authentication system to Runqora: describe how to read your
 * users (and, optionally, sessions and organizations) and mount the returned
 * handler at a route in your application.
 *
 * ```ts
 * import { createAuthBridge } from "runqora/auth";
 *
 * const bridge = createAuthBridge({
 *   basePath: "/api/runqora",
 *   secret: process.env.RUNQORA_AUTH_SECRET!,
 *   users: {
 *     get: (id) => db.users.find(id),
 *     list: ({ limit, offset, search }) => db.users.page({ limit, offset, search }),
 *   },
 * });
 *
 * // Any runtime with Web `Request`/`Response`: Next.js route handlers, Hono, Bun...
 * export const GET = bridge;
 * export const POST = bridge;
 * ```
 */

import { type AuthSource, createBridge, readBridgeHeaders } from "./bridge";

export { type AuthSource, BridgeNotFoundError } from "./bridge";
export type {
  BridgeOrganization,
  BridgeSession,
  BridgeStats,
  BridgeUser,
} from "./protocol";

export interface AuthBridgeOptions extends AuthSource {
  /** Path the handler is mounted at, e.g. "/api/runqora". */
  basePath: string;
  /** Shared with Runqora when connecting. At least 32 characters; keep it in an environment variable. */
  secret: string;
}

const EDGE_SLASHES = /^\/+|\/+$/g;

/** Returns a `(request: Request) => Promise<Response>` handler for the bridge. */
export function createAuthBridge(options: AuthBridgeOptions) {
  const { basePath, secret, ...source } = options;
  const bridge = createBridge(source, { provider: "custom", secret });
  const base = `/${basePath.replace(EDGE_SLASHES, "")}`;

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.pathname !== base && !url.pathname.startsWith(`${base}/`)) {
      return Response.json(
        { error: { code: "not_found", message: "Not found." } },
        { status: 404 }
      );
    }

    let segments: string[];
    try {
      segments = url.pathname
        .slice(base.length)
        .split("/")
        .filter(Boolean)
        .map(decodeURIComponent);
    } catch {
      return Response.json(
        { error: { code: "bad_request", message: "Malformed path." } },
        { status: 400 }
      );
    }

    const result = await bridge.handle({
      method: request.method,
      query: Object.fromEntries(url.searchParams),
      segments,
      ...readBridgeHeaders(request.headers),
    });
    return Response.json(result.body, {
      headers: { "Cache-Control": "no-store" },
      status: result.status,
    });
  };
}
