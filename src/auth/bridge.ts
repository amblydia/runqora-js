import {
  type BridgeCapabilities,
  type BridgeErrorBody,
  type BridgeErrorCode,
  type BridgeInfo,
  type BridgeMethod,
  type BridgeOrganization,
  type BridgeSession,
  type BridgeStats,
  type BridgeUser,
  DEFAULT_PAGE_SIZE,
  MAX_CLOCK_SKEW_SECONDS,
  MAX_PAGE_SIZE,
  MIN_SECRET_LENGTH,
  PROTOCOL_VERSION,
  SIGNATURE_HEADER,
  signRequest,
  TIMESTAMP_HEADER,
  timingSafeEqual,
} from "./protocol";

/**
 * What an application provides to be manageable from Runqora. Only
 * `users.list` and `users.get` are required; every optional function that is
 * present switches the matching dashboard feature on.
 */
export interface AuthSource {
  organizations?: {
    list: () => Promise<BridgeOrganization[]>;
  };
  /** Set when users carry a `role`. */
  roles?: boolean;
  sessions?: {
    list: (input: {
      limit: number;
      offset: number;
      userId?: string;
    }) => Promise<BridgeSession[]>;
    revoke: (id: string) => Promise<void>;
  };
  stats?: () => Promise<Partial<BridgeStats>>;
  users: {
    ban?: (id: string) => Promise<void>;
    get: (id: string) => Promise<BridgeUser | null>;
    list: (input: {
      limit: number;
      offset: number;
      search?: string;
    }) => Promise<{ total?: number | null; users: BridgeUser[] }>;
    unban?: (id: string) => Promise<void>;
  };
}

export interface BridgeRequest {
  method: string;
  query: Record<string, string>;
  /** Path below the bridge's base, split and decoded: `/users/42` -> `["users", "42"]`. */
  segments: string[];
  signature: string | null;
  timestamp: string | null;
}

export interface BridgeResponse {
  body: unknown;
  status: number;
}

const MAX_SEARCH_LENGTH = 200;
const MILLISECONDS = 1000;

/**
 * Throw this from an `AuthSource` function when the user or session it was
 * asked to change does not exist. Runqora then reports "not found".
 */
export class BridgeNotFoundError extends Error {
  constructor(message = "Not found.") {
    super(message);
    this.name = "BridgeNotFoundError";
  }
}

class BridgeError extends Error {
  readonly code: BridgeErrorCode;
  readonly status: number;

  constructor(code: BridgeErrorCode, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const notFound = () => new BridgeError("not_found", 404, "Not found.");

function toBridgeError(error: unknown): BridgeError {
  if (error instanceof BridgeError) {
    return error;
  }
  if (error instanceof BridgeNotFoundError) {
    return notFound();
  }
  // Details of the application's own failure stay in the application.
  return new BridgeError("internal", 500, "The application failed.");
}
const unsupported = (feature: string) =>
  new BridgeError(
    "unsupported",
    501,
    `This application does not support ${feature}.`
  );

function toInteger(value: string | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new BridgeError("bad_request", 400, "Invalid pagination value.");
  }
  return parsed;
}

function pagination(query: Record<string, string>) {
  return {
    limit: Math.min(
      Math.max(toInteger(query.limit, DEFAULT_PAGE_SIZE), 1),
      MAX_PAGE_SIZE
    ),
    offset: toInteger(query.offset, 0),
  };
}

export function describeCapabilities(source: AuthSource): BridgeCapabilities {
  return {
    bans: Boolean(source.users.ban && source.users.unban),
    // Signing in as a user is deliberately not part of the protocol.
    impersonation: false,
    organizations: Boolean(source.organizations),
    roles: Boolean(source.roles),
    sessions: Boolean(source.sessions),
  };
}

/**
 * The protocol's server side, independent of any web framework. It verifies
 * the signature, then routes the request to the `AuthSource`.
 */
export function createBridge(
  source: AuthSource,
  options: {
    /** Injected in tests. Defaults to the system clock. */
    now?: () => number;
    provider: string;
    secret: string;
  }
) {
  if (options.secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `The Runqora auth secret must be at least ${MIN_SECRET_LENGTH} characters. Generate one with: openssl rand -base64 32`
    );
  }
  const now = options.now ?? Date.now;

  async function verify(request: BridgeRequest, method: BridgeMethod) {
    const timestamp = Number(request.timestamp);
    const unauthorized = new BridgeError(
      "unauthorized",
      401,
      "The request signature is missing, expired or invalid."
    );
    if (
      !(request.signature && Number.isInteger(timestamp)) ||
      Math.abs(now() / MILLISECONDS - timestamp) > MAX_CLOCK_SKEW_SECONDS
    ) {
      throw unauthorized;
    }

    const expected = await signRequest({
      method,
      query: request.query,
      secret: options.secret,
      segments: request.segments,
      timestamp,
    });
    if (!timingSafeEqual(expected, request.signature)) {
      throw unauthorized;
    }
  }

  /** GET routes without an id, by first path segment. */
  const collections = new Map<
    string,
    (query: Record<string, string>) => Promise<unknown>
  >([
    [
      "organizations",
      async () => {
        if (!source.organizations) {
          throw unsupported("organizations");
        }
        return { organizations: await source.organizations.list() };
      },
    ],
    [
      "sessions",
      async (query) => {
        if (!source.sessions) {
          throw unsupported("sessions");
        }
        return {
          sessions: await source.sessions.list({
            ...pagination(query),
            userId: query.userId || undefined,
          }),
        };
      },
    ],
    [
      "stats",
      async (): Promise<BridgeStats> => ({
        activeSessions: null,
        organizations: null,
        users: null,
        ...(await source.stats?.()),
      }),
    ],
    [
      "users",
      async (query) => {
        const { search = "" } = query;
        const result = await source.users.list({
          ...pagination(query),
          search: search.slice(0, MAX_SEARCH_LENGTH) || undefined,
        });
        return { total: result.total ?? null, users: result.users };
      },
    ],
  ]);

  async function getUser(id: string) {
    const user = await source.users.get(id);
    if (!user) {
      throw notFound();
    }
    return { user };
  }

  function get(request: BridgeRequest): Promise<unknown> {
    const [resource, id, extra] = request.segments;
    if (extra !== undefined) {
      throw notFound();
    }
    if (resource === undefined) {
      const info: BridgeInfo = {
        capabilities: describeCapabilities(source),
        protocol: PROTOCOL_VERSION,
        provider: options.provider,
      };
      return Promise.resolve(info);
    }
    if (id !== undefined) {
      if (resource !== "users") {
        throw notFound();
      }
      return getUser(id);
    }

    const list = collections.get(resource);
    if (!list) {
      throw notFound();
    }
    return list(request.query);
  }

  async function post(request: BridgeRequest): Promise<unknown> {
    const [resource, id, action, extra] = request.segments;
    if (!(id && action) || extra !== undefined) {
      throw notFound();
    }

    if (resource === "sessions" && action === "revoke") {
      if (!source.sessions) {
        throw unsupported("sessions");
      }
      await source.sessions.revoke(id);
      return { ok: true };
    }
    if (resource === "users" && (action === "ban" || action === "unban")) {
      const change = source.users[action];
      if (!(source.users.ban && source.users.unban && change)) {
        throw unsupported("banning users");
      }
      await change(id);
      return { ok: true };
    }
    throw notFound();
  }

  return {
    async handle(request: BridgeRequest): Promise<BridgeResponse> {
      try {
        if (request.method !== "GET" && request.method !== "POST") {
          throw new BridgeError("bad_request", 405, "Method not allowed.");
        }
        // Nothing, not even "not found", is revealed to an unsigned request.
        await verify(request, request.method);

        const body =
          request.method === "GET" ? await get(request) : await post(request);
        return { body, status: 200 };
      } catch (error) {
        const failure = toBridgeError(error);
        const body: BridgeErrorBody = {
          error: { code: failure.code, message: failure.message },
        };
        return { body, status: failure.status };
      }
    },
  };
}

export type Bridge = ReturnType<typeof createBridge>;

/** Reads the protocol's two headers from any `Headers`-like object. */
export function readBridgeHeaders(headers: Headers) {
  return {
    signature: headers.get(SIGNATURE_HEADER),
    timestamp: headers.get(TIMESTAMP_HEADER),
  };
}
