/**
 * The Runqora auth bridge protocol.
 *
 * Runqora never reads a customer's user database. Instead the customer's
 * application exposes a few read-mostly HTTP endpoints (the "bridge") and
 * Runqora calls them with signed requests. This file is the whole contract
 * and is shared by both sides. It has no dependencies.
 *
 * Requests carry no body: everything is in the method, the path and the
 * query string, and all three are covered by the signature.
 */

export const PROTOCOL_VERSION = 1;
export const TIMESTAMP_HEADER = "x-runqora-timestamp";
export const SIGNATURE_HEADER = "x-runqora-signature";
export const SIGNATURE_PREFIX = "v1=";

/** A request older or newer than this is refused, which limits replays. */
export const MAX_CLOCK_SKEW_SECONDS = 300;
export const MIN_SECRET_LENGTH = 32;

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;

export type BridgeMethod = "GET" | "POST";

/** Dates travel as ISO 8601 strings. */
export interface BridgeUser {
  banned?: boolean | null;
  createdAt?: string | null;
  email?: string | null;
  emailVerified?: boolean;
  id: string;
  image?: string | null;
  name?: string | null;
  role?: string | null;
}

/** The session token is a credential and must never be included. */
export interface BridgeSession {
  createdAt?: string | null;
  expiresAt?: string | null;
  id: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  userId: string;
}

export interface BridgeOrganization {
  createdAt?: string | null;
  id: string;
  name: string;
  slug?: string | null;
}

export interface BridgeCapabilities {
  bans: boolean;
  impersonation: boolean;
  organizations: boolean;
  roles: boolean;
  sessions: boolean;
}

export interface BridgeStats {
  activeSessions: number | null;
  organizations: number | null;
  users: number | null;
}

export interface BridgeInfo {
  capabilities: BridgeCapabilities;
  protocol: number;
  /** Free-form name of the implementation, e.g. "better-auth". */
  provider: string;
}

export type BridgeErrorCode =
  | "bad_request"
  | "internal"
  | "not_found"
  | "unauthorized"
  | "unsupported";

export interface BridgeErrorBody {
  error: { code: BridgeErrorCode; message: string };
}

/** `["users", "a b"]` -> `/users/a%20b`. Both sides build paths this way. */
export function buildRoute(segments: readonly string[]): string {
  return `/${segments.map(encodeURIComponent).join("/")}`;
}

/** Query parameters in one fixed order, so both sides sign the same text. */
export function canonicalQuery(query: Record<string, string>): string {
  return Object.keys(query)
    .sort()
    .map(
      (key) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(query[key] ?? "")}`
    )
    .join("&");
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * HMAC-SHA256 over the timestamp, method, route and query. Uses Web Crypto,
 * so it runs in Node.js, Bun, Deno and edge runtimes alike.
 */
export async function signRequest(input: {
  method: BridgeMethod;
  query: Record<string, string>;
  secret: string;
  segments: readonly string[];
  timestamp: number;
}): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(input.secret),
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"]
  );
  const message = [
    `v${PROTOCOL_VERSION}`,
    input.timestamp,
    input.method,
    buildRoute(input.segments),
    canonicalQuery(input.query),
  ].join("\n");

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  );
  return `${SIGNATURE_PREFIX}${toHex(new Uint8Array(signature))}`;
}

/** Compares without stopping at the first difference, to avoid leaking a prefix through timing. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    // biome-ignore lint/suspicious/noBitwiseOperators: constant-time comparison needs XOR and OR.
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}
