/**
 * Server-side client for Runqora.
 *
 * ```ts
 * const runqora = new Runqora({ apiKey: process.env.RUNQORA_API_KEY });
 *
 * const result = await runqora.keys.verify(key, { scopes: ["orders:read"] });
 * await runqora.webhooks.send({ type: "order.created", data: { id: "o_1" } });
 * await runqora.monitoring.heartbeat(process.env.NIGHTLY_EXPORT_MONITOR_ID);
 * ```
 *
 * Has no dependencies and uses only `fetch` and Web Crypto, so it runs in
 * Node.js, Bun, Deno and edge runtimes. Use it on a server: the API key it
 * holds must never reach a browser.
 */

import { RunqoraError } from "./errors";

export { RunqoraError, type RunqoraErrorCode } from "./errors";
export {
  type VerifyWebhookInput,
  verifyWebhook,
  type WebhookEvent,
  WebhookVerificationError,
} from "./webhook-signature";

const DEFAULT_BASE_URL = "https://api.runqora.dev";
const DEFAULT_TIMEOUT_MS = 5000;
/** Longer than any real key; anything above it is refused without a request. */
const MAX_KEY_LENGTH = 256;
const TRAILING_SLASHES = /\/+$/;

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface RunqoraOptions {
  /**
   * An API key of the project, created in the dashboard with the platform
   * permissions this server needs. It also decides the environment: a
   * production key only works with production keys and endpoints.
   */
  apiKey: string;
  /** Only needed when the API is not at its public address. */
  baseUrl?: string;
  /** For tests and runtimes without a global `fetch`. */
  fetch?: FetchLike;
  /** How long to wait for an answer. Defaults to 5 seconds. */
  timeoutMs?: number;
}

/** Why a key was refused. `not_found` includes keys of other projects. */
export type KeyRejectionCode =
  | "expired"
  | "insufficient_scopes"
  | "not_found"
  | "revoked"
  | "wrong_environment";

export interface VerifiedKey {
  /** Identifier of the environment the key was issued for. */
  environment: string;
  /** ISO 8601 timestamp, or null when the key does not expire. */
  expiresAt: string | null;
  keyId: string;
  name: string;
  scopes: string[];
  valid: true;
}

export interface RejectedKey {
  code: KeyRejectionCode;
  valid: false;
}

export type VerifyKeyResult = RejectedKey | VerifiedKey;

export interface VerifyKeyOptions {
  /** Scopes the key must all have. */
  scopes?: string[];
}

export interface KeysClient {
  /**
   * Checks a key one of your consumers presented. Resolves for every key,
   * good or bad; rejects with `RunqoraError` only when no answer was obtained.
   * Needs the "Verify API keys" permission.
   */
  verify: (key: string, options?: VerifyKeyOptions) => Promise<VerifyKeyResult>;
}

export interface SendWebhookInput {
  /** Any JSON value. Delivered as the event's `data`. */
  data: unknown;
  /**
   * Your own identifier for this event. Sending the same id again delivers
   * nothing new, which makes a retried request safe.
   */
  id?: string;
  /** Your own event name, e.g. `order.created`. Endpoints subscribe by type. */
  type: string;
}

export interface SentWebhook {
  /** Endpoints the event was queued for. Zero when none subscribe to the type. */
  deliveries: number;
  eventId: string;
}

export interface WebhooksClient {
  /**
   * Queues an event for every enabled endpoint of this key's environment that
   * subscribes to its type. Returns as soon as it is queued; delivery and
   * retries happen in the background. Needs the "Send webhooks" permission.
   */
  send: (event: SendWebhookInput) => Promise<SentWebhook>;
}

export interface HeartbeatOptions {
  /** Report that the job ran and failed, instead of that it finished. */
  failed?: boolean;
}

export interface MonitoringClient {
  /**
   * Tells a cron monitor that its job has run. Call it when the job finishes;
   * if no heartbeat arrives in time, the monitor turns late and then failed.
   * Needs the "Send cron heartbeats" permission, and a key of the monitor's
   * environment.
   */
  heartbeat: (monitorId: string, options?: HeartbeatOptions) => Promise<void>;
}

const REJECTION_CODES: readonly string[] = [
  "expired",
  "insufficient_scopes",
  "not_found",
  "revoked",
  "wrong_environment",
] satisfies KeyRejectionCode[];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseVerification(data: unknown): VerifyKeyResult | null {
  if (!isRecord(data)) {
    return null;
  }

  if (data.valid === false) {
    return typeof data.code === "string" && REJECTION_CODES.includes(data.code)
      ? { code: data.code as KeyRejectionCode, valid: false }
      : null;
  }

  const { environment, expiresAt, keyId, name, scopes } = data;
  if (
    data.valid !== true ||
    typeof environment !== "string" ||
    typeof keyId !== "string" ||
    typeof name !== "string" ||
    !(expiresAt === null || typeof expiresAt === "string") ||
    !(
      Array.isArray(scopes) &&
      scopes.every((scope) => typeof scope === "string")
    )
  ) {
    return null;
  }
  return { environment, expiresAt, keyId, name, scopes, valid: true };
}

function parseSent(data: unknown): SentWebhook | null {
  return isRecord(data) &&
    typeof data.eventId === "string" &&
    typeof data.deliveries === "number"
    ? { deliveries: data.deliveries, eventId: data.eventId }
    : null;
}

/** The API's own explanation, which never contains a key. */
function describeFailure(body: unknown, status: number): string {
  const error = isRecord(body) ? body.error : null;
  return isRecord(error) && typeof error.message === "string"
    ? `Runqora refused the request (${status}): ${error.message}`
    : `Runqora refused the request (${status}).`;
}

function toTransportError(error: unknown): RunqoraError {
  const timedOut =
    error instanceof Error &&
    (error.name === "TimeoutError" || error.name === "AbortError");
  return timedOut
    ? new RunqoraError("Runqora did not answer in time.", {
        cause: error,
        code: "timeout",
      })
    : new RunqoraError("Runqora could not be reached.", {
        cause: error,
        code: "network_error",
      });
}

function notUnderstood(): RunqoraError {
  return new RunqoraError("Runqora sent an answer that was not understood.", {
    code: "invalid_response",
  });
}

export class Runqora {
  readonly keys: KeysClient;
  readonly monitoring: MonitoringClient;
  readonly webhooks: WebhooksClient;

  constructor(options: RunqoraOptions) {
    const { apiKey } = options;
    if (!apiKey) {
      throw new TypeError("Runqora: apiKey is required.");
    }

    const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(
      TRAILING_SLASHES,
      ""
    );
    const send: FetchLike =
      options.fetch ?? ((input, init) => fetch(input, init));
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    /** Returns the `data` of a successful answer. */
    async function post(path: string, payload: unknown): Promise<unknown> {
      let response: Response;
      let body: unknown;
      try {
        response = await send(`${baseUrl}${path}`, {
          body: JSON.stringify(payload),
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          method: "POST",
          signal: AbortSignal.timeout(timeoutMs),
        });
        body = await response.json().catch(() => null);
      } catch (error) {
        throw toTransportError(error);
      }

      if (!response.ok) {
        throw new RunqoraError(describeFailure(body, response.status), {
          code: "request_failed",
          status: response.status,
        });
      }
      return isRecord(body) ? body.data : null;
    }

    this.keys = {
      async verify(key, verifyOptions = {}) {
        if (typeof key !== "string" || !key || key.length > MAX_KEY_LENGTH) {
          return { code: "not_found", valid: false };
        }

        const result = parseVerification(
          await post("/v1/keys/verify", { key, scopes: verifyOptions.scopes })
        );
        if (!result) {
          throw notUnderstood();
        }
        return result;
      },
    };

    this.monitoring = {
      async heartbeat(monitorId, heartbeatOptions = {}) {
        await post("/v1/monitoring/heartbeats", {
          monitorId,
          status: heartbeatOptions.failed ? "failure" : "success",
        });
      },
    };

    this.webhooks = {
      async send(event) {
        const result = parseSent(
          await post("/v1/webhooks/events", {
            data: event.data,
            id: event.id,
            type: event.type,
          })
        );
        if (!result) {
          throw notUnderstood();
        }
        return result;
      },
    };
  }
}
