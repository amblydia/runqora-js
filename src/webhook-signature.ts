/**
 * Verification for the receiving side of a webhook.
 *
 * Runqora signs deliveries the way the Standard Webhooks specification
 * describes (https://www.standardwebhooks.com), so receivers written in other
 * languages can use any library that implements it instead of this function.
 */

const SECRET_PREFIX = "whsec_";
const SIGNATURE_VERSION = "v1";
const DEFAULT_TOLERANCE_SECONDS = 5 * 60;
const MILLISECONDS_PER_SECOND = 1000;

export type WebhookVerificationCode =
  | "invalid_payload"
  | "invalid_secret"
  | "invalid_signature"
  | "missing_headers"
  | "timestamp_out_of_range";

/** The delivery cannot be trusted. Answer it with a 400 and do not act on it. */
export class WebhookVerificationError extends Error {
  readonly code: WebhookVerificationCode;

  constructor(code: WebhookVerificationCode, message: string) {
    super(message);
    this.name = "WebhookVerificationError";
    this.code = code;
  }
}

export interface WebhookEvent<TData = unknown> {
  data: TData;
  /** The same for every attempt and replay of one event: use it to deduplicate. */
  id: string;
  /** ISO 8601 time the event was sent to Runqora. */
  timestamp: string;
  type: string;
}

export interface VerifyWebhookInput {
  /** The request's headers. */
  headers: Headers | Record<string, string | string[] | undefined>;
  /** Overrides the clock, in milliseconds. For tests. */
  now?: number;
  /** The request body exactly as received, before any JSON parsing. */
  payload: string;
  /** The endpoint's signing secret (`whsec_...`). */
  secret: string;
  /** How far the delivery's timestamp may be from now. Defaults to 5 minutes. */
  toleranceSeconds?: number;
}

function readHeader(
  headers: VerifyWebhookInput["headers"],
  name: string
): string | null {
  if (headers instanceof Headers) {
    return headers.get(name);
  }
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) {
      return (Array.isArray(value) ? value[0] : value) ?? null;
    }
  }
  return null;
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> | null {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

function parseEvent(payload: string): WebhookEvent | null {
  let body: unknown;
  try {
    body = JSON.parse(payload);
  } catch {
    return null;
  }
  if (typeof body !== "object" || body === null) {
    return null;
  }

  const { data, id, timestamp, type } = body as Record<string, unknown>;
  return typeof id === "string" &&
    typeof type === "string" &&
    typeof timestamp === "string"
    ? { data, id, timestamp, type }
    : null;
}

/**
 * Confirms that a delivery was sent by Runqora for this endpoint and returns
 * its event. Throws `WebhookVerificationError` otherwise.
 */
export async function verifyWebhook<TData = unknown>(
  input: VerifyWebhookInput
): Promise<WebhookEvent<TData>> {
  const id = readHeader(input.headers, "webhook-id");
  const timestamp = readHeader(input.headers, "webhook-timestamp");
  const signatures = readHeader(input.headers, "webhook-signature");
  if (!(id && timestamp && signatures)) {
    throw new WebhookVerificationError(
      "missing_headers",
      "The webhook-id, webhook-timestamp and webhook-signature headers are required."
    );
  }

  const key = input.secret.startsWith(SECRET_PREFIX)
    ? fromBase64(input.secret.slice(SECRET_PREFIX.length))
    : null;
  if (!key || key.length === 0) {
    throw new WebhookVerificationError(
      "invalid_secret",
      "The signing secret must be the whsec_ value shown for the endpoint."
    );
  }

  const sentAt = Number(timestamp);
  const tolerance = input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const now = (input.now ?? Date.now()) / MILLISECONDS_PER_SECOND;
  if (!Number.isInteger(sentAt) || Math.abs(now - sentAt) > tolerance) {
    throw new WebhookVerificationError(
      "timestamp_out_of_range",
      "The delivery is too old or too far in the future to be trusted."
    );
  }

  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["verify"]
  );
  const signed = encoder.encode(`${id}.${timestamp}.${input.payload}`);

  // Several signatures can be listed while a secret is being replaced.
  let trusted = false;
  for (const entry of signatures.split(" ")) {
    const [version, value] = entry.split(",");
    const signature =
      version === SIGNATURE_VERSION && value ? fromBase64(value) : null;
    // `verify` compares in constant time.
    if (
      signature &&
      // biome-ignore lint/performance/noAwaitInLoops: at most a handful of signatures, checked in order.
      (await crypto.subtle.verify("HMAC", cryptoKey, signature, signed))
    ) {
      trusted = true;
    }
  }
  if (!trusted) {
    throw new WebhookVerificationError(
      "invalid_signature",
      "The signature does not match this endpoint's signing secret."
    );
  }

  const event = parseEvent(input.payload);
  if (!event) {
    throw new WebhookVerificationError(
      "invalid_payload",
      "The delivery is signed correctly but is not a Runqora event."
    );
  }
  return event as WebhookEvent<TData>;
}
