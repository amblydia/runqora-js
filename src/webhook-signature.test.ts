import { describe, expect, it } from "vitest";
import { verifyWebhook, WebhookVerificationError } from "./webhook-signature";

const KEY_BYTES = new Uint8Array(32).map((_value, index) => index * 7);
const SECRET = `whsec_${btoa(String.fromCharCode(...KEY_BYTES))}`;
const NOW = Date.parse("2026-10-12T12:00:00.000Z");
const TIMESTAMP = String(NOW / 1000);
const ID = "evt_2kQJ8";
const PAYLOAD = JSON.stringify({
  data: { orderId: "o_1" },
  id: ID,
  timestamp: "2026-10-12T11:59:58.000Z",
  type: "order.created",
});

async function sign(
  content: string,
  keyBytes: Uint8Array<ArrayBuffer> = KEY_BYTES
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(content)
  );
  return `v1,${btoa(String.fromCharCode(...new Uint8Array(signature)))}`;
}

async function headers(overrides: Record<string, string> = {}) {
  return {
    "webhook-id": ID,
    "webhook-signature": await sign(`${ID}.${TIMESTAMP}.${PAYLOAD}`),
    "webhook-timestamp": TIMESTAMP,
    ...overrides,
  };
}

async function failure(input: Parameters<typeof verifyWebhook>[0]) {
  const error = await verifyWebhook(input).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(WebhookVerificationError);
  return (error as WebhookVerificationError).code;
}

describe("verifyWebhook", () => {
  it("returns the event of a correctly signed delivery", async () => {
    const event = await verifyWebhook<{ orderId: string }>({
      headers: await headers(),
      now: NOW,
      payload: PAYLOAD,
      secret: SECRET,
    });

    expect(event).toEqual({
      data: { orderId: "o_1" },
      id: ID,
      timestamp: "2026-10-12T11:59:58.000Z",
      type: "order.created",
    });
  });

  it("reads a Headers object and any header casing", async () => {
    const plain = await headers();
    const mixed = {
      "WEBHOOK-TIMESTAMP": plain["webhook-timestamp"],
      "Webhook-Id": plain["webhook-id"],
      "Webhook-Signature": [plain["webhook-signature"]],
    };

    for (const candidate of [new Headers(plain), mixed]) {
      const event = await verifyWebhook({
        headers: candidate,
        now: NOW,
        payload: PAYLOAD,
        secret: SECRET,
      });
      expect(event.id).toBe(ID);
    }
  });

  it("refuses a body that was changed after signing", async () => {
    const code = await failure({
      headers: await headers(),
      now: NOW,
      payload: PAYLOAD.replace("o_1", "o_2"),
      secret: SECRET,
    });

    expect(code).toBe("invalid_signature");
  });

  it("refuses a signature made with another secret", async () => {
    const other = new Uint8Array(32).fill(9);
    const code = await failure({
      headers: await headers({
        "webhook-signature": await sign(`${ID}.${TIMESTAMP}.${PAYLOAD}`, other),
      }),
      now: NOW,
      payload: PAYLOAD,
      secret: SECRET,
    });

    expect(code).toBe("invalid_signature");
  });

  it("refuses a delivery whose id or timestamp was swapped", async () => {
    const swappedId = await failure({
      headers: await headers({ "webhook-id": "evt_other" }),
      now: NOW,
      payload: PAYLOAD,
      secret: SECRET,
    });
    const later = String(NOW / 1000 + 60);
    const swappedTime = await failure({
      headers: await headers({ "webhook-timestamp": later }),
      now: NOW,
      payload: PAYLOAD,
      secret: SECRET,
    });

    expect(swappedId).toBe("invalid_signature");
    expect(swappedTime).toBe("invalid_signature");
  });

  it("refuses a replayed delivery outside the tolerance", async () => {
    const input = {
      headers: await headers(),
      payload: PAYLOAD,
      secret: SECRET,
    };

    expect(await failure({ ...input, now: NOW + 301_000 })).toBe(
      "timestamp_out_of_range"
    );
    expect(await failure({ ...input, now: NOW - 301_000 })).toBe(
      "timestamp_out_of_range"
    );
    await expect(
      verifyWebhook({ ...input, now: NOW + 299_000 })
    ).resolves.toMatchObject({ id: ID });
    await expect(
      verifyWebhook({ ...input, now: NOW + 301_000, toleranceSeconds: 600 })
    ).resolves.toMatchObject({ id: ID });
  });

  it("accepts any one of several listed signatures", async () => {
    const good = await sign(`${ID}.${TIMESTAMP}.${PAYLOAD}`);
    const stale = await sign("something else");

    const event = await verifyWebhook({
      headers: await headers({
        "webhook-signature": `${stale} v2,ignored ${good}`,
      }),
      now: NOW,
      payload: PAYLOAD,
      secret: SECRET,
    });

    expect(event.id).toBe(ID);
  });

  it("refuses unknown signature versions and malformed values", async () => {
    const good = await sign(`${ID}.${TIMESTAMP}.${PAYLOAD}`);

    for (const value of [good.replace("v1,", "v2,"), "v1,", "v1,***", "junk"]) {
      const code = await failure({
        headers: await headers({ "webhook-signature": value }),
        now: NOW,
        payload: PAYLOAD,
        secret: SECRET,
      });
      expect(code).toBe("invalid_signature");
    }
  });

  it("names missing headers and an unusable secret", async () => {
    const complete = await headers();
    const { "webhook-signature": _signature, ...unsigned } = complete;

    expect(
      await failure({
        headers: unsigned,
        now: NOW,
        payload: PAYLOAD,
        secret: SECRET,
      })
    ).toBe("missing_headers");
    for (const secret of ["", "whsec_", "not-a-secret", "whsec_***"]) {
      expect(
        await failure({
          headers: complete,
          now: NOW,
          payload: PAYLOAD,
          secret,
        })
      ).toBe("invalid_secret");
    }
  });

  it("refuses a signed body that is not an event", async () => {
    const payload = JSON.stringify(["not", "an", "event"]);
    const code = await failure({
      headers: await headers({
        "webhook-signature": await sign(`${ID}.${TIMESTAMP}.${payload}`),
      }),
      now: NOW,
      payload,
      secret: SECRET,
    });

    expect(code).toBe("invalid_payload");
  });
});
