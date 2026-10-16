import { describe, expect, it } from "vitest";
import { type FetchLike, Runqora, RunqoraError } from "./index";

const API_KEY = "rq_prod_9876543210987654321098765432109876543210";
const KEY = "rq_prod_0123456789012345678901234567890123456789";

interface Call {
  body: Record<string, unknown>;
  init: RequestInit;
  url: string;
}

function respondWith(
  body: unknown,
  status = 200
): { calls: Call[]; fetch: FetchLike } {
  const calls: Call[] = [];
  return {
    calls,
    fetch: (url, init) => {
      calls.push({ body: JSON.parse(String(init.body)), init, url });
      return Promise.resolve(
        typeof body === "string"
          ? new Response(body, { status })
          : Response.json(body, { status })
      );
    },
  };
}

function client(fetch: FetchLike, baseUrl?: string): Runqora {
  return new Runqora({ apiKey: API_KEY, baseUrl, fetch });
}

const verified = {
  data: {
    environment: "production",
    expiresAt: null,
    keyId: "key_1",
    name: "Partner",
    scopes: ["orders:read"],
    valid: true,
  },
};

describe("Runqora", () => {
  it("requires an API key", () => {
    expect(() => new Runqora({ apiKey: "" })).toThrow(TypeError);
  });

  it("authenticates every request with the API key", async () => {
    const { calls, fetch } = respondWith(verified);

    await client(fetch, "https://api.example.test/").keys.verify(KEY);

    expect(calls[0]?.url).toBe("https://api.example.test/v1/keys/verify");
    expect(calls[0]?.init.method).toBe("POST");
    expect(calls[0]?.init.headers).toMatchObject({
      Authorization: `Bearer ${API_KEY}`,
    });
  });

  it("uses the public API by default", async () => {
    const { calls, fetch } = respondWith(verified);

    await client(fetch).keys.verify(KEY);

    expect(calls[0]?.url).toBe("https://api.runqora.dev/v1/keys/verify");
  });

  it("never puts its own key in an error", async () => {
    const { fetch } = respondWith(
      { error: { code: "forbidden", message: "Missing permission." } },
      403
    );

    const failure = await client(fetch)
      .keys.verify(KEY)
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(RunqoraError);
    expect(failure).toMatchObject({ code: "request_failed", status: 403 });
    expect((failure as Error).message).toContain("Missing permission.");
    expect((failure as Error).message).not.toContain(API_KEY);
    expect((failure as Error).message).not.toContain(KEY);
  });
});

describe("keys.verify", () => {
  it("asks about the key and returns the answer", async () => {
    const { calls, fetch } = respondWith(verified);

    const result = await client(fetch).keys.verify(KEY, {
      scopes: ["orders:read"],
    });

    expect(result).toEqual(verified.data);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.body).toEqual({ key: KEY, scopes: ["orders:read"] });
  });

  it("returns why a key was refused", async () => {
    const { fetch } = respondWith({ data: { code: "revoked", valid: false } });

    expect(await client(fetch).keys.verify(KEY)).toEqual({
      code: "revoked",
      valid: false,
    });
  });

  it.each(["", "x".repeat(257), undefined, null, 42])(
    "refuses %j without calling the API",
    async (value) => {
      const { calls, fetch } = respondWith(verified);

      const result = await client(fetch).keys.verify(value as string);

      expect(result).toEqual({ code: "not_found", valid: false });
      expect(calls).toHaveLength(0);
    }
  );

  it("throws on a failure page that is not JSON", async () => {
    const { fetch } = respondWith("<html>Bad gateway</html>", 502);

    await expect(client(fetch).keys.verify(KEY)).rejects.toMatchObject({
      code: "request_failed",
      status: 502,
    });
  });

  it.each([
    ["an empty body", {}],
    ["an unknown reason", { data: { code: "banana", valid: false } }],
    ["a missing key id", { data: { ...verified.data, keyId: undefined } }],
    ["malformed scopes", { data: { ...verified.data, scopes: [1] } }],
    ["a truthy non-boolean", { data: { ...verified.data, valid: "yes" } }],
  ])("never treats %s as a valid key", async (_label, body) => {
    const { fetch } = respondWith(body);

    await expect(client(fetch).keys.verify(KEY)).rejects.toMatchObject({
      code: "invalid_response",
    });
  });

  it("throws when the API cannot be reached", async () => {
    const cause = new Error("ECONNREFUSED");
    const runqora = client(() => Promise.reject(cause));

    const failure = await runqora.keys
      .verify(KEY)
      .catch((error: unknown) => error);

    expect(failure).toMatchObject({ code: "network_error", status: null });
    expect((failure as Error).cause).toBe(cause);
  });

  it("gives up after the timeout", async () => {
    const runqora = new Runqora({
      apiKey: API_KEY,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason)
          );
        }),
      timeoutMs: 20,
    });

    await expect(runqora.keys.verify(KEY)).rejects.toMatchObject({
      code: "timeout",
    });
  });
});

describe("webhooks.send", () => {
  it("queues the event and reports how many endpoints will get it", async () => {
    const { calls, fetch } = respondWith(
      { data: { deliveries: 2, eventId: "evt_1" } },
      202
    );

    const sent = await client(fetch).webhooks.send({
      data: { orderId: "o_1" },
      id: "order-o_1-created",
      type: "order.created",
    });

    expect(sent).toEqual({ deliveries: 2, eventId: "evt_1" });
    expect(calls[0]?.url).toBe("https://api.runqora.dev/v1/webhooks/events");
    expect(calls[0]?.body).toEqual({
      data: { orderId: "o_1" },
      id: "order-o_1-created",
      type: "order.created",
    });
  });

  it("throws when the event is refused", async () => {
    const { fetch } = respondWith(
      { error: { code: "validation_failed", message: "Use a shorter type." } },
      400
    );

    await expect(
      client(fetch).webhooks.send({ data: null, type: "x".repeat(200) })
    ).rejects.toMatchObject({ code: "request_failed", status: 400 });
  });

  it("does not report success for an answer it cannot read", async () => {
    const { fetch } = respondWith({ data: { eventId: 1 } }, 202);

    await expect(
      client(fetch).webhooks.send({ data: null, type: "order.created" })
    ).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("monitoring.heartbeat", () => {
  it("reports that a job finished", async () => {
    const { calls, fetch } = respondWith({ data: { recorded: "heartbeat" } });

    await client(fetch).monitoring.heartbeat("monitor-1");

    expect(calls[0]?.url).toBe(
      "https://api.runqora.dev/v1/monitoring/heartbeats"
    );
    expect(calls[0]?.body).toEqual({
      monitorId: "monitor-1",
      status: "success",
    });
  });

  it("reports that a job failed", async () => {
    const { calls, fetch } = respondWith({ data: { recorded: "failure" } });

    await client(fetch).monitoring.heartbeat("monitor-1", { failed: true });

    expect(calls[0]?.body).toMatchObject({ status: "failure" });
  });

  it("throws when the heartbeat was not accepted", async () => {
    const { fetch } = respondWith(
      { error: { code: "not_found", message: "Cron monitor not found." } },
      404
    );

    await expect(
      client(fetch).monitoring.heartbeat("monitor-1")
    ).rejects.toMatchObject({ code: "request_failed", status: 404 });
  });
});
