# runqora

Everything your server needs to work with [Runqora](https://runqora.dev):
verify the API keys your customers send, send and receive webhooks, report
cron heartbeats, and let Runqora manage your application's users.

```bash
bun add runqora
```

It has no dependencies and uses only `fetch` and Web Crypto, so it runs in
Node.js, Bun, Deno and edge runtimes. Use it on a server: the API key and the
auth secret must never reach a browser.

## API keys, webhooks and cron monitors

```ts
import { Runqora } from "runqora";

const runqora = new Runqora({ apiKey: process.env.RUNQORA_API_KEY! });

const result = await runqora.keys.verify(key, { scopes: ["orders:read"] });
await runqora.webhooks.send({ type: "order.created", data: { id: "o_1" } });
await runqora.monitoring.heartbeat(process.env.NIGHTLY_EXPORT_MONITOR_ID!);
```

Receiving webhooks Runqora sends to your application:

```ts
import { verifyWebhook } from "runqora";

export async function POST(request: Request) {
  const event = await verifyWebhook({
    headers: request.headers,
    payload: await request.text(),
    secret: process.env.RUNQORA_WEBHOOK_SECRET!,
  });
  // event.id is the same on every retry, so use it to skip duplicates.
  return new Response(null, { status: 204 });
}
```

## Users, with Better Auth

`runqora/better-auth` is a Better Auth plugin (Better Auth 1.6.13 or
later). Your users stay in your database: the plugin answers signed requests
from Runqora with data it reads through Better Auth's own adapter, so custom
table and field names keep working.

```ts
import { betterAuth } from "better-auth";
import { runqora } from "runqora/better-auth";

export const auth = betterAuth({
  // ...your existing configuration
  plugins: [runqora({ secret: process.env.RUNQORA_AUTH_SECRET! })],
});
```

Then connect Better Auth in your Runqora project with your Better Auth URL
(usually your site followed by `/api/auth`) and the same secret. Banning users
and showing roles need Better Auth's `admin` plugin; organizations need its
`organization` plugin. Without them, Runqora hides those features.

## Users, with any other auth system

`runqora/auth` turns a few functions into a handler you mount at a route:

```ts
import { createAuthBridge } from "runqora/auth";

const bridge = createAuthBridge({
  basePath: "/api/runqora",
  secret: process.env.RUNQORA_AUTH_SECRET!,
  users: {
    get: (id) => db.users.find(id),
    list: ({ limit, offset, search }) => db.users.page({ limit, offset, search }),
  },
});

// Any runtime with Web Request/Response: Next.js route handlers, Hono, Bun...
export const GET = bridge;
export const POST = bridge;
```

`users.get` and `users.list` are required. Every optional function you add
(`users.ban`, `users.unban`, `sessions`, `organizations`, `stats`) switches the
matching dashboard feature on.

`RUNQORA_AUTH_SECRET` is shared with Runqora when you connect the integration.
It must be at least 32 characters.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Report security problems privately, as [SECURITY.md](SECURITY.md) describes.

## License

[MIT](LICENSE)
