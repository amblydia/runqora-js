# Contributing to runqora-js

Thanks for helping. This repository is `runqora`, the package customers
install to use [Runqora](https://runqora.dev) from their servers. Bug reports,
fixes, documentation and ideas are all welcome.

## Before you start

1. Search the existing issues and pull requests first.
2. For a new feature or a change to the public API, open an issue and agree on
   the direction before writing the code. The SDK talks to a service that
   older versions also talk to, so its API and the auth bridge protocol
   change slowly and on purpose.
3. Report security problems privately, as [SECURITY.md](SECURITY.md)
   describes, never in a public issue.

## Development

Use [Bun](https://bun.sh) 1.3 or newer. Do not add npm, Yarn or pnpm
lockfiles.

```bash
bun install
bun run test      # Vitest
bun run check     # lint, formatting and TypeScript
bun run fix       # apply lint and formatting fixes
bun run build     # bundle into dist
```

The package has no runtime dependencies and uses only `fetch` and Web Crypto,
so it runs in Node.js, Bun, Deno and edge runtimes. Keep it that way: a change
that needs a dependency should be discussed first. `better-auth` is an
optional peer, used only by `runqora/better-auth`; the build fails if a
bundle imports anything that is not a declared peer.

The layout:

| Path | Entry point | What it is |
| --- | --- | --- |
| `src/index.ts` | `runqora` | The API client and webhook verification |
| `src/auth/index.ts` | `runqora/auth` | The auth bridge for any auth system |
| `src/better-auth/index.ts` | `runqora/better-auth` | The Better Auth plugin |
| `src/auth/protocol.ts` | `runqora/protocol` | The signed request protocol both sides share |

Changes to `src/auth/protocol.ts` affect Runqora's servers too, and versions
of this package already installed in applications must keep working, so a
protocol change needs a new protocol version rather than an edit in place.

## Pull requests

Add or update tests whenever behaviour changes, and run `bun run check` and
`bun run test` before opening one. Explain the problem, the change and how you
verified it. Keep unrelated changes and formatting out of it.

## Licensing

This package is licensed under the [MIT License](LICENSE). By submitting a
contribution, you agree that it is distributed under the same license.

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
