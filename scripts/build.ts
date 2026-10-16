/**
 * Bundles each entry point of the package into `dist` with tsdown: one ES
 * module and one type file per entry, sharing chunks between them.
 * `package.json` maps every public subpath to its files in `dist`.
 */

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { build } from "tsdown";

const root = join(import.meta.dir, "..");
const outDir = join(root, "dist");

/** Bundle name -> source file; `package.json` exports point at the bundles. */
const ENTRIES = {
  auth: "src/auth/index.ts",
  "better-auth": "src/better-auth/index.ts",
  index: "src/index.ts",
  protocol: "src/auth/protocol.ts",
};

/**
 * Import and re-export statements of packages, skipping relative paths and
 * `node:` builtins. Anchored to the line start so examples in doc comments
 * don't match.
 */
const BARE_IMPORT =
  /^(?:import|export)\b[^"';]*?["']((?![./]|node:)[^"']+)["']/gm;

const manifest = JSON.parse(
  await readFile(join(root, "package.json"), "utf8")
) as { name: string; peerDependencies?: Record<string, string> };

await build({
  checks: { pluginTimings: false },
  clean: true,
  config: false,
  cwd: root,
  dts: true,
  entry: ENTRIES,
  format: "esm",
  logLevel: "warn",
  outDir,
  platform: "neutral",
  target: "es2022",
});
await assertOnlyPeerImports();

console.log(`${manifest.name} -> dist`);

/**
 * The package has no `dependencies`: anything a bundle still imports must be
 * a peer the application installs itself, such as `better-auth` for
 * `@runqora/sdk/better-auth`.
 */
async function assertOnlyPeerImports(): Promise<void> {
  const peers = Object.keys(manifest.peerDependencies ?? {});
  const bundles = (await readdir(outDir)).filter((file) =>
    file.endsWith(".js")
  );
  const code = await Promise.all(
    bundles.map((bundle) => readFile(join(outDir, bundle), "utf8"))
  );
  const imported = new Set(
    code.flatMap((text) =>
      Array.from(text.matchAll(BARE_IMPORT), (match) => match[1] ?? "")
    )
  );
  const undeclared = [...imported].filter(
    (specifier) =>
      !peers.some(
        (peer) => specifier === peer || specifier.startsWith(`${peer}/`)
      )
  );
  if (undeclared.length > 0) {
    throw new Error(
      `${manifest.name} imports ${undeclared.join(", ")}, which is not a peer dependency.`
    );
  }
}
