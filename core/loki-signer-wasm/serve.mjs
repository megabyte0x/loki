// The signer origin: a static server for the in-browser signer, on its OWN origin, apart from
// the wallet UI. It serves only this directory's signer page + Worker + wasm and the transport
// pkg, so wallet-page JS never runs where the share, the passkey ceremony or the passphrase
// live. The wallet embeds `${origin}/` in an iframe and talks to it over postMessage.
//
//   node serve.mjs            # dev: http://localhost:3002, wallet http://localhost:3001
//   node serve.mjs --hash     # print the published build hash and exit
//
// Environment (a deploy MUST set the first four; see web/wallet/README.md):
//   LOKI_WALLET_ORIGIN    the one wallet origin allowed to embed and message the signer
//                         (default http://localhost:3001)
//   LOKI_FROSTD_URL       the frostd relay the signer logs in to (shown to the member)
//   LOKI_RP_ID            WebAuthn rpId; must stay STABLE across deploys or passkeys stop
//                         unlocking (default: the signer page's hostname)
//   LOKI_CEREMONY_ORIGINS creator member-app origins a joiner may call during setup
//                         (space-separated CSP sources; default: loopback member apps)
//   LOKI_NONCE_WITNESSES  the two nonce-witness relays every signature is claimed at: the same
//                         JSON file a native member takes with --nonce-witnesses. Without it
//                         the browser signer refuses to sign. Only routes and pins are public.
//   LOKI_NETWORK          the deployment's network, testnet (default) or regtest; mainnet is
//                         refused. A regtest stack must set it, or LokiSigner is told testnet. Served for the native signer (LokiSigner), which reads this
//                         config through the wallet's /api/signer-config.
//   LOKI_LIGHTWALLETD_URL the lightwalletd the native signer syncs from (served the same way)
//   LOKI_LIGHTWALLETD_GRPCWEB_URL  lightwalletd behind gRPC-web + CORS for this origin
//                         (communication/deploy/lightwalletd-grpcweb.sh); the signer scans the
//                         chain through it for the vault balance and history
//   LOKI_SIGNER_PORT      listen port (default 3002)
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.LOKI_SIGNER_PORT || 3002);
// Loopback by default: a tunnel or reverse proxy on this host publishes the origin.
const host = process.env.LOKI_SIGNER_HOST || "127.0.0.1";
const walletOrigin = new URL(process.env.LOKI_WALLET_ORIGIN || "http://localhost:3001").origin;
const frostdUrl = process.env.LOKI_FROSTD_URL || "";
const rpId = process.env.LOKI_RP_ID || "";
const ceremonyOrigins = process.env.LOKI_CEREMONY_ORIGINS || "http://127.0.0.1:* http://localhost:*";
const network = process.env.LOKI_NETWORK || "testnet";
if (network !== "testnet" && network !== "regtest") throw new Error(`LOKI_NETWORK must be testnet or regtest, not ${network}`);
const lightwalletdUrl = process.env.LOKI_LIGHTWALLETD_URL || "";
const lightwalletdGrpcWebUrl = process.env.LOKI_LIGHTWALLETD_GRPCWEB_URL || "";
// Native `[WitnessConfig; 2]` (byte arrays) → hex for the page; empty when unset.
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const nonceWitnesses = process.env.LOKI_NONCE_WITNESSES
  ? JSON.parse(readFileSync(process.env.LOKI_NONCE_WITNESSES, "utf8")).map((w) => ({
      endpoint: w.endpoint, key: hex(w.key), run: hex(w.run), mailbox: hex(w.mailbox),
    }))
  : [];

// The whole servable bundle, read ONCE at startup: the page files plus the two wasm-pack
// pkgs. Requests are answered from this snapshot by exact path, so nothing else on disk is
// reachable and the bytes served are exactly the bytes hashed below.
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json" };
const bundle = new Map();
for (const name of ["signer.html", "signer-page.js", "signer-page.css", "signer-worker.js", "lightwalletd.js", "control-inbox.js", "vault-list.js", "storage-guard.js"]) {
  bundle.set(`/${name}`, readFileSync(join(here, name)));
}
// The signer pkg is required. The browser relay transport is served only when it was built: a
// native-only deployment (LokiSigner members only) needs just /config.json from this origin.
const transportPkg = resolve(here, "../wasm-transport/pkg");
for (const [prefix, dir] of [["/pkg/", resolve(here, "pkg")], ...(existsSync(transportPkg) ? [["/wasm-transport/pkg/", transportPkg]] : [])]) {
  for (const name of readdirSync(dir, { recursive: true })) {
    if (statSync(join(dir, name)).isFile() && !name.endsWith(".gitignore")) bundle.set(`${prefix}${name}`, readFileSync(join(dir, name)));
  }
}

// The published build hash: SHA-256 of every served file, and one bundle hash over that sorted
// list. The running server serves it at /build-hash.json, so a member or auditor can compare
// the deployed signer against the published one. Browsers have no SRI for module Workers,
// dynamic imports or wasm, so this whole-bundle hash is what pins the signer's code.
const fileHashes = [...bundle].map(([p, b]) => [p, createHash("sha256").update(b).digest("hex")]).sort(([a], [b]) => (a < b ? -1 : 1));
const build = {
  bundle: createHash("sha256").update(fileHashes.map(([p, h]) => `${h}  ${p}\n`).join("")).digest("hex"),
  files: Object.fromEntries(fileHashes),
};
if (process.argv.includes("--hash")) {
  console.log(JSON.stringify(build, null, 2));
  process.exit(0);
}
// Outside the hashed bundle: deployment values do not change the published build hash.
bundle.set("/config.json", Buffer.from(JSON.stringify({ walletOrigin, frostdUrl, rpId, nonceWitnesses, network, lightwalletdUrl, lightwalletdGrpcWebUrl })));
bundle.set("/build-hash.json", Buffer.from(JSON.stringify(build)));

// Strict CSP on every response (the page, the Worker script and its imports all get it).
// Only this origin's scripts run: no inline script, no eval, no third-party code;
// 'wasm-unsafe-eval' is the one exception, needed to instantiate wasm. connect-src: this
// origin (the .wasm fetch), the relay, and the creator member apps a joiner calls in setup.
const csp = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  `connect-src 'self' ${frostdUrl ? new URL(frostdUrl).origin : ""} ${nonceWitnesses.map((w) => new URL(w.endpoint).origin).join(" ")} ${lightwalletdGrpcWebUrl ? new URL(lightwalletdGrpcWebUrl).origin : ""} ${ceremonyOrigins}`.replace(/\s+/g, " ").trim(),
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return; }
  const target = req.url;
  if (!/^\/(?!\/)[^\s\\#]*$/.test(target)) { res.writeHead(400).end(); return; }
  let path;
  try {
    path = new URL(target, "http://x").pathname;
  } catch {
    res.writeHead(400).end();
    return;
  }
  const key = path === "/" ? "/signer.html" : path;
  const topLevelOnly = ["/receive-address", "/manage-custody", "/approve-payment", "/approve-roster", "/recovery"].includes(key);
  const asset = topLevelOnly ? "/signer.html" : key;
  const body = bundle.get(asset);
  const type = body ? types[extname(asset)] || "application/octet-stream" : "text/plain";
  res.writeHead(body ? 200 : 404, {
    "Content-Type": type.startsWith("text/") ? `${type}; charset=utf-8` : type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": `${csp}; worker-src ${topLevelOnly ? "'none'" : "'self'"}; frame-ancestors ${topLevelOnly ? "'none'" : walletOrigin}`,
  });
  res.end(req.method === "HEAD" ? undefined : body ?? "not found");
}).listen(port, host, () => console.log(`loki signer origin on http://${host}:${port} (wallet ${walletOrigin}) build ${build.bundle}`));
