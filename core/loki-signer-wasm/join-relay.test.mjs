// A browser member joins a vault over frostd through the real worker (signer-worker.js
// `joinCeremony`) and the real wasm pkgs, with a native creator and a native joiner
// (loki_member_app). The invite's creator URL is a closed port, so frostd is the only channel.
// Node lacks the Worker globals, OPFS and IndexedDB: they are shimmed in memory below.
//
//   FROSTD_URL=http://127.0.0.1:2744 LOKI_MEMBER_APP_BIN=.../loki_member_app node join-relay.test.mjs
//
// Build both pkgs first (wasm-pack build --dev --target web, here and in ../wasm-transport).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const { FROSTD_URL: frostdUrl, LOKI_MEMBER_APP_BIN: bin } = process.env;

// ── In-memory OPFS: directory/file handles and synchronous access handles. ──
function notFound() { return new DOMException("not found", "NotFoundError"); }
function fileHandle(name) {
  const f = { kind: "file", name, data: new Uint8Array(0) };
  f.createSyncAccessHandle = async () => ({
    getSize: () => f.data.length,
    read: (buf, { at = 0 } = {}) => { const n = Math.max(0, Math.min(buf.length, f.data.length - at)); buf.set(f.data.subarray(at, at + n)); return n; },
    write: (bytes, { at = 0 } = {}) => {
      const next = new Uint8Array(Math.max(f.data.length, at + bytes.length));
      next.set(f.data); next.set(bytes, at); f.data = next; return bytes.length;
    },
    truncate: (n) => { f.data = f.data.slice(0, n); },
    flush: () => {},
    close: () => {},
  });
  f.getFile = async () => ({ text: async () => new TextDecoder().decode(f.data) });
  return f;
}
function dirHandle(name) {
  const children = new Map();
  const get = (child, kind, create, make) => {
    if (!children.has(child)) { if (!create) throw notFound(); children.set(child, make(child)); }
    const h = children.get(child);
    if (h.kind !== kind) throw new DOMException("type mismatch", "TypeMismatchError");
    return h;
  };
  return {
    kind: "directory", name,
    getDirectoryHandle: async (child, { create = false } = {}) => get(child, "directory", create, dirHandle),
    getFileHandle: async (child, { create = false } = {}) => get(child, "file", create, fileHandle),
    removeEntry: async (child) => { if (!children.delete(child)) throw notFound(); },
    entries: async function* () { yield* children.entries(); },
  };
}
const root = dirHandle("");
Object.defineProperty(globalThis.navigator, "storage", { value: { getDirectory: async () => root }, configurable: true });
// control-inbox.js opens IndexedDB when the worker loads; the join path never reads it.
globalThis.indexedDB = { open: () => ({}) };
// wasm-bindgen fetches each module's .wasm next to its JS; node's fetch has no file: URLs.
const netFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = input instanceof URL ? input : new URL(String(input?.url ?? input));
  return url.protocol === "file:"
    ? Promise.resolve(new Response(readFileSync(fileURLToPath(url)), { headers: { "Content-Type": "application/wasm" } }))
    : netFetch(input, init);
};

// ── The worker, as the signer page talks to it. ──
const replies = new Map();
const asked = [];
globalThis.self = globalThis;
self.addEventListener = () => {};
self.postMessage = (msg) => {
  if (msg.ask !== undefined) {
    // The member accepts the roster and confirms the roster code on the signer page.
    asked.push({ kind: msg.kind, data: msg.data });
    queueMicrotask(() => self.onmessage({ data: { answer: msg.ask, ok: true, value: true } }));
  } else if (msg.id !== undefined) {
    replies.get(msg.id)?.(msg);
  }
};
let nextId = 0;
function worker(op, fields = {}) {
  const id = ++nextId;
  return new Promise((ok, fail) => {
    replies.set(id, (m) => (m.ok ? ok(m.result) : fail(new Error(m.error))));
    self.onmessage({ data: { id, op, ...fields } });
  });
}

// The worker loads wasm-transport from ./wasm-transport/pkg beside it (serve.mjs maps that
// path); a scratch copy of the worker gets that layout through symlinks.
function workerDir() {
  const dir = mkdtempSync(join(tmpdir(), "loki-join-worker-"));
  for (const f of ["signer-worker.js", "lightwalletd.js", "control-inbox.js", "vault-list.js"]) copyFileSync(join(here, f), join(dir, f));
  symlinkSync(resolve(here, "pkg"), join(dir, "pkg"));
  mkdirSync(join(dir, "wasm-transport"));
  symlinkSync(resolve(here, "../wasm-transport/pkg"), join(dir, "wasm-transport", "pkg"));
  return dir;
}

const freePort = () => new Promise((ok) => { const s = createServer().listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => ok(port)); }); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function memberApp(data, port) {
  // The advertised URL is a closed port; the peer listener it would front is never dialed.
  const peerPort = await freePort();
  const child = spawn(bin, ["--data", data, "--port", String(port), "--frostd-url", frostdUrl, "--peer-port", String(peerPort), "--advertise-url", "http://127.0.0.1:9"], { stdio: ["ignore", "pipe", "pipe"] });
  let log = "";
  child.stdout.on("data", (b) => { log += b; });
  child.stderr.on("data", (b) => { log += b; });
  for (let i = 0; i < 100 && !/Signer: http:\/\/127\.0\.0\.1:\d+\/#/.test(log); i++) await sleep(100);
  const token = log.match(/Signer: http:\/\/127\.0\.0\.1:\d+\/#(\S+)/)?.[1];
  assert.ok(token, `member app did not start: ${log}`);
  const api = async (method, path, body) => {
    const res = await netFetch(`http://127.0.0.1:${port}${path}`, {
      method, headers: { "X-Loki-Token": token, "Content-Type": "application/json" }, body: body && JSON.stringify(body),
    });
    const value = await res.json();
    if (!res.ok) throw new Error(`${path}: ${value.error}`);
    return value;
  };
  return { child, api, log: () => log };
}

async function until(fn, what, seconds = 180) {
  for (let i = 0; i < seconds * 2; i++) {
    const value = await fn();
    if (value) return value;
    await sleep(500);
  }
  throw new Error(`timed out waiting for ${what}`);
}

test("a browser member joins over frostd with a native creator and joiner, and all reach one address",
  { skip: !(frostdUrl && bin) && "set FROSTD_URL and LOKI_MEMBER_APP_BIN" }, async () => {
  const scratch = mkdtempSync(join(tmpdir(), "loki-join-relay-"));
  const dir = workerDir();
  const members = [];
  try {
    await import(pathToFileURL(join(dir, "signer-worker.js")).href);
    for (const name of ["creator", "joiner"]) members.push(await memberApp(join(scratch, name), await freePort()));
    const [creator, joiner] = members;
    for (const [i, m] of members.entries()) await m.api("POST", "/api/profile-create", { name: `Member ${i + 1}`, passphrase: `join relay pass ${i + 1}` });
    const created = await creator.api("POST", "/api/create", { name: "Browser relay vault", members: 3, threshold: 2 });
    const { vault } = created;
    const invite = (slot) => created.invites.find((i) => i.slot === slot).code;
    const decoded = JSON.parse(Buffer.from(invite(3), "base64url"));
    assert.equal(decoded.creator_base_url, "http://127.0.0.1:9");
    assert.ok(decoded.creator?.encryption, "the invite names the creator");

    await worker("create", { method: "platform", name: "Browser", prfSecret: crypto.getRandomValues(new Uint8Array(32)) });
    await worker("recovery-begin");
    await worker("recovery-confirm");
    const browser = worker("join", { join: { invite: invite(3), network: "regtest", frostdUrl, label: "Browser relay vault" } });
    browser.catch(() => {}); // awaited below; the natives' steps run meanwhile
    await joiner.api("POST", "/api/join", { invite: invite(2) });

    const codes = new Set();
    for (const m of [creator, joiner]) {
      const status = await until(async () => {
        const s = await m.api("GET", `/api/status?vault=${vault}`);
        return s.phase === "compare_roster" && s;
      }, "compare_roster");
      await m.api("POST", "/api/agree", { vault, fingerprint: status.fingerprint, roster_code: status.roster_code });
      codes.add(status.roster_code);
    }
    // The code the browser's signer showed is the code every native member confirmed.
    const shown = await until(async () => asked.find((a) => a.kind === "roster-code"), "the browser's roster code");
    assert.deepEqual([...codes], [shown.data.code]);

    const joined = await browser;
    const addresses = new Set([joined.address]);
    for (const m of [creator, joiner]) {
      await until(async () => (await m.api("GET", `/api/status?vault=${vault}`)).phase === "active", "active");
      addresses.add((await m.api("GET", `/api/address?vault=${vault}`)).address);
    }
    console.log(`browser + 2 native members active at ${[...addresses].join(", ")}`);
    assert.equal(addresses.size, 1, [...addresses].join(" "));
  } catch (e) {
    for (const [i, m] of members.entries()) console.log(`member ${i + 1} log:\n${m.log().slice(-2000)}`);
    throw e;
  } finally {
    for (const m of members) m.child.kill();
    rmSync(scratch, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});
