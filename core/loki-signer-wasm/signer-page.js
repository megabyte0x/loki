// The signer-origin page. It runs on its own origin (serve.mjs), embedded by the wallet in an
// iframe, and is the ONLY place the custody secrets are entered: the passkey PRF ceremony, the
// passphrase, the roster-code comparison and every payment approval happen here, in this
// origin's JS, never in wallet-page JS. It owns the signer Worker (signer-worker.js).
//
// The wallet talks to it only over postMessage, carrying public data: {id, op, params} in,
// {id, ok, result | error, status} out, plus {cmd: "ready" | "failed" | "show" | "hide"} so the wallet
// can reveal the iframe while a prompt needs the member. Messages from any origin other than
// the configured wallet origin, or from any window other than the embedding parent, are dropped.

import { requirePersistentStorage, requireShare } from "./storage-guard.js";

const cfg = await fetch("./config.json", { cache: "no-store" }).then((r) => r.json());
const wallet = cfg.walletOrigin;
const rpId = cfg.rpId || location.hostname;
const custodyPath = "/manage-custody";
const paymentPath = "/approve-payment";
const receivePath = "/receive-address";
const framed = window !== top;
const embedded = framed && ![custodyPath, paymentPath, receivePath].includes(location.pathname);
const $ = (id) => document.getElementById(id);
$("self-origin").textContent = location.origin;
$("relay").textContent = `${cfg.frostdUrl || "none configured"} · nonce witnesses: ${cfg.nonceWitnesses?.map((w) => w.endpoint).join(", ") || "none (signing is refused)"}`;

class SignerError extends Error {
  constructor(message, status = 500) { super(message); this.status = status; }
}

// ─── one signer per storage partition ────────────────────────────────────────
// The Worker holds exclusive OPFS handles and the crash-safe nonce store, so exactly one tab
// may run it. This page holds a Web Lock for its lifetime; a second tab refuses every op
// instead of racing the first over the same share and nonces. Top-level tabs never open OPFS.
const owner = embedded && await new Promise((resolve) => {
  if (!navigator.locks) { resolve(false); return; }
  navigator.locks.request("loki-signer", { ifAvailable: true }, (lock) => {
    resolve(!!lock);
    return lock ? new Promise(() => {}) : undefined; // held until this page unloads
  });
});

// ─── the Worker ──────────────────────────────────────────────────────────────
let worker, workerFailure, dismissPrompt;
const pending = new Map();
let seq = 0;
let removing = false;
function failWorker() {
  if (workerFailure) return;
  workerFailure = new SignerError("The browser signer worker stopped or could not start. Try again.", 503);
  worker?.terminate();
  dismissPrompt?.(workerFailure);
  for (const p of pending.values()) p.reject(workerFailure);
  pending.clear();
  parent.postMessage({ cmd: "failed", error: workerFailure.message }, wallet);
}
function receiveWorker(e) {
  const d = e.data ?? {};
  if (d.cmd === "loaded") { parent.postMessage({ cmd: "ready" }, wallet); return; }
  if (d.cmd === "failed") { failWorker(); return; }
  if (d.ask !== undefined) { answerAsk(d); return; }
  const p = pending.get(d.id);
  if (!p) return;
  pending.delete(d.id);
  d.ok ? p.resolve(d.result) : p.reject(new SignerError(d.error ?? "signer error"));
}
async function call(msg) {
  if (workerFailure) throw workerFailure;
  if (!worker) throw new SignerError("Your signer is open in another tab. Close it there and reload.", 409);
  if (removing && msg.op !== "remove-verified") throw new SignerError("Signer removal is in progress. Try again in a moment.", 409);
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    try { worker.postMessage({ id, ...msg }); }
    catch { failWorker(); }
  });
}

// ─── prompts ─────────────────────────────────────────────────────────────────
function el(tag, props = {}, ...children) {
  const n = Object.assign(document.createElement(tag), props);
  for (const c of children) n.append(c);
  return n;
}
function facts(rows) {
  const dl = el("dl");
  for (const [k, v, mono] of rows) dl.append(el("dt", { textContent: k }), el("dd", { textContent: String(v), className: mono ? "mono" : "" }));
  return dl;
}

// Show one prompt and resolve with the value of the button the member pressed. A button's
// `run` (async, called inside the click so WebAuthn keeps its user activation) may throw to
// keep the prompt open with the error shown, or return the value to resolve with.
function prompt(title, body, buttons) {
  if (workerFailure) throw workerFailure;
  const main = $("prompt");
  $("title").textContent = title;
  $("body").replaceChildren(...body);
  $("error").textContent = "";
  main.hidden = false;
  if (embedded) parent.postMessage({ cmd: "show" }, wallet);
  return new Promise((resolve, reject) => {
    const wait = new AbortController();
    const actions = $("actions");
    const done = (fn) => {
      wait.abort(); dismissPrompt = undefined;
      main.hidden = true;
      $("body").replaceChildren();
      actions.replaceChildren();
      if (embedded) parent.postMessage({ cmd: "hide" }, wallet);
      fn();
    };
    dismissPrompt = (error) => done(() => reject(error));
    actions.replaceChildren(...buttons.map((b) => {
      const btn = el("button", { textContent: b.label, className: b.ghost ? "ghost" : "" });
      btn.onclick = async () => {
        if (b.cancel) {
          if ("value" in b) done(() => resolve(b.value)); // A worker decision can decline explicitly.
          else dismissPrompt(new SignerError("Cancelled on the signer", 400));
          return;
        }
        for (const [i, x] of Array.from(actions.children).entries()) x.disabled = !(b.abortable && buttons[i].cancel);
        // A credential prompt can be cancelled, but not a write already dispatched to the worker.
        const commit = () => {
          wait.signal.throwIfAborted();
          for (const x of actions.children) x.disabled = true;
        };
        try {
          const v = b.run ? await b.run(wait.signal, commit) : b.value;
          if (!wait.signal.aborted) done(() => resolve(v));
        } catch (e) {
          if (wait.signal.aborted) return;
          $("error").textContent = e.message || String(e);
          for (const x of actions.children) x.disabled = false;
        }
      };
      return btn;
    }));
  });
}
const cancelButton = { label: "Cancel", ghost: true, cancel: true };

// ─── WebAuthn PRF (the custody secret is released here, on the signer origin) ─────────────
const PRF_SALT = new TextEncoder().encode("loki/signer/share-kek/v1");
const CRED = "loki_passkey_cred";
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

async function createPasskey(name, attachment, signal) {
  const cred = await navigator.credentials.create({
    signal,
    publicKey: {
      challenge: random(32),
      rp: { id: rpId, name: "Loki" },
      user: { id: random(16), name, displayName: name },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: attachment, residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  signal.throwIfAborted();
  if (!cred.getClientExtensionResults().prf?.enabled) {
    throw new SignerError("This authenticator has no PRF support. Use a passphrase instead.", 400);
  }
  return new Uint8Array(cred.rawId);
}

// A fresh user-verified assertion releasing the PRF secret. The remembered credential id is
// only a hint: without it (cleared storage) the authenticator offers its discoverable Loki
// passkeys for this rpId.
function rememberedCredential() {
  try { const h = localStorage.getItem(CRED); if (/^(?:[0-9a-f]{2})+$/.test(h ?? "")) return fromHex(h); } catch {}
}
async function passkeyAssertion(id, signal) {
  const assertion = await navigator.credentials.get({
    signal,
    publicKey: {
      challenge: random(32),
      rpId,
      ...(id ? { allowCredentials: [{ type: "public-key", id }] } : {}),
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  signal.throwIfAborted();
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first || first.byteLength < 32) throw new SignerError("This passkey released no PRF secret. Use a passphrase instead.", 400);
  return { prfSecret: new Uint8Array(first).slice(0, 32), id: toHex(new Uint8Array(assertion.rawId)) };
}

async function prfSecret(id, signal) {
  return (await passkeyAssertion(id, signal)).prfSecret;
}

async function submitPasskey(id, signal, commit, submit) {
  const assertion = await passkeyAssertion(id, signal);
  commit();
  const result = await submit({ prfSecret: assertion.prfSecret });
  // A valid WebAuthn assertion is not necessarily the passkey that opens this signer.
  try { localStorage.setItem(CRED, assertion.id); } catch {}
  return result;
}

// Passphrase floor for the passphrase tier: long enough that the offline Argon2id guess
// cost dominates. ponytail: length-only rule; add a strength estimator if users pick weak long phrases.
const MIN_PASSPHRASE = 12;
function passField(label, autocomplete) {
  return el("input", { type: "password", autocomplete, spellcheck: false, placeholder: label });
}

// ─── custody: create / unlock / reauthorize ──────────────────────────────────
let current = null; // { profile, se }
let persisted = null;

// A share is sealed only while the browser keeps this origin's storage persistent
// (storage-guard.js); each unlock re-reads it so a lost grant shows in status.
async function persistent() {
  await requirePersistentStorage(navigator.storage);
  persisted = true;
}

// Ask for a new custody secret (a passphrase typed twice, or a new passkey) and pass it to
// `submit`, which seals the signer under it.
function newCustody(name, method, submit) {
  if (method === "passphrase") {
    const a = passField("Passphrase", "new-password"), b = passField("Repeat passphrase", "new-password");
    return prompt("Protect your signer with a passphrase", [
      el("p", { textContent: `At least ${MIN_PASSPHRASE} characters. It seals your share in this browser; it is not sent anywhere.` }),
      el("label", { textContent: "Passphrase" }, a), el("label", { textContent: "Repeat" }, b),
    ], [cancelButton, { label: "Create signer", run: async () => {
      if (a.value.length < MIN_PASSPHRASE) throw new SignerError(`Use at least ${MIN_PASSPHRASE} characters.`, 400);
      if (a.value !== b.value) throw new SignerError("The two passphrases differ.", 400);
      return submit({ passphrase: a.value });
    } }]);
  }
  return prompt("Create a passkey for your signer", [
    el("p", { textContent: `Your share is sealed under a passkey for ${rpId}. Touch/Face ID, a security key or your phone unlocks it.` }),
  ], [cancelButton, { label: "Create passkey", abortable: true, run: async (signal, commit) => {
    const id = await createPasskey(name, method === "platform" ? "platform" : "cross-platform", signal);
    return submitPasskey(id, signal, commit, submit);
  } }]);
}

async function create({ name, method }) {
  name = String(name || "You");
  await persistent();
  const result = await newCustody(name, method, (secret) => call({ op: "create", method, name, ...secret }));
  current = { profile: result, se: method === "passphrase" ? "software" : "passkey" };
  return { profile: result, persisted };
}

async function unlock({ method }) {
  await requireShare(() => call({ op: "has" }));
  let result;
  if (method === "passphrase") {
    const a = passField("Passphrase", "current-password");
    result = await prompt("Unlock your signer", [el("label", { textContent: "Passphrase" }, a)],
      [cancelButton, { label: "Unlock", run: () => call({ op: "unlock", method, passphrase: a.value }) }]);
  } else {
    const hint = rememberedCredential();
    const usePasskey = (label, id) => ({ label, abortable: true, run: (signal, commit) =>
      submitPasskey(id, signal, commit, (secret) => call({ op: "unlock", method, ...secret })) });
    result = await prompt("Unlock your signer", [el("p", { textContent: `Use your passkey for ${rpId}.` })],
      [cancelButton, ...(hint ? [usePasskey("Use saved passkey", hint)] : []),
        usePasskey(hint ? "Choose another passkey" : "Use passkey", undefined)]);
  }
  current = { profile: result, se: method === "passphrase" ? "software" : "passkey" };
  persisted = await navigator.storage?.persisted?.().catch(() => false) ?? false;
  return { profile: result, persisted };
}

// A fresh proof the member is present, for one approval: a new passkey assertion, or the
// passphrase typed again. The Worker checks it re-derives the unlocked KEK before signing.
function reauthField() {
  return current?.se === "passkey" ? null : passField("Passphrase", "current-password");
}
async function reauthValue(field, signal) {
  return field ? { method: "passphrase", passphrase: field.value } : { method: "platform", prfSecret: await prfSecret(undefined, signal) };
}

// ─── recovery: 24 words shown once, backups sealed to them ──────────────────
// The words exist only on this page, once; the signer keeps only their public keys. Each
// vault's recovery backup is ciphertext only the words open, so it is safe to download.
async function recoverySetup() {
  if (!current) throw new SignerError("Unlock your signer", 401);
  const status = await call({ op: "recovery-status" });
  if (status.legacy_recovery) {
    const saved = el("textarea", { autocomplete: "off", spellcheck: false, rows: 4 });
    await prompt("Confirm your saved recovery words", [
      el("p", { textContent: "Confirm your original words before making new backups. Existing backups will not change." }),
      el("label", { textContent: "Your 24 recovery words" }, saved),
    ], [cancelButton, { label: "Confirm", run: () => call({ op: "recovery-migrate", words: saved.value }) }]);
    return { recovery: true };
  }
  const words = (await call({ op: "recovery-begin" })).split(" ");
  await prompt("Write down your 24 recovery words", [
    el("p", { textContent: "They are shown only now. With them and a vault's recovery backup file, you can restore your signer in a new browser. Anyone who has both can sign as you." }),
    el("ol", { className: "mono" }, ...words.map((w) => el("li", { textContent: w }))),
  ], [cancelButton, { label: "I wrote them down", value: true }]);
  const chosen = new Set();
  while (chosen.size < 3) chosen.add(random(1)[0] % 24);
  const picks = [...chosen].sort((a, b) => a - b);
  const fields = picks.map(() => el("input", { autocomplete: "off", spellcheck: false }));
  await prompt("Confirm your recovery words", [
    ...picks.map((i, k) => el("label", { textContent: `Word ${i + 1}` }, fields[k])),
  ], [cancelButton, { label: "Confirm", run: async () => {
    if (picks.some((i, k) => fields[k].value.trim().toLowerCase() !== words[i])) {
      throw new SignerError("Those words do not match. Check what you wrote down.", 400);
    }
    return call({ op: "recovery-confirm" });
  } }]);
  return { recovery: true };
}

// Download a vault's recovery backup on this origin. The wallet gets the same opaque bytes.
async function recoveryExport({ vault }) {
  const blob = await call({ op: "recovery-backup", vaultHex: vault });
  const fingerprint = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", blob)));
  await prompt("Save this vault's recovery backup", [
    el("p", { textContent: "Keep the file anywhere you like. It opens only with your 24 recovery words." }),
    el("p", { textContent: "Write down this SHA-256 fingerprint separately to verify the file on restore:" }),
    el("code", { className: "mono", textContent: fingerprint }),
  ], [cancelButton, { label: "Download backup", run: () => {
    const a = el("a", { href: URL.createObjectURL(new Blob([blob])), download: `loki-recovery-${vault}.bin` });
    a.click();
    URL.revokeObjectURL(a.href);
  } }]);
  return { backup: toHex(blob) };
}

// Restore a vault member into this (fresh) browser from its words and backup file.
// The backup is opaque ciphertext, so the wallet may hand it over (`backup`, hex, with its
// `vault`), e.g. one the member kept with the coordinator; otherwise the member picks the file.
async function restore({ vault, name, method, backup }) {
  await persistent();
  const words = el("textarea", { autocomplete: "off", spellcheck: false, rows: 4 });
  const file = el("input", { type: "file" });
  const fingerprint = el("input", { autocomplete: "off", spellcheck: false });
  const given = typeof backup === "string" && /^([0-9a-f]{2})+$/i.test(backup) && /^[0-9a-f]{64}$/i.test(vault ?? "");
  const input = await prompt("Restore your signer", [
    el("label", { textContent: "Your 24 recovery words" }, words),
    given ? el("p", { className: "mono", textContent: `Backup for vault ${vault.slice(0, 16)}… provided by the wallet` })
      : el("label", { textContent: "The vault's recovery backup file" }, file),
    el("label", { textContent: "SHA-256 fingerprint saved separately from the backup" }, fingerprint),
    el("p", { textContent: "For an older backup you saved yourself, you can compute the fingerprint from that original offline copy. Do not use a value supplied with an untrusted file." }),
  ], [cancelButton, { label: "Continue", abortable: true, run: async () => {
    const typed = words.value.trim().toLowerCase().split(/\s+/).join(" ");
    const expected = fingerprint.value.trim();
    if (!/^[0-9a-f]{64}$/i.test(expected)) throw new SignerError("Enter the 64-character SHA-256 fingerprint.", 400);
    if (given) return { vaultHex: vault, words: typed, blob: fromHex(backup), fingerprint: expected };
    const f = file.files[0];
    const vaultHex = vault || f?.name.match(/[0-9a-f]{64}/i)?.[0];
    if (!f || !vaultHex) throw new SignerError("Choose the loki-recovery-<vault>.bin file you saved.", 400);
    return { vaultHex, words: typed, blob: new Uint8Array(await f.arrayBuffer()), fingerprint: expected };
  } }]);
  name = String(name || "You");
  const result = await newCustody(name, method, (secret) => call({ op: "restore", method, name, ...input, ...secret }));
  current = { profile: result.profile, se: method === "passphrase" ? "software" : "passkey" };
  return { ...result, persisted };
}

// Only the tab opened by this signer frame can send a removal confirmation. Its private port
// bridges the two storage partitions without giving the top-level tab a worker or a lock.
function manageCustody() {
  return prompt("Open signer controls", [
    el("p", { textContent: `Continue in a separate tab. Check its address is ${location.origin} before verifying your identity there.` }),
  ], [{ ...cancelButton, value: false }, { label: "Open signer controls", run: (signal) => {
    const openedFor = current;
    if (!openedFor || !worker) throw new SignerError("Unlock your signer first", 401);
    const tab = window.open(custodyPath, "_blank");
    if (!tab) throw new SignerError("Allow the signer to open a new tab and try again.", 400);

    return new Promise((resolve, reject) => {
      let port;
      const finish = () => {
        removeEventListener("message", connect);
        signal.removeEventListener("abort", abort);
        clearInterval(closed);
        clearTimeout(timeout);
        port?.close();
      };
      const abort = () => { finish(); tab.close(); resolve(false); };
      const connect = (e) => {
        if (e.source !== tab || e.origin !== location.origin || e.data?.cmd !== "custody-connect" || !e.ports[0]) return;
        removeEventListener("message", connect);
        clearTimeout(timeout);
        port = e.ports[0];
        const passkey = openedFor.se === "passkey";
        port.postMessage({ name: openedFor.profile.name, passkey });
        port.onmessage = async ({ data }) => {
          if (data?.cmd !== "confirm-removal" || removing || tab.closed) return;
          if (current !== openedFor || pending.size) {
            port.postMessage({ error: current !== openedFor ? "The signer session changed. Return to the wallet and open signer controls again." : "The signer is busy. Try again in a moment." });
            return;
          }
          removing = true;
          try {
            const secret = passkey ? { method: "platform", prfSecret: data.prfSecret } : { method: "passphrase", passphrase: data.passphrase };
            await call({ op: "remove-verified", ...secret });
            current = null;
            enrollment = null;
            try { localStorage.removeItem(CRED); } catch {}
            port.postMessage({ removed: true });
            finish();
            resolve(true);
          } catch (e) {
            port.postMessage({ error: e.message || String(e) });
          } finally { removing = false; }
        };
      };
      addEventListener("message", connect);
      const closed = setInterval(() => { if (tab.closed && !removing) { finish(); resolve(false); } }, 500);
      const timeout = setTimeout(() => {
        finish();
        tab.close();
        reject(new SignerError("The signer tab could not connect. Allow tabs opened by the signer and try again.", 409));
      }, 10000);
      signal.addEventListener("abort", abort, { once: true });
    });
  } }]);
}

async function connectToSignerFrame(cmd) {
  if (!opener) return null;
  const { port1, port2 } = new MessageChannel();
  const context = await new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 10000);
    port1.onmessage = ({ data }) => { clearTimeout(timeout); resolve(data); };
    opener.postMessage({ cmd }, location.origin, [port2]);
  });
  if (!context) {
    port1.close();
    return null;
  }
  return { port: port1, context };
}

async function showCustodyControls() {
  const connection = await connectToSignerFrame("custody-connect");
  if (!connection) {
    void prompt("Signer controls unavailable", [el("p", { textContent: "Unlock the signer in your wallet and open signer controls from there. This tab does not access your wallet's stored shares." })], []);
    return;
  }

  const { port: port1, context } = connection;
  const field = context.passkey ? null : passField("Passphrase", "current-password");
  const kept = el("input", { type: "checkbox" });
  const confirmed = await prompt("Remove the signer from this browser?", [
    facts([["Signer", context.name], ["Wallet", wallet]]),
    el("p", { textContent: "This deletes the sealed identity and every vault share this wallet uses in this browser. You can sign again only by restoring from your 24 recovery words and each vault's recovery backup file." }),
    el("label", {}, kept, " I exported every vault's recovery backup and I have my 24 words"),
    field ? el("label", { textContent: "Passphrase" }, field) : el("p", { textContent: `Verify with your passkey for ${rpId}.` }),
  ], [{ ...cancelButton, value: false }, { label: "Verify and remove signer", abortable: true, run: async (signal, commit) => {
    if (!kept.checked) throw new SignerError("Export your recovery backups first.", 400);
    const secret = field ? { passphrase: field.value } : { prfSecret: await prfSecret(undefined, signal) };
    commit();
    if (field) field.value = "";
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new SignerError("No response. Return to your wallet to check whether the signer was removed.")), 15000);
      port1.onmessage = ({ data }) => {
        clearTimeout(timeout);
        data.removed ? resolve() : reject(new SignerError(data.error));
      };
      port1.postMessage({ cmd: "confirm-removal", ...secret });
    });
    return true;
  } }]);
  port1.close();
  if (!confirmed) { window.close(); return; }
  void prompt("Signer removed", [el("p", { textContent: "This wallet's local shares were removed. Return to the wallet to restore from a recovery backup." })], []);
}

// The locked-down tab cannot read the wallet's storage partition. Send only the public
// derivation from this frame's unlocked worker, and never accept operations on the port.
async function openReceiveAddress(payment) {
  const receive = await call({ op: "address", payment });
  return prompt("Verify receive address", [
    el("p", { textContent: `Open the read-only address in a separate tab. Check that the address bar shows ${location.origin} before copying.` }),
  ], [{ ...cancelButton, value: null }, { label: "Open signer address", run: () => {
    const tab = window.open(receivePath, "_blank");
    if (!tab) throw new SignerError("Allow the signer to open a new tab and try again.", 400);
    return new Promise((resolve, reject) => {
      const wait = new AbortController();
      const timeout = setTimeout(() => {
        wait.abort();
        tab.close();
        reject(new SignerError("The signer tab could not connect. Try again.", 409));
      }, 10000);
      addEventListener("message", (e) => {
        if (e.source !== tab || e.origin !== location.origin || e.data?.cmd !== "receive-connect" || !e.ports[0]) return;
        clearTimeout(timeout);
        wait.abort();
        e.ports[0].postMessage(receive);
        e.ports[0].close();
        resolve(null);
      }, { signal: wait.signal });
    });
  } }]);
}

async function showReceiveAddress() {
  document.title = "Vault receive address · Loki signer";
  const connection = await connectToSignerFrame("receive-connect");
  window.opener = null;
  if (!connection) {
    void prompt("Receive address unavailable", [el("p", { textContent: "Unlock the signer in your wallet, select a vault, then choose Verify on signer." })], []);
    return;
  }
  connection.port.close();
  const { vault, network, address } = connection.context;
  void prompt("Vault receive address", [
    facts([["Vault ID", vault, true], ["Network", network], ["Address", address, true]]),
    el("p", { textContent: "Copy from this tab, or compare the full vault ID and address before sharing the address shown in the wallet." }),
  ], []);
  const copy = el("button", { textContent: "Copy receive address", onclick: async () => {
    try {
      await navigator.clipboard.writeText(address);
      $("error").textContent = "";
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Copy receive address";
      $("error").textContent = "Copy failed. Select the address above to copy it manually.";
    }
  } });
  $("actions").append(copy);
}

// ─── Worker asks: on-device decisions ────────────────────────────────────────
const zec = (zat) => `${(Number(zat) / 1e8).toFixed(8)} TAZ`;
const asks = {
  // The full member list, before this member tells the creator it agrees.
  "roster-members": (d) => prompt(`Join "${d.name}"?`, [
    el("p", { textContent: `${d.threshold} of ${d.members.length} members must approve each payment. Network: ${d.network}. You are member ${d.slot}.` }),
    el("ul", {}, ...d.members.map((m) => el("li", { className: "mono", textContent: `#${m.id}${m.id === d.slot ? " (you)" : ""} signing ${m.signing.slice(0, 16)}… relay ${m.encryption.slice(0, 16)}…` }))),
  ], [{ label: "Reject", ghost: true, value: false }, { label: "These are the members", value: true }]),

  // The 24-digit roster code, compared out of band with every other member.
  "roster-code": (d) => prompt("Compare this code with every other member", [
    el("p", { className: "code", textContent: d.code }),
    el("p", { textContent: "Every member's signer must show exactly these digits. If any differ, someone changed the vault setup." }),
    ...(d.birth_height != null ? [facts([["Vault birth height", d.birth_height]])] : []),
  ], [{ label: "Codes differ", ghost: true, value: false }, { label: "All codes match", value: true }]),

  "nonce-witnesses": (endpoints) => {
    const code = el("input", { type: "text", autocomplete: "off", spellcheck: false, maxLength: 64 });
    const field = reauthField();
    return prompt("Verify the nonce witnesses", [
      facts(endpoints.map((endpoint, i) => [`Witness ${i + 1}`, endpoint, true])),
      el("p", { textContent: "Get the 64-character pair fingerprint from the witness operators through a channel you trust, not from this wallet. An old signing attempt cannot use replacement witnesses." }),
      el("label", { textContent: "Witness fingerprint" }, code),
      ...(field ? [el("label", { textContent: "Passphrase" }, field)] : []),
    ], [cancelButton, { label: "Approve witnesses", run: async () => {
      const fingerprint = code.value.trim();
      if (!/^[0-9a-f]{64}$/i.test(fingerprint)) throw new SignerError("Enter the complete 64-character hexadecimal fingerprint.", 400);
      return { ...await reauthValue(field), fingerprint };
    } }]);
  },

  "payment-terms": (d) => openPaymentConsent("payment-terms", d),
  "payment-sign": (d) => openPaymentConsent("payment-sign", d),
};

// This port belongs to one worker ask for one payment. Only the tab opened here can
// connect; the wallet neither supplies the displayed details nor sees the answer.
function openPaymentConsent(kind, details) {
  const openedFor = current;
  return prompt("Continue in the Loki signer tab", [
    el("p", { textContent: `Review the payment in a separate tab. Check its address starts with ${location.origin}${paymentPath} before approving or entering any credentials.` }),
  ], [{ ...cancelButton, value: null }, { label: "Open signer tab", abortable: true, run: (signal) => {
    if (!openedFor || current !== openedFor) throw new SignerError("The signer session changed. Return to the wallet and try again.", 401);
    const tab = window.open(paymentPath, "_blank");
    if (!tab) throw new SignerError("Allow the signer to open a new tab and try again.", 400);
    return new Promise((resolve, reject) => {
      let port;
      const finish = () => {
        removeEventListener("message", connect);
        signal.removeEventListener("abort", cancel);
        clearInterval(closed);
        clearTimeout(timeout);
        port?.close();
        tab.close();
      };
      const cancel = () => { finish(); resolve(null); };
      const connect = (e) => {
        if (e.source !== tab || e.origin !== location.origin || e.data?.cmd !== "payment-connect" || !e.ports[0]) return;
        removeEventListener("message", connect);
        clearTimeout(timeout);
        if (current !== openedFor || tab.closed) { cancel(); return; }
        port = e.ports[0];
        port.onmessage = ({ data }) => {
          if (current !== openedFor || tab.closed) { cancel(); return; }
          finish();
          resolve(data);
        };
        const passkey = openedFor.se === "passkey";
        port.postMessage({ kind, details, passkey, credentialId: passkey ? rememberedCredential() : undefined });
      };
      addEventListener("message", connect);
      signal.addEventListener("abort", cancel, { once: true });
      const closed = setInterval(() => { if (tab.closed || current !== openedFor) cancel(); }, 500);
      const timeout = setTimeout(() => {
        finish();
        reject(new SignerError("The signer tab could not connect. Allow tabs opened by the signer and try again.", 409));
      }, 10000);
    });
  } }]);
}

// These prompts are only rendered by showPaymentConsent on the unframeable route.
const paymentPrompts = {
  "payment-terms": (d) => prompt("Approve this payment request?", [
    facts([["To", d.recipient, true], ["Amount", zec(d.amount_zat)], ["Fee", zec(d.fee_zat)], ["Memo", d.memo || "(none)"],
      ["Proposed by", `member ${d.proposer}`], ["Expires by height", d.expiry_height],
      ["Vault", d.vaultHex, true], ["Attempt", d.attemptHex, true]]),
    el("p", { textContent: "Nothing is signed yet: the transaction itself is checked against these terms before you sign." }),
  ], [{ label: "Decline", ghost: true, value: false }, { label: "Approve request", value: true }]),

  // The signer's OWN parse of the candidate transaction, after it matched the approved terms.
  // Signing needs a fresh passkey assertion (or the passphrase again).
  "payment-sign": (d, { passkey, credentialId }) => {
    const field = passkey ? null : passField("Passphrase", "current-password");
    return prompt("Sign this transaction?", [
      facts([["To", d.recipient_ua || d.recipient, true], ["Amount", zec(d.amount_zat)], ["Fee", `${zec(d.fee_zat)}${d.fee_verified ? "" : " (unverified)"}`],
        ["Change", zec(d.change_zat)], ["Memo", d.memo_text || "(none)"], ["Expires at height", d.expiry_height],
        ["Vault", d.vaultHex, true], ["Attempt", d.attemptHex, true], ["Sighash", d.sighash, true]]),
      field ? el("label", { textContent: "Passphrase" }, field) : el("p", { textContent: `Verify with your passkey for ${rpId}.` }),
    ], [{ label: "Decline", ghost: true, cancel: true, value: null }, { label: "Sign", abortable: true, run: async (signal) =>
      field ? { method: "passphrase", passphrase: field.value } : { method: "platform", prfSecret: await prfSecret(credentialId, signal) },
    }]);
  },
};

async function showPaymentConsent() {
  const connection = await connectToSignerFrame("payment-connect");
  if (!connection) {
    void prompt("Payment review unavailable", [el("p", { textContent: "Return to the wallet and use the signer’s Open signer tab button to review a payment." })], []);
    return;
  }
  const { port, context } = connection;
  const value = await paymentPrompts[context.kind](context.details, context);
  port.postMessage(value);
  port.close();
}

async function answerAsk(d) {
  let reply;
  try { reply = { answer: d.ask, ok: true, value: await asks[d.kind](d.data) }; }
  catch (e) { reply = { answer: d.ask, ok: false, error: e.message || String(e) }; }
  if (!workerFailure) worker.postMessage(reply);
}

// ─── enrollment: the device-login key lives on the signer origin ────────────────────────
// A non-extractable P-256 key in this origin's IndexedDB, authorized by the member identity in
// wasm. The wallet sees only public enrollment material and the transcript signature.
function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("loki_signer", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("device");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
function idbReq(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const r = fn(db.transaction("device", mode).objectStore("device"));
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function deviceKeypair() {
  const db = await idb();
  const existing = await idbReq(db, "readonly", (s) => s.get("enrollment-device-key"));
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await idbReq(db, "readwrite", (s) => s.put(pair, "enrollment-device-key"));
  return pair;
}
let enrollment = null;
async function enrollBegin() {
  if (!current) throw new SignerError("Unlock your signer", 401);
  const material = await call({ op: "enroll-material" });
  const pair = await deviceKeypair();
  const device_pubkey = toHex(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const authorization = await call({ op: "authorize-device", devicePubHex: device_pubkey });
  enrollment = { signing_pubkey: material.signing_pubkey, relay_pubkey: material.relay_pubkey, device_pubkey, authorization };
  return enrollment;
}
// Sign the coordinator's registration transcript. The coordinator is the wallet origin; the
// transcript binds it, the enrollment above and the coordinator's challenge — nothing else.
async function enrollSign({ challenge, replacement_generation, relay_challenge_pubkey }) {
  if (!enrollment) throw new SignerError("Start enrollment first", 400);
  if (typeof challenge !== "string" || !/^[0-9a-f]{64}$/.test(challenge)) throw new SignerError("invalid challenge", 400);
  if (typeof relay_challenge_pubkey !== "string" || !/^[0-9a-f]{64}$/.test(relay_challenge_pubkey)) throw new SignerError("invalid relay challenge key", 400);
  const e = enrollment;
  const transcript = ["loki-member-registration-v1", wallet, 0, e.signing_pubkey, e.relay_pubkey, "", e.device_pubkey, challenge].join("\n");
  const pair = await deviceKeypair();
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(transcript));
  const relay_proof = await call({ op: "relay-registration-proof", origin: wallet, challenge, key: relay_challenge_pubkey });
  const proof = { signature: toHex(new Uint8Array(sig)), relay_proof };
  if (replacement_generation !== undefined) {
    if (!Number.isSafeInteger(replacement_generation) || replacement_generation < 1) throw new SignerError("invalid replacement generation", 400);
    proof.replacement_authorization = await call({ op: "authorize-device-replacement", origin: wallet, devicePubHex: e.device_pubkey, challenge, generation: replacement_generation });
  }
  return proof;
}

// ─── the wallet bridge ───────────────────────────────────────────────────────
const relay = (p) => ({ ...p, frostdUrl: cfg.frostdUrl, nonceWitnesses: cfg.nonceWitnesses });
const ops = {
  has: () => call({ op: "has" }),
  status: () => {
    if (!current) throw new SignerError("Unlock your signer", 401);
    return { ...current, persisted, relay: cfg.frostdUrl, network: cfg.network, origin: location.origin };
  },
  create,
  unlock,
  lock: async () => { if (worker) await call({ op: "lock" }); current = null; enrollment = null; return null; },
  "enroll-begin": enrollBegin,
  "enroll-sign": enrollSign,
  // A vault backup must also seal to recovery words, so set them up before the first join.
  join: async (p) => {
    if (!(await call({ op: "recovery-status" })).recovery_identity) await recoverySetup();
    return call({ op: "join", join: relay(p) });
  },
  "payment-review": (p) => call({ op: "payment-review", payment: relay(p) }),
  "payment-approve": (p) => call({ op: "payment-approve", payment: relay(p) }),
  pending: (p) => call({ op: "pending", payment: { ...relay(p), lightwalletdGrpcWeb: cfg.lightwalletdGrpcWebUrl } }),
  vaults: () => call({ op: "vaults" }),
  address: async (p) => (await call({ op: "address", payment: p })).address,
  "verify-address": openReceiveAddress,
  chain: (p) => call({ op: "chain", payment: { ...p, lightwalletdGrpcWeb: cfg.lightwalletdGrpcWebUrl } }),
  "payment-status": (p) => call({ op: "payment-status", payment: { ...relay(p), lightwalletdGrpcWeb: cfg.lightwalletdGrpcWebUrl } }),
  "recovery-setup": recoverySetup,
  "recovery-status": () => call({ op: "recovery-status" }),
  "recovery-export": recoveryExport,
  restore,
  "manage-custody": manageCustody,
};
const UNLOCKED = new Set(["join", "payment-review", "payment-approve", "pending", "vaults", "address", "verify-address", "chain", "payment-status", "recovery-setup", "recovery-export", "recovery-status", "manage-custody"]);
// Ops that may show a prompt run one at a time; the read-only ones answer alongside them
// (the Worker refuses them with "busy" while a join or payment holds the vault).
const PROMPTING = new Set(["create", "unlock", "join", "verify-address", "payment-approve", "recovery-setup", "recovery-export", "restore", "manage-custody"]);

let queue = Promise.resolve(); // one op (and so one prompt) at a time
addEventListener("message", (e) => {
  if (!embedded || e.origin !== wallet || e.source !== parent) return;
  const { id, op, params } = e.data ?? {};
  if (typeof id !== "number" || !Object.hasOwn(ops, op)) return;
  const run = async () => {
    try {
      if (workerFailure) throw workerFailure;
      if (UNLOCKED.has(op) && !current) throw new SignerError("Unlock your signer", 401);
      parent.postMessage({ id, ok: true, result: await ops[op](params ?? {}) }, wallet);
    } catch (err) {
      parent.postMessage({ id, ok: false, error: err.message || String(err), status: err.status ?? 500 }, wallet);
    }
  };
  if (PROMPTING.has(op)) queue = queue.then(run);
  else run();
});
if (embedded) {
  if (!owner) parent.postMessage({ cmd: "ready" }, wallet); // Report the existing other-tab error per call.
  else try {
    worker = new Worker("./signer-worker.js", { type: "module" });
    worker.addEventListener("message", receiveWorker);
    worker.addEventListener("error", failWorker);
    worker.addEventListener("messageerror", failWorker);
  } catch { failWorker(); }
}
if (!framed && location.pathname === custodyPath) void showCustodyControls();
if (!framed && location.pathname === paymentPath) void showPaymentConsent();
if (!framed && location.pathname === receivePath) void showReceiveAddress();
