// Module Web Worker hosting the stateful in-browser signer (Phase A: profile lifecycle).
//
// The signing/DKG core is synchronous and persists to OPFS through synchronous access
// handles, which exist ONLY inside a Worker and must be acquired asynchronously FIRST. So
// this worker owns the pre-open protocol: before each synchronous `Signer` call it awaits
// `opfsPreopen{Write,Read}` on exactly the deterministic paths that op touches, then calls
// the sync wasm method. The path set is `devicePaths()` from the wasm module — one source
// of truth, no drift.
//
//   createSigner  preopenWrite: identity.sealed, profile.json, (passphrase) kek.salt
//   hasSigner     preopenRead:  identity.sealed
//   unlock        preopenRead:  identity.sealed, profile.json, (passphrase) kek.salt
//   lock          no I/O
//
// One worker per page lifetime: OPFS sync handles are exclusive, so a single long-lived
// Signer instance holds them; a page reload terminates it and releases them.

import init, { Signer, devicePaths, vaultPaths } from "./pkg/loki_signer_wasm.js";
import {
  opfsPreopenWrite as preopenWriteOnce,
  opfsPreopenRead as preopenReadOnce,
  opfsCloseAll,
} from "./pkg/snippets/loki-signer-core-8724841f4db15c9f/js/opfs_fs.js";
import { blockRange, latestHeight } from "./lightwalletd.js";
import { controlInbox, endsRequest, idbStore, MAX_CONTROL_SESSIONS } from "./control-inbox.js";
import { vaultSummary, saveVaultName, readVaultName } from "./vault-list.js";

// Ops run concurrently (a status read during a join), and two pre-opens of one path racing
// would each try to take its exclusive sync handle; the second throws. Share one in-flight
// pre-open per path instead.
const inflight = new Map();
function shared(open) {
  return (path) => {
    const key = `${open === preopenWriteOnce ? "w" : "r"}:${path}`;
    if (!inflight.has(key)) inflight.set(key, open(path).finally(() => inflight.delete(key)));
    return inflight.get(key);
  };
}
const opfsPreopenWrite = shared(preopenWriteOnce);
const opfsPreopenRead = shared(preopenReadOnce);

const ready = init().then(() => {
  const P = JSON.parse(devicePaths()); // { identity, profile, salt, recovery }
  return { signer: new Signer(), P };
});

// The frostd transport is a SEPARATE wasm module (core/wasm-transport) so its reqwest dep tree
// stays isolated from the signer core. It is loaded lazily, and only from its pinned path on
// this (the signer) origin — never from a caller-supplied URL — so lifecycle-only pages never
// fetch it and no page can swap the code that runs beside the signer.
const TRANSPORT_URL = new URL("./wasm-transport/pkg/loki_wasm_transport.js", import.meta.url).href;
let transport = null;
async function loadTransport() {
  if (!transport) {
    const mod = await import(TRANSPORT_URL);
    await mod.default();
    transport = mod;
  }
  return transport;
}
async function loadFrostd() {
  return (await loadTransport()).FrostdClient;
}

// Claim this signature's nonce at BOTH external witnesses (fresh, pinned-key receipts verified
// in wasm-transport), then tell the signer; the core's witness check in signApprove accepts
// only that claim. A duplicate at either relay (a nonce already used) refuses the signature.
async function claimAtWitnesses(signer, witnesses, attemptHex, packageHex, seedHex, sighashHex) {
  const { cid, record, pins } = JSON.parse(signer.nonceClaim(attemptHex, packageHex, seedHex, sighashHex));
  const routes = pins.map((pin) => witnesses.find((w) =>
    ["key", "run", "mailbox"].every((field) => w[field].toLowerCase() === pin[field])));
  if (routes.some((w) => !w)) throw new Error("An original nonce witness is missing; start a new signing attempt");
  const { claimNonce } = await loadTransport();
  for (const w of routes) {
    const challenge = toHex(crypto.getRandomValues(new Uint8Array(32)));
    const proof = signer.nonceClaimProof(w.key, w.run, w.mailbox, cid, record, challenge);
    const created = await claimNonce(w.endpoint, w.key, w.run, w.mailbox, cid, record, challenge, proof)
      .catch(() => { throw new Error("An original nonce witness is unavailable; start a new signing attempt"); });
    if (!created) {
      throw new Error("This nonce was already claimed at a nonce witness; start a new signing attempt");
    }
  }
  signer.nonceClaimed(cid, record);
}

// Testnet NU5 (Orchard) activation height (zakura-protocol consensus.rs, TestNetwork). No
// Orchard vault can be born below it.
const TESTNET_NU5_HEIGHT = 1_842_420;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const bin = atob(b64 + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `request to ${url} failed (${res.status})`);
  return data;
}

// Retry `fn` until it resolves (the creator's roster/session endpoints 404 "pending" until
// every member has enrolled/agreed), bounded so a stalled ceremony fails instead of hanging.
async function poll(fn, p) {
  const pollMs = Number(p.joinPollMs) || 500;
  const max = Number(p.joinMaxTicks) || 240;
  let lastErr;
  for (let i = 0; i < max; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      await sleep(pollMs);
    }
  }
  throw lastErr ?? new Error("ceremony step timed out");
}

// One join request to the creator over frostd, as native joiners send it (ceremony.rs
// `relay_request`): a session of this member and the creator, the request sealed to the creator
// in wasm (the invite token never crosses the relay in the clear), and the creator's sealed reply.
async function relayRequest(signer, fc, invite, op) {
  const { vault, slot, token, creator } = invite;
  const creatorJson = JSON.stringify(creator);
  const sessionId = await fc.openSession([signer.frostdPubkey(), creator.encryption]);
  try {
    await fc.sendToPeer(creator.encryption, signer.joinSeal(vault, sessionId, slot, creatorJson, JSON.stringify({ op, vault, slot, token })));
    for (let i = 0; i < 40; i++) {
      await sleep(250);
      for (const m of JSON.parse(await fc.recv())) {
        if (m.from !== creator.encryption) continue;
        let reply;
        try { reply = JSON.parse(signer.joinOpen(vault, sessionId, slot, creatorJson, m.message)); } catch { continue; }
        if (reply.error) throw new Error(reply.error);
        return reply;
      }
    }
    throw new Error("the creator did not answer over frostd");
  } finally {
    await fc.close().catch(() => {});
  }
}

// Decode a creator invite and run the native joiner dance with the creator's member app
// (core/src/host/ceremony.rs: enroll → poll roster → agree → poll session), then hand the
// assembled DKG params to driveDkg. An invite naming the creator's identity goes over frostd
// (relayRequest); an older one POSTs the token-authenticated endpoints the creator CORS-opens
// for browser joiners (routes.rs `browser_origin`). The setup
// document the creator feeds its own dkg_begin is rebuilt here from the polled roster — the
// roster fingerprint is over PARSED content (member_state::Roster::fingerprint), so field/byte
// order is irrelevant and only the values must match.
async function joinCeremony(signer, p) {
  const invite = JSON.parse(new TextDecoder().decode(b64urlToBytes(p.invite)));
  const base = invite.creator_base_url.replace(/\/+$/, "");
  const { vault, slot, token, threshold, name } = invite;
  const network = p.network ?? "testnet";

  // Our enrolled identity at the target slot: the device signing/relay keys (slot-independent;
  // restamp only overwrites the id bytes) stamped with the slot id. Needs the signer unlocked.
  const material = JSON.parse(signer.enrollMaterial());
  const identity = { id: slot, signing: material.signing_pubkey, encryption: material.relay_pubkey };
  const auth = { vault, slot, token };
  const frostdUrl = p.frostdUrl ?? invite.frostd_url;
  const fc = invite.creator ? await frostdClient(signer, { frostdUrl }) : null;
  const request = (op) => fc
    ? relayRequest(signer, fc, invite, op)
    : postJson(`${base}/api/${op}`, op === "enroll" ? { ...auth, identity } : auth);
  await request("enroll");

  // Poll until the full roster is published (fingerprint present).
  const rosterResp = await poll(() => request("roster"), p);
  const roster = rosterResp.roster;

  // The creator must not have swapped our slot's identity.
  const mine = roster[String(slot)];
  if (!mine || mine.signing !== identity.signing || mine.encryption !== identity.encryption) {
    throw new Error("creator roster changed this member's identity");
  }

  // Rebuild the creator's setup document (setup_version 2), members sorted by slot. The
  // testnet birth_height is NOT reconstructed from a guessed tip (it would mismatch the
  // creator's and the DKG setup certificate would be refused) — it is adopted from the
  // creator's published session below, so the document matches byte-for-byte.
  const members = Object.keys(roster)
    .map(Number)
    .sort((a, b) => a - b)
    .map((s) => ({ id: s, signing: roster[String(s)].signing, encryption: roster[String(s)].encryption }));

  // The member sees EVERY member before telling the creator it agrees, not just its own slot.
  if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > members.length) {
    throw new Error("the invite's threshold does not fit the roster");
  }
  if (await ask("roster-members", { name, vault, threshold, network, slot, members }) !== true) {
    throw new Error("You rejected this vault's members");
  }

  // Agree, then poll for the creator's frostd session + coordinator relay peer (+ birth_height).
  await request("agreed");
  const session = await poll(
    () =>
      request("session").then((s) =>
        s.session_id && s.coordinator_peer && (network !== "testnet" || s.birth_height != null)
          ? s
          : Promise.reject(new Error("session pending"))),
    p,
  );

  // The creator's birth height: it is inside the roster fingerprint, so every member's roster
  // code differs if the creator gave members different heights. Here it must at least be a
  // real Orchard-era Testnet height. ponytail: no upper bound — the browser has no chain
  // source to compare against; add one when the signer can reach a lightwalletd.
  const doc = { vault, threshold, setup_version: 2, network, members };
  if (network === "testnet") {
    const height = Number(session.birth_height);
    if (!Number.isSafeInteger(height) || height < TESTNET_NU5_HEIGHT) {
      throw new Error("the creator's vault birth height is not a Testnet Orchard height");
    }
    doc.birth_height = height;
  }
  const rosterHex = toHex(new TextEncoder().encode(JSON.stringify(doc)));

  return driveDkg(signer, {
    vaultHex: vault,
    slot,
    label: p.label ?? name,
    network,
    rosterHex,
    birthHeight: doc.birth_height,
    frostdUrl,
    sessionId: session.session_id,
    coordinatorPeer: session.coordinator_peer,
    pollMs: p.pollMs,
    maxTicks: p.maxTicks,
  });
}

// Drive this member through create-or-reopen → confirm roster → DKG rounds ↔ frostd → backup
// → active, then release the vault address. The signer core is synchronous (vaultJoin/vaultStep/
// vaultBackup/vaultReady/vaultAddress); this loop owns the async frostd pump. The coordinator
// (a roster member running the frostd relay) forwards each member's wires to its peers; this
// member only ever sends to the coordinator and keeps the coordinator's relayed wires.
async function driveDkg(signer, p) {
  const { slot, label, network, rosterHex, frostdUrl, coordinatorPeer, sessionId } = p;
  const vaultHex = await vaultPathId(p.vaultHex);
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
  // The backup also seals to the recovery public key; without one vaultJoin refuses.
  await opfsPreopenRead(JSON.parse(devicePaths()).recovery);

  // The 24-digit roster code, computed by the signer from the exact roster it will confirm,
  // shown on the signer page for the member to compare with every other member. vaultJoin's
  // roster prompt answers Match only for the code the member confirmed here.
  const roster = Uint8Array.from(rosterHex.match(/../g).map((b) => parseInt(b, 16)));
  const code = signer.rosterCode(roster);
  if (await ask("roster-code", { code, birth_height: p.birthHeight ?? null }) !== true) {
    throw new Error("You reported that the roster codes differ; this vault setup is stopped");
  }
  const vref = JSON.parse(signer.vaultJoin(vaultHex, slot, label ?? "vault", network, roster, code));
  if (label) await saveVaultName(await (await (await (await navigator.storage.getDirectory()).getDirectoryHandle("loki")).getDirectoryHandle("vaults")).getDirectoryHandle(vaultHex), label);

  const fc = await frostdClient(signer, { frostdUrl });
  fc.useSession(sessionId);

  const pollMs = Number(p.pollMs) || 200;
  const maxTicks = Number(p.maxTicks) || 1200;
  let ready = false;
  for (let tick = 0; tick < maxTicks && !ready; tick++) {
    const inbox = JSON.parse(await fc.recv());
    const inWires = inbox.filter((m) => m.from === coordinatorPeer).map((m) => m.message);
    for (const w of signer.vaultStep(inWires)) await fc.sendToCoordinator(w);
    for (const r of signer.vaultBackup()) await fc.sendToCoordinator(r);
    ready = signer.vaultReady();
    if (!ready) await sleep(pollMs);
  }
  if (!ready) throw new Error("DKG did not reach active before the deadline");
  return { vault: vref.vault_id, address: signer.vaultAddress() };
}

// Reopen this browser's signer for an active vault from its own stored state. Every member
// key the payment flow uses comes from the roster this member confirmed at setup.
async function openVault(signer, vaultHex) {
  const vault = await openVaultAny(signer, vaultHex);
  if (!vault.ready) throw new Error("this vault is not active yet");
  return vault;
}
async function openVaultAny(signer, vaultHex) {
  vaultHex = await vaultPathId(vaultHex);
  for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenWrite(path);
  return JSON.parse(signer.vaultOpen(vaultHex));
}

async function vaultPathId(id) {
  if (!/^[0-9a-f]{64}$/i.test(id ?? "")) throw new Error("invalid vault id");
  const canonical = id.toLowerCase();
  const root = await navigator.storage.getDirectory();
  let dir;
  try { dir = await (await root.getDirectoryHandle("loki")).getDirectoryHandle("vaults"); }
  catch (e) { if (e.name === "NotFoundError") return canonical; throw e; }
  let existing;
  for await (const [name] of dir.entries()) {
    if (name.toLowerCase() !== canonical) continue;
    if (existing) throw new Error("Multiple local vault directories match; keep both backups and resolve the conflict before restoring.");
    existing = name;
  }
  return existing ?? canonical;
}

// Trial decryption and checkpoint matching only establish what the configured provider reported.
async function chainScan(signer, p) {
  const source = p.lightwalletdGrpcWeb;
  if (!source) throw new Error("This signer has no lightwalletd gRPC-web endpoint configured, so it cannot read the chain");
  await openVault(signer, p.vaultHex);
  const tip = await latestHeight(source);
  const matchesCheckpoint = async (height) => {
    const [block] = await blockRange(source, height, height);
    return signer.scanMatchesCheckpoint(block);
  };
  const saved = signer.scanStart(source);
  let checkedTip = false;
  if (saved != null) {
    if (saved > tip || !(await matchesCheckpoint(saved))) signer.scanReset();
    else checkedTip = saved === tip;
  }
  // A reorg may also happen after the checkpoint read. Retry once from vault birth.
  for (let rescanned = false; ;) {
    try {
      for (let next = signer.scanNext(); next <= tip; next = signer.scanNext()) {
        const end = Math.min(tip, next + 499);
        signer.scanBlocks(next, end, await blockRange(source, next, end));
        signer.scanSave();
      }
      break;
    } catch (e) {
      if (rescanned || !String(e?.message ?? e).includes("block does not extend the saved scan tip")) throw e;
      rescanned = true;
      signer.scanReset();
    }
  }
  const result = JSON.parse(signer.scanResult());
  if (result.height !== tip || (!checkedTip && !(await matchesCheckpoint(tip)))) {
    throw new Error("lightwalletd did not provide a consistent scan through its reported tip; retry sync");
  }
  return { tip, ...result, chain_trust: "provider_reported" };
}

// Local decisions and checked effects, never the proposer's claimed approval or txid.
let paymentRecords;
async function paymentRecord(key, record) {
  paymentRecords ??= new Promise((resolve, reject) => {
    const req = indexedDB.open("loki_payment_records", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("attempts");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const tx = (await paymentRecords).transaction("attempts", record ? "readwrite" : "readonly", { durability: "strict" });
  const store = tx.objectStore("attempts");
  const req = record ? store.put(record, key) : store.get(key);
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(req.result ?? {});
    tx.onabort = () => reject(tx.error ?? new Error("could not save payment verification"));
  });
}
async function paymentKey(signer, notice) {
  const scope = JSON.stringify([signer.frostdPubkey(), notice.hash, notice.termsKey]);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(scope)));
  return btoa(String.fromCharCode(...hash));
}
// paymentCheck only accepts an Ironwood-only v6 candidate. Its shielded sighash is its
// effects txid in wire byte order (ZIP 233); the display txid reverses those bytes.
const reviewedTxid = (review) => review.sighash.match(/../g).reverse().join("");

// A payment's status for the wallet: relay terms, this member's own decision, and the
// chain's spend as separate facts. Only matching checked effects identify the attempt.
async function paymentStatus(signer, p) {
  const vault = await openVault(signer, p.vaultHex);
  const control = await frostdClient(signer, p);
  const { notice, start, signed } = await findPayment(signer, control, vault, p);
  const terms = notice.intent;
  const ended = notice.kind === "cancelled" || notice.kind === "failed" ? notice.kind : null;
  const signers = start?.intent.signers ?? [];
  const key = await paymentKey(signer, notice);
  const record = await paymentRecord(key);
  const { chain_trust } = await chainScan(signer, p);
  const spent = JSON.parse(signer.scanSpentBy(terms.note_selection[0]));
  let txid = record.txid ?? null;
  if (spent && !txid && signed) {
    // An authenticated copy supplies candidate effects, not proof of a broadcast or approval.
    try {
      const review = JSON.parse(signer.paymentCheck(signed.pczt, JSON.stringify({ ...terms, tx_expiry: signed.intent.signing_expiry })));
      if (reviewedTxid(review) === spent.txid) txid = spent.txid;
    } catch { /* An unchecked copy cannot identify the spend. */ }
    if (txid) {
      await paymentRecord(key, { ...record, txid });
    }
  }
  const closed = endsRequest(notice, vault.slot);
  return { terms, signers, ended, closed, spent, txid, approved: record.approved === true, slot: vault.slot, chain_trust };
}

// The terms a proposer announced for this payment, read-only: nothing is approved or sent.
// The wallet shows them before the member opens the approval on the signer page.
async function paymentTerms(signer, p) {
  const vault = await openVault(signer, p.vaultHex);
  const control = await frostdClient(signer, p);
  const { notice: { intent: t } } = await findPayment(signer, control, vault, p);
  return { review_token: p.attemptHex, recipient: t.recipient, amount_zat: String(t.amount_zat), fee_zat: String(t.fee_zat), memo: t.memo };
}

// Log in to frostd without the relay secret ever reaching JS: the transport fetches the
// challenge, the wasm signer XEdDSA-signs it, and only the signature crosses back.
async function frostdClient(signer, p) {
  const Client = await loadFrostd();
  const fc = new Client(p.frostdUrl, signer.frostdPubkey());
  const challenge = await fc.challenge();
  await fc.loginSigned(challenge, signer.frostdSignChallenge(challenge));
  return fc;
}

const controlHistory = controlInbox(idbStore());
// These are control states, not evidence of a finalized or mined transaction.
const noticeOrder = ["intent", "start", "signed", "broadcast", "confirmed", "failed", "cancelled"];
// PeerReply permits a 64 KiB body, which can round up to a 128 KiB sealed bucket.
const MAX_CONTROL_WIRE = 2 * (128 * 1024 + 53);
const MAX_CONTROL_BATCH = 256;
const hex32 = (s) => typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
const uuid = (s) => typeof s === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s);
const txHex = (s) => typeof s === "string" && s.length % 2 === 0 && /^[0-9a-f]+$/.test(s);

function openNotice(signer, vault, sessionId, owner, wire) {
  try {
    const { from, body } = JSON.parse(signer.openControl(sessionId, wire.from, wire.message));
    const { kind, hash, intent: i, txid, pczt, raw_tx } = JSON.parse(body);
    if (from !== owner.id || !noticeOrder.includes(kind) || !hex32(hash)
      || (kind !== "signed" && wire.message.length > 16 * 1024)
      || !i || i.proposer !== from || i.vault !== vault.vault_id || !hex32(i.attempt)
      || i.control_session_id !== sessionId || !uuid(i.session_id) || i.session_id === sessionId
      || typeof i.phase !== "string" || typeof i.recipient !== "string" || !i.recipient.length
      || typeof i.memo !== "string" || new TextEncoder().encode(i.memo).length > 512
      || ![i.amount_zat, i.fee_zat, i.change_zat].every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 2_100_000_000_000_000)
      || !i.amount_zat || ![i.target_height, i.expiry_height].every((h) => Number.isInteger(h) && h >= 0 && h <= 0xffffffff)
      || i.expiry_height <= i.target_height || !Array.isArray(i.note_selection)
      || i.note_selection.length !== 1 || !hex32(i.note_selection[0])) return null;
    if (i.replaces !== undefined && (!hex32(i.replaces?.attempt) || typeof i.replaces.cancel !== "boolean")) return null;
    const pin = i.coordinator;
    if (pin !== undefined && (pin?.id !== 0 || !hex32(pin.signing) || !hex32(pin.encryption)
      || vault.members.some((m) => m.signing === pin.signing || m.encryption === pin.encryption))) return null;
    if (!Array.isArray(i.signers)) return null;
    const validGroup = i.signers.length === vault.threshold
      && i.signers[0] === from && new Set(i.signers).size === vault.threshold
      && i.signers.every((slot) => vault.members.some((m) => m.id === slot));
    // Older starts did not fix a separate expiry; they used the approved bound.
    const fixesGroup = kind === "start" || kind === "signed";
    const expiry = i.signing_expiry ?? (fixesGroup ? i.expiry_height : undefined);
    if ((i.signers.length || fixesGroup) && !validGroup
      || (expiry != null && (!Number.isInteger(expiry) || expiry <= i.target_height || expiry > i.expiry_height))) return null;
    const sent = kind === "signed" || kind === "broadcast" || kind === "confirmed";
    if ((sent || txid != null) && !hex32(txid)) return null;
    if (kind === "signed" && (!txHex(pczt) || !txHex(raw_tx))) return null;
    // This projection matches the native hash's immutable fields; phase, group and actual
    // signing expiry are excluded. Compare the terms too, not just the proposer's hash label.
    const intent = {
      vault: i.vault, attempt: i.attempt, proposer: from, session_id: i.session_id, control_session_id: sessionId,
      recipient: i.recipient, memo: i.memo, amount_zat: i.amount_zat, fee_zat: i.fee_zat, change_zat: i.change_zat,
      target_height: i.target_height, expiry_height: i.expiry_height, note_selection: i.note_selection,
      ...(i.replaces && { replaces: { attempt: i.replaces.attempt, cancel: i.replaces.cancel } }),
      ...(pin && { coordinator: { id: 0, signing: pin.signing, encryption: pin.encryption } }),
    };
    return {
      from, kind, hash, txid, ...(kind === "signed" && { pczt }),
      termsKey: JSON.stringify(intent),
      intent: { ...intent, phase: i.phase, signers: i.signers, signing_expiry: expiry },
    };
  } catch { return null; } // Authentication or decoding failed.
}

function selectNotices(signer, vault, sessionId, owner, wires) {
  let notice, start, signed;
  for (const wire of wires) {
    const event = openNotice(signer, vault, sessionId, owner, wire);
    if (!event || (notice && (event.hash !== notice.event.hash || event.termsKey !== notice.event.termsKey))) continue;
    if (event.kind === "start" || event.kind === "signed") {
      const fixed = (start ?? signed)?.event.intent;
      if (fixed && (event.intent.signing_expiry !== fixed.signing_expiry
        || String(event.intent.signers) !== String(fixed.signers))) continue;
    }
    const entry = { wire, event };
    if (event.kind === "start") start ??= entry;
    if (event.kind === "signed") signed ??= entry;
    if (!notice || noticeOrder.indexOf(event.kind) > noticeOrder.indexOf(notice.event.kind)) notice = entry;
  }
  if (!notice) return null;
  return {
    notice: notice.event, start: start?.event, signed: signed?.event,
    wires: [...new Set([start?.wire, signed?.wire, notice.wire].filter(Boolean))],
  };
}

function controlOwner(vault, info) {
  const participants = new Set(info.participants);
  if (info.participants.length !== vault.members.length || !vault.members.every((m) => participants.has(m.encryption))) return null;
  return vault.members.find((m) => m.id !== vault.slot && m.encryption === info.coordinator);
}

// Match the whole roster before draining. If two local vaults share a roster, try the other
// vault before discarding its one-shot notice; the sealed envelope binds the actual vault.
async function readControl(signer, control, vault, sessionId, owner, scope, info) {
  let reduced = null;
  await controlHistory([scope, sessionId], async (saved, markDraining) => {
    if (saved.blocked || saved.vault && saved.vault !== vault.vault_id || saved.wires.length > MAX_CONTROL_BATCH) return [];
    control.useSession(sessionId);
    await markDraining();
    return JSON.parse(await control.recv());
  }, async (saved, fresh) => {
    if (saved.vault && saved.vault !== vault.vault_id) return saved;
    const unique = new Map();
    let bytes = 0;
    let blocked = saved.blocked ?? false;
    for (const batch of [saved.wires, fresh]) {
      if (batch.length > MAX_CONTROL_BATCH) blocked = true;
      for (const wire of batch.slice(0, MAX_CONTROL_BATCH)) {
        const msg = wire?.message;
        if (wire?.from !== owner.encryption || typeof msg !== "string" || !msg.length
          || msg.length > MAX_CONTROL_WIRE || unique.has(msg)) continue;
        bytes += msg.length;
        if (bytes > 4 * 1024 * 1024) { blocked = true; break; }
        unique.set(msg, { from: owner.encryption, message: msg });
      }
    }
    const wires = [...unique.values()];
    // Only a fresh copy of the selected notice can clear an interrupted drain. In
    // particular, receiving an old intent must not make a cached start signable again.
    const reannounced = ({ notice }, target, proposer) => fresh.slice(0, MAX_CONTROL_BATCH).some((wire) => {
      if (wire?.from !== proposer.encryption || !unique.has(wire.message)) return false;
      const event = openNotice(signer, target, sessionId, proposer, wire);
      return event?.kind === notice.kind && event.hash === notice.hash && event.termsKey === notice.termsKey
        && event.intent.signing_expiry === notice.intent.signing_expiry
        && String(event.intent.signers) === String(notice.intent.signers);
    });
    const record = (name, state, draining) => ({
      vault: name, wires: state.wires, blocked, draining,
      // Don't discard legacy data if only a prefix could be checked.
      migrated: !blocked && !saved.vault && saved.wires.some((w) => state.wires.some((m) => m.message === w?.message)),
    });
    reduced = selectNotices(signer, vault, sessionId, owner, wires);
    if (!reduced && info && wires.length && !saved.vault) {
      const dir = await vaultDirectory();
      try {
        if (dir) for await (const [name, h] of dir.entries()) {
          if (name === vault.vault_id || h.kind !== "directory" || !hex32(name)) continue;
          let other;
          try { other = await openVault(signer, name); } catch { continue; }
          const proposer = controlOwner(other, info);
          if (!proposer) continue;
          const match = selectNotices(signer, other, sessionId, proposer, wires);
          if (match) return record(name, match, !!saved.draining && !reannounced(match, other, proposer));
        }
      } finally { await openVault(signer, vault.vault_id); }
    }
    if (!reduced) return blocked && !saved.blocked ? { ...saved, blocked } : saved;
    const draining = !!saved.draining && !reannounced(reduced, vault, owner);
    // Keep newly authenticated wires even while signing is blocked. An interrupted drain
    // must still accept later notices, unlike a session that exceeded the wire budget.
    reduced.blocked = blocked || draining;
    if (!saved.draining && saved.vault && blocked === saved.blocked && reduced.wires.length === saved.wires.length
      && reduced.wires.every((wire, i) => wire.message === saved.wires[i].message)) return saved;
    return record(vault.vault_id, reduced, draining);
  });
  return reduced;
}

const controlScope = (signer, p) => JSON.stringify([p.frostdUrl, signer.frostdPubkey()]);

async function controlSessions(control, scope) {
  const ids = await control.list_sessions();
  if (ids.length > MAX_CONTROL_SESSIONS) throw new Error("too many relay sessions to check for payments");
  const live = new Set(ids);
  await controlHistory.prune(scope, live);
  return live;
}

// A signing session has a one-shot coordinator, not a confirmed vault member.
async function findPayment(signer, control, vault, p) {
  const { attemptHex, proposer } = p;
  if (!Number.isInteger(proposer) || proposer === vault.slot || !vault.members.some((m) => m.id === proposer)) {
    throw new Error("a payment lookup requires a valid proposer from this vault");
  }
  const scope = controlScope(signer, p);
  const skip = new Set();
  const pollMs = Number(p.findPollMs) || 2000;
  const maxTicks = Number(p.findMaxTicks) || 30;
  for (let tick = 0; tick < maxTicks; tick++) {
    for (const sessionId of await controlSessions(control, scope)) {
      if (skip.has(sessionId)) continue;
      control.useSession(sessionId);
      const info = JSON.parse(await control.sessionInfo());
      const owner = controlOwner(vault, info);
      if (owner?.id !== proposer) {
        skip.add(sessionId);
        continue;
      }
      const state = await readControl(signer, control, vault, sessionId, owner, scope, info);
      if (state?.notice.from === proposer && state.notice.intent.attempt === attemptHex) {
        if (state.blocked) throw new Error("this payment's notice history exceeded the inbox limit");
        return { controlSessionId: sessionId, ...state };
      }
      if (state) skip.add(sessionId);
    }
    await sleep(pollMs);
  }
  throw new Error("this payment was not found on the relay; it may be finished, cancelled or for another vault");
}

// Payments other members proposed in this vault that still want this member: one pass over the
// relay's control sessions, read like findPayment. The proposer sends its notice once at publish
// and again only after it approves, so a request stays listed from the notices readControl kept.
async function listPending(signer, vaultHex, p) {
  const vault = await openVault(signer, vaultHex);
  const control = await frostdClient(signer, p);
  const scope = controlScope(signer, p);
  const pending = new Map();
  for (const sessionId of await controlSessions(control, scope)) {
    control.useSession(sessionId);
    const info = JSON.parse(await control.sessionInfo());
    const owner = controlOwner(vault, info);
    if (!owner) continue;
    const state = await readControl(signer, control, vault, sessionId, owner, scope, info);
    if (!state) continue;
    const { notice: m } = state;
    const i = m.intent;
    const key = `${m.from}:${i.attempt}`;
    if (state.blocked || endsRequest(m, vault.slot)) { pending.set(key, null); continue; }
    if (pending.get(key) === null) continue;
    pending.set(key, { attempt: i.attempt, amount_zat: String(i.amount_zat), recipient: i.recipient, proposer: m.from, note: i.note_selection[0] });
  }
  const requests = [...pending.values()].filter(Boolean);
  if (!requests.length) return [];
  await chainScan(signer, p);
  // A spent input ends this request's opportunity to sign, but doesn't identify the payment.
  return requests.flatMap(({ note, ...request }) => JSON.parse(signer.scanSpentBy(note)) ? [] : [request]);
}

async function vaultDirectory() {
  try {
    return await (await (await navigator.storage.getDirectory()).getDirectoryHandle("loki")).getDirectoryHandle("vaults");
  } catch { return null; } // no vault yet
}

// Every vault this browser holds a signer for, from its own OPFS (loki/vaults/<id>/signer).
async function listVaults(signer) {
  const dir = await vaultDirectory();
  if (!dir) return [];
  const out = [];
  for await (const [name, h] of dir.entries()) {
    if (h.kind !== "directory" || !/^[0-9a-f]{64}$/i.test(name)) continue;
    let v;
    try { v = await openVaultAny(signer, name); } catch { continue; } // setup never started
    out.push(vaultSummary(v, await readVaultName(h)));
  }
  return out;
}

function activeGroup({ notice, start, blocked }, slot) {
  if (blocked) throw new Error("this payment's notice history exceeded the inbox limit");
  if (endsRequest(notice, slot)) {
    if (notice.kind === "cancelled") throw new Error("the proposer cancelled this payment");
    if (notice.kind === "failed") throw new Error("the proposer could not complete this payment");
    if (notice.kind === "start") throw new Error("enough members already approved this payment");
    throw new Error("the proposer ended this signing request");
  }
  return start?.intent;
}

// Drive this NON-proposer member through one payment signing attempt over frostd, mirroring
// the native `signer_loop`: find the payment on the relay → approve → wait for the signing
// group → commit → receive the proposer's sealed candidate + the coordinator's signing package
// and rerandomizer seed → WYSIWYS-review the candidate → release the signature share.
// Everything comes from the relay and this member's own stored roster; no member serves HTTP.
//
// The request is open to every member: the proposer fixes the signing group from the first
// approvals to arrive. So this member approves, waits for the group, and commits a nonce only
// if the group includes it; a commitment from outside the group would fail the round.
async function drivePayment(signer, p, witnessPinsPath) {
  const { vaultHex, attemptHex } = p;
  // Like a native member without --nonce-witnesses: no witnesses, no signing — refused before
  // anything is approved or committed.
  if (!Array.isArray(p.nonceWitnesses) || p.nonceWitnesses.length !== 2) {
    throw new Error("This signer has no nonce witnesses configured, so it cannot sign");
  }
  const vault = await openVault(signer, vaultHex);
  const control = await frostdClient(signer, p);
  const { controlSessionId, notice: announced, start } = await findPayment(signer, control, vault, p);
  const pins = JSON.stringify(p.nonceWitnesses.map(({ key, run, mailbox }) => ({ key, run, mailbox })));
  await opfsPreopenRead(witnessPinsPath);
  if (!signer.setNonceWitnesses(pins)) {
    const consent = await ask("nonce-witnesses", p.nonceWitnesses.map((w) => w.endpoint));
    signer.reauth(consent.method, consent.passphrase, consent.prfSecret);
    await opfsPreopenWrite(witnessPinsPath);
    signer.setNonceWitnesses(pins, consent.fingerprint);
  }
  const proposer = vault.members.find((m) => m.id === announced.from);
  const terms = announced.intent;
  // Trust the key in the authenticated payment terms, never signing-session metadata.
  const coordinator = terms.coordinator;
  if (!coordinator) {
    throw new Error("This payment has no sealed signing coordinator; ask the proposer to create a fresh payment");
  }
  const key = await paymentKey(signer, announced);
  const record = await paymentRecord(key);
  const scope = controlScope(signer, p);
  const refresh = async () => {
    const state = await readControl(signer, control, vault, controlSessionId, proposer, scope);
    if (!state || state.notice.hash !== announced.hash || state.notice.termsKey !== announced.termsKey) {
      throw new Error("the payment's approved terms are no longer available");
    }
    return activeGroup(state, vault.slot);
  };

  // Approve on the control session: a sealed {kind:"approval"} for the terms the proposer
  // announced, which the proposer records (payment.rs `sync_control`). Durable at frostd. The
  // member sees those terms on the signer page first; declining sends nothing.
  let group = activeGroup({ notice: announced, start }, vault.slot);
  if (!group) {
    if (!await ask("payment-terms", { ...terms, vaultHex, attemptHex })) throw new Error("You declined this payment request");
    group = await refresh();
    if (!group) {
      const approval = JSON.stringify({ kind: "approval", hash: announced.hash, intent: terms, txid: null });
      await control.sendToPeer(proposer.encryption, signer.sealControl(controlSessionId, proposer.id, approval));
      group = await waitForSigningGroup(refresh, p);
    }
  }
  const { signers, signing_expiry: expiry } = group;

  const fc = await frostdClient(signer, p);
  fc.useSession(terms.session_id);

  // Pre-open this attempt's crash-safe nonce files (name = payment_id ++ attempt_id hex; the
  // native host sets both to the attempt), so the synchronous commit/sign can persist.
  const nonceId = attemptHex + attemptHex;
  const dir = `loki/vaults/${await vaultPathId(vaultHex)}/signer`;
  await opfsPreopenWrite(`${dir}/nonces/${nonceId}.nonce`);
  await opfsPreopenWrite(`${dir}/nonces/${nonceId}.burn`);

  const signersCsv = signers.join(",");
  const seal = (body, share) => signer.sealSigning(coordinator.signing, coordinator.encryption, signersCsv, attemptHex, body, share);
  await refresh();
  await fc.sendToCoordinator(seal(signer.signCommit(attemptHex), false));

  // Accept one authenticated message of each expected kind, regardless of delivery order.
  const received = new Map();
  const pollMs = Number(p.pollMs) || 200;
  const maxTicks = Number(p.maxTicks) || 1200;
  for (let tick = 0; tick < maxTicks; tick++) {
    for (const m of JSON.parse(await fc.recv())) {
      const sender = m.from === proposer.encryption ? proposer : m.from === coordinator.encryption ? coordinator : null;
      if (!sender) continue;
      try {
        const { kind, body } = JSON.parse(signer.openSigning(sender.signing, sender.encryption, sender.id, signersCsv, attemptHex, m.message));
        if (!received.has(kind)) received.set(kind, body);
      } catch { /* not an authenticated round message for this attempt */ }
    }
    if (received.size === 3) break;
    await sleep(pollMs);
  }
  const candidateHex = received.get("candidate"), packageHex = received.get("package"), seedHex = received.get("seed");
  if (!candidateHex || !packageHex || !seedHex) {
    throw new Error("payment signing messages did not arrive before the deadline");
  }

  // The signer's own parse of the candidate must be exactly the approved terms (network,
  // expiry, the one input note, recipient, amount, memo, change, fee) — refused otherwise,
  // before the member is even asked. Then the member confirms that parse on the signer page
  // with a fresh passkey assertion (or the passphrase again), and signApprove releases the
  // share only for the sighash the member confirmed.
  const review = JSON.parse(signer.paymentCheck(candidateHex, JSON.stringify({ ...terms, tx_expiry: expiry })));
  const txid = reviewedTxid(review);
  if (record.txid && record.txid !== txid) throw new Error("this attempt already has different reviewed effects");
  const consent = await ask("payment-sign", { ...review, vaultHex, attemptHex });
  if (!consent) throw new Error("You declined to sign this payment");
  await refresh();
  signer.reauth(consent.method, consent.passphrase, consent.prfSecret);
  await paymentRecord(key, { ...record, txid });
  await claimAtWitnesses(signer, p.nonceWitnesses, attemptHex, packageHex, seedHex, review.sighash);
  const share = signer.signApprove(attemptHex, candidateHex, packageHex, seedHex, review.sighash, JSON.stringify({ ...terms, tx_expiry: expiry }));
  await fc.sendToCoordinator(seal(share, true));
  // Keep a terms-only approval or an interrupted share send retryable in the wallet.
  await paymentRecord(key, { approved: true, txid });
  return { approved: true, signed: true, review };
}

// Wait on the control session until the proposer names the signing group. Nothing secret is
// committed while waiting, so giving up here is safe: approving again resumes the wait.
async function waitForSigningGroup(refresh, p) {
  const pollMs = Number(p.groupPollMs) || 2000;
  const maxTicks = Number(p.groupMaxTicks) || 900; // 30 minutes at the default poll
  for (let tick = 0; tick < maxTicks; tick++) {
    await sleep(pollMs);
    const group = await refresh();
    if (group) return group;
  }
  throw new Error("Your approval is recorded, but not enough members approved yet. Open this payment again later to sign.");
}

async function preopenCreate(P, method) {
  await opfsPreopenWrite(P.identity);
  await opfsPreopenWrite(P.profile);
  if (method === "passphrase") await opfsPreopenWrite(P.salt);
}

async function preopenUnlock(P, method) {
  await opfsPreopenRead(P.identity);
  await opfsPreopenRead(P.profile);
  if (method === "passphrase") await opfsPreopenRead(P.salt);
}

// On-device decisions: the worker asks the signer page (signer-page.js), which shows the
// prompt on the signer origin and answers. The wallet page never sees or answers these.
const asks = new Map();
let askSeq = 0;
let busy = null; // "join" | "payment-approve" while one holds the open vault
let turn = Promise.resolve(); // vault ops take turns
function ask(kind, data) {
  const id = ++askSeq;
  return new Promise((resolve, reject) => {
    asks.set(id, { resolve, reject });
    self.postMessage({ ask: id, kind, data });
  });
}

self.onmessage = async (e) => {
  if (e.data.answer !== undefined) {
    const a = asks.get(e.data.answer);
    asks.delete(e.data.answer);
    if (a) e.data.ok ? a.resolve(e.data.value) : a.reject(new Error(e.data.error));
    return;
  }
  const { id, op, method, name, passphrase, prfSecret, join, payment, devicePubHex, vaultHex, words, blob, fingerprint } = e.data;
  // The Signer holds ONE open vault, and these ops each reopen one. A join, payment or
  // restore holds it, so the quick reads are refused while one runs (the wallet polls
  // again) and otherwise take turns, so no op swaps the vault under another mid-flight.
  const holds = op === "join" || op === "payment-approve" || op === "restore";
  const reads = op === "payment-review" || op === "pending" || op === "vaults" || op === "address" || op === "recovery-backup" || op === "chain" || op === "payment-status";
  let release = () => {};
  try {
    if (reads && busy) throw new Error(`the signer is busy with a ${{ join: "vault setup", "payment-approve": "payment", restore: "restore" }[busy]}; try again when it finishes`);
    if (holds) busy = op;
    if (reads || holds) {
      const prev = turn;
      turn = new Promise((r) => { release = r; });
      await prev;
    }
    const { signer, P } = await ready;
    let result;
    switch (op) {
      case "has":
        await opfsPreopenRead(P.identity);
        result = signer.hasSigner();
        break;
      case "enroll-material":
        // Public roster enrollment identity; the unlocked device identity is already in memory.
        result = JSON.parse(signer.enrollMaterial());
        break;
      case "authorize-device":
        result = signer.authorizeDevice(devicePubHex);
        break;
      case "authorize-device-replacement": {
        const { origin, challenge, generation } = e.data;
        result = signer.authorizeDeviceReplacement(origin, devicePubHex, challenge, BigInt(generation));
        break;
      }
      case "relay-registration-proof": {
        const { origin, challenge, key } = e.data;
        result = signer.relayRegistrationProof(origin, challenge, key);
        break;
      }
      case "join":
        result = await joinCeremony(signer, join);
        break;
      case "payment-review":
        // The announced terms only; the candidate is checked against them inside approval.
        result = await paymentTerms(signer, payment);
        break;
      case "pending":
        result = await listPending(signer, payment.vaultHex, payment);
        break;
      case "vaults":
        result = await listVaults(signer);
        break;
      case "chain":
        result = await chainScan(signer, payment);
        break;
      case "payment-status":
        result = await paymentStatus(signer, payment);
        break;
      case "address": {
        const vaultHex = await vaultPathId(payment.vaultHex);
        // A receive-address lookup must not create files for a missing vault.
        for (const path of JSON.parse(vaultPaths(vaultHex))) await opfsPreopenRead(path);
        const vault = JSON.parse(signer.vaultOpen(vaultHex));
        if (!vault.ready) throw new Error("this vault is not active yet");
        result = { vault: vault.vault_id, network: vault.network, address: signer.vaultAddress() };
        break;
      }
      case "payment-approve":
        result = await drivePayment(signer, payment, P.witnessPins);
        break;
      case "create":
        await preopenCreate(P, method);
        result = JSON.parse(
          signer.createSigner(method, name ?? "", passphrase, prfSecret)
        );
        break;
      case "unlock":
        await preopenUnlock(P, method);
        result = JSON.parse(signer.unlock(method, passphrase, prfSecret));
        break;
      case "lock":
        signer.lock();
        result = null;
        break;
      case "recovery-status":
        await opfsPreopenRead(P.recovery);
        await opfsPreopenRead(P.legacyRecovery);
        result = { recovery_identity: signer.hasRecovery(), legacy_recovery: signer.needsRecoveryMigration() };
        break;
      case "recovery-begin":
        // The words go only to the signer page, which shows them once.
        await opfsPreopenRead(P.recovery);
        await opfsPreopenRead(P.legacyRecovery);
        result = signer.recoveryBegin();
        break;
      case "recovery-confirm":
        await opfsPreopenWrite(P.recovery);
        signer.recoveryConfirm();
        result = null;
        break;
      case "recovery-migrate":
        await opfsPreopenRead(P.legacyRecovery);
        await opfsPreopenWrite(P.recovery);
        signer.recoveryMigrate(words);
        result = null;
        break;
      case "recovery-backup": {
        const pathId = await vaultPathId(vaultHex);
        for (const path of JSON.parse(vaultPaths(pathId))) await opfsPreopenRead(path);
        result = signer.recoveryBackup(pathId);
        break;
      }
      case "restore": {
        const pathId = await vaultPathId(vaultHex);
        await opfsPreopenRead(P.identity);
        if (signer.hasSigner()) {
          await opfsPreopenRead(P.profile);
        } else {
          await preopenCreate(P, method);
          await opfsPreopenWrite(P.recovery);
        }
        for (const path of JSON.parse(vaultPaths(pathId))) await opfsPreopenWrite(path);
        result = JSON.parse(signer.restoreSigner(method, name ?? "", passphrase, prfSecret, pathId, words, blob, fingerprint));
        break;
      }
      case "remove-verified": {
        // The page drains and blocks other ops during removal. Verify against the active
        // KEK in the same worker that holds this partition's custody and sync handles.
        signer.reauth(method, passphrase, prfSecret);
        const root = await navigator.storage.getDirectory();
        await controlHistory.clear();
        opfsCloseAll();
        await root.removeEntry("loki", { recursive: true }).catch((e) => { if (e.name !== "NotFoundError") throw e; });
        signer.lock();
        result = null;
        break;
      }
      default:
        throw new Error(`unknown op: ${op}`);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  } finally {
    if (holds) busy = null;
    release();
  }
};

self.addEventListener("unhandledrejection", () => self.postMessage({ cmd: "failed" }));
try {
  await ready;
  self.postMessage({ cmd: "loaded" });
} catch { self.postMessage({ cmd: "failed" }); }
