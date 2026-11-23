"use client";

// Member calls go to one of two signer kinds, chosen per tab:
//   - a paired NATIVE member app (loki_member_app): HTTP to its loopback origin with its
//     process capability (X-Loki-Token), exactly the device API it serves; or
//   - the in-browser wasm signer (src/lib/signer.ts) on its own origin.
// A tab paired with a native member routes every member call there; otherwise to the browser
// signer. Only coordinator calls (/api/members, /api/fund) go to this origin.
// Explicit .ts extension so Node's test loader resolves the chained import.
import { signer, ApiError, onboardingGrant, type CreateSignerOpts, type EnrolledMember, type SignerSession, type UnlockOpts } from "./signer.ts";
import { isLokiSignerUrl } from "./lokisigner-url.ts";
export { ApiError };
export type { CustodyMethod, CreateSignerOpts, EnrolledMember, UnlockOpts } from "./signer";
export type Slot = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };

/** Register this in-browser signer into the public roster; returns its allocated member/slot. */
export function enroll(coordinatorOrigin?: string): Promise<EnrolledMember> { return signer.enroll(coordinatorOrigin); }

// ─── native member (paired tab) ──────────────────────────────────────────────
type Pairing = { endpoint: string; capability: string; lokisigner?: true };
const PAIRING = "loki_device_session"; // sessionStorage: headless paste flow only
const LOKISIGNER_SLOT = "loki_lokisigner_slot"; // public reconnect hint, not authorization
// Browsers can copy sessionStorage to a new tab; keep an approved grant in this page only.
let lokiSignerSession: Pairing | null = null;
function paired(): Pairing | null {
  if (typeof window === "undefined") return null;
  if (lokiSignerSession) return lokiSignerSession;
  try {
    const raw = sessionStorage.getItem(PAIRING);
    const stored = raw ? JSON.parse(raw) as Pairing : null;
    if (!stored?.lokisigner) return stored;
    // Older wallets stored LokiSigner grants here. Never use a copy from storage.
    sessionStorage.removeItem(PAIRING);
  } catch {}
  return null;
}
/** Which signer this tab drives. */
export function signerKind(): "native" | "browser" { return paired() ? "native" : "browser"; }
export function hasLokiSignerSession(): boolean { return paired()?.lokisigner === true; }
export function lastLokiSignerSlot(): number | undefined {
  try {
    const slot = Number(sessionStorage.getItem(LOKISIGNER_SLOT));
    return Number.isSafeInteger(slot) && slot > 0 ? slot : undefined;
  } catch { return undefined; }
}

async function nativeApi<T>(session: Pairing, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  if (session.lokisigner && !isLokiSignerUrl(session.endpoint)) throw new ApiError("invalid LokiSigner endpoint", 401);
  const headers: Record<string, string> = { "X-Loki-Token": session.capability };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`${session.endpoint}/api/${path}`, {
    method: body === undefined ? "GET" : "POST", headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit", redirect: "error", cache: "no-store", signal,
  });
  const text = await res.text();
  if (session.lokisigner && res.status === 401) throw new ApiError("LokiSigner disconnected this tab", 401);
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new ApiError(data.error ?? `${path} failed (${res.status})`, res.status);
  return data as T;
}

/** Pair this tab with a native member from the link it printed (`http://127.0.0.1:<port>/#<capability>`).
 *  The member's identity must be the one the public roster lists for its slot. */
export async function pairDevice(link: string, expectedSlot?: number, cancel?: AbortSignal): Promise<Slot> {
  const url = new URL(link.trim());
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)
    || !url.port || Number(url.port) < 1024 || url.pathname !== "/" || url.search || url.username || url.password
    || !/^#[A-Za-z0-9_-]{43}$/.test(url.hash)) throw new Error("Paste the local pairing link printed by your member process");
  const session = { endpoint: url.origin, capability: url.hash.slice(1) };
  const timeout = AbortSignal.timeout(30_000);
  const signal = cancel ? AbortSignal.any([cancel, timeout]) : timeout;
  let member: Slot;
  try {
    member = await nativeApi<Slot>(session, "registration", undefined, signal);
    if (expectedSlot !== undefined && member.slot !== expectedSlot) {
      throw new Error(`Pairing link belongs to a different member. Use the link for slot ${expectedSlot}.`);
    }
    const roster = await listSlots(signal);
    if (!roster.some((m) => m.slot === member.slot && m.signing_pubkey === member.signing_pubkey && m.relay_pubkey === member.relay_pubkey && m.advertise_url === member.advertise_url)) {
      throw new Error("Device identity does not match the public roster; register the device first");
    }
    const status = await nativeApi<{ phase: string }>(session, "status", undefined, signal);
    if (status.phase !== "home") throw new Error("Unlock the profile locally on your device, then pair again");
    signal.throwIfAborted();
  } catch (error) {
    cancel?.throwIfAborted();
    if (timeout.aborted) throw new Error("Pairing timed out. Check that your member app is still running and try again.");
    throw error;
  }
  sessionStorage.setItem(PAIRING, JSON.stringify(session));
  sessionStorage.setItem("loki_me", JSON.stringify({ slot: member.slot }));
  sessionStorage.removeItem(LOKISIGNER_SLOT);
  lokiSignerSession = null;
  return member;
}

export type ConnectProgress = { phase: "starting" } | { phase: "compare"; code: string };

export class LokiSignerStartupTimeout extends Error {
  constructor() {
    super("Could not reach LokiSigner. It may not be open and unlocked on this Mac, local network permission may have been denied, or this browser may block the request.");
  }
}

/** Discover this launch and keep its single response open until LokiSigner decides. */
export async function connectLokiSigner(slot: number, show: (progress: ConnectProgress) => void, signal: AbortSignal): Promise<void> {
  show({ phase: "starting" });
  const starting = new AbortController();
  const discovery = AbortSignal.any([signal, starting.signal]);
  const deadline = setTimeout(() => starting.abort(new LokiSignerStartupTimeout()), 60_000);
  try {
    while (true) {
      discovery.throwIfAborted();
      const member = (await listSlots(discovery)).find((m) => m.slot === slot);
      discovery.throwIfAborted();
      const endpoint = member?.lokisigner_url;
      if (endpoint !== undefined && !isLokiSignerUrl(endpoint)) throw new Error("The coordinator did not give a valid LokiSigner loopback address.");
      if (member && endpoint) {
        const { signing_pubkey, relay_pubkey } = member;
        const stalled = new AbortController();
        const responseSignal = AbortSignal.any([discovery, stalled.signal]);
        const timer = setTimeout(() => stalled.abort(), 15_000);
        const res = await fetch(`${endpoint}/api/connect`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ slot, signing_pubkey, relay_pubkey }),
          signal: responseSignal, credentials: "omit", redirect: "error", cache: "no-store",
        }).catch(() => null).finally(() => clearTimeout(timer));
        discovery.throwIfAborted();
        if (res?.ok) {
          clearTimeout(deadline);
          // The native app can wait 110 seconds for Allow. Bound the entire body, including EOF.
          const decision = setTimeout(() => stalled.abort(new Error("LokiSigner connection timed out. Try again.")), 120_000);
          const capability = await readConnectDecision(res, show, responseSignal).finally(() => clearTimeout(decision));
          responseSignal.throwIfAborted();
          sessionStorage.setItem(LOKISIGNER_SLOT, String(slot));
          sessionStorage.setItem("loki_me", JSON.stringify({ slot }));
          sessionStorage.removeItem(PAIRING);
          lokiSignerSession = { endpoint, capability, lokisigner: true };
          return;
        }
        if (res && ![404, 405, 425].includes(res.status)) {
          throw new Error(res.status === 429
            ? "LokiSigner is showing another connection request or waiting before it can show a new one. Refuse any request you did not start, then try again in a few seconds."
            : "LokiSigner did not allow this connection.");
        }
      }
      // Wait for a fresh registration rather than sending a credential to a stale port.
      await new Promise<void>((resolve) => {
        const wake = () => { clearTimeout(timer); discovery.removeEventListener("abort", wake); resolve(); };
        const timer = setTimeout(wake, 1500);
        discovery.addEventListener("abort", wake, { once: true });
      });
    }
  } finally { clearTimeout(deadline); }
}

async function readConnectDecision(res: Response, show: (progress: ConnectProgress) => void, signal: AbortSignal): Promise<string> {
  const refused = () => new Error("LokiSigner did not allow this connection.");
  if (res.headers.get("content-type") !== "application/x-ndjson" || !res.body) {
    void res.body?.cancel().catch(() => {});
    throw refused();
  }
  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  let partial = "", code = "", token = "", received = 0;
  try {
    signal.throwIfAborted();
    while (true) {
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      received += value.length;
      if (received > 1024) throw refused();
      const lines = (partial + value).split("\n");
      partial = lines.pop()!;
      for (const line of lines) {
        const frame = JSON.parse(line);
        if (!code && typeof frame.code === "string" && /^[0-9]{6}$/.test(frame.code)) {
          code = frame.code;
          show({ phase: "compare", code });
        } else if (code && !token && typeof frame.token === "string" && /^[A-Za-z0-9_-]{43}$/.test(frame.token)) {
          token = frame.token;
        } else { throw refused(); }
      }
    }
    if (!token || partial) throw refused();
    return token;
  } catch { signal.throwIfAborted(); throw refused(); }
  finally { signal.removeEventListener("abort", cancel); cancel(); }
}

/** A pairing link LokiSigner opens; the coordinator reserves its slot until `expires`, in this
 *  browser's clock (ms). */
export type PairingLink = { slot: number; url: string; expires: number };
/** The asked-for slot is registered or reserved, possibly by another member: the next link must
 *  let the coordinator pick a new slot. */
export class PairingSlotTaken extends Error {}
// The coordinator builds `loki://pair?` + URLSearchParams; anything else is never a link target.
const PAIRING_LINK = /^loki:\/\/pair\?[A-Za-z0-9%*._+=&-]+$/;
const PAIRING_TTL_MS = 120_000;
const PAIRING_REFUSALS: [string, (slot?: number) => string][] = [
  ["a valid onboarding grant is required", () => "Open the onboarding link from your coordinator operator to pair a new signer."],
  ["onboarding grant already used", () => "This onboarding link has already been used. Ask your coordinator operator for a new one."],
  ["too many pending registrations", () => "The coordinator has too many pairing links waiting. Try again in two minutes."],
  ["registration is busy", () => "The coordinator is busy registering another member. Try again in a moment."],
  ["expected an HTTPS origin", () => "This coordinator issues pairing links only over HTTPS. Open the wallet at its HTTPS address and try again."],
];

/** Ask the coordinator for a native pairing link: the next free slot, or `slot` again after
 *  its link expired. Each request reserves a slot, so callers never reissue on their own. */
export async function requestPairingLink(slot?: number): Promise<PairingLink> {
  const res = await fetch("/api/members/pairing", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slot, onboarding_grant: onboardingGrant() }), cache: "no-store",
  });
  const now = Date.now();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Only our own sentences reach the page, never the coordinator's text.
    const error = typeof data.error === "string" ? data.error : "";
    if (error.startsWith("slot already registered or reserved")) {
      throw new PairingSlotTaken(`${slot === undefined ? "That slot" : `Slot ${slot}`} was taken, possibly by another member. If LokiSigner is running and paired with that slot, connect in step 2. Otherwise get a new link; it will use another slot.`);
    }
    const known = PAIRING_REFUSALS.find(([prefix]) => error.startsWith(prefix));
    throw new Error(known ? known[1](slot) : `The coordinator refused a pairing link (HTTP ${res.status}). Try again, or ask whoever runs it.`);
  }
  if (!Number.isSafeInteger(data.slot) || data.slot < 1 || !Number.isSafeInteger(data.expires)
    || typeof data.url !== "string" || !PAIRING_LINK.test(data.url)) {
    throw new Error("The coordinator returned a pairing link LokiSigner would not accept. Try again, or ask whoever runs it.");
  }
  // LokiSigner shows the origin and slot from the link itself; they must be what this page shows.
  const query = new URLSearchParams(data.url.slice("loki://pair?".length));
  const keys = [...query.keys()].sort();
  if ((slot !== undefined && data.slot !== slot) || keys.join() !== "challenge,origin,slot"
    || query.get("origin") !== window.location.origin || query.get("slot") !== String(data.slot)
    || !/^[0-9a-f]{64}$/.test(query.get("challenge")!)) {
    throw new Error("The coordinator's pairing link does not match this page, so it is not shown. Ask whoever runs the coordinator.");
  }
  // `expires` is on the coordinator's clock: keep only the time left, measured from its Date header.
  const served = Date.parse(res.headers.get("date") ?? "");
  const left = Number.isNaN(served) ? PAIRING_TTL_MS : data.expires - served;
  return { slot: data.slot, url: data.url, expires: now + Math.min(left, PAIRING_TTL_MS) };
}

/** A member request: to this tab's paired native member, else into the in-browser signer. */
export async function api<T = unknown>(path: string, body?: unknown): Promise<T> {
  if (!/^[a-z][a-z0-9-]*(\?[^#]*)?$/.test(path)) throw new Error("invalid signer API path");
  const native = paired();
  try {
    return native ? await nativeApi<T>(native, path, body) : await signer.request<T>(path, body);
  } catch (e) {
    const unauthorized = e instanceof ApiError && e.status === 401;
    if (typeof window !== "undefined" && native?.lokisigner && (unauthorized || e instanceof TypeError || e instanceof SyntaxError)) {
      if (paired()?.capability === native.capability) {
        forgetSession();
        window.dispatchEvent(new Event("loki:auth-lost"));
      }
    } else if (unauthorized && !native?.lokisigner && typeof window !== "undefined") {
      window.dispatchEvent(new Event("loki:auth-lost"));
    }
    throw e;
  }
}

export async function listSlots(signal?: AbortSignal): Promise<Slot[]> {
  const res = await fetch("/api/members", { cache: "no-store", signal });
  if (!res.ok) throw new Error("could not read public roster");
  return (await res.json()).slots as Slot[];
}

/** True once a share is sealed in this browser → Unlock rather than Create. */
export function hasSigner(): Promise<boolean> { return signer.hasSigner(); }
export { hasSignerHint } from "./signer.ts"; // sync first-paint guess; hasSigner() confirms

function rememberMe(s: SignerSession): void {
  try { sessionStorage.setItem("loki_me", JSON.stringify({ slot: s.slot })); sessionStorage.removeItem(LOKISIGNER_SLOT); } catch {}
}
export async function createSigner(opts: CreateSignerOpts): Promise<SignerSession> {
  const s = await signer.createSigner(opts);
  rememberMe(s);
  return s;
}
export async function unlock(opts: UnlockOpts): Promise<SignerSession> {
  const s = await signer.unlock(opts);
  // The browser signer returns no slot. If it registered before this reload, its roster entry
  // is the one carrying its signing key, which is its profile id.
  const slot = s.slot ?? (await listSlots(AbortSignal.timeout(15_000)).catch(() => [])).find((m) => m.signing_pubkey === s.profile.id)?.slot;
  rememberMe({ ...s, slot });
  return s;
}
export function forgetSession(): void {
  lokiSignerSession = null;
  try { sessionStorage.removeItem("loki_me"); sessionStorage.removeItem(PAIRING); } catch {}
}
export async function logout(): Promise<boolean> {
  // A native member locks its own profile; unlock it locally before reconnecting.
  try { if (paired()) await api("lock", {}); else await signer.lock(); return true; }
  catch { return false; }
  finally { forgetSession(); }
}

/** Development faucet accepts a public regtest address and a stable attempt key. */
export async function fund(address: string, idempotency_key: string): Promise<{ mined: boolean }> {
  const res = await fetch("/api/fund", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address, idempotency_key }) });
  if (!res.ok) throw new Error((await res.json()).error ?? "could not request funds");
  return { mined: res.status === 200 };
}
export type RecoveryStatus = { recovery_identity: boolean; recovery_backup: boolean; recovery_in_app?: boolean };
export function recoveryStatus(vault: string): Promise<RecoveryStatus> { return api(`recovery-status?vault=${vault}`); }
export function recoveryBackup(vault: string): Promise<{ vault: string; backup: string; fingerprint?: string }> { return api(`recovery-backup?vault=${vault}`); }

// Browser recovery words and backup downloads stay in the separate signer tab.
function browserOnly(): void {
  if (paired()) throw new ApiError("This tab uses a native member; recover it in the member app", 400);
}
/** Show the 24 words once on the signer page and confirm three of them. */
export async function setupBrowserRecovery(): Promise<{ recovery: boolean }> { browserOnly(); return signer.request("recovery-setup", {}); }
/** Download this vault's recovery backup on the signer page (ciphertext only the words open). */
export async function exportRecoveryBackup(vault: string): Promise<void> { browserOnly(); await signer.request("recovery-export", { vault }); }
/** Restore in the separate signer tab. Only a fresh signer needs new custody. */
export async function restoreSigner(opts: Partial<CreateSignerOpts> & { vault?: string; backup?: string }): Promise<SignerSession> { browserOnly(); return signer.request("restore", opts); }
/** Open signer controls and report whether the member removed custody in the signer tab. */
export async function manageBrowserCustody(): Promise<boolean> {
  browserOnly();
  const removed = await signer.request<boolean>("manage-custody");
  if (removed) forgetSession();
  return removed;
}
export type PendingApproval = { attempt: string; amount_zat: string; recipient: string; proposer: number; replaces?: { attempt: string; cancel: boolean } | null };
export function pendingApprovals(vault: string): Promise<{ pending: PendingApproval[] }> { return api(`pending?vault=${vault}`); }
