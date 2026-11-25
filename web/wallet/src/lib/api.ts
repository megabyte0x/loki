"use client";

import { signer, ApiError, type CreateSignerOpts, type EnrolledMember, type SignerSession, type UnlockOpts } from "./signer.ts";
import { isLokiSignerUrl } from "./lokisigner-url.ts";
export { ApiError };
export type { CustodyMethod, CreateSignerOpts, EnrolledMember, UnlockOpts } from "./signer";
export type Slot = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };

export function enroll(coordinatorOrigin?: string): Promise<EnrolledMember> { return signer.enroll(coordinatorOrigin); }

type Pairing = { endpoint: string; capability: string; lokisigner?: true };
const PAIRING = "loki_device_session";
const LOKISIGNER_SLOT = "loki_lokisigner_slot";
let lokiSignerSession: Pairing | null = null;
function paired(): Pairing | null {
  if (typeof window === "undefined") return null;
  if (lokiSignerSession) return lokiSignerSession;
  try {
    const raw = sessionStorage.getItem(PAIRING);
    const stored = raw ? JSON.parse(raw) as Pairing : null;
    if (!stored?.lokisigner) return stored;
    sessionStorage.removeItem(PAIRING);
  } catch {}
  return null;
}
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
    const listed = await findMember({ slot: member.slot }, signal);
    if (!listed || listed.signing_pubkey !== member.signing_pubkey || listed.relay_pubkey !== member.relay_pubkey || listed.advertise_url !== member.advertise_url) {
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

export async function connectLokiSigner(slot: number, show: (progress: ConnectProgress) => void, signal: AbortSignal): Promise<void> {
  show({ phase: "starting" });
  const starting = new AbortController();
  const discovery = AbortSignal.any([signal, starting.signal]);
  const deadline = setTimeout(() => starting.abort(new LokiSignerStartupTimeout()), 60_000);
  try {
    while (true) {
      discovery.throwIfAborted();
      const member = await findMember({ slot }, discovery);
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

export type PairingLink = { slot: number; url: string; expires: number };
export class PairingSlotTaken extends Error {}
const PAIRING_LINK = /^loki:\/\/pair\?[A-Za-z0-9%*._+=&-]+$/;
const PAIRING_TTL_MS = 120_000;
function retryIn(header: string | null): string {
  const seconds = /^\d{1,6}$/.test(header ?? "") ? Number(header) : NaN;
  if (!(seconds > 0)) return "later";
  if (seconds < 90) return "in about a minute";
  if (seconds < 90 * 60) return `in about ${Math.round(seconds / 60)} minutes`;
  return `in about ${Math.round(seconds / 3600)} hours`;
}
const PAIRING_REFUSALS: [string, (wait: string) => string][] = [
  ["This coordinator has reached its sign-up limit", (wait) => `This coordinator has reached its sign-up limit for this hour. Try again ${wait}.`],
  ["Too many pairing requests", (wait) => `Too many pairing requests from this network. Try again ${wait}.`],
  ["no free slot", () => "This coordinator has no free slot numbers left."],
  ["too many pending registrations", () => "The coordinator has too many pairing links waiting. Try again in two minutes."],
  ["registration is busy", () => "The coordinator is busy registering another member. Try again in a moment."],
  ["expected an HTTPS origin", () => "This coordinator issues pairing links only over HTTPS. Open the wallet at its HTTPS address and try again."],
];

export async function requestPairingLink(slot?: number): Promise<PairingLink> {
  const res = await fetch("/api/members/pairing", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slot }), cache: "no-store",
  });
  const now = Date.now();
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = typeof data.error === "string" ? data.error : "";
    if (error.startsWith("slot already registered or reserved")) {
      throw new PairingSlotTaken(`${slot === undefined ? "That slot" : `Slot ${slot}`} was taken, possibly by another member. If LokiSigner is running and paired with that slot, connect in step 2. Otherwise get a new link; it will use another slot.`);
    }
    const known = PAIRING_REFUSALS.find(([prefix]) => error.startsWith(prefix));
    throw new Error(known ? known[1](retryIn(res.status === 429 ? res.headers.get("retry-after") : null)) : `The coordinator refused a pairing link (HTTP ${res.status}). Try again, or ask whoever runs it.`);
  }
  if (!Number.isSafeInteger(data.slot) || data.slot < 1 || !Number.isSafeInteger(data.expires)
    || typeof data.url !== "string" || !PAIRING_LINK.test(data.url)) {
    throw new Error("The coordinator returned a pairing link LokiSigner would not accept. Try again, or ask whoever runs it.");
  }
  const query = new URLSearchParams(data.url.slice("loki://pair?".length));
  const keys = [...query.keys()].sort();
  if ((slot !== undefined && data.slot !== slot) || keys.join() !== "challenge,origin,slot"
    || query.get("origin") !== window.location.origin || query.get("slot") !== String(data.slot)
    || !/^[0-9a-f]{64}$/.test(query.get("challenge")!)) {
    throw new Error("The coordinator's pairing link does not match this page, so it is not shown. Ask whoever runs the coordinator.");
  }
  const served = Date.parse(res.headers.get("date") ?? "");
  const left = Number.isNaN(served) ? PAIRING_TTL_MS : data.expires - served;
  return { slot: data.slot, url: data.url, expires: now + Math.min(left, PAIRING_TTL_MS) };
}

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

// The first page of the coordinator's public directory. The directory has no member cap, so
// code that needs one member looks it up with `findMember` instead of scanning a listing.
export async function listSlots(signal?: AbortSignal): Promise<Slot[]> {
  const res = await fetch("/api/members", { cache: "no-store", signal });
  if (!res.ok) throw new Error("could not read public roster");
  return (await res.json()).slots as Slot[];
}

export async function findMember(query: { slot: number } | { signing_pubkey: string }, signal?: AbortSignal): Promise<Slot | undefined> {
  const params = new URLSearchParams("slot" in query ? { slot: String(query.slot) } : { signing_pubkey: query.signing_pubkey });
  const res = await fetch(`/api/members?${params}`, { cache: "no-store", signal });
  if (!res.ok) throw new Error("could not read public roster");
  const rows = (await res.json()).slots as Slot[];
  return rows.find((m) => "slot" in query ? m.slot === query.slot : m.signing_pubkey === query.signing_pubkey);
}

export function hasSigner(): Promise<boolean> { return signer.hasSigner(); }
export { hasSignerHint } from "./signer.ts";

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
  const slot = s.slot ?? (await findMember({ signing_pubkey: s.profile.id }, AbortSignal.timeout(15_000)).catch(() => undefined))?.slot;
  rememberMe({ ...s, slot });
  return s;
}
export function forgetSession(): void {
  lokiSignerSession = null;
  try { sessionStorage.removeItem("loki_me"); sessionStorage.removeItem(PAIRING); } catch {}
}
export async function logout(): Promise<boolean> {
  try { if (paired()) await api("lock", {}); else await signer.lock(); return true; }
  catch { return false; }
  finally { forgetSession(); }
}

export async function fund(address: string, idempotency_key: string): Promise<{ mined: boolean }> {
  const res = await fetch("/api/fund", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ address, idempotency_key }) });
  if (!res.ok) throw new Error((await res.json()).error ?? "could not request funds");
  return { mined: res.status === 200 };
}
export type RecoveryStatus = { recovery_identity: boolean; recovery_backup: boolean; recovery_in_app?: boolean };
export function recoveryStatus(vault: string): Promise<RecoveryStatus> { return api(`recovery-status?vault=${vault}`); }
export function recoveryBackup(vault: string): Promise<{ vault: string; backup: string; fingerprint?: string }> { return api(`recovery-backup?vault=${vault}`); }

function browserOnly(): void {
  if (paired()) throw new ApiError("This tab uses a native member; recover it in the member app", 400);
}
export async function setupBrowserRecovery(): Promise<{ recovery: boolean }> { browserOnly(); return signer.request("recovery-setup", {}); }
export async function exportRecoveryBackup(vault: string): Promise<void> { browserOnly(); await signer.request("recovery-export", { vault }); }
export async function restoreSigner(opts: Partial<CreateSignerOpts> & { vault?: string; backup?: string }): Promise<SignerSession> { browserOnly(); return signer.request("restore", opts); }
export async function manageBrowserCustody(): Promise<boolean> {
  browserOnly();
  const removed = await signer.request<boolean>("manage-custody");
  if (removed) forgetSession();
  return removed;
}
export type PendingApproval = { attempt: string; amount_zat: string; recipient: string; proposer: number; replaces?: { attempt: string; cancel: boolean } | null };
export function pendingApprovals(vault: string): Promise<{ pending: PendingApproval[] }> { return api(`pending?vault=${vault}`); }
