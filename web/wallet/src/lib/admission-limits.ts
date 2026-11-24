import { isIP } from "node:net";

/** A refusal the routes answer with HTTP 429 and a `Retry-After` header. Its message is fixed
 *  and safe to show; `retryAfter` is the seconds until the exhausted window admits again. */
export class RateLimited extends Error {
  readonly retryAfter: number;
  constructor(message: string, retryAfter: number) { super(message); this.retryAfter = retryAfter; }
}

export const SIGNUP_LIMIT_MESSAGE = "This coordinator has reached its sign-up limit for this hour. Try again later.";
export const IP_LIMIT_MESSAGE = "Too many pairing requests from this network. Try again later.";
export const ATTEMPT_LIMIT_MESSAGE = "Too many registration attempts. Try again in a minute.";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Bounds each in-memory table. Past it, new keys share one overflow bucket (see `charge`).
const MAX_CLIENTS = 10_000;

/** A non-negative whole number from the coordinator process's environment. A value the operator
 *  set but that isn't one stops admission instead of silently using the default. */
function setting(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!/^\d+$/.test(raw.trim()) || !Number.isSafeInteger(value)) {
    console.error(`loki admission: ${name} is not a whole number; refusing admission`);
    throw new Error("coordinator admission is misconfigured");
  }
  return value;
}

export const signupsPerHour = () => setting("LOKI_SIGNUPS_PER_HOUR", 6);

/** Refusals are logged by reason only: never an address. */
export function logRefusal(reason: "sign-up limit" | "ip minute limit" | "ip day limit" | "pending slots" | "attempt minute limit" | "resume limit") {
  console.warn(`loki admission: refused (${reason})`);
}

/** Seconds until `oldest` leaves a window of `span` ms, at least one. */
const secondsUntil = (oldest: number, span: number, now: number) => Math.max(1, Math.ceil((oldest + span - now) / 1000));

/** Drops sign-up times older than an hour and refuses when the hourly cap is reached. The caller
 *  holds the registry lock and records a new identity with `state.signups.push(now)`. These
 *  times are wall-clock and persisted: one later than `now` (the clock stepped back) still
 *  counts until the clock passes it, so a clock step can't reopen the hour. */
export function checkSignups(signups: number[], now: number): number[] {
  const recent = signups.filter((at) => at > now - HOUR).sort((a, b) => a - b);
  const limit = signupsPerHour();
  if (recent.length >= limit) {
    logRefusal("sign-up limit");
    throw new RateLimited(SIGNUP_LIMIT_MESSAGE, limit > 0 ? secondsUntil(recent[recent.length - limit], HOUR, now) : HOUR / 1000);
  }
  return recent;
}

/** One spelling per address: IPv6 in its compressed lowercase form, and an IPv4-mapped IPv6
 *  address as its IPv4 address. Returns undefined for anything that isn't an IP address. */
export function canonicalAddress(value: string): string | undefined {
  try {
    if (isIP(value) === 4) return new URL(`http://${value}`).hostname;
    if (isIP(value) !== 6 || value.includes("%")) return undefined; // no zone identifiers
    const host = new URL(`http://[${value}]`).hostname.slice(1, -1);
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (!mapped) return host;
    const [high, low] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
    return [high >> 8, high & 255, low >> 8, low & 255].join(".");
  } catch { return undefined; }
}

/** The client address from the one header the operator's proxy sets (`LOKI_CLIENT_IP_HEADER`,
 *  for example `cf-connecting-ip`). Without it, or when it is missing or invalid, every request
 *  shares the bucket "unknown", so the limits still apply. Nothing else the client sends is used. */
export function clientAddress(req: Request): string {
  const header = process.env.LOKI_CLIENT_IP_HEADER?.trim().toLowerCase();
  if (!header) return "unknown";
  return canonicalAddress(req.headers.get(header)?.split(",")[0]?.trim() ?? "") ?? "unknown";
}

type Bucket = { table: Map<string, number[]>; overflow: number[] };
// Shared across the route bundles in the coordinator's Node process, one per kind of limit. A
// table's insertion order is the order of each key's latest admitted request, oldest first.
// Times are monotonic milliseconds (`performance.now()`), so a wall-clock step changes no window.
const shared = globalThis as typeof globalThis & { lokiAdmissionBuckets?: Record<string, Bucket> };

/** Counts one request for `key` in the named bucket, or throws `RateLimited(message)`. A full
 *  table first drops keys idle for a day, oldest first, stopping at the first live one; new keys
 *  then share one overflow bucket with the same limits, so they're still admitted. No request
 *  scans the whole table. */
function charge(name: string, key: string, limits: { perMinute: number; perDay: number }, message: string,
                reasons: [Parameters<typeof logRefusal>[0], Parameters<typeof logRefusal>[0]], now: number) {
  const buckets = shared.lokiAdmissionBuckets ??= {};
  const bucket = buckets[name] ??= { table: new Map(), overflow: [] };
  const { table } = bucket;
  if (!table.has(key)) {
    for (const [oldest, seen] of table) {
      if (table.size < MAX_CLIENTS || seen.some((at) => at > now - DAY)) break;
      table.delete(oldest);
    }
  }
  const overflow = !table.has(key) && table.size >= MAX_CLIENTS;
  const times = (overflow ? bucket.overflow : table.get(key) ?? []).filter((at) => at > now - DAY);
  const save = (value: number[], latest: boolean) => {
    if (overflow) { bucket.overflow = value; return; }
    if (latest) table.delete(key); // move to the end: most recently admitted
    if (value.length || table.has(key)) table.set(key, value);
  };
  if (times.length >= limits.perDay) {
    save(times, false);
    logRefusal(reasons[1]);
    throw new RateLimited(message, secondsUntil(times[times.length - limits.perDay] ?? now, DAY, now));
  }
  const minute = times.filter((at) => at > now - MINUTE);
  if (minute.length >= limits.perMinute) {
    save(times, false);
    logRefusal(reasons[0]);
    throw new RateLimited(message, secondsUntil(minute[minute.length - limits.perMinute] ?? now, MINUTE, now));
  }
  save([...times, now], true);
}

/** Counts one request that could admit a new identity (a pairing link, or enrollment of an
 *  identity the registry doesn't know) from `client`, or refuses it. */
export function admitClient(client: string, now = performance.now()) {
  const limits = { perMinute: setting("LOKI_IP_PAIRING_PER_MINUTE", 5), perDay: setting("LOKI_IP_PAIRING_PER_DAY", 30) };
  charge("pairing", client, limits, IP_LIMIT_MESSAGE, ["ip minute limit", "ip day limit"], now);
}

/** Counts every direct registration-challenge or proof request from `client`, members included,
 *  before any registry access. Generous: an unlock is two requests, and a member's background
 *  retries back off from five seconds, so only a client hammering the routes reaches it. */
export function admitAttempt(client: string, now = performance.now()) {
  const limits = { perMinute: setting("LOKI_IP_REGISTRATION_PER_MINUTE", 60), perDay: Number.MAX_SAFE_INTEGER };
  charge("registration", client, limits, ATTEMPT_LIMIT_MESSAGE, ["attempt minute limit", "attempt minute limit"], now);
}

/** Bounds retries of one pending enrollment that need the registry lock (identical retries are
 *  answered from the snapshot without one): per pending signing key, not per address. */
export function admitResume(signing: string, now = performance.now()) {
  charge("resume", signing, { perMinute: 6, perDay: Number.MAX_SAFE_INTEGER }, ATTEMPT_LIMIT_MESSAGE, ["resume limit", "resume limit"], now);
}

/** The JSON error reply for a member route: 429 with `Retry-After` for a rate limit, 400 otherwise. */
export function refusal(error: unknown): Response {
  const limited = error instanceof RateLimited;
  const headers: Record<string, string> = { "Cache-Control": "no-store" };
  if (limited) headers["Retry-After"] = String(error.retryAfter);
  return Response.json({ error: (error as Error).message }, { status: limited ? 429 : 400, headers });
}
