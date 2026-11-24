import { isIP } from "node:net";

/** A refusal the routes answer with HTTP 429 and a `Retry-After` header. Its message is fixed
 *  and safe to show; `retryAfter` is the seconds until the exhausted window admits again. */
export class RateLimited extends Error {
  readonly retryAfter: number;
  constructor(message: string, retryAfter: number) { super(message); this.retryAfter = retryAfter; }
}

export const SIGNUP_LIMIT_MESSAGE = "This coordinator has reached its sign-up limit for this hour. Try again later.";
export const IP_LIMIT_MESSAGE = "Too many pairing requests from this network. Try again later.";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Bounds the in-memory table. Past it, new addresses share one overflow bucket (see `admitClient`).
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
export function logRefusal(reason: "sign-up limit" | "ip minute limit" | "ip day limit" | "pending slots") {
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

// Shared across the route bundles in the coordinator's Node process. The table's insertion
// order is the order of each address's latest admitted request, oldest first. Its times are
// monotonic milliseconds (`performance.now()`), so a wall-clock step changes no window.
const shared = globalThis as typeof globalThis & { lokiPairingRequests?: Map<string, number[]>; lokiPairingOverflow?: number[] };

/** Counts one request that could admit a new identity (a pairing link, or enrollment of an
 *  identity the registry doesn't know) from `client`, or refuses it. A full table first drops
 *  addresses idle for a day, oldest first, stopping at the first live one; new addresses then
 *  share one overflow bucket with the same limits, so they are still admitted. */
export function admitClient(client: string, now = performance.now()) {
  const perMinute = setting("LOKI_IP_PAIRING_PER_MINUTE", 5);
  const perDay = setting("LOKI_IP_PAIRING_PER_DAY", 30);
  const table = shared.lokiPairingRequests ??= new Map<string, number[]>();
  if (!table.has(client)) {
    for (const [oldest, seen] of table) {
      if (table.size < MAX_CLIENTS || seen.some((at) => at > now - DAY)) break;
      table.delete(oldest);
    }
  }
  const overflow = !table.has(client) && table.size >= MAX_CLIENTS;
  const times = (overflow ? shared.lokiPairingOverflow ?? [] : table.get(client) ?? []).filter((at) => at > now - DAY);
  const save = (value: number[], latest: boolean) => {
    if (overflow) { shared.lokiPairingOverflow = value; return; }
    if (latest) table.delete(client); // move to the end: most recently admitted
    if (value.length || table.has(client)) table.set(client, value);
  };
  if (times.length >= perDay) {
    save(times, false);
    logRefusal("ip day limit");
    throw new RateLimited(IP_LIMIT_MESSAGE, secondsUntil(times[times.length - perDay] ?? now, DAY, now));
  }
  const minute = times.filter((at) => at > now - MINUTE);
  if (minute.length >= perMinute) {
    save(times, false);
    logRefusal("ip minute limit");
    throw new RateLimited(IP_LIMIT_MESSAGE, secondsUntil(minute[minute.length - perMinute] ?? now, MINUTE, now));
  }
  save([...times, now], true);
}

/** The JSON error reply for a member route: 429 with `Retry-After` for a rate limit, 400 otherwise. */
export function refusal(error: unknown): Response {
  const limited = error instanceof RateLimited;
  const headers: Record<string, string> = { "Cache-Control": "no-store" };
  if (limited) headers["Retry-After"] = String(error.retryAfter);
  return Response.json({ error: (error as Error).message }, { status: limited ? 429 : 400, headers });
}
