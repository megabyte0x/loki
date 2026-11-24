import { isIP } from "node:net";

/** A refusal the routes answer with HTTP 429. Its message is fixed and safe to show. */
export class RateLimited extends Error {}

export const SIGNUP_LIMIT_MESSAGE = "This coordinator has reached its sign-up limit for this hour. Try again later.";
export const IP_LIMIT_MESSAGE = "Too many pairing requests from this network. Try again later.";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
// Bounds the in-memory table. Past it, a new address is refused until old entries age out.
const MAX_CLIENTS = 10_000;

/** A non-negative whole number from the environment, read on every request. A value the
 *  operator set but that isn't one stops admission instead of silently using the default. */
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
export function logRefusal(reason: "sign-up limit" | "ip minute limit" | "ip day limit" | "client table full") {
  console.warn(`loki admission: refused (${reason})`);
}

/** Drops sign-up times older than an hour and refuses when the hourly cap is reached. The caller
 *  holds the registry lock and records a new identity with `state.signups.push(now)`. */
export function checkSignups(signups: number[], now: number): number[] {
  const recent = signups.filter((at) => at > now - HOUR && at <= now);
  if (recent.length >= signupsPerHour()) {
    logRefusal("sign-up limit");
    throw new RateLimited(SIGNUP_LIMIT_MESSAGE);
  }
  return recent;
}

/** The client address from the one header the operator's proxy sets (`LOKI_CLIENT_IP_HEADER`,
 *  for example `cf-connecting-ip`). Without it, or when it is missing or invalid, every request
 *  shares the bucket "unknown", so the limits still apply. Nothing else the client sends is used. */
export function clientAddress(req: Request): string {
  const header = process.env.LOKI_CLIENT_IP_HEADER?.trim().toLowerCase();
  if (!header) return "unknown";
  const value = req.headers.get(header)?.split(",")[0]?.trim() ?? "";
  return isIP(value) ? value.toLowerCase() : "unknown";
}

// Share the table across the route bundles in the coordinator's Node process.
const shared = globalThis as typeof globalThis & { lokiPairingRequests?: Map<string, number[]> };

/** Counts one pairing or registration-challenge request from this client, or refuses it. */
export function admitClient(req: Request, now = Date.now()) {
  const perMinute = setting("LOKI_IP_PAIRING_PER_MINUTE", 5);
  const perDay = setting("LOKI_IP_PAIRING_PER_DAY", 30);
  const table = shared.lokiPairingRequests ??= new Map<string, number[]>();
  const key = clientAddress(req);
  let times = (table.get(key) ?? []).filter((at) => at > now - DAY && at <= now);
  if (!table.has(key) && table.size >= MAX_CLIENTS) {
    for (const [other, seen] of table) {
      if (!seen.some((at) => at > now - DAY)) table.delete(other);
    }
    if (table.size >= MAX_CLIENTS) {
      logRefusal("client table full");
      throw new RateLimited(IP_LIMIT_MESSAGE);
    }
  }
  if (times.length >= perDay) {
    table.set(key, times);
    logRefusal("ip day limit");
    throw new RateLimited(IP_LIMIT_MESSAGE);
  }
  if (times.filter((at) => at > now - MINUTE).length >= perMinute) {
    table.set(key, times);
    logRefusal("ip minute limit");
    throw new RateLimited(IP_LIMIT_MESSAGE);
  }
  times = [...times, now];
  table.set(key, times);
}

/** The JSON error reply for a member route: 429 for a rate limit, 400 otherwise. */
export function refusal(error: unknown): Response {
  const status = error instanceof RateLimited ? 429 : 400;
  return Response.json({ error: (error as Error).message }, { status, headers: { "Cache-Control": "no-store" } });
}
