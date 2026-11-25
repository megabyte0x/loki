import { isIP } from "node:net";

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
const MAX_CLIENTS = 10_000;

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
// Unset (the default) means no cap on the member directory.
export const maxMembers = (): number | undefined =>
  process.env.LOKI_MAX_MEMBERS === undefined || process.env.LOKI_MAX_MEMBERS.trim() === "" ? undefined : setting("LOKI_MAX_MEMBERS", 0);

export function logRefusal(reason: "sign-up limit" | "ip minute limit" | "ip day limit" | "pending slots" | "member cap" | "attempt minute limit" | "resume limit") {
  console.warn(`loki admission: refused (${reason})`);
}

const secondsUntil = (oldest: number, span: number, now: number) => Math.max(1, Math.ceil((oldest + span - now) / 1000));

export function checkSignups(signups: number[], now: number): number[] {
  const recent = signups.filter((at) => at > now - HOUR).sort((a, b) => a - b);
  const limit = signupsPerHour();
  if (recent.length >= limit) {
    logRefusal("sign-up limit");
    throw new RateLimited(SIGNUP_LIMIT_MESSAGE, limit > 0 ? secondsUntil(recent[recent.length - limit], HOUR, now) : HOUR / 1000);
  }
  return recent;
}

export function canonicalAddress(value: string): string | undefined {
  try {
    if (isIP(value) === 4) return new URL(`http://${value}`).hostname;
    if (isIP(value) !== 6 || value.includes("%")) return undefined;
    const host = new URL(`http://[${value}]`).hostname.slice(1, -1);
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (mapped) {
      const [high, low] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
      return [high >> 8, high & 255, low >> 8, low & 255].join(".");
    }
    // One client usually holds a whole /64, so count the network, not each address in it.
    const [head, tail] = host.split("::").map((part) => (part ? part.split(":") : []));
    const groups = tail ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail] : head;
    return `${groups.slice(0, 4).join(":")}::/64`;
  } catch { return undefined; }
}

export function clientAddress(req: Request): string {
  const header = process.env.LOKI_CLIENT_IP_HEADER?.trim().toLowerCase();
  if (!header) return "unknown";
  return canonicalAddress(req.headers.get(header)?.split(",")[0]?.trim() ?? "") ?? "unknown";
}

type Bucket = { table: Map<string, number[]>; overflow: number[] };
const shared = globalThis as typeof globalThis & { lokiAdmissionBuckets?: Record<string, Bucket> };

function charge(name: string, key: string, limits: { perMinute: number; perDay?: number }, message: string,
                reasons: [Parameters<typeof logRefusal>[0], Parameters<typeof logRefusal>[0]], now: number) {
  const buckets = shared.lokiAdmissionBuckets ??= {};
  const bucket = buckets[name] ??= { table: new Map(), overflow: [] };
  const { table } = bucket;
  const span = limits.perDay === undefined ? MINUTE : DAY;
  if (!table.has(key)) {
    for (const [oldest, seen] of table) {
      if (table.size < MAX_CLIENTS || seen.some((at) => at > now - span)) break;
      table.delete(oldest);
    }
  }
  const overflow = !table.has(key) && table.size >= MAX_CLIENTS;
  const times = (overflow ? bucket.overflow : table.get(key) ?? []).filter((at) => at > now - span);
  const save = (value: number[], latest: boolean) => {
    if (overflow) { bucket.overflow = value; return; }
    if (latest) table.delete(key);
    if (value.length || table.has(key)) table.set(key, value);
  };
  if (limits.perDay !== undefined && times.length >= limits.perDay) {
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

export function admitClient(client: string, now = performance.now()) {
  const limits = { perMinute: setting("LOKI_IP_PAIRING_PER_MINUTE", 5), perDay: setting("LOKI_IP_PAIRING_PER_DAY", 30) };
  charge("pairing", client, limits, IP_LIMIT_MESSAGE, ["ip minute limit", "ip day limit"], now);
}

export function admitAttempt(client: string, now = performance.now()) {
  const limits = { perMinute: setting("LOKI_IP_REGISTRATION_PER_MINUTE", 60) };
  charge("registration", client, limits, ATTEMPT_LIMIT_MESSAGE, ["attempt minute limit", "attempt minute limit"], now);
}

export function admitResume(signing: string, now = performance.now()) {
  charge("resume", signing, { perMinute: 6 }, ATTEMPT_LIMIT_MESSAGE, ["resume limit", "resume limit"], now);
}

export function refusal(error: unknown): Response {
  const limited = error instanceof RateLimited;
  const headers: Record<string, string> = { "Cache-Control": "no-store" };
  if (limited) headers["Retry-After"] = String(error.retryAfter);
  return Response.json({ error: (error as Error).message }, { status: limited ? 429 : 400, headers });
}
