import { createHash } from "node:crypto";

export const MAX_SLOT = 16;

export function registrationSlot(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_SLOT) {
    throw new Error("slot must be in 1..16");
  }
  return value;
}

export function freeSlot(used: ReadonlySet<number>, desired?: number): number {
  if (desired !== undefined) {
    if (used.has(desired)) throw new Error("slot already registered or reserved");
    return registrationSlot(desired);
  }
  for (let slot = 1; slot <= MAX_SLOT; slot++) {
    if (!used.has(slot)) return slot;
  }
  throw new Error("no free slot (1..16)");
}

const DIGEST = /^[0-9a-f]{64}$/;

export function grantDigest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value)) throw new Error("a valid onboarding grant is required");
  return createHash("sha256").update(value).digest("hex");
}

export function grantedSlot(digest: string): number | undefined {
  const data: unknown = JSON.parse(process.env.LOKI_ONBOARDING_GRANTS ?? "{}");
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("invalid onboarding configuration");
  const grants = Object.entries(data);
  if (grants.length > MAX_SLOT || grants.some(([key]) => !DIGEST.test(key))) throw new Error("invalid onboarding configuration");
  for (const [, value] of grants) if (value !== null) registrationSlot(value);
  const found = grants.find(([key]) => key === digest);
  if (!found) throw new Error("a valid onboarding grant is required");
  return found[1] === null ? undefined : found[1];
}
