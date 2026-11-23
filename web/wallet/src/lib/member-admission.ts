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

/** Grant digests and their pinned slot (`null` = lowest free slot), as stored in the registry. */
export type RegisteredGrants = Record<string, number | null>;

/** The grants the operator added with `scripts/grants.ts`. They live in the registry, so a new
 *  grant needs no restart. */
function onboardingGrants(registered: RegisteredGrants): [string, number | null][] {
  return Object.entries(registered);
}

export function grantedSlot(digest: string, registered: RegisteredGrants): number | undefined {
  const found = onboardingGrants(registered).find(([key]) => key === digest);
  if (!found) throw new Error("a valid onboarding grant is required");
  return found[1] ?? undefined;
}

export function otherPinnedSlots(digest: string, registered: RegisteredGrants): number[] {
  return onboardingGrants(registered).flatMap(([key, slot]) => key !== digest && slot !== null ? [slot] : []);
}
