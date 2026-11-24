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
