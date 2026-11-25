// A coordinator slot is the member's number in this coordinator's directory, nothing more.
// Each vault numbers its own members 1..N at setup (the creator is 1, invites carry 2..N),
// so the directory is not bounded by the 16 members a vault can hold. Slots stay positive
// u32 values because LokiSigner parses them as `u32`.
export const MAX_SLOT = 0xffffffff;

export function registrationSlot(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > MAX_SLOT) {
    throw new Error("slot must be a positive member number");
  }
  return value;
}

export function freeSlot(used: ReadonlySet<number>, desired?: number): number {
  if (desired !== undefined) {
    if (used.has(desired)) throw new Error("slot already registered or reserved");
    return registrationSlot(desired);
  }
  // The lowest free number; one of 1..used.size+1 is always free.
  for (let slot = 1; slot <= Math.min(used.size + 1, MAX_SLOT); slot++) {
    if (!used.has(slot)) return slot;
  }
  throw new Error("no free slot");
}
