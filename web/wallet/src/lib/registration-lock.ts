import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";

// Share the budget across the route bundles in the coordinator's Node process.
const shared = globalThis as typeof globalThis & {
  lokiRegistrationBudget?: { tokens: number; updated: number; inFlight: number };
};

export async function registrationLock(file: string): Promise<() => void> {
  const now = performance.now();
  const budget = shared.lokiRegistrationBudget ??= { tokens: 128, updated: now, inFlight: 0 };
  budget.tokens = Math.min(128, budget.tokens + (now - budget.updated) * 0.016);
  budget.updated = now;
  if (budget.tokens < 1 || budget.inFlight >= 8) throw new Error("registration is busy");
  budget.tokens--;
  budget.inFlight++;
  let lock: DatabaseSync | undefined;
  const unlock = () => {
    try { lock?.close(); } finally { budget.inFlight--; }
  };
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    // Only the SQLite write lock is used here. The JSON snapshot remains authoritative.
    lock = new DatabaseSync(`${file}.mutex.sqlite`, { timeout: 0 });
    const deadline = performance.now() + 5000;
    for (;;) {
      try {
        lock.exec("BEGIN IMMEDIATE");
        return unlock; // Ends the transaction; never unlink the lock database.
      } catch (error) {
        if ((Number((error as { errcode?: number }).errcode) & 0xff) !== 5) throw error; // SQLITE_BUSY
        if (performance.now() >= deadline) throw new Error("registration is busy");
        await delay(25);
      }
    }
  } catch (error) {
    unlock();
    throw error;
  }
}
