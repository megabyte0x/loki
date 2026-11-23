// Frostd's receive is destructive and offers no cursor. The worker serializes reads and
// marks each destructive drain before receiving. Retry a failed commit before the next
// receive; after a crash the durable marker prevents use of a possibly stale start.
export function controlInbox(store = memoryStore()) {
  let dirty;
  async function flush() {
    if (!dirty) return;
    await store.put(...dirty);
    dirty = undefined;
  }
  async function read(key, drain, reduce = (old, fresh) => fresh.length ? [...old, ...fresh] : old) {
    await flush();
    const old = await store.get(key);
    let marked = false;
    const fresh = await drain(old, async () => {
      await store.put(key, { ...old, draining: true });
      marked = true;
    });
    const next = await reduce(old, fresh);
    if (next !== old || marked && !old.draining) {
      dirty = [key, next];
      await flush();
    }
    return next;
  }
  read.prune = async (scope, live) => {
    await flush();
    await store.prune(scope, live);
  };
  read.clear = async () => {
    await store.clear();
    dirty = undefined;
  };
  return read;
}

function memoryStore() {
  const m = new Map();
  return { get: async (k) => m.get(k) ?? [], put: async (k, v) => { m.set(k, v); } };
}

export const MAX_CONTROL_SESSIONS = 256;

// Keep legacy ciphertext readable until it can be authenticated and compacted. New records
// are scoped to the relay and device, and still contain only sealed payment terms.
export function idbStore(name = "loki_control") {
  const db = new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 2);
    req.onupgradeneeded = (e) => {
      if (e.oldVersion === 0) req.result.createObjectStore("sessions");
      req.result.createObjectStore("notices");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const run = async (mode, fn) => {
    const tx = (await db).transaction(["notices", "sessions"], mode, { durability: "strict" });
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error ?? new Error("could not save the payment inbox"));
      fn(tx.objectStore("notices"), tx.objectStore("sessions"), tx);
    });
  };
  return {
    async get(key) {
      let result;
      await run("readonly", (notices, legacy) => {
        const req = notices.get(key);
        req.onsuccess = () => {
          if (req.result) { result = req.result; return; }
          const count = notices.count();
          count.onsuccess = () => {
            if (count.result >= MAX_CONTROL_SESSIONS) return;
            const prior = legacy.get(key[1]);
            prior.onsuccess = () => { result = { wires: prior.result ?? [] }; };
          };
        };
      });
      if (!result) throw new Error("the payment inbox is full; close old relay sessions first");
      return result;
    },
    put: (key, { migrated, ...value }) => run("readwrite", (notices, legacy, tx) => {
      const count = notices.count();
      count.onsuccess = () => {
        const update = () => {
          notices.put(value, key);
          if (migrated) legacy.delete(key[1]);
        };
        if (count.result < MAX_CONTROL_SESSIONS) { update(); return; }
        const existing = notices.getKey(key);
        existing.onsuccess = () => existing.result ? update() : tx.abort();
      };
    }),
    prune: (scope, live) => run("readwrite", (notices) => {
      const keys = notices.getAllKeys();
      keys.onsuccess = () => {
        for (const key of keys.result) {
          if (key[0] !== scope || !live.has(key[1])) notices.delete(key);
        }
      };
    }),
    clear: () => run("readwrite", (notices, legacy) => {
      notices.clear();
      legacy.clear();
    }),
  };
}

// Whether a proposer notice ends a request for this member (slot): cancelled, failed, already
// signed or sent, or a signing group that leaves this member out. Kept notices outlive the
// request, so the inbox must drop it on these, not only when the notices stop coming.
export function endsRequest(msg, slot) {
  if (["cancelled", "failed", "signed", "broadcast", "confirmed"].includes(msg.kind)) return true;
  return msg.kind === "start" && !!msg.intent?.signers?.length && !msg.intent.signers.includes(slot);
}
