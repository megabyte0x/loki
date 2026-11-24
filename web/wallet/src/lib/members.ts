import { createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { isLokiSignerUrl } from "./lokisigner-url.ts";
import { admitClient, checkSignups, logRefusal } from "./admission-limits.ts";
import { freeSlot, MAX_SLOT, registrationSlot } from "./member-admission.ts";
import { registrationLock, type RegistrationPool } from "./registration-lock.ts";
import { newRelayChallenge, verifyRelayProof } from "./relay-registration.ts";

export type Member = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };
type Enrollment = Omit<Member, "slot"> & { slot?: number; device_pubkey: string; authorization: string };
type Challenge = { challenge: string; origin: string; enrollment?: Enrollment; pairing_slot?: number; expires: number; generation?: number; relay?: ReturnType<typeof newRelayChallenge> };
type Device = { slot: number; signing_pubkey: string; device_pubkey: string; generation: number; retired: string[] };
// `signups`: when each new identity registered, kept for the last hour (LOKI_SIGNUPS_PER_HOUR).
type Registry = { version: 1; access: Member[]; devices: Device[]; challenges: Challenge[]; signups: number[]; retired: string[]; replacement_key?: string };
const CHALLENGE_TTL = 120_000;
// Slots held by unfinished new-identity reservations (pairing links and direct enrollments
// together), counted as distinct slots. Well under 16, so pending holds never fill the roster.
const MAX_PENDING_SLOTS = MAX_SLOT / 2;
const publicFields = ["slot", "signing_pubkey", "relay_pubkey", "advertise_url", "lokisigner_url"];
const enrollmentFields = [...publicFields, "device_pubkey", "authorization"];

function registryPath(): string {
  return process.env.LOKI_REGISTRY ?? join(process.cwd(), ".access.json");
}

function read(file: string, fallback: unknown): unknown {
  try { return JSON.parse(readFileSync(file, "utf8")); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    throw error;
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected an object");
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, allowed: string[]) {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error("unexpected registration field");
}
function hex(value: unknown, length: number): string {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) throw new Error("invalid public key or proof");
  return value;
}
function slot(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > 0xffffffff) throw new Error("invalid slot");
  return Number(value);
}
function publicOrigin(value: unknown): string {
  if (typeof value !== "string") throw new Error("missing public origin");
  const url = new URL(value);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.origin !== value || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))) {
    throw new Error("expected an HTTPS origin (HTTP is local development only)");
  }
  return value;
}
// A frostd-only member (an in-browser signer) advertises no peer origin: peer-over-frostd
// removed inbound peer HTTP, so "" means "reachable only via the frostd relay". A native
// member still advertises its loopback origin, which must be a valid origin.
function optionalOrigin(value: unknown): string {
  return value === undefined || value === "" ? "" : publicOrigin(value);
}
function lokiSignerField(value: unknown): { lokisigner_url?: string } {
  if (value === undefined) return {};
  if (!isLokiSignerUrl(value)) throw new Error("invalid LokiSigner loopback endpoint");
  return { lokisigner_url: value };
}
function publicMember(raw: unknown): Member {
  const m = object(raw);
  fields(m, publicFields);
  return { slot: slot(m.slot), signing_pubkey: hex(m.signing_pubkey, 32), relay_pubkey: hex(m.relay_pubkey, 32), advertise_url: optionalOrigin(m.advertise_url), ...lokiSignerField(m.lokisigner_url) };
}

function publicRoster(data: Record<string, unknown>): Member[] {
  if (!Array.isArray(data.access)) throw new Error("invalid public roster");
  return data.access.map(publicMember).sort((a, b) => a.slot - b.slot);
}

/** Never include private registry metadata in the public roster. */
export function slots(): Member[] {
  const data = object(read(registryPath(), { access: [] }));
  checkRegistryFields(data);
  return publicRoster(data);
}

function checkRegistryFields(data: Record<string, unknown>) {
  fields(data, data.version === 1 ? ["version", "access", "devices", "challenges", "signups", "retired", "replacement_key"] : ["access"]);
}

function loadRegistry(file: string): Registry {
  const data = object(read(file, { access: [] }));
  checkRegistryFields(data);
  const access = publicRoster(data);
  const legacy = data.version === undefined;
  const bindings = legacy ? read(`${file}.devices`, []) : data.devices;
  // Legacy nonces are not bound to a generation. Let users obtain fresh pairing links.
  const challenges = legacy ? [] : data.challenges;
  if (!Array.isArray(bindings) || !Array.isArray(challenges)) throw new Error("invalid registration store");
  const devices = bindings.map((raw): Device => {
    const d = object(raw);
    fields(d, legacy ? ["slot", "signing_pubkey", "device_pubkey"] : ["slot", "signing_pubkey", "device_pubkey", "generation", "retired"]);
    const generation = legacy ? 1 : d.generation;
    const retired = legacy ? [] : d.retired;
    if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 1 || !Array.isArray(retired)) {
      throw new Error("invalid device binding generation");
    }
    return { slot: slot(d.slot), signing_pubkey: hex(d.signing_pubkey, 32), device_pubkey: hex(d.device_pubkey, 65), generation, retired: retired.map((key) => hex(key, 65)) };
  });
  const retired = data.retired === undefined ? [] : data.retired;
  if (!Array.isArray(retired)) throw new Error("invalid retired identities");
  const signups = data.signups === undefined ? [] : data.signups;
  if (!Array.isArray(signups) || signups.some((at) => typeof at !== "number" || !Number.isSafeInteger(at))) throw new Error("invalid sign-up history");
  return { version: 1, access, devices, challenges, signups, retired: retired.map((key) => hex(key, 32)),
    replacement_key: data.replacement_key === undefined ? undefined : hex(data.replacement_key, 32) };
}
export function memberById(id: number): Member | null {
  return slots().find((m) => m.slot === id) ?? null;
}

function write(file: string, value: unknown) {
  const temp = `${file}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    writeFileSync(temp, JSON.stringify(value), { mode: 0o600, flag: "wx", flush: true });
    renameSync(temp, file);
    const dir = openSync(dirname(file), "r");
    try { fsyncSync(dir); } finally { closeSync(dir); }
  } finally { rmSync(temp, { force: true }); }
}

function liveChallenges(state: Registry, now: number) {
  state.challenges = state.challenges.filter((c) => c.expires > now && (c.enrollment ? !!c.relay : c.pairing_slot !== undefined));
}

/** The registry as last written, read without the lock or a budget token. Only for cheap
 *  refusals and choosing a budget pool before `changeRegistry`, which decides again. */
function peekRegistry(now: number): Registry {
  const state = loadRegistry(registryPath());
  liveChallenges(state, now);
  return state;
}

/** One durable snapshot for nonce consumption, device bindings and roster writes. `pool` pays
 *  for it (see registration-lock.ts). */
async function changeRegistry<T>(pool: RegistrationPool, change: (state: Registry, now: number) => T | Error): Promise<T> {
  const file = registryPath();
  const unlock = await registrationLock(file, pool);
  try {
    const state = loadRegistry(file);
    const before = JSON.stringify(state);
    const now = Date.now();
    liveChallenges(state, now);
    const result = change(state, now);
    // An explicit Error result commits consumption of a rejected proof, then reports it.
    if (JSON.stringify(state) !== before) write(file, state);
    if (result instanceof Error) throw result;
    return result;
  } finally { unlock(); }
}

function identityKey(signing_pubkey: string) {
  return createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(signing_pubkey, "hex")]), format: "der", type: "spki" });
}

// Same Ed25519 authorization of SEC1 P-256 bytes as signer/device_auth.rs::enroll.
function enrollment(raw: unknown): Enrollment {
  const e = object(raw);
  fields(e, enrollmentFields);
  const signing_pubkey = hex(e.signing_pubkey, 32);
  const relay_pubkey = hex(e.relay_pubkey, 32);
  if (relay_pubkey === "00".repeat(32)) throw new Error("invalid relay key");
  const device_pubkey = hex(e.device_pubkey, 65);
  deviceKey(device_pubkey); // Reject invalid points before issuing a challenge.
  const authorization = hex(e.authorization, 64);
  const identity = identityKey(signing_pubkey);
  if (!verify(null, Buffer.from(device_pubkey, "hex"), identity, Buffer.from(authorization, "hex"))) throw new Error("device authorization does not verify");
  return { ...(e.slot === undefined ? {} : { slot: registrationSlot(e.slot) }), signing_pubkey, relay_pubkey, advertise_url: optionalOrigin(e.advertise_url), ...lokiSignerField(e.lokisigner_url), device_pubkey, authorization };
}
function deviceKey(key: string) {
  if (!key.startsWith("04")) throw new Error("expected uncompressed P-256 key");
  return createPublicKey({ key: Buffer.concat([Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"), Buffer.from(key, "hex")]), format: "der", type: "spki" });
}
// Removed keys keep their original identity binding even after a replacement.
function checkDevice(e: Enrollment, bindings: Device[]): Device | undefined {
  for (const d of bindings) {
    if ((d.device_pubkey === e.device_pubkey || d.retired.includes(e.device_pubkey)) && d.signing_pubkey !== e.signing_pubkey) throw new Error("registered device cannot change identity");
    if (d.signing_pubkey === e.signing_pubkey && e.slot !== undefined && d.slot !== e.slot) throw new Error("registered identity cannot change slot");
  }
  return bindings.find((d) => d.signing_pubkey === e.signing_pubkey);
}

function occupied(state: Registry, signing?: string): Set<number> {
  return new Set([
    ...state.access.map((m) => m.slot),
    ...state.devices.filter((d) => d.signing_pubkey !== signing && !state.retired.includes(d.signing_pubkey)).map((d) => d.slot),
    ...state.challenges.flatMap((c) => c.pairing_slot === undefined ? [] : [c.pairing_slot]),
  ]);
}

/** Refuses a new hold once unfinished new-identity reservations hold MAX_PENDING_SLOTS slots. */
function checkPendingSlots(state: Registry) {
  const held = new Set(state.challenges.flatMap((c) => c.pairing_slot === undefined ? [] : [c.pairing_slot]));
  if (held.size >= MAX_PENDING_SLOTS) {
    logRefusal("pending slots");
    throw new Error("too many pending registrations");
  }
}

function existingMember(e: Enrollment, state: Registry): Member | undefined {
  if (state.retired.includes(e.signing_pubkey)) throw new Error("registration identity retired");
  const existing = state.access.find((m) => m.signing_pubkey === e.signing_pubkey);
  if (existing && ((e.slot !== undefined && e.slot !== existing.slot) || existing.relay_pubkey !== e.relay_pubkey)) {
    throw new Error("registered identity cannot change slot or relay key");
  }
  return existing;
}

export async function retireMember(signing: string): Promise<void> {
  hex(signing, 32);
  await changeRegistry("member", (state) => {
    if (state.retired.includes(signing)) return;
    if (!state.access.some((m) => m.signing_pubkey === signing) && !state.devices.some((d) => d.signing_pubkey === signing)) throw new Error("unknown member identity");
    state.retired.push(signing);
    state.access = state.access.filter((m) => m.signing_pubkey !== signing);
    state.challenges = state.challenges.filter((c) => c.enrollment?.signing_pubkey !== signing);
  });
}
export function registrationMessage(e: Enrollment, origin: string, challenge: string): Buffer {
  const local = e.lokisigner_url === undefined ? [] : [e.lokisigner_url];
  return Buffer.from([local.length ? "loki-member-registration-v2" : "loki-member-registration-v1", origin, e.slot ?? 0, e.signing_pubkey, e.relay_pubkey, e.advertise_url, ...local, e.device_pubkey, challenge].join("\n"));
}

function replacementGeneration(e: Enrollment, state: Registry, previous: Device | undefined): number | undefined {
  if (previous?.device_pubkey === e.device_pubkey) return undefined;
  if (!previous && !state.access.some((m) => m.signing_pubkey === e.signing_pubkey)) return undefined;
  const next = (previous?.generation ?? 0) + 1;
  if (!Number.isSafeInteger(next)) throw new Error("registration generation exhausted");
  return next;
}

function replacementMessage(e: Enrollment, origin: string, challenge: string, generation: number): Buffer {
  return Buffer.from(["loki-member-device-replacement-v1", origin, e.signing_pubkey, e.device_pubkey, generation, challenge].join("\n"));
}

// Replacement issuance proves nothing fresh. Carry the enrollment and generation in a MAC,
// not in an exclusive database reservation. A successful proof advances the generation atomically.
function replacementTag(key: string, prefix: Buffer, e: Enrollment, origin: string, generation: number) {
  return createHmac("sha256", Buffer.from(key, "hex")).update("replacement/v1\0").update(prefix)
    .update(JSON.stringify([origin, generation, e])).digest().subarray(0, 16);
}

/** A replacement challenge is not stored: its MAC carries the enrollment, origin and generation. */
function replacementChallengeValid(key: string, challenge: string, e: Enrollment, origin: string, generation: number, now: number) {
  const wire = Buffer.from(challenge, "hex");
  const timestamp = wire.readBigUInt64BE();
  return timestamp <= BigInt(now) && timestamp > BigInt(now - CHALLENGE_TTL)
    && timingSafeEqual(wire.subarray(16), replacementTag(key, wire.subarray(0, 16), e, origin, generation));
}

/** New-identity admission checks that need no lock: the roster isn't full, the shared pending
 *  slots and the hourly sign-up cap have room, and the wanted slot is free. `changeRegistry`
 *  repeats them authoritatively. */
function checkNewcomer(state: Registry, now: number, desired: number | undefined, signing?: string) {
  if (state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
  checkPendingSlots(state);
  checkSignups(state.signups, now);
  freeSlot(occupied(state, signing), desired);
}

function replacementRelay(key: string, challenge: string) {
  const seed = createHmac("sha256", Buffer.from(key, "hex")).update("replacement-relay/v1\0").update(challenge).digest();
  try { return newRelayChallenge(seed); } finally { seed.fill(0); }
}

/** Reserves a slot for one `loki://pair` link. Anyone may ask: the hourly sign-up cap, the shared
 *  pending-slot cap and, when the route passes `client`, its per-address limits bound it. `slot`
 *  asks for that slot again, to re-pair a profile whose registration never finished; it is
 *  refused while any reservation or member holds it. Without it the lowest free slot is reserved.
 *  Every request counts against `client`, and every cheap refusal happens before the registry
 *  lock, so retried refusals can't drain the registration budget. Writes use the newcomer pool. */
export async function issuePairingChallenge(raw: unknown, origin: string, client?: string) {
  const body = object(raw);
  fields(body, ["slot"]);
  publicOrigin(origin);
  const requested = body.slot === undefined ? undefined : registrationSlot(body.slot);
  if (client !== undefined) admitClient(client);
  checkNewcomer(peekRegistry(Date.now()), Date.now(), requested);
  return changeRegistry("newcomer", (state, now) => {
    if (state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
    checkPendingSlots(state);
    state.signups = checkSignups(state.signups, now);
    const id = freeSlot(occupied(state), requested);
    const expires = now + CHALLENGE_TTL;
    const challenge = randomBytes(32).toString("hex");
    state.challenges.push({ challenge, origin, pairing_slot: id, expires });
    const query = new URLSearchParams({ origin, slot: String(id), challenge });
    return { slot: id, challenge, expires, url: `loki://pair?${query}` };
  });
}

/** A one-use registration challenge. Only enrollment of an identity the registry doesn't know,
 *  without a claimed pairing link (whose issuance was already counted), counts toward `client`'s
 *  per-address limits, the hourly sign-up cap and the pending-slot cap. A registered identity
 *  (roster refresh, recovery, device replacement) is exempt, and uses the member budget pool,
 *  only because `enrollment()` first verified `authorization`: that identity's own Ed25519
 *  signature over the device key. Naming an identity is not enough, and registering still
 *  needs the device signature and relay proof. Everything else uses the newcomer pool. Cheap
 *  refusals and the per-address check come before the registry lock. */
export async function issueRegistrationChallenge(raw: unknown, origin: string, client?: string) {
  const { pairing_challenge, ...identity } = object(raw);
  const e = enrollment(identity);
  publicOrigin(origin);
  const nonce = pairing_challenge === undefined ? undefined : hex(pairing_challenge, 32);
  const seen = peekRegistry(Date.now());
  if (seen.retired.includes(e.signing_pubkey)) throw new Error("registration identity retired");
  const registered = seen.access.some((m) => m.signing_pubkey === e.signing_pubkey) || seen.devices.some((d) => d.signing_pubkey === e.signing_pubkey);
  const resuming = seen.challenges.some((c) => c.enrollment?.signing_pubkey === e.signing_pubkey);
  let charged = false;
  if (nonce !== undefined) {
    if (!seen.challenges.some((c) => c.challenge === nonce && !c.enrollment)) throw new Error("unknown, expired or changed pairing challenge");
  } else if (!registered && !resuming) {
    if (client !== undefined) admitClient(client);
    charged = true;
    checkNewcomer(seen, Date.now(), e.slot, e.signing_pubkey);
  }
  const pool: RegistrationPool = nonce === undefined && registered ? "member" : "newcomer";
  return changeRegistry(pool, (state, now) => {
    let claimed: Challenge | undefined;
    if (nonce !== undefined) {
      claimed = state.challenges.find((c) => c.challenge === nonce && !c.enrollment);
      if (!claimed) throw new Error("unknown, expired or changed pairing challenge");
      state.challenges = state.challenges.filter((c) => c !== claimed);
      if (claimed.origin !== origin || claimed.pairing_slot !== e.slot) return new Error("unknown, expired or changed pairing challenge");
    }
    try {
      const existing = existingMember(e, state);
      const previous = checkDevice(e, state.devices);
      const generation = replacementGeneration(e, state, previous);
      const boundGeneration = previous?.generation ?? 0;
      const challenges = state.challenges;
      if (generation !== undefined) {
        if (claimed) return new Error("device replacement does not use a pairing reservation");
        const key = state.replacement_key ??= randomBytes(32).toString("hex");
        const prefix = randomBytes(16);
        prefix.writeBigUInt64BE(BigInt(now));
        const challenge = Buffer.concat([prefix, replacementTag(key, prefix, e, origin, generation)]).toString("hex");
        return { challenge, relay_challenge_pubkey: replacementRelay(key, challenge).publicKey, replacement_generation: generation };
      }
      // Exclude pre-upgrade replacement holds from renewal and capacity accounting.
      state.challenges = challenges.filter((c) => !c.enrollment ||
        replacementGeneration(c.enrollment, state, state.devices.find((d) => d.signing_pubkey === c.enrollment!.signing_pubkey)) === undefined);
      const pending = state.challenges.find((c) => c.enrollment?.signing_pubkey === e.signing_pubkey);
      if (pending) {
        const old = pending.enrollment!;
        const same = JSON.stringify(old) === JSON.stringify(e);
        const moved = old.lokisigner_url !== undefined && e.lokisigner_url !== undefined && old.slot === e.slot
          && old.device_pubkey === e.device_pubkey && old.relay_pubkey === e.relay_pubkey;
        if (claimed || pending.origin !== origin || pending.generation !== boundGeneration || (!same && !moved)) throw new Error("identity already has a pending registration");
        pending.enrollment = e;
        return { challenge: pending.challenge, relay_challenge_pubkey: pending.relay!.publicKey };
      }
      if (state.challenges.filter((c) => c.enrollment).length >= MAX_SLOT * 2) throw new Error("too many pending registrations");
      let reserved: number | undefined;
      const expires = claimed?.expires ?? now + CHALLENGE_TTL;
      if (!existing && state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
      if (existing) {
        registrationSlot(existing.slot);
      } else if (previous) {
        // An orphan from the legacy split write already owns this slot and device binding.
        freeSlot(occupied(state, e.signing_pubkey), previous.slot);
      } else if (claimed) {
        // The claimed link's reservation is gone from `challenges`, so its slot is free again
        // for this identity only: the claim matched `e.slot` above.
        reserved = freeSlot(occupied(state, e.signing_pubkey), claimed.pairing_slot);
      } else {
        // A brand-new identity without a pairing link: it holds a slot until it registers. The
        // member pool never pays for one (identities are never unregistered, only retired).
        if (pool === "member") throw new Error("registration changed; request a new challenge");
        checkPendingSlots(state);
        state.signups = checkSignups(state.signups, now);
        reserved = freeSlot(occupied(state, e.signing_pubkey), e.slot);
        // Rare: a pending registration expired between the first read and the lock.
        if (!charged && client !== undefined) admitClient(client);
      }
      const challenge = randomBytes(32).toString("hex");
      const relay = newRelayChallenge();
      state.challenges.push({ challenge, origin, enrollment: e, generation: boundGeneration, pairing_slot: reserved, relay, expires });
      return { challenge, relay_challenge_pubkey: relay.publicKey };
    } catch (error) {
      if (claimed && error instanceof Error) return error;
      throw error;
    }
  });
}

export async function registerMember(raw: unknown, origin: string): Promise<Member> {
  const body = object(raw);
  fields(body, [...enrollmentFields, "challenge", "signature", "replacement_authorization", "relay_proof"]);
  const { challenge: rawChallenge, signature: rawSignature, replacement_authorization, relay_proof, ...identity } = body;
  const e = enrollment(identity);
  const challenge = hex(rawChallenge, 32);
  const signature = typeof rawSignature === "string" && /^[0-9a-f]{128,144}$/.test(rawSignature) ? Buffer.from(rawSignature, "hex") : null;
  if (!signature) throw new Error("invalid device signature");
  // Only a request holding a live issued challenge (or a valid replacement MAC) spends the
  // member budget; anything else is refused before the lock.
  const now = Date.now();
  const seen = peekRegistry(now);
  if (!seen.challenges.some((c) => c.challenge === challenge && c.enrollment)) {
    let next: number | undefined;
    try { next = replacementGeneration(e, seen, seen.devices.find((d) => d.signing_pubkey === e.signing_pubkey)); } catch { next = undefined; }
    if (next === undefined || !seen.replacement_key || !replacementChallengeValid(seen.replacement_key, challenge, e, origin, next, now)) {
      throw new Error("unknown, expired or changed registration challenge");
    }
  }
  return changeRegistry("member", (state, now) => {
    const issued = state.challenges.find((c) => c.challenge === challenge && c.enrollment);
    if (issued) state.challenges = state.challenges.filter((c) => c !== issued);
    try {
      const existing = existingMember(e, state);
      const previous = checkDevice(e, state.devices);
      const next = replacementGeneration(e, state, previous);
      let relay = issued?.relay;
      if (next !== undefined) {
        const key = state.replacement_key;
        if (issued || !key || !replacementChallengeValid(key, challenge, e, origin, next, now)) {
          throw new Error("unknown, expired or changed registration challenge");
        }
        if (replacement_authorization === undefined) throw new Error("replacement authorization is required");
        const proof = Buffer.from(hex(replacement_authorization, 64), "hex");
        if (!verify(null, replacementMessage(e, origin, challenge, next), identityKey(e.signing_pubkey), proof)) throw new Error("replacement authorization does not verify");
        relay = replacementRelay(key, challenge);
      } else {
        if (!issued || issued.origin !== origin || JSON.stringify(issued.enrollment) !== JSON.stringify(e)) throw new Error("unknown, expired or changed registration challenge");
        if (issued.generation !== (previous?.generation ?? 0)) throw new Error("registration generation changed; request a new challenge");
      }
      const key = deviceKey(e.device_pubkey);
      const bytes = registrationMessage(e, origin, challenge);
      if (!verify("sha256", bytes, key, signature) && !(signature.length === 64 && verify("sha256", bytes, { key, dsaEncoding: "ieee-p1363" }, signature))) throw new Error("device signature does not verify");
      if (!relay || !verifyRelayProof(relay.privateKey, hex(relay_proof, 32), origin, e.signing_pubkey, e.relay_pubkey, challenge)) throw new Error("relay proof does not verify");
      if (state.access.some((m) => m.signing_pubkey !== e.signing_pubkey && m.relay_pubkey === e.relay_pubkey)) throw new Error("relay key already registered");
      if (!existing && state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
      let id: number;
      if (existing) {
        id = registrationSlot(existing.slot);
      } else if (previous) {
        id = freeSlot(occupied(state, e.signing_pubkey), previous.slot);
      } else {
        if (!issued || issued.pairing_slot === undefined) throw new Error("unknown, expired or changed registration challenge");
        // Only a brand-new identity counts toward the hourly cap; re-pairing and refresh don't.
        state.signups = checkSignups(state.signups, now);
        id = freeSlot(occupied(state, e.signing_pubkey), issued.pairing_slot);
        state.signups.push(now);
      }
      const member: Member = { slot: id, signing_pubkey: e.signing_pubkey, relay_pubkey: e.relay_pubkey, advertise_url: e.advertise_url, ...lokiSignerField(e.lokisigner_url) };
      if (!previous || next !== undefined) {
        const retired = previous ? [...previous.retired.filter((k) => k !== e.device_pubkey), previous.device_pubkey] : [];
        state.devices = [...state.devices.filter((d) => d !== previous), { slot: member.slot, signing_pubkey: e.signing_pubkey, device_pubkey: e.device_pubkey, generation: next ?? 1, retired }];
        state.challenges = state.challenges.filter((c) => c.enrollment?.signing_pubkey !== e.signing_pubkey);
      }
      state.access = [...state.access.filter((m) => m.slot !== member.slot), member];
      return member;
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      return error;
    }
  });
}

/** Limit the stream, including chunked requests, before JSON parsing. */
export async function readRegistrationBody(req: Request): Promise<unknown> {
  const reader = req.body?.getReader();
  if (!reader) throw new Error("missing registration body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 4096) { await reader.cancel(); throw new Error("registration too large"); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
