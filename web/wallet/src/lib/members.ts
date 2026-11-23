import { createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto";
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { isLokiSignerUrl } from "./lokisigner-url.ts";
import { freeSlot, grantDigest, grantedSlot, MAX_SLOT, otherPinnedSlots, registrationSlot, type RegisteredGrants } from "./member-admission.ts";
import { registrationLock } from "./registration-lock.ts";
import { newRelayChallenge, verifyRelayProof } from "./relay-registration.ts";

export type Member = { slot: number; signing_pubkey: string; relay_pubkey: string; advertise_url: string; lokisigner_url?: string };
type Enrollment = Omit<Member, "slot"> & { slot?: number; device_pubkey: string; authorization: string };
type Challenge = { challenge: string; origin: string; enrollment?: Enrollment; pairing_slot?: number; expires: number; generation?: number; grant?: string; paired?: boolean; relay?: ReturnType<typeof newRelayChallenge> };
type Device = { slot: number; signing_pubkey: string; device_pubkey: string; generation: number; retired: string[] };
type GrantUse = { slot: number; retry_after: number; used: boolean };
// `onboarding`: grant digests the operator added with scripts/grants.ts. `grants`: their use.
type Registry = { version: 1; access: Member[]; devices: Device[]; challenges: Challenge[]; grants: Record<string, GrantUse>; onboarding: RegisteredGrants; retired: string[]; replacement_key?: string };
const CHALLENGE_TTL = 120_000;
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
  fields(data, data.version === 1 ? ["version", "access", "devices", "challenges", "grants", "onboarding", "retired", "replacement_key"] : ["access"]);
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
  const grants = Object.fromEntries(Object.entries(object(data.grants === undefined ? {} : data.grants)).map(([key, raw]) => {
    const use = object(raw);
    fields(use, ["slot", "retry_after", "used"]);
    if (typeof use.retry_after !== "number" || !Number.isSafeInteger(use.retry_after) || typeof use.used !== "boolean") throw new Error("invalid onboarding history");
    return [hex(key, 32), { slot: registrationSlot(use.slot), retry_after: use.retry_after, used: use.used }];
  }));
  const onboarding = Object.fromEntries(Object.entries(object(data.onboarding === undefined ? {} : data.onboarding)).map(([key, slot]) =>
    [hex(key, 32), slot === null ? null : registrationSlot(slot)]));
  return { version: 1, access, devices, challenges, grants, onboarding, retired: retired.map((key) => hex(key, 32)),
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

/** One durable snapshot for nonce consumption, device bindings and roster writes. */
async function changeRegistry<T>(change: (state: Registry, now: number) => T | Error): Promise<T> {
  const file = registryPath();
  const unlock = await registrationLock(file);
  try {
    const state = loadRegistry(file);
    const before = JSON.stringify(state);
    const now = Date.now();
    state.challenges = state.challenges.filter((c) => c.expires > now && (c.enrollment ? !!c.relay : !!c.grant));
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

function occupied(state: Registry, signing?: string, automaticGrant?: string): Set<number> {
  return new Set([
    ...state.access.map((m) => m.slot),
    ...state.devices.filter((d) => d.signing_pubkey !== signing && !state.retired.includes(d.signing_pubkey)).map((d) => d.slot),
    ...state.challenges.flatMap((c) => c.pairing_slot === undefined ? [] : [c.pairing_slot]),
    ...(automaticGrant === undefined ? [] : otherPinnedSlots(automaticGrant, state.onboarding)),
  ]);
}

function existingMember(e: Enrollment, state: Registry): Member | undefined {
  if (state.retired.includes(e.signing_pubkey)) throw new Error("registration identity retired");
  const existing = state.access.find((m) => m.signing_pubkey === e.signing_pubkey);
  if (existing && ((e.slot !== undefined && e.slot !== existing.slot) || existing.relay_pubkey !== e.relay_pubkey)) {
    throw new Error("registered identity cannot change slot or relay key");
  }
  return existing;
}

function availableGrant(state: Registry, digest: string) {
  const pinned = grantedSlot(digest, state.onboarding);
  const prior = state.grants[digest];
  if (prior?.used) throw new Error("onboarding grant already used");
  return { pinned, prior };
}

export async function retireMember(signing: string): Promise<void> {
  hex(signing, 32);
  await changeRegistry((state) => {
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

function replacementRelay(key: string, challenge: string) {
  const seed = createHmac("sha256", Buffer.from(key, "hex")).update("replacement-relay/v1\0").update(challenge).digest();
  try { return newRelayChallenge(seed); } finally { seed.fill(0); }
}

export async function issuePairingChallenge(raw: unknown, origin: string) {
  const body = object(raw);
  fields(body, ["slot", "onboarding_grant"]);
  publicOrigin(origin);
  const grant = grantDigest(body.onboarding_grant);
  grantedSlot(grant, loadRegistry(registryPath()).onboarding);
  const requested = body.slot === undefined ? undefined : registrationSlot(body.slot);
  return changeRegistry((state, now) => {
    const { pinned, prior } = availableGrant(state, grant);
    if (requested !== undefined && requested !== (pinned ?? prior?.slot)) throw new Error("slot not authorized by onboarding grant");
    let reservation = state.challenges.find((c) => c.grant === grant);
    if (reservation) {
      if (reservation.enrollment || reservation.origin !== origin || (pinned !== undefined && reservation.pairing_slot !== pinned)) throw new Error("onboarding grant already has a pending registration");
    } else {
      if (prior && now < prior.retry_after) throw new Error("onboarding grant issuance is rate limited");
      if (state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
      // Pairing alone cannot reserve the entire supported slot range.
      if (state.challenges.filter((c) => !c.enrollment).length >= MAX_SLOT / 2) throw new Error("too many pending registrations");
      const id = freeSlot(occupied(state, undefined, pinned === undefined ? grant : undefined), pinned ?? requested);
      const expires = now + CHALLENGE_TTL;
      reservation = { challenge: randomBytes(32).toString("hex"), origin, pairing_slot: id, grant, expires };
      state.challenges.push(reservation);
      state.grants[grant] = { slot: id, retry_after: expires, used: false };
    }
    const { pairing_slot: id, challenge, expires } = reservation;
    if (id === undefined) throw new Error("invalid pairing reservation");
    const query = new URLSearchParams({ origin, slot: String(id), challenge });
    return { slot: id, challenge, expires, url: `loki://pair?${query}` };
  });
}

export async function issueRegistrationChallenge(raw: unknown, origin: string) {
  const { pairing_challenge, onboarding_grant, ...identity } = object(raw);
  const suppliedGrant = onboarding_grant === undefined ? undefined : grantDigest(onboarding_grant);
  if (suppliedGrant !== undefined) grantedSlot(suppliedGrant, loadRegistry(registryPath()).onboarding);
  const e = enrollment(identity);
  publicOrigin(origin);
  const nonce = pairing_challenge === undefined ? undefined : hex(pairing_challenge, 32);
  return changeRegistry((state, now) => {
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
        if (pending.grant) {
          availableGrant(state, pending.grant);
          // A native/headless retry can resume its claimed link; direct signup still needs its grant.
          if (!pending.paired && suppliedGrant !== pending.grant) throw new Error("a valid onboarding grant is required");
        }
        pending.enrollment = e;
        return { challenge: pending.challenge, relay_challenge_pubkey: pending.relay!.publicKey };
      }
      if (state.challenges.filter((c) => c.enrollment).length >= MAX_SLOT * 2) throw new Error("too many pending registrations");
      let grant: string | undefined;
      let reserved: number | undefined;
      const expires = claimed?.expires ?? now + CHALLENGE_TTL;
      if (!existing && state.access.length >= MAX_SLOT) throw new Error("no free slot (1..16)");
      if (existing) {
        registrationSlot(existing.slot);
      } else if (previous) {
        // An orphan from the legacy split write already owns this slot and device binding.
        freeSlot(occupied(state, e.signing_pubkey), previous.slot);
      } else {
        grant = claimed?.grant ?? suppliedGrant;
        if (grant === undefined) throw new Error("a valid onboarding grant is required");
        const { pinned, prior } = availableGrant(state, grant);
        if (!claimed && prior && now < prior.retry_after) throw new Error("onboarding grant issuance is rate limited");
        if (state.challenges.some((c) => c.grant === grant)) throw new Error("onboarding grant already has a pending registration");
        const permitted = pinned ?? claimed?.pairing_slot ?? prior?.slot;
        const desired = e.slot;
        if (desired !== undefined && desired !== permitted) throw new Error("slot not authorized by onboarding grant");
        // A still-live pairing link already holds its slot, even if operator pins changed.
        reserved = freeSlot(occupied(state, e.signing_pubkey, pinned === undefined && !claimed ? grant : undefined), pinned ?? claimed?.pairing_slot ?? desired);
        state.grants[grant] = { slot: reserved, retry_after: expires, used: false };
      }
      const challenge = randomBytes(32).toString("hex");
      const relay = newRelayChallenge();
      state.challenges.push({ challenge, origin, enrollment: e, generation: boundGeneration, pairing_slot: reserved, grant, paired: claimed !== undefined || undefined, relay, expires });
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
  return changeRegistry((state, now) => {
    const issued = state.challenges.find((c) => c.challenge === challenge && c.enrollment);
    if (issued) state.challenges = state.challenges.filter((c) => c !== issued);
    try {
      const existing = existingMember(e, state);
      const previous = checkDevice(e, state.devices);
      const next = replacementGeneration(e, state, previous);
      let relay = issued?.relay;
      if (next !== undefined) {
        const key = state.replacement_key;
        const wire = Buffer.from(challenge, "hex");
        const timestamp = wire.readBigUInt64BE();
        if (issued || !key || timestamp > BigInt(now) || timestamp <= BigInt(now - CHALLENGE_TTL) ||
            !timingSafeEqual(wire.subarray(16), replacementTag(key, wire.subarray(0, 16), e, origin, next))) {
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
        if (!issued?.grant || issued.pairing_slot === undefined) throw new Error("a valid onboarding grant is required");
        const { pinned, prior } = availableGrant(state, issued.grant);
        if (!prior || prior.slot !== issued.pairing_slot || (pinned !== undefined && pinned !== prior.slot)) throw new Error("slot not authorized by onboarding grant");
        id = freeSlot(occupied(state, e.signing_pubkey), issued.pairing_slot);
        prior.used = true;
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

// ─── onboarding grants (operator CLI: scripts/grants.ts) ────────────────────

export type GrantRow = { digest: string; slot: number | null; state: "unused" | "pending" | "used" };

function grantState(state: Registry, digest: string): GrantRow["state"] {
  if (state.grants[digest]?.used) return "used";
  return state.challenges.some((c) => c.grant === digest) ? "pending" : "unused";
}

/** Admits the grant whose SHA-256 digest is `digest`. At most 16 grants may be unused at once.
 *  Takes effect on the next request; no restart. */
export async function registerOnboardingGrant(digest: string, slot?: number): Promise<void> {
  const pinned = slot === undefined ? null : registrationSlot(slot);
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error("a grant digest is 64 lowercase hex characters");
  await changeRegistry((state) => {
    const open = Object.keys(state.onboarding).filter((d) => d !== digest && grantState(state, d) !== "used").length;
    if (open >= MAX_SLOT) return new Error("16 grants are already unused; prune or use some first");
    state.onboarding[digest] = pinned;
  });
}

/** Creates a grant and returns its bearer string, which is never stored: only its digest is. */
export async function addOnboardingGrant(slot?: number): Promise<string> {
  const bearer = randomBytes(32).toString("hex");
  await registerOnboardingGrant(grantDigest(bearer), slot);
  return bearer;
}

export async function listOnboardingGrants(): Promise<GrantRow[]> {
  return changeRegistry((state) => Object.entries(state.onboarding).map(([digest, slot]) => ({ digest, slot, state: grantState(state, digest) })));
}

/** Removes used grants. Their use stays recorded, so a removed grant can never admit again. */
export async function pruneOnboardingGrants(): Promise<number> {
  return changeRegistry((state) => {
    const used = Object.keys(state.onboarding).filter((d) => grantState(state, d) === "used");
    for (const digest of used) delete state.onboarding[digest];
    return used.length;
  });
}
