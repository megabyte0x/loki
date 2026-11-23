import assert from 'node:assert/strict';
import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import * as members from '../src/lib/members.ts';
import { admitGrant } from './grants.mjs';

const origin = 'http://localhost:3001';
function grant(slot = null) {
  const onboarding_grant = randomBytes(32).toString('hex');
  admitGrant(createHash('sha256').update(onboarding_grant).digest('hex'), slot);
  return { onboarding_grant };
}
function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
  delete process.env.LOKI_REGISTRY;
}
function relayProof(d, { challenge, relay_challenge_pubkey }) {
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(relay_challenge_pubkey, 'hex').toString('base64url') }, format: 'jwk' });
  const secret = diffieHellman({ privateKey: d.relay.privateKey, publicKey });
  const info = ['loki-relay-registration-v1', origin, d.input.signing_pubkey, d.input.relay_pubkey, challenge].join('\n');
  return Buffer.from(hkdfSync('sha256', secret, '', info, 32)).toString('hex');
}
function device(slot, { advertise_url = 'http://127.0.0.1:3601' } = {}) {
  const identity = generateKeyPairSync('ed25519');
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const relay = generateKeyPairSync('x25519');
  const jwk = key.publicKey.export({ format: 'jwk' });
  const device_pubkey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('hex');
  const input = { ...(slot ? { slot } : {}), signing_pubkey: identity.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), relay_pubkey: relay.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), ...(advertise_url === null ? {} : { advertise_url }), device_pubkey,
    authorization: sign(null, Buffer.from(device_pubkey, 'hex'), identity.privateKey).toString('hex') };
  return { input, key, identity, relay };
}
// The same identity on a new device: a fresh device key, authorized by the identity's key.
function newDevice(d) {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = key.publicKey.export({ format: 'jwk' });
  const device_pubkey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('hex');
  return { ...d, key, input: { ...d.input, device_pubkey, authorization: sign(null, Buffer.from(device_pubkey, 'hex'), d.identity.privateKey).toString('hex') } };
}
function response(d, issued, changed = {}) {
  const { challenge } = issued;
  const input = { ...d.input, ...changed };
  const message = ['loki-member-registration-v1', origin, input.slot ?? 0, input.signing_pubkey, input.relay_pubkey, input.advertise_url, input.device_pubkey, challenge].join('\n');
  return { ...input, challenge, relay_proof: relayProof(d, issued), signature: sign('sha256', Buffer.from(message), d.key.privateKey).toString('hex') };
}

function expirePending() {
  const file = process.env.LOKI_REGISTRY;
  const snapshot = JSON.parse(readFileSync(file));
  snapshot.challenges = snapshot.challenges.map((c) => ({ ...c, expires: 0 }));
  for (const use of Object.values(snapshot.grants)) use.retry_after = 0;
  writeFileSync(file, JSON.stringify(snapshot));
}

test('device self-registration binds identity, endpoint and slot; consumes challenges across reloads', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-roster-'));
  process.env.LOKI_REGISTRY = join(dir, '.access.json');
  try {
    assert.equal(typeof members.issueRegistrationChallenge, 'function', 'device challenge endpoint is required');
    const d = device();
    const challenge = await members.issueRegistrationChallenge({ ...d.input, ...grant() }, origin);
    const member = await members.registerMember(response(d, challenge), origin);
    assert.deepEqual(Object.keys(member).sort(), ['advertise_url', 'relay_pubkey', 'signing_pubkey', 'slot']);
    assert.equal(member.slot, 1);
    assert.deepEqual(members.memberById(1), member);
    assert.deepEqual(JSON.parse(readFileSync(process.env.LOKI_REGISTRY)).access, [member]);
    await assert.rejects(members.registerMember(response(d, challenge), origin), /challenge/);
    const reloaded = await import(`../src/lib/members.ts?restart=${Date.now()}`);
    const pending = await members.issueRegistrationChallenge(d.input, origin);
    assert.equal((await reloaded.registerMember(response(d, pending), origin)).slot, 1);
    const tampered = await members.issueRegistrationChallenge(d.input, origin);
    await assert.rejects(members.registerMember(response(d, tampered, { advertise_url: 'http://127.0.0.1:3602' }), origin), /registration|challenge/);
    const foreign = device(1);
    await assert.rejects(members.issueRegistrationChallenge({ ...foreign.input, ...grant(1) }, origin), /slot/);
    await assert.rejects(members.issueRegistrationChallenge({ ...d.input, authorization: '00'.repeat(64) }, origin), /authorization/);
    await assert.rejects(members.issueRegistrationChallenge({ ...d.input, passphrase: 'never accept' }, origin), /field/);
  } finally { cleanup(dir); }
});

test('a frostd-only in-browser signer enrolls without an advertise_url, beside native members', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-roster-frostd-'));
  process.env.LOKI_REGISTRY = join(dir, '.access.json');
  try {
    // No advertise_url: the browser signer has no inbound peer HTTP (peer-over-frostd).
    const browser = device(undefined, { advertise_url: null });
    const challenge = await members.issueRegistrationChallenge({ ...browser.input, ...grant() }, origin);
    const member = await members.registerMember(response(browser, challenge), origin);
    assert.equal(member.slot, 1);
    assert.equal(member.advertise_url, '', 'frostd-only member stores an empty advertise_url');
    assert.deepEqual(members.memberById(1), member);
    // A native member that still advertises a loopback origin registers alongside it.
    const native = device();
    const nativeChallenge = await members.issueRegistrationChallenge({ ...native.input, ...grant() }, origin);
    const nativeMember = await members.registerMember(response(native, nativeChallenge), origin);
    assert.equal(nativeMember.slot, 2);
    assert.equal(nativeMember.advertise_url, 'http://127.0.0.1:3601');
    // response() signs the original v1 transcript for both the browser and the headless member.
    assert.equal(Object.hasOwn(member, 'lokisigner_url'), false);
    assert.equal(Object.hasOwn(nativeMember, 'lokisigner_url'), false);
    assert.equal(members.slots().length, 2);
    // A non-empty advertise_url that is not a valid origin is still rejected.
    await assert.rejects(members.issueRegistrationChallenge(device(undefined, { advertise_url: 'not-an-origin' }).input, origin));
  } finally { cleanup(dir); }
});

test('registration v2 matches the shared byte-for-byte Rust and Node fixture', () => {
  const fixture = new URL('../../../core/tests/fixtures/lokisigner-registration-v2.json', import.meta.url);
  const { enrollment, origin, challenge, expected } = JSON.parse(readFileSync(fixture, 'utf8'));
  assert.deepEqual(members.registrationMessage(enrollment, origin, challenge), Buffer.from(expected));
});

test('registration signs the separate LokiSigner loopback port and refuses unsigned changes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-roster-local-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  const d = device(7, { advertise_url: 'https://peer.example' });
  const endpoint = 'http://127.0.0.1:43812';
  const moved = 'http://[::1]:42761';
  const proof = (issued, value, signed = value) => {
    const { challenge } = issued;
    const { slot, signing_pubkey, relay_pubkey, advertise_url, device_pubkey } = d.input;
    const transcript = `loki-member-registration-v2\n${origin}\n${slot}\n${signing_pubkey}\n${relay_pubkey}\n${advertise_url}\n${signed}\n${device_pubkey}\n${challenge}`;
    return { ...d.input, lokisigner_url: value, challenge, relay_proof: relayProof(d, issued), signature: sign('sha256', Buffer.from(transcript), d.key.privateKey).toString('hex') };
  };
  const onboarding = grant(7);
  const issue = (value) => members.issueRegistrationChallenge({ ...d.input, ...onboarding, lokisigner_url: value }, origin);
  try {
    for (const invalid of [null, '', 'http://127.0.0.2:43812', 'http://localhost:43812', 'https://127.0.0.1:43812',
      'http://127.0.0.1', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', ` ${endpoint}`, `${endpoint}\n`,
      `${endpoint}/`, `${endpoint}?x`, `${endpoint}#x`, 'http://user@127.0.0.1:43812']) {
      await assert.rejects(issue(invalid), /invalid LokiSigner loopback endpoint/);
    }
    const added = await issue(endpoint);
    await assert.rejects(members.registerMember(response(d, added, { lokisigner_url: endpoint }), origin), /signature/);
    expirePending();
    const altered = await issue(moved);
    await assert.rejects(members.registerMember(proof(altered, moved, endpoint), origin), /signature/);
    assert.deepEqual(members.slots(), []);

    expirePending();
    const first = await issue(endpoint);
    const enrolled = await members.registerMember(proof(first, endpoint), origin);
    assert.equal(enrolled.lokisigner_url, endpoint);
    assert.equal(enrolled.advertise_url, 'https://peer.example');
    const restart = await issue(moved);
    await members.registerMember(proof(restart, moved), origin);
    assert.deepEqual(members.slots(), [{ ...enrolled, lokisigner_url: moved }]);
    writeFileSync(process.env.LOKI_REGISTRY, JSON.stringify({ access: [{ ...enrolled, lokisigner_url: 'http://example.com:43812' }] }));
    assert.throws(() => members.slots(), /invalid LokiSigner loopback endpoint/);
  } finally { cleanup(dir); }
});

test('registration bounds request bodies before parsing', async () => {
  assert.equal(typeof members.readRegistrationBody, 'function');
  const req = (body) => new Request('http://localhost:3001/api/members', { method: 'POST', body });
  assert.deepEqual(await members.readRegistrationBody(req('{"slot":1}')), { slot: 1 });
  await assert.rejects(members.readRegistrationBody(req(' '.repeat(4097))), /too large/);
});

test('failed, expired and wrong-origin proofs cannot be replayed; allocations are serialized', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-roster-proof-'));
  process.env.LOKI_REGISTRY = join(dir, '.access.json');
  try {
    const d = device();
    let challenge = await members.issueRegistrationChallenge({ ...d.input, ...grant() }, origin);
    await assert.rejects(members.registerMember({ ...response(d, challenge), signature: '00'.repeat(64) }, origin));
    await assert.rejects(members.registerMember(response(d, challenge), origin), /challenge/);
    challenge = await members.issueRegistrationChallenge({ ...d.input, ...grant() }, origin);
    await assert.rejects(members.registerMember(response(d, challenge), 'https://other.example'), /challenge/);
    challenge = await members.issueRegistrationChallenge({ ...d.input, ...grant() }, origin);
    expirePending();
    await assert.rejects(members.registerMember(response(d, challenge), origin), /challenge/);
    const devices = Array.from({ length: 6 }, () => device());
    const pending = await Promise.all(devices.map((d) => members.issueRegistrationChallenge({ ...d.input, ...grant() }, origin)));
    const registered = await Promise.all(devices.map((d, i) => members.registerMember(response(d, pending[i]), origin)));
    assert.equal(new Set(registered.map((m) => m.slot)).size, 6);
    assert.equal(members.slots().length, 6);
    const bad = { ...devices[0].input, relay_pubkey: '00'.repeat(32) };
    await assert.rejects(members.issueRegistrationChallenge(bad, origin), /relay key/);
    writeFileSync(process.env.LOKI_REGISTRY, JSON.stringify({ access: [{ id: 1, port: 3601, token: 'legacy' }] }));
    assert.throws(() => members.slots(), /field/);
    await assert.rejects(members.issueRegistrationChallenge(d.input, origin), /field/);
  } finally { cleanup(dir); }
});

test('pairing reserves one slot, claims once, and pins one device to one identity and slot', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-pairing-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  try {
    const pair = await members.issuePairingChallenge(grant(), origin);
    assert.equal(pair.slot, 1);
    assert(pair.expires > Date.now() && pair.expires <= Date.now() + 120_000);
    const link = new URL(pair.url);
    assert.equal(link.protocol, 'loki:');
    assert.equal(link.hostname, 'pair');
    assert.equal(link.searchParams.get('origin'), origin);
    assert.equal(link.searchParams.get('challenge'), pair.challenge);
    assert.equal(link.searchParams.get('slot'), '1');
    assert.deepEqual(members.slots(), []);
    const competing = grant(1);
    await assert.rejects(members.issuePairingChallenge({ slot: 1, ...competing }, origin), /slot/);
    const d = device(1);
    await assert.rejects(members.issueRegistrationChallenge({ ...d.input, ...competing }, origin), /reserved/);
    const claims = await Promise.allSettled([1, 2].map(() => members.issueRegistrationChallenge({ ...d.input, pairing_challenge: pair.challenge }, origin)));
    assert.equal(claims.filter((r) => r.status === 'fulfilled').length, 1);
    const claim = claims.find((r) => r.status === 'fulfilled').value;
    await assert.rejects(members.issueRegistrationChallenge({ ...device(1).input, ...competing }, origin), /reserved/);
    const member = await members.registerMember(response(d, claim), origin);
    assert.equal(member.slot, 1);
    await assert.rejects(members.registerMember(response(d, claim), origin), /challenge/);
    await assert.rejects(members.issuePairingChallenge({ slot: 1, ...competing }, origin), /slot/);
    const next = await members.issuePairingChallenge(grant(), origin);
    assert.equal(next.slot, 2);
    // A different identity cannot reuse the same device, even with valid authorization.
    const other = generateKeyPairSync('ed25519');
    const moved = { ...d.input, slot: 2, signing_pubkey: other.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
      authorization: sign(null, Buffer.from(d.input.device_pubkey, 'hex'), other.privateKey).toString('hex') };
    await assert.rejects(members.issueRegistrationChallenge({ ...moved, pairing_challenge: next.challenge }, origin), /device/);
    const reloaded = await import(`../src/lib/members.ts?pair-restart=${Date.now()}`);
    const renewed = await reloaded.issueRegistrationChallenge(d.input, origin);
    assert.deepEqual(await reloaded.registerMember(response(d, renewed), origin), member);
    const rotated = device(1);
    await assert.rejects(members.issueRegistrationChallenge({ ...rotated.input, signing_pubkey: d.input.signing_pubkey }, origin));
    // The same identity may move to a new device; its slot and relay key stay pinned.
    const moved2 = newDevice(d);
    await assert.rejects(members.issueRegistrationChallenge({ ...moved2.input, slot: 2 }, origin), /slot/);
    await assert.rejects(members.issueRegistrationChallenge({ ...moved2.input, relay_pubkey: randomBytes(32).toString('hex') }, origin), /relay key/);
    const replaced = await members.issueRegistrationChallenge(moved2.input, origin);
    const message = ['loki-member-device-replacement-v1', origin, moved2.input.signing_pubkey,
      moved2.input.device_pubkey, replaced.replacement_generation, replaced.challenge].join('\n');
    const replacement_authorization = sign(null, Buffer.from(message), moved2.identity.privateKey).toString('hex');
    assert.deepEqual(await members.registerMember(response(moved2, replaced, { replacement_authorization }), origin), member);
    assert.deepEqual(members.slots(), [member]);
    const { devices } = JSON.parse(readFileSync(process.env.LOKI_REGISTRY));
    assert.deepEqual(devices, [{ slot: 1, signing_pubkey: d.input.signing_pubkey, device_pubkey: moved2.input.device_pubkey,
      generation: 2, retired: [d.input.device_pubkey] }]);
    // The new device key is now bound to this identity; another identity still cannot take it.
    const thief = generateKeyPairSync('ed25519');
    await assert.rejects(members.issueRegistrationChallenge({ ...moved2.input, slot: undefined, signing_pubkey: thief.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
      authorization: sign(null, Buffer.from(moved2.input.device_pubkey, 'hex'), thief.privateKey).toString('hex') }, origin), /device/);
  } finally { cleanup(dir); }
});

test('pairing rejects expired, wrong-origin and changed-slot claims without reviving them', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-pairing-reject-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  try {
    const d = device(1);
    for (const failure of ['origin', 'slot', 'expiry']) {
      const pair = await members.issuePairingChallenge({ slot: 1, ...grant(1) }, origin);
      if (failure === 'expiry') {
        expirePending();
      }
      await assert.rejects(members.issueRegistrationChallenge({ ...d.input, slot: failure === 'slot' ? 2 : 1, pairing_challenge: pair.challenge }, failure === 'origin' ? 'https://other.example' : origin), /pairing challenge/);
      await assert.rejects(members.issueRegistrationChallenge({ ...d.input, pairing_challenge: pair.challenge }, origin), /pairing challenge/);
    }
    assert.deepEqual(members.slots(), []);
    await assert.rejects(members.issuePairingChallenge({ passphrase: 'forbidden' }, origin), /field/);
    await assert.rejects(members.issuePairingChallenge({}, 'http://remote.example'), /HTTPS/);
  } finally { cleanup(dir); }
});

test('native pairing retries a cancelled proof on the same reservation without extending it', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-pairing-resume-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  const file = process.env.LOKI_REGISTRY;
  try {
    const d = device(7);
    const first = { ...d.input, lokisigner_url: 'http://127.0.0.1:3601' };
    const retry = { ...first, advertise_url: 'http://127.0.0.1:3687', lokisigner_url: 'http://127.0.0.1:3687' };
    const pair = await members.issuePairingChallenge({ slot: 7, ...grant(7) }, origin);
    const issue = (input, from = origin) => members.issueRegistrationChallenge(input, from);
    const issued = await issue({ ...first, pairing_challenge: pair.challenge });
    const { challenge } = issued;
    await assert.rejects(issue({ ...first, pairing_challenge: pair.challenge }), /pairing challenge/);
    await assert.rejects(issue({ ...device(7).input, ...grant(7), lokisigner_url: retry.lokisigner_url }), /reserved/);
    await assert.rejects(issue({ ...newDevice(d).input, lokisigner_url: retry.lokisigner_url }), /pending registration/);
    await assert.rejects(issue(retry, 'https://other.example'), /pending registration/);
    assert.deepEqual(await issue(retry), issued);
    assert.equal(JSON.parse(readFileSync(file)).challenges[0].expires, pair.expires);

    const proof = { ...retry, challenge, relay_proof: relayProof(d, issued), signature: sign('sha256', members.registrationMessage(retry, origin, challenge), d.key.privateKey).toString('hex') };
    assert.deepEqual(await members.registerMember(proof, origin), {
      slot: 7, signing_pubkey: retry.signing_pubkey, relay_pubkey: retry.relay_pubkey,
      advertise_url: retry.advertise_url, lokisigner_url: retry.lokisigner_url,
    });
    await assert.rejects(members.registerMember(proof, origin), /challenge/);

    const nextGrant = grant(8);
    const next = await members.issuePairingChallenge({ slot: 8, ...nextGrant }, origin);
    const fresh = { ...device(8).input, lokisigner_url: first.lokisigner_url };
    const pending = await issue({ ...fresh, pairing_challenge: next.challenge });
    expirePending();
    assert.notEqual((await issue({ ...fresh, ...nextGrant })).challenge, pending.challenge);
  } finally { cleanup(dir); }
});

test('a binding saved before a crashed roster write still reserves and recovers its slot', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-pairing-crash-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  try {
    const d = device();
    const { signing_pubkey, device_pubkey, relay_pubkey, advertise_url } = d.input;
    // Legacy crash after the binding write but before the roster write.
    writeFileSync(process.env.LOKI_REGISTRY + '.devices', JSON.stringify([{ slot: 1, signing_pubkey, device_pubkey }]));
    const first = { slot: 1, signing_pubkey, relay_pubkey, advertise_url };
    const pair = await members.issuePairingChallenge(grant(), origin);
    assert.equal(pair.slot, 2);
    await assert.rejects(members.issueRegistrationChallenge({ ...device(1).input, ...grant(1) }, origin), /slot/);
    const retry = await members.issueRegistrationChallenge(d.input, origin);
    assert.deepEqual(await members.registerMember(response(d, retry), origin), first);
  } finally { cleanup(dir); }
});
