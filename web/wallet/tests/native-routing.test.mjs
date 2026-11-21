import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { api, pairDevice, requestPairingLink, signerKind, logout } from '../src/lib/api.ts';
import * as members from '../src/lib/members.ts';

test('a tab paired with a native member routes member calls to it, with its capability', async () => {
  const sess = new Map();
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  globalThis.window = { dispatchEvent: () => {} };
  const member = { slot: 2, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'http://127.0.0.1:3602' };
  const capability = 'A'.repeat(43);
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url, token: init.headers?.['X-Loki-Token'], body: init.body });
    if (url === '/api/members') return Response.json({ slots: [member] });
    if (url === 'http://127.0.0.1:3602/api/registration') return Response.json(member);
    if (url === 'http://127.0.0.1:3602/api/status') return Response.json({ phase: 'home' });
    if (url === 'http://127.0.0.1:3602/api/payment-approve') return Response.json({ phase: 'signing' });
    if (url === 'http://127.0.0.1:3602/api/lock') return Response.json({});
    throw new Error(`unexpected fetch ${url}`);
  };
  try {
    assert.equal(signerKind(), 'browser');
    // Malformed links never reach the network.
    await assert.rejects(pairDevice('http://example.com:3602/#' + capability), /pairing link/);
    await assert.rejects(pairDevice('http://127.0.0.1:3602/#short'), /pairing link/);
    assert.equal(calls.length, 0);

    assert.equal((await pairDevice(`http://127.0.0.1:3602/#${capability}`)).slot, 2);
    assert.equal(signerKind(), 'native');
    const approve = { vault: 'a'.repeat(64), attempt: 'b'.repeat(64), review_token: 't', intent_hash: 'h' };
    assert.equal((await api('payment-approve', approve)).phase, 'signing');
    const last = calls.at(-1);
    assert.equal(last.url, 'http://127.0.0.1:3602/api/payment-approve');
    assert.equal(last.token, capability);
    assert.deepEqual(JSON.parse(last.body), approve, 'the reviewed intent_hash reaches the member');

    assert.equal(await logout(), true);
    assert.equal(calls.at(-1).url, 'http://127.0.0.1:3602/api/lock');
    assert.equal(signerKind(), 'browser', 'logout forgets the pairing');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('the wallet asks for a pairing link, then for the same slot again only once it expired', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loki-wallet-pairing-'));
  process.env.LOKI_REGISTRY = join(dir, 'roster.json');
  const origin = 'http://localhost:3001';
  const grant = '1a'.repeat(32);
  const otherGrant = '2b'.repeat(32);
  const digest = (token) => createHash('sha256').update(token).digest('hex');
  process.env.LOKI_ONBOARDING_GRANTS = JSON.stringify({ [digest(grant)]: null, [digest(otherGrant)]: null });
  const bodies = [];
  let reply = null; // replaces the real coordinator for one request
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    assert.equal(url, '/api/members/pairing');
    assert.equal(init.method, 'POST');
    const body = JSON.parse(init.body);
    bodies.push(body);
    if (reply) { const r = reply(body); reply = null; return r; }
    try { return Response.json(await members.issuePairingChallenge(body, origin)); }
    catch (e) { return Response.json({ error: e.message }, { status: 400 }); }
  };
  const originalWindow = globalThis.window;
  const location = { origin, pathname: '/', search: '', hash: `#onboarding=${grant}` };
  globalThis.window = { location, history: { replaceState: () => { location.hash = ''; } } };
  try {
    const first = await requestPairingLink();
    assert.deepEqual(bodies[0], { onboarding_grant: grant }, 'the first link lets the coordinator pick the slot');
    assert.equal(first.slot, 1);
    assert(first.url.startsWith('loki://pair?') && first.expires > Date.now());
    // Another member's link takes the next slot, so a request without a slot no longer returns 1.
    assert.equal((await members.issuePairingChallenge({ onboarding_grant: otherGrant }, origin)).slot, 2);

    // While the link is live its owner receives the same claim, not a new reservation.
    assert.equal((await requestPairingLink(first.slot)).url, first.url);

    // Once it expired, a new link is for slot 1 again, with a new claim.
    const file = process.env.LOKI_REGISTRY;
    const snapshot = JSON.parse(readFileSync(file));
    snapshot.challenges = snapshot.challenges.map((c) => c.pairing_slot === 1 ? { ...c, expires: 0 } : c);
    snapshot.grants[digest(grant)].retry_after = 0;
    writeFileSync(file, JSON.stringify(snapshot));
    const again = await requestPairingLink(first.slot);
    assert.deepEqual(bodies.at(-1), { slot: 1, onboarding_grant: grant });
    assert.equal(again.slot, 1);
    assert.notEqual(new URL(again.url).searchParams.get('challenge'), new URL(first.url).searchParams.get('challenge'));

    // LokiSigner shows the origin and slot inside the link, so they must be what this page shows,
    // even when the reply's own `slot` field is right.
    const challenge = new URL(again.url).searchParams.get('challenge');
    const enc = encodeURIComponent(origin);
    const forged = (query, fields = {}) => () => Response.json({ slot: 1, expires: Date.now() + 120_000, url: `loki://pair?${query}`, ...fields });
    const good = `origin=${enc}&slot=1&challenge=${challenge}`;
    reply = forged(good);
    assert.equal((await requestPairingLink(1)).url, `loki://pair?${good}`, 'a link that matches is shown');
    for (const query of [
      `origin=${enc}&slot=9&challenge=${challenge}`, // another slot in the link only
      `origin=https%3A%2F%2Fother.example&slot=1&challenge=${challenge}`, // another origin (a rewritten Host)
      `origin=${enc}&slot=1&slot=9&challenge=${challenge}`, // a duplicate key
      `origin=${enc}&slot=1&challenge=${challenge}&x=1`, // an extra key
      `origin=${enc}&slot=01&challenge=${challenge}`, // the same number, written differently
      `origin=${enc}&slot=1&challenge=${challenge.toUpperCase()}`, // not lowercase hex
      `origin=${enc}&slot=1`, // no challenge
    ]) {
      reply = forged(query);
      await assert.rejects(requestPairingLink(1), /does not match this page/, query);
    }
    // A link for another slot than the one asked for is refused, even when it is consistent.
    reply = forged(`origin=${enc}&slot=3&challenge=${challenge}`, { slot: 3 });
    await assert.rejects(requestPairingLink(1), /does not match this page/);

    // A reply to a first request with a slot or deadline that is not a whole number is refused.
    for (const fields of [{ slot: '1' }, { slot: 1.5 }, { expires: Date.now() + 120_000.5 }, { expires: String(Date.now() + 120_000) }]) {
      reply = forged(good, fields);
      await assert.rejects(requestPairingLink(), /would not accept/, JSON.stringify(fields));
    }

    // The deadline is the time the coordinator has left, on this browser's clock, never over 120 s.
    const leftAfter = async (serverNow, expires, date = new Date(serverNow).toUTCString()) => {
      reply = () => Response.json({ slot: 1, url: `loki://pair?${good}`, expires }, date === null ? {} : { headers: { Date: date } });
      const issued = await requestPairingLink(1);
      return issued.expires - Date.now();
    };
    const ahead = await leftAfter(Date.now() - 600_000, Date.now() - 600_000 + 120_000); // this clock is 10 min fast
    assert(ahead > 118_000 && ahead <= 120_000, `fast clock: ${ahead}`);
    const behind = await leftAfter(Date.now() + 600_000, Date.now() + 600_000 + 30_000); // 10 min slow, 30 s left
    assert(behind > 28_000 && behind < 31_000, `slow clock: ${behind}`);
    const capped = await leftAfter(Date.now(), Date.now() + 600_000);
    assert(capped > 118_000 && capped <= 120_000, `capped: ${capped}`);
    for (const date of [null, 'yesterday']) {
      const fallback = await leftAfter(Date.now(), Date.now() - 600_000, date);
      assert(fallback > 118_000 && fallback <= 120_000, `no usable Date header (${date}): ${fallback}`);
    }

    // Only a plain `loki://pair?` link from the coordinator becomes a link target.
    for (const url of ['javascript:alert(1)//loki://pair?slot=1', 'https://evil.example/?u=loki://pair?slot=1', 'loki://pairing?slot=1',
      'loki://pair?', ' loki://pair?slot=1', 'LOKI://pair?slot=1', 'loki://pair?slot=1"><img src=x onerror=alert(1)>', 'loki://pair?slot=1\njavascript:alert(1)']) {
      reply = () => Response.json({ slot: 4, url, expires: Date.now() + 120_000 });
      await assert.rejects(requestPairingLink(), /would not accept/, url);
    }
    // An unknown refusal is described in the wallet's words; its text never reaches the page.
    reply = () => Response.json({ error: '<a href="javascript:alert(1)">fix it here</a>' }, { status: 400 });
    await assert.rejects(requestPairingLink(), (e) => e.message === 'The coordinator refused a pairing link (HTTP 400). Try again, or ask whoever runs it.');
    reply = () => new Response('<html>Bad gateway</html>', { status: 502 });
    await assert.rejects(requestPairingLink(), /HTTP 502/);
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.window = originalWindow;
    rmSync(dir, { recursive: true, force: true }); delete process.env.LOKI_REGISTRY; delete process.env.LOKI_ONBOARDING_GRANTS;
  }
});
