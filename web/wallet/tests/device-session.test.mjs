import assert from 'node:assert/strict';
import { test } from 'node:test';
import { api, findMember, createSigner, unlock, hasSigner, logout, forgetSession } from '../src/lib/api.ts';

test('member calls run in the in-browser signer; only the coordinator is fetched', async () => {
  const sess = new Map(), local = new Map(), events = [];
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: (k) => local.get(k) ?? null, setItem: (k, v) => local.set(k, v), removeItem: (k) => local.delete(k) };
  globalThis.window = { dispatchEvent: (e) => events.push(e.type) };
  const originalFetch = globalThis.fetch;
  const member = { slot: 1, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'http://127.0.0.1:3601' };
  const fetched = [];
  globalThis.fetch = async (url, init = {}) => {
    fetched.push(url);
    assert(url === '/api/members?slot=1', 'the only network call is a public roster lookup');
    assert(!init.headers, 'coordinator receives no signer capability');
    return Response.json({ slots: [member] });
  };
  try {
    assert.equal(await hasSigner(), false);
    await assert.rejects(api('status'), /Unlock your signer/);

    const created = await createSigner({ name: 'Alex', method: 'passphrase', passphrase: 'correct horse' });
    assert.equal(created.profile.name, 'Alex');
    assert.equal(await hasSigner(), true);
    const status = await api('status');
    assert.equal(status.phase, 'home');
    assert.equal(status.secure_element, 'software');
    assert.deepEqual(status.vaults, []);

    await assert.rejects(api('create', { name: 'v', members: 3, threshold: 2 }), /does not serve/);
    await assert.rejects(api('../api/members'), /invalid signer API path/);

    assert.deepEqual(await findMember({ slot: 1 }), member);
    assert.deepEqual(fetched, ['/api/members?slot=1']);


    assert.equal(await logout(), true);
    await assert.rejects(api('status'), /Unlock your signer/);
    assert(events.includes('loki:auth-lost'));

    assert.equal(await hasSigner(), true);
    assert.equal((await unlock({ method: 'passphrase', passphrase: 'correct horse' })).profile.name, 'Alex');
    assert.equal((await api('status')).phase, 'home');
    forgetSession();
  } finally {
    globalThis.fetch = originalFetch;
    delete globalThis.window; delete globalThis.sessionStorage; delete globalThis.localStorage;
  }
});
