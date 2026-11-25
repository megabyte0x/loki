import assert from 'node:assert/strict';
import { test } from 'node:test';
import { unlock } from '../src/lib/api.ts';
import { signer } from '../src/lib/signer.ts';

test('unlocking a registered browser signer remembers its roster slot', async () => {
  const sess = new Map();
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  const id = 'ab'.repeat(32);
  const originalUnlock = signer.unlock, originalFetch = globalThis.fetch;
  signer.unlock = async () => ({ profile: { id, name: 'Browser member' }, persisted: false });
  globalThis.fetch = async (url) => {
    const query = new URL(url, 'http://coordinator.test');
    assert.equal(query.pathname, '/api/members');
    const signing = query.searchParams.get('signing_pubkey');
    return Response.json({ slots: [
      { slot: 1, signing_pubkey: 'cd'.repeat(32), relay_pubkey: '11'.repeat(32), advertise_url: 'http://127.0.0.1:3601' },
      { slot: 4, signing_pubkey: id, relay_pubkey: '22'.repeat(32), advertise_url: '' },
    ].filter((m) => m.signing_pubkey === signing) });
  };
  try {
    await unlock({ method: 'platform' });
    assert.deepEqual(JSON.parse(sess.get('loki_me')), { slot: 4 });
    signer.unlock = async () => ({ profile: { id: 'ef'.repeat(32), name: 'New' } });
    await unlock({ method: 'platform' });
    assert.equal(JSON.parse(sess.get('loki_me')).slot, undefined);
  } finally {
    signer.unlock = originalUnlock;
    globalThis.fetch = originalFetch;
  }
});
