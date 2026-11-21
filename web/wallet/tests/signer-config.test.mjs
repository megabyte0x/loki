import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { signerConfigResponse, signerOrigin } from '../src/lib/signer-config.ts';

const hex = (n) => n.toString(16).padStart(2, '0').repeat(32);
const witness = (n, endpoint) => ({ endpoint, key: hex(n), run: hex(n + 1), mailbox: hex(n + 2), read: hex(n + 3) });
// What core/loki-signer-wasm/serve.mjs serves at /config.json.
const served = () => ({
  walletOrigin: 'http://localhost:3001', frostdUrl: 'https://frostd.example', rpId: 'signer.example',
  nonceWitnesses: [witness(1, 'https://w1.example'), witness(5, 'https://w2.example')],
  network: 'testnet', lightwalletdUrl: 'https://lwd.example:443',
});

test('the coordinator serves the signer origin\'s configuration to LokiSigner, and fails closed', async () => {
  let reply = (res) => res.end(JSON.stringify(served()));
  const signer = createServer((req, res) => (req.url === '/config.json' ? reply(res) : res.writeHead(404).end()));
  await new Promise((resolve) => signer.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${signer.address().port}`;
  const get = async () => {
    const response = await signerConfigResponse(origin, 'production');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return { status: response.status, body: await response.json() };
  };
  try {
    const ok = await get();
    assert.equal(ok.status, 200);
    // Only what the native signer needs, with witnesses in the native `--nonce-witnesses` shape.
    assert.deepEqual(ok.body, {
      network: 'testnet', frostdUrl: 'https://frostd.example', lightwalletdUrl: 'https://lwd.example:443',
      nonceWitnesses: [1, 5].map((n, i) => ({ endpoint: `https://w${i + 1}.example`, key: Array(32).fill(n),
        run: Array(32).fill(n + 1), mailbox: Array(32).fill(n + 2) })),
    });
    reply = (res) => res.end(JSON.stringify({ ...served(), lightwalletdUrl: '' }));
    assert.equal((await get()).body.lightwalletdUrl, null, 'an unset lightwalletd is absent, not invented');

    const refused = async (respond, pattern) => {
      reply = respond;
      const { status, body } = await get();
      assert.equal(status, 502);
      assert.deepEqual(Object.keys(body), ['error']);
      assert.match(body.error, pattern);
    };
    for (const network of ['mainnet', 'main', undefined]) {
      await refused((res) => res.end(JSON.stringify({ ...served(), network })), /invalid network/);
    }
    await refused((res) => res.writeHead(302, { Location: '/elsewhere' }).end(), /answered 302/);
    await refused((res) => res.end(JSON.stringify({ ...served(), nonceWitnesses: [served().nonceWitnesses[0]] })), /nonce witness list/);
    await refused((res) => res.end(JSON.stringify({ ...served(), nonceWitnesses: [witness(1, 'https://w1.example'), { ...witness(5, 'https://w2.example'), mailbox: 'zz' }] })), /nonce witness mailbox/);
    await refused((res) => res.end(JSON.stringify({ ...served(), frostdUrl: '' })), /frostd URL/);
    await refused((res) => res.end('not json'), /invalid configuration/);
  } finally {
    await new Promise((resolve) => signer.close(resolve));
  }
  // Unreachable, or no signer origin configured: a clear error, never a configuration.
  const unreachable = await signerConfigResponse(origin, 'production');
  assert.equal(unreachable.status, 502);
  assert.match((await unreachable.json()).error, /unreachable/);
  const unset = await signerConfigResponse('', 'production');
  assert.equal(unset.status, 502);
  assert.match((await unset.json()).error, /NEXT_PUBLIC_SIGNER_ORIGIN/);
  assert.equal(signerOrigin('https://signer.example/path', 'production'), 'https://signer.example');
});
