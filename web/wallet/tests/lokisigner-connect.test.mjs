import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { api, connectLokiSigner, hasLokiSignerSession, lastLokiSignerSlot } from '../src/lib/api.ts';

// Compile just this JSX module so the existing Node test command can render the production component.
const componentUrl = new URL('../src/components/NativeTabConnection.tsx', import.meta.url);
const jsx = registerHooks({ load(url, context, next) {
  if (url !== componentUrl.href) return next(url, context);
  return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(componentUrl, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX },
  }).outputText };
} });
const { NativeTabConnection } = await import(componentUrl.href);
jsx.deregister();

const member = { slot: 7, signing_pubkey: '11'.repeat(32), relay_pubkey: '22'.repeat(32), advertise_url: 'https://peer.example' };
const old = 'http://127.0.0.1:40117';
const current = 'http://[::1]:41227';
const sessionKey = 'loki_device_session';
const token = (letter) => letter.repeat(43);

function tabFixture(t, fakeFetch) {
  let active;
  const events = [];
  t.mock.method(globalThis, 'fetch', fakeFetch);
  globalThis.window = { dispatchEvent: (event) => events.push(event.type) };
  globalThis.sessionStorage = {
    getItem: (key) => active.get(key) ?? null,
    setItem: (key, value) => active.set(key, value),
    removeItem: (key) => active.delete(key),
  };
  t.after(() => { delete globalThis.window; delete globalThis.sessionStorage; });
  return { events, use: (tab) => { active = tab; } };
}

function streamed(...parts) {
  const encoder = new TextEncoder();
  return new Response(new ReadableStream({ start(controller) {
    for (const part of parts) controller.enqueue(encoder.encode(part));
    controller.close();
  } }), { headers: { 'content-type': 'application/x-ndjson' } });
}

test('the real native login component chooses Connect for LokiSigner and paste for headless or older apps', () => {
  const render = (row) => renderToStaticMarkup(createElement(NativeTabConnection, {
    slot: row.slot, member: row, disabled: false, onBusy() {}, onConnected() {},
  }));
  const lokiSigner = render({ ...member, lokisigner_url: current });
  assert.match(lokiSigner, /<button[^>]*>Connect LokiSigner<\/button>/);
  assert.doesNotMatch(lokiSigner, /<input|Pair this tab/);
  const headless = render(member);
  assert.match(headless, /<input[^>]*type="password"/);
  assert.match(headless, /<button[^>]*>Pair this tab<\/button>/);
  assert.doesNotMatch(headless, /Connect LokiSigner/);
});

test('duplicating an approved tab copies the slot but needs its own Allow, and a stale grant can reconnect', async (t) => {
  const first = await import('../src/lib/api.ts?tab=first');
  const duplicate = await import('../src/lib/api.ts?tab=duplicate');
  let launch = 1, ready = false, requests = 0, statusToken;
  const posts = [], progress = [], nativeCalls = [];
  const tab1 = new Map();
  const fixture = tabFixture(t, async (url, options = {}) => {
    if (url === '/api/members') {
      // The first launch's row is visible before the app has consumed its registration reply.
      const endpoint = launch === 1 ? old : current;
      return Response.json({ slots: [{ ...member, lokisigner_url: endpoint }] });
    }
    if (url.endsWith('/api/connect')) {
      posts.push(url);
      assert.deepEqual(options.headers, { 'Content-Type': 'application/json' });
      assert.equal(options.redirect, 'error');
      assert.deepEqual(JSON.parse(options.body), { slot: member.slot, signing_pubkey: member.signing_pubkey, relay_pubkey: member.relay_pubkey });
      if (!ready) { ready = true; return new Response(null, { status: 425 }); }
      return streamed('{"co', 'de":"061274"}\n', JSON.stringify({ token: token(String(++requests)) }) + '\n');
    }
    assert.match(url, /\/api\/status$/);
    nativeCalls.push(options.headers['X-Loki-Token']);
    if (launch === 2 && url.startsWith(old)) return new Response(null, { status: 401 });
    assert.equal(options.headers['X-Loki-Token'], statusToken);
    return Response.json({ phase: 'home' });
  });
  const connect = (wallet) => wallet.connectLokiSigner(member.slot, (event) => progress.push(event), new AbortController().signal);

  fixture.use(tab1);
  const connecting = connect(first);
  assert.deepEqual(progress, [{ phase: 'starting' }]);
  assert.equal(first.hasLokiSignerSession(), false);
  await connecting;
  assert.deepEqual(posts, [`${old}/api/connect`, `${old}/api/connect`]);
  assert.deepEqual(progress, [{ phase: 'starting' }, { phase: 'compare', code: '061274' }]);
  assert.equal(tab1.has(sessionKey), false);
  statusToken = token('1');
  assert.equal((await first.api('status')).phase, 'home');

  const tab2 = new Map(tab1); // The browser duplicates sessionStorage, not the JS module.
  fixture.use(tab2);
  assert.equal(duplicate.lastLokiSignerSlot(), member.slot);
  assert.equal(duplicate.hasLokiSignerSession(), false);
  await assert.rejects(duplicate.api('status'), { status: 401 });
  assert.deepEqual(nativeCalls, [token('1')]);
  fixture.events.length = 0;
  await connect(duplicate);
  assert.equal(tab2.has(sessionKey), false);
  statusToken = token('2');
  assert.equal((await duplicate.api('status')).phase, 'home');

  fixture.use(tab1);
  statusToken = token('1');
  assert.equal((await first.api('status')).phase, 'home', 'the original retains its own grant');
  launch = 2;
  await assert.rejects(first.api('status'), { status: 401 });
  assert.deepEqual(fixture.events, ['loki:auth-lost']);
  assert.equal(first.hasLokiSignerSession(), false);
  assert.equal(first.lastLokiSignerSlot(), member.slot);
  await connect(first);
  assert.equal(posts.at(-1), `${current}/api/connect`);
  statusToken = token('3');
  assert.equal((await first.api('status')).phase, 'home');
});

test('a stale loopback port retries discovery; a foreign URL or a refused response cannot set a session', async (t) => {
  const tab = new Map();
  let endpoint = old, posts = 0;
  const fixture = tabFixture(t, async (url) => {
    if (url === '/api/members') return Response.json({ slots: [{ ...member, lokisigner_url: endpoint }] });
    posts++;
    if (url === `${old}/api/connect`) { endpoint = current; throw new TypeError('connection refused'); }
    assert.equal(url, `${current}/api/connect`);
    return streamed('{"code":"061274"}\n', '{"refused":true}\n');
  });
  fixture.use(tab);
  const events = [];
  const connect = () => connectLokiSigner(member.slot, (event) => events.push(event), new AbortController().signal);
  await assert.rejects(connect(), /did not allow/);
  assert.deepEqual(events, [{ phase: 'starting' }, { phase: 'compare', code: '061274' }]);
  assert.equal(hasLokiSignerSession(), false);
  assert.equal(tab.has(sessionKey), false);
  assert.equal(posts, 2, 'an explicit refusal does not retry');

  for (const invalid of ['http://example.com:41227', 'http://127.0.0.1:41227/', 'http://user@127.0.0.1:41227', 'http://[::1]:41227#x']) {
    endpoint = invalid;
    await assert.rejects(connect(), /valid LokiSigner loopback address/);
  }
  assert.equal(posts, 2, 'no invalid roster address is contacted');
});

test('a forbidden or busy connect response is final and displays no comparison code', async (t) => {
  let status, posts = 0;
  const tab = new Map();
  tabFixture(t, async (url) => {
    if (url === '/api/members') return Response.json({ slots: [{ ...member, lokisigner_url: current }] });
    return ++posts === 1 ? new Response(null, { status }) : streamed('{"code":"061274"}\n', `{"token":"${token('a')}"}\n`);
  }).use(tab);
  for (const [reply, message] of [[403, /did not allow/], [429, /another connection request or waiting.*Refuse.*few seconds/]]) {
    status = reply;
    posts = 0;
    const events = [];
    await assert.rejects(connectLokiSigner(member.slot, (event) => events.push(event), new AbortController().signal), message);
    assert.equal(posts, 1);
    assert.deepEqual(events, [{ phase: 'starting' }]);
    assert.equal(hasLokiSignerSession(), false);
    assert.equal(tab.has(sessionKey), false);
  }
});

test('startup retries stop after one minute and a new attempt can connect', { timeout: 5_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const wallet = await import('../src/lib/api.ts?tab=startup');
  const tab = new Map();
  let ready = false, posts = 0;
  tabFixture(t, async (url) => {
    if (url === '/api/members') return Response.json({ slots: [{ ...member, lokisigner_url: current }] });
    if (ready) return streamed('{"code":"061274"}\n', `{"token":"${token('b')}"}\n`);
    const status = [undefined, 404, 405, 425][posts++ % 4];
    if (!status) throw new TypeError('network error');
    return new Response(null, { status });
  }).use(tab);
  const events = [];
  const connect = () => wallet.connectLokiSigner(member.slot, (event) => events.push(event), new AbortController().signal);
  const stopped = assert.rejects(connect(), (error) => error instanceof wallet.LokiSignerStartupTimeout
    && /open and unlocked.*local network permission.*browser may block/.test(error.message));
  for (let n = 0; n < 40; n++) {
    await new Promise(setImmediate);
    assert.equal(posts, n + 1);
    t.mock.timers.tick(1500);
  }
  await stopped;
  assert.deepEqual(events, [{ phase: 'starting' }]);
  assert.equal(wallet.hasLokiSignerSession(), false);
  ready = true;
  await connect();
  assert.equal(wallet.hasLokiSignerSession(), true);
  assert.equal(tab.has(sessionKey), false);
});

test('only a code followed by a token in a live request can persist a grant', async (t) => {
  const tab = new Map();
  const code = '{"code":"061274"}\n';
  const grant = `{"token":"${token('c')}"}\n`;
  let frames = [grant, code];
  tabFixture(t, async (url) => url === '/api/members'
    ? Response.json({ slots: [{ ...member, lokisigner_url: current }] })
    : streamed(...frames)).use(tab);
  const request = new AbortController();
  await assert.rejects(connectLokiSigner(member.slot, () => {}, request.signal), /did not allow/);
  assert.equal(hasLokiSignerSession(), false);
  assert.equal(tab.size, 0);

  frames = [code, grant];
  // The fake stream deliberately delivers a valid decision even after we cancel the request.
  await assert.rejects(connectLokiSigner(member.slot, (event) => {
    if (event.phase === 'compare') request.abort();
  }, request.signal), { name: 'AbortError' });
  assert.equal(hasLokiSignerSession(), false);
  assert.equal(tab.size, 0);
});

test('even a valid-looking LokiSigner grant stored by an older wallet is discarded, not used', async (t) => {
  const tab = new Map([
    [sessionKey, JSON.stringify({ endpoint: current, capability: token('d'), lokisigner: true })],
    ['loki_lokisigner_slot', String(member.slot)],
  ]);
  tabFixture(t, () => assert.fail('a copied grant must not reach the signer')).use(tab);
  await assert.rejects(api('status'), { status: 401 });
  assert.equal(tab.has(sessionKey), false);
  assert.equal(lastLokiSignerSlot(), member.slot);
});
