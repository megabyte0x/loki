import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { exportRecoveryBackup, manageBrowserCustody, restoreSigner, setupBrowserRecovery } from '../src/lib/api.ts';

test('browser recovery calls go only to the browser signer, never to a paired native member', async () => {
  const sess = new Map();
  globalThis.sessionStorage = { getItem: (k) => sess.get(k) ?? null, setItem: (k, v) => sess.set(k, v), removeItem: (k) => sess.delete(k) };
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  globalThis.window = { dispatchEvent: () => {} };
  const fetched = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => { fetched.push(url); throw new Error('no network expected'); };
  const calls = [setupBrowserRecovery, () => exportRecoveryBackup('a'.repeat(64)),
    () => restoreSigner({ name: 'A', method: 'passphrase' }), manageBrowserCustody];
  try {
    // Browser kind: each call is dispatched to the signer (the Node mock serves none of them;
    // the signer origin does; locked, it asks to unlock first), and nothing is fetched here.
    for (const call of calls) await assert.rejects(call(), /does not serve|Unlock your signer/);
    // A tab paired with a native member refuses them before any request.
    sess.set('loki_device_session', JSON.stringify({ endpoint: 'http://127.0.0.1:3602', capability: 'A'.repeat(43) }));
    for (const call of calls) await assert.rejects(call(), /native member/);
    assert.deepEqual(fetched, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('the wallet Recovery card distinguishes LokiSigner from a paired headless member', () => {
  // Render the actual page component without Next's app shell. Model its first render after
  // the member status arrives; both sessions report the same signerKind to the wallet.
  const source = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
  const page = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const card = page.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'RecoveryCard');
  assert.ok(card);
  const { outputText } = ts.transpileModule(card.getText(page), { compilerOptions: { jsx: ts.JsxEmit.React } });
  const load = new Function('React', 'useState', 'useCallback', 'useEffect', 'GlassCard', 'Btn', 'ErrMsg', 'signerKind',
    `${outputText}\nreturn RecoveryCard;`);
  function render(status) {
    let initialized = false;
    const useState = (initial) => {
      const value = initialized ? initial : status;
      initialized = true;
      return React.useState(value);
    };
    const RecoveryCard = load(React, useState, React.useCallback, () => {}, 'section', 'button', () => null, () => 'native');
    return renderToStaticMarkup(React.createElement(RecoveryCard, { vault: 'a'.repeat(64) }));
  }

  const status = { recovery_identity: true, recovery_backup: true };
  const headless = render(status);
  assert.match(headless, /loki_member_app recovery-setup/);
  assert.match(headless, /loki_member_app recovery-restore/);
  assert.match(headless, /Download encrypted backup/);
  assert.doesNotMatch(headless, /Use LokiSigner|Restore access|<textarea|<input/);
  const lokiSigner = render({ ...status, recovery_in_app: true });
  assert.match(lokiSigner, /Download encrypted backup/);
  assert.match(lokiSigner, /Use LokiSigner/);
  assert.doesNotMatch(lokiSigner, /Restore access|Set up recovery|<textarea/);
});
