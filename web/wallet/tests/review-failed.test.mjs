import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

// Render the actual ReviewApprove component once this member approved, with the session preset.
function render(session) {
  const source = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8');
  const page = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const screen = page.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'ReviewApprove');
  assert.ok(screen);
  const { outputText } = ts.transpileModule(screen.getText(page), { compilerOptions: { jsx: ts.JsxEmit.React } });
  const load = new Function('React', 'useState', 'useCallback', 'useEffect', 'useRef', 'api', 'rememberedVaultSlot',
    'GlassCard', 'Btn', 'ErrMsg', 'SignerList', 'BackLink', 'Row', 'zatToTaz', 'short', `${outputText}\nreturn ReviewApprove;`);
  // review and session; approval comes from the signer's session response.
  const preset = [null, session];
  let call = 0;
  const useState = (initial) => React.useState(call < preset.length ? preset[call++] : initial);
  const ReviewApprove = load(React, useState, React.useCallback, () => {}, React.useRef, null, () => null,
    'section', 'button', ({ msg }) => msg, () => React.createElement('ul'), () => null, () => null, String, String);
  const vault = { vault: 'a'.repeat(64), name: 'V', threshold: 2, members: 3 };
  return renderToStaticMarkup(React.createElement(ReviewApprove, { vault, attempt: 'b'.repeat(64), onBack: () => {} }));
}

const session = { phase: 'signing', approvals: [1, 3], approval_requested: true, signatures_received: false,
  intent: { proposer: 1, signers: [1, 3] } };

test('an approved payment whose signing failed reads as failed, not approved', () => {
  const failed = render({ ...session, phase: 'failed', error: 'Member 3 refused or failed to complete this signing attempt.' });
  assert.match(failed, /Payment signing failed/);
  assert.match(failed, /Member 3 refused/);
  assert.doesNotMatch(failed, /✓|You approved|Once enough have approved/);
  const approved = render(session);
  assert.match(approved, /✓/);
  assert.match(approved, /You approved this payment/);
});
