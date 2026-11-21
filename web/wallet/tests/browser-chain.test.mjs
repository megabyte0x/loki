import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chainPayments, chainPaymentSession } from '../src/lib/signer.ts';

// The browser signer's history comes from its own chain scan (one entry per transaction).
test('chain history becomes the wallet History list', () => {
  const history = [
    { txid: 'd2'.repeat(32), height: 4639094, received_zat: 0, change_zat: 740000, spent_zat: 780000 },
    { txid: 'bd'.repeat(32), height: 4639001, received_zat: 950000, change_zat: 0, spent_zat: 0 },
  ];
  assert.deepEqual(chainPayments(history), [
    { attempt: 'd2'.repeat(32), phase: 'confirmed', recipient: '', amount_zat: '40000', txid: 'd2'.repeat(32), direction: 'sent', amount_is_net: true, mined_height: 4639094 },
    { attempt: 'bd'.repeat(32), phase: 'confirmed', recipient: '', amount_zat: '950000', txid: 'bd'.repeat(32), direction: 'received', amount_is_net: false, mined_height: 4639001 },
  ]);
});

test('payment status uses the reviewed transaction and keeps personal approval separate', () => {
  const terms = { proposer: 1, recipient: 'utest1x', amount_zat: 30000, fee_zat: 10000 };
  const waiting = chainPaymentSession({ terms, signers: [1, 3], spent: null });
  assert.equal(waiting.phase, 'signing');
  assert.equal(waiting.txid, null);
  assert.equal(waiting.approval_requested, false, 'the Approve button stays for an unsigned request');
  assert.deepEqual(waiting.intent, { proposer: 1, signers: [1, 3], recipient: 'utest1x', amount_zat: 30000, fee_zat: 10000, open_approval: true });
  const txid = 'd2'.repeat(32);
  const spent = { txid, height: 4639094 };
  assert.equal(chainPaymentSession({ terms, signers: [1, 3], spent }).phase, 'spent_unverified');
  assert.equal(chainPaymentSession({ terms, signers: [1, 3], spent, txid: 'a1'.repeat(32) }).phase, 'replaced');
  const mined = chainPaymentSession({ terms, signers: [1, 3], spent, txid, slot: 3, approved: false });
  assert.equal(mined.phase, 'confirmed');
  assert.equal(mined.txid, 'd2'.repeat(32));
  assert.equal(mined.signatures_received, true);
  assert.equal(mined.approval_requested, false, 'mining does not prove the local member approved');
  assert.deepEqual(mined.approvals, [], 'the signing list is not approval evidence');
  assert.equal(chainPaymentSession({ terms, signers: [], ended: 'cancelled', spent: null }).phase, 'cancelled');
});
