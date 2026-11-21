import assert from "node:assert/strict";
import { test } from "node:test";
import { comparesInLokiSigner, emptyHistoryText, invitePreview, nativeRosterRefusal, pairingSecondsLeft, paymentLabel, rememberedVaultSlot, rememberVaultSlot, storageLabel } from "../src/lib/wallet-ui.ts";

const invite = { vault: "a".repeat(64), name: "Friends’ vault", members: 3, threshold: 2, slot: 2 };
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

test("invite preview preserves Unicode and rejects malformed metadata", () => {
  assert.deepEqual(invitePreview(encode(invite)), invite);
  for (const change of [{ name: "" }, { vault: "bad" }, { members: 17 }, { threshold: 4 }, { slot: 1 }, { slot: 4 }, { threshold: "2" }]) {
    assert.equal(invitePreview(encode({ ...invite, ...change })), null);
  }
  for (const code of ["not an invite", "", encode(null), encode([])]) assert.equal(invitePreview(code), null);
});

test("pending payments never look sent and internal phase names stay hidden", () => {
  assert.equal(paymentLabel("signing", false, false), "Collecting approvals");
  assert.equal(paymentLabel("signing", true, false), "Ready to send");
  assert.equal(paymentLabel("signing", true, true), "Sending");
  assert.equal(paymentLabel("broadcast", false, true), "Awaiting confirmation");
  assert.equal(paymentLabel("confirmed", false, true), "Confirmed");
  assert.equal(paymentLabel("not_selected", false, false), "Other members are signing");
  assert.equal(paymentLabel("failed", true, true), "Failed · not sent");
  assert.equal(paymentLabel("discarding", true, true), "Releasing reserved input");
  assert.equal(paymentLabel("cancelled", true, true), "Cancelled");
  assert.equal(paymentLabel("expired", true, true), "Expired");
  assert.equal(paymentLabel("signed", false, false), "Signed · not sent yet");
  assert.equal(paymentLabel("signed", false, true), "Sending");
  assert.equal(paymentLabel("replaced", false, true), "Replaced");
  assert.equal(paymentLabel("unknown_internal_phase", false, false), "Status unavailable");
});

test("only LokiSigner's empty history warns that deposits are not listed", () => {
  assert.equal(emptyHistoryText(true), "Outgoing payment requests and sent payments will appear here. Incoming deposits aren’t listed.");
  assert.equal(emptyHistoryText(false), "Payments sent and received by this vault will appear here.");
});

test("the storage badge only claims protection reported by the native signer", () => {
  for (const [element, enclave, label] of [
    ["apple", true, "Enclave-protected wrapping key"],
    ["software", false, "Software device storage"],
    [undefined, false, "Share protection not reported"],
    ["unexpected", false, "Share protection not reported"],
  ]) {
    assert.equal(storageLabel(element, "native").label, label);
    assert.equal(storageLabel(element, "native").enclave, enclave);
  }
  assert.equal(storageLabel("passkey", "browser").label, "Sealed under your passkey in this browser");
  assert.equal(storageLabel(undefined, "browser").label, "Sealed under your passphrase in this browser");
});

test("remembered vault slots are scoped to the authenticated profile and vault", () => {
  const values = new Map();
  globalThis.localStorage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  rememberVaultSlot("alice", "vault-a", 2);
  assert.equal(rememberedVaultSlot("alice", "vault-a"), 2);
  assert.equal(rememberedVaultSlot("bob", "vault-a"), null);
  assert.equal(rememberedVaultSlot("alice", "vault-b"), null);
  assert.equal(rememberedVaultSlot(undefined, "vault-a"), null);
  values.set("loki_slot:alice:vault-a", "99");
  assert.equal(rememberedVaultSlot("alice", "vault-a"), null);
  globalThis.localStorage = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };
  assert.doesNotThrow(() => rememberVaultSlot("alice", "vault-a", 2));
  assert.equal(rememberedVaultSlot("alice", "vault-a"), null);
  delete globalThis.localStorage;
});

test("a pairing link counts down in whole seconds and is expired exactly at its deadline", () => {
  const expires = 1_700_000_120_000;
  assert.equal(pairingSecondsLeft(expires, expires - 120_000), 120);
  assert.equal(pairingSecondsLeft(expires, expires - 1001), 2);
  assert.equal(pairingSecondsLeft(expires, expires - 1000), 1);
  assert.equal(pairingSecondsLeft(expires, expires - 1), 1, "still live: never shown as 0:00 before it expires");
  assert.equal(pairingSecondsLeft(expires, expires), 0, "the coordinator drops the reservation at its deadline");
  assert.equal(pairingSecondsLeft(expires, expires + 5000), 0);
});

test("a native member's roster refusals say what to do next", () => {
  const refusal = (message, answered = true) => nativeRosterRefusal(message, answered);
  assert.match(refusal("roster codes differ: LokiSigner refuses this vault until it restarts"), /^You chose Codes differ/);
  assert.match(refusal("roster code not confirmed in LokiSigner"), /closed or timed out .* nothing was recorded/);
  assert.match(refusal("LokiSigner is already asking about a roster code"), /Answer that dialog first/);
  assert.match(refusal("the vault setup changed while LokiSigner was asking; nothing was recorded: roster code mismatch"), /members changed while LokiSigner was asking/);
  assert.match(refusal("roster code mismatch"), /changed since this page loaded/);
  assert.match(refusal("anything", false), /lost its connection/);
  assert.equal(refusal("profile is locked"), "LokiSigner recorded no agreement: profile is locked");
});

test("only a member with LokiSigner's roster dialog compares there; a headless member sees the code", () => {
  const status = { phase: "compare_roster", members: 3, threshold: 2, roster_code: "1234 5678 9012 3456 7890 1234" };
  assert.equal(comparesInLokiSigner(status), false, "a headless loki_member_app or LokiSigner serve status");
  assert.equal(comparesInLokiSigner(JSON.parse(JSON.stringify({ ...status, roster_dialog: null }))), true);
  assert.equal(comparesInLokiSigner({ ...status, roster_dialog: "open" }), true);
  assert.equal(comparesInLokiSigner({ ...status, roster_dialog: "codes_differ" }), true);
});
