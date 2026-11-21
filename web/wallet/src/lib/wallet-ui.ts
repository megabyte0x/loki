/** Invite metadata is a preview only; the existing join endpoint validates the invite. */
export function invitePreview(code: string): { vault: string; name: string; members: number; threshold: number; slot: number } | null {
  try {
    const raw = atob(code.replace(/-/g, "+").replace(/_/g, "/"));
    const value = JSON.parse(new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0))));
    if (typeof value.name !== "string" || !value.name.trim() || value.name.length > 80
      || typeof value.vault !== "string" || !/^[a-f0-9]{64}$/i.test(value.vault)
      || !Number.isInteger(value.members) || value.members < 2 || value.members > 16
      || !Number.isInteger(value.threshold) || value.threshold < 2 || value.threshold > value.members
      || !Number.isInteger(value.slot) || value.slot < 2 || value.slot > value.members) return null;
    return value;
  } catch { return null; }
}

export function paymentLabel(phase: string, ready: boolean, sending: boolean): string {
  if (phase === "confirmed") return "Confirmed";
  if (phase === "replaced") return "Replaced";
  if (phase === "spent_unverified") return "Input spent · payment unverified";
  if (phase === "awaiting_verification") return "Awaiting transaction verification";
  if (phase === "broadcast") return "Awaiting confirmation";
  if (phase === "expired") return "Expired";
  if (phase === "failed") return "Failed · not sent";
  if (phase === "discarding") return "Releasing reserved input";
  if (phase === "cancelled") return "Cancelled";
  if (sending) return "Sending";
  if (ready) return "Ready to send";
  const labels: Record<string, string> = {
    draft: "Draft", preparing: "Preparing payment", signing: "Collecting approvals",
    approved: "Approved · awaiting the signed transaction", not_selected: "Other members are signing",
    ready: "Signed · building the transaction", signed: "Signed · not sent yet",
  };
  return labels[phase] ?? "Status unavailable";
}

export function emptyHistoryText(lokiSigner: boolean): string {
  return lokiSigner
    ? "Outgoing payment requests and sent payments will appear here. Incoming deposits aren’t listed."
    : "Payments sent and received by this vault will appear here.";
}

// shortcut: status omits the viewer's slot; retain successful joins until the API exposes it.
export function rememberVaultSlot(profile: string | undefined, vault: string, slot: number) {
  if (!profile) return;
  try { localStorage.setItem(`loki_slot:${profile}:${vault}`, String(slot)); } catch {}
}

export function rememberedVaultSlot(profile: string | undefined, vault: string): number | null {
  if (!profile) return null;
  try {
    const slot = Number(localStorage.getItem(`loki_slot:${profile}:${vault}`));
    return Number.isInteger(slot) && slot >= 1 && slot <= 16 ? slot : null;
  } catch { return null; }
}

/** Whole seconds before a pairing link lapses, rounded up; 0 once expired. The coordinator
 *  keeps a reservation while `expires > now`, so the link is gone at `now === expires`. */
export function pairingSecondsLeft(expires: number, now: number): number {
  return expires > now ? Math.ceil((expires - now) / 1000) : 0;
}

/** Whether this member asks LokiSigner's dialog to agree to a roster. Only a member with
 *  LokiSigner's roster channel reports `roster_dialog` in its vault status (null while no dialog
 *  is open); a headless member paired with this tab does not, and agrees on the page's request,
 *  so the page shows it the code to compare as before. */
export function comparesInLokiSigner(status: object): boolean {
  return Object.hasOwn(status, "roster_dialog");
}

/** What a native member reads when LokiSigner recorded no agreement to a roster. `answered` is
 *  false when the request lost its connection before LokiSigner replied. The member's own error
 *  prefixes come from `agree` in core/src/host/ceremony.rs. */
export function nativeRosterRefusal(message: string, answered: boolean): string {
  if (!answered) return "This page lost its connection to LokiSigner. If its dialog is still open, answer it there; this page moves on once you choose Codes match.";
  if (message.startsWith("roster codes differ")) return "You chose Codes differ in LokiSigner, so it will not agree to this vault. Tell the creator and the other members: someone may have been swapped in. If you chose it by mistake, quit and reopen LokiSigner, pair this tab again, and compare once more.";
  if (message.startsWith("roster code not confirmed")) return "LokiSigner's dialog closed or timed out before you answered, so nothing was recorded. Choose Compare in LokiSigner again when every member is ready to compare.";
  if (message.startsWith("LokiSigner is already asking")) return "LokiSigner is already showing a roster code. Answer that dialog first.";
  if (message.startsWith("the vault setup changed while LokiSigner was asking")) return "The vault's members changed while LokiSigner was asking, so nothing was recorded. Choose Compare in LokiSigner again to see the new code, and compare it with every member again.";
  if (message === "roster code mismatch" || message === "roster fingerprint mismatch") return "The vault's members changed since this page loaded. Choose Compare in LokiSigner again to see the current code.";
  return `LokiSigner recorded no agreement: ${message}`;
}

/** What protects this signer's share, from its status `secure_element` and the signer kind. The
 *  in-browser signer reports `passkey`, or `software` for its passphrase tier; a native member
 *  reports `apple` (Secure Enclave) or `software` (the development backend). */
export function storageLabel(se: string | undefined, kind: "native" | "browser"): { enclave: boolean; label: string; detail: string } {
  if (se === "apple") return { enclave: true, label: "Enclave-protected wrapping key",
    detail: "The signer host’s Secure Enclave protects the unwrapping key. Your share enters process memory during signing; it is not hardware-contained FROST signing." };
  if (kind === "browser") {
    const by = se === "passkey" ? "passkey" : "passphrase";
    return { enclave: false, label: `Sealed under your ${by} in this browser`,
      detail: `Your share is sealed in the Loki signer’s own browser storage under your ${by}. It enters browser memory during signing, without hardware isolation.` };
  }
  if (se !== "software") return { enclave: false, label: "Share protection not reported",
    detail: "This signer did not report a recognized storage type. The wallet cannot tell how your share is protected." };
  return { enclave: false, label: "Software device storage", detail: "Software development signer: local sealed storage, without hardware isolation." };
}
