// Shared domain types mirroring the backend contract.

export type VaultSummary = {
  vault: string;
  name: string;
  policy?: string;
  members: number;
  threshold: number;
  // False while the vault is still in setup (no DKG key yet, so no address).
  active?: boolean;
};

export type StatusResponse = {
  phase: "new_profile" | "locked" | "home";
  network?: string;
  // Share encryption on the signer host: Enclave wrapping key or software sealing.
  secure_element?: "apple" | "software" | string;
  profile?: { name: string; id: string };
  vaults?: VaultSummary[];
  // In-browser signer: whether the browser granted persistent storage (null: not asked yet),
  // and the frostd relay the signer origin logs in to.
  persisted?: boolean | null;
  relay?: string;
};

export type InviteSlot = { slot: number; code: string; joined: boolean };

export type CeremonyStatus = {
  phase:
    | "waiting_for_members"
    | "compare_roster"
    | "creating_keys"
    | "back_up"
    | "waiting_for_backups"
    | "final_backup"
    | "connecting_relays"
    | "setup_interrupted"
    | "active";
  fingerprint?: string;
  // The 24-digit roster code the member's own signer derives; agree must echo the one shown.
  roster_code?: string | null;
  // LokiSigner's roster dialog for this vault (native members only): open, or the member chose
  // "Codes differ" and it refuses the vault until it restarts.
  roster_dialog?: "open" | "codes_differ" | null;
  invites?: InviteSlot[];
  // The creator counts all confirmations; a joining device records its own confirmation.
  confirmations?: number;
  confirmed?: boolean;
  error?: string;
  members: number;
  threshold: number;
};

/** The stuck payment a replacement request replaces; it spends the same note. */
export type Replaces = { attempt: string; cancel: boolean };

export type ChainProvenance = { chain_trust?: "provider_reported" };

export type Payment = {
  attempt: string;
  phase: string;
  proposer?: number;
  recipient: string;
  amount_zat: string;
  approvals?: number[];
  approval_requested?: boolean;
  can_discard?: boolean;
  can_dismiss?: boolean;
  // This member holds the signed transaction and can send it, or send it again.
  can_send?: boolean;
  sending?: boolean;
  // The payment looks stuck: any member may replace it by spending the same note.
  can_replace?: boolean;
  replaces?: Replaces | null;
  spent_by?: string | null;
  error?: string | null;
  txid?: string | null;
  direction?: "sent" | "received";
  amount_is_net?: boolean;
  mined_height?: number | null;
  fee_zat?: string | null;
  signers?: number[];
};

export type PaymentSession = ChainProvenance & {
  phase: string;
  signatures_received: boolean;
  txid?: string | null;
  spent_by?: string | null;
  replaces?: Replaces | null;
  approvals: number[];
  approval_requested: boolean;
  error?: string | null;
  intent: {
    proposer: number;
    signers: number[];
    recipient: string;
    amount_zat: number;
    fee_zat: number;
    open_approval: boolean;
  };
};

export type PaymentReview = {
  review_token: string;
  // Hash of the terms shown; a native member approves only with the hash it reviewed.
  intent_hash?: string;
  recipient: string;
  amount_zat: string;
  fee_zat: string;
  memo: string;
  // The terms of the replaced payment, when this member holds it.
  replaces?: (Replaces & { phase?: string | null; recipient?: string | null; amount_zat?: string | null }) | null;
};
