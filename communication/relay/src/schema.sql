CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    protocol_version INTEGER NOT NULL CHECK (protocol_version = 1),
    run_id BLOB NOT NULL CHECK (typeof(run_id) = 'blob' AND length(run_id) = 32),
    receipt_public_key BLOB NOT NULL CHECK (typeof(receipt_public_key) = 'blob' AND length(receipt_public_key) = 32),
    provisioning_verifier BLOB NOT NULL CHECK (typeof(provisioning_verifier) = 'blob' AND length(provisioning_verifier) = 32),
    total_bytes INTEGER NOT NULL CHECK (typeof(total_bytes) = 'integer' AND total_bytes >= 0),
    mailbox_bytes INTEGER NOT NULL CHECK (typeof(mailbox_bytes) = 'integer' AND mailbox_bytes >= 0),
    mailbox_count INTEGER NOT NULL CHECK (typeof(mailbox_count) = 'integer' AND mailbox_count >= 0),
    used_bytes INTEGER NOT NULL CHECK (typeof(used_bytes) = 'integer' AND used_bytes >= 0 AND used_bytes <= total_bytes)
) STRICT;

-- Mailbox schema is installed transactionally on first provisioning, including existing roots.
CREATE TABLE IF NOT EXISTS mailboxes (
    id BLOB PRIMARY KEY NOT NULL CHECK (typeof(id) = 'blob' AND length(id) = 32),
    read_verifier BLOB NOT NULL CHECK (typeof(read_verifier) = 'blob' AND length(read_verifier) = 32),
    append_verifier BLOB NOT NULL CHECK (typeof(append_verifier) = 'blob' AND length(append_verifier) = 32),
    admin_verifier BLOB NOT NULL CHECK (typeof(admin_verifier) = 'blob' AND length(admin_verifier) = 32),
    creation_request BLOB NOT NULL,
    append_revision INTEGER NOT NULL CHECK (append_revision > 0),
    append_update BLOB,
    byte_quota INTEGER NOT NULL CHECK (byte_quota >= 0),
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0 AND used_bytes <= byte_quota),
    next_sequence INTEGER NOT NULL CHECK (next_sequence > 0)
) STRICT;

-- Object schema is installed after mailbox authentication, including existing roots.
CREATE TABLE IF NOT EXISTS objects (
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    wire BLOB NOT NULL,
    wire_length INTEGER NOT NULL CHECK (wire_length >= 1024 AND wire_length <= 65536 AND wire_length % 1024 = 0 AND length(wire) = wire_length),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    receipt BLOB NOT NULL,
    PRIMARY KEY (mailbox, hash),
    UNIQUE (mailbox, sequence),
    FOREIGN KEY (mailbox) REFERENCES mailboxes(id)
) STRICT;

-- First-writer-wins nonce claims survive relay restarts for the lifetime of this root.
CREATE TABLE IF NOT EXISTS nonce_uses (
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    cid BLOB NOT NULL CHECK (length(cid) = 32),
    record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
    wire BLOB NOT NULL CHECK (length(wire) > 0 AND length(wire) <= 65536),
    PRIMARY KEY (mailbox, cid),
    FOREIGN KEY (mailbox) REFERENCES mailboxes(id)
) STRICT;

-- Even an older binary pointed at an enrolled root must not issue a fresh legacy receipt.
CREATE TRIGGER IF NOT EXISTS nonce_uses_read_only BEFORE INSERT ON nonce_uses
BEGIN
    SELECT RAISE(ABORT, 'legacy nonce ledger is read-only');
END;

CREATE TABLE IF NOT EXISTS nonce_claimants (
    mailbox BLOB NOT NULL REFERENCES mailboxes(id),
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    slot INTEGER NOT NULL CHECK (slot BETWEEN 1 AND 65535),
    signing_key BLOB NOT NULL CHECK (length(signing_key) = 32),
    quota INTEGER NOT NULL CHECK (quota > 0),
    used_bytes INTEGER NOT NULL CHECK (used_bytes BETWEEN 0 AND quota),
    PRIMARY KEY (mailbox, vault, slot)
) STRICT;

CREATE TABLE IF NOT EXISTS nonce_claims (
    mailbox BLOB NOT NULL,
    vault BLOB NOT NULL,
    slot INTEGER NOT NULL,
    cid BLOB NOT NULL CHECK (length(cid) = 32),
    record_hash BLOB NOT NULL CHECK (length(record_hash) = 32),
    wire BLOB NOT NULL CHECK (length(wire) BETWEEN 1 AND 65536),
    PRIMARY KEY (mailbox, vault, slot, cid),
    FOREIGN KEY (mailbox, vault, slot) REFERENCES nonce_claimants(mailbox, vault, slot)
) STRICT, WITHOUT ROWID;
