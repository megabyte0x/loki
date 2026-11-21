CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    owner INTEGER NOT NULL CHECK (owner BETWEEN 1 AND 3)
) STRICT;
CREATE TRIGGER metadata_no_update BEFORE UPDATE ON metadata
BEGIN SELECT RAISE(ABORT, 'immutable association'); END;
CREATE TRIGGER metadata_no_delete BEFORE DELETE ON metadata
BEGIN SELECT RAISE(ABORT, 'immutable association'); END;
CREATE TABLE config_versions (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    hash BLOB NOT NULL CHECK (length(hash) = 32)
) STRICT;
CREATE TABLE ciphertext_objects (
    hash BLOB PRIMARY KEY NOT NULL CHECK (length(hash) = 32),
    wire BLOB NOT NULL,
    length INTEGER NOT NULL CHECK (length BETWEEN 1024 AND 65536 AND length % 1024 = 0 AND length(wire) = length),
    UNIQUE (hash, length)
) STRICT;
CREATE TABLE logical_records (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    session BLOB CHECK (session IS NULL OR length(session) = 32),
    state TEXT NOT NULL CHECK (state = 'committed'),
    source_root BLOB NOT NULL REFERENCES ciphertext_objects(hash),
    PRIMARY KEY (vault, roster, sender, message_id)
) STRICT;
CREATE TRIGGER logical_records_scope BEFORE INSERT ON logical_records
WHEN NOT EXISTS (SELECT 1 FROM metadata WHERE vault=NEW.vault AND roster=NEW.roster AND owner=NEW.sender)
BEGIN SELECT RAISE(ABORT, 'outgoing association'); END;
CREATE TRIGGER logical_records_identity BEFORE UPDATE ON logical_records
BEGIN SELECT RAISE(ABORT, 'immutable logical record'); END;
CREATE TRIGGER ciphertext_objects_no_update BEFORE UPDATE ON ciphertext_objects
BEGIN SELECT RAISE(ABORT, 'immutable ciphertext'); END;
CREATE TABLE outgoing_recipients (
    vault BLOB NOT NULL,
    roster BLOB NOT NULL,
    sender INTEGER NOT NULL,
    message_id BLOB NOT NULL,
    recipient INTEGER NOT NULL CHECK (recipient BETWEEN 1 AND 3),
    transfer BLOB CHECK (transfer IS NULL OR length(transfer) = 32),
    root_hash BLOB NOT NULL REFERENCES ciphertext_objects(hash),
    state TEXT NOT NULL CHECK (state IN ('needs_route', 'pending')),
    PRIMARY KEY (vault, roster, sender, message_id, recipient),
    FOREIGN KEY (vault, roster, sender, message_id) REFERENCES logical_records(vault, roster, sender, message_id)
) STRICT;
CREATE TABLE required_objects (
    vault BLOB NOT NULL,
    roster BLOB NOT NULL,
    sender INTEGER NOT NULL,
    message_id BLOB NOT NULL,
    recipient INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 274),
    hash BLOB NOT NULL,
    length INTEGER NOT NULL,
    PRIMARY KEY (vault, roster, sender, message_id, recipient, hash),
    UNIQUE (vault, roster, sender, message_id, recipient, ordinal),
    FOREIGN KEY (vault, roster, sender, message_id, recipient) REFERENCES outgoing_recipients(vault, roster, sender, message_id, recipient),
    FOREIGN KEY (hash, length) REFERENCES ciphertext_objects(hash, length)
) STRICT;
CREATE TABLE upload_work (
    vault BLOB NOT NULL,
    roster BLOB NOT NULL,
    sender INTEGER NOT NULL,
    message_id BLOB NOT NULL,
    recipient INTEGER NOT NULL,
    hash BLOB NOT NULL,
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'acknowledged')),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    retry_at INTEGER NOT NULL CHECK (retry_at >= 0),
    PRIMARY KEY (vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox),
    FOREIGN KEY (vault, roster, sender, message_id, recipient, hash) REFERENCES required_objects(vault, roster, sender, message_id, recipient, hash)
) STRICT;
CREATE TABLE verified_receipts (
    vault BLOB NOT NULL,
    roster BLOB NOT NULL,
    sender INTEGER NOT NULL,
    message_id BLOB NOT NULL,
    recipient INTEGER NOT NULL,
    hash BLOB NOT NULL,
    relay_key BLOB NOT NULL,
    run BLOB NOT NULL,
    mailbox BLOB NOT NULL,
    length INTEGER NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    retention INTEGER NOT NULL CHECK (retention >= 0),
    receipt BLOB NOT NULL CHECK (length(receipt) BETWEEN 1 AND 4096),
    PRIMARY KEY (vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox),
    FOREIGN KEY (vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox) REFERENCES upload_work(vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox),
    FOREIGN KEY (hash, length) REFERENCES ciphertext_objects(hash, length)
) STRICT;
CREATE TABLE caller_requests (
    request_id BLOB PRIMARY KEY NOT NULL CHECK (length(request_id) = 32),
    intent_digest BLOB NOT NULL CHECK (length(intent_digest) = 32),
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    FOREIGN KEY (vault, roster, sender, message_id) REFERENCES logical_records(vault, roster, sender, message_id)
) STRICT;
CREATE TRIGGER caller_requests_no_update BEFORE UPDATE ON caller_requests
BEGIN SELECT RAISE(ABORT, 'immutable request'); END;
CREATE TRIGGER caller_requests_no_delete BEFORE DELETE ON caller_requests
BEGIN SELECT RAISE(ABORT, 'immutable request'); END;
CREATE TRIGGER outgoing_recipients_identity BEFORE UPDATE OF vault,roster,sender,message_id,recipient,transfer,root_hash ON outgoing_recipients
BEGIN SELECT RAISE(ABORT, 'immutable recipient'); END;
CREATE TRIGGER required_objects_no_update BEFORE UPDATE ON required_objects
BEGIN SELECT RAISE(ABORT, 'immutable requirement'); END;
CREATE TRIGGER required_objects_no_delete BEFORE DELETE ON required_objects
BEGIN SELECT RAISE(ABORT, 'immutable requirement'); END;
CREATE TRIGGER outgoing_recipients_no_delete BEFORE DELETE ON outgoing_recipients
BEGIN SELECT RAISE(ABORT, 'immutable recipient'); END;
CREATE TRIGGER logical_records_no_delete BEFORE DELETE ON logical_records
BEGIN SELECT RAISE(ABORT, 'immutable logical record'); END;
CREATE TRIGGER ciphertext_objects_no_delete BEFORE DELETE ON ciphertext_objects
BEGIN SELECT RAISE(ABORT, 'immutable ciphertext'); END;
CREATE TABLE upload_generation (
    vault BLOB NOT NULL,
    roster BLOB NOT NULL,
    sender INTEGER NOT NULL,
    message_id BLOB NOT NULL,
    recipient INTEGER NOT NULL,
    hash BLOB NOT NULL,
    relay_key BLOB NOT NULL,
    run BLOB NOT NULL,
    mailbox BLOB NOT NULL,
    descriptor_revision INTEGER NOT NULL CHECK (descriptor_revision > 0),
    append_revision INTEGER NOT NULL CHECK (append_revision > 0),
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    config_hash BLOB NOT NULL CHECK (length(config_hash) = 32),
    PRIMARY KEY (vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox),
    FOREIGN KEY (vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox) REFERENCES upload_work(vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox)
) STRICT;
CREATE TRIGGER upload_generation_identity BEFORE UPDATE OF vault, roster, sender, message_id, recipient, hash, relay_key, run, mailbox ON upload_generation
BEGIN SELECT RAISE(ABORT, 'immutable generation'); END;
CREATE TABLE delivery_completion (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    source_root BLOB NOT NULL CHECK (length(source_root) = 32),
    PRIMARY KEY (vault, roster, sender, message_id),
    FOREIGN KEY (vault, roster, sender, message_id) REFERENCES logical_records(vault, roster, sender, message_id),
    FOREIGN KEY (source_root) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER delivery_completion_no_update BEFORE UPDATE ON delivery_completion
BEGIN SELECT RAISE(ABORT, 'immutable completion'); END;
CREATE TRIGGER delivery_completion_no_delete BEFORE DELETE ON delivery_completion
BEGIN SELECT RAISE(ABORT, 'immutable completion'); END;
CREATE TABLE route_cursors (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (relay_key, run, mailbox)
) STRICT;
CREATE TRIGGER route_cursors_no_delete BEFORE DELETE ON route_cursors
BEGIN SELECT RAISE(ABORT, 'immutable cursor'); END;
CREATE TABLE incoming_journal (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    source_hash BLOB NOT NULL CHECK (length(source_hash) = 32),
    wire_length INTEGER NOT NULL CHECK (wire_length >= 0),
    receipt BLOB NOT NULL CHECK (length(receipt) <= 131072),
    disposition TEXT NOT NULL CHECK (disposition IN ('missing', 'cached', 'quarantine')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    body_digest BLOB CHECK (body_digest IS NULL OR length(body_digest) = 32),
    PRIMARY KEY (relay_key, run, mailbox, sequence)
) STRICT;
CREATE TRIGGER incoming_journal_no_delete BEFORE DELETE ON incoming_journal
BEGIN SELECT RAISE(ABORT, 'immutable journal'); END;
CREATE TRIGGER incoming_journal_capture BEFORE UPDATE OF relay_key, run, mailbox, sequence, source_hash, wire_length, receipt, reason ON incoming_journal
BEGIN SELECT RAISE(ABORT, 'immutable capture'); END;
CREATE TRIGGER incoming_journal_disposition BEFORE UPDATE OF disposition ON incoming_journal
WHEN NOT (OLD.disposition = 'missing' AND NEW.disposition IN ('cached', 'quarantine'))
BEGIN SELECT RAISE(ABORT, 'immutable disposition'); END;
CREATE TRIGGER incoming_journal_digest BEFORE UPDATE OF body_digest ON incoming_journal
WHEN NOT (OLD.body_digest IS NULL AND NEW.body_digest IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'immutable digest'); END;
CREATE TABLE pending_downloads (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    source_hash BLOB NOT NULL CHECK (length(source_hash) = 32),
    wire_length INTEGER NOT NULL CHECK (wire_length BETWEEN 1024 AND 65536 AND wire_length % 1024 = 0),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    retry_at INTEGER NOT NULL CHECK (retry_at >= 0),
    PRIMARY KEY (relay_key, run, mailbox, source_hash)
) STRICT;
CREATE TRIGGER pending_downloads_identity BEFORE UPDATE OF relay_key, run, mailbox, source_hash, wire_length ON pending_downloads
BEGIN SELECT RAISE(ABORT, 'immutable download'); END;
CREATE TABLE download_rejections (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    source_hash BLOB NOT NULL CHECK (length(source_hash) = 32),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    PRIMARY KEY (relay_key, run, mailbox, source_hash)
) STRICT;
CREATE TRIGGER download_rejections_no_update BEFORE UPDATE ON download_rejections
BEGIN SELECT RAISE(ABORT, 'immutable download rejection'); END;
CREATE TRIGGER download_rejections_no_delete BEFORE DELETE ON download_rejections
BEGIN SELECT RAISE(ABORT, 'immutable download rejection'); END;
CREATE TABLE transfer_groups (
    group_id BLOB PRIMARY KEY NOT NULL CHECK (length(group_id) = 32),
    claimed_transfer BLOB CHECK (claimed_transfer IS NULL OR length(claimed_transfer) = 32)
) STRICT;
CREATE TRIGGER transfer_groups_no_update BEFORE UPDATE ON transfer_groups
BEGIN SELECT RAISE(ABORT, 'immutable group'); END;
CREATE TRIGGER transfer_groups_no_delete BEFORE DELETE ON transfer_groups
BEGIN SELECT RAISE(ABORT, 'immutable group'); END;
CREATE TABLE staged_sources (
    root_hash BLOB PRIMARY KEY NOT NULL CHECK (length(root_hash) = 32),
    group_id BLOB CHECK (group_id IS NULL OR length(group_id) = 32),
    claimed_transfer BLOB CHECK (claimed_transfer IS NULL OR length(claimed_transfer) = 32),
    claimed_vault BLOB CHECK (claimed_vault IS NULL OR length(claimed_vault) = 32),
    claimed_roster BLOB CHECK (claimed_roster IS NULL OR length(claimed_roster) = 32),
    claimed_sender INTEGER CHECK (claimed_sender IS NULL OR claimed_sender BETWEEN 1 AND 3),
    claimed_message BLOB CHECK (claimed_message IS NULL OR length(claimed_message) = 32),
    CHECK ((claimed_vault IS NULL) = (claimed_roster IS NULL) AND (claimed_vault IS NULL) = (claimed_sender IS NULL) AND (claimed_vault IS NULL) = (claimed_message IS NULL)),
    FOREIGN KEY (group_id) REFERENCES transfer_groups(group_id)
) STRICT;
CREATE TRIGGER staged_sources_no_delete BEFORE DELETE ON staged_sources
BEGIN SELECT RAISE(ABORT, 'immutable source'); END;
CREATE TRIGGER staged_sources_identity BEFORE UPDATE OF root_hash, claimed_transfer, claimed_vault, claimed_roster, claimed_sender, claimed_message ON staged_sources
BEGIN SELECT RAISE(ABORT, 'immutable source'); END;
CREATE TRIGGER staged_sources_group BEFORE UPDATE OF group_id ON staged_sources
WHEN NOT (OLD.group_id IS NULL AND NEW.group_id IS NOT NULL)
BEGIN SELECT RAISE(ABORT, 'immutable group link'); END;
CREATE TABLE staged_requirements (
    root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 274),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    wire_length INTEGER NOT NULL CHECK (wire_length BETWEEN 1024 AND 65536 AND wire_length % 1024 = 0),
    PRIMARY KEY (root_hash, ordinal),
    UNIQUE (root_hash, hash),
    FOREIGN KEY (root_hash) REFERENCES staged_sources(root_hash)
) STRICT;
CREATE TRIGGER staged_requirements_no_update BEFORE UPDATE ON staged_requirements
BEGIN SELECT RAISE(ABORT, 'immutable staged requirement'); END;
CREATE TRIGGER staged_requirements_no_delete BEFORE DELETE ON staged_requirements
BEGIN SELECT RAISE(ABORT, 'immutable staged requirement'); END;
CREATE TABLE staged_coverage (
    root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    PRIMARY KEY (root_hash, relay_key, run, mailbox, sequence),
    FOREIGN KEY (root_hash) REFERENCES staged_sources(root_hash),
    FOREIGN KEY (relay_key, run, mailbox, sequence) REFERENCES incoming_journal(relay_key, run, mailbox, sequence)
) STRICT;
CREATE TRIGGER staged_coverage_no_update BEFORE UPDATE ON staged_coverage
BEGIN SELECT RAISE(ABORT, 'immutable coverage'); END;
CREATE TRIGGER staged_coverage_no_delete BEFORE DELETE ON staged_coverage
BEGIN SELECT RAISE(ABORT, 'immutable coverage'); END;
CREATE TABLE source_rejections (
    root_hash BLOB PRIMARY KEY NOT NULL CHECK (length(root_hash) = 32),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    body_digest BLOB CHECK (body_digest IS NULL OR length(body_digest) = 32),
    FOREIGN KEY (root_hash) REFERENCES staged_sources(root_hash)
) STRICT;
CREATE TRIGGER source_rejections_no_update BEFORE UPDATE ON source_rejections
BEGIN SELECT RAISE(ABORT, 'immutable source rejection'); END;
CREATE TRIGGER source_rejections_no_delete BEFORE DELETE ON source_rejections
BEGIN SELECT RAISE(ABORT, 'immutable source rejection'); END;
CREATE TABLE incoming_originals (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    session BLOB CHECK (session IS NULL OR length(session) = 32),
    source_root BLOB NOT NULL CHECK (length(source_root) = 32),
    PRIMARY KEY (vault, roster, sender, message_id),
    FOREIGN KEY (source_root) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER incoming_originals_no_update BEFORE UPDATE ON incoming_originals
BEGIN SELECT RAISE(ABORT, 'immutable original'); END;
CREATE TRIGGER incoming_originals_no_delete BEFORE DELETE ON incoming_originals
BEGIN SELECT RAISE(ABORT, 'immutable original'); END;
CREATE TABLE incoming_original_objects (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 274),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    wire_length INTEGER NOT NULL CHECK (wire_length BETWEEN 1024 AND 65536 AND wire_length % 1024 = 0),
    PRIMARY KEY (vault, roster, sender, message_id, ordinal),
    UNIQUE (vault, roster, sender, message_id, hash),
    FOREIGN KEY (vault, roster, sender, message_id) REFERENCES incoming_originals(vault, roster, sender, message_id),
    FOREIGN KEY (hash, wire_length) REFERENCES ciphertext_objects(hash, length)
) STRICT;
CREATE TRIGGER incoming_original_objects_no_update BEFORE UPDATE ON incoming_original_objects
BEGIN SELECT RAISE(ABORT, 'immutable original object'); END;
CREATE TRIGGER incoming_original_objects_no_delete BEFORE DELETE ON incoming_original_objects
BEGIN SELECT RAISE(ABORT, 'immutable original object'); END;
CREATE TABLE incoming_application (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    PRIMARY KEY (vault, roster, sender, message_id),
    FOREIGN KEY (vault, roster, sender, message_id) REFERENCES incoming_originals(vault, roster, sender, message_id)
) STRICT;
CREATE TRIGGER incoming_application_no_update BEFORE UPDATE ON incoming_application
BEGIN SELECT RAISE(ABORT, 'immutable application'); END;
CREATE TRIGGER incoming_application_no_delete BEFORE DELETE ON incoming_application
BEGIN SELECT RAISE(ABORT, 'immutable application'); END;
CREATE TABLE incoming_dependencies (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    prerequisite_sender INTEGER NOT NULL CHECK (prerequisite_sender BETWEEN 1 AND 3),
    prerequisite BLOB NOT NULL CHECK (length(prerequisite) = 32),
    prerequisite_digest BLOB NOT NULL CHECK (length(prerequisite_digest) = 32),
    prerequisite_source BLOB CHECK (prerequisite_source IS NULL OR length(prerequisite_source) = 32),
    PRIMARY KEY (vault, roster, sender, message_id, prerequisite_sender, prerequisite, prerequisite_digest),
    FOREIGN KEY (prerequisite_source) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER incoming_dependencies_no_update BEFORE UPDATE ON incoming_dependencies
BEGIN SELECT RAISE(ABORT, 'immutable dependency'); END;
CREATE TRIGGER incoming_dependencies_no_delete BEFORE DELETE ON incoming_dependencies
BEGIN SELECT RAISE(ABORT, 'immutable dependency'); END;
CREATE TABLE ack_links (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    ack_author INTEGER NOT NULL CHECK (ack_author BETWEEN 1 AND 3),
    ack_message BLOB NOT NULL CHECK (length(ack_message) = 32),
    request_id BLOB NOT NULL CHECK (length(request_id) = 32),
    PRIMARY KEY (vault, roster, sender, message_id, digest, ack_author),
    FOREIGN KEY (vault, roster, ack_author, ack_message) REFERENCES logical_records(vault, roster, sender, message_id),
    FOREIGN KEY (request_id) REFERENCES caller_requests(request_id)
) STRICT;
CREATE TRIGGER ack_links_no_update BEFORE UPDATE ON ack_links
BEGIN SELECT RAISE(ABORT, 'immutable ack link'); END;
CREATE TRIGGER ack_links_no_delete BEFORE DELETE ON ack_links
BEGIN SELECT RAISE(ABORT, 'immutable ack link'); END;
CREATE TABLE early_received_refs (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    session BLOB CHECK (session IS NULL OR length(session) = 32),
    from_member INTEGER NOT NULL CHECK (from_member BETWEEN 1 AND 3),
    source_root BLOB NOT NULL CHECK (length(source_root) = 32),
    PRIMARY KEY (vault, roster, sender, message_id, digest, from_member),
    FOREIGN KEY (source_root) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER early_received_refs_no_update BEFORE UPDATE ON early_received_refs
BEGIN SELECT RAISE(ABORT, 'immutable received reference'); END;
CREATE TRIGGER early_received_refs_no_delete BEFORE DELETE ON early_received_refs
BEGIN SELECT RAISE(ABORT, 'immutable received reference'); END;
CREATE TABLE incoming_conflicts (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    source_root BLOB NOT NULL CHECK (length(source_root) = 32),
    PRIMARY KEY (vault, roster, sender, message_id, digest),
    FOREIGN KEY (source_root) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER incoming_conflicts_no_update BEFORE UPDATE ON incoming_conflicts
BEGIN SELECT RAISE(ABORT, 'immutable conflict'); END;
CREATE TRIGGER incoming_conflicts_no_delete BEFORE DELETE ON incoming_conflicts
BEGIN SELECT RAISE(ABORT, 'immutable conflict'); END;
CREATE TABLE incoming_conflict_objects (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 274),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    wire_length INTEGER NOT NULL CHECK (wire_length BETWEEN 1024 AND 65536 AND wire_length % 1024 = 0),
    PRIMARY KEY (vault, roster, sender, message_id, digest, ordinal),
    UNIQUE (vault, roster, sender, message_id, digest, hash),
    FOREIGN KEY (vault, roster, sender, message_id, digest) REFERENCES incoming_conflicts(vault, roster, sender, message_id, digest),
    FOREIGN KEY (hash, wire_length) REFERENCES ciphertext_objects(hash, length)
) STRICT;
CREATE TRIGGER incoming_conflict_objects_no_update BEFORE UPDATE ON incoming_conflict_objects
BEGIN SELECT RAISE(ABORT, 'immutable conflict object'); END;
CREATE TRIGGER incoming_conflict_objects_no_delete BEFORE DELETE ON incoming_conflict_objects
BEGIN SELECT RAISE(ABORT, 'immutable conflict object'); END;
CREATE TABLE reference_rejections (
    vault BLOB NOT NULL CHECK (length(vault) = 32),
    roster BLOB NOT NULL CHECK (length(roster) = 32),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    message_id BLOB NOT NULL CHECK (length(message_id) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    from_member INTEGER NOT NULL CHECK (from_member BETWEEN 1 AND 3),
    source_root BLOB CHECK (source_root IS NULL OR length(source_root) = 32),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    PRIMARY KEY (vault, roster, sender, message_id, digest, from_member),
    FOREIGN KEY (source_root) REFERENCES ciphertext_objects(hash)
) STRICT;
CREATE TRIGGER reference_rejections_no_update BEFORE UPDATE ON reference_rejections
BEGIN SELECT RAISE(ABORT, 'immutable reference rejection'); END;
CREATE TRIGGER reference_rejections_no_delete BEFORE DELETE ON reference_rejections
BEGIN SELECT RAISE(ABORT, 'immutable reference rejection'); END;
CREATE TABLE quarantine_samples (
    id INTEGER PRIMARY KEY,
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    sample BLOB NOT NULL CHECK (length(sample) BETWEEN 1 AND 4096),
    FOREIGN KEY (relay_key, run, mailbox, sequence) REFERENCES incoming_journal(relay_key, run, mailbox, sequence)
) STRICT;
CREATE TRIGGER quarantine_samples_bound BEFORE INSERT ON quarantine_samples
WHEN (SELECT count(*) FROM quarantine_samples) >= 1024
    OR (SELECT coalesce(sum(length(sample)), 0) FROM quarantine_samples) + length(NEW.sample) > 8388608
BEGIN SELECT RAISE(ABORT, 'diagnostic sample bound'); END;
CREATE TABLE route_capture (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    attempts INTEGER NOT NULL CHECK (attempts >= 0),
    retry_at INTEGER NOT NULL CHECK (retry_at >= 0),
    isolated INTEGER NOT NULL CHECK (isolated IN (0, 1)),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 64),
    config_revision INTEGER CHECK (config_revision IS NULL OR config_revision > 0),
    config_hash BLOB CHECK (config_hash IS NULL OR length(config_hash) = 32),
    CHECK ((config_revision IS NULL) = (config_hash IS NULL)),
    CHECK (isolated = 0 OR reason IS NOT NULL),
    PRIMARY KEY (relay_key, run, mailbox)
) STRICT;
CREATE TRIGGER route_capture_no_delete BEFORE DELETE ON route_capture
BEGIN SELECT RAISE(ABORT, 'retained capture route'); END;
CREATE TRIGGER route_capture_isolation BEFORE UPDATE OF isolated ON route_capture
WHEN OLD.isolated = 1 AND NEW.isolated != 1
BEGIN SELECT RAISE(ABORT, 'retained capture isolation'); END;
CREATE TABLE download_auth_wait (
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    source_hash BLOB NOT NULL CHECK (length(source_hash) = 32),
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    config_hash BLOB NOT NULL CHECK (length(config_hash) = 32),
    PRIMARY KEY (relay_key, run, mailbox, source_hash),
    FOREIGN KEY (relay_key, run, mailbox, source_hash) REFERENCES pending_downloads(relay_key, run, mailbox, source_hash)
) STRICT;
CREATE TRIGGER download_auth_wait_identity BEFORE UPDATE OF relay_key, run, mailbox, source_hash ON download_auth_wait
BEGIN SELECT RAISE(ABORT, 'immutable download auth'); END;
CREATE TABLE page_diagnostics (
    id INTEGER PRIMARY KEY,
    relay_key BLOB NOT NULL CHECK (length(relay_key) = 32),
    run BLOB NOT NULL CHECK (length(run) = 32),
    mailbox BLOB NOT NULL CHECK (length(mailbox) = 32),
    sample BLOB NOT NULL CHECK (length(sample) BETWEEN 1 AND 4096)
) STRICT;
CREATE TABLE diagnostic_ids (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_id INTEGER NOT NULL CHECK (next_id > 0)
) STRICT;
CREATE TRIGGER diagnostic_ids_no_delete BEFORE DELETE ON diagnostic_ids
BEGIN SELECT RAISE(ABORT, 'retained diagnostic order'); END;
CREATE TRIGGER diagnostic_ids_advance BEFORE UPDATE OF next_id ON diagnostic_ids
WHEN NEW.singleton != 1 OR NEW.next_id <= OLD.next_id
BEGIN SELECT RAISE(ABORT, 'diagnostic id order'); END;
CREATE TRIGGER quarantine_samples_id BEFORE INSERT ON quarantine_samples
WHEN NEW.id IS NULL OR NEW.id <= 0 OR NEW.id >= (SELECT next_id FROM diagnostic_ids)
BEGIN SELECT RAISE(ABORT, 'diagnostic id'); END;
CREATE TRIGGER page_diagnostics_id BEFORE INSERT ON page_diagnostics
WHEN NEW.id IS NULL OR NEW.id <= 0 OR NEW.id >= (SELECT next_id FROM diagnostic_ids)
BEGIN SELECT RAISE(ABORT, 'diagnostic id'); END;
CREATE TRIGGER quarantine_samples_shared BEFORE INSERT ON quarantine_samples
WHEN (SELECT count(*) FROM quarantine_samples) + (SELECT count(*) FROM page_diagnostics) >= 1024
    OR (SELECT coalesce(sum(length(sample)), 0) FROM quarantine_samples)
        + (SELECT coalesce(sum(length(sample)), 0) FROM page_diagnostics)
        + length(NEW.sample) > 8388608
BEGIN SELECT RAISE(ABORT, 'diagnostic sample bound'); END;
CREATE TRIGGER page_diagnostics_shared BEFORE INSERT ON page_diagnostics
WHEN (SELECT count(*) FROM quarantine_samples) + (SELECT count(*) FROM page_diagnostics) >= 1024
    OR (SELECT coalesce(sum(length(sample)), 0) FROM quarantine_samples)
        + (SELECT coalesce(sum(length(sample)), 0) FROM page_diagnostics)
        + length(NEW.sample) > 8388608
BEGIN SELECT RAISE(ABORT, 'diagnostic sample bound'); END;
CREATE TABLE incomplete_leases (
    group_id BLOB PRIMARY KEY NOT NULL REFERENCES transfer_groups(group_id),
    sender INTEGER NOT NULL CHECK (sender BETWEEN 1 AND 3),
    expires_ms INTEGER NOT NULL CHECK (expires_ms > 0)
) STRICT;
CREATE INDEX staged_by_group ON staged_sources(group_id);
CREATE INDEX staged_by_requirement ON staged_requirements(hash);
CREATE INDEX received_by_target ON incoming_dependencies(vault,roster,prerequisite_sender,prerequisite,prerequisite_digest,sender,message_id);
CREATE TABLE received_work (
    incoming INTEGER NOT NULL CHECK (incoming IN (0,1)),
    source INTEGER NOT NULL CHECK (source > 0),
    PRIMARY KEY (incoming, source)
) STRICT;
CREATE TRIGGER received_incoming_work AFTER INSERT ON incoming_originals
WHEN NEW.kind=2 BEGIN INSERT INTO received_work(incoming,source) VALUES(1,NEW.rowid); END;
CREATE TRIGGER received_local_work AFTER INSERT ON ack_links
BEGIN INSERT INTO received_work(incoming,source) VALUES(0,NEW.rowid); END;
