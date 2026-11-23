CREATE TABLE IF NOT EXISTS setup_namespaces (
    mailbox BLOB PRIMARY KEY NOT NULL CHECK(length(mailbox)=32),
    creation_digest BLOB NOT NULL CHECK(length(creation_digest)=32),
    expires INTEGER NOT NULL CHECK(expires>0),
    retired INTEGER NOT NULL CHECK(retired IN(0,1))
) STRICT;
CREATE INDEX IF NOT EXISTS setup_namespaces_expiry ON setup_namespaces(retired, expires);
