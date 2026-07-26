CREATE TABLE members (
    list            TEXT NOT NULL,
    address         TEXT NOT NULL,
    -- 1 = subscriber (receives the list); 0 = not subscribed.
    subscribed      INTEGER NOT NULL DEFAULT 1,
    -- 1 = a moderator of the list (exposed to Sieve policies as the `moderators` list).
    moderator       INTEGER NOT NULL DEFAULT 0,
    -- Running bounce score; when it reaches the configured threshold, delivery is disabled.
    bounce_score    REAL NOT NULL DEFAULT 0,
    bounce_disabled INTEGER NOT NULL DEFAULT 0,
    last_bounce_at  INTEGER,
    PRIMARY KEY (list, address)
);

CREATE TABLE seen_messages (
    list       TEXT NOT NULL,
    message_id TEXT NOT NULL,
    seen_at    INTEGER NOT NULL,
    PRIMARY KEY (list, message_id)
);

CREATE TABLE moderation_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    list        TEXT NOT NULL,
    mail_from   TEXT NOT NULL,
    helo        TEXT NOT NULL,
    remote_ip   TEXT NOT NULL,
    sender      TEXT,
    subject     TEXT,
    raw         BLOB NOT NULL,
    received_at INTEGER NOT NULL
);
