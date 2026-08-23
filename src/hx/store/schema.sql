-- src/hx/store/schema.sql
-- All timestamps are integer microseconds since epoch.

CREATE TABLE IF NOT EXISTS engagement (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  client       TEXT NOT NULL,
  created_us   INTEGER NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('active','sealed','archived')),
  config_path  TEXT
);

-- Exactly one engagement per database: the engagement is the unit of
-- isolation (spec S3), and `quarantine` and every unqualified `open_()`
-- lookup presume a single authoritative row. Without this, a second INSERT
-- is accepted silently and which client the store believes it holds becomes
-- arbitrary.
CREATE TRIGGER IF NOT EXISTS trg_engagement_singleton
BEFORE INSERT ON engagement
WHEN (SELECT COUNT(*) FROM engagement) > 0
BEGIN
  SELECT RAISE(ABORT, 'only one engagement row is permitted per database');
END;

-- Append-only. Never UPDATE a row here: "what was in scope when request X was
-- issued" is the query that matters under dispute.
CREATE TABLE IF NOT EXISTS scope_version (
  id                TEXT PRIMARY KEY,
  engagement_id     TEXT NOT NULL REFERENCES engagement(id),
  yaml              TEXT NOT NULL,
  sha256            TEXT NOT NULL,
  effective_from_us INTEGER NOT NULL,
  author            TEXT NOT NULL,
  reason            TEXT
);

CREATE TABLE IF NOT EXISTS authorization (
  id            TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL REFERENCES engagement(id),
  doc_blob      TEXT,
  doc_sha256    TEXT,
  signatory     TEXT,
  valid_from_us INTEGER,
  valid_to_us   INTEGER,
  scope_sha256  TEXT
);

CREATE TABLE IF NOT EXISTS run (
  id               TEXT PRIMARY KEY,
  engagement_id    TEXT NOT NULL REFERENCES engagement(id),
  kind             TEXT NOT NULL CHECK (kind IN ('manual','scheduled','retest')),
  safety_profile   TEXT NOT NULL CHECK (safety_profile IN ('production','staging')),
  scope_version_id TEXT REFERENCES scope_version(id),
  started_us       INTEGER NOT NULL,
  ended_us         INTEGER,
  status           TEXT NOT NULL
                   CHECK (status IN ('running','completed','aborted','killed','error')),
  stop_reason      TEXT,
  heartbeat_us     INTEGER,
  requests_issued  INTEGER NOT NULL DEFAULT 0,
  dropped_total    INTEGER NOT NULL DEFAULT 0
);

-- Surface identity is the TEMPLATE. /order/1..9999 is one surface, not 9999.
CREATE TABLE IF NOT EXISTS surface (
  id                  TEXT PRIMARY KEY,
  engagement_id       TEXT NOT NULL REFERENCES engagement(id),
  method              TEXT NOT NULL,
  scheme              TEXT NOT NULL,
  host                TEXT NOT NULL,
  port                INTEGER NOT NULL,
  path_template       TEXT NOT NULL,
  query_key_set       TEXT NOT NULL DEFAULT '',
  kind                TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (kind IN ('idempotent_read','state_changing','unknown')),
  discovered_by       TEXT NOT NULL DEFAULT 'proxy'
                      CHECK (discovered_by IN ('proxy','crawl','import','agent')),
  normaliser_version  INTEGER NOT NULL DEFAULT 1,
  first_seen_run      TEXT REFERENCES run(id),
  last_seen_run       TEXT REFERENCES run(id),
  exemplar_exchange_id TEXT REFERENCES exchange(id),
  UNIQUE (engagement_id, method, scheme, host, port, path_template, query_key_set)
);

CREATE TABLE IF NOT EXISTS exchange (
  id                  TEXT PRIMARY KEY,
  run_id              TEXT REFERENCES run(id),
  surface_id          TEXT REFERENCES surface(id),
  action_id           TEXT,
  identity            TEXT,
  identity_generation INTEGER,
  identity_state      TEXT CHECK (identity_state IN ('proven','assumed','dead')),
  via                 TEXT NOT NULL CHECK (via IN ('proxy','send','crawl')),
  outcome             TEXT NOT NULL
                      CHECK (outcome IN ('ok','timeout','conn_refused','dns_error',
                                         'tls_error','scope_denied','rate_limited',
                                         'bridge_lost','truncated',
                                         -- The exchange COMPLETED but its final
                                         -- status could not be read: a peer put
                                         -- more interim 1xx heads in front of the
                                         -- response than the scan tolerates.
                                         -- `status` then holds the conservative
                                         -- sentinel 599, so this value is the only
                                         -- thing separating that sentinel from a
                                         -- peer that genuinely answered 599.
                                         'status_unreadable')),
  sent_us             INTEGER NOT NULL,
  recv_us             INTEGER,
  method              TEXT NOT NULL,
  url                 TEXT NOT NULL,
  resolved_ip         TEXT,
  status              INTEGER,
  req_blob            TEXT,
  resp_blob           TEXT,
  resp_len            INTEGER,
  body_shed           INTEGER NOT NULL DEFAULT 0,
  scope_version_id    TEXT REFERENCES scope_version(id),
  seq                 INTEGER
);
CREATE INDEX IF NOT EXISTS idx_exchange_run  ON exchange(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_exchange_surf ON exchange(surface_id);

-- Records that a check RAN. Without this, "tested clean", "never reached",
-- "blocked" and "errored" are indistinguishable and reports lie.
CREATE TABLE IF NOT EXISTS check_run (
  id             TEXT PRIMARY KEY,
  run_id         TEXT NOT NULL REFERENCES run(id),
  surface_id     TEXT REFERENCES surface(id),
  insertion_name TEXT,
  check_id       TEXT NOT NULL,
  check_version  TEXT NOT NULL,
  started_us     INTEGER,
  ended_us       INTEGER,
  verdict        TEXT NOT NULL
                 CHECK (verdict IN ('pending','clean','finding','inconclusive',
                                    'skipped','error')),
  reason         TEXT,
  requests_sent  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_checkrun_run ON check_run(run_id, verdict);

CREATE TABLE IF NOT EXISTS finding (
  id                 TEXT PRIMARY KEY,
  engagement_id      TEXT NOT NULL REFERENCES engagement(id),
  dedupe_key         TEXT NOT NULL,
  issue_type_id      TEXT,
  title              TEXT NOT NULL,
  description        TEXT,
  impact             TEXT,
  remediation        TEXT,
  cwe                TEXT,
  references_json    TEXT,
  severity           TEXT NOT NULL
                     CHECK (severity IN ('Critical','High','Medium','Low','Info')),
  severity_source    TEXT,
  confidence         TEXT NOT NULL CHECK (confidence IN ('Certain','Firm','Tentative')),
  created_by         TEXT NOT NULL CHECK (created_by IN ('agent','human','check')),
  -- Cached projection of finding_status_event, the source of truth. Direct
  -- `UPDATE finding SET status=...` is deliberately left unguarded here --
  -- unlike the event log, this column is a read-optimisation, not the
  -- record of who changed what and when.
  status             TEXT NOT NULL
                     CHECK (status IN ('new','triaged','confirmed','false_positive','reported')),
  surface_id         TEXT REFERENCES surface(id),
  insertion_name     TEXT,
  insertion_kind     TEXT,
  host               TEXT,
  scope_level        TEXT NOT NULL
                     CHECK (scope_level IN ('engagement','host','surface','insertion')),
  payload            TEXT,
  normaliser_version INTEGER NOT NULL DEFAULT 1,
  first_seen_run     TEXT REFERENCES run(id),
  last_seen_run      TEXT REFERENCES run(id),
  UNIQUE (engagement_id, dedupe_key)
);

-- Presence per run as a SET, not a range: found in run 3, fixed in run 5,
-- reintroduced in run 7 must be expressible. That is the retest deliverable.
CREATE TABLE IF NOT EXISTS finding_observation (
  finding_id    TEXT NOT NULL REFERENCES finding(id),
  run_id        TEXT NOT NULL REFERENCES run(id),
  observed      INTEGER NOT NULL,
  exchange_id   TEXT REFERENCES exchange(id),
  severity_at   TEXT,
  confidence_at TEXT,
  ts_us         INTEGER NOT NULL,
  PRIMARY KEY (finding_id, run_id)
);

CREATE TABLE IF NOT EXISTS finding_status_event (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES finding(id),
  from_status TEXT,
  to_status   TEXT NOT NULL
               CHECK (to_status IN ('new','triaged','confirmed','false_positive','reported')),
  actor       TEXT NOT NULL CHECK (actor IN ('agent','human','check')),
  note        TEXT,
  ts_us       INTEGER NOT NULL
);

-- The agent may never confirm its own finding. Enforced by the database,
-- not by discipline. Covers both the initial INSERT and any later UPDATE
-- that tries to rewrite an existing event row into a confirmed/reported one
-- -- an UPDATE bypassed the INSERT-only version of this trigger entirely.
CREATE TRIGGER IF NOT EXISTS trg_agent_cannot_confirm
BEFORE INSERT ON finding_status_event
WHEN NEW.actor = 'agent' AND NEW.to_status IN ('confirmed','reported')
BEGIN
  SELECT RAISE(ABORT, 'agent may not set status confirmed or reported');
END;

CREATE TRIGGER IF NOT EXISTS trg_agent_cannot_confirm_update
BEFORE UPDATE ON finding_status_event
WHEN NEW.actor = 'agent' AND NEW.to_status IN ('confirmed','reported')
BEGIN
  SELECT RAISE(ABORT, 'agent may not set status confirmed or reported');
END;

-- scope_version is append-only: tamper-evidence for contract disputes.
CREATE TRIGGER IF NOT EXISTS trg_scope_version_no_update
BEFORE UPDATE ON scope_version
BEGIN
  SELECT RAISE(ABORT, 'scope_version is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_scope_version_no_delete
BEFORE DELETE ON scope_version
BEGIN
  SELECT RAISE(ABORT, 'scope_version is append-only');
END;

-- finding_status_event is append-only, same rationale as scope_version: it
-- is the audit trail of who changed a finding's status and when. An UPDATE
-- or DELETE here would let a status transition be silently rewritten after
-- the fact, including one that used to launder an agent-confirmed status
-- through a legitimate human INSERT and then UPDATE it back.
CREATE TRIGGER IF NOT EXISTS trg_finding_status_event_no_update
BEFORE UPDATE ON finding_status_event
BEGIN
  SELECT RAISE(ABORT, 'finding_status_event is append-only');
END;

CREATE TRIGGER IF NOT EXISTS trg_finding_status_event_no_delete
BEFORE DELETE ON finding_status_event
BEGIN
  SELECT RAISE(ABORT, 'finding_status_event is append-only');
END;

CREATE TABLE IF NOT EXISTS evidence (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES finding(id),
  seq         INTEGER NOT NULL,
  role        TEXT NOT NULL,
  kind        TEXT NOT NULL,
  exchange_id TEXT REFERENCES exchange(id),
  ref         TEXT,
  note        TEXT,
  captured_us INTEGER NOT NULL
);

-- Immutable, same rationale as finding_status_event: evidence is what a
-- disputed finding is proven with, and it must not be alterable after
-- capture.
CREATE TRIGGER IF NOT EXISTS trg_evidence_no_update
BEFORE UPDATE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_evidence_no_delete
BEFORE DELETE ON evidence
BEGIN
  SELECT RAISE(ABORT, 'evidence is immutable');
END;

CREATE TABLE IF NOT EXISTS agent_action (
  id             TEXT PRIMARY KEY,
  engagement_id  TEXT NOT NULL REFERENCES engagement(id),
  run_id         TEXT REFERENCES run(id),
  ts_us          INTEGER NOT NULL,
  actor          TEXT NOT NULL,
  tool           TEXT NOT NULL,
  args_blob      TEXT,
  result_summary TEXT,
  why            TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_run ON agent_action(run_id, ts_us);

CREATE TABLE IF NOT EXISTS denial (
  id               TEXT PRIMARY KEY,
  run_id           TEXT REFERENCES run(id),
  ts_us            INTEGER NOT NULL,
  kind             TEXT NOT NULL
                   CHECK (kind IN ('scope','method','dangerous','rate','budget',
                                   'not_configured')),
  method           TEXT,
  url              TEXT,
  resolved_ip      TEXT,
  reason           TEXT,
  scope_version_id TEXT REFERENCES scope_version(id)
);

-- Inbound traffic that did not match this engagement. Never silently
-- discarded, never allowed into `exchange`.
CREATE TABLE IF NOT EXISTS quarantine (
  id                    TEXT PRIMARY KEY,
  received_us           INTEGER NOT NULL,
  engagement_id_claimed TEXT,
  method                TEXT,
  url                   TEXT,
  reason                TEXT NOT NULL,
  raw_blob              TEXT
);
