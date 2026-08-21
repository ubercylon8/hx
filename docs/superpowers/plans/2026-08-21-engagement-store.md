# hx Engagement Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the per-engagement persistence layer — SQLite schema, content-addressed blob store, config, and the `hx new` / `hx info` CLI — so every later subsystem has somewhere durable and isolated to write.

**Architecture:** One directory per engagement, mode 0700, containing its own SQLite database, its own `blobs/` tree, and its own `config.yaml`. Nothing is shared between engagements — this is the structural guarantee that client A's bytes cannot reach client B's report. SQLite runs in WAL mode with exactly one writer connection; the blob store writes to a temp file, fsyncs, verifies the digest of what actually landed, then atomically renames.

**Tech Stack:** Python 3.12+ (3.14.7 available), `uv` for env management, stdlib `sqlite3`, `PyYAML`, `click` for CLI, `pytest`.

**Spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§3 Architecture, §5 Data model)

## Global Constraints

- Python 3.12 minimum; target the installed 3.14.7.
- Engagement directories are created mode `0o700`; blob and DB files `0o600`. Never looser.
- At every SQLite connection open: `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`. Foreign keys are OFF per-connection by default in SQLite — without this pragma none of the declared relationships are enforced.
- Exactly **one** writer connection per engagement, fed by an in-process queue. Readers use separate connections.
- All timestamps are integer microseconds since epoch, column suffix `_us`. Never floats, never strings.
- `dedupe_key` is one NOT NULL TEXT column; absent parts are the literal `-`, never `NULL`, because SQLite treats NULLs as distinct in a UNIQUE index and would silently defeat the constraint.
- No network access in this plan. Nothing here talks to Burp or to a target.

---

### Task 1: Project scaffold and the schema

**Files:**
- Create: `pyproject.toml`
- Create: `src/hx/__init__.py`
- Create: `src/hx/store/__init__.py`
- Create: `src/hx/store/schema.sql`
- Create: `src/hx/store/db.py`
- Test: `tests/test_db.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `hx.store.db.SCHEMA_VERSION: int`
  - `hx.store.db.connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection` — applies all required pragmas
  - `hx.store.db.init_schema(conn: sqlite3.Connection) -> None` — idempotent
  - `hx.store.db.TABLES: tuple[str, ...]` — the 14 table names, for tests and diagnostics

- [ ] **Step 1: Create the project scaffold**

```toml
# pyproject.toml
[project]
name = "hx"
version = "0.1.0"
description = "Agent-driven web application security assessment harness"
requires-python = ">=3.12"
dependencies = ["PyYAML>=6.0", "click>=8.1"]

[project.scripts]
hx = "hx.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/hx"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

```bash
mkdir -p src/hx/store tests
touch src/hx/__init__.py src/hx/store/__init__.py
uv venv .venv
uv pip install --python .venv/bin/python -e . pytest
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_db.py
import sqlite3
from pathlib import Path

import pytest

from hx.store import db


def test_connect_applies_required_pragmas(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_init_schema_creates_every_table(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    present = {
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert set(db.TABLES) <= present


def test_init_schema_is_idempotent(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    db.init_schema(conn)  # must not raise
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_readonly_connection_opens(tmp_path: Path):
    """journal_mode is a write; a readonly connection must not attempt it."""
    path = tmp_path / "hx.db"
    db.init_schema(db.connect(path))
    ro = db.connect(path, readonly=True)
    assert ro.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert ro.execute("SELECT COUNT(*) FROM engagement").fetchone()[0] == 0


def test_foreign_keys_are_actually_enforced(tmp_path: Path):
    """A declared FK is worthless if the pragma is off. Prove it bites."""
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us, status)"
            " VALUES('r1','NO_SUCH_ENGAGEMENT','manual','production',1,'running')"
        )


def test_dedupe_key_uniqueness_holds_per_engagement(tmp_path: Path):
    conn = db.connect(tmp_path / "hx.db")
    db.init_schema(conn)
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status)"
        " VALUES('e1','acme','Acme',1,'active')"
    )
    key = "sqli|https|app.acme.com|443|GET|/order/{n}|url_param|id"
    conn.execute(
        "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
        " confidence, created_by, status, scope_level)"
        " VALUES('f1','e1',?,'SQLi','High','Firm','agent','new','insertion')",
        (key,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding(id, engagement_id, dedupe_key, title, severity,"
            " confidence, created_by, status, scope_level)"
            " VALUES('f2','e1',?,'SQLi dup','High','Firm','agent','new','insertion')",
            (key,),
        )
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.store.db'`

- [ ] **Step 4: Write the schema**

```sql
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
  valid_from    INTEGER,
  valid_to      INTEGER,
  scope_sha256  TEXT
);

CREATE TABLE IF NOT EXISTS run (
  id               TEXT PRIMARY KEY,
  engagement_id    TEXT NOT NULL REFERENCES engagement(id),
  kind             TEXT NOT NULL CHECK (kind IN ('manual','scheduled','retest')),
  safety_profile   TEXT NOT NULL,
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
  first_seen_run      TEXT,
  last_seen_run       TEXT,
  exemplar_exchange_id TEXT,
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
                                         'bridge_lost','truncated')),
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
  first_seen_run     TEXT,
  last_seen_run      TEXT,
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
  to_status   TEXT NOT NULL,
  actor       TEXT NOT NULL CHECK (actor IN ('agent','human','check')),
  note        TEXT,
  ts_us       INTEGER NOT NULL
);

-- The agent may never confirm its own finding. Enforced by the database,
-- not by discipline.
CREATE TRIGGER IF NOT EXISTS trg_agent_cannot_confirm
BEFORE INSERT ON finding_status_event
WHEN NEW.actor = 'agent' AND NEW.to_status IN ('confirmed','reported')
BEGIN
  SELECT RAISE(ABORT, 'agent may not set status confirmed or reported');
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
```

- [ ] **Step 5: Write the minimal implementation**

```python
# src/hx/store/db.py
"""SQLite access for one engagement.

Every connection must apply the same pragmas. foreign_keys in particular is
OFF per-connection by default in SQLite, so a connection opened without it
silently ignores every REFERENCES clause in the schema.
"""
from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path

SCHEMA_VERSION = 1

TABLES: tuple[str, ...] = (
    "engagement",
    "scope_version",
    "authorization",
    "run",
    "surface",
    "exchange",
    "check_run",
    "finding",
    "finding_observation",
    "finding_status_event",
    "evidence",
    "agent_action",
    "denial",
    "quarantine",
)


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    if not readonly:
        # journal_mode is a write to the database header, so it raises
        # OperationalError on a read-only connection. The mode is a property
        # of the file, already set by the writer, so readers inherit it.
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _schema_sql() -> str:
    return resources.files("hx.store").joinpath("schema.sql").read_text(encoding="utf-8")


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_schema_sql())
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_db.py -v`
Expected: PASS, 6 passed

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/hx tests/test_db.py
git commit -m "feat(store): engagement schema with enforced FKs and agent-cannot-confirm trigger"
```

---

### Task 2: Content-addressed blob store

**Files:**
- Create: `src/hx/store/blobs.py`
- Test: `tests/test_blobs.py`

**Interfaces:**
- Consumes: nothing from Task 1
- Produces:
  - `hx.store.blobs.BlobStore(root: Path)`
  - `BlobStore.put(data: bytes) -> tuple[str, int]` — returns `(sha256_hex, length)`
  - `BlobStore.get(digest: str, expected_len: int | None = None) -> bytes`
  - `BlobStore.path_for(digest: str) -> Path`
  - `hx.store.blobs.CorruptBlob(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_blobs.py
from pathlib import Path

import pytest

from hx.store.blobs import BlobStore, CorruptBlob


def test_put_then_get_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"hello burp")
    assert length == 10
    assert store.get(digest) == b"hello burp"


def test_identical_content_stored_once(tmp_path: Path):
    store = BlobStore(tmp_path)
    d1, _ = store.put(b"same bytes")
    d2, _ = store.put(b"same bytes")
    assert d1 == d2
    assert sum(1 for p in tmp_path.rglob("*") if p.is_file()) == 1


def test_get_verifies_length(tmp_path: Path):
    store = BlobStore(tmp_path)
    digest, length = store.put(b"abcdef")
    with pytest.raises(CorruptBlob):
        store.get(digest, expected_len=999)


def test_truncated_blob_on_disk_is_detected(tmp_path: Path):
    """A torn write must fail loudly, not poison every future identical body."""
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"a" * 200)
    with pytest.raises(CorruptBlob):
        store.get(digest)


def test_put_repairs_a_same_length_corruption(tmp_path: Path):
    """The nastier torn write: same length, wrong bytes.

    A size-only dedupe check accepts this forever, so put() returns success
    while holding the correct bytes and the digest stays poisoned. put() must
    re-verify and repair.
    """
    store = BlobStore(tmp_path)
    digest, _ = store.put(b"a" * 500)
    store.path_for(digest).write_bytes(b"b" * 500)  # same length, wrong content

    again, length = store.put(b"a" * 500)
    assert again == digest and length == 500
    assert store.get(digest) == b"a" * 500, "put() did not repair the blob"


def test_large_blob_round_trips(tmp_path: Path):
    store = BlobStore(tmp_path)
    payload = bytes(range(256)) * 8000  # ~2 MB, larger than a Burp response
    digest, length = store.put(payload)
    assert length == len(payload)
    assert store.get(digest, expected_len=length) == payload


def test_no_temp_files_left_behind(tmp_path: Path):
    store = BlobStore(tmp_path)
    store.put(b"x" * 1000)
    assert list((tmp_path / "tmp").glob("*")) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_blobs.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.store.blobs'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/store/blobs.py
"""Content-addressed blob storage, scoped to one engagement.

Blobs are partitioned per engagement rather than globally. Cross-engagement
dedupe would save little at 320 req/s of mostly-distinct bodies, and it would
make contractual data destruction impossible to perform correctly: deleting
client A's data must not corrupt client B's evidence.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path


class CorruptBlob(Exception):
    """A blob's bytes do not match the digest or length they are stored under."""


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def path_for(self, digest: str) -> Path:
        return self.root / digest[:2] / digest[2:4] / digest

    def put(self, data: bytes) -> tuple[str, int]:
        digest = hashlib.sha256(data).hexdigest()
        final = self.path_for(digest)
        # Trusting st_size here is the bug the design warns about: a torn write
        # that happens to preserve length (bit rot, a zero-filled tail after a
        # crash) would be accepted forever, and put() would report success while
        # holding the correct bytes. Re-hash what is actually on disk; on any
        # mismatch fall through and repair it via the atomic path below.
        if final.exists():
            try:
                if hashlib.sha256(final.read_bytes()).hexdigest() == digest:
                    return digest, len(data)
            except OSError:
                pass  # unreadable: repair it

        final.parent.mkdir(parents=True, exist_ok=True)
        staging = self.tmp / f"{uuid.uuid4().hex}.part"
        with open(staging, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

        written = staging.read_bytes()
        if hashlib.sha256(written).hexdigest() != digest:
            staging.unlink(missing_ok=True)
            raise CorruptBlob(f"digest mismatch writing {digest}")

        os.replace(staging, final)
        os.chmod(final, 0o600)
        return digest, len(data)

    def get(self, digest: str, expected_len: int | None = None) -> bytes:
        path = self.path_for(digest)
        if not path.exists():
            raise CorruptBlob(f"blob {digest} missing")
        data = path.read_bytes()
        if expected_len is not None and len(data) != expected_len:
            raise CorruptBlob(
                f"blob {digest} length {len(data)} != expected {expected_len}"
            )
        if hashlib.sha256(data).hexdigest() != digest:
            raise CorruptBlob(f"blob {digest} failed digest verification")
        return data
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_blobs.py -v`
Expected: PASS, 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/store/blobs.py tests/test_blobs.py
git commit -m "feat(store): content-addressed blob store with atomic writes and verification"
```

---

### Task 3: Engagement config

**Files:**
- Create: `src/hx/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `hx.config.Config` dataclass with fields: `name: str`, `client: str`, `safety_profile: str`, `scope_include: list[str]`, `scope_exclude: list[str]`, `render_allow: list[str]`, `dangerous_paths: list[str]`, `checks: dict[str, bool]`, `rate_limit_rps: int`, `max_concurrency: int`, `identities: dict[str, dict]`, `preserve_segments: list[str]`, `slug_threshold: int`
  - `hx.config.load(path: Path) -> Config`
  - `hx.config.dumps(cfg: Config) -> str`
  - `hx.config.DEFAULT_DANGEROUS_PATHS: list[str]`
  - `hx.config.DEFAULT_CHECKS: dict[str, bool]`
  - `hx.config.VALID_PROFILES: tuple[str, ...]` — used by the CLI in Task 5
  - `hx.config.ConfigError(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from pathlib import Path

import pytest

from hx import config


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_minimal_config(tmp_path: Path):
    p = _write(
        tmp_path,
        """
name: acme-2026-09
client: Acme Corp
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.name == "acme-2026-09"
    assert cfg.client == "Acme Corp"
    assert cfg.scope_include == ["https://app.acme.com/*"]


def test_defaults_are_safe(tmp_path: Path):
    """Unspecified means safe: production profile, mutating checks off."""
    p = _write(
        tmp_path,
        """
name: acme
client: Acme
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.safety_profile == "production"
    assert cfg.checks["active_mutate"] is False
    assert cfg.checks["active_dos"] is False
    assert cfg.checks["passive"] is True
    assert cfg.rate_limit_rps <= 10
    assert "logout" in " ".join(cfg.dangerous_paths)


def test_empty_scope_include_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "name: acme\nclient: Acme\nscope:\n  include: []\n")
    with pytest.raises(config.ConfigError, match="scope.include"):
        config.load(p)


def test_missing_name_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "client: Acme\nscope:\n  include: ['https://a/*']\n")
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


def test_unknown_safety_profile_is_rejected(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nsafety_profile: yolo\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="safety_profile"):
        config.load(p)


def test_dumps_round_trips(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\n",
    )
    cfg = config.load(p)
    p2 = tmp_path / "again.yaml"
    p2.write_text(config.dumps(cfg), encoding="utf-8")
    assert config.load(p2) == cfg
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.config'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/config.py
"""Engagement configuration.

Defaults are chosen so that an under-specified config is a SAFE config: the
production profile, mutating and DoS checks off, a low rate limit. Anything
that increases blast radius must be written down explicitly, in the file,
where it is recorded and reviewable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_PROFILES = ("production", "staging")

DEFAULT_DANGEROUS_PATHS: list[str] = [
    "*/logout*",
    "*/signout*",
    "*/password*",
    "*/change-password*",
    "*/reset*",
    "*/delete*",
    "*/purge*",
    "*/deactivate*",
    "*/close-account*",
]

DEFAULT_CHECKS: dict[str, bool] = {
    "passive": True,
    "active_safe": True,
    "active_timing": True,
    "active_mutate": False,
    "active_dos": False,
}


class ConfigError(Exception):
    """The engagement config is missing something required, or is nonsense."""


@dataclass(frozen=True)
class Config:
    name: str
    client: str
    safety_profile: str = "production"
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    render_allow: list[str] = field(default_factory=list)
    dangerous_paths: list[str] = field(default_factory=lambda: list(DEFAULT_DANGEROUS_PATHS))
    checks: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CHECKS))
    rate_limit_rps: int = 5
    max_concurrency: int = 2
    identities: dict[str, dict] = field(default_factory=dict)
    preserve_segments: list[str] = field(default_factory=lambda: ["api", "v1", "v2", "v3"])
    slug_threshold: int = 12


def load(path: Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    for required in ("name", "client"):
        if not raw.get(required):
            raise ConfigError(f"config is missing required key: {required}")

    profile = raw.get("safety_profile", "production")
    if profile not in VALID_PROFILES:
        raise ConfigError(
            f"safety_profile must be one of {VALID_PROFILES}, got {profile!r}"
        )

    scope = raw.get("scope") or {}
    include = scope.get("include") or []
    if not include:
        raise ConfigError("scope.include must list at least one target pattern")

    checks = dict(DEFAULT_CHECKS)
    checks.update(raw.get("checks") or {})

    return Config(
        name=raw["name"],
        client=raw["client"],
        safety_profile=profile,
        scope_include=list(include),
        scope_exclude=list(scope.get("exclude") or []),
        render_allow=list(raw.get("render_allow") or []),
        dangerous_paths=list(raw.get("dangerous_paths") or DEFAULT_DANGEROUS_PATHS),
        checks=checks,
        rate_limit_rps=int(raw.get("rate_limit_rps", 5)),
        max_concurrency=int(raw.get("max_concurrency", 2)),
        identities=dict(raw.get("identities") or {}),
        preserve_segments=list(raw.get("preserve_segments") or ["api", "v1", "v2", "v3"]),
        slug_threshold=int(raw.get("slug_threshold", 12)),
    )


def dumps(cfg: Config) -> str:
    return yaml.safe_dump(
        {
            "name": cfg.name,
            "client": cfg.client,
            "safety_profile": cfg.safety_profile,
            "scope": {"include": cfg.scope_include, "exclude": cfg.scope_exclude},
            "render_allow": cfg.render_allow,
            "dangerous_paths": cfg.dangerous_paths,
            "checks": cfg.checks,
            "rate_limit_rps": cfg.rate_limit_rps,
            "max_concurrency": cfg.max_concurrency,
            "identities": cfg.identities,
            "preserve_segments": cfg.preserve_segments,
            "slug_threshold": cfg.slug_threshold,
        },
        sort_keys=False,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_config.py -v`
Expected: PASS, 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/config.py tests/test_config.py
git commit -m "feat(config): engagement config with safe-by-default values"
```

---

### Task 4: Engagement lifecycle and directory isolation

**Files:**
- Create: `src/hx/engagement.py`
- Test: `tests/test_engagement.py`

**Interfaces:**
- Consumes:
  - `hx.store.db.connect`, `hx.store.db.init_schema`
  - `hx.store.blobs.BlobStore`
  - `hx.config.Config`, `hx.config.load`, `hx.config.dumps`
- Produces:
  - `hx.engagement.Engagement` with attributes `id: str`, `root: Path`, `config: Config`, `db: sqlite3.Connection`, `blobs: BlobStore`
  - `hx.engagement.create(root: Path, cfg: Config, *, author: str) -> Engagement`
  - `hx.engagement.open_(root: Path) -> Engagement`
  - `hx.engagement.record_scope_version(eng: Engagement, *, author: str, reason: str) -> str` — returns the new `scope_version.id`
  - `hx.engagement.now_us() -> int`
  - `hx.engagement.EngagementError(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_engagement.py
import hashlib
import stat
from pathlib import Path

import pytest

from hx import config, engagement


def _cfg(name="acme-2026-09") -> config.Config:
    return config.Config(
        name=name, client="Acme Corp", scope_include=["https://app.acme.com/*"]
    )


def test_create_builds_isolated_directory(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    assert (eng.root / "hx.db").exists()
    assert (eng.root / "blobs").is_dir()
    assert (eng.root / "config.yaml").exists()
    assert (eng.root / "exports").is_dir()


def test_engagement_directory_is_not_world_readable(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    mode = stat.S_IMODE(eng.root.stat().st_mode)
    assert mode == 0o700, f"engagement dir mode {oct(mode)} leaks client data"


def test_create_writes_engagement_row_and_initial_scope_version(tmp_path: Path):
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    row = eng.db.execute("SELECT name, client, status FROM engagement").fetchone()
    assert row["name"] == "acme-2026-09"
    assert row["status"] == "active"
    sv = eng.db.execute("SELECT yaml, sha256, author FROM scope_version").fetchone()
    assert sv["author"] == "jimx"
    assert sv["sha256"] == hashlib.sha256(sv["yaml"].encode()).hexdigest()


def test_create_refuses_existing_directory(tmp_path: Path):
    engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    with pytest.raises(engagement.EngagementError, match="exists"):
        engagement.create(tmp_path / "acme", _cfg(), author="jimx")


def test_open_round_trips(tmp_path: Path):
    created = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    created.db.close()
    reopened = engagement.open_(tmp_path / "acme")
    assert reopened.id == created.id
    assert reopened.config.client == "Acme Corp"


def test_scope_versions_are_append_only(tmp_path: Path):
    """The query that matters under dispute is what was in scope at time T."""
    eng = engagement.create(tmp_path / "acme", _cfg(), author="jimx")
    first = eng.db.execute("SELECT id, sha256 FROM scope_version").fetchone()
    eng.config.scope_include.append("https://api.acme.com/*")
    second_id = engagement.record_scope_version(
        eng, author="jimx", reason="client added API host"
    )
    rows = eng.db.execute(
        "SELECT id, sha256 FROM scope_version ORDER BY effective_from_us"
    ).fetchall()
    assert len(rows) == 2
    assert rows[0]["id"] == first["id"]
    assert rows[0]["sha256"] == first["sha256"], "history was mutated"
    assert rows[1]["id"] == second_id


def test_two_engagements_share_nothing(tmp_path: Path):
    a = engagement.create(tmp_path / "acme", _cfg("acme"), author="jimx")
    b = engagement.create(tmp_path / "globex", _cfg("globex"), author="jimx")
    digest, _ = a.blobs.put(b"acme secret response")
    assert a.blobs.get(digest) == b"acme secret response"
    assert not b.blobs.path_for(digest).exists(), "blob leaked across engagements"
    assert a.root != b.root and a.id != b.id
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_engagement.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.engagement'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/engagement.py
"""Engagement lifecycle.

The engagement is the unit of isolation: its own directory, its own database,
its own blob tree. Nothing is shared between engagements, so client A's bytes
cannot reach client B's report and contractual data destruction is a single
`rm -rf` of one directory.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from hx import config as config_mod
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod


class EngagementError(Exception):
    """The engagement directory is missing, malformed, or already present."""


def now_us() -> int:
    return time.time_ns() // 1000


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass
class Engagement:
    id: str
    root: Path
    config: config_mod.Config
    db: sqlite3.Connection
    blobs: blobs_mod.BlobStore


def _record_scope(
    conn: sqlite3.Connection,
    engagement_id: str,
    cfg: config_mod.Config,
    *,
    author: str,
    reason: str,
) -> str:
    yaml_text = config_mod.dumps(cfg)
    sv_id = _new_id("sv")
    conn.execute(
        "INSERT INTO scope_version(id, engagement_id, yaml, sha256,"
        " effective_from_us, author, reason) VALUES(?,?,?,?,?,?,?)",
        (
            sv_id,
            engagement_id,
            yaml_text,
            hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
            now_us(),
            author,
            reason,
        ),
    )
    return sv_id


def create(root: Path, cfg: config_mod.Config, *, author: str) -> Engagement:
    root = Path(root)
    if root.exists():
        raise EngagementError(f"engagement directory already exists: {root}")

    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    (root / "exports").mkdir(mode=0o700)

    (root / "config.yaml").write_text(config_mod.dumps(cfg), encoding="utf-8")
    os.chmod(root / "config.yaml", 0o600)

    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    os.chmod(root / "hx.db", 0o600)

    eng_id = _new_id("e")
    conn.execute(
        "INSERT INTO engagement(id, name, client, created_us, status, config_path)"
        " VALUES(?,?,?,?,?,?)",
        (eng_id, cfg.name, cfg.client, now_us(), "active", str(root / "config.yaml")),
    )
    _record_scope(conn, eng_id, cfg, author=author, reason="engagement created")

    return Engagement(
        id=eng_id,
        root=root,
        config=cfg,
        db=conn,
        blobs=blobs_mod.BlobStore(root / "blobs"),
    )


def open_(root: Path) -> Engagement:
    root = Path(root)
    if not (root / "hx.db").exists():
        raise EngagementError(f"no engagement at {root}")
    conn = db_mod.connect(root / "hx.db")
    row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if row is None:
        raise EngagementError(f"engagement row missing in {root}")
    return Engagement(
        id=row["id"],
        root=root,
        config=config_mod.load(root / "config.yaml"),
        db=conn,
        blobs=blobs_mod.BlobStore(root / "blobs"),
    )


def record_scope_version(eng: Engagement, *, author: str, reason: str) -> str:
    """Append a new scope version. Never updates an existing row."""
    sv_id = _record_scope(eng.db, eng.id, eng.config, author=author, reason=reason)
    (eng.root / "config.yaml").write_text(
        config_mod.dumps(eng.config), encoding="utf-8"
    )
    return sv_id
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_engagement.py -v`
Expected: PASS, 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/hx/engagement.py tests/test_engagement.py
git commit -m "feat(engagement): isolated engagement directories with append-only scope history"
```

---

### Task 5: CLI — `hx new` and `hx info`

**Files:**
- Create: `src/hx/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `hx.config.Config`, `hx.engagement.create`, `hx.engagement.open_`
- Produces:
  - `hx.cli.main()` — click group registered as the `hx` console script
  - `hx new NAME --client CLIENT --scope PATTERN [--scope PATTERN ...] [--profile production|staging] [--root DIR]`
  - `hx info [--root DIR]`
  - `hx.cli.default_root() -> Path` — `$HX_HOME` if set, else `~/hx/engagements`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
from pathlib import Path

from click.testing import CliRunner

from hx import cli


def test_new_creates_engagement(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09",
            "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*",
            "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09" / "hx.db").exists()
    assert "acme-2026-09" in result.output


def test_new_requires_a_scope(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "scope" in result.output.lower()


def test_new_refuses_to_clobber(tmp_path: Path):
    runner = CliRunner()
    args = [
        "new", "acme", "--client", "Acme",
        "--scope", "https://a/*", "--root", str(tmp_path),
    ]
    assert runner.invoke(cli.main, args).exit_code == 0
    second = runner.invoke(cli.main, args)
    assert second.exit_code != 0
    assert "exists" in second.output.lower()


def test_info_reports_engagement(tmp_path: Path):
    runner = CliRunner()
    runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code == 0, result.output
    assert "Acme Corp" in result.output
    assert "production" in result.output
    assert "https://app.acme.com/*" in result.output


def test_default_root_honours_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HX_HOME", str(tmp_path / "custom"))
    assert cli.default_root() == tmp_path / "custom"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.cli'`

- [ ] **Step 3: Write the minimal implementation**

```python
# src/hx/cli.py
"""Command line entry points.

Creating an engagement and inspecting one are human acts, so they live here
rather than in the agent-facing tool layer.
"""
from __future__ import annotations

import os
from pathlib import Path

import click

from hx import config as config_mod
from hx import engagement as eng_mod


def default_root() -> Path:
    env = os.environ.get("HX_HOME")
    if env:
        return Path(env)
    return Path.home() / "hx" / "engagements"


@click.group()
def main() -> None:
    """hx — agent-driven web application security assessment."""


@main.command()
@click.argument("name")
@click.option("--client", required=True, help="Client name, as it appears in the report.")
@click.option(
    "--scope",
    "scope",
    multiple=True,
    required=True,
    help="In-scope URL pattern. Repeatable. At least one is required.",
)
@click.option("--exclude", multiple=True, help="Excluded URL pattern. Repeatable.")
@click.option(
    "--profile",
    type=click.Choice(config_mod.VALID_PROFILES),
    default="production",
    show_default=True,
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--author", default=lambda: os.environ.get("USER", "unknown"))
def new(name, client, scope, exclude, profile, root, author) -> None:
    """Create a new engagement."""
    base = root or default_root()
    cfg = config_mod.Config(
        name=name,
        client=client,
        safety_profile=profile,
        scope_include=list(scope),
        scope_exclude=list(exclude),
    )
    try:
        eng = eng_mod.create(base / name, cfg, author=author)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"created engagement {name} ({eng.id})")
    click.echo(f"  root    {eng.root}")
    click.echo(f"  profile {cfg.safety_profile}")
    click.echo(f"  scope   {', '.join(cfg.scope_include)}")


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def info(root) -> None:
    """Show an engagement's configuration and current counts."""
    path = root or default_root()
    try:
        eng = eng_mod.open_(path)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc

    counts = {
        t: eng.db.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
        for t in ("run", "surface", "exchange", "finding", "check_run")
    }
    click.echo(f"engagement {eng.config.name} ({eng.id})")
    click.echo(f"  client   {eng.config.client}")
    click.echo(f"  profile  {eng.config.safety_profile}")
    click.echo(f"  scope    {', '.join(eng.config.scope_include)}")
    if eng.config.scope_exclude:
        click.echo(f"  exclude  {', '.join(eng.config.scope_exclude)}")
    click.echo(f"  root     {eng.root}")
    click.echo("  counts   " + "  ".join(f"{k}={v}" for k, v in counts.items()))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_cli.py -v`
Expected: PASS, 5 passed

- [ ] **Step 5: Run the whole suite and the real CLI**

Run: `.venv/bin/pytest -v`
Expected: PASS, 30 passed

```bash
HX_HOME=/tmp/hx-smoke .venv/bin/hx new smoke --client "Smoke Test" --scope 'http://127.0.0.1:3000/*'
HX_HOME=/tmp/hx-smoke .venv/bin/hx info --root /tmp/hx-smoke/smoke
ls -la /tmp/hx-smoke/smoke        # expect drwx------ and hx.db, blobs, config.yaml, exports
rm -rf /tmp/hx-smoke
```

- [ ] **Step 6: Commit**

```bash
git add src/hx/cli.py tests/test_cli.py
git commit -m "feat(cli): hx new and hx info"
```

---

## Self-review

**Spec coverage.** §3 engagement directory layout → Task 4. §5 all 14 tables, pragmas, single-writer discipline, `dedupe_key` uniqueness, blob atomicity, agent-cannot-confirm → Tasks 1, 2, 4. §5 append-only `scope_version` → Task 4. §13 "engagement.create is not agent-facing" → Task 5 (CLI only).

**Deliberately out of this plan**, covered by later plans: scope *matching* (Plan 2, authoritative implementation lives in the Java extension); `path_template` normalisation (Plan 5, alongside the crawler that produces surfaces); the single-writer queue (Plan 2, when concurrent writers first exist — this plan uses one connection and has no concurrency to serialise yet).

**Known gap accepted for now:** `Config.scope_include` is a mutable list on a frozen dataclass, which `test_scope_versions_are_append_only` relies on via `.append()`. That is intentional for v1 ergonomics; if it causes aliasing bugs later, switch to `dataclasses.replace` with a fresh list.

---

## Execution handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.
