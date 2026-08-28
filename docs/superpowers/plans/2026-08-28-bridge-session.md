# Bridge Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the product the bridge session it never had — `hx` launches Burp, verifies its listeners are loopback-only, configures the extension out of DENY-ALL, and holds the session while a consultant browses.

**Architecture:** One new module, `src/hx/session.py`, built by promoting proven code out of `tests/integration/burp_fixture.py`. Each command owns its own Burp; there is no daemon and no second IPC channel. `tests/integration/conftest.py` and `scripts/demo_capture.py` are then rewritten to import the product's session, so the code a consultant runs becomes the code under test.

**Tech Stack:** Python 3.12, `.venv/bin/pytest`, click CLI, `subprocess`, Unix domain sockets. Zero new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-08-28-bridge-session-design.md` (approved 2026-08-28)
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md` (§4 enforcement invariant and the DENY-ALL default, §5 tables, §6 bridge `configure`/epoch, §13 v1 scope)

## Global Constraints

- **§4 enforcement invariant:** every byte that leaves this machine crosses one of two points inside the JVM. DENY-ALL is terminal. This plan starts a Burp and authorises it; it does not add an egress path.
- **The agent's rules never bind the operator's browser.** §4: the method allowlist, dangerous-path denylist, rate limit and budget "apply to the send path in full, and to crawler traffic in full. They do **not** apply to traffic from the operator's own browser." The two are told apart by **which proxy listener the request arrived on**, never by anything in the traffic — so **both listeners must always be configured and `-Dhx.crawler_port` must always be passed.**
- **No Java changes.** `extension/` is untouched. `./extension/test.sh` must still print `13 ALL PASS`, 2330 `ok`, ~2352 output lines, rc 0. Check the **line count**, not just rc — it has printed zero summary lines and exited 0 with a missing jar.
- **`hx` never bundles or redistributes Burp.** This plan only *locates* a jar the operator already has.
- **Never run Burp against the real `$HOME`.** A private home is built per run and the operator's home is a read-only seed.
- **All test targets are loopback only.** Nothing in this project has ever sent a request off this machine.
- Engagement directories `0o700`; blob and DB files `0o600`. Never looser, never widened.
- **Baselines to hold:** `.venv/bin/pytest` → `931 passed, 1 skipped, 30 deselected`; `.venv/bin/pytest -m integration` → `30 passed` (~200s, real headless Burp).
- Some functions are guarded by plan byte-compare tests. If one breaks, sync it with a trailing `chore(plans):` commit — see `13a029e` and `3fc0a41`.

---

## File Structure

**Created:**
- `src/hx/session.py` — the whole session: locating Burp, building a private home, writing the listener config, launching, waiting for the handshake, verifying loopback-only listeners, configuring, and tearing down. One module because these steps are one lifecycle and splitting them would put the teardown guarantee in a different file from the thing it guarantees.

**Modified:**
- `src/hx/cli.py` — `capture start` launches Burp and blocks.
- `tests/integration/burp_fixture.py` — keeps only what is genuinely test-only (`missing`, `unbuilt`, `burp_available`, the `Probe.java` helper and its compile/launch); everything else is re-exported from `hx.session` so existing imports keep working.
- `tests/integration/conftest.py` — the rig uses the product's session and its config body.
- `scripts/demo_capture.py` — the demo uses the product's session.

**Not in this plan:** `hx scan` does not open a session. Passive checks read the store offline; scan needs a bridge only once active checks exist, and that is the active-checks plan's task.

---

## Task 1: locating Burp

**Files:**
- Create: `src/hx/session.py`
- Test: `tests/test_session_jar.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SessionError(Exception)`; `find_burp_jar(explicit: Path | None = None) -> Path`.

The fixture hardcodes `BURP_JAR = LAB / "burpsuite_desktop_v2026.7.3.jar"`. That is right for a pinned fixture and wrong for a product whose user upgrades Burp.

- [ ] **Step 1: Write the failing tests**

```python
def test_an_explicit_jar_path_wins(tmp_path):
    jar = tmp_path / "burpsuite_desktop_v2026.7.3.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar(jar) == jar


def test_a_named_jar_that_does_not_exist_is_a_clear_error(tmp_path):
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar(tmp_path / "nope.jar")
    assert "nope.jar" in str(exc.value)


def test_the_lab_is_searched_without_pinning_a_version(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    jar = tmp_path / "burpsuite_desktop_v2027.1.0.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar() == jar


def test_two_matching_jars_is_an_error_naming_both(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    (tmp_path / "burpsuite_desktop_v2026.7.3.jar").write_bytes(b"x")
    (tmp_path / "burpsuite_desktop_v2027.1.0.jar").write_bytes(b"x")
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    # Picking the newest silently would let a consultant run an assessment
    # against a different Burp from the one they believe, and the report
    # records the version.
    assert "2026.7.3" in str(exc.value) and "2027.1.0" in str(exc.value)
    assert "--burp-jar" in str(exc.value)


def test_no_jar_anywhere_names_all_three_places_it_looked(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    monkeypatch.delenv("HX_BURP_JAR", raising=False)
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    msg = str(exc.value)
    assert "--burp-jar" in msg and "HX_BURP_JAR" in msg and str(tmp_path) in msg
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_jar.py -v`
Expected: FAIL — `No module named 'hx.session'`.

- [ ] **Step 3: Write the locator**

```python
"""Standing up a live, configured Burp — and taking it down again.

hx NEVER BUNDLES OR REDISTRIBUTES BURP. This module locates a jar the
operator already has, launches it with the bridge extension, and authorises
it. Nothing here ships Burp and nothing here may.

WHY THIS MODULE EXISTS AT ALL: until it did, nothing in `src/` called
`bridge.configure()`. `hx capture start` opened a database row and stopped
there, while `scripts/demo_capture.py` and `tests/integration/` each stood up
their own session -- so capture worked in a demo and not from the CLI, and an
active check had nowhere to send. The extension defaults to DENY-ALL, so an
unconfigured extension refuses everything.
"""
from __future__ import annotations

import os
from pathlib import Path

JAR_GLOB = "burpsuite_desktop_v*.jar"
DEFAULT_LAB = Path.home() / "F0RT1KA" / "burp-lab"


class SessionError(Exception):
    """The session cannot be established. The message names the fix."""


def _lab() -> Path:
    return Path(os.environ.get("HX_BURP_LAB", DEFAULT_LAB))


def find_burp_jar(explicit: Path | None = None) -> Path:
    """`--burp-jar`, then `$HX_BURP_JAR`, then a search of `$HX_BURP_LAB`.

    AMBIGUITY IS AN ERROR, NOT A GUESS. Two jars in the lab means the operator
    has upgraded and kept the old one, and silently taking the newer would run
    an assessment against a different Burp from the one they believe they are
    running -- which the report then records as the version under test.
    """
    if explicit is not None:
        if not Path(explicit).is_file():
            raise SessionError(f"no Burp jar at {explicit}")
        return Path(explicit)

    from_env = os.environ.get("HX_BURP_JAR")
    if from_env:
        if not Path(from_env).is_file():
            raise SessionError(f"HX_BURP_JAR names {from_env}, which is not a file")
        return Path(from_env)

    lab = _lab()
    found = sorted(lab.glob(JAR_GLOB))
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        names = ", ".join(p.name for p in found)
        raise SessionError(
            f"{len(found)} Burp jars in {lab}: {names}. Pass --burp-jar to say "
            "which one this engagement runs against -- the report records the "
            "version, so this is not a choice hx may make for you")
    raise SessionError(
        f"no Burp jar found. Pass --burp-jar, set HX_BURP_JAR, or put one "
        f"matching {JAR_GLOB} in {lab} (override with HX_BURP_LAB). hx does "
        "not ship Burp")
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_jar.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_jar.py
git commit -m "feat(session): locate the operator's Burp jar, refusing to guess"
```

---

## Task 2: the extension jar, and a private Burp home seeded from the operator's

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_home.py`

**Interfaces:**
- Consumes: `SessionError` (Task 1).
- Produces: `EXT_JAR: Path`; `extension_problem() -> str | None`; `seed_home() -> Path`; `make_home(workdir: Path) -> Path`.

**The decision this task settles, which the spec left open.** `burp_fixture.make_home` copies from `SEED_HOME = LAB / "burphome"` — a lab directory that exists on a developer's machine and not on a consultant's. A wholly fresh Burp home sits at an unaccepted licence prompt and never completes the handshake, which would surface as a bare timeout.

**Ruling: the seed is the operator's own Burp home** — `$HX_BURP_SEED_HOME` if set, else `$HOME`. It is **copied, never run against**, exactly as the fixture treats its seed. An operator who has never run Burp gets told to run it once and accept the licence, rather than a 90-second timeout.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_seed_is_the_operators_own_burp_home(monkeypatch, tmp_path):
    monkeypatch.delenv("HX_BURP_SEED_HOME", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert session.seed_home() == tmp_path


def test_the_seed_can_be_overridden(monkeypatch, tmp_path):
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(tmp_path))
    assert session.seed_home() == tmp_path


def test_a_home_that_never_accepted_the_licence_says_so(monkeypatch, tmp_path):
    # The failure this replaces is a 90-second handshake timeout with no
    # diagnostic: Burp starts, waits at the licence prompt, and never dials.
    monkeypatch.setenv("HX_BURP_SEED_HOME", str(tmp_path))
    (tmp_path / ".BurpSuite").mkdir()
    with pytest.raises(session.SessionError) as exc:
        session.make_home(tmp_path / "work")
    assert "accept" in str(exc.value).lower()


def test_the_private_home_is_a_copy_and_the_seed_is_untouched(seeded_home, tmp_path):
    home = session.make_home(tmp_path / "work")
    assert home != seeded_home
    (home / ".BurpSuite" / "scratch").write_text("written by the run")
    assert not (seeded_home / ".BurpSuite" / "scratch").exists(), (
        "the run wrote into the operator's own Burp home")


def test_a_copied_preferences_lock_is_removed(seeded_home, tmp_path):
    # A lock file copied from the seed belongs to the seed's process, and
    # leaving it makes Java Preferences fight a Burp that is not running.
    home = session.make_home(tmp_path / "work")
    assert not list((home / ".java" / ".userPrefs").glob(".user*"))
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_home.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'seed_home'`.

- [ ] **Step 3: Move `make_home`, `_eula_accepted`, `_jar_is_stale`, `_jar_mtime`, `_newest_source_mtime` from `tests/integration/burp_fixture.py`**

Move these **unchanged except where named below**, keeping their docstrings — each one records a failure that was diagnosed once and must not be rediscovered:

- `make_home` (fixture line 274): change `SEED_HOME` to `seed_home()`, and raise `SessionError` when the seed has no accepted licence. Keep the symlink for `burpbrowser` — it is 650 MB and read-mostly — and keep the `.userPrefs` lock removal.
- `_eula_accepted` (line 254): take the seed as an argument. **Keep the byte search and its comment**: `read_text()` on Burp's 1.75 MB prefs file raised `UnicodeDecodeError` on a torn write, which is not an `OSError`, and turned every pytest run in the repo into a collection error with zero tests run.
- `_jar_problem` (line 75), `_jar_is_stale` (209), `_jar_mtime` (231) and `_newest_source_mtime` (235): these judge the **extension** jar against `extension/src`, not Burp's jar (`_jar_mtime` reads `EXT_JAR.stat()`). `_jar_problem`'s three-way judgement becomes `extension_problem()` below — keep all three outcomes.

Add, using the same `parents[2]` depth the fixture uses — `src/hx/session.py` and `tests/integration/burp_fixture.py` are both two levels below the repo root, so the expression is identical:

```python
EXT_JAR = Path(__file__).resolve().parents[2] / "extension" / "build" / "hx-bridge.jar"
EXT_SRC = Path(__file__).resolve().parents[2] / "extension" / "src"


def seed_home() -> Path:
    """The Burp home to COPY FROM. Never the home Burp runs against.

    The operator's own, because that is the one whose licence they accepted.
    hx has no way to accept it for them and must not try.
    """
    from_env = os.environ.get("HX_BURP_SEED_HOME")
    return Path(from_env) if from_env else Path.home()


def extension_problem() -> str | None:
    """Why the bridge extension jar cannot be used, or None.

    Burp STARTS HAPPILY WITHOUT AN EXTENSION, so an unbuilt or stale jar does
    not fail the launch -- it fails the handshake ninety seconds later with
    nothing pointing at the cause. Judged before launching for that reason.

    THREE OUTCOMES, NOT TWO, and the third is why this is one function.
    `_jar_problem` in the fixture records the bug: a FUTURE-dated source
    cannot be cleared by rebuilding -- no jar can be stamped later than a
    source dated years ahead -- so routing it to "run build.sh" told the
    operator to run a script that provably cannot help, permanently
    ("two honest rebuilds, still reported stale both times"). Missing and
    stale are build.sh's; future is the clock's, and it says so.
    """
    if not EXT_JAR.is_file():
        return (f"the bridge extension is not built: {EXT_JAR} does not exist. "
                "Run ./extension/build.sh")
    newest = _newest_source_mtime()
    if newest > time.time() + 60:
        return (f"a source under {EXT_SRC} is dated in the future, so no "
                "rebuild can make the jar newer than it. Fix the file's "
                "timestamp or the clock -- ./extension/build.sh cannot help")
    if newest > _jar_mtime():
        return (f"{EXT_JAR} is older than {EXT_SRC}. Run ./extension/build.sh "
                "-- Burp would start with the previous extension and the "
                "difference would show up as a handshake timeout")
    return None
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_home.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `941 passed, 1 skipped, 30 deselected` (931 + 5 from Task 1 + 5 here).

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session_home.py
git commit -m "feat(session): a private Burp home, seeded from the operator's own"
```

---

## Task 3: launching Burp

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_launch.py`

**Interfaces:**
- Consumes: `find_burp_jar`, `make_home`, `extension_problem`, `EXT_JAR` (Tasks 1-2).
- Produces: `PROXY_CONFIG: str`; `ADD_OPENS: list[str]`; `_free_port() -> int`; `write_listener_config(workdir: Path, second_port: int = 0) -> list[int]`; `launch_burp(socket_path, engagement_id, workdir, *, sentinel, jar, instance, crawler_port=0) -> subprocess.Popen`; `wait_for(predicate, timeout=90.0, interval=0.5) -> bool`.

**What changes in the promotion, and nothing else does.** `burp_fixture.launch_burp` hardcodes two things a product cannot:

1. `-Dhx.instance=integration` becomes the `instance` argument, so a capture session identifies itself as `capture`.
2. `-cp f"{BURP_JAR}:{EXT_JAR}"` takes the located `jar` rather than the pinned module constant, and `cwd=LAB` becomes `cwd=workdir`.

**Everything else moves verbatim, including every comment.** Three of them record failures that cost real debugging time and would otherwise be rediscovered:

- `-Dhx.halt_sentinel` is **required, not optional**: `HxExtension.initialize()` returns early ("extension idle") without it, so the extension never dials and the handshake never happens.
- `-Dhx.crawler_port` is **required and read back from the config file**, never from the argument, which may be the `0` meaning "choose one for me". Omitting it makes `Source.forListenerPort` answer OPERATOR for every request however many listeners run — so §4's operator/agent split silently stops working while everything appears fine.
- Output goes to `workdir/burp.log`, **never a pipe**: an unread `subprocess.PIPE` deadlocks once Burp fills the buffer, and a file lets a failure quote what Burp actually said.
- `proc.stdin.write(b"\n\n")` selects Community Edition.

- [ ] **Step 1: Write the failing tests**

These assert the command hx *builds*, without launching a JVM, so they run in the default suite. Define the stub once, at the top of the file — later tasks reuse it:

```python
class _FakeProc:
    """A launched process that never was. `pid` is real enough to be passed
    to a monkeypatched `not_loopback_only`, and `on_kill` lets a test prove
    teardown happened."""

    def __init__(self, on_kill=None):
        self.pid = 4242
        self.stdin = io.BytesIO()
        self._on_kill = on_kill

    def kill(self):
        if self._on_kill is not None:
            self._on_kill(self.pid)

    def wait(self, timeout=None):
        return 0
```

```python
def test_the_launch_command_carries_every_required_property(monkeypatch, tmp_path):
    seen = {}

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return _FakeProc()

    monkeypatch.setattr(session.subprocess, "Popen", fake_popen)
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture")
    joined = " ".join(seen["cmd"])
    assert "-Dhx.halt_sentinel=" in joined, (
        "without the sentinel HxExtension returns early and never dials, so "
        "the handshake times out with nothing naming the cause")
    assert "-Dhx.crawler_port=" in joined, (
        "without it Source.forListenerPort answers OPERATOR for every request "
        "and S4's operator/agent split stops working silently")
    assert "-Dhx.instance=capture" in joined
    assert "--developer-extension-class-name=hx.HxExtension" in joined
    assert "--disable-auto-update" in joined


def test_the_crawler_port_is_the_one_burp_was_actually_given(monkeypatch, tmp_path):
    # Read back out of the config file, never from the argument, which may be
    # the 0 that means "choose one for me".
    monkeypatch.setattr(session.subprocess, "Popen", lambda cmd, **kw: _FakeProc())
    ports = session.write_listener_config(tmp_path / "w", 0)
    assert ports[1] != 0


def test_output_goes_to_a_file_not_a_pipe(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(session.subprocess, "Popen",
                        lambda cmd, **kw: (seen.update(kw), _FakeProc())[1])
    session.launch_burp(tmp_path / "hx.sock", "e-1", tmp_path / "w",
                        sentinel=tmp_path / "HALTED", jar=tmp_path / "b.jar",
                        instance="capture")
    assert seen["stdout"] is not session.subprocess.PIPE, (
        "an unread PIPE deadlocks once Burp fills the buffer")
    assert (tmp_path / "w" / "burp.log").exists()
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_launch.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'launch_burp'`.

- [ ] **Step 3: Move the launcher**

Move `ADD_OPENS` (fixture line 33), `PROXY_CONFIG` (308), `_free_port` (311), `write_listener_config` (339), `launch_burp` (366) and `wait_for` (426) into `src/hx/session.py`, applying only the two changes named above. Keep `write_listener_config`'s comment about `listen_mode: loopback_only` being written once and read back by `not_loopback_only`.

Call `extension_problem()` at the top of `launch_burp` and raise `SessionError` if it returns a message — before spending ninety seconds on a handshake that cannot happen.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_launch.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_launch.py
git commit -m "feat(session): launch Burp with the bridge extension"
```

---

## Task 4: loopback-only listeners, enforced

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_loopback.py`

**Interfaces:**
- Consumes: `PROXY_CONFIG` (Task 3).
- Produces: `_listening_sockets(pid: int) -> list[str]`; `_is_loopback(local: str) -> bool`; `not_loopback_only(pid: int, ports: list[int]) -> str | None`; `listener_ports(workdir: Path) -> list[int]`; `proxy_port(workdir: Path) -> int`; `second_proxy_port(workdir: Path) -> int`.

In the fixture this is a check a test consults. **In the product it is a refusal.** A consultant running against a client network needs a proxy that cannot be reached from that network far more than a test does. `demo_capture.py` already treats it as a refusal (`refusing to continue`); this makes that the product's behaviour rather than the demo's.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_loopback_only_listener_passes(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["127.0.0.1:8080", "[::1]:8081"])
    assert session.not_loopback_only(1, [8080, 8081]) is None


def test_a_listener_on_all_interfaces_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["0.0.0.0:8080"])
    why = session.not_loopback_only(1, [8080])
    assert why and "8080" in why


def test_a_listener_on_a_routable_address_is_named(monkeypatch):
    monkeypatch.setattr(session, "_listening_sockets",
                        lambda pid: ["192.168.1.10:8080"])
    assert session.not_loopback_only(1, [8080]) is not None
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_loopback.py -v`
Expected: FAIL — attribute does not exist.

- [ ] **Step 3: Move them unchanged**

Move `_listening_sockets` (fixture 515), `_is_loopback` (530), `not_loopback_only` (558), `listener_ports` (679), `proxy_port` (691), `second_proxy_port` (702) into `src/hx/session.py` **verbatim, with their docstrings**. They are correct; only their home changes. Do not "improve" the parsing — it reads `/proc` and its edge cases were established against a real Burp.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_loopback.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/session.py tests/test_session_loopback.py
git commit -m "feat(session): loopback-only listeners move into the product"
```

---

## Task 5: the configure body, and the scope hash that must not be recomputed

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session_configure.py`

**Interfaces:**
- Consumes: `hx.config.Config`, `hx.bridge.codec.CONFIG_KEYS`.
- Produces: `METHOD_ALLOW: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")`; `config_body(cfg) -> dict[str, list[str]]`; `stored_scope_sha256(conn, engagement_id: str) -> str`.

**The rule this task exists for.** `engagement.py:120` records `scope_version.sha256 = sha256(yaml_text)`. `scripts/demo_capture.py:226` instead **recomputes** `sha256(config.dumps(cfg))`. They agree today and would diverge on a hand-edited `config.yaml`, a different key order, or an added comment — and since Plan 5's F4 fix the report renders `scope_version.sha256` as provenance for contract disputes. **Read the stored value; never recompute one.**

`limit.max_requests` is deliberately absent. `Limits.arm()` falls back to a `defaultMaxRequests` that `Distress.java` documents as 2000 per run, and §4 is explicit that the budget never binds the operator's browser — so its absence costs a browsing consultant nothing, and the plan that spends the budget is the plan that should bound it.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_body_uses_only_keys_the_codec_permits(a_config):
    assert set(session.config_body(a_config)) <= codec.CONFIG_KEYS


def test_every_config_field_reaches_its_key(a_config):
    body = session.config_body(a_config)
    assert body["scope.include"] == a_config.scope_include
    assert body["scope.exclude"] == a_config.scope_exclude
    assert body["dangerous.path"] == a_config.dangerous_paths
    assert body["render.allow"] == a_config.render_allow
    assert body["limit.rate_rps"] == [str(a_config.rate_limit_rps)]
    assert body["limit.concurrency"] == [str(a_config.max_concurrency)]
    assert body["method.allow"] == ["GET", "HEAD", "OPTIONS"]


def test_the_budget_key_is_absent(a_config):
    # Java's Limits.arm() falls back to its documented default of 2000, and
    # S4 says the budget never binds the operator's browser. The plan that
    # spends it is the plan that bounds it.
    assert "limit.max_requests" not in session.config_body(a_config)


def test_the_scope_hash_is_read_from_the_store(engagement):
    conn, eng = engagement
    stored = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
    assert session.stored_scope_sha256(conn, eng.id) == stored


def test_a_hand_edited_config_does_not_change_the_authorised_hash(engagement):
    """The failure this rule prevents.

    If the session recomputed the hash from today's config, the report would
    render one hash as the authorised scope while the extension had been
    authorised against another -- and nothing would notice.
    """
    conn, eng = engagement
    before = session.stored_scope_sha256(conn, eng.id)
    (eng.root / "config.yaml").write_text(
        (eng.root / "config.yaml").read_text() + "\n# a comment\n")
    assert session.stored_scope_sha256(conn, eng.id) == before


def test_an_engagement_with_no_scope_version_is_an_error(empty_engagement):
    conn, eng = empty_engagement
    with pytest.raises(session.SessionError):
        session.stored_scope_sha256(conn, eng.id)
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session_configure.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'config_body'`.

- [ ] **Step 3: Write both**

```python
# S4's method allowlist, stated rather than defaulted. `Policy.DEFAULT_METHODS`
# is these same three verbs, so sending them explicitly widens nothing and
# says what the engagement authorised. `Config` has no `method` key and this
# plan does not add one: an active_safe check is idempotent by S10's own
# definition, and GET is what idempotent means.
METHOD_ALLOW: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")


def config_body(cfg) -> dict[str, list[str]]:
    """The authorisation, built from the engagement's config.

    `limit.max_requests` IS DELIBERATELY ABSENT. `Limits.arm()` falls back to
    a documented default of 2000 per run, and S4 is explicit that the method
    allowlist, dangerous-path denylist, rate limit and budget "apply to the
    send path in full, and to crawler traffic in full. They do NOT apply to
    traffic from the operator's own browser." Nothing this plan starts spends
    the budget, so bounding it here would be a number with no referent.
    """
    return {
        "scope.include": list(cfg.scope_include),
        "scope.exclude": list(cfg.scope_exclude),
        "dangerous.path": list(cfg.dangerous_paths),
        "render.allow": list(cfg.render_allow),
        "method.allow": list(METHOD_ALLOW),
        "limit.rate_rps": [str(cfg.rate_limit_rps)],
        "limit.concurrency": [str(cfg.max_concurrency)],
    }


def stored_scope_sha256(conn, engagement_id: str) -> str:
    """The hash of the scope IN FORCE, read from `scope_version`.

    NEVER RECOMPUTED FROM TODAY'S CONFIG. `scope_version` is append-only and
    tamper-evident precisely so a contract dispute has one answer, and since
    Plan 5's F4 fix the report renders this column as the engagement's
    provenance. Recomputing would let the report show one hash as the
    authorised boundary while the extension had been authorised against
    another -- two facts that usually agree, which is the failure mode worth
    designing out rather than testing for.
    """
    row = conn.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (engagement_id,)).fetchone()
    if row is None:
        raise SessionError(
            f"engagement {engagement_id} has no scope_version row, so there is "
            "no recorded boundary to authorise the extension against")
    return row[0]
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session_configure.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `953 passed, 1 skipped, 30 deselected`.

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session_configure.py
git commit -m "feat(session): authorise from the scope hash the store recorded"
```

---

## Task 6: the session itself

**Files:**
- Modify: `src/hx/session.py`
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: everything from Tasks 1-5; `hx.halt.OperatorHalt`, `hx.capture.Capture`, `hx.bridge.server.BridgeServer`, `hx.store.db.connect`, `hx.store.blobs.BlobStore`.
- Produces:
  - `ExchangeSink(root, engagement_id, config)` — callable `(header, request, response)`
  - `LiveSession` dataclass: `.operator_port: int`, `.crawler_port: int`, `.epoch: int`, `.bridge`, `.workdir: Path`
  - `session(eng, *, instance: str, jar: Path | None = None, workdir: Path | None = None)` — a context manager yielding `LiveSession`

**The trap this task must not fall into, quoted from `scripts/demo_capture.py:85`:**

> The bridge calls its exchange sink **ON THE READ THREAD**, and a sqlite connection belongs to the thread that opened it — so a `Capture` built over the main thread's connection raises `ProgrammingError` on every frame. The bridge catches everything the sink throws, by design (§4: a lost record changes what hx KNOWS, never what it ALLOWS), so the observable would be **a live Burp, traffic flowing, and an empty database.**

The sink therefore opens its own connection **lazily, on first call**, which is already on the read thread. `ExchangeSink` moves into the product for that reason: it is not demo scaffolding, it is the only correct way to hold this connection.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_sink_opens_its_connection_on_the_calling_thread(tmp_path, an_engagement):
    """The failure this guards is silent: a live Burp and an empty database.

    A Capture built over the main thread's connection raises ProgrammingError
    on every frame, the bridge swallows it by design, and nothing surfaces.
    """
    sink = session.ExchangeSink(an_engagement.root, an_engagement.id,
                                an_engagement.config)
    errors = []

    def on_other_thread():
        try:
            sink({"id": "x-1", "method": "GET", "url": "https://a.test/",
                  "status": 200, "outcome": "ok"}, b"GET / HTTP/1.1\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n\r\n")
        except Exception as exc:            # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=on_other_thread)
    t.start(); t.join()
    assert not errors, f"the sink raised off the main thread: {errors}"
    conn = db_mod.connect(an_engagement.root / "hx.db")
    assert conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 1


def test_a_failed_configure_leaves_no_burp_running(monkeypatch, an_engagement):
    """A session that looks alive and is at DENY-ALL is worse than none."""
    killed = []
    monkeypatch.setattr(session, "launch_burp",
                        lambda *a, **k: _FakeProc(on_kill=killed.append))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure",
                        lambda self, *a, **k: (_ for _ in ()).throw(
                            server.BridgeError("bad_config")))
    with pytest.raises(session.SessionError):
        with session.session(an_engagement, instance="capture"):
            pass
    assert killed, "configure failed and Burp was left running"


def test_listeners_that_are_not_loopback_only_refuse_the_session(monkeypatch, an_engagement):
    killed = []
    monkeypatch.setattr(session, "launch_burp",
                        lambda *a, **k: _FakeProc(on_kill=killed.append))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only",
                        lambda pid, ports: "8080 is bound to 0.0.0.0")
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture"):
            pass
    assert "0.0.0.0" in str(exc.value)
    assert killed, "a session that refused to continue left Burp running"


def test_burp_is_torn_down_when_the_body_raises(monkeypatch, an_engagement):
    killed = []
    monkeypatch.setattr(session, "launch_burp",
                        lambda *a, **k: _FakeProc(on_kill=killed.append))
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: True)
    monkeypatch.setattr(session, "not_loopback_only", lambda pid, ports: None)
    monkeypatch.setattr(session.BridgeServer, "configure", lambda self, *a, **k: 1)
    with pytest.raises(ZeroDivisionError):
        with session.session(an_engagement, instance="capture"):
            1 / 0
    assert killed, "an exception in the body orphaned a Burp process"


def test_a_handshake_that_never_completes_points_at_burps_log(monkeypatch, an_engagement):
    monkeypatch.setattr(session, "launch_burp", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(session, "wait_for", lambda *a, **k: False)
    with pytest.raises(session.SessionError) as exc:
        with session.session(an_engagement, instance="capture"):
            pass
    assert "burp.log" in str(exc.value)
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: FAIL — `module 'hx.session' has no attribute 'ExchangeSink'`.

- [ ] **Step 3: Write the sink and the context manager**

```python
@dataclass(frozen=True)
class LiveSession:
    operator_port: int
    crawler_port: int
    epoch: int
    bridge: object
    workdir: Path


class ExchangeSink:
    """`hx.capture.Capture` on a connection owned by the thread that uses it.

    THE BRIDGE CALLS ITS SINK ON THE READ THREAD, and a sqlite connection
    belongs to the thread that opened it -- so a `Capture` built over the main
    thread's connection raises `ProgrammingError` on every frame. The bridge
    catches everything the sink throws, BY DESIGN (S4: a lost record changes
    what hx KNOWS, never what it ALLOWS), so the observable is not an error:
    it is a live Burp, traffic flowing, and an empty database.

    The connection is therefore opened LAZILY, on the first call, which is
    already on the read thread.
    """

    def __init__(self, root: Path, engagement_id: str, cfg) -> None:
        self._root, self._id, self._cfg = Path(root), engagement_id, cfg
        self._capture = None

    def __call__(self, header: dict, request: bytes, response: bytes) -> None:
        if self._capture is None:
            self._capture = capture_mod.Capture(
                db_mod.connect(self._root / "hx.db"),
                blobs_mod.BlobStore(self._root / "blobs"),
                engagement_id=self._id, config=self._cfg)
        self._capture(header, request, response)


@contextlib.contextmanager
def session(eng, *, instance: str, jar: Path | None = None,
            workdir: Path | None = None):
    """A live, configured Burp -- or nothing at all.

    EVERY EXIT TEARS BURP DOWN, including a refused `configure` and a raise
    from the body. The alternative to tearing down after a failed configure is
    a running Burp whose extension is at DENY-ALL: it looks like a working
    session and captures nothing.
    """
    jar = find_burp_jar(jar)
    work = Path(workdir) if workdir else eng.root / "session"
    work.mkdir(parents=True, exist_ok=True)

    halt = halt_mod.OperatorHalt(eng.root, eng.db)
    srv = BridgeServer(work / "hx.sock", engagement_id=eng.id,
                       operator_halt=halt,
                       on_exchange=ExchangeSink(eng.root, eng.id, eng.config))
    srv.start()
    proc = None
    try:
        proc = launch_burp(work / "hx.sock", eng.id, work,
                           sentinel=halt.sentinel_path, jar=jar,
                           instance=instance)
        if not wait_for(lambda: srv.state == "connected"):
            raise SessionError(
                f"Burp never completed the bridge handshake. See "
                f"{work / 'burp.log'} -- the usual cause is an extension jar "
                "that is unbuilt or stale, and Burp starts happily without one")

        operator, crawler = proxy_port(work), second_proxy_port(work)
        why = not_loopback_only(proc.pid, [operator, crawler])
        if why:
            raise SessionError(f"refusing to continue: {why}")

        try:
            epoch = srv.configure(config_body(eng.config),
                                  scope_sha256=stored_scope_sha256(eng.db, eng.id),
                                  profile=eng.config.safety_profile)
        except Exception as exc:            # noqa: BLE001
            raise SessionError(f"the extension refused the scope: {exc}") from exc

        yield LiveSession(operator, crawler, epoch, srv, work)
    finally:
        if proc is not None:
            proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=15)
        srv.stop()
```

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_session.py -v`
Expected: all pass.

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/pytest -q`
Expected: `958 passed, 1 skipped, 30 deselected`.

- [ ] **Step 6: Commit**

```bash
git add src/hx/session.py tests/test_session.py
git commit -m "feat(session): one context manager that always tears Burp down"
```

---

## Task 7: `hx capture start` brings Burp up

**Files:**
- Modify: `src/hx/cli.py:214-238`
- Test: `tests/test_cli_capture.py`

**Interfaces:**
- Consumes: `session.session`, `session.SessionError`, `session.LiveSession`.
- Produces: `hx capture start [--kind] [--root] [--burp-jar]`, which launches Burp, prints the operator proxy port, opens the run, and blocks until interrupted.

Today this command opens a `run` row and prints one line. It never starts Burp, so a consultant who runs it and browses records nothing.

- [ ] **Step 1: Write the failing tests**

```python
def test_capture_start_reports_the_port_to_browse_through(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session",
                        _fake_session(operator_port=18080))
    monkeypatch.setattr(cli, "_block_until_interrupt", lambda: None)
    result = CliRunner().invoke(cli.main, ["capture", "start",
                                           "--root", str(an_engagement.root)])
    assert result.exit_code == 0
    assert "18080" in result.output, (
        "the operator cannot browse through a proxy whose port they were "
        "never told")


def test_ctrl_c_closes_the_run(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    def interrupt():
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "_block_until_interrupt", interrupt)
    CliRunner().invoke(cli.main, ["capture", "start",
                                  "--root", str(an_engagement.root)])
    status = an_engagement.db.execute(
        "SELECT status FROM run ORDER BY started_us DESC LIMIT 1").fetchone()[0]
    assert status != "running", "Ctrl-C left the run open"


def test_a_session_error_exits_non_zero_and_says_why(monkeypatch, an_engagement):
    monkeypatch.setattr(cli.session_mod, "session",
                        _raising_session(session_mod.SessionError("no Burp jar found")))
    result = CliRunner().invoke(cli.main, ["capture", "start",
                                           "--root", str(an_engagement.root)])
    assert result.exit_code != 0
    assert "no Burp jar found" in result.output
```

- [ ] **Step 2: Run to verify they fail**

Run: `.venv/bin/pytest tests/test_cli_capture.py -v`
Expected: FAIL — the command never opens a session.

- [ ] **Step 3: Rewrite the command**

Keep `current_run` and its "typing start twice resumes the one live run" behaviour. Wrap it in a session, print the operator port, block, and close the run on exit. Add `--burp-jar` (a `click.Path`) passed through to `session.session`.

```python
def _block_until_interrupt() -> None:
    """Separate so a test can drive the command without a real signal."""
    signal.pause()
```

The command body: open the session first, then the run — a run row opened before a session that fails to start is a run that never captured anything. `SessionError` becomes `click.ClickException`. On exit, close the run with `run_mod.close_run`, inside a `finally`.

- [ ] **Step 4: Run to verify they pass**

Run: `.venv/bin/pytest tests/test_cli_capture.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/hx/cli.py tests/test_cli_capture.py
git commit -m "feat(cli): capture start brings Burp up and holds it"
```

---

## Task 8: the rig uses the product's session

**Files:**
- Modify: `tests/integration/burp_fixture.py`, `tests/integration/conftest.py`
- Test: the existing 30 integration tests are the test.

**Interfaces:**
- Consumes: everything in `hx.session`.
- Produces: no new interface. `burp_fixture` re-exports the promoted names from `hx.session` so existing imports keep working.

**This is the highest-risk task in the plan and the one that gives it its point.** Thirty integration tests depend on this fixture. Until now the code a consultant runs and the code under test were different code; after this they are the same. `conftest.py`'s own comment already names the hazard: *"a config body spelled anywhere else is a second spelling free to drift from this one."* There have been three spellings and none of them shipped.

- [ ] **Step 1: Record the baseline before touching anything**

Run: `.venv/bin/pytest -m integration -q`
Expected: `30 passed`. Write the exact line into your report — it is what "no regression" means here.

- [ ] **Step 2: Re-export from the product instead of defining**

In `tests/integration/burp_fixture.py`, delete the promoted definitions and import them:

```python
from hx.session import (           # noqa: F401  -- re-exported for the rig
    ADD_OPENS, EXT_JAR, EXT_SRC, PROXY_CONFIG, SessionError,
    _free_port, _jar_is_stale, _jar_mtime, _newest_source_mtime,
    extension_problem, find_burp_jar, seed_home,
    launch_burp, listener_ports, make_home, not_loopback_only,
    proxy_port, second_proxy_port, wait_for, write_listener_config,
)
```

**Keep in the fixture**, because they are genuinely test-only: `missing`, `unbuilt`, `_environment_missing`, `_environment_missing_unguarded`, `_missing`, `burp_available`, and the whole `Probe.java` section (`PROBE_SRC`, `PROBE_CLASS`, `probe_missing`, `probe_source_missing`, `_compile_probe`, `launch_probe`).

`launch_burp` now requires `jar` and `instance`. The fixture supplies `jar=find_burp_jar()` and `instance="integration"`, so the rig keeps identifying itself as the rig.

`BURP_JAR` was a module constant several call sites read. Replace it with a module-level `BURP_JAR = find_burp_jar()` **inside a try/except that leaves it `None`** — `missing()` must still be able to report a missing jar rather than raising at import and turning the whole run into a collection error. That exact failure mode has happened here before, via `_eula_accepted` raising `UnicodeDecodeError` at import time.

- [ ] **Step 3: Run the integration suite**

Run: `.venv/bin/pytest -m integration -q`
Expected: `30 passed`.

If a test fails, read it before changing it. A test that broke because the product's session differs from the rig's is telling you the product is wrong, not the test.

- [ ] **Step 4: Point the rig's config body at the product's**

`conftest.py`'s `build_config_body` becomes a thin wrapper over `session.config_body(cfg)`, adding only what the rig genuinely needs beyond it: `limit.max_requests` (the rig tests budget exhaustion, which the product omits) and the `rate_rps` override that exists for one test — the one pushing a second `configure` with a different rate and expecting `bad_config`. Keep both docstrings explaining why they are overrides rather than the default.

- [ ] **Step 5: Run both suites**

Run: `.venv/bin/pytest -q && .venv/bin/pytest -m integration -q`
Expected: `961 passed, 1 skipped, 30 deselected` and `30 passed`.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/burp_fixture.py tests/integration/conftest.py
git commit -m "refactor(tests): the rig drives the product's session"
```

---

## Task 9: the demo uses the product's session, and the whole thing is verified end to end

**Files:**
- Modify: `scripts/demo_capture.py`
- Test: `tests/integration/test_cli_session.py` (create)

**Interfaces:**
- Consumes: `hx.session.session`, `hx.session.ExchangeSink`.
- Produces: nothing new.

- [ ] **Step 1: Replace the demo's hand-rolled session**

Delete the demo's `Sink` class (line 85) and its inline assembly (lines ~195-236): the `OperatorHalt`, `BridgeServer`, `launch_burp`, `wait_for`, `not_loopback_only` and `configure` block all become one `with session.session(eng, instance="demo") as live:`.

**Keep the demo's narration** — the `did(...)` and `saw(...)` lines are the point of the script. Keep its deliberately-broken-sink demonstration (step 6 flips `failing`), which now subclasses `ExchangeSink` rather than reimplementing it: the demonstration is that the bridge keeps the exception and the browser does not notice, and that is worth keeping.

**The demo's hand-computed `scope_sha256` goes.** It recomputed `sha256(config.dumps(cfg))` where the session now reads the stored value — the exact divergence Task 5 exists to prevent.

- [ ] **Step 2: Run the demo against a real Burp**

Run: `.venv/bin/python scripts/demo_capture.py`
Expected: it completes with the same narration as before, and the config epoch line still prints.

- [ ] **Step 3: Write the end-to-end integration test**

```python
@pytest.mark.integration
def test_capture_start_records_what_the_operator_browses(tmp_path, target):
    """The whole point of this plan, in one test.

    Before it, `hx capture start` opened a database row and nothing else: a
    consultant could run it, browse, and record nothing, because the extension
    defaults to DENY-ALL and nothing in the product ever configured it.
    """
    eng = _engagement(tmp_path, scope=f"{target.origin}/*")
    with session_mod.session(eng, instance="test") as live:
        _browse_through(live.operator_port, f"{target.origin}/api/orders")
        _settle(eng.db, "SELECT COUNT(*) FROM exchange", want=1)

    rows = eng.db.execute(
        "SELECT method, url FROM exchange").fetchall()
    assert rows == [("GET", f"{target.origin}/api/orders")]


@pytest.mark.integration
def test_the_authorised_hash_is_the_one_the_report_renders(tmp_path, target):
    """Task 5's rule, proved against a real extension rather than a fake."""
    eng = _engagement(tmp_path, scope=f"{target.origin}/*")
    with session_mod.session(eng, instance="test") as live:
        assert live.epoch >= 1
    stored = eng.db.execute(
        "SELECT sha256 FROM scope_version WHERE engagement_id=?"
        " ORDER BY effective_from_us DESC LIMIT 1", (eng.id,)).fetchone()[0]
    assert stored in report.render(eng.db, engagement_id=eng.id, config=eng.config)
```

- [ ] **Step 4: Run everything**

```bash
.venv/bin/pytest -q
.venv/bin/pytest -m integration -q
./extension/test.sh 2>&1 | tail -3
```

Expected: `961 passed, 1 skipped, 30 deselected`; `32 passed`; and for Java `13 ALL PASS` with **2352 output lines and 2330 `ok`** — check the line count, not just rc.

- [ ] **Step 5: Commit**

```bash
git add scripts/demo_capture.py tests/integration/test_cli_session.py
git commit -m "refactor(demo): the demo drives the product's session"
```
