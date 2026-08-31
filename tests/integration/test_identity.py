"""Probes issued under a real session, against a real Burp.

THE ONE ASSERTION NEITHER SIDE CAN FAKE is here and is made twice over: the
target server's own request log saw the credential, and the engagement store
did not. Either half alone proves nothing. "The credential is not in the
database" is satisfied for ever by a run that never sent one, and "the target
saw a cookie" is satisfied by a rig that wrote it into a browse. Together they
are the whole of what spec s7 asks of the injection path -- the credential
reaches the application and never becomes an address in a content-addressed
store that exists in every backup taken since.

WHAT DRIVES THE SCAN, AND WHY IT IS NOT `hx scan`: `test_active_checks.py`'s
own header. The rig is what `hx capture start` produces, and the scan is
`scan.run(..., bridge=rig.srv)` -- the same call the CLI makes, handed the same
kind of bridge. `tests/test_cli.py` drives the CLI's own `except IdentityDead`
against a stubbed session, where it costs no JVM.

EVERY BYTE STAYS ON THIS MACHINE, and the identity makes that rule sharper
rather than looser. The credential below is `target_server`'s own constant, the
only host any surface here can name is the fixture's loopback target (its
constructor refuses anything outside 127.0.0.0/8), and `origins` on the
registered identity is the engagement's `scope.include` -- which is that target
and nothing else, so the extension refuses to apply the credential anywhere
else even if a surface for it somehow existed.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from hx import config as config_mod
from hx import report, scan
from hx.checks import base, registry
from tests.integration import target_server as ts
from tests.integration.target_server import (SESSION_COOKIE_VALUE,
                                             VULNERABLE_ROUTES)

pytestmark = pytest.mark.integration

# The variable the credential comes out of. The identity design's s3 keeps it
# off `Config` because `scope_version.yaml` copies a config verbatim into an
# append-only table, so the config below declares the NAME and
# `hx.identity.resolve` reads the environment.
ENV_NAME = "HX_IDENTITY_INTEGRATION_USER"

# The route `hx.active.reflected-input` finds a flaw on, and the one every
# retirement test here is built around: one check, one surface, one issue type,
# and `TargetServer.fix` can repair it while it goes on answering 200.
REFLECTING_ROUTE = VULNERABLE_ROUTES["hx.active.reflected-input"]


def rows(rig, sql: str, args=()) -> list[dict]:
    return [dict(row) for row in rig.eng.db.execute(sql, args).fetchall()]


def _identity(**over) -> config_mod.Identity:
    """The `user` identity these tests scan under.

    `every_n_probes` is left at the config default of 25. Every scan below
    sends fewer than that, so the only canaries are the opening and closing
    ones -- which is what makes the closing canary the thing that decides
    `proven` against `assumed`, and lets a test kill the session at a moment
    it controls rather than racing a mid-run one.
    """
    args = dict(
        id="user", strategy="static",
        inject=config_mod.Inject(header="Cookie", value_from_env=ENV_NAME),
        liveness=config_mod.Liveness(path="/account",
                                     expect_body=ts.SESSION_SIGNATURE,
                                     expect_absent=ts.NO_SESSION_SIGNATURE))
    args.update(over)
    return config_mod.Identity(**args)


def _declare(rig, monkeypatch, ident=None) -> None:
    """Give this run an identity, and the credential to resolve it with.

    THE SCOPE IS NOT TOUCHED. `scope.include` is what `scan.run` registers as
    the identity's `origins`, the extension reads the host out of each entry
    (`Sender.hostOf`), and the rig's own entry is `http://127.0.0.1:<port>/*`
    -- the target and nothing else. Rewriting it here would either widen where
    the credential may be applied or, if it lost its host, bound it to nothing
    and turn every canary into an `identity_origin` refusal.

    The extension is NOT re-configured either: identity is its own frame
    (s5), precisely so a credential can be registered without re-opening
    scope, and `rig.configure()` has already authorised this run's boundary.
    """
    monkeypatch.setenv(ENV_NAME, f"session={SESSION_COOKIE_VALUE}")
    ident = ident or _identity()
    rig.eng.config = dataclasses.replace(
        rig.eng.config, identities={ident.id: ident}, scan_identity=ident.id)


def _scan(rig, **kwargs) -> scan.ScanSummary:
    return scan.run(rig.eng.db, engagement_id=rig.eng.id, blobs=rig.eng.blobs,
                    config=rig.eng.config, bridge=rig.srv, **kwargs)


def _reflected_input():
    return next(c for c in registry.CHECKS
                if c.id == "hx.active.reflected-input")


def _browse_the_reflecting_route(rig) -> None:
    """One browse, WITHOUT the session cookie, and the surface it produces.

    ANONYMOUS ON PURPOSE. `rig.browse` goes through the proxy listener and may
    carry a cookie -- S4 lets an operator's own browsing do what a browser
    does -- and a browse carrying this credential would put it in the captured
    request, which is the OTHER route into the blob store and is
    `test_send_path.py`'s subject. Keeping it out of here is what makes
    "the credential is nowhere in the store" a statement about the SEND path.
    """
    rig.browse("GET", REFLECTING_ROUTE)
    rig.settle(lambda: len(rows(rig, "SELECT id FROM surface")) == 1,
               "the browsed surface")


def _observations(rig) -> list[int]:
    return [r["observed"] for r in rows(
        rig, "SELECT o.observed FROM finding_observation o"
        " JOIN finding f ON f.id = o.finding_id"
        " WHERE f.check_id='hx.active.reflected-input'"
        " ORDER BY o.ts_us, o.rowid")]


def _blobs_containing(eng, needle: bytes) -> list[Path]:
    """Every blob whose bytes contain `needle`. Empty is the only good answer.

    `test_send_path.py`'s, spelled again here rather than imported across two
    test modules for one helper -- and the reason it is a tree walk rather
    than a query is the same: content-addressed storage means that once raw
    bytes are hashed in they are in every backup taken since, whether or not
    any row references them.
    """
    return [p for p in sorted(eng.blobs.root.rglob("*"))
            if p.is_file() and needle in p.read_bytes()]


def _db_text(rig) -> str:
    """Every TEXT column of every row in the store, as one string.

    A grep over the blob tree is not enough on its own. The columns that could
    hold a credential without any blob being written are all free text --
    `exchange.url`, `denial.reason`, `run.stop_reason`, `check_run.reason`,
    `finding.description` -- and they reach a client through `report.render`.
    Reading the whole store is cheaper than enumerating them and cannot go
    stale when a column is added.
    """
    parts: list[str] = []
    tables = [r[0] for r in rig.eng.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for table in tables:
        for row in rig.eng.db.execute(f"SELECT * FROM {table}").fetchall():
            parts.extend(str(v) for v in tuple(row) if v is not None)
    return "\n".join(parts)


class _KillsTheSession:
    """A check that logs the run out after the real corpus has finished.

    NOT A CHECK, in every sense that matters: it examines nothing, sends
    nothing and retires nothing. It is the only way to reach the one state a
    test cannot otherwise time -- a session that dies between the last probe
    and the CLOSING canary, which is what downgrades a run from `proven` to
    `assumed` without halting it. `every_n_probes` is 25 and every scan here
    sends fewer, so no mid-run canary fires and this is the last thing that
    happens before `bracket.finish()`.

    `passive` so `scan.run` dispatches it through `on_surface` and never asks
    it for a probe; it is passed in `checks=` and so never goes through
    `registry.validate`.
    """

    id, version, klass = "hx.test.kills-the-session", "1", "passive"

    def __init__(self, target) -> None:
        self._target = target
        self.calls = 0

    def on_surface(self, ctx, surface, exchanges):
        self.calls += 1
        self._target.kill_session()
        return base.Verdict.clean()


# ---------------------------------------------------------------------------
# 1. The credential reaches the target and not the database.
# ---------------------------------------------------------------------------

def test_the_credential_reaches_the_target_and_never_the_store(rig, monkeypatch):
    """SPEC s7'S INJECTION PATH, END TO END, ON THE TWO WITNESSES.

    The target server's own log is the one this side cannot fake: it records
    every request before answering it, so a cookie in it arrived over a
    socket. The blob tree and the store are the other half -- once raw bytes
    are content-addressed they are in every backup, which is why s7 calls the
    blob store the one item that cannot be retrofitted.

    BOTH CANARIES AND EVERY PROBE CARRY IT. A build that injected on the
    canary alone would prove its session live and then test the logged-out
    view of the application -- proof attached to exactly the wrong traffic --
    so the assertion is over the whole log and not over `/account`.
    """
    assert rig.configure() == 1
    _declare(rig, monkeypatch)
    _browse_the_reflecting_route(rig)

    summary = _scan(rig, checks=(_reflected_input(),))
    assert summary.identity_state == "proven", summary
    assert summary.canary_requests == 2, "one canary opens the run, one closes it"

    # THE CREDENTIAL ARRIVED. `/account` is the canary's; the rest are the
    # check's probes. The browse above is the only hit that may lack it, and
    # naming that expectation is what stops a scan that sent nothing from
    # satisfying this.
    cookie = f"session={SESSION_COOKIE_VALUE}"
    carried = [h for h in rig.target.hits if cookie in (h.headers.get("Cookie") or "")]
    assert [h.path for h in carried].count("/account") == 2, [
        (h.path, h.headers.get("Cookie")) for h in rig.target.hits]
    assert len(carried) > 2, (
        "only the canaries carried the session, so the probes tested the "
        f"logged-out view: {[(h.path, h.headers.get('Cookie')) for h in rig.target.hits]}")
    assert [h for h in rig.target.hits if cookie not in
            (h.headers.get("Cookie") or "")] == [rig.target.hits[0]], (
        "something hx issued went out without the credential")

    # AND IT IS NOWHERE IN THE ENGAGEMENT. Not in the content-addressed blob
    # tree, and not in any text column of any row.
    assert _blobs_containing(rig.eng, SESSION_COOKIE_VALUE.encode()) == []
    assert SESSION_COOKIE_VALUE not in _db_text(rig)
    assert ENV_NAME not in _db_text(rig), (
        "the variable's NAME is in the config and so in `scope_version.yaml`, "
        "which is correct -- but a value beside it would not be")

    # AND NOT IN THE DELIVERABLE, which is the artefact that leaves the
    # machine. Rendered rather than reasoned about: `_db_text` above is the
    # store, and the report is composed from it plus the config.
    rendered = report.render(rig.eng.db, engagement_id=rig.eng.id,
                             config=rig.eng.config, blobs=rig.eng.blobs)
    assert "### Session identity" in rendered, (
        "nothing about the identity rendered, so the absence below is not "
        "about a page that had the chance to leak")
    assert SESSION_COOKIE_VALUE not in rendered
    assert ENV_NAME not in rendered


def test_no_probe_exchange_is_stored_at_all_yet(rig, monkeypatch):
    """THE GAP THE ASSERTION ABOVE RESTS ON, PINNED SO IT CANNOT MOVE IN
    SILENCE.

    The brief for this task asked for the stored exchange to hold
    `{{identity:user:authz}}` -- the placeholder `Redactor` writes over an
    injected range. It cannot: `Capture.java` delivers `via: proxy` and
    nothing else, `records.record_exchange` has exactly one caller and it is
    the proxy sink, and `Sender.Composed`'s own javadoc says the send path's
    `result` frame carries one body and it is the redacted RESPONSE. So no
    row exists for a probe, the placeholder appears nowhere, and the
    credential's absence from the store above is currently guaranteed by
    there being no send-path writer rather than by redaction alone.

    THIS TEST REDDENS THE DAY SEND-PATH RECORDING LANDS, which is the point of
    it. On that day the credential's absence stops being free and the
    registration `Sender.compose` already performs becomes the only thing
    keeping it out -- and whoever writes that plan should be made to come back
    here and re-establish the assertion above rather than inherit it.
    """
    assert rig.configure() == 1
    _declare(rig, monkeypatch)
    _browse_the_reflecting_route(rig)
    _scan(rig, checks=(_reflected_input(),))

    vias = {r["via"] for r in rows(rig, "SELECT DISTINCT via FROM exchange")}
    assert vias == {"proxy"}, (
        "an exchange was recorded off the proxy path. If hx now stores the "
        "requests it issues itself, re-read this test and the credential "
        f"assertions in the one above it: {vias}")
    assert _blobs_containing(rig.eng, b"{{identity:") == []


# ---------------------------------------------------------------------------
# 2. A proven run retires; an assumed one does not.
# ---------------------------------------------------------------------------

def test_a_proven_run_retires_the_finding_it_can_no_longer_find(rig, monkeypatch):
    """SECTION 9, AGAINST A TARGET THAT REALLY CHANGES.

    `test_active_checks.py::test_a_second_scan_is_stable_and_a_wholly_fixed_
    target_retires_nothing` is this scan without an identity, and it requires
    the opposite outcome. The two together are the whole of the gate: the same
    corpus, the same repair, the same `clean` off a probe that really went,
    and the retirement turns on whether the run could prove the view it was
    looking at.

    NOT VACUOUS: the second scan's row is asserted to be a real `clean` with
    requests on the wire, so what is measured is a retirement and not a check
    that stopped running.
    """
    assert rig.configure() == 1
    _declare(rig, monkeypatch)
    _browse_the_reflecting_route(rig)

    assert _scan(rig, checks=(_reflected_input(),)).identity_state == "proven"
    assert _observations(rig) == [1], "the first scan found nothing to retire"

    rig.target.fix("hx.active.reflected-input")
    summary = _scan(rig, checks=(_reflected_input(),))

    assert summary.identity_state == "proven"
    row = rows(rig, "SELECT verdict, requests_sent FROM check_run"
               " WHERE check_id='hx.active.reflected-input'"
               " ORDER BY rowid DESC LIMIT 1")[0]
    assert (row["verdict"], row["requests_sent"] > 0) == ("clean", True), row
    assert _observations(rig) == [1, 0], (
        "a run that proved its session live did not close a finding whose "
        "flaw is genuinely repaired")

    # WHERE THE CLIENT READS IT, and the two sentences that have to move
    # together: the finding is shown as fixed, and the Limits page no longer
    # claims that can never happen.
    rendered = report.render(rig.eng.db, engagement_id=rig.eng.id,
                             config=rig.eng.config, blobs=rig.eng.blobs)
    assert "appears fixed" in rendered
    assert "An active finding is never automatically marked as fixed" not in \
        rendered
    assert ("An active finding is marked as no longer observed only where it "
            "was re-tested under a session proved live") in rendered


def test_a_run_whose_session_dies_before_the_closing_canary_retires_nothing(
        rig, monkeypatch):
    """THE SEPARATING CASE, and the reason the gate is not asked inside the
    surface loop.

    Byte for byte the scan above, except that the session is killed after the
    check has run and before `bracket.finish()`. Every probe went out while
    the window still read `proven`; the closing canary is what turns the run
    `assumed`, and it runs after the last check. A gate asked per check would
    have collected the retirement before the downgrade existed and told the
    client their repaired-looking finding was closed on traffic hx cannot
    vouch for.

    THE RUN DOES NOT HALT, which is section 6's decision rather than an
    omission: at the close there is nothing left to continue, and raising
    would throw away a completed pass's rows to prevent traffic that no longer
    exists.
    """
    assert rig.configure() == 1
    _declare(rig, monkeypatch)
    _browse_the_reflecting_route(rig)

    assert _scan(rig, checks=(_reflected_input(),)).identity_state == "proven"
    assert _observations(rig) == [1]

    rig.target.fix("hx.active.reflected-input")
    killer = _KillsTheSession(rig.target)
    summary = _scan(rig, checks=(_reflected_input(), killer))

    assert killer.calls == 1, "the session was never killed"
    assert summary.identity_state == "assumed", (
        "the closing canary did not catch the death, so nothing below "
        f"measures a downgrade: {summary}")
    row = rows(rig, "SELECT verdict, requests_sent FROM check_run"
               " WHERE check_id='hx.active.reflected-input'"
               " ORDER BY rowid DESC LIMIT 1")[0]
    assert (row["verdict"], row["requests_sent"] > 0) == ("clean", True), row
    assert _observations(rig) == [1], (
        "a run downgraded to `assumed` closed a finding: every probe in it "
        "may have been issued logged out")

    rendered = report.render(rig.eng.db, engagement_id=rig.eng.id,
                             config=rig.eng.config, blobs=rig.eng.blobs)
    assert "appears fixed" not in rendered
    assert "assumed (1)" in rendered, (
        "the page does not say the run could not vouch for what it saw")


# ---------------------------------------------------------------------------
# 3. A dead session halts, and the halt is recorded.
# ---------------------------------------------------------------------------

def test_a_dead_session_halts_the_run_and_the_halt_is_recorded(rig, monkeypatch):
    """SPEC s7's INSTRUCTION -- "on failure the run halts rather than
    continuing" -- with a real 200 login page on the other end of it.

    `/account` answers 200 either way, so nothing about the response tells a
    status rule anything: the run stops because the body did not carry the
    signature the identity is declared to prove itself by, which is the only
    proof there is. A canary that read the status would pass here and stamp
    every probe of a logged-out run `proven`.

    BEFORE ANY PROBE. The canary is the only request hx puts on this target,
    the corpus writes no `check_run` row at all, and the run row says why.
    """
    assert rig.configure() == 1
    _declare(rig, monkeypatch)
    _browse_the_reflecting_route(rig)
    before = len(rig.target.hits)
    rig.target.kill_session()

    with pytest.raises(scan.IdentityDead) as raised:
        _scan(rig, checks=(_reflected_input(),))

    told = str(raised.value)
    assert "could not be proved live before the first probe" in told
    assert "not with the signature this identity is declared to prove itself " \
        "by" in told, ("a canary that was ANSWERED reads as one that was "
                       f"refused: {told}")
    assert "no refresh command to try" in told, (
        f"the message does not name which of section 6's outcomes this is: {told}")

    assert len(rig.target.hits) == before + 1, (
        "the run probed after the session failed to prove: "
        f"{[(h.method, h.path) for h in rig.target.hits[before:]]}")
    assert rows(rig, "SELECT id FROM check_run") == []

    run_row = rows(rig, "SELECT status, identity, identity_state, stop_reason"
                   " FROM run WHERE kind='scan'")[0]
    assert (run_row["status"], run_row["identity"],
            run_row["identity_state"]) == ("error", "user", "dead"), run_row
    assert "IdentityDead" in run_row["stop_reason"]

    # AND THE CLIENT IS TOLD, which is the difference between "we tested this
    # and found nothing" and "our session died at 01:50".
    rendered = report.render(rig.eng.db, engagement_id=rig.eng.id,
                             config=rig.eng.config, blobs=rig.eng.blobs)
    assert ("**1 run(s) stopped because the session being tested under "
            "stopped being valid.**") in rendered
    assert SESSION_COOKIE_VALUE not in rendered
