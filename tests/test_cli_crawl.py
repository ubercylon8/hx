# tests/test_cli_crawl.py
"""`hx crawl` (Task 7): the CLI step that drives the crawler synchronously.

NO JVM IS STARTED HERE. `cli.session_mod.session` is replaced with a fake
context manager, matching `tests/test_cli_capture.py`'s own convention for
`capture start` -- the real thing is exercised under `pytest -m integration`.
`cli.crawl_run_mod.crawl` is stubbed too, so no real Chromium is launched
either: this file is about the CLI's own wiring (engagement resolution, the
run bracket, the printed summary), not the crawler's own arithmetic, which
`tests/test_crawl_run.py` already owns.
"""
from __future__ import annotations

import contextlib

from click.testing import CliRunner

from hx import cli
from hx.crawl import run as crawl_run_mod


class _FakeLiveSession:
    def __init__(self, crawler_port=41999, operator_port=41998):
        self.crawler_port = crawler_port
        self.operator_port = operator_port
        self.epoch = 1
        self.bridge = None
        self.workdir = None

    def gone(self):
        return None


def _fake_session(**kw):
    @contextlib.contextmanager
    def factory(eng, *, instance, jar=None, workdir=None):
        yield _FakeLiveSession(**kw)
    return factory


def test_crawl_dials_the_crawler_port_and_prints_the_summary(
        engagement, monkeypatch):
    """The command opens a `crawl` run, drives `hx.crawl.run.crawl` against
    the SESSION'S CRAWLER PORT (never the operator one -- Ruling 21), closes
    the run `completed`, and prints the summary including the dropped-host
    list and the truncation line.

    MUTATION: pass `live.operator_port` instead of `live.crawler_port`.
    Must go red -- `_FakeLiveSession` gives the two distinct values
    (41999/41998) on purpose, so `seen["proxy_port"]` tells them apart
    directly.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())
    seen = {}

    def fake_crawl(*, seeds, proxy_port, budget):
        seen["seeds"] = list(seeds)
        seen["proxy_port"] = proxy_port
        seen["budget"] = budget
        return crawl_run_mod.CrawlSummary(
            pages=2, rendered=2, degraded=0, failed=0, capped=0, requests=3,
            dropped_hosts=("cdn.test",), truncated_by=None)

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", fake_crawl)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code == 0, result.output
    assert seen["seeds"] == ["https://app.test/"]
    # THE CRAWLER PORT, NOT THE OPERATOR ONE. `_FakeLiveSession` gives the
    # two distinct values on purpose.
    assert seen["proxy_port"] == 41999
    assert "pages     2" in result.output
    assert "dropped   cdn.test" in result.output
    assert "truncated no" in result.output

    rows = engagement.db.execute(
        "SELECT kind, status FROM run WHERE engagement_id=?",
        (engagement.id,)).fetchall()
    assert [tuple(r) for r in rows] == [("crawl", "completed")]


def test_crawl_truncation_is_printed_not_only_logged(engagement, monkeypatch):
    """S12's rule reaches the CLI too: a truncated crawl must say so in the
    printed summary, not only in a log line an operator might not read.

    MUTATION: print `truncated no -- ...` unconditionally instead of
    branching on `summary.truncated_by`. Must go red -- this summary's
    `truncated_by` is `"max_pages"`, and the mutated line would never say
    so.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())

    def fake_crawl(*, seeds, proxy_port, budget):
        return crawl_run_mod.CrawlSummary(
            pages=200, rendered=200, degraded=0, failed=0, capped=0,
            requests=400, dropped_hosts=(), truncated_by="max_pages")

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", fake_crawl)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code == 0, result.output
    assert "truncated max_pages" in result.output


def test_crawl_closes_the_run_error_when_the_crawler_raises(
        engagement, monkeypatch):
    """A dead browser is not a completed run -- the same rule `capture
    start` follows for a dead Burp. `run.finish`'s own row must read
    `error`, not `completed`, or a report generated from a crawl that broke
    halfway would claim to be complete.

    MUTATION: always close the run `status="completed"` regardless of
    `died`. Must go red -- the stubbed crawler always raises here, so the
    row would read `completed` for a crawl that never finished.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())

    def boom(*, seeds, proxy_port, budget):
        raise RuntimeError("the browser vanished mid-crawl")

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", boom)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code != 0

    rows = engagement.db.execute(
        "SELECT kind, status FROM run WHERE engagement_id=?",
        (engagement.id,)).fetchall()
    assert [tuple(r) for r in rows] == [("crawl", "error")]


def test_crawl_gives_a_message_not_a_traceback_when_the_crawler_raises(
        engagement, monkeypatch):
    """`capture_start`'s own rule for a Burp that dies mid-session: a died
    instrument gets one clean message at the terminal, not a stack trace.
    The run still closes `error` correctly either way (see the test above);
    this is purely about what an operator running a security tool against a
    client's application sees when the crawler breaks.

    MUTATION: bare `raise` the caught exception (drop the trailing `if
    died: raise click.ClickException(died)`, restoring the original re-raise
    inside the `except BaseException` block). Must go red -- Click's runner
    would then report the raw `RuntimeError` rather than a `ClickException`,
    and `result.output` (Click's own default traceback rendering for an
    uncaught exception) would carry `Traceback` instead of one `Error: ...`
    line.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())

    def boom(*, seeds, proxy_port, budget):
        raise RuntimeError("the browser vanished mid-crawl")

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", boom)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code != 0
    assert "Error: RuntimeError: the browser vanished mid-crawl" in result.output
    assert "Traceback" not in result.output


def test_crawl_discloses_the_four_things_it_did_not_do(engagement, monkeypatch):
    """F1: spec §9 requires the CLI summary (§8's surface for long crawls) to
    disclose, in as many words, that this crawler submits no forms, clicks
    nothing, walks no interaction-gated route, and crawls unauthenticated --
    the operator running from a terminal is the one most likely to over-read
    a clean-looking result.

    Each phrase is asserted SEPARATELY and each is a multi-word phrase
    UNIQUE to this disclosure (not a bare word like "interaction" or
    "unauthenticated", which this branch's own vacuity history shows can
    match unrelated text elsewhere) -- asked of each: is there any other
    line this command could print that would contain this exact phrase? No
    other line in this command's output ever mentions forms, clicking,
    interaction-gated routes, or authentication at all.

    MUTATION: delete the `not done` loop (or drop one of `crawl_run_mod.
    NOT_DONE`'s four entries). Must go red -- the corresponding assertion
    below finds nothing to match.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())

    def fake_crawl(*, seeds, proxy_port, budget):
        return crawl_run_mod.CrawlSummary(
            pages=1, rendered=1, degraded=0, failed=0, capped=0, requests=1,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", fake_crawl)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code == 0, result.output
    assert "not done  forms are not submitted" in result.output
    assert "not done  nothing is clicked" in result.output
    assert "not done  no interaction-gated route is walked" in result.output
    assert "not done  the crawl is unauthenticated" in result.output


def test_crawl_dropped_hosts_point_at_the_denial_rows_as_authoritative(
        engagement, monkeypatch):
    """F2: `dropped_hosts` is built from seed origins, not scope
    (`hx.crawl.page.classify`'s docstring), so it can misclassify a
    target-side failure on an in-scope-but-unseeded origin as a policy drop.
    The CLI must point an operator at the denial rows -- spec §6's own
    authoritative record -- rather than let the list stand unqualified.

    MUTATION: drop the pointer line (keep only the `dropped   ...` line).
    Must go red -- this phrase appears nowhere else in the command's output.
    """
    monkeypatch.setattr(cli.session_mod, "session", _fake_session())

    def fake_crawl(*, seeds, proxy_port, budget):
        return crawl_run_mod.CrawlSummary(
            pages=1, rendered=1, degraded=0, failed=0, capped=0, requests=1,
            dropped_hosts=("cdn.test",), truncated_by=None)

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", fake_crawl)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--root", str(engagement.root)])
    assert result.exit_code == 0, result.output
    assert "denial rows, which remain authoritative" in result.output


def test_crawl_max_requests_authorises_the_session_and_bounds_the_budget(
        engagement, monkeypatch):
    """`--max-requests` is unconditional (the option always carries a value)
    and reaches both the session's own authorised budget and the crawl's
    `Budget`, so a crawl asking the browser for more than the extension was
    configured to allow does not just start collecting policy denials.

    MUTATION: drop the `eng.config = dataclasses.replace(...)` override.
    Must go red -- `seen_config["max_requests"]` would then read the
    engagement's unmodified default (2000), not the flag's 42.
    """
    seen_config = {}

    @contextlib.contextmanager
    def factory(eng, *, instance, jar=None, workdir=None):
        seen_config["max_requests"] = eng.config.max_requests
        yield _FakeLiveSession()

    monkeypatch.setattr(cli.session_mod, "session", factory)

    def fake_crawl(*, seeds, proxy_port, budget):
        seen_config["budget_max_requests"] = budget.max_requests
        return crawl_run_mod.CrawlSummary(
            pages=1, rendered=1, degraded=0, failed=0, capped=0, requests=1,
            dropped_hosts=(), truncated_by=None)

    monkeypatch.setattr(cli.crawl_run_mod, "crawl", fake_crawl)

    result = CliRunner().invoke(
        cli.main, ["crawl", "--target", "https://app.test/",
                  "--max-requests", "42",
                  "--root", str(engagement.root)])
    assert result.exit_code == 0, result.output
    assert seen_config["max_requests"] == 42
    assert seen_config["budget_max_requests"] == 42
