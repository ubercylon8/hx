"""The consumer: one exchange frame in, one surface and one exchange row out.

This is where three components meet that were each tested alone, and the
previous branch's evidence is that boundaries are where the defects live --
every finding that survived eight task reviews was at a join.
"""
from __future__ import annotations

import hashlib
import sqlite3

import pytest

from hx import capture as cap_mod
from hx import config as config_mod
from hx import run as run_mod
from hx.store import blobs as blobs_mod
from hx.store import db as db_mod
from hx.store import paths as paths_mod

ENG = "e-test"
REQ = (b"GET /order/7?id=1 HTTP/1.1\r\nHost: app.test\r\n"
       b"Cookie: session=[REDACTED]\r\n\r\n")
RESP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"


@pytest.fixture
def cap_with(tmp_path):
    """Build a Capture over a config THE TEST chooses.

    `preserve_segments` and `slug_threshold` reach the normaliser through this
    call and through nothing else, so a fixture that fixes them leaves the
    threading unpinned: replacing both with constants reddened no test in the
    task's own set. A factory is what lets a test separate the operator's
    value from the default.
    """
    opened = []

    def make(**cfg_over):
        root = tmp_path / f"engagement{len(opened)}"
        paths_mod.secure_mkdir(root)
        conn = db_mod.connect(root / "hx.db")
        db_mod.init_schema(conn)
        conn.execute("INSERT INTO engagement(id, name, client, created_us,"
                     " status) VALUES(?,'T','T',1,'active')", (ENG,))
        opened.append(conn)
        cfg = config_mod.Config(name="t", client="t",
                                scope_include=["http://app.test/*"],
                                **cfg_over)
        return cap_mod.Capture(conn=conn,
                               blobs=blobs_mod.BlobStore(root / "blobs"),
                               engagement_id=ENG, config=cfg)

    yield make
    for conn in opened:
        conn.close()


@pytest.fixture
def cap(cap_with):
    return cap_with()


def _header(**over) -> dict:
    h = {"v": 1, "t": "exchange", "method": "GET",
         "url": "http://app.test/order/7?id=1", "status": 200, "ms": 12,
         "via": "proxy", "outcome": "ok", "source": "operator"}
    h.update(over)
    return h


class TestTheHappyPath:
    def test_one_frame_writes_one_exchange_row(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        assert rid is not None
        row = cap.conn.execute("SELECT via, status, method FROM exchange"
                               " WHERE id=?", (rid,)).fetchone()
        assert tuple(row) == ("proxy", 200, "GET")

    def test_and_opens_a_browse_run_without_being_asked(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        kind = cap.conn.execute("SELECT kind FROM run").fetchone()[0]
        assert kind == "browse"

    def test_and_stores_both_halves_as_blobs(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        req_blob, resp_blob = cap.conn.execute(
            "SELECT req_blob, resp_blob FROM exchange WHERE id=?", (rid,)).fetchone()
        assert cap.blobs.get(req_blob) == REQ
        assert cap.blobs.get(resp_blob) == RESP

    def test_and_creates_one_surface(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        row = cap.conn.execute("SELECT path_template, query_key_set, kind"
                               " FROM surface").fetchone()
        assert tuple(row) == ("/order/{id}", "id", "idempotent_read")

    def test_and_the_exchange_names_the_surface_it_belongs_to(self, cap):
        """The join the whole plan is for, and it was written by nothing.

        `exchange.surface_id` is a column, has its own index
        (`idx_exchange_surf`), and every coverage figure in a report is a join
        across it: "which surfaces has anything actually reached". The task
        brief's consumer computed the surface id and threw it away, which left
        the column NULL on every row this egress point will ever write -- and
        a NULL there is not recoverable later without re-deriving the template
        from the url under whatever the normaliser's rules have become by
        then, which is the one thing `normaliser_version` exists to say cannot
        be done.
        """
        rid = cap.on_exchange(_header(), REQ, RESP)
        surface_id, = cap.conn.execute(
            "SELECT surface_id FROM exchange WHERE id=?", (rid,)).fetchone()
        assert surface_id is not None
        assert surface_id == cap.conn.execute(
            "SELECT id FROM surface").fetchone()[0]


class TestWhatTheHeaderSays:
    """Every header field this module threads into a row, separated from its
    absence.

    MEASURED before these existed: `resp_len` -> always None, `ms` -> 0,
    `outcome` -> "ok", the `via` default -> "send", the `method` default ->
    "GET", and the whole `config` -> `normalise` threading replaced by
    constants -- six mutations, zero red tests between them. A field nothing
    checks is a field that can be dropped on the floor without anyone finding
    out, and the rows are the only evidence this plan produces.
    """

    def test_the_response_length_is_the_response_it_measured(self, cap):
        rid = cap.on_exchange(_header(), REQ, RESP)
        assert cap.conn.execute("SELECT resp_len FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == len(RESP)

    def test_the_elapsed_time_separates_the_two_timestamps(self, cap):
        """`ms` is the only thing that makes `recv_us` differ from `sent_us`,
        and hardcoding it to 0 made every exchange look instantaneous."""
        rid = cap.on_exchange(_header(ms=12), REQ, RESP)
        sent, recv = cap.conn.execute(
            "SELECT sent_us, recv_us FROM exchange WHERE id=?", (rid,)).fetchone()
        assert recv - sent == 12_000

    def test_the_outcome_is_the_frame_s_and_not_an_assumption_of_ok(self, cap):
        """`ok` is the guessing direction: it claims a response came back.

        `header.get("outcome") or "ok"` turns an absent outcome into that
        claim, so the value that separates the two is one the frame carries
        and `"ok"` is not.
        """
        rid = cap.on_exchange(_header(outcome="truncated"), REQ, RESP)
        assert cap.conn.execute("SELECT outcome FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == "truncated"

    def test_a_frame_that_names_no_via_is_proxy_traffic(self, cap):
        """The default this whole task exists to keep honest.

        `via` tells the two egress points apart -- it is the stated reason
        `denial` gained the column and SCHEMA_VERSION went to 5. Defaulting to
        `"send"` instead files proxy observations as send-path traffic, which
        is exactly the conflation being ended, and no test could see it.
        """
        h = _header()
        del h["via"]
        rid = cap.on_exchange(h, REQ, RESP)
        assert cap.conn.execute("SELECT via FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == "proxy"

    def test_a_frame_that_names_no_method_says_so_rather_than_guessing_GET(self, cap):
        """`""` and `"GET"` are not the same missing value.

        `surface.kind` is derived from the method, and `GET` earns
        `idempotent_read` -- a check reading that is being told it may replay
        the request. A method nobody sent must not buy that permission.
        """
        h = _header()
        del h["method"]
        rid = cap.on_exchange(h, REQ, RESP)
        assert cap.conn.execute("SELECT method FROM exchange WHERE id=?",
                                (rid,)).fetchone()[0] == ""
        assert cap.conn.execute("SELECT kind FROM surface").fetchone()[0] == "unknown"

    def test_the_operator_s_preserve_list_reaches_the_normaliser(self, cap_with):
        """Task 2 spent a round establishing this rule; the call site can undo
        it silently. `2024` is digit-shaped, so it templates to `{id}` unless
        the operator's `preserve` list arrives here and says it is a route."""
        cap = cap_with(preserve_segments=["2024"])
        cap.on_exchange(_header(url="http://app.test/2024/report"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT path_template FROM surface").fetchone()[0] == "/2024/report"

    def test_and_so_does_the_operator_s_slug_threshold(self, cap_with):
        """`abc-123-xyz` is 11 characters: a slug at threshold 8, a route at
        the default 12. Only the config can move that line."""
        cap = cap_with(slug_threshold=8)
        cap.on_exchange(_header(url="http://app.test/abc-123-xyz"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT path_template FROM surface").fetchone()[0] == "/{slug}"

    def test_the_surface_records_which_egress_point_found_it(self, cap):
        """`surface.discovered_by`, which lost its DEFAULT in SCHEMA_VERSION
        6. S5 draws a coverage figure straight off it -- "crawl-discovered
        surfaces are recorded with discovered_by = 'crawl'" -- so the value a
        writer that never thought about it used to get was a wrong answer to a
        question a report asks."""
        cap.on_exchange(_header(via="proxy"), REQ, RESP)
        cap.on_exchange(_header(via="crawl", source="crawler",
                                url="http://app.test/other"), REQ, RESP)
        rows = dict(cap.conn.execute(
            "SELECT path_template, discovered_by FROM surface"))
        assert rows == {"/order/{id}": "proxy", "/other": "crawl"}

    def test_and_the_first_finder_keeps_the_credit(self, cap):
        """Same family as the exemplar, and the `DO UPDATE` must not touch it:
        the crawler walking into an endpoint the proxy already recorded does
        not make it a crawler discovery."""
        cap.on_exchange(_header(via="proxy"), REQ, RESP)
        cap.on_exchange(_header(via="crawl", source="crawler"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT discovered_by FROM surface").fetchone()[0] == "proxy"


class TestDeduplication:
    def test_two_ids_under_one_endpoint_are_one_surface(self, cap):
        """The sentence S5 exists for. Without this, /order/1..9999 is 9999
        rows and every coverage number derived from them is meaningless."""
        cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 1

    def test_but_a_different_query_key_set_is_a_different_surface(self, cap):
        """Separates dedup from 'merge everything on this path'. A parameter
        is an input, and an input is where a flaw lives."""
        cap.on_exchange(_header(url="http://app.test/order/1?id=1"), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/1?debug=1"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 2

    def test_and_a_different_method_is_a_different_surface(self, cap):
        cap.on_exchange(_header(method="GET"), REQ, RESP)
        cap.on_exchange(_header(method="POST"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 2

    def test_the_second_sighting_updates_last_seen_not_first_seen(self, cap):
        cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        first = cap.conn.execute("SELECT first_seen_run FROM surface").fetchone()[0]
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        row = cap.conn.execute("SELECT first_seen_run, last_seen_run"
                               " FROM surface").fetchone()
        assert row[0] == first

    def test_a_sighting_in_a_LATER_run_moves_last_seen_and_not_first_seen(self, cap):
        """The input that separates `DO UPDATE` from `INSERT OR IGNORE`.

        The test above cannot: both its sightings land in ONE run, so
        `last_seen_run` holds the same value whether the conflicting insert
        updated it or was silently discarded, and it asserts only
        `first_seen_run` besides. Mutating the upsert to `INSERT OR IGNORE`
        left it green -- a rule invisible to the test named after it, which is
        the shape this plan has now found on every task.

        Two runs is what makes the two columns disagree, and both directions
        matter: `first_seen_run` is when this endpoint entered the assessment
        and `last_seen_run` is whether it is still there. The exemplar is
        checked in the same breath, because it is written on insert and the
        `DO UPDATE` deliberately does not touch it -- a surface's exemplar is
        the exchange that PROVED it exists, and rewriting it on every sighting
        would make "show me an example of this endpoint" answer with whatever
        happened most recently rather than with what was reviewed.
        """
        first_x = cap.on_exchange(_header(url="http://app.test/order/1"), REQ, RESP)
        first_run, exemplar = cap.conn.execute(
            "SELECT first_seen_run, exemplar_exchange_id FROM surface").fetchone()
        assert exemplar == first_x
        run_mod.close_run(cap.conn, run_id=first_run)

        second_x = cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        second_run, = cap.conn.execute(
            "SELECT run_id FROM exchange WHERE id=?", (second_x,)).fetchone()
        assert second_run != first_run

        row = cap.conn.execute(
            "SELECT first_seen_run, last_seen_run, exemplar_exchange_id"
            " FROM surface").fetchone()
        assert tuple(row) == (first_run, second_run, first_x)


class TestDenials:
    def test_a_dropped_request_writes_a_denial_and_no_exchange(self, cap):
        cap.on_exchange(_header(t="denial", error_class="scope_denied",
                                detail="matches no scope.include pattern"),
                        REQ, b"")
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        kind = cap.conn.execute("SELECT kind FROM denial").fetchone()[0]
        assert kind == "scope"

    def test_and_the_denial_records_which_egress_point_refused(self, cap):
        cap.on_exchange(_header(t="denial", error_class="scope_denied", detail="x"),
                        REQ, b"")
        assert cap.conn.execute("SELECT via FROM denial").fetchone()[0] == "proxy"

    def test_a_refused_request_is_not_counted_as_one_that_left(self, cap):
        """S5's `requests_issued` counts what LEFT.

        A denial is a request that never did, so the counter must not move for
        it -- counting refusals as issued inflates every coverage figure
        derived from the column, and a report claiming reach the run never had
        is the failure this store exists to avoid.

        MEASURED: with only the brief's own tests in the file, moving the bump
        above the `t == "denial"` branch reddened NOTHING -- the counter was
        written by the consumer and read by nobody. It now reddens this and
        `test_each_exchange_is_counted_against_the_run_that_issued_it`, which
        are the two halves of the rule: bumped there, and not bumped here.
        """
        cap.on_exchange(_header(t="denial", error_class="scope_denied", detail="x"),
                        REQ, b"")
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0

    def test_a_denial_frame_says_the_request_never_left(self, cap):
        """`row_for(..., issued=False)`, and it was pinned by nothing.

        `timeout` and `bridge_lost` each name a request that left the JVM AND
        one that never did, so `row_for` refuses to route either from the
        class alone. A denial frame is the case where it never did -- that is
        what makes it a denial -- so this consumer answers False, and
        `row_for` then writes NO row at all: `denial.kind` has no value for
        "the caller gave up before we started", and a row filed under a reason
        that is not the reason is worse than no row.

        Flipping the argument to True was invisible to the whole suite. It is
        not invisible here: True routes the same frame to ("exchange",
        "timeout"), which is an exchange row for a request that was never
        sent -- the one direction every guard in `records` leans against,
        because it inflates `requests_issued` and every coverage figure drawn
        from it.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="timeout",
                    detail="deadline passed before this frame was decided"),
            REQ, b"") is None
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0

    def test_a_credential_refusal_is_a_denial_and_not_a_silence(self, cap):
        """S4 is unconditional and this was the class that escaped it.

        MEASURED at the previous commit: an `unmanaged_credential` denial
        reaching this egress point produced no row, no counter, no log and no
        exception, and `on_exchange` returned None -- indistinguishable from a
        recorded denial and from a drop report. `records.UNRECORDABLE` itself
        called it "a real denial ... the gap to close first", and the reason
        it had nowhere to go was that `denial.kind`'s CHECK had no value for
        it. SCHEMA_VERSION 6 adds one.

        S7's "refused and never persisted" is about the REQUEST BYTES: the row
        below carries the method, the url and a reason, and no credential.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="unmanaged_credential",
                    detail="Authorization header we did not inject"),
            REQ, b"") is None
        row = cap.conn.execute("SELECT kind, via, url, reason FROM denial").fetchone()
        assert tuple(row) == ("credential", "proxy",
                              "http://app.test/order/7?id=1",
                              "Authorization header we did not inject")
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0

    def test_an_unrecordable_class_writes_nothing_rather_than_guessing(self, cap):
        """`records.UNRECORDABLE`: a class with no row to file it under.

        `row_for` answers None, and None must mean no row -- not a row under a
        reason that is not the reason. `transport_error` is one of the seven
        left in that set: the request DID leave the JVM, so it belongs in
        `exchange`, and the extension reports one class for conn_refused,
        dns_error and tls_error alike, so picking one of the three would put a
        guess in the evidence store.

        No run either, since the routing decision is now settled above `_run`:
        a frame that produces nothing must not leave a run behind claiming
        zero coverage.
        """
        assert cap.on_exchange(
            _header(t="denial", error_class="transport_error",
                    detail="the connection did not complete"),
            REQ, b"") is None
        assert cap.conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0


class TestDrops:
    def test_a_drop_report_is_counted_against_the_run(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        cap.on_exchange(_header(t="dropped", n=4), b"", b"")
        assert cap.conn.execute("SELECT dropped_total FROM run").fetchone()[0] == 4

    def test_a_drop_report_before_any_exchange_still_lands(self, cap):
        """The queue can overflow before the first exchange gets through --
        that is precisely the case where the harness was slow to start. A
        counter that needed a run to exist first would lose exactly the drops
        that matter most."""
        cap.on_exchange(_header(t="dropped", n=2), b"", b"")
        assert cap.conn.execute("SELECT dropped_total FROM run").fetchone()[0] == 2

    def test_a_saturated_run_is_not_an_idle_one(self, cap):
        """A harness dropping everything is the opposite of an idle harness.

        MEASURED before the drop path heartbeated: a run receiving only
        `dropped` frames never moved `heartbeat_us`, so after IDLE_CLOSE_US
        the next drop report made `current_run` close it
        `status='completed', stop_reason='idle'` with `dropped_total=100` on
        it and open a fresh run for the rest. S5, quoted in `run.py`'s own
        docstring: "an aborted run must never render as a clean one, and
        neither must one that merely stopped being updated." A run that
        dropped a hundred exchanges is incomplete coverage by definition, and
        it read as clean -- while the total fragmented across a chain of runs
        where no single row showed the drops.

        Each frame here is followed by winding the heartbeat back two thirds
        of the window. Beating on every drop keeps the age at two thirds
        forever; not beating accumulates it, and the third frame arrives at
        four thirds of the window -- which is what makes this two runs rather
        than one.
        """
        for _ in range(3):
            cap.on_exchange(_header(t="dropped", n=50), b"", b"")
            cap.conn.execute(
                "UPDATE run SET heartbeat_us = heartbeat_us - ?"
                " WHERE status='running'", (run_mod.IDLE_CLOSE_US * 2 // 3,))
        rows = cap.conn.execute("SELECT status, dropped_total FROM run").fetchall()
        assert [tuple(r) for r in rows] == [("running", 150)]


class TestRefusals:
    def test_an_unknown_via_is_refused(self, cap):
        with pytest.raises(ValueError, match="via"):
            cap.on_exchange(_header(via="carrier-pigeon"), REQ, RESP)

    def test_a_frame_with_no_url_is_refused_rather_than_guessed(self, cap):
        with pytest.raises(ValueError):
            cap.on_exchange(_header(url=None), REQ, RESP)

    def test_a_frame_type_this_version_does_not_know_is_refused(self, cap):
        """S6 carries an `unknown_frame` class precisely for this.

        MEASURED with no else-arm on `t`: `{"t": "quarantine", ...}` returned
        a row id and wrote 1 exchange row, 1 surface, 2 blobs and
        `requests_issued = 1`. Plan 5's crawler, or any later extension build,
        adds one frame type this side does not know and every such frame
        becomes observed traffic that never existed -- inflating every
        coverage figure drawn from that column, in a store whose entire
        purpose is not to claim reach a run never had.
        """
        with pytest.raises(ValueError, match="unknown frame type"):
            cap.on_exchange(_header(t="quarantine"), REQ, RESP)
        for table in ("exchange", "surface", "run"):
            assert cap.conn.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
        assert not cap.blobs.path_for(hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_drop_report_that_would_run_the_counter_backwards_is_refused(self, cap):
        """`int(header.get("n", 1))` was unchecked and MEASURED
        `dropped_total = -5`. See `run.count_drop`, which refuses the same
        bound at the writer; this is the same refusal placed early enough that
        the malformed frame does not leave a run behind either."""
        cap.on_exchange(_header(t="dropped", n=3), b"", b"")
        with pytest.raises(ValueError, match="floor"):
            cap.on_exchange(_header(t="dropped", n=-5), b"", b"")
        assert cap.conn.execute(
            "SELECT dropped_total FROM run").fetchone()[0] == 3

    def test_a_refused_frame_opens_no_run(self, cap):
        """Each frame below is refused before `current_run` is reached, so a
        stream of malformed frames manufactures neither runs whose coverage is
        zero nor blob files nothing will ever name.

        THE LIST IS THE CLAIM; the module's comment deliberately no longer
        says it is complete. Five of the entries were added after being
        measured opening a run: the unparseable port (`normalise` is
        explicitly NOT TOTAL), the unrecognised `error_class` and the empty
        string `header.get("error_class") or ""` produces, and then `ms="abc"`
        and `outcome="bogus"`, which raised from INSIDE `record_exchange` --
        below the blob puts as well. Three frames of either measured 1 run, 0
        exchanges and 2 orphan blob files: six puts of two distinct bodies
        into a content-addressed store.

        The blob assertion is why the last two belong here rather than in a
        test of their own: a refusal that opens no run can still leave files
        behind, and that is strictly the worse leak of the two -- a run with
        no exchanges is visible in the store, an orphan blob is not.
        """
        bad_frames = (
            _header(via="carrier-pigeon"),
            _header(url=None),
            _header(t="quarantine"),
            _header(t="dropped", n=-5),
            _header(url="http://h:abc/x"),
            _header(t="denial", error_class="no-such-class"),
            _header(t="denial", error_class=""),
            _header(ms="abc"),
            _header(outcome="bogus"),
        )
        for bad in bad_frames:
            with pytest.raises(ValueError):
                cap.on_exchange(bad, REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0
        assert not cap.blobs.path_for(
            hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_response_that_came_back_cannot_be_filed_without_a_status(self, cap):
        """An absent `status` is refused, not written as NULL.

        This module invents a default for nine header fields and for `status`
        it invents nothing -- so the frame with no `status` key at all had to
        land somewhere, and for `outcome='truncated'` it landed on disk:
        MEASURED `ACCEPTED rid=x-...  exchange 1  surface 1
        requests_issued 1  status NULL`. `record_exchange` guarded only 'ok'
        and 'status_unreadable'.

        A truncated response is a response that CAME BACK, so that row said a
        peer answered and declined to say what it answered -- while
        `status_unreadable` plus the 599 sentinel is the store's whole
        apparatus for saying exactly that. A NULL status now carries one
        reading and only one: nothing on the far side ever answered.
        """
        header = _header(outcome="truncated")
        del header["status"]
        with pytest.raises(ValueError, match="no status"):
            cap.on_exchange(header, REQ, RESP)
        assert cap.conn.execute(
            "SELECT COUNT(*) FROM exchange").fetchone()[0] == 0

    def test_the_one_refusal_that_does_leave_a_run_behind(self, cap):
        """The boundary of the sentence above, pinned from the other side.

        `record_exchange`'s coherence guards belong to the STORE, not to this
        module, and they fire on a frame whose shape was already accepted --
        `outcome='ok'` with no status is a frame that says two things which
        cannot both be true. By then the run exists and has been heartbeated.
        An empty run is the honest cost: something WAS captured here, and the
        refusal is about what the row would have claimed rather than about
        whether the frame could be read at all.
        """
        with pytest.raises(ValueError):
            cap.on_exchange(_header(status=None), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0


class TestTheOrderThingsHappenIn:
    def test_a_row_that_cannot_be_written_leaves_its_blob_behind(self, cap):
        """The separating input for "blobs before the row that names them".

        The ordering guards a crash between two statements, and no unit test
        can crash the interpreter -- so the brief expected this invariant to be
        unpinned and it very nearly was. What CAN be observed is the same
        window reached by a different route: `record_exchange`'s own coherence
        guard refuses `outcome='ok'` with no status, and it refuses at exactly
        the point a crash would land. Blobs-first therefore leaves an ORPHAN
        BLOB and no row; blobs-after leaves a row-less store and no blob, which
        is the same state -- but with the two statements the other way round a
        successful put followed by a failed row is impossible to reach, so the
        assertion below is False.

        The asymmetry is the point and is worth saying plainly: an orphan blob
        is garbage a sweep can collect, and a row naming a blob that was never
        written is corruption a report reads as evidence.
        """
        with pytest.raises(ValueError):
            cap.on_exchange(_header(status=None), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.blobs.path_for(hashlib.sha256(REQ).hexdigest()).exists()

    def test_a_failure_partway_through_leaves_no_half_written_exchange(self, cap):
        """The four row writes are one unit, and they were four units.

        `db.connect` is autocommit and `records`'s own docstring says so --
        "a caller writing an exchange row and its blobs together should wrap
        the pair in `db.transaction` itself". Unwrapped, with `upsert_surface`
        raising `OperationalError("database is locked")` -- which WAL plus a
        concurrent writer past `busy_timeout=5000` is enough to produce --
        this MEASURED an exchange row COMMITTED with `surface_id` NULL, zero
        surface rows, and `requests_issued = 1`. That NULL is the precise
        state the back-reference was added to prevent and cannot be repaired
        afterwards, and the counter is then a phantom issued request.

        Ordering cannot fix this one: the back-reference has to come last
        because the surface's exemplar is the exchange. Atomicity is the
        mechanism, and it is a different mechanism from the blob ordering
        above -- which stays, because the blob store is not in the database
        and no ROLLBACK reaches it.
        """
        def explode(*_a, **_k):
            raise sqlite3.OperationalError("database is locked")

        cap.upsert_surface = explode
        with pytest.raises(sqlite3.OperationalError):
            cap.on_exchange(_header(), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM surface").fetchone()[0] == 0
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 0


class TestTheRunTheFrameBelongsTo:
    def test_crawler_traffic_is_a_crawl_run_and_not_a_browse_one(self, cap):
        """`source` decides the kind, and nothing else did.

        MEASURED: collapsing the mapping to a constant `"browse"` reddened no
        test in the brief's own set. `test_and_opens_a_browse_run_without_
        being_asked` asserts the branch a constant already satisfies, and it
        was the only test that looked at `run.kind`. Attributing crawler
        traffic to a browse run would make the denial rows lie about who was
        driving, and the enforcement rules differ by exactly that distinction.
        """
        cap.on_exchange(_header(source="crawler"), REQ, RESP)
        assert cap.conn.execute("SELECT kind FROM run").fetchone()[0] == "crawl"
        cap.on_exchange(_header(source="operator"), REQ, RESP)
        assert set(r[0] for r in cap.conn.execute("SELECT kind FROM run")) == \
            {"crawl", "browse"}

    def test_each_exchange_is_counted_against_the_run_that_issued_it(self, cap):
        cap.on_exchange(_header(), REQ, RESP)
        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute(
            "SELECT requests_issued FROM run").fetchone()[0] == 2

    def test_a_frame_keeps_its_run_alive(self, cap):
        """The heartbeat, separated from its absence.

        `run.reap_stale` resolves a run whose heartbeat went stale to `error`
        -- "its coverage is incomplete" -- so a capture session that beats only
        when the run is OPENED is one that reports itself as a crash after
        half an hour of steady browsing. The window below is inside
        IDLE_CLOSE_US, so `current_run` returns the same run rather than
        closing it as idle, which is what makes the update observable.
        """
        cap.on_exchange(_header(), REQ, RESP)
        run_id, = cap.conn.execute("SELECT id FROM run").fetchone()
        stale = cap.conn.execute(
            "SELECT heartbeat_us FROM run").fetchone()[0] - run_mod.IDLE_CLOSE_US // 2
        cap.conn.execute("UPDATE run SET heartbeat_us=? WHERE id=?",
                         (stale, run_id))

        cap.on_exchange(_header(url="http://app.test/order/2"), REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 1
        assert cap.conn.execute(
            "SELECT heartbeat_us FROM run").fetchone()[0] > stale
