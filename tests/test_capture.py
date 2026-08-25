"""The consumer: one exchange frame in, one surface and one exchange row out.

This is where three components meet that were each tested alone, and the
previous branch's evidence is that boundaries are where the defects live --
every finding that survived eight task reviews was at a join.
"""
from __future__ import annotations

import hashlib

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
def cap(tmp_path):
    root = tmp_path / "engagement"
    paths_mod.secure_mkdir(root)
    conn = db_mod.connect(root / "hx.db")
    db_mod.init_schema(conn)
    conn.execute("INSERT INTO engagement(id, name, client, created_us, status)"
                 " VALUES(?,'T','T',1,'active')", (ENG,))
    cfg = config_mod.Config(name="t", client="t",
                            scope_include=["http://app.test/*"])
    c = cap_mod.Capture(conn=conn, blobs=blobs_mod.BlobStore(root / "blobs"),
                        engagement_id=ENG, config=cfg)
    yield c
    conn.close()


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

    def test_an_unrecordable_class_writes_nothing_rather_than_guessing(self, cap):
        """`records.UNRECORDABLE`: a real refusal with no `kind` to file it
        under. `row_for` answers None, and None must mean no row -- not a row
        under a reason that is not the reason."""
        assert cap.on_exchange(
            _header(t="denial", error_class="unmanaged_credential",
                    detail="Authorization header we did not inject"),
            REQ, b"") is None
        assert cap.conn.execute("SELECT COUNT(*) FROM denial").fetchone()[0] == 0
        assert cap.conn.execute("SELECT COUNT(*) FROM exchange").fetchone()[0] == 0


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


class TestRefusals:
    def test_an_unknown_via_is_refused(self, cap):
        with pytest.raises(ValueError, match="via"):
            cap.on_exchange(_header(via="carrier-pigeon"), REQ, RESP)

    def test_a_frame_with_no_url_is_refused_rather_than_guessed(self, cap):
        with pytest.raises(ValueError):
            cap.on_exchange(_header(url=None), REQ, RESP)

    def test_a_refused_frame_opens_no_run(self, cap):
        """Both refusals above are settled before `current_run`, so a stream of
        malformed frames cannot manufacture runs whose coverage is zero."""
        for bad in (_header(via="carrier-pigeon"), _header(url=None)):
            with pytest.raises(ValueError):
                cap.on_exchange(bad, REQ, RESP)
        assert cap.conn.execute("SELECT COUNT(*) FROM run").fetchone()[0] == 0


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
