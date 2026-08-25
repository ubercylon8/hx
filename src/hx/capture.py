# src/hx/capture.py
"""One exchange frame in; one surface, one exchange row, two blobs out.

Three components tested alone meet here, and on the previous branch every
defect that survived eight task reviews lived at a join like this one. So the
module is deliberately thin: it validates, and it delegates.

IT IS NOT RULE-FREE, and saying so was a claim that did not survive its own
review. The rules it owns, each named where it is written:

  - the frame-type vocabulary (`FRAME_TYPES`), and the refusal of anything
    else;
  - `source` -> run KIND, in `_run`;
  - `via` -> `surface.discovered_by`, in `DISCOVERED_BY`;
  - what an ABSENT header field means, which is nine separate decisions:
    `t`, `n`, `source`, `via`, `method`, `error_class`, `detail`, `ms` and
    `outcome` all have a default here. Only `url` and `status` have none, and
    both are refused rather than filled in -- `url` by this module, `status`
    by `record_exchange`'s coherence guard;
  - the `requests_issued` bump, and that the denial path does not do it;
  - the whole upsert/conflict policy in `upsert_surface`;
  - the `exchange.surface_id` back-reference.

TWO GUARANTEES, TWO MECHANISMS, and they are not the same one said twice:

  - ATOMICITY OF THE FOUR ROW WRITES comes from `db.transaction` and from
    nothing else. The connection is autocommit, so an unwrapped run of
    statements commits as far as it got -- measured, with `upsert_surface`
    raising: an exchange row committed with a NULL `surface_id`, no surface,
    and `requests_issued` bumped for it.
  - BLOB-BEFORE-ROW ORDERING is about the blob store, which is not in the
    database and cannot be rolled back with it. A blob written for a row that
    never commits is garbage a sweep can collect; a committed row naming a
    blob that was never written is corruption a report reads as evidence. So
    the puts stay OUTSIDE the transaction and ahead of it.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from hx import config as config_mod
from hx import run as run_mod
from hx import surface as surface_mod
from hx.engagement import now_us
from hx.store import db as db_mod
from hx.store import records
from hx.store.blobs import BlobStore

# The frame types this version knows. S6 carries an `unknown_frame` error
# class precisely because a `t` outside this set must be REFUSED: without the
# refusal, `t` fell through to the exchange arm and a `{"t": "quarantine"}`
# frame measured 1 exchange row, 1 surface, 2 blobs and `requests_issued=1` --
# traffic that never happened, inflating every coverage figure drawn from that
# column. The next frame type Plan 5 adds must be decided about here rather
# than fabricated into an exchange.
FRAME_TYPES = frozenset({"exchange", "denial", "dropped"})

# `via` (S5's egress point) -> `surface.discovered_by` (S5's discovery
# provenance). Two vocabularies, one fact, and they are spelt differently:
# S5 draws coverage off `discovered_by = 'crawl'`, and `discovered_by` has no
# 'send' -- an agent's own request is what 'agent' names. The column lost its
# DEFAULT in SCHEMA_VERSION 6, so this map is not an optimisation: an insert
# from here without it now fails.
DISCOVERED_BY = {"proxy": "proxy", "crawl": "crawl", "send": "agent"}


@dataclass
class Capture:
    conn: sqlite3.Connection
    blobs: BlobStore
    engagement_id: str
    config: config_mod.Config

    def _run(self, source: str) -> str:
        """The run this frame belongs to, opened if need be.

        `source` decides the KIND, and that mapping is the whole reason the
        two are told apart at the listener: attributing crawler traffic to a
        browse run would make the denial rows lie about who was driving, and
        the enforcement rules differ by exactly that distinction.
        """
        kind = "crawl" if source == "crawler" else "browse"
        return run_mod.current_run(
            self.conn, engagement_id=self.engagement_id, kind=kind,
            safety_profile=self.config.safety_profile)

    def on_exchange(self, header: dict, request: bytes,
                    response: bytes) -> str | None:
        """Handle one frame. Returns the exchange row id, or None.

        Called on the bridge's READ THREAD, so it must not block for long and
        must not raise into the read loop for anything recoverable -- Plan 2's
        read loop drops to DENY-ALL on an unhandled throw, which would turn a
        bookkeeping bug into an outage. A malformed frame is a ValueError the
        caller logs; a database failure is not caught here, because a store
        that cannot be written to is not a condition to carry on through.
        """
        t = header.get("t", "exchange")
        if t not in FRAME_TYPES:
            raise ValueError(
                f"unknown frame type {t!r}; this version knows "
                f"{sorted(FRAME_TYPES)}. S6 answers one with the "
                "`unknown_frame` error class -- one frame refused, the channel "
                "kept -- and recording it as an exchange would file traffic "
                "that never happened")

        if t == "dropped":
            # Parsed and bounded BEFORE `_run`, so a malformed drop report
            # cannot manufacture a run whose coverage is zero. `count_drop`
            # refuses the same bound at the writer; see its docstring for why
            # a negative n is the one that matters.
            drops = int(header.get("n", 1))
            if drops < 1:
                raise ValueError(
                    f"a dropped frame reporting n={drops!r} is malformed; "
                    "run.dropped_total is an accumulator and S5 makes it the "
                    "reason a run's coverage numbers are a floor")
            run_id = self._run(header.get("source", "operator"))
            # The drop path heartbeats too, and that is not decoration. A
            # saturated harness may be dropping every exchange it sees while
            # reporting each drop faithfully; without this, `heartbeat_us`
            # never moved, and after IDLE_CLOSE_US the next drop report made
            # `current_run` close the run `completed`/`idle` and open another
            # -- MEASURED at status='completed', stop_reason='idle',
            # dropped_total=100, with the rest of the total on a second run.
            # A run that dropped 100 exchanges is the definition of incomplete
            # coverage and it read as a clean, idle one.
            #
            # `idle` STAYS the reason for a genuine idle close, drops or not:
            # the close is made by a LIVE harness observing a quiet window,
            # which is what separates it from `reap_stale`'s `error` close for
            # a harness that is gone. `completed` says the run ENDED cleanly,
            # never that its coverage is complete -- `dropped_total` on the
            # same row is what says otherwise, and the heartbeat above is what
            # keeps that number whole instead of fragmenting it across a chain
            # of runs where no single row shows the drops.
            run_mod.heartbeat(self.conn, run_id=run_id, now_us=now_us())
            run_mod.count_drop(self.conn, run_id=run_id, n=drops)
            return None

        via = header.get("via", "proxy")
        if via not in records.VIA_VALUES:
            raise ValueError(f"unknown via {via!r}")
        url = header.get("url")
        if not url:
            raise ValueError("exchange frame has no url")
        method = header.get("method") or ""

        # EVERY REFUSAL ABOUT THE FRAME ITSELF RUNS ABOVE `_run`. `row_for`
        # raises on an error class it cannot place -- including the empty
        # string the `or ""` below produces -- and `normalise` is explicitly
        # NOT TOTAL: `http://h:abc/x` raises on the port. Both used to run
        # after the run was opened, so a stream of malformed frames measured
        # one empty run each, which is precisely what
        # `test_a_refused_frame_opens_no_run` says cannot happen. Neither call
        # touches the database, so hoisting them costs nothing and the run is
        # opened only once this frame is known to be recordable.
        #
        # ONE REFUSAL IS STILL BELOW, deliberately: `record_exchange`'s
        # coherence guards are the STORE's, they fire on a frame this module
        # already accepted, and they are about what the ROW would claim rather
        # than about whether the frame could be read. That case does leave an
        # empty run behind, and
        # `test_the_one_refusal_that_does_leave_a_run_behind` pins the
        # boundary from that side so the sentence above stays exactly as wide
        # as it is true.
        if t == "denial":
            error_class = header.get("error_class") or ""
            # row_for answers ("denial", kind) OR ("exchange", outcome) -- it
            # is the supported way in precisely because reading DENIAL_KIND
            # directly gets the precedence wrong for the two classes that
            # appear in both maps. So the table it names is checked, not
            # assumed: passing an OUTCOME where a KIND belongs is not a thing
            # to find out about downstream.
            #
            # MEASURED, because the two sentences the brief wrote here were
            # both claims and both are false. (1) The branch is UNREACHABLE
            # while `issued=False`, and no input can redden it: `row_for`'s
            # third arm is the only one that answers ("exchange", ...), and
            # every key of EXCHANGE_OUTCOME is caught by an earlier arm --
            # scope_denied and rate_limited by DENIAL_KIND, timeout and
            # bridge_lost by AMBIGUOUS_ISSUANCE, which answers None when the
            # request never left. The reachable answers here are
            # ("denial", kind), None, and ValueError. (2) It would NOT "fail
            # the denial table's CHECK": `record_denial` checks `kind` against
            # DENIAL_KINDS itself, so `kind='timeout'` raises ValueError in
            # Python and never reaches SQLite at all.
            #
            # It stays anyway, because (1) is a fact about TODAY'S maps rather
            # than about this call -- EXCHANGE_OUTCOME gaining one key that
            # neither DENIAL_KIND nor AMBIGUOUS_ISSUANCE names makes the
            # branch live -- and because it names the TABLE in its message,
            # which the check downstream cannot. `issued=False` is the load-
            # bearing half of the pair and IS pinned; see
            # test_a_denial_frame_says_the_request_never_left.
            row = records.row_for(error_class, issued=False)
            if row is None:
                return None
            table, value = row
            if table != "denial":
                raise ValueError(
                    f"{error_class!r} routes to {table!r}, not a denial; a "
                    "dropped request that produced no exchange cannot be "
                    "recorded as one")
            run_id = self._run(header.get("source", "operator"))
            at = now_us()
            run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)
            records.record_denial(
                self.conn, run_id=run_id, kind=value, method=method, url=url,
                detail=header.get("detail") or "", at_us=at, via=via)
            return None

        norm = surface_mod.normalise(
            method, url,
            preserve=frozenset(self.config.preserve_segments),
            slug_threshold=self.config.slug_threshold)
        run_id = self._run(header.get("source", "operator"))
        at = now_us()
        run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)

        # Blobs before the transaction, deliberately: the blob store is not in
        # the database, so a ROLLBACK cannot take a file back. Writing them
        # first means a failed exchange leaves an orphan blob, which is
        # garbage a sweep can collect; writing them after a committed row that
        # names them would leave corruption a report reads as evidence. This
        # is an ordering argument only -- the four writes below are atomic
        # because of the transaction, not because of where they sit.
        req_blob, _ = self.blobs.put(request) if request else (None, None)
        resp_blob, resp_len = (self.blobs.put(response) if response
                               else (None, None))

        # One unit. `db.connect` is autocommit, so without this each statement
        # commits on its own: `upsert_surface` failing -- "database is locked"
        # under WAL past busy_timeout is enough -- MEASURED an exchange row
        # committed with `surface_id` NULL, no surface row, and
        # `requests_issued` bumped for it. That NULL is the exact state the
        # back-reference was added to prevent, and it is unrecoverable
        # afterwards.
        with db_mod.transaction(self.conn):
            exchange_id = records.record_exchange(
                self.conn, run_id=run_id, method=method, url=url,
                status=header.get("status"), req_blob=req_blob,
                resp_blob=resp_blob, resp_len=resp_len,
                ms=int(header.get("ms") or 0), at_us=at,
                outcome=header.get("outcome") or "ok", via=via)

            # S5's run.requests_issued, which nothing has ever written to. It
            # counts what LEFT, so it is bumped here and not on the denial
            # path: a refused request is in `denial`, and counting it as
            # issued would inflate every coverage figure derived from this
            # column.
            self.conn.execute(
                "UPDATE run SET requests_issued = requests_issued + 1"
                " WHERE id=?", (run_id,))

            surface_id = self.upsert_surface(norm, exchange_id=exchange_id,
                                             run_id=run_id, via=via)
            # The back-reference, and it cannot be written any earlier: the
            # surface's exemplar is this exchange, so the exchange row has to
            # exist before the surface row can name it. `exchange.surface_id`
            # is what every coverage query joins on -- "which surfaces has
            # anything actually reached" -- and a NULL here is not recoverable
            # afterwards except by re-deriving the template under whatever the
            # normaliser's rules have become by then, which is the one thing
            # `normaliser_version` exists to say cannot be done.
            self.conn.execute("UPDATE exchange SET surface_id=? WHERE id=?",
                              (surface_id, exchange_id))
        return exchange_id

    def upsert_surface(self, n: surface_mod.Normalised, *, exchange_id: str,
                       run_id: str, via: str) -> str:
        """Insert or touch the surface this exchange belongs to.

        `first_seen_run` is written once and never updated; `last_seen_run`
        moves. The exemplar is likewise set only on insert -- a surface's
        exemplar is the first exchange that proved it exists, and rewriting it
        on every sighting would make "show me an example of this endpoint"
        return whatever happened most recently rather than what was reviewed.

        `discovered_by` is in the same family as the exemplar and is likewise
        untouched by the `DO UPDATE`: it answers WHICH EGRESS POINT FOUND
        this surface, and the crawler seeing an endpoint the proxy already
        recorded does not make it a crawler discovery. S5 draws a coverage
        figure straight off that distinction.
        """
        self.conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, query_key_set, kind, discovered_by,"
            " normaliser_version, first_seen_run, last_seen_run,"
            " exemplar_exchange_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, method, scheme, host, port,"
            "             path_template, query_key_set)"
            " DO UPDATE SET last_seen_run=excluded.last_seen_run",
            (records.new_id("s"), self.engagement_id, n.method, n.scheme,
             n.host, n.port, n.path_template, n.query_key_set, n.kind,
             DISCOVERED_BY[via],
             n.normaliser_version, run_id, run_id, exchange_id))
        return self.conn.execute(
            "SELECT id FROM surface WHERE engagement_id=? AND method=?"
            " AND scheme=? AND host=? AND port=? AND path_template=?"
            " AND query_key_set=?",
            (self.engagement_id, n.method, n.scheme, n.host, n.port,
             n.path_template, n.query_key_set)).fetchone()[0]
