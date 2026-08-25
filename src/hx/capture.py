# src/hx/capture.py
"""One exchange frame in; one surface, one exchange row, two blobs out.

Three components tested alone meet here, and on the previous branch every
defect that survived eight task reviews lived at a join like this one. So the
module is deliberately thin: it validates, it delegates, and it owns no rules
of its own beyond the order things happen in.

The order is load-bearing. Blobs are written BEFORE the row that names them,
so a crash between the two leaves an orphan blob rather than a row pointing at
nothing -- an orphan is garbage, a dangling reference is corruption.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from hx import config as config_mod
from hx import run as run_mod
from hx import surface as surface_mod
from hx.engagement import now_us
from hx.store import records
from hx.store.blobs import BlobStore


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

        if t == "dropped":
            n = int(header.get("n", 1))
            run_mod.count_drop(self.conn,
                               run_id=self._run(header.get("source", "operator")),
                               n=n)
            return None

        via = header.get("via", "proxy")
        if via not in records.VIA_VALUES:
            raise ValueError(f"unknown via {via!r}")
        url = header.get("url")
        if not url:
            raise ValueError("exchange frame has no url")
        method = header.get("method") or ""
        run_id = self._run(header.get("source", "operator"))
        at = now_us()
        run_mod.heartbeat(self.conn, run_id=run_id, now_us=at)

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
            records.record_denial(
                self.conn, run_id=run_id, kind=value, method=method, url=url,
                detail=header.get("detail") or "", at_us=at, via=via)
            return None

        n = surface_mod.normalise(
            method, url,
            preserve=frozenset(self.config.preserve_segments),
            slug_threshold=self.config.slug_threshold)

        # Blobs first: an orphan blob is garbage, a row naming a blob that was
        # never written is corruption.
        req_blob, _ = self.blobs.put(request) if request else (None, None)
        resp_blob, resp_len = (self.blobs.put(response) if response
                               else (None, None))

        exchange_id = records.record_exchange(
            self.conn, run_id=run_id, method=method, url=url,
            status=header.get("status"), req_blob=req_blob,
            resp_blob=resp_blob, resp_len=resp_len,
            ms=int(header.get("ms") or 0), at_us=at,
            outcome=header.get("outcome") or "ok", via=via)

        # S5's run.requests_issued, which nothing has ever written to. It
        # counts what LEFT, so it is bumped here and not on the denial path:
        # a refused request is in `denial`, and counting it as issued would
        # inflate every coverage figure derived from this column.
        self.conn.execute(
            "UPDATE run SET requests_issued = requests_issued + 1 WHERE id=?",
            (run_id,))

        surface_id = self.upsert_surface(n, exchange_id=exchange_id,
                                         run_id=run_id)
        # The back-reference, and it cannot be written any earlier: the
        # surface's exemplar is this exchange, so the exchange row has to exist
        # before the surface row can name it. `exchange.surface_id` is what
        # every coverage query joins on -- "which surfaces has anything
        # actually reached" -- and a NULL here is not recoverable afterwards
        # except by re-deriving the template under whatever the normaliser's
        # rules have become by then, which is the one thing
        # `normaliser_version` exists to say cannot be done.
        self.conn.execute("UPDATE exchange SET surface_id=? WHERE id=?",
                          (surface_id, exchange_id))
        return exchange_id

    def upsert_surface(self, n: surface_mod.Normalised, *, exchange_id: str,
                       run_id: str) -> str:
        """Insert or touch the surface this exchange belongs to.

        `first_seen_run` is written once and never updated; `last_seen_run`
        moves. The exemplar is likewise set only on insert -- a surface's
        exemplar is the first exchange that proved it exists, and rewriting it
        on every sighting would make "show me an example of this endpoint"
        return whatever happened most recently rather than what was reviewed.
        """
        self.conn.execute(
            "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
            " path_template, query_key_set, kind, normaliser_version,"
            " first_seen_run, last_seen_run, exemplar_exchange_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, method, scheme, host, port,"
            "             path_template, query_key_set)"
            " DO UPDATE SET last_seen_run=excluded.last_seen_run",
            (records.new_id("s"), self.engagement_id, n.method, n.scheme,
             n.host, n.port, n.path_template, n.query_key_set, n.kind,
             n.normaliser_version, run_id, run_id, exchange_id))
        return self.conn.execute(
            "SELECT id FROM surface WHERE engagement_id=? AND method=?"
            " AND scheme=? AND host=? AND port=? AND path_template=?"
            " AND query_key_set=?",
            (self.engagement_id, n.method, n.scheme, n.host, n.port,
             n.path_template, n.query_key_set)).fetchone()[0]
