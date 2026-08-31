"""One `agent_action` row per dispatch, refusals included.

WHY REFUSALS TOO. Section 8 asks `run.journal` to answer "what have I already
tried this run". A journal holding only what worked answers that question with
"everything that worked", which is the shape of every agent loop this table
exists to break: the tool that keeps being refused is precisely the one the
agent keeps retrying.

`args_blob` IS INLINE JSON TO 4096 BYTES AND `sha256:<digest>` ABOVE IT. The
column's name follows `exchange.req_blob` and `resp_blob`, which are digests --
but `http.send` can carry a 100 KB request and `scan.run` a thousand surface
ids, while the overwhelming majority of calls are a few hundred bytes and
`run.journal` is the most-read tool in the set. Inline-with-spill keeps the
common read a single row and refuses to truncate the record of what was tried.
The `sha256:` prefix makes the two cases unambiguous to whoever reads the
column, which a bare digest would not.

STORING ARGUMENTS VERBATIM IS SAFE ONLY BECAUSE PRINCIPLE 5 HOLDS: the agent
passes identity BY NAME, `hx.identity.resolve` runs below this layer, and no
tool returns a `Resolved`. If a tool ever accepted a credential value, this
column becomes the place credentials are written to disk in the clear.
`tests/test_credentials_never_reach_the_store.py` carries the case.
"""
from __future__ import annotations

import json
import time
from typing import Any

from ..store.records import new_id
from .envelope import Envelope

#: Above this many bytes of encoded JSON, the arguments go to the blob store.
ARGS_INLINE_MAX = 4096

#: What marks the column as a reference rather than the arguments themselves.
SPILL_PREFIX = "sha256:"

#: `result_summary` is read in a list; it is a line, not a document.
SUMMARY_MAX = 300


def _now_us() -> int:
    return time.time_ns() // 1000


def encode_args(args: dict[str, Any], blobs) -> str | None:
    """The value for `agent_action.args_blob`.

    Sorted keys, so two identical calls produce two identical strings and a
    reader comparing journal rows is comparing arguments rather than dict
    ordering.
    """
    if not args:
        return None
    text = json.dumps(args, sort_keys=True, separators=(",", ":"))
    raw = text.encode("utf-8")
    if len(raw) <= ARGS_INLINE_MAX:
        return text
    digest, _ = blobs.put(raw)
    return f"{SPILL_PREFIX}{digest}"


def summarise(env: Envelope) -> str:
    """One line saying what happened, for a reader scanning the journal.

    A page answers in COUNTS, never in rows: the rows are already in the store
    and repeating them here would make the journal the second copy of every
    query result the agent ever ran.
    """
    if not env.ran:
        line = f"{env.outcome}: {env.reason}"
    elif (isinstance(env.result, dict) and "returned" in env.result
          and "total" in env.result):
        line = f"{env.outcome}: {env.result['returned']} of {env.result['total']} rows"
    elif isinstance(env.result, dict) and "id" in env.result:
        line = f"{env.outcome}: {env.result['id']}"
    else:
        line = env.outcome
    return line[:SUMMARY_MAX]


def record(conn, *, engagement_id: str, run_id: str | None, tool: str,
           args: dict[str, Any], why: str | None, env: Envelope, blobs,
           at_us: int | None = None, actor: str = "agent") -> str:
    """Write the row. Returns its id.

    `tool` is what the caller ASKED FOR, which for an unregistered name is a
    tool that does not exist. That is deliberate: a row naming a nonexistent
    tool is how an agent looping on a name it invented becomes visible.
    """
    row_id = new_id("a")
    conn.execute(
        "INSERT INTO agent_action(id, engagement_id, run_id, ts_us, actor,"
        " tool, args_blob, result_summary, why) VALUES(?,?,?,?,?,?,?,?,?)",
        (row_id, engagement_id, run_id, _now_us() if at_us is None else at_us,
         actor, tool, encode_args(args, blobs), summarise(env), why))
    return row_id
