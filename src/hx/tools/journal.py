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

STORING ARGUMENTS VERBATIM IS SAFE BECAUSE THE ENCODER REDACTS -- and that
sentence used to end "because Principle 5 holds". Principle 5 does hold: the
agent passes identity BY NAME, `hx.identity.resolve` runs below this layer,
and no tool returns a `Resolved`. But the argument rested on a second claim,
that it "holds for the registered tools' schemas", and that claim expired the
moment a tool accepted arbitrary header lines. RULING 21, MEASURED:
`http.send(headers=["Cookie: session=SUPERSECRETVALUE"])` wrote

    {"headers":["Cookie: session=SUPERSECRETVALUE"], ...}

into `agent_action.args_blob`, and "a credential value never appears in a
journal row" is a stated binding constraint of this project. `http.send` now
refuses that argument outright -- but the refusal path is journalled too, so
the refusal alone would not have closed it, and a future tool that legitimately
carries header lines would reopen it.

So `encode_args` redacts, and the guarantee is a property of THIS module
rather than of the schemas above it. It is deliberately blunt: EVERY string
anywhere in the arguments that BEGINS with one of
`config.CREDENTIAL_HEADERS` and a colon loses its value, whichever argument
it arrived in. The cost is real and is the right way round -- an agent
grepping for its own session cookie sees `http.grep(pattern=...)` recorded
with the value replaced -- because the alternative is a per-argument rule
that a future tool would silently fall outside of, which is the exact shape
of the defect this closes.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import CREDENTIAL_HEADERS
from ..store.records import new_id, redact_url
from .envelope import Envelope

#: Above this many bytes of encoded JSON, the arguments go to the blob store.
ARGS_INLINE_MAX = 4096

#: What marks the column as a reference rather than the arguments themselves.
SPILL_PREFIX = "sha256:"

#: `result_summary` is read in a list; it is a line, not a document.
SUMMARY_MAX = 300

#: A string that OPENS with one of the three credential header names and a
#: colon. Anchored at the start, so `"the Cookie: header"` inside a `why` or a
#: detail is not a header line and is left alone; the wire lines a tool takes
#: begin with the field name by definition.
#:
#: `config.CREDENTIAL_HEADERS` is IMPORTED rather than restated, for the
#: reason `hx.tools.impl.http._replayed_headers` gives for importing the same
#: tuple: it is already pinned byte for byte against the extension's own
#: `Redactor.CREDENTIAL_HEADERS`, and a second copy is a second thing to keep
#: in sync with the JVM.
#: PER LINE, ANYWHERE IN THE STRING -- not anchored at position 0. The
#: anchored `.match` version covered `headers` (whose lines arrive as separate
#: array items) and missed the shape `http.send` ALREADY SHIPS: a `body` is a
#: free string, and an agent replaying a captured request by hand puts a whole
#: request in one -- `"field=1\r\nCookie: session=<real>"` -- where the
#: credential is on line two and nothing looked past line one. That was
#: recorded as debt against a hypothetical FUTURE tool; the tool exists.
#:
#: `[^\r\n]*` rather than `.*`: MULTILINE's `$` matches before the `\n` but
#: not before the `\r`, so `.*` would keep a trailing CR inside the value it
#: was replacing and leave a stray one in the row.
_CREDENTIAL_LINE = re.compile(
    r"^[ \t]*(" + "|".join(re.escape(h) for h in CREDENTIAL_HEADERS)
    + r")[ \t]*:[^\r\n]*", re.IGNORECASE | re.MULTILINE)

def _placeholder(name: str) -> str:
    """What replaces a credential header's VALUE.

    The vocabulary the extension already writes into a redacted blob --
    `{{observed:<name>}}`, lower-cased, `Redactor.observedHeader` -- so an
    operator reading a journal row and an operator reading a stored request
    are reading one placeholder rather than two.
    """
    return "{{observed:" + name.strip().lower() + "}}"


def _redacted(value: Any) -> Any:
    """`value` with every credential header line's value replaced.

    Recursive over the JSON shapes an argument can be, because the line can
    arrive anywhere: `http.send` takes an ARRAY of them today, and nothing
    stops a future tool from taking one string or a dict of them. A guard
    written for the one shape that exists is the guard that misses the next
    one -- which is how this hole opened in the first place.

    The NAME is kept and only the value goes, exactly as `records.redact_url`
    keeps a credential parameter's key: "the agent sent a Cookie header" is
    the fact `run.journal` exists to report, and a row that dropped the line
    entirely would answer "what did I already try" with a request that was
    never made.

    A CREDENTIAL IN A URL IS THE SAME EXPOSURE AND WAS NOT COVERED. Header
    lines were the shape this guard was written for, and an argument can
    carry one in a query string just as easily: `http.send`'s `path` is
    agent-supplied and required, and replaying an OAuth callback --
    `/cb?access_token=...` -- is ordinary work during an assessment.
    MEASURED: `exchange.url` held `access_token={{observed:param}}` while
    `agent_action.args_blob` held the token, so the store redacted the same
    string in one table and kept it in the other.

    `records.redact_url` is REUSED rather than reimplemented -- it already
    knows userinfo and the credential parameter names, and it is what writes
    the redacted `exchange.url` this was disagreeing with. It is safe on
    arbitrary strings: measured against prose, bare words, header lines and
    empty input, it returns them unchanged and raises on none of them, so it
    can run over every string argument rather than over ones guessed to be
    URLs. Found by the first automated review this repository completed.
    """
    if isinstance(value, str):
        # `sub`, not `match`: one string can carry several credential lines and
        # can carry them beside content worth keeping. Replacing only the
        # matched LINES leaves the rest of a body intact, so the journal still
        # answers "what did I already try" with the request that was made.
        redacted = _CREDENTIAL_LINE.sub(
            lambda m: f"{m.group(1)}: {_placeholder(m.group(1))}", value)
        return redact_url(redacted)
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(item) for item in value]
    return value


def _now_us() -> int:
    return time.time_ns() // 1000


def encode_args(args: dict[str, Any], blobs) -> str | None:
    """The value for `agent_action.args_blob`.

    Sorted keys, so two identical calls produce two identical strings and a
    reader comparing journal rows is comparing arguments rather than dict
    ordering.

    CREDENTIAL HEADER LINES LOSE THEIR VALUES FIRST -- see this module's
    docstring for why that guarantee lives here rather than in the schemas
    above. The redaction runs before `json.dumps`, so it covers the spilled
    blob exactly as it covers the inline column.

    May raise `TypeError` or `ValueError` if `json.dumps` encounters a
    non-serialisable value or circular reference; the raise happens before
    the `INSERT`, so no partial row is written.
    """
    if not args:
        return None
    text = json.dumps(_redacted(args), sort_keys=True, separators=(",", ":"))
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
        if env.detail:
            line = f"{line} — {env.detail}"
    elif (isinstance(env.result, dict)
          and set(env.result.keys()) == {"rows", "returned", "total",
                                         "truncated", "next_cursor", "facets"}):
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
