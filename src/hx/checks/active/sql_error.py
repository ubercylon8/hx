"""SQL error disclosure -- a syntax-breaking value at each point, matched
against a table of driver-emitted error text.

WHAT THIS CHECK PROVES AND WHAT IT DOES NOT. The probe puts a value ending
in an unmatched single quote where a query might use it, and looks for the
exact wording a database driver emits when a query it received does not
parse. Finding that text in the response proves *the application disclosed
a database error* -- that this input reaches a query unsanitised. It does
NOT prove the query can be manipulated to change what it returns, extract
data, or do anything beyond fail to parse: that would need a second,
data-altering probe this check never sends. Every description below says
the first sentence and is careful never to say the second.

THE PROBE IS SAFE BECAUSE IT IS INERT, NOT BECAUSE IT IS GENTLE. A quote
character that breaks a query's syntax makes that query FAIL to run; it
does not make a different query run instead, and a failed query changes
nothing. Nothing here attempts a working injection (no `OR 1=1`, no UNION,
no time-based payload) -- the whole probe is one character, and S4's method
allowlist (GET/HEAD/OPTIONS in the production profile) is what keeps any
of this off a request that could itself carry a write.

WHY THE VALUE IS `_probe_util.canary()` PLUS A QUOTE, NOT JUST A QUOTE. A
bare `'` alone answers nothing for a field that never reaches string
interpolation to begin with -- an integer-typed ID column bound with a
placeholder ignores it -- but it also risks the OPPOSITE failure: a field
with a length or shape check might reject an empty-looking or too-short
value before the value ever reaches a query, and a check that always sent
the same single character could never tell "rejected by input validation"
apart from "reached the query and parsed fine". A random alphanumeric
prefix (an ordinary-shaped value, courtesy of the same `canary()` Task 10
built for `reflected_input.py` -- see `_probe_util.py`'s own docstring for
why this module and not a fresh `secrets` call) gives the value a plausible
shape before the trailing quote breaks it, and reusing `canary()` rather
than minting a second random-string generator is exactly the "do not
reimplement it" this task's brief names.

THE SIGNATURE TABLE IS EXACT SUBSTRINGS, NOT REGEX, AND THAT IS DELIBERATE.
`secret_in_response.py` matches shapes a regex is the only sane way to
describe (a fixed-length key prefix, a variable suffix). A database driver's
syntax-error wording is not like that: it is a small number of FIXED,
versioned strings a driver emits close to verbatim across releases --
`"You have an error in your SQL syntax"`, `"ORA-01756: quoted string not
properly terminated"` -- so an exact substring is both sufficient and the
narrower, more precise tool, the same "deliberately narrow" argument
`secret_in_response.py`'s own docstring makes for why it rejected entropy
heuristics. That is also what makes `_probe_util.reflected(response,
marker)` the right helper to reuse here even though `marker` there means "a
canary this check minted": the function itself does one thing --
ASCII-encode a string and test it against `response.head` and
`response.body` -- and does not care whether the string was random or
literal. Reusing it is what "do not reimplement it" asks for; writing a
second `needle in haystack` check beside it would be exactly the
duplication that instruction exists to prevent.

EVERY ENTRY NAMES ITS VENDOR, so a reader (and every description built from
a match) can say which database's wording was seen, not merely that
"a database error" appeared -- the brief's own requirement, and the same
"name what matched" instinct `secret_in_response.py`'s pattern table
follows for credential shapes.

BUDGET: ONE PROBE PER INSERTION POINT. The table below has a dozen entries
across five vendors; none of that costs a second request; one probe's
response is matched against every entry, and the loop stops at the first
match -- a response cannot plausibly BE two vendors' error page at once, and
trying every remaining entry after a hit would spend cycles without
changing the answer. `insertion_kinds = frozenset({"query",
"path_segment"})`: no name-based pre-filter the way `open_redirect.py`
narrows to redirect-shaped parameter names, because unlike a redirect
target, almost any parameter -- an id, a filter, a sort key, a search term
-- can plausibly reach a query, so every declared insertion point earns its
one probe, the same reasoning `reflected_input.py` gives for probing every
kind it declares.

EXAMINED, THE SAME SHAPE `reflected_input.py` SETTLED. One issue type
covers every vendor this check can name -- the finding is always "a
database error was disclosed", regardless of which driver's wording proved
it -- so a second vendor's wording on the same parameter is the same
finding, and `records.dedupe_key` merges the two rather than filing two. As
with both predecessors, `_ISSUE_TYPE` is passed to `_probe_util.verdict` as
`examined` only when at least one point was actually probed, never on a
surface with none of the declared kinds -- and, since N3 of the scoped
re-review, such a call answers `inconclusive` with `_nothing_probeable()`
rather than `clean`: nothing an active check says retires anything since fix
round 6, but a `clean` row still claimed coverage in `report._coverage` of a
surface this check never sent a request to.

EACH CANDIDATE CARRIES ITS `Insertion`, for the reason `open_redirect.py`
and `reflected_input.py` both give: `records.dedupe_key` folds
`insertion_kind`/`insertion_name` into a finding's identity, and two
parameters that each independently disclose a database error must stay two
rows, not collapse into one.

THE PROBE GOES TO THE EXEMPLAR'S OWN PATH (`sender.path`), NOT TO THE SURFACE
ROW'S `path_template`, AND THE PATH-SEGMENT SUBSTITUTION IS BY INDEX BECAUSE
OF IT. F1 of the whole-branch review: `_for_insertion` used to build its
request line out of `surface[5]`, which on a templated surface is an identity
(`/order/{id}/doc`) and not an address -- a query probe went to a URL that
cannot exist, the 404 carried no driver wording, and this check answered
`clean` with its issue type in `considered`, retiring live findings. The
concrete path does not contain the placeholder a `path_segment` probe has to
replace, so `str.replace` against it silently substitutes NOTHING and sends
the exemplar's own value back; `_probe_util.substitute_segment` aligns the
two paths by segment index instead and returns `None` rather than a probe
that tests nothing.

A RESPONSE THAT REFUSED IS NOT A CLEAN ONE. A 400, a 403, a 422, a 429, a
404 or a 3xx to a login page carries no driver wording for the same reason a
parameterised query carries none. A 5xx is no answer either, and the ordering
below is what keeps that honest: `_match` is consulted FIRST, so a driver
error disclosed ON a 500 -- which is exactly where one usually arrives -- is
a finding, and only a 5xx that disclosed nothing becomes a gap. See
`_probe_util.py` for the doctrine all five active checks share.

THE EVIDENCE THIS CHECK CITES is the surface's exemplar exchange, for the
same reason every active check in this corpus gives: nothing in this build
records a probe's own request and response anywhere, so `surface[6]` is the
only exchange id this check can truthfully name. The gap is disclosed to
the client via `report._limits`; closing it needs a new bridge frame type
and writer, which is Java work outside this plan and open debt no current
task owns.
"""
from __future__ import annotations

from urllib.parse import quote

from hx.checks import base
from hx.checks.active import _probe_util

# Identity, not a label (see `base.Candidate`'s own docstring): it goes in
# the dedupe key and in `finding.issue_type_id`, and renaming it later
# re-files every existing finding of this type as new. One type covers
# every vendor below -- see the module docstring's CONSIDERED section.
_ISSUE_TYPE = "sql-error-disclosure"

# (exact substring, vendor) -- driver-emitted wording, close to verbatim
# across releases, checked in this order and stopped at the first match
# (see the module docstring's BUDGET section for why trying the rest after
# a hit would not change the answer). Not a claim that this list is
# exhaustive -- a vendor or a phrasing this table does not know about is
# simply not found, which is the same false-negative-over-false-positive
# trade `secret_in_response.py` makes with its own narrow table.
_SIGNATURES = (
    ("You have an error in your SQL syntax", "MySQL"),
    ("mysql_fetch_array()", "MySQL (legacy mysql_* PHP API)"),
    ("mysql_fetch_assoc()", "MySQL (legacy mysql_* PHP API)"),
    ("Unclosed quotation mark after the character string",
     "Microsoft SQL Server"),
    ("Microsoft OLE DB Provider for SQL Server", "Microsoft SQL Server"),
    ("com.microsoft.sqlserver.jdbc.SQLServerException",
     "Microsoft SQL Server (JDBC driver)"),
    ("PostgreSQL query failed", "PostgreSQL"),
    ("org.postgresql.util.PSQLException", "PostgreSQL (JDBC driver)"),
    ("ORA-01756: quoted string not properly terminated", "Oracle"),
    ("ORA-00933: SQL command not properly ended", "Oracle"),
    ("sqlite3.OperationalError", "SQLite (Python driver)"),
    ("Warning: SQLite3::query()", "SQLite (PHP driver)"),
    ("SQLSTATE[42000]", "generic SQL (PDO/ODBC SQLSTATE)"),
    ("SQLSTATE[HY000]", "generic SQL (PDO/ODBC SQLSTATE)"),
)


def _probe_value() -> str:
    """A plausible-shaped value with a syntax-breaking tail.

    See the module docstring's "WHY THE VALUE IS canary() PLUS A QUOTE"
    section: the alphanumeric prefix gives a length- or shape-checked field
    something to accept before the trailing quote ever reaches a query.
    """
    return f"{_probe_util.canary()}'"


def _for_insertion(path: str, path_template: str,
                   insertion: base.Insertion, value: str) -> str | None:
    """The path for one probe, `value` in exactly the place `insertion`
    names. Percent-encoded (`quote(..., safe="")`) because the value rides
    the request line -- the same discipline `open_redirect.py`'s
    `_probe_path` and `reflected_input.py`'s `_for_insertion` document.

    `path` IS THE ADDRESS AND `path_template` IS ONLY THE MAP: everything sent
    is built on the exemplar's concrete path, and the template is consulted
    for one thing, which segment index a `path_segment` insertion names.

    `path_segment` replaces EVERY occurrence of the placeholder, matching
    `reflected_input.py`'s own handling of a template that repeats
    `{id}` -- `hx.insertion.derive` yields one `Insertion` per name, so both
    occurrences are the same insertion point and both must carry the value.
    `None` when that substitution cannot be made at all; the caller records a
    gap rather than probing an address assembled out of a mismatch.
    """
    if insertion.kind == "query":
        return (f"{path}?{quote(insertion.name, safe='')}="
                f"{quote(value, safe='')}")
    if insertion.kind == "path_segment":
        return _probe_util.substitute_segment(
            path, path_template, insertion.name, quote(value, safe=""))
    raise ValueError(f"sql_error does not probe insertion kind {insertion.kind!r}")


def _location(resp, signature: str) -> str:
    """WHERE `signature` was found, read off the same response the match
    came from -- not a generic "the response body" the way a description
    that assumed the common case would say it. A database error is
    overwhelmingly a body phenomenon, but this check does not assume that;
    it reads `resp.body` first only because that IS the common case, and
    falls back to naming the header only when the body did not carry it."""
    needle = signature.encode("ascii")
    if needle in resp.body:
        return "the response body"
    return "a response header"


def _match(resp) -> tuple[str, str] | None:
    """The first `(signature, vendor)` from `_SIGNATURES` present in `resp`,
    or `None`. Reuses `_probe_util.reflected` -- see the module docstring
    for why a function built for a random canary is exactly the right tool
    for a literal signature too: it does one thing, ASCII-substring-search
    both response halves, and does not care where the needle came from."""
    for signature, vendor in _SIGNATURES:
        if _probe_util.reflected(resp, signature):
            return signature, vendor
    return None


def _describe(insertion: base.Insertion, resp, signature: str, vendor: str) -> str:
    return (
        f"Sending {insertion.kind} {insertion.name!r} with a random, "
        "ordinary-shaped value ending in an unmatched single quote drew "
        f"back status {resp.status} with {_location(resp, signature)} "
        f"containing {signature!r} -- {vendor} wording for a query that "
        "did not parse. This shows the application disclosed a database "
        "error in response to unexpected input, which is evidence that "
        "this input reaches a database query unsanitised. It is not proof "
        "that the query can be manipulated: this check sent one character "
        "and read the response, and never attempted to alter, extend or "
        "otherwise exploit the query.")


class SqlError:
    id = "hx.active.sql-error"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query", "path_segment"})

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        path_template = surface[5]
        candidates = []
        gaps = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind not in self.insertion_kinds:
                continue

            value = _probe_value()
            path = _for_insertion(sender.path, path_template, insertion, value)
            if path is None:
                # Nothing was sent, so nothing was examined: a gap, and
                # `probed_any` deliberately not set.
                gaps.append(f"{insertion.name}: no probe could be built for "
                            "this insertion point")
                continue
            # A REFUSAL ENDS THIS POINT, NOT THE CHECK. `ProbeSender.get()`
            # RAISES `ProbeRefused` on every refusal and never returns one
            # (see `hx/checks/probe.py`); `_probe_util.send_or_gap` catches it
            # HERE, one point at a time, so a rate limit or a budget on the
            # first parameter does not discard every parameter after it. The
            # gap it records is what keeps that honest -- see
            # `_probe_util.verdict`.
            resp = _probe_util.send_or_gap(sender, path, insertion, gaps)
            if resp is None:
                continue
            probed_any = True

            found = _match(resp)
            if found is None:
                # ASKED ONLY WHERE NOTHING MATCHED, and that ordering is what
                # keeps a 500 usable: driver wording disclosed on one IS the
                # finding, and only a response that disclosed nothing AND
                # did not answer is a gap -- `_probe_util.unanswered`, which
                # reads a 2xx and nothing else as an answer.
                # `_probe_util.verdict`'s "a candidate wins over a gap", one
                # step earlier.
                refusal = _probe_util.unanswered(resp)
                if refusal is not None:
                    gaps.append(f"{insertion.name}: {refusal}")
                continue
            signature, vendor = found

            candidates.append(base.Candidate(
                title=f"Database error disclosed via {insertion.name!r}",
                issue_type_id=_ISSUE_TYPE,
                severity="Medium", confidence="Certain",
                insertion=insertion,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-209",
                payload=value,
                description=_describe(insertion, resp, signature, vendor),
                remediation=(
                    "Use parameterised queries or prepared statements for "
                    "every value built from user input, and turn off "
                    "verbose database error output in production (log it "
                    "server-side instead of returning it to the client).")))

        if not probed_any:
            # NOTHING WAS SENT, SO NOTHING WAS TESTED, AND THAT IS NOT
            # `clean` -- N3 of the scoped re-review; see
            # `reflected_input.py`'s identical branch for why this check
            # carries one despite having no name filter of its own.
            return _probe_util.verdict(candidates, gaps,
                                       unprobed=self._nothing_probeable())
        return _probe_util.verdict(candidates, gaps,
                                   examined=(_ISSUE_TYPE,))

    def _nothing_probeable(self) -> str:
        """What a coverage row says for a surface nothing was sent to,
        derived from `insertion_kinds` for the reason `reflected_input.
        ReflectedInput._nothing_probeable` gives."""
        return ("no insertion point on this surface is one this check "
                "probes -- it probes "
                f"{', '.join(sorted(self.insertion_kinds))} points -- so "
                "nothing was sent and this surface was not examined for "
                "database error disclosure")
