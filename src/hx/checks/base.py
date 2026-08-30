"""The types a check speaks in, and the ones it deliberately cannot.

A PASSIVE check is pure: it reads a surface and the exchanges captured
against it and returns a verdict. An ACTIVE check additionally builds
requests -- but it does not own a socket, and cannot construct one. It is
handed a `hx.checks.probe.ProbeSender` by the runner, which is the only
route to the wire and which enforces S4 by going through the extension
like everything else.

What NO check does, active or passive: write rows, compute dedupe keys,
learn its own `check_run` id, or hold a database connection. Each of those
belongs to the runner, and each is a place where ONE implementation must
serve every check or the guarantees stop being uniform.

THE VERDICT VOCABULARY IS NARROWER THAN THE COLUMN, ON PURPOSE.
`check_run.verdict` carries six values. A check may return three. `pending`,
`skipped` and `error` are the runner's, because:

  * a check that can say `skipped` can hide that it never ran;
  * a check that can say `error` can swallow its own crash;
  * `pending` is written BEFORE the check is called, so no check has ever been
    in a position to say it.

S12: a report that cannot distinguish "tested, clean" from "never reached" is
worse than no report. Every one of those three words is the second half of
that distinction, and none of them is a check's to give.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# The schema's own vocabularies, restated NOWHERE ELSE in this package. The
# pairing against schema.sql lives in tests/test_vocabularies_match_the_schema.py.
SEVERITIES = frozenset({"Critical", "High", "Medium", "Low", "Info"})
CONFIDENCES = frozenset({"Certain", "Firm", "Tentative"})
SCOPE_LEVELS = frozenset({"engagement", "host", "surface", "insertion"})

# S4 of the design doc. `body_form` and `body_json` are DERIVED AND RECORDED
# but never probed in this plan or the next: the production profile's method
# allowlist is GET/HEAD/OPTIONS, so an active_safe check can only re-issue a
# GET and no payload can reach a body. Recording them anyway is what lets the
# coverage section say "this parameter exists and was not probed".
INSERTION_KINDS = frozenset({
    "query", "path_segment", "header", "cookie", "body_form", "body_json",
})


@dataclass(frozen=True)
class Insertion:
    """One place a payload could go, derived from an exemplar exchange.

    `name` is the parameter, header or cookie name; for `path_segment` it is
    the template placeholder the normaliser produced, e.g. `{id}`.
    """
    kind: str
    name: str

    def __post_init__(self) -> None:
        if self.kind not in INSERTION_KINDS:
            raise ValueError(
                f"unknown insertion kind {self.kind!r}; this version knows "
                f"{sorted(INSERTION_KINDS)}")
        if not self.name:
            raise ValueError("an insertion point must have a name")


@dataclass(frozen=True)
class Candidate:
    """A finding a check believes in, before the runner gives it identity.

    The check does NOT compute the dedupe key. That is one canonical string
    (S5) and one place must build it, or two checks will spell the same
    finding two ways and the UNIQUE constraint will hold two rows.

    `issue_type_id` IS WHAT THE CHECK FOUND, and it is required for the same
    reason `title` is. Every OTHER part of the dedupe key is fixed by the
    check and the surface, so before this field existed every candidate one
    check yielded for one surface produced a byte-identical key. MEASURED, on
    one document response missing three security headers: `summary.findings`
    said 3 and `finding` held ONE row, `('Missing X-Content-Type-Options',
    'Low', 'CWE-16')` -- the FIRST candidate's title and CWE (which
    `upsert_finding`'s `DO UPDATE SET` never moves) wearing the LAST
    candidate's severity (which it does), with the Medium frame-protection
    issue absent from the store altogether.

    IT IS A STABLE IDENTITY STRING, NOT A LABEL. It goes in the dedupe key
    and in `finding.issue_type_id`, so renaming one later re-files every
    existing finding of that type as new. Lowercase kebab, describing the
    ISSUE (`missing-hsts`) and never the code path that noticed it -- EXCEPT
    where the issue type must carry a name the protocol itself treats as
    case-sensitive, which is why `hx.checks.passive.cookie_flags` preserves
    the cookie's case (RFC 6265: `Session` and `session` are two cookies, and
    folding them gave them one finding). It is a
    DIFFERENT AXIS from the check's own `id`: `check_id` answers "which of
    hx's checks found this", `issue_type_id` answers "what kind of issue is
    this", and `hx.scan._mark_unobserved` and schema.sql both depend on the
    two never being conflated.
    """
    title: str
    issue_type_id: str
    severity: str
    confidence: str
    insertion: Insertion | None
    exchange_ids: tuple[str, ...]
    description: str | None = None
    impact: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    scope_level: str = "surface"
    # THE VALUE THIS FINDING WAS DEMONSTRATED WITH, as the check meant it and
    # BEFORE any transport encoding: `../../../../../../etc/passwd`, not
    # `..%2F..%2F...`. F10 of the whole-branch review -- the first corpus in
    # this project's history that actually has payloads left this NULL on
    # every candidate, in a column `records.upsert_finding` has always
    # written and the schema has always had. Nothing renders it (that is a
    # separate decision about what belongs in a client deliverable), so what
    # it buys today is a store that holds the answer rather than one that
    # would have to re-derive it from a description.
    payload: str | None = None

    def __post_init__(self) -> None:
        if not self.title:
            raise ValueError("a candidate must have a title")
        if not self.issue_type_id:
            raise ValueError("a candidate must have an issue_type_id")
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"unknown severity {self.severity!r}; the schema takes "
                f"{sorted(SEVERITIES)}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(
                f"unknown confidence {self.confidence!r}; the schema takes "
                f"{sorted(CONFIDENCES)}")
        if self.scope_level not in SCOPE_LEVELS:
            raise ValueError(
                f"unknown scope_level {self.scope_level!r}; the schema takes "
                f"{sorted(SCOPE_LEVELS)}")
        if not self.exchange_ids:
            # S12 renders an evidence chain per finding. A candidate with no
            # exchange behind it has nothing to chain, and the operator would
            # be asked to believe a claim with no way to check it.
            raise ValueError("a candidate must name at least one exchange")
        if not all(self.exchange_ids):
            # THE SAME RULE, AND THE HOLE IT HAD. `(None,)` is a non-empty
            # tuple, so the guard above admitted it -- and every active check
            # in this corpus builds its evidence out of
            # `surface.exemplar_exchange_id`, which is NULL for a surface whose
            # first sighting was purged. MEASURED, `hx.active.cors` against
            # such a surface: the candidate constructed, `evidence` took a row
            # with a NULL `exchange_id` (the column is nullable), and
            # `hx.report._evidence` rendered "1 of the 1 shown could not be
            # resolved to a request" -- which is precisely the claim-with-no-
            # way-to-check the paragraph above forbids, filed as a finding.
            # `hx.scan.run` now skips an active check on such a surface before
            # it sends anything; this is the guard for a candidate that got a
            # blank id from anywhere else.
            raise ValueError(
                f"a candidate's exchange_ids are {self.exchange_ids!r}: every "
                "entry must name a real exchange. A blank one chains to "
                "nothing, and a finding whose evidence resolves to no request "
                "asks the operator to believe a claim they cannot check")


# Not scanned by tests/test_vocabularies_match_the_schema.py's enumeration
# (leading underscore): this is a subset of check_run.verdict chosen by this
# module's own rule, not a second copy of a schema CHECK, so there is nothing
# in schema.sql to pair it against.
_VERDICT_STATES = frozenset({"clean", "finding", "inconclusive"})


@dataclass(frozen=True)
class Verdict:
    """What a check returns. Constructed only through the three classmethods.

    There is deliberately no *public* `Verdict(state=...)` call site in this
    repository -- every caller uses a named constructor -- but the raw
    constructor is still reachable, exactly like `Candidate`'s and
    `Insertion`'s, so it carries the same kind of `__post_init__` they do:
    `state` is checked against `_VERDICT_STATES`, `finding` is checked for at
    least one candidate, and `inconclusive` is checked for a reason. That is
    what actually stops `Verdict("skipped")`, `Verdict("error")` and
    `Verdict("pending")` from constructing -- not the classmethods, which a
    caller can always step around by naming the dataclass directly.
    `test_a_check_cannot_express_skipped_or_error_or_pending` pins that the
    classmethods don't exist for those three words;
    `test_the_raw_constructor_also_refuses_skipped_error_and_pending` pins
    that the constructor itself refuses them too.
    """
    state: str
    candidates: tuple[Candidate, ...] = ()
    reason: str | None = None
    # What this check EXAMINED on this subject and reached a conclusion about,
    # as `issue_type_id` strings. `hx.scan._mark_unobserved` retires a finding
    # whose issue type is in here and was NOT re-emitted this run.
    #
    # It exists because the retirement gate it replaces was sound only while a
    # check filed at most ONE finding per surface. `issue_type_id` (F1 of Plan
    # 5's whole-branch review) made N-per-surface the norm, and a check that
    # finds one of three issues answers `finding` -- so under the old
    # clean-only gate the other two were never retired and rendered live off
    # stale observations, telling a client a fixed issue was still open.
    #
    # RUN-TIME, NOT DECLARED. A class-level list cannot express
    # `hx.checks.passive.cookie_flags`, which mints an issue type per cookie
    # NAME; what it considered is whatever cookies this surface actually set.
    #
    # DEFAULTS EMPTY, AND THAT IS THE SAFE DIRECTION: a check that populates
    # nothing retires nothing. The failure mode is a finding staying live,
    # never one falsely closed.
    #
    # PASSIVE CHECKS ONLY, SINCE FIX ROUND 6, AND THE RUNNER ENFORCES IT.
    # `hx.scan._retirable` returns nothing for a check driven through the
    # `probes` hook and RAISES if such a check populated this at all: every
    # probe this build sends is unauthenticated, so an active check's
    # conclusion is about the logged-out view of the application and cannot
    # close a finding about the view the client's users are in. An active
    # check names what it examined to `hx.checks.active._probe_util.verdict`
    # as `examined` instead -- which is what lets it say `clean` -- and that
    # value deliberately never reaches this field. See `_retirable` for the
    # argument and for the two narrower rules that were tried first.
    considered: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in _VERDICT_STATES:
            raise ValueError(
                f"unknown verdict state {self.state!r}; a check may only say "
                f"{sorted(_VERDICT_STATES)} -- pending, skipped and error "
                f"belong to the runner, never to a check")
        if self.state == "finding" and not self.candidates:
            raise ValueError(
                "a finding verdict needs at least one candidate; an empty one "
                "is a row claiming a finding with no title and no evidence")
        if self.state == "inconclusive" and not self.reason:
            raise ValueError(
                "inconclusive requires a reason: S10 says a check that cannot "
                "run says so, and a reason-less one tells the operator "
                "nothing they can act on")
        for issue_type in self.considered:
            if not isinstance(issue_type, str) or not issue_type:
                raise ValueError(
                    f"considered holds {issue_type!r}; it is a tuple of "
                    "issue_type_id strings, and a blank or non-string entry "
                    "would retire a finding nothing can be matched against")

    @classmethod
    def clean(cls, *, considered: tuple[str, ...] = ()) -> "Verdict":
        return cls("clean", (), None, tuple(considered))

    @classmethod
    def finding(cls, *candidates: Candidate,
                considered: tuple[str, ...] = ()) -> "Verdict":
        return cls("finding", tuple(candidates), None, tuple(considered))

    @classmethod
    def inconclusive(cls, reason: str) -> "Verdict":
        return cls("inconclusive", (), reason)


@dataclass(frozen=True)
class CheckContext:
    """What a check is given besides its subject.

    NO DATABASE CONNECTION, deliberately. A check that can write is a check
    that can write the wrong thing -- the wrong run id, a status the trigger
    forbids, a dedupe key spelled its own way. Everything a check produces
    goes back through its return value.
    """
    config: object          # hx.config.Config
    blobs: object           # hx.store.blobs.BlobStore
    run_id: str
    log: object             # a callable taking one str


class Check(Protocol):
    """The shape the registry validates and the runner calls.

    `klass` decides which hooks are legal. A `passive` check implementing
    `probes` is a registry error rather than a runtime surprise; see
    `hx.checks.registry`.
    """
    id: str
    version: str
    klass: str
    insertion_kinds: frozenset[str]


@dataclass(frozen=True)
class ExchangeRow:
    """One captured exchange, as a check sees it.

    Blob DIGESTS, not bytes. A surface with two hundred exchanges would
    otherwise pull two hundred response bodies into memory before any check
    decided it wanted one, and most checks want a handful. `ctx.blobs.get`
    is the fetch, and it is the check's decision when to call it.

    `outcome` IS CARRIED AND HAS NO DEFAULT, added by F6 of the whole-branch
    review. S5 says why, in the schema comment on the column itself: "a
    transport failure has no HTTP status; without `outcome` a check reads
    silence as 'not vulnerable'". This row used to stop at `resp_blob`, so a
    check could not tell a response that came back whole from one that timed
    out, was cut off mid-body, or never had its final status read -- and
    MEASURED, a surface holding one readable response beside one
    `status_unreadable` exchange recorded `check_run` = `('clean', NULL)`,
    byte for byte what a wholly tested surface says. A DEFAULT would have
    let a construction site quietly claim `ok` for an exchange nobody asked
    about, which is the same silence one layer up.
    """
    id: str
    method: str
    url: str
    status: int | None
    outcome: str
    req_blob: str | None
    resp_blob: str | None
