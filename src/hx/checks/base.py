"""The types a check speaks in, and the ones it deliberately cannot.

A check is pure. It reads a surface and the exchanges captured against it and
returns a verdict. It does not build requests, write rows, compute dedupe
keys, learn its own `check_run` id, or reach the bridge -- each of those
belongs to the runner, and each is a place where ONE implementation must serve
every check or the guarantees stop being uniform.

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
    ISSUE (`missing-hsts`) and never the code path that noticed it. It is a
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

    @classmethod
    def clean(cls) -> "Verdict":
        return cls("clean")

    @classmethod
    def finding(cls, *candidates: Candidate) -> "Verdict":
        return cls("finding", tuple(candidates))

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
    """
    id: str
    method: str
    url: str
    status: int | None
    req_blob: str | None
    resp_blob: str | None
