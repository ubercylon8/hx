"""Path traversal -- a directory-traversal sequence at a file-shaped
parameter, matched against a table of file-content signatures.

WHAT THIS CHECK PROVES AND WHAT IT DOES NOT. The probe replaces a
file-shaped parameter's value with a sequence that climbs out of whatever
directory the application meant to serve from and names a real file. Its
CONTENT coming back -- not a status code, not an absence of error, the
actual bytes of a known file -- is what a finding says: this input was used,
unsanitised, to build a filesystem path outside the intended directory. It
does not say arbitrary files can be read, that write access exists, or
anything about what else might be reachable: those all need probes this
check never sends. Every description below names the file and the exact
line that matched, never a generic "path traversal confirmed".

THE SAFETY CONSTRAINT, AND THE CHOICES IT DROVE. The brief for this check is
explicit: do not send a sequence that could reach outside the target's
document root on a server that is NOT vulnerable. Three choices follow from
that:

  1. THE TARGET FILE IS `/etc/passwd`. World-readable on every Unix-like
     system by design, containing nothing sensitive on any system built in
     the last twenty years (password hashes live in `/etc/shadow`, which
     this check never asks for), and reading it has no side effect whether
     the traversal lands or not. There is no file this check could name
     whose successful read is safer.
  2. THE DEPTH IS BOUNDED, NOT MAXIMAL. `_TRAVERSAL_DEPTH` climbs six
     directories -- comfortably past any realistic web application's
     nesting depth without being the kind of excessive, `../` × 20 payload
     that adds risk for no gain: six either reaches `/` (from which further
     `..` segments are inert -- the filesystem clamps at the root, it does
     not walk past it) or it does not, and a deeper prefix answers the same
     question no more conclusively once it has.
  3. THE PAYLOAD IS PERCENT-ENCODED BEFORE IT EVER REACHES `path`. Every
     `.` and `/` in `_TRAVERSAL_PAYLOAD` goes through the same
     `quote(value, safe="")` every other active check in this corpus uses
     for a query or path-segment value (`open_redirect.py`,
     `reflected_input.py`, `sql_error.py`) -- so the literal string that
     lands on hx's OWN request line is `..%2F..%2F...`, never a raw `../`.
     Nothing in `ProbeSender._request_bytes` decodes it back (see
     `hx/checks/probe.py`): this check never constructs a request whose
     PATH, as hx sends it, contains an unresolved `..` segment for some
     intermediate proxy to normalise into a request nobody authorised. A
     vulnerable application decodes the value itself, the same way it would
     decode any other percent-encoded parameter, and that decode is where
     the traversal actually happens -- on the target's side, at the layer
     this check is testing, not on the wire.

"A PARAMETER THAT LOOKS LIKE IT NAMES A FILE": NAME-BASED, LIKE
`open_redirect.py`, UNLIKE `sql_error.py`. `sql_error.py`'s probe applies to
almost any parameter -- nearly anything can reach a query. A traversal
target is narrower: an `id` or a `page_number` cannot plausibly become a
filesystem path, so this check filters by name first, the identical
canary-first argument `open_redirect.py`'s own docstring makes for why that
is a name test and not a value test (`insertions` carries no value to test
against -- see that module's "CANARY-FIRST" section, and the ruling in this
plan's ledger that name-only filtering is accepted project-wide). A
conventionally-named file parameter (`file`, `path`, `filename`, `document`,
`template`, `include`, `download`, `attachment`, `image`, `src`) earns a
probe; `id`, `page`, `sort` and the like do not.

THE SIGNATURE TABLE IS EXACT SUBSTRINGS FROM `/etc/passwd` ITSELF, checked
with `_probe_util.reflected` -- the same reuse `sql_error.py` documents:
that function does one thing, ASCII-substring-search both response halves,
and does not care whether the needle is a random canary or a literal file
line. `root:x:0:0:` is universal across every Unix-like distribution --
UID and GID 0 belong to root everywhere -- and is specific enough that
nothing an ordinary application would emit could produce it by coincidence
(the same "a signature only a successful read would produce" the brief
asks for); the other entries add distros' common low-numbered system
accounts as corroborating, still-narrow signatures.

BUDGET: ONE PROBE PER INSERTION POINT. One traversal payload, one request;
the single response is matched against every table entry, and the loop
stops at the first hit -- a table with more entries never costs more
requests, exactly the rule `sql_error.py` and this task's brief both state.

CONSIDERED, THE SAME SHAPE AS EVERY ACTIVE CHECK IN THIS CORPUS. One issue
type -- the finding is always "this input let a file outside the intended
directory be read", regardless of which line of `/etc/passwd` proved it --
named in `considered` only when at least one file-shaped parameter was
actually probed, never on a surface with no insertion point this check's
name filter accepted. Such a surface answers `inconclusive` and not `clean`
(N3 of the scoped re-review): an empty `considered` retires nothing, but a
`clean` row still tells `report._coverage` this check examined a surface it
never sent a request to. `_NOTHING_PROBEABLE` is the sentence it says
instead.

EACH CANDIDATE CARRIES ITS `Insertion`, for the same reason
`open_redirect.py`, `reflected_input.py` and `sql_error.py` all give:
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into a
finding's identity, and two parameters that each independently disclose
file content must stay two rows.

THE PROBE GOES TO THE EXEMPLAR'S OWN PATH (`sender.path`), NOT TO THE SURFACE
ROW'S `path_template`, AND THE PATH-SEGMENT SUBSTITUTION IS BY INDEX BECAUSE
OF IT. F1 of the whole-branch review: `_for_insertion` used to build its
request line out of `surface[5]`, which on a templated surface is an identity
(`/order/{id}/doc`) and not an address -- the probe reached a URL that cannot
exist, the 404 carried no file content, and this check answered `clean` with
its issue type in `considered`, retiring live findings. The concrete path
does not contain the placeholder a `path_segment` probe has to replace, so
`str.replace` against it silently substitutes NOTHING and sends the
exemplar's own value back; `_probe_util.substitute_segment` aligns the two
paths by segment index instead and returns `None` rather than a probe that
tests nothing.

A RESPONSE THAT REFUSED IS NOT A CLEAN ONE. A 400, a 403, a 429, a 5xx, a
404 or a redirect to a login page carries no `/etc/passwd` line for the same
reason a target that canonicalises its paths carries none, and the two must
not record the same verdict. `_match` is consulted first, so a signature
disclosed on any status is still the finding. See `_probe_util.py` for the
doctrine all five active checks share.

THE EVIDENCE THIS CHECK CITES is the surface's exemplar exchange, for the
same reason every active check in this corpus gives: nothing in this build
records a probe's own request and response anywhere -- the extension
captures proxy traffic only. `report._limits` already tells the client so;
a real fix needs a new bridge frame type and a new writer, Java work this
plan does not touch, and until then the gap is debt no current task owns.
"""
from __future__ import annotations

from urllib.parse import quote

from hx import surface as surface_mod
from hx.checks import base
from hx.checks.active import _probe_util

# Identity, not a label (see `base.Candidate`'s own docstring). One type
# covers every signature below -- see the module docstring's CONSIDERED
# section.
_ISSUE_TYPE = "path-traversal"

# Substrings a query or path-segment parameter's NAME is checked against,
# case-insensitively, before it earns a probe at all -- see the module
# docstring's "A PARAMETER THAT LOOKS LIKE IT NAMES A FILE" section.
_FILE_NAME_HINTS = (
    "file", "path", "filename", "document", "doc", "template", "include",
    "download", "attachment", "image", "img", "src", "resource", "asset",
    "load", "report",
)

# Six levels climbs past any realistic web application's nesting depth
# without being excessive -- see the module docstring's safety section.
_TRAVERSAL_DEPTH = 6
_TARGET_FILE = "/etc/passwd"
_TRAVERSAL_PAYLOAD = "../" * _TRAVERSAL_DEPTH + "etc/passwd"

# (exact substring, what it identifies) -- lines from `/etc/passwd` itself,
# checked in this order and stopped at the first match (see the module
# docstring's BUDGET section). `root:x:0:0:` is universal; the rest are
# common low-numbered system accounts present on most distributions, kept
# as corroborating signatures rather than the sole one.
_SIGNATURES = (
    ("root:x:0:0:", "the root account's line"),
    ("root:*:0:0:", "the root account's line (BSD-style shadow marker)"),
    ("daemon:x:1:1:", "the daemon account's line"),
    ("bin:x:2:2:", "the bin account's line"),
    ("nobody:x:65534:", "the nobody account's line"),
)


# What a coverage row says for a surface this check never sent anything to --
# the same shape as `open_redirect._NOTHING_PROBEABLE`, and naming the filter
# for the same reason.
_NOTHING_PROBEABLE = (
    "no insertion point on this surface is one this check probes -- it "
    "probes a query or path_segment point whose name contains one of "
    f"{', '.join(_FILE_NAME_HINTS)} -- so nothing was sent and this surface "
    "was not examined for path traversal")


def _looks_like_file_target(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _FILE_NAME_HINTS)


def _for_insertion(path: str, path_template: str,
                   insertion: base.Insertion, value: str) -> str | None:
    """The path for one probe, `value` in exactly the place `insertion`
    names -- percent-encoded, matching `sql_error.py`'s `_for_insertion`
    and the module docstring's safety section on why.

    `path` IS THE ADDRESS AND `path_template` IS ONLY THE MAP: everything
    sent is built on the exemplar's concrete path, and the template is
    consulted for one thing, which segment index a `path_segment` insertion
    names. `path_segment` replaces every occurrence of the placeholder
    (`_probe_util.substitute_segment` does, and says why), matching
    `reflected_input.py`'s handling of a repeated `{id}`, and answers `None`
    when it cannot -- which the caller records as a gap rather than probing
    an address assembled out of a mismatch.
    """
    if insertion.kind == "query":
        return (f"{path}?{quote(insertion.name, safe='')}="
                f"{quote(value, safe='')}")
    if insertion.kind == "path_segment":
        return _probe_util.substitute_segment(
            path, path_template, insertion.name, quote(value, safe=""))
    raise ValueError(
        f"path_traversal does not probe insertion kind {insertion.kind!r}")


def _location(resp, signature: str) -> str:
    """WHERE `signature` was found, read off the same response the match
    came from -- the same discipline `sql_error.py`'s `_location` and
    `reflected_input.py`'s `_where` both follow: report the half that
    actually carried it, never assume the common case."""
    needle = signature.encode("ascii")
    if needle in resp.body:
        return "the response body"
    return "a response header"


def _match(resp) -> tuple[str, str] | None:
    """The first `(signature, what)` from `_SIGNATURES` present in `resp`,
    or `None`. Reuses `_probe_util.reflected` -- see `sql_error.py`'s
    identical reasoning for why a function built for a random canary is
    also the right tool for a literal file-content signature."""
    for signature, what in _SIGNATURES:
        if _probe_util.reflected(resp, signature):
            return signature, what
    return None


def _describe(insertion: base.Insertion, resp, signature: str, what: str) -> str:
    return (
        f"Requesting {insertion.kind} {insertion.name!r} with a "
        f"directory-traversal sequence ({_TRAVERSAL_PAYLOAD!r}, six levels "
        f"up and back down to {_TARGET_FILE}) drew back status "
        f"{resp.status} with {_location(resp, signature)} containing "
        f"{signature!r} -- {what} from {_TARGET_FILE}. The response could "
        f"only carry that file's own content if this input was used, "
        "unsanitised, to build a filesystem path outside the directory "
        "the application intended to serve from. This shows that a file "
        "outside the intended directory can be read; it does not show "
        "what else is reachable, and no attempt was made here to read "
        "anything beyond this one, deliberately harmless, world-readable "
        "file.")


class PathTraversal:
    id = "hx.active.path-traversal"
    version = "1"
    klass = "active_safe"
    insertion_kinds = frozenset({"query", "path_segment"})

    # DERIVED AT IMPORT, NOT ASSERTED IN PROSE: this check's own name filter
    # run over every placeholder the normaliser can mint. It is `False`, and
    # that is a real coverage gap rather than a curiosity -- `path_segment`
    # is declared above, but `hx.surface` templates an identifier-shaped
    # segment to `{id}`, `{uuid}`, `{hex}` or `{slug}`, and not one of those
    # contains a `_FILE_NAME_HINTS` substring, so in production this check
    # tests query parameters and nothing else. Pre-existing and harmless in
    # direction (a false negative: `considered` stays empty for a point that
    # was never probed, so nothing retires), and a report that implied
    # otherwise would be claiming coverage it does not have --
    # `hx.report._limits` reads this attribute and discloses it. Fixing it is
    # a check-design question: either the filter widens or the normaliser
    # learns a `{file}` shape, and both are decisions beyond a fix round.
    probes_templated_segments = any(
        _looks_like_file_target(p) for p in surface_mod.PLACEHOLDERS)

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        path_template = surface[5]
        candidates = []
        gaps = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind not in self.insertion_kinds:
                continue
            if not _looks_like_file_target(insertion.name):
                continue

            path = _for_insertion(sender.path, path_template, insertion,
                                  _TRAVERSAL_PAYLOAD)
            if path is None:
                # Nothing was sent, so nothing was examined: a gap, and
                # `probed_any` deliberately not set.
                gaps.append(f"{insertion.name}: no probe could be built for "
                            "this insertion point")
                continue
            # A REFUSAL ENDS THIS POINT, NOT THE CHECK -- the same rule the
            # other three probing checks follow, and for the reason
            # `_probe_util.send_or_gap` gives: `ProbeSender.get()` RAISES on
            # every refusal and never returns one, and letting that propagate
            # out of this loop discards every insertion point after the
            # refused one.
            resp = _probe_util.send_or_gap(sender, path, insertion, gaps)
            if resp is None:
                continue
            probed_any = True

            found = _match(resp)
            if found is None:
                # ASKED ONLY WHERE NOTHING MATCHED: a file's own content
                # coming back proves the traversal landed whatever the status
                # line said. `_probe_util.verdict`'s "a candidate wins over a
                # gap", one step earlier.
                refusal = _probe_util.unanswered(resp)
                if refusal is not None:
                    gaps.append(f"{insertion.name}: {refusal}")
                continue
            signature, what = found

            candidates.append(base.Candidate(
                title=f"File content disclosed via {insertion.name!r} "
                      "(path traversal)",
                issue_type_id=_ISSUE_TYPE,
                severity="High", confidence="Certain",
                insertion=insertion,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-22",
                payload=_TRAVERSAL_PAYLOAD,
                description=_describe(insertion, resp, signature, what),
                remediation=(
                    "Resolve this input against an allowlist of permitted "
                    "files, or canonicalise the resulting path and reject "
                    "any request whose resolved path falls outside the "
                    "intended directory, rather than concatenating this "
                    "input directly into a filesystem path.")))

        if not probed_any:
            # NOTHING WAS SENT, SO NOTHING WAS TESTED -- see
            # `open_redirect.py`'s identical branch and N3 of the scoped
            # re-review. Reached by either filter: a point of the wrong
            # KIND, or one whose name does not look like a file's. Both are
            # "this check did not look here", and the coverage row has to
            # say so rather than say `clean`.
            return _probe_util.verdict(candidates, gaps,
                                       unprobed=_NOTHING_PROBEABLE)
        return _probe_util.verdict(candidates, gaps,
                                   considered=(_ISSUE_TYPE,))
