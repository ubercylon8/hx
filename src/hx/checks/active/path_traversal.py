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
name filter accepted.

EACH CANDIDATE CARRIES ITS `Insertion`, for the same reason
`open_redirect.py`, `reflected_input.py` and `sql_error.py` all give:
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into a
finding's identity, and two parameters that each independently disclose
file content must stay two rows.

THE EVIDENCE THIS CHECK CITES is the surface's exemplar exchange, for the
same reason every active check in this corpus gives: nothing in this
build's probe path writes an exchange row for a probe's own traffic yet
(Task 13's), so `surface[6]` is the only exchange id this check can
truthfully name.
"""
from __future__ import annotations

from urllib.parse import quote

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


def _looks_like_file_target(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in _FILE_NAME_HINTS)


def _for_insertion(path_template: str, insertion: base.Insertion,
                   value: str) -> str:
    """The path for one probe, `value` in exactly the place `insertion`
    names -- percent-encoded, matching `sql_error.py`'s `_for_insertion`
    and the module docstring's safety section on why. `path_segment`
    replaces every occurrence of the placeholder, matching
    `reflected_input.py`'s handling of a repeated `{id}`.
    """
    if insertion.kind == "query":
        return (f"{path_template}?{quote(insertion.name, safe='')}="
                f"{quote(value, safe='')}")
    if insertion.kind == "path_segment":
        return path_template.replace(insertion.name, quote(value, safe=""))
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

    def probes(self, ctx, surface, insertions, sender) -> base.Verdict:
        exemplar_exchange_id = surface[6]
        path_template = surface[5]
        candidates = []
        probed_any = False

        for insertion in insertions:
            if insertion.kind not in self.insertion_kinds:
                continue
            if not _looks_like_file_target(insertion.name):
                continue
            probed_any = True

            path = _for_insertion(path_template, insertion, _TRAVERSAL_PAYLOAD)
            # No `try`/`except`: `ProbeSender.get()` RAISES `ProbeRefused`
            # on every refusal and never returns one (see
            # `hx/checks/probe.py`), and letting it propagate is what turns
            # this into `inconclusive` in `hx.scan.run` rather than a
            # `clean` this check mistook a refusal for.
            resp = sender.get(path)

            found = _match(resp)
            if found is None:
                continue
            signature, what = found

            candidates.append(base.Candidate(
                title=f"File content disclosed via {insertion.name!r} "
                      "(path traversal)",
                issue_type_id=_ISSUE_TYPE,
                severity="High", confidence="Certain",
                insertion=insertion,
                exchange_ids=(exemplar_exchange_id,), cwe="CWE-22",
                description=_describe(insertion, resp, signature, what),
                remediation=(
                    "Resolve this input against an allowlist of permitted "
                    "files, or canonicalise the resulting path and reject "
                    "any request whose resolved path falls outside the "
                    "intended directory, rather than concatenating this "
                    "input directly into a filesystem path.")))

        considered = (_ISSUE_TYPE,) if probed_any else ()
        if candidates:
            return base.Verdict.finding(*candidates, considered=considered)
        return base.Verdict.clean(considered=considered)
