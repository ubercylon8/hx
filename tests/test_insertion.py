"""Where a payload could go, read off one captured request.

S5: derived, not stored. The derivation is pure -- bytes in, insertion points
out -- so it is testable without a database, a surface row or a Burp.
"""
import pytest

from hx import insertion, surface
from hx.checks.base import Insertion

REQ = (
    b"POST /api/orders/1001?page=2&sort=asc HTTP/1.1\r\n"
    b"Host: app.test\r\n"
    b"Cookie: session=abc; theme=dark\r\n"
    b"X-Request-Id: r-9\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 16\r\n"
    b"Connection: keep-alive\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Upgrade: h2c\r\n"
    b"Expect: 100-continue\r\n"
    b"Accept-Encoding: gzip\r\n"
    b"\r\n"
    b"note=hello&qty=3"
)


def test_query_parameters_are_derived_by_name():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("query", "page") in got
    assert Insertion("query", "sort") in got


def test_path_placeholders_are_derived_from_the_template():
    """The NORMALISER decided `{id}`, and the template is the authority. A
    derivation that re-guessed which segment was variable would disagree with
    the surface the finding is attributed to."""
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("path_segment", "{id}") in got


def test_cookies_are_derived_individually():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("cookie", "session") in got
    assert Insertion("cookie", "theme") in got


def test_headers_are_derived_but_hop_by_hop_and_fixed_ones_are_not():
    """`Host`, `Content-Length` and `Content-Type` are structural, not
    insertion points in any useful sense, and probing them produces noise,
    not findings. `Connection`, `Transfer-Encoding`, `Upgrade`, `Expect` and
    `Accept-Encoding` are hop-by-hop/transport-negotiation headers a proxy or
    the target acts on, not the application. `Cookie` is excluded here
    because it is derived as individual cookies above -- deriving it twice
    would double-count the coverage denominator. Every name in this list is
    load-bearing: deleting any one of them from `insertion._NOT_INSERTABLE`
    (or, for `Cookie`, from the request fixture) must redden this test, or
    the exclusion is a guard nothing separates from its absence."""
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("header", "X-Request-Id") in got
    for excluded in (
        "Host", "Content-Type", "Cookie", "Content-Length",
        "Connection", "Transfer-Encoding", "Upgrade", "Expect",
        "Accept-Encoding",
    ):
        assert Insertion("header", excluded) not in got


def test_form_body_members_are_derived():
    got = insertion.derive(REQ, "/api/orders/{id}")
    assert Insertion("body_form", "note") in got
    assert Insertion("body_form", "qty") in got


def test_json_body_members_are_derived_by_dotted_path():
    req = (b"POST /api/orders HTTP/1.1\r\nHost: app.test\r\n"
           b"Content-Type: application/json\r\n\r\n"
           b'{"customer": {"id": 7}, "items": [1, 2]}')
    got = insertion.derive(req, "/api/orders")
    assert Insertion("body_json", "customer.id") in got
    assert Insertion("body_json", "items") in got


def test_body_kinds_are_derived_but_are_not_probeable_here():
    """S4 of the design doc, pinned. The production method allowlist is
    GET/HEAD/OPTIONS, so no payload can reach a body -- but the parameter is
    RECORDED so the coverage section can say `exists, not probed`.

    This asserts the first half. The second half -- that nothing probes them --
    is Plan 6's to hold, and this test names it so the pairing is not lost.
    """
    got = insertion.derive(REQ, "/api/orders/{id}")
    body = {i for i in got if i.kind in ("body_form", "body_json")}
    assert body, "body insertion points must be derived even though unprobeable"


def test_a_request_with_no_head_terminator_yields_nothing_rather_than_throwing():
    """Malformed captures exist. A derivation that raises would take a scan
    down over one bad row."""
    assert insertion.derive(b"GET / HTTP/1.1\r\nHost: a", "/") == ()


def test_derivation_is_deterministic_and_ordered():
    """Two runs over one request must produce the same tuple in the same
    order, or `check_run` rows for one surface differ between scans and the
    retest diff fills with noise."""
    a = insertion.derive(REQ, "/api/orders/{id}")
    b = insertion.derive(REQ, "/api/orders/{id}")
    assert a == b
    assert list(a) == sorted(a, key=lambda i: (i.kind, i.name))


# ---- request_path() -------------------------------------------------------
#
# THE ADDRESS, NOT THE TEMPLATE. `hx.scan.run` reads this off a surface's
# exemplar request and binds `probe.ProbeSender` to it. Before F1 of the
# whole-branch review nothing read it at all: every active check built its
# probe out of `surface.path_template`, so on a templated surface the request
# went to `/api/orders/{id}` -- a URL that cannot exist -- and the 404 was
# recorded as `clean`.


def test_the_concrete_path_is_read_off_the_request_line():
    assert insertion.request_path(REQ) == "/api/orders/1001"


def test_the_query_string_is_not_part_of_the_path():
    """`open_redirect._probe_path` and every other query probe append the
    first and only `?` themselves; a path that already carried one would put
    two on the request line."""
    assert "?" not in insertion.request_path(REQ)


def test_an_absolute_form_request_line_still_yields_its_path():
    """A browser addresses a PROXY with the absolute URI, and the proxy is
    the only way anything reaches `hx.capture` today -- so this is not an
    exotic shape, it is the ordinary one for half the captures."""
    raw = (b"GET http://app.test/api/orders/1001?page=2 HTTP/1.1\r\n"
           b"Host: app.test\r\n\r\n")
    assert insertion.request_path(raw) == "/api/orders/1001"


def test_a_bare_lf_request_line_is_still_read():
    """RFC 9112 s2.2 requires a recipient to accept a bare LF. `derive`
    itself yields nothing for such a capture (it splits the head on CRLF),
    and the two disagreeing is deliberate: a surface with no insertion points
    is skipped `no_insertion_point`, which is a better row than
    `no_probe_path` for a request whose address was perfectly readable."""
    assert insertion.request_path(b"GET /a/b HTTP/1.1\nHost: app.test\n\n") \
        == "/a/b"


@pytest.mark.parametrize("raw", [
    b"OPTIONS * HTTP/1.1\r\nHost: app.test\r\n\r\n",   # asterisk-form
    b"CONNECT app.test:443 HTTP/1.1\r\n\r\n",            # authority-form
    b"GET\r\n\r\n",                                      # no target at all
    b"",
])
def test_a_request_with_no_absolute_path_yields_None(raw):
    """`None` rather than a guess. The caller's answer is a `skipped` row
    naming it -- never a probe aimed at something invented here."""
    assert insertion.request_path(raw) is None


# ---- is_placeholder() -----------------------------------------------------
#
# One definition of the shape, read by `derive` above and by
# `hx.checks.probe.ProbeSender.get`, which REFUSES to put one on the wire.


@pytest.mark.parametrize("segment", ["{id}", "{uuid}", "{hex}", "{slug}"])
def test_every_placeholder_the_normaliser_mints_is_recognised(segment):
    """Read out of `hx.surface` rather than trusted: a fifth placeholder
    added there without this set knowing would be a segment `derive` never
    turns into an insertion point and `ProbeSender` happily sends."""
    assert insertion.is_placeholder(segment)


def test_the_normalisers_whole_vocabulary_is_the_four_above():
    minted = {surface.path_template(f"/{seg}", preserve=frozenset(),
                                    slug_threshold=12).lstrip("/")
              for seg in ("1", "0f8c8b1e-1e2a-4b3c-8d4e-5f60718293a4",
                          "a" * 32, "hello-world-2026-edition")}
    assert minted == {"{id}", "{uuid}", "{hex}", "{slug}"}
    assert all(insertion.is_placeholder(m) for m in minted)


@pytest.mark.parametrize("segment", [
    "", "id", "{}", "{", "}", "%7Bid%7D", "a{b}c", "{id}x", "x{id}",
])
def test_nothing_else_is_a_placeholder(segment):
    """`{}` is excluded because nothing mints it, and `%7Bid%7D` is what
    `hx.surface._kept_segment` turns a literal `{id}` segment into -- so a
    captured path cannot forge one."""
    assert not insertion.is_placeholder(segment)

