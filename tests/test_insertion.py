"""Where a payload could go, read off one captured request.

S5: derived, not stored. The derivation is pure -- bytes in, insertion points
out -- so it is testable without a database, a surface row or a Burp.
"""
from hx import insertion
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
