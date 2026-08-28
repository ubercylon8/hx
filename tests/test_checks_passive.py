"""The four checks that read only what a browser already fetched.

Each test drives the real check with a fixture exchange and a fake blob store.
Rule 2 applies to a check as much as to a guard: a check with no input that
separates `finding` from `clean` is not done, so every check here has both.
"""
import pytest

from hx.checks import base
from hx.checks.passive import (cookie_flags, secret_in_response,
                               security_headers, stack_trace)


class FakeBlobs:
    def __init__(self, **blobs): self._b = blobs
    def get(self, digest, expected_len=None): return self._b[digest]


def ctx_for(**blobs):
    return base.CheckContext(config=None, blobs=FakeBlobs(**blobs),
                             run_id="r-1", log=lambda s: None)


def rows(resp_blob="d1", url="https://app.test/x", status=200, outcome="ok"):
    return (base.ExchangeRow(id="x-1", method="GET", url=url, status=status,
                             outcome=outcome, req_blob=None,
                             resp_blob=resp_blob),)


def resp(*headers, body=b""):
    head = b"HTTP/1.1 200 OK\r\n" + b"".join(h + b"\r\n" for h in headers)
    return head + b"\r\n" + body


# ---- cookie flags -----------------------------------------------------

def test_a_cookie_missing_httponly_and_secure_is_a_finding():
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; Path=/")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    assert "session" in v.candidates[0].title
    assert v.candidates[0].insertion is None      # S5: cookie findings have none


def test_a_cookie_with_every_flag_is_clean():
    """The separating case. Without it the check could return `finding`
    unconditionally and every test above would still pass."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_secure_is_not_demanded_over_plain_http():
    """A `Secure` cookie on an http:// origin is not sent at all. Demanding it
    on a target that has no TLS is a finding the client cannot act on and a
    false positive in every report that carries it."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: session=abc; HttpOnly; SameSite=Lax")
    v = c.on_surface(ctx_for(d1=blob), None, rows(url="http://app.test/x"))
    assert v.state == "clean"


def test_a_surface_with_no_set_cookie_is_clean_not_inconclusive():
    """`clean` means tested and nothing found; `inconclusive` means could not
    test. A page that simply sets no cookie WAS tested."""
    c = cookie_flags.CookieFlags()
    assert c.on_surface(ctx_for(d1=resp()), None, rows()).state == "clean"


def test_an_unreadable_blob_is_inconclusive_with_a_reason():
    """S10: never `clean` when the check could not run."""
    c = cookie_flags.CookieFlags()
    v = c.on_surface(ctx_for(), None, rows())      # d1 absent from the store
    assert v.state == "inconclusive"
    assert v.reason


def test_a_second_set_cookie_header_is_still_checked():
    """`Set-Cookie` legitimately repeats: a response can set several cookies
    at once. A parser that reads only the first header of a repeated name
    would check one cookie of five and report the whole surface clean."""
    c = cookie_flags.CookieFlags()
    blob = resp(b"Set-Cookie: a=1; Path=/; Secure; HttpOnly; SameSite=Lax",
                b"Set-Cookie: b=2; Path=/")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    assert "b" in v.candidates[0].title


# ---- security headers -------------------------------------------------

def test_missing_nosniff_and_frame_protection_are_findings():
    c = security_headers.SecurityHeaders()
    v = c.on_surface(ctx_for(d1=resp(b"Content-Type: text/html")), None, rows())
    assert v.state == "finding"
    titles = " ".join(x.title for x in v.candidates)
    assert "X-Content-Type-Options" in titles
    assert "frame" in titles.lower()


def test_a_fully_headed_https_response_is_clean():
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html",
                b"Strict-Transport-Security: max-age=31536000",
                b"X-Content-Type-Options: nosniff",
                b"X-Frame-Options: DENY")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_csp_frame_ancestors_satisfies_the_frame_check():
    """Two headers answer one question, and a check that demands the older one
    when the newer is present reports a finding the client already fixed."""
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html",
                b"Strict-Transport-Security: max-age=1",
                b"X-Content-Type-Options: nosniff",
                b"Content-Security-Policy: frame-ancestors 'none'")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


def test_hsts_is_not_demanded_over_plain_http():
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: text/html", b"X-Content-Type-Options: nosniff",
                b"X-Frame-Options: DENY")
    v = c.on_surface(ctx_for(d1=blob), None, rows(url="http://app.test/x"))
    assert v.state == "clean"


def test_headers_are_not_demanded_of_a_non_document_response():
    """A JSON API response cannot be framed and will not be sniffed into a
    document. Demanding frame protection of it is noise, and noise is what
    makes a report get skimmed."""
    c = security_headers.SecurityHeaders()
    blob = resp(b"Content-Type: application/json",
                b"X-Content-Type-Options: nosniff")
    assert c.on_surface(ctx_for(d1=blob), None, rows()).state == "clean"


# ---- secret in response -----------------------------------------------

def test_a_private_key_block_in_a_body_is_a_finding():
    c = secret_in_response.SecretInResponse()
    blob = resp(body=b"...\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
    v = c.on_surface(ctx_for(d1=blob), None, rows())
    assert v.state == "finding"
    assert v.candidates[0].severity == "High"


def test_an_aws_access_key_id_is_a_finding():
    c = secret_in_response.SecretInResponse()
    v = c.on_surface(ctx_for(d1=resp(body=b'{"k":"AKIAIOSFODNN7EXAMPLE"}')),
                     None, rows())
    assert v.state == "finding"


def test_ordinary_html_is_clean():
    """The separating case, and the one that matters most for this check: a
    corpus that cries wolf on every page is one an operator stops reading."""
    c = secret_in_response.SecretInResponse()
    body = b"<html><body><h1>Welcome</h1><p>AKIA is a prefix.</p></body></html>"
    assert c.on_surface(ctx_for(d1=resp(body=body)), None, rows()).state == "clean"


def test_the_finding_does_not_repeat_the_secret_in_its_title():
    """A report is an artifact that leaves the machine (S12). A finding whose
    TITLE carries the credential re-publishes what redaction removed from the
    blob, one layer up."""
    c = secret_in_response.SecretInResponse()
    v = c.on_surface(ctx_for(d1=resp(body=b'{"k":"AKIAIOSFODNN7EXAMPLE"}')),
                     None, rows())
    assert "AKIAIOSFODNN7EXAMPLE" not in v.candidates[0].title
    assert "AKIAIOSFODNN7EXAMPLE" not in (v.candidates[0].description or "")


# ---- stack traces -----------------------------------------------------

@pytest.mark.parametrize("body", [
    b"Traceback (most recent call last):\n  File \"app.py\", line 3",
    b"java.lang.NullPointerException\n\tat com.acme.Handler.doGet(Handler.java:42)",
    b"PHP Fatal error:  Uncaught Error: Call to a member function",
])
def test_a_framework_stack_trace_is_a_finding(body):
    c = stack_trace.StackTrace()
    v = c.on_surface(ctx_for(d1=resp(body=body)), None, rows(status=500))
    assert v.state == "finding"


def test_prose_mentioning_an_exception_is_clean():
    c = stack_trace.StackTrace()
    body = b"<p>If you see a NullPointerException, contact support.</p>"
    assert c.on_surface(ctx_for(d1=resp(body=body)), None, rows()).state == "clean"


# ---- unreadable evidence ----------------------------------------------
# Whole-branch review F6 (MEDIUM): `_fetch` went `inconclusive` only when
# EVERY blob failed, so a surface where SOME of the evidence was missing was
# scanned as though it were complete and its silence recorded as `clean`.


def two_rows(*, second_outcome, second_blob="d2"):
    """One exchange that came back whole, and one that did not."""
    return (
        base.ExchangeRow(id="x-1", method="GET", url="https://app.test/x",
                         status=200, outcome="ok", req_blob=None,
                         resp_blob="d1"),
        base.ExchangeRow(id="x-2", method="GET", url="https://app.test/x",
                         status=None, outcome=second_outcome, req_blob=None,
                         resp_blob=second_blob),
    )


_FULLY_HEADED = (b"Content-Type: text/html",
                 b"Strict-Transport-Security: max-age=1",
                 b"X-Content-Type-Options: nosniff",
                 b"X-Frame-Options: DENY")


@pytest.mark.parametrize("check,blob", [
    (cookie_flags.CookieFlags(), resp(b"Set-Cookie: a=1; Secure; HttpOnly; SameSite=Lax")),
    (security_headers.SecurityHeaders(), resp(*_FULLY_HEADED)),
    (secret_in_response.SecretInResponse(), resp(body=b"<html>fine</html>")),
    (stack_trace.StackTrace(), resp(body=b"<html>fine</html>")),
])
def test_one_exchange_that_never_answered_makes_the_surface_inconclusive(
    check, blob,
):
    """F6, and it applies to all four checks because the rule lives in
    `_http.verdict`, not in any of them.

    The FIRST exchange is readable and gives every check a genuine `clean`;
    the second timed out. MEASURED before this fix, with the same shape
    driven through `scan.run`: `check_run` recorded `('clean', NULL)` --
    indistinguishable, in the coverage section S12 requires, from a surface
    every one of whose exchanges was read whole. S5 names the mechanism on
    `exchange.outcome` itself: "a transport failure has no HTTP status;
    without `outcome` a check reads silence as 'not vulnerable'".
    """
    v = check.on_surface(ctx_for(d1=blob), None,
                         two_rows(second_outcome="timeout", second_blob=None))
    assert v.state == "inconclusive", (check.id, v)
    assert "x-2" in v.reason and "timeout" in v.reason, v.reason


def test_the_same_surface_with_every_exchange_readable_is_clean():
    """The separating case. Without it, `inconclusive` unconditionally would
    satisfy the test above and no check could ever clear anything -- which is
    the other half of S12's rule, not a safe direction to fail in."""
    c = security_headers.SecurityHeaders()
    rows_ok = (base.ExchangeRow(id="x-1", method="GET", url="https://app.test/x",
                                status=200, outcome="ok", req_blob=None,
                                resp_blob="d1"),)
    assert c.on_surface(ctx_for(d1=resp(*_FULLY_HEADED)), None,
                        rows_ok).state == "clean"


def test_a_partly_unreadable_surface_that_finds_something_still_says_finding():
    """A gap does not un-find what was found. Downgrading a real finding to
    `inconclusive` because some OTHER exchange was unreadable would lose the
    one thing this surface did prove."""
    c = cookie_flags.CookieFlags()
    v = c.on_surface(ctx_for(d1=resp(b"Set-Cookie: session=abc; Path=/")), None,
                     two_rows(second_outcome="conn_refused", second_blob=None))
    assert v.state == "finding"
    assert "session" in v.candidates[0].title


def test_a_truncated_response_is_read_for_what_it_holds_and_still_not_clean():
    """`truncated` and `status_unreadable` DID bring bytes back -- `capture`'s
    own docstring lists them with `ok` as the outcomes meaning a response
    came back -- so the bytes are searched: a private key in a partial body
    is a private key. What they cannot do is license `clean`, because the
    thing that was going to be missing may simply be past the cut."""
    c = secret_in_response.SecretInResponse()
    leaky = resp(body=b"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n")
    rows_cut = (base.ExchangeRow(id="x-9", method="GET",
                                 url="https://app.test/x", status=599,
                                 outcome="truncated", req_blob=None,
                                 resp_blob="d1"),)
    found = c.on_surface(ctx_for(d1=leaky), None, rows_cut)
    assert found.state == "finding"

    clean_looking = c.on_surface(ctx_for(d1=resp(body=b"<html>fine</html>")),
                                 None, rows_cut)
    assert clean_looking.state == "inconclusive"
    assert "truncated" in clean_looking.reason


def test_a_surface_with_no_exchanges_at_all_is_inconclusive():
    """Nothing was read, so nothing was tested. The reason must not claim a
    gap it cannot name."""
    c = stack_trace.StackTrace()
    v = c.on_surface(ctx_for(), None, ())
    assert v.state == "inconclusive"
    assert v.reason == "no response could be read for this surface"
