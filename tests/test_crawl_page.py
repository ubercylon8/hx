# tests/test_crawl_page.py -- harvesting and the S12 classifier
"""`hx.crawl.page`. No browser: the classifier is a pure function over a
list of CDP events, and the harvester is a pure function over HTML.

The events are the real shapes Chromium emits -- `Network.requestWillBeSent`
carries `request.url`, `Network.loadingFailed` carries `errorText`. They are
written out here rather than recorded from a live browser so that a reader
can see what each test is claiming.
"""
from __future__ import annotations

from hx.crawl import cdp, page

ORIGINS = {"https://app.test"}


def _sent(url: str, *, rtype: str | None = None) -> dict:
    params = {"requestId": url, "request": {"url": url}}
    if rtype is not None:
        params["type"] = rtype
    return {"method": "Network.requestWillBeSent", "params": params}


def _failed(url: str) -> dict:
    return {"method": "Network.loadingFailed",
            "params": {"requestId": url, "errorText": "net::ERR_EMPTY_RESPONSE"}}


def _ok(url: str) -> dict:
    return {"method": "Network.responseReceived",
            "params": {"requestId": url, "response": {"status": 200}}}


# --- harvesting ------------------------------------------------------------

def test_anchors_areas_iframes_and_form_actions_are_all_harvested():
    """All four link-bearing tags in one call, so a fix or refactor to one
    entry of `_LINK_ATTRS` cannot silently drop another.

    MUTATION: remove the `"area": "href"` entry from `_LINK_ATTRS`. This
    test must go red -- `https://app.test/b` would be missing from `out`,
    and an `<area>` inside an image map (the one HTML link shape none of
    the other tests here uses) would go uncrawled.
    """
    html = ('<a href="/a">x</a>'
            '<area href="/b">'
            '<iframe src="/c"></iframe>'
            '<form action="/d"></form>')
    out = page.harvest(html, "https://app.test/start")
    assert set(out) == {"https://app.test/a", "https://app.test/b",
                        "https://app.test/c", "https://app.test/d"}


def test_a_form_action_is_harvested_as_a_url_and_never_submitted():
    """S9's form policy is DEFERRED, and this pins the half that ships: the
    action is a page address we may GET, not a form we may POST.

    MUTATION: have `harvest` return a (url, method, fields) triple that a
    caller could submit. Must go red -- and the review that follows would be
    reviewing form submission, which this plan does not ship.
    """
    out = page.harvest('<form action="/pay" method="post">'
                       '<input name="amount"></form>', "https://app.test/")
    assert out == ["https://app.test/pay"]


def test_relative_urls_resolve_against_the_page_not_the_origin():
    """`urljoin` needs the FULL page URL, path and all, or `b` off
    `/deep/a` resolves to the wrong place. The origin alone is not enough.

    MUTATION: when no `<base>` tag is present, resolve against the page's
    origin instead of its full URL, e.g. `base = f"{urlsplit(base_url).
    scheme}://{urlsplit(base_url).netloc}/"`. This test must go red --
    `b` would resolve to `https://app.test/b`, discarding the `/deep/`
    the page actually lives under.
    """
    out = page.harvest('<a href="b">x</a>', "https://app.test/deep/a")
    assert out == ["https://app.test/deep/b"]


def test_a_base_tag_is_honoured():
    """A page that sets `<base>` means relative links there, not against its
    own URL -- `v1` here must resolve under `/api/`, not under `/other`.

    MUTATION: drop the `<base>`-tag branch and always resolve against
    `base_url` (`base = base_url`, unconditionally). This test must go red --
    `v1` would resolve to `https://app.test/v1`, ignoring the declared base.
    """
    out = page.harvest('<base href="https://app.test/api/">'
                       '<a href="v1">x</a>', "https://app.test/other")
    assert out == ["https://app.test/api/v1"]


def test_grossly_malformed_markup_does_not_raise():
    """Documents the tolerant behaviour on real garbled markup. NOT a
    mutation-carrying test: CPython's `html.parser` is deliberately
    exception-safe for any `str` input (strict mode was removed in 3.5) --
    fuzzed 20,000 random strings over `<>"'=/!` plus NUL, a lone surrogate,
    and out-of-range numeric character references, and none raised. So this
    input alone cannot exercise `harvest`'s `except Exception` guard; see
    `test_malformed_html_yields_what_it_can_rather_than_raising` below for
    the test that actually forces that path and carries the mutation.
    """
    assert page.harvest('<a href="/a">x<<<>>"', "https://app.test/") == \
        ["https://app.test/a"]


def test_malformed_html_yields_what_it_can_rather_than_raising(monkeypatch):
    """A page under test is attacker-influenced input, and some future
    document could make parsing fail partway through. MUTATION: let that
    exception propagate out of `harvest` (delete its try/except around
    `parser.feed`/`.close`). Must go red -- one broken page would end the
    crawl.

    CPython's `html.parser` will not raise for any crafted HTML string we
    could find (see the sibling test above), so the failure is forced the
    only way available in this Python version: patching the per-tag handler
    `feed` calls into, so the SAME code path `harvest` protects -- an
    exception raised while `HTMLParser.feed` is running -- is exercised for
    real, and the first tag's link (parsed before the raise) is still real
    and still returned.
    """
    real_handle = page._Links.handle_starttag

    def flaky(self, tag, attrs):
        real_handle(self, tag, attrs)
        if tag == "b":
            raise ValueError("simulated parser failure mid-document")

    monkeypatch.setattr(page._Links, "handle_starttag", flaky)
    out = page.harvest('<a href="/a">x</a><b href="/b">y</b>',
                       "https://app.test/")
    assert out == ["https://app.test/a"]


# --- classification: S12 applied to one page -------------------------------

def test_a_page_that_loaded_and_yielded_links_is_rendered():
    """`classify` returns "rendered" from two different places: the `yielded`
    branch (`if yielded: state = "rendered"`) and the fallback at the bottom
    of the same if/elif/else (`else: state = "rendered"`, taken whenever
    nothing was dropped). MEASURED: as first written this test's events had
    no drop, so `dropped` was empty and deleting the `yielded` branch
    entirely (`if False: state = "rendered"`) fell straight through to the
    no-drop fallback and produced the identical verdict -- the test stayed
    green under a mutation that removed the exact thing it claims to check.
    A dropped third party is included below (the same fix
    `test_a_page_with_xhr_but_no_links_still_counts_as_rendered` already
    needed for its own case) so the assertion actually depends on `yielded`:
    without it, `dropped` is non-empty and this page would fall to
    "degraded", not "rendered".

    MUTATION: delete the `if yielded: state = "rendered"` branch (e.g.
    replace its condition with `if False:`), leaving `elif dropped: state =
    "degraded"` as the next thing tested. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)
    assert r.state == "rendered"


def test_a_page_that_yielded_nothing_after_a_drop_is_degraded():
    """THE FAILURE THIS WHOLE FUNCTION EXISTS FOR. The proxy drops the CDN
    bundle, the SPA never boots, and a naive crawler records a clean crawl of
    an application it never rendered -- S12's exact failure.

    MUTATION: return "rendered" whenever the document itself loaded. This
    test must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "degraded"
    assert r.dropped_hosts == ("cdn.test",)


def test_a_drop_that_did_not_matter_is_still_rendered():
    """THE SEPARATING CASE. A dropped font on a page that produced links did
    not stop anything, and calling it degraded would under-report coverage on
    every page with a third-party asset.

    MUTATION: return "degraded" whenever any drop occurred. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://fonts.test/f.woff2"),
              _failed("https://fonts.test/f.woff2")]
    r = page.classify(events, page_origins=ORIGINS, harvested=4)
    assert r.state == "rendered"


def test_an_in_scope_failure_is_the_target_failing_not_a_policy_drop():
    """Two different facts that must not be reported as one: hx dropped it,
    versus the target could not serve it.

    MUTATION: put every failure in `dropped_hosts`. Must go red -- and the
    operator would paste their own application's host into render_allow.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/broken.js"),
              _failed("https://app.test/broken.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=2)
    assert r.dropped_hosts == ()
    assert r.in_scope_failures == ("https://app.test/broken.js",)


def test_page_origins_is_seed_origins_so_unseeded_in_scope_failure_reads_dropped():
    """F2, PINNING THE DOCUMENTED LIMITATION rather than hiding it: `page_
    origins` is SEED origins, not scope (see `classify`'s docstring). A
    scope that covers `api.app.test` but was only ever seeded from
    `app.test` has no way, from inside this function, to tell "target-side
    failure on an in-scope-but-unseeded origin" apart from "hx dropped an
    out-of-scope host" -- both look identical here: a failed request whose
    origin is not in `page_origins`. This is CURRENT, INTENDED-DOCUMENTED
    behaviour (the fix is the docstring plus the CLI's pointer at the
    authoritative denial rows, not a second scope matcher -- spec §7
    forbids one) -- this test exists to keep the limitation visible rather
    than let a future change silently narrow or widen it unnoticed.

    MUTATION: swap the two branches of the `dropped_candidates` loop (`if
    origin_of(url) in page_origins: dropped.add(host)` / `else: in_scope_
    failures.append(url)`, i.e. the opposite of today's code). Must go
    red -- `api.app.test` is not in `page_origins` here, so under the swap
    it lands in `in_scope_failures` and `dropped_hosts` comes back empty,
    failing both assertions below.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://api.app.test/data"),
              _failed("https://api.app.test/data")]
    r = page.classify(events, page_origins={"https://app.test"}, harvested=2)
    assert r.dropped_hosts == ("api.app.test",)
    assert r.in_scope_failures == ()


def test_a_document_that_never_loaded_is_failed_not_degraded():
    """The document itself is the request in `dropped_candidates` here (no
    `responseReceived` for it at all) -- the most basic case `document in
    dropped_candidates` exists for, distinct from the `degraded` cases below
    where a THIRD PARTY, not the document, drops.

    MUTATION: drop `or document in dropped_candidates` from the `state =
    "failed"` guard, leaving only `if document is None:`. This test must go
    red -- `document` is not `None` here (it is the sent request's id), so
    the mutated guard does not fire; the loop below then classifies the
    document's own origin as in-scope (it IS in `page_origins`) and files it
    under `in_scope_failures` rather than `dropped`, so `dropped` stays
    empty and `classify` falls all the way to the "no drop" fallback,
    reporting `rendered` for a page that never loaded.
    """
    events = [_sent("https://app.test/"), _failed("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "failed"


def test_a_page_with_xhr_but_no_links_still_counts_as_rendered():
    """The measured reason this crawler is worth building: S9's 65-requests
    result came from a page's own fetch calls, not from its links. A page
    that yielded only XHR has been reached.

    A dropped third party is included so the assertion actually depends on
    `own` rather than passing by the unconditional "no drop -> rendered"
    branch: with no drop present at all, `state` lands on "rendered"
    regardless of `yielded`, and this test would pass even with the named
    mutation applied, catching nothing. (Found by asking, of this test,
    "is there any other path to this same assertion?")

    MUTATION: judge `rendered` on `harvested` alone (drop `or own > 0`).
    Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/api/items?q=1"),
              _ok("https://app.test/api/items?q=1"),
              _sent("https://cdn.test/app.js"), _failed("https://cdn.test/app.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "rendered"
    assert r.requests == 3


def test_dropped_hosts_are_deduplicated_and_ordered():
    """Two dropped requests to `cdn.test` (`a.js` and `b.js`) must collapse
    to one entry, and the two distinct hosts must come back sorted rather
    than in event-arrival order (`cdn.test` is sent first here, `ads.test`
    second, and the expected tuple is alphabetical).

    DEDUPLICATION is structural, not something a mutation can meaningfully
    target: `dropped` is a `set`, and a set cannot hold `"cdn.test"` twice
    by construction (see DECISIONS.md's "Structure beats behaviour"). The
    runtime-testable half of this test's name is the ORDERING, which is a
    behavioural choice (`sorted(...)`) and can regress.

    MUTATION: sort in reverse, `tuple(sorted(dropped, reverse=True))`. This
    test must go red -- `dropped_hosts` would come back as `("cdn.test",
    "ads.test")`.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    for u in ("https://cdn.test/a.js", "https://cdn.test/b.js",
              "https://ads.test/t.gif"):
        events += [_sent(u), _failed(u)]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.dropped_hosts == ("ads.test", "cdn.test")


# --- classification: F4 -- the document is identified by `type`, not by
# arrival order -------------------------------------------------------------

def test_a_stale_request_from_the_previous_page_does_not_masquerade_as_the_document():
    """F4, the re-diagnosed favicon race. `visit` reuses one page session for
    every URL in the crawl, and `drain(0.0)` before navigation only clears
    events that have ALREADY arrived -- a trailing event from page N-1 can
    still be in flight and be the FIRST thing this page's event list holds.
    Judging "the document" by arrival order then risks taking that stale,
    successful request as this page's document while the real, typed
    `Document` request failed -- an OVER-CLAIM (`rendered` for a page that
    never loaded), which §12 calls the unsurvivable direction.

    Here the stale request (no `type`, arrives first, succeeds) precedes the
    real document (`type="Document"`, arrives second, fails with no
    response).

    MUTATION: identify the document by first arrival (`first_seen`) instead
    of preferring `typed_document`. Must go red -- first-arrival picks the
    stale successful request as the document, and this page would be
    reported `rendered` (having harvested nothing but a drop of nobody, so
    it would in fact fall through to `rendered` on the "no drop" branch)
    instead of `failed`.
    """
    events = [
        _sent("https://app.test/favicon.ico"),  # stale, from the prior page
        _ok("https://app.test/favicon.ico"),
        _sent("https://app.test/real-page", rtype="Document"),
        _failed("https://app.test/real-page"),
    ]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)
    assert r.state == "failed"


def test_the_document_falls_back_to_first_arrival_when_nothing_carries_type():
    """F4's fallback half: a synthetic or truncated event stream (every
    OTHER test in this file, and a real capped/aborted page) may carry no
    `type` field on any event at all. The fix must not regress those --
    first-arrival is still used when no event is typed.

    MUTATION: require a typed event unconditionally (drop the `if typed_
    document is not None else first_seen` fallback, e.g. leave `document`
    as `None` whenever nothing is typed). Must go red -- with `document`
    forced to `None`, `classify` takes the `document is None` branch and
    reports `failed` for a page that in fact loaded and yielded a link.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=1)
    assert r.state == "rendered"


# --- classification: Ruling 11 -- a drop is a failure with NO response -----

def test_a_document_served_then_truncated_is_not_reported_as_failed():
    """MEASURED 2026-09-02: a request can appear in BOTH `responseReceived`
    and `loadingFailed` -- served, then broken mid-body. The crawler did
    receive and harvest that page.

    MUTATION: classify the document on `failed` rather than on
    `failed - answered`. Must go red -- a page we read would be reported as
    one that never loaded.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _failed("https://app.test/")]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)
    assert r.state == "rendered"


def test_a_third_party_served_then_broken_is_not_named_as_dropped():
    """`dropped_hosts` is the list an operator pastes into `render_allow`.
    A resource that WAS served and then broke was not blocked by anything,
    and naming it would have them widen scope to fix a phantom.

    MUTATION: put every out-of-scope failure in `dropped_hosts` rather than
    only those with no response. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://cdn.test/a.js"), _ok("https://cdn.test/a.js"),
              _failed("https://cdn.test/a.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=2)
    assert r.dropped_hosts == ()


# --- visit: Ruling 18 -- a page's CDP error is contained, a dead browser is
# not -------------------------------------------------------------------

class _FakeConn:
    """A `cdp.Connection` double whose `.call` raises once, on a named
    method, and answers empty-but-valid on everything else. `.drain` never
    raises -- the real `Connection.drain` swallows `CdpTimeout`/`CdpClosed`
    internally (see `cdp.py`), so `visit` never sees those from `drain`.
    """

    def __init__(self, raise_on: str, exc: Exception) -> None:
        self._raise_on = raise_on
        self._exc = exc
        self.calls: list[str] = []

    def call(self, method, params=None, *, session_id=None, timeout=None):
        self.calls.append(method)
        if method == self._raise_on:
            raise self._exc
        if method == "DOM.getDocument":
            return {"root": {"nodeId": 1}}
        if method == "DOM.getOuterHTML":
            return {"outerHTML": "<a href=\"/x\">x</a>"}
        return {}

    def drain(self, timeout):
        return []


def test_a_page_whose_network_enable_raises_cdp_error_is_recorded_failed():
    """Ruling 18: `visit`'s contract is "tell me about this page", and "I
    could not reach it" is an ANSWER, not an exception -- `classify` already
    has a `failed` state for exactly that.

    MUTATION: remove the `except cdp.CdpError` guard around `Network.enable`
    / `Page.enable` inside `visit` (let the error propagate). Must go red --
    without it, `page.visit` itself raises instead of returning, so this
    call raises `cdp.CdpError` instead of returning a `PageResult`.
    """
    conn = _FakeConn(raise_on="Network.enable", exc=cdp.CdpError("boom"))
    result, links = page.visit(conn, "https://app.test/",
                               page_origins=ORIGINS, session_id="s1")
    assert result == page.PageResult(state="failed", requests=0,
                                     dropped_hosts=(), in_scope_failures=(),
                                     capped=False)
    assert links == []


def test_a_page_whose_call_raises_cdp_closed_propagates():
    """Ruling 18: `cdp.CdpClosed` means the browser itself is gone -- every
    later page would fail the identical way, so ending the crawl by letting
    it propagate is correct. This is the more important of the two halves:
    catching `CdpClosed` alongside `CdpError` would turn a dead browser into
    a silent run of N "failed" pages, which is S12's failure wearing a new
    hat.

    MUTATION: catch `cdp.CdpClosed` inside `visit` (e.g. list it after the
    general `except cdp.CdpError`, or drop its `except cdp.CdpClosed: raise`
    clause entirely) so it is treated the same as a contained `CdpError`.
    Must go red -- `visit` would return a failed `PageResult` instead of
    raising.
    """
    conn = _FakeConn(raise_on="Network.enable", exc=cdp.CdpClosed("closed"))
    try:
        page.visit(conn, "https://app.test/", page_origins=ORIGINS,
                  session_id="s1")
    except cdp.CdpClosed:
        pass
    else:
        raise AssertionError("expected cdp.CdpClosed to propagate")


def test_a_page_whose_dom_read_raises_cdp_closed_also_propagates():
    """Ruling 18, the third site. The DOM-read guard's `except cdp.CdpError`
    is a superclass match and would ALSO catch `CdpClosed` unless it has its
    own `except cdp.CdpClosed: raise` ahead of it -- silently reducing a
    dead browser mid-DOM-read to `html = ""` instead of ending the crawl.

    Both tests above raise on `Network.enable`, the FIRST call `visit`
    makes, so neither one ever reaches this guard. This is the test that
    does: `Network.enable`, `Page.enable` and `Page.navigate` must all
    succeed here, or this test would pass because of an earlier guard and
    prove nothing about the site it names.

    MUTATION: at the DOM-read site, remove `except cdp.CdpClosed: raise` so
    the broad `except cdp.CdpError` swallows it. Must go red.
    """
    conn = _FakeConn(raise_on="DOM.getDocument", exc=cdp.CdpClosed("closed"))
    try:
        page.visit(conn, "https://app.test/", page_origins=ORIGINS,
                  session_id="s1", settle=0.0)
    except cdp.CdpClosed:
        pass
    else:
        raise AssertionError("expected cdp.CdpClosed to propagate")
    assert conn.calls[:4] == ["Network.enable", "Page.enable",
                              "Log.enable", "Page.navigate"]


# --- the page's own account of what it could not load ----------------------

def _console_error(text: str, url: str = "") -> dict:
    """A `Log.entryAdded` in the shape measured off real Chromium 150."""
    return {"method": "Log.entryAdded",
            "params": {"entry": {"source": "javascript", "level": "error",
                                 "text": text, "url": url}}}


_MODULE_FAIL = ("Failed to load module script: Expected a JavaScript-or-Wasm "
                'module script but the server responded with a MIME type of '
                '"text/html". Strict MIME type checking is enforced for module '
                "scripts per HTML spec.")


def test_a_page_that_could_not_load_its_own_module_is_degraded():
    """THE JUICE SHOP CASE, and the reason this signal exists.

    MEASURED 2026-09-03 against OWASP Juice Shop through this crawler's own
    Burp: its Express server mishandles the absolute-form request line every
    client sends to a proxy, so four module scripts came back as `text/html`,
    Chrome refused all four, and Angular never bootstrapped. The crawl saw 5
    requests instead of 41 and reported the page `rendered` with no
    truncation -- nothing was dropped and no budget was hit, so every other
    S12 mechanism in this file stayed silent.

    MUTATION: delete the `elif failures:` branch from `classify`. This test
    must go red -- the page would be `rendered`, exactly as it wrongly was.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(_MODULE_FAIL, "https://app.test/chunk-a.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)

    assert r.state == "degraded"
    assert r.load_errors == ("https://app.test/chunk-a.js",)


def test_a_load_failure_outranks_a_page_that_yielded_something():
    """THE SEPARATING CASE, and the one that makes the branch worth having
    where it sits. A document that fetched links and THEN could not execute
    its main module has not rendered the application; counting those links as
    yield reports it `rendered`.

    MUTATION: move the `elif failures:` branch below the `if yielded:` one.
    Must go red -- and the Juice Shop page would be reported `rendered` again
    the moment it harvested a single link.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _sent("https://app.test/api/x"), _ok("https://app.test/api/x"),
              _console_error(_MODULE_FAIL, "https://app.test/main.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=7)

    assert r.state == "degraded"


def test_an_ordinary_console_error_is_not_a_load_failure():
    """NARROW ON PURPOSE. A page under test logs errors all day -- a caught
    exception, a deprecation, a failed analytics beacon -- and none of them
    mean the application did not come up. Marking every one `degraded` would
    make the verdict noise.

    MUTATION: treat any `level == "error"` entry as a load failure, dropping
    the `_LOAD_FAILURE_MARKERS` test. Must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error("Uncaught TypeError: x is not a function"),
              _console_error("[Deprecation] SomeAPI is deprecated")]
    r = page.classify(events, page_origins=ORIGINS, harvested=4)

    assert r.state == "rendered"
    assert r.load_errors == ()


def test_a_warning_is_not_an_error():
    """MUTATION: drop the `level != "error"` guard. Must go red -- a warning
    is the browser telling you about something it went ahead and did.
    """
    warn = {"method": "Log.entryAdded",
            "params": {"entry": {"source": "network", "level": "warning",
                                 "text": "Failed to load resource: slow",
                                 "url": "https://app.test/z.js"}}}
    events = [_sent("https://app.test/"), _ok("https://app.test/"), warn]
    r = page.classify(events, page_origins=ORIGINS, harvested=3)

    assert r.state == "rendered"


def test_load_failures_are_deduplicated():
    """Four chunks failing the same way is four entries; the same chunk
    logged twice is one."""
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(_MODULE_FAIL, "https://app.test/a.js"),
              _console_error(_MODULE_FAIL, "https://app.test/a.js"),
              _console_error(_MODULE_FAIL, "https://app.test/b.js")]
    r = page.classify(events, page_origins=ORIGINS, harvested=0)

    assert r.load_errors == ("https://app.test/a.js", "https://app.test/b.js")


def test_a_dead_favicon_is_not_a_load_failure():
    """THE MARKER THAT WAS TOO BROAD. `"failed to load resource"` is Chrome's
    generic console message for ANY failed subresource -- a 404 favicon, a
    blocked analytics beacon, a missing font. It was in
    `_LOAD_FAILURE_MARKERS` for one review round, which made the exact
    example the module's own comment gives as NOT a load failure into one.

    Every surviving marker is the browser refusing to EXECUTE or APPLY
    something. A dead image is not refused; it is simply absent.

    MUTATION: re-add `"failed to load resource"` to `_LOAD_FAILURE_MARKERS`.
    This test must go red.
    """
    events = [_sent("https://app.test/"), _ok("https://app.test/"),
              _console_error(
                  "Failed to load resource: the server responded with a "
                  "status of 404 (Not Found)", "https://app.test/favicon.ico")]
    r = page.classify(events, page_origins=ORIGINS, harvested=5)

    assert r.state == "rendered"
    assert r.load_errors == ()
