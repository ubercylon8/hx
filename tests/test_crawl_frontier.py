# tests/test_crawl_frontier.py -- the queue, as pure functions
"""`hx.crawl.frontier`. No browser, no network, no clock of its own.

The budget clock is injected so that `max_seconds` is testable without a
sleep -- the pattern `extension/test/hx/policy/TickClock.java` uses on the
Java side for the same reason.
"""
from __future__ import annotations

from hx.crawl import frontier


def _b(pages=100, seconds=100.0, requests=10_000):
    return frontier.Budget(max_pages=pages, max_seconds=seconds,
                           max_requests=requests)


def test_a_fragment_is_not_a_different_page():
    """`#a` and `#b` are one document and one request -- see the module
    docstring's "the fragment goes" line.

    MUTATION: pass `parts.fragment` instead of `""` as the fifth element of
    the `urlunsplit(...)` tuple in `normalise`. This test must go red.
    """
    assert frontier.normalise("https://a.test/x#frag") == "https://a.test/x"


def test_a_query_string_is_a_different_page():
    """The query is exactly what a scan later probes, so collapsing it would
    discard the surfaces this crawler exists to find.

    MUTATION: strip the query in `normalise`. This test must go red.
    """
    a = frontier.normalise("https://a.test/x?id=1")
    b = frontier.normalise("https://a.test/x?id=2")
    assert a != b


def test_two_ids_on_one_path_are_two_pages():
    """DEDUPE IS BY URL, NOT BY PATH TEMPLATE. hx's normaliser maps
    /user/1 and /user/2 to one template, which is right for coverage
    attribution and wrong here: the second may reach code the first did not.

    MUTATION: dedupe on a templated path. This test must go red.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://a.test/user/1", "https://a.test/user/2"]) == 2


def test_a_url_already_seen_is_not_enqueued_twice():
    """The `_seen` set, not just the queue: a URL already visited-or-queued
    must not be offered again, or the same page would be crawled twice for
    every link back to it. The second offer spells the URL with a different
    fragment on purpose, so this also depends on `normalise` collapsing it to
    the same seen-set key as the first.

    MUTATION: delete the `if n in self._seen: return False` guard in
    `_enqueue` (leave the unconditional `self._seen.add(n)` in place). This
    test must go red -- the second `offer()` would return 1, not 0.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://a.test/x"]) == 1
    assert f.offer(["https://a.test/x#other"]) == 0


def test_a_foreign_origin_is_not_enqueued():
    """The origin allowlist. NOT a scope check -- see the module docstring.

    MUTATION: drop the origin test from `offer`. This test must go red.
    """
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["https://cdn.test/app.js"]) == 0


def test_a_non_http_scheme_is_refused():
    """`javascript:`, `mailto:`, `data:` and `blob:` are not pages.

    The `normalise()` assertion on `ftp://a.test/x` is load-bearing and the
    `offer()` assertion alone is not enough: `javascript:`/`mailto:`/
    `data:`/`blob:` have no host, so the `not host` branch refuses them
    with the scheme check deleted entirely -- a wrong-reason pass. And
    `ftp://a.test/x` DOES have a host, but routed through `offer()` its
    differing scheme also gives it a differing origin, so the origin
    allowlist would refuse it even with the scheme check gone -- a second
    wrong-reason pass. Only a direct call to `normalise()` isolates the
    scheme guard from both of those.

    MUTATION: accept any scheme in `normalise`. Must go red -- and the
    crawler would try to navigate to `javascript:alert(1)` harvested from a
    page under test.
    """
    assert frontier.normalise("ftp://a.test/x") is None
    assert frontier.normalise("ws://a.test/x") is None
    f = frontier.Frontier(["https://a.test/"], _b())
    assert f.offer(["javascript:alert(1)", "mailto:x@a.test",
                    "data:text/html,x", "blob:https://a.test/z",
                    "ftp://a.test/x"]) == 0


def test_a_second_seed_origin_is_allowed():
    """The origin allowlist is built from EVERY seed, not just the first --
    a two-origin engagement (say `app.test` plus its `api.app.test`) must be
    able to crawl both.

    MUTATION: build `self._origins` from only the first seed, e.g.
    `for seed in list(seeds)[:1]:` in `Frontier.__init__`. This test must go
    red -- `b.test` would never make it into the allowlist and `offer()`
    would return 0.
    """
    f = frontier.Frontier(["https://a.test/", "https://b.test/"], _b())
    assert f.offer(["https://b.test/x"]) == 1


def test_the_page_budget_stops_the_crawl_and_names_itself():
    """S12 one level up: a truncated crawl that presented as a complete one
    would be the same failure the report guards against.

    MUTATION: return None from `next()` without setting `exhausted`. Must go
    red -- the crawl would look complete.
    """
    f = frontier.Frontier(["https://a.test/1"], _b(pages=1))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted == "max_pages"


def test_the_request_budget_stops_the_crawl_and_names_itself():
    """`next()`'s three budget checks read three DIFFERENT fields off
    `self._budget`, and it is easy to copy-paste one check into another's
    shape and read the wrong field -- `_b(requests=10)` leaves `max_pages`
    and `max_seconds` at their generous defaults, so only the requests check
    can fire here, and this test isolates it from its two siblings rather
    than merely happening not to collide with them.

    MUTATION: in the `self._requests >= self._budget.max_requests` check,
    read `self._budget.max_pages` instead. This test must go red -- with
    `max_pages` still at its default of 100, `11 >= 100` is false and
    `next()` returns the queued page instead of `None`.
    """
    f = frontier.Frontier(["https://a.test/1"], _b(requests=10))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    f.note_requests(11)
    assert f.next() is None
    assert f.exhausted == "max_requests"


def test_the_time_budget_stops_the_crawl_and_names_itself():
    """Same isolation concern as the request-budget test above, for the
    third of `next()`'s three budget checks: `_b(seconds=5.0)` leaves
    `max_pages` and `max_requests` at their generous defaults, so only the
    elapsed-time check can fire.

    MUTATION: in the `self._clock() - self._started >= self._budget.
    max_seconds` check, read `self._budget.max_requests` instead. This test
    must go red -- with `max_requests` still at its default of 10_000, the
    elapsed 99.0 seconds does not clear it and `next()` returns the queued
    page instead of `None`.
    """
    ticks = iter([0.0, 0.0, 99.0, 99.0])
    f = frontier.Frontier(["https://a.test/1"], _b(seconds=5.0),
                          clock=lambda: next(ticks))
    f.offer(["https://a.test/2"])
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted == "max_seconds"


def test_an_unexhausted_frontier_that_simply_ran_out_says_nothing():
    """THE SEPARATING CASE. A crawl that visited everything is COMPLETE, and
    must not report a budget as the reason it stopped.

    MUTATION: set `exhausted` whenever `next()` returns None. Must go red --
    every completed crawl would report itself truncated.
    """
    f = frontier.Frontier(["https://a.test/1"], _b())
    assert f.next() is not None
    assert f.next() is None
    assert f.exhausted is None


# -- Ruling 13: three bugs measured in the brief's `normalise`, corrected. --


def test_a_malformed_port_is_refused_and_does_not_end_the_crawl():
    """These URLs come from `harvest`, which reads the DOM of a page under
    test -- ATTACKER-INFLUENCED INPUT. `urlsplit` does not validate the
    port; `parts.port` does, and it raises. MEASURED 2026-09-02: the first
    draft read `.port` outside its `try` and one
    `<a href="https://a.test:99999/">` ended the whole crawl with an
    unhandled ValueError.

    MUTATION: move the `parts.port` read outside the `try`. Must go red.
    """
    for bad in ("https://a.test:99999/x", "https://a.test:-1/x",
                "https://a.test:abc/x"):
        assert frontier.normalise(bad) is None


def test_an_ipv6_host_keeps_its_brackets():
    """`parts.hostname` strips them and a bare `::1` is not an authority.

    MUTATION: drop the re-bracketing. Must go red -- and the crawler would
    build `https://::1:8443/x`, which nothing can navigate to and which
    compares equal to no origin.
    """
    assert frontier.normalise("https://[::1]:8443/x") == "https://[::1]:8443/x"
    assert frontier.origin_of("https://[::1]:8443/x") == "https://[::1]:8443"


def test_userinfo_is_refused_rather_than_stripped():
    """REFUSED, NOT REWRITTEN. Stripping would visit a URL the page did not
    name -- the confusion userinfo exists to create, and the shape
    `Policy.checkScope` refuses on the Java side.

    MUTATION: strip the userinfo and continue instead of returning None.
    Must go red.
    """
    assert frontier.normalise("https://evil.test@app.test/") is None
    assert frontier.normalise("https://user:pw@a.test/x") is None
