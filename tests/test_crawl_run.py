# tests/test_crawl_run.py -- the loop and the summary, with a fake browser
"""`hx.crawl.run`. No Chromium: `crawl` takes its `visit` and its browser
factory as parameters, so the loop, the budget accounting and the summary
arithmetic are exercised as pure logic.
"""
from __future__ import annotations

from hx.crawl import frontier, page
from hx.crawl import run as crawl_run


class _FakeBrowser:
    def __init__(self, **kw) -> None:
        self.conn = object()
        self.session_id = "fake-session"
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def close(self):
        self.closed = True


def _visitor(pages: dict[str, tuple[page.PageResult, list[str]]]):
    """A `visit` double: a map from URL to what that page yields."""
    default = (page.PageResult("rendered", 1, (), (), False), [])

    def visit(conn, url, *, page_origins, session_id, settle=2.0, cap=20.0):
        return pages.get(url, default)
    return visit


def _b(pages=100, seconds=100.0, requests=10_000):
    return frontier.Budget(max_pages=pages, max_seconds=seconds,
                           max_requests=requests)


def test_links_from_one_page_become_the_next_pages():
    """A page's harvested links must reach the frontier, or the crawl never
    leaves its seeds.

    MUTATION: drop the `frontier.offer(links)` call. Must go red.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 2, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.pages == 3


def test_the_summary_counts_each_state_separately():
    """`rendered`/`degraded`/`failed` are separate counts, not one bucket --
    an operator reading only `pages` cannot tell a clean crawl from one that
    never rendered.

    MUTATION: bucket every page's result into `counts["rendered"]`
    regardless of `result.state`. Must go red.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, (), (), False),
                            ["https://a.test/d", "https://a.test/f"]),
        "https://a.test/d": (page.PageResult("degraded", 1, ("cdn.test",), (),
                                             False), []),
        "https://a.test/f": (page.PageResult("failed", 1, (), (), False), []),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert (s.rendered, s.degraded, s.failed) == (1, 1, 1)


def test_dropped_hosts_are_unioned_across_pages_because_that_is_the_fix_list():
    """The summary's dropped-host list IS the list an operator pastes into
    `render_allow`. A per-page list would make them assemble it by hand.

    MUTATION: report only the last page's dropped hosts. Must go red.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, ("cdn.test",), (),
                                            False), ["https://a.test/b"]),
        "https://a.test/b": (page.PageResult("degraded", 1, ("ads.test",), (),
                                             False), []),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.dropped_hosts == ("ads.test", "cdn.test")


def test_a_truncated_crawl_names_the_budget_that_stopped_it():
    """MUTATION: leave `truncated_by` None. Must go red -- a truncated crawl
    would present as a complete one, which is S12 one level up.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 1, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1,
                        budget=_b(pages=2), visit=visit,
                        browser_factory=_FakeBrowser)
    assert s.truncated_by == "max_pages"


def test_a_complete_crawl_reports_no_truncation():
    """THE SEPARATING CASE, without which every crawl claims truncation.

    MUTATION: report `truncated_by=frontier.exhausted or "max_pages"`
    (or any expression that names a budget even when the queue simply
    emptied). Must go red.
    """
    visit = _visitor({})
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=visit, browser_factory=_FakeBrowser)
    assert s.truncated_by is None


def test_requests_are_charged_to_the_budget_as_pages_are_visited():
    """MUTATION: never call `note_requests`. Must go red -- `max_requests`
    would be unenforceable and a crawl could run away inside a page budget.
    """
    visit = _visitor({
        "https://a.test/": (page.PageResult("rendered", 40, (), (), False),
                            ["https://a.test/x", "https://a.test/y"]),
    })
    s = crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1,
                        budget=_b(requests=5), visit=visit,
                        browser_factory=_FakeBrowser)
    assert s.truncated_by == "max_requests"


def test_the_browser_is_closed_even_when_a_page_raises():
    """A leaked Chromium outlives the crawl and holds a proxy connection the
    extension is accounting for.

    MUTATION: drop the context manager around the loop (call
    `browser_factory(...)` directly instead of `with browser_factory(...)`).
    Must go red.
    """
    made: list[_FakeBrowser] = []

    def factory(**kw):
        b = _FakeBrowser()
        made.append(b)
        return b

    def boom(conn, url, **kw):
        raise RuntimeError("page exploded")

    try:
        crawl_run.crawl(seeds=["https://a.test/"], proxy_port=1, budget=_b(),
                        visit=boom, browser_factory=factory)
    except RuntimeError:
        pass
    assert made and made[0].closed
