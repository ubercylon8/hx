# src/hx/crawl/run.py -- the loop and the summary, in full
"""Drive the frontier through one browser and report what happened.

`visit` and `browser_factory` are parameters rather than imports-by-name so
that the loop, the budget accounting and the summary arithmetic can be
tested without Chromium. That is the seam, not a convenience: the parts of
this file worth getting right are arithmetic, and arithmetic should not need
a browser to exercise.

SESSION REQUIRED (Ruling 9): a `--remote-debugging-pipe` connection is
BROWSER-level -- `Page`/`Network`/`DOM` do not exist on it. `browser.Browser`
attaches a page target once, for the browser's whole lifetime, and exposes
the resulting `.session_id`; every call to `visit` below passes it on.

ONE PAGE'S FAILURE DOES NOT END THE CRAWL, BUT A DEAD BROWSER DOES (Ruling
18). That guard lives inside `page.visit`, not here: `visit`'s contract is
"tell me about this page", and "I could not reach it" is an answer
(`PageResult(state="failed", ...)`), not an exception -- so this loop calls
`visit` with no guard of its own, on purpose. A `cdp.CdpClosed` means the
browser itself is gone and `visit` lets it propagate; this function does not
catch it either, so it propagates out of `crawl` and the `with` block below
still closes the browser on the way out.
"""
from __future__ import annotations

from typing import Callable, Iterable, NamedTuple

from hx.crawl import browser as browser_mod
from hx.crawl import frontier as frontier_mod
from hx.crawl import page as page_mod


#: The four things this crawler does not do, worded once. `as_tool_result`
#: puts these in the agent-facing dict as `not_done`; `hx crawl`'s CLI
#: (`cli.py`) echoes them verbatim as the closing lines of its printed
#: summary, so the operator who ran the crawl from a terminal reads the
#: identical disclosure the agent gets rather than a fifth phrasing of the
#: same four facts. Spec §9: the crawl summary AND the report's Limits
#: section must both say this in as many words.
NOT_DONE = (
    "forms are not submitted",
    "nothing is clicked",
    "no interaction-gated route is walked",
    "the crawl is unauthenticated",
)


class CrawlSummary(NamedTuple):
    pages: int
    rendered: int
    degraded: int
    failed: int
    capped: int
    requests: int
    dropped_hosts: tuple[str, ...]
    truncated_by: str | None


def crawl(*, seeds: Iterable[str], proxy_port: int,
          budget: frontier_mod.Budget, burp_home=None,
          visit: Callable = page_mod.visit,
          browser_factory: Callable = browser_mod.Browser) -> CrawlSummary:
    """Visit pages until the frontier is empty or a budget stops us.

    The browser is opened as a context manager and stays one for the whole
    loop, on purpose: a page that raises must still close it. A leaked
    Chromium outlives the crawl and holds a proxy connection the extension
    is accounting for.
    """
    seeds = list(seeds)
    origins = {o for o in (frontier_mod.origin_of(s) for s in seeds) if o}
    frontier = frontier_mod.Frontier(seeds, budget)

    counts = {"rendered": 0, "degraded": 0, "failed": 0}
    capped = 0
    requests = 0
    dropped: set[str] = set()

    with browser_factory(proxy_port=proxy_port, burp_home=burp_home) as br:
        while True:
            url = frontier.next()
            if url is None:
                break
            result, links = visit(br.conn, url, page_origins=origins,
                                  session_id=br.session_id)
            counts[result.state] = counts.get(result.state, 0) + 1
            capped += 1 if result.capped else 0
            requests += result.requests
            # UNIONED across pages (not just the last one), because this
            # list is what an operator pastes into `render_allow` -- a
            # per-page list would make them assemble it by hand.
            dropped.update(result.dropped_hosts)
            # CHARGED AS WE GO. Without this `max_requests` is unenforceable
            # and a crawl can run away inside a page budget -- one page that
            # fires a thousand XHR is a thousand requests against the
            # target, not zero.
            frontier.note_requests(result.requests)
            frontier.offer(links)

    return CrawlSummary(
        pages=frontier.visited,
        rendered=counts["rendered"], degraded=counts["degraded"],
        failed=counts["failed"], capped=capped, requests=requests,
        dropped_hosts=tuple(sorted(dropped)),
        # NAMED, or None. A truncated crawl that presented as complete is
        # S12's failure one level up; a complete crawl that claimed
        # truncation would be the same error pointing the other way.
        truncated_by=frontier.exhausted)


def as_tool_result(summary: CrawlSummary) -> dict:
    """The summary as the agent sees it.

    `truncated_by` is not optional in this dict. A crawl that stopped on a
    budget and reported only its counts would read as a complete crawl of a
    small application, which is S12's failure with the numbers intact.
    """
    return {
        "pages": summary.pages,
        "rendered": summary.rendered,
        "degraded": summary.degraded,
        "failed": summary.failed,
        "capped": summary.capped,
        "requests": summary.requests,
        "dropped_hosts": list(summary.dropped_hosts),
        "truncated_by": summary.truncated_by,
        "not_done": list(NOT_DONE),
    }
