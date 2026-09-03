"""What to visit next, and when to stop.

AN ORIGIN ALLOWLIST, NOT A SCOPE CHECK, and the distinction is the whole
design. There is no Python scope matcher in this repo: scope lives in
`Policy.Rule` behind percent-decoding to a fixed point, userinfo rejection,
path-length bounds and reading sets. A second matcher here would be a
second answer to the question that gates egress, and the one that drifts is
the one nobody is enforcing with.

So this file answers the narrower question -- IS THIS PAGE WORTH VISITING --
and the JVM answers the only one that matters for egress. A URL on a seed
origin but outside `scope.include` by path is enqueued, visited, dropped at
ProxyGate and recorded as a denial. That costs one refused request, and it
is the correct trade.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Callable, Iterable, NamedTuple
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


class Budget(NamedTuple):
    max_pages: int
    max_seconds: float
    max_requests: int


def normalise(url: str) -> str | None:
    """One canonical spelling of a page address, or None if it is not one.

    The fragment goes: `#a` and `#b` are one document and one request. The
    QUERY STAYS: it is exactly what a scan later probes, and collapsing it
    would discard the surfaces this crawler exists to find.

    These URLs come from `harvest`, which reads the DOM of a page under
    test -- attacker-influenced input. Every failure mode below must
    resolve to `None`, never to a raised exception or a rewritten URL:
    a malformed port must not end the crawl, and userinfo must be
    refused, not silently stripped (see ruling-13-normalise.md).
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port  # INSIDE the try: `.port` validates and raises,
        # and this input came from a page under test
        username = parts.username
        password = parts.password
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    if username is not None or password is not None:
        # REFUSED, NOT STRIPPED. Rewriting would visit a URL the page did
        # not name -- exactly the confusion userinfo exists to create, and
        # the shape `Policy.checkScope` refuses on the Java side.
        return None
    # Re-bracket IPv6: `.hostname` removes the brackets and a bare `::1`
    # is not a URL authority.
    netloc = f"[{host}]" if ":" in host else host.lower()
    if port and port != _DEFAULT_PORTS[parts.scheme]:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path or "/",
                       parts.query, ""))


def origin_of(url: str) -> str | None:
    """`scheme://host[:port]`, with a default port normalised away."""
    n = normalise(url)
    if n is None:
        return None
    parts = urlsplit(n)
    return f"{parts.scheme}://{parts.netloc}"


class Frontier:
    """The queue, the seen-set and the budgets."""

    def __init__(self, seeds: Iterable[str], budget: Budget,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._budget = budget
        self._clock = clock
        self._started = clock()
        self._queue: deque[str] = deque()
        self._seen: set[str] = set()
        self._origins: set[str] = set()
        self._requests = 0
        self.visited = 0
        self.exhausted: str | None = None

        for seed in seeds:
            origin = origin_of(seed)
            if origin is None:
                continue
            self._origins.add(origin)
        for seed in seeds:
            self._enqueue(seed)

    def offer(self, urls: Iterable[str]) -> int:
        """Enqueue every URL that is new and on a seed origin."""
        return sum(1 for url in urls if self._enqueue(url))

    def note_requests(self, n: int) -> None:
        self._requests += n

    def next(self) -> str | None:
        """The next page, or None -- and `exhausted` says which None it is.

        A budget sets `exhausted`; an empty queue does NOT. That difference
        is the whole of S12 applied one level up: a crawl that visited
        everything is COMPLETE, and must not report a budget as its reason
        for stopping.
        """
        if self.visited >= self._budget.max_pages:
            self.exhausted = "max_pages"
            return None
        if self._requests >= self._budget.max_requests:
            self.exhausted = "max_requests"
            return None
        if self._clock() - self._started >= self._budget.max_seconds:
            self.exhausted = "max_seconds"
            return None
        if not self._queue:
            return None
        self.visited += 1
        return self._queue.popleft()

    def _enqueue(self, url: str) -> bool:
        n = normalise(url)
        if n is None:
            return False
        if origin_of(n) not in self._origins:
            return False
        if n in self._seen:
            return False
        self._seen.add(n)
        self._queue.append(n)
        return True
