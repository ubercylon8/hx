"""The app: what it serves, and who it refuses to serve it to.

THIS APP SENDS NOTHING. No bridge client, no `Sender`, no socket to the
extension, no outbound HTTP of any kind. S4's invariant -- every byte
leaving this machine crosses one of two points inside the JVM -- is
untouched by everything here, and the security question is not what this
app enforces but what it can LEAK.

Reads open a fresh read-only connection per request and close it. Nothing is
cached between requests, so the app holds no shared mutable state: Starlette
runs `def` endpoints in a threadpool and `sqlite3` connections default to
`check_same_thread=True`, so a cached connection would raise
`ProgrammingError` the moment two requests landed on different threads.
"""
from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from hx import config as config_mod
from hx.web import reads as reads_mod
from hx.web import registry as registry_mod
from hx.web import render as render_mod

#: S11: "v1 binds 127.0.0.1 only". `hx web` has no --host option, so this
#: set is the whole of what an operator can reach the app at -- and, more to
#: the point, the whole of what a DNS-rebinding page cannot.
ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")

#: `script-src 'none'` is honest for Plan A: it ships no JavaScript at all.
#: Plan B widens it to 'self' in the commit that vendors htmx, where a
#: reviewer sees the widening rather than inheriting it.
CSP = ("default-src 'none'; script-src 'none'; style-src 'self'; "
       "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
       "base-uri 'none'")


def hostname(header: str) -> str:
    """The host half of a `Host` header, without its port.

    Bracketed IPv6 first, because `[::1]:8901` split on the first colon is
    `[`. Parsing is where a Host check goes wrong quietly, so it is a named
    function with its own test rather than an expression inside the guard.
    """
    value = header.strip()
    if value.startswith("["):
        end = value.find("]")
        return value if end == -1 else value[:end + 1]
    return value.partition(":")[0]


def _secured(response):
    """Every response this app emits, refusals included.

    ONE place, because refusal paths are the ones that get forgotten: they
    return EARLY, before whatever the success path does on its way out.
    MEASURED on 2026-09-01 -- an earlier draft set these three headers only
    after `call_next`, so the 421, which is the response a DNS-rebinding
    attack actually receives, went out with no CSP and no `nosniff` at all.
    The test asked `client.get("/")` and was perfectly happy.
    """
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


async def _guard(request, call_next):
    """The Host allowlist, and the headers every response carries.

    THE HOST CHECK IS THE DNS-REBINDING DEFENCE. Binding 127.0.0.1 stops
    remote packets; it does not stop a page the operator is browsing from
    issuing requests to 127.0.0.1:PORT, and a site that resolves its own
    name to 127.0.0.1 would otherwise have same-origin access to every
    engagement on this machine. S4 named the shape of this for the bridge --
    "a loopback port is reachable by any local process or browser tab" --
    and answered it by not being a port at all. A web app has no such
    option.

    421 rather than 403: Misdirected Request is exactly the case, a request
    for an authority this server does not answer for.
    """
    if hostname(request.headers.get("host", "")) not in ALLOWED_HOSTS:
        return _secured(PlainTextResponse("this host is not served here",
                                          status_code=421))
    return _secured(await call_next(request))


def _entry(request):
    """The engagement this request names, or a 404.

    THROUGH `registry.lookup`, which goes through `registry.scan`. A handler
    that built `base / name` itself would be a second definition of "an
    engagement this app answers about", and the second one is always the one
    without the allowlist.
    """
    entry = registry_mod.lookup(request.app.state.base,
                                request.path_params["name"])
    if entry is None or entry.problem is not None:
        raise HTTPException(status_code=404)
    return entry


def index(request):
    entries = registry_mod.scan(request.app.state.base)
    return request.app.state.templates.TemplateResponse(
        request, "engagements.html",
        {"entries": entries, "base": str(request.app.state.base)})


def overview(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        config = config_mod.load(entry.path / "config.yaml")
        data = reads_mod.overview(conn, entry.engagement_id, config)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "overview.html", {"entry": entry, "config": config, **data})


def create_app(base) -> Starlette:
    app = Starlette(
        routes=[
            Route("/", index),
            Route("/e/{name}", overview),
            Mount("/static",
                  StaticFiles(directory=str(render_mod.STATIC)),
                  name="static"),
        ],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=_guard)],
    )
    app.state.base = Path(base)
    app.state.templates = render_mod.templates()
    return app
