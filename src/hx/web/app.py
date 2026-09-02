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
from urllib.parse import parse_qsl

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from hx import config as config_mod
from hx import halt as halt_mod
from hx import triage as triage_mod
from hx.store import db as db_mod
from hx.store.blobs import BlobStore
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

#: Methods that cannot change anything, and so need no cross-site guard.
#: HEAD and OPTIONS are here because a guard that broke them would break
#: ordinary browsers on a read-only app.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

#: The largest form body either write route will read. Both carry a status
#: word and a note; 64 KiB is generous for that and finite, which is the
#: property that matters -- `request.body()` reads the whole thing into
#: memory before anyone looks at it.
MAX_FORM = 64 * 1024


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


async def _form_fields(request):
    """The two write routes' form, or None if the request is not one.

    NOT `request.form()`. MEASURED against Starlette 1.6.0: that method
    asserts `python-multipart` is installed BEFORE it looks at the content
    type, so it raises even for a plain urlencoded body.

    Installing `python-multipart` is the easy fix and the wrong one. With it
    present, `request.form()` parses `multipart/form-data` -- file uploads
    included -- on two routes that want two short strings. This app accepts
    exactly ONE content type on a path that can change something, and
    `parse_qsl` is stdlib doing what it has done correctly for decades
    rather than a parser written here.

    None means "this was not a form this app accepts", and the caller
    answers 415. An empty dict is a different thing: a well-formed empty
    form, which `set_status` then refuses on its own terms.
    """
    ctype = request.headers.get("content-type", "")
    if ctype.split(";")[0].strip().lower() != "application/x-www-form-urlencoded":
        return None
    body = await request.body()
    if len(body) > MAX_FORM:
        return None
    return dict(parse_qsl(body.decode("utf-8", "replace"),
                          keep_blank_values=True))


def _same_origin(request) -> bool:
    """Whether a state-changing request came from this app's own pages.

    `Sec-Fetch-Site` FIRST and decisively: it is the browser's own account
    of where the request came from, and a page cannot forge it. When it is
    absent -- an older browser, or a client that is not a browser -- the
    fallback is an exact `Origin` match against THIS request's own origin.

    Exact, not "the origin's host is in ALLOWED_HOSTS": another web app on
    this machine is not this web app, and a host-level comparison would let
    anything on `localhost:9999` write into a client engagement.

    Neither header present is a REFUSAL. Fail closed: the operator has
    `hx triage` and `hx halt` for the no-browser case, and the cost of the
    strict answer is a curl command that needs one more flag, against a
    silent write from a page the operator merely visited.
    """
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site == "same-origin"
    origin = request.headers.get("origin")
    if not origin:
        return False
    return origin == f"{request.url.scheme}://{request.headers.get('host', '')}"


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
    if request.method not in SAFE_METHODS and not _same_origin(request):
        # REFUSED BEFORE THE HANDLER RUNS, which is the whole point: a guard
        # that rejects after writing is not a guard, and the tests assert
        # the finding's status is unchanged rather than only that a 403 came
        # back.
        return _secured(PlainTextResponse("cross-site write refused",
                                          status_code=403))
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
        try:
            # `_entry`'s own check catches the CHEAP fault -- missing or
            # unreadable -- for every engagement the index scans. Malformed
            # YAML is only discoverable by parsing, and this is the one
            # place that cost is paid for one engagement rather than all
            # of them. Either way the failure becomes a 404 raised INSIDE
            # this handler, not an uncaught exception: Starlette's
            # ServerErrorMiddleware sits outside `_guard`, so anything that
            # escapes this far would leave with no CSP, no `nosniff` and no
            # `Referrer-Policy` -- exactly the response a captured, hostile
            # body is rendered next to.
            config = config_mod.load(entry.path / "config.yaml")
        except (config_mod.ConfigError, OSError) as exc:
            raise HTTPException(status_code=404) from exc
        data = reads_mod.overview(conn, entry.engagement_id, config)
        # Through OperatorHalt rather than by testing for the file, so this
        # sees a halt recorded in the STORE as well as one on disk --
        # `halted` is a union, and the two disagree when a harness died
        # between the two writes. A read-only connection is enough: the
        # constructor and both properties only SELECT.
        halt_state = halt_mod.OperatorHalt(entry.path, conn)
        data["halted"] = halt_state.halted
        data["halt_reason"] = halt_state.reason
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "overview.html", {"entry": entry, "config": config, **data})


def surfaces(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        rows = reads_mod.surfaces(conn, entry.engagement_id)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "surfaces.html", {"entry": entry, "surfaces": rows})


def findings(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        rows = reads_mod.findings(
            conn, entry.engagement_id,
            severity=request.query_params.get("severity"),
            status=request.query_params.get("status"))
    except reads_mod.FilterError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "findings.html", {
            "entry": entry, "findings": rows,
            "severities": reads_mod.SEVERITIES,
            "statuses": reads_mod.STATUSES,
            "severity": request.query_params.get("severity"),
            "status": request.query_params.get("status"),
        })


def finding(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        detail = reads_mod.finding_detail(conn, request.path_params["fid"])
        if detail is None:
            raise HTTPException(status_code=404)
        context = {
            "entry": entry,
            "finding": detail,
            "evidence": reads_mod.evidence(conn, detail["id"]),
            "observations": reads_mod.observations(conn, detail["id"]),
            "history": triage_mod.history(conn, detail["id"]),
            "targets": triage_mod.TARGETS,
            "note_required": triage_mod.NOTE_REQUIRED,
        }
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "finding.html", context)


def exchange(request):
    entry = _entry(request)
    conn = registry_mod.open_read(entry)
    try:
        data = reads_mod.exchange(conn, BlobStore(entry.path / "blobs"),
                                  request.path_params["xid"])
        if data is None:
            raise HTTPException(status_code=404)
    finally:
        conn.close()
    return request.app.state.templates.TemplateResponse(
        request, "exchange.html", {"entry": entry, "exchange": data})


async def triage_post(request):
    entry = _entry(request)
    form = await _form_fields(request)
    if form is None:
        return PlainTextResponse(
            "this route accepts application/x-www-form-urlencoded only",
            status_code=415)
    finding_id = request.path_params["fid"]
    to_status = form.get("status", "")
    note = form.get("note")

    def write():
        conn = db_mod.connect(entry.path / "hx.db")
        try:
            return triage_mod.set_status(conn, finding_id=finding_id,
                                         to_status=to_status, note=note)
        finally:
            conn.close()

    try:
        await run_in_threadpool(write)
    except triage_mod.TriageError as exc:
        return PlainTextResponse(str(exc), status_code=400)
    # POST/redirect/GET: a reload must not re-submit a triage decision.
    return RedirectResponse(f"/e/{entry.name}/findings/{finding_id}",
                            status_code=303)


async def halt_post(request):
    entry = _entry(request)
    form = await _form_fields(request)
    if form is None:
        return PlainTextResponse(
            "this route accepts application/x-www-form-urlencoded only",
            status_code=415)
    reason = form.get("reason", "").strip() or "stopped from the web app"

    def write():
        conn = db_mod.connect(entry.path / "hx.db")
        try:
            halt_mod.OperatorHalt(entry.path, conn).halt(reason)
        finally:
            conn.close()

    await run_in_threadpool(write)
    return RedirectResponse(f"/e/{entry.name}", status_code=303)


def create_app(base) -> Starlette:
    app = Starlette(
        routes=[
            Route("/", index),
            Route("/e/{name}", overview),
            Route("/e/{name}/surfaces", surfaces),
            Route("/e/{name}/findings", findings),
            Route("/e/{name}/findings/{fid}", finding),
            Route("/e/{name}/exchanges/{xid}", exchange),
            Route("/e/{name}/findings/{fid}/status", triage_post,
                  methods=["POST"]),
            Route("/e/{name}/halt", halt_post, methods=["POST"]),
            Mount("/static",
                  StaticFiles(directory=str(render_mod.STATIC)),
                  name="static"),
        ],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=_guard)],
    )
    app.state.base = Path(base)
    app.state.templates = render_mod.templates()
    return app
