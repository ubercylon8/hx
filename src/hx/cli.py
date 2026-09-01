"""Command line entry points.

Creating an engagement and inspecting one are human acts, so they live here
rather than in the agent-facing tool layer.
"""
from __future__ import annotations

import contextlib
import dataclasses
import os
import re
import signal
import sqlite3
import time
import uuid
from pathlib import Path

import click

from hx import config as config_mod
from hx import engagement as eng_mod
from hx import halt as halt_mod
from hx import identity as identity_mod
from hx import report as report_mod
from hx import run as run_mod
from hx import scan as scan_mod
from hx import session as session_mod
from hx.bridge import codec as codec_mod
from hx.bridge import server as bridge_mod
from hx.checks import registry
from hx.store import db as db_mod
from hx.store.paths import secure_mkdir

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def default_root() -> Path:
    env = os.environ.get("HX_HOME")
    if env:
        return Path(env)
    return Path.home() / "hx" / "engagements"


def _open_engagement(path: Path) -> eng_mod.Engagement:
    """`eng_mod.open_`, with every failure turned into a `ClickException`
    instead of a traceback. Shared by `info` and both `capture` subcommands,
    which all open an existing engagement the same way `info` always has.
    """
    try:
        return eng_mod.open_(path)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    except config_mod.ConfigError as exc:
        raise click.ClickException(f"invalid config at {path}: {exc}") from exc
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot read the database at {path}: {exc}") from exc
    except OSError as exc:
        raise click.ClickException(f"cannot access the engagement at {path}: {exc}") from exc


@click.group()
def main() -> None:
    """hx — agent-driven web application security assessment."""


@main.command()
@click.argument("name")
@click.option("--client", required=True, help="Client name, as it appears in the report.")
@click.option(
    "--scope",
    "scope",
    multiple=True,
    required=True,
    help="In-scope URL pattern. Repeatable. At least one is required.",
)
@click.option("--exclude", multiple=True, help="Excluded URL pattern. Repeatable.")
@click.option(
    "--profile",
    type=click.Choice(config_mod.VALID_PROFILES),
    default="production",
    show_default=True,
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--author", default=lambda: os.environ.get("USER", "unknown"))
def new(name, client, scope, exclude, profile, root, author) -> None:
    """Create a new engagement."""
    for field, value in (("NAME", name), ("--client", client)):
        if not value.strip():
            raise click.ClickException(f"{field} must not be empty")
    # The same refusal one field along, and it has to be HERE rather than only
    # in config.load(): this command builds a Config directly and dumps() it,
    # so the load-time guard does not run until the engagement already exists.
    # `hx new --exclude ""` wrote `exclude: ['']` to config.yaml and to the
    # scope_version row, and the operator found out on the next open. The
    # extension still fails closed on an empty pattern -- it is not a bypass --
    # but the guard exists so that the operator learns at `hx new`.
    for option, values in (("scope.include", scope), ("scope.exclude", exclude)):
        try:
            config_mod.check_entries(option, list(values))
        except config_mod.ConfigError as exc:
            raise click.ClickException(str(exc)) from exc
    # NAME becomes a path segment under the engagements root (`base / name`).
    # Without this check, "." makes the engagements root ITSELF an
    # engagement (so `rm -rf` of it destroys every client), ".." or
    # "../escaped" walk outside the root, and an absolute NAME like
    # "/tmp/anywhere" makes pathlib's `/` operator discard `base` entirely
    # -- `--root` silently ignored. User-controlled NAME also reaches
    # `shutil.rmtree` on create()'s failure path, so this has to hold before
    # any directory is touched.
    if not _NAME_RE.fullmatch(name) or name in (".", ".."):
        raise click.ClickException(
            "NAME must be 1-64 characters of letters, digits, dot, underscore "
            "or hyphen, and must start with a letter or digit"
        )
    base = root or default_root()
    cfg = config_mod.Config(
        name=name,
        client=client,
        safety_profile=profile,
        scope_include=list(scope),
        scope_exclude=list(exclude),
    )
    try:
        eng = eng_mod.create(base / name, cfg, author=author)
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    except config_mod.ConfigError as exc:
        raise click.ClickException(f"invalid config for {base / name}: {exc}") from exc
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot create the database at {base / name}: {exc}") from exc
    except OSError as exc:
        raise click.ClickException(f"cannot create the engagement at {base / name}: {exc}") from exc

    click.echo(f"created engagement {name} ({eng.id})")
    click.echo(f"  root    {eng.root}")
    click.echo(f"  profile {cfg.safety_profile}")
    click.echo(f"  scope   {', '.join(cfg.scope_include)}")


def _group_counts(conn, table: str, column: str) -> str:
    """`SELECT column, COUNT(*) FROM table GROUP BY column`, rendered as
    `value=n  value=n`. The database holds exactly one engagement (I5), so
    no WHERE clause is needed -- the same assumption `info`'s row counts
    below have always made."""
    rows = conn.execute(
        f"SELECT {column} AS k, COUNT(*) AS n FROM {table} GROUP BY {column}"
    ).fetchall()
    return "  ".join(f"{r['k']}={r['n']}" for r in rows) or "none"


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def info(root) -> None:
    """Show an engagement's configuration and current counts."""
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        # First, so a run whose harness died reads `error` rather than a
        # `running` that has not been true for a while -- otherwise the
        # first thing an operator sees after a crash is a run that claims
        # to still be live.
        run_mod.reap_stale(eng.db)

        counts = {
            t: eng.db.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
            for t in ("run", "surface", "exchange", "finding", "check_run")
        }
        runs_by_status = _group_counts(eng.db, "run", "status")
        surfaces_by_kind = _group_counts(eng.db, "surface", "kind")
        exchanges_by_outcome = _group_counts(eng.db, "exchange", "outcome")
        denials_by_kind = _group_counts(eng.db, "denial", "kind")
        dropped_total = eng.db.execute(
            "SELECT COALESCE(SUM(dropped_total), 0) AS n FROM run"
        ).fetchone()["n"]
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot read the database at {path}: {exc}") from exc

    click.echo(f"engagement {eng.config.name} ({eng.id})")
    click.echo(f"  client   {eng.config.client}")
    click.echo(f"  profile  {eng.config.safety_profile}")
    click.echo(f"  scope    {', '.join(eng.config.scope_include)}")
    if eng.config.scope_exclude:
        click.echo(f"  exclude  {', '.join(eng.config.scope_exclude)}")
    click.echo(f"  root     {eng.root}")
    click.echo("  counts   " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    click.echo(f"  runs      {runs_by_status}")
    click.echo(f"  surfaces  {surfaces_by_kind}")
    click.echo(f"  exchanges {exchanges_by_outcome}")
    click.echo(f"  denials   {denials_by_kind}")
    # THE HALT, and only when there is one -- the same rule the drop warning
    # below follows, so a line that appears means something. S4 makes the
    # sentinel a path an operator can take from a shell with no harness
    # running, which means an operator can also arrive at a halted engagement
    # they did not halt themselves. `info` is where they look first, and until
    # this line nothing in the CLI could tell them issuance was stopped.
    #
    # Read through OperatorHalt rather than by testing for the file, so this
    # sees a halt recorded in the store as well as one on disk -- `halted` is
    # a union, and the two can disagree when a harness died between the two
    # writes.
    halt_state = _operator_halt(eng)
    if halt_state.halted:
        click.echo(f"  HALTED    {halt_state.reason}")
        click.echo(f"            issuance is stopped; `hx resume` lifts it "
                   f"and records who did ({halt_state.sentinel_path})")
    # S5: a run with drops has coverage numbers that are a FLOOR, not a
    # complete count -- only said out loud when it is true, so it stays
    # meaningful when it fires.
    if dropped_total > 0:
        click.echo(
            f"  WARNING   {dropped_total} dropped: the surface and exchange "
            "counts above are a FLOOR, not the whole picture -- the "
            "extension could not hand over every exchange."
        )


@main.group()
def capture() -> None:
    """Start or stop traffic capture for an engagement."""


# How often `capture start` asks whether the session it is holding open is
# still a session. A second is far below anything a human notices and far
# above anything the check costs: `Popen.poll()` is a non-blocking waitpid and
# the bridge state is an attribute read.
_HEALTH_POLL_S = 1.0


def _block_until_interrupt(live) -> str | None:
    """Hold the session open until the operator interrupts -- or Burp dies.

    Returns None when the wait ended the way it usually does (Ctrl-C, which
    arrives as a KeyboardInterrupt out of `time.sleep`), or the reason the
    session stopped being one.

    NOT `signal.pause()` ANY MORE, and that is S8's "Burp dies mid-session"
    path. Paused, a command whose Burp had died blocked forever: the browser
    got connection-refused, nothing was printed, and the run row stayed
    `status='running'` until the operator gave up and pressed Ctrl-C, which
    then closed the run as though they had ended it on purpose. Nothing polled
    `proc.poll()` or re-read the bridge state, so the only witness was the
    consultant noticing their proxy had stopped answering.

    Separate so a test can drive the command without a real signal.
    """
    while True:
        why = live.gone()
        if why is not None:
            return why
        time.sleep(_HEALTH_POLL_S)


@contextlib.contextmanager
def _sigterm_ends_the_session():
    """SIGTERM tears Burp down instead of orphaning it.

    S7: "A Burp process is never orphaned." `capture_start` covered Ctrl-C and
    exceptions, and SIGTERM -- a `kill`, a terminal closing, a service manager
    stopping the unit -- killed the command where it stood, leaving a 900 MB
    JVM and a bridge socket behind. The next run then got the (good) stale
    socket refusal naming the path to remove.

    Raised as KeyboardInterrupt deliberately: a SIGTERM is somebody stopping
    this command, which is what Ctrl-C is, and giving the two paths one
    meaning keeps one teardown and one `stop_reason` rather than two that have
    to agree. The previous handler is restored on the way out, and a
    non-main-thread caller (where `signal.signal` raises) simply does not get
    the handler -- an inability to install one must not stop the session.
    """
    def handler(signum, frame):
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@capture.command("start")
@click.option(
    "--kind",
    type=click.Choice(sorted(run_mod.RUN_KINDS)),
    default="browse",
    show_default=True,
    help="Run kind. The vocabulary is derived from the schema, not restated.",
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option(
    "--burp-jar",
    type=click.Path(path_type=Path),
    default=None,
    help="Which Burp jar to launch against. Default: $HX_BURP_JAR, then the "
         "one jar found in $HX_BURP_LAB -- two jars there is an error, never "
         "a guess, because the report records the version under test.",
)
@click.option(
    "--max-requests",
    type=click.IntRange(min=1),
    default=None,
    help="Per-run request budget, authorised on the extension's first "
         "configure. Default: the engagement's own config.yaml (2000 if "
         "unset) -- this flag overrides that number for this run only, it "
         "does not rewrite config.yaml.",
)
def capture_start(kind, root, burp_jar, max_requests) -> None:
    """Launch Burp, open the live run of KIND, and hold the session open
    until interrupted.

    THE SESSION OPENS BEFORE THE RUN. A run row opened in front of a
    session that then fails to start is a run that never captured
    anything, and `hx report` would go on to render it as a real one.

    This is `run.current_run`, not `run.open_run`: typing `start` twice
    resumes the one live run of that kind rather than opening a second one.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    if max_requests is not None:
        # A per-invocation OVERRIDE, not a rewrite: `eng.config` is replaced
        # in memory so `session.config_body` picks it up, and `config.yaml`
        # on disk is untouched -- the flag says what THIS run authorises,
        # the file stays the record of what the operator wrote down.
        eng.config = dataclasses.replace(eng.config, max_requests=max_requests)
    try:
        with _sigterm_ends_the_session(), \
                session_mod.session(eng, instance="capture", jar=burp_jar) as live:
            click.echo(f"operator proxy listening on 127.0.0.1:{live.operator_port}")
            try:
                run_id = run_mod.current_run(
                    eng.db, engagement_id=eng.id, kind=kind,
                    safety_profile=eng.config.safety_profile)
            except sqlite3.Error as exc:
                raise click.ClickException(
                    f"cannot write to the database at {path}: {exc}") from exc
            died = None
            try:
                # The echo lives IN the try, not between it and current_run's:
                # `hx capture start | head` closes the pipe once `head` has
                # what it wants, Python does not restore SIGPIPE, and this
                # echo is the first write after the run opens -- outside the
                # try that BrokenPipeError would escape past the finally
                # below, leaving the run open and never closed.
                click.echo(f"{kind} run {run_id} is live")
                died = _block_until_interrupt(live)
            finally:
                # Runs even when the block above ends in a KeyboardInterrupt
                # or a BrokenPipeError: a run left `status='running'` after
                # the operator's Burp is gone would read as a live capture
                # forever.
                #
                # A DEAD BURP IS NOT A COMPLETED RUN. `run.py`'s own rule --
                # "a run whose harness DIED resolves to `error`, never to
                # `completed`, because a report generated from a session that
                # stopped halfway and claims to be complete is the worst
                # output this project could produce" -- and the reason
                # `stop_reason` carries the message rather than the word
                # "operator": S5 renders it, and an operator reading the
                # report should find out there that Burp went away.
                try:
                    run_mod.close_run(
                        eng.db, run_id=run_id,
                        status="error" if died else "completed",
                        stop_reason=died or "operator")
                except sqlite3.Error as exc:
                    raise click.ClickException(
                        f"cannot write to the database at {path}: {exc}") from exc
            if died:
                # Raised INSIDE the `with`, so `session()`'s teardown still
                # runs: a Burp that died is a Burp whose bridge socket and
                # accept thread are still this process's to clean up. S8 asks
                # for a distinct message and a non-zero exit; ClickException
                # is both, and it is not a SessionError, so the handler below
                # does not re-wrap it.
                raise click.ClickException(died)
    except session_mod.SessionError as exc:
        raise click.ClickException(str(exc)) from exc


@capture.command("stop")
@click.option(
    "--kind",
    type=click.Choice(sorted(run_mod.RUN_KINDS)),
    default=None,
    help="Close only runs of this kind. Default: every live run.",
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
def capture_stop(kind, root) -> None:
    """Close every live run of the engagement (`--kind` narrows it to one).

    An operator typing `stop` means every kind currently recording, because
    a crawl can run while a human browses and those are two runs -- "stop
    capturing" means both. Closed with status='completed',
    stop_reason='operator': an operator ending a run on purpose is neither
    an `error` nor `aborted`, which mean the harness or the auto-halt ended
    it instead.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        query = "SELECT id FROM run WHERE status='running'"
        params: list[str] = []
        if kind is not None:
            query += " AND kind=?"
            params.append(kind)
        rows = eng.db.execute(query, params).fetchall()
        if not rows:
            suffix = f" of kind {kind}" if kind else ""
            click.echo(f"no live runs{suffix} to stop")
            return
        with db_mod.transaction(eng.db):
            for row in rows:
                run_mod.close_run(eng.db, run_id=row["id"], status="completed",
                                  stop_reason="operator")
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot write to the database at {path}: {exc}") from exc
    click.echo(f"stopped {len(rows)} run(s)")


def _operator_halt(eng: eng_mod.Engagement) -> halt_mod.OperatorHalt:
    """The SAME `OperatorHalt` the extension polls, built the same way.

    S4 gives the kill switch three independent paths and the whole argument is
    "any one works when the others are wedged". Two of the three were
    unreachable by a human before these commands existed: `BridgeServer.halt()`
    and `resume()` are correct and durable and had no CLI and no production
    driver, and the STOP button in the Burp suite tab is unbuilt and stated as
    such. So of the three, only "create the sentinel file from a shell" was
    something an operator could actually do -- and the path §4 argues for is
    the redundancy, not any one of them.

    NOT A SECOND PATH. An operator halt is durable, and durable means the row
    AND the file: `OperatorHalt.halt` writes the sentinel FIRST so a failure to
    explain cannot become a failure to stop, and `resume` writes the row first
    so a failure to record cannot lift a halt silently. A CLI that touched the
    file itself would have neither ordering and no audit trail. The path is
    `<engagement>/HALTED`, which is what `burp_fixture.launch_burp` passes as
    `-Dhx.halt_sentinel` -- so the file this writes is the file the extension
    polls, and there is no third spelling of it anywhere.

    NO FRAME IS SENT, and that is not an omission. The bridge lives in the
    harness process, not this one; the sentinel is the path that works when
    the bridge does not, and the extension polls it directly. A harness that
    IS running re-reads the same file: `OperatorHalt.halted` is a union of the
    armed flag and a stat(), so a halt written from another process is seen by
    `BridgeServer.send` on its next call and re-asserted after any hello.
    """
    try:
        return halt_mod.OperatorHalt(eng.root, eng.db)
    except halt_mod.HaltError as exc:
        raise click.ClickException(str(exc)) from exc
    except sqlite3.Error as exc:
        raise click.ClickException(
            f"cannot read the halt state at {eng.root}: {exc}") from exc


@main.command()
@click.option("--reason", default=None,
              help="Why issuance is being stopped. Recorded in the audit trail "
                   "and written into the sentinel file for whoever finds it.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
def halt(reason, root) -> None:
    """Stop issuance for an engagement, durably.

    `--reason` is OPTIONAL on purpose. This is a kill switch, and the moment
    it is used is the moment something is going wrong on a client's
    production system; a required argument is friction in front of a stop.
    The default says who stopped it and how, which is the part a later reader
    cannot reconstruct.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    oh = _operator_halt(eng)
    was = oh.reason if oh.halted else None
    text = reason or f"halted from the command line by {os.environ.get('USER', 'unknown')}"
    try:
        oh.halt(text)
    except (sqlite3.Error, OSError) as exc:
        # The sentinel is written before the row, so a failure here may mean
        # the halt IS in force and only its audit line is missing. Say which
        # rather than leaving the operator to guess, because the guess that
        # matters is "did it stop".
        raise click.ClickException(
            f"halt failed after {'writing' if oh.sentinel_path.exists() else 'failing to write'} "
            f"{oh.sentinel_path}: {exc}") from exc
    if was is not None:
        click.echo(f"already halted: {was}")
    click.echo(f"issuance halted: {text}")
    click.echo(f"  sentinel {oh.sentinel_path}")
    click.echo("  the extension polls that file and refuses every send while "
               "it exists; `hx resume` is how to lift it -- deleting the file "
               "by hand also lifts it for the extension, and records nothing")


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def resume(root) -> None:
    """Re-arm issuance, and record that it was re-armed.

    A `configure` re-authorises SCOPE and never issuance, and a reconnect
    re-asserts the halt rather than clearing it -- so nothing in the bridge
    lifts a halt by accident, which is what makes refusing to run this on an
    un-halted engagement safe rather than pedantic.

    IT IS NOT THE ONLY WAY BACK, and an earlier version of this docstring said
    it was. `rm <engagement>/HALTED` also lifts the halt AS FAR AS THE
    EXTENSION IS CONCERNED -- the extension polls the file and nothing else,
    which is precisely what S4 asks of it ("an operator can create it from a
    shell when the socket is dead"), and a mechanism that can be created by
    hand can be removed by hand. What that loses is the record: no
    `agent_action` row says who lifted it, and a harness process that had
    already read `_armed` from the store goes on refusing sends of its own
    while the extension issues. This command is the one that leaves both
    sides agreeing and leaves a row behind.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    oh = _operator_halt(eng)
    if not oh.halted:
        # Nothing is written. `resume()` would append a resume row for a stop
        # that never happened, and an audit trail whose entries do not
        # correspond to events is worse than a short one.
        click.echo("not halted; nothing to resume")
        return
    was = oh.reason
    try:
        oh.resume()
    except (sqlite3.Error, OSError) as exc:
        # The row goes first, so a failure here leaves the sentinel in place
        # and the halt STANDING -- which is the direction S4 asks for, and is
        # worth saying out loud rather than reporting a bare error.
        raise click.ClickException(
            f"resume failed and the halt still stands ({oh.sentinel_path}): {exc}"
        ) from exc
    click.echo(f"issuance resumed; the halt was: {was}")


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--max-seconds", type=int, default=None,
              help="Stop after this long. Remaining checks are recorded as "
                   "skipped, never left absent.")
@click.option(
    "--max-requests",
    type=click.IntRange(min=1),
    default=None,
    help="Per-run request budget an active check's session is authorised "
         "against. Default: the engagement's own config.yaml (2000 if "
         "unset) -- this flag overrides that number for this run only, it "
         "does not rewrite config.yaml.",
)
# F6 of the whole-branch review. THE SAME OPTION `capture start` HAS, spelt
# the same way and with the same help text, because it answers the same
# question about the same launch. `hx scan` opens a Burp on every default
# run now (`active_safe` is on in `DEFAULT_CHECKS` and five active checks
# ship), and without this an operator with two jars in `$HX_BURP_LAB` and no
# `$HX_BURP_JAR` could not scan at all: `find_burp_jar` refuses to guess,
# deliberately -- the report records the version under test -- and this was
# the only command with no way to answer it.
@click.option(
    "--burp-jar",
    type=click.Path(path_type=Path),
    default=None,
    help="Which Burp jar to launch against. Default: $HX_BURP_JAR, then the "
         "one jar found in $HX_BURP_LAB -- two jars there is an error, never "
         "a guess, because the report records the version under test.",
)
def scan(root, max_seconds, max_requests, burp_jar) -> None:
    """Run the enabled check corpus over everything captured so far."""
    path = root or default_root()
    eng = _open_engagement(path)
    if max_requests is not None:
        # Same override as `capture start`'s -- see its comment. `scan.run`
        # takes `eng.config` as-is, and the active-check session opened
        # below hands the same object to `session.config_body`, so this
        # single replacement is what authorises the extension for THIS
        # invocation. It must stay ahead of both.
        eng.config = dataclasses.replace(eng.config, max_requests=max_requests)
    try:
        surfaces = eng.db.execute(
            "SELECT COUNT(*) FROM surface WHERE engagement_id=?",
            (eng.id,)).fetchone()[0]
        if surfaces == 0:
            # NOT an error, and not silence either. Nothing captured is a
            # different fact from nothing found, and an operator who forgot
            # to browse must not read `0 findings` as a clean bill.
            click.echo("no surfaces captured yet -- browse the target "
                       "through the proxy first, then scan")
            return

        # THE SESSION IS OPENED HERE, AND ONLY WHEN SOMETHING WILL SEND.
        # `scan.run` takes a bridge and never builds one: it has no
        # engagement root, no jar and no business owning a JVM whose
        # lifetime is a local variable's. This command has all three.
        #
        # ONLY WHEN SOMETHING WILL SEND, because a passive scan that paid
        # Burp's ~10 s startup to send nothing would be a cost with no answer
        # attached. THE COMMON `hx scan` IS NOT THAT SCAN ANY MORE, and the
        # sentence here used to say it was: "the corpus this build ships is
        # still all passive, so the common `hx scan` stays entirely offline"
        # survived Tasks 7 through 13 and both of Task 13's fix rounds, by
        # which time five `active_safe` checks were registered and
        # `config.DEFAULT_CHECKS` had `active_safe: True`. A default-
        # configured engagement opens a Burp on every scan; what stays
        # offline is a scan of an engagement whose config has switched the
        # active classes off, which is now the exception rather than the
        # rule. The guard below is unchanged -- it was always the right
        # guard, and only its justification was stale.
        #
        # TWO FILTERS, TWO DIFFERENT QUESTIONS, AND NEITHER IS RESTATED HERE.
        # `registry.enabled` is the one place "switched on for this
        # engagement" is decided, which also settles a class enabled with no
        # checks in it (the shipped `active_timing`) -- `enabled` returns
        # nothing for it, so it starts no Burp. `scan.needs_a_bridge` is the
        # one place "will the runner send for this check" is decided, and it
        # answers by asking which hook the runner would dispatch to.
        #
        # This second one was `c.klass != "passive"` until fix round 1 (LOW):
        # a class-string restatement of a rule the registry owns, of exactly
        # the kind `scan._runner_hook` refuses to make. A future non-passive
        # class whose `_HOOKS` entry never gets `probes` would have launched
        # a JVM here while `scan.run` called `on_surface` and sent nothing,
        # with no test anywhere pinning the disagreement.
        sending = tuple(c for c in registry.enabled(eng.config)
                        if scan_mod.needs_a_bridge(c))
        try:
            if sending:
                with session_mod.session(eng, instance="scan",
                                          jar=burp_jar) as live:
                    summary = scan_mod.run(
                        eng.db, engagement_id=eng.id, blobs=eng.blobs,
                        config=eng.config, max_seconds=max_seconds,
                        bridge=live.bridge)
            else:
                summary = scan_mod.run(
                    eng.db, engagement_id=eng.id, blobs=eng.blobs,
                    config=eng.config, max_seconds=max_seconds)
        except session_mod.SessionError as exc:
            # The message intact, as `capture start` does: every one of
            # them already names the fix (a stale socket to remove, an
            # unbuilt extension jar, a listener that came up off loopback),
            # and re-wording it here would put this command between the
            # operator and the sentence that tells them what to do.
            raise click.ClickException(str(exc)) from exc
        except scan_mod.IdentityDead as exc:
            # A DEAD SESSION IS A RESULT, NOT A CRASH -- and until Task 8 it
            # was a traceback. `scan.run` halts rather than scanning
            # anonymously (spec s7's instruction, and the identity design's
            # s6 gives the reason: a dead session produces a run of "not
            # vulnerable" answers that look exactly like a clean
            # application), and nothing here caught it, so the one outcome
            # this whole plan exists to make visible arrived at an operator
            # as a stack trace with the sentence at the bottom.
            #
            # THE MESSAGE INTACT, for the reason above it: it names which of
            # section 6's four outcomes happened (`_IdentityBracket._outcome`
            # -- `fails, static` and `fails after refresh` send an operator
            # to different places), whether the canary was REFUSED or
            # answered without the declared signature (`_unproved` -- a
            # refused canary means no credential they can mint will help),
            # and why halting was the right answer.
            #
            # NON-ZERO EXIT, like every other `ClickException`, and that is
            # the point rather than an accident: the run did not complete,
            # its `run` row reads `error`, and a shell that treated this as
            # success would let a scheduled scan report clean coverage for
            # an application it stopped testing at the first surface. The
            # run's own tallies are in that row's `stop_reason`
            # (`scan._halt_reason`) and reach a reader through `hx report`,
            # not through this line.
            raise click.ClickException(str(exc)) from exc
        except identity_mod.IdentityError as exc:
            # THE FAR COMMONER MISTAKE, ONE EXCEPTION CLASS OVER FROM
            # `IdentityDead` ABOVE. `_resolve_scan_identity` (`scan.py:986`)
            # reads a static identity's credential out of `os.environ` and
            # RAISES `IdentityError` when the declared variable was simply
            # never exported -- no session was ever opened, no canary was
            # ever sent, so `IdentityDead` (which is a session that WAS
            # proved and then died, or never provably lived) is the wrong
            # class for it and always was. Forgetting an `export` on a
            # terminal an operator just opened is ordinary; nothing here
            # caught it, so it reached them as a traceback with the message
            # `identity.resolve` already wrote for them at the bottom of it
            # -- the same defect commit a88388d fixed for the rarer case,
            # one exception class over.
            #
            # THE MESSAGE INTACT, for the same reason as above: `resolve`
            # already names the variable that is missing and refuses to
            # issue anonymously rather than silently testing the logged-out
            # view of an authenticated application, and re-wording it here
            # would put this command between the operator and the sentence
            # that tells them what to do. No credential value is in it --
            # `resolve` raises before it has one to leak.
            #
            # NON-ZERO EXIT, like every other `ClickException`: the run's
            # own row still closes `error` (`scan.run`'s `except
            # BaseException`, unconditionally), so nothing here masks a
            # scan that sent no probe or canary as one that succeeded.
            raise click.ClickException(str(exc)) from exc
        except (bridge_mod.BridgeError, codec_mod.FrameError) as exc:
            # THE TWO `register_identity` FLAGS FOR ITS CALLER, AND NEITHER
            # HAD ONE. F5 of the whole-branch review. That method's docstring
            # says in as many words that the caller "has two exception types
            # to handle, not one", `_IdentityBracket.start` deliberately
            # wraps neither -- correctly, since each says what actually
            # happened -- and this command caught neither. So a credential
            # with an internal newline or a smart quote pasted out of a file
            # reached the operator as a traceback, with the sentence
            # `codec._refuse_unwritable` had already written for them at the
            # bottom of it. The same defect commit a88388d fixed for
            # `IdentityDead` and 20b0a64 for `IdentityError`, two doors over.
            #
            # BOTH ARMS, ONE HANDLER, because from the operator's side they
            # are one outcome: the identity could not be registered, so no
            # probe was issued under it and the run stopped. The message is
            # what tells them which -- `FrameError` names the character class
            # and why such a value is refused rather than escaped, and
            # `BridgeError` names the peer's own refusal class.
            #
            # THE MESSAGE INTACT, and it holds no credential: every branch of
            # `_refuse_unwritable` refuses to quote the character or the text
            # it came from (spec section 5 -- the credential is logged on
            # neither side, and a caught `FrameError`'s message is logged by
            # whatever catches it), and `register_identity`'s `BridgeError`
            # quotes the peer's `class` and `detail`, which the extension
            # builds from the identity id and the host and never from the
            # value. A traceback would have leaked nothing either -- Python
            # prints source lines, not values -- so this is about the
            # operator's experience of an ordinary mistake, not about a leak.
            #
            # NOT NARROWER THAN `BridgeError`, deliberately. Every other
            # bridge failure a scan can suffer is already translated before
            # it gets here: `ProbeSender` turns one into a `ProbeRefused`
            # (`probe.py`'s `except BridgeError`), which the runner records
            # as an `inconclusive` row. What is left to arrive raw is the
            # identity registration, which is the one this handler is for.
            raise click.ClickException(str(exc)) from exc
        click.echo(f"surfaces  {summary.surfaces}")
        click.echo(f"checks    {summary.checks_run}")
        click.echo(f"findings  {summary.findings}")
        if summary.skipped:
            for reason, n in sorted(summary.by_reason.items()):
                click.echo(f"skipped   {n} ({reason})")
        # A DIFFERENT LINE FROM `skipped`, and F11's reason for existing: a
        # skipped row is one the runner never ran, a refused probe is one it
        # ran and the extension or the bridge said no to. `budget_exhausted`
        # here is the operator's warning that everything after some point in
        # the corpus was reported `inconclusive` -- the same sentence the
        # run row's `stop_reason` now carries.
        for reason, n in sorted(summary.refused.items()):
            click.echo(f"refused   {n} ({reason})")
        # THE CANARIES ARE HX'S OWN TRAFFIC AND AN OPERATOR IS TOLD ABOUT
        # THEM -- F5 of the task-7 fix round A review. Section 6 says the
        # canary "is counted in `requests_sent` for the run, because it is a
        # request `hx` put on the client's system", and
        # `ScanSummary.canary_requests` counted it faithfully and was READ BY
        # NOTHING: `check_run.requests_sent` excludes it (no check asked for
        # it, so no row owns it), the `run` table has no request column, and
        # `report._limits` renders no request tally at all. A number that
        # satisfies a spec sentence and reaches nobody satisfies nothing.
        #
        # THIS IS NOT THE WHOLE OF WHAT SECTION 6 ASKS and the difference is
        # worth naming rather than papering over: the section says
        # `requests_sent` FOR THE RUN, and this build has no such column to
        # add it to. What it can have today is the operator being told, at
        # the same terminal that already gets `skipped` and `refused`, that
        # a run put N requests of its own on a client's system. The client's
        # own copy of that fact belongs in section 10's identity section,
        # which the plan gives to Task 8, derived from the run.
        #
        # ONLY WHEN THERE WERE ANY. An anonymous run sends no canary, and
        # `canaries  0` on every scan is a line an operator learns to skip.
        if summary.canary_requests:
            click.echo(f"canaries  {summary.canary_requests}")

        # A class the operator enabled that this build ships nothing for.
        # Without this line, `active_timing: true` plus no rows reads as
        # "ran, found nothing".
        for klass, on in sorted(eng.config.checks.items()):
            if on and not any(c.klass == klass for c in registry.CHECKS):
                click.echo(f"note      {klass} is enabled but this build "
                           f"ships no checks in it")
    finally:
        eng.db.close()


def _write_export_secure(path: Path, text: str) -> None:
    """Atomically write the report at 0o600, never briefly looser.

    Fix round 1, F2: `target.parent.mkdir(parents=True, exist_ok=True)`
    followed by `write_text` then `chmod` created directories at the ambient
    umask (`755` under `umask 022`, measured, including directories nested
    inside the engagement root when `--out` named one) and left the file
    itself at `0o644` for the window between the write and the chmod, on
    every invocation. §3 is unconditional -- "engagement directories `0o700`,
    files `0o600`, never looser" -- and a client report earns no less care
    than `config.yaml` or the halt sentinel.

    Same shape as `engagement._write_config_secure` and
    `halt.OperatorHalt._write_sentinel`, for the same reasons: `O_EXCL` at
    the final mode so the file never exists world-readable even for an
    instant, and a rename so a reader never sees a partial write. Not a
    shared import of either -- this codebase's own precedent
    (`halt._write_sentinel`'s docstring: "Same shape as
    `engagement._write_config_secure`, for the same reasons") is to
    duplicate this exact shape per module with a cross-reference, not to
    import a leading-underscore name across module boundaries.
    """
    path = Path(path)
    tmp = path.parent / f".{uuid.uuid4().hex}.{path.name}"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        fh = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise
    try:
        with fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--out", type=click.Path(path_type=Path), default=None,
              help="Where to write it. Defaults to <engagement>/exports/.")
def report(root, out) -> None:
    """Render the engagement as one Markdown file."""
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        text = report_mod.render(eng.db, engagement_id=eng.id,
                                 config=eng.config, blobs=eng.blobs)
        target = out or (eng.root / "exports" / f"{eng.config.name}.md")
        secure_mkdir(target.parent)   # S3: 0o700, never looser, no window
        _write_export_secure(target, text)   # S3: 0o600, never looser
        click.echo(f"wrote {target}")
    finally:
        eng.db.close()


@main.command("tool")
@click.argument("name", required=False)
@click.option("--json", "args_json", default=None,
              help="Arguments as a JSON object.")
@click.option("--why", default=None,
              help="Why you are doing this. Required by state-changing tools; "
                   "written to agent_action.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--list", "list_only", is_flag=True,
              help="List every tool and exit.")
def tool(name, args_json, why, root, list_only) -> None:
    """Call one agent tool and print its envelope as JSON."""
    from hx.tools.adapters import cli as tool_cli

    if list_only or not name:
        click.echo(tool_cli.render_listing())
        return
    eng = _open_engagement(root or default_root())
    text, status = tool_cli.run_tool(eng, name, args_json, why)
    click.echo(text)
    if status:
        raise SystemExit(status)


@main.command("mcp")
@click.option("--root", type=click.Path(path_type=Path), default=None)
def mcp(root) -> None:
    """Serve the tool layer over MCP on stdio.

    THE ADAPTER THAT CAN HOLD A BURP. `hx tool` is one process per call and
    `hx.session.session()` tears Burp down on every exit, so egress tools
    there answer `no_host`. This command is one process for the whole
    conversation: `run.start` brings a session up and `run.finish` -- or any
    exit from this command -- takes it down.

    NOTHING BUT JSON-RPC MAY REACH STDOUT while this runs.
    """
    from hx.tools.adapters import mcp as mcp_adapter

    eng = _open_engagement(root or default_root())
    mcp_adapter.serve(eng)
