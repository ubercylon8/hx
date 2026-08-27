"""Command line entry points.

Creating an engagement and inspecting one are human acts, so they live here
rather than in the agent-facing tool layer.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

import click

from hx import config as config_mod
from hx import engagement as eng_mod
from hx import halt as halt_mod
from hx import run as run_mod
from hx.store import db as db_mod

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
        click.echo(f"            issuance is stopped; `hx resume` is what "
                   f"lifts it ({halt_state.sentinel_path})")
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


@capture.command("start")
@click.option(
    "--kind",
    type=click.Choice(sorted(run_mod.RUN_KINDS)),
    default="browse",
    show_default=True,
    help="Run kind. The vocabulary is derived from the schema, not restated.",
)
@click.option("--root", type=click.Path(path_type=Path), default=None)
def capture_start(kind, root) -> None:
    """Open the live run of KIND, the deliberately-named path.

    This is `run.current_run`, not `run.open_run`: typing `start` twice
    resumes the one live run of that kind rather than opening a second one.
    """
    path = root or default_root()
    eng = _open_engagement(path)
    try:
        run_id = run_mod.current_run(
            eng.db, engagement_id=eng.id, kind=kind,
            safety_profile=eng.config.safety_profile)
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot write to the database at {path}: {exc}") from exc
    click.echo(f"{kind} run {run_id} is live")


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
               "it exists; `hx resume` is the only thing that lifts it")


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def resume(root) -> None:
    """Re-arm issuance. The only thing that lifts a halt.

    A `configure` re-authorises SCOPE and never issuance, and a reconnect
    re-asserts the halt rather than clearing it -- so this command is the
    single way back, which is what makes refusing to run it on an
    un-halted engagement safe rather than pedantic.
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
