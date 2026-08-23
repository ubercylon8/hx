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

_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def default_root() -> Path:
    env = os.environ.get("HX_HOME")
    if env:
        return Path(env)
    return Path.home() / "hx" / "engagements"


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


@main.command()
@click.option("--root", type=click.Path(path_type=Path), default=None)
def info(root) -> None:
    """Show an engagement's configuration and current counts."""
    path = root or default_root()
    try:
        eng = eng_mod.open_(path)
        counts = {
            t: eng.db.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
            for t in ("run", "surface", "exchange", "finding", "check_run")
        }
    except eng_mod.EngagementError as exc:
        raise click.ClickException(str(exc)) from exc
    except config_mod.ConfigError as exc:
        raise click.ClickException(f"invalid config at {path}: {exc}") from exc
    except sqlite3.Error as exc:
        raise click.ClickException(f"cannot read the database at {path}: {exc}") from exc
    except OSError as exc:
        raise click.ClickException(f"cannot access the engagement at {path}: {exc}") from exc

    click.echo(f"engagement {eng.config.name} ({eng.id})")
    click.echo(f"  client   {eng.config.client}")
    click.echo(f"  profile  {eng.config.safety_profile}")
    click.echo(f"  scope    {', '.join(eng.config.scope_include)}")
    if eng.config.scope_exclude:
        click.echo(f"  exclude  {', '.join(eng.config.scope_exclude)}")
    click.echo(f"  root     {eng.root}")
    click.echo("  counts   " + "  ".join(f"{k}={v}" for k, v in counts.items()))
