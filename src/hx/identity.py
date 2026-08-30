"""Credentials, and the one place in this codebase that holds one.

WHY THIS IS NOT ON `Config`. `hx.engagement.record_scope_version` writes the
config YAML VERBATIM into `scope_version.yaml` (the `INSERT INTO scope_version`
at `engagement.py:114`, whose `yaml` column takes `config.dumps(cfg)` whole), a
table the schema calls "append-only: tamper-evidence for contract disputes". A
credential reachable from a `Config`
is therefore a credential copied, unredactable, into a table designed to be
impossible to rewrite -- which is spec section 7's warning about the blob store
wearing different clothes. `Config` holds the DECLARATION; a `Resolved` holds
the secret, and the two never meet in a serialiser.

`Resolved.__repr__` is overridden for the same reason at a smaller scale: a
dataclass repr would put a live session cookie into every traceback that
happens to hold one.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from hx.config import Identity


class IdentityError(Exception):
    """A credential could not be obtained, or was obviously not a credential."""


@dataclass(frozen=True)
class Resolved:
    id: str
    header: str
    value: str
    generation: int

    def __repr__(self) -> str:            # noqa: D105 -- see module docstring
        return (f"Resolved(id={self.id!r}, header={self.header!r}, "
                f"generation={self.generation}, value=<redacted>)")


def resolve(ident: Identity, env: dict[str, str]) -> Resolved:
    """The static strategy: read the declared variable out of the environment.

    A PROGRAMMATIC identity does not come through here -- its credential is
    minted by `refresh()` from a command's stdout, and the config loader
    deliberately does not require `value_from_env` for one. Without the guard
    below, calling this on one produced "identity 'admin' needs None in the
    environment and it is not set", which reads like a missing variable rather
    than a call that should never have been made.
    """
    if ident.strategy != "static":
        raise IdentityError(
            f"identity {ident.id!r} is {ident.strategy!r} and has no "
            "environment variable to read; a programmatic identity is minted "
            "by refresh(), not resolved")
    name = ident.inject.value_from_env
    if name not in env:
        raise IdentityError(
            f"identity {ident.id!r} needs {name} in the environment and it is "
            "not set. Refusing rather than issuing anonymously: an anonymous "
            "run of an authenticated application answers `clean` about a view "
            "none of its users are in")
    value = env[name].strip()
    if not value:
        raise IdentityError(f"{name} is set but empty, for identity {ident.id!r}")
    return Resolved(id=ident.id, header=ident.inject.header, value=value,
                    generation=1)


def refresh(ident: Identity, generation: int) -> Resolved:
    """The programmatic strategy: run the declared command, take stdout.

    NO SHELL. `subprocess.run` with a list argv goes straight to execve, so a
    `;` or a `>` in an argument is an ordinary character. The config loader
    already refuses a string command for the same reason; this is the half that
    makes the refusal mean something.
    """
    if ident.refresh is None:
        raise IdentityError(
            f"identity {ident.id!r} has no refresh command; only a "
            "programmatic identity can be refreshed")
    try:
        proc = subprocess.run(list(ident.refresh.command), capture_output=True,
                              text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise IdentityError(
            f"refresh command for {ident.id!r} could not run: {exc}") from exc
    if proc.returncode != 0:
        raise IdentityError(
            f"refresh command for {ident.id!r} exit {proc.returncode}: "
            f"{proc.stderr.strip()[:200]}")
    value = proc.stdout.strip()
    if not value:
        raise IdentityError(
            f"refresh command for {ident.id!r} printed nothing; an empty "
            "credential is not a credential")
    return Resolved(id=ident.id, header=ident.inject.header, value=value,
                    generation=generation + 1)
