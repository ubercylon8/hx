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

This module also holds the liveness canary (`canary`) and the bracketed-window
bookkeeping (`IdentityWindow`) that decides whether a run's traffic was issued
while the session was proved live -- not because either shares a type with the
credential machinery above, but because both are downstream of one `Identity`
declaration and Task 6 was scoped to append to this file rather than open a
third module for one function and one class. Nothing above this line is
implied to be all this file will ever hold.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

from hx.checks import probe
from hx.config import Identity, Liveness


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
        # THE COMMAND'S OUTPUT DOES NOT TRAVEL WITH THIS MESSAGE, and that
        # sentence is the whole of the guard. F1 of fix round A: this string
        # is caught by `hx.scan._IdentityBracket._settle`, interpolated into
        # an `IdentityDead`, and written to `run.stop_reason`, which
        # `hx.report._provenance` renders on the CLIENT-FACING page through a
        # `_redact` that strips URL userinfo and nothing else. The command
        # whose stderr this was is the one that MINTS A CREDENTIAL: a
        # `curl -v`, a `set -x`, or an auth error quoting the request it just
        # made prints the token on stderr, and 200 bytes of it went into the
        # deliverable. Task 7 is what made that path reachable -- before it,
        # nothing a run could execute called this function at all.
        #
        # NOT TRUNCATED HARDER, NOT SUMMARISED, NOT HASHED. Each of those is
        # still a function of the secret, and a shorter prefix of a bearer
        # token is still a prefix of a bearer token. The exit code stays
        # because it is the command's own status and carries nothing of what
        # the command printed, and it is what tells an operator which of
        # their own failures they are looking at.
        #
        # WHERE THE OPERATOR GETS THE OUTPUT: by running the command, which
        # is theirs. There is no operator-only channel here to divert it to
        # -- `hx.scan.run` builds its one `CheckContext` with
        # `log=lambda s: None` -- so a field holding it would be a leak
        # waiting for its first reader, which is F5's complaint pointed the
        # other way.
        raise IdentityError(
            f"refresh command for {ident.id!r} exit {proc.returncode}. Its "
            "output is deliberately not repeated here: this message reaches "
            "the client-facing report, and the stderr of a command that "
            "mints a credential is presumed to carry one. Run the command "
            "yourself to see what it said")
    value = proc.stdout.strip()
    if not value:
        raise IdentityError(
            f"refresh command for {ident.id!r} printed nothing; an empty "
            "credential is not a credential")
    return Resolved(id=ident.id, header=ident.inject.header, value=value,
                    generation=generation + 1)


def canary(liveness: Liveness, sender) -> bool:
    """Is this session still logged in?

    STATUS IS NECESSARY AND NOWHERE NEAR SUFFICIENT. An application that
    answers a logged-out request with a 200 login PAGE is the shape no
    response-status rule can catch. `hx.scan._retirable`'s own docstring
    calls it out by number: six ways an active check could call a probe
    `clean` off nothing were closed by the status doctrine, an eighth was
    closed the same way a round later, and the SEVENTH -- this one -- was not,
    because "a fixture whose anonymous view differs from its anonymous view
    does not exist" and so could never be measured against the corpus. That
    is the open hazard `_retirable` refuses all active-check retirement over
    today, and the reason `expect_body` is required by the config loader and
    checked here rather than left to a status code: re-enabling retirement on
    a proof a login page satisfies would hand the hazard back wearing a
    stamp.

    A refusal (`probe.ProbeRefused`) is a FAILURE, not an exception to
    propagate: a canary that could not be sent has proved nothing, and the
    caller's next move -- treat the session as unproven -- is the same as if
    it had come back and failed. Any other exception (a malformed
    `liveness.path`, for instance) is a programming error in the caller and
    is left to propagate; swallowing it here would read as "session dead"
    when the actual fault is a config that was never sendable.
    """
    try:
        resp = sender.get(liveness.path)
    except probe.ProbeRefused:
        return False
    if resp.status is None or not (200 <= resp.status < 300):
        return False
    body = resp.body or b""
    if liveness.expect_body.encode("utf-8", "replace") not in body:
        return False
    if (liveness.expect_absent is not None
            and liveness.expect_absent.encode("utf-8", "replace") in body):
        return False
    return True


class IdentityWindow:
    """Whether this run's traffic was issued while the session was proved live.

    A canary at the start of a run proves the session was live AT THE START.
    It says nothing about the request issued an hour later, and spec section
    6's own motivating case is exactly that: an SSO session dying at 01:50
    produces six hours of unauthenticated traffic that every check reads as
    not vulnerable. Stamping those six hours `proven` on the strength of an
    01:00 canary would be worse than having no proof, because the proof is
    what Task 8's retirement gate reads.

    So a window is BRACKETED: it opens on a canary result and closes on the
    next one, and only a window closed by a PASS is proof of anything. Three
    states, and only three:

      - the window never opened, or the run's first canary failed -> `dead`
        (the run could not even start proved)
      - it opened cleanly, and some later canary failed -> `assumed`
      - it opened cleanly, and nothing ever failed -> `proven`

    A run's state collapses to the WORST window in it, not the last one: any
    failure anywhere downgrades the whole run to `assumed`, because the
    retirement gate in Task 8 is decided per run (a `check_run`'s probes may
    span more than one window) and a finding retired on this run's evidence
    could sit on a surface probed inside the one window that came back
    unproven. The run under-claims rather than over-claims.
    """

    def __init__(self, *, due_every: int) -> None:
        self.due_every = due_every
        self._since = 0
        # None: never opened. False: the run's first canary failed outright,
        # which is `dead` and stays `dead` no matter what a later open/close
        # does -- the run never had a proved starting point to stand on.
        self._first_open_passed: bool | None = None
        self._any_failure = False

    def open(self, *, passed: bool) -> None:
        if self._first_open_passed is None:
            self._first_open_passed = passed
        if not passed:
            self._any_failure = True
        self._since = 0

    def note_probe(self) -> bool:
        """Count one probe issued inside the current window.

        True when `due_every` probes have been counted since the window last
        opened or last came due, meaning a canary is now due before another
        probe goes out.
        """
        self._since += 1
        if self._since >= self.due_every:
            self._since = 0
            return True
        return False

    def close(self, *, passed: bool) -> None:
        if not passed:
            self._any_failure = True

    def state_for_run(self) -> str:
        if not self._first_open_passed:        # None or False
            return "dead"
        return "assumed" if self._any_failure else "proven"
