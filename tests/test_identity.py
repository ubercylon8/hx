from __future__ import annotations

import sys

import pytest

from hx import config, identity


def _static(env="HX_ID_USER") -> config.Identity:
    return config.Identity(
        id="user", strategy="static",
        inject=config.Inject(header="Cookie", value_from_env=env),
        liveness=config.Liveness(path="/account", expect_body="Sign out"))


def _programmatic(command) -> config.Identity:
    return config.Identity(
        id="admin", strategy="programmatic",
        inject=config.Inject(header="Authorization", value_from_env="HX_ID_ADMIN"),
        liveness=config.Liveness(path="/admin", expect_body='"role":"admin"'),
        refresh=config.Refresh(command=tuple(command)))


def test_a_static_identity_resolves_from_the_environment():
    r = identity.resolve(_static(), {"HX_ID_USER": "session=abc"})
    assert r.id == "user" and r.header == "Cookie" and r.value == "session=abc"
    assert r.generation == 1, "the first resolution is generation 1, not 0"


def test_a_missing_environment_variable_is_a_loud_failure():
    # Silently issuing anonymously is the outcome this whole plan exists to
    # remove: it produces a run of `clean` answers about a view nobody sees.
    with pytest.raises(identity.IdentityError, match="HX_ID_USER"):
        identity.resolve(_static(), {})


def test_a_blank_environment_variable_is_also_refused():
    with pytest.raises(identity.IdentityError, match="empty"):
        identity.resolve(_static(), {"HX_ID_USER": "   "})


def test_a_programmatic_identity_takes_its_value_from_stdout():
    r = identity.refresh(_programmatic(["printf", "Bearer t0ken"]), generation=2)
    assert r.value == "Bearer t0ken"
    assert r.generation == 3, "a refresh advances the generation"


def test_refresh_strips_only_the_trailing_newline_a_command_adds():
    r = identity.refresh(_programmatic(["printf", "Bearer t0ken\\n"]), generation=1)
    assert r.value == "Bearer t0ken"


def test_a_refresh_command_that_fails_is_an_error_not_an_empty_credential():
    with pytest.raises(identity.IdentityError, match="exit"):
        identity.refresh(_programmatic(["false"]), generation=1)


def test_a_refresh_command_that_prints_nothing_is_refused():
    with pytest.raises(identity.IdentityError, match="empty"):
        identity.refresh(_programmatic(["true"]), generation=1)


def test_the_command_is_never_run_through_a_shell():
    # `;` and `>` reach printf as ORDINARY ARGV CHARACTERS, because a list
    # argv goes straight to execve and no shell ever sees them. Under a shell
    # this command does not survive: the review measured both regression
    # shapes (list-form and string-join) and each fails on a non-zero exit
    # rather than by creating a file, which an earlier version of this comment
    # claimed. The test still catches the regression; only the mechanism was
    # described wrongly, and a comment that names the wrong mechanism is how
    # the next person "fixes" the wrong thing.
    r = identity.refresh(
        _programmatic(["printf", "%s", "a;b>c"]), generation=1)
    assert r.value == "a;b>c"


def test_a_resolved_credential_is_not_in_its_own_repr():
    # A Resolved reaches log lines and tracebacks. Its repr must not carry
    # the credential, or the value leaks everywhere an exception is printed.
    r = identity.resolve(_static(), {"HX_ID_USER": "session=SUPERSECRET"})
    assert "SUPERSECRET" not in repr(r)
    assert "user" in repr(r)


def test_resolve_refuses_a_programmatic_identity_by_name():
    """Finding 3 of the Task 2 review: the guard, and the message it replaced.

    Without it, `resolve()` on a programmatic identity read
    `ident.inject.value_from_env`, found `None` -- which the config loader
    deliberately allows for that strategy -- and raised "identity 'admin' needs
    None in the environment and it is not set". That reads like an operator
    forgot to export something, sending them to fix a variable that was never
    supposed to exist, when the real fault is a caller reaching for the wrong
    function.
    """
    with pytest.raises(identity.IdentityError, match="minted by refresh"):
        identity.resolve(_programmatic(["true"]), {})


def test_a_failing_refresh_commands_stderr_is_not_in_the_message():
    """F1 OF FIX ROUND A, AT THE POINT THE MESSAGE IS BUILT.

    This exception's text is caught by `hx.scan._IdentityBracket._settle`,
    interpolated into an `IdentityDead`, and -- before the store-point cut in
    `hx.scan._halt_reason` -- written verbatim to `run.stop_reason`, which
    `hx.report._provenance` renders on the client-facing page. The command
    whose stderr it was is the one that MINTS the credential, so its output
    is presumed to be one: a `curl -v`, a `set -x` or an auth error quoting
    the request it just made prints the token there.

    `tests/test_scan_probes.py::test_a_failing_refresh_commands_output_never_
    reaches_a_rendered_report` is the same fact asserted on the deliverable.
    This one holds the half that must not depend on it.
    """
    leaky = [sys.executable, "-c",
             "import sys; sys.stderr.write("
             "'Authorization: Bearer SUPERSECRET\\n'); raise SystemExit(3)"]
    with pytest.raises(identity.IdentityError) as raised:
        identity.refresh(_programmatic(leaky), generation=1)

    assert "SUPERSECRET" not in str(raised.value)
    assert "exit 3" in str(raised.value), (
        "the exit code is what tells an operator WHICH of their failures "
        "this is, and it carries nothing the command printed")
    assert "admin" in str(raised.value), "the message names no identity"
