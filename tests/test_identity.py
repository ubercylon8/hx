from __future__ import annotations

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
    # `;` and `>` are ordinary argv characters to execve. If a shell were
    # involved this would create the file and the value would be empty.
    r = identity.refresh(
        _programmatic(["printf", "%s", "a;b>c"]), generation=1)
    assert r.value == "a;b>c"


def test_a_resolved_credential_is_not_in_its_own_repr():
    # A Resolved reaches log lines and tracebacks. Its repr must not carry
    # the credential, or the value leaks everywhere an exception is printed.
    r = identity.resolve(_static(), {"HX_ID_USER": "session=SUPERSECRET"})
    assert "SUPERSECRET" not in repr(r)
    assert "user" in repr(r)
