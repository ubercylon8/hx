"""The explicit list, and the rules every entry must satisfy.

ADD A NEW CHECK HERE, on its own line, and nowhere else. There is no
discovery, deliberately, and the argument is not stylistic -- it is the same
one extension/test.sh makes about its own hand-rolled runner: a class nobody
lists is a file that imports, never runs, and reads in review exactly like a
check that passed. In a report that renders as `tested, clean`, which is the
one thing S12 says a report must never do.

`validate` runs at import. A malformed entry is a crash on `import hx.scan`,
loudly, rather than a check that quietly contributes nothing to a scan an
operator has already billed for.
"""
from __future__ import annotations

from hx.checks import base
from hx.checks.passive import cookie_flags, secret_in_response
from hx.checks.passive import security_headers, stack_trace

# S10's five class names. `config.DEFAULT_CHECKS` carries the same five and is
# the authority for which are ENABLED; this set is which are IMPLEMENTABLE.
# They are separate questions: `active_timing` is enabled by default in the
# config and has no checks in it, which the scan summary must say out loud
# rather than imply the class ran.
KNOWN_CLASSES = frozenset({
    "passive", "active_safe", "active_timing", "active_mutate", "active_dos",
})

# Which hooks each class may implement. A class may implement none of the
# others: the pairing is what turns "this check lies about its class" from a
# runtime surprise into an import error.
_HOOKS = {
    "passive": ("on_surface", "on_corpus"),
    "active_safe": ("probes", "on_corpus"),
    "active_timing": ("probes", "on_corpus"),
    "active_mutate": ("probes", "on_corpus"),
    "active_dos": ("probes", "on_corpus"),
}
_ALL_HOOKS = ("on_surface", "probes", "on_corpus")


class RegistryError(Exception):
    """An entry in CHECKS that cannot be run as declared."""


def validate(checks) -> None:
    seen: set[str] = set()
    for check in checks:
        if check.klass not in KNOWN_CLASSES:
            raise RegistryError(
                f"{check.id}: unknown class {check.klass!r}; this version "
                f"knows {sorted(KNOWN_CLASSES)}")
        if check.id in seen:
            raise RegistryError(
                f"duplicate check id {check.id!r}. check_run.check_id is how "
                "coverage is attributed, so two checks sharing one make the "
                "coverage section unreadable and a retest wrong")
        seen.add(check.id)

        allowed = _HOOKS[check.klass]
        implemented = [h for h in _ALL_HOOKS if callable(getattr(check, h, None))]
        if not implemented:
            raise RegistryError(
                f"{check.id}: no hook. It would produce a check_run row for "
                "every surface and never a verdict")
        for hook in implemented:
            if hook not in allowed:
                raise RegistryError(
                    f"{check.id}: class {check.klass!r} may not implement "
                    f"{hook!r}. Either the class is wrong or the hook is "
                    "one nothing will ever call")


CHECKS: tuple[base.Check, ...] = (
    cookie_flags.CookieFlags(),
    security_headers.SecurityHeaders(),
    secret_in_response.SecretInResponse(),
    stack_trace.StackTrace(),
)

validate(CHECKS)


def enabled(config) -> tuple[base.Check, ...]:
    """The checks this engagement has switched on.

    `config.checks` is `DEFAULT_CHECKS` overlaid with the engagement's own
    file, and `config.load` already refuses a key outside that vocabulary --
    so an unknown class cannot reach here.
    """
    return tuple(c for c in CHECKS if config.checks.get(c.klass, False))
