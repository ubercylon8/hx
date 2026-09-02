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
from hx.checks.active import (cors, open_redirect, path_traversal,
                              reflected_input, sql_behaviour,
                              sql_error)
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

# Which of those hooks `hx.scan.run` ACTUALLY CALLS. Today: two. `_HOOKS`
# above answers "may this class implement this hook"; this answers "will
# anything ever invoke it", and they are different questions that were being
# asked as one. F7 of the whole-branch review: a check implementing only
# `on_corpus` passed `validate()` and then produced an `error` row per
# surface (`scan.run` calls `check.on_surface` unconditionally, so the
# missing attribute raises inside the per-check try) -- verbatim the outcome
# the "no hook" guard below exists to prevent, arrived at by a different
# route. WHEN A RUNNER PASS IS ADDED, ADD ITS HOOK HERE -- this tuple is what
# makes such a check runnable, and forgetting it is a loud import error rather
# than a silent corpus.
#
# `probes` WAS IN `on_corpus`'S POSITION AND IS NOT ANY MORE, and the reason
# it was refused is the reason it is now listed rather than a reason that
# stopped applying: `hx.scan.run` grew the probe pass (this plan, Task 7), so
# something does now invoke it, and the refusal below lifts for active checks
# by that fact alone. Nothing about the RULE changed. `on_corpus` is still
# here-but-uncalled for every class in `_HOOKS`, still refused as the only
# hook of a check, and the day a corpus pass is written this tuple is the one
# line that has to move with it -- which is what this paragraph is kept for.
_RUNNER_CALLS = ("on_surface", "probes")


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
        if not any(hook in _RUNNER_CALLS for hook in implemented):
            raise RegistryError(
                f"{check.id}: implements only {implemented!r}, and the runner "
                f"does not yet call {'it' if len(implemented) == 1 else 'any of them'}. "
                f"`hx.scan.run` calls {list(_RUNNER_CALLS)} and nothing else, "
                "so this check would open a check_run row for every surface "
                "and end every one of them `error` -- the same outcome as "
                "having no hook at all. The hook is legal for this class and "
                "the runner pass that would drive it is not written yet; add "
                "the pass and list its hook in `_RUNNER_CALLS` before "
                "registering a check that needs it")

        # LAST, DELIBERATELY. Every rule above decides whether this check can
        # RUN; this one decides whether the report can DESCRIBE it, and a
        # check with no hook and no `looks_for` should hear about the hook
        # first.
        looks_for = getattr(check, "looks_for", None)
        if not isinstance(looks_for, str) or not looks_for.strip():
            raise RegistryError(
                f"{check.id}: no `looks_for`. The report's Findings section "
                "opens by naming what this build looked for, derived from "
                "this attribute -- a check without one would vanish from that "
                "sentence AND take the absence of its category with it, so "
                "the report would under-claim its own coverage with nothing "
                "to say so. One lowercase noun phrase (an acronym may open "
                "it), no trailing stop; see `base.Check.looks_for`")


CHECKS: tuple[base.Check, ...] = (
    cookie_flags.CookieFlags(),
    security_headers.SecurityHeaders(),
    secret_in_response.SecretInResponse(),
    stack_trace.StackTrace(),
    cors.Cors(),
    open_redirect.OpenRedirect(),
    reflected_input.ReflectedInput(),
    sql_error.SqlError(),
    sql_behaviour.SqlBehaviour(),
    path_traversal.PathTraversal(),
)

validate(CHECKS)


def enabled(config) -> tuple[base.Check, ...]:
    """The checks this engagement has switched on.

    `config.checks` is `DEFAULT_CHECKS` overlaid with the engagement's own
    file, and `config.load` already refuses a key outside that vocabulary --
    so an unknown class cannot reach here.
    """
    return tuple(c for c in CHECKS if config.checks.get(c.klass, False))
