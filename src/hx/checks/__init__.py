"""The check corpus: S10's extensibility surface.

One file per check, an explicit registry, and a base module whose whole job is
to make a check unable to say things only the runner may say.
"""
from hx.checks.base import (      # noqa: F401
    Candidate, Check, CheckContext, Insertion, Verdict,
    CONFIDENCES, INSERTION_KINDS, SCOPE_LEVELS, SEVERITIES,
)
