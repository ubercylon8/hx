"""Canary minting and reflection testing, shared by the checks that need both.

WHY THIS EXISTS AND WHY IT IS SO SMALL. `cors.py` and `open_redirect.py` each
mint their own fixed marker (`_PROBE_ORIGIN`, `_MARKER_URL`) because each
needs exactly one string, per check, chosen for what it NAMES -- an Origin
that cannot be the target, a host a `Location` cannot legitimately point at.
Neither would gain anything from a shared minting function: a constant
assigned once is not a helper. `reflected_input.py` is the different case --
it plants one canary per insertion point, on a surface that can hold any
number of them, and needs the *same* two operations (mint a fresh
unmistakable value, then ask whether a response contains it) run once per
point. THAT repetition is what a helper is for; a helper used by one caller
still belongs in its caller, so this module exists only because a second
active check that also needs both operations would otherwise have to copy
them or import from `reflected_input.py` sideways.

THE CANARY IS ALPHANUMERIC ONLY, AND THAT IS THE INERTNESS GUARANTEE. It
cannot close a tag, break out of an attribute, terminate a JSON string, or
open a script context -- there is no character in it capable of being
anything other than itself, wherever it lands. That is what lets a check
built on `canary()` prove reflection happened without ever constructing a
payload: the string that comes back could not have executed no matter what
surrounded it. A caller that wants to learn whether the surrounding context
would let a *different*, character-bearing value survive builds that value
itself, on top of a canary this module minted -- see `reflected_input.py`'s
own escalation step -- because that decision (which characters, and when to
spend the extra request) is specific to what that check is trying to learn,
not something this module can decide on every caller's behalf.

RANDOM, PER CALL, AND WHY THAT MATTERS MORE HERE THAN IN EITHER PREDECESSOR.
`records.dedupe_key` folds `insertion_kind`/`insertion_name` into a finding's
identity, so two insertion points that each plant the SAME marker and then
find it reflected cannot be told apart by the marker alone -- only by which
request carried which value. A check that reused one canary across several
insertion points would also risk reading insertion B's echo as insertion A's
answer if the two requests raced or if the target itself echoed something
static that happened to match a fixed string. A fresh random value per call
removes both risks by construction: nothing on the wire ever repeats.
"""
from __future__ import annotations

import secrets
import string

# Alphanumeric only -- see the module docstring's inertness paragraph. Base62
# rather than hex: more bits of randomness per character, so the same
# collision resistance is reached at a shorter, still-comfortably-readable
# length.
_ALPHABET = string.ascii_letters + string.digits

# 24 characters of base62 is ~142 bits of entropy -- collision with anything
# already on the page, or with another call's own canary, is not a
# realistic concern at any corpus size this tool will ever scan. Short
# enough to survive a field's length limit in the overwhelming common case,
# which a canary that never reflects at all cannot be distinguished from a
# canary that was truncated past recognition.
_LENGTH = 24


def canary() -> str:
    """A fresh, random, purely alphanumeric marker.

    Every call returns a new value -- there is no seed, no counter, and no
    way to ask for the same string twice. A check that needs to tell two
    insertion points' reflections apart calls this once per point, never
    once per surface.
    """
    return "".join(secrets.choice(_ALPHABET) for _ in range(_LENGTH))


def reflected(response, marker: str) -> bool:
    """Whether `marker` appears verbatim anywhere in `response`.

    Checks both halves -- `response.head` and `response.body` -- because a
    value planted in a query parameter, path segment, header or cookie can
    be echoed into either: a diagnostic response header, a `Set-Cookie` that
    mirrors what was sent, or an ordinary place in the body are all
    "reflected" in the sense this module tests for, and a check for the body
    alone would call a target clean for reflecting input straight back in
    its headers.

    A plain substring test, not a parse: `marker` is alphanumeric ASCII (see
    `canary()`), so there is no encoding question a smarter check could get
    right that this one gets wrong, and the response halves are already
    bytes -- nothing here decodes them.
    """
    needle = marker.encode("ascii")
    return needle in response.head or needle in response.body
