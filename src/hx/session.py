"""Standing up a live, configured Burp — and taking it down again.

hx NEVER BUNDLES OR REDISTRIBUTES BURP. This module locates a jar the
operator already has, launches it with the bridge extension, and authorises
it. Nothing here ships Burp and nothing here may.

WHY THIS MODULE EXISTS AT ALL: until it did, nothing in `src/` called
`bridge.configure()`. `hx capture start` opened a database row and stopped
there, while `scripts/demo_capture.py` and `tests/integration/` each stood up
their own session -- so capture worked in a demo and not from the CLI, and an
active check had nowhere to send. The extension defaults to DENY-ALL, so an
unconfigured extension refuses everything.
"""
from __future__ import annotations

import os
from pathlib import Path

JAR_GLOB = "burpsuite_desktop_v*.jar"
DEFAULT_LAB = Path.home() / "F0RT1KA" / "burp-lab"


class SessionError(Exception):
    """The session cannot be established. The message names the fix."""


def _lab() -> Path:
    return Path(os.environ.get("HX_BURP_LAB", DEFAULT_LAB))


def find_burp_jar(explicit: Path | None = None) -> Path:
    """`--burp-jar`, then `$HX_BURP_JAR`, then a search of `$HX_BURP_LAB`.

    AMBIGUITY IS AN ERROR, NOT A GUESS. Two jars in the lab means the operator
    has upgraded and kept the old one, and silently taking the newer would run
    an assessment against a different Burp from the one they believe they are
    running -- which the report then records as the version under test.
    """
    if explicit is not None:
        if not Path(explicit).is_file():
            raise SessionError(f"no Burp jar at {explicit}")
        return Path(explicit)

    from_env = os.environ.get("HX_BURP_JAR")
    if from_env:
        if not Path(from_env).is_file():
            raise SessionError(f"HX_BURP_JAR names {from_env}, which is not a file")
        return Path(from_env)

    lab = _lab()
    found = sorted(lab.glob(JAR_GLOB))
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        names = ", ".join(p.name for p in found)
        raise SessionError(
            f"{len(found)} Burp jars in {lab}: {names}. Pass --burp-jar to say "
            "which one this engagement runs against -- the report records the "
            "version, so this is not a choice hx may make for you")
    raise SessionError(
        f"no Burp jar found. Pass --burp-jar, set HX_BURP_JAR, or put one "
        f"matching {JAR_GLOB} in {lab} (override with HX_BURP_LAB). hx does "
        "not ship Burp")
