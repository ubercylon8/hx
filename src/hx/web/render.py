"""The Jinja environment, and the filters that must never be forgotten.

AUTOESCAPE IS OURS, NOT A FRAMEWORK DEFAULT. The environment is built here
and handed to `Jinja2Templates(env=...)` rather than letting Starlette
construct one, so that "is autoescape on" is a line in this repository that
a test can pin, instead of a property of whichever Starlette is installed.
It is the single defence between a captured response body and the
operator's browser.

`StrictUndefined` for the same reason: a screen that renders a blank where a
number should be is S12's failure in miniature -- a reader cannot tell
"zero" from "this template asked for a name nobody passed". Every context
value a template reads is passed explicitly, including the ones that are
None.
"""
from __future__ import annotations

import datetime
from pathlib import Path

import jinja2
from starlette.templating import Jinja2Templates

from hx.store import records

TEMPLATES = Path(__file__).parent / "templates"
STATIC = Path(__file__).parent / "static"

#: What a screen shows where a timestamp, count or field is genuinely absent.
#: One spelling, so "we have no value" never reads as "the value is empty".
ABSENT = "—"


def when(us) -> str:
    """A microsecond timestamp as UTC.

    UTC and not local time: a report and a screen read side by side during
    an incident must agree, and the operator's timezone is not part of the
    evidence.
    """
    if us is None:
        return ABSENT
    moment = datetime.datetime.fromtimestamp(us / 1_000_000,
                                             tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%SZ")


def templates() -> Jinja2Templates:
    """The environment every screen renders through."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        autoescape=True,
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # THE ONE REDACTION RULE, borrowed and not rewritten. `records.redact_url`
    # is already the rule the Java side applies to a request line, character
    # for character, compared over one shared vector file. A second spelling
    # here would be a third rule, and S4 is explicit that Python must never
    # gain a second place that decides any of this.
    #
    # Blob BYTES need no filter: `Redactor.java` runs extension-side before
    # hashing, so what is on disk already carries `{{identity:<id>:authz}}`
    # and `{{observed:set-cookie}}` where credentials were.
    env.filters["redact"] = records.redact_url
    env.filters["when"] = when
    return Jinja2Templates(env=env)
