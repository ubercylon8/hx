"""The handlers.

Importing this package imports every module below it, which is what puts the
tools in `hx.tools.registry.TOOLS`. Adapters import THIS; nothing imports the
handler modules one at a time except their own tests.
"""

from . import checks, finding, http, report, run, surface  # noqa: F401
