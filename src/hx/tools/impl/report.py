"""The client deliverable, rendered.

A READ, NOT A MUTATION, so it works while a halt is armed -- which is exactly
when someone wants it. Rendering writes nothing: `hx.report.render` reads the
store and returns text, and putting that text on disk is `hx report`'s job, not
a tool's.

THE WHOLE DOCUMENT COMES BACK. Principle 1 says handles and digests rather than
payloads, and section 8 nonetheless spells this one `report.render(engagement)
-> Markdown`. The exception is deliberate: a report the agent cannot read is a
report it cannot check before an operator sends it to a client. `bytes` is
returned alongside so the caller can see the size it just took on.
"""
from __future__ import annotations

from ... import report as report_mod
from .. import registry, spec


def render(ctx) -> dict:
    text = report_mod.render(ctx.conn, engagement_id=ctx.engagement.id,
                             config=ctx.config, blobs=ctx.blobs)
    return {"markdown": text, "bytes": len(text.encode("utf-8"))}


registry.register(spec.ToolSpec(
    name="report.render", handler=render,
    summary="Render the engagement report as Markdown, coverage included.",
    params={"type": "object", "additionalProperties": False, "properties": {}}))
