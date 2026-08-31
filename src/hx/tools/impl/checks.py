"""The corpus, including what is switched off.

A LISTING THAT HID DISABLED CHECKS WOULD BE SECTION 12'S FAILURE ONE LAYER UP.
An agent that cannot see `active_mutate` in the corpus concludes the class does
not apply to this application; an agent that sees it listed `enabled: false`
knows the class exists and that an operator turned it off. Those are different
facts, and only one of them belongs in a report.
"""
from __future__ import annotations

from ... import scan as scan_mod
from ...checks import registry as check_registry
from .. import envelope, registry, spec


def list_(ctx, **kw) -> dict:
    """Every check, with whether it is on and whether it needs a session.

    The argument is spelled `class` on the wire because section 8 spells it
    that way, and `class` is a Python keyword -- so the handler takes `**kw`
    and reads it out. Renaming it in the schema would make the published tool
    disagree with the spec to spare this one line.
    """
    wanted = kw.get("class")
    on = {c.id for c in check_registry.enabled(ctx.config)}
    rows = [{"id": c.id, "version": c.version, "class": c.klass,
             "enabled": c.id in on,
             "needs_egress": scan_mod.needs_a_bridge(c),
             "insertion_kinds": sorted(c.insertion_kinds)}
            for c in check_registry.CHECKS
            if wanted is None or c.klass == wanted]
    rows.sort(key=lambda r: (r["class"], r["id"]))
    return envelope.page(rows, total=len(rows), limit=envelope.MAX_LIMIT)


registry.register(spec.ToolSpec(
    name="checks.list", handler=list_,
    summary="Every check in the corpus, with whether it is enabled and "
            "whether it needs a live session.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "class": {"type": "string",
                  "enum": sorted(check_registry.KNOWN_CLASSES),
                  "description": "only checks of this class"}}}))
