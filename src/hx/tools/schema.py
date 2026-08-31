"""A JSON Schema subset that refuses what it cannot enforce.

`ToolSpec.params` is JSON Schema because an MCP adapter publishes it verbatim,
so the schema is the interface rather than a convenience. Validating it needs a
validator, and this project runs on two Python dependencies beside a Java
extension with none -- a security tool's dependency footprint is part of its
argument -- so this is a subset rather than `jsonschema`.

A SUBSET THAT SILENTLY IGNORED AN UNKNOWN KEYWORD WOULD BE A HOLE. A schema
reading `{"type": "string", "pattern": "^[a-z]+$"}` would accept every string
while the published schema promised otherwise, and the agent would be told its
argument was fine. So `check_schema` refuses every keyword this module does not
implement, and `registry.register` calls it: the refusal lands at REGISTRATION,
which is import time and a test run, never at a call. Adding a keyword to a
tool's schema means implementing it here first.

Each constraint keyword has two facts: (1) which types it applies to, and
(2) what type its value must be. Leaving either unstated caused defects:
`{"type": "string", "minimum": 5}` accepts and silently ignores `minimum` because
it only applies to numbers; `{"type": "string", "minLength": "two"}` accepts and
crashes on len(value) < "two"; `{"type": "integer", "minimum": "five"}` accepts
and crashes on value < "five". check_schema now validates both by consulting a
table for each keyword present.

`minItems`/`maxItems` WERE MISSING ENTIRELY until the final whole-branch
review's item 2, which is a sharper hole than a keyword with one fact
unstated: with no array-length keyword AT ALL, no schema in this system could
bound an array's size, so `finding.record`'s `exchange_ids` had no ceiling and
60,000 of them became `OperationalError: too many SQL variables` from the
`IN (...)` list the handler builds -- `error / internal`, which tells the
agent hx is broken when its argument was simply too large. `minItems` doubles
as the "must cite exchanges" rule `finding.record`'s docstring already wanted;
`maxItems` is the ceiling.
"""
from __future__ import annotations

from typing import Any


class SchemaError(Exception):
    """A schema this module cannot enforce in full."""


_TYPES: dict[str, Any] = {
    "object": dict, "array": list, "string": str,
    "integer": int, "number": (int, float), "boolean": bool,
}

#: Each constraint keyword paired with (applicable_types, value_type).
#: applicable_types is a frozenset of type strings, or None if the keyword
#: applies to any type. value_type is the type the keyword's value must have.
_CONSTRAINT_TABLE: dict[str, tuple[frozenset[str] | None, type]] = {
    "type": (None, str),
    "enum": (frozenset({"string", "integer", "number", "boolean"}), list),
    "properties": (frozenset({"object"}), dict),
    "required": (frozenset({"object"}), list),
    "additionalProperties": (frozenset({"object"}), bool),
    "items": (frozenset({"array"}), dict),
    "minimum": (frozenset({"integer", "number"}), (int, float)),
    "maximum": (frozenset({"integer", "number"}), (int, float)),
    "minLength": (frozenset({"string"}), int),
    "maxLength": (frozenset({"string"}), int),
    "minItems": (frozenset({"array"}), int),
    "maxItems": (frozenset({"array"}), int),
}

#: Keywords that constrain a value. Every one is implemented by `validate`, and
#: a test proves each changes the answer for some value.
CONSTRAINTS = frozenset(_CONSTRAINT_TABLE)

#: Keywords that carry no constraint and are published to the agent as help.
#: Accepted precisely because they cannot widen what is accepted.
METADATA = frozenset({"description", "title", "default", "examples"})


def check_schema(obj: Any, *, where: str = "params") -> None:
    """Refuse a schema this module cannot enforce in full."""
    if not isinstance(obj, dict):
        raise SchemaError(f"{where}: a schema must be an object")
    unknown = set(obj) - CONSTRAINTS - METADATA
    if unknown:
        raise SchemaError(
            f"{where}: {sorted(unknown)} are not implemented by hx.tools.schema. "
            "A keyword this validator ignores is a constraint the published "
            "schema promises and nothing applies; implement it here first."
        )
    type_ = obj.get("type")
    if type_ is None:
        raise SchemaError(
            f"{where}: a schema must declare a type; {where} gives _validate "
            "nothing to dispatch on, so every constraint in it is inert"
        )
    # Check type's value type BEFORE using it as a dict key to avoid TypeError.
    if not isinstance(type_, str):
        raise SchemaError(
            f"{where}: 'type' value must be of type {str!r}, "
            f"got {type(type_).__name__!r}"
        )
    if type_ not in _TYPES:
        raise SchemaError(f"{where}: unknown type {type_!r}")
    # Validate each constraint keyword: applicability to this type and value type.
    for keyword in obj:
        if keyword in METADATA:
            continue
        applicable_types, value_type = _CONSTRAINT_TABLE[keyword]
        if applicable_types is not None and type_ not in applicable_types:
            raise SchemaError(
                f"{where}: {keyword!r} does not apply to type {type_!r}"
            )
        value = obj[keyword]
        # bool-is-not-int exclusion for numeric constraint values.
        # minimum, maximum take (int, float); minLength, maxLength, minItems,
        # maxItems take int.
        if keyword in ("minimum", "maximum", "minLength", "maxLength",
                       "minItems", "maxItems"):
            ok = isinstance(value, value_type) and not isinstance(value, bool)
        else:
            ok = isinstance(value, value_type) and not (
                isinstance(value_type, tuple) and isinstance(value, bool))
        if not ok:
            raise SchemaError(
                f"{where}: {keyword!r} value must be of type {value_type!r}, "
                f"got {type(value).__name__!r}"
            )
        # Additional validation for enum members.
        if keyword == "enum":
            if not value:
                raise SchemaError(f"{where}: enum must be non-empty")
            for member in value:
                want = _TYPES[type_]
                # Same bool-is-not-int exclusion as _validate.
                ok = isinstance(member, want) and not (
                    type_ in ("integer", "number") and isinstance(member, bool))
                if not ok:
                    raise SchemaError(
                        f"{where}: enum member {member!r} is not of type {type_}"
                    )
    if type_ == "object":
        # `additionalProperties: false` is REQUIRED, never defaulted. An object
        # schema that admits extra keys accepts an argument the handler never
        # receives, and a silently dropped argument is how an agent comes to
        # believe it filtered a query it did not filter.
        if obj.get("additionalProperties") is not False:
            raise SchemaError(
                f"{where}: an object schema must set additionalProperties "
                "false, or it accepts arguments the handler never sees"
            )
        props = obj.get("properties") or {}
        for key, sub in props.items():
            # Property names are compared against JSON object keys, which are always strings.
            if not isinstance(key, str):
                raise SchemaError(
                    f"{where}: property name {key!r} must be a string "
                    "(JSON object keys are always strings)"
                )
            check_schema(sub, where=f"{where}.{key}")
        for key in obj.get("required") or ():
            # Required member names are compared against JSON object keys, which are always strings.
            if not isinstance(key, str):
                raise SchemaError(
                    f"{where}: required member {key!r} must be a string "
                    "(JSON object keys are always strings)"
                )
            if key not in props:
                raise SchemaError(
                    f"{where}: required names {key!r}, which has no property")
    if type_ == "array":
        if obj.get("items") is None:
            raise SchemaError(f"{where}: an array schema must declare items")
        check_schema(obj["items"], where=f"{where}[]")


def validate(obj: dict[str, Any], value: Any, *, where: str = "args") -> list[str]:
    """Every way `value` fails `obj`, as sentences. An empty list means valid.

    A LIST, NOT A RAISE. The dispatcher reports all of an agent's argument
    mistakes at once; answering one at a time turns a wrong call into a
    conversation.
    """
    problems: list[str] = []
    _validate(obj, value, where, problems)
    return problems


def _validate(obj, value, where, out) -> None:
    type_ = obj.get("type")
    if type_ is not None:
        want = _TYPES[type_]
        # `isinstance(True, int)` is True in Python, so a boolean satisfies
        # `integer` unless excluded by hand. `{"max_pages": true}` would
        # otherwise validate and then be used as arithmetic.
        ok = isinstance(value, want) and not (
            type_ in ("integer", "number") and isinstance(value, bool))
        if not ok:
            out.append(f"{where}: expected {type_}, got {type(value).__name__}")
            return
    if "enum" in obj and value not in obj["enum"]:
        # NEVER `{value!r}`. `dispatch._journalled` only journals a call's
        # arguments in full once they have passed this validator -- an
        # unvalidated call gets its sorted argument NAMES and nothing else
        # (see `_shape` there). This message is the loophole that made that
        # protection pointless: `dispatch` puts the joined problem strings
        # straight into the refusal `detail`, and `journal.summarise` appends
        # `detail` to `agent_action.result_summary` regardless of whether the
        # arguments themselves were journalled. `args.severity: 'Bearer
        # eyJ...secret' is not one of [...]` wrote the rejected value to disk
        # exactly where the args-blob guard was supposed to keep it from
        # reaching. A property name and the constraint are what make a
        # refusal actionable, and the value is the one thing the caller
        # already knows -- it does not need to be told what it just sent.
        out.append(f"{where}: not one of {sorted(obj['enum'])}")
    if type_ == "object":
        props = obj.get("properties") or {}
        for key in obj.get("required") or ():
            # `key` here is a NAME from the schema's own `required` list, not
            # anything the caller supplied -- there is nothing of the
            # caller's to echo.
            if key not in value:
                out.append(f"{where}: {key} is required")
        for key in sorted(set(value) - set(props)):
            # `key` here IS caller-supplied -- an argument NAME the caller
            # invented, not one the schema declares. Still fine to echo:
            # `dispatch._shape` already treats argument names as safe to
            # journal even for a call this validator never reaches ("the
            # whole loop-prevention signal... it needs no value to say it"),
            # and Principle 5 is the same argument one layer up -- identity
            # and anything else worth hiding is passed BY NAME, so a name
            # itself carries nothing that value-echoing put on disk.
            out.append(f"{where}: {key} is not an argument of this tool")
        for key, sub in props.items():
            if key in value:
                _validate(sub, value[key], f"{where}.{key}", out)
    elif type_ == "array":
        # Same rule as minimum/maximum below: the constraint, never the
        # value -- there is nothing to echo for an array's length anyway.
        if "minItems" in obj and len(value) < obj["minItems"]:
            out.append(f"{where}: fewer than {obj['minItems']} items")
        if "maxItems" in obj and len(value) > obj["maxItems"]:
            out.append(f"{where}: more than {obj['maxItems']} items")
        for i, item in enumerate(value):
            _validate(obj["items"], item, f"{where}[{i}]", out)
    elif type_ in ("integer", "number"):
        # Same rule as `enum` above: the constraint, never the value. A
        # number is a far less likely secret carrier than the enum case this
        # was measured against, but the rule this validator enforces is "does
        # not echo values it was given", not "does not echo values shaped
        # like a credential" -- the second is a guess about what a secret
        # looks like, and the first needs no guessing.
        if "minimum" in obj and value < obj["minimum"]:
            out.append(f"{where}: below the minimum {obj['minimum']}")
        if "maximum" in obj and value > obj["maximum"]:
            out.append(f"{where}: above the maximum {obj['maximum']}")
    elif type_ == "string":
        if "minLength" in obj and len(value) < obj["minLength"]:
            out.append(f"{where}: shorter than {obj['minLength']} characters")
        if "maxLength" in obj and len(value) > obj["maxLength"]:
            out.append(f"{where}: longer than {obj['maxLength']} characters")
