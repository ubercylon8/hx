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
"""
from __future__ import annotations

from typing import Any


class SchemaError(Exception):
    """A schema this module cannot enforce in full."""


#: Keywords that constrain a value. Every one is implemented by `validate`, and
#: a test proves each changes the answer for some value.
CONSTRAINTS = frozenset({
    "type", "properties", "required", "additionalProperties",
    "enum", "items", "minimum", "maximum", "minLength", "maxLength",
})

#: Keywords that carry no constraint and are published to the agent as help.
#: Accepted precisely because they cannot widen what is accepted.
METADATA = frozenset({"description", "title", "default", "examples"})

_TYPES: dict[str, Any] = {
    "object": dict, "array": list, "string": str,
    "integer": int, "number": (int, float), "boolean": bool,
}


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
    # _validate dispatches required/properties/additionalProperties off "object",
    # items off "array", minimum/maximum off number types, minLength/maxLength off
    # "string", and enum off a scalar type. Without a type, every constraint in
    # the schema is inert. Measured: {"properties": {"name": ...}, "required":
    # ["name"]} accepts {} and 42. The same hole as an unimplemented keyword.
    if type_ is None:
        raise SchemaError(
            f"{where}: a schema must declare a type; {where} gives _validate "
            "nothing to dispatch on, so every constraint in it is inert"
        )
    if type_ not in _TYPES:
        raise SchemaError(f"{where}: unknown type {type_!r}")
    if "enum" in obj:
        # Refuse enums on containers (not meaningful in this subset) and
        # homogeneity errors: sorted() would raise TypeError on a mixed-type
        # enum like [1, "two"], and that's the same hole the module doctrine
        # exists to close. Also refuse the bool-is-not-int case.
        if type_ not in ("string", "integer", "number", "boolean"):
            raise SchemaError(
                f"{where}: enum on a {type_} is not meaningful in this subset"
            )
        enum_vals = obj.get("enum")
        if not enum_vals:
            raise SchemaError(f"{where}: enum must be non-empty")
        for member in enum_vals:
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
            check_schema(sub, where=f"{where}.{key}")
        for key in obj.get("required") or ():
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
        out.append(f"{where}: {value!r} is not one of {sorted(obj['enum'])}")
    if type_ == "object":
        props = obj.get("properties") or {}
        for key in obj.get("required") or ():
            if key not in value:
                out.append(f"{where}: {key} is required")
        for key in sorted(set(value) - set(props)):
            out.append(f"{where}: {key} is not an argument of this tool")
        for key, sub in props.items():
            if key in value:
                _validate(sub, value[key], f"{where}.{key}", out)
    elif type_ == "array":
        for i, item in enumerate(value):
            _validate(obj["items"], item, f"{where}[{i}]", out)
    elif type_ in ("integer", "number"):
        if "minimum" in obj and value < obj["minimum"]:
            out.append(f"{where}: {value} is below the minimum {obj['minimum']}")
        if "maximum" in obj and value > obj["maximum"]:
            out.append(f"{where}: {value} is above the maximum {obj['maximum']}")
    elif type_ == "string":
        if "minLength" in obj and len(value) < obj["minLength"]:
            out.append(f"{where}: shorter than {obj['minLength']} characters")
        if "maxLength" in obj and len(value) > obj["maxLength"]:
            out.append(f"{where}: longer than {obj['maxLength']} characters")
