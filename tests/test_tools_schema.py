"""A validator that ignores a keyword is worse than no validator: the schema
published to the agent promises a constraint that nothing applies."""
from __future__ import annotations

import pytest

from hx.tools import schema

OBJ = {"type": "object", "additionalProperties": False,
       "properties": {"name": {"type": "string"}}}


def test_an_unimplemented_keyword_is_refused_at_registration_time():
    with pytest.raises(schema.SchemaError, match="not implemented"):
        schema.check_schema({"type": "string", "pattern": "^[a-z]+$"})


def test_metadata_keywords_are_accepted_because_they_constrain_nothing():
    schema.check_schema({"type": "string", "description": "the run kind"})


def test_an_object_schema_must_close_itself():
    with pytest.raises(schema.SchemaError, match="additionalProperties"):
        schema.check_schema({"type": "object", "properties": {}})


def test_required_must_name_a_declared_property():
    bad = {"type": "object", "additionalProperties": False,
           "properties": {"a": {"type": "string"}}, "required": ["b"]}
    with pytest.raises(schema.SchemaError, match="has no property"):
        schema.check_schema(bad)


def test_an_array_must_declare_items():
    with pytest.raises(schema.SchemaError, match="must declare items"):
        schema.check_schema({"type": "array"})


def test_nested_schemas_are_checked_too():
    nested = {"type": "object", "additionalProperties": False,
              "properties": {"inner": {"type": "string", "pattern": "x"}}}
    with pytest.raises(schema.SchemaError, match=r"params\.inner"):
        schema.check_schema(nested)


def test_a_valid_value_produces_no_problems():
    assert schema.validate(OBJ, {"name": "x"}) == []


def test_an_undeclared_argument_is_named_as_such():
    problems = schema.validate(OBJ, {"name": "x", "limit": 5})
    assert problems == ["args: limit is not an argument of this tool"]


def test_a_missing_required_argument_is_reported():
    req = dict(OBJ, required=["name"])
    assert schema.validate(req, {}) == ["args: name is required"]


def test_a_boolean_does_not_satisfy_integer():
    # isinstance(True, int) is True in Python. Without the explicit exclusion
    # `{"max_pages": true}` validates and then becomes arithmetic.
    ints = {"type": "object", "additionalProperties": False,
            "properties": {"n": {"type": "integer"}}}
    assert schema.validate(ints, {"n": True}) == [
        "args.n: expected integer, got bool"]
    assert schema.validate(ints, {"n": 3}) == []


def test_bounds_and_lengths_and_enums_are_enforced():
    s = {"type": "object", "additionalProperties": False, "properties": {
        "n": {"type": "integer", "minimum": 1, "maximum": 10},
        "s": {"type": "string", "minLength": 1, "maxLength": 3},
        "k": {"type": "string", "enum": ["a", "b"]},
    }}
    assert schema.validate(s, {"n": 0}) == ["args.n: 0 is below the minimum 1"]
    assert schema.validate(s, {"n": 11}) == ["args.n: 11 is above the maximum 10"]
    assert schema.validate(s, {"s": ""}) == ["args.s: shorter than 1 characters"]
    assert schema.validate(s, {"s": "abcd"}) == ["args.s: longer than 3 characters"]
    assert schema.validate(s, {"k": "c"}) == ["args.k: 'c' is not one of ['a', 'b']"]


def test_array_items_are_validated_by_position():
    s = {"type": "array", "items": {"type": "string"}}
    assert schema.validate(s, ["a", 2]) == ["args[1]: expected string, got int"]


def test_every_constraint_keyword_is_actually_implemented():
    # The guarantee this module rests on: CONSTRAINTS is not a wish list.
    # Each keyword below must change the answer for some value, or it is
    # accepted and ignored -- the exact hole check_schema exists to close.
    cases = {
        "type": ({"type": "string"}, 1),
        "enum": ({"enum": ["a"]}, "b"),
        "minimum": ({"type": "integer", "minimum": 1}, 0),
        "maximum": ({"type": "integer", "maximum": 1}, 2),
        "minLength": ({"type": "string", "minLength": 2}, "a"),
        "maxLength": ({"type": "string", "maxLength": 1}, "ab"),
        "items": ({"type": "array", "items": {"type": "string"}}, [1]),
        "properties": (OBJ, {"name": 1}),
        "additionalProperties": (OBJ, {"zzz": 1}),
        "required": (dict(OBJ, required=["name"]), {}),
    }
    assert set(cases) == schema.CONSTRAINTS
    for keyword, (sch, bad) in cases.items():
        assert schema.validate(sch, bad), f"{keyword} accepted a bad value"
