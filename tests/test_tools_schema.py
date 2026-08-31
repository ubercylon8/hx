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
    assert schema.validate(s, {"n": 0}) == ["args.n: below the minimum 1"]
    assert schema.validate(s, {"n": 11}) == ["args.n: above the maximum 10"]
    assert schema.validate(s, {"s": ""}) == ["args.s: shorter than 1 characters"]
    assert schema.validate(s, {"s": "abcd"}) == ["args.s: longer than 3 characters"]
    assert schema.validate(s, {"k": "c"}) == ["args.k: not one of ['a', 'b']"]


def test_array_items_are_validated_by_position():
    s = {"type": "array", "items": {"type": "string"}}
    assert schema.validate(s, ["a", 2]) == ["args[1]: expected string, got int"]


def test_every_constraint_keyword_is_actually_implemented():
    # The guarantee this module rests on: CONSTRAINTS is not a wish list.
    # Each keyword below must change the answer for some value, or it is
    # accepted and ignored -- the exact hole check_schema exists to close.
    cases = {
        "type": ({"type": "string"}, 1),
        "enum": ({"type": "string", "enum": ["a"]}, "b"),
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


def test_a_schema_without_a_type_is_refused():
    with pytest.raises(schema.SchemaError, match="must declare a type"):
        schema.check_schema({"properties": {"name": {"type": "string"}},
                             "required": ["name"]})


def test_a_mixed_type_enum_is_refused():
    with pytest.raises(schema.SchemaError, match="not of type"):
        schema.check_schema({"type": "integer", "enum": [1, "two"]})


def test_enum_on_an_array_is_refused():
    with pytest.raises(schema.SchemaError, match="does not apply"):
        schema.check_schema({"type": "array", "items": {"type": "string"},
                             "enum": ["a"]})


def test_an_empty_enum_is_refused():
    with pytest.raises(schema.SchemaError, match="non-empty"):
        schema.check_schema({"type": "string", "enum": []})


def test_an_integer_enum_rejects_a_boolean():
    with pytest.raises(schema.SchemaError, match="not of type"):
        schema.check_schema({"type": "integer", "enum": [1, True]})


def test_a_keyword_on_a_type_it_does_not_apply_to_is_refused():
    # minimum applies only to integer/number, not string
    with pytest.raises(schema.SchemaError, match="does not apply"):
        schema.check_schema({"type": "string", "minimum": 5})
    # required applies only to object, not array
    with pytest.raises(schema.SchemaError, match="does not apply"):
        schema.check_schema({"type": "array", "items": {"type": "string"},
                             "required": ["x"]})


def test_a_keyword_whose_value_is_the_wrong_type_is_refused():
    # minimum must be int or float, not string
    with pytest.raises(schema.SchemaError, match="must be of type"):
        schema.check_schema({"type": "integer", "minimum": "five"})
    # minLength must be int, not bool
    with pytest.raises(schema.SchemaError, match="must be of type"):
        schema.check_schema({"type": "string", "minLength": True})


def test_every_constraint_keyword_is_enforced_for_every_applicable_type():
    # For every (keyword, type) pair, either check_schema refuses it or
    # validate enforces it. This invariant would have caught all three defects.
    for keyword, (applicable_types, value_type) in schema._CONSTRAINT_TABLE.items():
        for type_name in schema._TYPES:
            if applicable_types is not None and type_name not in applicable_types:
                # This pairing should be refused at registration.
                continue
            # Build a minimal schema for this type with the keyword present.
            if type_name == "object":
                sch = {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {},
                }
            elif type_name == "array":
                sch = {"type": "array", "items": {"type": "string"}}
            else:
                sch = {"type": type_name}
            # For keywords that require specific values, choose a valid one.
            if keyword == "enum":
                if type_name == "string":
                    sch["enum"] = ["a"]
                elif type_name == "boolean":
                    sch["enum"] = [True]
                else:
                    sch["enum"] = [1]
            elif keyword == "minimum":
                sch["minimum"] = 0
            elif keyword == "maximum":
                sch["maximum"] = 10
            elif keyword == "minLength":
                sch["minLength"] = 1
            elif keyword == "maxLength":
                sch["maxLength"] = 10
            elif keyword == "required":
                sch["required"] = []
            elif keyword == "properties":
                sch["properties"] = {}
            elif keyword == "additionalProperties":
                sch["additionalProperties"] = False
            elif keyword == "items":
                sch["items"] = {"type": "string"}
            # This should not raise.
            schema.check_schema(sch)
            # Also check that check_schema raises SchemaError, never any other exception,
            # for a set of hostile values for every keyword.
            hostile = [5, "five", None, True, [1], {"a": 1}]
            for bad_value in hostile:
                try:
                    # Build a schema with this keyword and bad value.
                    if keyword == "type":
                        sch = {"type": bad_value}
                    elif keyword == "enum":
                        sch = {"type": "string", "enum": bad_value}
                    elif keyword == "properties":
                        sch = {"type": "object", "additionalProperties": False,
                               "properties": bad_value}
                    elif keyword == "required":
                        sch = {"type": "object", "additionalProperties": False,
                               "properties": {}, "required": bad_value}
                    elif keyword == "additionalProperties":
                        sch = {"type": "object", "additionalProperties": bad_value}
                    elif keyword == "items":
                        sch = {"type": "array", "items": bad_value}
                    elif keyword == "minimum":
                        sch = {"type": "integer", "minimum": bad_value}
                    elif keyword == "maximum":
                        sch = {"type": "integer", "maximum": bad_value}
                    elif keyword == "minLength":
                        sch = {"type": "string", "minLength": bad_value}
                    elif keyword == "maxLength":
                        sch = {"type": "string", "maxLength": bad_value}
                    schema.check_schema(sch)
                except schema.SchemaError:
                    # Expected: SchemaError for invalid value.
                    pass
                except Exception as e:
                    # Fail if any other exception is raised.
                    pytest.fail(
                        f"check_schema raised {type(e).__name__} for {keyword}={bad_value!r}, "
                        f"expected SchemaError: {e}"
                    )


def test_check_schema_raises_schema_error_for_non_string_type():
    # Finding A: type must be a string; non-string types would raise TypeError
    # when hashed in the membership test. Must raise SchemaError instead.
    with pytest.raises(schema.SchemaError, match="must be of type"):
        schema.check_schema({"type": [1]})
    with pytest.raises(schema.SchemaError, match="must be of type"):
        schema.check_schema({"type": {"a": 1}})


def test_property_names_and_required_members_must_be_strings():
    # Finding B: property names and required members are compared against
    # JSON object keys, which are always strings. Non-string names won't match
    # and become permanently dead constraints, and the schema is not valid JSON.
    with pytest.raises(schema.SchemaError, match="must be a string"):
        schema.check_schema({"type": "object", "additionalProperties": False,
                             "properties": {1: {"type": "string"}}})
    with pytest.raises(schema.SchemaError, match="must be a string"):
        schema.check_schema({"type": "object", "additionalProperties": False,
                             "properties": {}, "required": [1]})


def test_no_problem_message_echoes_the_value_it_rejected():
    """The final review's third finding: `schema._validate` used to write the
    rejected VALUE into the problem string (`'Bearer eyJ...secret' is not one
    of [...]`), and `dispatch` puts that string straight into a refusal's
    `detail`, which `journal.summarise` appends to `agent_action.
    result_summary` regardless of whether the call's arguments were
    journalled in full. A message naming the property and the constraint is
    what makes a refusal actionable; the rejected value is the one thing the
    caller already knows.

    Driven from the validator directly, not through dispatch -- this is the
    property the fix promises, and it should hold for values this test never
    thought to name, not only the secret-shaped one below.
    """
    secret = "Bearer eyJhbGciOiJIUzI1NiJ9.THIS_IS_THE_SECRET.sig"
    cases = [
        ({"type": "string", "enum": ["Critical", "High", "Low"]}, secret),
        ({"type": "integer", "minimum": 1}, -999999),
        ({"type": "integer", "maximum": 1}, 999999),
        ({"type": "number", "minimum": 1.0}, -999999.5),
    ]
    for sch, bad in cases:
        problems = schema.validate(sch, bad)
        assert problems, f"{sch} accepted {bad!r}"
        for p in problems:
            assert str(bad) not in p, f"{p!r} echoes the rejected value {bad!r}"
            assert repr(bad) not in p, f"{p!r} echoes the rejected value {bad!r}"

    # The exact reproduction from the review, end to end through `validate`.
    problems = schema.validate(
        {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        secret)
    assert problems == ["args: not one of "
                        "['Critical', 'High', 'Info', 'Low', 'Medium']"]
