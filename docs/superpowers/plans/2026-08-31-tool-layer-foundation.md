# Tool Layer (Foundation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tool *definition* — registry, schema validator, envelope,
journal, dispatcher — and the eleven tools that need no live Burp, reachable
through a `hx tool` CLI adapter.

**Architecture:** A `ToolSpec` holds a name, a JSON Schema for its arguments, a
handler, and two capability bits (`needs_egress`, `mutates`). A registry keyed
by name is the allowlist. One dispatcher validates, authorises in a published
order, calls the handler, and writes one `agent_action` row per call —
refusals included. Handlers are plain functions that neither validate nor
authorise nor journal, which is what lets the same tests drive the CLI adapter,
the MCP adapter (Plan B) and the v2 embedded loop.

**Tech Stack:** Python 3.12, `click`, `PyYAML`, `sqlite3`, `pytest`. **No new
dependencies.**

**Spec:** `docs/superpowers/specs/2026-08-31-tool-layer-design.md`
**Master spec:** `docs/superpowers/specs/2026-08-21-hx-design.md`
(§4 enforcement invariant, §5 data model, §8 tool layer, §12 reporting)

## Global Constraints

- **No new Python dependencies.** The project runs on `PyYAML>=6.0` and
  `click>=8.1`; the Java extension has none. This is why the JSON Schema
  validator is a subset written here rather than `jsonschema`.
- **The tool layer adds no security logic and no egress path.** Scope, rate,
  budget, dangerous-path, method allowlist and credential redaction all stay
  in the JVM (§4). A tool reports what came back.
- **The registry is the allowlist.** `engagement.create`, `surface.add` and
  `finding.set_status` are enforced by *having no entry*, never by a check.
- **The published decision order is**
  `not_registered → halted → missing_why → bad_args → no_session`.
  Earliest matching rule wins; each is terminal.
- **The five outcomes are** `ok · empty · unavailable · refused · error`.
  `empty` means the tool ran and matched nothing; `unavailable` means it could
  not run. Never collapse them.
- **`reason` comes from a closed vocabulary**, never free text. Free text
  cannot be counted, and the report counts refusals. `refused` takes
  `not_registered`, `halted`, `missing_why`, `bad_args`, `run_open`;
  `unavailable` takes `no_session`, `no_run`, `not_implemented`; `error` takes
  `internal`.
- **A credential value never reaches `agent_action`.** Identity is passed by
  name; `hx.identity.resolve` runs below this layer and no tool returns a
  `Resolved`.
- **List defaults:** limit 50, hard ceiling 500 — with one named exception:
  `run.journal` defaults to 20 (`JOURNAL_DEFAULT`), because it answers "what
  have I already tried" and is read rather than paged through. An exception
  visible only inside one task's code block would be a constraint the plan
  states and the code quietly contradicts, so it is stated here.
- **`args_blob`:** inline JSON to 4096 bytes, `sha256:<digest>` above it.
- Python style follows the repo: module docstring first (no path-comment
  header), docstrings that argue rather than describe, `from __future__ import
  annotations`.
- **A block describing a future APPEND to a file an earlier task creates must
  not carry a `# path` marker.** `tests/test_plan_matches_repo.py` skips a
  marked block only while its file does not exist; once an earlier task creates
  the file, a marked block describing content that has not been written yet is
  compared and fails — reporting the later task's name while the earlier task
  is what just landed. Such blocks are written unmarked (first line is code,
  never a comment) and the prose names the file instead. This applies to
  `src/hx/tools/impl/run.py` (Task 7), `src/hx/tools/impl/__init__.py`
  (Task 11), `src/hx/store/records.py` (Task 9) and `src/hx/cli.py` (Task 11).
- Run the suite with `.venv/bin/pytest -q`. It must stay green: the baseline is
  **1649 passed, 1 skipped, 44 deselected**.

---

## File Structure

**Created:**

| File | Responsibility |
|---|---|
| `src/hx/tools/__init__.py` | package marker; imports `impl` so registration happens on import |
| `src/hx/tools/spec.py` | `ToolSpec`, `V1_TOOL_NAMES`, `NEVER_AGENT_FACING` |
| `src/hx/tools/registry.py` | `TOOLS`, `register`, `lookup` — the allowlist |
| `src/hx/tools/schema.py` | fail-closed JSON Schema subset |
| `src/hx/tools/envelope.py` | the five outcomes, `page()`, closed `REASONS` |
| `src/hx/tools/errors.py` | `ToolRefused`, `ToolUnavailable` |
| `src/hx/tools/journal.py` | the `agent_action` writer |
| `src/hx/tools/dispatch.py` | `ToolContext`, `dispatch()` |
| `src/hx/tools/impl/run.py` | `run.start` `run.finish` `run.journal` `run.resume` |
| `src/hx/tools/impl/surface.py` | `surface.query` `surface.detail` |
| `src/hx/tools/impl/finding.py` | `finding.record` `finding.query` `evidence.attach` |
| `src/hx/tools/impl/checks.py` | `checks.list` |
| `src/hx/tools/impl/report.py` | `report.render` |
| `src/hx/tools/adapters/cli.py` | `hx tool <name>` |

**Modified:** `src/hx/store/records.py` (widen `record_evidence`),
`src/hx/cli.py` (register the `tool` command), `tests/test_plan_matches_repo.py`
(`EXPECTED_BLOCKS`).

**Not touched:** anything under `extension/`. This plan writes no Java.

---

### Task 1: The schema validator that refuses what it cannot enforce

**Files:**
- Create: `src/hx/tools/__init__.py`, `src/hx/tools/schema.py`
- Test: `tests/test_tools_schema.py`

**Interfaces:**
- Consumes: nothing. This module imports only `typing`.
- Produces: `schema.SchemaError`; `schema.check_schema(obj, *, where="params") -> None`
  (raises); `schema.validate(schema, value, *, where="args") -> list[str]`
  (empty list means valid); `schema.CONSTRAINTS`; `schema.METADATA`.

It comes first because `registry.register` calls `check_schema`, and writing
the registry twice would leave Task 2's block stale in this plan.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_schema.py -- the whole file
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
        "minItems": ({"type": "array", "items": {"type": "string"},
                     "minItems": 2}, ["a"]),
        "maxItems": ({"type": "array", "items": {"type": "string"},
                     "maxItems": 1}, ["a", "b"]),
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
            elif keyword == "minItems":
                sch["minItems"] = 0
            elif keyword == "maxItems":
                sch["maxItems"] = 10
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
                    elif keyword == "minItems":
                        sch = {"type": "array", "items": {"type": "string"},
                               "minItems": bad_value}
                    elif keyword == "maxItems":
                        sch = {"type": "array", "items": {"type": "string"},
                               "maxItems": bad_value}
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
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_schema.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.tools'`

- [ ] **Step 3: Write `src/hx/tools/__init__.py`**

```python
# src/hx/tools/__init__.py -- the whole file
"""The tool layer: one definition, many adapters.

Spec section 8 opens with the architecture -- "One definition; an MCP adapter
in v1 and an embedded loop later" -- so what is built here is the DEFINITION.
Every transport is a thin projection of `registry.TOOLS`.

Importing this package does NOT import the handlers. `hx.tools.impl` does that,
and an adapter imports it explicitly, so a test can exercise the registry
machinery against specs of its own without eleven real tools appearing in it.
"""
```

- [ ] **Step 4: Write `src/hx/tools/schema.py`**

```python
# src/hx/tools/schema.py -- the whole file
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
```

- [ ] **Step 5: Run the tests**

Run: `.venv/bin/pytest tests/test_tools_schema.py -q`
Expected: PASS, 13 tests.

- [ ] **Step 6: Run the whole suite and commit**

```bash
.venv/bin/pytest -q
git add src/hx/tools/__init__.py src/hx/tools/schema.py tests/test_tools_schema.py
git commit -m "feat(tools): a schema subset that refuses what it cannot enforce"
```

---
### Task 2: The spec and the registry

**Files:**
- Create: `src/hx/tools/spec.py`, `src/hx/tools/registry.py`
- Test: `tests/test_tools_registry.py`

**Interfaces:**
- Consumes: `schema.check_schema`, `schema.SchemaError` (Task 1).
- Produces: `spec.ToolSpec(name, summary, params, handler, needs_egress=False,
  mutates=False)` with derived `.requires_why`; `spec.V1_TOOL_NAMES` (17 names);
  `spec.NEVER_AGENT_FACING` (3 names); `registry.TOOLS: dict[str, ToolSpec]`;
  `registry.register(ToolSpec) -> ToolSpec`; `registry.lookup(str) -> ToolSpec | None`;
  `registry.RegistryError`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_registry.py -- the whole file as of Task 2
"""The registry is the allowlist, so its refusals are the security story."""
from __future__ import annotations

import pytest

from hx.tools import registry, schema, spec

EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}


def _spec(name: str, **kw) -> spec.ToolSpec:
    return spec.ToolSpec(name=name, summary="x", params=EMPTY,
                         handler=lambda ctx: None, **kw)


@pytest.fixture
def clean_registry(monkeypatch):
    """A registry of our own.

    `hx.tools.impl` registers the real tools at import, and pytest imports
    every test module before running any test -- so by the time this file runs,
    `checks.list` and `surface.query` are already taken. Rebinding the module
    attribute gives these tests an empty one; `register` and `lookup` both
    resolve the global at call time, so they follow it.
    """
    monkeypatch.setattr(registry, "TOOLS", {})
    return registry.TOOLS


def test_the_two_name_sets_are_disjoint():
    # If a name were in both, `register` would refuse it twice with two
    # different explanations and one of them would be wrong.
    assert not (spec.V1_TOOL_NAMES & spec.NEVER_AGENT_FACING)


def test_there_are_seventeen_v1_names():
    assert len(spec.V1_TOOL_NAMES) == 17


def test_a_name_outside_the_v1_set_cannot_be_registered():
    with pytest.raises(registry.RegistryError, match="not one of the seventeen"):
        registry.register(_spec("surface.delete_everything"))


def test_a_human_act_is_refused_by_name_and_says_so():
    # Refused by the v1-set rule too, but the message an operator reads has to
    # be the one that explains WHY, not merely that the name is unknown.
    for name in sorted(spec.NEVER_AGENT_FACING):
        with pytest.raises(registry.RegistryError, match="human act"):
            registry.register(_spec(name))


def test_registering_twice_is_refused(clean_registry):
    registry.register(_spec("checks.list"))
    with pytest.raises(registry.RegistryError, match="already registered"):
        registry.register(_spec("checks.list"))


def test_a_schema_the_validator_cannot_enforce_is_refused_here(clean_registry):
    # The point of check_schema being called at REGISTRATION: an unenforceable
    # schema fails a test run, never an agent's call.
    bad = {"type": "object", "additionalProperties": False,
           "properties": {"q": {"type": "string", "pattern": "^x"}}}
    with pytest.raises(schema.SchemaError, match="not implemented"):
        registry.register(spec.ToolSpec(name="surface.query", summary="x",
                                        params=bad, handler=lambda ctx: None))
    assert "surface.query" not in registry.TOOLS


def test_lookup_of_an_unregistered_name_is_none_not_an_error():
    # The dispatcher turns this into `refused / not_registered`; raising here
    # would make an ordinary agent mistake look like a defect in hx.
    assert registry.lookup("nothing.at.all") is None


def test_requires_why_is_derived_from_mutates():
    assert _spec("run.start", mutates=True).requires_why is True
    assert _spec("run.journal").requires_why is False


def test_a_toolspec_may_not_be_subclassed():
    """The third door into `requires_why`, found by the Task 2 review.

    `frozen=True` already refuses `dataclasses.replace` and
    `object.__setattr__`. A subclass overriding the property was open, and it
    registered cleanly: a mutating tool reporting `requires_why False` is one
    the dispatcher never asks a `why` for.
    """
    with pytest.raises(TypeError, match="may not be subclassed"):
        class Evil(spec.ToolSpec):
            requires_why = property(lambda self: False)
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_registry.py -q`
Expected: FAIL — `ImportError: cannot import name 'registry' from 'hx.tools'`

- [ ] **Step 3: Write `src/hx/tools/spec.py`**

```python
# src/hx/tools/spec.py -- the whole file
"""What a tool IS, before any transport knows about it.

A `ToolSpec` is what the registry holds, what the dispatcher reads and what an
adapter projects. `params` is JSON Schema because MCP's `tools/list` must
publish it verbatim -- so the schema is the interface, not a convenience.

THE TWO NAME SETS BELOW ARE ENFORCEMENT, NOT DOCUMENTATION. Section 8 names
seventeen tools and three that are deliberately not agent-facing; both lists
live here as data that `hx.tools.registry` refuses against, so neither can
drift into being a comment nobody checks.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Callable

#: Spec section 8's seventeen. A name outside this set cannot be registered.
#: Plan A of the tool layer builds eleven of them; the other six carry the
#: `needs_egress` bit and arrive with the session bracket in Plan B. The full
#: seventeen are listed from the start so what is missing is visible.
V1_TOOL_NAMES = frozenset({
    "run.start", "run.finish", "run.journal", "run.resume",
    "surface.query", "surface.detail",
    "http.send", "http.grep", "http.body", "http.replay_as",
    "crawl.run",
    "checks.list", "scan.run",
    "finding.record", "finding.query",
    "evidence.attach",
    "report.render",
})

#: Section 8: "Not agent-facing: `engagement.create`, `surface.add`,
#: `finding.set_status`. Creating an engagement and confirming a finding are
#: human acts; they live in the CLI and the web app."
#:
#: DISJOINT FROM THE SET ABOVE, asserted by a test. The registry refuses both
#: sets separately even though the first refusal already covers these three,
#: because the two messages say different things to whoever hits them -- "that
#: is not a v1 tool" and "that is a human act" -- and the day `V1_TOOL_NAMES`
#: grows is the day the second stops being implied by the first.
NEVER_AGENT_FACING = frozenset({
    "engagement.create", "surface.add", "finding.set_status",
})


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    """One tool: its name, its arguments, and what it is allowed to do.

    `needs_egress` and `mutates` are the only two capability bits, and the
    DISPATCHER reads them, never the handler. A handler that decided for itself
    whether it needed a session, or whether a `why` was required, would be a
    second place the rule lives and a first place it can be forgotten.
    """

    name: str
    summary: str
    params: dict[str, Any]
    handler: Callable[..., Any]
    needs_egress: bool = False
    mutates: bool = False

    def __init_subclass__(cls, **kwargs) -> None:
        """A ToolSpec has no subclasses, and that is load-bearing.

        THE THIRD DOOR INTO `requires_why`. `frozen=True` blocks the first two
        -- `dataclasses.replace` and `object.__setattr__` both raise -- and a
        subclass overriding the property was open until the Task 2 review
        found it. MEASURED: `class Evil(ToolSpec): requires_why = property(
        lambda self: False)` constructed with `mutates=True`, registered
        cleanly, and reported `requires_why False` -- a state-changing tool the
        dispatcher would never ask a `why` for, which is Principle 5 defeated
        by a subclass rather than by a typo.

        Nothing needs to subclass this: a tool varies by its data, never by its
        type. So the door is closed rather than watched.
        """
        raise TypeError(
            "ToolSpec may not be subclassed; requires_why is derived from "
            "mutates and an override would un-derive it")

    @property
    def requires_why(self) -> bool:
        """Principle 5: "state-changing tools require `why`".

        DERIVED, never stored. A separate field could be set False on a
        mutating tool, and then the rule would hold everywhere except the one
        place someone typed it wrong. See `__init_subclass__` for the other
        way that was possible.
        """
        return self.mutates
```

- [ ] **Step 4: Write `src/hx/tools/registry.py`**

```python
# src/hx/tools/registry.py -- the whole file
"""The allowlist.

WHAT IS NOT HERE HAS NO CODE PATH. Section 8's "not agent-facing" list is
enforced by those three names having no entry, so a future refactor cannot
forget a check that was never written as a check. This is the same move
section 4 makes inside the JVM -- two enforcement points, both unavoidable --
and the same one `IdentityRegistry.register` makes by keeping the three-name
header allowlist at the one door rather than at each caller.

`TOOLS` is module state, which is the one thing here worth arguing about: it
makes registration an import side effect, and a test that registers must clean
up after itself. The alternative -- a registry instance threaded through every
adapter -- buys an isolation nothing needs, because the set of tools is fixed
at build time and identical in every process.
"""
from __future__ import annotations

from . import schema
from .spec import NEVER_AGENT_FACING, V1_TOOL_NAMES, ToolSpec


class RegistryError(Exception):
    """A tool that may not be registered, refused at registration."""


#: name -> spec. Populated by `hx.tools.impl` at import.
TOOLS: dict[str, ToolSpec] = {}


def register(tool: ToolSpec) -> ToolSpec:
    """Add `tool`, or refuse.

    Order matters only for the first two rules: the human-act refusal comes
    FIRST so its message is the one an author of `finding.set_status` reads.
    The v1-set rule would also catch those three names, and would explain
    nothing.

    The schema check runs before insertion, so a tool whose schema this
    validator cannot enforce is absent rather than half-registered.
    """
    if tool.name in NEVER_AGENT_FACING:
        raise RegistryError(
            f"{tool.name} is a human act, not a tool: spec section 8 keeps "
            "creating an engagement and confirming a finding in the CLI and "
            "the web app. There is no agent-facing form of it."
        )
    if tool.name not in V1_TOOL_NAMES:
        raise RegistryError(
            f"{tool.name} is not one of the seventeen tools spec section 8 "
            "names. Add it to the spec before adding it here."
        )
    if tool.name in TOOLS:
        raise RegistryError(f"{tool.name} is already registered")
    schema.check_schema(tool.params, where=f"{tool.name}.params")
    TOOLS[tool.name] = tool
    return tool


def lookup(name: str) -> ToolSpec | None:
    """The spec, or None.

    None rather than a raise: an agent naming a tool that does not exist is an
    ordinary mistake the dispatcher answers with `refused / not_registered`,
    and an exception here would make it look like a defect in hx.
    """
    return TOOLS.get(name)
```

- [ ] **Step 5: Run the tests, then the suite, then commit**

```bash
.venv/bin/pytest tests/test_tools_registry.py -q     # 8 pass
.venv/bin/pytest -q
git add src/hx/tools/spec.py src/hx/tools/registry.py tests/test_tools_registry.py
git commit -m "feat(tools): the registry is the allowlist"
```

---

### Task 3: The envelope, the five outcomes, and the two refusals

**Files:**
- Create: `src/hx/tools/envelope.py`, `src/hx/tools/errors.py`
- Test: `tests/test_tools_envelope.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `envelope.OUTCOMES`, `envelope.REASONS`, `envelope.DEFAULT_LIMIT` (50),
  `envelope.MAX_LIMIT` (500), `envelope.Envelope(tool, outcome, result, reason,
  detail)` with `.as_dict()` and `.ran`; `envelope.answered(tool, result)`;
  `envelope.refused(tool, reason, detail=None)`;
  `envelope.unavailable(tool, reason, detail=None)`;
  `envelope.failed(tool, detail)`;
  `envelope.page(rows, *, total, limit, cursor_of=None, facets=None) -> dict`;
  `errors.ToolError`, `errors.ToolRefused`, `errors.ToolUnavailable`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_envelope.py -- the whole file
"""Design section 4: `empty` and `unavailable` are different facts, and the
tool layer is where an agent first has the chance to confuse them."""
from __future__ import annotations

import pytest

from hx.tools import envelope, errors


def test_the_five_outcomes_are_exactly_the_designs_five():
    assert envelope.OUTCOMES == ("ok", "empty", "unavailable", "refused", "error")


def test_a_ran_outcome_may_not_carry_a_reason():
    with pytest.raises(ValueError, match="ran"):
        envelope.Envelope(tool="t", outcome="ok", reason="halted")


def test_a_non_ran_outcome_must_carry_a_reason_from_the_closed_set():
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="refused", reason="because I said so")


def test_empty_is_decided_from_the_result_not_by_the_handler():
    assert envelope.answered("t", []).outcome == "empty"
    assert envelope.answered("t", None).outcome == "empty"
    assert envelope.answered("t", ["a"]).outcome == "ok"
    assert envelope.answered("t", {"id": "s-1"}).outcome == "ok"


def test_a_page_with_no_total_is_empty_and_one_with_a_total_is_not():
    # A cursor past the end returns zero rows out of a non-zero total. The
    # QUERY matched things; this page did not. That is `ok`, not `empty` --
    # answering `empty` there would tell an agent the surface set is bare.
    page = envelope.page([], total=0, limit=50)
    assert envelope.answered("t", page).outcome == "empty"
    page = envelope.page([], total=12, limit=50)
    assert envelope.answered("t", page).outcome == "ok"


def test_the_page_envelope_has_principle_threes_six_keys():
    page = envelope.page(["a", "b"], total=2, limit=50)
    assert set(page) == {"rows", "returned", "total", "truncated",
                         "next_cursor", "facets"}
    assert page["returned"] == 2 and page["truncated"] is False


def test_truncation_is_known_from_one_extra_row_not_from_the_total():
    # The caller fetches limit+1. Comparing `returned < total` instead would
    # call every cursored page truncated, including the last one.
    page = envelope.page(["a", "b", "c"], total=99, limit=2,
                         cursor_of=lambda row: f"c-{row}")
    assert page["returned"] == 2
    assert page["rows"] == ["a", "b"]
    assert page["truncated"] is True
    assert page["next_cursor"] == "c-b"


def test_the_last_page_has_no_cursor():
    page = envelope.page(["a"], total=1, limit=2, cursor_of=lambda row: "never")
    assert page["truncated"] is False and page["next_cursor"] is None


def test_a_limit_above_the_ceiling_is_refused():
    with pytest.raises(ValueError, match="500"):
        envelope.page([], total=0, limit=501)


def test_as_dict_is_the_wire_shape():
    got = envelope.unavailable("crawl.run", "not_implemented", "no crawler").as_dict()
    assert got == {"tool": "crawl.run", "outcome": "unavailable",
                   "reason": "not_implemented", "detail": "no crawler",
                   "result": None}


def test_a_tool_error_refuses_a_reason_outside_the_vocabulary():
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolRefused("whatever")


def test_the_two_handler_exceptions_carry_their_outcomes():
    assert errors.ToolRefused("halted").outcome == "refused"
    assert errors.ToolUnavailable("no_session").outcome == "unavailable"


def test_cross_partition_reasons_are_refused_in_envelope():
    # "no_session" belongs to unavailable, not refused
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="refused", reason="no_session")
    # "halted" belongs to refused, not unavailable
    with pytest.raises(ValueError, match="closed vocabulary"):
        envelope.Envelope(tool="t", outcome="unavailable", reason="halted")


def test_cross_partition_reasons_are_refused_in_exceptions():
    # "no_session" belongs to unavailable, not refused
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolRefused("no_session")
    # "halted" belongs to refused, not unavailable
    with pytest.raises(ValueError, match="closed vocabulary"):
        errors.ToolUnavailable("halted")


def test_every_reason_belongs_to_exactly_one_outcome():
    # Each reason appears in exactly one outcome's set
    all_reasons = set()
    for outcome, reasons in envelope.REASONS_FOR.items():
        overlap = all_reasons & reasons
        assert not overlap, f"Reason(s) {overlap} appear in multiple outcomes"
        all_reasons.update(reasons)
    # REASONS is exactly the union of all reason sets
    assert envelope.REASONS == all_reasons


def test_envelope_may_not_be_subclassed():
    with pytest.raises(TypeError, match="Envelope may not be subclassed"):
        class Evil(envelope.Envelope):
            pass


def test_parse_offset_is_none_for_no_cursor():
    assert envelope.parse_offset(None) == 0


def test_parse_offset_reads_back_what_it_was_given():
    assert envelope.parse_offset("o-50") == 50
    assert envelope.parse_offset("o-0") == 0


def test_parse_offset_refuses_a_cursor_from_nowhere():
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset("nonsense")
    assert exc.value.reason == "bad_args"


def test_parse_offset_refuses_an_overflowing_offset_before_sqlite_ever_sees_it():
    # `int("9" * 20)` succeeds -- Python ints have no ceiling -- but SQLite
    # binds an offset as a signed 64-bit C integer and raises `OverflowError`
    # the moment the query runs. Uncaught, that lands in dispatch's generic
    # `except Exception` and answers `error / internal`, telling the agent hx
    # is broken when its cursor was merely implausible. `parse_offset` catches
    # it here instead, as an ordinary `bad_args` refusal.
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}{'9' * 20}")
    assert exc.value.reason == "bad_args"
    # Comfortably inside the bound is still fine.
    assert envelope.parse_offset(
        f"{envelope.CURSOR_PREFIX}{envelope.MAX_OFFSET}") == envelope.MAX_OFFSET
    with pytest.raises(errors.ToolRefused):
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}{envelope.MAX_OFFSET + 1}")


def test_parse_offset_refuses_a_unicode_digit_that_isdigit_would_have_missed():
    # "²" (superscript two) answers True to `str.isdigit()` -- it IS a
    # digit, by Unicode, just not one `int()` accepts in base 10 -- so a
    # cursor built from it used to pass the digit check and then raise
    # `ValueError` two lines later, inside `int()`.
    assert "²".isdigit()
    with pytest.raises(errors.ToolRefused) as exc:
        envelope.parse_offset(f"{envelope.CURSOR_PREFIX}²")
    assert exc.value.reason == "bad_args"


def test_a_non_ran_envelope_may_not_carry_a_result():
    # Non-ran outcomes cannot carry results
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="refused", reason="halted",
                         result={"leaked": "data"})
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="unavailable", reason="no_session",
                         result=[])
    with pytest.raises(ValueError, match="did not run"):
        envelope.Envelope(tool="t", outcome="error", reason="internal",
                         result="error details")
    # But result=None is allowed and will be the default
    e = envelope.Envelope(tool="t", outcome="error", reason="internal")
    assert e.result is None
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_envelope.py -q`
Expected: FAIL — `ImportError: cannot import name 'envelope' from 'hx.tools'`

- [ ] **Step 3: Write `src/hx/tools/envelope.py`**

```python
# src/hx/tools/envelope.py -- the whole file
"""The one shape every tool answers in, and the five things it can say.

PRINCIPLE 4 SAYS THE TRI-STATE HOLDS AT EVERY LAYER, and section 12 says why:
a report that cannot distinguish "tested, clean" from "never reached" is worse
than no report. `check_run.verdict` already carries that distinction for
checks. Without it HERE, an agent whose `surface.query` returned nothing
because the engagement is empty writes the same sentence as one whose query
returned nothing because the tool could not run -- and section 12's failure
arrives one layer above the layer that was hardened against it.

So `empty` and `unavailable` are separate outcomes, and `answered` decides
between `ok` and `empty` from the RESULT rather than leaving each handler to
spell it. Two handlers spelling "nothing matched" two ways is the same defect
one layer down.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any, Callable, Sequence

#: Design section 4. `ok` and `empty` both mean the tool RAN; `unavailable`
#: means it could not; `refused` means a gate said no; `error` is a defect.
OUTCOMES = ("ok", "empty", "unavailable", "refused", "error")

#: Closed, because the report counts refusals and free text cannot be counted.
#: Each outcome has its own set of reasons; nothing that crosses a boundary
#: can construct. Before the review, REASONS was a flat frozenset with comment
#: groups, and reasons from neighbouring outcomes constructed cleanly:
#: `ToolRefused("no_session")` built, though "no_session" is unavailable's.
#: The report counts refusals by reason -- a cross-partition reason corrupts a
#: client-facing number. Twelve tests passed with this open because only one
#: tried a reason outside REASONS entirely; none crossed between groups.
#: WIDENED FOR `http.send` (Task 4): the wire's own refusal classes now flow
#: through, unchanged, from `hx.tools.impl.http.REASON_FOR_CLASS`. The split
#: between the two outcomes is not arbitrary. REFUSED is "something decided
#: no" -- scope, method, dangerous-path, rate and budget are the extension's
#: POLICY answering, and a client-facing count of refusals is a statement
#: about scope discipline. UNAVAILABLE is "no answer came back" -- a timeout,
#: a dropped bridge or an unconfigured extension decided NOTHING, and counting
#: those as refusals would put network weather into a number an operator
#: reads as policy. Both are `ran=False`, so neither can be misread as a clean
#: result; what differs is what the report is entitled to say about them.
REASONS_FOR = {
    "refused": frozenset({
        "not_registered", "halted", "missing_why", "bad_args", "run_open",
        "scope_denied", "method_denied", "dangerous_denied", "rate_limited",
        "budget_exhausted", "bad_frame", "wrong_run_kind",
        # WIDENED AGAIN BY RULING 19, and for the same reason as the first
        # widening: these are the rest of what the extension can put on an
        # `error` frame, and nine of them were falling through to
        # `unavailable / transport_error` -- a policy denial counted as
        # network weather in the one number an operator reads as scope
        # discipline. `tests/test_tools_http.py` compares this side against
        # the emit sites the Java actually carries.
        "unmanaged_credential", "unknown_identity", "identity_origin",
        "unknown_frame", "protocol_mismatch", "engagement_mismatch",
        "bad_config", "bad_identity", "stale_generation"}),
    "unavailable": frozenset({
        "no_session", "no_run", "not_implemented", "identity_dead",
        "identity_unresolved", "transport_error", "timeout", "bridge_lost",
        "not_configured", "unreadable"}),
    "error": frozenset({"internal"}),
}

#: Union of all reason sets, used by `answered` and other generic code that
#: does not know the outcome in advance.
REASONS = frozenset().union(*REASONS_FOR.values())

#: Principle 3: "a tool that can return 3,400 rows must never do so by
#: default."
DEFAULT_LIMIT = 50
MAX_LIMIT = 500


@dataclasses.dataclass(frozen=True)
class Envelope:
    """What every tool returns, list tool or not."""

    tool: str
    outcome: str
    result: Any = None
    reason: str | None = None
    detail: str | None = None

    def __init_subclass__(cls, **kwargs) -> None:
        """An Envelope has no subclasses, and that is load-bearing.

        The `ran` property decides whether a `reason` is permitted. A subclass
        overriding `ran` produces a `refused` envelope that exits 0, and a
        shell or CI job reads a refusal as success. `adapters/cli.py` sets the
        process exit status from `ran`, so the fix is not a rule but a closing.
        """
        raise TypeError(
            "Envelope may not be subclassed; ran is derived from outcome and "
            "an override would un-derive it")

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(
                f"{self.outcome!r} is not an outcome; the design names {OUTCOMES}")
        if self.ran:
            if self.reason is not None:
                # A tool that ran has nothing to excuse. Allowing a reason here
                # would let `ok / halted` exist, and something downstream would
                # eventually read the reason and believe it.
                raise ValueError(
                    f"{self.outcome!r} means the tool ran; it may not carry a reason")
        else:
            # Non-ran outcomes: unavailable, refused, error
            if self.reason not in REASONS_FOR.get(self.outcome, frozenset()):
                raise ValueError(
                    f"{self.reason!r} is not in the closed vocabulary "
                    f"{sorted(REASONS_FOR.get(self.outcome, frozenset()))}; "
                    f"the report counts refusals by reason")
            if self.result is not None:
                raise ValueError(
                    f"{self.outcome!r} means the tool did not run; "
                    f"it may not carry a result")

    @property
    def ran(self) -> bool:
        """Whether the tool executed. `empty` did; `unavailable` did not."""
        return self.outcome in ("ok", "empty")

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "outcome": self.outcome,
                "reason": self.reason, "detail": self.detail,
                "result": self.result}


def answered(tool: str, result: Any) -> Envelope:
    """`ok`, or `empty` when the tool ran and matched nothing.

    A PAGE ENVELOPE ANSWERS BY ITS `total`, not by its `returned`. A cursor
    past the end returns zero rows out of a non-zero total: the query matched
    things and this page did not, which is `ok`. Answering `empty` there would
    tell an agent the surface set is bare when it is merely finished.
    """
    if isinstance(result, dict) and "returned" in result and "total" in result:
        empty = result["total"] == 0
    else:
        empty = result is None or (
            isinstance(result, (list, tuple, dict, str)) and not result)
    return Envelope(tool=tool, outcome="empty" if empty else "ok", result=result)


def refused(tool: str, reason: str, detail: str | None = None) -> Envelope:
    return Envelope(tool=tool, outcome="refused", reason=reason, detail=detail)


def unavailable(tool: str, reason: str, detail: str | None = None) -> Envelope:
    return Envelope(tool=tool, outcome="unavailable", reason=reason, detail=detail)


def failed(tool: str, detail: str) -> Envelope:
    """A defect in hx, not a decision about the request."""
    return Envelope(tool=tool, outcome="error", reason="internal", detail=detail)


def page(rows: Sequence[Any], *, total: int, limit: int,
         cursor_of: Callable[[Any], str] | None = None,
         facets: dict[str, Any] | None = None) -> dict[str, Any]:
    """Principle 3's uniform list envelope.

    `rows` MUST hold up to `limit + 1` rows: the extra one is how "there is
    more" is known. The obvious alternative -- `truncated = returned < total`
    -- calls every cursored page truncated, the last one included, so an agent
    following cursors never learns it has finished.
    """
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}, got {limit}")
    kept = list(rows[:limit])
    truncated = len(rows) > limit
    return {
        "rows": kept,
        "returned": len(kept),
        "total": total,
        "truncated": truncated,
        "next_cursor": cursor_of(kept[-1]) if truncated and cursor_of and kept
                       else None,
        "facets": facets or {},
    }


#: Every list tool that pages by offset uses this cursor shape, `o-<n>`. One
#: constant so `surface.query` and `finding.query` cannot drift into two
#: prefixes for the same idea -- which is exactly what their two `_offset`
#: functions had started to do before this fix.
CURSOR_PREFIX = "o-"

#: SQLite binds an offset as a signed 64-bit C integer and raises
#: `OverflowError` past that range. Uncaught, that lands in `dispatch`'s
#: generic `except Exception` and answers `error / internal` -- telling the
#: agent hx is broken when its cursor was merely implausible. No real
#: engagement's row count comes close to this, so a cursor naming more is
#: refused as `bad_args` before it ever reaches a query.
MAX_OFFSET = 1_000_000_000

#: What `int(s, 10)` actually parses. `str.isdigit()` is NOT this: it answers
#: True for `"²"` (superscript two) -- a digit BY UNICODE, not one base
#: 10 accepts -- so a cursor built from it passed the old digit check and
#: `int()` then raised `ValueError` two lines later. Anchored, so this never
#: matches a substring of something longer.
_CURSOR_DIGITS = re.compile(r"[0-9]+")


def parse_offset(cursor: str | None) -> int:
    """The offset an `o-<n>` cursor encodes, or 0 for none.

    THE ONE COPY. `surface.query` and `finding.query` each carried their own
    `_offset`, with divergent refusal messages, and neither bounded the
    result nor restricted the digit check to ASCII -- the final whole-branch
    review's item 2. Both defects were shared by construction: any cursor
    parser built this way would have had them, so the fix is one function
    both import, not two patches that could drift apart again.

    RAISES `ToolRefused`, imported inside the function rather than at module
    level: `hx.tools.errors` imports `REASONS_FOR` from this module, so a
    top-level import back here would be a cycle. By the time anything CALLS
    this function both modules have finished importing, so the deferred
    import inside it is safe where one at the top would not be.
    """
    from .errors import ToolRefused

    if cursor is None:
        return 0
    digits = cursor[len(CURSOR_PREFIX):]
    if not cursor.startswith(CURSOR_PREFIX) or not _CURSOR_DIGITS.fullmatch(digits):
        raise ToolRefused(
            "bad_args",
            f"{cursor!r} is not a cursor from this tool; pass back the "
            "next_cursor you were given, or omit it to start over")
    offset = int(digits)
    if offset > MAX_OFFSET:
        raise ToolRefused(
            "bad_args",
            f"{cursor!r} names an offset further than any real engagement "
            "reaches; pass back the next_cursor you were given, or omit it "
            "to start over")
    return offset
```

- [ ] **Step 4: Write `src/hx/tools/errors.py`**

```python
# src/hx/tools/errors.py -- the whole file
"""The two ways a handler may decline, and the vocabulary it declines in.

A HANDLER RAISES; THE DISPATCHER BUILDS THE ENVELOPE. That split is what makes
design section 4 a claim about every tool rather than about the ones that
remembered: there is exactly one place the outer shape is written, and a
handler cannot answer in a shape of its own.
"""
from __future__ import annotations

from .envelope import REASONS_FOR


class ToolError(Exception):
    """A handler declining, with a reason from the closed vocabulary."""

    outcome = "error"

    def __init__(self, reason: str, detail: str | None = None) -> None:
        if reason not in REASONS_FOR.get(self.outcome, frozenset()):
            raise ValueError(
                f"{reason!r} is not in the closed vocabulary "
                f"{sorted(REASONS_FOR.get(self.outcome, frozenset()))}; "
                f"the report counts refusals by reason")
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class ToolRefused(ToolError):
    """A gate said no. The tool could have run; it was not allowed to."""

    outcome = "refused"


class ToolUnavailable(ToolError):
    """The tool COULD NOT RUN, which is not the same as finding nothing.

    Section 12's governing rule lives on this distinction.
    """

    outcome = "unavailable"
```

- [ ] **Step 5: Run the tests, then the suite, then commit**

```bash
.venv/bin/pytest tests/test_tools_envelope.py -q     # 12 pass
.venv/bin/pytest -q
git add src/hx/tools/envelope.py src/hx/tools/errors.py tests/test_tools_envelope.py
git commit -m "feat(tools): five outcomes, and empty is not unavailable"
```

---
### Task 4: The journal

**Files:**
- Create: `src/hx/tools/journal.py`
- Test: `tests/test_tools_journal.py`

**Interfaces:**
- Consumes: `envelope.Envelope` (Task 3); `hx.store.records.new_id`;
  `hx.store.blobs.BlobStore.put(bytes) -> (digest, length)`.
- Produces: `journal.ARGS_INLINE_MAX` (4096), `journal.SPILL_PREFIX`
  (`"sha256:"`), `journal.SUMMARY_MAX` (300),
  `journal.encode_args(args, blobs) -> str | None`,
  `journal.summarise(env) -> str`,
  `journal.record(conn, *, engagement_id, run_id, tool, args, why, env, blobs,
  at_us=None, actor="agent") -> str` returning the `agent_action` row id.

Connections from `hx.store.db.connect` are `isolation_level=None`, so every
`execute` commits. No explicit commit is needed anywhere in this plan.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_journal.py -- the whole file
"""Principle 5's record. It is also the loop-prevention hole: an agent that
cannot see what it already tried repeats it."""
from __future__ import annotations

import json

import pytest

from hx.tools import envelope, journal


def _row(conn, engagement_id):
    return conn.execute(
        "SELECT actor, tool, args_blob, result_summary, why FROM agent_action"
        " WHERE engagement_id=? ORDER BY ts_us DESC, rowid DESC LIMIT 1",
        (engagement_id,)).fetchone()


def test_small_arguments_are_stored_inline_and_read_back_as_json(engagement):
    args = {"host": "app.example.com", "limit": 10}
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="surface.query", args=args, why=None,
                   env=envelope.answered("surface.query", ["a"]),
                   blobs=engagement.blobs)
    actor, tool, args_blob, summary, why = _row(engagement.db, engagement.id)
    assert actor == "agent" and tool == "surface.query" and why is None
    assert json.loads(args_blob) == args


def test_large_arguments_spill_to_the_blob_store_and_are_retrievable(engagement):
    args = {"request": "A" * (journal.ARGS_INLINE_MAX + 1)}
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="surface.query", args=args, why=None,
                   env=envelope.answered("surface.query", []),
                   blobs=engagement.blobs)
    args_blob = _row(engagement.db, engagement.id)[2]
    assert args_blob.startswith(journal.SPILL_PREFIX)
    digest = args_blob[len(journal.SPILL_PREFIX):]
    assert json.loads(engagement.blobs.get(digest)) == args


def test_a_refusal_is_journalled_too(engagement):
    # The rows that make the report's refusal counts real. A layer that
    # recorded only successes would answer "what did the agent try" with
    # "everything that worked".
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="run.start", args={}, why=None,
                   env=envelope.refused("run.start", "missing_why"),
                   blobs=engagement.blobs)
    assert _row(engagement.db, engagement.id)[3] == "refused: missing_why"


def test_a_page_result_summarises_as_counts_not_as_rows(engagement):
    page = envelope.page(["a", "b"], total=97, limit=2)
    env = envelope.answered("surface.query", page)
    assert journal.summarise(env) == "ok: 2 of 97 rows"


def test_a_summary_is_capped(engagement):
    # The "id" branch produces a summary; exercise truncation there.
    env = envelope.answered("report.render", {"id": "x" * 5000})
    summary = journal.summarise(env)
    assert len(summary) == journal.SUMMARY_MAX
    assert summary.startswith("ok: ")


def test_the_why_is_stored_verbatim(engagement):
    journal.record(engagement.db, engagement_id=engagement.id, run_id=None,
                   tool="run.start", args={}, why="mapping the checkout flow",
                   env=envelope.answered("run.start", {"run_id": "r-1"}),
                   blobs=engagement.blobs)
    assert _row(engagement.db, engagement.id)[4] == "mapping the checkout flow"


@pytest.mark.parametrize("raw,expect_absent", [
    ("/callback?access_token=SEKRIT&state=x", "SEKRIT"),
    ("/cb?token=SEKRIT", "SEKRIT"),
    ("http://alice:SEKRIT@app.test/a", "SEKRIT"),
])
def test_a_credential_in_a_url_argument_is_redacted_too(raw, expect_absent):
    """THE HEADER GUARD DID NOT COVER THIS, and the store disagreed with
    itself about the same string. MEASURED before the fix: `exchange.url`
    held `access_token={{observed:param}}` while `agent_action.args_blob`
    held the token verbatim -- one table redacting what the other kept.

    `http.send`'s `path` is agent-supplied and required, and replaying an
    OAuth callback is ordinary work during an assessment, so this is
    reachable by typing rather than by contriving."""
    got = journal._redacted(raw)
    assert expect_absent not in got
    # The KEY survives: "the agent sent an access_token" is the fact
    # run.journal exists to report.
    assert "{{observed:" in got


def test_redaction_leaves_ordinary_strings_alone():
    """The redactor runs over EVERY string argument, so it has to be inert on
    the ones that carry nothing. A guard that mangled `pattern` or `path`
    would corrupt the journal's account of what was tried."""
    for benign in ["needle", "/a?b=c", "GET", "", "not a url, just prose"]:
        assert journal._redacted(benign) == benign
```

`tests/conftest.py` has no `engagement` fixture yet — it has `engagement_conn`
(an in-memory connection with no config, no blob store and no root). Add this
one beside it. **`tests/test_halt.py` defines a LOCAL fixture also called
`engagement` that returns a `(root, conn)` tuple**; a local fixture wins over
conftest, so that file is unaffected, but the collision is worth the docstring.

```python
@pytest.fixture
def engagement(tmp_path):
    """A throwaway engagement on disk: config, database and blob store.

    Returns `hx.engagement.Engagement`, NOT the `(root, conn)` tuple
    `tests/test_halt.py` defines under this same name. A local fixture wins
    over conftest, so that file keeps its own; the two shapes are worth
    knowing about before reaching for either.

    `staging` rather than `production` because nothing here sends a request
    and the stricter profile would only make a future egress test harder to
    write than it needs to be.
    """
    from hx import config as config_mod
    from hx import engagement as eng_mod

    cfg = config_mod.Config(name="t", client="T", safety_profile="staging",
                            scope_include=["https://app.test/*"])
    eng = eng_mod.create(tmp_path / "e", cfg, author="test")
    yield eng
    eng.db.close()
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_journal.py -q`
Expected: FAIL — `ImportError: cannot import name 'journal' from 'hx.tools'`

- [ ] **Step 3: Write `src/hx/tools/journal.py`**

```python
# src/hx/tools/journal.py -- the whole file
"""One `agent_action` row per dispatch, refusals included.

WHY REFUSALS TOO. Section 8 asks `run.journal` to answer "what have I already
tried this run". A journal holding only what worked answers that question with
"everything that worked", which is the shape of every agent loop this table
exists to break: the tool that keeps being refused is precisely the one the
agent keeps retrying.

`args_blob` IS INLINE JSON TO 4096 BYTES AND `sha256:<digest>` ABOVE IT. The
column's name follows `exchange.req_blob` and `resp_blob`, which are digests --
but `http.send` can carry a 100 KB request and `scan.run` a thousand surface
ids, while the overwhelming majority of calls are a few hundred bytes and
`run.journal` is the most-read tool in the set. Inline-with-spill keeps the
common read a single row and refuses to truncate the record of what was tried.
The `sha256:` prefix makes the two cases unambiguous to whoever reads the
column, which a bare digest would not.

STORING ARGUMENTS VERBATIM IS SAFE BECAUSE THE ENCODER REDACTS -- and that
sentence used to end "because Principle 5 holds". Principle 5 does hold: the
agent passes identity BY NAME, `hx.identity.resolve` runs below this layer,
and no tool returns a `Resolved`. But the argument rested on a second claim,
that it "holds for the registered tools' schemas", and that claim expired the
moment a tool accepted arbitrary header lines. RULING 21, MEASURED:
`http.send(headers=["Cookie: session=SUPERSECRETVALUE"])` wrote

    {"headers":["Cookie: session=SUPERSECRETVALUE"], ...}

into `agent_action.args_blob`, and "a credential value never appears in a
journal row" is a stated binding constraint of this project. `http.send` now
refuses that argument outright -- but the refusal path is journalled too, so
the refusal alone would not have closed it, and a future tool that legitimately
carries header lines would reopen it.

So `encode_args` redacts, and the guarantee is a property of THIS module
rather than of the schemas above it. It is deliberately blunt: EVERY string
anywhere in the arguments that BEGINS with one of
`config.CREDENTIAL_HEADERS` and a colon loses its value, whichever argument
it arrived in. The cost is real and is the right way round -- an agent
grepping for its own session cookie sees `http.grep(pattern=...)` recorded
with the value replaced -- because the alternative is a per-argument rule
that a future tool would silently fall outside of, which is the exact shape
of the defect this closes.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import CREDENTIAL_HEADERS
from ..store.records import new_id, redact_url
from .envelope import Envelope

#: Above this many bytes of encoded JSON, the arguments go to the blob store.
ARGS_INLINE_MAX = 4096

#: What marks the column as a reference rather than the arguments themselves.
SPILL_PREFIX = "sha256:"

#: `result_summary` is read in a list; it is a line, not a document.
SUMMARY_MAX = 300

#: A string that OPENS with one of the three credential header names and a
#: colon. Anchored at the start, so `"the Cookie: header"` inside a `why` or a
#: detail is not a header line and is left alone; the wire lines a tool takes
#: begin with the field name by definition.
#:
#: `config.CREDENTIAL_HEADERS` is IMPORTED rather than restated, for the
#: reason `hx.tools.impl.http._replayed_headers` gives for importing the same
#: tuple: it is already pinned byte for byte against the extension's own
#: `Redactor.CREDENTIAL_HEADERS`, and a second copy is a second thing to keep
#: in sync with the JVM.
#: PER LINE, ANYWHERE IN THE STRING -- not anchored at position 0. The
#: anchored `.match` version covered `headers` (whose lines arrive as separate
#: array items) and missed the shape `http.send` ALREADY SHIPS: a `body` is a
#: free string, and an agent replaying a captured request by hand puts a whole
#: request in one -- `"field=1\r\nCookie: session=<real>"` -- where the
#: credential is on line two and nothing looked past line one. That was
#: recorded as debt against a hypothetical FUTURE tool; the tool exists.
#:
#: `[^\r\n]*` rather than `.*`: MULTILINE's `$` matches before the `\n` but
#: not before the `\r`, so `.*` would keep a trailing CR inside the value it
#: was replacing and leave a stray one in the row.
#: `(?:^|(?<=\r))` rather than `^` alone: Python's MULTILINE `^` treats only
#: `\n` as a line boundary, and CR is a line terminator in HTTP. A request
#: split on bare CR -- which RFC 9112 s2.2 requires a recipient to tolerate,
#: and which `hx.http_text.split_head_body` tolerates for exactly that reason
#: -- puts a credential at a real line start that `^` does not recognise.
#: MEASURED: `"field=1\rCookie: session=<real>"` reached `args_blob` intact.
#: `\r\n` cannot double-match: after the CR sits the LF, which `[ \t]*` will
#: not cross, so only the MULTILINE `^` after the LF fires.
#:
#: MID-LINE OCCURRENCES ARE DELIBERATELY NOT MATCHED, and that is a decision
#: rather than the same gap unfixed. `"the Cookie: header was odd"` is prose,
#: `"a=1; Cookie: b"` is a form field, and neither is a header line; a
#: redactor that fired on either would corrupt the journal's account of what
#: was tried, which is the one thing it exists to preserve. A test pins that
#: inertness. What is guarded is a credential at a LINE START, in any of the
#: three spellings a line can start with.
_CREDENTIAL_LINE = re.compile(
    r"(?:^|(?<=\r))[ \t]*(" + "|".join(re.escape(h) for h in CREDENTIAL_HEADERS)
    + r")[ \t]*:[^\r\n]*", re.IGNORECASE | re.MULTILINE)

def _placeholder(name: str) -> str:
    """What replaces a credential header's VALUE.

    The vocabulary the extension already writes into a redacted blob --
    `{{observed:<name>}}`, lower-cased, `Redactor.observedHeader` -- so an
    operator reading a journal row and an operator reading a stored request
    are reading one placeholder rather than two.
    """
    return "{{observed:" + name.strip().lower() + "}}"


def _redacted(value: Any) -> Any:
    """`value` with every credential header line's value replaced.

    Recursive over the JSON shapes an argument can be, because the line can
    arrive anywhere: `http.send` takes an ARRAY of them today, and nothing
    stops a future tool from taking one string or a dict of them. A guard
    written for the one shape that exists is the guard that misses the next
    one -- which is how this hole opened in the first place.

    The NAME is kept and only the value goes, exactly as `records.redact_url`
    keeps a credential parameter's key: "the agent sent a Cookie header" is
    the fact `run.journal` exists to report, and a row that dropped the line
    entirely would answer "what did I already try" with a request that was
    never made.

    A CREDENTIAL IN A URL IS THE SAME EXPOSURE AND WAS NOT COVERED. Header
    lines were the shape this guard was written for, and an argument can
    carry one in a query string just as easily: `http.send`'s `path` is
    agent-supplied and required, and replaying an OAuth callback --
    `/cb?access_token=...` -- is ordinary work during an assessment.
    MEASURED: `exchange.url` held `access_token={{observed:param}}` while
    `agent_action.args_blob` held the token, so the store redacted the same
    string in one table and kept it in the other.

    `records.redact_url` is REUSED rather than reimplemented -- it already
    knows userinfo and the credential parameter names, and it is what writes
    the redacted `exchange.url` this was disagreeing with. It is safe on
    arbitrary strings: measured against prose, bare words, header lines and
    empty input, it returns them unchanged and raises on none of them, so it
    can run over every string argument rather than over ones guessed to be
    URLs. Found by the first automated review this repository completed.
    """
    if isinstance(value, str):
        # `sub`, not `match`: one string can carry several credential lines and
        # can carry them beside content worth keeping. Replacing only the
        # matched LINES leaves the rest of a body intact, so the journal still
        # answers "what did I already try" with the request that was made.
        redacted = _CREDENTIAL_LINE.sub(
            lambda m: f"{m.group(1)}: {_placeholder(m.group(1))}", value)
        return redact_url(redacted)
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redacted(item) for item in value]
    return value


def _now_us() -> int:
    return time.time_ns() // 1000


def encode_args(args: dict[str, Any], blobs) -> str | None:
    """The value for `agent_action.args_blob`.

    Sorted keys, so two identical calls produce two identical strings and a
    reader comparing journal rows is comparing arguments rather than dict
    ordering.

    CREDENTIAL HEADER LINES LOSE THEIR VALUES FIRST -- see this module's
    docstring for why that guarantee lives here rather than in the schemas
    above. The redaction runs before `json.dumps`, so it covers the spilled
    blob exactly as it covers the inline column.

    May raise `TypeError` or `ValueError` if `json.dumps` encounters a
    non-serialisable value or circular reference; the raise happens before
    the `INSERT`, so no partial row is written.
    """
    if not args:
        return None
    text = json.dumps(_redacted(args), sort_keys=True, separators=(",", ":"))
    raw = text.encode("utf-8")
    if len(raw) <= ARGS_INLINE_MAX:
        return text
    digest, _ = blobs.put(raw)
    return f"{SPILL_PREFIX}{digest}"


def summarise(env: Envelope) -> str:
    """One line saying what happened, for a reader scanning the journal.

    A page answers in COUNTS, never in rows: the rows are already in the store
    and repeating them here would make the journal the second copy of every
    query result the agent ever ran.
    """
    if not env.ran:
        line = f"{env.outcome}: {env.reason}"
        if env.detail:
            line = f"{line} — {env.detail}"
    elif (isinstance(env.result, dict)
          and set(env.result.keys()) == {"rows", "returned", "total",
                                         "truncated", "next_cursor", "facets"}):
        line = f"{env.outcome}: {env.result['returned']} of {env.result['total']} rows"
    elif isinstance(env.result, dict) and "id" in env.result:
        line = f"{env.outcome}: {env.result['id']}"
    else:
        line = env.outcome
    return line[:SUMMARY_MAX]


def record(conn, *, engagement_id: str, run_id: str | None, tool: str,
           args: dict[str, Any], why: str | None, env: Envelope, blobs,
           at_us: int | None = None, actor: str = "agent") -> str:
    """Write the row. Returns its id.

    `tool` is what the caller ASKED FOR, which for an unregistered name is a
    tool that does not exist. That is deliberate: a row naming a nonexistent
    tool is how an agent looping on a name it invented becomes visible.
    """
    row_id = new_id("a")
    conn.execute(
        "INSERT INTO agent_action(id, engagement_id, run_id, ts_us, actor,"
        " tool, args_blob, result_summary, why) VALUES(?,?,?,?,?,?,?,?,?)",
        (row_id, engagement_id, run_id, _now_us() if at_us is None else at_us,
         actor, tool, encode_args(args, blobs), summarise(env), why))
    return row_id
```

- [ ] **Step 4: Run the tests, then the suite, then commit**

```bash
.venv/bin/pytest tests/test_tools_journal.py -q      # 6 pass
.venv/bin/pytest -q
git add src/hx/tools/journal.py tests/test_tools_journal.py tests/conftest.py
git commit -m "feat(tools): the journal, refusals included"
```

---

### Task 5: The dispatcher and the published decision order

**Files:**
- Create: `src/hx/tools/dispatch.py`
- Test: `tests/test_tools_dispatch.py`

**Interfaces:**
- Consumes: everything from Tasks 1-4.
- Produces: `dispatch.DECISION_ORDER`; `dispatch._shape(args)`;
  `dispatch.ToolContext(engagement, conn, blobs, config, halt, run_id=None,
  session=None, actor="agent")`;
  `dispatch.dispatch(ctx, name, args=None, *, why=None) -> envelope.Envelope`.
  **`dispatch` never raises.** Every outcome, defects included, comes back as
  an envelope, and every call writes exactly one `agent_action` row.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_dispatch.py -- the whole file
"""One order, published, that every layer and every test agrees on -- the same
device that made the send path's gate reviewable."""
from __future__ import annotations

import pytest

import json

from hx.tools import dispatch, registry, spec

EMPTY = {"type": "object", "additionalProperties": False, "properties": {}}
ONE = {"type": "object", "additionalProperties": False,
       "properties": {"n": {"type": "integer"}}, "required": ["n"]}


@pytest.fixture
def a_tool(monkeypatch):
    """Install stubs under real v1 names, in a registry of our own.

    `hx.tools.impl` has already registered `run.start`, `checks.list` and the
    rest by the time this file runs -- pytest imports every test module before
    running any test -- so registering by name against the real registry would
    raise "already registered". Rebinding the module attribute sidesteps that
    without teardown bookkeeping.
    """
    monkeypatch.setattr(registry, "TOOLS", {})

    def make(name, handler, **kw):
        return registry.register(spec.ToolSpec(
            name=name, summary="x", params=kw.pop("params", EMPTY),
            handler=handler, **kw))

    return make


def _actions(conn):
    return conn.execute(
        "SELECT tool, result_summary FROM agent_action WHERE actor='agent'"
        " ORDER BY ts_us, rowid").fetchall()


def test_the_order_is_the_published_one():
    assert dispatch.DECISION_ORDER == (
        "not_registered", "halted", "missing_why", "bad_args", "no_session")


def test_an_unregistered_name_is_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "nothing.at.all", {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")
    rows = _actions(tool_ctx.conn)
    # The row names the tool that does NOT exist -- that is how an agent
    # looping on a name it invented becomes visible.
    #
    # The summary is asserted by PARTS rather than as one string. It used to
    # be `== "refused: not_registered"`, and Task 4's fix round made
    # `journal.summarise` append a refusal's detail -- because a bare
    # `bad_args` sends an agent round the same loop, which is what this table
    # exists to break. Both changes are right and the exact-string assertion
    # was what stood between them. The detail reaching the journal is now
    # itself worth asserting, so it is.
    assert len(rows) == 1 and rows[0][0] == "nothing.at.all"
    assert rows[0][1].startswith("refused: not_registered")
    # `checks.list` lists security checks, not tools -- an agent told to "ask
    # checks.list" for a tool list learns nothing and asks again. The message
    # now points at the thing that actually lists tools, `hx tool --list`,
    # and no longer tells the agent to ask checks.list for one.
    assert "hx tool --list" in rows[0][1]
    assert "Ask checks.list" not in rows[0][1]


def test_a_halt_stops_a_mutating_tool(tool_ctx, a_tool):
    # `run.start`, not `run.finish` -- the latter is the one member of
    # `HALT_EXEMPT` (item 6 of the final whole-branch review, tested below),
    # and would make this test say the opposite of what it means to show.
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why="because")
    assert (env.outcome, env.reason) == ("refused", "halted")


def test_a_halt_does_not_stop_a_read(tool_ctx, a_tool):
    # Deliberate: an operator who has just hit STOP wants the agent able to
    # explain what it was doing. Reads change nothing.
    a_tool("run.journal", lambda c: ["an action"])
    tool_ctx.halt.halt("stop now")
    assert dispatch.dispatch(tool_ctx, "run.journal", {}).outcome == "ok"


def test_the_halt_exemption_is_exactly_run_finish():
    # Item 6 of the final whole-branch review: closing an open run does LESS,
    # not more, so a halt must not block it -- and in Plan B, `run.finish` is
    # what stops the Burp JVM, so refusing it under a halt would leave one
    # running with nothing holding it. A named set, asserted exactly, so a
    # future tool cannot join it quietly.
    assert dispatch.HALT_EXEMPT == frozenset({"run.finish"})


def test_a_halt_does_not_stop_the_exempt_tool(tool_ctx, a_tool):
    a_tool("run.finish", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.finish", {}, why="closing up")
    assert env.outcome == "ok"


def test_a_halt_still_stops_every_other_mutating_tool(tool_ctx, a_tool):
    # The exemption is `run.finish` alone -- every other mutating tool must
    # still be refused under a halt, or the set is not doing its job.
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    tool_ctx.halt.halt("stop now")
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why="mapping")
    assert (env.outcome, env.reason) == ("refused", "halted")


def test_a_mutating_tool_without_a_why_is_refused(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    for why in (None, "", "   "):
        env = dispatch.dispatch(tool_ctx, "run.start", {}, why=why)
        assert (env.outcome, env.reason) == ("refused", "missing_why")


def test_bad_arguments_are_refused_with_every_problem_at_once(tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    env = dispatch.dispatch(tool_ctx, "surface.query", {"nope": 1})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "n is required" in env.detail and "nope is not an argument" in env.detail


def test_an_egress_tool_without_a_session_is_unavailable_not_refused(tool_ctx, a_tool):
    # It could not run; nothing said no. Section 12 lives on this difference.
    a_tool("http.send", lambda c: None, needs_egress=True, mutates=True)
    env = dispatch.dispatch(tool_ctx, "http.send", {}, why="probing")
    assert (env.outcome, env.reason) == ("unavailable", "no_session")


def test_halt_beats_missing_why_which_beats_bad_args(tool_ctx, a_tool):
    # Trip three rules at once; the earliest must win, or the order is only
    # a comment. Same test shape the send path's order already has.
    a_tool("scan.run", lambda c, n: n, params=ONE, mutates=True,
           needs_egress=True)
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}).reason == "halted"
    # The two LENGTH guards are `bad_args` refusals too, and used to sit above
    # `lookup` and the halt check -- so a halted engagement plus a `why` too
    # long to accept used to answer `bad_args` here instead of `halted`. Still
    # halted, on the earliest-matching-rule rule.
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1},
                             why="x" * 501).reason == "halted"
    tool_ctx.halt.resume()
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}).reason == "missing_why"
    assert dispatch.dispatch(tool_ctx, "scan.run", {"bad": 1}, why="w").reason == "bad_args"
    assert dispatch.dispatch(tool_ctx, "scan.run", {"n": 1}, why="w").reason == "no_session"


def test_not_registered_beats_an_over_long_name(tool_ctx):
    # The other length guard, same shape: a name over 64 characters that is
    # ALSO unregistered used to answer `bad_args` -- the length guard sat
    # above `lookup` -- when the order says `not_registered` should win,
    # since a name that long was never going to be found anyway.
    env = dispatch.dispatch(tool_ctx, "x" * 70, {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")


def test_a_handler_raising_ToolUnavailable_keeps_its_outcome(tool_ctx, a_tool):
    from hx.tools.errors import ToolUnavailable

    def dead(c):
        raise ToolUnavailable("not_implemented", "no crawler exists")

    a_tool("crawl.run", dead)
    env = dispatch.dispatch(tool_ctx, "crawl.run", {})
    assert (env.outcome, env.reason) == ("unavailable", "not_implemented")


def test_a_handler_raising_anything_else_becomes_an_error_not_a_traceback(tool_ctx, a_tool):
    def broken(c):
        raise ZeroDivisionError("division by zero")

    a_tool("checks.list", broken)
    env = dispatch.dispatch(tool_ctx, "checks.list", {})
    assert (env.outcome, env.reason) == ("error", "internal")
    assert "ZeroDivisionError" in env.detail


def _last_args(conn):
    return conn.execute("SELECT args_blob FROM agent_action"
                        " ORDER BY ts_us DESC, rowid DESC LIMIT 1").fetchone()[0]


def test_an_unvalidated_call_journals_key_names_and_never_values(tool_ctx):
    # Principle 5 makes `args_blob` safe to store verbatim, and that argument
    # covers calls a schema ACCEPTED. Every refusal at or before validation
    # carries a dict nobody checked -- and `additionalProperties: false` means
    # {"password": ...} sent to a REAL tool is exactly a bad_args refusal.
    dispatch.dispatch(tool_ctx, "nothing.at.all", {"password": "hunter2"})
    blob = _last_args(tool_ctx.conn)
    assert "hunter2" not in blob
    assert json.loads(blob) == {"unvalidated_argument_names": ["password"]}


def test_bad_args_is_unvalidated_too_because_validation_is_what_failed(
        tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    dispatch.dispatch(tool_ctx, "surface.query", {"password": "hunter2"})
    blob = _last_args(tool_ctx.conn)
    assert "hunter2" not in blob


def test_a_validated_call_journals_its_argument_values(tool_ctx, a_tool):
    a_tool("surface.query", lambda c, n: n, params=ONE)
    dispatch.dispatch(tool_ctx, "surface.query", {"n": 7})
    assert json.loads(_last_args(tool_ctx.conn)) == {"n": 7}


def test_every_call_writes_exactly_one_action_row(tool_ctx, a_tool):
    a_tool("checks.list", lambda c: ["passive"])
    for _ in range(3):
        dispatch.dispatch(tool_ctx, "checks.list", {})
    dispatch.dispatch(tool_ctx, "not.a.tool", {})
    assert len(_actions(tool_ctx.conn)) == 4


# `name`, `args` and `why` arrive over MCP or JSON-RPC, where nothing stops
# the wrong JSON type reaching any of them. Before the guards at the top of
# `dispatch`, each of the four below raised before a single row was written --
# breaking both "never raises" and "exactly one row" at once, and reaching no
# test, because nothing here had passed a non-string name/why or a non-dict
# args.

def test_a_non_string_name_is_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, ["nope"], {})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    rows = _actions(tool_ctx.conn)
    # `agent_action.tool` is NOT NULL TEXT, so the row still names something --
    # rendered, not dropped.
    assert len(rows) == 1 and rows[0][0] == "<list>"


def test_non_dict_arguments_are_refused_and_still_journalled(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", "not a dict")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_non_string_argument_keys_are_refused_and_still_journalled(tool_ctx):
    # A JSON object's keys are always strings, so a non-string key here did
    # not come from JSON at all -- and `schema.validate`'s own
    # `sorted(set(value) - set(props))` cannot sort a set of mixed types
    # either, which is the second raise this same guard closes.
    env = dispatch.dispatch(tool_ctx, "surface.query", {1: "x", "z": "y"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_non_string_why_is_refused_not_coerced(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why=123)
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    row = tool_ctx.conn.execute(
        "SELECT why FROM agent_action WHERE actor='agent'"
        " ORDER BY ts_us DESC, rowid DESC LIMIT 1").fetchone()
    # Refused, not coerced: `str(123)` in `agent_action.why` would read as an
    # operator's reason for a state change nobody gave.
    assert row[0] is None
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_why_longer_than_500_characters_is_refused_and_journalled(tool_ctx, a_tool):
    a_tool("run.start", lambda c: {"id": "r-1"}, mutates=True)
    long_why = "x" * 501
    env = dispatch.dispatch(tool_ctx, "run.start", {}, why=long_why)
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert len(_actions(tool_ctx.conn)) == 1


def test_a_name_longer_than_64_characters_on_an_unregistered_name_is_not_registered(
        tool_ctx):
    # A name this long cannot be registered -- nothing in V1_TOOL_NAMES is
    # anywhere near 64 characters -- so `lookup` already answers None for it,
    # and the published order gives `not_registered` before the length guard
    # ever gets a turn. This used to answer `bad_args` instead, which is
    # exactly the inversion the whole-branch review's item 1 named.
    long_name = "x" * 65
    env = dispatch.dispatch(tool_ctx, long_name, {})
    assert (env.outcome, env.reason) == ("refused", "not_registered")
    assert len(_actions(tool_ctx.conn)) == 1
```

- [ ] **Step 2: Add the shared context fixture to `tests/conftest.py`**

Five test files in this plan need the same four-field context. It goes in
`conftest.py` once rather than five times, beside the `engagement` fixture
Task 4 added.

```python
@pytest.fixture
def tool_ctx(engagement):
    """A ToolContext over a throwaway engagement, with no run and no session.

    `run_id` is None because a fresh process has no open run, and `session` is
    None because nothing in Plan A needs egress -- which is exactly the state
    `needs_egress` tools are refused against.
    """
    from hx import halt as halt_mod
    from hx.tools import dispatch

    return dispatch.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))
```

- [ ] **Step 3: Run the dispatch tests and watch them fail**

Run: `.venv/bin/pytest tests/test_tools_dispatch.py -q`
Expected: FAIL — `ImportError: cannot import name 'dispatch' from 'hx.tools'`

- [ ] **Step 4: Write `src/hx/tools/dispatch.py`**

```python
# src/hx/tools/dispatch.py -- the whole file
"""The one door every tool call goes through.

THE PUBLISHED DECISION ORDER IS

    not_registered -> halted -> missing_why -> bad_args -> no_session

and it is published for the reason the send path's is (section 4): a gate whose
order is undocumented is a gate whose behaviour is discovered by experiment.
Earliest matching rule wins; each is terminal.

`not_registered` FIRST, because the registry is the allowlist and a name that
is not in it is not a tool to have opinions about.

`halted` BEFORE `missing_why`, so an operator who has hit STOP gets "the
engagement is halted" rather than a lecture about argument hygiene for a call
that was never going to run.

`halted` APPLIES ONLY TO `mutates` TOOLS, deliberately. A halt stops the
engagement from changing; it does not blind the operator's agent. Someone who
has just hit STOP wants to ask what was happening, and every tool that can
answer that is a read.

`halted` ALSO DOES NOT APPLY TO `HALT_EXEMPT`, which today holds exactly
`run.finish`. The rule the gate encodes is "a halted engagement must not do
MORE"; closing an open run does less, not more, and in Plan B `run.finish` is
what stops the Burp JVM -- so refusing it under a halt would leave a JVM
running with nothing left holding it, which is exactly what section 8's
bracket exists to prevent. `HALT_EXEMPT` is a named, greppable set checked
here, not a per-spec boolean on `ToolSpec`: a boolean would invite a future
tool to opt itself out of the halt gate one flag at a time, and the set makes
every exemption a decision visible in one place instead of scattered across
specs.

`no_session` LAST, because it is the most expensive question to answer and the
only one that depends on state outside this process.

THE TWO LENGTH GUARDS -- `why` OVER 500 CHARACTERS, `name` OVER 64 -- SIT
BELOW `lookup` AND THE HALT CHECK, deliberately, and did not always: a
too-long `why` used to answer `bad_args` on a halted engagement, ahead of
`halted`, and a too-long unknown name used to answer `bad_args` ahead of
`not_registered`. Neither length is a `bad_args` question the published order
puts before those two: a name over 64 characters is simply not a registered
name (nothing in `V1_TOOL_NAMES` is that long, so `lookup` already returns
`None` for it), and a `why` over 500 characters is an argument problem the
order deliberately ranks below `halted`. The four TYPE guards immediately
below this docstring are a different kind of guard and stay above `lookup`:
a non-string `name` cannot be looked up at all, hashable or not.

THIS FUNCTION NEVER RAISES. Every outcome -- refusal, unavailability, and a
defect in hx itself -- comes back as an envelope, and every call writes AT
MOST one `agent_action` row -- a failure to write it is logged, never silent;
see `_journalled`. An adapter that had to catch exceptions as well as read
envelopes would be two error paths, and the second would be the one nobody
tested.

`name`, `args` and `why` ARE THEMSELVES UNTRUSTED. They arrive over MCP or
JSON-RPC, where nothing stops a `name` that is a list, an `args` that is a
string, or a `why` that is an integer. The four guards at the top of
`dispatch` catch exactly that, before `registry.lookup` (which needs a
hashable `name`), before `dict(args or {})` (which needs a mapping or None),
before `schema.validate`'s internal `sorted()` over argument names (which
needs every key to be a string), and before `.strip()` on `why`. Each is a
`bad_args` refusal, journalled like any other -- a malformed call is exactly
what `agent_action` exists to make visible, not a crash that erases it.
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from .. import run as run_mod
from . import envelope, journal, registry, schema
from .errors import ToolError

_log = logging.getLogger(__name__)

#: Design section 5. Asserted by a test, so it cannot become a comment.
DECISION_ORDER = ("not_registered", "halted", "missing_why", "bad_args",
                  "no_session")

#: Tools the halt gate does not apply to, even though they mutate. `run.finish`
#: is the only member: closing an open run does LESS, not more, and section
#: 8's bracket needs it reachable under a halt so Plan B's Burp JVM is never
#: left running with nothing holding it. A named set here rather than a
#: `ToolSpec` boolean, so a future tool cannot opt itself out of the halt gate
#: one flag at a time -- every exemption is a decision visible in this one
#: place, and a test asserts the set holds exactly this.
HALT_EXEMPT = frozenset({"run.finish"})


@dataclasses.dataclass
class ToolContext:
    """Everything a handler is allowed to reach.

    IT CARRIES NO CREDENTIAL. Principle 5 puts identity resolution below this
    layer: a handler that could reach a `Resolved` could put one in a return
    value, and the return value is journalled.

    `session` is None throughout Plan A -- nothing here needs egress -- and
    Plan B fills it from `run.start`. `needs_egress` tools are already refused
    against it, so the seam is a field rather than a change.
    """

    engagement: Any
    conn: Any
    blobs: Any
    config: Any
    halt: Any
    session: Any = None
    #: The ADAPTER'S ExitStack, and the reason egress belongs to a long-lived
    #: adapter rather than to `hx tool`. `hx.session.session()` tears Burp
    #: down on EVERY exit, so a JVM launched inside a one-shot `hx tool`
    #: process dies microseconds later -- there is no object in that adapter
    #: for a session to outlive. `hx mcp` is one process for the whole
    #: conversation, opens a stack around its serve loop, and hands it here;
    #: `run.start` pushes the session onto it and `run.finish` pops it. A
    #: crash unwinds the stack, which is spec section 8's "a crash must not
    #: orphan a JVM" -- the FIRST of its three layers, the other two being
    #: `run.reap_stale` and `session()`'s own teardown.
    #:
    #: None means this adapter cannot host a session, which is a different
    #: fact from "no session is open" and is reported as its own reason.
    stack: Any = None
    #: The run that launched the session on `stack`. At most one session at a
    #: time -- see `hx.tools.live`.
    _session_run_id: str | None = dataclasses.field(default=None, repr=False)
    #: An ExitStack NESTED inside `stack`, holding the session and nothing
    #: else, so that `run.finish` can tear down the session WITHOUT tearing
    #: down whatever else the adapter registered on its own stack. Closing an
    #: inner stack unwinds only what the inner stack holds and leaves it
    #: reusable; closing the outer one still unwinds the inner, so a crash
    #: kills the JVM exactly as before.
    #:
    #: CREATED ONCE AND REUSED, deliberately. Entering a fresh inner stack per
    #: session would leave one spent `__exit__` callback on the adapter's
    #: stack per session -- a no-op each, and unbounded growth across an
    #: `hx mcp` conversation that opens and closes runs all day. `ExitStack.
    #: close()` leaves the stack usable, so one is enough for every session
    #: this context will ever hold.
    _session_stack: Any = dataclasses.field(default=None, repr=False)
    #: `(identity_id, generation)` already registered on THIS session's
    #: extension. `BridgeServer.register_identity` refuses a generation that
    #: does not advance what the extension holds (`stale_generation`), so a
    #: second registration of the same pair is an error, not a no-op. Cleared
    #: with the session, because a new extension has heard of none of them.
    _registered: set = dataclasses.field(default_factory=set, repr=False)
    actor: str = "agent"
    _bound_run_id: str | None = dataclasses.field(default=None, repr=False)
    #: `None` means "not resolved for this call yet", never "resolved to
    #: zero open runs" -- `hx.run.open_runs` returns a `list`, so the
    #: sentinel and a genuine empty answer cannot collide. Reset by
    #: `dispatch()`; see `open_runs()`.
    _open_runs_cache: list[tuple[str, str]] | None = dataclasses.field(
        default=None, repr=False)

    def open_runs(self) -> list[tuple[str, str]]:
        """`(id, kind)` for every run of this engagement still open --
        resolved from the store AT MOST ONCE PER `dispatch()` CALL, memoised
        here and reused by every reader inside it, `run_id` included.

        A SECOND FINDING OF THE FINAL REVIEW, IN THE FIRST FINDING'S OWN FIX.
        Before this, `run_id` queried live on EVERY access, and a handler
        that reads it more than once -- `finding.record` does, at its guard
        and again at each of two writes -- could see two different answers
        to the same question inside one call. MEASURED: one `manual` run
        open, the guard at `finding.record`'s top passes; before the writes
        run, a concurrent actor (an operator's `hx scan`, a second agent's
        `run.start`) opens a run of a DIFFERENT kind -- ordinary concurrent
        use, the exact case `hx.run.current_run`'s docstring blesses ("a
        crawl running while you browse is two runs"). The now-ambiguous
        resolution turns `None` between the guard and the write, and
        `finding_observation.run_id` (`NOT NULL`) raises `IntegrityError`,
        rolling the transaction back -- the agent's finding and its evidence
        are lost, and it is told hx is broken (`error/internal`) rather than
        given a clean disambiguation.

        `dispatch()` clears this cache at the TOP of every call, before the
        first guard runs -- so the four call-shape refusals, the handler
        (whatever it reads and however many times), and `_journalled`'s own
        trailing read afterward all see ONE snapshot, taken at the first
        access within this call. `run.finish` reads it directly too (for its
        `kind` branch and its ambiguous-refusal message) rather than issuing
        its own live query, for the same reason `finding.record`'s two later
        reads must agree with its first: one resolution, not three.

        EXPLICIT BINDING STILL WINS. This cache backs only the UNBOUND path
        -- `run_id`'s bound check runs first and returns immediately when
        `run.start` (or a caller) has set `_bound_run_id`, so a `ctx.run_id =
        ...` assignment mid-handler is never shadowed by a snapshot taken
        before it.
        """
        if self._open_runs_cache is None:
            self._open_runs_cache = run_mod.open_runs(
                self.conn, engagement_id=self.engagement.id)
        return self._open_runs_cache

    @property
    def run_id(self) -> str | None:
        """The open run -- BOUND if `run.start` (or a caller) set one on this
        context, else RESOLVED FROM THE STORE (see `open_runs()` for the
        per-call memoisation that makes repeated reads agree).

        THE OPEN RUN IS A PROPERTY OF THE ENGAGEMENT, NOT OF THE PROCESS. The
        CLI adapter builds a fresh `ToolContext` -- nothing bound -- for every
        `hx tool` invocation, so a plain field that only ever held what THIS
        process set would leave `run.finish` and every run-scoped tool
        permanently unreachable through it: `run.start` binds a run in one
        process and exits, and the next process's context has never heard of
        it. Resolving from `hx.run.open_runs` instead means a run a prior
        `run.start` opened is still findable.

        AMBIGUITY IS NEVER GUESSED. Two runs of different kinds may
        legitimately be open at once -- `run.start`'s own refusal only blocks
        a second run of the SAME kind, because "a crawl running while you
        browse is two runs" (`hx.run.current_run`'s docstring gives the
        rule). So this resolves to a run only when exactly one is open; zero
        or several both come back `None` rather than picking one. A caller
        that must tell two open runs apart -- `run.finish`'s `kind` argument,
        `finding.record`'s ambiguous-refusal message -- reads `open_runs()`
        itself rather than trusting this property to guess.

        NOT `hx.run.current_run`. That function auto-opens a run, which is
        right for `hx capture start` -- a forgotten command should not cost
        an hour of unrecorded browsing -- and wrong here: silently handing
        back some OTHER run's id would make `run.start`'s `run_open` refusal
        a lie about which run is open, and would make `run.finish` close a
        run nobody asked it to.
        """
        if self._bound_run_id is not None:
            return self._bound_run_id
        rows = self.open_runs()
        return rows[0][0] if len(rows) == 1 else None

    @run_id.setter
    def run_id(self, value: str | None) -> None:
        # `run.start` binds with this; `run.finish` clears with it -- both are
        # a plain `ctx.run_id = ...` at the call site, unchanged by this
        # property existing. Checked FIRST by the getter above, so this
        # always wins over whatever `open_runs()` cached earlier in the call.
        self._bound_run_id = value


def dispatch(ctx: ToolContext, name: str, args: dict[str, Any] | None = None,
             *, why: str | None = None) -> envelope.Envelope:
    """Validate, authorise, call, journal. Never raises."""
    # ONE run-resolution snapshot per call, taken lazily on first read and
    # reused by everything below -- the guards, the handler (however many
    # times IT reads `ctx.run_id` or `ctx.open_runs()`), and `_journalled`'s
    # own trailing read. Without this reset a context left over from a prior
    # dispatch would hand a NEW call the OLD call's snapshot; see
    # `ToolContext.open_runs` for the defect this closes.
    ctx._open_runs_cache = None

    # A malformed `why` is never written to `agent_action.why`, in any of the
    # rows the four guards below produce -- refused or not. `str(123)` there
    # would read as an operator's reason for a state change nobody gave, so a
    # non-string `why` is refused rather than coerced, and every row journalled
    # before that refusal fires carries None instead of the raw value.
    safe_why = why if why is None or isinstance(why, str) else None

    if not isinstance(name, str):
        # `agent_action.tool` is NOT NULL TEXT. A name malformed enough that
        # it cannot be looked up still gets a row -- rendered, not dropped --
        # because an agent looping on a malformed call is exactly what this
        # table exists to make visible.
        placeholder = f"<{type(name).__name__}>"
        return _journalled(ctx, placeholder, {}, safe_why, envelope.refused(
            placeholder, "bad_args",
            f"tool name must be a string, got {type(name).__name__}"))

    if args is not None and not isinstance(args, dict):
        return _journalled(ctx, name, {}, safe_why, envelope.refused(
            name, "bad_args",
            f"arguments must be an object, got {type(args).__name__}"))

    args = dict(args or {})

    if not all(isinstance(key, str) for key in args):
        # The same guard that keeps `schema.validate`'s internal
        # `sorted(set(value) - set(props))` from raising on a set of mixed
        # str and non-str keys: a JSON object's keys are always strings, so a
        # non-string key here did not come from JSON at all.
        return _journalled(ctx, name, {}, safe_why, envelope.refused(
            name, "bad_args", "argument names must be strings"))

    if why is not None and not isinstance(why, str):
        return _journalled(ctx, name, args, safe_why, envelope.refused(
            name, "bad_args", f"why must be a string, got {type(why).__name__}"))

    # THE TWO LENGTH GUARDS BELOW USED TO SIT HERE, ABOVE `registry.lookup`
    # AND THE HALT CHECK, WHICH INVERTED THE PUBLISHED ORDER FOR BOTH. A name
    # over 64 characters is simply not a registered name -- `bad_args` for it
    # answered before `not_registered` got a chance to, on a call the order
    # says `not_registered` should own. A `why` over 500 characters is an
    # argument problem, and the order puts `bad_args` after `halted`
    # deliberately: an operator who has hit STOP should hear "the engagement
    # is halted", not a lecture about `why`'s length, for a call that was
    # never going to run either way. Both guards move below `lookup` and the
    # halt check for exactly that reason -- see the module docstring's
    # account of the four TYPE guards that must stay above them, which this
    # does not touch: a non-string name or `why` cannot be looked up or
    # `.strip()`-ed at all, so those four are a different kind of guard from
    # these two.

    tool = registry.lookup(name)
    if tool is None:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "not_registered",
            f"{name} is not a tool. Run `hx tool --list` to see the "
            "registered tools; checks.list only lists security checks."))

    if tool.mutates and ctx.halt.halted and name not in HALT_EXEMPT:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "halted", ctx.halt.reason))

    if tool.requires_why and not (why or "").strip():
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "missing_why",
            f"{name} changes state, so it needs a `why`: it is written to "
            "agent_action and read by whoever asks what this run did."))

    if len(name) > 64:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args",
            f"tool name must be at most 64 characters, got {len(name)}"))

    if why is not None and len(why) > 500:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args",
            f"why must be at most 500 characters, got {len(why)}"))

    problems = schema.validate(tool.params, args)
    if problems:
        return _journalled(ctx, name, args, why, envelope.refused(
            name, "bad_args", "; ".join(problems)))

    # EVERYTHING BELOW THIS LINE HAS PASSED A SCHEMA, and that is what makes
    # `validated=True` safe -- see `_journalled`.
    if tool.needs_egress and ctx.session is None:
        return _journalled(ctx, name, args, why, envelope.unavailable(
            name, "no_session",
            f"{name} sends requests and there is no live session. Start a run "
            "first."), validated=True)

    try:
        result = tool.handler(ctx, **args)
    except ToolError as exc:
        env = envelope.Envelope(tool=name, outcome=exc.outcome,
                                reason=exc.reason, detail=exc.detail)
    except Exception as exc:  # noqa: BLE001 -- see the module docstring
        # Named, not swallowed. The class and message go into the envelope and
        # the journal so a defect is visible without a traceback reaching an
        # agent that would try to act on it.
        env = envelope.failed(name, f"{type(exc).__name__}: {exc}")
    else:
        env = envelope.answered(name, result)
    return _journalled(ctx, name, args, why, env, validated=True)


def _shape(args: dict[str, Any]) -> dict[str, Any]:
    """The argument NAMES of a call nothing validated, never its values."""
    return {"unvalidated_argument_names": sorted(args)}


def _journalled(ctx: ToolContext, name: str, args: dict[str, Any],
                why: str | None, env: envelope.Envelope,
                *, validated: bool = False) -> envelope.Envelope:
    """Write the row and hand back the envelope.

    ARGUMENT VALUES ARE JOURNALLED ONLY FOR A CALL THAT PASSED A SCHEMA.
    `hx.tools.journal` stores `args_blob` verbatim, and Principle 5 is the
    argument for why that is safe: identity is passed by name and resolved
    below this layer. That argument covers arguments a schema ACCEPTED. It
    covers nothing about the refusals above -- the four decision-order ones,
    and the four call-shape guards ahead of them -- which happen before or at
    validation and carry a dict nobody has checked -- and since every tool
    schema sets `additionalProperties: false`, `{"password": ...}` sent to a
    real tool IS a `bad_args` refusal. So an unvalidated call journals its
    sorted key NAMES and nothing else.

    The names are kept rather than dropped because they are the whole
    loop-prevention signal: "I keep calling this with a password field" is
    what an agent needs to read back, and it needs no value to say it.

    A journal failure must not turn a successful call into a failed one, nor a
    refusal into a success: the envelope is returned either way, and the write
    is the thing that is allowed to be missing. An engagement whose database
    has gone read-only has larger problems than an unrecorded row, and the
    caller finding out about them from `surface.query` would be misleading.

    MISSING, BUT NEVER SILENT. This block was written `except Exception: pass`,
    and the paragraph above was the argument for it -- correctly, right up to
    the word `pass`. A swallowed failure lets the journal go incomplete with
    nothing anywhere saying so, and `run.journal` and `run.resume` then answer
    "what have I already tried" out of a record that is quietly short. That is
    section 12's governing rule broken inside the table built to keep it: a
    journal that cannot tell "did not happen" from "happened and was not
    recorded". `hx.bridge.server` sets the convention this uses.
    """
    try:
        journal.record(ctx.conn, engagement_id=ctx.engagement.id,
                       run_id=ctx.run_id, tool=name,
                       args=args if validated else _shape(args), why=why,
                       env=env, blobs=ctx.blobs, actor=ctx.actor)
    except Exception:  # noqa: BLE001
        _log.exception("could not journal %s; the call itself stands", name)
    return env
```

- [ ] **Step 5: Run the tests, then the suite, then commit**

```bash
.venv/bin/pytest tests/test_tools_dispatch.py -q     # 18 pass
.venv/bin/pytest -q
git add src/hx/tools/dispatch.py tests/test_tools_dispatch.py tests/conftest.py
git commit -m "feat(tools): the dispatcher and its published order"
```

---
### Task 6: `run.start`, `run.finish`, `run.journal`

**Files:**
- Create: `src/hx/tools/impl/__init__.py`, `src/hx/tools/impl/run.py`
- Test: `tests/test_tools_run.py`

**Interfaces:**
- Consumes: `hx.run.open_run/close_run/RUN_KINDS`; `hx.config.Config.safety_profile`;
  `dispatch.ToolContext`; `envelope.page/DEFAULT_LIMIT/MAX_LIMIT`;
  `errors.ToolUnavailable`.
- Produces: registrations for `run.start`, `run.finish`, `run.journal`. Handler
  functions `start(ctx, kind)`, `finish(ctx, status, note=None)`,
  `journal(ctx, since=None, last_n=None, tool=None)`.
  **`start` sets `ctx.run_id`; `finish` clears it.** Task 7 appends `resume` to
  the same module.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_run.py -- the whole file as of Task 6
"""Section 8's bracket. `run.start` and `run.finish` are what a run IS to the
tool layer, and in Plan B they are also what a live Burp is bracketed by."""
from __future__ import annotations

from hx.tools import dispatch, registry
from hx.tools.impl import run as run_tools  # noqa: F401  (registers)


def test_the_three_tools_are_registered_and_only_two_mutate():
    assert registry.lookup("run.start").mutates is True
    assert registry.lookup("run.finish").mutates is True
    assert registry.lookup("run.journal").mutates is False


def test_start_opens_a_run_and_binds_it_to_the_context(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    assert env.outcome == "ok"
    assert env.result["id"].startswith("r-")
    assert tool_ctx.run_id == env.result["id"]
    row = tool_ctx.conn.execute("SELECT kind, status FROM run WHERE id=?",
                           (env.result["id"],)).fetchone()
    assert row == ("manual", "running")


def test_an_unknown_kind_is_a_schema_refusal_not_a_valueerror(tool_ctx):
    # hx.run.open_run raises ValueError on a bad kind. Reaching it would turn
    # an ordinary agent mistake into `error / internal`, which reads as a
    # defect in hx rather than as a wrong argument.
    env = dispatch.dispatch(tool_ctx, "run.start", {"kind": "audit"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finish_closes_the_run_and_unbinds_it(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    run_id = tool_ctx.run_id
    env = dispatch.dispatch(tool_ctx, "run.finish",
                            {"status": "completed", "note": "done"}, why="done")
    assert env.outcome == "ok" and tool_ctx.run_id is None
    assert tool_ctx.conn.execute("SELECT status, stop_reason FROM run WHERE id=?",
                            (run_id,)).fetchone() == ("completed", "done")


def test_finish_without_a_run_is_unavailable_not_an_error(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "run.finish", {"status": "completed"}, why="w")
    assert (env.outcome, env.reason) == ("unavailable", "no_run")


def test_killed_is_not_a_status_the_agent_may_write(tool_ctx):
    # `killed` is the operator's word for what they did to a run. An agent
    # writing it would put a human act in the run table.
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="w")
    env = dispatch.dispatch(tool_ctx, "run.finish", {"status": "killed"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_journal_shows_what_was_already_tried_newest_first(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="one")
    dispatch.dispatch(tool_ctx, "run.finish", {"status": "completed"}, why="two")
    env = dispatch.dispatch(tool_ctx, "run.journal", {})
    tools = [r["tool"] for r in env.result["rows"]]
    assert tools[0] == "run.finish" and "run.start" in tools


def test_the_journal_can_be_filtered_by_tool(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="one")
    dispatch.dispatch(tool_ctx, "run.journal", {})
    env = dispatch.dispatch(tool_ctx, "run.journal", {"tool": "run.start"})
    assert {r["tool"] for r in env.result["rows"]} == {"run.start"}


def test_the_journal_page_is_capped_and_says_when_there_is_more(tool_ctx):
    for _ in range(4):
        dispatch.dispatch(tool_ctx, "run.journal", {})
    env = dispatch.dispatch(tool_ctx, "run.journal", {"last_n": 2})
    assert env.result["returned"] == 2 and env.result["truncated"] is True


def test_starting_twice_on_the_same_context_is_refused(tool_ctx):
    env1 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    run_id_1 = env1.result["id"]
    env2 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="second")
    assert (env2.outcome, env2.reason) == ("refused", "run_open")
    # Exactly one running row exists
    rows = tool_ctx.conn.execute(
        "SELECT id, status FROM run WHERE engagement_id=?",
        (tool_ctx.engagement.id,)).fetchall()
    running = [r for r in rows if r[1] == "running"]
    assert len(running) == 1 and running[0][0] == run_id_1


def test_a_different_kind_can_start_while_one_is_running(tool_ctx):
    env1 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    run_id_1 = env1.result["id"]
    env2 = dispatch.dispatch(tool_ctx, "run.start", {"kind": "browse"}, why="second")
    assert env2.outcome == "ok" and env2.result["id"].startswith("r-")
    run_id_2 = env2.result["id"]
    assert run_id_1 != run_id_2
    # Both running rows exist
    rows = tool_ctx.conn.execute(
        "SELECT id, kind, status FROM run WHERE engagement_id=?",
        (tool_ctx.engagement.id,)).fetchall()
    running = [(r[0], r[1]) for r in rows if r[2] == "running"]
    assert len(running) == 2
    assert {r[1] for r in running} == {"manual", "browse"}


def test_starting_the_same_kind_from_a_new_context_is_refused(tool_ctx, engagement):
    from hx import halt as halt_mod
    from hx.tools import dispatch as dispatch_mod
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="first")
    # Create a new context for the same engagement
    new_ctx = dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db))
    env2 = dispatch.dispatch(new_ctx, "run.start", {"kind": "manual"}, why="second")
    assert (env2.outcome, env2.reason) == ("refused", "run_open")
```

- [ ] **Step 2: Run it and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_run.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.tools.impl'`

- [ ] **Step 3: Write `src/hx/tools/impl/__init__.py`**

Task 11 appends the imports that make every tool register from one place. It
starts as a docstring alone so this task's block stays a contiguous run of the
finished file.

```python
# src/hx/tools/impl/__init__.py -- the docstring, as of Task 6
"""The handlers.

Importing this package imports every module below it, which is what puts the
tools in `hx.tools.registry.TOOLS`. Adapters import THIS; nothing imports the
handler modules one at a time except their own tests.
"""
```

- [ ] **Step 4: Write `src/hx/tools/impl/run.py`**

```python
# src/hx/tools/impl/run.py -- start, finish and journal, as of Task 6
"""The run lifecycle: section 8's bracket, and in Plan B the JVM's.

`run.start` and `run.finish` are the only pair in the seventeen that mean
something to the layer itself rather than to the store: `ctx.run_id` is bound
by one and cleared by the other, and every row anything else writes hangs off
it. Plan B gives the same pair a live Burp to bracket, which is why the design
puts the session here rather than in a tool of its own.
"""
from __future__ import annotations

from ... import run as run_mod
from .. import envelope, live as live_mod, registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: `killed` is absent DELIBERATELY. The run table admits five statuses; that
#: one is the operator's word for what they did to a run, and an agent writing
#: it would put a human act in the run table. `aborted` is the agent's word
#: for a run it stopped itself.
AGENT_STATUSES = ("completed", "aborted", "error")

#: The journal answers "what have I already tried"; it is read, not paged
#: through, so its default is smaller than a query's.
JOURNAL_DEFAULT = 20


def start(ctx, kind: str) -> dict:
    """Open a run, bind it to this context, and bracket a Burp if the kind
    needs one -- `session` in the result says whether it got one, and if not,
    which of `hx.tools.live`'s four reasons applies."""
    # Check for existing running runs of the same kind for this engagement.
    # Per-kind, not per-engagement: a crawl running while you browse is two runs,
    # because the enforcement rules differ by exactly that distinction.
    existing = ctx.conn.execute(
        "SELECT id FROM run WHERE engagement_id=? AND kind=? AND status='running'",
        (ctx.engagement.id, kind)).fetchone()
    if existing is not None:
        raise ToolRefused(
            "run_open",
            f"a {kind} run is already open: {existing[0]}; run.finish closes it")

    run_id = run_mod.open_run(ctx.conn, engagement_id=ctx.engagement.id,
                              kind=kind,
                              safety_profile=ctx.config.safety_profile)
    ctx.run_id = run_id
    # AFTER the run row, deliberately: `open_for` can fail, and a failure
    # that had to be reported with no run to report it against would be a
    # failure with no journal row and no run row -- the one call that was
    # trying to set the instrument up, leaving no trace that it did not.
    return {"id": run_id, "kind": kind,
            "safety_profile": ctx.config.safety_profile,
            "session": live_mod.open_for(ctx, run_id, kind)}


def finish(ctx, status: str, note: str | None = None, kind: str | None = None) -> dict:
    """Close a run.

    `no_run` rather than a refusal: nothing said no, there was simply nothing
    to close. Section 12's distinction, one tool down.

    `kind` DISAMBIGUATES WHEN MORE THAN ONE RUN IS OPEN. Two runs of
    different kinds may legitimately be running at once -- `start`'s own
    refusal above only blocks a second run of the SAME kind -- so with no
    `kind` given, `ctx.run_id` already tells "one open run" from "zero or
    several" (it resolves to a run only when exactly one is open); this only
    reads `ctx.open_runs()` when it comes back `None`, to say WHICH of those
    two -- none open, or several and ambiguous -- is the case. With `kind`
    given, the run of that kind closes -- there can be at most one, by the
    rule `start` enforces -- regardless of what (if anything) this context
    has bound.

    `ctx.open_runs()`, NOT `run_mod.open_runs(...)` DIRECTLY, in both
    branches below. The two used to be separate live queries -- one here, a
    different one behind `ctx.run_id` -- that could disagree if a run opened
    or closed between them; `ctx.open_runs()` is memoised for the whole
    `dispatch()` call, so this and `ctx.run_id`'s own resolution above always
    read the same snapshot.
    """
    if kind is not None:
        running = ctx.open_runs()
        matches = [rid for rid, k in running if k == kind]
        if not matches:
            raise ToolUnavailable(
                "no_run",
                f"no {kind} run is open on this context; run.start opens one")
        closed = matches[0]
    else:
        closed = ctx.run_id
        if closed is None:
            running = ctx.open_runs()
            if len(running) > 1:
                kinds = sorted(k for _, k in running)
                raise ToolRefused(
                    "bad_args",
                    f"{len(running)} runs are open ({', '.join(kinds)}); "
                    "run.finish needs kind to say which one")
            raise ToolUnavailable(
                "no_run", "no run is open on this context; run.start opens one")

    run_mod.close_run(ctx.conn, run_id=closed, status=status, stop_reason=note)
    # THE JVM GOES WITH THE RUN. `run.finish` is the one tool exempt from the
    # halt refusal (`dispatch.HALT_EXEMPT`) precisely so that an operator who
    # has hit STOP can still close the bracket -- and closing the bracket has
    # to include tearing the Burp down, or a halt leaves a live JVM behind
    # with nothing left that is allowed to stop it.
    #
    # `closed`, not `ctx.run_id`: `kind` may have named a run this context
    # never bound, and the session belongs to whichever run LAUNCHED it --
    # `close_for` answers False for any other, so a `finish` that closed one
    # run cannot take away another run's instrument.
    session_closed = live_mod.close_for(ctx, closed)
    # Only clear what THIS context bound, and only if it is the run just
    # closed -- `kind` may have closed a run this context never bound (one
    # opened by a different context on the same engagement), and clearing an
    # unrelated binding would forget a run that is still open.
    if ctx.run_id == closed:
        ctx.run_id = None
    return {"id": closed, "status": status, "session_closed": session_closed}


def journal(ctx, since: int | None = None, last_n: int | None = None,
            tool: str | None = None) -> dict:
    """What this agent has already tried, newest first.

    NEWEST FIRST because the question is "what did I just do", not "what is the
    history of this engagement". An agent re-reading its own journal after a
    compaction wants the last thing it tried at the top.

    `next_cursor` IS ALWAYS NULL, and that is a limitation rather than an
    oversight: section 8 gives this tool `since` and `last_n` and no cursor, so
    `truncated` means "narrow with `since`, or raise `last_n`". Paging a
    descending time series through a cursor needs a `before`, which section 8
    does not name and this plan does not invent.
    """
    limit = JOURNAL_DEFAULT if last_n is None else last_n
    where = ["engagement_id = ?", "actor = ?"]
    params: list = [ctx.engagement.id, ctx.actor]
    if since is not None:
        where.append("ts_us >= ?")
        params.append(since)
    if tool is not None:
        where.append("tool = ?")
        params.append(tool)
    clause = " AND ".join(where)
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM agent_action WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT ts_us, tool, why, result_summary FROM agent_action"
        f" WHERE {clause} ORDER BY ts_us DESC, rowid DESC LIMIT ?",
        (*params, limit + 1)).fetchall()
    return envelope.page(
        [{"ts_us": r[0], "tool": r[1], "why": r[2], "result": r[3]}
         for r in rows],
        total=total, limit=limit)


registry.register(spec.ToolSpec(
    name="run.start", handler=start, mutates=True,
    summary="Open a run. Every row anything else writes hangs off it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["kind"],
            "properties": {"kind": {
                "type": "string", "enum": sorted(run_mod.RUN_KINDS),
                "description": "browse for proxy traffic, scan for a check "
                               "pass, crawl for discovery, manual otherwise"}}}))

registry.register(spec.ToolSpec(
    name="run.finish", handler=finish, mutates=True,
    summary="Close a run.",
    params={"type": "object", "additionalProperties": False,
            "required": ["status"],
            "properties": {
                "status": {"type": "string", "enum": list(AGENT_STATUSES),
                           "description": "completed, or aborted if you "
                                          "stopped it, or error"},
                "note": {"type": "string", "maxLength": 500,
                         "description": "why it ended this way"},
                "kind": {"type": "string", "enum": sorted(run_mod.RUN_KINDS),
                         "description": "which run to close, if more than "
                                        "one is open at once"}}}))

registry.register(spec.ToolSpec(
    name="run.journal", handler=journal,
    summary="What you have already tried this engagement, newest first.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "since": {"type": "integer", "minimum": 0,
                  "description": "only actions at or after this ts_us"},
        "last_n": {"type": "integer", "minimum": 1,
                   "maximum": envelope.MAX_LIMIT,
                   "description": f"how many, default {JOURNAL_DEFAULT}"},
        "tool": {"type": "string", "maxLength": 64,
                 "description": "only this tool's actions"}}}))
```

- [ ] **Step 5: Run the tests, then the suite, then commit**

```bash
.venv/bin/pytest tests/test_tools_run.py -q          # 9 pass
.venv/bin/pytest -q
git add src/hx/tools/impl/ tests/test_tools_run.py
git commit -m "feat(tools): the run bracket, and the journal that reads itself"
```

---

### Task 7: `run.resume` — the recovery brief

**Files:**
- Modify: `src/hx/tools/impl/run.py` (append only, after Task 6's content)
- Test: `tests/test_tools_run.py` (append)

**Interfaces:**
- Consumes: Task 6's module; `hx.halt.OperatorHalt.halted/.reason`.
- Produces: a registration for `run.resume` and `resume(ctx) -> dict` with keys
  `engagement`, `halt`, `run`, `surfaces`, `findings`, `recent`.

Spec §13.2 leaves `run.resume`'s size budget open. **This task closes it:**
`RECENT_LIMIT = 20` actions, and the brief holds counts rather than rows
everywhere else. It is read when a context window is already under pressure,
so a brief that could grow with the engagement would be useless exactly when it
is needed.

- [ ] **Step 1: Append the failing tests to `tests/test_tools_run.py`**

```python
def test_resume_answers_the_four_questions_a_compacted_agent_has(tool_ctx):
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="mapping")
    env = dispatch.dispatch(tool_ctx, "run.resume", {})
    brief = env.result
    assert set(brief) == {"engagement", "halt", "run", "surfaces",
                          "findings", "recent"}
    assert brief["run"]["id"] == tool_ctx.run_id
    assert brief["halt"]["armed"] is False


def test_resume_reports_a_halt_because_that_is_why_nothing_is_working(tool_ctx):
    tool_ctx.halt.halt("client asked us to stop")
    brief = dispatch.dispatch(tool_ctx, "run.resume", {}).result
    assert brief["halt"] == {"armed": True, "reason": "client asked us to stop"}


def test_resume_says_there_is_no_run_rather_than_omitting_the_key(tool_ctx):
    assert dispatch.dispatch(tool_ctx, "run.resume", {}).result["run"] is None


def test_the_brief_is_bounded(tool_ctx):
    from hx.tools.impl import run as run_tools
    for _ in range(run_tools.RECENT_LIMIT + 5):
        dispatch.dispatch(tool_ctx, "run.journal", {})
    brief = dispatch.dispatch(tool_ctx, "run.resume", {}).result
    assert len(brief["recent"]) == run_tools.RECENT_LIMIT


def test_resume_is_a_read_and_survives_a_halt(tool_ctx):
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "run.resume", {}).outcome == "ok"
```

- [ ] **Step 2: Run and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_run.py -q -k resume`
Expected: FAIL — `refused / not_registered`

- [ ] **Step 3: Append to `src/hx/tools/impl/run.py`**

```python
RECENT_LIMIT = 20


def resume(ctx) -> dict:
    """The purpose-built recovery brief, section 8.

    `RECENT_LIMIT` caps this brief rather than letting it grow with the
    engagement. It is read when a context window is already under pressure, so
    everything except the recent actions is a COUNT: a brief proportional to
    the store would be unreadable in exactly the situation it exists for.

    "`run.journal` and `run.resume` exist because a long run compacts. Without
    them the agent re-scans surfaces it already covered and cannot tell what it
    has done. This is the loop-prevention hole and the compaction-recovery
    hole, and they are the same hole."

    THE HALT COMES BEFORE THE WORK. An agent resuming into a halted engagement
    will otherwise read a run that is open, surfaces that are untested and
    findings that are thin, and conclude it has work to do -- when the true
    answer is that an operator stopped it. That is one refusal repeated until
    the budget is gone.
    """
    conn, eid = ctx.conn, ctx.engagement.id
    run = None
    if ctx.run_id is not None:
        row = conn.execute(
            "SELECT id, kind, status, started_us, requests_issued FROM run"
            " WHERE id=?", (ctx.run_id,)).fetchone()
        if row is not None:
            run = {"id": row[0], "kind": row[1], "status": row[2],
                   "started_us": row[3], "requests_issued": row[4]}
    surfaces = conn.execute(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE id NOT IN"
        " (SELECT surface_id FROM check_run WHERE surface_id IS NOT NULL))"
        " FROM surface WHERE engagement_id=?", (eid,)).fetchone()
    findings = dict(conn.execute(
        "SELECT severity, COUNT(*) FROM finding WHERE engagement_id=?"
        " GROUP BY severity", (eid,)).fetchall())
    recent = conn.execute(
        "SELECT ts_us, tool, why, result_summary FROM agent_action"
        " WHERE engagement_id=? AND actor=? ORDER BY ts_us DESC, rowid DESC"
        " LIMIT ?", (eid, ctx.actor, RECENT_LIMIT)).fetchall()
    return {
        "engagement": {"id": eid, "name": ctx.config.name,
                       "client": ctx.config.client,
                       "safety_profile": ctx.config.safety_profile},
        "halt": {"armed": ctx.halt.halted, "reason": ctx.halt.reason},
        "run": run,
        "surfaces": {"total": surfaces[0], "untested": surfaces[1]},
        "findings": findings,
        "recent": [{"ts_us": r[0], "tool": r[1], "why": r[2], "result": r[3]}
                   for r in recent],
    }


registry.register(spec.ToolSpec(
    name="run.resume", handler=resume,
    summary="Where you are: the halt, the open run, coverage, findings, and "
            "the last few things you tried. Read this first after a compaction.",
    params={"type": "object", "additionalProperties": False, "properties": {}}))
```

- [ ] **Step 4: Run, suite, commit**

```bash
.venv/bin/pytest tests/test_tools_run.py -q          # 14 pass
.venv/bin/pytest -q
git add src/hx/tools/impl/run.py tests/test_tools_run.py
git commit -m "feat(tools): run.resume, bounded on purpose"
```

---
### Task 8: `surface.query` and `surface.detail`

**Files:**
- Create: `src/hx/tools/impl/surface.py`
- Test: `tests/test_tools_surface.py`

**Interfaces:**
- Consumes: the `surface`, `exchange` and `check_run` tables; `envelope.page`.
- Produces: registrations for `surface.query` and `surface.detail`; handlers
  `query(ctx, host=None, method=None, kind=None, discovered_by=None,
  untested=None, limit=None, cursor=None)` and `detail(ctx, surface_id)`;
  `surface.CURSOR_PREFIX = "o-"`.

**Paging is offset-based**, cursor `o-<n>`. Keyset paging over the compound
risk-first ordering would need the whole sort tuple in the cursor. The
engagement store has one writer and a query is not held open across a scan, so
the failure mode — a row inserted mid-page shifting the boundary — is small and
must be *stated* rather than hidden. Say so in the docstring.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_surface.py -- the whole file
"""Principle 3: a tool that can return 3,400 rows must never do so by default."""
from __future__ import annotations

from hx.tools import dispatch, envelope
from hx.tools.impl import surface as surface_tools  # noqa: F401  (registers)


def _surface(conn, engagement_id, *, sid, method="GET", host="app.test",
             path="/x", kind="idempotent_read"):
    conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by, normaliser_version)"
        " VALUES(?,?,?,'https',?,443,?,'',?,'proxy',2)",
        (sid, engagement_id, method, host, path, kind))


def test_an_empty_engagement_answers_empty_not_unavailable(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", {})
    assert env.outcome == "empty" and env.result["total"] == 0


def test_state_changing_surfaces_sort_first(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", path="/read")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", path="/write",
             method="POST", kind="state_changing")
    rows = dispatch.dispatch(tool_ctx, "surface.query", {}).result["rows"]
    assert rows[0]["id"] == "s-2"


def test_filters_narrow_and_facets_count_the_filtered_set(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", host="a.test")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", host="b.test")
    env = dispatch.dispatch(tool_ctx, "surface.query", {"host": "a.test"})
    assert env.result["total"] == 1
    assert env.result["facets"]["host"] == {"a.test": 1}


def test_both_facets_count_the_filtered_set_under_two_filters(tool_ctx):
    # The test above exercises one filter and one facet key, so a bug isolated
    # to the `kind` facet -- or to facet drift when two filters combine --
    # would survive it. `total`, the page and both facets are three separate
    # queries sharing one WHERE clause; this is what holds them together.
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", host="a.test",
             path="/read")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", host="a.test",
             path="/write", method="POST", kind="state_changing")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-3", host="b.test",
             path="/other")
    env = dispatch.dispatch(tool_ctx, "surface.query",
                            {"host": "a.test", "kind": "state_changing"})
    page = env.result
    assert page["total"] == 1
    assert sum(page["facets"]["host"].values()) == page["total"]
    assert sum(page["facets"]["kind"].values()) == page["total"]
    assert page["facets"]["kind"] == {"state_changing": 1}


def test_the_default_limit_is_fifty_and_the_cursor_walks(tool_ctx):
    for i in range(60):
        _surface(tool_ctx.conn, tool_ctx.engagement.id, sid=f"s-{i:03d}", path=f"/p{i:03d}")
    first = dispatch.dispatch(tool_ctx, "surface.query", {}).result
    assert first["returned"] == envelope.DEFAULT_LIMIT
    assert first["truncated"] is True and first["next_cursor"] == "o-50"
    second = dispatch.dispatch(tool_ctx, "surface.query",
                               {"cursor": first["next_cursor"]}).result
    assert second["returned"] == 10 and second["truncated"] is False
    assert not {r["id"] for r in first["rows"]} & {r["id"] for r in second["rows"]}


def test_the_cursor_walks_three_pages_and_from_an_off_multiple_offset(tool_ctx):
    # The two-page test proves full coverage only by pigeonhole on its exact
    # fixture size (50 + 10 = 60). This walks three pages and then re-enters
    # at an offset that is not a multiple of the limit, which is what an agent
    # that resumed from a stale cursor actually does.
    for i in range(12):
        _surface(tool_ctx.conn, tool_ctx.engagement.id, sid=f"s-{i:02d}",
                 path=f"/p{i:02d}")
    seen, cursor = [], None
    while True:
        args = {"limit": 5}
        if cursor:
            args["cursor"] = cursor
        page = dispatch.dispatch(tool_ctx, "surface.query", args).result
        seen.extend(r["id"] for r in page["rows"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 12 and len(set(seen)) == 12

    off = dispatch.dispatch(tool_ctx, "surface.query",
                            {"limit": 5, "cursor": "o-3"}).result
    assert [r["id"] for r in off["rows"]] == seen[3:8]


def test_a_malformed_cursor_is_a_refusal_not_a_crash(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "surface.query", {"cursor": "nonsense"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_an_overflowing_cursor_is_a_refusal_not_error_internal(tool_ctx):
    # Item 2 of the final whole-branch review, end to end: `o-` followed by
    # twenty nines is a valid Python int but not a valid SQLite offset --
    # SQLite binds it as a signed 64-bit C integer and raises `OverflowError`.
    # This used to reach dispatch's generic `except Exception` and answer
    # `error / internal`, which tells the agent hx is broken when its cursor
    # was simply implausible.
    env = dispatch.dispatch(tool_ctx, "surface.query",
                            {"cursor": "o-" + "9" * 20})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_a_unicode_digit_cursor_is_a_refusal_not_a_valueerror(tool_ctx):
    # "²" (superscript two) is a digit BY UNICODE -- `str.isdigit()` answers
    # True -- but not one `int()` accepts in base 10, so the old guard let it
    # through and `int()` raised `ValueError` two lines later.
    env = dispatch.dispatch(tool_ctx, "surface.query", {"cursor": "o-²"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_untested_is_the_filter_that_makes_coverage_actionable(tool_ctx):
    # DISTINCT PATHS, and not incidentally: `surface` is UNIQUE on
    # (engagement_id, method, scheme, host, port, path_template, query_key_set)
    # -- schema.sql:128 -- because a surface IS its template. Two rows that
    # differ only by id are not two surfaces, and the store says so.
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1", path="/tested")
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-2", path="/untested")
    tool_ctx.conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-1',?,'scan','staging',1,'running')",
        (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO check_run(id, run_id, surface_id, check_id, check_version,"
        " verdict) VALUES('c-1','r-1','s-1','x','1','clean')")
    env = dispatch.dispatch(tool_ctx, "surface.query", {"untested": True})
    assert [r["id"] for r in env.result["rows"]] == ["s-2"]


def test_detail_says_what_was_tested_as_well_as_what_the_surface_is(tool_ctx):
    _surface(tool_ctx.conn, tool_ctx.engagement.id, sid="s-1")
    env = dispatch.dispatch(tool_ctx, "surface.detail", {"surface_id": "s-1"})
    assert env.result["id"] == "s-1"
    assert env.result["checks"] == [] and env.result["exchanges"] == 0


def test_detail_of_an_unknown_surface_is_empty_not_an_error(tool_ctx):
    # It ran and matched nothing. `unavailable` would say the tool could not
    # look, which is false and would send an agent chasing a broken tool.
    env = dispatch.dispatch(tool_ctx, "surface.detail", {"surface_id": "s-nope"})
    assert env.outcome == "empty"
```

- [ ] **Step 2: Run and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_surface.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.tools.impl.surface'`

- [ ] **Step 3: Write `src/hx/tools/impl/surface.py`**

```python
# src/hx/tools/impl/surface.py -- the whole file
"""The attack surface, as the agent sees it.

ORDERING IS RISK-FIRST AND STABLE: state-changing surfaces before idempotent
reads, then host, path, method, id. Principle 3 asks for "stable ordering by
novelty/risk", and rowid order would hand an agent whatever the proxy happened
to see first -- which is the order a human browsed in, not an order that means
anything.

PAGING IS BY OFFSET, cursor `o-<n>`. Keyset paging over that compound ordering
would have to carry the whole sort tuple in the cursor. The engagement store
has one writer and a query is not held open across a scan, so the failure mode
-- a row inserted mid-page shifting the boundary by one -- is small. It is
still real, and it is written down here rather than discovered later.
"""
from __future__ import annotations

from .. import envelope, registry, spec

#: The one ordering, used by the page and by the count, so they cannot drift.
_ORDER = ("ORDER BY (kind = 'state_changing') DESC, host, path_template,"
          " method, id")


def query(ctx, host=None, method=None, kind=None, discovered_by=None,
          untested=None, limit=None, cursor=None) -> dict:
    """Surfaces matching the filter, riskiest first."""
    limit = envelope.DEFAULT_LIMIT if limit is None else limit
    offset = envelope.parse_offset(cursor)
    where = ["engagement_id = ?"]
    params: list = [ctx.engagement.id]
    for column, value in (("host", host), ("method", method),
                          ("kind", kind), ("discovered_by", discovered_by)):
        if value is not None:
            where.append(f"{column} = ?")
            params.append(value)
    if untested:
        # "Untested" is the coverage question section 12 turns into a report
        # table: a surface no check_run row names has not been looked at, which
        # is not the same as one that was looked at and came back clean.
        where.append("id NOT IN (SELECT surface_id FROM check_run"
                     " WHERE surface_id IS NOT NULL)")
    clause = " AND ".join(where)
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM surface WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT id, method, scheme, host, port, path_template, query_key_set,"
        f" kind, discovered_by, first_seen_run, last_seen_run"
        f" FROM surface WHERE {clause} {_ORDER} LIMIT ? OFFSET ?",
        (*params, limit + 1, offset)).fetchall()
    facets = {
        "host": dict(ctx.conn.execute(
            f"SELECT host, COUNT(*) FROM surface WHERE {clause}"
            f" GROUP BY host ORDER BY COUNT(*) DESC", params).fetchall()),
        "kind": dict(ctx.conn.execute(
            f"SELECT kind, COUNT(*) FROM surface WHERE {clause}"
            f" GROUP BY kind", params).fetchall()),
    }
    return envelope.page(
        [{"id": r[0], "method": r[1], "scheme": r[2], "host": r[3],
          "port": r[4], "path_template": r[5], "query_keys": r[6],
          "kind": r[7], "discovered_by": r[8],
          "first_seen_run": r[9], "last_seen_run": r[10]} for r in rows],
        total=total, limit=limit, facets=facets,
        cursor_of=lambda _row: f"{envelope.CURSOR_PREFIX}{offset + limit}")


def detail(ctx, surface_id: str) -> dict | None:
    """One surface, with what has been tested on it.

    Returns None -- which the envelope reads as `empty` -- for a surface that
    does not exist. `unavailable` would claim the tool could not look, and an
    agent would go looking for a broken tool instead of a wrong id.

    THE `engagement_id` IN THE WHERE CLAUSE IS DEFENCE IN DEPTH OVER A
    STRUCTURAL GUARANTEE, and there is deliberately no test for it. Section 3
    makes the engagement the isolation unit -- its own directory, its own
    database -- and two engagements cannot share one store:
    `trg_engagement_singleton` aborts a second `engagement` row, and
    `surface.engagement_id REFERENCES engagement(id)` under `foreign_keys=ON`
    aborts a surface naming any other. Both measured. A test for cross-
    engagement leakage would have to disable the trigger AND the foreign keys
    to build the row it then asserts is unreachable, which would exercise the
    fixture rather than the product. The clause stays because it costs
    nothing and it is what the day someone relaxes those guarantees will need.
    """
    row = ctx.conn.execute(
        "SELECT id, method, scheme, host, port, path_template, query_key_set,"
        " kind, discovered_by, normaliser_version, first_seen_run,"
        " last_seen_run, exemplar_exchange_id FROM surface"
        " WHERE id=? AND engagement_id=?",
        (surface_id, ctx.engagement.id)).fetchone()
    if row is None:
        return None
    checks = ctx.conn.execute(
        "SELECT check_id, verdict, reason, requests_sent FROM check_run"
        " WHERE surface_id=? ORDER BY started_us DESC, rowid DESC",
        (surface_id,)).fetchall()
    exchanges = ctx.conn.execute(
        "SELECT COUNT(*) FROM exchange WHERE surface_id=?",
        (surface_id,)).fetchone()[0]
    return {
        "id": row[0], "method": row[1], "scheme": row[2], "host": row[3],
        "port": row[4], "path_template": row[5], "query_keys": row[6],
        "kind": row[7], "discovered_by": row[8], "normaliser_version": row[9],
        "first_seen_run": row[10], "last_seen_run": row[11],
        "exemplar_exchange_id": row[12],
        "exchanges": exchanges,
        "checks": [{"check_id": c[0], "verdict": c[1], "reason": c[2],
                    "requests_sent": c[3]} for c in checks],
    }


registry.register(spec.ToolSpec(
    name="surface.query", handler=query,
    summary="Attack surface, riskiest first. Filter, then page with the cursor.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "host": {"type": "string", "maxLength": 253},
        "method": {"type": "string", "maxLength": 16},
        "kind": {"type": "string",
                 "enum": ["idempotent_read", "state_changing", "unknown"]},
        "discovered_by": {"type": "string",
                          "enum": ["proxy", "crawl", "import", "agent"]},
        "untested": {"type": "boolean",
                     "description": "only surfaces no check has run against"},
        "limit": {"type": "integer", "minimum": 1,
                  "maximum": envelope.MAX_LIMIT,
                  "description": f"default {envelope.DEFAULT_LIMIT}"},
        "cursor": {"type": "string", "maxLength": 32,
                   "description": "the next_cursor from a previous page"}}}))

registry.register(spec.ToolSpec(
    name="surface.detail", handler=detail,
    summary="One surface, with every check that has run against it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["surface_id"],
            "properties": {"surface_id": {"type": "string", "maxLength": 64}}}))
```

- [ ] **Step 4: Run, suite, commit**

```bash
.venv/bin/pytest tests/test_tools_surface.py -q      # 8 pass
.venv/bin/pytest -q
git add src/hx/tools/impl/surface.py tests/test_tools_surface.py
git commit -m "feat(tools): surface.query and surface.detail"
```

---
### Task 9: `finding.record`, `finding.query`, `evidence.attach`

**Files:**
- Modify: `src/hx/store/records.py` (`record_evidence`, ~line 1024)
- Create: `src/hx/tools/impl/finding.py`
- Test: `tests/test_tools_finding.py`, `tests/test_records_findings.py` (append)

**Interfaces:**
- Consumes: `records.dedupe_key`, `records.upsert_finding`,
  `records.record_observation`, `records.record_evidence`;
  `checks.base.Candidate`, `checks.base.Insertion`; `hx.store.db.transaction`.
- Produces: `records.record_evidence(..., role="proof", note=None)`;
  registrations for `finding.record`, `finding.query`, `evidence.attach`;
  `finding.AGENT_TYPE = "agent"`; `finding.EVIDENCE_ROLES`.

**Read `src/hx/store/records.py:1024-1115` and `src/hx/scan.py:1853-1876` before
writing anything.** `_write_finding` is the pattern this tool follows —
`dedupe_key`, then `upsert_finding` + `record_observation` + `record_evidence`
inside one `db.transaction`.

- [ ] **Step 1: Widen `records.record_evidence`**

The columns `role`, `kind` and `note` have existed since Plan 1 and nothing has
ever written the first or the last: the INSERT hardcodes `'proof'` and
`'exchange'`. §8 gives `evidence.attach` a `role` and a `note`, so they become
keyword arguments **with defaults that preserve every existing call site byte
for byte**. One writer, because `evidence` is append-only by trigger and a
second writer is a second chance to get `seq` wrong.

Change the signature to:

```python
def record_evidence(conn: sqlite3.Connection, *, finding_id: str,
                    exchange_ids, at_us: int, role: str = "proof",
                    note: str | None = None) -> None:
```

and the INSERT inside it to:

```python
                "INSERT INTO evidence(id, finding_id, seq, role, kind,"
                " exchange_id, note, captured_us) VALUES(?,?,?,?,'exchange',?,?,?)",
```

passing `role` where `'proof'` was and `note` before `captured_us`. Add a
paragraph to the docstring saying the defaults exist so that the check runner's
calls are unchanged, and that `kind` stays `'exchange'` because that is the
only evidence kind anything can attach.

- [ ] **Step 2: Add a regression test to `tests/test_records_findings.py`**

```python
def test_record_evidence_still_defaults_to_proof_and_can_be_told_otherwise(
        engagement_conn):
    """The default keeps every check-runner call site unchanged; the parameter
    is what `evidence.attach` needs. Both, or neither is safe."""
    c = base.Candidate(title="t", issue_type_id="t-issue", severity="Low",
                       confidence="Firm", insertion=None,
                       exchange_ids=("x-1", "x-2"))
    fid = records.upsert_finding(engagement_conn, engagement_id="e-1",
                                 candidate=c, dedupe_key=key(), run_id="r-1")
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-1",), at_us=1)
    records.record_evidence(engagement_conn, finding_id=fid,
                            exchange_ids=("x-2",), at_us=2,
                            role="baseline", note="unauthenticated control")
    rows = engagement_conn.execute(
        "SELECT role, note FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert rows == [("proof", None), ("baseline", "unauthenticated control")]
```

`engagement_conn`, `base.Candidate`, `key()` and `records` are already
imported at the top of that file — this is the same shape as
`test_evidence_rows_are_ordered_by_seq` at `tests/test_records_findings.py:264`.

- [ ] **Step 3: Write the failing tool tests**

```python
# tests/test_tools_finding.py -- the whole file
"""An agent finding must cite traffic. `Candidate` already required that of
checks; it is a better rule for an agent."""
from __future__ import annotations

import pytest

from hx.tools import dispatch
from hx.tools.impl import finding as finding_tools  # noqa: F401  (registers)
from hx.tools.impl import run as run_tools  # noqa: F401  (registers)


@pytest.fixture
def ready(tool_ctx):
    """A run, a surface and an exchange -- the least a finding can hang off."""
    dispatch.dispatch(tool_ctx, "run.start", {"kind": "manual"}, why="setup")
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version) VALUES('s-1',?,'GET','https','app.test',443,"
        "'/login','','idempotent_read','proxy',2)", (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO exchange(id, run_id, surface_id, via, outcome, sent_us,"
        " method, url, status) VALUES('x-1',?, 's-1','proxy','ok',1,'GET',"
        "'https://app.test/login',200)", (tool_ctx.run_id,))
    return tool_ctx


BASE = {"title": "Login form over plaintext", "issue_type_id": "cleartext-login",
        "severity": "Medium", "confidence": "Firm", "surface_id": "s-1",
        "exchange_ids": ["x-1"]}


def test_a_recorded_finding_is_created_by_the_agent_and_starts_new(ready):
    env = dispatch.dispatch(ready, "finding.record", BASE, why="saw it")
    assert env.outcome == "ok"
    row = ready.conn.execute(
        "SELECT created_by, status, check_id, severity FROM finding WHERE id=?",
        (env.result["id"],)).fetchone()
    assert row == ("agent", "new", None, "Medium")


def test_the_agent_does_not_get_to_spell_its_own_dedupe_key(ready):
    env = dispatch.dispatch(ready, "finding.record", BASE, why="w")
    key = ready.conn.execute("SELECT dedupe_key FROM finding WHERE id=?",
                             (env.result["id"],)).fetchone()[0]
    # Nine parts, and the first says an agent found it -- so an agent finding
    # can never collide with a check's finding of the same issue type on the
    # same surface, and a re-record of the same thing collapses onto one row.
    assert key.split("|")[0] == "agent"
    assert len(key.split("|")) == 9
    again = dispatch.dispatch(ready, "finding.record", BASE, why="w")
    assert again.result["id"] == env.result["id"]


def test_a_finding_with_no_exchanges_is_refused(ready):
    # `exchange_ids` now carries `minItems: 1` in the schema (final
    # whole-branch review's item 2), so this is caught at validation, before
    # the handler's own "a finding must cite the exchanges" check ever runs
    # -- `dispatch` validates before it calls. The handler's own check stays
    # in place as defence in depth for a caller that reaches `record()`
    # directly, bypassing the schema (as `tests/test_records_findings.py`
    # and this module's own fixtures do elsewhere).
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, exchange_ids=[]), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "exchange_ids" in env.detail and "fewer than 1" in env.detail


def test_exchange_ids_past_the_ceiling_is_refused_not_too_many_sql_variables(ready):
    # MEASURED, before this fix: 60,000 exchange ids reached `record`'s own
    # `IN (...)` lookup and raised `OperationalError: too many SQL
    # variables` -- `error / internal`, telling the agent hx was broken when
    # its argument was simply too large. `exchange_ids` now carries
    # `maxItems` (final whole-branch review's item 2), so an over-long list
    # is `bad_args` at validation and the handler never builds the query.
    from hx.tools.impl import finding as finding_mod
    too_many = [f"x-{i}" for i in range(finding_mod.MAX_EXCHANGE_IDS + 1)]
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, exchange_ids=too_many), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
    assert "exchange_ids" in env.detail and "more than" in env.detail


def test_finding_query_cursor_rejects_an_overflowing_offset(ready):
    env = dispatch.dispatch(ready, "finding.query", {"cursor": "o-" + "9" * 20})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finding_query_cursor_rejects_a_unicode_digit(ready):
    env = dispatch.dispatch(ready, "finding.query", {"cursor": "o-²"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_recording_without_a_run_is_unavailable(tool_ctx):
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version) VALUES('s-1',?,'GET','https','app.test',443,"
        "'/login','','idempotent_read','proxy',2)", (tool_ctx.engagement.id,))
    env = dispatch.dispatch(tool_ctx, "finding.record", BASE, why="w")
    assert (env.outcome, env.reason) == ("unavailable", "no_run")


def test_an_unknown_surface_is_refused_rather_than_written(ready):
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, surface_id="s-nope"), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_agent_cannot_write_a_status_at_all(ready):
    # Not "cannot write confirmed" -- cannot write ANY status. Status is a
    # human act (section 8) and `finding.set_status` has no registry entry.
    env = dispatch.dispatch(ready, "finding.record",
                            dict(BASE, status="confirmed"), why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_finding_query_filters_and_pages(ready):
    dispatch.dispatch(ready, "finding.record", BASE, why="w")
    dispatch.dispatch(ready, "finding.record",
                      dict(BASE, issue_type_id="other", severity="Low",
                           title="Something else"), why="w")
    env = dispatch.dispatch(ready, "finding.query", {"severity": "Medium"})
    assert env.result["total"] == 1
    assert env.result["rows"][0]["issue_type_id"] == "cleartext-login"


def test_evidence_attaches_with_a_role_and_a_note(ready):
    fid = dispatch.dispatch(ready, "finding.record", BASE, why="w").result["id"]
    env = dispatch.dispatch(ready, "evidence.attach",
                            {"finding_id": fid, "exchange_id": "x-1",
                             "role": "baseline", "note": "control request"},
                            why="showing the difference")
    assert env.outcome == "ok"
    rows = ready.conn.execute(
        "SELECT role, note FROM evidence WHERE finding_id=? ORDER BY seq",
        (fid,)).fetchall()
    assert ("baseline", "control request") in rows


def test_an_evidence_role_outside_the_set_is_refused(ready):
    fid = dispatch.dispatch(ready, "finding.record", BASE, why="w").result["id"]
    env = dispatch.dispatch(ready, "evidence.attach",
                            {"finding_id": fid, "exchange_id": "x-1",
                             "role": "smoking-gun"}, why="w")
    assert (env.outcome, env.reason) == ("refused", "bad_args")
```

- [ ] **Step 4: Write `src/hx/tools/impl/finding.py`**

```python
# src/hx/tools/impl/finding.py -- the whole file
"""What the agent believes, and what it is showing you.

TWO PROPERTIES THIS MODULE DOES NOT INVENT, because `checks.base.Candidate`
already had them for checks and they are better rules for an agent:

  - A FINDING MUST CITE EXCHANGES. `Candidate.exchange_ids` is required, so an
    agent-recorded finding cannot exist without traffic behind it. That is what
    keeps a `created_by='agent'` row answerable in a client deliverable.
  - THE AGENT DOES NOT SPELL ITS OWN DEDUPE KEY. Candidate's own docstring:
    "The check does NOT compute the dedupe key. That is one canonical string
    and one place must build it, or two checks will spell the same finding two
    ways and the UNIQUE constraint will hold two rows." An agent is a worse
    offender than a check, not a better one.

`type_` IS `agent`, NOT A CHECK ID. It is the first of the nine parts, so an
agent finding can never collide with a check's finding of the same issue type
on the same surface -- and two agent recordings of the same thing collapse onto
one row, which is the behaviour a re-run needs.

STATUS IS NOT AN ARGUMENT. Section 8 keeps `finding.set_status` out of the
agent's hands entirely; `upsert_finding` writes `new` and never moves it. The
schema here has no `status` property, so asking for one is `bad_args` -- the
absence is the rule, and `trg_agent_cannot_confirm` is what survives someone
adding the tool back.
"""
from __future__ import annotations

from ...checks import base as checks_base
from ...engagement import now_us
from ...store import db as db_mod
from ...store import records
from .. import envelope, registry, spec
from ..errors import ToolRefused, ToolUnavailable

#: One word, two columns, deliberately. It is the first part of the dedupe key
#: for anything an agent records -- which is what keeps an agent finding from
#: colliding with a check's finding of the same issue type on the same surface
#: -- and it is `finding.created_by`. The two are the same claim about the
#: same row, so they are one constant; and if the dedupe prefix were ever
#: changed independently, `created_by`'s CHECK constraint would refuse the
#: write rather than let the two drift quietly apart. `created_by` is a
#: storage-layer distinction, not yet a reporting one -- no report renders it
#: today; see `records.upsert_finding`'s docstring for the correction.
AGENT_TYPE = "agent"

#: The ceiling on `exchange_ids`. Before the final whole-branch review's item
#: 2, no array in the schema subset could be bounded at all -- `schema.py` had
#: no `maxItems` keyword to bound one with -- so `finding.record` built an
#: `IN (...)` list straight from whatever an agent sent. MEASURED: 60,000
#: exchange ids raised `OperationalError: too many SQL variables`, an
#: `error / internal` that told the agent hx was broken when its argument was
#: simply too large. Comfortably above any real citation -- a finding with a
#: few dozen supporting exchanges is already generous -- and comfortably below
#: SQLite's own default variable ceiling (999 in most builds).
MAX_EXCHANGE_IDS = 200

#: The `evidence.role` column has no CHECK constraint -- it was written by one
#: caller with one literal, so it never needed one. Now that a tool can set it,
#: the vocabulary has to live somewhere, and a closed set here is what stops it
#: becoming free text that no report can group by.
EVIDENCE_ROLES = ("proof", "baseline", "context")


def record(ctx, *, title, issue_type_id, severity, confidence, surface_id,
           exchange_ids, description=None, impact=None, remediation=None,
           cwe=None, payload=None, scope_level="surface",
           insertion_kind=None, insertion_name=None) -> dict:
    """Write a finding the agent believes in. Returns its id and dedupe key."""
    if ctx.run_id is None:
        # "There is nothing" and "I cannot tell" are different facts --
        # section 12's distinction, and `run.finish` already draws it for
        # the same `None`. Ambiguity is DIFFERENT from an empty engagement:
        # an agent reading `no_run` when two runs are actually open would
        # believe `run.start` is what it needs, when what it needs is
        # `run.finish` closing the one it did not mean. `ctx.open_runs()`
        # reads the SAME per-call snapshot `ctx.run_id` just consulted above
        # -- no second live query, and so no chance of a different answer.
        open_now = ctx.open_runs()
        if len(open_now) > 1:
            kinds = sorted(k for _, k in open_now)
            raise ToolRefused(
                "bad_args",
                f"{len(open_now)} runs are open ({', '.join(kinds)}); a "
                "finding cannot be attributed to one without run.finish "
                "closing the rest first")
        raise ToolUnavailable(
            "no_run", "a finding belongs to a run; run.start opens one")
    if not exchange_ids:
        raise ToolRefused(
            "bad_args",
            "a finding must cite the exchanges that show it. Record the "
            "traffic first, then record what it demonstrates.")
    surface = ctx.conn.execute(
        "SELECT id, method, scheme, host, port, path_template FROM surface"
        " WHERE id=? AND engagement_id=?",
        (surface_id, ctx.engagement.id)).fetchone()
    if surface is None:
        raise ToolRefused("bad_args", f"no surface {surface_id!r} in this engagement")
    known = {r[0] for r in ctx.conn.execute(
        "SELECT id FROM exchange WHERE id IN (%s)"
        % ",".join("?" * len(exchange_ids)), exchange_ids).fetchall()}
    missing = [x for x in exchange_ids if x not in known]
    if missing:
        raise ToolRefused("bad_args", f"no such exchanges: {sorted(missing)}")

    insertion = None
    if insertion_kind or insertion_name:
        if not (insertion_kind and insertion_name):
            raise ToolRefused(
                "bad_args", "an insertion point needs both a kind and a name")
        insertion = checks_base.Insertion(kind=insertion_kind, name=insertion_name)

    candidate = checks_base.Candidate(
        title=title, issue_type_id=issue_type_id, severity=severity,
        confidence=confidence, insertion=insertion,
        exchange_ids=tuple(exchange_ids), description=description,
        impact=impact, remediation=remediation, cwe=cwe,
        scope_level=scope_level, payload=payload)

    _sid, method, scheme, host, port, path_template = surface
    key = records.dedupe_key(
        type_=AGENT_TYPE, issue_type_id=issue_type_id, scheme=scheme,
        host=host, port=port, method=method, path_template=path_template,
        insertion_kind=insertion.kind if insertion else None,
        insertion_name=insertion.name if insertion else None,
        scope_level=scope_level)
    at = now_us()
    with db_mod.transaction(ctx.conn):
        fid = records.upsert_finding(
            ctx.conn, engagement_id=ctx.engagement.id, candidate=candidate,
            dedupe_key=key, run_id=ctx.run_id, surface_id=surface_id,
            host=host, check_id=None, created_by=AGENT_TYPE)
        records.record_observation(
            ctx.conn, finding_id=fid, run_id=ctx.run_id, observed=True,
            exchange_id=exchange_ids[0], severity_at=severity,
            confidence_at=confidence, at_us=at)
        records.record_evidence(ctx.conn, finding_id=fid,
                                exchange_ids=tuple(exchange_ids), at_us=at)
    return {"id": fid, "dedupe_key": key}


def query(ctx, severity=None, status=None, host=None, surface_id=None,
          created_by=None, limit=None, cursor=None) -> dict:
    """Findings matching the filter, most severe first."""
    limit = envelope.DEFAULT_LIMIT if limit is None else limit
    offset = envelope.parse_offset(cursor)
    where = ["engagement_id = ?"]
    params: list = [ctx.engagement.id]
    for column, value in (("severity", severity), ("status", status),
                          ("host", host), ("surface_id", surface_id),
                          ("created_by", created_by)):
        if value is not None:
            where.append(f"{column} = ?")
            params.append(value)
    clause = " AND ".join(where)
    # Severity order is the report's, not alphabetical: Critical before High
    # before Medium. Alphabetical would put Critical after Low and an agent
    # reading the first page would meet the least important thing first.
    order = ("ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
             " WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, id")
    total = ctx.conn.execute(
        f"SELECT COUNT(*) FROM finding WHERE {clause}", params).fetchone()[0]
    rows = ctx.conn.execute(
        f"SELECT id, title, issue_type_id, severity, confidence, status,"
        f" created_by, host, surface_id, check_id, cwe FROM finding"
        f" WHERE {clause} {order} LIMIT ? OFFSET ?",
        (*params, limit + 1, offset)).fetchall()
    facets = {"severity": dict(ctx.conn.execute(
        f"SELECT severity, COUNT(*) FROM finding WHERE {clause}"
        f" GROUP BY severity", params).fetchall())}
    return envelope.page(
        [{"id": r[0], "title": r[1], "issue_type_id": r[2], "severity": r[3],
          "confidence": r[4], "status": r[5], "created_by": r[6],
          "host": r[7], "surface_id": r[8], "check_id": r[9], "cwe": r[10]}
         for r in rows],
        total=total, limit=limit, facets=facets,
        cursor_of=lambda _row: f"{envelope.CURSOR_PREFIX}{offset + limit}")


def attach(ctx, finding_id, exchange_id, role="proof", note=None) -> dict:
    """Add one exchange to a finding's evidence chain."""
    if role not in EVIDENCE_ROLES:
        raise ToolRefused("bad_args",
                          f"role must be one of {list(EVIDENCE_ROLES)}")
    exists = ctx.conn.execute(
        "SELECT 1 FROM finding WHERE id=? AND engagement_id=?",
        (finding_id, ctx.engagement.id)).fetchone()
    if exists is None:
        raise ToolRefused("bad_args", f"no finding {finding_id!r}")
    if ctx.conn.execute("SELECT 1 FROM exchange WHERE id=?",
                        (exchange_id,)).fetchone() is None:
        raise ToolRefused("bad_args", f"no exchange {exchange_id!r}")
    records.record_evidence(ctx.conn, finding_id=finding_id,
                            exchange_ids=(exchange_id,), at_us=now_us(),
                            role=role, note=note)
    return {"id": finding_id, "exchange_id": exchange_id, "role": role}


_TEXT = {"type": "string", "maxLength": 4000}

registry.register(spec.ToolSpec(
    name="finding.record", handler=record, mutates=True,
    summary="Record a finding. It must cite the exchanges that show it.",
    params={"type": "object", "additionalProperties": False,
            "required": ["title", "issue_type_id", "severity", "confidence",
                         "surface_id", "exchange_ids"],
            "properties": {
                "title": {"type": "string", "maxLength": 200},
                "issue_type_id": {
                    "type": "string", "maxLength": 100,
                    "description": "stable lowercase-kebab name for the KIND "
                                   "of issue, e.g. missing-hsts; never the "
                                   "code path that noticed it"},
                "severity": {"type": "string",
                             "enum": ["Critical", "High", "Medium", "Low", "Info"]},
                "confidence": {"type": "string",
                               "enum": ["Certain", "Firm", "Tentative"]},
                "surface_id": {"type": "string", "maxLength": 64},
                "exchange_ids": {"type": "array",
                                 "items": {"type": "string", "maxLength": 64},
                                 "minItems": 1, "maxItems": MAX_EXCHANGE_IDS,
                                 "description": "the traffic that shows it -- "
                                                f"at least one, at most "
                                                f"{MAX_EXCHANGE_IDS}"},
                "description": _TEXT, "impact": _TEXT, "remediation": _TEXT,
                "cwe": {"type": "string", "maxLength": 32},
                "payload": {"type": "string", "maxLength": 2000,
                            "description": "the value it was demonstrated "
                                           "with, before transport encoding"},
                "scope_level": {"type": "string",
                                "enum": ["engagement", "host", "surface",
                                         "insertion"]},
                "insertion_kind": {
                    "type": "string",
                    "enum": sorted(checks_base.INSERTION_KINDS)},
                "insertion_name": {"type": "string", "maxLength": 200}}}))

registry.register(spec.ToolSpec(
    name="finding.query", handler=query,
    summary="Findings, most severe first.",
    params={"type": "object", "additionalProperties": False, "properties": {
        "severity": {"type": "string",
                     "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "status": {"type": "string",
                   "enum": ["new", "triaged", "confirmed", "false_positive",
                            "reported"]},
        "host": {"type": "string", "maxLength": 253},
        "surface_id": {"type": "string", "maxLength": 64},
        "created_by": {"type": "string", "enum": ["agent", "human", "check"]},
        "limit": {"type": "integer", "minimum": 1,
                  "maximum": envelope.MAX_LIMIT},
        "cursor": {"type": "string", "maxLength": 32}}}))

registry.register(spec.ToolSpec(
    name="evidence.attach", handler=attach, mutates=True,
    summary="Add one exchange to a finding's evidence chain.",
    params={"type": "object", "additionalProperties": False,
            "required": ["finding_id", "exchange_id"],
            "properties": {
                "finding_id": {"type": "string", "maxLength": 64},
                "exchange_id": {"type": "string", "maxLength": 64},
                "role": {"type": "string", "enum": list(EVIDENCE_ROLES),
                         "description": "proof shows it; baseline is the "
                                        "control it differs from; context is "
                                        "neither"},
                "note": {"type": "string", "maxLength": 500}}}))
```

Note the `status` filter on `finding.query` DOES admit `confirmed` and
`reported`: reading a status an operator set is not writing one, and an agent
that cannot see what was already triaged will re-report it.

- [ ] **Step 5: Run, suite, commit**

```bash
.venv/bin/pytest tests/test_tools_finding.py tests/test_records_findings.py -q
.venv/bin/pytest -q
git add src/hx/store/records.py src/hx/tools/impl/finding.py tests/test_tools_finding.py tests/test_records_findings.py
git commit -m "feat(tools): findings the agent must cite traffic for"
```

---
### Task 10: `checks.list` and `report.render`

**Files:**
- Create: `src/hx/tools/impl/checks.py`, `src/hx/tools/impl/report.py`
- Test: `tests/test_tools_checks_report.py`

**Interfaces:**
- Consumes: `hx.checks.registry.CHECKS/KNOWN_CLASSES/enabled`;
  `hx.checks.base.Check` (`.id`, `.version`, `.klass`, `.insertion_kinds`);
  `hx.scan.needs_a_bridge(check)`; `hx.report.render(conn, *, engagement_id,
  config, blobs=None)`.
- Produces: registrations for `checks.list` and `report.render`.

`checks.list` reports **every** check with an `enabled` flag, not only the
enabled ones. A corpus listing that hid disabled checks would let an agent
conclude a class was not applicable when it was merely switched off — the same
confusion §12 forbids one layer down.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_checks_report.py -- the whole file
"""What can be run, and what the client will read."""
from __future__ import annotations

from hx.tools import dispatch
from hx.tools.impl import checks as checks_tools  # noqa: F401  (registers)
from hx.tools.impl import report as report_tools  # noqa: F401  (registers)


def test_the_corpus_lists_disabled_checks_too_and_says_so(tool_ctx):
    rows = dispatch.dispatch(tool_ctx, "checks.list", {}).result["rows"]
    assert rows, "the corpus is not empty"
    assert {"id", "version", "class", "enabled", "needs_egress",
            "insertion_kinds"} <= set(rows[0])
    assert all(r["enabled"] for r in rows), "the fixture enables every class"
    whole_corpus = {r["id"] for r in rows}

    # THE PROPERTY, and the first version of this test did not test it. It
    # asserted `any(r["enabled"] for r in rows)` -- which passes while every
    # class is enabled, and would go on passing if `checks.list` returned
    # ONLY the enabled ones. It asserted the opposite of what its own comment
    # claimed.
    #
    # What matters is that disabling a class changes a FLAG and not
    # MEMBERSHIP: an agent that cannot see `active_safe` in the corpus
    # concludes the class does not apply to this application, where one that
    # sees it listed `enabled: false` knows an operator turned it off. Those
    # are different facts and only one of them belongs in a report.
    tool_ctx.config.checks["active_safe"] = False
    rows = dispatch.dispatch(tool_ctx, "checks.list", {}).result["rows"]
    assert {r["id"] for r in rows} == whole_corpus, "a disabled class vanished"
    off = [r for r in rows if not r["enabled"]]
    assert off and {r["class"] for r in off} == {"active_safe"}


def test_a_class_filter_narrows(tool_ctx):
    rows = dispatch.dispatch(tool_ctx, "checks.list",
                             {"class": "passive"}).result["rows"]
    assert rows and {r["class"] for r in rows} == {"passive"}


def test_an_unknown_class_is_a_schema_refusal(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "checks.list", {"class": "telepathy"})
    assert (env.outcome, env.reason) == ("refused", "bad_args")


def test_the_report_renders_markdown_and_reports_its_size(tool_ctx):
    env = dispatch.dispatch(tool_ctx, "report.render", {})
    assert env.outcome == "ok"
    assert env.result["markdown"].lstrip().startswith("#")
    assert env.result["bytes"] == len(env.result["markdown"].encode("utf-8"))


def test_the_report_is_a_read_and_survives_a_halt(tool_ctx):
    # A halted engagement is exactly when someone wants the report.
    tool_ctx.halt.halt("stop")
    assert dispatch.dispatch(tool_ctx, "report.render", {}).outcome == "ok"


def test_the_report_is_rendered_with_the_blob_store_not_without_it(tool_ctx):
    """`report.render` passes `ctx.blobs` through, proved rather than assumed.

    The insertion-points section is derived at render time from the captured
    request bytes -- `report._insertion_coverage` reads `blobs.get(req_blob)`
    -- so it is the one part of the document that vanishes if the blob store
    does not arrive. On the empty fixture the other tests use,
    `render(blobs=...)` and `render(blobs=None)` are byte-identical: writing
    `blobs=None` in the handler would silently drop insertion coverage from
    every real engagement and change nothing they assert.

    `_insertion_coverage`'s own docstring records this exact defect landing
    once already -- a bare `except Exception` swallowed `blobs.get`'s
    `AttributeError` for a `blobs=None` caller, and fourteen tests went on
    passing.
    """
    digest, _ = tool_ctx.blobs.put(
        b"GET /search?q=hello&page=2 HTTP/1.1\r\nHost: app.test\r\n\r\n")
    tool_ctx.conn.execute(
        "INSERT INTO run(id, engagement_id, kind, safety_profile, started_us,"
        " status) VALUES('r-1',?,'browse','staging',1,'completed')",
        (tool_ctx.engagement.id,))
    tool_ctx.conn.execute(
        "INSERT INTO exchange(id, run_id, via, outcome, sent_us, method, url,"
        " status, req_blob) VALUES('x-1','r-1','proxy','ok',1,'GET',"
        "'https://app.test/search?q=hello&page=2',200,?)", (digest,))
    tool_ctx.conn.execute(
        "INSERT INTO surface(id, engagement_id, method, scheme, host, port,"
        " path_template, query_key_set, kind, discovered_by,"
        " normaliser_version, exemplar_exchange_id)"
        " VALUES('s-1',?,'GET','https','app.test',443,'/search','page,q',"
        "'idempotent_read','proxy',2,'x-1')", (tool_ctx.engagement.id,))

    out = dispatch.dispatch(tool_ctx, "report.render", {}).result["markdown"]
    assert "### Insertion points" in out
    assert "`query`" in out
```

- [ ] **Step 2: Run and watch it fail**

Run: `.venv/bin/pytest tests/test_tools_checks_report.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'hx.tools.impl.checks'`

- [ ] **Step 3: Write `src/hx/tools/impl/checks.py`**

```python
# src/hx/tools/impl/checks.py -- the whole file
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
```

- [ ] **Step 4: Write `src/hx/tools/impl/report.py`**

```python
# src/hx/tools/impl/report.py -- the whole file
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
```

- [ ] **Step 5: Run, suite, commit**

```bash
.venv/bin/pytest tests/test_tools_checks_report.py -q    # 5 pass
.venv/bin/pytest -q
git add src/hx/tools/impl/checks.py src/hx/tools/impl/report.py tests/test_tools_checks_report.py
git commit -m "feat(tools): the corpus including what is switched off"
```

---

### Task 11: The CLI adapter, the wiring, and the five properties

**Files:**
- Modify: `src/hx/tools/impl/__init__.py` (append), `src/hx/cli.py`,
  `tests/test_plan_matches_repo.py` (`EXPECTED_BLOCKS`),
  `tests/test_credentials_never_reach_the_store.py` (append), `README.md`
- Create: `src/hx/tools/adapters/__init__.py`, `src/hx/tools/adapters/cli.py`,
  `tests/test_tools_contract.py`
- Test: `tests/test_tools_contract.py`, `tests/test_cli_tool.py`

**Interfaces:**
- Consumes: everything.
- Produces: `hx tool` and `hx tool --list`; `adapters/cli.py:build_context(root)`.

This task closes design §11's five properties. Four of them can only be
asserted once every Plan A tool is registered, which is why they live here.

- [ ] **Step 1: Append the imports to `src/hx/tools/impl/__init__.py`**

```python
from . import checks, finding, report, run, surface  # noqa: F401
```

- [ ] **Step 2: Write the contract tests**

```python
# tests/test_tools_contract.py -- the whole file
"""Design section 11: the five properties asserted about the layer itself,
rather than about any one tool."""
from __future__ import annotations

import pytest

from hx.tools import dispatch, registry, spec
from hx.tools import impl  # noqa: F401  (registers every tool)

#: The eleven Plan A builds. The other six carry `needs_egress` and arrive
#: with the session bracket in Plan B.
PLAN_A = {
    "run.start", "run.finish", "run.journal", "run.resume",
    "surface.query", "surface.detail",
    "finding.record", "finding.query", "evidence.attach",
    "checks.list", "report.render",
}

PLAN_B = {"http.send", "http.grep", "http.body", "http.replay_as",
          "scan.run", "crawl.run"}

#: Which of PLAN_B is actually registered so far. Each Plan B task adds its
#: tool's name here in the same commit that registers it -- the discipline
#: PLAN_A already kept as a fixed set, now split in two because PLAN_A no
#: longer describes the whole registry once ANY Plan B tool lands. Task 7
#: (`scan.run`, `crawl.run`) is the last, so this now equals `PLAN_B`.
PLAN_B_BUILT = {"http.send", "http.grep", "http.body", "http.replay_as",
                "scan.run", "crawl.run"}


def test_the_registry_is_exactly_the_tools_built_so_far():
    # Property 1, half of it. Adding a tool without spec'ing it fails here,
    # and so does spec'ing one without building it. PLAN_B_BUILT grows to
    # match PLAN_B as the rest of Plan B lands, at which point this is the
    # full seventeen.
    assert set(registry.TOOLS) == PLAN_A | PLAN_B_BUILT


def test_plan_b_built_is_a_subset_of_plan_b():
    # Fix round 1's finding 3. `test_the_registry_is_exactly_the_tools_built_
    # so_far` above is only as strong as `PLAN_B_BUILT` itself: without this,
    # a tool registered under a name outside section 8's seventeen is
    # admitted into the registry just by adding it to `PLAN_B_BUILT`, and
    # `test_plan_a_and_plan_b_together_are_section_eights_seventeen` below
    # would never see it -- it compares only `PLAN_A | PLAN_B`, which
    # `PLAN_B_BUILT` does not appear in at all. This restores the half of
    # property 1 that check was meant to cover: `PLAN_B_BUILT` may only ever
    # name tools the plan already promised.
    assert PLAN_B_BUILT <= PLAN_B


def test_plan_a_and_plan_b_together_are_section_eights_seventeen():
    assert PLAN_A | PLAN_B == spec.V1_TOOL_NAMES
    assert not (PLAN_A & PLAN_B)


def test_the_three_human_acts_have_no_entry():
    # Property 2. The absence IS the rule -- there is no code path to forget.
    for name in ("engagement.create", "surface.add", "finding.set_status"):
        assert registry.lookup(name) is None


def test_every_registered_tool_has_an_enforceable_schema_and_a_summary():
    from hx.tools import schema
    for name, tool in registry.TOOLS.items():
        schema.check_schema(tool.params, where=name)
        assert tool.summary.strip(), f"{name} has no summary"
        assert tool.params.get("type") == "object", f"{name} takes an object"


def test_mutating_tools_are_exactly_the_ones_that_write():
    writes = {"run.start", "run.finish", "finding.record", "evidence.attach",
              "http.send", "http.replay_as", "scan.run", "crawl.run"}
    assert {n for n, t in registry.TOOLS.items() if t.mutates} == writes


def test_no_plan_a_tool_needs_egress():
    # The claim is about PLAN_A specifically, not about the registry as a
    # whole: PLAN_B's whole reason to exist is the six tools that DO carry
    # `needs_egress` (spec section 8), and `http.send` is the first of them
    # to be built. Filtered to PLAN_A so this keeps meaning what it always
    # meant rather than becoming vacuously true or falsely red the moment
    # any Plan B tool lands.
    assert not any(t.needs_egress for n, t in registry.TOOLS.items()
                   if n in PLAN_A)


def test_every_tool_schema_matches_its_handlers_signature():
    """A schema property the handler has no parameter for is a `TypeError` at
    call time, which `dispatch` reports as `error / internal` -- an hx defect
    surfaced to the agent mid-engagement, for what is really a wrong tool
    definition.

    Task 5's review proposed catching it inside `registry.register` with
    `inspect`. It lives here instead: the registry should not need to
    introspect a callable to do its job, and a test covers tools added after
    this plan exactly as well -- Plan B's six included.
    """
    import inspect

    for name, tool in registry.TOOLS.items():
        params = inspect.signature(tool.handler).parameters
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            # `checks.list` takes **kw because its argument is spelled `class`
            # on the wire, which is a Python keyword. Nothing to check.
            continue
        declared = set(tool.params.get("properties") or {})
        missing = declared - (set(params) - {"ctx"})
        assert not missing, (
            f"{name}: the schema declares {sorted(missing)} and the handler "
            "takes no such parameter; dispatch would raise TypeError")
        for optional in declared - set(tool.params.get("required") or ()):
            assert params[optional].default is not inspect.Parameter.empty, (
                f"{name}: {optional} is optional in the schema but the handler "
                "gives it no default, so omitting it raises")


def test_the_agent_cannot_confirm_its_own_finding_two_ways_over(engagement):
    # Property 4. The registry has no finding.set_status, so there is no path;
    # and the trigger is what survives someone adding the tool back.
    assert registry.lookup("finding.set_status") is None
    with pytest.raises(Exception, match="agent may not set status"):
        engagement.db.execute(
            "INSERT INTO finding_status_event(id, finding_id, ts_us, actor,"
            " from_status, to_status) VALUES('e-1','f-1',1,'agent',"
            "'new','confirmed')")


def test_every_mutating_tool_is_refused_while_a_halt_is_armed(tool_ctx):
    # `run.finish` is the one deliberate exception -- `dispatch.HALT_EXEMPT`,
    # item 6 of the final whole-branch review. Closing an open run does LESS,
    # not more, and in Plan B it is what stops the Burp JVM, so the halt gate
    # must not block it. `test_the_halt_exemption_is_exactly_run_finish` (in
    # `test_tools_dispatch.py`) asserts the exempt set holds nothing else, so
    # skipping it here does not widen what this test lets through silently.
    tool_ctx.halt.halt("stop")
    for name, tool in registry.TOOLS.items():
        if not tool.mutates or name in dispatch.HALT_EXEMPT:
            continue
        env = dispatch.dispatch(tool_ctx, name, {}, why="trying anyway")
        assert env.reason == "halted", f"{name} ran while halted"
```

The `finding_status_event` insert above must match that table's real columns —
read `src/hx/store/schema.sql` and adjust the column list if it differs. The
assertion that matters is the trigger message, not the column names.

- [ ] **Step 3: Append the credential case to `tests/test_credentials_never_reach_the_store.py`**

```python
def test_a_credential_never_reaches_agent_action(engagement):
    """Principle 5 is what makes `args_blob` safe to store verbatim: identity
    is passed by NAME and resolved below the tool layer. If a tool ever took a
    credential value, this column becomes the place credentials are written to
    disk in the clear."""
    from hx.tools import registry
    from hx.tools import impl  # noqa: F401

    # No tool declares a property that could carry a secret. Checked against
    # the SCHEMAS rather than against a run, so it holds for arguments nobody
    # has thought to pass yet.
    for name, tool in registry.TOOLS.items():
        for prop in (tool.params.get("properties") or {}):
            assert not any(w in prop.lower() for w in
                           ("cookie", "authorization", "token", "password",
                            "secret", "credential")), f"{name}.{prop}"
```

Follow the file's existing style for the rest of its assertions; if it already
has a helper that scans a database for credential-shaped strings, add a call to
it that covers `agent_action` as well.

- [ ] **Step 4: Write `src/hx/tools/adapters/__init__.py` and `adapters/cli.py`**

```python
# src/hx/tools/adapters/__init__.py -- the whole file
"""Transports. Each one is a projection of `hx.tools.registry.TOOLS`.

An adapter validates nothing, authorises nothing and journals nothing: it turns
a request into `dispatch(ctx, name, args, why=...)` and an envelope into
whatever its transport speaks. Anything more here is a second place the rules
live.
"""
```

```python
# src/hx/tools/adapters/cli.py -- the whole file
"""`hx tool` -- the tool layer from a shell.

The adapter the test suite drives, and the one an agent with a shell can use
with no MCP wiring at all. Plan B adds `hx mcp` beside it over the same
`dispatch`.

EXIT STATUS FOLLOWS `Envelope.ran`, not the outcome: `ok` and `empty` are both
0, because a query that matched nothing ran correctly, and a shell that treated
"no findings" as a failure would make every clean engagement look broken.
Everything else is 1.
"""
from __future__ import annotations

import json

import click

from ... import halt as halt_mod
from .. import dispatch as dispatch_mod
from .. import impl  # noqa: F401  -- registers every tool
from .. import registry


def build_context(engagement, *, stack=None) -> dispatch_mod.ToolContext:
    """A context over an open engagement.

    NOTHING IS BOUND HERE, and that is fine: each `hx tool` invocation is its
    own process, so a context built here has never seen a `run.start` this
    process ran. `ToolContext.run_id` does not need it to have -- unbound, it
    resolves the open run from the store, and a run `run.start` opened in an
    EARLIER `hx tool` process is still there to find. What this adapter
    cannot do is hold a run across invocations in the FIELD -- there is no
    long-lived object here for `run.start` to bind onto that a later call
    would see -- which is exactly why the resolution had to move to the
    store rather than staying a process-local field.

    `stack` IS NONE FROM THIS ADAPTER AND THAT IS THE HONEST ANSWER, not a
    limitation waiting to be lifted. `hx.session.session()` tears Burp down on
    every exit, so a JVM launched inside a one-shot `hx tool` process dies
    with it -- there is no object here for a session to outlive. `run.start`
    is told so and reports `session: {live: false, reason: "no_host"}`, which
    names `hx mcp` as the adapter that can. The parameter exists because
    `hx mcp` builds its context through this same function.
    """
    return dispatch_mod.ToolContext(
        engagement=engagement, conn=engagement.db, blobs=engagement.blobs,
        config=engagement.config,
        halt=halt_mod.OperatorHalt(engagement.root, engagement.db),
        stack=stack)


def render_listing() -> str:
    """Every tool, for an operator or an agent orienting itself."""
    lines = []
    for name in sorted(registry.TOOLS):
        tool = registry.TOOLS[name]
        marks = "".join(("!" if tool.mutates else " ",
                         "*" if tool.needs_egress else " "))
        lines.append(f"{marks} {name:<20} {tool.summary}")
    lines.append("")
    lines.append("! changes state and needs --why    * needs a live session")
    return "\n".join(lines)


def run_tool(engagement, name: str, args_json: str | None,
             why: str | None) -> tuple[str, int]:
    """Dispatch and render. Returns the text to print and the exit status."""
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"--json is not JSON: {exc}") from exc
    if not isinstance(args, dict):
        raise click.ClickException("--json must be an object")
    env = dispatch_mod.dispatch(build_context(engagement), name, args, why=why)
    return json.dumps(env.as_dict(), indent=2, sort_keys=True), 0 if env.ran else 1
```

- [ ] **Step 5: Register the command in `src/hx/cli.py`**

Add this after the existing `report` command, using the module's own
`_open_engagement` and `default_root` helpers. Import `adapters.cli` lazily
inside the function so `hx --help` does not import the check corpus.

```python
@main.command("tool")
@click.argument("name", required=False)
@click.option("--json", "args_json", default=None,
              help="Arguments as a JSON object.")
@click.option("--why", default=None,
              help="Why you are doing this. Required by state-changing tools; "
                   "written to agent_action.")
@click.option("--root", type=click.Path(path_type=Path), default=None)
@click.option("--list", "list_only", is_flag=True,
              help="List every tool and exit.")
def tool(name, args_json, why, root, list_only) -> None:
    """Call one agent tool and print its envelope as JSON."""
    from hx.tools.adapters import cli as tool_cli

    if list_only or not name:
        click.echo(tool_cli.render_listing())
        return
    eng = _open_engagement(root or default_root())
    text, status = tool_cli.run_tool(eng, name, args_json, why)
    click.echo(text)
    if status:
        raise SystemExit(status)
```

- [ ] **Step 6: Write `tests/test_cli_tool.py`**

`tests/test_cli.py` already stands up a `CliRunner` and an engagement on disk.
Reuse its fixtures if they are in `conftest.py`; if they are local to that
file, lift the smaller of the two rather than writing a third. The header and
the four assertions:

```python
import json

import pytest
from click.testing import CliRunner

from hx import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def engagement_root(engagement):
    """The directory `hx tool --root` is pointed at."""
    return engagement.root


def test_listing_needs_no_engagement(runner):
    out = runner.invoke(cli.main, ["tool", "--list"])
    assert out.exit_code == 0 and "run.resume" in out.output


def test_a_query_prints_an_envelope_and_exits_zero_when_empty(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "surface.query", "--root",
                                   str(engagement_root)])
    assert out.exit_code == 0
    assert json.loads(out.output)["outcome"] == "empty"


def test_a_refusal_exits_nonzero(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "run.start", "--json",
                                   '{"kind":"manual"}', "--root",
                                   str(engagement_root)])
    assert out.exit_code == 1
    assert json.loads(out.output)["reason"] == "missing_why"


def test_malformed_json_is_a_click_error_not_a_traceback(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "surface.query", "--json", "{",
                                   "--root", str(engagement_root)])
    assert out.exit_code != 0 and "not JSON" in out.output
```

- [ ] **Step 7: Verify `EXPECTED_BLOCKS`**

`tests/test_plan_matches_repo.py` counts every path-marked block across all
plans. The commit that added THIS plan already raised `EXPECTED_BLOCKS` from
141 to 169 — its 28 blocks were counted the moment it landed, while being
skipped from comparison because none of their files existed yet. As each task
creates its files those blocks start being compared byte for byte, which is the
point. Confirm the number is still right rather than assuming it:

```bash
.venv/bin/python -c "
import sys; sys.path.insert(0, 'tests')
import test_plan_matches_repo as t
print(len(t._cases()))
"
```

It must print 169. If it does not, a block was added or removed during
execution — update the constant in the same commit and name the block.

- [ ] **Step 8: Document it in `README.md`**

Add a **Tools** section after the CLI section: what the tool layer is, the
`hx tool --list` invocation, the five outcomes with one line each, the
published decision order, and one worked example (`hx tool surface.query
--json '{"untested":true}'`). State plainly that six of the seventeen are not
built yet and that they are the ones needing a live session.

- [ ] **Step 9: Full green, then commit**

```bash
.venv/bin/pytest -q
.venv/bin/ruff check src tests
git add -A
git commit -m "feat(tools): the CLI adapter, and the five properties asserted"
```

---

## Done means

- `.venv/bin/pytest -q` green, `.venv/bin/ruff check` clean.
- `hx tool --list` prints eleven tools.
- `set(registry.TOOLS) == PLAN_A`, and `PLAN_A | PLAN_B == V1_TOOL_NAMES`.
- The three human acts have no entry.
- Every mutating tool is refused while a halt is armed.
- No registered tool declares a credential-shaped argument.
- `EXPECTED_BLOCKS` updated in the commit that changed the block count.
