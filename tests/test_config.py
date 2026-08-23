from pathlib import Path

import pytest

from hx import config


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_minimal_config(tmp_path: Path):
    p = _write(
        tmp_path,
        """
name: acme-2026-09
client: Acme Corp
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.name == "acme-2026-09"
    assert cfg.client == "Acme Corp"
    assert cfg.scope_include == ["https://app.acme.com/*"]


def test_defaults_are_safe(tmp_path: Path):
    """Unspecified means safe: production profile, mutating checks off."""
    p = _write(
        tmp_path,
        """
name: acme
client: Acme
scope:
  include: ["https://app.acme.com/*"]
""",
    )
    cfg = config.load(p)
    assert cfg.safety_profile == "production"
    assert cfg.checks["active_mutate"] is False
    assert cfg.checks["active_dos"] is False
    assert cfg.checks["passive"] is True
    # `<= 10` and a substring of a joined string both pass even if the real
    # default drifted -- e.g. a join could make an unrelated pair of entries
    # spell "logout" across a boundary. Assert the actual documented default
    # value and check membership in the list itself.
    assert cfg.rate_limit_rps == 5
    assert "*/logout*" in cfg.dangerous_paths


def test_empty_scope_include_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "name: acme\nclient: Acme\nscope:\n  include: []\n")
    with pytest.raises(config.ConfigError, match="scope.include"):
        config.load(p)


def test_missing_name_is_rejected(tmp_path: Path):
    p = _write(tmp_path, "client: Acme\nscope:\n  include: ['https://a/*']\n")
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


def test_unknown_safety_profile_is_rejected(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nsafety_profile: yolo\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="safety_profile"):
        config.load(p)


def test_dumps_round_trips(tmp_path: Path):
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\n",
    )
    cfg = config.load(p)
    p2 = tmp_path / "again.yaml"
    p2.write_text(config.dumps(cfg), encoding="utf-8")
    assert config.load(p2) == cfg


def test_checks_string_false_is_rejected(tmp_path: Path):
    """String 'false' must not coerce to bool True; must be rejected."""
    p = _write(
        tmp_path,
        'name: a\nclient: b\nscope:\n  include: ["https://a/*"]\nchecks:\n  active_mutate: "false"\n',
    )
    with pytest.raises(config.ConfigError, match="active_mutate.*boolean"):
        config.load(p)


def test_checks_true_bool_is_honoured(tmp_path: Path):
    """A real bool true in checks must be accepted."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks:\n  active_mutate: true\n",
    )
    cfg = config.load(p)
    assert cfg.checks["active_mutate"] is True


def test_checks_unknown_class_is_rejected(tmp_path: Path):
    """An unknown check class must be rejected, with a message naming valid classes."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks:\n  no_such_class: true\n",
    )
    with pytest.raises(config.ConfigError, match="no_such_class.*valid check class.*passive.*active_mutate"):
        config.load(p)


def test_dangerous_paths_string_is_rejected(tmp_path: Path):
    """A string dangerous_paths must not be iterated into chars; must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\ndangerous_paths: custom\n",
    )
    with pytest.raises(config.ConfigError, match="dangerous_paths.*list"):
        config.load(p)


def test_scope_include_string_is_rejected(tmp_path: Path):
    """A string scope.include must not be iterated into chars; must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: 'https://a/*'\n",
    )
    with pytest.raises(config.ConfigError, match="include.*list"):
        config.load(p)


def test_rate_limit_rps_zero_is_rejected(tmp_path: Path):
    """rate_limit_rps must be >= 1, not 0."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: 0\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_rate_limit_rps_negative_is_rejected(tmp_path: Path):
    """rate_limit_rps must be >= 1, not negative."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: -5\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_rate_limit_rps_bool_is_rejected(tmp_path: Path):
    """bool is an int subclass; rate_limit_rps: true must be rejected."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nrate_limit_rps: true\n",
    )
    with pytest.raises(config.ConfigError, match="rate_limit_rps.*integer >= 1"):
        config.load(p)


def test_scope_string_raises_config_error(tmp_path: Path):
    """scope: 'oops' must raise ConfigError, not AttributeError."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope: oops\n",
    )
    with pytest.raises(config.ConfigError, match="scope.*mapping"):
        config.load(p)


def test_checks_string_raises_config_error(tmp_path: Path):
    """checks: 'yes' must raise ConfigError, not ValueError."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\nchecks: yes\n",
    )
    with pytest.raises(config.ConfigError, match="checks.*mapping"):
        config.load(p)


def test_explicit_empty_dangerous_paths_is_honoured(tmp_path: Path):
    """An explicit empty dangerous_paths: [] must NOT be replaced by defaults."""
    p = _write(
        tmp_path,
        "name: a\nclient: b\nscope:\n  include: ['https://a/*']\ndangerous_paths: []\n",
    )
    cfg = config.load(p)
    assert cfg.dangerous_paths == []


def test_invalid_yaml_raises_config_error(tmp_path: Path):
    """Malformed YAML must raise ConfigError, not yaml.YAMLError."""
    p = _write(tmp_path, "{ invalid yaml: [")
    with pytest.raises(config.ConfigError, match="invalid YAML"):
        config.load(p)


# --- M6: name and client are the only unvalidated types in this module ---


def test_name_int_is_rejected(tmp_path: Path):
    """`if not raw.get(required)` is a truthiness test: `name: 123` is
    truthy and used to load fine, reaching the database and the report as
    a coerced value."""
    p = _write(
        tmp_path,
        "name: 123\nclient: Acme\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


def test_client_bool_is_rejected(tmp_path: Path):
    """`client: true` is truthy and used to load fine for the same reason."""
    p = _write(
        tmp_path,
        "name: acme\nclient: true\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="client"):
        config.load(p)


def test_name_blank_string_is_rejected(tmp_path: Path):
    """A whitespace-only name is a string (truthy), but not a real name."""
    p = _write(
        tmp_path,
        "name: '   '\nclient: Acme\nscope:\n  include: ['https://a/*']\n",
    )
    with pytest.raises(config.ConfigError, match="name"):
        config.load(p)


# --- Test-suite fix: a direct Config() construction, bypassing load()
# entirely ---


def test_direct_config_construction_has_safe_defaults():
    """`hx new` builds Config(...) directly and never calls load() -- so
    every default_factory field must be independently proven safe here,
    not only when reached through the YAML-parsing path."""
    cfg = config.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    assert cfg.safety_profile == "production"
    assert cfg.checks["active_mutate"] is False
    assert cfg.checks["active_dos"] is False
    assert cfg.rate_limit_rps == 5
    assert "*/logout*" in cfg.dangerous_paths
    assert cfg.scope_exclude == []
    assert cfg.identities == {}


def test_direct_config_construction_round_trips_through_dumps_and_load(tmp_path: Path):
    """The same direct-construction path `hx new` uses, proven to still
    dump and reload correctly -- not just to have safe field values."""
    cfg = config.Config(
        name="acme-2026-09",
        client="Acme Corp",
        scope_include=["https://app.acme.com/*"],
    )
    p = tmp_path / "config.yaml"
    p.write_text(config.dumps(cfg), encoding="utf-8")
    assert config.load(p) == cfg


def test_a_blank_entry_in_a_string_list_is_refused(tmp_path: Path):
    """A stray blank line in scope.exclude takes the engagement to deny-all.

    The extension already fails closed on it -- an empty pattern makes
    Rule.forExclude throw and the whole decision becomes scope_denied -- so the
    run stops rather than proceeding unprotected. That is the right direction
    and it is pinned on the Java side. The cost is that the operator learns
    mid-run, from a refusal, that a config written hours ago has a blank line
    in it. Catching it at load time is the same answer, delivered when it is
    cheap to act on.
    """
    head = 'name: a\nclient: b\n'
    for body in (
        'scope:\n  include:\n    - ""\n',
        'scope:\n  include: ["https://a/*"]\n  exclude:\n    - ""\n',
        'scope:\n  include: ["https://a/*"]\ndangerous_paths:\n  - "   "\n',
        'scope:\n  include: ["https://a/*"]\nrender_allow:\n  - ""\n',
    ):
        p = _write(tmp_path, head + body)
        with pytest.raises(config.ConfigError, match=r"\[0\] is blank"):
            config.load(p)


def test_a_deliberately_empty_list_is_still_allowed(tmp_path: Path):
    """The blank-ENTRY guard must not become a no-empty-LISTS guard.

    An explicitly written empty list is the operator saying so in the file,
    which the spec requires to stay possible and reviewable. Only a blank entry
    inside a list is meaningless.
    """
    p = _write(tmp_path, 'name: a\nclient: b\nscope:\n  include: ["https://a/*"]\n  exclude: []\n')
    cfg = config.load(p)
    assert cfg.scope_exclude == []
