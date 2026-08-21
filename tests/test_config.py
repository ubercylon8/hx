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
    assert cfg.rate_limit_rps <= 10
    assert "logout" in " ".join(cfg.dangerous_paths)


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
