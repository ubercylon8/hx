"""Engagement configuration.

Defaults are chosen so that an under-specified config is a SAFE config: the
production profile, mutating and DoS checks off, a low rate limit. Anything
that increases blast radius must be written down explicitly, in the file,
where it is recorded and reviewable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_PROFILES = ("production", "staging")

DEFAULT_DANGEROUS_PATHS: list[str] = [
    "*/logout*",
    "*/signout*",
    "*/password*",
    "*/change-password*",
    "*/reset*",
    "*/delete*",
    "*/purge*",
    "*/deactivate*",
    "*/close-account*",
]

DEFAULT_CHECKS: dict[str, bool] = {
    "passive": True,
    "active_safe": True,
    "active_timing": True,
    "active_mutate": False,
    "active_dos": False,
}


class ConfigError(Exception):
    """The engagement config is missing something required, or is nonsense."""


@dataclass(frozen=True)
class Config:
    name: str
    client: str
    safety_profile: str = "production"
    scope_include: list[str] = field(default_factory=list)
    scope_exclude: list[str] = field(default_factory=list)
    render_allow: list[str] = field(default_factory=list)
    dangerous_paths: list[str] = field(default_factory=lambda: list(DEFAULT_DANGEROUS_PATHS))
    checks: dict[str, bool] = field(default_factory=lambda: dict(DEFAULT_CHECKS))
    rate_limit_rps: int = 5
    max_concurrency: int = 2
    identities: dict[str, dict] = field(default_factory=dict)
    preserve_segments: list[str] = field(default_factory=lambda: ["api", "v1", "v2", "v3"])
    slug_threshold: int = 12


def _mapping(raw: dict, key: str) -> dict:
    """A YAML block that must be a mapping, or absent."""
    v = raw.get(key)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ConfigError(f"{key} must be a mapping, got {type(v).__name__}")
    return v


def _string_list(raw: dict, key: str, default: list[str]) -> list[str]:
    """A list of strings.

    Absent means "use the default". An explicitly written empty list means
    empty -- the operator said so in the file, which is what the spec's
    "written down explicitly, where it is recorded and reviewable" requires.

    A non-list is REJECTED rather than coerced.
    """
    if key not in raw or raw[key] is None:
        return list(default)
    v = raw[key]
    if not isinstance(v, list):
        raise ConfigError(f"{key} must be a list, got {type(v).__name__}")
    if not all(isinstance(x, str) for x in v):
        raise ConfigError(f"every entry in {key} must be a string")
    return list(v)


def _positive_int(raw: dict, key: str, default: int) -> int:
    v = raw.get(key, default)
    # bool is a subclass of int; `rate_limit_rps: true` must not become 1.
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ConfigError(f"{key} must be an integer >= 1, got {v!r}")
    return v


def load(path: Path) -> Config:
    # A YAML syntax error is "nonsense" by this module's own definition of
    # ConfigError. Wrapping it here means no caller has to know PyYAML is
    # the parser underneath.
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    # `if not raw.get(required)` is a truthiness test: `name: 123` and
    # `name: true` pass it (both truthy) and reach the database and the
    # report as coerced values. Every other field in this module rejects
    # rather than coerces; name/client must not be the exception.
    for required in ("name", "client"):
        value = raw.get(required)
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(
                f"config key {required!r} must be a non-empty string, "
                f"got {value!r} ({type(value).__name__})"
            )

    profile = raw.get("safety_profile", "production")
    if profile not in VALID_PROFILES:
        raise ConfigError(
            f"safety_profile must be one of {VALID_PROFILES}, got {profile!r}"
        )

    scope = _mapping(raw, "scope")
    include = _string_list(scope, "include", [])
    if not include:
        raise ConfigError("scope.include must list at least one target pattern")

    # Build checks by iterating over what was written, rejecting unknown keys
    # and non-bool values. Do not use dict.update().
    checks = dict(DEFAULT_CHECKS)
    checks_raw = _mapping(raw, "checks")
    for key, value in checks_raw.items():
        if key not in DEFAULT_CHECKS:
            raise ConfigError(
                f"checks.{key} is not a valid check class. Valid classes are: {', '.join(DEFAULT_CHECKS.keys())}"
            )
        if not isinstance(value, bool):
            raise ConfigError(f"checks.{key} must be a boolean, got {type(value).__name__}")
        checks[key] = value

    return Config(
        name=raw["name"],
        client=raw["client"],
        safety_profile=profile,
        scope_include=include,
        scope_exclude=_string_list(scope, "exclude", []),
        render_allow=_string_list(raw, "render_allow", []),
        dangerous_paths=_string_list(raw, "dangerous_paths", DEFAULT_DANGEROUS_PATHS),
        checks=checks,
        rate_limit_rps=_positive_int(raw, "rate_limit_rps", 5),
        max_concurrency=_positive_int(raw, "max_concurrency", 2),
        identities=_mapping(raw, "identities"),
        preserve_segments=_string_list(raw, "preserve_segments", ["api", "v1", "v2", "v3"]),
        slug_threshold=_positive_int(raw, "slug_threshold", 12),
    )


def dumps(cfg: Config) -> str:
    return yaml.safe_dump(
        {
            "name": cfg.name,
            "client": cfg.client,
            "safety_profile": cfg.safety_profile,
            "scope": {"include": cfg.scope_include, "exclude": cfg.scope_exclude},
            "render_allow": cfg.render_allow,
            "dangerous_paths": cfg.dangerous_paths,
            "checks": cfg.checks,
            "rate_limit_rps": cfg.rate_limit_rps,
            "max_concurrency": cfg.max_concurrency,
            "identities": cfg.identities,
            "preserve_segments": cfg.preserve_segments,
            "slug_threshold": cfg.slug_threshold,
        },
        sort_keys=False,
    )
