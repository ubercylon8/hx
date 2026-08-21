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


def load(path: Path) -> Config:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping")

    for required in ("name", "client"):
        if not raw.get(required):
            raise ConfigError(f"config is missing required key: {required}")

    profile = raw.get("safety_profile", "production")
    if profile not in VALID_PROFILES:
        raise ConfigError(
            f"safety_profile must be one of {VALID_PROFILES}, got {profile!r}"
        )

    scope = raw.get("scope") or {}
    include = scope.get("include") or []
    if not include:
        raise ConfigError("scope.include must list at least one target pattern")

    checks = dict(DEFAULT_CHECKS)
    checks.update(raw.get("checks") or {})

    return Config(
        name=raw["name"],
        client=raw["client"],
        safety_profile=profile,
        scope_include=list(include),
        scope_exclude=list(scope.get("exclude") or []),
        render_allow=list(raw.get("render_allow") or []),
        dangerous_paths=list(raw.get("dangerous_paths") or DEFAULT_DANGEROUS_PATHS),
        checks=checks,
        rate_limit_rps=int(raw.get("rate_limit_rps", 5)),
        max_concurrency=int(raw.get("max_concurrency", 2)),
        identities=dict(raw.get("identities") or {}),
        preserve_segments=list(raw.get("preserve_segments") or ["api", "v1", "v2", "v3"]),
        slug_threshold=int(raw.get("slug_threshold", 12)),
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
