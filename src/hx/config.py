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


# The three headers `Redactor.unmanagedCredential`
# (extension/src/hx/send/Redactor.java:143-144) already refuses when the
# extension did not itself inject them -- confirmed against that file rather
# than assumed: `CREDENTIAL_HEADERS = {"authorization", "cookie",
# "proxy-authorization"}`, byte for byte the same three, there lower-cased for
# ASCII-insensitive comparison. Injecting anything else through `identity`
# would not be a credential in the sense the send path enforces, and would
# not need any of this machinery. Not configurable: an operator cannot widen
# the set here without also widening what the extension itself will carry.
CREDENTIAL_HEADERS = ("Cookie", "Authorization", "Proxy-Authorization")

VALID_STRATEGIES = ("static", "programmatic")


@dataclass(frozen=True)
class Inject:
    """Which header carries the credential, and where the value comes from.

    `value_from_env` names an environment variable rather than holding a
    value -- see the module-level note on `Config.identities` for why. It is
    required for a `static` identity (the only place a value ever comes from
    the environment) and optional for a `programmatic` one, whose credential
    instead comes from `Refresh.command`'s stdout at resolve time (spec §4's
    `admin` example declares `inject: {header: Authorization}` with no
    `value_from_env` at all).
    """
    header: str
    value_from_env: str | None = None


@dataclass(frozen=True)
class Liveness:
    """How this identity proves it is still logged in.

    `expect_body` is REQUIRED and is the load-bearing field. A canary that
    accepted a status code would be satisfied by an application answering a
    logged-out request with a 200 login page -- the one shape no
    response-status rule can catch, and the one `hx.scan._retirable` refused
    ALL active-check retirement over until this plan gave it a proof to read.
    It reads one now: an active check's `considered` is honoured for a run
    whose canary came back `proven`, so a canary a login page could satisfy
    would hand that hazard straight back with a stamp on it. This field is
    what stops it.
    """
    path: str
    expect_body: str
    expect_absent: str | None = None
    every_n_probes: int = 25


@dataclass(frozen=True)
class Refresh:
    # A LIST, never a string. `hx.identity.refresh` (a later task) executes
    # this without a shell, and the list is what makes "no shell ever sees
    # it" true regardless of what an operator writes -- a string would invite
    # `shell=True` at the call site however it was spelled.
    command: tuple[str, ...]
    value_from: str = "stdout"


@dataclass(frozen=True)
class Identity:
    id: str
    strategy: str
    inject: Inject
    liveness: Liveness
    refresh: Refresh | None = None


def _identity(name: str, raw: dict) -> Identity:
    """Parse one `identities.<name>` block into a declaration.

    Structurally cannot carry a resolved secret: every field here is a name
    (a header, an env var, a command) or a proof (a liveness signature),
    never a value. Task 2's `hx.identity.resolve` reads the environment
    separately and keeps the result off this type entirely.
    """
    if not isinstance(raw, dict):
        raise ConfigError(f"identities.{name} must be a mapping")

    strategy = raw.get("strategy")
    if strategy not in VALID_STRATEGIES:
        raise ConfigError(
            f"identities.{name}.strategy must be one of {VALID_STRATEGIES}, "
            f"got {strategy!r}"
        )

    inj = _mapping(raw, "inject")
    header = inj.get("header")
    if header not in CREDENTIAL_HEADERS:
        raise ConfigError(
            f"identities.{name}.inject.header must be one of "
            f"{CREDENTIAL_HEADERS}, got {header!r}"
        )
    env = inj.get("value_from_env")
    if env is not None and (not isinstance(env, str) or not env.strip()):
        raise ConfigError(
            f"identities.{name}.inject.value_from_env must be a non-empty "
            "string naming an environment variable when given; a credential "
            "may not be written here"
        )
    if strategy == "static" and not env:
        raise ConfigError(
            f"identities.{name}.inject.value_from_env is required for a "
            "static identity: it is the only source of the credential a "
            "static identity has, and the config must name where the "
            "secret comes from without ever holding it"
        )

    live = _mapping(raw, "liveness")
    if not live:
        raise ConfigError(
            f"identities.{name} has no liveness block. An identity that "
            "cannot prove it is live can never be `proven`, and traffic "
            "issued under it is indistinguishable from anonymous traffic"
        )
    expect = live.get("expect_body")
    if not isinstance(expect, str) or not expect.strip():
        raise ConfigError(
            f"identities.{name}.liveness.expect_body is required and must "
            "be a non-empty string: a signature only an AUTHENTICATED "
            "response carries. A status code is not one -- a 200 login "
            "page has one too, and accepting that is the exact defect this "
            "declaration exists to close"
        )
    path = live.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ConfigError(
            f"identities.{name}.liveness.path must be an origin-form path "
            f"starting with '/', got {path!r}"
        )
    absent = live.get("expect_absent")
    if absent is not None and (not isinstance(absent, str) or not absent.strip()):
        raise ConfigError(
            f"identities.{name}.liveness.expect_absent, when given, must be "
            "a non-empty string"
        )
    liveness = Liveness(
        path=path,
        expect_body=expect,
        expect_absent=absent,
        every_n_probes=_positive_int(live, "every_n_probes", 25),
    )

    refresh_raw = _mapping(raw, "refresh")
    if strategy == "static" and refresh_raw:
        raise ConfigError(
            f"identities.{name} is static and may not declare refresh: "
            "there is no command to re-run, and a static credential that "
            "expired is a dead session, not a refreshable one"
        )
    if strategy == "programmatic" and not refresh_raw:
        raise ConfigError(
            f"identities.{name} is programmatic and must declare refresh"
        )

    refresh = None
    if refresh_raw:
        command = refresh_raw.get("command")
        if not isinstance(command, list) or not command:
            raise ConfigError(
                f"identities.{name}.refresh.command must be a non-empty "
                "list of arguments, never a string: it is executed without "
                "a shell, and a string would invite one"
            )
        if not all(isinstance(x, str) for x in command):
            raise ConfigError(
                f"every entry in identities.{name}.refresh.command must be "
                "a string"
            )
        value_from = refresh_raw.get("value_from", "stdout")
        if value_from != "stdout":
            raise ConfigError(
                f"identities.{name}.refresh.value_from must be 'stdout', "
                f"got {value_from!r}"
            )
        refresh = Refresh(command=tuple(command), value_from=value_from)

    return Identity(
        id=name,
        strategy=strategy,
        inject=Inject(header=header, value_from_env=env),
        liveness=liveness,
        refresh=refresh,
    )


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
    # `Limits.arm()` (extension/src/hx/send/Limits.java) falls back to this
    # same number -- documented in HxExtension.DEFAULT_MAX_REQUESTS -- when a
    # configure body omits `limit.max_requests`. Matching it means adding the
    # field to this dataclass changes no behaviour for an operator who set
    # nothing: the budget was always 2000, it was just never written down.
    max_requests: int = 2000
    max_concurrency: int = 2
    # A credential value must NEVER be reachable from here.
    # `hx.engagement.record_scope_version` writes the loaded config's YAML
    # verbatim into `scope_version.yaml` -- `_record_scope`'s `INSERT INTO
    # scope_version` at `engagement.py:114`, whose `yaml` column takes
    # `config.dumps(cfg)` whole -- a
    # table the schema calls "append-only: tamper-evidence for contract
    # disputes" -- so a secret on this object is a secret copied,
    # unredactably, into a table designed to be impossible to rewrite. Each
    # `Identity` names an environment variable instead; the value that
    # variable holds is resolved separately (`hx.identity.resolve`, a later
    # task) into an object that never touches `Config`. `dumps()` below is
    # built to make that structural, not just documented: it reads only
    # declaration fields off `Identity`, so there is no field to leak even by
    # accident.
    identities: dict[str, Identity] = field(default_factory=dict)
    # Which declared identity `hx scan` issues its probes under. `None` is
    # anonymous, same as before this field existed. Validated against
    # `identities` at load time -- see `load_text` -- so a typo here is a
    # config-time error, not a scan that silently runs unauthenticated.
    scan_identity: str | None = None
    # `preserve_segments` names path segments the normaliser must NOT template.
    # THE DEFAULT PROTECTS NOTHING, and an operator who leaves it alone should
    # know that: no rule in `hx.surface` matches `api`, `v1`, `v2` or `v3` at
    # any threshold above 2, so the list changes no template until you put
    # something in it that a rule would otherwise reach. That is a numeric
    # segment which is really a route -- a year, an API generation, a tenant
    # number -- which is what the field is for. `["2024", "2025"]` is a list
    # that does something; the shipped one is a placeholder.
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
    check_entries(key, v)
    return list(v)


def check_entries(key: str, values: list[str]) -> None:
    """Refuse a blank entry in a list of patterns.

    A blank entry means nothing to any consumer, and in a scope list it is
    actively dangerous: the extension refuses an empty pattern outright --
    Rule.forExclude("") throws and the whole decision becomes scope_denied --
    so one stray blank line in scope.exclude takes the engagement to deny-all
    mid-run. Failing closed there is right; failing HERE is better, because the
    operator finds out before the run rather than after the first refusal.

    A PUBLIC function rather than a branch inside _string_list, because
    _string_list only ever runs in load(), and load() is not the only way a
    Config is built. `hx new` constructs one directly from its options and
    dumps() it, so `hx new --exclude ''` wrote `exclude: ['', ...]` to
    config.yaml AND to the scope_version row while every check in this module
    passed -- the guard fired on the next `load()`, which is to say after the
    engagement existed. Not a bypass (the extension still fails closed), but
    the whole point of the guard was that the operator learns at `hx new`, and
    on that path they did not. cli.new() calls this before it builds anything.

    Narrow on purpose, and unchanged from where the check used to live: a blank
    ENTRY is refused, an explicitly empty LIST is not. The spec requires
    `exclude: []` to stay writable and reviewable.
    """
    for i, x in enumerate(values):
        if not x.strip():
            raise ConfigError(
                f"{key}[{i}] is blank; remove the entry or give it a value"
            )


def _positive_int(raw: dict, key: str, default: int) -> int:
    v = raw.get(key, default)
    # bool is a subclass of int; `rate_limit_rps: true` must not become 1.
    if isinstance(v, bool) or not isinstance(v, int) or v < 1:
        raise ConfigError(f"{key} must be an integer >= 1, got {v!r}")
    return v


def load(path: Path) -> Config:
    """Read `path` and parse it. Everything else lives in `load_text`.

    Two parsers that must agree is how they come to disagree, so `load`
    is reduced to the read and delegates parsing entirely -- `load_text` is
    the one place YAML becomes a `Config`, whether the text came from disk
    or, as the round-trip test does, from `dumps()` still in memory.
    """
    return load_text(Path(path).read_text(encoding="utf-8"))


def load_text(text: str) -> Config:
    # A YAML syntax error is "nonsense" by this module's own definition of
    # ConfigError. Wrapping it here means no caller has to know PyYAML is
    # the parser underneath.
    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
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

    identities = {
        ident_name: _identity(ident_name, body)
        for ident_name, body in _mapping(raw, "identities").items()
    }

    scan_identity = raw.get("scan_identity")
    if scan_identity is not None:
        if not isinstance(scan_identity, str):
            raise ConfigError(
                "scan_identity must be a string, got "
                f"{type(scan_identity).__name__}"
            )
        if scan_identity not in identities:
            raise ConfigError(
                f"scan_identity names {scan_identity!r}, which is not a "
                f"declared identity. Declared: {sorted(identities) or 'none'}"
            )

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
        max_requests=_positive_int(raw, "max_requests", 2000),
        max_concurrency=_positive_int(raw, "max_concurrency", 2),
        identities=identities,
        scan_identity=scan_identity,
        preserve_segments=_string_list(raw, "preserve_segments", ["api", "v1", "v2", "v3"]),
        slug_threshold=_positive_int(raw, "slug_threshold", 12),
    )


def _identity_yaml(i: Identity) -> dict:
    """The DECLARATION, and structurally nothing else.

    Built field by field from the dataclass rather than by dumping an
    object, so there is no path by which a resolved credential could ride
    along: `Identity` has no field holding one (see `hx.identity.resolve`,
    a later task, which keeps secrets in a separate mapping that is never
    passed here). `scope_version.yaml` stores whatever this returns
    VERBATIM in an append-only table -- see the spec's §3.
    """
    out: dict = {
        "strategy": i.strategy,
        "inject": {"header": i.inject.header},
        "liveness": {
            "path": i.liveness.path,
            "expect_body": i.liveness.expect_body,
            "every_n_probes": i.liveness.every_n_probes,
        },
    }
    if i.inject.value_from_env is not None:
        out["inject"]["value_from_env"] = i.inject.value_from_env
    if i.liveness.expect_absent is not None:
        out["liveness"]["expect_absent"] = i.liveness.expect_absent
    if i.refresh is not None:
        out["refresh"] = {
            "command": list(i.refresh.command),
            "value_from": i.refresh.value_from,
        }
    return out


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
            "max_requests": cfg.max_requests,
            "max_concurrency": cfg.max_concurrency,
            "identities": {n: _identity_yaml(i) for n, i in cfg.identities.items()},
            "scan_identity": cfg.scan_identity,
            "preserve_segments": cfg.preserve_segments,
            "slug_threshold": cfg.slug_threshold,
        },
        sort_keys=False,
    )
