"""The normaliser, exhaustively.

Every test here separates one rule from its absence. That is not a style
preference on this project: on the previous branch, rule 3 -- a guard is only
tested by the input that separates it from its absence -- fired on all eight
tasks without exception, and the normaliser is the component where a missing
separation is least visible, because a wrong template still LOOKS like a
template.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from hx import surface

PRESERVE = frozenset({"api", "v1", "v2", "v3"})
KW = {"preserve": PRESERVE, "slug_threshold": 12}

POLICY_JAVA = Path(__file__).resolve().parents[1] / "extension/src/hx/policy/Policy.java"


def t(path: str) -> str:
    return surface.path_template(path, **KW)


class TestNumericSegments:
    def test_a_numeric_segment_becomes_a_placeholder(self):
        assert t("/order/1") == "/order/{id}"

    def test_and_every_numeric_segment_collapses_to_the_same_template(self):
        assert t("/order/1") == t("/order/9999") == t("/order/0")

    def test_a_word_segment_is_kept_verbatim(self):
        """The separating case: without this, everything templates to {id}."""
        assert t("/order/status") == "/order/status"

    def test_several_numeric_segments_each_template(self):
        assert t("/user/12/order/34") == "/user/{id}/order/{id}"


class TestPlaceholderSyntaxCannotBeForged:
    r"""A segment kept verbatim must not be able to spell a template.

    `{` and `}` are the placeholder syntax, and until NORMALISER_VERSION 2 a
    literal one was emitted unchanged: `/order/1`, `/order/{id}` and
    `/order/%7Bid%7D` all produced `/order/{id}`. Same `path_template` means
    the same row under `UNIQUE (engagement_id, method, scheme, host, port,
    path_template, query_key_set)`, so an un-interpolated `href="/order/{id}"`
    on a page -- or anyone sending `GET /order/%7Bid%7D` through the proxy --
    upserts onto the real `/order/N` row and moves its `last_seen_run` onto a
    request that never touched the endpoint. Seen FIRST, the forgery is that
    row's `exemplar_exchange_id` for good: Task 4's planned `DO UPDATE SET`
    touches only `last_seen_run`, so the exemplar is whatever inserted it.

    `Policy` does not stop it: `checkHostChars` is host-only, there is no path
    charset, and `{` decodes fully, so the request is allowed.
    """

    def test_a_literal_placeholder_segment_is_escaped_not_emitted(self):
        assert t("/order/{id}") == "/order/%7Bid%7D"

    def test_so_it_cannot_share_a_row_with_the_template_it_spells(self):
        """THE SEPARATING CASE. Both sides were `/order/{id}` before."""
        assert t("/order/1") == "/order/{id}"
        assert t("/order/{id}") != t("/order/1")

    def test_and_neither_can_its_encoded_spelling(self):
        """`%7Bid%7D` decodes to `{id}`, so escaping only the literal would
        leave the same forgery one percent-escape away."""
        assert t("/order/%7Bid%7D") == "/order/%7Bid%7D"
        assert t("/order/%7buuid%7d") == "/order/%7Buuid%7D"
        assert t("/order/%7buuid%7d") != t("/session/3f2504e0-4f89-11d3-9a0c-0305e82c3301")

    def test_a_segment_with_no_braces_is_untouched_by_the_escaping(self):
        """Separates the escaping from 'mangle every kept segment'."""
        assert t("/order/status") == "/order/status"


class TestPreservedSegments:
    r"""The preserve list, and the fact that the DEFAULT list does nothing.

    Deleting the preserve rule entirely reddens nothing that the SHIPPED
    defaults reach, and the reason is not a missing test -- it is that none of
    `api`, `v1`, `v2`, `v3` is matched by any shape rule anyway. `_DIGITS` is
    `\A[0-9]+\Z`, so `v1` never matched it; there is nothing for the list to
    protect them from. `v1`, `v2` and `v3` become reachable only below
    `slug_threshold` 3, which templates `/h2`, `/v9` and nearly every short
    digit-bearing segment -- a configuration that is legal and that nobody
    runs -- and `api` never becomes reachable at all, having no digit.
    `config.py` says so where an operator will read it.

    Three claims in the first version of this class asserted otherwise -- that
    `v1` "is digits-adjacent and must survive, this is why the list exists",
    that `/v2` would "otherwise match a rule", and that `/v9` "separates the
    preserve list" (it separates the digits rule). All three were false, and
    they are the reason the no-op went unnoticed: a class full of confident
    comments about a rule that was doing nothing.

    The rule is kept because it IS reachable under legal configurations, and
    the last two tests here are what separate it from its absence.
    """

    def test_a_preserved_segment_survives_alongside_templated_ones(self):
        """Not because the list protects it -- nothing threatens `v1` under the
        defaults -- but because the digits rule must not reach across it."""
        assert t("/api/v1/order/7") == "/api/v1/order/{id}"

    def test_a_default_preserved_segment_alone_is_unchanged(self):
        assert t("/v2") == "/v2"

    def test_a_segment_not_on_the_list_is_templated_by_the_digits_rule(self):
        """`/v9` is not on the list, but that is not what templates `7`."""
        assert t("/v9/order/7") == "/v9/order/{id}"

    def test_the_default_entries_are_protected_from_nothing(self):
        """The claim above, executable: with the list EMPTY and the shipped
        threshold, every default entry templates to itself anyway."""
        bare = {"preserve": frozenset(), "slug_threshold": 12}
        for seg in ("api", "v1", "v2", "v3"):
            assert surface.path_template("/" + seg, **bare) == "/" + seg

    def test_the_list_is_load_bearing_under_a_config_that_needs_it(self):
        """A separating case for the rule.

        A numeric path segment that is genuinely a route -- a year, a version,
        an API generation -- is exactly what an operator puts on this list, and
        without the rule it templates to `{id}` and merges with every other
        number in that position. Measured: `/2024/report` becomes
        `/{id}/report` when the rule is deleted.
        """
        kw = {"preserve": frozenset({"2024"}), "slug_threshold": 12}
        assert surface.path_template("/2024/report", **kw) == "/2024/report"
        assert surface.path_template("/2025/report", **kw) == "/{id}/report"

    def test_and_it_is_checked_after_decoding_so_one_escape_cannot_defeat_it(self):
        """THE OTHER SEPARATING CASE, and the ordering bug of version 1.

        `/%32024/report` and `/20%324/report` are the same request to the same
        server as `/2024/report`. Matched against the RAW spelling, the
        operator's explicit "this segment is a route" was bypassed by one
        escape AND the encoded spelling merged into the numeric-id family:
        both measured `/{id}/report`.
        """
        kw = {"preserve": frozenset({"2024"}), "slug_threshold": 12}
        assert surface.path_template("/%32024/report", **kw) == "/2024/report"
        assert surface.path_template("/20%324/report", **kw) == "/2024/report"


class TestIdentifierShapes:
    def test_a_uuid_becomes_a_placeholder(self):
        assert t("/session/3f2504e0-4f89-11d3-9a0c-0305e82c3301") == "/session/{uuid}"

    def test_a_uuid_is_matched_case_insensitively(self):
        assert t("/session/3F2504E0-4F89-11D3-9A0C-0305E82C3301") == "/session/{uuid}"

    def test_a_long_hex_string_becomes_a_placeholder(self):
        assert t("/blob/" + "a" * 40) == "/blob/{hex}"

    def test_but_a_short_hex_word_is_left_alone(self):
        """`face` is valid hex and is also an English word. The separating case."""
        assert t("/theme/face") == "/theme/face"

    def test_a_long_mixed_segment_with_a_digit_is_a_slug(self):
        assert t("/post/hello-world-2026-edition") == "/post/{slug}"

    def test_but_a_long_segment_with_no_digit_is_kept(self):
        """Separates slug_threshold from 'anything long'. `/documentation`
        is a route, not an identifier."""
        assert t("/documentation-index") == "/documentation-index"

    def test_a_short_segment_with_a_digit_is_kept(self):
        """Separates the threshold from 'anything containing a digit'."""
        assert t("/h2") == "/h2"


class TestPercentEncoding:
    def test_an_encoded_digit_templates_the_same_as_a_bare_one(self):
        """Otherwise `/order/%31` and `/order/1` are two surfaces for one
        endpoint, and the checks visit it twice while the report counts two."""
        assert t("/order/%31") == t("/order/1") == "/order/{id}"

    def test_an_encoded_separator_does_not_create_a_segment(self):
        """`%2f` is a slash the SERVER may or may not split on. Templating as
        though it did would merge two different endpoints, so it does not."""
        assert t("/a%2fb") == "/a%2fb"

    def test_malformed_encoding_is_left_verbatim_rather_than_guessed(self):
        assert t("/order/%zz") == "/order/%zz"

    def test_an_escape_that_is_not_utf8_is_left_verbatim_rather_than_folded(self):
        """`unquote`'s default `errors="replace"` folds all 128 invalid
        single-byte escapes to U+FFFD, so `/order/%80` .. `/order/%FF` all
        measured `/order/�`: byte-level fuzzing through the proxy would
        record 128 requests as one surface."""
        assert t("/order/%80") == "/order/%80"
        assert t("/order/%FF") == "/order/%FF"
        assert t("/order/%80") != t("/order/%FF")

    def test_but_a_valid_utf8_escape_still_decodes(self):
        """The separating case for the line above: strictness must not turn
        into 'never decode anything non-ASCII'."""
        assert t("/caf%C3%A9") == "/café"


class TestDecodingDepth:
    """Decoding runs to a fixed point, because `Policy` decides on one.

    `Policy.decodeToFixedPoint` unwraps nested escapes until nothing changes;
    version 1 decoded once. So `/order/%2531` was `/order/1` to the scope
    decision that authorised the request and `/order/%31` to the row recording
    it -- the evidence and the authorisation naming different endpoints -- and
    it split from `/order/1` into a second row besides.
    """

    def test_a_doubly_encoded_segment_reaches_the_same_template(self):
        """Measured before: `/order/%2531` -> `/order/%31`."""
        assert t("/order/%2531") == t("/order/%31") == t("/order/1") == "/order/{id}"

    def test_the_bound_is_the_one_Policy_enforces(self):
        """The mirror cannot share code across the language boundary, so it is
        pinned by reading Policy's constant rather than by a comment."""
        java = POLICY_JAVA.read_text(encoding="utf-8")
        m = re.search(r"MAX_DECODE_ROUNDS\s*=\s*(\d+)\s*;", java)
        assert m is not None, f"Policy.MAX_DECODE_ROUNDS not found in {POLICY_JAVA}"
        assert int(m.group(1)) == surface.MAX_DECODE_ROUNDS == 16

    def test_past_the_bound_the_partial_decode_is_what_is_recorded(self):
        """Exactly `decodeToFixedPoint`'s behaviour. Policy answers this shape
        with a DENIAL (`decodesFully`), so it does not reach here through the
        gate; the two still agree about everything the gate admits."""
        at_the_bound = "%" + "25" * 15 + "31"    # 16 rounds to reach "1"
        past_it = "%" + "25" * 16 + "31"         # 17
        assert t("/order/" + at_the_bound) == "/order/{id}"
        assert t("/order/" + past_it) == "/order/%31"

    def test_an_encoded_separator_is_refused_however_deeply_it_is_nested(self):
        """`%252f` decodes to `/` too, so the refusal has to survive the extra
        rounds or the fixed point would undo it."""
        assert t("/a%252fb") == "/a%252fb"


class TestShape:
    def test_the_root_path_survives(self):
        assert t("/") == "/"

    def test_a_trailing_slash_is_significant(self):
        """`/order/` and `/order` can be different routes. Merging them is a
        guess about someone else's router."""
        assert t("/order/") == "/order/"
        assert t("/order") == "/order"

    def test_an_empty_path_normalises_to_root(self):
        assert t("") == "/"

    def test_an_empty_interior_segment_survives_as_one(self):
        """`//` is two empty segments, not one collapsed slash: no rule matches
        the empty string, so it needs no special case to come back unchanged."""
        assert t("/a//b") == "/a//b"


class TestQueryKeySet:
    def test_values_are_dropped_and_keys_kept(self):
        assert surface.query_key_set("id=1&sort=asc") == "id,sort"

    def test_key_order_does_not_matter(self):
        assert surface.query_key_set("sort=asc&id=1") == surface.query_key_set("id=1&sort=asc")

    def test_a_repeated_key_appears_once(self):
        assert surface.query_key_set("id=1&id=2") == "id"

    def test_a_valueless_key_still_counts(self):
        assert surface.query_key_set("debug") == "debug"

    def test_an_empty_query_is_empty(self):
        assert surface.query_key_set("") == ""

    def test_a_key_containing_the_delimiter_is_escaped(self):
        """THE SEPARATING CASE for the escaping. `a%2Cb=1` is ONE parameter and
        `a=1&b=2` is two; both measured `a,b`, so a check enumerating inputs
        off the row would see a different count than the exchange carried."""
        assert surface.query_key_set("a%2Cb=1") == "a%2Cb"
        assert surface.query_key_set("a=1&b=2") == "a,b"
        assert surface.query_key_set("a%2Cb=1") != surface.query_key_set("a=1&b=2")

    def test_and_the_bare_spelling_of_that_key_is_the_same_key(self):
        """`?a,b` and `?a%2Cb` are one parameter under either spelling."""
        assert surface.query_key_set("a,b") == surface.query_key_set("a%2Cb=1")

    def test_a_two_key_set_renders_as_two_fields_not_three(self):
        """Measured before: `a=1&a%2Cb=2` -> `a,a,b`."""
        assert surface.query_key_set("a=1&a%2Cb=2") == "a,a%2Cb"

    def test_an_empty_key_is_distinguishable_from_no_query_at_all(self):
        """`GET /x` and `GET /x?=1` are different requests; both measured
        `""`, so they merged into one row."""
        assert surface.query_key_set("=1") == "(empty)"
        assert surface.query_key_set("=1") != surface.query_key_set("")

    def test_and_it_sorts_and_joins_like_any_other_key(self):
        assert surface.query_key_set("a=2&=1") == "(empty),a"

    def test_a_key_cannot_forge_the_empty_key_token(self):
        """`(` and `)` are outside what `quote(safe="")` emits, which is what
        makes `(empty)` unforgeable rather than merely unlikely."""
        assert surface.query_key_set("(empty)=1") == "%28empty%29"
        assert surface.query_key_set("(empty)=1") != surface.query_key_set("=1")


class TestKind:
    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
    def test_safe_methods_are_idempotent_reads(self, method):
        assert surface.kind_for(method) == "idempotent_read"

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_the_rest_change_state(self, method):
        assert surface.kind_for(method) == "state_changing"

    def test_an_unrecognised_method_is_unknown_not_safe(self):
        """Fail-closed: an unknown verb is not assumed harmless."""
        assert surface.kind_for("PROPFIND") == "unknown"

    def test_method_matching_is_case_sensitive(self):
        """RFC 9110 s9.1: methods are case-sensitive. `get` is not GET, and
        treating it as one would let a lowercase verb inherit a safe kind."""
        assert surface.kind_for("get") == "unknown"


class TestNormalise:
    def test_it_pulls_a_url_apart_and_templates_the_path(self):
        n = surface.normalise("GET", "https://app.test:8443/order/7?id=1", **KW)
        assert (n.scheme, n.host, n.port) == ("https", "app.test", 8443)
        assert n.path_template == "/order/{id}"
        assert n.query_key_set == "id"
        assert n.kind == "idempotent_read"
        assert n.normaliser_version == surface.NORMALISER_VERSION

    def test_the_default_port_is_filled_in_from_the_scheme(self):
        assert surface.normalise("GET", "https://app.test/x", **KW).port == 443
        assert surface.normalise("GET", "http://app.test/x", **KW).port == 80

    def test_a_scheme_with_no_default_port_records_zero(self):
        """The fallback arm of `_DEFAULT_PORT.get`, which nothing reached: it
        could be any number at all and every test still passed."""
        assert surface.normalise("GET", "ftp://app.test/x", **KW).port == 0

    def test_an_explicit_port_zero_is_recorded_rather_than_replaced(self):
        """`parts.port or ...` made this 80 -- a row naming an endpoint nobody
        addressed. `port` is a UNIQUE-key field, so it is the row's identity."""
        assert surface.normalise("GET", "http://app.test:0/x", **KW).port == 0

    def test_the_host_is_lowercased_and_the_path_is_not(self):
        """Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not.
        Lowercasing a path would merge /Admin and /admin, which on some
        servers are two different places. The fold itself is `urlsplit`'s --
        this pins the output contract, not an implementation here."""
        n = surface.normalise("GET", "http://APP.Test/Admin", **KW)
        assert n.host == "app.test"
        assert n.path_template == "/Admin"

    def test_the_host_fold_is_urlsplit_s_and_stops_at_a_zone_id(self):
        """`hostname` lowercases up to the first `%` and leaves the rest,
        which it reads as an IPv6 zone id. A second `.lower()` here used to
        fold that tail too -- the only inputs it changed, and `Policy` refuses
        both (`checkHostChars` allows neither `%` nor a bracket). Recorded as
        `urlsplit` reports it rather than folded a second time."""
        n = surface.normalise("GET", "http://[fe80::1%tESt]/x", **KW)
        assert n.host == "fe80::1%tESt"

    def test_a_url_with_no_authority_has_an_empty_host_not_None(self):
        """`parts.hostname` is None for a relative url, and `host` feeds a NOT
        NULL column. The `or ""` is the only thing between the two."""
        assert surface.normalise("GET", "/order/1", **KW).host == ""

    @pytest.mark.parametrize("url", ["http://app.test:99999/x",
                                     "http://app.test:abc/x",
                                     "http://[fe80::/x"])
    def test_normalise_is_not_total_and_says_so(self, url):
        """A url this cannot parse is one the gate has already refused --
        `Policy.checkScope` turns exactly these into `scope_denied` -- so
        swallowing the error would record a surface for a request that had no
        authority behind it. A caller arriving by another route (`via='send'`,
        `via='crawl'`) owes the exception a handler."""
        with pytest.raises(ValueError):
            surface.normalise("GET", url, **KW)


def test_the_version_is_pinned_to_the_ruleset_in_this_file():
    """A rule change without a version bump silently reinterprets history:
    old rows claim a template the current rules would never produce.

    Pinned to the EXACT value. `>= 1` was the assertion here while the rules
    changed underneath it, which left the one field whose whole purpose is
    saying which ruleset produced a row unpinned by anything.
    """
    assert surface.NORMALISER_VERSION == 2
