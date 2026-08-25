"""The normaliser, exhaustively.

Every test here separates one rule from its absence. That is not a style
preference on this project: on the previous branch, rule 3 -- a guard is only
tested by the input that separates it from its absence -- fired on all eight
tasks without exception, and the normaliser is the component where a missing
separation is least visible, because a wrong template still LOOKS like a
template.
"""
from __future__ import annotations

import pytest

from hx import surface

PRESERVE = frozenset({"api", "v1", "v2", "v3"})
KW = {"preserve": PRESERVE, "slug_threshold": 12}


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


class TestPreservedSegments:
    """The preserve list, and the fact that the DEFAULT list does nothing.

    Deleting the preserve rule entirely reddens NOTHING in the rest of this
    file, and the reason is not a missing test -- it is that none of the
    defaults (`api`, `v1`, `v2`, `v3`) is matched by any shape rule anyway.
    `_DIGITS` is `\A[0-9]+\Z`, so `v1` never matched it; there is nothing for
    the list to protect them from.

    Three claims in the first version of this class asserted otherwise -- that
    `v1` "is digits-adjacent and must survive, this is why the list exists",
    that `/v2` would "otherwise match a rule", and that `/v9` "separates the
    preserve list" (it separates the digits rule). All three were false, and
    they are the reason the no-op went unnoticed: a class full of confident
    comments about a rule that was doing nothing.

    The rule is kept because it IS reachable under legal configurations, and
    the last test here is the one that separates it from its absence.
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

    def test_the_list_is_load_bearing_under_a_config_that_needs_it(self):
        """THE SEPARATING CASE, and the only one in this file.

        A numeric path segment that is genuinely a route -- a year, a version,
        an API generation -- is exactly what an operator puts on this list, and
        without the rule it templates to `{id}` and merges with every other
        number in that position. Measured: `/2024/report` becomes
        `/{id}/report` when the rule is deleted.
        """
        kw = {"preserve": frozenset({"2024"}), "slug_threshold": 12}
        assert surface.path_template("/2024/report", **kw) == "/2024/report"
        assert surface.path_template("/2025/report", **kw) == "/{id}/report"

    def test_and_under_a_threshold_low_enough_to_reach_the_defaults(self):
        """The other direction: with a short slug threshold the default entries
        DO become reachable, so the list stops being decorative."""
        kw = {"preserve": frozenset({"v1"}), "slug_threshold": 2}
        assert surface.path_template("/v1", **kw) == "/v1"
        assert surface.path_template("/v9", **kw) == "/{slug}"


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

    def test_the_host_is_lowercased_and_the_path_is_not(self):
        """Hosts are case-insensitive (RFC 9110 s4.2.3); paths are not.
        Lowercasing a path would merge /Admin and /admin, which on some
        servers are two different places."""
        n = surface.normalise("GET", "http://APP.Test/Admin", **KW)
        assert n.host == "app.test"
        assert n.path_template == "/Admin"


def test_the_version_is_an_integer_that_someone_must_bump():
    """A rule change without a version bump silently reinterprets history:
    old rows claim a template the current rules would never produce."""
    assert isinstance(surface.NORMALISER_VERSION, int)
    assert surface.NORMALISER_VERSION >= 1
