"""§7's boundary, from the Python side: what a url column may hold.

This file exists for one finding and one rule.

THE FINDING. §7's mechanism was three request header names, `Set-Cookie`, and
the byte ranges the extension injected. A credential in the request TARGET is
none of those, and `http://user:pass@app.test/` was measured surviving verbatim
into the content-addressed blob store AND into `exchange.url`. The blob is the
half that cannot be taken back -- §7 calls it the one item that cannot be
retrofitted, because once written it is in every backup -- and it is closed in
`Redactor` (job 5). The column half is closed in `records.redact_url`, and that
is what this file holds.

THE RULE. A VOCABULARY THAT EXISTS IN TWO PLACES MUST BE COMPARED IN ONE --
`tests/test_vocabularies_match_the_schema.py`'s subject, one artifact further
out. Here the two places are two LANGUAGES: `Redactor.redactObservedRequest`
rewrites a request line inside the JVM and `records.redact_url` rewrites a url
column in Python, and they are the same RFC 3986 rule written twice. So neither
side owns the cases: both read `tests/vectors/request-target.txt`, the Java side from
`RedactorTest.theSharedTargetVectorsAreRedactedTheSameWayPythonRedactsThem`
and this side from `test_the_shared_vectors_are_redacted_the_same_way_java_redacts_them`
below. The PLACEHOLDER is pinned separately, by reading it out of the .java
file, because a shared vector file cannot catch two sides that agree with each
other and disagree with the constant they both quote.

TWO RULES LIVE HERE NOW. Userinfo is STRUCTURAL -- RFC 3986 says where it is,
and nothing is guessed. Credential PARAMETERS are a fixed list of NAMES,
matched whole and case-insensitively, with the key kept and only the value
replaced. Names and never shapes: a rule that redacted what looks opaque would
rewrite `?id=1001` and corrupt the exact evidence an access-control check
reads, which is the finding the redaction was protecting.

WHAT IS NOT CLOSED is asserted here as loudly as what is. The list catches
well-known names and NOT a client's own name for a token:
`test_a_clients_own_name_for_a_token_is_not_caught` drives a made-up parameter
and requires it to survive, so the limit is a measured fact rather than a
caveat someone can quietly widen. If that test goes red the list grew -- which
is allowed, but is a DECISION, and the honest version of it is an
operator-declared list in the engagement config. That needs a config schema
change AND a `configure` wire key to carry it, and an unrecognised `configure`
key is a hard `bad_config` today, so there is no wire for it either; both
halves land together or an operator's list is silently ignored.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from hx import surface
from hx.store import db as db_mod
from hx.store import records

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "tests" / "vectors" / "request-target.txt"
REDACTOR_JAVA = REPO / "extension" / "src" / "hx" / "send" / "Redactor.java"


def _vectors() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in VECTORS.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        assert "\t" in line, f"vector line with no tab: {line!r}"
        given, want = line.split("\t", 1)
        out.append((given, want))
    return out


def test_the_vector_file_was_read_rather_than_nothing():
    """Anti-vacuity, and it is the same shape every vacuous check in this
    repository has had: a parametrisation over an empty list is a green test
    that asserts nothing, and a format change that turned every line into a
    comment would produce exactly that on both sides at once."""
    cases = _vectors()
    assert len(cases) >= 20, f"only parsed {len(cases)} vectors from {VECTORS}"
    changed = [c for c in cases if c[0] != c[1]]
    assert len(changed) >= 8, (
        "the vector file has almost no case that the rule actually CHANGES, "
        "so it would pass with redact_url returning its argument"
    )
    unchanged = [c for c in cases if c[0] == c[1]]
    assert len(unchanged) >= 5, (
        "the vector file has almost no case the rule must LEAVE ALONE, so it "
        "would pass with redact_url blanking every authority"
    )


@pytest.mark.parametrize("given,want", _vectors(),
                         ids=[v[0] for v in _vectors()])
def test_the_shared_vectors_are_redacted_the_same_way_java_redacts_them(given, want):
    assert records.redact_url(given) == want


def test_the_placeholder_is_the_string_the_extension_writes_into_the_blob():
    """The half a shared vector file cannot hold.

    Both sides could agree with the vectors and disagree with the constant they
    quote -- the vectors would have to be edited too, which is the drift this
    reads the .java file to prevent. The same technique `tests/test_surface.py`
    uses for `Policy.MAX_DECODE_ROUNDS`, and for the same reason: the Java
    constant is the copy that can move without any Python test noticing.

    It matters because the two halves land side by side. A `url` column reading
    `{{observed:userinfo}}@host` next to a request blob reading
    `{{redacted:userinfo}}@host` is one fact spelt two ways, and a report that
    joins them shows two.
    """
    java = REDACTOR_JAVA.read_text(encoding="utf-8")
    m = re.search(r'OBSERVED_USERINFO\s*=\s*\n?\s*"([^"]*)"', java)
    assert m is not None, f"Redactor.OBSERVED_USERINFO not found in {REDACTOR_JAVA}"
    assert m.group(1) == records.OBSERVED_USERINFO == "{{observed:userinfo}}"


def test_the_parameter_vocabulary_is_the_extensions_vocabulary():
    """A VOCABULARY THAT EXISTS IN TWO PLACES, COMPARED IN ONE.

    `Redactor.CREDENTIAL_PARAMS` and `records.CREDENTIAL_PARAMS` are one list
    written twice, in two languages. The shared vector file catches a
    BEHAVIOURAL difference on the cases it happens to contain; this catches a
    name added to one side and not the other, which is the drift that leaks
    without ever failing a vector -- the column would redact `?api_key=` and
    the blob beside it would not, and a report joining them shows two
    different requests.
    """
    java = REDACTOR_JAVA.read_text(encoding="utf-8")
    m = re.search(r"CREDENTIAL_PARAMS\s*=\s*\{(.*?)\};", java, re.S)
    assert m is not None, f"Redactor.CREDENTIAL_PARAMS not found in {REDACTOR_JAVA}"
    names = set(re.findall(r'"([^"]+)"', m.group(1)))
    assert names, "parsed an EMPTY name list out of the .java file"
    assert names == set(records.CREDENTIAL_PARAMS), (
        "the two credential-parameter lists have drifted. Only in Java: "
        f"{sorted(names - set(records.CREDENTIAL_PARAMS))}; only in Python: "
        f"{sorted(set(records.CREDENTIAL_PARAMS) - names)}")
    # Anti-vacuity and a spot value, so a regex that matched structure but not
    # content cannot pass.
    assert "access_token" in names and len(names) >= 20


def test_the_parameter_placeholder_is_the_string_the_extension_writes():
    java = REDACTOR_JAVA.read_text(encoding="utf-8")
    m = re.search(r'OBSERVED_PARAM\s*=\s*\n?\s*"([^"]*)"', java)
    assert m is not None, f"Redactor.OBSERVED_PARAM not found in {REDACTOR_JAVA}"
    assert m.group(1) == records.OBSERVED_PARAM == "{{observed:param}}"


def test_every_listed_name_actually_redacts():
    """The list is only worth what it DOES. A name present in both constants
    and matched by neither implementation is a vocabulary entry with no
    behaviour, which is how a list becomes decoration."""
    for name in sorted(records.CREDENTIAL_PARAMS):
        url = f"https://app.example.test/p?{name}=live-secret-value"
        got = records.redact_url(url)
        assert got == f"https://app.example.test/p?{name}={{{{observed:param}}}}", \
            f"{name!r} is in the vocabulary and does not redact: {got!r}"


def test_a_credential_parameter_loses_its_value_and_keeps_its_key():
    """Property 1. The key is what `surface.query_key_set` reads."""
    token = "eyJhbGciOiJIUzI1NiJ9.live.9f2c"
    got = records.redact_url(
        f"https://app.example.test/cb?access_token={token}&id=1001")
    assert token not in got
    assert got == ("https://app.example.test/cb?access_token="
                   "{{observed:param}}&id=1001")


def test_the_surface_a_request_belongs_to_is_unchanged_by_the_redaction():
    """PROPERTY 1, VERIFIED AGAINST THE REAL NORMALISER rather than by reading
    it. `query_key_set` builds its set from `parse_qsl` KEYS, so a redaction
    that touched only values cannot move it -- but that is an argument, and
    the thing it is an argument about is which SURFACE a request is filed
    under. Over-templating merges endpoints the checks then visit once, and
    §5 says a wrong rule is a permanent hole in the evidence rather than a
    re-runnable step. So it is driven.

    Today `hx.capture` normalises the RAW url and redacts at the writer, so
    the two cannot disagree by construction. This is what holds if the
    redaction ever moves earlier.
    """
    raw = ("https://app.example.test/order/1001"
           "?access_token=eyJ.live.9f2c&id=1001&page=2")
    kw = dict(preserve=frozenset(), slug_threshold=24)
    before = surface.normalise("GET", raw, **kw)
    after = surface.normalise("GET", records.redact_url(raw), **kw)
    assert before.query_key_set == after.query_key_set
    assert before.path_template == after.path_template
    assert before == after, (
        "redacting a parameter VALUE changed the surface the request belongs "
        f"to: {before} vs {after}")
    # Anti-vacuity: the fixture really does carry the keys, so an equality
    # between two empty key sets cannot be what passed.
    assert before.query_key_set == "access_token,id,page"


def test_an_identifier_parameter_is_never_touched():
    """Property 2, and the reason the mechanism is a list of NAMES. `?id=1001`
    is what an IDOR check reads; a shape rule eats exactly this and makes the
    finding it was protecting unprovable."""
    url = "https://app.example.test/order/1001?id=1001&state=xyzzy&code=US"
    assert records.redact_url(url) == url


def test_two_urls_differing_only_in_the_credential_are_one_string():
    """Property 3. The column half of determinism: two rows for one endpoint
    under two tokens must not differ, or every query grouping by url splits."""
    a = records.redact_url("https://app.example.test/cb?access_token=aaaa&id=7")
    b = records.redact_url("https://app.example.test/cb?access_token=z&id=7")
    assert a == b == ("https://app.example.test/cb?access_token="
                      "{{observed:param}}&id=7")


def test_a_clients_own_name_for_a_token_is_not_caught():
    """THE LIMIT, AS A MEASURED FACT.

    This catches a fixed list of well-known names and does NOT catch a
    client's own name for a token. The parameter below is made up on purpose:
    no list can hold the name an application has not chosen yet, and a
    javadoc saying so is a caveat that can be quietly widened while this is a
    check that goes red when someone does.

    The Java side pins the same input against the BLOB
    (`aClientsOwnNameForATokenIsNotCaught`), so the limit is visible from both
    halves of the exposure rather than from the deletable one only.
    """
    secret = "live-acme-session-value"
    url = f"https://app.example.test/p?acme_session={secret}"
    assert records.redact_url(url) == url
    assert secret in records.redact_url(url)
    # The two smaller edges, so neither is a claim: the name is matched RAW,
    # and `;` is not a pair separator.
    enc = "https://app.example.test/p?%61ccess_token=live"
    assert records.redact_url(enc) == enc
    semi = "https://app.example.test/p?id=1;token=live"
    assert records.redact_url(semi) == semi


# ---- the two writers -------------------------------------------------------


@pytest.fixture()
def conn(tmp_path):
    c = db_mod.connect(tmp_path / "hx.db")
    db_mod.init_schema(c)
    c.execute("INSERT INTO engagement(id, name, client, created_us, status)"
              " VALUES('e-1','Example','Example Ltd',1,'active')")
    c.execute("INSERT INTO run(id, engagement_id, kind, safety_profile,"
              " started_us, status) VALUES('r-1','e-1','browse','production',"
              " 1,'running')")
    yield c
    c.close()


def test_an_exchange_row_never_holds_a_userinfo_credential(conn):
    """The writer, not the caller. `hx.capture` hands `record_exchange` the
    frame's url unchanged, so a redaction that lived there would cover one
    caller and no other -- and Plan 5's tool layer is a second one."""
    secret = "s3cret-live-password"
    records.record_exchange(
        conn, run_id="r-1", method="GET",
        url=f"http://alice:{secret}@app.example.test/orders",
        status=200, req_blob=None, resp_blob=None, ms=1, at_us=1)
    stored = conn.execute("SELECT url FROM exchange").fetchone()["url"]
    assert secret not in stored
    assert "alice" not in stored
    assert stored == "http://{{observed:userinfo}}@app.example.test/orders"


def test_a_denial_row_never_holds_a_userinfo_credential(conn):
    """`denial.url` is the column an operator reads when a request was refused
    -- which is exactly when a mistyped `https://user:pass@wrong-host/` is
    likeliest to be what got refused."""
    secret = "s3cret-live-password"
    records.record_denial(
        conn, run_id="r-1", kind="scope",
        method="GET", url=f"http://alice:{secret}@offside.example.test/",
        detail="out of scope", at_us=1)
    stored = conn.execute("SELECT url FROM denial").fetchone()["url"]
    assert secret not in stored
    assert stored == "http://{{observed:userinfo}}@offside.example.test/"


def test_an_ordinary_url_reaches_the_row_byte_for_byte(conn):
    """The control, and it is the assertion that stops the fix being "blank
    the authority". `exchange.url` is evidence: the only edit it may carry is
    the one §7 asks for."""
    url = "https://app.example.test:8443/a/b?c=d&e=&f#g"
    records.record_exchange(conn, run_id="r-1", method="GET", url=url,
                            status=200, req_blob=None, resp_blob=None,
                            ms=1, at_us=1)
    assert conn.execute("SELECT url FROM exchange").fetchone()["url"] == url


def test_only_records_py_writes_a_url_into_a_row():
    """A CHECK THAT COUNTS THE WRITERS, instead of a comment that names them.

    `redact_url` is applied inside `record_exchange` and `record_denial`, so
    the guarantee is "every url that becomes a row goes through one of those
    two" -- and that is a statement about INSERT statements, not about
    callers. A module that grew its own `INSERT INTO exchange` would bypass
    §7 entirely with every existing test still green, which is the exact shape
    of the finding this file exists for: a mechanism that covers the paths
    somebody thought of.

    Deliberately a text scan over `src/`, deliberately not over `tests/`: a
    test fixture inserting a row by hand is a fixture, and the invariant is
    about what the SHIPPED code can do.
    """
    src = REPO / "src"
    offenders = []
    for path in sorted(src.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for table in ("INSERT INTO exchange", "INSERT INTO denial"):
            if table in text and path != REPO / "src/hx/store/records.py":
                offenders.append(f"{path.relative_to(REPO)}: {table}")
    assert not offenders, (
        "a url reaches a row without passing records.redact_url: "
        + ", ".join(offenders)
        + ". Either write through records.record_exchange / record_denial, or "
        "move the redaction to a boundary that covers this writer too")
    # Anti-vacuity: the scan really did reach the file that DOES hold them.
    records_text = (REPO / "src/hx/store/records.py").read_text(encoding="utf-8")
    assert "INSERT INTO exchange" in records_text
    assert "INSERT INTO denial" in records_text


def test_an_exchange_row_never_holds_a_credential_parameter(conn):
    """The writer again, for the second of job 5's two rules. `hx.capture`
    hands `record_exchange` the frame's url unchanged, so a redaction that
    lived at the caller would cover one caller and no other."""
    token = "eyJhbGciOiJIUzI1NiJ9.live.9f2c"
    records.record_exchange(
        conn, run_id="r-1", method="GET",
        url=f"https://app.example.test/cb?access_token={token}&id=1001",
        status=200, req_blob=None, resp_blob=None, ms=1, at_us=1)
    stored = conn.execute("SELECT url FROM exchange").fetchone()["url"]
    assert token not in stored
    assert stored == ("https://app.example.test/cb?access_token="
                      "{{observed:param}}&id=1001")


def test_a_denial_row_never_holds_a_credential_parameter(conn):
    """`denial.url` is what an operator reads when a request was refused, and
    a token in the query of a refused request is still a live token."""
    token = "AKIAIOSFODNN7EXAMPLE"
    records.record_denial(
        conn, run_id="r-1", kind="scope", method="GET",
        url=f"http://offside.example.test/x?api_key={token}",
        detail="out of scope", at_us=1)
    stored = conn.execute("SELECT url FROM denial").fetchone()["url"]
    assert token not in stored
    assert stored == "http://offside.example.test/x?api_key={{observed:param}}"


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
