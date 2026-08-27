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
side owns the cases: both read `tests/vectors/userinfo.txt`, the Java side from
`RedactorTest.theSharedUserinfoVectorsAreRedactedTheSameWayPythonRedactsThem`
and this side from `test_the_shared_vectors_are_redacted_the_same_way_java_redacts_them`
below. The PLACEHOLDER is pinned separately, by reading it out of the .java
file, because a shared vector file cannot catch two sides that agree with each
other and disagree with the constant they both quote.

WHAT IS NOT CLOSED is asserted here as loudly as what is: a credential in a
QUERY PARAMETER reaches both the column and the blob, and
`test_a_credential_in_the_query_is_not_redacted_and_that_is_the_open_half`
pins it. Reaching it needs either a list of parameter names -- a vocabulary
that drifts silently toward storing a credential -- or a rule that redacts by
shape, which rewrites `?id=5` and corrupts the evidence a check reads. If that
test ever goes red, someone has chosen one of those, and it should be a
decision rather than a side effect.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from hx.store import db as db_mod
from hx.store import records

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "tests" / "vectors" / "userinfo.txt"
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


def test_a_credential_in_the_query_is_not_redacted_and_that_is_the_open_half():
    """THE HALF THIS DOES NOT CLOSE, pinned as a fact.

    `?access_token=` reaches `exchange.url` and the blob store verbatim. The
    reviewer measured it; nothing here fixes it; and an unstated leak is the
    thing this project keeps finding, so it is stated as a check rather than a
    sentence. The Java side pins the same input against the blob
    (`aCredentialInTheQUERYIsNamedAsNotCovered`), so both halves of the
    exposure are visible from both sides.
    """
    token = "eyJhbGciOiJIUzI1NiJ9.live.9f2c"
    url = f"https://app.example.test/cb?access_token={token}"
    assert records.redact_url(url) == url
    assert token in records.redact_url(url)


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
