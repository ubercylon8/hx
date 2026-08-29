from pathlib import Path

import pytest

from hx import session


def test_an_explicit_jar_path_wins(tmp_path):
    jar = tmp_path / "burpsuite_desktop_v2026.7.3.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar(jar) == jar


def test_a_named_jar_that_does_not_exist_is_a_clear_error(tmp_path):
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar(tmp_path / "nope.jar")
    assert "nope.jar" in str(exc.value)


def test_the_lab_is_searched_without_pinning_a_version(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    jar = tmp_path / "burpsuite_desktop_v2027.1.0.jar"
    jar.write_bytes(b"x")
    assert session.find_burp_jar() == jar


def test_two_matching_jars_is_an_error_naming_both(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    (tmp_path / "burpsuite_desktop_v2026.7.3.jar").write_bytes(b"x")
    (tmp_path / "burpsuite_desktop_v2027.1.0.jar").write_bytes(b"x")
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    # Picking the newest silently would let a consultant run an assessment
    # against a different Burp from the one they believe, and the report
    # records the version.
    assert "2026.7.3" in str(exc.value) and "2027.1.0" in str(exc.value)
    assert "--burp-jar" in str(exc.value)


def test_no_jar_anywhere_names_all_three_places_it_looked(tmp_path, monkeypatch):
    monkeypatch.setenv("HX_BURP_LAB", str(tmp_path))
    monkeypatch.delenv("HX_BURP_JAR", raising=False)
    with pytest.raises(session.SessionError) as exc:
        session.find_burp_jar()
    msg = str(exc.value)
    assert "--burp-jar" in msg and "HX_BURP_JAR" in msg and str(tmp_path) in msg
