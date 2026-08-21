from pathlib import Path

from click.testing import CliRunner

from hx import cli


def test_new_creates_engagement(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "new", "acme-2026-09",
            "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*",
            "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "acme-2026-09" / "hx.db").exists()
    assert "acme-2026-09" in result.output


def test_new_requires_a_scope(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["new", "acme", "--client", "Acme", "--root", str(tmp_path)],
    )
    assert result.exit_code != 0
    assert "scope" in result.output.lower()


def test_new_refuses_to_clobber(tmp_path: Path):
    runner = CliRunner()
    args = [
        "new", "acme", "--client", "Acme",
        "--scope", "https://a/*", "--root", str(tmp_path),
    ]
    assert runner.invoke(cli.main, args).exit_code == 0
    second = runner.invoke(cli.main, args)
    assert second.exit_code != 0
    assert "exists" in second.output.lower()


def test_info_reports_engagement(tmp_path: Path):
    runner = CliRunner()
    runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code == 0, result.output
    assert "Acme Corp" in result.output
    assert "production" in result.output
    assert "https://app.acme.com/*" in result.output


def test_default_root_honours_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HX_HOME", str(tmp_path / "custom"))
    assert cli.default_root() == tmp_path / "custom"


def test_info_missing_config_yaml(tmp_path: Path):
    """Test that info handles missing config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Delete config.yaml
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.unlink()

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output or "config" in result.output.lower()


def test_info_malformed_config_yaml(tmp_path: Path):
    """Test that info handles malformed config.yaml gracefully."""
    runner = CliRunner()
    # Create an engagement
    result = runner.invoke(
        cli.main,
        [
            "new", "acme", "--client", "Acme Corp",
            "--scope", "https://app.acme.com/*", "--root", str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    # Write malformed YAML
    config_path = tmp_path / "acme" / "config.yaml"
    config_path.write_text("{ invalid yaml: [")

    # Try to run info - should show an error, not a traceback
    result = runner.invoke(cli.main, ["info", "--root", str(tmp_path / "acme")])
    assert result.exit_code != 0
    assert "Traceback" not in result.output
    assert str(tmp_path / "acme") in result.output or "config" in result.output.lower()
