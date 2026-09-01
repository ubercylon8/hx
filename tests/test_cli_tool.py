import json

import pytest
from click.testing import CliRunner

from hx import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def engagement_root(engagement):
    """The directory `hx tool --root` is pointed at."""
    return engagement.root


def test_listing_needs_no_engagement(runner):
    out = runner.invoke(cli.main, ["tool", "--list"])
    assert out.exit_code == 0 and "run.resume" in out.output


def test_a_query_prints_an_envelope_and_exits_zero_when_empty(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "surface.query", "--root",
                                   str(engagement_root)])
    assert out.exit_code == 0
    assert json.loads(out.output)["outcome"] == "empty"


def test_a_refusal_exits_nonzero(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "run.start", "--json",
                                   '{"kind":"manual"}', "--root",
                                   str(engagement_root)])
    assert out.exit_code == 1
    assert json.loads(out.output)["reason"] == "missing_why"


def test_malformed_json_is_a_click_error_not_a_traceback(runner, engagement_root):
    out = runner.invoke(cli.main, ["tool", "surface.query", "--json", "{",
                                   "--root", str(engagement_root)])
    assert out.exit_code != 0 and "not JSON" in out.output
