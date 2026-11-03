import json

import pytest

from arh.defenses.config import PRESETS
from arh.mappings import ATLAS_TECHNIQUES, CATEGORY_RMF, OWASP
from arh.report import write_reports
from arh.runner import run_case, run_suite
from arh.suite import CASES, get_cases

CONTROLS = {"JB-00"}


@pytest.mark.parametrize("case", [c for c in get_cases("attack") if c.id not in CONTROLS], ids=lambda c: c.id)
def test_every_attack_works_against_the_undefended_agent(model, case):
    """Suite validity: each attack must actually succeed with no defenses, or it measures nothing."""
    assert run_case(model, PRESETS["none"], case).success


def test_control_case_fails_without_defenses(model):
    case = next(c for c in CASES if c.id == "JB-00")
    assert not run_case(model, PRESETS["none"], case).success


@pytest.mark.parametrize("cfg", ["none", "full"])
@pytest.mark.parametrize("case", get_cases("benign"), ids=lambda c: c.id)
def test_benign_tasks_complete(model, cfg, case):
    assert run_case(model, PRESETS[cfg], case).success


def test_full_stack_stops_all_tool_abuse(model):
    run = run_suite(model, ["full"])
    cats = run["summary"]["full"]["by_category"]
    for cat in ("direct_injection", "indirect_injection", "exfiltration", "privilege_escalation"):
        assert cats[cat]["succeeded"] == 0, cat


def test_rubber_stamp_reviewer_reopens_insider_exfil(model):
    """Approval fatigue: same stack, careless reviewer -> confused-deputy exfil succeeds."""
    case = next(c for c in CASES if c.id == "EXF-01")
    assert not run_case(model, PRESETS["full"], case).success
    assert run_case(model, PRESETS["full_rubber_stamp"], case).success


def test_mappings_are_complete():
    for c in CASES:
        assert c.category in CATEGORY_RMF
        assert all(t in ATLAS_TECHNIQUES for t in c.atlas), c.id
        assert all(o in OWASP for o in c.owasp), c.id
        if c.kind == "attack":
            assert c.atlas, c.id


def test_reports_are_written(model, tmp_path):
    run = run_suite(model, ["none", "full"])
    jp, mp = write_reports(run, tmp_path)
    data = json.loads(jp.read_text())
    assert data["model"] == "mock-compliant-v1" and "mock" in data["note"]
    assert {r["config"] for r in data["results"]} == {"none", "full"}
    md = mp.read_text()
    assert "deterministic mock model" in md and "Residual risk" in md


def test_runs_are_reproducible(model):
    a = run_suite(model, ["none", "full"])["summary"]
    b = run_suite(model, ["none", "full"])["summary"]
    assert a == b


def test_readme_results_block_matches_a_fresh_run(model):
    """Keeps the README honest: its results table must equal what the code produces."""
    import re
    from pathlib import Path

    from arh.report import category_table, results_table

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    block = re.search(r"<!-- RESULTS:START -->(.*?)<!-- RESULTS:END -->", readme, re.S).group(1)
    run = run_suite(model)
    assert results_table(run) in block
    assert category_table(run) in block
