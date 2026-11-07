from app.static_analysis import builtin_analysis
from app.testgen import generate_tests
from app.scenarios import list_scenarios


def _scenario(scenario_id: str) -> str:
    for item in list_scenarios():
        if item["id"] == scenario_id:
            return item["code"]
    raise AssertionError(scenario_id)


def test_vulnerable_example_has_confirmed_static_findings():
    findings = builtin_analysis(_scenario("vulnerable-cross-clinic"))["findings"]
    confirmed = {item["policy_id"] for item in findings if item["confirmed"]}
    assert {"POL-05", "POL-06", "POL-07"} <= confirmed
    heuristics = [item for item in findings if not item["confirmed"]]
    assert heuristics
    assert all(item["source"] == "builtin_heuristic" for item in heuristics)


def test_corrected_example_has_no_confirmed_or_auth_heuristics():
    findings = builtin_analysis(_scenario("corrected-clinic-scope"))["findings"]
    assert findings == []


def test_generated_tests_compile_and_do_not_trust_model_text():
    generated = generate_tests()
    compile(generated["source"], "test_security.py", "exec")
    assert "clinic-a" in generated["source"]
    assert "suggested_tests" not in generated["source"]
    assert len(generated["plan"]) == 9


def test_scenarios_are_synthetic():
    payload = list_scenarios()
    assert {item["expected_decision"] for item in payload} == {"BLOCK", "APPROVE", "REVIEW"}
    blob = " ".join(item["code"] for item in payload)
    assert "Alex Rivera" in blob
    assert "Jordan Blake" in blob
