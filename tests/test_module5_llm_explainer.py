"""
tests/test_module5_llm_explainer.py - Verification suite for GeminiRiskExplainer.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.llm_explainer import GeminiRiskExplainer
from analyzers.sandbox_runner import DynamicSandboxRunner
from analyzers.static_analyzer import StaticAPKAnalyzer
from schemas.contracts import LLMExplanation


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp LLM Explainer Verification")
    print("=" * 60)

    static_analyzer = StaticAPKAnalyzer()
    sandbox_runner = DynamicSandboxRunner()
    explainer = GeminiRiskExplainer()

    # 1. Test Benign Calculator Explanation
    print("\n[TEST 1] Testing Benign Calculator Explanation...")
    meta_calc, static_calc = static_analyzer.analyze("benign_calculator")
    dyn_calc = sandbox_runner.run("benign_calculator", static_calc)
    exp_calc = explainer.explain(meta_calc, static_calc, dyn_calc)

    assert isinstance(exp_calc, LLMExplanation), f"Expected LLMExplanation, got {type(exp_calc)}"
    assert exp_calc.overall_risk_level == "LOW", f"Expected LOW risk, got {exp_calc.overall_risk_level}"
    assert len(exp_calc.purpose_behavior_contradictions) == 0, "Expected zero contradictions for benign calculator"
    print(f"  ✓ Risk Level: {exp_calc.overall_risk_level}")
    print(f"  ✓ Summary: {exp_calc.executive_summary[:90]}...")
    print(f"  ✓ Recommended Actions: {len(exp_calc.recommended_actions)}")

    # 2. Test Adware Weather Explanation
    print("\n[TEST 2] Testing Over-Privileged Weather Explanation...")
    meta_weath, static_weath = static_analyzer.analyze("adware_weather")
    dyn_weath = sandbox_runner.run("adware_weather", static_weath)
    exp_weath = explainer.explain(meta_weath, static_weath, dyn_weath)

    assert isinstance(exp_weath, LLMExplanation)
    assert exp_weath.overall_risk_level in ["MEDIUM", "HIGH"]
    assert len(exp_weath.privacy_risks) > 0, "Expected privacy risks for adware tracking"
    print(f"  ✓ Risk Level: {exp_weath.overall_risk_level}")
    print(f"  ✓ Identified Privacy Risks: {len(exp_weath.privacy_risks)}")
    for r in exp_weath.privacy_risks:
        print(f"      - {r}")

    # 3. Test Trojan Flashlight Explanation
    print("\n[TEST 3] Testing Critical Trojan Flashlight Explanation...")
    meta_trojan, static_trojan = static_analyzer.analyze("trojan_flashlight")
    dyn_trojan = sandbox_runner.run("trojan_flashlight", static_trojan)
    exp_trojan = explainer.explain(meta_trojan, static_trojan, dyn_trojan)

    assert isinstance(exp_trojan, LLMExplanation)
    assert exp_trojan.overall_risk_level == "CRITICAL", f"Expected CRITICAL risk, got {exp_trojan.overall_risk_level}"
    assert len(exp_trojan.purpose_behavior_contradictions) > 0, "Expected purpose contradictions for trojan"
    assert any("uninstall" in a.lower() for a in exp_trojan.recommended_actions), "Expected immediate uninstall recommendation"
    print(f"  ✓ Risk Level: {exp_trojan.overall_risk_level}")
    print(f"  ✓ Purpose Contradictions: {len(exp_trojan.purpose_behavior_contradictions)}")
    for c in exp_trojan.purpose_behavior_contradictions:
        print(f"      ✕ {c}")
    print(f"  ✓ Urgent Actions: {exp_trojan.recommended_actions[0]}")

    print("\n" + "=" * 60)
    print("[SUCCESS] All Gemini LLM Explainer tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
