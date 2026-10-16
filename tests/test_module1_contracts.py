"""
tests/test_module1_contracts.py - Verification script for Module 1 contracts and samples.
"""

import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from schemas.contracts import (
    AppMetadata,
    StaticFeatures,
    DynamicFeatures,
    NetworkConnection,
    MLScores,
    LLMExplanation,
    ShadowAppReport,
    validate_report_dict,
)

SAMPLE_FILES = [
    "benign_calculator.json",
    "adware_weather.json",
    "trojan_flashlight.json",
]


def test_schema_parsing():
    print("=" * 60)
    print("ShadowApp Module 1 Contract Verification")
    print("=" * 60)

    sample_dir = ROOT_DIR / "sample_data"
    all_passed = True

    for filename in SAMPLE_FILES:
        filepath = sample_dir / filename
        assert filepath.exists(), f"Sample file not found: {filepath}"
        
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        try:
            report = validate_report_dict(raw_data)
            print(f"[PASS] {filename}")
            print(f"       App: {report.app_metadata.app_name} ({report.app_metadata.package_name})")
            print(f"       Category: {report.app_metadata.stated_category}")
            print(f"       Mismatch Score: {report.ml_scores.purpose_mismatch_score}/100")
            print(f"       Malware Prob: {report.ml_scores.malware_probability:.2f}")
            print(f"       Classification: {report.ml_scores.anomaly_classification}")
            if report.llm_explanation:
                print(f"       Risk Level: {report.llm_explanation.overall_risk_level}")
                print(f"       Contradictions: {len(report.llm_explanation.purpose_behavior_contradictions)}")
            print("-" * 50)
        except Exception as e:
            print(f"[FAIL] {filename}: {e}")
            all_passed = False

    if all_passed:
        print("[SUCCESS] All 3 sample telemetry files strictly conform to Module 1 schemas!")
        return 0
    else:
        print("[ERROR] Schema validation failures detected.")
        return 1


if __name__ == "__main__":
    sys.exit(test_schema_parsing())
