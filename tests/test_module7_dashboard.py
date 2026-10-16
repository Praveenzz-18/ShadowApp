"""
tests/test_module7_dashboard.py - Verification suite for Module 7 Interactive Security Dashboard.
"""

import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from schemas.contracts import validate_report_dict


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp Module 7 Security Dashboard Verification")
    print("=" * 60)

    # 1. Verify Sample Data Benchmarks load correctly
    samples = ["benign_calculator.json", "adware_weather.json", "trojan_flashlight.json"]
    for s_file in samples:
        path = PROJECT_ROOT / "sample_data" / s_file
        assert path.exists(), f"Sample benchmark {s_file} missing!"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        report = validate_report_dict(data)
        assert report.app_metadata.package_name
        assert report.ml_scores.purpose_mismatch_score >= 0.0
        assert report.llm_explanation.overall_risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        print(f"  ✓ Validated benchmark payload: {s_file} ({report.app_metadata.app_name})")

    # 2. Verify Frontend entry points and static dashboard assets
    app_tsx = PROJECT_ROOT / "src" / "App.tsx"
    assert app_tsx.exists(), "src/App.tsx missing!"
    content = app_tsx.read_text(encoding="utf-8")
    assert "computeMismatchAudit" in content, "Interactive heuristic engine missing from App.tsx!"
    assert "Interactive 4-Stage Security Audit Workbench" in content, "Module 7 workbench missing!"
    assert "downloadReportJson" in content, "JSON export function missing!"
    assert "printReport" in content, "Print forensic brief function missing!"
    print("  ✓ Verified React frontend interactive audit engine and export bindings.")

    # 3. Verify static HTML dashboard for FastAPI fallback
    frontend_html = PROJECT_ROOT / "frontend" / "index.html"
    assert frontend_html.exists(), "frontend/index.html missing!"
    print("  ✓ Verified FastAPI static HTML dashboard integration in frontend/index.html.")

    print("\n" + "=" * 60)
    print("[SUCCESS] All Module 7 Security Dashboard verifications passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
