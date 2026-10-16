"""
tests/test_module6_main_api.py - Verification suite for Module 6 FastAPI Orchestration Backend.
"""

import os
import sys
import tempfile
import zipfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from main import SAMPLE_CATALOG, run_full_pipeline
from schemas.contracts import ShadowAppReport


def create_test_apk(output_path: Path) -> None:
    """Generates a synthetic Android APK zip container."""
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="com.pipeline.test.trojan" versionCode="1" versionName="1.0">\n'
        '  <uses-permission android:name="android.permission.INTERNET" />\n'
        '  <uses-permission android:name="android.permission.SEND_SMS" />\n'
        '  <uses-permission android:name="android.permission.READ_CONTACTS" />\n'
        '  <application android:label="Pipeline Trojan">\n'
        '    <receiver android:name=".receiver.Boot">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.BOOT_COMPLETED" />\n'
        '      </intent-filter>\n'
        '    </receiver>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    dex = (
        b"dex\n035\x00"
        b"Landroid/telephony/SmsManager;->sendTextMessage"
        b"http://194.26.29.112:8080/c2/register"
    )
    with zipfile.ZipFile(output_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp Module 6 Full Orchestration Verification")
    print("=" * 60)

    # 1. Test Catalog Integrity
    print("[TEST 1] Testing sample catalog integrity...")
    assert len(SAMPLE_CATALOG) == 3
    for s_id, s_info in SAMPLE_CATALOG.items():
        assert "package_name" in s_info
        assert "risk_level" in s_info
        print(f"  ✓ Sample catalog entry: {s_info['name']} ({s_id})")

    # 2. Test End-to-End Pipeline on Benign Calculator
    print("\n[TEST 2] Testing 4-stage pipeline on Benign Calculator...")
    report_calc = run_full_pipeline("benign_calculator")
    assert isinstance(report_calc, ShadowAppReport)
    assert report_calc.ml_scores.anomaly_classification == "Benign / Expected"
    assert report_calc.llm_explanation.overall_risk_level == "LOW"
    print(f"  ✓ App: {report_calc.app_metadata.app_name}")
    print(f"  ✓ Mismatch Score: {report_calc.ml_scores.purpose_mismatch_score}/100")
    print(f"  ✓ Risk Rating: {report_calc.llm_explanation.overall_risk_level}")

    # 3. Test End-to-End Pipeline on Trojan Flashlight
    print("\n[TEST 3] Testing 4-stage pipeline on Trojan Flashlight...")
    report_trojan = run_full_pipeline("trojan_flashlight")
    assert isinstance(report_trojan, ShadowAppReport)
    assert report_trojan.ml_scores.anomaly_classification == "Malicious / Purpose Mismatch"
    assert report_trojan.llm_explanation.overall_risk_level == "CRITICAL"
    print(f"  ✓ App: {report_trojan.app_metadata.app_name}")
    print(f"  ✓ Mismatch Score: {report_trojan.ml_scores.purpose_mismatch_score}/100")
    print(f"  ✓ Malware Prob: {report_trojan.ml_scores.malware_probability:.2f}")
    print(f"  ✓ Risk Rating: {report_trojan.llm_explanation.overall_risk_level}")
    print(f"  ✓ Contradictions: {len(report_trojan.llm_explanation.purpose_behavior_contradictions)}")

    # 4. Test Live Synthetic APK File Upload Pipeline
    print("\n[TEST 4] Testing 4-stage pipeline on uploaded synthetic APK file...")
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_apk:
        tmp_path = Path(tmp_apk.name)

    try:
        create_test_apk(tmp_path)
        report_upload = run_full_pipeline(
            str(tmp_path),
            stated_description="A harmless scientific calculator that calculates derivatives offline",
            stated_category="Tools / Calculator",
            run_dynamic_sandbox=True,
        )

        assert isinstance(report_upload, ShadowAppReport)
        assert "android.permission.SEND_SMS" in report_upload.static_features.dangerous_permissions
        assert report_upload.dynamic_features.sms_sent is True
        assert report_upload.ml_scores.purpose_mismatch_score >= 70.0
        assert report_upload.llm_explanation.overall_risk_level in ["HIGH", "CRITICAL"]

        print(f"  ✓ Uploaded APK Package: {report_upload.app_metadata.package_name}")
        print(f"  ✓ Detected Dangerous Perms: {report_upload.static_features.dangerous_permissions}")
        print(f"  ✓ Dynamic SMS Sent Flag: {report_upload.dynamic_features.sms_sent}")
        print(f"  ✓ Mismatch Score: {report_upload.ml_scores.purpose_mismatch_score}/100")
        print(f"  ✓ AI Threat Rating: {report_upload.llm_explanation.overall_risk_level}")
        print("  ✓ Full 4-stage pipeline execution verified end-to-end on uploaded APK!")
    finally:
        if tmp_path.exists():
            os.unlink(tmp_path)

    print("\n" + "=" * 60)
    print("[SUCCESS] All Module 6 FastAPI Orchestration tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
