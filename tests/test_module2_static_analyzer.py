"""
tests/test_module2_static_analyzer.py - Verification suite for Module 2 StaticAPKAnalyzer.
"""

import os
import sys
import tempfile
import zipfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.static_analyzer import StaticAPKAnalyzer
from schemas.contracts import AppMetadata, StaticFeatures


def create_synthetic_test_apk(output_path: Path) -> None:
    """Generates a synthetic Android APK zip container containing mock manifest & DEX strings."""
    manifest_content = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="com.security.test.malware" versionCode="1" versionName="1.0">\n'
        '  <uses-permission android:name="android.permission.INTERNET" />\n'
        '  <uses-permission android:name="android.permission.SEND_SMS" />\n'
        '  <uses-permission android:name="android.permission.READ_CONTACTS" />\n'
        '  <application android:label="Synthetic Trojan">\n'
        '    <receiver android:name=".receiver.BootReceiver">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.BOOT_COMPLETED" />\n'
        '      </intent-filter>\n'
        '    </receiver>\n'
        '  </application>\n'
        '</manifest>\n'
    )

    dex_content = (
        b"dex\n035\x00"
        b"Landroid/telephony/SmsManager;->sendTextMessage"
        b"dalvik/system/DexClassLoader;->loadClass"
        b"Ljava/lang/reflect/Method;->invoke"
        b"http://194.26.29.112:8080/c2/register"
        b"https://api.trackingnode.org/sync"
    )

    with zipfile.ZipFile(output_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        zf.writestr("classes.dex", dex_content)


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp Module 2 StaticAPKAnalyzer Verification")
    print("=" * 60)

    analyzer = StaticAPKAnalyzer()

    # 1. Test benchmark sample loading
    print("[TEST 1] Testing benchmark sample loading...")
    for sample in ["benign_calculator", "adware_weather", "trojan_flashlight"]:
        meta, static = analyzer.analyze(sample)
        assert isinstance(meta, AppMetadata), f"Expected AppMetadata, got {type(meta)}"
        assert isinstance(static, StaticFeatures), f"Expected StaticFeatures, got {type(static)}"
        print(f"  ✓ Sample '{sample}': {meta.app_name} (Total perms: {static.total_permissions_count})")

    # 2. Test synthetic real APK inspection via direct zip/DEX engine
    print("\n[TEST 2] Testing synthetic APK inspection...")
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp_apk:
        tmp_path = Path(tmp_apk.name)

    try:
        create_synthetic_test_apk(tmp_path)
        meta, static = analyzer.analyze(
            str(tmp_path),
            stated_description="A benign flashlight tool that illuminates dark rooms",
            stated_category="Tools / Flashlight",
        )

        print(f"  Package: {meta.package_name}")
        print(f"  Requested Perms: {static.requested_permissions}")
        print(f"  Dangerous Perms: {static.dangerous_permissions}")
        print(f"  Suspicious Receivers: {static.suspicious_receivers}")
        print(f"  Suspicious APIs: {static.suspicious_api_calls}")
        print(f"  Hardcoded URLs/IPs: {static.hardcoded_urls}")
        print(f"  Uses Reflection: {static.uses_reflection}")
        print(f"  Uses Dynamic Loading: {static.uses_dynamic_code_loading}")

        assert "android.permission.SEND_SMS" in static.dangerous_permissions, "Failed to extract SEND_SMS dangerous perm"
        assert "android.permission.READ_CONTACTS" in static.dangerous_permissions, "Failed to extract READ_CONTACTS"
        assert "android.intent.action.BOOT_COMPLETED" in static.suspicious_receivers, "Failed to extract BOOT_COMPLETED receiver"
        assert static.uses_reflection is True, "Failed to flag reflection usage"
        assert static.uses_dynamic_code_loading is True, "Failed to flag DexClassLoader usage"
        assert any("194.26.29.112" in u for u in static.hardcoded_urls), "Failed to match hardcoded C2 IP"

        print("  ✓ Synthetic APK inspection successfully detected all malicious static indicators!")
    finally:
        if tmp_path.exists():
            os.unlink(tmp_path)

    # 3. Test corrupted APK fallback mode
    print("\n[TEST 3] Testing corrupted APK fallback mode...")
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False, prefix="corrupted_flashlight_") as tmp_corrupt:
        tmp_corrupt.write(b"NOT_A_VALID_ZIP_HEADER_CORRUPTED_BYTES")
        corrupt_path = Path(tmp_corrupt.name)

    try:
        meta_fb, static_fb = analyzer.analyze(str(corrupt_path))
        assert meta_fb is not None and static_fb is not None
        print(f"  ✓ Graceful fallback succeeded on corrupted APK (loaded fallback: {meta_fb.app_name})")
    finally:
        if corrupt_path.exists():
            os.unlink(corrupt_path)

    print("\n" + "=" * 60)
    print("[SUCCESS] All Module 2 Static Analysis tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
