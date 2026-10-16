"""
tests/test_module3_sandbox_runner.py - Verification suite for Module 3 DynamicSandboxRunner.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.sandbox_runner import DynamicSandboxRunner
from schemas.contracts import DynamicFeatures, NetworkConnection, StaticFeatures


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp Module 3 DynamicSandboxRunner Verification")
    print("=" * 60)

    runner = DynamicSandboxRunner()

    # 1. Test benchmark sample loading
    print("[TEST 1] Testing dynamic telemetry sample benchmark loading...")
    for sample in ["benign_calculator", "adware_weather", "trojan_flashlight"]:
        dyn = runner.run(sample)
        assert isinstance(dyn, DynamicFeatures), f"Expected DynamicFeatures, got {type(dyn)}"
        print(f"  ✓ Sample '{sample}':")
        print(f"      Runtime APIs: {len(dyn.runtime_api_invocations)}")
        print(f"      Network Flows: {len(dyn.network_connections)}")
        print(f"      SMS Sent: {dyn.sms_sent} | Location: {dyn.location_accessed} | Contacts: {dyn.contacts_accessed}")

    # 2. Test mitmproxy log parser
    print("\n[TEST 2] Testing mitmproxy flow log parser...")
    mock_flows = [
        {
            "host": "api.clean-weather.org",
            "port": 443,
            "protocol": "HTTPS",
            "bytes_sent": 1200,
            "bytes_received": 14000,
            "is_tls": True
        },
        {
            "host": "194.26.29.112",
            "port": 8080,
            "protocol": "HTTP",
            "bytes_sent": 54000,
            "bytes_received": 1200,
            "is_tls": False
        },
        {
            "host": "telemetry.adclicknetwork.biz",
            "port": 443,
            "protocol": "HTTPS",
            "bytes_sent": 42000,
            "bytes_received": 800,
            "is_tls": True
        }
    ]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp_flow:
        json.dump(mock_flows, tmp_flow)
        tmp_flow_path = Path(tmp_flow.name)

    try:
        parsed_conns = runner.parse_mitmproxy_dump(tmp_flow_path)
        assert len(parsed_conns) == 3, f"Expected 3 parsed connections, got {len(parsed_conns)}"
        
        # Verify raw IP detection
        raw_ip_conn = next(c for c in parsed_conns if c.destination_host == "194.26.29.112")
        assert raw_ip_conn.is_tls is False
        assert any("Raw IPv4" in ind for ind in raw_ip_conn.suspicious_indicators)

        # Verify tracker detection
        tracker_conn = next(c for c in parsed_conns if "adclicknetwork" in c.destination_host)
        assert any("tracker" in ind.lower() for ind in tracker_conn.suspicious_indicators)

        print("  ✓ mitmproxy parser correctly identified raw IPv4 C2 node and cleartext traffic!")
    finally:
        if tmp_flow_path.exists():
            os.unlink(tmp_flow_path)

    # 3. Test Frida log parser
    print("\n[TEST 3] Testing Frida structured event parser...")
    mock_frida_lines = [
        json.dumps({
            "timestamp": "2026-10-16T12:00:00Z",
            "category": "TELEPHONY",
            "api": "android.telephony.SmsManager.sendTextMessage",
            "metadata": {"destination": "55512", "messageLength": 28}
        }),
        json.dumps({
            "timestamp": "2026-10-16T12:00:01Z",
            "category": "CONTENT_RESOLVER",
            "api": "android.content.ContentResolver.query",
            "metadata": {"uri": "content://contacts/people"}
        }),
        json.dumps({
            "timestamp": "2026-10-16T12:00:02Z",
            "category": "DYNAMIC_CODE_LOADING",
            "api": "dalvik.system.DexClassLoader.loadClass",
            "metadata": {"className": "com.trojan.core.PayloadDispatcher"}
        })
    ]

    parsed_frida = runner.parse_frida_logs(mock_frida_lines)
    assert parsed_frida["sms_sent"] is True, "Failed to flag sms_sent from Frida events"
    assert parsed_frida["contacts_accessed"] is True, "Failed to flag contacts_accessed from Frida events"
    assert "com.trojan.core.PayloadDispatcher" in parsed_frida["dex_class_loaded"]
    print("  ✓ Frida log parser correctly decoded SMS, Contacts, and Dynamic DEX events!")

    # 4. Test Simulation Mode Grounding from Static Features
    print("\n[TEST 4] Testing Simulation Mode synthesis from static features...")
    mock_static = StaticFeatures(
        requested_permissions=["android.permission.INTERNET", "android.permission.SEND_SMS", "android.permission.READ_CONTACTS"],
        dangerous_permissions=["android.permission.SEND_SMS", "android.permission.READ_CONTACTS"],
        exported_components=[],
        suspicious_api_calls=["android.telephony.SmsManager.sendTextMessage"],
        hardcoded_urls=["http://194.26.29.112:8080/c2"],
        suspicious_receivers=["android.intent.action.BOOT_COMPLETED"],
        total_permissions_count=3,
        uses_reflection=True,
        uses_dynamic_code_loading=True,
        uses_crypto=True
    )

    sim_dyn = runner.run(
        package_name="com.suspicious.test.app",
        static_features=mock_static,
        simulation_mode=True
    )

    assert sim_dyn.sms_sent is True, "Simulation failed to infer sms_sent"
    assert sim_dyn.contacts_accessed is True, "Simulation failed to infer contacts_accessed"
    assert len(sim_dyn.network_connections) == 1, "Simulation failed to synthesize C2 network connection"
    assert sim_dyn.network_connections[0].destination_host == "194.26.29.112"
    assert len(sim_dyn.dex_class_loaded) > 0, "Simulation failed to include dropped DEX payload"
    print("  ✓ Simulation mode successfully synthesized realistic dynamic telemetry from static indicators!")

    print("\n" + "=" * 60)
    print("[SUCCESS] All Module 3 Dynamic Sandbox Runner tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
