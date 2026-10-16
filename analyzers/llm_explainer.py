"""
analyzers/llm_explainer.py - ShadowApp Gemini LLM Risk Explanation Service

Uses the Google GenAI SDK (gemini-3.8-flash) with Structured Outputs to evaluate
static/dynamic telemetry anomalies against stated purpose, producing an evidence-backed
security assessment conforming to the LLMExplanation schema.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from schemas.contracts import (
    AppMetadata,
    DynamicFeatures,
    LLMExplanation,
    MLScores,
    StaticFeatures,
)

logger = logging.getLogger("ShadowApp.LLMExplainer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SECURITY_ANALYST_SYSTEM_PROMPT = """You are ShadowApp Senior Mobile Security Analyst, an automated threat intelligence system inspecting Android applications for deceptive, over-privileged, or malicious behavior.

Your objective:
1. Compare the application's stated marketing purpose (category, Play Store description) against its actual technical reality (declared permissions, dangerous permissions, runtime API invocations, and network connections).
2. Explicitly highlight purpose-versus-behavior contradictions. For instance, if a flashlight or calculator accesses SMS, contacts, location, or initiates external network connections, flag these as severe anomalies.
3. Quantify privacy risks, including data harvesting, cross-application user tracking, unencrypted HTTP transmission, or covert command-and-control communication.
4. Provide concrete, actionable remediation steps for end-users, mobile enterprise administrators, and app store reviewers.

CRITICAL RULES:
- Never hallucinate permissions or APIs that were not provided in the technical profile.
- Ground every claim directly in the provided static and dynamic indicators.
- Produce output strictly conforming to the requested JSON schema.
"""


class GeminiRiskExplainer:
    """
    Evaluates Purpose-vs-Behavior telemetry using Gemini Structured Outputs.
    """

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-3.8-flash") -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model_name = model_name
        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        """Initializes the google-genai client if API key and library are present."""
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not configured. Rule-based explanation fallback will be active.")
            return

        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
            logger.info(f"Google GenAI Client initialized successfully with model: {self.model_name}")
        except ImportError:
            logger.warning("google-genai library not installed. Falling back to rule-based explanation engine.")
        except Exception as e:
            logger.warning(f"Failed to instantiate GenAI client: {e}. Falling back to rule-based explanation engine.")

    def explain(
        self,
        app_metadata: AppMetadata,
        static_features: StaticFeatures,
        dynamic_features: DynamicFeatures,
        ml_scores: Optional[MLScores] = None,
    ) -> LLMExplanation:
        """
        Generates an evidence-backed LLMExplanation for the provided telemetry profile.
        """
        # Build prompt payload
        prompt_payload = {
            "app_identity": {
                "package_name": app_metadata.package_name,
                "app_name": app_metadata.app_name,
                "stated_category": app_metadata.stated_category,
                "stated_description": app_metadata.stated_description,
            },
            "technical_findings": {
                "requested_permissions": static_features.requested_permissions,
                "dangerous_permissions": static_features.dangerous_permissions,
                "exported_components": static_features.exported_components,
                "suspicious_api_calls": static_features.suspicious_api_calls,
                "hardcoded_urls": static_features.hardcoded_urls,
                "uses_reflection": static_features.uses_reflection,
                "uses_dynamic_code_loading": static_features.uses_dynamic_code_loading,
                "uses_crypto": static_features.uses_crypto,
            },
            "runtime_telemetry": {
                "runtime_api_invocations": dynamic_features.runtime_api_invocations,
                "sms_sent": dynamic_features.sms_sent,
                "location_accessed": dynamic_features.location_accessed,
                "contacts_accessed": dynamic_features.contacts_accessed,
                "dex_class_loaded": dynamic_features.dex_class_loaded,
                "background_traffic_mb": dynamic_features.background_traffic_mb,
                "network_connections": [
                    {
                        "host": c.destination_host,
                        "port": c.destination_port,
                        "protocol": c.protocol,
                        "is_tls": c.is_tls,
                        "suspicious_flags": c.suspicious_indicators,
                    }
                    for c in dynamic_features.network_connections
                ],
            },
            "mismatch_heuristics": {
                "malware_probability": ml_scores.malware_probability if ml_scores else 0.5,
                "purpose_mismatch_score": ml_scores.purpose_mismatch_score if ml_scores else 50.0,
                "unexpected_permissions": ml_scores.unexpected_permissions if ml_scores else [],
                "unexpected_runtime_apis": ml_scores.unexpected_runtime_apis if ml_scores else [],
            },
        }

        # If live Gemini client is available, invoke Structured Outputs
        if self.client:
            try:
                return self._call_gemini_api(prompt_payload)
            except Exception as e:
                logger.error(f"Gemini API request failed: {e}. Engaging deterministic analyst fallback.")

        # Fallback to deterministic rule-based analyst engine
        return self._rule_based_fallback_explanation(
            app_metadata, static_features, dynamic_features, ml_scores
        )

    def _call_gemini_api(self, prompt_payload: Dict[str, Any]) -> LLMExplanation:
        """Queries Gemini with Structured Outputs enforcement."""
        from google.genai import types

        user_content = (
            f"Analyze this mobile application profile and evaluate purpose-versus-behavior contradictions:\n\n"
            f"{json.dumps(prompt_payload, indent=2)}"
        )

        # Build JSON schema for response_schema
        response_schema = {
            "type": "OBJECT",
            "properties": {
                "overall_risk_level": {
                    "type": "STRING",
                    "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    "description": "Comprehensive security threat rating",
                },
                "executive_summary": {
                    "type": "STRING",
                    "description": "Executive summary explaining declared intent vs actual technical capabilities",
                },
                "purpose_behavior_contradictions": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                    "description": "Specific contradictions between declared purpose and detected behavior",
                },
                "privacy_risks": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                    "description": "Privacy and surveillance threats",
                },
                "recommended_actions": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"},
                    "description": "Mitigation steps for users and administrators",
                },
            },
            "required": [
                "overall_risk_level",
                "executive_summary",
                "purpose_behavior_contradictions",
                "privacy_risks",
                "recommended_actions",
            ],
        }

        config = types.GenerateContentConfig(
            system_instruction=SECURITY_ANALYST_SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_schema=response_schema,
            temperature=0.2,
        )

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=user_content,
            config=config,
        )

        raw_json = json.loads(response.text)
        return LLMExplanation(**raw_json)

    def _rule_based_fallback_explanation(
        self,
        meta: AppMetadata,
        static: StaticFeatures,
        dynamic: DynamicFeatures,
        ml: Optional[MLScores],
    ) -> LLMExplanation:
        """
        Deterministic, rule-based analyst synthesizer when offline or without API key.
        """
        contradictions: List[str] = []
        privacy_risks: List[str] = []
        actions: List[str] = []

        mismatch_score = ml.purpose_mismatch_score if ml else 0.0
        malware_prob = ml.malware_probability if ml else 0.0

        # Assess Telephony / SMS
        if dynamic.sms_sent or "android.permission.SEND_SMS" in static.dangerous_permissions:
            contradictions.append(
                f"Application requests SEND_SMS permission despite being marketed as '{meta.stated_category}', which has 0% utility relevance."
            )
            privacy_risks.append(
                "Potential financial toll fraud through unauthorized background premium-rate SMS dispatch."
            )
            actions.append("Immediately revoke SMS permissions in Android OS settings and check mobile carrier bills.")

        # Assess Contacts
        if dynamic.contacts_accessed or "android.permission.READ_CONTACTS" in static.dangerous_permissions:
            contradictions.append(
                f"Stated purpose '{meta.stated_description[:60]}...' does not justify reading private address book contacts."
            )
            privacy_risks.append(
                "Exfiltration of personal contacts database exposing user associates to phishing."
            )
            actions.append("Deny Contacts permissions to prevent unauthorized address book harvesting.")

        # Assess Phone State / Device Identification
        if "android.permission.READ_PHONE_STATE" in static.dangerous_permissions:
            contradictions.append(
                f"Application requests READ_PHONE_STATE to harvest persistent hardware identifiers, which has zero meteorological or utility relevance in '{meta.stated_category}'."
            )
            privacy_risks.append(
                "Hardware device identifiers (IMEI/IMSI) allow advertising SDKs to track user behavior across disparate applications."
            )
            actions.append("Revoke 'Phone' permission in Android application settings to prevent device fingerprinting.")

        # Assess Location
        if dynamic.location_accessed or any("LOCATION" in p for p in static.dangerous_permissions):
            if "weather" not in meta.stated_category.lower() and "map" not in meta.stated_category.lower():
                contradictions.append(
                    f"Geolocation monitoring active in category '{meta.stated_category}' without user-facing spatial utility."
                )
            privacy_risks.append(
                "Persistent device geolocation tracking builds a continuous historical movement profile."
            )

        # Assess Dynamic Loading & Root Shell
        if static.uses_dynamic_code_loading:
            contradictions.append(
                "Application dynamically unrolls and executes unverified secondary DEX bytecodes via DexClassLoader."
            )
            privacy_risks.append("Arbitrary remote payload execution bypassing static store vetting.")
            actions.append("Uninstall application; dynamic code loading poses critical integrity hazards.")

        # Assess Cleartext and Raw IP connections
        for conn in dynamic.network_connections:
            if not conn.is_tls:
                privacy_risks.append(
                    f"Unencrypted HTTP communication observed to {conn.destination_host}:{conn.destination_port} vulnerable to sniffing."
                )
            if any("Raw IPv4" in s for s in conn.suspicious_indicators):
                contradictions.append(
                    f"Application connects directly to an unauthenticated numeric IP C2 node ({conn.destination_host}:{conn.destination_port})."
                )

        # Determine Overall Risk Level
        if malware_prob >= 0.75 or mismatch_score >= 80 or dynamic.sms_sent or static.uses_dynamic_code_loading:
            risk_level = "CRITICAL"
            summary = (
                f"CRITICAL SECURITY THREAT: {meta.app_name} exhibits severe purpose-behavior contradictions. "
                f"Marketed as a '{meta.stated_category}', it executes high-risk operations including "
                f"{', '.join([c.split()[0] for c in contradictions[:2]])} without legitimate user-facing justification."
            )
            actions.insert(0, "IMMEDIATELY UNINSTALL the application from all devices.")
        elif malware_prob >= 0.35 or mismatch_score >= 40 or len(contradictions) > 0 or len(privacy_risks) >= 2:
            risk_level = "MEDIUM"
            summary = (
                f"SUSPICIOUS / OVER-PRIVILEGED: {meta.app_name} provides functional {meta.stated_category} capabilities, "
                f"but embeds aggressive telemetry and tracking features that harvest persistent hardware or location data."
            )
            actions.append("Review and restrict granted runtime permissions in device settings.")
        else:
            risk_level = "LOW"
            summary = (
                f"BENIGN OPERATION VERIFIED: {meta.app_name} operates strictly within the expected functional bounds "
                f"of a {meta.stated_category}. No covert data exfiltration or anomalous runtime behaviors were detected."
            )
            actions.append("Safe for installation. No security remediations required.")

        return LLMExplanation(
            overall_risk_level=risk_level,
            executive_summary=summary,
            purpose_behavior_contradictions=contradictions,
            privacy_risks=privacy_risks,
            recommended_actions=actions,
        )


# Alias LLMExplainer to GeminiRiskExplainer for developer convenience
LLMExplainer = GeminiRiskExplainer


if __name__ == "__main__":
    from analyzers.static_analyzer import StaticAPKAnalyzer
    from analyzers.sandbox_runner import DynamicSandboxRunner

    static_eng = StaticAPKAnalyzer()
    sandbox = DynamicSandboxRunner()
    explainer = GeminiRiskExplainer()

    meta, static = static_eng.analyze("trojan_flashlight")
    dyn = sandbox.run("trojan_flashlight", static)
    explanation = explainer.explain(meta, static, dyn)

    print("=" * 60)
    print("Gemini Risk Explanation:")
    print("Risk Level:", explanation.overall_risk_level)
    print("Executive Summary:", explanation.executive_summary)
    print("Contradictions:", len(explanation.purpose_behavior_contradictions))
    print("Privacy Risks:", len(explanation.privacy_risks))
    print("Actions:", len(explanation.recommended_actions))
    print("=" * 60)
