"""
schemas/contracts.py - ShadowApp Core Data Contracts & Pydantic v2 Models

Defines the shared schemas across all 7 modules:
- AppMetadata: Stated store metadata and UI labels
- StaticFeatures: Extracted AndroidManifest and DEX call-graph telemetry
- DynamicFeatures: Frida hooks & mitmproxy network runtime telemetry
- MLScores: Purpose-vs-Behavior mismatch & malware anomaly scores
- LLMExplanation: Evidence-backed Gemini structured risk explanation
- ShadowAppReport: Aggregated report container
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

try:
    from pydantic import BaseModel, Field, ConfigDict
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    # Fallback base class if running in minimal Python environment without pydantic
    class BaseModel:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self) -> Dict[str, Any]:
            return {
                k: (v.model_dump() if hasattr(v, "model_dump") else v)
                for k, v in self.__dict__.items()
                if not k.startswith("_")
            }
        def model_dump_json(self, indent: int = 2) -> str:
            return json.dumps(self.model_dump(), indent=indent, default=str)
        @classmethod
        def model_validate(cls, obj: Any) -> Any:
            if isinstance(obj, dict):
                return cls(**obj)
            return obj

    def Field(*args: Any, **kwargs: Any) -> Any:  # type: ignore
        return kwargs.get("default", None)


class AppMetadata(BaseModel):
    """Declared app identity, store category, and marketing text."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    package_name: str = Field(description="Reverse-DNS Android package identifier (e.g. com.tool.cleanflashlight)")
    app_name: str = Field(description="Human-readable application label")
    stated_category: str = Field(description="Play Store declared category (e.g. Tools, Weather, Utilities)")
    stated_description: str = Field(description="Full user-facing marketing description from store listing")
    ui_strings: List[str] = Field(default_factory=list, description="Extracted UI strings from strings.xml or views")
    version_code: Optional[int] = Field(default=1, description="Version code integer from manifest")
    version_name: Optional[str] = Field(default="1.0.0", description="Display version string")
    min_sdk: Optional[int] = Field(default=26, description="Minimum Android SDK required")
    target_sdk: Optional[int] = Field(default=34, description="Target Android SDK")


class StaticFeatures(BaseModel):
    """Static analysis indicators extracted via Androguard from Manifest and DEX classes."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    requested_permissions: List[str] = Field(default_factory=list, description="All permissions declared in manifest")
    dangerous_permissions: List[str] = Field(default_factory=list, description="Dangerous permissions according to Android security guidelines")
    exported_components: List[str] = Field(default_factory=list, description="Activities, services, receivers exported without protection")
    suspicious_api_calls: List[str] = Field(default_factory=list, description="Sensitive Dalvik method invocations (SMS, reflection, crypto)")
    hardcoded_urls: List[str] = Field(default_factory=list, description="Extracted raw IP addresses and HTTP/HTTPS URLs")
    suspicious_receivers: List[str] = Field(default_factory=list, description="Broadcast receivers listening to sensitive intents (BOOT_COMPLETED, SMS_RECEIVED)")
    total_permissions_count: int = Field(default=0, description="Total count of declared permissions")
    uses_reflection: bool = Field(default=False, description="Flag indicating java.lang.reflect invocation in DEX")
    uses_dynamic_code_loading: bool = Field(default=False, description="Flag indicating DexClassLoader or PathClassLoader usage")
    uses_crypto: bool = Field(default=False, description="Flag indicating javax.crypto.Cipher usage")


class NetworkConnection(BaseModel):
    """Network connection metadata intercepted during dynamic testing."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    destination_host: str = Field(description="Hostname or IP address contacted")
    destination_port: int = Field(default=443, description="Target TCP/UDP port")
    protocol: str = Field(default="HTTPS", description="Application protocol (HTTP, HTTPS, TCP, DNS)")
    bytes_sent: int = Field(default=0, description="Payload volume sent in bytes")
    bytes_received: int = Field(default=0, description="Payload volume received in bytes")
    is_tls: bool = Field(default=True, description="Whether traffic used TLS encryption")
    suspicious_indicators: List[str] = Field(default_factory=list, description="Heuristic flags (e.g. Raw IP without SNI, Known C2, Cleartext HTTP)")


class DynamicFeatures(BaseModel):
    """Runtime telemetry captured via Frida hooks and mitmproxy sandbox."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    runtime_api_invocations: List[str] = Field(default_factory=list, description="Specific sensitive APIs called at runtime")
    network_connections: List[NetworkConnection] = Field(default_factory=list, description="Captured outbound network flows")
    file_system_modifications: List[str] = Field(default_factory=list, description="Modified or created files in app sandbox or shared storage")
    ssl_pinning_bypassed: bool = Field(default=False, description="Whether SSL pinning was present or bypassed")
    dex_class_loaded: List[str] = Field(default_factory=list, description="Dynamically loaded secondary DEX or JAR files")
    sms_sent: bool = Field(default=False, description="Runtime trigger of SmsManager.sendTextMessage")
    location_accessed: bool = Field(default=False, description="Runtime trigger of LocationManager or FusedLocation")
    contacts_accessed: bool = Field(default=False, description="Runtime query of ContentResolver for ContactsContract")
    background_traffic_mb: float = Field(default=0.0, description="Total outbound megabytes observed when app is backgrounded")


class ShapFeature(BaseModel):
    """Behavioral feature contributing to the ML classification decision."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    feature_name: str = Field(description="Identifier of the feature (e.g. perm::SEND_SMS or api::DexClassLoader)")
    importance_score: float = Field(description="Relative SHAP or importance weight")
    direction: Literal["increases_risk", "decreases_risk"] = Field(description="Impact on final maliciousness probability")
    description: str = Field(description="Analyst explanation of feature impact")


class MLScores(BaseModel):
    """Machine learning Purpose-vs-Behavior mismatch and anomaly metrics."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    malware_probability: float = Field(description="Supervised probability that the app exhibits malware behaviors (0.0 to 1.0)")
    purpose_mismatch_score: float = Field(description="Semantic deviation score between stated purpose and actual behaviors (0 to 100)")
    expected_permissions: List[str] = Field(default_factory=list, description="Permissions typically justified by the stated category and description")
    unexpected_permissions: List[str] = Field(default_factory=list, description="Permissions requested that possess zero semantic justification")
    unexpected_runtime_apis: List[str] = Field(default_factory=list, description="Runtime APIs invoked that fall outside stated utility bounds")
    top_shap_features: List[ShapFeature] = Field(default_factory=list, description="Ranked feature drivers influencing the risk calculation")
    anomaly_classification: Literal[
        "Benign / Expected",
        "Suspicious / Over-Privileged",
        "Malicious / Purpose Mismatch"
    ] = Field(description="Discrete categorization derived from the joint probability and mismatch thresholds")


class LLMExplanation(BaseModel):
    """Gemini Structured Output security analyst evaluation."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    overall_risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Comprehensive security rating"
    )
    executive_summary: str = Field(
        description="High-level analyst summary contrasting declared functionality against technical reality"
    )
    purpose_behavior_contradictions: List[str] = Field(
        default_factory=list,
        description="Specific contradictions between stated description and detected permissions or APIs"
    )
    privacy_risks: List[str] = Field(
        default_factory=list,
        description="Data harvesting, exfiltration, or user tracking vulnerabilities"
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Clear actionable recommendations for store reviewers, enterprise MDM, or users"
    )


class ShadowAppReport(BaseModel):
    """Master comprehensive audit report containing full pipeline state."""
    if PYDANTIC_AVAILABLE:
        model_config = ConfigDict(extra="ignore")

    app_metadata: AppMetadata
    static_features: StaticFeatures
    dynamic_features: DynamicFeatures
    ml_scores: MLScores
    llm_explanation: Optional[LLMExplanation] = Field(default=None, description="Gemini generated explanation")
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


def validate_report_dict(data: Dict[str, Any]) -> ShadowAppReport:
    """Helper function to parse and validate a dictionary into a ShadowAppReport."""
    if PYDANTIC_AVAILABLE:
        return ShadowAppReport.model_validate(data)
    else:
        # Fallback recursive parser
        app_meta = AppMetadata(**data.get("app_metadata", {}))
        static_f = StaticFeatures(**data.get("static_features", {}))
        
        dynamic_raw = data.get("dynamic_features", {})
        net_raw = dynamic_raw.pop("network_connections", [])
        net_conns = [NetworkConnection(**nc) for nc in net_raw]
        dynamic_f = DynamicFeatures(network_connections=net_conns, **dynamic_raw)

        ml_raw = data.get("ml_scores", {})
        shap_raw = ml_raw.pop("top_shap_features", [])
        shap_feats = [ShapFeature(**sf) for sf in shap_raw]
        ml_s = MLScores(top_shap_features=shap_feats, **ml_raw)

        llm_raw = data.get("llm_explanation")
        llm_e = LLMExplanation(**llm_raw) if llm_raw else None

        return ShadowAppReport(
            app_metadata=app_meta,
            static_features=static_f,
            dynamic_features=dynamic_f,
            ml_scores=ml_s,
            llm_explanation=llm_e,
            analyzed_at=data.get("analyzed_at", datetime.utcnow().isoformat() + "Z")
        )
