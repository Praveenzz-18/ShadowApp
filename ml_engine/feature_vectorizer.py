"""
ml_engine/feature_vectorizer.py - ShadowApp Feature Vectorizer

Converts stated descriptions and category metadata into dense semantic embeddings
(using Gemini Embeddings or deterministic semantic hashing fallback), and encodes
StaticFeatures + DynamicFeatures into fixed behavioral numerical vectors for ML models.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from schemas.contracts import DynamicFeatures, StaticFeatures

logger = logging.getLogger("ShadowApp.FeatureVectorizer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Fixed vocabulary of evaluated permissions (binary features)
TRACKED_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SEND_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.FLASHLIGHT",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
]

# Fixed vocabulary of evaluated Dalvik API signatures
TRACKED_APIS = [
    "android.telephony.SmsManager.sendTextMessage",
    "android.telephony.TelephonyManager.getDeviceId",
    "android.telephony.TelephonyManager.getSubscriberId",
    "dalvik.system.DexClassLoader.loadClass",
    "dalvik.system.PathClassLoader.loadClass",
    "java.lang.reflect.Method.invoke",
    "java.lang.Runtime.getRuntime.exec",
    "javax.crypto.Cipher.getInstance",
    "android.content.ContentResolver.query",
    "android.location.LocationManager.getLastKnownLocation",
]

# Dynamic runtime telemetry signals
DYNAMIC_SIGNALS = [
    "dynamic::sms_sent",
    "dynamic::contacts_accessed",
    "dynamic::location_accessed",
    "dynamic::dex_class_loaded",
    "dynamic::unencrypted_http",
    "dynamic::raw_ip_c2",
    "dynamic::high_background_traffic",
]

EMBEDDING_DIM = 64


class FeatureVectorizer:
    """
    Transforms textual app purpose and static/dynamic telemetry into ML-ready feature matrices.
    """

    def __init__(self, api_key: Optional[str] = None, embedding_model: str = "gemini-embedding-2-preview") -> None:
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.embedding_model = embedding_model
        self.client = None
        self._init_genai()

    def _init_genai(self) -> None:
        if not self.api_key:
            return
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            logger.warning(f"Could not initialize GenAI embeddings client: {e}. Using deterministic semantic hashing.")

    def embed_purpose_text(self, description: str, category: str) -> List[float]:
        """
        Embeds app description and category into a dense float vector.
        Uses Gemini Embeddings API if configured, or deterministic semantic hashing fallback.
        """
        combined_text = f"Category: {category}. Description: {description}".strip()

        if self.client:
            try:
                response = self.client.models.embed_content(
                    model=self.embedding_model,
                    contents=combined_text,
                )
                if response.embedding and response.embedding.values:
                    # Return first EMBEDDING_DIM dimensions or full vector
                    vals = response.embedding.values[:EMBEDDING_DIM]
                    # Normalize vector
                    norm = math.sqrt(sum(v * v for v in vals)) or 1.0
                    return [v / norm for v in vals]
            except Exception as e:
                logger.warning(f"Gemini embedding API call failed: {e}. Falling back to semantic hashing.")

        return self._deterministic_semantic_hashing(combined_text, EMBEDDING_DIM)

    def _deterministic_semantic_hashing(self, text: str, dimension: int) -> List[float]:
        """
        Produces a stable, normalized pseudo-semantic embedding vector using n-gram feature hashing.
        """
        vector = [0.0] * dimension
        words = re.findall(r"\w+", text.lower())

        # Unigrams & bigrams
        tokens = list(words)
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")

        for token in tokens:
            # Hash token into an index and sign
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            idx = h % dimension
            sign = 1.0 if (h >> 16) % 2 == 0 else -1.0
            # Keyword weighting for security categories
            weight = 1.0
            if token in ["calculator", "offline", "math", "clean"]:
                weight = 2.0
            elif token in ["flashlight", "torch", "led", "bright"]:
                weight = 2.0
            elif token in ["weather", "radar", "forecast", "storm"]:
                weight = 2.0
            elif token in ["sms", "message", "contacts", "c2"]:
                weight = 2.5
            vector[idx] += sign * weight

        # L2 Normalization
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 0.0:
            vector = [v / norm for v in vector]
        return vector

    def vectorize_behavior(
        self, static: StaticFeatures, dynamic: DynamicFeatures
    ) -> Tuple[List[float], List[str]]:
        """
        Vectorizes static Dalvik findings and dynamic sandbox flows into a fixed numerical vector.
        Returns: (feature_vector, feature_names)
        """
        values: List[float] = []
        names: List[str] = []

        # 1. Permission indicators (0.0 or 1.0)
        actual_perms = set(static.requested_permissions)
        for perm in TRACKED_PERMISSIONS:
            name = f"perm::{perm.split('.')[-1]}"
            val = 1.0 if perm in actual_perms else 0.0
            values.append(val)
            names.append(name)

        # 2. Static Dalvik API calls (0.0 or 1.0)
        actual_apis = set(static.suspicious_api_calls)
        for api in TRACKED_APIS:
            name = f"api::{api.split('.')[-1]}"
            val = 1.0 if any(api in a for a in actual_apis) else 0.0
            values.append(val)
            names.append(name)

        # 3. Static behavioral flags
        values.append(1.0 if static.uses_reflection else 0.0)
        names.append("static::uses_reflection")

        values.append(1.0 if static.uses_dynamic_code_loading else 0.0)
        names.append("static::uses_dynamic_code_loading")

        values.append(1.0 if static.uses_crypto else 0.0)
        names.append("static::uses_crypto")

        # 4. Dynamic runtime indicators
        values.append(1.0 if dynamic.sms_sent else 0.0)
        names.append("dynamic::sms_sent")

        values.append(1.0 if dynamic.contacts_accessed else 0.0)
        names.append("dynamic::contacts_accessed")

        values.append(1.0 if dynamic.location_accessed else 0.0)
        names.append("dynamic::location_accessed")

        values.append(1.0 if len(dynamic.dex_class_loaded) > 0 else 0.0)
        names.append("dynamic::dex_class_loaded")

        # Dynamic network flags
        has_cleartext = any(not c.is_tls for c in dynamic.network_connections)
        values.append(1.0 if has_cleartext else 0.0)
        names.append("dynamic::unencrypted_http")

        has_raw_ip = any(
            any("Raw IPv4" in ind for ind in c.suspicious_indicators)
            for c in dynamic.network_connections
        )
        values.append(1.0 if has_raw_ip else 0.0)
        names.append("dynamic::raw_ip_c2")

        # Background traffic volume normalized (clipped at 50 MB)
        norm_traffic = min(dynamic.background_traffic_mb / 50.0, 1.0)
        values.append(norm_traffic)
        names.append("dynamic::background_traffic_norm")

        return values, names

    @property
    def total_feature_count(self) -> int:
        return len(TRACKED_PERMISSIONS) + len(TRACKED_APIS) + 3 + 7
