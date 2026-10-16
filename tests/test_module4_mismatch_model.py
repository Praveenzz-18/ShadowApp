"""
tests/test_module4_mismatch_model.py - Verification suite for Module 4 ML Pipeline.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml_engine.feature_vectorizer import FeatureVectorizer
from ml_engine.mismatch_model import PurposeBehaviorMismatchEngine
from analyzers.static_analyzer import StaticAPKAnalyzer
from analyzers.sandbox_runner import DynamicSandboxRunner
from schemas.contracts import MLScores


def run_tests() -> int:
    print("=" * 60)
    print("ShadowApp Module 4 ML Mismatch Pipeline Verification")
    print("=" * 60)

    vectorizer = FeatureVectorizer()
    mismatch_engine = PurposeBehaviorMismatchEngine()
    static_analyzer = StaticAPKAnalyzer()
    sandbox_runner = DynamicSandboxRunner()

    # 1. Test Feature Vectorizer Embeddings & Behavior Encoding
    print("\n[TEST 1] Testing FeatureVectorizer text embedding & telemetry vectorization...")
    emb = vectorizer.embed_purpose_text("A simple offline calculator for basic math", "Tools / Calculator")
    assert len(emb) == 64, f"Expected 64-dim embedding, got {len(emb)}"
    
    meta_calc, static_calc = static_analyzer.analyze("benign_calculator")
    dyn_calc = sandbox_runner.run("benign_calculator", static_calc)
    vec, names = vectorizer.vectorize_behavior(static_calc, dyn_calc)
    assert len(vec) == len(names) and len(vec) > 30
    print(f"  ✓ Text embedding vector dimension: {len(emb)}")
    print(f"  ✓ Behavioral feature vector dimensions: {len(vec)} features")

    # 2. Test Benign Calculator Evaluation
    print("\n[TEST 2] Testing Benign Calculator ML scoring...")
    scores_calc = mismatch_engine.predict(meta_calc, static_calc, dyn_calc)
    assert isinstance(scores_calc, MLScores)
    assert scores_calc.purpose_mismatch_score <= 15.0, f"Expected low mismatch, got {scores_calc.purpose_mismatch_score}"
    assert scores_calc.malware_probability <= 0.15, f"Expected low malware prob, got {scores_calc.malware_probability}"
    assert scores_calc.anomaly_classification == "Benign / Expected"
    assert len(scores_calc.unexpected_permissions) == 0
    print(f"  ✓ Mismatch Score: {scores_calc.purpose_mismatch_score}/100")
    print(f"  ✓ Malware Probability: {scores_calc.malware_probability}")
    print(f"  ✓ Classification: {scores_calc.anomaly_classification}")

    # 3. Test Adware Weather Evaluation
    print("\n[TEST 3] Testing Over-Privileged Weather ML scoring...")
    meta_weath, static_weath = static_analyzer.analyze("adware_weather")
    dyn_weath = sandbox_runner.run("adware_weather", static_weath)
    scores_weath = mismatch_engine.predict(meta_weath, static_weath, dyn_weath)
    assert isinstance(scores_weath, MLScores)
    assert "android.permission.READ_PHONE_STATE" in scores_weath.unexpected_permissions
    assert scores_weath.purpose_mismatch_score >= 35.0
    assert scores_weath.anomaly_classification == "Suspicious / Over-Privileged"
    print(f"  ✓ Mismatch Score: {scores_weath.purpose_mismatch_score}/100")
    print(f"  ✓ Unexpected Perms: {scores_weath.unexpected_permissions}")
    print(f"  ✓ Classification: {scores_weath.anomaly_classification}")

    # 4. Test Trojan Flashlight Evaluation
    print("\n[TEST 4] Testing Trojan Flashlight ML scoring...")
    meta_trojan, static_trojan = static_analyzer.analyze("trojan_flashlight")
    dyn_trojan = sandbox_runner.run("trojan_flashlight", static_trojan)
    scores_trojan = mismatch_engine.predict(meta_trojan, static_trojan, dyn_trojan)
    assert isinstance(scores_trojan, MLScores)
    assert "android.permission.SEND_SMS" in scores_trojan.unexpected_permissions
    assert "android.permission.READ_CONTACTS" in scores_trojan.unexpected_permissions
    assert scores_trojan.purpose_mismatch_score >= 75.0
    assert scores_trojan.malware_probability >= 0.85
    assert scores_trojan.anomaly_classification == "Malicious / Purpose Mismatch"
    assert len(scores_trojan.top_shap_features) > 0
    print(f"  ✓ Mismatch Score: {scores_trojan.purpose_mismatch_score}/100")
    print(f"  ✓ Malware Probability: {scores_trojan.malware_probability}")
    print(f"  ✓ Top SHAP Driver: {scores_trojan.top_shap_features[0].feature_name} (weight: {scores_trojan.top_shap_features[0].importance_score})")
    print(f"  ✓ Classification: {scores_trojan.anomaly_classification}")

    # 5. Test Model Bootstrap Serialization
    print("\n[TEST 5] Testing bootstrap model serialization...")
    model_meta = mismatch_engine.train_bootstrap_model()
    assert model_meta["synthetic_instances_count"] == 200
    model_path = PROJECT_ROOT / "models" / "mismatch_model.json"
    assert model_path.exists()
    print(f"  ✓ Model successfully saved to {model_path} with 200 synthetic training instances")

    print("\n" + "=" * 60)
    print("[SUCCESS] All Module 4 ML Pipeline tests passed!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run_tests())
