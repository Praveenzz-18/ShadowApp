"""
main.py - ShadowApp FastAPI Orchestration Backend

Wires Modules 1-5 into an asynchronous REST API service:
- POST /api/analyze/apk: Full 4-stage pipeline (Static -> Dynamic -> ML -> Gemini)
- POST /api/analyze/json: Instant evaluation of uploaded or raw telemetry JSON
- GET /api/samples: Lists built-in sample benchmarks
- GET /api/samples/{sample_id}: Fetches pre-computed audit reports
- Static files hosting for Module 7 frontend dashboard
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.llm_explainer import GeminiRiskExplainer
from analyzers.sandbox_runner import DynamicSandboxRunner
from analyzers.static_analyzer import StaticAPKAnalyzer
from ml_engine.mismatch_model import PurposeBehaviorMismatchEngine
from schemas.contracts import (
    AppMetadata,
    DynamicFeatures,
    MLScores,
    ShadowAppReport,
    StaticFeatures,
    validate_report_dict,
)

logger = logging.getLogger("ShadowApp.API")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Initialize analysis singleton engines
static_analyzer = StaticAPKAnalyzer()
sandbox_runner = DynamicSandboxRunner()
mismatch_engine = PurposeBehaviorMismatchEngine()
risk_explainer = GeminiRiskExplainer()

SAMPLE_DATA_DIR = PROJECT_ROOT / "sample_data"
SAMPLE_CATALOG = {
    "benign_calculator": {
        "id": "benign_calculator",
        "name": "Simple Calc Pro",
        "package_name": "com.simpletools.calculator",
        "category": "Tools / Calculator",
        "risk_level": "LOW",
        "file": "benign_calculator.json",
    },
    "adware_weather": {
        "id": "adware_weather",
        "name": "SkyForecast Live HD",
        "package_name": "com.skycast.weather.radar",
        "category": "Weather",
        "risk_level": "MEDIUM",
        "file": "adware_weather.json",
    },
    "trojan_flashlight": {
        "id": "trojan_flashlight",
        "name": "SuperBright Ultra Flashlight",
        "package_name": "com.brightlite.torch.pro",
        "category": "Utilities / Flashlight",
        "risk_level": "CRITICAL",
        "file": "trojan_flashlight.json",
    },
}

# --- Core Analysis Pipeline Helper ---
def run_full_pipeline(
    apk_path_or_name: str,
    stated_description: str = "",
    stated_category: str = "",
    run_dynamic_sandbox: bool = True,
) -> ShadowAppReport:
    """Executes the complete 4-stage analysis pipeline and returns ShadowAppReport."""
    logger.info(f"Starting 4-stage audit on: {apk_path_or_name}")

    # Stage 1: Static APK Analysis (Module 2)
    app_meta, static_feat = static_analyzer.analyze(
        apk_path_or_name,
        stated_description=stated_description,
        stated_category=stated_category,
    )

    # Stage 2: Dynamic Sandbox Execution (Module 3)
    if run_dynamic_sandbox:
        dynamic_feat = sandbox_runner.run(
            package_name=app_meta.package_name,
            static_features=static_feat,
            apk_path=apk_path_or_name if os.path.exists(apk_path_or_name) else None,
            simulation_mode=True,
        )
    else:
        dynamic_feat = DynamicFeatures()

    # Stage 3: Purpose-vs-Behavior ML Mismatch Scoring (Module 4)
    ml_scores = mismatch_engine.predict(app_meta, static_feat, dynamic_feat)

    # Stage 4: Gemini LLM Risk Explanation (Module 5)
    llm_explanation = risk_explainer.explain(app_meta, static_feat, dynamic_feat, ml_scores)

    return ShadowAppReport(
        app_metadata=app_meta,
        static_features=static_feat,
        dynamic_features=dynamic_feat,
        ml_scores=ml_scores,
        llm_explanation=llm_explanation,
    )


# --- FastAPI Application Setup ---
try:
    from fastapi import FastAPI, File, Form, HTTPException, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    app = FastAPI(
        title="ShadowApp API",
        description="Mobile Malware Purpose-vs-Behavior Anomaly Detection Service",
        version="1.0.0",
    )

    # Enable CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health_check() -> Dict[str, str]:
        return {"status": "ok", "service": "ShadowApp FastAPI Backend"}

    @app.get("/api/samples")
    def list_samples() -> List[Dict[str, Any]]:
        """Returns the catalog of pre-configured sample benchmarks."""
        return list(SAMPLE_CATALOG.values())

    @app.get("/api/samples/{sample_id}")
    def get_sample_report(sample_id: str) -> Dict[str, Any]:
        """Loads and returns the pre-computed audit report for a sample benchmark."""
        if sample_id not in SAMPLE_CATALOG:
            raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found")

        filepath = SAMPLE_DATA_DIR / SAMPLE_CATALOG[sample_id]["file"]
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    @app.post("/api/analyze/json")
    def analyze_json_profile(profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Accepts a pre-extracted profile JSON or a sample identifier and runs
        the ML Mismatch Scorer + Gemini Explainer.
        """
        sample_id = profile_data.get("sample_id")
        if sample_id and sample_id in SAMPLE_CATALOG:
            report = run_full_pipeline(sample_id)
            return report.model_dump() if hasattr(report, "model_dump") else report.__dict__

        try:
            # Parse provided profile
            app_meta = AppMetadata.model_validate(profile_data.get("app_metadata", {}))
            static_feat = StaticFeatures.model_validate(profile_data.get("static_features", {}))
            dynamic_feat = DynamicFeatures.model_validate(profile_data.get("dynamic_features", {}))

            ml_scores = mismatch_engine.predict(app_meta, static_feat, dynamic_feat)
            llm_explanation = risk_explainer.explain(app_meta, static_feat, dynamic_feat, ml_scores)

            report = ShadowAppReport(
                app_metadata=app_meta,
                static_features=static_feat,
                dynamic_features=dynamic_feat,
                ml_scores=ml_scores,
                llm_explanation=llm_explanation,
            )
            return report.model_dump() if hasattr(report, "model_dump") else report.__dict__
        except Exception as e:
            logger.error(f"Failed to analyze JSON profile: {e}")
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/analyze/apk")
    async def analyze_apk_upload(
        apk_file: UploadFile = File(...),
        stated_description: str = Form(""),
        stated_category: str = Form(""),
        run_dynamic_sandbox: bool = Form(True),
    ) -> Dict[str, Any]:
        """
        Uploads and processes an Android APK through the 4-stage analysis pipeline.
        """
        suffix = Path(apk_file.filename or "uploaded.apk").suffix or ".apk"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            content = await apk_file.read()
            tmp.write(content)
            tmp_path = Path(tmp.name)

        try:
            report = run_full_pipeline(
                str(tmp_path),
                stated_description=stated_description,
                stated_category=stated_category,
                run_dynamic_sandbox=run_dynamic_sandbox,
            )
            return report.model_dump() if hasattr(report, "model_dump") else report.__dict__
        finally:
            if tmp_path.exists():
                os.unlink(tmp_path)

    # Mount static frontend files if directory exists
    frontend_dir = PROJECT_ROOT / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

except ImportError:
    # Minimal fallback mock application when fastapi is not installed in local shell
    logger.warning("FastAPI not installed in environment. Standalone fallback server initialized.")
    app = None  # type: ignore


# Standalone runner for testing or direct python3 execution
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    host = os.environ.get("HOST", "0.0.0.0")

    if app:
        import uvicorn
        logger.info(f"Launching ShadowApp FastAPI on http://{host}:{port}")
        uvicorn.run("main:app", host=host, port=port, reload=False)
    else:
        print("=" * 60)
        print("ShadowApp Standalone Test Execution")
        print("=" * 60)
        for s_id in SAMPLE_CATALOG:
            rep = run_full_pipeline(s_id)
            print(f"Sample: {s_id}")
            print(f"  App: {rep.app_metadata.app_name}")
            print(f"  Mismatch: {rep.ml_scores.purpose_mismatch_score}/100")
            print(f"  Malware Prob: {rep.ml_scores.malware_probability:.2f}")
            print(f"  Risk: {rep.llm_explanation.overall_risk_level if rep.llm_explanation else 'N/A'}")
            print("-" * 50)
