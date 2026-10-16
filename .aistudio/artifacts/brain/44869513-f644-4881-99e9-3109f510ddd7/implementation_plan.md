# ShadowApp: Purpose-vs-Behavior Mobile Malware Detection Platform

ShadowApp identifies deceptive and malicious Android applications by detecting mismatches between an application's declared purpose (Play Store description, stated category) and its actual static/dynamic capabilities (requested permissions, exported components, Dalvik API calls, network traffic).

***

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural decisions were confirmed during the Phase 1 consultation:

- **Confirmed Decision 1 (Runtime Architecture)**: Pure Python FastAPI backend running with Uvicorn, serving the interactive static HTML/Tailwind/JavaScript dashboard directly on port 3000 to comply with AI Studio container requirements.
- **Confirmed Decision 2 (Implementation Pacing)**: Step-by-step execution module-by-module. We will build, verify, and lock **Module 1 (Contracts, Schemas & Realistic Mock Benchmarks)** first before initiating downstream modules.
- **Confirmed Decision 3 (Input & Demonstration Modes)**: The platform will support both direct `.apk` file uploads (with client-side/server-side parsing) and one-click preloaded benchmark profiles (`benign_calculator.json`, `adware_weather.json`, and `trojan_flashlight.json`).
- **Python Environment & Dev Server**: Fast-start `uvicorn` runner configured in `package.json` to bridge AI Studio's dev runner cleanly on port 3000 while maintaining seamless Python 3 execution.

***

## 1. Overview & Core Concept

- **What It Does**: Inspects Android APKs and behavioral telemetry to evaluate whether an app asks for permissions or invokes APIs that contradict its stated domain (e.g., a flashlight requiring SMS/Telephony access and contacting external C2 servers). It scores behavioral anomalies using machine learning heuristics and generates plain-language, evidence-backed security explanations via Gemini Structured Outputs.
- **Target Audience**: Mobile security researchers, app store review analysts, enterprise security teams, and end users auditing suspicious APKs.
- **Key Value**: Replaces black-box signature detection with semantic purpose-behavior alignment inspired by CHABADA and Drebin, making covert trojans and over-privileged adware immediately transparent.

***

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Inspection Selection**: The user either drops an Android `.apk` file or selects a pre-configured scenario button:
     - *Benign Calculator*: Offline utility requesting zero dangerous permissions.
     - *Over-Privileged Adware*: Weather app extracting continuous background GPS and phone identifiers for ad-trackers.
     - *Trojanized Flashlight*: Covert spyware reading contacts and dispatching premium SMS messages.
  2. **Pipeline Execution**: The dashboard displays real-time progression through the 4-stage pipeline: Static Extraction $\rightarrow$ Dynamic Sandbox Simulation $\rightarrow$ Semantic Mismatch Scoring $\rightarrow$ Gemini Security Analysis.
  3. **Multi-Faceted Report View**:
     - **Purpose-vs-Behavior Mismatch Gauge** ($0\text{–}100$) and **Malware Probability (%)**.
     - **Expected vs. Actual Permissions Matrix**: Clean tabular comparison highlighting unexpected permissions in crimson.
     - **AI Security Analyst Report**: Structured executive summary, specific purpose-behavior contradictions, privacy risks, and actionable remediation steps.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: High-density SOC / Threat-Intelligence workstation aesthetic using refined cool slate neutrals (`#0B0F19`, `#111827`, `#1F2937`) with sharp crimson (`#EF4444`) for malicious indicators, amber (`#F59E0B`) for warnings, and emerald (`#10B981`) for nominal states.
  - *Typography*: Clean sans typography (`Plus Jakarta Sans` / `DM Sans`) paired with monospace tabular numerals (`JetBrains Mono` / `tabular-nums`) for package names, cryptographic hashes, permission keys, and scores.
  - *Anti-Slop Discipline*: Zero static pill enclosures on metadata; unboxed inline text with typographic dot separators (`·`); single-elevation depth with 1px border lines; strictly no hallucinated cocktail scoreboards or decorative pulsing dots.
  - *Top Bar Contract*: 1-row layout with brand wordmark (`ShadowApp`), clean navigation links (`Overview`, `Telemetry Benchmarks`, `API Docs`), and 1 primary CTA button (`Analyze APK`).

***

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: 7-Module Incremental Construction**:
  - *Chosen Approach*: Deliver **Module 1** first: `requirements.txt`, `.env.example`, `schemas/contracts.py` (Pydantic v2 data models), and 3 full benchmark JSON files in `sample_data/`.
  - *Why*: Allows immediate unit testing of data validation, pipeline contracts, and model serialization before compiling analyzers or training ML engines.
- **Decision 2: Python Backend with Port 3000 Serving**:
  - *Chosen Approach*: FastAPI running on `0.0.0.0:3000` with static files mounted at root (`/`) for the single-page security dashboard, combined with `/api/analyze/*` and `/api/samples` endpoints.
  - *Why*: Perfectly integrates with AI Studio's dev server port expectations while executing the requested Python FastAPI backend.
- **Decision 3: Gemini Structured Outputs Integration**:
  - *Chosen Approach*: Use the official `google-genai` Python SDK with `response_mime_type="application/json"` and Pydantic schema validation for deterministic security analyst reporting.
  - *Why*: Eliminates markdown parsing errors and guarantees schema conformance across all security risk dimensions.

***

## 4. Technical Architecture & Data Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      ShadowApp Web Interface (Port 3000)                    │
│      [APK File Upload]   [Play Store Purpose]   [Quick-Load Benchmarks]     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP POST /api/analyze/apk or /json
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FastAPI Backend Service                            │
│                                                                             │
│  ┌───────────────────────┐                    ┌──────────────────────────┐  │
│  │ Static APK Analyzer   │                    │ Dynamic Sandbox Runner   │  │
│  │ (Androguard + DEX)    │                    │ (Frida Hooks + MITM /    │  │
│  │ Module 2              │                    │  Simulation Mode) Mod 3  │  │
│  └───────────┬───────────┘                    └────────────┬─────────────┘  │
│              │ StaticFeatures                              │ DynamicFeatures│
│              └───────────────────────┬─────────────────────┘                │
│                                      ▼                                      │
│              ┌──────────────────────────────────────────────┐               │
│              │       Purpose-vs-Behavior Mismatch Engine     │               │
│              │   (Gemini Embeddings + Isolation Forest +    │               │
│              │       Expected Permissions Multi-Label)      │               │
│              │                   Module 4                   │               │
│              └───────────────────────┬──────────────────────┘               │
│                                      │ MLScores                             │
│                                      ▼                                      │
│              ┌──────────────────────────────────────────────┐               │
│              │          Gemini LLM Risk Explainer           │               │
│              │ (Structured Outputs via google-genai SDK)    │               │
│              │                   Module 5                   │               │
│              └───────────────────────┬──────────────────────┘               │
│                                      │ LLMExplanation                       │
│                                      ▼                                      │
│              ┌──────────────────────────────────────────────┐               │
│              │          Final ShadowAppReport (JSON)        │               │
│              │          schemas/contracts.py (Module 1)     │               │
│              └──────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Module 1 Delivery Scope (Immediate Step)
1. **`requirements.txt`**: Complete Python package definitions (`fastapi`, `uvicorn`, `pydantic>=2.0`, `google-genai`, `scikit-learn`, `joblib`, `numpy`, `androguard`, `python-multipart`).
2. **`.env.example`**: Specifying `GEMINI_API_KEY` and server environment variables.
3. **`schemas/contracts.py`**: Robust, type-safe Pydantic v2 schemas:
   - `AppMetadata`: Package name, app label, stated category, Play Store description, UI strings.
   - `StaticFeatures`: Requested permissions, dangerous permissions, exported components, suspicious Dalvik API invocations, hardcoded URLs/IPs.
   - `DynamicFeatures`: Runtime API invocations, network connections, file system modifications, SSL pinning bypass status, dynamic DEX class loading.
   - `MLScores`: Malware probability, purpose mismatch score ($0\text{–}100$), expected vs. unexpected permissions list, top behavioral feature drivers.
   - `LLMExplanation`: Overall risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), executive summary, purpose-behavior contradictions, privacy risks, and recommended actions.
   - `ShadowAppReport`: Master aggregated report contract.
4. **`sample_data/` Telemetry Benchmarks**:
   - `benign_calculator.json`: Validated clean benchmark.
   - `adware_weather.json`: Validated over-privileged adware benchmark.
   - `trojan_flashlight.json`: Validated stealth spyware benchmark.
5. **Execution Verification**: Validation script to parse and assert all three JSON samples against the Pydantic schema.
