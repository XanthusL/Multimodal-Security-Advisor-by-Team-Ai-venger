# Multimodal-Security-Advisor-by-Team-Ai-venger

A prototype AI-assisted decision support system for security officers, designed around Singapore's regulatory framework. It fuses video, audio, access control logs, and terminal output into threat assessments with step-by-step SOP recommendations — while keeping a human officer in the loop for high-stakes decisions.

> **Disclaimer:** This system is a decision support tool, not an autonomous decision-maker. All recommendations must be reviewed by a qualified Security Manager. Outputs are not legal advice and do not substitute for site-specific SOPs or the judgement of licensed security professionals.

---

## What It Does

- **Multimodal signal fusion** — combines CCTV frames, audio recordings, access control logs, and terminal/system output into a single threat picture
- **Threat classification** — rates incidents as LOW / MEDIUM / HIGH / CRITICAL with confidence scores and alternative scenarios
- **SOP generation** — produces numbered, officer-ready action steps calibrated to Singapore regulations (PSIA, GEBSS, SPF Advisories)
- **Proportionality rationale** — explains *why* a given response level is appropriate, not just *what* to do
- **Human approval gates** — flags CRITICAL and HIGH incidents that require human sign-off before officers advance
- **Sensor attack detection** — identifies patterns consistent with camera obstruction, replay attacks, or coordinated system interference
- **Terminal log analysis** — parses raw system/access logs to extract structured security events without manual review

---

## Architecture

```
Frontend (certis_security_advisor1.html)
        │
        │  REST (JSON)
        ▼
  Flask Server (server.py)
        │
        ├── video_analysis_pipeline.py  ←  Ollama vision model (e.g. llava)
        ├── audio_analysis_pipeline.py  ←  Whisper + librosa
        ├── multimodal_pipeline.py      ←  Signal fusion & officer briefing
        └── security_agent.py           ←  Threat logic, SOP, proportionality
                │
                └── models.py           ←  Shared Pydantic types
```

### Key data types (`models.py`)

| Type | Purpose |
|---|---|
| `Signal` | A single sensor event (type, confidence, location, timestamp) |
| `SecurityContext` | Zone metadata (security level, time of day, authorised personnel) |
| `IncidentReport` | Full output: threat level, signals analysed, timeline, recommendation |
| `Recommendation` | SOP steps, urgency, visual cue, proportionality rationale, guideline reference |
| `ThreatLevel` | `low` / `medium` / `high` / `critical` |

---

## API Endpoints

### `POST /analyze`
Multimodal analysis: accepts video frames, audio, and access logs.

**Request body**

| Field | Type | Description |
|---|---|---|
| `frames` | `string[]` | Base64-encoded JPEG frames |
| `audBase64` | `string` | Base64-encoded WAV file |
| `audDesc` | `string` | Plain-text audio description (fallback if no file) |
| `logs` | `object[]` | Structured access/sensor log entries |
| `zone` | `string` | Zone identifier (e.g. `"SERVER_ROOM_3"`) |
| `ctx` | `string` | Free-text context notes for the officer |

**Response** — JSON with `threat_level`, `confidence`, `sop_steps`, `officer_briefing`, `requires_human_approval`, and fusion diagnostics.

---

### `POST /analyze-terminal`
Parses raw terminal or system log text and extracts security events automatically.

**Request body**

| Field | Type | Description |
|---|---|---|
| `terminal_text` | `string` | Raw log/terminal output |
| `zone` | `string` | Zone identifier |
| `ctx` | `string` | Context notes |

**Response** — same shape as `/analyze`, plus `parsed_events` and `terminal_lines_analyzed`.

---

### `GET /health`
Returns server status and whether Ollama is running.

---

## Threat Levels & Response Logic

| Level | Colour | Typical triggers | Human approval required? |
|---|---|---|---|
| CRITICAL | 🔴 RED | Gunshot, explosion, fire, arson | Yes |
| HIGH | 🟠 (urgent) | Forced entry, panic call, unauthorised access | Yes |
| MEDIUM | 🟡 YELLOW | Loitering, failed badge, after-hours motion | Recommended |
| LOW | 🟢 GREEN | Routine activity, single motion in low-security zone | No |

Signal fusion rules (excerpt):
- Gunshot or explosion → always CRITICAL, overrides all other signals
- Panic call or forced entry → always HIGH
- Motion-only in high-security zone, corroborated by ≥3 sensors → HIGH
- Motion-only in low-security zone, no corroborating evidence → LOW
- Camera obstruction + abnormal credential activity → HIGH (police notification justified before on-site confirmation)

---

## Installation

### Requirements

- Python 3.10+
- [Ollama](https://ollama.com) with a vision model pulled (e.g. `llava`)
- Audio dependencies: `librosa`, `openai-whisper`, `soundfile`

```bash
pip install flask flask-cors pydantic librosa openai-whisper soundfile
```

### Start Ollama

```bash
ollama serve
ollama pull llava
```

### Run the server

```bash
python server.py
```

Server starts on `http://localhost:5000`.

### Open the frontend

Open `certis_security_advisor1.html` directly in a browser. It connects to the local Flask server.

---

## Scenarios

See [`scenarios.md`](scenarios.md) for six fully worked example incidents with inputs, key indicators, recommended SOP steps, proportionality rationale, and Singapore regulatory references:

1. Gunshot detected → CRITICAL
2. Intrusion sequence (failed badge → forced door → interior motion) → HIGH
3. Loitering / suspicious behaviour → MEDIUM
4. Panic call → HIGH
5. Camera obstruction + credential anomaly → HIGH
6. Normal / routine activity → LOW

---

## Regulatory Basis

Recommendations are grounded in the following publicly available Singapore documents:

| Document | Issuing body |
|---|---|
| Contingency Planning and Protective Security Advisories for Workplaces (Apr 2022) | SPF / MHA |
| VSS Standard for Buildings | SPF CPS |
| Guidelines for Enhancing Building Security in Singapore (GEBSS) | MHA / SPF CPS |
| Private Security Industry Act (PSIA) | AGC Singapore |
| PLRD SACE Elective Competencies Checklist (Oct 2024) | SPF PLRD |
| WSQ Guard and Patrol / Access Control Management (SEC-SOP-1007-1.1) | SkillsFuture |
| WSH Guidelines for the Private Security Industry | WSH Council / SAS |
| SCDF Emergency Response Plan Guidelines | SCDF |

Full source URLs are listed in [`scenarios.md`](scenarios.md#source-index).

---

## Limitations & Intended Use

- This is a **prototype** built for evaluation and demonstration purposes.
- Video analysis requires Ollama running locally — if unavailable, video signals are skipped and fusion proceeds on audio and logs only.
- Audio description fallback (text instead of WAV) provides reduced accuracy; use actual audio files where possible.
- The system does not retain state between requests; each call is independently assessed.
- All high-stakes actions (police calls, lockdowns, officer dispatch into potentially dangerous zones) require human confirmation — the system will not trigger them autonomously.

---

## Project Structure

```
.
├── server.py                    # Flask API server
├── security_agent.py            # Threat assessment, SOP, proportionality logic
├── models.py                    # Pydantic data models
├── video_analysis_pipeline.py   # Ollama vision analysis
├── audio_analysis_pipeline.py   # Whisper + librosa audio analysis
├── multimodal_pipeline.py       # Signal fusion and officer briefing
├── certis_security_advisor1.html  # Browser-based officer UI
└── scenarios.md                 # Reference scenario library
```
