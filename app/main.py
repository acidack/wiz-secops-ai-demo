"""Cymbal Bank AI Assistant — Wiz + Google SecOps + Model Armor + CodeMender Demo App.

WARNING: Intentionally contains realistic security vulnerabilities (OS Command Injection,
Path Traversal, SQL Injection) strictly for demonstrating Wiz Code, Wiz Defend Runtime
Sensor, Google Cloud Model Armor, Google SecOps correlation, and CodeMender auto-remediation
in an isolated sandbox environment. Do NOT deploy to production.
"""
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import google.auth
import google.auth.transport.requests
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# Structured JSON logging for Google Cloud Logging -> Google SecOps ingestion
class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "pod_name": os.getenv("HOSTNAME", socket.gethostname()),
            "app": "wiz-ai-chat-demo",
        }
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            payload.update(record.extra_data)
        return json.dumps(payload)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger = logging.getLogger("cymbal_ai_demo")
logger.setLevel(logging.INFO)
logger.handlers = [handler]

GCP_PROJECT = os.getenv("GCP_PROJECT", "sumitpatel-wiz-ai-demo")
GCP_LOCATION = os.getenv("GCP_LOCATION", "us-central1")
MODEL_ARMOR_TEMPLATE = os.getenv(
    "MODEL_ARMOR_TEMPLATE",
    f"projects/{GCP_PROJECT}/locations/{GCP_LOCATION}/templates/wiz_demo_model_armor",
)
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
GEMINI_LOCATION = os.getenv("GEMINI_LOCATION", "global")

BASE_DIR = Path(__file__).resolve().parent
KB_DIR = BASE_DIR / "kb_docs"

app = FastAPI(title="Cymbal Bank AI Security Demo (Wiz + Model Armor + SecOps)")


def init_demo_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE tickets (id INTEGER PRIMARY KEY, customer TEXT, subject TEXT, status TEXT, notes TEXT)"
    )
    cur.executemany(
        "INSERT INTO tickets (customer, subject, status, notes) VALUES (?, ?, ?, ?)",
        [
            ("alice@cymbalbank.example", "Wire transfer limit increase", "OPEN", "Standard tier review"),
            ("bob@cymbalbank.example", "Card replacement request", "RESOLVED", "Dispatched via courier"),
            ("carol@cymbalbank.example", "Mobile app MFA reset", "OPEN", "Pending identity verification"),
            ("castor.troy@cymbalbank.example", "Suspicious API token activity", "ESCALATED", "Flagged by SOC"),
        ],
    )
    conn.commit()
    return conn


DB_CONN = init_demo_db()


def get_gcp_access_token() -> str:
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)
    return creds.token


def call_model_armor(text: str, mode: str = "prompt", correlation_id: str = "") -> dict:
    """Screen a prompt or model response using Google Cloud Model Armor."""
    endpoint = "sanitizeUserPrompt" if mode == "prompt" else "sanitizeModelResponse"
    url = f"https://modelarmor.{GCP_LOCATION}.rep.googleapis.com/v1/{MODEL_ARMOR_TEMPLATE}:{endpoint}"
    token = get_gcp_access_token()
    body = {"userPromptData": {"text": text}} if mode == "prompt" else {"modelResponseData": {"text": text}}
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Goog-User-Project": GCP_PROJECT,
    }
    if correlation_id:
        headers["X-Client-Correlation-Id"] = correlation_id
    resp = requests.post(url, headers=headers, json=body, timeout=15)
    if resp.status_code != 200:
        raise RuntimeError(f"Model Armor HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    san = data.get("sanitizationResult", {})
    match_state = san.get("filterMatchState", "NO_MATCH_FOUND")
    filter_results = san.get("filterResults", {})
    matched_filters = []
    for fname, fobj in filter_results.items():
        if not isinstance(fobj, dict):
            continue
        for sub_key, sub_val in fobj.items():
            if isinstance(sub_val, dict):
                ms = sub_val.get("matchState") or sub_val.get("inspectResult", {}).get("matchState")
                if ms == "MATCH_FOUND":
                    matched_filters.append(fname)
    return {
        "blocked": match_state == "MATCH_FOUND",
        "match_state": match_state,
        "matched_filters": matched_filters,
        "raw": san,
    }


def call_vertex_gemini(prompt: str) -> tuple[str, str]:
    """Call Vertex AI Gemini using GKE Workload Identity / ADC."""
    token = get_gcp_access_token()
    host = "aiplatform.googleapis.com" if GEMINI_LOCATION == "global" else f"{GEMINI_LOCATION}-aiplatform.googleapis.com"
    models_to_try = [GEMINI_MODEL, "gemini-3.5-flash", "gemini-3-flash-preview"]
    last_err = ""
    for model_name in models_to_try:
        url = (
            f"https://{host}/v1/projects/{GCP_PROJECT}"
            f"/locations/{GEMINI_LOCATION}/publishers/google/models/{model_name}:generateContent"
        )
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "You are the Cymbal Bank AI Support Assistant. Answer concisely and helpfully "
                                "about banking support topics without inventing confidential customer data.\n\n"
                                f"Customer message: {prompt}"
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
        }
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
            timeout=25,
        )
        if resp.status_code == 200:
            data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                used_model = data.get("modelVersion", model_name)
                return "".join(p.get("text", "") for p in parts), used_model
        last_err = f"{model_name} HTTP {resp.status_code}: {resp.text[:200]}"
    raise RuntimeError(f"Vertex AI Gemini call failed: {last_err}")


ARMOR_LOGS: deque = deque(maxlen=100)


def record_armor_log(
    *,
    correlation_id: str,
    user_id: str,
    source_ip: str,
    prompt_preview: str,
    attachment_name: Optional[str],
    model_armor_enabled: bool,
    blocked: bool,
    model: str,
    latency_ms: int,
    prompt_armor: dict,
    response_armor: dict,
) -> dict:
    matched = sorted(
        set(prompt_armor.get("matched_filters", []) + response_armor.get("matched_filters", []))
    )
    if not model_armor_enabled:
        verdict = "BYPASSED"
    elif blocked:
        verdict = "BLOCKED"
    else:
        verdict = "ALLOWED"
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "correlation_id": correlation_id,
        "user_id": user_id,
        "source_ip": source_ip,
        "prompt_preview": prompt_preview[:180],
        "attachment_name": attachment_name,
        "model_armor_enabled": model_armor_enabled,
        "verdict": verdict,
        "matched_filters": matched,
        "model": model,
        "latency_ms": latency_ms,
        "prompt_match_state": prompt_armor.get("match_state", "UNKNOWN"),
        "response_match_state": response_armor.get("match_state", "UNKNOWN"),
        "prompt_armor": prompt_armor,
        "response_armor": response_armor,
    }
    ARMOR_LOGS.appendleft(entry)
    return entry


class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = "castor.troy@cymbalbank.example"
    enable_model_armor: Optional[bool] = True
    correlation_id: Optional[str] = None
    attachment_name: Optional[str] = None
    attachment_content: Optional[str] = None


class PingRequest(BaseModel):
    host: str = "8.8.8.8"
    user_id: Optional[str] = "castor.troy@cymbalbank.example"


@app.get("/", response_class=HTMLResponse)
def index():
    html_path = BASE_DIR / "static" / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/healthz")
def healthz():
    return {
        "status": "ok",
        "project": GCP_PROJECT,
        "location": GCP_LOCATION,
        "gemini_model": GEMINI_MODEL,
        "gemini_location": GEMINI_LOCATION,
        "model_armor_template": MODEL_ARMOR_TEMPLATE,
        "pod": os.getenv("HOSTNAME", socket.gethostname()),
    }


@app.get("/api/armor-logs")
def get_armor_logs():
    return {
        "template": MODEL_ARMOR_TEMPLATE,
        "model": GEMINI_MODEL,
        "logs": list(ARMOR_LOGS),
    }


@app.delete("/api/armor-logs")
def clear_armor_logs():
    ARMOR_LOGS.clear()
    return {"cleared": True}


@app.post("/api/chat")
def chat(req: ChatRequest, request: Request):
    started = time.perf_counter()
    corr_id = req.correlation_id or f"demo-{uuid.uuid4().hex[:10]}"
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")

    attachment_text = req.attachment_content
    if req.attachment_name and not attachment_text:
        candidate = (KB_DIR / Path(req.attachment_name).name).resolve()
        if candidate.is_file() and candidate.parent == KB_DIR.resolve():
            attachment_text = candidate.read_text(encoding="utf-8", errors="replace")[:4000]

    effective_prompt = req.message
    if req.attachment_name and attachment_text:
        effective_prompt = (
            f"{req.message}\n\n"
            f"[Attached Workspace Document: {req.attachment_name}]\n"
            f"{attachment_text}"
        )

    prompt_armor = {"blocked": False, "match_state": "BYPASSED", "matched_filters": []}
    response_armor = {"blocked": False, "match_state": "BYPASSED", "matched_filters": []}

    if req.enable_model_armor:
        try:
            prompt_armor = call_model_armor(effective_prompt, mode="prompt", correlation_id=corr_id)
        except Exception as exc:
            logger.error(
                "Model Armor prompt check error",
                extra={"extra_data": {"event_type": "MODEL_ARMOR_ERROR", "error": str(exc), "correlation_id": corr_id}},
            )
            prompt_armor = {"blocked": False, "match_state": "ERROR", "matched_filters": [], "error": str(exc)}

        if prompt_armor["blocked"]:
            latency_ms = int((time.perf_counter() - started) * 1000)
            logger.warning(
                "Model Armor blocked malicious user prompt",
                extra={
                    "extra_data": {
                        "event_type": "AI_PROMPT_BLOCKED",
                        "user_id": req.user_id,
                        "source_ip": client_ip,
                        "correlation_id": corr_id,
                        "attachment_name": req.attachment_name,
                        "matched_filters": prompt_armor["matched_filters"],
                        "action": "BLOCK",
                    }
                },
            )
            record_armor_log(
                correlation_id=corr_id,
                user_id=req.user_id or "anonymous",
                source_ip=client_ip,
                prompt_preview=req.message,
                attachment_name=req.attachment_name,
                model_armor_enabled=True,
                blocked=True,
                model=GEMINI_MODEL,
                latency_ms=latency_ms,
                prompt_armor=prompt_armor,
                response_armor=response_armor,
            )
            reply_msg = (
                "I wasn't able to process that attachment — Google Cloud Model Armor detected and blocked a policy violation."
                if req.attachment_name
                else "Blocked by Google Cloud Model Armor: Prompt violated AI security policy."
            )
            return JSONResponse(
                {
                    "blocked": True,
                    "model": GEMINI_MODEL,
                    "reply": reply_msg,
                    "correlation_id": corr_id,
                    "latency_ms": latency_ms,
                    "attachment_name": req.attachment_name,
                    "prompt_armor": prompt_armor,
                    "response_armor": response_armor,
                }
            )

    try:
        reply, used_model = call_vertex_gemini(effective_prompt)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    if req.enable_model_armor:
        try:
            response_armor = call_model_armor(reply, mode="response", correlation_id=corr_id)
            if response_armor["blocked"]:
                reply = "Blocked by Google Cloud Model Armor: Model response violated safety/DLP policy."
        except Exception as exc:
            response_armor = {"blocked": False, "match_state": "ERROR", "matched_filters": [], "error": str(exc)}

    latency_ms = int((time.perf_counter() - started) * 1000)
    is_blocked = bool(response_armor.get("blocked"))
    record_armor_log(
        correlation_id=corr_id,
        user_id=req.user_id or "anonymous",
        source_ip=client_ip,
        prompt_preview=req.message,
        attachment_name=req.attachment_name,
        model_armor_enabled=bool(req.enable_model_armor),
        blocked=is_blocked,
        model=used_model,
        latency_ms=latency_ms,
        prompt_armor=prompt_armor,
        response_armor=response_armor,
    )

    logger.info(
        "AI chat completed",
        extra={
            "extra_data": {
                "event_type": "AI_CHAT_ALLOWED",
                "user_id": req.user_id,
                "source_ip": client_ip,
                "correlation_id": corr_id,
                "attachment_name": req.attachment_name,
                "model": used_model,
                "model_armor_enabled": req.enable_model_armor,
                "prompt_match_state": prompt_armor["match_state"],
                "response_match_state": response_armor["match_state"],
            }
        },
    )
    return {
        "blocked": is_blocked,
        "model": used_model,
        "reply": reply,
        "correlation_id": corr_id,
        "latency_ms": latency_ms,
        "attachment_name": req.attachment_name,
        "prompt_armor": prompt_armor,
        "response_armor": response_armor,
    }


@app.post("/api/diagnostics/ping")
def diagnostics_ping(req: PingRequest, request: Request):
    """INTENTIONAL DEMO VULNERABILITY (CWE-78: OS Command Injection).

    Used to demonstrate:
      1. Wiz Code SAST/Code-to-Cloud detection
      2. CodeMender autonomous verification & remediation PR
      3. Wiz Defend Runtime Sensor live container threat detection
    """
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    logger.warning(
        "Diagnostics ping invoked",
        extra={
            "extra_data": {
                "event_type": "DIAGNOSTICS_PING",
                "user_id": req.user_id,
                "source_ip": client_ip,
                "target_host": req.host,
            }
        },
    )
    try:
        # VULNERABLE: unsanitized user input passed directly to shell=True
        output = subprocess.check_output(
            f"ping -c 1 {req.host}",
            shell=True,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=8,
        )
        return {"ok": True, "host": req.host, "output": output}
    except subprocess.CalledProcessError as exc:
        return {"ok": False, "host": req.host, "output": exc.output}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/kb/document")
def read_kb_document(name: str = "welcome.txt"):
    """INTENTIONAL DEMO VULNERABILITY (CWE-22: Path Traversal)."""
    # VULNERABLE: unsanitized path join allows reading arbitrary files via ../
    target_path = os.path.join(str(KB_DIR), name)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Document not found")
    with open(target_path, "r", encoding="utf-8", errors="replace") as fh:
        return {"name": name, "content": fh.read(4096)}


@app.get("/api/tickets/search")
def search_tickets(q: str = ""):
    """INTENTIONAL DEMO VULNERABILITY (CWE-89: SQL Injection)."""
    cur = DB_CONN.cursor()
    # VULNERABLE: direct string interpolation into SQL query
    query = f"SELECT id, customer, subject, status, notes FROM tickets WHERE subject LIKE '%{q}%'"
    try:
        rows = cur.execute(query).fetchall()
    except sqlite3.Error as exc:
        raise HTTPException(status_code=400, detail=f"Database error: {exc}")
    return {
        "query": q,
        "results": [
            {"id": r[0], "customer": r[1], "subject": r[2], "status": r[3], "notes": r[4]}
            for r in rows
        ],
    }
