import os
import time
import json
import re

import requests


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))
OLLAMA_RETRIES = int(os.getenv("OLLAMA_RETRIES", "2"))
LLM_HISTORY_WINDOW = int(os.getenv("LLM_HISTORY_WINDOW", "5"))


def _extract_scene_context(event_text: str):
    scene = "unknown"
    period = "unknown"
    light = "unknown"

    match = re.search(r"Context:\s*([^|]+)", event_text)
    if match:
        parts = [p.strip().lower() for p in match.group(1).split(",")]
        if len(parts) > 0:
            scene = parts[0]
        if len(parts) > 1:
            period = parts[1]
        if len(parts) > 2:
            light = parts[2]

    return scene, period, light


def _format_explainable_result(raw: str) -> str:
    """Return deterministic explainable output even when model returns plain text."""
    try:
        parsed = json.loads(raw)
        risk = str(parsed.get("risk", "MEDIUM")).upper()
        reason = parsed.get("reason", "Risk inferred from detected activity.")
        pattern = parsed.get("pattern", "No clear long-term suspicious pattern.")
        action = parsed.get("action", "Continue monitoring.")
        return (
            f"Risk: {risk}\n"
            f"Reason: {reason}\n"
            f"Pattern: {pattern}\n"
            f"Recommended Action: {action}"
        )
    except Exception:
        return (
            "Risk: MEDIUM\n"
            f"Reason: {raw.strip()}\n"
            "Pattern: Insufficient structured pattern details from model response.\n"
            "Recommended Action: Continue monitoring and collect more sequence data."
        )


def analyze_event(text, event_history=None):
    history = event_history or []
    scene, period, light = _extract_scene_context(text)
    recent_history = history[-LLM_HISTORY_WINDOW:] if history else []
    history_block = "\n".join(recent_history) if recent_history else "No recent history."

    prompt = (
        "You are a CCTV reasoning assistant for security triage.\n"
        "Use temporal sequence and context to estimate suspicious behavior.\n"
        "Return ONLY JSON with keys: risk, reason, pattern, action.\n"
        "Risk must be one of LOW, MEDIUM, HIGH, CRITICAL.\n\n"
        "Context:\n"
        f"- scene: {scene}\n"
        f"- time_of_day: {period}\n"
        f"- lighting: {light}\n\n"
        "Recent event sequence (oldest -> newest):\n"
        f"{history_block}\n\n"
        "Current event:\n"
        f"{text}\n\n"
        "Now infer risk with concise explanation and behavior pattern signal."
    )

    last_error = None
    for attempt in range(OLLAMA_RETRIES + 1):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=(5, OLLAMA_TIMEOUT_SECONDS),
            )
            response.raise_for_status()
            payload = response.json()
            raw = payload.get("response", "No response from model").strip()
            return _format_explainable_result(raw)
        except Exception as exc:
            last_error = exc
            if attempt < OLLAMA_RETRIES:
                time.sleep(1.5)

    return f"LLM unavailable: {last_error}"
