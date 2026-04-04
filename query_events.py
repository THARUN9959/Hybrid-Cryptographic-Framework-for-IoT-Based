import argparse
import glob
import os
import time
from typing import List, Dict

import requests


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "tinyllama")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "90"))


def read_event_files(base_dir: str, lookback_minutes: int) -> List[Dict[str, str]]:
    now = time.time()
    cutoff = now - (lookback_minutes * 60)
    events = []

    for path in sorted(glob.glob(os.path.join(base_dir, "*.txt"))):
        try:
            mtime = os.path.getmtime(path)
            if mtime < cutoff:
                continue

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()

            if not content:
                continue

            events.append(
                {
                    "file": os.path.basename(path),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)),
                    "content": content,
                }
            )
        except OSError:
            continue

    return events


def call_ollama(query: str, events: List[Dict[str, str]]) -> str:
    if not events:
        return "No events found in the requested time window."

    event_lines = []
    for idx, event in enumerate(events, start=1):
        event_lines.append(
            f"[{idx}] {event['timestamp']} | {event['file']}\n{event['content']}"
        )
    events_block = "\n\n".join(event_lines)

    prompt = (
        "You are a CCTV event query assistant. "
        "Answer user query using only provided events.\n\n"
        f"User query: {query}\n\n"
        "Events:\n"
        f"{events_block}\n\n"
        "Return concise answer with:\n"
        "1) direct answer\n"
        "2) suspicious event count\n"
        "3) key evidence timestamps/files"
    )

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
    return payload.get("response", "No response from model").strip()


def fallback_query(query: str, events: List[Dict[str, str]]) -> str:
    if not events:
        return "No events found in the requested time window."

    keywords = [w.lower() for w in query.split() if len(w) > 2]
    matched = []
    for event in events:
        text = event["content"].lower()
        if any(word in text for word in keywords):
            matched.append(event)

    if not matched:
        return f"No matching events found for query: {query}"

    lines = [f"Matched {len(matched)} events:"]
    for event in matched[:10]:
        lines.append(f"- {event['timestamp']} | {event['file']}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Query CCTV event logs using natural language")
    parser.add_argument("query", help="Natural language query, e.g. 'show suspicious events from last 10 minutes'")
    parser.add_argument("--minutes", type=int, default=10, help="Lookback window in minutes (default: 10)")
    parser.add_argument("--dir", default="shared/decrypted", help="Directory containing decrypted event files")
    args = parser.parse_args()

    events = read_event_files(args.dir, args.minutes)

    print(f"Loaded {len(events)} events from last {args.minutes} minutes.")

    try:
        answer = call_ollama(args.query, events)
        print("\n=== Query Answer (LLM) ===")
        print(answer)
    except Exception as exc:
        print(f"\nLLM unavailable ({exc}). Using keyword fallback.")
        print("\n=== Query Answer (Fallback) ===")
        print(fallback_query(args.query, events))


if __name__ == "__main__":
    main()
