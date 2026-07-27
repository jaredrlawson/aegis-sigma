#!/usr/bin/env python3
"""
AEGIS-SIGMA Teacher Labeler — labels uncertain traffic via LLM API.
Reads teacher_labels.ndjson from C engine, sends to LLM for labels,
writes results to local SQLite database.

Runs via cron. Configure via .env or environment variables.
"""
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error

# Config from environment — no hardcoded paths
BRAIN_DB = os.environ.get("BRAIN_DB", "brain.sqlite")
NDJSON_PATH = os.environ.get("NDJSON_PATH", "/tmp/teacher_labels.ndjson")
LLM_URL = os.environ.get("LLM_URL", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")
LLM_KEY = os.environ.get("LLM_KEY", "")

SYSTEM_PROMPT = """You are a network security classifier. Given HTTP request features,
classify the request as BENIGN (real user) or HOSTILE (attack/bot).

Respond with ONLY a JSON object:
{"verdict": "BENIGN" or "HOSTILE", "confidence": 0.0-1.0, "reasoning": "one line"}

Features are a 30-dim float vector:
[ttl_norm, window_norm, mss_norm, ua_script_score, ua_len_norm, has_referer,
 path_score, path_len_norm, is_sensitive, geo_risk, has_country, asn_risk,
 timing_risk, severity_binary, timing_baseline, prior_strikes_norm,
 has_evidence, evidence_len_norm, has_fingerprint, harmonic_score,
 ja3_risk, tls_cipher_risk, header_anomaly, lang_risk,
 hour_sin, hour_cos, day_sin, day_cos, volume_coherence, phi_divergence]"""


def get_api_key():
    """Get LLM API key from env or vault."""
    key = os.environ.get("LLM_KEY", "")
    if key:
        return key
    # Try vault paths
    for path in ["/etc/aegis-sigma/vault/LLM_KEY",
                 os.path.expanduser("~/.aegis/vault/LLM_KEY")]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return f.read().strip()
            except:
                pass
    return ""


def call_llm(features, consensus, c_hostile, api_key):
    """Call LLM API for teacher classification."""
    feat_str = ", ".join(f"{v:.4f}" for v in features)
    user_msg = f"C-engine consensus: {consensus:.4f} (hostile={c_hostile})\nFeatures: [{feat_str}]"

    payload = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "max_tokens": 200,
        "temperature": 0.1,
    }).encode()

    req = urllib.request.Request(LLM_URL, data=payload)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        body = json.loads(resp.read())
        content = body["choices"][0]["message"]["content"]

        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            content = content[start:end]

        return json.loads(content)
    except Exception as e:
        print(f"  [ERR] LLM call failed: {e}")
        return None


def process_ndjson(api_key):
    """Read ndjson, label via LLM, write to SQLite."""
    if not os.path.exists(NDJSON_PATH):
        return 0

    with open(NDJSON_PATH, "r") as f:
        lines = f.readlines()

    if not lines:
        return 0

    # Truncate file after reading
    with open(NDJSON_PATH, "w") as f:
        f.write("")

    conn = sqlite3.connect(BRAIN_DB)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS teacher_labels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        features_json TEXT,
        c_engine_verdict INTEGER,
        c_engine_consensus REAL,
        teacher_verdict INTEGER,
        teacher_confidence REAL,
        teacher_reasoning TEXT,
        model TEXT
    )""")

    labeled = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        consensus = entry.get("consensus", 0.5)
        c_hostile = entry.get("c_hostile", 0)

        if consensus < 0.2 or consensus > 0.8:
            cur.execute("""INSERT INTO teacher_labels
                (ip, features_json, c_engine_verdict, c_engine_consensus,
                 teacher_verdict, teacher_confidence, teacher_reasoning, model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry.get("ip", ""), json.dumps(entry.get("features", [])),
                 c_hostile, consensus, c_hostile, 1.0, "C-engine confident", "c-engine-auto"))
            labeled += 1
            continue

        result = call_llm(entry.get("features", []), consensus, c_hostile, api_key)

        if result:
            t_hostile = 1 if result.get("verdict", "BENIGN") == "HOSTILE" else 0
            t_conf = result.get("confidence", 0.5)
            t_reason = result.get("reasoning", "")[:500]
        else:
            t_hostile = c_hostile
            t_conf = 0.5
            t_reason = "API failed, using C-engine verdict"

        cur.execute("""INSERT INTO teacher_labels
            (ip, features_json, c_engine_verdict, c_engine_consensus,
             teacher_verdict, teacher_confidence, teacher_reasoning, model)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry.get("ip", ""), json.dumps(entry.get("features", [])),
             c_hostile, consensus, t_hostile, t_conf, t_reason, LLM_MODEL))
        labeled += 1
        time.sleep(3)

    conn.commit()
    conn.close()
    return labeled


def main():
    api_key = get_api_key()
    if not api_key:
        print("[ERROR] No LLM API key. Set LLM_KEY env var or add to vault.")
        sys.exit(1)

    print(f"[labeler] Model: {LLM_MODEL}")
    labeled = process_ndjson(api_key)
    print(f"[labeler] Labeled {labeled} samples")


if __name__ == "__main__":
    main()
