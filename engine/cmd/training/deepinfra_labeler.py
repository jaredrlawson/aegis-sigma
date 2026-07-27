#!/usr/bin/env python3
"""
DeepInfra labeler — reads teacher_labels.ndjson from C engine,
sends ambiguous cases to DeepInfra API for authoritative labels,
writes results to brain.sqlite teacher_labels table.

Runs every 15 minutes via cron during business hours.
"""
import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error

BRAIN_DB = "/mnt/data/databases/brain.sqlite"
NDJSON_PATH = "/var/log/aegis/teacher_labels.ndjson"
DEEPINFRA_URL = "https://ai.aegis-sigma.com/v1/chat/completions"
DEEPINFRA_MODEL = "oc-prod/openai/gpt-oss-20b"

# Read API key from vault
def get_api_key():
    key_paths = [
        "/etc/aegis-sigma/vault/LLM_KEY",
        os.path.expanduser("~/.aegis/vault/LLM_KEY"),
    ]
    for p in key_paths:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    return f.read().strip()
            except PermissionError:
                pass
    # Try reading via sudo
    try:
        import subprocess
        result = subprocess.run(
            ["sudo", "cat", "/etc/aegis-sigma/vault/LLM_KEY"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    return os.environ.get("LLM_KEY", "")

SYSTEM_PROMPT = """You are a network security classifier. Given HTTP request features,
classify the request as BENIGN (real user) or HOSTILE (attack/bot).

Respond with ONLY a JSON object:
{"verdict": "BENIGN" or "HOSTILE", "confidence": 0.0-1.0, "reasoning": "one line"}

Features are a 30-dim float vector matching the Aegis-SIGMA extractor format:
[ttl_norm, window_norm, mss_norm, ua_script_score, ua_len_norm, has_referer,
 path_score, path_len_norm, is_sensitive, geo_risk, has_country, asn_risk,
 timing_risk, severity_binary, timing_baseline, prior_strikes_norm,
 has_evidence, evidence_len_norm, has_fingerprint, harmonic_score,
 ja3_risk, tls_cipher_risk, header_anomaly, lang_risk,
 hour_sin, hour_cos, day_sin, day_cos, volume_coherence, phi_divergence]

Key indicators:
- ua_script_score > 0.5: scripting library or attack tool
- path_score > 0.7: attack pattern in URI
- geo_risk > 0.5: hostile country (RU, CN, KP, IR)
- timing_risk > 0.5: rapid automated requests
- header_anomaly > 0.3: missing standard headers
- prior_strikes_norm > 0: known offender"""


def call_deepinfra(features, consensus, c_hostile, api_key):
    """Call DeepInfra API for teacher classification."""
    feat_str = ", ".join(f"{v:.4f}" for v in features)
    user_msg = f"C-engine consensus: {consensus:.4f} (hostile={c_hostile})\nFeatures: [{feat_str}]"

    payload = json.dumps({
        "model": DEEPINFRA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "max_tokens": 200,
        "temperature": 0.1,
    }).encode()

    req = urllib.request.Request(DEEPINFRA_URL, data=payload)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        body = json.loads(resp.read())
        content = body["choices"][0]["message"]["content"]

        # Parse JSON from response
        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

        # Find the first complete JSON object
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            content = content[start:end]

        result = json.loads(content)
        return result
    except Exception as e:
        print(f"  [ERR] DeepInfra call failed: {e}")
        return None


def process_ndjson(api_key):
    """Read ndjson, label via DeepInfra, write to brain.sqlite."""
    if not os.path.exists(NDJSON_PATH):
        return 0

    # Read the ndjson file (may need sudo)
    try:
        with open(NDJSON_PATH, "r") as f:
            lines = f.readlines()
    except PermissionError:
        import subprocess
        result = subprocess.run(
            ["sudo", "cat", NDJSON_PATH],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return 0
        lines = result.stdout.splitlines(keepends=True)

    if not lines:
        return 0

    # Truncate the file
    try:
        with open(NDJSON_PATH, "w") as f:
            f.write("")
    except PermissionError:
        import subprocess
        subprocess.run(["sudo", "truncate", "-s", "0", NDJSON_PATH], timeout=5)

    conn = sqlite3.connect(BRAIN_DB)
    cur = conn.cursor()

    # Ensure table exists
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
        model TEXT DEFAULT 'oc-prod/openai/gpt-oss-20b'
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

        # Only label uncertain cases (consensus 0.2-0.8) to save API credits
        # Skip very confident predictions — teacher adds little value there
        if consensus < 0.2 or consensus > 0.8:
            # Still log to teacher_labels with the C engine's verdict
            cur.execute("""INSERT INTO teacher_labels
                (ip, features_json, c_engine_verdict, c_engine_consensus,
                 teacher_verdict, teacher_confidence, teacher_reasoning, model)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry.get("ip", ""), json.dumps(entry.get("features", [])),
                 c_hostile, consensus,
                 c_hostile, 1.0, "C-engine confident (no teacher needed)",
                 "c-engine-auto"))
            labeled += 1
            continue

        # Call DeepInfra for uncertain cases
        result = call_deepinfra(
            entry.get("features", []), consensus, c_hostile, api_key
        )

        if result:
            t_hostile = 1 if result.get("verdict", "BENIGN") == "HOSTILE" else 0
            t_conf = result.get("confidence", 0.5)
            t_reason = result.get("reasoning", "")[:500]
        else:
            # API failed — use C engine's verdict as fallback
            t_hostile = c_hostile
            t_conf = 0.5
            t_reason = "API failed, using C-engine verdict"

        cur.execute("""INSERT INTO teacher_labels
            (ip, features_json, c_engine_verdict, c_engine_consensus,
             teacher_verdict, teacher_confidence, teacher_reasoning, model)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (entry.get("ip", ""), json.dumps(entry.get("features", [])),
             c_hostile, consensus,
             t_hostile, t_conf, t_reason, DEEPINFRA_MODEL))
        labeled += 1

        # Rate limit: 1 request per 3 seconds
        time.sleep(3)

    conn.commit()
    conn.close()
    return labeled


def main():
    api_key = get_api_key()
    if not api_key:
        print("[ERROR] No API key found")
        sys.exit(1)

    print(f"[labeler] Processing teacher labels... (model={DEEPINFRA_MODEL})")
    labeled = process_ndjson(api_key)
    print(f"[labeler] Labeled {labeled} samples")

    # Show stats
    try:
        conn = sqlite3.connect(BRAIN_DB)
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM teacher_labels")
        total = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM teacher_labels WHERE teacher_verdict = 1")
        hostile = cur.fetchone()[0]
        conn.close()
        print(f"[labeler] Total in teacher_labels: {total} (hostile={hostile}, benign={total-hostile})")
    except:
        pass


if __name__ == "__main__":
    main()
