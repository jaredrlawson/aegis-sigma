#!/usr/bin/env python3
"""
Generate synthetic CSIC 2010-like training data.
Produces 61K labeled HTTP request feature vectors matching the 30-dim format
used by the Go extractor (pkg/extractor/extractor.go).

Also generates real attack vectors (SQLi, XSS, path traversal) and normal
browsing patterns for the C engine to train on.

Output: /mnt/data/training/csic_training.parquet (30 features + label)
"""
import json
import math
import os
import random
import sqlite3
import sys
from datetime import datetime, timedelta

import numpy as np

random.seed(42)
np.random.seed(42)

# --- Constants matching Go extractor (pkg/extractor/extractor.go) ---
PHI = 1.618033988749895

# Feature indices (0-29) matching Go extractor
IDX_TTL_NORM = 0
IDX_WINDOW_NORM = 1
IDX_MSS_NORM = 2
IDX_UA_SCRIPT = 3
IDX_UA_LEN = 4
IDX_HAS_REFERER = 5
IDX_PATH_SCORE = 6
IDX_PATH_LEN = 7
IDX_IS_SENSITIVE = 8
IDX_GEO_RISK = 9
IDX_HAS_COUNTRY = 10
IDX_ASN_RISK = 11
IDX_TIMING_RISK = 12
IDX_SEVERITY_BINARY = 13
IDX_TIMING_BASELINE = 14
IDX_PRIOR_STRIKES = 15
IDX_HAS_EVIDENCE = 16
IDX_EVIDENCE_LEN = 17
IDX_HAS_FINGERPRINT = 18
IDX_HARMONIC = 19
IDX_JA3_RISK = 20
IDX_TLS_CIPHER = 21
IDX_HEADER_ANOMALY = 22
IDX_LANG_RISK = 23
IDX_HOUR_SIN = 24
IDX_HOUR_COS = 25
IDX_DAY_SIN = 26
IDX_DAY_COS = 27
IDX_VOLUME_COHERENCE = 28
IDX_PHI_DIVERGENCE = 29

N_FEATURES = 30

# --- Attack patterns ---
SQLI_PAYLOADS = [
    "' OR 1=1 --", "' UNION SELECT null,null,null --",
    "admin'--", "' OR 'x'='x", "1; DROP TABLE users--",
    "' UNION SELECT username,password FROM users--",
    "1' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; EXEC xp_cmdshell('dir')--",
    "' OR 1=1 LIMIT 1--", "admin' OR '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>", "'-alert(1)-'",
    "<body onload=alert(1)>", "<input onfocus=alert(1)>",
    "<marquee onstart=alert(1)>", "<details open ontoggle=alert(1)>",
]

PATH_TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..%252f..%252f..%252fetc/passwd", "/etc/passwd%00",
    "../../../etc/shadow", "....\\\\....\\\\....\\\\etc/passwd",
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/17.5",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) Chrome/131.0.0.0 Mobile Safari/537.36",
]

ATTACK_UAS = [
    "sqlmap/1.7", "nikto/2.1.5", "Nmap/7.94",
    "python-requests/2.31", "Go-http-client/1.1",
    "curl/8.4.0", "Wget/1.21", "scrapy/2.11",
    "-", "", "masscan/1.3",
]

NORMAL_PATHS = [
    "/", "/index.html", "/about", "/contact", "/services", "/pricing",
    "/blog", "/blog/post-1", "/docs", "/support", "/login",
    "/assets/style.css", "/assets/app.js", "/images/logo.png",
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/api/health",
    "/api/v1/status", "/terms", "/privacy", "/faq",
]

ATTACK_PATHS = SQLI_PAYLOADS + XSS_PAYLOADS + PATH_TRAVERSAL

NORMAL_REFERERS = [
    "", "https://www.google.com/", "https://www.bing.com/",
		"https://example.com/", "https://app.example.com/",
    "", "", "",  # 37.5% direct
]

COUNTRIES = ["US", "GB", "DE", "FR", "JP", "CA", "AU", "BR", "IN", "NL"]
HOSTILE_COUNTRIES = ["RU", "CN", "KP", "IR"]

NORMAL_METHODS = ["GET"] * 85 + ["POST"] * 10 + ["PUT"] * 3 + ["DELETE"] * 2


def gen_normal_request():
    """Generate a normal (benign) HTTP request feature vector."""
    features = np.zeros(N_FEATURES)

    # TCP features - normal browsers
    features[IDX_TTL_NORM] = random.choice([64, 128, 255]) / 255.0
    features[IDX_WINDOW_NORM] = random.choice([16384, 32768, 65535]) / 65535.0
    features[IDX_MSS_NORM] = random.choice([1400, 1460]) / 1460.0

    # UA features - normal
    features[IDX_UA_SCRIPT] = 0.0
    features[IDX_UA_LEN] = len(random.choice(NORMAL_UAS)) / 200.0

    # Referer
    ref = random.choice(NORMAL_REFERERS)
    features[IDX_HAS_REFERER] = 1.0 if ref else 0.0

    # Path features - normal
    path = random.choice(NORMAL_PATHS)
    features[IDX_PATH_SCORE] = random.choice([0.1, 0.15, 0.2])
    features[IDX_PATH_LEN] = len(path) / 200.0
    features[IDX_IS_SENSITIVE] = 0.0

    # Geo - normal
    country = random.choice(COUNTRIES)
    features[IDX_GEO_RISK] = 0.0
    features[IDX_HAS_COUNTRY] = 1.0
    features[IDX_ASN_RISK] = 0.3

    # Timing - normal
    features[IDX_TIMING_RISK] = random.uniform(0.0, 0.3)
    features[IDX_SEVERITY_BINARY] = 0.0
    features[IDX_TIMING_BASELINE] = abs(random.gauss(0, 0.1))
    features[IDX_PRIOR_STRIKES] = 0.0

    # Evidence
    features[IDX_HAS_EVIDENCE] = 0.0
    features[IDX_EVIDENCE_LEN] = 0.0
    features[IDX_HAS_FINGERPRINT] = 0.0

    # Harmonic score
    features[IDX_HARMONIC] = (
        features[IDX_PATH_SCORE] * 0.3 +
        features[IDX_UA_SCRIPT] * 0.3 +
        features[IDX_GEO_RISK] * 0.2 +
        features[IDX_TIMING_RISK] * 0.2
    )

    # TLS features - normal
    features[IDX_JA3_RISK] = 0.2
    features[IDX_TLS_CIPHER] = 0.3

    # Header anomaly - low
    features[IDX_HEADER_ANOMALY] = random.choice([0.0, 0.0, 0.0, 0.2])
    features[IDX_LANG_RISK] = 0.1

    # Temporal encoding
    hour = random.gauss(14, 4) % 24  # peak around 2pm
    day = random.randint(0, 6)
    features[IDX_HOUR_SIN] = math.sin(2 * math.pi * hour / 24)
    features[IDX_HOUR_COS] = math.cos(2 * math.pi * hour / 24)
    features[IDX_DAY_SIN] = math.sin(2 * math.pi * day / 7)
    features[IDX_DAY_COS] = math.cos(2 * math.pi * day / 7)

    # Volume coherence
    features[IDX_VOLUME_COHERENCE] = random.uniform(0.05, 0.15)

    # Phi divergence - low
    features[IDX_PHI_DIVERGENCE] = abs(random.gauss(0, 0.05))

    return features, 0  # label 0 = benign


def gen_attack_request():
    """Generate a malicious (hostile) HTTP request feature vector."""
    features = np.zeros(N_FEATURES)

    attack_type = random.choice(["sqli", "xss", "traversal", "scanner", "bruteforce"])

    # TCP features - more varied (bots, scripts)
    features[IDX_TTL_NORM] = random.choice([32, 64, 128, 255, 50, 100]) / 255.0
    features[IDX_WINDOW_NORM] = random.choice([1024, 4096, 16384, 65535]) / 65535.0
    features[IDX_MSS_NORM] = random.choice([536, 1400, 1460]) / 1460.0

    # UA features - attack tools
    ua = random.choice(ATTACK_UAS)
    features[IDX_UA_SCRIPT] = 0.8 if ua in ["sqlmap/1.7", "nikto/2.1.5", "Nmap/7.94"] else 0.5
    features[IDX_UA_LEN] = len(ua) / 200.0

    # Referer - often missing
    features[IDX_HAS_REFERER] = random.choice([0.0, 0.0, 0.0, 0.0, 1.0])

    # Path features - attack patterns
    if attack_type == "sqli":
        path = random.choice(SQLI_PAYLOADS)
        features[IDX_PATH_SCORE] = 0.9
    elif attack_type == "xss":
        path = random.choice(XSS_PAYLOADS)
        features[IDX_PATH_SCORE] = 0.85
    elif attack_type == "traversal":
        path = random.choice(PATH_TRAVERSAL)
        features[IDX_PATH_SCORE] = 0.95
    elif attack_type == "scanner":
        path = random.choice(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup.sql"])
        features[IDX_PATH_SCORE] = 0.7
    else:
        path = random.choice(["/login", "/admin/login", "/api/auth"])
        features[IDX_PATH_SCORE] = 0.5

    features[IDX_PATH_LEN] = len(path) / 200.0
    features[IDX_IS_SENSITIVE] = 1.0

    # Geo - hostile countries more likely
    country = random.choice(HOSTILE_COUNTRIES + COUNTRIES)
    features[IDX_GEO_RISK] = 0.8 if country in HOSTILE_COUNTRIES else 0.2
    features[IDX_HAS_COUNTRY] = 1.0
    features[IDX_ASN_RISK] = 0.6 if country in HOSTILE_COUNTRIES else 0.3

    # Timing - rapid, automated
    features[IDX_TIMING_RISK] = random.uniform(0.5, 1.0)
    features[IDX_SEVERITY_BINARY] = random.choice([0.0, 1.0, 1.0, 1.0])
    features[IDX_TIMING_BASELINE] = abs(random.gauss(0.3, 0.2))
    features[IDX_PRIOR_STRIKES] = random.choice([0.0, 0.5, 1.0, 2.0, 5.0]) / 10.0

    # Evidence - present
    features[IDX_HAS_EVIDENCE] = 1.0
    features[IDX_EVIDENCE_LEN] = random.uniform(0.1, 0.5)
    features[IDX_HAS_FINGERPRINT] = random.choice([0.0, 0.5, 1.0])

    # Harmonic score - high
    features[IDX_HARMONIC] = (
        features[IDX_PATH_SCORE] * 0.3 +
        features[IDX_UA_SCRIPT] * 0.3 +
        features[IDX_GEO_RISK] * 0.2 +
        features[IDX_TIMING_RISK] * 0.2
    )

    # TLS features - suspicious
    features[IDX_JA3_RISK] = random.choice([0.5, 0.8, 1.0])
    features[IDX_TLS_CIPHER] = random.choice([0.5, 0.8, 1.0])

    # Header anomaly - high
    features[IDX_HEADER_ANOMALY] = random.uniform(0.3, 1.0)
    features[IDX_LANG_RISK] = 0.5

    # Temporal - can be any time (automated)
    hour = random.uniform(0, 24)
    day = random.randint(0, 6)
    features[IDX_HOUR_SIN] = math.sin(2 * math.pi * hour / 24)
    features[IDX_HOUR_COS] = math.cos(2 * math.pi * hour / 24)
    features[IDX_DAY_SIN] = math.sin(2 * math.pi * day / 7)
    features[IDX_DAY_COS] = math.cos(2 * math.pi * day / 7)

    # Volume coherence - high (payload)
    features[IDX_VOLUME_COHERENCE] = random.uniform(0.2, 0.8)

    # Phi divergence - high
    features[IDX_PHI_DIVERGENCE] = abs(random.gauss(0.4, 0.2))

    return features, 1  # label 1 = hostile


def extract_from_security_events(db_path):
    """Extract features from real brain.sqlite security_events."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
        SELECT ip, COALESCE(user_agent,''), COALESCE(request_uri,''),
               COALESCE(reason,''), COALESCE(severity,'info'),
               COALESCE(tcp_window,0), COALESCE(tcp_ttl,0),
               COALESCE(country_code,''), COALESCE(tcp_mss,0),
               COALESCE(inter_arrival_time,0), COALESCE(strikes,1),
               COALESCE(evidence,''), COALESCE(tls_ja3,''),
               COALESCE(tls_cipher,''), COALESCE(http_referer,''),
               COALESCE(accept_language,''), COALESCE(city,''),
               COALESCE(region,'')
        FROM security_events
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def features_from_event(row):
    """Convert a security_events row to 30-dim feature vector."""
    (ip, ua, uri, reason, severity, tcp_win, tcp_ttl, country,
     tcp_mss, iat, strikes, evidence, ja3, cipher, referer,
     lang, city, region) = row

    # Coerce numeric fields
    try:
        tcp_win = int(tcp_win) if tcp_win else 0
    except (ValueError, TypeError):
        tcp_win = 0
    try:
        tcp_ttl = int(tcp_ttl) if tcp_ttl else 0
    except (ValueError, TypeError):
        tcp_ttl = 0
    try:
        tcp_mss = int(tcp_mss) if tcp_mss else 0
    except (ValueError, TypeError):
        tcp_mss = 0
    try:
        iat = int(iat) if iat else 0
    except (ValueError, TypeError):
        iat = 0
    try:
        strikes = int(strikes) if strikes else 1
    except (ValueError, TypeError):
        strikes = 1

    features = np.zeros(N_FEATURES)

    # TCP
    features[IDX_TTL_NORM] = min(tcp_ttl, 255) / 255.0 if tcp_ttl > 0 else 0.5
    features[IDX_WINDOW_NORM] = min(tcp_win, 65535) / 65535.0 if tcp_win > 0 else 0.5
    features[IDX_MSS_NORM] = min(tcp_mss, 1460) / 1460.0 if tcp_mss > 0 else 0.5

    # UA
    ua_lower = ua.lower()
    script_keywords = ["sqlmap", "nikto", "nmap", "masscan", "scrapy", "python", "go-http", "curl", "wget"]
    features[IDX_UA_SCRIPT] = 0.8 if any(k in ua_lower for k in script_keywords) else (1.0 if ua == "-" or ua == "" else 0.0)
    features[IDX_UA_LEN] = min(len(ua), 200) / 200.0

    # Referer
    features[IDX_HAS_REFERER] = 1.0 if referer and referer.strip() else 0.0

    # Path
    uri_lower = uri.lower()
    attack_indicators = ["'", "select", "union", "<script", "../", "etc/passwd", "admin", "wp-", "phpmyadmin"]
    path_score = 0.1
    if any(a in uri_lower for a in attack_indicators):
        path_score = 0.8
    elif "/admin" in uri_lower or "/login" in uri_lower:
        path_score = 0.5
    elif "/api/" in uri_lower:
        path_score = 0.3
    features[IDX_PATH_SCORE] = path_score
    features[IDX_PATH_LEN] = min(len(uri), 200) / 200.0
    features[IDX_IS_SENSITIVE] = 1.0 if path_score > 0.5 else 0.0

    # Geo
    hostile_countries = ["RU", "CN", "KP", "IR"]
    features[IDX_GEO_RISK] = 0.8 if country in hostile_countries else (0.2 if country else 0.0)
    features[IDX_HAS_COUNTRY] = 1.0 if country else 0.0
    features[IDX_ASN_RISK] = 0.3 if country else 0.0

    # Timing
    features[IDX_TIMING_RISK] = 0.8 if iat < 100 else (0.5 if iat < 1000 else 0.2)
    features[IDX_SEVERITY_BINARY] = 1.0 if severity in ["critical", "high"] else 0.0
    features[IDX_TIMING_BASELINE] = abs(iat - 500) / 1000.0 if iat > 0 else 0.0
    features[IDX_PRIOR_STRIKES] = min(strikes, 10) / 10.0

    # Evidence
    features[IDX_HAS_EVIDENCE] = 1.0 if evidence and evidence.strip() else 0.0
    features[IDX_EVIDENCE_LEN] = min(len(evidence), 500) / 500.0 if evidence else 0.0
    features[IDX_HAS_FINGERPRINT] = 1.0 if ja3 and ja3.strip() else 0.0

    # Harmonic
    features[IDX_HARMONIC] = (
        features[IDX_PATH_SCORE] * 0.3 +
        features[IDX_UA_SCRIPT] * 0.3 +
        features[IDX_GEO_RISK] * 0.2 +
        features[IDX_TIMING_RISK] * 0.2
    )

    # TLS
    features[IDX_JA3_RISK] = 0.8 if not ja3 or ja3.strip() == "" else 0.2
    features[IDX_TLS_CIPHER] = 0.8 if cipher and ("RC4" in cipher or "DES" in cipher or "NULL" in cipher) else 0.3

    # Header anomaly
    anomaly = 0.0
    if not referer or not referer.strip():
        anomaly += 0.2
    if not lang or not lang.strip():
        anomaly += 0.2
    if ua == "-" or ua == "":
        anomaly += 0.3
    features[IDX_HEADER_ANOMALY] = min(anomaly, 1.0)
    features[IDX_LANG_RISK] = 0.1 if lang and lang.strip() else 0.5

    # Temporal - use current time
    now = datetime.now()
    features[IDX_HOUR_SIN] = math.sin(2 * math.pi * now.hour / 24)
    features[IDX_HOUR_COS] = math.cos(2 * math.pi * now.hour / 24)
    features[IDX_DAY_SIN] = math.sin(2 * math.pi * now.weekday() / 7)
    features[IDX_DAY_COS] = math.cos(2 * math.pi * now.weekday() / 7)

    # Volume coherence
    features[IDX_VOLUME_COHERENCE] = (len(uri) + len(evidence)) / (PHI * 2000.0) if evidence else len(uri) / (PHI * 2000.0)

    # Phi divergence
    iat_sec = iat / 1000.0 if iat > 0 else 1.0
    features[IDX_PHI_DIVERGENCE] = abs(math.log(iat_sec / PHI)) if iat_sec > 0 else 0.0

    # Label from reason
    hostile_keywords = ["attack", "injection", "xss", "sqli", "traversal", "brute",
                        "overflow", "malicious", "scan", "probe", "exploit", "suspicious"]
    label = 1 if any(k in (reason or "").lower() for k in hostile_keywords) else 0

    return features, label


def main():
    output_dir = "/mnt/data/training"
    os.makedirs(output_dir, exist_ok=True)

    all_features = []
    all_labels = []

    print("[1/4] Extracting from brain.sqlite security_events...")
    db_path = "/mnt/data/databases/brain.sqlite"
    if os.path.exists(db_path):
        rows = extract_from_security_events(db_path)
        print(f"  Found {len(rows)} security events")
        for row in rows:
            features, label = features_from_event(row)
            all_features.append(features)
            all_labels.append(label)
    else:
        print("  brain.sqlite not found, skipping")

    print("[2/4] Generating synthetic normal requests (36K)...")
    for _ in range(36000):
        features, label = gen_normal_request()
        all_features.append(features)
        all_labels.append(label)

    print("[3/4] Generating synthetic attack requests (25K)...")
    for _ in range(25000):
        features, label = gen_attack_request()
        all_features.append(features)
        all_labels.append(label)

    print("[4/4] Saving training data...")
    features_arr = np.array(all_features, dtype=np.float32)
    labels_arr = np.array(all_labels, dtype=np.int32)

    # Save as numpy arrays (no parquet dependency needed)
    np.save(os.path.join(output_dir, "csic_features.npy"), features_arr)
    np.save(os.path.join(output_dir, "csic_labels.npy"), labels_arr)

    # Also save as CSV for easy inspection
    header = ",".join([f"f{i}" for i in range(N_FEATURES)] + ["label"])
    with open(os.path.join(output_dir, "csic_training.csv"), "w") as f:
        f.write(header + "\n")
        for i in range(len(all_features)):
            row = ",".join(f"{v:.6f}" for v in all_features[i])
            f.write(f"{row},{all_labels[i]}\n")

    # Stats
    n_hostile = sum(all_labels)
    n_benign = len(all_labels) - n_hostile
    print(f"\n=== Training Dataset Summary ===")
    print(f"Total samples: {len(all_labels)}")
    print(f"  Benign (0): {n_benign}")
    print(f"  Hostile (1): {n_hostile}")
    print(f"  Ratio: {n_benign/max(n_hostile,1):.2f}:1")
    print(f"Features: {N_FEATURES}")
    print(f"Output: {output_dir}/csic_features.npy + csic_labels.npy + csic_training.csv")
    print(f"Size: {features_arr.nbytes / 1024 / 1024:.1f} MB (numpy)")


if __name__ == "__main__":
    main()
