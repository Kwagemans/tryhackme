#!/usr/bin/env python3
"""
New hypothesis: flags are revealed through:
1. Query count tracking (hit N queries without reset → flag leaks)
2. Hidden endpoints (Flask/Werkzeug specific routes)
3. /reset response changes after N resets
4. A /submit or /validate endpoint for extracted model
"""
import requests, time, json

BASE = "http://10.128.156.28:8000"

def q(feats):
    r = requests.post(f"{BASE}/predict", json={"features": feats}, timeout=8)
    return r.json(), r.headers, r.text, r.status_code

def reset():
    r = requests.post(f"{BASE}/reset", json={}, timeout=5)
    return r.json(), r.headers, r.text

# ── 1. Thorough endpoint scan including Flask/Werkzeug internals
print("=== ENDPOINT SCAN ===")
endpoints = [
    # Flask internals
    "/console", "/_debug", "/__debugger__", "/werkzeug",
    "/.well-known", "/sitemap.xml", "/robots.txt",
    # Potential challenge endpoints  
    "/submit", "/validate", "/verify", "/score", "/check",
    "/extract", "/steal", "/replicate", "/copy",
    "/progress", "/stats", "/queries", "/budget", "/counter",
    "/flag", "/flags", "/flag1", "/flag2", "/flag3",
    "/answer", "/solution", "/result",
    # Model endpoints
    "/model", "/model/info", "/model/params", "/model/tree",
    "/model/weights", "/model/export", "/model/accuracy",
    "/api", "/api/flag", "/api/model",
    "/admin", "/debug", "/secret", "/hidden",
    # Common Flask
    "/static/", "/favicon.ico",
]
for ep in endpoints:
    for method in ["GET", "POST"]:
        try:
            fn = requests.get if method == "GET" else requests.post
            r = fn(f"{BASE}{ep}", json={}, timeout=4)
            if r.status_code not in [404, 405, 308]:
                print(f"  [{method}] {ep} → {r.status_code}: {r.text[:300]}")
        except: pass

# ── 2. Make 100+ queries WITHOUT resetting — watch for ANY change
print("\n=== 100 QUERIES WITHOUT RESET (watching for behavior change) ===")
seen = {}
for i in range(100):
    resp, hdrs, raw, code = q([0.5, 0.5, 1.0, 0.5, 0.5, 0.5])  # always ROUTE_REVIEW
    key = raw.strip()
    if key not in seen:
        seen[key] = i+1
        print(f"  Query {i+1}: NEW RESPONSE: {raw[:200]}")
        for k,v in hdrs.items():
            if k.lower() not in ["content-type","content-length","date","server","connection"]:
                print(f"    HEADER {k}: {v}")
    elif (i+1) % 10 == 0:
        print(f"  Query {i+1}: (same: {key[:60]})")

# ── 3. Reset many times — does it change?
print("\n=== 50 RESETS (watching for change) ===")
seen_reset = {}
for i in range(50):
    resp, hdrs, raw = reset()
    key = str(resp)
    if key not in seen_reset:
        seen_reset[key] = i+1
        print(f"  Reset {i+1}: NEW: {resp}")
        for k,v in hdrs.items():
            if k.lower() not in ["content-type","content-length","date","server","connection"]:
                print(f"    HEADER {k}: {v}")

# ── 4. Try submitting an extracted model description
print("\n=== SUBMIT EXTRACTED MODEL ===")
model_desc = {
    "model": {
        "type": "decision_tree",
        "feature": "RR",
        "feature_index": 2,
        "threshold": 0.45,
        "left": {"classification": "STANDARD_ROUTE", "risk_band": "low"},
        "right": {"classification": "ROUTE_REVIEW", "risk_band": "elevated"}
    }
}
for ep in ["/submit", "/validate", "/verify", "/extract", "/steal", "/answer"]:
    try:
        r = requests.post(f"{BASE}{ep}", json=model_desc, timeout=5)
        print(f"  POST {ep}: {r.status_code}: {r.text[:300]}")
    except: pass

# ── 5. Try query count milestones — maybe 10, 25, 50, 100 queries unlock things
print("\n=== MILESTONE QUERIES (checking /status after each) ===")
requests.post(f"{BASE}/reset", json={}, timeout=5)  # start fresh
for milestone in [10, 25, 50, 100, 250]:
    for _ in range(milestone if milestone == 10 else milestone - prev_milestone):
        q([0.5, 0.5, 1.0, 0.5, 0.5, 0.5])
    prev_milestone = milestone if milestone == 10 else milestone
    # Check any status endpoints after milestone
    for ep in ["/status", "/stats", "/progress", "/budget", "/counter", "/flag"]:
        try:
            r = requests.get(f"{BASE}{ep}", timeout=4)
            if r.status_code == 200:
                print(f"  After {milestone} queries, GET {ep}: {r.text[:200]}")
        except: pass
