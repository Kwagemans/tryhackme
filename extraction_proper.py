#!/usr/bin/env python3
"""
REAL model extraction approach:
The briefing says "internal behavior may be inferred OVER TIME"
= model behavior CHANGES as queries accumulate (without reset)
= /reset sends it back to simple state
= we need to NOT reset and watch for new decision boundaries emerging

Strategy: flood queries, sweep ALL features every 50 queries, 
detect when new thresholds appear.
"""
import requests, numpy as np, time

BASE = "http://10.128.156.28:8000"
FEATURES = ["CM","SE","RR","OS","CT","MS"]

def q(feats):
    r = requests.post(f"{BASE}/predict", json={"features": feats}, timeout=8)
    return r.json() if r.status_code == 200 else None

def full_sweep():
    """Quick sweep of all 6 features — returns all seen responses."""
    results = {}
    for fi, fname in enumerate(FEATURES):
        transitions = []
        prev = None
        # Use 50 points per feature for speed
        for v in np.linspace(0, 1, 50):
            feats = [0.5]*6
            feats[fi] = round(float(v), 3)
            resp = q(feats)
            if resp != prev:
                transitions.append((round(float(v),3), resp))
                prev = resp
        results[fname] = transitions
    return results

def sweep_summary(sweep):
    """Return compact summary: feature → number of unique responses."""
    out = {}
    for fname, trans in sweep.items():
        unique = set(str(t[1]) for t in trans)
        out[fname] = len(unique)
    return out

print("=" * 60)
print("PHASE 1: Reset state, baseline sweep")
print("=" * 60)
requests.post(f"{BASE}/reset", json={}, timeout=5)
baseline = full_sweep()
print("Baseline (after reset):")
for fname, trans in baseline.items():
    print(f"  {fname}: {trans}")

print("\n" + "=" * 60)
print("PHASE 2: Accumulate queries WITHOUT reset, sweep every 50")
print("=" * 60)

total_queries = 0
prev_summary = sweep_summary(baseline)
discoveries = []

# Use VARIED inputs to maximize information gain
query_patterns = [
    [0.0, 0.0, 0.0, 0.0, 0.0, 0.0],  # all min
    [1.0, 1.0, 1.0, 1.0, 1.0, 1.0],  # all max
    [0.5, 0.5, 0.5, 0.5, 0.5, 0.5],  # all mid
    [0.0, 0.0, 1.0, 0.0, 0.0, 0.0],  # only RR high
    [1.0, 1.0, 0.0, 1.0, 1.0, 1.0],  # only RR low
    [0.1, 0.9, 0.4, 0.2, 0.8, 0.3],  # mixed low RR
    [0.9, 0.1, 0.6, 0.8, 0.2, 0.7],  # mixed high RR
]

for batch in range(40):  # up to 2000 queries
    # Send 50 varied queries
    for i in range(50):
        feats = query_patterns[i % len(query_patterns)]
        # Add slight noise to explore more
        noisy = [round(min(1,max(0,f + np.random.uniform(-0.05,0.05))),3) for f in feats]
        q(noisy)
        total_queries += 1

    # Full sweep to detect new behavior
    current = full_sweep()
    current_summary = sweep_summary(current)
    
    changed = {f: (prev_summary[f], current_summary[f]) 
               for f in FEATURES 
               if current_summary[f] != prev_summary.get(f)}
    
    print(f"\n--- After {total_queries} queries ---")
    print(f"  Feature complexity: { {f: current_summary[f] for f in FEATURES} }")
    
    if changed:
        print(f"  *** CHANGE DETECTED: {changed} ***")
        discoveries.append((total_queries, changed, current))
        for fname, trans in current.items():
            if len(trans) > len(baseline.get(fname,[])):
                print(f"  NEW TRANSITIONS in {fname}: {trans}")
    
    prev_summary = current_summary
    
    if total_queries >= 2000:
        break

print("\n" + "=" * 60)
print(f"DISCOVERIES: {len(discoveries)}")
for d in discoveries:
    print(f"  At {d[0]} queries: {d[1]}")
