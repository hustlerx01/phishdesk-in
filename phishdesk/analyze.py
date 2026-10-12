"""Combine header, URL, attachment and lure findings into an explainable score and verdict."""
from __future__ import annotations
from pathlib import Path
from .parse import parse_eml
from .auth import check_auth
from .domains import lookalike, url_findings, registrable, BRANDS
from .india_rules import match_lures

RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".hta", ".iso", ".img", ".lnk", ".apk", ".bat", ".cmd", ".msi", ".docm", ".xlsm", ".html", ".htm", ".zip", ".rar"}
THRESH_PHISH, THRESH_SUSP = 50, 25


def analyze_bytes(raw: bytes, name: str = "") -> dict:
    p = parse_eml(raw)
    a = check_auth(p)
    f: list[dict] = []
    add = lambda rid, w, why, cat: f.append({"rule": rid, "weight": w, "why": why, "category": cat})

    # --- headers
    if a["spf"] in ("fail", "softfail"):
        add("SPF_FAIL", 15, f"SPF {a['spf']}", "auth")
    if a["dkim"] == "fail":
        add("DKIM_FAIL", 15, "DKIM signature failed", "auth")
    if a["dmarc"] == "fail":
        add("DMARC_FAIL", 25, "DMARC fail: From domain not authenticated", "auth")
    elif a["dmarc"] == "none" and a["spf"] != "pass" and a["dkim"] != "pass":
        add("NO_AUTH", 10, "no passing SPF/DKIM and no DMARC result", "auth")
    if a["reply_to_mismatch"]:
        add("REPLYTO_MISMATCH", 15, f"Reply-To domain {p['reply_to_domain']} differs from From {p['from_domain']}", "auth")
    la = lookalike(p["from_domain"])
    if la:
        add("FROM_LOOKALIKE", 35, f"sender domain: {la['reason']}", "lookalike")
    dn = p["display_name"].lower().replace(" ", "")
    for brand, doms in BRANDS.items():
        if brand in dn and registrable(p["from_domain"]) not in {registrable(d) for d in doms}:
            add("DISPLAYNAME_SPOOF", 20, f"display name claims '{brand}' but sender is {p['from_domain']}", "lookalike")
            break
    # --- urls
    anchors = {h: t for h, t in p["anchors"]}
    seen = set()
    for u in p["urls"]:
        for rid, w, why in url_findings(u, anchors.get(u, "")):
            if rid in seen:  # count each URL rule once per mail to avoid score inflation
                continue
            seen.add(rid)
            add(rid, w, f"{why} [{u[:80]}]", "url")
    # --- attachments
    for att in p["attachments"]:
        fn = att["filename"].lower()
        exts = [("." + x) for x in fn.split(".")[1:]]
        if exts and exts[-1] in RISKY_EXT:
            add("ATT_RISKY_EXT", 25, f"risky attachment type {att['filename']}", "attachment")
        if len(exts) >= 2 and exts[-2] in {".pdf", ".doc", ".docx", ".jpg", ".png", ".xls", ".txt"}:
            add("ATT_DOUBLE_EXT", 25, f"double extension {att['filename']}", "attachment")
    # --- India lures (subject + body)
    for rid, w, why in match_lures(p["subject"] + "\n" + p["body"]):
        add(rid, w, why, "lure")

    # Mitigation: fully aligned DMARC pass from an official brand domain is strong evidence of legitimacy
    official = registrable(p["from_domain"]) in {registrable(d) for v in BRANDS.values() for d in v}
    score = sum(x["weight"] for x in f)
    if a["dmarc"] == "pass" and (a["dkim_aligned"] or a["spf_aligned"]):
        score -= 20 if official else 10
        f.append({"rule": "AUTH_ALIGNED_PASS", "weight": -(20 if official else 10), "why": "DMARC pass with aligned identifier", "category": "auth"})
    score = max(0, min(100, score))
    verdict = "phishing" if score >= THRESH_PHISH else "suspicious" if score >= THRESH_SUSP else "clean"
    return {
        "file": name, "subject": p["subject"], "from": p["from"], "verdict": verdict, "score": score,
        "auth": a, "urls": p["urls"], "attachments": p["attachments"],
        "findings": sorted(f, key=lambda x: -x["weight"]),
    }


def analyze_file(path: str | Path) -> dict:
    path = Path(path)
    return analyze_bytes(path.read_bytes(), path.name)
