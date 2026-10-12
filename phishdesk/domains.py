"""Domain helpers: registrable domain, lookalike/homoglyph detection, URL reputation heuristics (offline)."""
from __future__ import annotations
import ipaddress, re
from urllib.parse import urlsplit

# Small public-suffix subset (no network). Real deployments should use the full PSL (tldextract).
MULTI_SUFFIX = {"co.in", "gov.in", "org.in", "net.in", "ac.in", "nic.in", "res.in", "co.uk", "com.au"}

# Brands commonly impersonated in Indian phishing (RBI / CERT-In / NPCI advisories). Legit domains only.
BRANDS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"], "hdfcbank": ["hdfcbank.com"],
    "icicibank": ["icicibank.com"], "axisbank": ["axisbank.com"], "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"], "bankofbaroda": ["bankofbaroda.in"], "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"], "npci": ["npci.org.in"], "bhim": ["bhimupi.org.in"],
    "incometax": ["incometax.gov.in"], "uidai": ["uidai.gov.in"], "indiapost": ["indiapost.gov.in"],
    "irctc": ["irctc.co.in"], "epfo": ["epfindia.gov.in"], "googlepay": ["pay.google.com", "google.com"],
    "amazon": ["amazon.in", "amazon.com"],
}
LEGIT = {d for v in BRANDS.values() for d in v}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly"}
RISKY_TLDS = {"xyz", "top", "icu", "buzz", "click", "live", "online", "site", "shop", "info", "cfd", "sbs", "rest", "monster", "support", "cyou"}
HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def registrable(host: str) -> str:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _label(reg: str) -> str:
    return reg.split(".")[0]


def lookalike(host: str) -> dict | None:
    """Return {brand, reason} if host imitates a brand but is not one of its legit domains."""
    host = (host or "").lower()
    if host.startswith("xn--") or ".xn--" in host:
        return {"brand": "?", "reason": "punycode/IDN host (possible homograph)"}
    reg = registrable(host)
    if reg in LEGIT or host in LEGIT:
        return None
    lab = _label(reg)
    norm = lab.translate(HOMO).replace("rn", "m").replace("vv", "w")
    tokens = re.split(r"[-.]", host)
    for brand in BRANDS:
        if norm == brand and lab != brand:
            return {"brand": brand, "reason": f"homoglyph of '{brand}' ({lab})"}
        if lab == brand:
            return {"brand": brand, "reason": f"brand name on non-official domain ({reg})"}
        if len(brand) >= 5 and 0 < levenshtein(norm, brand) <= 1 + (len(brand) >= 9):
            return {"brand": brand, "reason": f"typosquat of '{brand}' ({lab}, edit distance {levenshtein(norm, brand)})"}
        if brand in tokens or (len(brand) >= 4 and any(t.startswith(brand) or t.endswith(brand) for t in tokens if t != brand and len(t) > len(brand))):
            return {"brand": brand, "reason": f"brand '{brand}' embedded in unrelated domain ({host})"}
    return None


def url_findings(url: str, anchor_text: str = "") -> list[tuple[str, int, str]]:
    """Heuristic (rule_id, weight, explanation) list for one URL."""
    out = []
    if url.lower().startswith("upi://"):
        q = url.lower()
        out.append(("UPI_DEEPLINK", 25, "upi:// payment deep link inside an email (banks never ask you to pay to receive money)"))
        if "pay?" in q and ("am=" in q):
            out.append(("UPI_PAY_AMOUNT", 10, "pre-filled UPI pay amount"))
        return out
    if url.lower().startswith("www."):
        url = "http://" + url
    s = urlsplit(url)
    host = (s.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        out.append(("URL_IP_HOST", 20, f"raw IP host {host}"))
    except ValueError:
        pass
    if s.scheme == "http":
        out.append(("URL_NO_TLS", 5, "plain http link"))
    if "@" in (s.netloc or ""):
        out.append(("URL_USERINFO", 20, "'@' in URL authority hides the real host"))
    if registrable(host) in SHORTENERS:
        out.append(("URL_SHORTENER", 10, f"URL shortener {host} hides destination"))
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        out.append(("URL_RISKY_TLD", 10, f".{tld} TLD frequently abused for phishing"))
    if host.count(".") >= 4:
        out.append(("URL_DEEP_SUBDOMAIN", 5, "many subdomain levels"))
    la = lookalike(host)
    if la:
        out.append(("LOOKALIKE_DOMAIN", 35, la["reason"]))
    if anchor_text:
        m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", anchor_text.lower())
        if m and registrable(m.group(0)) != registrable(host):
            out.append(("ANCHOR_MISMATCH", 25, f"link text shows {m.group(0)} but points to {host}"))
    if re.search(r"(login|verify|kyc|update|secure|signin|account|otp|refund)", (s.path or "") + host):
        out.append(("URL_CRED_KEYWORDS", 5, "credential/KYC keywords in URL"))
    return out
