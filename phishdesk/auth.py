"""SPF / DKIM / DMARC verdicts from Authentication-Results (RFC 8601) + alignment (RFC 7489 relaxed).

We trust the receiving MTA's Authentication-Results (as a mail gateway would); we do NOT re-verify
DKIM signatures cryptographically or re-query DNS, because lab mail has no live DNS.
"""
from __future__ import annotations
import re
from .domains import registrable


def _res(text: str, mech: str) -> str:
    m = re.search(rf"\b{mech}\s*=\s*(\w+)", text, re.I)
    return m.group(1).lower() if m else "none"


def check_auth(p: dict) -> dict:
    ar = " ; ".join(p["auth_results"])
    spf = _res(ar, "spf")
    if spf == "none" and p["received_spf"]:
        spf = p["received_spf"].split()[0].lower()
    dkim, dmarc = _res(ar, "dkim"), _res(ar, "dmarc")
    m = re.search(r"\bd=([\w.-]+)", p["dkim_signature"] or "")
    dkim_d = (m.group(1).lower() if m else "") or (re.search(r"header\.d=([\w.-]+)", ar) or [None, ""])[1]
    org = registrable(p["from_domain"])
    return {
        "spf": spf, "dkim": dkim, "dmarc": dmarc, "dkim_domain": dkim_d,
        "spf_aligned": bool(p["return_path_domain"]) and registrable(p["return_path_domain"]) == org,
        "dkim_aligned": bool(dkim_d) and registrable(dkim_d) == org,
        "reply_to_mismatch": bool(p["reply_to_domain"]) and registrable(p["reply_to_domain"]) != org,
    }
