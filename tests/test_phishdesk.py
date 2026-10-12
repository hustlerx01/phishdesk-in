import json
from pathlib import Path
from email.message import EmailMessage
from phishdesk.domains import lookalike, registrable, url_findings, levenshtein
from phishdesk.india_rules import match_lures
from phishdesk.analyze import analyze_bytes
from phishdesk.report import to_markdown
from phishdesk.evaluate import evaluate

ROOT = Path(__file__).resolve().parents[1]


def mail(frm, subject, body, ar="spf=pass; dkim=pass header.d=x; dmarc=pass", att=None, html=None):
    m = EmailMessage(); m["From"] = frm; m["Subject"] = subject; m["Authentication-Results"] = "mx; " + ar
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    if att:
        m.add_attachment(att[1], maintype="application", subtype="octet-stream", filename=att[0])
    return bytes(m)


def test_registrable_handles_indian_suffixes():
    assert registrable("www.sbi.co.in") == "sbi.co.in"
    assert registrable("a.b.hdfcbank.com") == "hdfcbank.com"


def test_lookalikes():
    assert lookalike("sbi.co.in") is None and lookalike("netbanking.hdfcbank.com") is None
    assert lookalike("hdfcbank-kyc.site")["brand"] == "hdfcbank"
    assert "typosquat" in lookalike("icicbank.info")["reason"]
    assert "homoglyph" in lookalike("paytrn.in")["reason"]          # rn -> m
    assert "punycode" in lookalike("xn--sb-ihp.com")["reason"]
    assert lookalike("github.com") is None
    assert levenshtein("kitten", "sitting") == 3


def test_url_heuristics():
    ids = {r for r, _, _ in url_findings("http://192.0.2.5/login")}
    assert {"URL_IP_HOST", "URL_NO_TLS", "URL_CRED_KEYWORDS"} <= ids
    assert "URL_USERINFO" in {r for r, _, _ in url_findings("https://www.sbi.co.in@evil.top/")}
    assert "UPI_DEEPLINK" in {r for r, _, _ in url_findings("upi://pay?pa=x@ybl&am=999")}
    assert "ANCHOR_MISMATCH" in {r for r, _, _ in url_findings("https://evil.top/x", "www.onlinesbi.sbi")}


def test_india_lures_and_negation():
    ids = {r for r, _, _ in match_lures("Approve the collect request and enter UPI PIN to receive money from a1b2c@ybl")}
    assert {"IN_UPI_PIN", "IN_UPI_RECEIVE", "IN_VPA_IN_BODY"} <= ids
    assert "IN_UPI_PIN" not in {r for r, _, _ in match_lures("Never share your OTP or UPI PIN with anyone.")}
    assert "IN_HINGLISH_URGENCY" in {r for r, _, _ in match_lures("aapka account band ho jayega")}


def test_phish_vs_legit_end_to_end():
    bad = analyze_bytes(mail("SBI <a@sbi-kyc-update.top>", "KYC pending", "Your KYC is pending, account will be blocked. https://sbi-kyc-update.top/kyc",
                             ar="spf=softfail; dkim=none; dmarc=fail"))
    good = analyze_bytes(mail("HDFC Bank <alerts@hdfcbank.com>", "Txn alert", "Rs 500 debited. Never share your OTP.",
                              ar="spf=pass smtp.mailfrom=hdfcbank.com; dkim=pass header.d=hdfcbank.com; dmarc=pass"))
    assert bad["verdict"] == "phishing" and good["verdict"] == "clean"


def test_attachment_hashed_and_flagged():
    r = analyze_bytes(mail("x <a@b.example>", "inv", "see attached", att=("inv.pdf.exe", b"LAB")))
    import hashlib; assert r["attachments"][0]["sha256"] == hashlib.sha256(b"LAB").hexdigest()
    assert {"ATT_RISKY_EXT", "ATT_DOUBLE_EXT"} <= {f["rule"] for f in r["findings"]}


def test_report_markdown_and_json_serialisable():
    r = analyze_bytes(mail("x <a@b.example>", "hi", "hello"), "t.eml")
    assert "## Why" in to_markdown(r)
    json.dumps(r)


def test_eval_on_lab_corpus_meets_floor():
    m = evaluate(ROOT / "data/samples", ROOT / "data/labels.csv")
    assert m["n"] == 69 and m["recall"] >= 0.8 and m["precision"] >= 0.85
