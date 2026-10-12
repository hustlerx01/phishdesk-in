"""Indian bank / UPI phishing lure rules. Patterns derived from public advisories:
RBI 'BE(A)WARE' booklet, CERT-In phishing advisories, NPCI UPI safety guidance, I4C/cybercrime.gov.in.
Each rule: (id, weight, regex, explanation)."""
import re

RULES = [
    ("IN_KYC_BLOCK", 25, r"\b(re-?)?kyc\b.{0,80}\b(block|suspend|expire|deactivat|freez|band|update|pending)", "KYC-expiry / account-block lure (RBI BE(A)WARE: 'KYC update' fraud)"),
    ("IN_PAN_AADHAAR", 15, r"\b(pan|aadhaa?r)\b.{0,60}\b(link|seed|update|verify|deactivat|block)", "PAN/Aadhaar linking lure"),
    ("IN_UPI_PIN", 35, r"\b(enter|share|type)\b.{0,40}\b(upi\s*pin|mpin|otp|cvv)\b", "asks to enter/share UPI PIN/OTP/CVV (NPCI: PIN is never needed to receive money)"),
    ("IN_UPI_RECEIVE", 25, r"\b(collect request|receive (?:the )?(?:money|amount|refund|cashback)|approve the request)\b", "'approve collect request to receive money' UPI lure"),
    ("IN_TAX_REFUND", 20, r"\b(income\s*tax|it department|itr)\b.{0,80}\brefund", "income-tax refund lure"),
    ("IN_BILL_DISCONNECT", 20, r"\b(electricity|bijli|power)\b.{0,80}\b(disconnect|cut|kat)", "electricity disconnection lure"),
    ("IN_REWARD", 15, r"\b(reward points?|cashback|kbc|lottery|lucky draw|prize)\b.{0,60}\b(redeem|claim|won|expire)", "reward/lottery lure"),
    ("IN_COURIER_CUSTOMS", 15, r"\b(india post|courier|parcel|customs|fedex)\b.{0,80}\b(held|fee|pay|redeliver)", "parcel/customs fee lure"),
    ("IN_REMOTE_APP", 30, r"\b(anydesk|teamviewer|quicksupport|rustdesk|\.apk)\b", "asks to install remote-access app / APK"),
    ("IN_HINGLISH_URGENCY", 10, r"\b(turant|abhi|band ho jayega|aapka (?:khata|account)|24 ghante)\b", "Hinglish urgency phrasing"),
    ("IN_DIGITAL_ARREST", 30, r"\b(digital arrest|cbi|narcotics|money laundering)\b.{0,80}\b(case|warrant|arrest|verify)", "'digital arrest' impersonation scam (I4C advisory)"),
    ("URGENCY", 10, r"\b(within 24 hours|immediately|urgent|final notice|last chance|today itself)\b", "generic urgency"),
]
_COMPILED = [(i, w, re.compile(p, re.I | re.S), e) for i, w, p, e in RULES]
VPA_RE = re.compile(r"\b[\w.-]{3,}@(?:ok\w+|ybl|ibl|axl|paytm|upi|apl|ptyes|ptsbi|ptaxis)\b", re.I)


NEGATION = re.compile(r"\b(never|do not|don't|dont|will not|won't|not)\b[^.]{0,25}$", re.I)


def _positive_match(rx, text):
    """True if rx matches somewhere NOT preceded by a negation ('never share your OTP' is advice, not a lure)."""
    for m in rx.finditer(text):
        if not NEGATION.search(text[max(0, m.start() - 40):m.start()]):
            return True
    return False


def match_lures(text: str) -> list[tuple[str, int, str]]:
    hits = [(i, w, e) for i, w, rx, e in _COMPILED if _positive_match(rx, text)]
    if VPA_RE.search(text):
        hits.append(("IN_VPA_IN_BODY", 10, f"UPI VPA in body ({VPA_RE.search(text).group(0)})"))
    return hits
