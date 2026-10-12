"""Parse a raw .eml into a plain dict: headers, bodies, URLs, attachments (hashed, never executed)."""
from __future__ import annotations
import email, hashlib, re
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]+|upi://[^\s<>"']+)""")


class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors, self.text, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._buf = dict(attrs).get("href"), []

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def domain_of(addr: str) -> str:
    _, a = parseaddr(addr or "")
    return a.rsplit("@", 1)[-1].lower().strip(">") if "@" in a else ""


def parse_eml(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)
    text_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fn = part.get_filename()
        ctype = part.get_content_type()
        if fn or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": fn or "(unnamed)", "content_type": ctype, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
            })
        elif ctype == "text/plain":
            text_parts.append(part.get_content())
        elif ctype == "text/html":
            html_parts.append(part.get_content())
    anchors, html_text = [], []
    for h in html_parts:
        p = _AnchorParser(); p.feed(h)
        anchors += p.anchors; html_text += p.text
    body = "\n".join(text_parts + [" ".join(html_text)])
    urls = []
    for u in URL_RE.findall(body) + [a[0] for a in anchors if a[0]]:
        u = u.rstrip(".,;")
        if u not in urls and not u.lower().startswith("mailto:"):
            urls.append(u)
    hdr = lambda k: str(msg.get(k, "") or "")
    return {
        "subject": hdr("Subject"), "from": hdr("From"), "from_domain": domain_of(hdr("From")),
        "display_name": parseaddr(hdr("From"))[0],
        "reply_to_domain": domain_of(hdr("Reply-To")), "return_path_domain": domain_of(hdr("Return-Path")),
        "auth_results": msg.get_all("Authentication-Results") or [],
        "received_spf": hdr("Received-SPF"), "dkim_signature": hdr("DKIM-Signature"),
        "received": msg.get_all("Received") or [], "body": body, "urls": urls,
        "anchors": anchors, "attachments": attachments,
    }
