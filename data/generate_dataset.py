"""Generate the labelled SYNTHETIC lab corpus (data/samples/*.eml + data/labels.csv).

LAB DATA ONLY. Every email is fabricated. Lure wording is paraphrased from public advisories
(RBI BE(A)WARE, CERT-In, NPCI, I4C) — see README 'Sources'. Attacker domains are fictitious
lookalikes; IPs are RFC 5737 documentation ranges; people/accounts are invented.
Seeded => byte-for-byte reproducible (CI checks for drift).
"""
import csv, random
from email.message import EmailMessage
from pathlib import Path

R = random.Random(20261011)
OUT = Path(__file__).parent / "samples"
NAMES = ["Rahul Patil", "Priya Nair", "Amit Verma", "Sneha Kulkarni", "Imran Khan", "Kavya Iyer", "Rohan Mehta", "Fatima Shaikh", "Arjun Reddy", "Neha Joshi"]
DOC_IPS = ["192.0.2.", "198.51.100.", "203.0.113."]
rows = []


def ip():
    return R.choice(DOC_IPS) + str(R.randint(2, 250))


def auth(spf, dkim, dmarc, from_dom, dkim_d=None, mailfrom=None):
    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "from_dom": from_dom, "dkim_d": dkim_d or from_dom, "mailfrom": mailfrom or from_dom}


def build(fname, label, cat, note, frm, subject, text, a, html=None, reply_to=None, attachments=()):
    m = EmailMessage()
    m["Return-Path"] = f"<bounce@{a['mailfrom']}>"
    m["Received"] = f"from mail.{a['mailfrom']} ({ip()}) by mx.lab-corp.example with ESMTPS; Sat, 10 Oct 2026 {R.randint(0,23):02d}:{R.randint(0,59):02d}:00 +0530"
    m["Authentication-Results"] = (f"mx.lab-corp.example; spf={a['spf']} smtp.mailfrom={a['mailfrom']}; "
                                   f"dkim={a['dkim']} header.d={a['dkim_d']}; dmarc={a['dmarc']} header.from={a['from_dom']}")
    if a["dkim"] != "none":
        m["DKIM-Signature"] = f"v=1; a=rsa-sha256; d={a['dkim_d']}; s=sel1; h=from:subject; bh=LAB; b=LAB"
    m["From"] = frm
    m["To"] = f"{R.choice(NAMES)} <user{R.randint(1,99)}@lab-corp.example>"
    if reply_to:
        m["Reply-To"] = reply_to
    m["Subject"] = subject
    m["Date"] = "Sat, 10 Oct 2026 10:00:00 +0530"
    m["Message-ID"] = f"<{R.getrandbits(64):x}@{a['from_dom']}>"
    m["X-Lab-Data"] = "synthetic - PhishDesk-IN corpus - not real mail"
    m.set_content(text)
    if html:
        m.add_alternative(html, subtype="html")
    for fn, ctype, data in attachments:
        mt, st = ctype.split("/")
        m.add_attachment(data, maintype=mt, subtype=st, filename=fn)
    (OUT / fname).write_bytes(bytes(m))
    rows.append({"file": fname, "label": label, "category": cat, "note": note})


def amt():
    return f"{R.randint(1, 99)},{R.randint(100, 999)}"


def main():
    random.seed(7)  # email.generator uses the global RNG for MIME boundaries
    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob("*.eml"):
        f.unlink()
    n = 0
    def nm(prefix):
        nonlocal n; n += 1; return f"{n:03d}_{prefix}.eml"

    # ---------------- PHISHING ----------------
    for d in ["sbi-kyc-update.top", "onlinesbi-verify.xyz", "sbl-netbanking.online", "hdfcbank-kyc.site", "icicbank.info", "axisbank-alerts.click"]:
        name = R.choice(NAMES)
        url = f"https://{d}/kyc/login?id={R.getrandbits(24):x}"
        brand = "SBI" if "sb" in d else "HDFC Bank" if "hdfc" in d else "ICICI Bank" if "icic" in d else "Axis Bank"
        build(nm("kyc"), "phishing", "kyc_lure", f"lookalike {d}", f"{brand} Alerts <alerts@{d}>",
              f"Your {brand} account will be blocked - KYC pending", 
              f"Dear {name},\nYour KYC is pending and your account will be blocked within 24 hours. Update KYC now: {url}\nAapka account band ho jayega.\n",
              auth(R.choice(["fail", "softfail", "pass"]), "none", "fail" if R.random() < .5 else "none", d),
              html=f'<p>Dear customer, update KYC: <a href="{url}">https://www.onlinesbi.sbi/kyc</a></p>')
    for d in ["paytm-cashback.xyz", "phonepe-rewards.top", "paytrn.in", "bhim-upi-refund.site", "gpay-offers.live"]:
        vpa = f"refund{R.randint(10,99)}@ybl"
        build(nm("upi"), "phishing", "upi_lure", f"UPI collect/PIN lure {d}", f"Cashback Team <noreply@{d}>",
              f"Rs {amt()} cashback credited - approve to receive",
              f"Congratulations! You won cashback. To receive the money, approve the collect request from {vpa} and enter UPI PIN.\n"
              f"Pay link: upi://pay?pa={vpa}&pn=Refund&am={R.randint(1,9)}999\nClaim before it expires: https://{d}/claim\n",
              auth("pass", "pass", "none", d))
    for d in ["lncometax-refund.top", "incometax-gov.info", "itr-refund-portal.xyz", "incometaxx.in"]:
        build(nm("tax"), "phishing", "tax_lure", f"IT refund lure {d}", f"Income Tax Department <refund@{d}>",
              "Income Tax Refund of Rs " + amt() + " approved",
              f"Your Income Tax refund of Rs {amt()} is approved. Verify your PAN and bank details to receive the refund: http://{d}/refund\n",
              auth(R.choice(["softfail", "none"]), "none", "none", d), reply_to=f"itrefund{R.randint(1,9)}@gmail.com")
    for i in range(4):
        num = f"9{R.randint(100000000, 999999999)}"
        build(nm("bijli"), "phishing", "bill_lure", "electricity disconnection, freemail sender",
              f"MSEDCL Bijli Vibhag <bijli.office{i}@gmail.com>", "Electricity connection will be disconnected tonight",
              f"Dear consumer, your electricity power will be disconnected tonight at 9.30 pm because previous month bill was not updated. "
              f"Contact electricity officer immediately on {num}. Install AnyDesk for bill verification.\n",
              auth("pass", "pass", "none", "gmail.com", mailfrom="gmail.com"))
    for d in ["indiapost-redelivery.top", "lndiapost.in", "indiapost-track.cyou", "parcel-customs-in.xyz"]:
        build(nm("courier"), "phishing", "courier_lure", f"courier fee + HTML attachment {d}", f"India Post <track@{d}>",
              "Your parcel is held - pay redelivery fee",
              f"Your parcel is held at the hub due to incomplete address. Pay Rs 25 redelivery fee within 24 hours at https://{d}/pay or open the attached form.\n",
              auth("softfail", "none", "none", d),
              attachments=[("Redelivery_Form.html", "text/html", f"<form action='https://{d}/pay'>LAB</form>".encode())])
    for ext in ["Invoice_Oct.pdf.exe", "Salary_Slip.pdf.scr", "PO_45781.docm"]:
        d = R.choice(["vendor-billing.icu", "payroll-hr.buzz", "tenders-gov.online"])
        build(nm("malatt"), "phishing", "malware_attachment", f"risky attachment {ext}", f"Accounts <accounts@{d}>",
              "Pending payment - invoice attached", "Dear Sir/Madam,\nPlease find attached invoice. Kindly process urgent payment today itself.\n",
              auth("fail", "none", "none", d), attachments=[(ext, "application/octet-stream", b"LAB-DUMMY-NOT-MALWARE-" + ext.encode())])
    for i in range(2):
        d = R.choice(["cbi-gov-in.site", "ncb-cyber.top"])
        build(nm("arrest"), "phishing", "digital_arrest", "digital arrest impersonation", f"CBI Cyber Cell <officer@{d}>",
              "Notice: money laundering case registered against your Aadhaar",
              f"Your Aadhaar is linked to a money laundering case. A warrant is issued. Join video call for verification immediately or face digital arrest. Case file: https://{d}/case\n",
              auth("none", "none", "none", d))
    for host in ["xn--sb-ihp.com", "xn--hdfcbnk-4wa.com"]:
        build(nm("idn"), "phishing", "idn_homograph", f"punycode {host}", f"NetBanking <secure@{host}>",
              "Unusual sign-in to your NetBanking", f"We noticed an unusual sign-in. Review it: https://{host}/review\n",
              auth("pass", "pass", "pass", host))
    # Hard phishing: compromised legit accounts (auth passes, aligned) + generic lure, no Indian keywords
    for d in ["sharma-traders.example", "pune-dental.example", "greenleaf-ngo.example", "techfab-pvt.example"]:
        build(nm("bec"), "phishing", "hard_compromised_account", f"HARD: compromised real account {d}, DMARC pass, shortener",
              f"{R.choice(NAMES)} <accounts@{d}>", "Shared document: Q3 payment details",
              f"Hi,\nI have shared the Q3 payment details with you. View document: https://bit.ly/{R.getrandbits(30):x}\nRegards\n",
              auth("pass", "pass", "pass", d))
    # Hard phishing: QR-code only (quishing) — URL lives inside an image the analyser does not decode
    for i in range(2):
        d = R.choice(["hr-portal-update.example", "benefits-desk.example"])
        build(nm("qr"), "phishing", "hard_quishing", "HARD: QR image only, no text URL",
              f"HR Desk <hr@{d}>", "Action required: annual benefits enrolment",
              "Scan the attached code with your phone to complete enrolment.\n", auth("pass", "pass", "pass", d),
              attachments=[("enrol.png", "image/png", b"\x89PNG\r\n\x1a\nLAB-QR-PLACEHOLDER")])

    # ---------------- LEGITIMATE ----------------
    bank_doms = [("HDFC Bank", "hdfcbank.com"), ("ICICI Bank", "icicibank.com"), ("Axis Bank", "axisbank.com"), ("SBI", "sbi.co.in")]
    for i in range(8):
        b, d = bank_doms[i % 4]
        build(nm("txn"), "legit", "bank_txn_alert", "real bank alert with safety advice", f"{b} <alerts@{d}>",
              f"Transaction alert: Rs {amt()} debited",
              f"Dear Customer, Rs {amt()} has been debited from account XX{R.randint(1000,9999)} via UPI. "
              "If not done by you, call the number on the back of your card. Never share your OTP, UPI PIN or CVV with anyone.\n",
              auth("pass", "pass", "pass", d))
    for i in range(4):
        b, d = bank_doms[i]
        build(nm("kycok"), "legit", "bank_kyc_reminder", "legit periodic KYC reminder, aligned DMARC", f"{b} <service@{d}>",
              "Periodic KYC update reminder",
              f"Dear Customer, as per RBI guidelines your periodic KYC update is pending. Please visit your home branch or update via the official app/website https://www.{d}/. "
              "We do not ask for passwords or OTP over email.\n", auth("pass", "pass", "pass", d))
    for d in ["mailer.flipkart.example", "news.zomato.example", "offers.myntra.example", "updates.nykaa.example", "promo.swiggy.example"]:
        build(nm("mkt"), "legit", "marketing", "marketing with shortened tracking link", f"Offers <offers@{d}>",
              "Festive sale: up to 70% off",
              f"Big festive sale is live. Shop now: http://bit.ly/{R.getrandbits(30):x} Unsubscribe: https://{d}/unsub\n",
              auth("pass", "pass", "pass", d))
    for s, t in [("Team lunch on Friday", "Hi all, team lunch Friday 1pm at the cafeteria."),
                 ("Q3 report v1", "Report attached, please review by Monday."),
                 ("Server patching window", "Patching prod-web-01..04 on Sunday 2-4 AM IST. Change ticket CHG-1042."),
                 ("Leave approval", "Your leave for 20-22 Oct is approved."),
                 ("Wi-Fi password rotated", "Guest Wi-Fi password rotated; collect from front desk, not by email."),
                 ("Security awareness training", "Complete the phishing awareness module on the LMS by 31 Oct.")]:
        atts = [("Q3_report_v1.pdf", "application/pdf", b"%PDF-1.4 LAB")] if "report" in s else []
        build(nm("internal"), "legit", "internal", "internal mail", f"{R.choice(NAMES)} <it@lab-corp.example>", s, t + "\n",
              auth("pass", "pass", "pass", "lab-corp.example"), attachments=atts)
    for i in range(2):
        build(nm("itd"), "legit", "gov_notice", "real IT dept refund notice", "Income Tax Department <donotreply@incometax.gov.in>",
              "Intimation u/s 143(1): refund determined", f"Your ITR for AY 2026-27 is processed and a refund of Rs {amt()} will be credited to your pre-validated bank account. Login at https://www.incometax.gov.in to view.\n",
              auth("pass", "pass", "pass", "incometax.gov.in"))
    build(nm("amzn"), "legit", "ecommerce", "reward points reminder from real Amazon", "Amazon.in <store-news@amazon.in>",
          "Your reward points expire soon", "You have 1,250 reward points. Redeem them before they expire on 31 Oct at https://www.amazon.in/rewards\n",
          auth("pass", "pass", "pass", "amazon.in"))
    build(nm("shop"), "legit", "ecommerce", "small D2C brand on .shop TLD", "Chai Co <hello@chaico.shop>",
          "Last chance: Diwali hampers", "Last chance to order Diwali hampers: https://chaico.shop/diwali\n", auth("pass", "pass", "pass", "chaico.shop"))
    # Hard legit: mailing-list forwarding breaks SPF/DKIM -> DMARC fail
    for i in range(3):
        build(nm("list"), "legit", "hard_mailing_list", "HARD: forwarded via mailing list, DMARC fails",
              f"{R.choice(NAMES)} <member{i}@partner-uni.example>", f"[owasp-pune] Meetup {i+1} slides",
              "Slides from the last OWASP Pune chapter meetup are on the chapter page.\n",
              auth("fail", "fail", "fail", "partner-uni.example", mailfrom="lists.owasp-pune.example"))
    for i in range(3):
        build(nm("vendor"), "legit", "vendor", "known vendor invoice, PDF", f"Billing <billing@cloudhost.example>",
              f"Invoice INV-{R.randint(1000,9999)} for October", "Hi, your monthly invoice is attached. Auto-debit on 5 Nov.\n",
              auth("pass", "pass", "pass", "cloudhost.example"), attachments=[("invoice.pdf", "application/pdf", b"%PDF-1.4 LAB INVOICE")])

    with open(Path(__file__).parent / "labels.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["file", "label", "category", "note"]); w.writeheader(); w.writerows(rows)
    print(f"wrote {len(rows)} emails: {sum(r['label']=='phishing' for r in rows)} phishing / {sum(r['label']=='legit' for r in rows)} legit")


if __name__ == "__main__":
    main()
