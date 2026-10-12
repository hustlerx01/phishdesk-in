# Interview talking points: PhishDesk-IN

1. **Header walk-through.** I read `Authentication-Results` for SPF, DKIM and DMARC, then check *alignment*. SPF can pass for `attacker.top` while the From says SBI. DMARC is the control that ties the visible From to an authenticated domain. Reply-To mismatch is the classic BEC signal.
2. **Why "DMARC pass" doesn't mean safe.** My 4 compromised-account samples pass everything and still score 0. Authentication proves *who sent* the mail, not *whether it's malicious*. That's why URL detonation and behavioural baselines exist.
3. **Lookalike detection.** Registrable domain (handling `.co.in`), then normalise homoglyphs (`0→o`, `1→l`, `rn→m`), then Levenshtein ≤1–2 against brand labels, brand embedded in an unrelated domain (`hdfcbank-kyc.site`), and punycode `xn--`. Example: `paytrn.in` becomes `paytm`.
4. **India-specific content.** KYC block, UPI collect "approve to receive", "enter UPI PIN", IT refund, bijli disconnection, India Post fee, AnyDesk/APK, digital arrest, and Hinglish urgency. Each one cites the RBI/NPCI/I4C advisory it came from.
5. **The false-positive trap I fixed.** Real bank alerts say "never share your OTP/UPI PIN". A naive regex flags them, so the rules are negation-aware and there's a regression test for it.
6. **Explainability.** Every point of the score maps to a rule with a reason and an IOC, so an L1 analyst can defend the verdict, and the JSON drops straight into SOAR or a ticket.
7. **Honest metrics.** P 0.909 / R 0.833 / F1 0.87 / FPR 0.091 on 69 lab mails. All 9 errors are the hard cases I designed: BEC (needs detonation), quishing (needs QR decode) and mailing lists (need ARC). I can name the next fix for each.
8. **Safety.** The parser never renders HTML or opens attachments; it only hashes them. Lab corpus uses doc-range IPs, `.example` domains for "real" senders and an `X-Lab-Data` header.
9. **Next steps.** urlscan.io/VirusTotal enrichment by URL and sha256, full PSL via tldextract, ARC, pyzbar QR decode, a held-out real-world eval set, and an Outlook "Report phish" add-in mock that posts to this API.
