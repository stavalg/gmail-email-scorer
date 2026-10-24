# Demo emails

Send these from a second account to the demo Gmail account before the demo.
Links are never visited by the tool; the addresses below don't need to exist.

## 1. Safe
- Sender name: your real name
- Subject: `Lunch on Thursday?`
- Body: `Hi! Are we still on for lunch on Thursday? Let me know.`
- Expected: 🟢 SAFE · 0, "Sender verified: gmail[.]com (DMARC/SPF/DKIM passed)."

## 2. Suspicious
- Sender name: `Rewards Team`
- Subject: `Action required: verify your account to keep your points`
- Body: `Your reward points expire soon.` + a link with text `Claim now` to `https://bit.ly/3xYzAbc`
- Expected: 🟠 SUSPICIOUS · 35 (urgency 10 + credential request 15 + shortener 10)

## 3. Malicious-looking
- Sender name: `PayPal Support`
- Subject: `Urgent: your account will be suspended`
- Body: `We noticed unusual activity. Please verify your password within 24 hours.` + a link with
  text `www.paypal.com` to `http://paypal.com.account-check.xyz/login`
- Attachment: a file named `login.html` containing `<p>test</p>`
- Expected: 🔴 MALICIOUS · 100 (brand in sender name, brand hidden in link, link text mismatch,
  abused ending, urgency, credential request, HTML attachment)

## Shown with a sample request (Gmail blocks these as real attachments)

```bash
cd backend
DEV_SKIP_AUTH=true .venv/bin/python -m uvicorn app.main:app --port 8080
curl -s -X POST localhost:8080/v1/analyze -H "content-type: application/json" --data @samples/phishing.json
```

- `samples/phishing.json` — lookalike `paypa1.com`, DMARC fail, double extension `invoice.pdf.exe` → 100
- `samples/safe.json` — ordinary email → 0
