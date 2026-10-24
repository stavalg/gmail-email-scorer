# Gmail Malicious Email Scorer — Design Spec

**Date:** 2026-10-23
**Status:** Draft, awaiting review
**Time budget:** ~15 hours (≈4–5h on day 1, ≈10h on day 2)

---

## 1. Goal

A Gmail Add-on that, when the user opens an email and clicks **Analyze**, shows a
**maliciousness score (0–100)**, a **verdict** (Safe / Suspicious / Malicious), the
**reasons** behind it, and **what the user should do**. A Python backend performs the
analysis.

Evaluation criteria from the assignment, and where this design addresses them:

| Criterion | Addressed by |
|---|---|
| Product thinking | On-demand analysis, actionable advice, honest coverage (§6) |
| Creativity | Evidence-based reasons, "What should I do?", dual audience card, layered analyzers (§4, §6) |
| Architecture | Thin add-on / smart backend, pluggable analyzers, graceful degradation (§3) |
| Code quality | Small focused modules, typed models, unit tests, pinned deps (§8, §9) |
| Security awareness | Identity-token auth, least privilege, untrusted-input handling, no stored data (§5) |
| Communication | README, architecture diagram, decision log (§10, §11) |

## 2. Constraints and decisions already made

| Decision | Choice | Reason |
|---|---|---|
| Add-on platform | Google Apps Script + CardService | Required (Google Workspace APIs) |
| Backend language | Python | Readable, standard in security, good parsing libraries |
| Backend hosting | Google Cloud Run (fallback: laptop + tunnel) | Same ecosystem, free tier, Secret Manager |
| Add-on → backend auth | Google OpenID Connect identity token + email allowlist | No shared secret to leak; free |
| Demo account | Personal `@gmail.com` | Avoids Workspace admin restrictions |
| Cost | $0 — every service stays within free tier; $1 budget alert as a safety net | Personal project |
| Analysis layers | Rules (required) → VirusTotal (if time) → LLM (if time) | Each layer ships independently |

## 3. Architecture

```
┌────────────────────────────┐  HTTPS POST /v1/analyze      ┌──────────────────────────────────┐
│ Gmail Add-on (Apps Script) │  Authorization: Bearer <ID>  │ Backend (Python, Cloud Run)      │
│                            │ ───────────────────────────▶ │                                  │
│ 1. Show "Analyze" card     │   minimal email data (JSON)  │ auth.py   verify Google ID token │
│ 2. Collect email data      │                              │ models.py validate + size limits │
│ 3. Hash attachments        │                              │ analyzers/                       │
│ 4. Call backend            │ ◀─────────────────────────── │   rules/*  (always)              │
│ 5. Render result (escaped) │   score, verdict, findings,  │   virustotal (optional, parallel)│
└────────────────────────────┘   advice, coverage           │   llm        (optional, parallel)│
                                                            │ scoring.py combine → verdict     │
                                                            └───────────┬──────────────────────┘
                                                                        │ domain + hash lookups /
                                                                        ▼ trimmed text
                                                            VirusTotal API     Gemini API
                                                            (keys in Google Secret Manager)
```

**Split of responsibilities**

- **Add-on (thin):** UI, collecting the minimum data, hashing attachments locally, calling the
  backend, escaping and rendering the response. No analysis logic, no secrets.
- **Backend (smart):** authentication, validation, all parsing and analysis, scoring.
  Stateless — stores nothing.

**Why:** Apps Script is limited and hard to test; Python is easy to test and extend; secrets
stay server-side; analyzers can be added without touching the add-on.

### 3.1 Analyzer interface

Every analyzer is independent and returns the same shape:

```
AnalyzerResult:
  name:     "rules" | "virustotal" | "llm"
  status:   "ok" | "skipped" | "error" | "timeout"
  findings: list[Finding]
  facts:    list[str]          # positive information, never affects score
  details:  dict               # technical data for the analyst section

Finding:
  id:       str     # e.g. "lookalike_domain"
  category: "authentication" | "sender" | "links" | "content" | "attachments" | "reputation" | "ai"
  title:    str     # "Lookalike domain"
  evidence: str     # "\"paypa1.com\" imitates paypal.com"
  points:   int
```

The scorer only sees `AnalyzerResult`s, so adding or removing an analyzer never changes the
scorer. A failed analyzer reports `status: error` and the response says so (graceful
degradation).

### 3.2 Request flow and time budget

1. User opens an email → contextual trigger shows the "Analyze" card (nothing is sent).
2. User clicks **Analyze** → add-on collects data, gets an ID token, calls the backend.
3. Backend verifies the token, validates input, runs the rules analyzer, then runs VirusTotal and
   LLM **in parallel** with a ~5s timeout each and a **~15s total budget**.
4. Scorer combines results → response.
5. Add-on renders the result card. Gmail's add-on limit is ~30s, so 15s leaves margin.

## 4. Analysis and scoring

### 4.1 Input the backend receives

| Field | Source in add-on | Limit |
|---|---|---|
| `headers_raw` | Header block of `message.getRawContent()` (text before the first blank line) | 64 KB |
| `body_html` | `message.getBody()` | 100 KB (truncated) |
| `body_text` | `message.getPlainBody()` | 100 KB (truncated) |
| `attachments[]` | `name`, `content_type`, `size`, `sha256` (only if size ≤ 10 MB) | 50 items |

The backend parses headers (From, Reply-To, Authentication-Results) with Python's `email`
module and extracts links from the HTML itself, so all parsing logic lives in testable Python.
Links: at most 200 processed.

### 4.2 Rules analyzer — signals

Each signal counts **once** per email, however many times it occurs; the evidence text mentions
the count. Points are configured in one file (`config.py` / weights table).

| Category | Signal | Points |
|---|---|---|
| Authentication | DMARC fail | +30 |
| | SPF fail | +15 |
| | DKIM fail | +15 |
| Sender | Display name contains a known brand, sender domain is not that brand | +25 |
| | Lookalike domain of a known brand (homoglyph normalization + edit distance) | +30 |
| | Display name contains an email address different from the real sender | +30 |
| | Reply-To domain differs from From domain | +15 |
| Links | Visible link text is a URL/domain, actual destination is a different domain | +25 |
| | Link to a raw IP address | +20 |
| | Punycode / mixed-script domain | +25 |
| | Brand name in a subdomain of a non-brand domain (`paypal.com.x.xyz`) | +30 |
| | URL shortener | +10 |
| | Commonly abused TLD (`.zip .top .xyz .click …`) | +10 |
| Content | Urgency / threat language | +10 |
| | Requests credentials or payment details | +15 |
| Attachments | Double extension (`invoice.pdf.exe`) | +60 |
| | Executable/script type (`.exe .scr .js .vbs .bat .cmd .ps1 .hta .lnk .msi .iso .img .one`) | +40 |
| | HTML attachment (`.html .htm`) | +30 |
| | Macro-enabled Office file (`.docm .xlsm .pptm`) | +20 |
| | Archive (`.zip .rar .7z`) | +15 |
| | Archive **and** body mentions a password | +30 (replaces +15) |

**Rules for trustworthy parsing**

- Only the `Authentication-Results` header added by `mx.google.com` (the topmost one) is trusted;
  any others are attacker-controlled and ignored.
- If no trusted authentication header exists, authentication signals are skipped (not penalized).
- Links are analyzed as text only — never fetched.
- Domains are split with a bundled Public Suffix List snapshot (no network fetch at runtime).

### 4.3 Optional analyzers

**VirusTotal** (free API: 4 requests/min, 500/day)

- Look up **domains** and **attachment hashes** only — never full URLs (they may contain private
  tokens) and never file contents.
- At most 3 lookups per email, priority: attachment hashes → most suspicious domains. Skip a small
  allowlist of very common domains (google.com, etc.).
- Known malicious (≥ 2 engines flag it) → finding +50 and a **score floor of 90**.
- Coverage shown as "VirusTotal: 3 of 10 checked".

**LLM** (Gemini, free tier)

- Input: subject + trimmed plain body (≤ 4,000 chars), wrapped in clear delimiters and labelled as
  untrusted data. The system instruction says to ignore any instructions inside the email.
- Output must be strict JSON: `{"phishing_likelihood": 0-100, "reason": "<≤200 chars>"}`;
  anything else is rejected (status `error`).
- Contribution: `round(likelihood / 100 * 25)`, i.e. **max +25**. The LLM can only add points,
  never lower the score, and cannot decide a verdict alone (prompt-injection defense).
- Privacy trade-off: free-tier data may be used by Google; documented in the README.

### 4.4 Scoring

1. `score = min(100, sum(points of all findings))`
2. If VirusTotal confirms something malicious: `score = max(score, 90)`
3. Verdict: **0–29 Safe**, **30–69 Suspicious**, **70–100 Malicious**
4. Positive facts (e.g. "DMARC passed") are shown but **never reduce** the score — anything the
   attacker controls must not be able to lower risk.

### 4.5 Response returned to the add-on

```json
{
  "score": 85,
  "verdict": "malicious",
  "summary": "This email shows strong signs of a phishing attempt.",
  "advice": ["Don't click links or open attachments.", "..."],
  "findings": [{"id": "...", "category": "...", "title": "...", "evidence": "...", "points": 30}],
  "facts": ["Sender passed SPF/DKIM for paypa1.com (not PayPal)"],
  "coverage": {
    "rules": {"status": "ok"},
    "virustotal": {"status": "ok", "checked": 3, "total": 5},
    "llm": {"status": "timeout"}
  },
  "details": {"from_domain": "...", "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "fail"}, "attachment_hashes": ["..."]}
}
```

Findings are sorted by points, highest first. Advice text is chosen by verdict on the backend.

## 5. Security design

### 5.1 Authentication (add-on → backend)

- Add-on calls `ScriptApp.getIdentityToken()` (requires the `openid` scope) and sends it as
  `Authorization: Bearer <token>`.
- Backend verifies it with `google.oauth2.id_token.verify_oauth2_token`: Google signature,
  issuer, expiry, **audience** = the Apps Script project's OAuth client ID (env var), and
  `email_verified` + email in `ALLOWED_EMAILS` (env var).
- Cloud Run service allows unauthenticated *network* access; authentication is enforced in the
  application (Cloud Run IAM cannot validate Apps Script-issued tokens for our audience).
- Fallback if setup fails: shared API key in Script Properties / Secret Manager, compared in
  constant time.

### 5.2 Least-privilege scopes (`appsscript.json`)

- `https://www.googleapis.com/auth/gmail.addons.execute`
- `https://www.googleapis.com/auth/gmail.addons.current.message.readonly`
- `https://www.googleapis.com/auth/script.external_request`
- `https://www.googleapis.com/auth/userinfo.email`, `openid`
- `urlFetchWhitelist` restricted to the backend URL.

No mailbox-wide read, no modify scopes.

### 5.3 Untrusted input

| Threat | Defense |
|---|---|
| Oversized input | Strict Pydantic models, size limits (§4.1), unknown fields rejected, request body cap |
| Following malicious links | Links are never fetched |
| Malicious attachments | Content never leaves Gmail; only metadata + SHA-256 |
| Malicious HTML | Parsed with the stdlib `html.parser` as text; nothing executed or rendered |
| Forged auth headers | Only trust the `mx.google.com` header (§4.2) |
| Injection into our own card | All email-derived strings HTML-escaped in the add-on before rendering |
| Hostile external responses | Timeouts, JSON schema validation, numeric clamping |
| LLM prompt injection | Delimited data, strict JSON output, capped additive contribution |

### 5.4 Secrets

- VirusTotal / Gemini keys in **Google Secret Manager**, injected as env vars into Cloud Run.
- Never in code, Git, or logs. `.gitignore` covers `.env`, `.clasp.json` credentials etc.;
  `.env.example` documents required variables with fake values.

### 5.5 Privacy

- On-demand: nothing leaves Gmail until the user clicks Analyze.
- Stateless backend; no database.
- Logs contain request ID, duration, verdict, analyzer statuses — never content or addresses.
- Third parties receive the minimum (domains/hashes to VirusTotal; trimmed text to the LLM).

### 5.6 Abuse, cost, errors

- Cloud Run `max-instances` = 2; budget alert at $1; old container images deleted.
- Generic error messages to clients; no stack traces.
- Pinned dependencies; `pip-audit` run before submission.

## 6. User interface (CardService)

**Homepage (no email open):** "Open an email to analyze it."

**Email opened:** title "Email Security Check", short explanation, privacy note
"🔒 Nothing is sent until you click Analyze", button **Analyze this email**.

**Result card**, sections in order:

1. **Header:** verdict icon + label + score ("🔴 MALICIOUS · 85 / 100") and one-line summary.
2. **✋ What should I do?** — advice per verdict.
3. **🔍 Why?** — findings sorted by points: `+30 Lookalike domain` + evidence line.
   Safe with no findings: "No warning signs found."
4. **✅ Verified facts** — positive information.
5. **📊 Analysis coverage** — which analyzers ran and their status.
6. **▸ Technical details** — collapsible, for analysts (auth results, domains, hashes, VT results).
7. Footer: score legend (0–29 / 30–69 / 70–100) and "Automated assessment — may be wrong."

**Error card:** friendly message + **Retry** button; no technical details.

**Deliberately not built (README "future work"):** move-to-spam/block buttons (needs modify
scope), first-time-sender check (needs mailbox-wide read), user feedback learning (needs
storage). Each is a conscious security/privacy trade-off.

## 7. Repository structure

```
/
├── README.md
├── .gitignore
├── addon/
│   ├── appsscript.json      # manifest: scopes, triggers, urlFetchWhitelist
│   ├── Code.gs              # trigger entry points + action handlers
│   ├── Extract.gs           # collect minimal email data, hash attachments
│   ├── Api.gs               # call backend with ID token
│   └── Cards.gs             # build cards, HTML-escape helper
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app, /v1/analyze, /healthz
│   │   ├── auth.py          # ID token verification + allowlist
│   │   ├── models.py        # Pydantic request/response models + limits
│   │   ├── config.py        # settings, weights, brand list, TLD lists
│   │   ├── scoring.py       # combine results → score, verdict, advice
│   │   ├── parsing.py       # headers, links, domains
│   │   └── analyzers/
│   │       ├── base.py      # AnalyzerResult, Finding
│   │       ├── rules/       # authentication, sender, links, content, attachments
│   │       ├── virustotal.py
│   │       └── llm.py
│   ├── tests/
│   ├── requirements.txt     # pinned
│   ├── Dockerfile
│   └── .env.example
└── docs/
    ├── superpowers/specs/   # this spec
    └── architecture.png|svg # diagram for the README
```

Main libraries: `fastapi`, `uvicorn`, `pydantic`, `httpx` (async, parallel calls with
timeouts), `google-auth` (token verification), `tldextract` (with bundled suffix list),
`pytest`.

## 8. Testing

- **Unit tests** (pytest) for each rule, parsing (including the forged-auth-header case), and
  scoring (thresholds, once-per-signal, VT floor, LLM cap).
- **API tests** with FastAPI `TestClient`: valid request, oversized input, missing/invalid token
  (token verification mocked).
- **Analyzer failure tests:** VirusTotal/LLM timeout → result still returned with coverage status.
- **Manual add-on test plan** with demo emails (§9).

## 9. Demo preparation

- Send test emails from a second account to the demo account:
  1. **Safe:** an ordinary personal email.
  2. **Suspicious:** marketing-style email with urgency words and a shortened link.
  3. **Malicious-looking:** display name "PayPal Support", link text `www.paypal.com` pointing
     elsewhere, password request, `.html` attachment.
- Gmail blocks executable attachments, so `.exe`/double-extension cases are demonstrated via unit
  tests and a sample request (`curl` with a fixture JSON) instead.
- Warm up the backend before presenting; have the laptop-tunnel fallback ready.

## 10. README outline

1. What it does (screenshot) · 2. Architecture (diagram) and why · 3. Signals and scoring ·
4. Security design · 5. Privacy · 6. Setup and deployment (step by step) · 7. Testing ·
8. Trade-offs and limitations · 9. Future work · 10. Decision log.

## 11. Known limitations (to state in README)

- Hand-picked weights, not calibrated on a dataset.
- Small hand-written brand list (~20 brands); English-only content keywords.
- Legitimate marketing (tracking redirects, shorteners) can produce false positives.
- VirusTotal free tier limits lookups to 3 per email.
- LLM free tier privacy trade-off.
- Single-user allowlist; not packaged for Marketplace publication.

## 12. Build order (time plan)

| Day | Step | Est. |
|---|---|---|
| 1 | Google Cloud project, budget alert, git repo | 0.5h |
| 1 | Minimal add-on ("Analyze" card) running in Gmail via test deployment | 1h |
| 1 | Minimal backend on Cloud Run + ID-token auth; add-on → backend round trip | 1.5h |
| 2 | Parsing + rules analyzer + scoring, with tests | 3h |
| 2 | Result card UI | 1.5h |
| 2 | VirusTotal analyzer (if on schedule) | 1.5h |
| 2 | LLM analyzer (if on schedule) | 1.5h |
| 2 | Security pass (limits, escaping, pip-audit), README, diagram | 2h |
| 2 | Demo emails + rehearsal | 0.5h |

Optional layers are dropped first if time runs short; they become "future work" in the README.
