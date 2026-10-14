# 🛡️ PhishDefense Toolkit

A defensive-only phishing triage assistant. Paste or upload a suspicious email
and get a **PASS / SUSPICIOUS / PHISH** verdict with human-readable reasons.
It is a learning project: it assists a human analyst and does not replace one.

## Why it's different
Instead of generic spam rules, it checks an email against **your organization's
identity**: your domains, your staff names, and your trusted vendors. An
attacker who registers `acme-corp.example` or poses as your CEO is compared
against what your real domains and people look like.

## Quick start (local, recommended)
```bash
git clone https://github.com/0xRedrabbit/phishdefense-toolkit_v2.git
cd phishdefense-toolkit_v2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python test_toolkit.py                                  # should print ALL CHECKS PASSED
streamlit run app.py --browser.gatherUsageStats false
```
Then try the samples in `sample_emails/`.

### Google Colab (demo with sample emails only)
```
!pip install -r requirements.txt
!streamlit run app.py & npx localtunnel --port 8501
```
> ⚠️ `localtunnel` publishes your app on a public URL. **Never paste or upload
> real email in a tunneled session.** Use the sample emails only.

## Privacy: what is and isn't claimed
- The analysis code (`phishdefense/`) makes **no network requests**; it only parses what you give it.
- Streamlit itself can send anonymous usage statistics by default. The command above turns that off.
- Installing dependencies (`pip install`) naturally uses the network.
- Nothing is written to disk by the toolkit. Uploaded text lives in memory for the session.
- This README is not legal advice. If you analyze real mail for an organization, check your own legal and policy requirements first.

## How detection works
| Check | What it catches |
|---|---|
| Lookalike sender domain | Typosquats of org + third-party domains (fuzzy match) |
| Display-name impersonation | `"Jane Smith" <j.smith.acme@gmail.com>` posing as the CEO |
| Reply-To mismatch | Replies silently redirected to another mailbox (typical of BEC fraud) |
| Lookalike URLs | Links to `acme-corp.example` that display as `acme.example` |
| Authentication headers | SPF/DKIM/DMARC failures reported in the headers |
| Urgency language | Wire transfer / invoice / account-suspension pressure phrases |

Scoring: critical 40 / high 25 / medium 10 / low 5 → PHISH ≥ 50, SUSPICIOUS ≥ 20.

## Limitations (read before trusting a verdict)
- Heuristics only: it will miss novel attacks and can flag legitimate mail.
- It does not verify SPF/DKIM/DMARC itself; it reads the `Authentication-Results` header, which is only as trustworthy as the mail server that added it. A message that *passes* authentication can still be phishing (see `phish_ceo_spoof.eml`).
- The registrable-domain logic takes the last two labels, so country-code suffixes like `co.uk` are handled imperfectly.
- Sample data uses reserved `.example` domains and fictional companies (Acme, Globex, Initech).

## Configuration
Edit `org_profile.yaml`:
- `domains`, `urls`, `staff`: your own assets
- `third_parties`: vendors/partners you do business with (invoice and supplier fraud)

## Responsible use
Analyze only mailboxes you own or are explicitly authorized to inspect.
See [SECURITY.md](SECURITY.md).

## Roadmap (not built yet)
- [ ] Gmail API / IMAP polling mode
- [ ] Training and simulation module with metrics dashboard
- [ ] Optional lightweight ML layer on extracted features

## License
MIT. See [LICENSE](LICENSE).
