# Security & Responsible Use

**This project is strictly defensive.** It analyzes emails you provide; it does
not send email, harvest credentials, or generate phishing lures.

## Allowed use
- Triaging emails from mailboxes you own or are explicitly authorized to inspect.
- Security education and awareness demonstrations.

## Not allowed
- Analyzing third parties' mail without consent.
- Using org profiles to *craft* lookalike phishing (including "testing" people without authorization).
- Presenting verdicts as guaranteed. This tool assists a human analyst; it does not replace one.

## Data handling
- The analysis code makes no network requests and stores nothing beyond the running session.
- Streamlit may collect anonymous usage stats unless started with `--browser.gatherUsageStats false`.
- Do not expose the app on a public URL (e.g. `localtunnel`) while analyzing real email.
- Do not commit real emails to this repository. `.gitignore` blocks `*.eml` outside `sample_emails/`.

## Handling untrusted input
Email headers and bodies are attacker-controlled. The GUI renders them as plain
text (`st.text`), not Markdown, so a crafted sender or URL cannot inject links
or remote images into the analyst's browser. Keep that property if you edit `app.py`.

## Reporting a vulnerability
Open a GitHub issue, or contact the maintainer via the profile linked on this repository.
