"""Core email analysis engine. Pure-Python, offline, defensive-only."""
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses
from urllib.parse import urlparse

try:
    from rapidfuzz import fuzz
    _ratio = fuzz.ratio
except ImportError:  # offline fallback - pure stdlib
    from difflib import SequenceMatcher
    def _ratio(a, b):
        return 100 * SequenceMatcher(None, a, b).ratio()

from .profile import protected_domains, protected_people

# ---------------------------------------------------------------- scoring
SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 10, "low": 5}

def verdict_from_score(score):
    if score >= 50:
        return "PHISH", "high-confidence phishing indicators detected"
    if score >= 20:
        return "SUSPICIOUS", "some risky indicators - verify before acting"
    return "PASS", "no significant spoofing indicators found"

# ------------------------------------------------------- text utilities
CONFUSABLES = str.maketrans({
    "0": "o", "@": "a", "$": "s", "5": "s", "3": "e", "1": "l",
    "!": "i", "|": "l", "7": "t", "+": "t", "8": "b", "6": "g",
})

def normalize_domain(domain):
    """Lowercase, strip scheme/path/trailing dot, decode punycode."""
    d = domain.strip().lower().rstrip(".")
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    if d.startswith("xn--") or ".xn--" in d:
        try:
            d = d.encode("ascii").decode("idna")
        except Exception:
            pass
    # fold homoglyphs + drop separators so lookalikes align
    d = unicodedata.normalize("NFKD", d)
    d = d.encode("ascii", "ignore").decode("ascii")
    return d.translate(CONFUSABLES).replace("-", "").replace("_", "")

def registrable(domain):
    """Best-effort registrable part: last two labels."""
    parts = domain.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

def is_subdomain_of(child, parent):
    child, parent = child.lower().rstrip("."), parent.lower().rstrip(".")
    return child == parent or child.endswith("." + parent)

def domain_distance(domain, protected):
    """0 = exact/subdomain (legit). Higher = more different."""
    if is_subdomain_of(domain, protected):
        return 0
    a, b = normalize_domain(registrable(domain)), normalize_domain(registrable(protected))
    if not a or not b:
        return 100
    dist = 100 - _ratio(a, b)
    na, nb = a.replace(".", ""), b.replace(".", "")
    # compare name cores too, ignoring the TLD (com/io/net ...)
    core_a = "".join(a.split(".")[:-1]) or a
    core_b = "".join(b.split(".")[:-1]) or b
    ca, cb = core_a.replace(".", ""), core_b.replace(".", "")
    # substring abuse: acme.example.evil.example contains acme
    if nb in na or cb in ca:
        dist = min(dist, 15)
    # prefix extension: globex-suppliers.example extends globex.example
    if na.startswith(nb) or nb.startswith(na) or ca.startswith(cb) or cb.startswith(ca):
        dist = min(dist, 15)
    return dist

URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>'\")\]]+")

def extract_urls(raw, html):
    urls = set(URL_RE.findall(raw or ""))
    for href in re.findall(r'(?i)href\s*=\s*["\']([^"\']+)', html or ""):
        urls.add(href)
    return [u for u in urls if u.lower().startswith(("http", "www"))]

def host_of(url):
    u = url if "//" in url else "http://" + url
    try:
        return urlparse(u).hostname or ""
    except Exception:
        return ""

# --------------------------------------------------------- parse emails
def parse_email(raw_bytes=None, raw_text=None):
    """Return dict of headers + body pieces from raw RFC822 content."""
    if raw_bytes is None:
        raw_bytes = (raw_text or "").encode("utf-8", "replace")
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    html, text = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/html":
                html.append(part.get_content())
            elif ctype == "text/plain":
                text.append(part.get_content())
    else:
        body = msg.get_content()
        (html if msg.get_content_type() == "text/html" else text).append(body)
    return {
        "from": msg.get("From", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "subject": msg.get("Subject", ""),
        "auth_results": msg.get("Authentication-Results", ""),
        "to": msg.get("To", ""),
        "date": msg.get("Date", ""),
        "text": "\n".join(text),
        "html": "\n".join(html),
        "raw": raw_bytes.decode("utf-8", "replace"),
    }

# ------------------------------------------------------------ the checks
URGENCY = re.compile(
    r"(?i)\b(urgent|immediately|within 24 hours|verify your account|"
    r"password expir|account (?:has been |will be )?suspend|unusual activity|"
    r"wire transfer|invoice attached|payment (?:overdue|required)|"
    r"confirm your (?:identity|password)|act now|final notice)\b")

def check_sender_domain(parsed, profile):
    """Lookalike detection of org AND third-party domains."""
    findings = []
    name, addr = parseaddr(parsed["from"])
    if "@" not in addr:
        return findings
    sender_dom = addr.split("@", 1)[1]
    prot = protected_domains(profile)
    if any(is_subdomain_of(sender_dom, p) for p in prot):
        return findings  # legit internal/partner domain
    best, best_d = None, 100
    for p in prot:
        d = domain_distance(sender_dom, p)
        if d < best_d:
            best, best_d = p, d
    if best_d == 0:
        return findings
    if best_d <= 15:
        findings.append({"check": "Lookalike sender domain (typosquat)",
                         "severity": "high",
                         "detail": f"'{sender_dom}' is a near-miss of trusted domain '{best}' (distance {best_d})."})
    elif best_d <= 30:
        findings.append({"check": "Suspicious sender domain similarity",
                         "severity": "medium",
                         "detail": f"'{sender_dom}' resembles trusted domain '{best}' (distance {best_d})."})
    elif sender_dom.count(".") >= 2:
        base = registrable(sender_dom)
        if any(normalize_domain(registrable(p)).replace(".", "") in normalize_domain(base).replace(".", "") for p in prot):
            findings.append({"check": "Trusted name hidden in subdomain",
                             "severity": "high",
                             "detail": f"'{sender_dom}' embeds a trusted name as a subdomain."})
    return findings

def check_display_name_spoof(parsed, profile):
    """From-name matches staff or partner, but mailbox is foreign."""
    findings = []
    name, addr = parseaddr(parsed["from"])
    if "@" not in addr or not name:
        return findings
    sender_dom = addr.split("@", 1)[1].lower()
    for person in protected_people(profile):
        legit_dom = person["email"].split("@", 1)[1].lower()
        name_hit = name.strip().lower() == person["name"].strip().lower()
        role_hit = person.get("affiliation") and person["affiliation"].lower() in name.strip().lower()
        if (name_hit or role_hit) and not is_subdomain_of(sender_dom, legit_dom):
            sev = "critical" if name_hit else "high"
            findings.append({"check": "Display-name impersonation",
                             "severity": sev,
                             "detail": (f"Display name '{name}' looks like {person['affiliation']}'s "
                                        f"'{person['name']}', but the mailbox is '{addr}'.")})
            break
    return findings

def check_reply_to_mismatch(parsed, profile):
    findings = []
    _, from_addr = parseaddr(parsed["from"])
    _, rt_addr = parseaddr(parsed["reply_to"])
    if "@" in from_addr and "@" in rt_addr:
        fd, rd = from_addr.split("@")[1], rt_addr.split("@")[1]
        if not (is_subdomain_of(fd, rd) or is_subdomain_of(rd, fd)):
            findings.append({"check": "Reply-To domain mismatch",
                             "severity": "high",
                             "detail": f"Replies go to '{rt_addr}', not the sender's domain '{fd}'. "
                                       "Classic redirect for wire-transfer/BEC fraud."})
    return findings

def check_authentication(parsed):
    findings = []
    ar = parsed["auth_results"]
    if not ar:
        findings.append({"check": "No authentication headers",
                         "severity": "low",
                         "detail": "Message carried no SPF/DKIM/DMARC results to verify."})
        return findings
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=([a-z]+)", ar, re.I)
        if m and m.group(1).lower() == "fail":
            findings.append({"check": f"{mech.upper()} failed",
                             "severity": "medium",
                             "detail": f"Authentication-Results reported {mech}=fail."})
    return findings

def check_urls(parsed, profile):
    findings = []
    urls = extract_urls(parsed["raw"], parsed["html"])
    prot = protected_domains(profile)
    flagged_hosts = []
    for u in urls:
        host = host_of(u)
        if not host:
            continue
        if any(is_subdomain_of(host, p) for p in prot + [registrable(h) for h in prot]):
            continue
        best, best_d = None, 100
        for p in prot:
            d = domain_distance(host, p)
            if d < best_d:
                best, best_d = p, d
        if best_d <= 15:
            flagged_hosts.append((u, host, best))
    # link text vs href mismatch (displayed acme.example, real link elsewhere)
    for href, disp in re.findall(r'(?is)<a\b[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>', parsed["html"] or ""):
        dhost = host_of(disp)
        hhost = host_of(href)
        if dhost and hhost and dhost != hhost and any(is_subdomain_of(dhost, p) for p in prot):
            flagged_hosts.append((href, hhost, dhost + " (displayed)"))
    for u, host, best in flagged_hosts[:5]:
        findings.append({"check": "Lookalike URL",
                         "severity": "critical",
                         "detail": f"Link {u[:90]} points to '{host}', impersonating '{best}'."})
    return findings, urls

def check_urgency(parsed):
    hits = URGENCY.findall(parsed["subject"] + " " + parsed["text"])
    if not hits:
        return []
    uniq = sorted(set(h.lower() for h in hits))[:4]
    return [{"check": "Urgency / pressure language",
             "severity": "low",
             "detail": "Pressure phrases: " + ", ".join(uniq) + "."}]

# ------------------------------------------------------------- the engine
def analyze_email(raw_bytes=None, raw_text=None, profile=None):
    parsed = parse_email(raw_bytes, raw_text)
    findings = []
    findings += check_sender_domain(parsed, profile)
    findings += check_display_name_spoof(parsed, profile)
    findings += check_reply_to_mismatch(parsed, profile)
    findings += check_authentication(parsed)
    url_findings, urls = check_urls(parsed, profile)
    findings += url_findings
    findings += check_urgency(parsed)

    score = min(100, sum(SEVERITY_POINTS[f["severity"]] for f in findings))
    verdict, reason = verdict_from_score(score)
    name, addr = parseaddr(parsed["from"])
    return {
        "verdict": verdict,
        "reason": reason,
        "score": score,
        "from": parsed["from"],
        "from_address": addr,
        "subject": parsed["subject"],
        "reply_to": parsed["reply_to"],
        "auth_results": parsed["auth_results"],
        "urls_found": urls,
        "findings": findings,
    }
