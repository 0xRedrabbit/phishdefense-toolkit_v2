"""PhishDefense GUI - Streamlit. Run:  streamlit run app.py  (works in Colab)."""
import streamlit as st

from phishdefense.profile import load_profile, ProfileError
from phishdefense.analyzer import analyze_email

st.set_page_config(page_title="PhishDefense Toolkit", page_icon="🛡️", layout="wide")

st.title("🛡️ PhishDefense Toolkit")
st.caption("Defensive-only email triage: paste or upload a suspicious email, get a verdict. "
           "Analysis runs locally and makes no network requests. See SECURITY.md.")

# ------------------------------------------------------------- profile
with st.sidebar:
    st.header("Organization profile")
    use_sample = st.checkbox("Use sample profile (Acme Corp)", value=True)
    uploaded_profile = st.file_uploader("Or upload your org_profile.yaml", type=["yaml", "yml"])
    profile_src = uploaded_profile if uploaded_profile else ("org_profile.yaml" if use_sample else None)
    if st.checkbox("Edit profile (YAML)", value=False):
        if use_sample:
            try:
                current = open("org_profile.yaml", encoding="utf-8").read()
            except OSError:
                current = ""
        else:
            current = ""
        if not current.strip():
            current = "organization: YourOrg\ndomains: [yourorg.example]\n"
        profile_src = st.text_area("Profile YAML", value=current, height=300)

profile = None
try:
    if profile_src is None:
        st.warning("Load a profile to begin.")
    else:
        profile = load_profile(profile_src)
        st.sidebar.success(f"Protecting: {profile['organization']} "
                           f"({len(profile['domains'])} domains, "
                           f"{len(profile.get('third_parties', []))} third parties)")
except ProfileError as e:
    st.sidebar.error(f"Profile error: {e}")

# --------------------------------------------------------------- input
st.subheader("1) Provide the email to analyze")
tab_paste, tab_upload = st.tabs(["📋 Paste raw email", "📎 Upload .eml file"])
raw_text = tab_paste.text_area("Paste the full raw email source (headers + body)", height=260,
                               placeholder="From: Jane Smith <jane.smith@acme-corp.example>\nSubject: Urgent wire transfer\n...")
up = tab_upload.file_uploader("Drop a .eml file", type=["eml"])

raw_bytes = None
if up is not None:
    raw_bytes = up.read()
elif raw_text.strip():
    raw_bytes = raw_text.encode()

# ------------------------------------------------------------- analyze
if st.button("🔍 Analyze", type="primary", use_container_width=True):
    if raw_bytes is None:
        st.info("Paste an email or upload a .eml first.")
    elif profile is None:
        st.info("Load an organization profile first.")
    else:
        with st.spinner("Analyzing..."):
            result = analyze_email(raw_bytes=raw_bytes, profile=profile)

        color = {"PASS": "green", "SUSPICIOUS": "orange", "PHISH": "red"}[result["verdict"]]
        st.markdown(f"## :{color}[{result['verdict']}] — risk score **{result['score']}/100**")
        st.write(result["reason"])

        # From/Subject/detail strings are attacker-controlled. Render them with
        # st.text (plain text), never st.write/st.markdown, so a crafted header
        # cannot inject Markdown links or remote images into the analyst's browser.
        c1, c2, c3 = st.columns(3)
        c1.caption("From")
        c1.text(result["from_address"] or "—")
        c2.caption("Subject")
        c2.text((result["subject"] or "—")[:60])
        c3.caption("URLs found")
        c3.text(str(len(result["urls_found"])))

        if result["findings"]:
            st.subheader("Findings")
            for f in result["findings"]:
                icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}[f["severity"]]
                with st.expander(f"{icon} [{f['severity'].upper()}] {f['check']}"):
                    st.text(f["detail"])
        else:
            st.success("No spoofing indicators detected against this organization's profile.")

        with st.expander("Technical details (auth headers)"):
            st.code(result["auth_results"] or "(none)")
