"""Quick verification: run `python test_toolkit.py` from the toolkit folder."""
from phishdefense.profile import load_profile
from phishdefense.analyzer import analyze_email

try:
    profile = load_profile("org_profile.yaml")   # string path = the exact call the GUI makes
except Exception as e:
    raise SystemExit(f"Profile failed to load: {e}")

print(f"Profile loaded: {profile['organization']} "
      f"({len(profile['domains'])} domains, {len(profile['third_parties'])} third parties)\n")

expected = {
    "legit_partner.eml": "PASS",
    "phish_ceo_spoof.eml": "PHISH",
    "phish_vendor_typosquat.eml": "PHISH",
    "phish_link_mismatch.eml": "PHISH",
}

all_ok = True
for name, want in expected.items():
    try:
        raw = open(f"sample_emails/{name}", "rb").read()
    except FileNotFoundError:
        print(f"--  {name}: not found (skipped)\n")
        continue
    r = analyze_email(raw_bytes=raw, profile=profile)
    ok = r["verdict"] == want
    all_ok = all_ok and ok
    print(f"{'OK  ' if ok else 'FAIL'} {name}: {r['verdict']}  {r['score']}/100  (expected {want})")
    for fd in r["findings"]:
        print(f"      [{fd['severity']:>8}] {fd['check']}")
    print()

print("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED - see FAIL lines above")

raise SystemExit(0 if all_ok else 1)
