"""Load and validate the organization profile (YAML)."""
import os

import yaml

REQUIRED_TOP = ["organization", "domains"]
REQUIRED_STAFF = ["name", "email"]
REQUIRED_TP = ["name", "domains"]


class ProfileError(Exception):
    pass


def load_profile(path_or_file):
    """Load an org profile from a YAML file path, a file-like object, or YAML text."""
    try:
        if isinstance(path_or_file, str):
            txt = path_or_file.strip()
            # A path is a single line ending in .yaml/.yml (or an existing file);
            # pasted YAML text always contains newlines.
            looks_like_path = ("\n" not in txt) and (
                txt.endswith((".yaml", ".yml")) or os.path.exists(txt))
            if looks_like_path:
                try:
                    with open(txt, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except OSError as e:
                    raise ProfileError(f"Cannot open profile file '{txt}': {e}")
            else:
                data = yaml.safe_load(txt)          # YAML text (GUI editor box)
        else:
            data = yaml.safe_load(path_or_file)    # uploaded file object
    except yaml.YAMLError as e:
        raise ProfileError(f"Invalid YAML: {e}")
    if not isinstance(data, dict):
        raise ProfileError("Profile must be a YAML mapping.")
    for key in REQUIRED_TOP:
        if key not in data:
            raise ProfileError(f"Missing required key: '{key}'")
    data.setdefault("urls", [])
    data.setdefault("staff", [])
    data.setdefault("third_parties", [])
    for i, s in enumerate(data["staff"]):
        for k in REQUIRED_STAFF:
            if k not in s:
                raise ProfileError(f"staff[{i}] missing '{k}'")
    for i, t in enumerate(data["third_parties"]):
        for k in REQUIRED_TP:
            if k not in t:
                raise ProfileError(f"third_parties[{i}] missing '{k}'")
        t.setdefault("emails", [])
    return data


def protected_domains(profile):
    """All domains an attacker might spoof: org + third-party domains."""
    doms = list(profile.get("domains", []))
    for tp in profile.get("third_parties", []):
        doms.extend(tp.get("domains", []))
    return [d.lower() for d in doms]


def protected_people(profile):
    """Staff + third-party contact identities for display-name spoof checks."""
    people = []
    for s in profile.get("staff", []):
        people.append({"name": s["name"], "affiliation": profile["organization"],
                       "email": s["email"]})
    for tp in profile.get("third_parties", []):
        for em in tp.get("emails", []):
            people.append({"name": tp["name"], "affiliation": tp["name"], "email": em})
    return people
