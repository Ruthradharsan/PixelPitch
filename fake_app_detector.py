import json, hashlib, difflib, argparse, os, datetime, textwrap

def load_candidates(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def sha256_of_file(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def string_similarity(a, b):
    if not a: a = ""
    if not b: b = ""
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()

def package_similarity(pkg_a, pkg_b):
    if not pkg_a or not pkg_b: return 0.0
    tokens_a = pkg_a.split('.')
    tokens_b = pkg_b.split('.')
    common = len(set(tokens_a) & set(tokens_b))
    token_score = common / max(len(set(tokens_a)|set(tokens_b)), 1)
    seq = string_similarity(pkg_a, pkg_b)
    return (0.6 * token_score) + (0.4 * seq)

def keyword_signal(description, suspicious_keywords):
    if not description: return 0.0
    desc = description.lower()
    hits = sum(1 for k in suspicious_keywords if k in desc)
    return min(1.0, hits / max(1, len(suspicious_keywords)))

def score_candidate(candidate, official, trusted_publishers, official_icon_hash):
    weights = {
        "name": 0.35,
        "package": 0.25,
        "icon": 0.20,
        "publisher": 0.10,
        "keywords": 0.10
    }
    name_sim = string_similarity(candidate.get("app_name",""), official.get("brand_name",""))
    pkg_sim = package_similarity(candidate.get("package_name",""), official.get("official_package",""))
    icon_hash = candidate.get("icon_sha256")
    icon_sim = 1.0 if (official_icon_hash and icon_hash and official_icon_hash == icon_hash) else 0.0
    pub = candidate.get("publisher","").lower()
    publisher_mismatch = 0.0 if any(tp.lower() in pub for tp in trusted_publishers) else 1.0
    suspicious = ["fake","scam","fraud","update","urgent","download now","immediately","customer care"]
    kw_sig = keyword_signal(candidate.get("description",""), suspicious)
    risk = (
        weights["name"] * name_sim +
        weights["package"] * pkg_sim +
        weights["icon"] * icon_sim +
        weights["publisher"] * publisher_mismatch +
        weights["keywords"] * kw_sig
    )
    return {
        "risk_score": round(risk * 100, 2),
        "details": {
            "name_similarity": round(name_sim*100,2),
            "package_similarity": round(pkg_sim*100,2),
            "icon_match_exact": bool(icon_sim),
            "publisher_mismatch_score": round(publisher_mismatch*100,2),
            "keyword_score": round(kw_sig*100,2)
        }
    }

def generate_takedown_email(candidate, evidence):
    subj = f"Urgent takedown request - Fake app impersonating {candidate.get('target_brand','<BRAND>')}"
    body = textwrap.dedent(f"""To: Google Play Support

Subject: {subj}

Dear Google Play Support team,

We have identified an app on the Google Play Store that appears to impersonate {candidate.get('target_brand','<BRAND>')}. Below is the evidence collected by our detection prototype:

- App name: {candidate.get('app_name')}
- Package: {candidate.get('package_name')}
- Store URL: {candidate.get('store_url')}
- Risk score: {evidence['risk_score']}
- Reasons / signal breakdown:
    * Name similarity: {evidence['details']['name_similarity']}%
    * Package similarity: {evidence['details']['package_similarity']}%
    * Icon exact match: {evidence['details']['icon_match_exact']}
    * Publisher mismatch score: {evidence['details']['publisher_mismatch_score']}%
    * Suspicious keywords score: {evidence['details']['keyword_score']}%

Please review the listing and take action if this app violates impersonation or fraud policies.

Thank you,
Security Researcher / Academic Prototype
""")
    return {"subject": subj, "body": body}

def main(args):
    if args.mock:
        # create mock candidates inline
        candidates = [
            {
                "app_name":"MyBank - Official",
                "package_name":"com.mybank.app",
                "publisher":"MyBank Ltd.",
                "description":"Official MyBank app for UPI and banking.",
                "store_url":"https://play.google.com/store/apps/details?id=com.mybank.app",
                "icon_sha256": None
            },
            {
                "app_name":"MyBank - Paytm Update",
                "package_name":"com.mybank.app.update",
                "publisher":"MyBank Updater Inc",
                "description":"Update your MyBank UPI to the latest version. Click to update immediately.",
                "store_url":"https://play.google.com/store/apps/details?id=com.mybank.app.update",
                "icon_sha256": None
            },
            {
                "app_name":"MyBannk",
                "package_name":"com.mvb.bank.app",
                "publisher":"MV Banking",
                "description":"Fast banking and payments.",
                "store_url":"https://play.google.com/store/apps/details?id=com.mvb.bank.app",
                "icon_sha256": None
            },
            {
                "app_name":"MyBank - Secure",
                "package_name":"com.mybank.secure",
                "publisher":"Trusted MyBank Partner",
                "description":"Secure banking from MyBank",
                "store_url":"https://play.google.com/store/apps/details?id=com.mybank.secure",
                "icon_sha256": None
            }
        ]
    else:
        if not args.input:
            print("Error: --input required unless --mock is used", flush=True)
            return
        candidates = load_candidates(args.input)

    official = {
        "brand_name": args.brand or "MyBank",
        "official_package": args.official_package or "com.mybank.app"
    }
    trusted_publishers = [p.strip() for p in (args.trusted_publishers or "MyBank Ltd.,MyBank Official").split(",")]
    official_icon_hash = None
    if args.official_icon:
        official_icon_hash = sha256_of_file(args.official_icon)

    results = []
    for c in candidates:
        c['target_brand'] = official['brand_name']
        evidence = score_candidate(c, official, trusted_publishers, official_icon_hash)
        row = {**c, **{"analysis": evidence}}
        results.append(row)

    results_sorted = sorted(results, key=lambda x: x['analysis']['risk_score'], reverse=True)

    threshold = args.threshold if args.threshold is not None else 50.0

    flagged = [r for r in results_sorted if r['analysis']['risk_score'] >= threshold]

    out = {
        "run_time": datetime.datetime.utcnow().isoformat() + 'Z',
        "brand": official['brand_name'],
        "official_package": official['official_package'],
        "threshold": threshold,
        "candidates_scored": results_sorted,
        "flagged": flagged
    }
    out_path = args.output or 'evidence.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2)

    emails = []
    for fapp in flagged:
        email = generate_takedown_email(fapp, fapp['analysis'])
        emails.append(email)
    emails_path = args.emails or 'takedown_emails.txt'
    with open(emails_path, 'w', encoding='utf-8') as f:
        for e in emails:
            f.write('Subject: ' + e['subject'] + '\n\n')
            f.write(e['body'] + '\n' + ('-'*80) + '\n\n')

    print('\n=== Summary (top candidates) ===\n')
    for r in results_sorted:
        print(f"{r.get('app_name')} | {r.get('package_name')} | risk={r['analysis']['risk_score']}")
    print(f"\nFlagged (risk >= {threshold}): {len(flagged)}\n")
    print(f"Evidence JSON written to: {out_path}")
    print(f"Takedown emails written to: {emails_path}")


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--input', help='path to candidates JSON (list of app objects)')
    p.add_argument('--brand', help='brand name (official)')
    p.add_argument('--official_package', help='official package id (ground truth)')
    p.add_argument('--mock', action='store_true', help='use embedded mock candidates')
    p.add_argument('--official_icon', help='path to official icon file (optional)')
    p.add_argument('--trusted_publishers', help='comma-separated trusted publisher substrings')
    p.add_argument('--threshold', type=float, help='risk threshold for flagging (0-100)')
    p.add_argument('--output', help='output evidence JSON path')
    p.add_argument('--emails', help='output emails text path')
    args = p.parse_args()
    main(args)

