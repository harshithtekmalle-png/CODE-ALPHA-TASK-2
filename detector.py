"""
PhishGuard Detection Engine
Real-Time Rule-Based Phishing Detection & Analysis

DISCLAIMER:
This engine performs deterministic, rule-based heuristic indicator analysis.
Detections reflect risk indicators and behavioral patterns commonly associated
with phishing lures and social engineering; they do not constitute an absolute
guarantee of maliciousness or safety.
"""

import re
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Scoring Constants & Thresholds
# ---------------------------------------------------------------------------
SCORE_LOW_MAX = 24
SCORE_SUSPICIOUS_MAX = 49
SCORE_HIGH_MAX = 74
SCORE_CRITICAL_MAX = 100


def get_risk_level(score: int) -> str:
    """Map a numerical risk score (0-100) to its designated risk tier."""
    if score <= SCORE_LOW_MAX:
        return "Low Risk"
    elif score <= SCORE_SUSPICIOUS_MAX:
        return "Suspicious"
    elif score <= SCORE_HIGH_MAX:
        return "High Risk"
    else:
        return "Critical"


# ---------------------------------------------------------------------------
# Heuristic Indicator Databases (URLs)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "buzz", "fit", "gq", "cf", "tk", "ml",
    "ga", "rest", "country", "stream", "download", "racing", "review",
    "country", "kim", "cricket", "science", "party", "faith", "date",
    "loan", "men", "accountant", "bid", "trade", "webcam", "win"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "goo.gl",
    "rb.gy", "bl.ink", "hyperurl.co"
}

SUSPICIOUS_URL_KEYWORDS = [
    ("login", 12, "Authentication credential endpoint keyword detected"),
    ("signin", 12, "Sign-in portal reference detected"),
    ("verify", 14, "Account verification trigger keyword detected"),
    ("verification", 14, "Explicit verification indicator detected"),
    ("update-account", 18, "High-risk account update keyword pattern"),
    ("security-alert", 18, "Security alert spoofing keyword pattern"),
    ("banking", 16, "Financial/banking sector keyword detected"),
    ("secure-login", 18, "High-risk composite secure-login keyword detected"),
    ("wallet", 14, "Cryptocurrency or payment wallet keyword detected"),
    ("confirm", 12, "Action confirmation prompt keyword detected"),
    ("recover", 14, "Account recovery lure keyword detected"),
    ("checkpoint", 16, "Security checkpoint impersonation keyword detected"),
    ("password", 15, "Sensitive password reference in URL structure"),
    ("credential", 15, "Direct credential token reference in URL"),
    ("billing", 14, "Billing/payment collection keyword detected"),
    ("invoice-review", 15, "Invoice lure keyword detected in URL"),
    ("appleid", 18, "Brand targeted keyword (Apple ID) detected"),
    ("paypal", 18, "Brand targeted keyword (PayPal) detected"),
    ("netflix", 14, "Brand targeted keyword (Netflix) detected"),
    ("microsoft", 14, "Brand targeted keyword (Microsoft) detected")
]

SUSPICIOUS_TYPOSQUAT_PATTERNS = [
    (r"paypa[l1i]\b", "PayPal typosquatting/lookalike pattern"),
    (r"g0+g[l1]e", "Google visual impersonation/leetspeak pattern"),
    (r"micr[o0]s[o0]ft", "Microsoft visual spoofing pattern"),
    (r"amaz[o0]n", "Amazon brand spoofing pattern"),
    (r"app[l1]e[-_]", "Apple brand prefix spoofing pattern"),
    (r"netf[l1]ix", "Netflix lookalike spoofing pattern"),
    (r"faceb[o0][o0]k", "Facebook lookalike spoofing pattern"),
    (r"b[a4]nk[o0]f", "Bank impersonation pattern")
]

UNUSUAL_WEB_PORTS = {
    21: "FTP Port (Port 21) in web URL",
    22: "SSH Port (Port 22) in web URL",
    23: "Telnet Port (Port 23) in web URL",
    25: "SMTP Port (Port 25) in web URL",
    2082: "cPanel unencrypted control port (Port 2082)",
    2083: "cPanel control port (Port 2083)",
    7000: "Non-standard web port (Port 7000)",
    8080: "Alternate web proxy port (Port 8080)",
    8888: "Alternate dev/management port (Port 8888)",
    9000: "Non-standard port (Port 9000)"
}


# ---------------------------------------------------------------------------
# Heuristic Indicator Databases (Messages)
# ---------------------------------------------------------------------------
MESSAGE_RULES = [
    {
        "id": "urgency_extreme",
        "category": "Urgency & Coercion",
        "patterns": [
            r"\b(within\s+(?:24|12|48|1|2|6)\s*(?:hours|hrs|hour))\b",
            r"\b(immediately|urgent\s+action\s+required|act\s+now|immediate\s+response)\b",
            r"\b(expires\s+(?:today|tonight|within\s+minutes))\b",
            r"\b(final\s+notice|last\s+warning|time\s+sensitive)\b"
        ],
        "weight": 22,
        "title": "Artificial Urgency & Time Pressure",
        "desc": "Message exerts strict time pressure to prompt impulsive, unverified action."
    },
    {
        "id": "account_threat",
        "category": "Account Threat",
        "patterns": [
            r"\b(account\s+(?:has\s+been\s+)?suspended|account\s+locked|account\s+disabled)\b",
            r"\b(unusual\s+activity\s+detected|unauthorized\s+(?:login|access|charge))\b",
            r"\b(terminated\s+permanently|access\s+revoked|security\s+breach)\b",
            r"\b(suspicious\s+activity\s+found|failed\s+login\s+attempts)\b"
        ],
        "weight": 24,
        "title": "Threat of Account Suspension / Restriction",
        "desc": "Claims your account is suspended, compromised, or locked to induce panic."
    },
    {
        "id": "credential_harvest",
        "category": "Credential Harvesting",
        "patterns": [
            r"\b(enter\s+your\s+password|verify\s+your\s+credentials|confirm\s+your\s+pin)\b",
            r"\b(username\s+and\s+password|provide\s+your\s+passcode|security\s+questions)\b",
            r"\b(reset\s+your\s+password\s+here|login\s+to\s+re-activate)\b",
            r"\b(social\s+security|ssn|identity\s+verification\s+document)\b"
        ],
        "weight": 28,
        "title": "Direct Credential / Sensitive ID Solicitation",
        "desc": "Solicits passwords, PIN numbers, authentication keys, or identity tokens."
    },
    {
        "id": "financial_solicitation",
        "category": "Financial Lure",
        "patterns": [
            r"\b(wire\s+transfer|bitcoin|crypto\s+wallet|gift\s+card|western\s+union)\b",
            r"\b(bank\s+account\s+details|routing\s+number|credit\s+card\s+number)\b",
            r"\b(payment\s+declined|outstanding\s+balance|pending\s+refund|invoice\s+attached)\b",
            r"\b(pay\s+the\s+fee|processing\s+charge|penalty\s+fee)\b"
        ],
        "weight": 25,
        "title": "Financial Transaction or Payment Solicitation",
        "desc": "Requests financial transfers, unconventional payments (gift cards/crypto), or payment credentials."
    },
    {
        "id": "prize_reward_lure",
        "category": "Reward & Prize Lures",
        "patterns": [
            r"\b(you\s+(?:have\s+)?won|congratulations\s+you(?:'ve)?\s+been\s+selected)\b",
            r"\b(lottery\s+winner|claim\s+your\s+(?:cash\s+)?prize|free\s+gift\s+card)\b",
            r"\b(reward\s+waiting|100%\s+bonus|guaranteed\s+payout)\b",
            r"\b(exclusive\s+giveaway|claim\s+voucher)\b"
        ],
        "weight": 22,
        "title": "Unsolicited Prize / Reward Lure",
        "desc": "Entices with unexpected financial windfalls, lottery rewards, or free gift cards."
    },
    {
        "id": "authority_legal_threat",
        "category": "Legal & Authority Intimidation",
        "patterns": [
            r"\b(legal\s+action\s+will\s+be\s+taken|law\s+enforcement|arrest\s+warrant)\b",
            r"\b(federal\s+court|irs\s+notice|internal\s+revenue|police\s+department)\b",
            r"\b(prosecution|subpoena|legal\s+proceedings)\b"
        ],
        "weight": 26,
        "title": "Authority / Legal Intimidation Threat",
        "desc": "Uses intimidation through fake government, police, or judicial authority threats."
    },
    {
        "id": "delivery_impersonation",
        "category": "Postal & Delivery Lure",
        "patterns": [
            r"\b(package\s+(?:could\s+not\s+be\s+delivered|delivery\s+failed|pending\s+customs))\b",
            r"\b(usps|ups|fedex|dhl)\s*(?:delivery|tracking|parcel|shipment|notice)\b",
            r"\b(reschedule\s+delivery|confirm\s+shipping\s+address|unpaid\s+shipping\s+fee)\b"
        ],
        "weight": 18,
        "title": "Delivery & Shipment Impersonation",
        "desc": "Common postal phishing lure alleging failed delivery or unpaid postage."
    },
    {
        "id": "embedded_links",
        "category": "Suspicious Links",
        "patterns": [
            r"https?://[^\s<>\"']+",
            r"www\.[^\s<>\"']+"
        ],
        "weight": 12,
        "title": "Embedded Hyperlinks Detected",
        "desc": "Contains embedded hyperlinks prompting external navigation."
    }
]


# ---------------------------------------------------------------------------
# URL Detection Logic
# ---------------------------------------------------------------------------
def analyze_url(url: str) -> dict:
    """
    Safely inspect a user-submitted URL using heuristic indicators.
    DOES NOT make any outbound network requests or visit the target.
    """
    if not isinstance(url, str):
        url = str(url or "")
    
    cleaned_url = url.strip()
    target_display = cleaned_url

    indicators = []
    accumulated_score = 0

    if not cleaned_url:
        return {
            "score": 0,
            "risk_level": "Low Risk",
            "indicators": [],
            "explanation": "No URL provided for analysis.",
            "target": target_display,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": "url"
        }

    # Normalize scheme for parsing if missing
    working_url = cleaned_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", working_url):
        # Default to prepending http:// for structural parsing
        working_url = "http://" + working_url

    try:
        parsed = urlparse(working_url)
    except Exception:
        indicators.append({
            "id": "malformed_url",
            "title": "Malformed URL Syntax",
            "description": "The URL cannot be parsed cleanly according to RFC standards.",
            "severity": "high",
            "weight": 35
        })
        accumulated_score += 35
        score = min(accumulated_score, 100)
        return {
            "score": score,
            "risk_level": get_risk_level(score),
            "indicators": indicators,
            "explanation": "The submitted URL possesses severely malformed syntax.",
            "target": target_display,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": "url"
        }

    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_str = (working_url).lower()

    # Extract hostname (strip credentials and port)
    hostname = parsed.hostname.lower() if parsed.hostname else ""

    # 1. IP Address Hostname Detection (IPv4 decimal, hex, or bracketed IPv6)
    ip_v4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if hostname and (re.match(ip_v4_pattern, hostname) or (hostname.startswith("[") and hostname.endswith("]"))):
        w = 32
        indicators.append({
            "id": "ip_as_host",
            "title": "Direct IP Address as Hostname",
            "description": f"URL connects directly to raw IP ({hostname}) instead of a verified domain name.",
            "severity": "critical",
            "weight": w
        })
        accumulated_score += w

    # 2. @ symbol trick (RFC authentication trick in URL userinfo)
    if "@" in netloc or "@" in cleaned_url.split("?")[0].split("#")[0]:
        w = 30
        indicators.append({
            "id": "at_symbol_obfuscation",
            "title": "Authority Redirection Trick (@ Symbol)",
            "description": "URL employs '@' in authority section; browsers treat the preceding portion as credentials and route to the following domain.",
            "severity": "critical",
            "weight": w
        })
        accumulated_score += w

    # 3. HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        w = 12
        indicators.append({
            "id": "unencrypted_http",
            "title": "Insecure HTTP Protocol",
            "description": "URL relies on unencrypted HTTP instead of modern TLS/HTTPS encryption.",
            "severity": "low",
            "weight": w
        })
        accumulated_score += w

    # 4. Known URL Shortener
    for shortener in KNOWN_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            w = 24
            indicators.append({
                "id": "url_shortener",
                "title": "URL Shortener Service Detected",
                "description": f"Domain utilizes a public URL redirector ({shortener}) that conceals destination address.",
                "severity": "medium",
                "weight": w
            })
            accumulated_score += w
            break

    # 5. Excessive Subdomains (Deep Subdomain Nesting)
    if hostname:
        subdomain_parts = [p for p in hostname.split(".") if p]
        if len(subdomain_parts) >= 4:
            w = 18
            indicators.append({
                "id": "excessive_subdomains",
                "title": "Excessive Subdomain Hierarchy",
                "description": f"Host contains {len(subdomain_parts)} domain segments, commonly utilized to spoof authentic brand names.",
                "severity": "medium",
                "weight": w
            })
            accumulated_score += w

    # 6. High-Risk / Suspicious TLD
    if hostname:
        tld = hostname.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            w = 20
            indicators.append({
                "id": "suspicious_tld",
                "title": f"High-Risk Top-Level Domain (.{tld})",
                "description": f"The top-level domain '.{tld}' has an elevated correlation with low-cost disposable phishing setups.",
                "severity": "medium",
                "weight": w
            })
            accumulated_score += w

    # 7. Brand Typosquatting / Visual Spoofing Patterns
    for pattern, desc in SUSPICIOUS_TYPOSQUAT_PATTERNS:
        if re.search(pattern, hostname):
            w = 28
            indicators.append({
                "id": "brand_typosquatting",
                "title": "Brand Typosquatting / Lookalike Pattern",
                "description": desc,
                "severity": "high",
                "weight": w
            })
            accumulated_score += w
            break

    # 8. Suspicious Keywords in Domain, Path, or Query
    keyword_hits = []
    kw_score = 0
    for kw, weight, desc in SUSPICIOUS_URL_KEYWORDS:
        if kw in full_str:
            keyword_hits.append(kw)
            kw_score += weight
            if len(keyword_hits) >= 3:
                break
    
    if keyword_hits:
        capped_kw_weight = min(kw_score, 30)
        indicators.append({
            "id": "suspicious_keywords",
            "title": f"Sensitive Phishing Keywords ({', '.join(keyword_hits)})",
            "description": f"Detected sensitive keyword(s) frequently targeted in social engineering lures: {', '.join(keyword_hits)}.",
            "severity": "high" if capped_kw_weight >= 25 else "medium",
            "weight": capped_kw_weight
        })
        accumulated_score += capped_kw_weight

    # 9. Unusual Web Port
    if parsed.port:
        if parsed.port in UNUSUAL_WEB_PORTS:
            w = 25
            indicators.append({
                "id": "unusual_port",
                "title": f"Non-Standard Service Port (Port {parsed.port})",
                "description": UNUSUAL_WEB_PORTS[parsed.port],
                "severity": "high",
                "weight": w
            })
            accumulated_score += w
        elif parsed.port not in [80, 443]:
            w = 15
            indicators.append({
                "id": "custom_port",
                "title": f"Custom Non-Default Port (Port {parsed.port})",
                "description": f"URL explicitly targets unconventional port {parsed.port}.",
                "severity": "medium",
                "weight": w
            })
            accumulated_score += w

    # 10. Excessive Special Characters (Hyphens, Double Slashes, Percent Encodings)
    hyphen_count = netloc.count("-")
    if hyphen_count >= 3:
        w = 15
        indicators.append({
            "id": "excessive_hyphens",
            "title": f"Excessive Hyphenation ({hyphen_count} hyphens)",
            "description": "Multi-hyphenated domain structures are typical of automated phishing kit domain generators.",
            "severity": "medium",
            "weight": w
        })
        accumulated_score += w

    if "//" in path:
        w = 16
        indicators.append({
            "id": "path_double_slash",
            "title": "Double Slash Path Obfuscation",
            "description": "URL path contains redundant double slashes commonly used to evade basic URL filtering filters.",
            "severity": "medium",
            "weight": w
        })
        accumulated_score += w

    # 11. Excessive Total Length (> 85 characters)
    if len(cleaned_url) > 85:
        w = 10
        indicators.append({
            "id": "excessive_length",
            "title": f"Abnormally Long URL ({len(cleaned_url)} characters)",
            "description": "Long URLs are frequently engineered to hide malicious destination components off-screen on mobile screens.",
            "severity": "low",
            "weight": w
        })
        accumulated_score += w

    # 12. Credential Harvesting Query Parameters
    suspicious_params = ["redirect", "return", "next", "goto", "destination", "email", "target_url"]
    for param in suspicious_params:
        if f"{param}=" in query:
            w = 14
            indicators.append({
                "id": "open_redirect_param",
                "title": f"Open Redirect / Relay Parameter ({param})",
                "description": f"URL query contains parameter '{param}' typically abused to bounce victims through authentic hosts to malicious endpoints.",
                "severity": "medium",
                "weight": w
            })
            accumulated_score += w
            break

    # Calculate final bounded score
    final_score = min(accumulated_score, 100)
    risk_level = get_risk_level(final_score)

    # Generate transparent explanation
    if not indicators:
        explanation = (
            "No high-risk structural indicators, IP obfuscations, or suspicious heuristics were triggered. "
            "The URL appears structurally standard. However, always exercise caution with untrusted links."
        )
    elif risk_level == "Low Risk":
        explanation = (
            f"Minor indicators detected ({len(indicators)} rule(s) triggered), such as unencrypted HTTP or "
            "minor structural features. The overall calculated threat profile remains Low Risk."
        )
    elif risk_level == "Suspicious":
        explanation = (
            f"Elevated risk indicators observed ({len(indicators)} rule(s) triggered). Features such as "
            "URL shortening, suspicious keywords, or abnormal domain hierarchy suggest the link warrants scrutiny."
        )
    elif risk_level == "High Risk":
        explanation = (
            f"Multiple strong phishing indicators identified ({len(indicators)} rules triggered). "
            "Pattern matches high-risk phishing lures (e.g. brand keywords, suspicious TLDs, or complex redirections)."
        )
    else:  # Critical
        explanation = (
            f"CRITICAL risk indicators detected ({len(indicators)} rules triggered). "
            "Observed high-confidence deception mechanisms such as raw IP addressing, authentication tricks, or aggressive brand typosquatting."
        )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
        "target": target_display,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": "url"
    }


# ---------------------------------------------------------------------------
# Message Detection Logic
# ---------------------------------------------------------------------------
def analyze_message(message: str) -> dict:
    """
    Safely inspect user-submitted message content for phishing / social engineering indicators.
    DOES NOT submit content to external APIs or third-party engines.
    """
    if not isinstance(message, str):
        message = str(message or "")

    cleaned_msg = message.strip()
    target_display = cleaned_msg

    indicators = []
    accumulated_score = 0

    if not cleaned_msg:
        return {
            "score": 0,
            "risk_level": "Low Risk",
            "indicators": [],
            "explanation": "No message text provided for analysis.",
            "target": target_display,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_type": "message"
        }

    # Evaluate all defined heuristic message rules
    for rule in MESSAGE_RULES:
        rule_matched = False
        matched_samples = []

        for pattern in rule["patterns"]:
            matches = re.findall(pattern, cleaned_msg, flags=re.IGNORECASE)
            if matches:
                rule_matched = True
                for m in matches:
                    text_str = m if isinstance(m, str) else m[0]
                    if text_str not in matched_samples:
                        matched_samples.append(text_str)
                    if len(matched_samples) >= 3:
                        break

        if rule_matched:
            sample_txt = f" (matches: '{', '.join(matched_samples)}')" if matched_samples else ""
            indicators.append({
                "id": rule["id"],
                "title": rule["title"],
                "category": rule["category"],
                "description": rule["desc"] + sample_txt,
                "severity": "critical" if rule["weight"] >= 26 else ("high" if rule["weight"] >= 22 else "medium"),
                "weight": rule["weight"]
            })
            accumulated_score += rule["weight"]

    # Check for excessive capitalization (SHOUTING / urgency pressure)
    letters = [c for c in cleaned_msg if c.isalpha()]
    if len(letters) >= 20:
        uppercase_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if uppercase_ratio > 0.45:
            w = 12
            indicators.append({
                "id": "excessive_caps",
                "title": "Aggressive Capitalization",
                "description": f"Over {int(uppercase_ratio * 100)}% of characters are capitalized, indicative of urgent pressure tactics.",
                "severity": "low",
                "weight": w
            })
            accumulated_score += w

    # Calculate final bounded score
    final_score = min(accumulated_score, 100)
    risk_level = get_risk_level(final_score)

    if not indicators:
        explanation = (
            "No known social engineering, urgency, credential harvesting, or threat patterns "
            "were detected in the submitted message text."
        )
    elif risk_level == "Low Risk":
        explanation = (
            f"Low overall risk detected ({len(indicators)} minor indicator(s)). "
            "Message contains minor flags but lacks typical coercive phishing indicators."
        )
    elif risk_level == "Suspicious":
        explanation = (
            f"Suspicious social engineering indicators identified ({len(indicators)} indicator(s)). "
            "Message exhibits pressure tactics, links, or incentives typical of untrusted communications."
        )
    elif risk_level == "High Risk":
        explanation = (
            f"High-risk phishing patterns detected ({len(indicators)} indicators triggered). "
            "The message combines urgency, account threats, or financial lures strongly associated with phishing campaigns."
        )
    else:  # Critical
        explanation = (
            f"CRITICAL phishing indicators detected ({len(indicators)} high-confidence indicators triggered). "
            "Content explicitly demands credentials, financial actions, or issues severe account threats under immediate pressure."
        )

    return {
        "score": final_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "explanation": explanation,
        "target": target_display,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": "message"
    }
