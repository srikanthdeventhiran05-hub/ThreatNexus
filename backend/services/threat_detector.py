import re
from typing import Optional
from utils.email_parser import (
    extract_links, check_url_shorteners, extract_email_text,
    check_display_name_spoofing, extract_sender_domain
)


PHISHING_KEYWORDS = [
    "verify your account", "urgent action required", "account suspended",
    "click here immediately", "confirm your identity", "verify your identity",
    "update your payment", "security alert", "unusual sign-in",
    "your account will be", "act now", "limited time",
    "congratulations you won", "claim your prize", "winner",
    "verify your email", "reset your password", "login attempt",
    "suspicious activity", "unauthorized access", "account locked",
    "banking security", "tax refund", "stimulus",
]

URGENCY_PATTERNS = [
    r'within \d+ hours?',
    r'expires? (?:today|tomorrow|soon)',
    r'immediate(?:ly)?',
    r'right away',
    r'last chance',
    r'don\'?t delay',
    r'act now',
    r'limited (?:time|offer)',
]

FINANCIAL_PATTERNS = [
    r'bank\s*(?:account|detail|info)',
    r'credit\s*card',
    r'wire\s*transfer',
    r'pay\s*pal',
    r'bitcoin|crypto|wallet',
    r'social\s*security',
    r'tax\s*(?:refund|return)',
    r'inheritance',
    r'million\s*(?:dollars?|usd)',
    r'prize\s*claim',
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".loan", ".racing", ".download", ".cricket",
]


class ThreatDetector:
    def __init__(self):
        self.phishing_keywords = PHISHING_KEYWORDS

    def analyze(self, sender_email: str, subject: str, body: str, headers: dict) -> dict:
        text_content = extract_email_text(body)
        full_text = f"{subject} {text_content}".lower()

        scores = {}

        scores["keyword"] = self._check_keywords(full_text)
        scores["urgency"] = self._check_urgency(full_text)
        scores["financial"] = self._check_financial(full_text)
        scores["links"] = self._check_links(body)
        scores["sender"] = self._check_sender(sender_email)
        scores["display_name"] = self._check_display_name(sender_email)
        scores["subject"] = self._check_subject(subject)
        scores["body"] = self._check_body_patterns(text_content)

        weights = {
            "keyword": 0.20,
            "urgency": 0.15,
            "financial": 0.15,
            "links": 0.15,
            "sender": 0.15,
            "display_name": 0.05,
            "subject": 0.10,
            "body": 0.05,
        }

        weighted_score = sum(scores[k]["score"] * weights[k] for k in weights)
        risk_score = min(max(weighted_score * 100, 0), 100)

        threat_type = self._classify_threat(full_text, scores)

        patterns = []
        for key, val in scores.items():
            if val["score"] > 0.3:
                patterns.extend(val.get("flags", []))

        return {
            "risk_score": round(risk_score, 2),
            "threat_type": threat_type,
            "scores": scores,
            "suspicious_patterns": list(set(patterns)),
            "details": {
                "keyword_hits": scores["keyword"].get("flags", []),
                "urgency_signals": scores["urgency"].get("flags", []),
                "financial_terms": scores["financial"].get("flags", []),
                "link_issues": scores["links"].get("details", []),
                "sender_issues": scores["sender"].get("flags", []),
            },
        }

    def _check_keywords(self, text: str) -> dict:
        hits = []
        for kw in self.phishing_keywords:
            if kw.lower() in text:
                hits.append(kw)
        score = min(len(hits) / 5, 1.0)
        return {"score": score, "flags": [f"Keyword: '{h}'" for h in hits]}

    def _check_urgency(self, text: str) -> dict:
        hits = []
        for pattern in URGENCY_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                hits.append(match.group())
        score = min(len(hits) / 3, 1.0)
        return {"score": score, "flags": [f"Urgency: '{h}'" for h in hits]}

    def _check_financial(self, text: str) -> dict:
        hits = []
        for pattern in FINANCIAL_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                hits.append(match.group())
        score = min(len(hits) / 3, 1.0)
        return {"score": score, "flags": [f"Financial: '{h}'" for h in hits]}

    def _check_links(self, body: str) -> dict:
        links = extract_links(body)
        link_info = check_url_shorteners(links)
        issues = []

        for info in link_info:
            if info["is_shortener"]:
                issues.append(f"URL shortener: {info['domain']}")
            domain = info["domain"].lower()
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    issues.append(f"Suspicious TLD: {domain}")
                    break

        text_version = extract_email_text(body)
        link_pattern = re.compile(r'(https?://[^\s<>"]+)', re.IGNORECASE)
        for match in link_pattern.finditer(body):
            url = match.group(1)
            text_ver_match = url in text_version
            if not text_ver_match:
                for info in link_info:
                    if info["url"] == url:
                        issues.append(f"Mismatched URL text/href: {url}")

        score = min(len(issues) / 3, 1.0)
        return {"score": score, "flags": issues, "details": link_info}

    def _check_sender(self, sender_email: str) -> dict:
        issues = []
        domain = extract_sender_domain(sender_email)

        if domain:
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    issues.append(f"Suspicious domain TLD: {domain}")
                    break

            if len(domain) > 50:
                issues.append(f"Unusually long domain: {domain}")

            digit_count = sum(c.isdigit() for c in domain)
            if digit_count > len(domain) * 0.5:
                issues.append(f"Domain has excessive digits: {domain}")

            if domain.count("-") > 3:
                issues.append(f"Domain has excessive hyphens: {domain}")

        score = min(len(issues) / 3, 1.0)
        return {"score": score, "flags": issues}

    def _check_display_name(self, sender_email: str) -> dict:
        result = check_display_name_spoofing(sender_email)
        score = 0.8 if result["has_issues"] else 0.0
        return {"score": score, "flags": result["issues"]}

    def _check_subject(self, subject: str) -> dict:
        issues = []
        subject_lower = subject.lower()

        if any(p in subject_lower for p in ["re:", "fw:", "fwd:"]):
            real_re_count = subject_lower.count("re:")
            if real_re_count > 1:
                issues.append("Multiple 'Re:' prefixes in subject")

        if subject.isupper() and len(subject) > 10:
            issues.append("ALL CAPS subject line")

        if re.search(r'[!]{2,}', subject):
            issues.append("Excessive exclamation marks")

        if any(w in subject_lower for w in ["free", "winner", "congratulations", "claim"]):
            issues.append("Spam-like words in subject")

        score = min(len(issues) / 3, 1.0)
        return {"score": score, "flags": issues}

    def _check_body_patterns(self, text: str) -> dict:
        issues = []

        if len(text) > 0:
            caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
            if caps_ratio > 0.5 and len(text) > 50:
                issues.append("Excessive use of capital letters")

        if len(text) > 0:
            special_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
            if special_ratio > 0.2:
                issues.append("Excessive special characters")

        if re.search(r'&\w+;', text):
            issues.append("HTML entities in plain text (potential obfuscation)")

        score = min(len(issues) / 3, 1.0)
        return {"score": score, "flags": issues}

    def _classify_threat(self, text: str, scores: dict) -> str:
        keywords = " ".join(scores["keyword"].get("flags", [])).lower()
        financial = " ".join(scores["financial"].get("flags", [])).lower()

        if "phish" in keywords or "verify your" in text:
            return "phishing"
        if "spoof" in " ".join(scores["sender"].get("flags", [])).lower():
            return "spoofing"
        if "impersonat" in " ".join(scores["display_name"].get("flags", [])).lower():
            return "impersonation"
        if "financial" in financial or "bank" in financial:
            return "financial_fraud"
        if scores["links"]["score"] > 0.5:
            return "malicious_links"
        return "suspicious"
