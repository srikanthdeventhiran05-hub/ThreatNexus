import asyncio
from datetime import datetime
from models.pydantic_models import (
    EmailAnalysisRequest, EmailAnalysisResponse, QuickScanRequest
)
from utils.email_parser import (
    extract_sender_ip, extract_sender_domain, extract_links,
    extract_attachments, parse_email
)
from services.auth_checker import AuthenticationChecker
from services.threat_detector import ThreatDetector
from services.geolocation import GeoLocationService
from services.threat_intel import ThreatIntelligenceService


class EmailAnalyzer:
    def __init__(self):
        self.auth_checker = AuthenticationChecker()
        self.threat_detector = ThreatDetector()
        self.geo_service = GeoLocationService()
        self.threat_intel = ThreatIntelligenceService()
        self._analyses = []

    async def analyze_email(self, request: EmailAnalysisRequest) -> dict:
        headers = parse_email(request.raw_headers) if request.raw_headers else {}
        sender_domain = extract_sender_domain(request.sender_email)
        sender_ip = extract_sender_ip(headers) or ""

        auth_results = self.auth_checker.full_authentication_check(
            sender_ip, sender_domain, headers
        )
        threat_results = self.threat_detector.analyze(
            request.sender_email, request.subject, request.raw_body, headers
        )

        links = extract_links(request.raw_body)
        link_analysis_task = asyncio.ensure_future(self.threat_intel.analyze_links(links))
        ip_info_task = asyncio.ensure_future(self.geo_service.get_ip_info(sender_ip)) if sender_ip else None
        trace_task = asyncio.ensure_future(self.geo_service.build_trace_path(sender_ip, headers, auth_results))

        if ip_info_task:
            ip_info = await ip_info_task
        else:
            ip_info = {}
        link_analysis = await link_analysis_task
        trace_path = await trace_task
        confidence = await self.geo_service.assess_confidence(ip_info, auth_results)

        risk_score = threat_results["risk_score"]
        auth_score = auth_results["auth_score"]
        final_score = (risk_score * 0.6) + ((1 - auth_score) * 40)
        final_score = min(max(final_score, 0), 100)

        if final_score < 20:
            threat_level = "safe"
        elif final_score < 40:
            threat_level = "low"
        elif final_score < 60:
            threat_level = "medium"
        elif final_score < 80:
            threat_level = "high"
        else:
            threat_level = "critical"

        recommendations = self._generate_recommendations(
            threat_level, auth_results, threat_results, link_analysis
        )

        forensic_evidence = self._build_forensic_evidence(
            auth_results, threat_results, ip_info, link_analysis, confidence
        )

        analysis = {
            "id": len(self._analyses) + 1,
            "status": "completed",
            "sender_email": request.sender_email,
            "sender_domain": sender_domain,
            "subject": request.subject,
            "risk_score": round(final_score, 2),
            "threat_level": threat_level,
            "threat_type": threat_results["threat_type"],
            "spf_result": "pass" if auth_results["spf"]["pass"] else "fail",
            "dkim_result": "pass" if auth_results["dkim"]["pass"] else "fail",
            "dmarc_result": "pass" if auth_results["dmarc"]["pass"] else "fail",
            "sender_ip": sender_ip,
            "sender_country": ip_info.get("country", ""),
            "sender_city": ip_info.get("city", ""),
            "sender_lat": ip_info.get("lat"),
            "sender_lng": ip_info.get("lng"),
            "sender_reputation": 1.0 - (risk_score / 100),
            "domain_age_days": None,
            "is_disposable_domain": False,
            "detected_links": link_analysis,
            "detected_attachments": extract_attachments(request.raw_headers) if request.raw_headers else [],
            "suspicious_patterns": threat_results["suspicious_patterns"],
            "trace_path": trace_path,
            "forensic_evidence": forensic_evidence,
            "recommendations": recommendations,
            "created_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
        }

        self._analyses.append(analysis)
        return analysis

    async def quick_scan(self, request: QuickScanRequest) -> dict:
        threat_results = self.threat_detector.analyze(
            request.sender_email, request.subject, request.body_preview, {}
        )
        sender_domain = extract_sender_domain(request.sender_email)
        return {
            "sender_email": request.sender_email,
            "sender_domain": sender_domain,
            "subject": request.subject,
            "risk_score": threat_results["risk_score"],
            "threat_type": threat_results["threat_type"],
            "suspicious_patterns": threat_results["suspicious_patterns"],
            "details": threat_results["details"],
        }

    async def get_stats(self) -> dict:
        total = len(self._analyses)
        threats = sum(1 for a in self._analyses if a["threat_level"] in ("high", "critical"))
        safe = sum(1 for a in self._analyses if a["threat_level"] == "safe")
        high_risk = threats
        avg_score = sum(a["risk_score"] for a in self._analyses) / max(total, 1)

        threat_types = {}
        for a in self._analyses:
            tt = a.get("threat_type", "unknown")
            threat_types[tt] = threat_types.get(tt, 0) + 1

        top_threats = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)[:5]

        distribution = {}
        for a in self._analyses:
            level = a["threat_level"]
            distribution[level] = distribution.get(level, 0) + 1

        return {
            "total_analyses": total,
            "threats_detected": threats,
            "safe_emails": safe,
            "high_risk_count": high_risk,
            "avg_risk_score": round(avg_score, 2),
            "top_threat_types": [{"type": t, "count": c} for t, c in top_threats],
            "recent_analyses": self._analyses[-10:][::-1],
            "threat_distribution": distribution,
        }

    async def get_recent_analyses(self, limit: int = 10) -> list:
        return self._analyses[-limit:][::-1]

    def _generate_recommendations(self, threat_level, auth_results, threat_results, link_analysis) -> list:
        recs = []
        if not auth_results["spf"]["pass"]:
            recs.append("SPF check failed - sender may be spoofed")
        if not auth_results["dkim"]["pass"]:
            recs.append("DKIM verification failed - email integrity cannot be confirmed")
        if not auth_results["dmarc"]["pass"]:
            recs.append("No DMARC policy - domain lacks anti-spoofing protection")
        if threat_results["risk_score"] > 50:
            recs.append("High risk score detected - do not interact with this email")
        for link in link_analysis:
            if link.get("is_threat"):
                recs.append(f"Malicious URL detected: {link['url'][:50]}...")
        if threat_level in ("high", "critical"):
            recs.append("Report this email to your security team immediately")
            recs.append("Do not click any links or open attachments")
        elif threat_level == "medium":
            recs.append("Exercise caution with this email")
            recs.append("Verify sender through alternative communication channel")
        return recs

    def _build_forensic_evidence(self, auth_results, threat_results, ip_info, link_analysis, confidence) -> list:
        evidence = []
        evidence.append({
            "type": "authentication",
            "description": "Email authentication results",
            "data": {
                "spf": auth_results["spf"],
                "dkim": auth_results["dkim"],
                "dmarc": auth_results["dmarc"],
                "auth_score": auth_results["auth_score"],
            },
        })
        evidence.append({
            "type": "threat_analysis",
            "description": "AI threat detection results",
            "data": threat_results["scores"],
        })
        if ip_info:
            evidence.append({
                "type": "ip_intelligence",
                "description": f"Sender IP {ip_info.get('ip', 'unknown')} analysis",
                "data": ip_info,
            })
        if link_analysis:
            evidence.append({
                "type": "link_analysis",
                "description": f"Analyzed {len(link_analysis)} URLs",
                "data": link_analysis,
            })
        evidence.append({
            "type": "origin_assessment",
            "description": "Confidence in source attribution",
            "data": confidence,
        })
        return evidence
