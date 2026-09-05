import httpx
from core.config import get_settings
from typing import Optional

settings = get_settings()


class ThreatIntelligenceService:
    def __init__(self):
        self.vt_base = "https://www.virustotal.com/api/v3"
        self.abuseipdb_base = "https://api.abuseipdb.com/api/v2"

    async def check_url_virustotal(self, url: str) -> dict:
        if not settings.VIRUSTOTAL_API_KEY:
            return {"available": False, "detail": "VirusTotal API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                import hashlib
                url_id = hashlib.sha256(url.encode()).hexdigest()
                resp = await client.get(
                    f"{self.vt_base}/urls/{url_id}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]["attributes"]["last_analysis_stats"]
                    return {
                        "available": True,
                        "malicious": data.get("malicious", 0),
                        "suspicious": data.get("suspicious", 0),
                        "harmless": data.get("harmless", 0),
                        "undetected": data.get("undetected", 0),
                    }
        except Exception:
            pass
        return {"available": True, "error": "Lookup failed"}

    async def check_ip_abuseipdb(self, ip: str) -> dict:
        if not settings.ABUSEIPDB_API_KEY:
            return {"available": False, "detail": "AbuseIPDB API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.abuseipdb_base}/check",
                    headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": "90"}
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]
                    return {
                        "available": True,
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "usage_type": data.get("usageType", ""),
                    }
        except Exception:
            pass
        return {"available": True, "error": "Lookup failed"}

    async def check_domain_reputation(self, domain: str) -> dict:
        result = {
            "is_known_threat": False,
            "confidence": 0.0,
            "sources": [],
        }

        if settings.VIRUSTOTAL_API_KEY:
            vt_result = await self.check_url_virustotal(f"http://{domain}")
            if vt_result.get("malicious", 0) > 0:
                result["is_known_threat"] = True
                result["confidence"] = max(result["confidence"], 0.8)
                result["sources"].append("VirusTotal")

        return result

    async def analyze_links(self, links: list[str]) -> list[dict]:
        results = []
        for link in links[:10]:
            analysis = {
                "url": link,
                "vt_result": {},
                "is_threat": False,
            }
            if settings.VIRUSTOTAL_API_KEY:
                analysis["vt_result"] = await self.check_url_virustotal(link)
                if analysis["vt_result"].get("malicious", 0) > 0:
                    analysis["is_threat"] = True
            results.append(analysis)
        return results
