import httpx
import asyncio
from typing import Optional
from ipwhois import IPWhois
import socket


class GeoLocationService:
    def __init__(self):
        self.ip_api_url = "http://ip-api.com/json"
        self.ipinfo_url = "https://ipinfo.io"

    async def get_ip_info(self, ip: str) -> dict:
        result = {
            "ip": ip,
            "country": "",
            "city": "",
            "lat": None,
            "lng": None,
            "isp": "",
            "org": "",
            "as": "",
            "proxy": False,
            "hosting": False,
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.ip_api_url}/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    result.update({
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "city": data.get("city", ""),
                        "region": data.get("regionName", ""),
                        "lat": data.get("lat"),
                        "lng": data.get("lon"),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                        "timezone": data.get("timezone", ""),
                    })
        except Exception:
            pass

        return result

    async def get_domain_ip(self, domain: str) -> str:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, socket.gethostbyname, domain)
            return result
        except Exception:
            return ""

    async def get_whois_info(self, domain: str) -> dict:
        result = {
            "registrar": "",
            "creation_date": "",
            "expiration_date": "",
            "name_servers": [],
            "registrant_country": "",
        }
        try:
            import whois as whois_module
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, whois_module.whois, domain)
            if data:
                result["registrar"] = str(data.get("registrar", "") or "")
                result["creation_date"] = str(data.get("creation_date", "") or "")
                result["expiration_date"] = str(data.get("expiration_date", "") or "")
                ns = data.get("name_servers", [])
                if isinstance(ns, str):
                    ns = [ns]
                result["name_servers"] = [str(n) for n in (ns or [])]
                result["registrant_country"] = str(data.get("country", "") or "")
        except Exception:
            pass
        return result

    async def trace_route(self, ip: str) -> list[dict]:
        hops = []
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{self.ip_api_url}/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    hops.append({
                        "hop": 1,
                        "ip": ip,
                        "country": data.get("country", ""),
                        "city": data.get("city", ""),
                        "lat": data.get("lat"),
                        "lng": data.get("lon"),
                        "isp": data.get("isp", ""),
                    })
        except Exception:
            pass
        return hops

    async def assess_confidence(self, ip_info: dict, auth_results: dict) -> dict:
        confidence = 0.5
        factors = []

        if ip_info.get("proxy"):
            confidence -= 0.2
            factors.append("IP is a known proxy/VPN")

        if ip_info.get("hosting"):
            confidence -= 0.1
            factors.append("IP belongs to hosting provider")

        if auth_results.get("all_pass"):
            confidence += 0.2
            factors.append("All authentication checks passed")
        elif auth_results.get("spf", {}).get("pass"):
            confidence += 0.1
            factors.append("SPF check passed")

        if auth_results.get("reverse_dns", {}).get("pass"):
            confidence += 0.1
            factors.append("Reverse DNS resolved")

        confidence = max(0.0, min(1.0, confidence))

        return {
            "origin_confidence": round(confidence, 2),
            "factors": factors,
            "assessment": "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low",
        }

    async def build_trace_path(self, sender_ip: str, headers: dict, auth_results: dict) -> list[dict]:
        path = []

        ip_info = await self.get_ip_info(sender_ip)
        path.append({
            "stage": "sender",
            "ip": sender_ip,
            "location": f"{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}",
            "isp": ip_info.get("isp", ""),
            "lat": ip_info.get("lat"),
            "lng": ip_info.get("lng"),
        })

        received_headers = headers.get("received_headers", [])
        hop = 2
        for rh in received_headers[:5]:
            import re
            ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', rh)
            if ip_match:
                relay_ip = ip_match.group(1)
                relay_info = await self.get_ip_info(relay_ip)
                path.append({
                    "stage": f"relay_{hop}",
                    "ip": relay_ip,
                    "location": f"{relay_info.get('city', 'Unknown')}, {relay_info.get('country', 'Unknown')}",
                    "isp": relay_info.get("isp", ""),
                    "lat": relay_info.get("lat"),
                    "lng": relay_info.get("lng"),
                })
                hop += 1

        return path
