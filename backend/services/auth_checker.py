import dns.resolver
import re
from typing import Optional
from utils.email_parser import extract_sender_domain


class AuthenticationChecker:
    def __init__(self):
        self.dns_timeout = 5

    def check_spf(self, sender_ip: str, sender_domain: str) -> dict:
        result = {"pass": False, "detail": "", "records": []}
        try:
            answers = dns.resolver.resolve(sender_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith("v=spf1"):
                    result["records"].append(txt)
                    if sender_ip and self._ip_in_spf(sender_ip, txt):
                        result["pass"] = True
                        result["detail"] = "SPF: IP authorized for domain"
                    elif sender_ip:
                        result["detail"] = "SPF: IP not authorized for domain"
                    else:
                        result["detail"] = "SPF: Record found but no sender IP to verify"
                        result["pass"] = True
                    return result
            result["detail"] = "SPF: No SPF record found"
        except dns.resolver.NXDOMAIN:
            result["detail"] = "SPF: Domain does not exist"
        except dns.resolver.NoAnswer:
            result["detail"] = "SPF: No TXT records found"
        except dns.resolver.Timeout:
            result["detail"] = "SPF: DNS query timed out"
        except Exception as e:
            result["detail"] = f"SPF: Check failed - {str(e)}"
        return result

    def check_dkim(self, sender_domain: str, headers: dict) -> dict:
        result = {"pass": False, "detail": "", "selector": ""}
        selectors = ["default", "google", "selector1", "selector2", "k1", "mandrill", "everlytickey1"]
        dkim_header = headers.get("DKIM-Signature", "")

        if dkim_header:
            sel_match = re.search(r's=([^;\s]+)', dkim_header)
            if sel_match:
                selectors.insert(0, sel_match.group(1))

        for sel in selectors:
            try:
                query = f"{sel}._domainkey.{sender_domain}"
                answers = dns.resolver.resolve(query, "TXT")
                for rdata in answers:
                    txt = str(rdata)
                    if "p=" in txt and "p=none" not in txt:
                        result["pass"] = True
                        result["selector"] = sel
                        result["detail"] = f"DKIM: Valid signature with selector '{sel}'"
                        return result
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception:
                continue

        result["detail"] = "DKIM: No valid DKIM record found"
        return result

    def check_dmarc(self, sender_domain: str) -> dict:
        result = {"pass": False, "detail": "", "policy": "none"}
        try:
            dmarc_domain = f"_dmarc.{sender_domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DMARC1" in txt:
                    result["pass"] = True
                    policy_match = re.search(r'p=(\w+)', txt)
                    if policy_match:
                        result["policy"] = policy_match.group(1)
                    pct_match = re.search(r'pct=(\d+)', txt)
                    if pct_match:
                        result["pct"] = int(pct_match.group(1))
                    result["detail"] = f"DMARC: Policy '{result['policy']}'"
                    return result
            result["detail"] = "DMARC: No DMARC record found"
        except dns.resolver.NXDOMAIN:
            result["detail"] = "DMARC: No DMARC record for domain"
        except dns.resolver.NoAnswer:
            result["detail"] = "DMARC: No TXT records"
        except dns.resolver.Timeout:
            result["detail"] = "DMARC: DNS timeout"
        except Exception as e:
            result["detail"] = f"DMARC: Check failed - {str(e)}"
        return result

    def get_mx_records(self, domain: str) -> list[dict]:
        records = []
        try:
            answers = dns.resolver.resolve(domain, "MX")
            for rdata in sorted(answers, key=lambda r: r.preference):
                records.append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip("."),
                })
        except Exception:
            pass
        return records

    def check_reverse_dns(self, ip: str) -> dict:
        result = {"pass": False, "hostname": "", "detail": ""}
        try:
            hostname = dns.resolver.resolve(ip.replace(".", ".") + ".in-addr.arpa", "PTR")
            for rdata in hostname:
                result["hostname"] = str(rdata).rstrip(".")
                result["pass"] = True
                result["detail"] = f"rDNS: {result['hostname']}"
                return result
        except dns.resolver.NXDOMAIN:
            result["detail"] = "rDNS: No reverse DNS record"
        except Exception as e:
            result["detail"] = f"rDNS: Check failed - {str(e)}"
        return result

    def _ip_in_spf(self, ip: str, spf_record: str) -> bool:
        if ip in spf_record:
            return True
        if "a:" in spf_record or "a" == spf_record.split()[-1]:
            try:
                domain_ips = dns.resolver.resolve(spf_record.split()[0].replace("v=spf1 ", ""), "A")
                for rdata in domain_ips:
                    if str(rdata) == ip:
                        return True
            except Exception:
                pass
        return False

    def full_authentication_check(self, sender_ip: str, sender_domain: str, headers: dict) -> dict:
        spf = self.check_spf(sender_ip, sender_domain)
        dkim = self.check_dkim(sender_domain, headers)
        dmarc = self.check_dmarc(sender_domain)
        rdns = self.check_reverse_dns(sender_ip) if sender_ip else {"pass": False, "detail": "No IP"}
        mx = self.get_mx_records(sender_domain)

        total = 4
        passed = sum([spf["pass"], dkim["pass"], dmarc["pass"], rdns["pass"]])

        return {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "reverse_dns": rdns,
            "mx_records": mx,
            "auth_score": round(passed / total, 2),
            "all_pass": passed == total,
        }
