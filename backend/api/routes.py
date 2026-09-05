from fastapi import APIRouter
from models.pydantic_models import (
    EmailAnalysisRequest, EmailAnalysisResponse, QuickScanRequest,
    DomainCheckRequest, IPCheckRequest, DashboardStats
)

router = APIRouter()

from services.email_analyzer import EmailAnalyzer
analyzer = EmailAnalyzer()


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    result = await analyzer.analyze_email(request)
    return result


@router.post("/quick-scan")
async def quick_scan(request: QuickScanRequest):
    result = await analyzer.quick_scan(request)
    return result


@router.post("/check-domain")
async def check_domain(request: DomainCheckRequest):
    from services.geolocation import GeoLocationService
    from services.auth_checker import AuthenticationChecker

    geo = GeoLocationService()
    auth = AuthenticationChecker()

    ip = await geo.get_domain_ip(request.domain)
    ip_info = await geo.get_ip_info(ip) if ip else {}
    whois_info = await geo.get_whois_info(request.domain)
    mx_records = auth.get_mx_records(request.domain)

    return {
        "domain": request.domain,
        "ip": ip,
        "ip_info": ip_info,
        "whois": whois_info,
        "mx_records": mx_records,
    }


@router.post("/check-ip")
async def check_ip(request: IPCheckRequest):
    from services.geolocation import GeoLocationService

    geo = GeoLocationService()
    ip_info = await geo.get_ip_info(request.ip_address)

    return {
        "ip": request.ip_address,
        "info": ip_info,
    }


@router.get("/stats")
async def get_dashboard_stats():
    return await analyzer.get_stats()


@router.get("/analyses/recent")
async def get_recent_analyses(limit: int = 10):
    return await analyzer.get_recent_analyses(limit)
