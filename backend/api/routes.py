from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from api.auth import get_current_user
from core.database import get_db
from models.schemas import User, EmailAnalysis
from models.pydantic_models import (
    EmailAnalysisRequest, EmailAnalysisResponse, QuickScanRequest,
    DomainCheckRequest, IPCheckRequest, DashboardStats
)

router = APIRouter()

from services.email_analyzer import EmailAnalyzer
analyzer = EmailAnalyzer()


def persist_analysis(db: Session, result, request, user: User):
    payload = result.model_dump() if hasattr(result, 'model_dump') else result.dict()
    record = EmailAnalysis(
        user_id=user.id,
        status=payload.get('status', 'completed'),
        sender_email=request.sender_email,
        sender_domain=payload.get('sender_domain'),
        recipient_email=request.recipient_email,
        subject=request.subject,
        raw_headers=request.raw_headers,
        raw_body=request.raw_body,
        risk_score=payload.get('risk_score', 0),
        threat_level=payload.get('threat_level'),
        threat_type=payload.get('threat_type'),
        analysis_details=payload,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return result


@router.post("/analyze", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    result = await analyzer.analyze_email(request)
    return persist_analysis(db, result, request, current_user)


@router.post("/quick-scan")
async def quick_scan(request: QuickScanRequest, current_user: User = Depends(get_current_user)):
    result = await analyzer.quick_scan(request)
    return result


@router.post("/check-domain")
async def check_domain(request: DomainCheckRequest, current_user: User = Depends(get_current_user)):
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
async def check_ip(request: IPCheckRequest, current_user: User = Depends(get_current_user)):
    from services.geolocation import GeoLocationService

    geo = GeoLocationService()
    ip_info = await geo.get_ip_info(request.ip_address)

    return {
        "ip": request.ip_address,
        "info": ip_info,
    }


@router.get("/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    return await analyzer.get_stats()


@router.get("/analyses/recent")
async def get_recent_analyses(limit: int = 10, current_user: User = Depends(get_current_user)):
    return await analyzer.get_recent_analyses(limit)
