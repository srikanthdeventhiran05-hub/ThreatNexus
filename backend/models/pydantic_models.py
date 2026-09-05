from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    email: Optional[str] = None


class EmailAnalysisRequest(BaseModel):
    sender_email: str
    recipient_email: str
    subject: str
    raw_headers: str
    raw_body: str
    attachments: list[dict] = []


class EmailAnalysisResponse(BaseModel):
    id: int
    status: str
    sender_email: str
    sender_domain: str
    subject: str
    risk_score: float
    threat_level: str
    threat_type: Optional[str]
    spf_result: Optional[str]
    dkim_result: Optional[str]
    dmarc_result: Optional[str]
    sender_ip: Optional[str]
    sender_country: Optional[str]
    sender_city: Optional[str]
    sender_lat: Optional[float]
    sender_lng: Optional[float]
    sender_reputation: Optional[float]
    domain_age_days: Optional[int]
    detected_links: list = []
    detected_attachments: list = []
    suspicious_patterns: list = []
    trace_path: list = []
    forensic_evidence: list = []
    recommendations: list = []
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class QuickScanRequest(BaseModel):
    sender_email: str
    subject: str
    body_preview: str


class DomainCheckRequest(BaseModel):
    domain: str


class IPCheckRequest(BaseModel):
    ip_address: str


class ThreatFeedResponse(BaseModel):
    id: int
    feed_name: str
    indicator_type: str
    indicator_value: str
    confidence: float
    source: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_analyses: int
    threats_detected: int
    safe_emails: int
    high_risk_count: int
    avg_risk_score: float
    top_threat_types: list[dict]
    recent_analyses: list[EmailAnalysisResponse]
    threat_distribution: dict
