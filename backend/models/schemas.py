from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Enum, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from core.database import Base
import enum


class ThreatLevel(str, enum.Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    analyses = relationship("EmailAnalysis", back_populates="user")


class EmailAnalysis(Base):
    __tablename__ = "email_analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(20), default=AnalysisStatus.PENDING.value)

    sender_email = Column(String(255))
    sender_domain = Column(String(255))
    recipient_email = Column(String(255))
    subject = Column(String(500))

    raw_headers = Column(Text)
    raw_body = Column(Text)

    risk_score = Column(Float, default=0.0)
    threat_level = Column(String(20), default=ThreatLevel.SAFE.value)
    threat_type = Column(String(100))

    spf_result = Column(String(50))
    dkim_result = Column(String(50))
    dmarc_result = Column(String(50))

    sender_ip = Column(String(45))
    sender_country = Column(String(100))
    sender_city = Column(String(200))
    sender_lat = Column(Float)
    sender_lng = Column(Float)

    sender_reputation = Column(Float)
    domain_age_days = Column(Integer)
    is_disposable_domain = Column(Boolean, default=False)

    detected_links = Column(JSON, default=list)
    detected_attachments = Column(JSON, default=list)
    suspicious_patterns = Column(JSON, default=list)

    trace_path = Column(JSON, default=list)
    forensic_evidence = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)

    analysis_details = Column(JSON, default=dict)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))

    user = relationship("User", back_populates="analyses")
    indicators = relationship("ThreatIndicator", back_populates="analysis")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("email_analyses.id"))
    indicator_type = Column(String(50))
    indicator_value = Column(String(500))
    confidence = Column(Float)
    source = Column(String(100))
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    analysis = relationship("EmailAnalysis", back_populates="indicators")


class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, index=True)
    feed_name = Column(String(100), nullable=False)
    feed_type = Column(String(50))
    indicator_type = Column(String(50))
    indicator_value = Column(String(500))
    confidence = Column(Float, default=0.0)
    source = Column(String(200))
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
