from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float
from datetime import datetime
from database import Base

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    dest_ip = Column(String)
    port = Column(Integer)
    protocol = Column(String)
    threat_type = Column(String)
    is_suspicious = Column(Boolean)
    confidence = Column(Float)
    raw_log = Column(String)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)