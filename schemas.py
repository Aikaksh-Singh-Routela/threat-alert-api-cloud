from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class ThreatAlertBase(BaseModel):
    source_ip: str
    dest_ip: str
    port: int
    protocol: str
    threat_type: str
    is_suspicious: bool
    confidence: float
    raw_log: str

class ThreatAlertCreate(ThreatAlertBase):
    pass

class ThreatAlertResponse(ThreatAlertBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    is_active: bool

class Token(BaseModel):
    access_token: str
    token_type: str