from pydantic import BaseModel
from typing import List


class DeviceData(BaseModel):
    device_name: str
    password_length: int
    failed_logins: int
    outdated_software: bool
    suspicious_ip: bool
    antivirus_enabled: bool
    open_ports: int


class RiskResponse(BaseModel):
    device_name: str
    risk_score: int
    risk_level: str
    issues_found: List[str]
    recommendations: List[str]