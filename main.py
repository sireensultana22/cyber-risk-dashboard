from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm.session import Session 
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from fastapi.responses import JSONResponse
from starlette.requests import Request

from models import DeviceData
from ai_client import get_ai_analysis
from scoring import calculate_risk
from alerts import generate_alerts
from database import engine, SessionLocal
from db_models import (
    Base,
    RiskReport,
    User,
    ScanHistory
)
from auth import (
    hash_password,
    verify_password,
    create_access_token
)

from db_models import User
from clamav_scanner import scan_file

from virustotal import check_url
from nmap_scanner import scan
from email_analyser import analyse_header
from fastapi import UploadFile, File
import shutil
import os

Base.metadata.create_all(bind=engine)

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter

app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(
    request: Request,
    exc: RateLimitExceeded
):

    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded. Try again later."
        }
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():

    return {
        "message":
        "Cyber Risk Dashboard Backend Running"
    }


@app.post("/analyze")
def analyze_device(data: DeviceData):

    result = calculate_risk(data)

    alerts = generate_alerts(result["risk_level"])

    final_report = {
        "device_name": data.device_name,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "issues_found": result["issues"],
        "recommendations": result["recommendations"],
        "alerts": alerts
    }

    db = SessionLocal()

    report = RiskReport(
        device_name=data.device_name,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"]
    )

    db.add(report)
    db.commit()
    db.close()

    return final_report

@app.get("/reports")
def get_reports():

    db = SessionLocal()

    reports = db.query(RiskReport).all()

    result = []

    for report in reports:
        result.append({
            "device_name": report.device_name,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level
        })

    db.close()

    return result


@app.get("/dashboard-summary")
def dashboard_summary():

    db = SessionLocal()

    reports = db.query(RiskReport).all()

    total_devices = len(reports)

    high_risk = sum(
        1 for report in reports
        if report.risk_level == "HIGH"
    )

    medium_risk = sum(
        1 for report in reports
        if report.risk_level == "MEDIUM"
    )

    low_risk = sum(
        1 for report in reports
        if report.risk_level == "LOW"
    )

    db.close()

    return {
        "total_devices": total_devices,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "low_risk": low_risk
    }

from fastapi import UploadFile, File

@app.post("/api/scan/file")
@limiter.limit("5/minute")
async def scan_file_endpoint(
    request: Request,
    file: UploadFile = File(...)
):

    temp_path = f"temp_{file.filename}"

    with open(temp_path, "wb") as f:

        shutil.copyfileobj(file.file, f)

    result = scan_file(temp_path)

    db = SessionLocal()

    scan_record = ScanHistory(
        scan_type="File Scan",
        target=file.filename,
        result=str(result),
        user_email="unknown"
    )

    db.add(scan_record)

    db.commit()

    db.close()

    os.remove(temp_path)

    return result

@app.post("/api/scan/url")
@limiter.limit("5/minute")
async def scan_url_endpoint(
    request: Request,
    body: dict
):

    result = check_url(body["url"])

    db = SessionLocal()

    scan_record = ScanHistory(
        scan_type="URL Scan",
        target=body["url"],
        result=str(result),
        user_email=body.get("email", "unknown")
    )

    db.add(scan_record)

    db.commit()

    db.close()

    ai_response = get_ai_analysis(result)

    return {
        "raw_output": result,
        "ai_analysis": ai_response
    }


@app.post("/api/scan/network")
@limiter.limit("5/minute")
async def scan_network_endpoint(
    request: Request,
    body: dict
):

    result = scan(
    body["target"]
)
    

    db = SessionLocal()

    scan_record = ScanHistory(
        scan_type="Network Scan",
        target=body["target"],
        result=str(result),
        user_email=body.get("email", "unknown")
    )

    db.add(scan_record)

    db.commit()

    db.close()

    return result

@app.post("/register")
def register(user: dict):

    db = SessionLocal()

    new_user = User(
        email=user["email"],
        password=user["password"]
    )

    db.add(new_user)

    db.commit()

    db.close()

    return {
        "message": "User registered successfully"
    }

@app.post("/login")
def login(user: dict):

    db = SessionLocal()

    existing_user = db.query(User).filter(
        User.email == user["email"]
    ).first()

    if not existing_user:

        return {
            "message": "User not found"
        }

    valid_password = (
    user["password"] == existing_user.password
)

    if not valid_password:

        return {
            "message": "Invalid password"
        }

    access_token = create_access_token(
        data={
            "sub": existing_user.email
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/scan-history")
def get_scan_history():

    db = SessionLocal()

    scans = db.query(ScanHistory).all()

    result = []

    for scan in scans:

        result.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "result": scan.result
        })

    db.close()

    return result

@app.get("/scan-history")
def get_scan_history():

    db = SessionLocal()

    scans = db.query(ScanHistory).all()

    result = []

    for scan in scans:

        result.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "result": scan.result,
            "user_email": scan.user_email
        })

    db.close()

    return result

@app.get("/user-scans/{email}")
def get_user_scans(email: str):

    db = SessionLocal()

    scans = db.query(ScanHistory).filter(
        ScanHistory.user_email == email
    ).all()

    result = []

    for scan in scans:

        result.append({
            "id": scan.id,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "result": scan.result
        })

    db.close()

    return result

@app.get("/scan/{scan_id}")
def get_scan(scan_id: int):

    db = SessionLocal()

    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id
    ).first()

    db.close()

    if not scan:

        return {
            "message": "Scan not found"
        }

    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "result": scan.result,
        "user_email": scan.user_email
    }

@app.delete("/scan/{scan_id}")
def delete_scan(scan_id: int):

    db = SessionLocal()

    scan = db.query(ScanHistory).filter(
        ScanHistory.id == scan_id
    ).first()

    if not scan:

        return {
            "message": "Scan not found"
        }

    db.delete(scan)

    db.commit()

    db.close()

    return {
        "message": "Scan deleted successfully"
    }

@app.post("/api/scan/email")
@limiter.limit("5/minute")
async def scan_email_endpoint(
    request: Request,
    body: dict
):
    result = analyse_header(
        body["header"]
    )

    db = SessionLocal()

    scan_record = ScanHistory(
        scan_type="Email Analysis",
        target="Email Header",
        result=str(result),
        user_email=body.get("email", "unknown")
    )

    db.add(scan_record)

    db.commit()

    db.close()

    return result 