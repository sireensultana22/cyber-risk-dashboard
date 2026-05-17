from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm.session import Session

from models import DeviceData
from scoring import calculate_risk
from alerts import generate_alerts
from database import engine, SessionLocal
from db_models import Base, RiskReport


Base.metadata.create_all(bind=engine)

app = FastAPI()


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