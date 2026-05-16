from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import DeviceData
from scoring import calculate_risk
from alerts import generate_alerts
from database import reports


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

    alerts = generate_alerts(result)

    final_report = {

        "device_name":
        data.device_name,

        "risk_score":
        result["risk_score"],

        "risk_level":
        result["risk_level"],

        "issues_found":
        result["issues_found"],

        "recommendations":
        result["recommendations"],

        "alerts":
        alerts
    }

    reports.append(final_report)

    return final_report


@app.get("/reports")
def get_reports():

    return reports


@app.get("/dashboard-summary")
def dashboard_summary():

    total_devices = len(reports)

    high_risk = sum(
        1 for report in reports
        if report["risk_level"] == "HIGH"
    )

    medium_risk = sum(
        1 for report in reports
        if report["risk_level"] == "MEDIUM"
    )

    low_risk = sum(
        1 for report in reports
        if report["risk_level"] == "LOW"
    )

    return {

        "total_devices":
        total_devices,

        "high_risk_devices":
        high_risk,

        "medium_risk_devices":
        medium_risk,

        "low_risk_devices":
        low_risk
    }