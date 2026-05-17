from sqlalchemy import Column, Integer, String
from database import Base

class RiskReport(Base):

    __tablename__ = "risk_reports"

    id = Column(Integer, primary_key=True, index=True)

    device_name = Column(String)

    risk_score = Column(Integer)

    risk_level = Column(String)