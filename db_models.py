from sqlalchemy import Column, Integer, String, Text
import database
from database import Base

class RiskReport(database.Base):

    __tablename__ = "risk_reports"

    id = Column(Integer, primary_key=True, index=True)

    device_name = Column(String)

    risk_score = Column(Integer)

    risk_level = Column(String)

from sqlalchemy import Column, Integer, String
class User(database.Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    email = Column(String, unique=True, index=True)

    password = Column(String)

class ScanHistory(database.Base):

    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)

    scan_type = Column(String)

    target = Column(String)

    result = Column(Text)

    user_email = Column(String)