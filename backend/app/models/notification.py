from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from app.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(50), default="Medium", index=True)  # Critical, High, Medium, Low, Info
    type = Column(String(100), default="threat_alert", index=True)  # threat_alert, containment, investigation, compliance
    employee_id = Column(String(50), ForeignKey("employees.id"), nullable=True, index=True)
    alert_id = Column(String(50), ForeignKey("alerts.id"), nullable=True, index=True)
    read = Column(Boolean, default=False, index=True)
    link = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
