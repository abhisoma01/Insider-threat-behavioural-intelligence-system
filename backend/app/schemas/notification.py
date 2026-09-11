from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    message: str
    severity: str
    type: str
    employee_id: Optional[str] = None
    alert_id: Optional[str] = None
    read: bool
    link: Optional[str] = None
    created_at: datetime


class NotificationCreate(BaseModel):
    title: str
    message: str
    severity: str = "Medium"
    type: str = "threat_alert"
    employee_id: Optional[str] = None
    alert_id: Optional[str] = None
    link: Optional[str] = None


class NotificationListResponse(BaseModel):
    total: int
    unread_count: int
    items: List[NotificationRead]
