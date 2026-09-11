from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models.notification import Notification
from app.schemas.notification import (
    NotificationRead,
    NotificationCreate,
    NotificationListResponse
)

router = APIRouter(prefix="/notifications", tags=["Notification Pipeline"])


def create_system_notification(
    db: Session,
    title: str,
    message: str,
    severity: str = "Medium",
    notif_type: str = "threat_alert",
    employee_id: Optional[str] = None,
    alert_id: Optional[str] = None,
    link: Optional[str] = None
) -> Notification:
    """Helper utility to emit and persist a real notification in the database."""
    notif = Notification(
        title=title,
        message=message,
        severity=severity,
        type=notif_type,
        employee_id=employee_id,
        alert_id=alert_id,
        link=link,
        read=False
    )
    db.add(notif)
    db.commit()
    db.refresh(notif)
    return notif


@router.get("", response_model=NotificationListResponse)
def list_notifications(
    unread_only: bool = False,
    db: Session = Depends(get_db)
):
    """Retrieves the live notification stream from the database."""
    query = db.query(Notification)
    if unread_only:
        query = query.filter(Notification.read == False)

    items = query.order_by(desc(Notification.created_at)).all()
    unread_count = db.query(Notification).filter(Notification.read == False).count()

    return NotificationListResponse(
        total=len(items),
        unread_count=unread_count,
        items=[NotificationRead.model_validate(n) for n in items]
    )


@router.patch("/{notification_id}/read", response_model=NotificationRead)
def mark_notification_read(notification_id: int, db: Session = Depends(get_db)):
    """Marks an individual notification as read."""
    notif = db.query(Notification).filter(Notification.id == notification_id).first()
    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification #{notification_id} not found."
        )

    notif.read = True
    db.commit()
    db.refresh(notif)
    return NotificationRead.model_validate(notif)


@router.post("/mark-all-read")
def mark_all_notifications_read(db: Session = Depends(get_db)):
    """Marks all notifications as read."""
    updated = db.query(Notification).filter(Notification.read == False).update({"read": True})
    db.commit()
    return {"status": "success", "marked_read": updated}


@router.delete("")
def clear_all_notifications(db: Session = Depends(get_db)):
    """Clears all notifications from the database."""
    deleted = db.query(Notification).delete()
    db.commit()
    return {"status": "success", "cleared_count": deleted}
