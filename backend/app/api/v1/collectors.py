from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.api.v1.auth import get_current_user, require_roles
from app.collectors.manager import collector_manager
from app.schemas.collector import (
    CollectorStatus,
    CollectorListResponse,
    CollectorPulseRequest,
    CollectorPulseResponse,
    CollectorToggleResponse
)

router = APIRouter(prefix="/collectors", tags=["Log Collectors & Telemetry Sensors"])


@router.get("", response_model=CollectorListResponse)
def get_all_log_collectors(current_user: User = Depends(get_current_user)):
    """
    Retrieves real-time operational status, throughput (EPS),
    and health metrics for all registered enterprise log collectors and sensors.
    """
    collectors_data = collector_manager.list_collectors()
    active_count = sum(1 for c in collectors_data if c.get("status") == "Active")
    total_events = sum(c.get("events_collected", 0) for c in collectors_data)

    return CollectorListResponse(
        total_collectors=len(collectors_data),
        active_count=active_count,
        total_events_collected=total_events,
        fleet_health="Operational // Nominal" if active_count >= 4 else "Degraded // Maintenance",
        collectors=[CollectorStatus(**c) for c in collectors_data]
    )


@router.post("/{collector_id}/pulse", response_model=CollectorPulseResponse)
def trigger_collector_telemetry_pulse(
    collector_id: str,
    payload: CollectorPulseRequest = CollectorPulseRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["SOC Engineer", "Administrator"]))
):
    """
    Triggers an on-demand telemetry collection pulse from a sensor.
    Captures live activity logs, runs heuristic/Z-score analysis, and commits to database.
    """
    try:
        result = collector_manager.dispatch_pulse(
            db=db,
            collector_id=collector_id,
            anomaly_simulation=payload.anomaly_simulation,
            custom_employee_id=payload.custom_employee_id
        )
        return CollectorPulseResponse(**result)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log collector sensor '{collector_id}' not found."
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/{collector_id}/toggle", response_model=CollectorToggleResponse)
def toggle_collector_state(
    collector_id: str,
    current_user: User = Depends(require_roles(["SOC Engineer", "Administrator"]))
):
    """
    Enables or pauses a log collector sensor stream (SOC Engineer or Administrator only).
    """
    try:
        updated = collector_manager.toggle_collector(collector_id)
        return CollectorToggleResponse(
            collector_id=collector_id,
            status=updated["status"],
            message=f"Collector sensor '{updated['name']}' status changed to {updated['status']}."
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log collector sensor '{collector_id}' not found."
        )
