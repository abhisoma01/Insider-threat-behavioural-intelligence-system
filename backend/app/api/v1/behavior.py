from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.employee import Employee
from app.models.behavioral_profile import BehavioralProfile
from app.models.activity import ActivityLog
from app.models.user import User
from app.api.v1.auth import require_roles
from app.schemas.behavior import (
    BehavioralProfileRead,
    BehavioralProfileSummary,
    BaselineRecalculateRequest,
    BaselineRecalculateResponse,
    DeviationEvaluationRequest,
    DeviationEvaluationResponse,
    DeviationFactor
)
from app.services.profiling_engine import (
    recalculate_employee_baseline,
    evaluate_deviation
)

router = APIRouter(prefix="/behavior", tags=["Behavioral Profiling & Baseline Engine"])


@router.get("/profiles", response_model=List[BehavioralProfileSummary])
def get_all_behavioral_profiles(db: Session = Depends(get_db)):
    """Retrieves high-level behavioral profiling summaries for all monitored employees."""
    employees = db.query(Employee).all()
    profiles = {p.employee_id: p for p in db.query(BehavioralProfile).all()}

    summaries = []
    for emp in employees:
        prof = profiles.get(emp.id)
        if prof:
            dev_score = prof.current_deviation_score
            sample_size = prof.sample_size
            last_profiled = prof.last_profiled_at
            anomalies_count = len(prof.deviation_factors or [])
        else:
            dev_score = 0
            sample_size = 0
            last_profiled = emp.created_at
            anomalies_count = 0

        summaries.append(
            BehavioralProfileSummary(
                employee_id=emp.id,
                employee_name=emp.name,
                department=emp.department,
                sample_size=sample_size,
                current_deviation_score=dev_score,
                risk_level=emp.risk_level,
                last_profiled_at=last_profiled,
                active_anomalies_count=anomalies_count
            )
        )

    return summaries


@router.get("/profiles/{employee_id}", response_model=BehavioralProfileRead)
def get_employee_behavioral_profile(employee_id: str, db: Session = Depends(get_db)):
    """Retrieves the complete empirical behavioral baseline and deviation analysis for an employee."""
    employee = db.query(Employee).filter(Employee.id == employee_id).first()
    if not employee:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Employee with ID {employee_id} not found."
        )

    profile = db.query(BehavioralProfile).filter(BehavioralProfile.employee_id == employee_id).first()
    if not profile:
        # Generate on-demand if not already created
        profile = recalculate_employee_baseline(db, employee_id)

    return BehavioralProfileRead.model_validate(profile)


@router.post("/recalculate-baseline", response_model=BaselineRecalculateResponse)
def trigger_baseline_recalculation(
    payload: BaselineRecalculateRequest = BaselineRecalculateRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(["SOC Engineer", "Administrator"]))
):
    """
    Triggers feature extraction and statistical baseline generation from multi-day activity logs.
    Can be run for a specific employee or across the entire monitored workforce.
    """
    target_ids = []
    if payload.employee_id:
        emp = db.query(Employee).filter(Employee.id == payload.employee_id).first()
        if not emp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Employee with ID {payload.employee_id} not found."
            )
        target_ids.append(emp.id)
    else:
        employees = db.query(Employee).all()
        target_ids = [e.id for e in employees]

    updated_profiles = []
    for emp_id in target_ids:
        prof = recalculate_employee_baseline(db, emp_id, window_days=payload.window_days)
        updated_profiles.append({
            "employee_id": prof.employee_id,
            "sample_size": prof.sample_size,
            "current_deviation_score": prof.current_deviation_score,
            "last_profiled_at": prof.last_profiled_at.isoformat()
        })

    return BaselineRecalculateResponse(
        status="success",
        profiles_updated=len(updated_profiles),
        message=f"Successfully extracted behavioral features and generated baselines for {len(updated_profiles)} identities.",
        profiles=updated_profiles
    )


@router.post("/evaluate-deviation", response_model=DeviationEvaluationResponse)
def evaluate_activity_deviation(
    payload: DeviationEvaluationRequest,
    db: Session = Depends(get_db)
):
    """
    Evaluates an activity batch or recent logs against an employee's established behavioral profile.
    Produces feature Z-scores, categorical novelty detection, and explainability vectors.
    """
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.employee_id == payload.employee_id).first()
    if not profile:
        profile = recalculate_employee_baseline(db, payload.employee_id)

    if payload.activities is not None:
        raw_logs = payload.activities
    else:
        # Load the latest 50 activities for this employee
        raw_logs = (
            db.query(ActivityLog)
            .filter(ActivityLog.employee_id == payload.employee_id)
            .order_by(ActivityLog.timestamp.desc())
            .limit(50)
            .all()
        )

    result = evaluate_deviation(profile, raw_logs)
    factors = [DeviationFactor(**f) for f in result["deviation_factors"]]

    return DeviationEvaluationResponse(
        employee_id=result["employee_id"],
        evaluated_events_count=result["evaluated_events_count"],
        composite_deviation_score=result["composite_deviation_score"],
        severity_tier=result["severity_tier"],
        deviation_factors=factors,
        feature_vector=result["feature_vector"],
        evaluated_at=result["evaluated_at"]
    )
