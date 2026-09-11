import io
import csv
from datetime import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.employee import Employee
from app.models.alert import Alert
from app.models.activity import ActivityLog
from app.models.behavioral_profile import BehavioralProfile

router = APIRouter(prefix="/reports", tags=["Executive Reports & Export"])


@router.get("/executive")
def get_executive_ciso_report(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Generates an on-demand Executive CISO Insider Risk & Threat Intelligence Dossier."""
    employees = db.query(Employee).all()
    alerts = db.query(Alert).all()
    profiles = {p.employee_id: p for p in db.query(BehavioralProfile).all()}

    total_employees = len(employees)
    if total_employees == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Insufficient workforce data to generate executive report."
        )

    high_risk_emps = [e for e in employees if e.risk_level in ["High", "Critical"]]
    avg_score = round(sum(e.score or 0 for e in employees) / total_employees)

    # Department breakdown
    dept_map: Dict[str, Dict[str, Any]] = {}
    for emp in employees:
        d = emp.department or "Other"
        if d not in dept_map:
            dept_map[d] = {"identities": 0, "total_score": 0, "high_risk": 0, "alerts": 0}
        dept_map[d]["identities"] += 1
        dept_map[d]["total_score"] += emp.score or 0
        if emp.risk_level in ["High", "Critical"]:
            dept_map[d]["high_risk"] += 1

    for a in alerts:
        d = a.department
        if d in dept_map:
            dept_map[d]["alerts"] += 1

    department_summary = [
        {
            "department": dept,
            "identities": data["identities"],
            "avg_threat_score": round(data["total_score"] / data["identities"]),
            "high_risk_count": data["high_risk"],
            "active_alerts": data["alerts"]
        }
        for dept, data in dept_map.items()
    ]

    # Top priority containment watchlist
    top_threats = sorted(employees, key=lambda e: e.score or 0, reverse=True)[:5]
    watchlist = [
        {
            "id": e.id,
            "name": e.name,
            "department": e.department,
            "role": e.role,
            "status": e.status,
            "risk_level": e.risk_level,
            "score": e.score,
            "primary_anomaly": e.details or e.last_activity,
            "behavioral_indicators": e.behavioral_indicators or []
        }
        for e in top_threats
    ]

    # Attack vector breakdown
    vector_counts: Dict[str, int] = {}
    for a in alerts:
        v = a.vector or "Behavioral Anomaly"
        vector_counts[v] = vector_counts.get(v, 0) + 1

    critical_alerts_count = sum(1 for a in alerts if a.severity == "Critical")

    return {
        "report_id": f"REP-CISO-{datetime.utcnow().strftime('%Y%m%d%H%M')}",
        "generated_at": datetime.utcnow().isoformat(),
        "classification": "TOP SECRET // CISO EXECUTIVE ACTION DIRECTIVE",
        "posture_summary": {
            "total_monitored_workforce": total_employees,
            "composite_risk_score": avg_score,
            "risk_tier": "Critical Risk" if avg_score >= 70 else "Elevated Risk" if avg_score >= 40 else "Low Risk",
            "high_risk_identities_count": len(high_risk_emps),
            "high_risk_ratio_pct": round((len(high_risk_emps) / total_employees) * 100, 1),
            "active_alerts_total": len(alerts),
            "critical_severity_alerts": critical_alerts_count
        },
        "departmental_risk_matrix": department_summary,
        "priority_containment_watchlist": watchlist,
        "threat_vector_distribution": vector_counts,
        "executive_recommendations": [
            "Mandate immediate hardware token MFA re-authentication for all Finance and Engineering identities.",
            "Enforce endpoint DLP policy blocking USB mass-copying on all Legal department workstations.",
            "Audit privileged AWS IAM roles and revoke unapproved AdministratorAccess attachments immediately."
        ]
    }


@router.get("/employee/{employee_id}")
def get_employee_investigation_report(employee_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Generates a complete forensic investigation dossier for a specific monitored employee."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Employee with ID {employee_id} not found."
        )

    alerts = db.query(Alert).filter(Alert.employee_id == employee_id).all()
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.employee_id == employee_id).first()

    return {
        "dossier_id": f"DOS-{emp.id}-{datetime.utcnow().strftime('%Y%m%d')}",
        "generated_at": datetime.utcnow().isoformat(),
        "identity": {
            "id": emp.id,
            "name": emp.name,
            "email": emp.email,
            "department": emp.department,
            "role": emp.role,
            "status": emp.status,
            "risk_level": emp.risk_level,
            "score": emp.score,
            "workstation": emp.workstation,
            "ip_address": emp.ip_address,
            "location": emp.location
        },
        "behavioral_profile": {
            "sample_size": profile.sample_size if profile else 0,
            "current_deviation_score": profile.current_deviation_score if profile else 0,
            "habitual_workstations": profile.habitual_workstations if profile else [emp.workstation],
            "habitual_ips": profile.habitual_ips if profile else [emp.ip_address],
            "metrics": profile.metrics if profile else {},
            "deviation_factors": profile.deviation_factors if profile else []
        },
        "security_incidents": [
            {
                "alert_id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "vector": a.vector,
                "summary": a.summary,
                "evidence": a.evidence
            }
            for a in alerts
        ]
    }


@router.get("/export/csv")
def export_system_csv(
    format: str = Query("employees", pattern="^(employees|activities|alerts)$"),
    db: Session = Depends(get_db)
):
    """Exports monitored workforce, telemetry activity logs, or alerts as a downloadable CSV audit file."""
    output = io.StringIO()
    writer = csv.writer(output)

    if format == "activities":
        logs = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(1000).all()
        writer.writerow([
            "activity_id",
            "employee_id",
            "activity_type",
            "source_ip",
            "workstation",
            "timestamp",
            "is_anomalous",
            "anomaly_score",
            "details"
        ])
        for log in logs:
            writer.writerow([
                log.id,
                log.employee_id,
                log.activity_type,
                log.source_ip,
                log.workstation,
                log.timestamp.isoformat() if log.timestamp else "",
                log.is_anomalous,
                log.anomaly_score,
                str(log.details or {})
            ])
        filename = f"telemetry_activity_logs_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    elif format == "alerts":
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).all()
        writer.writerow([
            "alert_id",
            "title",
            "severity",
            "status",
            "employee_id",
            "employee_name",
            "department",
            "vector",
            "timestamp"
        ])
        for a in alerts:
            writer.writerow([
                a.id,
                a.title,
                a.severity,
                a.status,
                a.employee_id,
                a.employee_name,
                a.department,
                a.vector,
                a.timestamp
            ])
        filename = f"security_alerts_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    else:
        employees = db.query(Employee).order_by(Employee.id.asc()).all()
        writer.writerow([
            "Employee ID",
            "Full Name",
            "Email",
            "Department",
            "Role",
            "Status",
            "Risk Level",
            "Threat Score",
            "Workstation",
            "IP Address",
            "Location",
            "Last Activity"
        ])
        for emp in employees:
            writer.writerow([
                emp.id,
                emp.name,
                emp.email,
                emp.department,
                emp.role,
                emp.status,
                emp.risk_level,
                emp.score,
                emp.workstation,
                emp.ip_address,
                emp.location,
                emp.last_activity
            ])
        filename = f"insider_threat_workforce_audit_{datetime.utcnow().strftime('%Y%m%d')}.csv"

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
