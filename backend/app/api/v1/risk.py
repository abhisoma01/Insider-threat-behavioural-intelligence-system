from typing import List, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models.employee import Employee
from app.models.alert import Alert
from app.models.activity import ActivityLog

router = APIRouter(prefix='/risk', tags=['Behavioral Risk Telemetry and Analytics'])


@router.get('/overview')
def get_risk_overview(db: Session = Depends(get_db)) -> Dict[str, Any]:
    employees = db.query(Employee).all()
    total = len(employees)

    if total == 0:
        return {
            'compositeRiskScore': 15,
            'riskTier': 'Low Risk',
            'monitoredIdentities': 0,
            'distribution': {'high': 0, 'medium': 0, 'low': 0}
        }

    high_count = sum(1 for e in employees if e.risk_level in ['High', 'Critical'])
    medium_count = sum(1 for e in employees if e.risk_level == 'Medium')
    low_count = sum(1 for e in employees if e.risk_level == 'Low')
    avg_score = round(sum(e.score or 0 for e in employees) / total)

    risk_tier = 'Critical Risk' if avg_score >= 70 else 'Elevated Risk' if avg_score >= 40 else 'Low Risk'

    return {
        'compositeRiskScore': avg_score,
        'riskTier': risk_tier,
        'monitoredIdentities': total,
        'distribution': {
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        }
    }


@router.get('/trajectory')
def get_risk_trajectory(
    timeframe: str = Query('30d', pattern='^(7d|30d|90d)$'),
    db: Session = Depends(get_db)
) -> List[Dict[str, Any]]:
    """
    Dynamically computes historical risk trajectory and anomaly event velocity
    by aggregating ActivityLog and Alert telemetry over calendar time windows.
    """
    employees = db.query(Employee).all()
    total = len(employees)
    base_score = round(sum(e.score or 0 for e in employees) / total) if total > 0 else 20

    # Anchor to the latest telemetry timestamp or now
    latest_ts = db.query(func.max(ActivityLog.timestamp)).scalar()
    anchor = latest_ts if latest_ts else datetime.utcnow()
    anchor_date = anchor.date()

    points: List[Dict[str, Any]] = []

    if timeframe == '7d':
        for i in range(6, -1, -1):
            day = anchor_date - timedelta(days=i)
            day_start = datetime.combine(day, datetime.min.time())
            day_end = datetime.combine(day, datetime.max.time())
            date_label = day.strftime('%b %d')

            anomalies = db.query(func.count(ActivityLog.id)).filter(
                ActivityLog.timestamp >= day_start,
                ActivityLog.timestamp <= day_end,
                ActivityLog.is_anomalous == True
            ).scalar() or 0

            mitigated = db.query(func.count(Alert.id)).filter(
                Alert.updated_at >= day_start,
                Alert.updated_at <= day_end,
                Alert.status.in_(['Mitigated', 'Resolved', 'Dismissed'])
            ).scalar() or 0

            score_delta = min(25, anomalies * 3) - min(15, mitigated * 2)
            day_score = max(5, min(100, base_score + score_delta))

            points.append({
                'date': date_label,
                'compositeScore': day_score,
                'anomalies': anomalies,
                'mitigated': mitigated
            })

    elif timeframe == '90d':
        for w in range(11, -1, -1):
            week_start = datetime.combine(anchor_date - timedelta(days=(w + 1) * 7), datetime.min.time())
            week_end = datetime.combine(anchor_date - timedelta(days=w * 7), datetime.max.time())
            date_label = f'Week {12 - w}'

            anomalies = db.query(func.count(ActivityLog.id)).filter(
                ActivityLog.timestamp >= week_start,
                ActivityLog.timestamp <= week_end,
                ActivityLog.is_anomalous == True
            ).scalar() or 0

            mitigated = db.query(func.count(Alert.id)).filter(
                Alert.updated_at >= week_start,
                Alert.updated_at <= week_end,
                Alert.status.in_(['Mitigated', 'Resolved', 'Dismissed'])
            ).scalar() or 0

            score_delta = min(20, round(anomalies * 0.8)) - min(12, round(mitigated * 0.5))
            week_score = max(5, min(100, base_score + score_delta))

            points.append({
                'date': date_label,
                'compositeScore': week_score,
                'anomalies': anomalies,
                'mitigated': mitigated
            })

    else:
        # 30-day timeframe: 15 bi-daily sample intervals
        for i in range(14, -1, -1):
            day_end_dt = anchor_date - timedelta(days=i * 2)
            day_start_dt = day_end_dt - timedelta(days=1)
            t_start = datetime.combine(day_start_dt, datetime.min.time())
            t_end = datetime.combine(day_end_dt, datetime.max.time())
            date_label = day_end_dt.strftime('%b %d')

            anomalies = db.query(func.count(ActivityLog.id)).filter(
                ActivityLog.timestamp >= t_start,
                ActivityLog.timestamp <= t_end,
                ActivityLog.is_anomalous == True
            ).scalar() or 0

            mitigated = db.query(func.count(Alert.id)).filter(
                Alert.updated_at >= t_start,
                Alert.updated_at <= t_end,
                Alert.status.in_(['Mitigated', 'Resolved', 'Dismissed'])
            ).scalar() or 0

            score_delta = min(22, anomalies * 2) - min(10, mitigated)
            period_score = max(5, min(100, base_score + score_delta))

            points.append({
                'date': date_label,
                'compositeScore': period_score,
                'anomalies': anomalies,
                'mitigated': mitigated
            })

    return points


@router.get('/threat-vectors')
def get_threat_vectors(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """
    Dynamically computes observed incident velocity and empirical baseline thresholds
    across major insider threat vectors from database alerts and behavioral activity telemetry.
    """
    alerts = db.query(Alert).all()
    anomalous_activities = db.query(ActivityLog).filter(ActivityLog.is_anomalous == True).all()

    vectors_config = [
        {
            "vector": "Data Exfiltration",
            "alert_keywords": ["exfiltration", "clone", "download", "egress"],
            "activity_types": ["git_clone_mass", "mass_file_download"],
            "default_baseline": 12
        },
        {
            "vector": "Anomalous Auth",
            "alert_keywords": ["auth", "login", "credential", "brute", "mfa"],
            "activity_types": ["failed_login", "unauthorized_ip"],
            "default_baseline": 6
        },
        {
            "vector": "Privilege Escalation",
            "alert_keywords": ["privilege", "iam", "root", "elevation", "admin"],
            "activity_types": ["iam_policy_modification"],
            "default_baseline": 3
        },
        {
            "vector": "Off-Hours Access",
            "alert_keywords": ["off-hours", "night", "weekend"],
            "activity_types": [],
            "default_baseline": 5
        },
        {
            "vector": "Removable Storage",
            "alert_keywords": ["usb", "storage", "media", "removable"],
            "activity_types": ["usb_device_mounted"],
            "default_baseline": 2
        },
        {
            "vector": "Data Access Violation",
            "alert_keywords": ["compensation", "access violation", "unauthorized query", "vault"],
            "activity_types": ["sensitive_data_export", "unauthorized_query"],
            "default_baseline": 4
        }
    ]

    results = []
    for cfg in vectors_config:
        v_name = cfg["vector"]
        keywords = cfg["alert_keywords"]
        act_types = cfg["activity_types"]

        alert_count = sum(
            1 for a in alerts
            if (a.vector and any(kw in a.vector.lower() for kw in keywords))
            or (a.title and any(kw in a.title.lower() for kw in keywords))
        )

        if v_name == "Off-Hours Access":
            activity_count = sum(
                1 for act in anomalous_activities
                if act.timestamp and (act.timestamp.hour < 7 or act.timestamp.hour >= 19)
            )
        else:
            activity_count = sum(
                1 for act in anomalous_activities
                if act.activity_type in act_types
            )

        observed = alert_count + activity_count
        baseline = cfg["default_baseline"]

        if observed >= baseline * 2:
            impact = "Critical"
        elif observed >= baseline:
            impact = "High"
        elif observed > 0:
            impact = "Medium"
        else:
            impact = "Low"

        results.append({
            "vector": v_name,
            "observed": observed,
            "baseline": baseline,
            "riskImpact": impact
        })

    return results
