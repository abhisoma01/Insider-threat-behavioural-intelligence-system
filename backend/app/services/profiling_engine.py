import math
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
from sqlalchemy.orm import Session
from app.models.activity import ActivityLog
from app.models.employee import Employee
from app.models.behavioral_profile import BehavioralProfile

FEATURE_KEYS = [
    "daily_action_count",
    "off_hours_activity_ratio",
    "failed_login_count",
    "data_transfer_volume_mb",
    "file_access_frequency",
    "sensitive_resource_access_count",
    "usb_device_events",
    "distinct_ip_count",
    "distinct_workstation_count"
]

FEATURE_WEIGHTS = {
    "data_transfer_volume_mb": 25,
    "sensitive_resource_access_count": 25,
    "usb_device_events": 20,
    "failed_login_count": 15,
    "off_hours_activity_ratio": 15,
    "file_access_frequency": 10,
    "daily_action_count": 10,
    "distinct_ip_count": 10,
    "distinct_workstation_count": 10
}


def is_off_hours(dt: datetime) -> bool:
    """Standard business hours are Monday-Friday, 08:00 to 18:00 local corporate time."""
    if dt.weekday() >= 5:  # Saturday or Sunday
        return True
    return dt.hour < 8 or dt.hour >= 18


def extract_daily_features(logs: List[ActivityLog]) -> Dict[str, Dict[str, float]]:
    """Groups activity logs by calendar day and computes normalized daily feature vectors."""
    days: Dict[str, List[ActivityLog]] = defaultdict(list)
    for log in logs:
        day_key = log.timestamp.strftime("%Y-%m-%d")
        days[day_key].append(log)

    daily_vectors = {}
    for day_str, day_logs in days.items():
        total_actions = len(day_logs)
        off_hours_count = sum(1 for log in day_logs if is_off_hours(log.timestamp))

        failed_logins = sum(
            1 for log in day_logs
            if "failed_login" in log.activity_type.lower() or "auth_fail" in log.activity_type.lower()
        )

        total_bytes = 0.0
        file_accesses = 0
        sensitive_accesses = 0
        usb_events = 0
        unique_ips = set()
        unique_ws = set()

        for log in day_logs:
            act_type = log.activity_type.lower()
            details = log.details or {}

            # Data volume extraction (supports bytes, mb, or file size in details)
            if "bytes" in details:
                total_bytes += float(details.get("bytes", 0)) / (1024 * 1024)
            elif "mb" in details:
                total_bytes += float(details.get("mb", 0))
            elif "file_size_mb" in details:
                total_bytes += float(details.get("file_size_mb", 0))
            elif "mass" in act_type or "exfil" in act_type or "clone" in act_type:
                total_bytes += float(details.get("volume_mb", 500.0))

            # File and repository access tracking
            if any(k in act_type for k in ["file", "download", "clone", "export", "read_record"]):
                file_accesses += 1

            # Sensitive resource access tracking
            if (
                details.get("is_confidential") or
                "patent" in str(details).lower() or
                "compensation" in str(details).lower() or
                "iam" in act_type or
                "privilege" in act_type or
                "confidential" in str(details).lower()
            ):
                sensitive_accesses += 1

            # Removable media detection
            if "usb" in act_type or "removable" in act_type:
                usb_events += 1

            if log.source_ip:
                unique_ips.add(log.source_ip)
            if log.workstation:
                unique_ws.add(log.workstation)

        daily_vectors[day_str] = {
            "daily_action_count": float(total_actions),
            "off_hours_activity_ratio": round(off_hours_count / max(1, total_actions), 4),
            "failed_login_count": float(failed_logins),
            "data_transfer_volume_mb": round(total_bytes, 2),
            "file_access_frequency": float(file_accesses),
            "sensitive_resource_access_count": float(sensitive_accesses),
            "usb_device_events": float(usb_events),
            "distinct_ip_count": float(len(unique_ips)),
            "distinct_workstation_count": float(len(unique_ws))
        }

    return daily_vectors


def compute_baseline_statistics(daily_vectors: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
    """Calculates empirical mean, standard deviation, min, and max for each behavioral feature."""
    if not daily_vectors:
        return {
            feat: {"mean": 0.0, "std": 1.0, "min": 0.0, "max": 0.0}
            for feat in FEATURE_KEYS
        }

    n = len(daily_vectors)
    stats = {}
    for feat in FEATURE_KEYS:
        values = [v.get(feat, 0.0) for v in daily_vectors]
        mean_val = sum(values) / n
        variance = sum((x - mean_val) ** 2 for x in values) / max(1, n - 1) if n > 1 else 0.0
        std_val = math.sqrt(variance)

        # Apply numerical stability threshold (epsilon = 0.05) to prevent division by zero
        stable_std = max(round(std_val, 3), 0.05)

        stats[feat] = {
            "mean": round(mean_val, 2),
            "std": stable_std,
            "min": round(min(values), 2),
            "max": round(max(values), 2)
        }

    return stats


def extract_habitual_patterns(logs: List[ActivityLog]) -> Tuple[List[str], List[str], Dict[str, Any]]:
    """Extracts habitual workstations, IP subnets, and active hour envelopes from historical logs."""
    ws_counts: Dict[str, int] = defaultdict(int)
    ip_counts: Dict[str, int] = defaultdict(int)
    hours = []

    for log in logs:
        if log.workstation and log.workstation != "WS-UNKNOWN":
            ws_counts[log.workstation] += 1
        if log.source_ip:
            ip_counts[log.source_ip] += 1
        hours.append(log.timestamp.hour)

    habitual_ws = [ws for ws, count in ws_counts.items() if count >= 1]
    habitual_ips = [ip for ip, count in ip_counts.items() if count >= 1]

    typical_hours = {
        "start_hour": min(hours) if hours else 8,
        "end_hour": max(hours) if hours else 18,
        "mode_active_span": "08:00 - 18:00"
    }

    return habitual_ws, habitual_ips, typical_hours


def evaluate_deviation(
    profile: BehavioralProfile,
    evaluated_logs: List[Any]
) -> Dict[str, Any]:
    """
    Compares a batch of evaluated activities against an employee's established behavioral profile.
    Produces per-feature Z-scores, categorical deviation flags, and a composite normalized score.
    """
    if not evaluated_logs:
        return {
            "employee_id": profile.employee_id,
            "evaluated_events_count": 0,
            "composite_deviation_score": 0,
            "severity_tier": "Baseline Normal",
            "deviation_factors": [],
            "feature_vector": {f: 0.0 for f in FEATURE_KEYS},
            "evaluated_at": datetime.utcnow()
        }

    # Extract observed features from the input batch
    total_actions = len(evaluated_logs)
    off_hours_count = 0
    failed_logins = 0
    total_bytes = 0.0
    file_accesses = 0
    sensitive_accesses = 0
    usb_events = 0
    observed_ips = set()
    observed_ws = set()

    for item in evaluated_logs:
        # Support both ActivityLog ORM objects and raw dictionaries
        if hasattr(item, "activity_type"):
            act_type = (item.activity_type or "").lower()
            ts = item.timestamp or datetime.utcnow()
            details = item.details or {}
            sip = item.source_ip or ""
            sws = item.workstation or ""
        elif isinstance(item, dict):
            act_type = (item.get("activity_type", "") or "").lower()
            ts = item.get("timestamp", datetime.utcnow())
            details = item.get("details", {}) or {}
            sip = item.get("source_ip", "")
            sws = item.get("workstation", "")
        else:
            continue

        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.utcnow()

        if is_off_hours(ts):
            off_hours_count += 1

        if "failed_login" in act_type or "auth_fail" in act_type:
            failed_logins += 1

        if "bytes" in details:
            total_bytes += float(details.get("bytes", 0)) / (1024 * 1024)
        elif "mb" in details:
            total_bytes += float(details.get("mb", 0))
        elif "file_size_mb" in details:
            total_bytes += float(details.get("file_size_mb", 0))
        elif any(k in act_type for k in ["mass", "exfil", "clone"]):
            total_bytes += float(details.get("volume_mb", 500.0))

        if any(k in act_type for k in ["file", "download", "clone", "export", "read_record"]):
            file_accesses += 1

        if (
            details.get("is_confidential") or
            "patent" in str(details).lower() or
            "compensation" in str(details).lower() or
            "iam" in act_type or
            "privilege" in act_type or
            "confidential" in str(details).lower()
        ):
            sensitive_accesses += 1

        if "usb" in act_type or "removable" in act_type:
            usb_events += 1

        if sip:
            observed_ips.add(sip)

        if sws:
            observed_ws.add(sws)

    observed_vector = {
        "daily_action_count": float(total_actions),
        "off_hours_activity_ratio": round(off_hours_count / max(1, total_actions), 4),
        "failed_login_count": float(failed_logins),
        "data_transfer_volume_mb": round(total_bytes, 2),
        "file_access_frequency": float(file_accesses),
        "sensitive_resource_access_count": float(sensitive_accesses),
        "usb_device_events": float(usb_events),
        "distinct_ip_count": float(len(observed_ips)),
        "distinct_workstation_count": float(len(observed_ws))
    }

    metrics = profile.metrics or {}
    deviation_factors = []
    total_deviation_points = 0.0

    # 1. Feature Z-score evaluation
    for feat, observed_val in observed_vector.items():
        feat_stat = metrics.get(feat, {"mean": 0.0, "std": 1.0})
        mean_val = feat_stat.get("mean", 0.0)
        std_val = max(feat_stat.get("std", 1.0), 0.05)

        z_score = round((observed_val - mean_val) / std_val, 2)

        # Check for statistically significant elevation or acute security indicator
        is_elevated = (z_score >= 1.5 and observed_val > mean_val)
        if feat == "usb_device_events" and observed_val >= 1.0:
            is_elevated = True
            if z_score < 1.5:
                z_score = max(z_score, 2.5)

        if is_elevated:
            if z_score >= 3.0:
                severity = "Critical"
                score_impact = 35
            elif z_score >= 2.0:
                severity = "High"
                score_impact = 20
            else:
                severity = "Moderate"
                score_impact = 10

            explanation = (
                f"{feat.replace('_', ' ').title()} observed at {observed_val:.1f}, "
                f"which is {z_score} standard deviations above baseline mean ({mean_val:.1f})."
            )

            deviation_factors.append({
                "feature": feat,
                "observed": round(observed_val, 2),
                "baseline_mean": round(mean_val, 2),
                "z_score": z_score,
                "severity": severity,
                "explanation": explanation
            })
            total_deviation_points += score_impact

    # 2. Categorical Novelty Evaluation: Unrecognized Workstation
    habitual_ws = set(profile.habitual_workstations or [])
    new_ws = observed_ws - habitual_ws
    if new_ws and habitual_ws:
        new_ws_str = ", ".join(list(new_ws)[:3])
        deviation_factors.append({
            "feature": "novel_workstation",
            "observed": len(new_ws),
            "baseline_mean": 0.0,
            "z_score": 3.5,
            "severity": "High",
            "explanation": f"Activity executed from unrecognized workstation(s): {new_ws_str}."
        })
        total_deviation_points += 25

    # 3. Categorical Novelty Evaluation: Unrecognized IP / Subnet
    habitual_ips = set(profile.habitual_ips or [])
    new_ips = observed_ips - habitual_ips
    if new_ips and habitual_ips:
        new_ip_str = ", ".join(list(new_ips)[:3])
        deviation_factors.append({
            "feature": "novel_network_ip",
            "observed": len(new_ips),
            "baseline_mean": 0.0,
            "z_score": 3.0,
            "severity": "High",
            "explanation": f"Authentication from unapproved external or foreign IP: {new_ip_str}."
        })
        total_deviation_points += 20

    # Composite normalized deviation score (0 - 100)
    composite_score = min(100, int(round(total_deviation_points)))

    if composite_score >= 70:
        severity_tier = "Critical Anomaly"
    elif composite_score >= 40:
        severity_tier = "High Deviation"
    elif composite_score >= 15:
        severity_tier = "Elevated Anomaly"
    else:
        severity_tier = "Baseline Normal"

    return {
        "employee_id": profile.employee_id,
        "evaluated_events_count": total_actions,
        "composite_deviation_score": composite_score,
        "severity_tier": severity_tier,
        "deviation_factors": deviation_factors,
        "feature_vector": observed_vector,
        "evaluated_at": datetime.utcnow()
    }


def recalculate_employee_baseline(
    db: Session,
    employee_id: str,
    window_days: int = 30
) -> BehavioralProfile:
    """
    Extracts multi-day activity log features for an employee, computes empirical baseline statistics,
    and upserts the BehavioralProfile record in the database.
    """
    cutoff = datetime.utcnow() - timedelta(days=window_days)
    logs = (
        db.query(ActivityLog)
        .filter(ActivityLog.employee_id == employee_id)
        .filter(ActivityLog.timestamp >= cutoff)
        .order_by(ActivityLog.timestamp.asc())
        .all()
    )

    # 1. Feature Extraction over Daily Windows
    daily_vectors = extract_daily_features(logs)
    metrics_stats = compute_baseline_statistics(list(daily_vectors.values()))
    habitual_ws, habitual_ips, typical_hours = extract_habitual_patterns(logs)

    # 2. Check or Create BehavioralProfile Record
    profile = db.query(BehavioralProfile).filter(BehavioralProfile.employee_id == employee_id).first()
    if not profile:
        profile = BehavioralProfile(
            employee_id=employee_id,
            profiling_window_days=window_days,
            sample_size=len(logs),
            metrics=metrics_stats,
            habitual_workstations=habitual_ws,
            habitual_ips=habitual_ips,
            typical_active_hours=typical_hours,
            current_deviation_score=0,
            deviation_factors=[]
        )
        db.add(profile)
    else:
        profile.profiling_window_days = window_days
        profile.sample_size = len(logs)
        profile.metrics = metrics_stats
        profile.habitual_workstations = habitual_ws
        profile.habitual_ips = habitual_ips
        profile.typical_active_hours = typical_hours
        profile.last_profiled_at = datetime.utcnow()

    # 3. Evaluate Recent Deviation (activities from the last 24h)
    last_24h_cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_logs = [log for log in logs if log.timestamp >= last_24h_cutoff]
    if recent_logs:
        deviation_result = evaluate_deviation(profile, recent_logs)
        profile.current_deviation_score = deviation_result["composite_deviation_score"]
        profile.deviation_factors = deviation_result["deviation_factors"]
    else:
        profile.current_deviation_score = 0
        profile.deviation_factors = []

    db.commit()
    db.refresh(profile)
    return profile
