from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class DeviationFactor(BaseModel):
    feature: str
    observed: float
    baseline_mean: float
    z_score: float
    severity: str  # Normal, Moderate, High, Critical
    explanation: str


class BehavioralProfileSummary(BaseModel):
    employee_id: str
    employee_name: str
    department: str
    sample_size: int
    current_deviation_score: int
    risk_level: str
    last_profiled_at: datetime
    active_anomalies_count: int


class BehavioralProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    employee_id: str
    profiling_window_days: int
    sample_size: int
    last_profiled_at: datetime
    metrics: Dict[str, Any]
    habitual_workstations: List[str]
    habitual_ips: List[str]
    typical_active_hours: Dict[str, Any]
    current_deviation_score: int
    deviation_factors: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class BaselineRecalculateRequest(BaseModel):
    employee_id: Optional[str] = Field(None, description="Specific employee ID to profile, or None for all")
    window_days: int = Field(30, ge=1, le=180, description="Historical lookback window in days")


class BaselineRecalculateResponse(BaseModel):
    status: str
    profiles_updated: int
    message: str
    profiles: List[Dict[str, Any]]


class DeviationEvaluationRequest(BaseModel):
    employee_id: str
    activities: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Optional batch of activities to evaluate; if omitted, evaluates recent unprofiled DB logs"
    )


class DeviationEvaluationResponse(BaseModel):
    employee_id: str
    evaluated_events_count: int
    composite_deviation_score: int
    severity_tier: str  # Baseline Normal, Elevated Anomaly, High Deviation, Critical Anomaly
    deviation_factors: List[DeviationFactor]
    feature_vector: Dict[str, float]
    evaluated_at: datetime
