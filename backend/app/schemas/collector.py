from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class CollectorStatus(BaseModel):
    id: str
    name: str
    type: str  # os_auth, removable_media, data_egress, cloud_audit, vpn_gateway
    description: str
    source_target: str
    status: str  # Active, Streaming, Paused, Degraded
    collection_interval_sec: int
    events_collected: int
    throughput_eps: float
    last_ping: str
    supported_event_types: List[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CollectorListResponse(BaseModel):
    total_collectors: int
    active_count: int
    total_events_collected: int
    fleet_health: str
    collectors: List[CollectorStatus]


from pydantic import BaseModel, Field, model_validator


class CollectorPulseRequest(BaseModel):
    anomaly_simulation: bool = False
    simulate_anomaly: Optional[bool] = None
    custom_employee_id: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def check_simulate_alias(cls, data: Any):
        if isinstance(data, dict):
            if "simulate_anomaly" in data and "anomaly_simulation" not in data:
                data["anomaly_simulation"] = data["simulate_anomaly"]
        return data


class CollectorPulseResponse(BaseModel):
    collector_id: str
    collector_name: str
    status: str
    timestamp: str
    events_ingested: int
    anomalies_flagged: int
    sample_events: List[Dict[str, Any]]
    message: str


class CollectorToggleResponse(BaseModel):
    collector_id: str
    status: str
    message: str
