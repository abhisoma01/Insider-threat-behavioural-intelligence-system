from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from app.database import Base


class BehavioralProfile(Base):
    __tablename__ = "behavioral_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    employee_id = Column(String(50), ForeignKey("employees.id"), unique=True, nullable=False, index=True)
    profiling_window_days = Column(Integer, default=30)
    sample_size = Column(Integer, default=0)
    last_profiled_at = Column(DateTime, default=datetime.utcnow)

    # Statistical baseline metrics:
    # {
    #   "daily_action_count": {"mean": 42.1, "std": 6.5, "min": 25, "max": 58},
    #   "off_hours_activity_ratio": {"mean": 0.04, "std": 0.02},
    #   "data_transfer_volume_mb": {"mean": 115.4, "std": 32.1},
    #   "file_access_frequency": {"mean": 18.2, "std": 4.1},
    #   "failed_login_count": {"mean": 0.1, "std": 0.3},
    #   "sensitive_resource_access_count": {"mean": 0.0, "std": 0.1},
    #   "usb_device_events": {"mean": 0.0, "std": 0.0}
    # }
    metrics = Column(JSON, default=dict)

    # Habitual environment patterns
    habitual_workstations = Column(JSON, default=list)
    habitual_ips = Column(JSON, default=list)
    typical_active_hours = Column(JSON, default=dict)  # {"start_hour": 8, "end_hour": 18}

    # Latest evaluated behavioral deviation
    current_deviation_score = Column(Integer, default=0)  # 0 to 100
    deviation_factors = Column(JSON, default=list)  # [{feature, observed, baseline_mean, z_score, severity, explanation}]

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
