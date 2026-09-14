import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.activity import ActivityLog
from app.models.employee import Employee
from app.api.v1.notifications import create_system_notification


class CollectorManager:
    """
    Enterprise Log Collector and Telemetry Sensor Manager.
    Coordinates distributed sensors across OS endpoints, USB buses, cloud IAM,
    network VPNs, and data repositories.
    """

    def __init__(self):
        self._collectors: Dict[str, Dict[str, Any]] = {
            "endpoint_auth": {
                "id": "endpoint_auth",
                "name": "Host OS Authentication Sensor",
                "type": "os_auth",
                "description": "Collects Windows Security Logs (IDs 4624/4625/4672) and Linux PAM auth events.",
                "source_target": "Monitored Endpoints (WS-FIN-091, WS-ENG-402, WS-OPS-114)",
                "status": "Active",
                "collection_interval_sec": 15,
                "events_collected": 4281,
                "throughput_eps": 14.2,
                "last_ping": "Just now",
                "supported_event_types": [
                    "login_success",
                    "failed_login",
                    "privilege_escalation",
                    "mfa_challenge"
                ],
                "metadata": {
                    "agent_version": "v3.4.1-enterprise",
                    "protocol": "HTTPS/mTLS (Agent Port 8443)",
                    "buffer_state": "Healthy (0 dropped)",
                    "log_source": "Windows Event Forwarding (WEF)"
                }
            },
            "removable_media": {
                "id": "removable_media",
                "name": "Plug-and-Play USB Storage Sensor",
                "type": "removable_media",
                "description": "Monitors USB Mass Storage insertions, PnP device mounts, and unapproved serial numbers.",
                "source_target": "Endpoint PnP Device Bus (Kernel DLP Driver)",
                "status": "Active",
                "collection_interval_sec": 10,
                "events_collected": 912,
                "throughput_eps": 2.8,
                "last_ping": "Just now",
                "supported_event_types": [
                    "usb_device_mounted",
                    "usb_mass_copy",
                    "usb_unmount"
                ],
                "metadata": {
                    "agent_version": "v3.4.1-enterprise",
                    "protocol": "PnP Endpoint Driver Hook",
                    "buffer_state": "Healthy (0 dropped)",
                    "enforcement": "DLP Audit Mode"
                }
            },
            "data_egress": {
                "id": "data_egress",
                "name": "Network Data Movement and Git Egress Sensor",
                "type": "data_egress",
                "description": "Captures high-volume document downloads, bulk git repository clones, and DMS vault pulls.",
                "source_target": "GitHub Enterprise and Corporate DMS Vault (//legal-dms)",
                "status": "Active",
                "collection_interval_sec": 20,
                "events_collected": 2840,
                "throughput_eps": 8.5,
                "last_ping": "Just now",
                "supported_event_types": [
                    "git_clone_mass",
                    "mass_file_download",
                    "sensitive_data_export"
                ],
                "metadata": {
                    "agent_version": "v2.9.0-forwarder",
                    "protocol": "Audit Webhook Stream",
                    "buffer_state": "Healthy (0 dropped)",
                    "threshold_mb": 500.0
                }
            },
            "cloud_audit": {
                "id": "cloud_audit",
                "name": "AWS CloudTrail IAM Audit Sensor",
                "type": "cloud_audit",
                "description": "Audits AWS IAM policy changes, root token usage, and permission boundary tampering.",
                "source_target": "AWS CloudTrail Event Stream (eu-west-1, us-east-1)",
                "status": "Active",
                "collection_interval_sec": 30,
                "events_collected": 1489,
                "throughput_eps": 5.1,
                "last_ping": "Just now",
                "supported_event_types": [
                    "iam_policy_modification",
                    "role_elevation_attempt",
                    "api_key_generated"
                ],
                "metadata": {
                    "agent_version": "v4.1.0-cloudtrail",
                    "protocol": "AWS EventBridge / SQS Forwarder",
                    "buffer_state": "Healthy (0 dropped)",
                    "monitored_accounts": 4
                }
            },
            "network_vpn": {
                "id": "network_vpn",
                "name": "Enterprise Zero-Trust VPN Gateway Sensor",
                "type": "vpn_gateway",
                "description": "Monitors remote perimeter VPN ingress, foreign IP geolocation, and off-hours sessions.",
                "source_target": "Global VPN Concentrator (194.26.29.4 Berlin, 10.200.5.21 London)",
                "status": "Active",
                "collection_interval_sec": 15,
                "events_collected": 3672,
                "throughput_eps": 11.4,
                "last_ping": "Just now",
                "supported_event_types": [
                    "vpn_connection_established",
                    "vpn_foreign_ip_detected",
                    "vpn_session_terminated"
                ],
                "metadata": {
                    "agent_version": "v3.2.0-syslog",
                    "protocol": "Syslog RFC 5424 (UDP 514)",
                    "buffer_state": "Healthy (0 dropped)",
                    "gateways_connected": 8
                }
            }
        }

    def list_collectors(self) -> List[Dict[str, Any]]:
        return list(self._collectors.values())

    def get_collector(self, collector_id: str) -> Optional[Dict[str, Any]]:
        return self._collectors.get(collector_id)

    def toggle_collector(self, collector_id: str) -> Dict[str, Any]:
        coll = self.get_collector(collector_id)
        if not coll:
            raise KeyError(f"Collector {collector_id} not found")
        coll["status"] = "Paused" if coll["status"] == "Active" else "Active"
        return coll

    def dispatch_pulse(
        self,
        db: Session,
        collector_id: str,
        anomaly_simulation: bool = False,
        custom_employee_id: Optional[str] = None
    ) -> Dict[str, Any]:
        coll = self.get_collector(collector_id)
        if not coll:
            raise KeyError(f"Collector sensor {collector_id} not found")

        employees = db.query(Employee).all()
        if not employees:
            raise ValueError("No monitored employees found in database to attach telemetry")

        target_emp = None
        if custom_employee_id:
            target_emp = db.query(Employee).filter(Employee.id == custom_employee_id).first()
        if not target_emp:
            target_emp = random.choice(employees)

        now = datetime.utcnow()
        new_logs: List[ActivityLog] = []
        anomalies_count = 0

        if collector_id == "endpoint_auth":
            if anomaly_simulation:
                for i in range(4):
                    new_logs.append(ActivityLog(
                        employee_id=target_emp.id,
                        activity_type="failed_login",
                        source_ip="194.26.29.4",
                        workstation="WS-BERLIN-UNKNOWN",
                        timestamp=now - timedelta(minutes=4 - i),
                        details={"reason": "bad_password", "origin": "Berlin, Germany", "collector": coll["name"]},
                        is_anomalous=True,
                        anomaly_score=85
                    ))
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="login_success",
                    source_ip="194.26.29.4",
                    workstation="WS-BERLIN-UNKNOWN",
                    timestamp=now,
                    details={"mfa_bypass_alert": True, "origin": "Berlin, Germany", "collector": coll["name"]},
                    is_anomalous=True,
                    anomaly_score=90
                ))
                anomalies_count += 5
            else:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="login_success",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"auth_method": "SSO_SAML", "status": "approved", "collector": coll["name"]},
                    is_anomalous=False,
                    anomaly_score=5
                ))

        elif collector_id == "removable_media":
            if anomaly_simulation:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="usb_device_mounted",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"device": "SanDisk Extreme 128GB", "action": "mass_copy", "collector": coll["name"]},
                    is_anomalous=True,
                    anomaly_score=95
                ))
                anomalies_count += 1
            else:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="usb_device_mounted",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"device": "YubiKey 5 NFC", "status": "fido2_approved", "collector": coll["name"]},
                    is_anomalous=False,
                    anomaly_score=0
                ))

        elif collector_id == "data_egress":
            if anomaly_simulation:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="git_clone_mass",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"repos_cloned": 14, "mb": 3200.0, "is_confidential": True, "collector": coll["name"]},
                    is_anomalous=True,
                    anomaly_score=92
                ))
                anomalies_count += 1
            else:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="file_access",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"resource": f"{target_emp.department.lower()}_report.pdf", "mb": 3.2, "collector": coll["name"]},
                    is_anomalous=False,
                    anomaly_score=5
                ))

        elif collector_id == "cloud_audit":
            if anomaly_simulation:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="iam_policy_modification",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"policy": "AdministratorAccess", "ticket_verified": False, "collector": coll["name"]},
                    is_anomalous=True,
                    anomaly_score=88
                ))
                anomalies_count += 1
            else:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="record_query",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"service": "Amazon RDS", "query_type": "SELECT", "collector": coll["name"]},
                    is_anomalous=False,
                    anomaly_score=5
                ))

        else:  # network_vpn
            if anomaly_simulation:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="vpn_foreign_ip_detected",
                    source_ip="194.26.29.4",
                    workstation="VPN-GATEWAY-BERLIN",
                    timestamp=now,
                    details={"gateway": "eu-central-vpn-1", "geo": "Berlin, DE", "collector": coll["name"]},
                    is_anomalous=True,
                    anomaly_score=82
                ))
                anomalies_count += 1
            else:
                new_logs.append(ActivityLog(
                    employee_id=target_emp.id,
                    activity_type="vpn_connection_established",
                    source_ip=target_emp.ip_address,
                    workstation=target_emp.workstation,
                    timestamp=now,
                    details={"gateway": "us-west-vpn-corp", "status": "active", "collector": coll["name"]},
                    is_anomalous=False,
                    anomaly_score=5
                ))

        db.add_all(new_logs)
        db.commit()

        coll["events_collected"] += len(new_logs)
        coll["last_ping"] = "Just now"

        if anomalies_count > 0:
            create_system_notification(
                db=db,
                title=f"Sensor Anomaly Flagged: {coll['name']}",
                message=f"Collector {coll['name']} flagged {anomalies_count} acute threat telemetry event(s) for identity {target_emp.name} ({target_emp.id}).",
                severity="High",
                notif_type="anomaly",
                employee_id=target_emp.id,
                link=f"/employees/{target_emp.id}"
            )

        return {
            "collector_id": coll["id"],
            "collector_name": coll["name"],
            "status": coll["status"],
            "timestamp": now.isoformat(),
            "events_ingested": len(new_logs),
            "anomalies_flagged": anomalies_count,
            "sample_events": [
                {
                    "id": log.id,
                    "activity_type": log.activity_type,
                    "employee_id": log.employee_id,
                    "is_anomalous": log.is_anomalous,
                    "score": log.anomaly_score
                }
                for log in new_logs
            ],
            "message": f"Successfully collected and ingested {len(new_logs)} telemetry events from sensor '{coll['name']}'."
        }


collector_manager = CollectorManager()
