import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_endpoints():
    print("Testing FastAPI endpoints with Enterprise RBAC and Real-time Telemetry...")

    # 1. Root & Health Check
    res = client.get("/")
    assert res.status_code == 200, f"Root failed: {res.text}"
    print("[PASS] GET /")

    res = client.get("/health")
    assert res.status_code == 200, f"Health failed: {res.text}"
    print("[PASS] GET /health")

    # 2. Multi-Role RBAC Authentication
    def get_token_for(email, password="admin123"):
        login_res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert login_res.status_code == 200, f"Login failed for {email}: {login_res.text}"
        return login_res.json()["access_token"]

    admin_token = get_token_for("admin@threat.ai")
    manager_token = get_token_for("manager@threat.ai")
    engineer_token = get_token_for("engineer@threat.ai")
    analyst_token = get_token_for("analyst@threat.ai")
    print("[PASS] POST /api/v1/auth/login (Generated tokens for Admin, Manager, Engineer, Analyst)")

    # 3. Authenticated /me Role Verification
    me_admin = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert me_admin["role"] == "Administrator"
    me_manager = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {manager_token}"}).json()
    assert me_manager["role"] == "Security Manager"
    me_engineer = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {engineer_token}"}).json()
    assert me_engineer["role"] == "SOC Engineer"
    me_analyst = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"}).json()
    assert me_analyst["role"] == "Security Analyst"
    print("[PASS] GET /api/v1/auth/me (All 4 RBAC identity roles validated)")

    # 4. Strict RBAC Enforcement on Containment Operations (/employees/{id}/lock)
    # 4a. Security Analyst MUST be denied (403 Forbidden)
    analyst_lock = client.post(
        "/api/v1/employees/101/lock",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert analyst_lock.status_code == 403, f"Expected 403 for analyst lock, got {analyst_lock.status_code}"
    print("[PASS] RBAC Check: Analyst denied from locking employee (HTTP 403 Forbidden)")

    # 4b. SOC Engineer MUST be denied (403 Forbidden)
    engineer_lock = client.post(
        "/api/v1/employees/101/lock",
        headers={"Authorization": f"Bearer {engineer_token}"}
    )
    assert engineer_lock.status_code == 403, f"Expected 403 for engineer lock, got {engineer_lock.status_code}"
    print("[PASS] RBAC Check: Engineer denied from locking employee (HTTP 403 Forbidden)")

    # 4c. Security Manager IS authorized (200 OK)
    manager_lock = client.post(
        "/api/v1/employees/101/lock",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert manager_lock.status_code == 200, f"Manager lock failed: {manager_lock.text}"
    assert manager_lock.json()["status"] == "Locked"
    print("[PASS] RBAC Check: Security Manager authorized to lock account (HTTP 200 OK)")

    # 4d. Administrator resets score (200 OK)
    admin_reset = client.post(
        "/api/v1/employees/101/reset-score",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_reset.status_code == 200
    print("[PASS] RBAC Check: Administrator authorized to reset employee score (HTTP 200 OK)")

    # 5. Strict RBAC Enforcement on Activity Ingestion (/activity/ingest)
    # 5a. Security Analyst MUST be denied (403 Forbidden)
    test_activity_payload = [
        {
            "employee_id": "104",
            "activity_type": "usb_device_mounted",
            "source_ip": "192.168.6.50",
            "workstation": "WS-LEG-014",
            "details": {"device": "Kingston DataTraveler 128GB"},
            "is_anomalous": True,
            "anomaly_score": 85
        }
    ]
    analyst_ingest = client.post(
        "/api/v1/activity/ingest",
        json=test_activity_payload,
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert analyst_ingest.status_code == 403, f"Expected 403 for analyst ingest, got {analyst_ingest.status_code}"
    print("[PASS] RBAC Check: Analyst denied from ingesting telemetry (HTTP 403 Forbidden)")

    # 5b. SOC Engineer IS authorized (201 Created)
    engineer_ingest = client.post(
        "/api/v1/activity/ingest",
        json=test_activity_payload,
        headers={"Authorization": f"Bearer {engineer_token}"}
    )
    assert engineer_ingest.status_code == 201, f"Engineer ingest failed: {engineer_ingest.text}"
    print("[PASS] RBAC Check: SOC Engineer authorized to ingest telemetry (HTTP 201 Created)")

    # 6. Strict RBAC Enforcement on Baseline Recalculation (/behavior/recalculate-baseline)
    # 6a. Security Analyst MUST be denied (403 Forbidden)
    analyst_recalc = client.post(
        "/api/v1/behavior/recalculate-baseline",
        json={"window_days": 30},
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert analyst_recalc.status_code == 403
    print("[PASS] RBAC Check: Analyst denied from recalculating baselines (HTTP 403 Forbidden)")

    # 6b. Administrator IS authorized (200 OK)
    admin_recalc = client.post(
        "/api/v1/behavior/recalculate-baseline",
        json={"window_days": 30},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_recalc.status_code == 200
    print("[PASS] RBAC Check: Administrator authorized to recalculate baselines (HTTP 200 OK)")

    # 7. Security Notifications System (Database Backed)
    notifs_res = client.get("/api/v1/notifications", headers={"Authorization": f"Bearer {admin_token}"})
    assert notifs_res.status_code == 200, f"Get notifications failed: {notifs_res.text}"
    notifs_payload = notifs_res.json()
    assert "items" in notifs_payload
    notifs_data = notifs_payload["items"]
    assert len(notifs_data) > 0
    print(f"[PASS] GET /api/v1/notifications ({len(notifs_data)} database notifications retrieved, {notifs_payload['unread_count']} unread)")

    # Check that containment action triggered an automatic system notification
    containment_notifs = [n for n in notifs_data if n.get("type") == "containment"]
    assert len(containment_notifs) >= 1
    print(f"[PASS] Notification System: Automatic containment notification verified ({containment_notifs[0]['title']})")

    # Mark notification read
    first_notif_id = notifs_data[0]["id"]
    patch_notif = client.patch(
        f"/api/v1/notifications/{first_notif_id}/read",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert patch_notif.status_code == 200
    assert patch_notif.json()["read"] is True
    print(f"[PASS] PATCH /api/v1/notifications/{first_notif_id}/read (Marked as read)")

    # Mark all read
    mark_all_res = client.post(
        "/api/v1/notifications/mark-all-read",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert mark_all_res.status_code == 200
    print("[PASS] POST /api/v1/notifications/mark-all-read (All notifications updated to read)")

    # 8. Forensic Reports & CSV Export Engine
    # 8a. Executive CISO Intelligence Dossier
    exec_report_res = client.get("/api/v1/reports/executive", headers={"Authorization": f"Bearer {admin_token}"})
    assert exec_report_res.status_code == 200, f"Exec report failed: {exec_report_res.text}"
    exec_data = exec_report_res.json()
    assert "posture_summary" in exec_data
    assert "departmental_risk_matrix" in exec_data
    assert "priority_containment_watchlist" in exec_data
    assert "executive_recommendations" in exec_data
    print(f"[PASS] GET /api/v1/reports/executive (CISO Dossier ID: {exec_data['report_id']})")

    # 8b. Employee Forensic Report
    emp_report_res = client.get("/api/v1/reports/employee/104", headers={"Authorization": f"Bearer {admin_token}"})
    assert emp_report_res.status_code == 200, f"Employee report failed: {emp_report_res.text}"
    emp_report = emp_report_res.json()
    assert emp_report["identity"]["id"] == "104"
    assert "behavioral_profile" in emp_report
    assert "security_incidents" in emp_report
    print(f"[PASS] GET /api/v1/reports/employee/104 (Forensic identity dossier: {emp_report['dossier_id']})")

    # 8c. Telemetry CSV Export
    csv_res = client.get("/api/v1/reports/export/csv?format=activities", headers={"Authorization": f"Bearer {admin_token}"})
    assert csv_res.status_code == 200, f"CSV export failed: {csv_res.text}"
    assert "text/csv" in csv_res.headers.get("content-type", "")
    csv_lines = csv_res.text.strip().split("\n")
    assert len(csv_lines) > 1
    assert "activity_id,employee_id,activity_type" in csv_lines[0]
    print(f"[PASS] GET /api/v1/reports/export/csv?format=activities ({len(csv_lines)} CSV lines exported)")

    # 9. Dynamic Behavioral Risk Trajectory & Vectors (Model-Based)
    # 9a. 7d Trajectory
    traj_7d = client.get("/api/v1/risk/trajectory?timeframe=7d").json()
    assert len(traj_7d) == 7
    assert all("compositeScore" in p and "anomalies" in p for p in traj_7d)
    print(f"[PASS] GET /api/v1/risk/trajectory?timeframe=7d (7 dynamic data points)")

    # 9b. 30d Trajectory
    traj_30d = client.get("/api/v1/risk/trajectory?timeframe=30d").json()
    assert len(traj_30d) == 15
    print(f"[PASS] GET /api/v1/risk/trajectory?timeframe=30d (15 dynamic bi-daily intervals)")

    # 9c. 90d Trajectory
    traj_90d = client.get("/api/v1/risk/trajectory?timeframe=90d").json()
    assert len(traj_90d) == 12
    print(f"[PASS] GET /api/v1/risk/trajectory?timeframe=90d (12 dynamic weekly intervals)")

    # 9d. Dynamic Threat Vectors (Database aggregated, zero hardcoded static clamps)
    vectors_res = client.get("/api/v1/risk/threat-vectors").json()
    assert len(vectors_res) >= 5
    for v in vectors_res:
        assert "vector" in v
        assert "observed" in v
        assert "baseline" in v
        assert "riskImpact" in v
        assert isinstance(v["observed"], int)
    print(f"[PASS] GET /api/v1/risk/threat-vectors (Dynamic vector calculations verified)")

    # 10. Behavioral Deviation Evaluation
    eval_res = client.post("/api/v1/behavior/evaluate-deviation", json={
        "employee_id": "104",
        "activities": [
            {
                "activity_type": "mass_file_download",
                "source_ip": "192.168.6.50",
                "workstation": "WS-LEG-014",
                "details": {"bytes": 4800 * 1024 * 1024, "is_confidential": True}
            },
            {
                "activity_type": "usb_device_mounted",
                "source_ip": "192.168.6.50",
                "workstation": "WS-LEG-014",
                "details": {"device": "Kingston DataTraveler 128GB"}
            }
        ]
    })
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert eval_data["composite_deviation_score"] >= 40
    print(f"[PASS] POST /api/v1/behavior/evaluate-deviation (Deviation score: {eval_data['composite_deviation_score']}, Tier: {eval_data['severity_tier']})")

    # 11. Distributed Log Collector Sensors & Telemetry Ingestion Fleet
    # 11a. List Collectors (Authenticated)
    collectors_res = client.get(
        "/api/v1/collectors",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert collectors_res.status_code == 200, f"List collectors failed: {collectors_res.text}"
    col_data = collectors_res.json()
    assert col_data["active_count"] == 5
    assert len(col_data["collectors"]) == 5
    collector_ids = [c["id"] for c in col_data["collectors"]]
    assert "endpoint_auth" in collector_ids
    assert "removable_media" in collector_ids
    assert "data_egress" in collector_ids
    assert "cloud_audit" in collector_ids
    assert "network_vpn" in collector_ids
    print(f"[PASS] GET /api/v1/collectors (5 distributed log collector sensors active, fleet status: {col_data['fleet_health']})")

    # 11b. RBAC: Analyst forbidden from pulsing or toggling collectors
    analyst_pulse = client.post(
        "/api/v1/collectors/endpoint_auth/pulse",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"simulate_anomaly": False}
    )
    assert analyst_pulse.status_code == 403, f"Expected 403 for analyst collector pulse, got {analyst_pulse.status_code}"
    print("[PASS] RBAC Check: Security Analyst denied from pulsing log collectors (HTTP 403 Forbidden)")

    # 11c. Engineer executes nominal telemetry pulse on endpoint_auth
    pulse_nominal = client.post(
        "/api/v1/collectors/endpoint_auth/pulse",
        headers={"Authorization": f"Bearer {engineer_token}"},
        json={"simulate_anomaly": False}
    )
    assert pulse_nominal.status_code == 200, f"Nominal pulse failed: {pulse_nominal.text}"
    pulse_nom_data = pulse_nominal.json()
    assert pulse_nom_data["events_ingested"] >= 1
    assert pulse_nom_data["anomalies_flagged"] == 0
    print(f"[PASS] POST /api/v1/collectors/endpoint_auth/pulse [Nominal] (Ingested {pulse_nom_data['events_ingested']} events into telemetry pipeline)")

    # 11d. Engineer executes anomaly simulation on removable_media (triggers automated notification)
    pulse_anomaly = client.post(
        "/api/v1/collectors/removable_media/pulse",
        headers={"Authorization": f"Bearer {engineer_token}"},
        json={"simulate_anomaly": True}
    )
    assert pulse_anomaly.status_code == 200, f"Anomaly pulse failed: {pulse_anomaly.text}"
    pulse_anom_data = pulse_anomaly.json()
    assert pulse_anom_data["events_ingested"] >= 1
    assert pulse_anom_data["anomalies_flagged"] >= 1
    print(f"[PASS] POST /api/v1/collectors/removable_media/pulse [Anomaly Simulation] (Ingested {pulse_anom_data['events_ingested']} events, Flagged {pulse_anom_data['anomalies_flagged']} high-risk anomalies)")

    # 11e. Toggle Collector state (Active -> Paused -> Active)
    toggle_pause = client.post(
        "/api/v1/collectors/cloud_audit/toggle",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert toggle_pause.status_code == 200
    assert toggle_pause.json()["status"] == "Paused"

    toggle_resume = client.post(
        "/api/v1/collectors/cloud_audit/toggle",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert toggle_resume.status_code == 200
    assert toggle_resume.json()["status"] == "Active"
    print("[PASS] POST /api/v1/collectors/cloud_audit/toggle (Sensor daemon Paused and Resumed successfully)")

    print("\n==================================================================")
    print("ALL FASTAPI ENTERPRISE RBAC, NOTIFICATIONS, REPORTS, BEHAVIORAL & LOG COLLECTOR ENDPOINTS PASSED VERIFICATION WITH 100% SUCCESS!")
    print("==================================================================")


if __name__ == "__main__":
    test_endpoints()
