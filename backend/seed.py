import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from datetime import datetime, timedelta
from app.database import engine, SessionLocal, Base
from app.models.user import User
from app.models.employee import Employee
from app.models.alert import Alert
from app.models.activity import ActivityLog
from app.models.behavioral_profile import BehavioralProfile
from app.models.notification import Notification
from app.services.profiling_engine import recalculate_employee_baseline
from app.utils.security import get_password_hash


def seed_database():
    print("Creating database schema...")
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # 1. Seed RBAC Users (Administrator, Security Manager, SOC Engineer, Security Analyst)
        users_to_seed = [
            {
                "email": "admin@threat.ai",
                "name": "System Administrator",
                "role": "Administrator",
                "initials": "SA",
                "department": "Security Operations",
                "clearance": "TOP SECRET // SCI"
            },
            {
                "email": "manager@threat.ai",
                "name": "Security Manager",
                "role": "Security Manager",
                "initials": "SM",
                "department": "Incident Response",
                "clearance": "TOP SECRET // SCI"
            },
            {
                "email": "engineer@threat.ai",
                "name": "SOC Lead Engineer",
                "role": "SOC Engineer",
                "initials": "SE",
                "department": "SOC Engineering",
                "clearance": "SECRET"
            },
            {
                "email": "analyst@threat.ai",
                "name": "Security Analyst",
                "role": "Security Analyst",
                "initials": "SO",
                "department": "Threat Triage",
                "clearance": "SECRET"
            },
        ]

        for u_data in users_to_seed:
            existing = db.query(User).filter(User.email == u_data["email"]).first()
            if not existing:
                new_user = User(
                    email=u_data["email"],
                    hashed_password=get_password_hash("admin123"),
                    name=u_data["name"],
                    role=u_data["role"],
                    initials=u_data["initials"],
                    department=u_data["department"],
                    clearance=u_data["clearance"],
                    is_active=True
                )
                db.add(new_user)
                print(f"Seeded RBAC user: {u_data['email']} ({u_data['role']})")
            else:
                # Update role to ensure consistency
                existing.role = u_data["role"]
                existing.name = u_data["name"]
                db.commit()

        # 2. Seed Monitored Employees
        if db.query(Employee).count() == 0:
            print("Seeding monitored employees workforce...")
            employees_data = [
                {
                    "id": "101",
                    "name": "John Carter",
                    "department": "Finance",
                    "role": "Senior Financial Analyst",
                    "status": "Under Review",
                    "email": "john.carter@threat.ai",
                    "workstation": "WS-FIN-091",
                    "ip_address": "192.168.4.112",
                    "location": "Frankfurt / Remote",
                    "risk_level": "High",
                    "score": 87,
                    "last_activity": "Unusual login — 3:14 AM, unrecognized device",
                    "seen": "2h ago",
                    "avatar_bg": "#e8f0fe",
                    "avatar_color": "#1a73e8",
                    "initial": "JC",
                    "details": "Attempted 5 failed logins from an unapproved IP in Berlin before successfully authenticating.",
                    "behavioral_indicators": [
                        "Off-Hours Authentication",
                        "Foreign IP (Berlin)",
                        "Brute Force Threshold",
                        "Unrecognized Device Token"
                    ],
                    "risk_factors": [
                        {"name": "Anomalous Authentication", "score": 92, "weight": "High"},
                        {"name": "Geographic Deviation", "score": 85, "weight": "High"},
                        {"name": "Data Movement Velocity", "score": 45, "weight": "Medium"},
                        {"name": "Privilege Scope Violation", "score": 30, "weight": "Low"}
                    ],
                    "security_events": [
                        {
                            "id": "EVT-101-1",
                            "title": "Consecutive Failed Login Attempts",
                            "severity": "Critical",
                            "timestamp": "Today, 03:12 AM",
                            "source": "VPN Gateway (Berlin IP: 194.26.29.4)",
                            "description": "5 consecutive authentication failures followed by MFA bypass alert."
                        }
                    ]
                },
                {
                    "id": "102",
                    "name": "Elena Rostova",
                    "department": "Engineering",
                    "role": "Core Infrastructure Lead",
                    "status": "Under Review",
                    "email": "elena.rostova@threat.ai",
                    "workstation": "WS-ENG-402",
                    "ip_address": "192.168.1.88",
                    "location": "San Francisco HQ",
                    "risk_level": "High",
                    "score": 92,
                    "last_activity": "Mass git clone — 14 restricted repositories",
                    "seen": "45m ago",
                    "avatar_bg": "#fce8e6",
                    "avatar_color": "#c5221f",
                    "initial": "ER",
                    "details": "Triggered mass repository checkout anomaly during non-working hours.",
                    "behavioral_indicators": [
                        "Bulk Git Exfiltration",
                        "Privileged Vault Access",
                        "High Volume Network Outbound"
                    ],
                    "risk_factors": [
                        {"name": "Data Movement Velocity", "score": 96, "weight": "High"},
                        {"name": "Privilege Scope Violation", "score": 88, "weight": "High"}
                    ],
                    "security_events": [
                        {
                            "id": "EVT-102-1",
                            "title": "Restricted Repo Mass Clone",
                            "severity": "Critical",
                            "timestamp": "Today, 01:22 AM",
                            "source": "GitHub Enterprise Server",
                            "description": "Cloned 14 Tier-1 proprietary infrastructure repositories."
                        }
                    ]
                },
                {
                    "id": "103",
                    "name": "Marcus Vance",
                    "department": "DevOps",
                    "role": "Cloud Architect",
                    "status": "Active",
                    "email": "marcus.vance@threat.ai",
                    "workstation": "WS-OPS-114",
                    "ip_address": "10.200.5.21",
                    "location": "London Office",
                    "risk_level": "High",
                    "score": 79,
                    "last_activity": "Production IAM policy modification attempt",
                    "seen": "10m ago",
                    "avatar_bg": "#fef7e0",
                    "avatar_color": "#b06000",
                    "initial": "MV",
                    "details": "Attempted to elevate IAM privileges across 3 AWS production accounts without change-board ticket.",
                    "behavioral_indicators": [
                        "Unauthorized IAM Elevation",
                        "Off-Hours Production Drift"
                    ],
                    "risk_factors": [
                        {"name": "Privilege Scope Violation", "score": 90, "weight": "High"},
                        {"name": "Anomalous Authentication", "score": 70, "weight": "Medium"}
                    ],
                    "security_events": [
                        {
                            "id": "EVT-103-1",
                            "title": "IAM Root Boundary Modification",
                            "severity": "Critical",
                            "timestamp": "Today, 04:18 AM",
                            "source": "AWS CloudTrail (eu-west-1)",
                            "description": "Attempted to attach AdministratorAccess policy without approved ticket."
                        }
                    ]
                },
                {
                    "id": "104",
                    "name": "Priya Nair",
                    "department": "Legal",
                    "role": "General Counsel Analyst",
                    "status": "Under Review",
                    "email": "priya.nair@threat.ai",
                    "workstation": "WS-LEG-014",
                    "ip_address": "192.168.6.50",
                    "location": "New York Office",
                    "risk_level": "High",
                    "score": 83,
                    "last_activity": "Downloaded 4.8 GB of classified patent filings",
                    "seen": "1h ago",
                    "avatar_bg": "#e6f4ea",
                    "avatar_color": "#137333",
                    "initial": "PN",
                    "details": "Large bulk download from restricted litigation and patent vault.",
                    "behavioral_indicators": [
                        "Volume Deviation (4.8 GB)",
                        "Unregistered USB Storage Attached"
                    ],
                    "risk_factors": [
                        {"name": "Data Movement Velocity", "score": 94, "weight": "High"},
                        {"name": "Removable Media Usage", "score": 85, "weight": "High"}
                    ],
                    "security_events": [
                        {
                            "id": "EVT-104-1",
                            "title": "Classified Patent Vault Bulk Pull",
                            "severity": "Critical",
                            "timestamp": "Today, 02:40 AM",
                            "source": "Corporate Legal DMS",
                            "description": "Transferred 1,420 unredacted litigation briefs."
                        }
                    ]
                },
                {
                    "id": "105",
                    "name": "David Chen",
                    "department": "Engineering",
                    "role": "Senior Full-Stack Engineer",
                    "status": "Active",
                    "email": "david.chen@threat.ai",
                    "workstation": "WS-ENG-210",
                    "ip_address": "192.168.1.144",
                    "location": "San Francisco HQ",
                    "risk_level": "Medium",
                    "score": 58,
                    "last_activity": "Connected unapproved USB storage device",
                    "seen": "3h ago",
                    "avatar_bg": "#f3e8fd",
                    "avatar_color": "#8430ce",
                    "initial": "DC",
                    "details": "SanDisk Ultra 64GB USB inserted into workstation without DLP authorization.",
                    "behavioral_indicators": [
                        "Unregistered USB Device Attached",
                        "Non-Compliant Endpoint Mount"
                    ],
                    "risk_factors": [
                        {"name": "Removable Media Usage", "score": 82, "weight": "High"},
                        {"name": "Data Movement Velocity", "score": 40, "weight": "Medium"}
                    ],
                    "security_events": []
                },
                {
                    "id": "106",
                    "name": "Sarah Jenkins",
                    "department": "HR",
                    "role": "Talent Operations Lead",
                    "status": "Active",
                    "email": "sarah.jenkins@threat.ai",
                    "workstation": "WS-HR-003",
                    "ip_address": "192.168.3.45",
                    "location": "Chicago / Remote",
                    "risk_level": "Medium",
                    "score": 64,
                    "last_activity": "Bulk export of employee compensation records",
                    "seen": "4h ago",
                    "avatar_bg": "#feefe3",
                    "avatar_color": "#b34000",
                    "initial": "SJ",
                    "details": "Exported complete salary, performance rating, and bonus tables.",
                    "behavioral_indicators": [
                        "Sensitive PII Bulk Query",
                        "Off-Schedule Export"
                    ],
                    "risk_factors": [
                        {"name": "Data Access Frequency", "score": 75, "weight": "Medium"}
                    ],
                    "security_events": []
                },
                {
                    "id": "107",
                    "name": "Alex Rivera",
                    "department": "Engineering",
                    "role": "QA Automation Engineer",
                    "status": "Active",
                    "email": "alex.rivera@threat.ai",
                    "workstation": "WS-ENG-308",
                    "ip_address": "192.168.1.92",
                    "location": "San Francisco HQ",
                    "risk_level": "Low",
                    "score": 12,
                    "last_activity": "Standard CI/CD pipeline deployment",
                    "seen": "15m ago",
                    "avatar_bg": "#e8eaed",
                    "avatar_color": "#3c4043",
                    "initial": "AR",
                    "details": "Routine automated test script runs.",
                    "behavioral_indicators": ["Within Peer Baseline"],
                    "risk_factors": [{"name": "Baseline Conformity", "score": 95, "weight": "Low"}],
                    "security_events": []
                },
                {
                    "id": "108",
                    "name": "Rachel Green",
                    "department": "Finance",
                    "role": "Accounts Payable Specialist",
                    "status": "Active",
                    "email": "rachel.green@threat.ai",
                    "workstation": "WS-FIN-019",
                    "ip_address": "192.168.4.55",
                    "location": "Frankfurt Office",
                    "risk_level": "Low",
                    "score": 18,
                    "last_activity": "Standard ERP vendor invoice approvals",
                    "seen": "30m ago",
                    "avatar_bg": "#e8f0fe",
                    "avatar_color": "#1a73e8",
                    "initial": "RG",
                    "details": "Normal invoice batch processing.",
                    "behavioral_indicators": ["Normal Working Hours"],
                    "risk_factors": [{"name": "Standard Access Velocity", "score": 90, "weight": "Low"}],
                    "security_events": []
                }
            ]

            for emp_dict in employees_data:
                db.add(Employee(**emp_dict))
            print(f"Seeded {len(employees_data)} monitored employees.")
        else:
            print("Employees already seeded.")

        # 3. Seed Security Alerts
        if db.query(Alert).count() == 0:
            print("Seeding initial alerts...")
            alerts_data = [
                {
                    "id": "ALT-2026-001",
                    "title": "Mass Bulk Download from Confidential Legal Vault",
                    "severity": "Critical",
                    "status": "New",
                    "employee_id": "104",
                    "employee_name": "Priya Nair",
                    "department": "Legal",
                    "timestamp": "12 mins ago",
                    "vector": "Data Exfiltration",
                    "summary": "Downloaded 4.8 GB of encrypted patent filings outside standard hours.",
                    "evidence": [
                        {"type": "File System", "detail": "1,420 PDF files copied from //legal-dms/patents"},
                        {"type": "Network", "detail": "Exceeded 99.8th percentile data egress threshold"}
                    ]
                },
                {
                    "id": "ALT-2026-002",
                    "title": "Multiple Off-Hours Failed Logins from Foreign IP (Berlin)",
                    "severity": "High",
                    "status": "Investigating",
                    "employee_id": "101",
                    "employee_name": "John Carter",
                    "department": "Finance",
                    "timestamp": "42 mins ago",
                    "vector": "Anomalous Authentication",
                    "summary": "5 consecutive failed authentications followed by successful MFA bypass.",
                    "evidence": [
                        {"type": "VPN Gateway", "detail": "Originating IP 194.26.29.4 (Berlin, Germany)"},
                        {"type": "Identity Provider", "detail": "Unrecognized macOS device token"}
                    ]
                },
                {
                    "id": "ALT-2026-003",
                    "title": "Unauthorized Production IAM Policy Modification Attempt",
                    "severity": "Critical",
                    "status": "New",
                    "employee_id": "103",
                    "employee_name": "Marcus Vance",
                    "department": "DevOps",
                    "timestamp": "1 hour ago",
                    "vector": "Privilege Scope Violation",
                    "summary": "Attempted to attach AdministratorAccess policy without approved ticket.",
                    "evidence": [
                        {"type": "AWS CloudTrail", "detail": "PutUserPolicy on arn:aws:iam::123456789012:user/mvance"}
                    ]
                },
                {
                    "id": "ALT-2026-004",
                    "title": "Mass Clone of Proprietary Repositories",
                    "severity": "Critical",
                    "status": "New",
                    "employee_id": "102",
                    "employee_name": "Elena Rostova",
                    "department": "Engineering",
                    "timestamp": "2 hours ago",
                    "vector": "Data Exfiltration",
                    "summary": "Cloned 14 core backend infrastructure repositories to an external endpoint.",
                    "evidence": [
                        {"type": "GitHub Audit", "detail": "Cloned 14 repos in 180 seconds"}
                    ]
                },
                {
                    "id": "ALT-2026-005",
                    "title": "Bulk Export of Sensitive Personnel Compensation Data",
                    "severity": "Medium",
                    "status": "Investigating",
                    "employee_id": "106",
                    "employee_name": "Sarah Jenkins",
                    "department": "HR",
                    "timestamp": "3 hours ago",
                    "vector": "Data Access Violation",
                    "summary": "Full export of corporate payroll and executive compensation tables.",
                    "evidence": [
                        {"type": "Workday Audit", "detail": "Report: Full_Workforce_Comp_2026.xlsx exported"}
                    ]
                }
            ]
            for alert_dict in alerts_data:
                db.add(Alert(**alert_dict))
            print(f"Seeded {len(alerts_data)} alerts.")
        else:
            print("Alerts already seeded.")

        # 4. Seed Multi-Day Activity Logs for Behavioral Profiling
        if db.query(ActivityLog).count() < 100:
            print("Seeding multi-day activity log history for behavioral baselines...")
            now = datetime.utcnow()
            activity_entries = []

            # 14-day history for all employees
            employees = db.query(Employee).all()
            for day_offset in range(14, 0, -1):
                day_date = now - timedelta(days=day_offset)
                is_weekend = day_date.weekday() >= 5
                if is_weekend:
                    continue  # standard baseline has no weekend activity

                for emp in employees:
                    # Normal morning authentication
                    login_time = day_date.replace(hour=8, minute=45, second=0) + timedelta(minutes=(int(emp.id) * 3) % 40)
                    activity_entries.append(ActivityLog(
                        employee_id=emp.id,
                        activity_type="login_success",
                        source_ip=emp.ip_address,
                        workstation=emp.workstation,
                        timestamp=login_time,
                        details={"auth_method": "SSO_SAML", "status": "approved"},
                        is_anomalous=False,
                        anomaly_score=5
                    ))

                    # Normal midday business activity
                    action_time = day_date.replace(hour=11, minute=15, second=0) + timedelta(minutes=(int(emp.id) * 5) % 90)
                    activity_entries.append(ActivityLog(
                        employee_id=emp.id,
                        activity_type="file_access",
                        source_ip=emp.ip_address,
                        workstation=emp.workstation,
                        timestamp=action_time,
                        details={"resource": f"{emp.department.lower()}_docs_portal", "mb": 4.5},
                        is_anomalous=False,
                        anomaly_score=5
                    ))

                    # Normal afternoon data query
                    query_time = day_date.replace(hour=15, minute=20, second=0)
                    activity_entries.append(ActivityLog(
                        employee_id=emp.id,
                        activity_type="record_query",
                        source_ip=emp.ip_address,
                        workstation=emp.workstation,
                        timestamp=query_time,
                        details={"records_viewed": 12, "mb": 2.1},
                        is_anomalous=False,
                        anomaly_score=5
                    ))

                # Inject sporadic historical anomaly events across days for rich trajectory analytics
                if day_offset == 8:
                    activity_entries.append(ActivityLog(
                        employee_id="101",
                        activity_type="failed_login",
                        source_ip="194.26.29.4",
                        workstation="WS-FIN-091",
                        timestamp=day_date.replace(hour=22, minute=14, second=0),
                        details={"reason": "bad_password", "origin": "Berlin, Germany"},
                        is_anomalous=True,
                        anomaly_score=65
                    ))
                elif day_offset == 5:
                    activity_entries.append(ActivityLog(
                        employee_id="102",
                        activity_type="mass_file_download",
                        source_ip="192.168.1.88",
                        workstation="WS-ENG-402",
                        timestamp=day_date.replace(hour=23, minute=45, second=0),
                        details={"files_count": 85, "mb": 420.0},
                        is_anomalous=True,
                        anomaly_score=72
                    ))
                elif day_offset == 3:
                    activity_entries.append(ActivityLog(
                        employee_id="104",
                        activity_type="sensitive_data_export",
                        source_ip="192.168.6.50",
                        workstation="WS-LEG-014",
                        timestamp=day_date.replace(hour=20, minute=10, second=0),
                        details={"report": "draft_litigation.pdf", "mb": 35.0},
                        is_anomalous=True,
                        anomaly_score=68
                    ))
                elif day_offset == 1:
                    activity_entries.append(ActivityLog(
                        employee_id="103",
                        activity_type="iam_policy_modification",
                        source_ip="10.200.5.21",
                        workstation="WS-OPS-114",
                        timestamp=day_date.replace(hour=21, minute=30, second=0),
                        details={"policy": "ReadOnlyAccess_Modified"},
                        is_anomalous=True,
                        anomaly_score=70
                    ))

            # Inject recent acute anomalous incidents (past 24h) corresponding to active threat alerts:
            # 1. John Carter (101): Off-hours brute force & foreign login
            for i in range(5):
                activity_entries.append(ActivityLog(
                    employee_id="101",
                    activity_type="failed_login",
                    source_ip="194.26.29.4",
                    workstation="WS-BERLIN-UNKNOWN",
                    timestamp=now - timedelta(hours=2, minutes=45 - i * 2),
                    details={"reason": "bad_password", "origin": "Berlin, Germany"},
                    is_anomalous=True,
                    anomaly_score=85
                ))
            activity_entries.append(ActivityLog(
                employee_id="101",
                activity_type="login_success",
                source_ip="194.26.29.4",
                workstation="WS-BERLIN-UNKNOWN",
                timestamp=now - timedelta(hours=2, minutes=35),
                details={"mfa_bypass_alert": True, "origin": "Berlin, Germany"},
                is_anomalous=True,
                anomaly_score=90
            ))

            # 2. Elena Rostova (102): Mass repository clone
            activity_entries.append(ActivityLog(
                employee_id="102",
                activity_type="git_clone_mass",
                source_ip="192.168.1.88",
                workstation="WS-ENG-402",
                timestamp=now - timedelta(hours=3, minutes=10),
                details={"repos_cloned": 14, "mb": 2400.0, "is_confidential": True},
                is_anomalous=True,
                anomaly_score=92
            ))

            # 3. Marcus Vance (103): IAM policy modification
            activity_entries.append(ActivityLog(
                employee_id="103",
                activity_type="iam_policy_modification",
                source_ip="192.168.3.10",
                workstation="WS-OPS-112",
                timestamp=now - timedelta(hours=4),
                details={"policy": "AdministratorAccess", "ticket_verified": False},
                is_anomalous=True,
                anomaly_score=88
            ))

            # 4. Priya Nair (104): Mass patent download & USB mount
            activity_entries.append(ActivityLog(
                employee_id="104",
                activity_type="mass_file_download",
                source_ip="192.168.6.50",
                workstation="WS-LEG-014",
                timestamp=now - timedelta(hours=5),
                details={"files_count": 1420, "mb": 4800.0, "is_confidential": True},
                is_anomalous=True,
                anomaly_score=95
            ))
            activity_entries.append(ActivityLog(
                employee_id="104",
                activity_type="usb_device_mounted",
                source_ip="192.168.6.50",
                workstation="WS-LEG-014",
                timestamp=now - timedelta(hours=4, minutes=50),
                details={"device": "Kingston DataTraveler 128GB", "action": "mass_copy"},
                is_anomalous=True,
                anomaly_score=96
            ))

            # 5. Sarah Jenkins (106): Sensitive compensation export
            activity_entries.append(ActivityLog(
                employee_id="106",
                activity_type="sensitive_data_export",
                source_ip="192.168.7.20",
                workstation="WS-HR-205",
                timestamp=now - timedelta(hours=6),
                details={"report": "Full_Workforce_Comp_2026.xlsx", "mb": 120.0, "is_confidential": True},
                is_anomalous=True,
                anomaly_score=75
            ))

            db.add_all(activity_entries)
            db.commit()
            print(f"Seeded {len(activity_entries)} historical activity log events.")
        else:
            print("Activity logs already seeded.")

        # 5. Seed Initial Security Notifications
        if db.query(Notification).count() == 0:
            print("Seeding initial security notifications...")
            now = datetime.utcnow()
            initial_notifications = [
                Notification(
                    title="Critical Alert: High-Volume Exfiltration Detected",
                    message="Priya Nair (Legal) triggered a 4.8 GB classified patent vault bulk pull.",
                    severity="Critical",
                    type="alert",
                    employee_id="104",
                    alert_id="ALT-2026-001",
                    link="/alerts",
                    read=False,
                    created_at=now - timedelta(minutes=12)
                ),
                Notification(
                    title="Brute Force Anomaly: Berlin IP Gateway",
                    message="John Carter (Finance) exhibited 5 consecutive failed logins followed by MFA bypass from 194.26.29.4.",
                    severity="High",
                    type="anomaly",
                    employee_id="101",
                    alert_id="ALT-2026-002",
                    link="/alerts",
                    read=False,
                    created_at=now - timedelta(minutes=42)
                ),
                Notification(
                    title="Containment Directive Executed",
                    message="Elena Rostova (Engineering) account isolated following mass repository clone detection.",
                    severity="Critical",
                    type="containment",
                    employee_id="102",
                    alert_id="ALT-2026-004",
                    link="/employees/102",
                    read=True,
                    created_at=now - timedelta(hours=2)
                ),
                Notification(
                    title="Empirical Behavioral Baseline Computed",
                    message="Workforce behavioral profiling engine updated 8 employee anomaly baselines.",
                    severity="Low",
                    type="system",
                    link="/behavior/profiles",
                    read=True,
                    created_at=now - timedelta(hours=6)
                ),
            ]
            db.add_all(initial_notifications)
            db.commit()
            print(f"Seeded {len(initial_notifications)} initial notifications.")
        else:
            print("Notifications already seeded.")

        # 6. Compute Behavioral Baselines
        print("Computing empirical behavioral baselines for monitored workforce...")
        employees = db.query(Employee).all()
        for emp in employees:
            prof = recalculate_employee_baseline(db, emp.id, window_days=30)
            print(f"  - Profiled {emp.name} ({emp.id}): Sample Size={prof.sample_size}, Deviation Score={prof.current_deviation_score}")

        db.commit()
        print("Database initialization and seeding completed successfully!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
