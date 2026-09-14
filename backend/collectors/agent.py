#!/usr/bin/env python3
"""
Threat AI — Autonomous Endpoint Log Collector & Telemetry Shipper Agent
=======================================================================
Simulates or executes real-time endpoint log collection across Windows Security
Event Logs, USB Removable Media buses, CloudTrail, DMS Egress, and VPN Gateways.

Transmits authenticated batches over HTTPS to the FastAPI Ingestion API.
"""

import sys
import time
import argparse
import json
import urllib.request
import urllib.error


def parse_args():
    parser = argparse.ArgumentParser(description="Threat AI Autonomous Log Collector Agent")
    parser.add_argument(
        "--collector",
        type=str,
        default="all",
        choices=["all", "endpoint_auth", "removable_media", "data_egress", "cloud_audit", "network_vpn"],
        help="Target sensor to collect logs from (default: all)"
    )
    parser.add_argument("--host", type=str, default="http://localhost:8000", help="FastAPI backend host URL")
    parser.add_argument("--interval", type=float, default=3.0, help="Seconds between collection pulses (default: 3.0)")
    parser.add_argument("--iterations", type=int, default=3, help="Number of pulses to stream (-1 for infinite, default: 3)")
    parser.add_argument("--simulate-anomaly", action="store_true", help="Inject an acute anomalous insider threat event")
    parser.add_argument("--employee-id", type=str, default=None, help="Target employee ID (e.g. 101, 102, 104)")
    return parser.parse_args()


def get_auth_token(host: str) -> str:
    """Authenticates as SOC Engineer to obtain JWT authorization token."""
    login_url = f"{host}/api/v1/auth/login"
    payload = json.dumps({"email": "engineer@threat.ai", "password": "admin123"}).encode("utf-8")
    req = urllib.request.Request(
        login_url,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["access_token"]
    except Exception as e:
        print(f"[!] Authentication failure connecting to {login_url}: {e}")
        print("    Ensure the backend server is running: uvicorn backend.app.main:app --reload --port 8000")
        sys.exit(1)


def trigger_pulse(host: str, token: str, collector_id: str, anomaly: bool, emp_id: str = None) -> dict:
    url = f"{host}/api/v1/collectors/{collector_id}/pulse"
    payload = json.dumps({"anomaly_simulation": anomaly, "custom_employee_id": emp_id}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    args = parse_args()
    host = args.host.rstrip("/")

    print("=================================================================")
    print("  THREAT AI — ENTERPRISE LOG COLLECTOR & TELEMETRY SHIPPER")
    print("=================================================================")
    print(f"Target Backend API : {host}")
    print(f"Collector Sensor   : {args.collector.upper()}")
    print(f"Anomaly Simulation : {args.simulate_anomaly}")
    print(f"Collection Interval: {args.interval}s")
    print(f"Pulse Batches      : {'Infinite' if args.iterations < 0 else args.iterations}")
    print("-----------------------------------------------------------------")
    print("[*] Contacting Keycloak / JWT Identity Provider...")

    token = get_auth_token(host)
    print("[+] Successfully authenticated as: SOC Lead Engineer (Role: SOC Engineer)")
    print("[+] Cryptographic JWT Bearer token obtained.")
    print("-----------------------------------------------------------------")

    target_collectors = [
        "endpoint_auth",
        "removable_media",
        "data_egress",
        "cloud_audit",
        "network_vpn"
    ] if args.collector == "all" else [args.collector]

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"\n>>> [PULSE #{iteration}] Polling telemetry queues...")

            for cid in target_collectors:
                try:
                    res = trigger_pulse(host, token, cid, args.simulate_anomaly, args.employee_id)
                    flag = " [!] ANOMALY FLAGGED" if res.get("anomalies_flagged", 0) > 0 else ""
                    print(
                        f"  [STREAM] {res['collector_name']:<40} "
                        f"| Ingested: {res['events_ingested']} "
                        f"| Anomalies: {res['anomalies_flagged']}{flag}"
                    )
                except Exception as e:
                    print(f"  [ERR] Failed collection on sensor '{cid}': {e}")

            if args.iterations > 0 and iteration >= args.iterations:
                print("\n[+] Reached requested batch count. Collector session completed successfully.")
                break

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[*] Log Collector agent terminated by operator.")


if __name__ == "__main__":
    main()
