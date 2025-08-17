# Siem-analysis-
This project mimics a SIEM system like Azure Sentinel, parsing log files to detect suspicious patterns and generate alerts. It showcases skills in processing large-scale log data and threat detection, advancing cybersecurity expertise. By analyzing logs for anomalies like unusual logins, it enables rapid threat response.

import json
import re
from datetime import datetime
import sys

def parse_logs(log_file):
    """
    Parse log file for suspicious patterns and generate SIEM alerts.
    """
    suspicious_patterns = [
        r"failed login",
        r"unauthorized access",
        r"error code 403",
        r"sql injection attempt"
    ]
    alerts = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                for pattern in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "log_entry": line.strip(),
                            "threat_type": pattern,
                            "severity": "High" if "sql injection" in pattern.lower() else "Medium"
                        }
                        alerts.append(alert)
        
        # Save alerts to a JSON file (simulating SIEM integration)
        with open("siem_alerts.json", "w") as f:
            json.dump(alerts, f, indent=2)
        print(f"Generated {len(alerts)} alerts. Saved to siem_alerts.json")
        return alerts
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return []
    except Exception as e:
        print(f"Error parsing logs: {e}")
        return []

def display_alerts(alerts):
    """
    Display generated alerts in a formatted manner.
    """
    if not alerts:
        print("No alerts generated.")
        return
    
    print("\nDetected Threats:")
    print("=" * 50)
    for alert in alerts:
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Threat Type: {alert['threat_type']}")
        print(f"Severity: {alert['severity']}")
        print(f"Log Entry: {alert['log_entry']}")
        print("-" * 50)

def main():
    """
    Main function to run SIEM log analysis.
    """
    log_file = input("Enter log file path (e.g., sample_logs.txt): ").strip()
    print(f"\nStarting SIEM log analysis for {log_file}")
    print("=" * 50)
    
    alerts = parse_logs(log_file)
    display_alerts(alerts)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
