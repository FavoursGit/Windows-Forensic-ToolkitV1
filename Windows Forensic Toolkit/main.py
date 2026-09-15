import json
import os

from modules.event_logs import collect_security_events
from modules.detections import detect_brute_force
from modules.registry import collect_run_keys
from modules.registry import collect_run_keys, detect_suspicious_run_keys

def save_events(events):
    os.makedirs("output", exist_ok=True)
    with open("output/security_events.json", "w") as file:
        json.dump(events, file, indent=4)

def save_alerts(alerts):
    os.makedirs("output", exist_ok=True)
    with open ("output/security_alerts.json", "w") as file:
        json.dump(alerts, file, indent=4)

def save_registry_entries(entries):
    os.makedirs("output", exist_ok=True)

    with open("output/registry_entries.json", "w") as file:
        json.dump(entries, file, indent=4)

def save_registry_alerts(alerts):
    os.makedirs("output", exist_ok=True)

    with open("output/registry_alerts.json", "w") as file:
        json.dump(alerts, file, indent=4)

def display_summary(events):
    counts = {
        "4624": 0,
        "4625": 0,
        "4634": 0,
        "4648": 0,
        "4688": 0,
        "1102": 0
    }
    for event in events:
        event_id = event["event_id"]
        if event_id in counts:
            counts[event_id] += 1

    print("\n====================================")
    print(" WINDOWS FORENSICS TOOLKIT")
    print("====================================")

    print(f"\nSecurity events collected: {len(events)}")

    print("\nEvent Summary")
    print("------------------------------------")

    print(f"4624 Successful Logons:  {counts['4624']}")
    print(f"4625 Failed Logons:      {counts['4625']}")
    print(f"4634 Logoffs:            {counts['4634']}")
    print(f"4648 Explicit Logons:    {counts['4648']}")
    print(f"4688 Process Creation:   {counts['4688']}")
    print(f"1102 Security Log Clear: {counts['1102']}")

    print("\nEvidence saved:")
    print("output/security_events.json")

def display_alerts(alerts):

    print("\n====================================")
    print(" SECURITY ALERTS")
    print("====================================")

    if not alerts:
        print("\nNo suspicious brute-force activity detected.")
        return

    for alert in alerts:
        print(f"\n[{alert['severity'].upper()}] {alert['type']}")
        print("------------------------------------")
        print(f"Source IP:       {alert['source_ip']}")
        print(f"Target User:     {alert['username']}")
        print(f"Failed Attempts: {alert['failed_attempts']}")

def display_registry_entries(entries):

    print("\n====================================")
    print(" REGISTRY RUN ENTRIES")
    print("====================================")

    if not entries:
        print("\nNo registry run entries found.")
        return

    for entry in entries:
        print(f"\nName:    {entry['name']}")
        print(f"Command: {entry['command']}")
        print(f"Path:    {entry['registry_path']}")

def display_registry_alerts(alerts):

    print("\n====================================")
    print("REGISTRY ALERTS")
    print("====================================")

    if not alerts:
        print("\nNo suspicious registry persistence detected.")
        return

    for alert in alerts:
        print(f"\n[{alert['severity'].upper()}] {alert['type']}")
        print("------------------------------------")
        print(f"Name:    {alert['name']}")
        print(f"Command: {alert['command']}")
        print(f"Path:    {alert['registry_path']}")

        print("\nReasons:")

        for reason in alert['reasons']:
            print(f"  - {reason}")

def main():

    print("\nCollecting Windows Security events...")

    events = collect_security_events()

    save_events(events)
    display_summary(events)

    alerts = detect_brute_force(events)
    save_alerts(alerts)
    display_alerts(alerts)

    
    registry_entries = collect_run_keys()

    save_registry_entries(registry_entries)
    display_registry_entries(registry_entries)

    registry_alerts = detect_suspicious_run_keys(registry_entries)

    save_registry_alerts(registry_alerts)
    display_registry_alerts(registry_alerts)



if __name__ == "__main__":
    main()