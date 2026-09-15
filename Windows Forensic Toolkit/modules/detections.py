from collections import defaultdict

def detect_brute_force(events, threshold = 2):
    failed_logins = defaultdict(list)

    #First: collect failed logins
    for event in events:
        if event["event_id"] != "4625":
            continue

        source_ip = event.get("source_ip")
        username = event.get("username")
        timestamp = event.get("time")

        #Ignore events without a useful source IP
        if not source_ip or source_ip in "-":
            continue

        key = (source_ip, username)

        failed_logins[key].append(timestamp)

    #Second Aanalyse them
    alerts = []

    for (source_ip, username), timestamps in failed_logins.items():
        if len(timestamps) >= threshold:
            alert = {
                "type": "Possible Brute Force",
                "severity": "Medium",
                "source_ip": source_ip,
                "username": username,
                "failed_attempts": len(timestamps),
                "timestamps": timestamps 
            }
            alerts.append(alert)
    return alerts