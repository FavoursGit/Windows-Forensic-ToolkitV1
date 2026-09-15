import subprocess
import xml.etree.ElementTree as ET
import json
import os

EVENT_IDS = [4624, 4625, 4634, 4648, 4688, 1102]

def get_security_events():
    event_ids_string = ",".join(str(event_id) for event_id in EVENT_IDS)
    command = [
        "powershell",
        "-Command",
        f"""
        Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={event_ids_string}}} -MaxEvents 100 |
        ForEach-Object{{
            $_.ToXml()
        }}
        """
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout

def parse_event(xml_string):
    root = ET.fromstring(xml_string)

    namespace = {
        "event": "http://schemas.microsoft.com/win/2004/08/events/event"
    }
    # Get basic event information
    Event_id = root.find("event:System/event:EventID", namespace).text
    time_created = root.find("event:System/event:TimeCreated", namespace).attrib["SystemTime"]

    #Get EventData fields
    event_data = {}

    for data in root.findall("event:EventData/event:Data", namespace):
        field_name = data.attrib.get("Name")
        field_value = data.text

        event_data[field_name] = field_value

    # Build the forensic record
    forensic_event = {
        "event_id": Event_id,
        "time": time_created,
        "username":event_data.get("TargetUserName"),
        "domain": event_data.get("TargetDomainName"),
        "logon_type": event_data.get("LogonType"),
        "source_ip": event_data.get("IpAddress"),
        "source_port": event_data.get("IpPort"),
        "process": event_data.get("ProcessName"),
        "new_process": event_data.get("NewProcessName"),
        "command_line": event_data.get("CommandLine"),
        "failure_reason": event_data.get("FailureReason"),
        "status": event_data.get("Status"),
    }

    return forensic_event

def collect_security_events():

    raw_events = get_security_events()

    xml_events = raw_events.split("</Event>")

    events = []

    for xml_event in xml_events:

        xml_event = xml_event.strip()

        if not xml_event:
            continue

        xml_event += "</Event>"

        event = parse_event(xml_event)

        events.append(event)

    return events