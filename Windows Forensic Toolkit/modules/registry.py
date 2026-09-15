import winreg

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"

def collect_run_keys():
    run_entries = []

    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            0,
            winreg.KEY_READ
        )

        number_of_values = winreg.QueryInfoKey(key)[1]

        for i in range(number_of_values):
            name, value, value_type = winreg.EnumValue(key, i)

            entry = {
                "name": name,
                "command": value,
                "registry_path":f"HKCU\\{RUN_KEY_PATH}",
                "value~_type": value_type
            }
            run_entries.append(entry)

        winreg.CloseKey(key)

    except FileNotFoundError:
        pass
    return run_entries

if __name__ == "__main__":
    entries = collect_run_keys()

    print ("\nRegistry Run Entries")
    print ("------------------------------------")

    if not entries:
        print("No entries found")

    for entry in entries:
        print(f"Name:    {entry['name']}")
        print(f"Command: {entry['command']}")
        print(f"Path:    {entry['registry_path']}")
        print()

def detect_suspicious_run_keys(entries):
    alerts = []

    suspicious_locations = [
        "\\AppData\\Roaming\\",
        "\\AppData\\Local\\Temp\\",
        "\\Temp\\",
        "\\Downloads\\"
    ]

    suspicious_processes = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ]

    for entry in entries:
        command = entry.get("command", "")
        command_lower = command.lower ()

        reasons = []

        #Check for suspicious file locations
        for location in suspicious_locations:
            if location.lower() in command_lower:
                reasons.append(f"Executable launched from suspicious location: {location}")

        #check for script execution
        for process in suspicious_processes:
            if process in command_lower:
                reasons.append(f"Startup entry uses interpreter: {process}")

        if reasons:
            alerts.append({
                "type": "Suspicious Registry Persistence",
                "severity": "Medium",
                "name": entry.get("name"),
                "command": command,
                "registry_path": entry.get("registry_path"),
                "reasons": reasons
            })
    return alerts