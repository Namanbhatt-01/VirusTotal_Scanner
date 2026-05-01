import datetime
from config.settings import settings

def get_message(**kwargs) -> str:
    filename = kwargs.get('filename', "Unknown")
    file_extension = kwargs.get('file_extension', "Unknown")
    file_path = kwargs.get('file_path', "Unknown")
    file_hash = kwargs.get('file_hash', "Unknown")
    
    last_checked_cache = kwargs.get('last_checked_cache', "Unknown")
    vt_scan_date = kwargs.get('vt_scan_date', last_checked_cache)
    
    old_scan_date = ""
    if vt_scan_date != "Unknown" and not isinstance(vt_scan_date, str):
        date = datetime.datetime.fromtimestamp(vt_scan_date)
        if datetime.datetime.now() - date > datetime.timedelta(days=15):
            old_scan_date = " (Relatively old scan)"
        vt_scan_date = datetime.datetime.fromtimestamp(vt_scan_date).strftime("%Y-%m-%d %I:%M:%S %p")
    elif isinstance(vt_scan_date, datetime.datetime):
        vt_scan_date = vt_scan_date.strftime("%Y-%m-%d %I:%M:%S %p")
    
    vt_reputation = kwargs.get('vt_reputation', "Unknown")
    vt_votes = kwargs.get('vt_votes', "Unknown")
    vt_url = kwargs.get('vt_url', "No Link")
    valhalla_url = kwargs.get('valhalla_url', False)
    malshare_url = kwargs.get('malshare_url', False)
    
    vt_malicious = kwargs.get('vt_malicious', 0)
    vt_suspicious = kwargs.get('vt_suspicious', 0)
    vt_undetected = kwargs.get('vt_undetected', 0)
    vt_harmless = kwargs.get('vt_harmless', 0)
    vt_failure = kwargs.get('vt_failure', 0)
    vt_unsupported = kwargs.get('vt_unsupported', 0)
    vt_total = kwargs.get('vt_total', 0)
    
    suspicious_ext = str(kwargs.get('suspicious_ext', False))
    alert_type = kwargs.get('alert_type', "Unknown")
    vt_checked = kwargs.get('vt_checked', False)
    
    processes_info = kwargs.get('processes_info', [])
    
    message = []
    
    if not filename or not file_path or not file_hash:
        return "[X] ERROR: Missing required parameters to generate message."
    
    message.append(f"File Name: '{filename}'")
    message.append(f"Full Path: '{file_path}'")
    message.append(f"SHA256 Hash: {file_hash}")
    message.append("")
    
    if alert_type != "Unknown":
        message.append(f"Alert Type: {alert_type}")
        if suspicious_ext == "True":
            message.append(f"Suspicious Extension: {suspicious_ext} ({file_extension})")
            
        if vt_checked and vt_url != "No Link":
            message.append(f"VirusTotal Last Scan Date: {vt_scan_date}{old_scan_date}")
            message.append(f"VirusTotal Reputation: {vt_reputation}")
            message.append(f"VirusTotal Votes: {vt_votes}")
            message.append(f"VirusTotal URL: {vt_url}")
            if vt_malicious or vt_suspicious:
                message.append(f"Virustotal Scan Details:")
                if vt_malicious: message.append(f"  Malicious: {vt_malicious}/{vt_total}")
                if vt_suspicious: message.append(f"  Suspicious: {vt_suspicious}/{vt_total}")
                if vt_undetected: message.append(f"  Undetected: {vt_undetected}/{vt_total}")
                if vt_harmless: message.append(f"  Harmless: {vt_harmless}/{vt_total}")
                if vt_failure: message.append(f"  Failure: {vt_failure}/{vt_total}")
                if vt_unsupported: message.append(f"  Unsupported: {vt_unsupported}/{vt_total}")
        elif 'http' in vt_url:
            message.append(f"Last Scan Date: {vt_scan_date}{old_scan_date}")
            message.append(f"VirusTotal URL: {vt_url}")
        else:
            message.append(f"Last Scan Date: {vt_scan_date}{old_scan_date}")
        
        if valhalla_url:
            message.append(f"Valhalla URL: {valhalla_url}")
        if malshare_url:
            message.append(f"MalShare URL: {malshare_url}")
    else:
        message.append("Alert Type: No Data")
        
    if processes_info:
        message.append("")
        message.append("Process(es) Information:")
        no_processes = len(processes_info)
        for i, process in enumerate(processes_info):
            message.append("")
            message.append(f"  Process {i+1}/{no_processes}:")
            message.append(f"    Status: {process['status']}")
            message.append(f"    Name: {process['name']} (PID: {process['pid']})")
            message.append(f"    User: {process['username']}")
            message.append(f"    Parent: {process['pname']} (PID: {process['ppid']})")
            message.append(f"    Process-Chain: {process['proc_chain']}")
            message.append(f"    Create Time: {process['create_time']} (Running Time: {process['running_time']})")
            message.append("")
            message.append(f"    Executable: '{process['exe']}'")
            message.append(f"    Current Working Directory: '{process['cwd']}'")
            message.append(f"    Cmdline: {process['cmdline']}")
            message.append("")
            
            if process['open_files']:
                message.append("    Open Files:")
                open_files = sorted(list(set(process['open_files'])))
                for ofile in open_files:
                    message.append(f"      '{ofile}'")
                message.append("")
            else:
                message.append("    Open Files: No Files Opened")
                message.append("")
            
            if process['connections']:
                message.append("    Connections:")
                connections = sorted(list(set(process['connections'])))
                for connection in connections:
                    message.append(f"      {connection}")
            else:
                message.append("    Connections: No Active Connections")
            if i+1 != no_processes: message.append("  " + ("-" * 25))
    
    elif not settings.skip_process:
        message.append("")
        message.append("Process Information: No Process Associated")
    
    return "\n".join(message)
