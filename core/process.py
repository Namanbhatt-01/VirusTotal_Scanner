import os
import psutil
import datetime
import platform
import ctypes
from importlib.util import find_spec
from utils.logger import logger

if find_spec('pypiwin32') and 'pypiwin32' in find_spec('pypiwin32').name: # type: ignore
    import win32evtlog  # type: ignore

def get_process_events_win() -> dict:
    events = {}
    try:
        if platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin():
            server = 'localhost'
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            handle = win32evtlog.OpenEventLog(server, log_type)

            while True:
                events_raw = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_raw:
                    break
                for event in events_raw:
                    if event.EventID == 4688:  # Process creation event ID
                        event_data = event.StringInserts
                        if not event_data or len(event_data) < 14: continue
                        pid = int(event_data[4].strip(), 16)
                        ppid = int(event_data[7].strip(), 16)
                        name = os.path.basename(event_data[5].strip()) or "Non-existent process"
                        pname = os.path.basename(event_data[13].strip()) or "Non-existent process"                        
                        events[pid] = {'name': name, 'pid': pid, 'pname': pname, 'ppid': ppid}

            win32evtlog.CloseEventLog(handle)
    except Exception as e:
        logger.debug(f"Could not retrieve Windows event logs: {e}")
    return events

def get_running_process(executable_path: str) -> list[dict]:
    processes = []
    if not os.path.exists(executable_path) or not os.path.isfile(executable_path):
        return processes
    
    for proc in psutil.process_iter():
        try:
            proc_dict = proc.as_dict()
            if proc_dict.get('exe') == executable_path:
                processes.append(proc_dict)
            else:
                if proc_dict.get('cmdline'):
                    for cmd in proc_dict['cmdline']:
                        if os.path.isfile(cmd) and os.path.samefile(executable_path, cmd):
                            processes.append(proc_dict)
                            break
                
                if proc_dict.get('open_files'):
                    for ofile in proc_dict['open_files']:
                        if os.path.isfile(ofile.path) and os.path.samefile(executable_path, ofile.path):
                            processes.append(proc_dict)
                            break
        except Exception:
            pass
    return processes

def get_process_info(executable_path: str) -> list[dict]:
    processes_data = []
    logger.info(f"Checking running processes for '{os.path.basename(executable_path)}'")
    
    processes = get_running_process(executable_path)
    if not processes: 
        return processes_data
    
    events = get_process_events_win()
    for process in processes:
        proc_info = {}
        proc_info['name'] = process.get('name')
        proc_info['pid'] = process.get('pid')
        proc_info['exe'] = process.get('exe')
        proc_info['cwd'] = process.get('cwd')
        proc_info['ppid'] = process.get('ppid')
        proc_info['status'] = process.get('status')
        proc_info['username'] = process.get('username') or "SYSTEM"
        
        try:
            proc_info['pname'] = psutil.Process(proc_info['pid']).parent().name()
        except Exception:
            if proc_info['ppid'] in events:
                proc_info['pname'] = events[proc_info['ppid']].get('name', "Non-existent process")
            else:
                proc_info['pname'] = "Non-existent process"
        
        cmdline = process.get('cmdline')
        if cmdline:
            processed_cmd = []
            for cmd in cmdline:
                if os.path.exists(cmd) or (" " in cmd and not (cmd.startswith(("'", '"')) and cmd.endswith(("'", '"')))):
                    processed_cmd.append(f'"{cmd}"')
                else:
                    processed_cmd.append(cmd)
            proc_info['cmdline'] = " ".join(processed_cmd)
        else: 
            proc_info['cmdline'] = f'"{proc_info["exe"]}"'
        
        chain_pid = [proc_info['pid']]
        chain_name = [proc_info['name']]
        while True:
            try:
                parent = psutil.Process(chain_pid[-1]).parent()
                if not parent: break
                chain_pid.append(parent.pid)
                chain_name.append(parent.name())
            except Exception:
                try:
                    if chain_pid[-1] in events:
                        parent_pid = events[chain_pid[-1]]['ppid']
                        if parent_pid in events:
                            chain_pid.append(parent_pid)
                            chain_name.append(events[parent_pid].get('name', "Non-existent process"))
                            break
                    chain_pid.append('Unknown')
                    chain_name.append("Non-existent process")
                except Exception:
                    chain_pid.append('Unknown')
                    chain_name.append("Non-existent process")
                break
                
        chain_pid_str = map(str, reversed(chain_pid))
        chain_name_str = map(str, reversed(chain_name))
        chain = [f"{n} ({p})" for n, p in zip(chain_name_str, chain_pid_str)]
        proc_info['proc_chain'] = " > ".join(chain)
        
        open_files = []
        if process.get('open_files'):
            for ofile in process['open_files']:
                open_files.append(ofile.path)
        proc_info['open_files'] = open_files
        
        connections = []
        net_connections = process.get('connections') or process.get('net_connections') or []
        for con in net_connections:
            try:
                status = con.status
                ip, port = con.laddr
                connections.append(f'{status}\t{ip}:{port}')
            except Exception:
                pass
        proc_info['connections'] = connections
        
        try:
            create_time = datetime.datetime.fromtimestamp(process.get('create_time', 0))
            running_time = datetime.datetime.now() - create_time
            proc_info['create_time'] = create_time.strftime("%Y-%m-%d %I:%M:%S %p")
            proc_info['running_time'] = ":".join(str(running_time).split(".")[:-1])
        except Exception:
            proc_info['create_time'] = "Unknown"
            proc_info['running_time'] = "Unknown"
            
        processes_data.append(proc_info)
    
    return processes_data
