import os
import time
import datetime
from config.settings import settings
from utils.logger import logger, log_to_file
from utils.file_ops import get_sha256, resolve_shortcut
from core.cache import load_data, save_data
from core.process import get_process_info
from integrations.virustotal import get_vt_report, upload_file_vt
from integrations.valhalla import get_valhalla
from integrations.malshare import get_malshare
from notifiers.formatter import get_message
from notifiers.slack import send_slack_alert

class ScannerEngine:
    def __init__(self):
        self.checked_files = load_data()
        self.vt_timer = datetime.datetime.now() - datetime.timedelta(seconds=15)

    def scan_paths(self):
        paths = settings.paths
        for i, path in enumerate(paths):
            self.checked_files = load_data()
            print(f"{chr(10) if i==0 else ''}{'='*100}\n")
            
            no_paths = len(paths)
            if not os.path.exists(path):
                logger.error(f"{i+1}/{no_paths} Path '{path}' does not exist. Skipping.")
                time.sleep(1)
                continue
            
            files = []
            if os.path.isfile(path):
                path = os.path.abspath(path).replace("\\", "/")
                files = [path]
            elif os.path.isdir(path):
                for root, _, filenames in os.walk(os.path.abspath(path)):
                    for filename in filenames:
                        files.append(os.path.join(root, filename).replace("\\", "/"))
            else:
                logger.error(f"{i+1}/{no_paths} Invalid Path: '{path}'")
                time.sleep(1)
                continue
            
            if not files:
                logger.warning(f"{i+1}/{no_paths} No files found in path: '{path}'")
                time.sleep(1)
                continue
                        
            no_files = len(files)
            logger.info(f"{i+1}/{no_paths} Checking Path: '{path}'")
            
            for j, file_path in enumerate(files):
                self._process_file(file_path, i, j, no_files)
                print(f"{chr(10) + ('-'*50) if j+1 != no_files else ''}")
                save_data(self.checked_files)

    def _process_file(self, file_path: str, path_idx: int, file_idx: int, total_files: int):
        message_data = {}
        filename = os.path.basename(file_path)
        file_extension = os.path.splitext(filename)[1].lower()
        
        if settings.scan_interval > 0:
            logger.info(f"{path_idx+1}: {file_idx+1}/{total_files} Checking file: '{file_path}'")
            
        if file_extension == '.lnk':
            resolved_path = resolve_shortcut(file_path)
            if resolved_path != file_path:
                file_path = resolved_path
                filename = os.path.basename(file_path)
                file_extension = os.path.splitext(filename)[1].lower()
                if settings.scan_interval > 0: 
                    logger.info(f"File is a shortcut. Resolving to: '{file_path}'")
            else:
                if settings.scan_interval > 0:
                    logger.error(f"Error resolving shortcut '{filename}'")
                time.sleep(1)
                return
                
        file_hash = get_sha256(file_path)
        if not file_hash:
            return
            
        message_data.update({
            'filename': filename,
            'file_extension': file_extension,
            'file_path': file_path,
            'file_hash': file_hash
        })
        
        cached_info = self.checked_files.get(file_hash, {})
        
        if (settings.scan_interval == 0 and
              cached_info.get("notified", False) and
              cached_info.get("vt_checked", False) and
              not cached_info.get("vt_check_again", False)):
            logger.info(f"File '{filename}' scanned and notified before (Scan Result: {cached_info.get('scan_result')}), skipping the process check.")
            time.sleep(1)
            return
            
        elif not (cached_info.get("notified", False) and cached_info.get("vt_checked", False)) or cached_info.get("vt_check_again", False):
            logger.info(f"New file detected: '{filename}'")
            self.checked_files[file_hash] = self.checked_files.get(file_hash, {
                "notified": False,
                "vt_checked": False,
                "vt_check_again": False,
                "file_path": file_path.replace("\\", "/"),
                "scan_result": "Unknown",
                "last_checked": datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
            })
            
            if (datetime.datetime.now() - self.vt_timer).seconds < 15:
                wait_time = 15 - (datetime.datetime.now() - self.vt_timer).seconds
                logger.warning(f"VirusTotal API rate limit. Waiting {wait_time}s before checking again.")
                time.sleep(wait_time)
                self.vt_timer = datetime.datetime.now()
            
            vt_report = get_vt_report(file_hash, self.checked_files)
            if settings.upload and vt_report and vt_report.get('error', 0):
                logger.info(f"Uploading file '{filename}' to VirusTotal for scanning.")
                vt_report = upload_file_vt(file_path, self.checked_files)
            
            is_suspicious_ext = file_extension in settings.suspicious_extensions
            message_data['suspicious_ext'] = is_suspicious_ext
            
            if is_suspicious_ext:
                self.checked_files[file_hash]['scan_result'] = "Suspicious Extension"
                message_data['alert_type'] = "Suspicious Extension"
            else:
                self.checked_files[file_hash]['scan_result'] = "Clean File"
                message_data['alert_type'] = "Clean File"
            
            self._parse_vt_report(vt_report, file_hash, message_data)
            self._check_threat_intel_apis(file_hash, message_data)
            
            processes_info = [] if settings.skip_process else get_process_info(file_path)
            message_data['processes_info'] = processes_info
            
            message_data['vt_checked'] = self.checked_files[file_hash].get('vt_checked', False)
            message_data['last_checked_cache'] = self.checked_files[file_hash].get('last_checked', "Unknown")
            
            message = get_message(**message_data)
            print(f"\n{message}\n")
            
            if message_data['alert_type'] != "Clean File" and send_slack_alert(message):
                self.checked_files[file_hash]['notified'] = True
            elif message_data['alert_type'] == "Clean File":
                logger.info(f"File '{filename}' is clean. No alert sent.")
                self.checked_files[file_hash]['notified'] = True
                
            log_to_file(message)
            
        else:
            logger.info(f"File '{filename}' already scanned and notified before (Scan Result: {cached_info.get('scan_result')}).")
            
            message_data['vt_url'] = f"https://www.virustotal.com/gui/file/{file_hash}"
            self._check_threat_intel_apis(file_hash, message_data)
            
            message_data['alert_type'] = cached_info.get('scan_result', "Unknown")
            message_data['suspicious_ext'] = file_extension in settings.suspicious_extensions
            message_data['last_checked_cache'] = cached_info.get('last_checked', "Unknown")
            message_data['vt_checked'] = cached_info.get('vt_checked', False)
            
            processes_info = [] if settings.skip_process else get_process_info(file_path)
            message_data['processes_info'] = processes_info
            
            message = get_message(**message_data)
            print(f"\n{message}")
            log_to_file(message)

    def _parse_vt_report(self, vt_report: dict, file_hash: str, message_data: dict):
        if not vt_report and not self.checked_files[file_hash].get('vt_checked') and self.checked_files[file_hash].get('vt_check_again'):
            return
        elif not vt_report:
            logger.error(f"Error checking VirusTotal for '{message_data['filename']}'.")
        elif not vt_report.get('data', 0):
            logger.warning(f"'{message_data['filename']}' not found in VirusTotal. Please enable <UPLOAD> to scan.")
        else:
            data = vt_report.get('data', {})
            attrs = data.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)
            failure = stats.get('timeout', 0) + stats.get('confirmed-timeout', 0) + stats.get('failure', 0)
            unsupported = stats.get('type-unsupported', 0)
            total = sum(int(x) for x in stats.values())
            
            message_data.update({
                'vt_malicious': malicious,
                'vt_suspicious': suspicious,
                'vt_undetected': undetected,
                'vt_harmless': harmless,
                'vt_failure': failure,
                'vt_unsupported': unsupported,
                'vt_total': total
            })
            
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
            self.checked_files[file_hash]['last_checked'] = str(attrs.get('last_analysis_date', current_time))
            
            message_data['vt_scan_date'] = attrs.get('last_analysis_date', "Unknown")
            status = "Malicious" if (malicious + suspicious) > 0 else "Clean"
            message_data['vt_reputation'] = f"{status} ({malicious+suspicious} / {total} scanners)"
            message_data['vt_url'] = f"https://www.virustotal.com/gui/file/{attrs.get('sha256', '')}"
            
            votes = attrs.get('total_votes', {})
            message_data['vt_votes'] = f"{votes.get('harmless', 0)} Good - {votes.get('malicious', 0)} Bad"
        
            if malicious + suspicious == 0:
                if message_data.get('suspicious_ext'):
                    self.checked_files[file_hash]['scan_result'] = "Suspicious Extension"
                    message_data['alert_type'] = "Suspicious Extension"
                else:
                    self.checked_files[file_hash]['scan_result'] = "Clean File"
                    message_data['alert_type'] = "Clean File"
            else:
                self.checked_files[file_hash]['scan_result'] = "Malicious File"
                message_data['alert_type'] = "Malicious File"

    def _check_threat_intel_apis(self, file_hash: str, message_data: dict):
        # Valhalla
        if 'http' not in self.checked_files[file_hash].get('valhalla_url', ""):
            valhalla_url = get_valhalla(file_hash)
            if valhalla_url:
                message_data['valhalla_url'] = valhalla_url
                self.checked_files[file_hash]['valhalla_url'] = valhalla_url
        elif 'http' in self.checked_files[file_hash].get('valhalla_url', ""):
            message_data['valhalla_url'] = self.checked_files[file_hash].get('valhalla_url', "")
        
        # MalShare
        if 'http' not in self.checked_files[file_hash].get('malshare_url', ""):
            malshare_url = get_malshare(file_hash)
            if malshare_url:
                message_data['malshare_url'] = malshare_url
                self.checked_files[file_hash]['malshare_url'] = malshare_url
        elif 'http' in self.checked_files[file_hash].get('malshare_url', ""):
            message_data['malshare_url'] = self.checked_files[file_hash].get('malshare_url', "")
