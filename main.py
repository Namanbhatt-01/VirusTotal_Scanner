import argparse
import sys
import os
import time
import datetime
import platform
from config.settings import settings
from utils.logger import logger
from core.engine import ScannerEngine

class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        parts = []
        if action.option_strings:
            parts.append(', '.join(action.option_strings))
        if action.nargs == 0:
            return ', '.join(parts)
        return ' '.join(parts)

def parse_args():
    parser = argparse.ArgumentParser(
        description="VirusTotal Scanner (Modular Architecture)",
        epilog="Refactored for Professional Security Engineering.",
        formatter_class=CustomHelpFormatter
    )
    parser.add_argument("-k", "--vt_api_key", help="VirusTotal API key")
    parser.add_argument("-p", "--paths", help="Folders/Files paths to scan", nargs="+")
    parser.add_argument("-w", "--slack_webhook", help="Slack Webhook URL")
    parser.add_argument("-i", "--stop_interval", type=float, help="Stop Interval in minutes")
    parser.add_argument("-f", "--cycles", type=int, help="Number of scan cycles (0 for forever)")
    parser.add_argument("-m", "--max_msg", type=int, help="Maximum number of messages per file (0 for unlimited)")
    parser.add_argument("-e", "--sus_ext", help="Suspicious file extensions", nargs="+")
    parser.add_argument("--malshare_api_key", help="MalShare API key")
    parser.add_argument("--no_send", help="Do not send alerts to Slack", action="store_true")
    parser.add_argument("--no_upload", help="Do not upload new files to VirusTotal", action="store_false")
    parser.add_argument("--skip_process", help="Skip checking the processes of old scanned files", action="store_true")
    parser.add_argument("--no_history", help="Do not cache the history of the scan", action="store_false")
    parser.add_argument("--no_log", help="Do not log the output to a file", action="store_false")
    parser.add_argument("--debug", help="Enable debug mode", action="store_true")
    
    args = parser.parse_args()
    args_dict = vars(args)
    
    # Override settings with command line arguments if provided
    if args_dict.get('vt_api_key'): settings.vt_api_key = args_dict['vt_api_key']
    if args_dict.get('paths'): settings.paths = [os.path.expandvars(p.strip()).replace("\\", "/") for p in args_dict['paths']]
    if args_dict.get('slack_webhook'): settings.slack_webhook_url = args_dict['slack_webhook']
    if args_dict.get('stop_interval') is not None: settings.scan_interval = args_dict['stop_interval']
    if args_dict.get('cycles') is not None: settings.cycles = args_dict['cycles']
    if args_dict.get('max_msg') is not None: settings.max_msg = args_dict['max_msg']
    if args_dict.get('sus_ext'): settings.suspicious_extensions = list(set([str(ext).strip().lower() for ext in args_dict['sus_ext']]))
    if args_dict.get('malshare_api_key'): settings.malshare_api_key = args_dict['malshare_api_key']
    if args_dict.get('no_send'): settings.no_send = args_dict['no_send']
    if args_dict.get('no_upload') is False: settings.upload = False # argparse store_false sets it to False when present
    if args_dict.get('skip_process'): settings.skip_process = args_dict['skip_process']
    if args_dict.get('no_history') is False: settings.history_log = False
    if args_dict.get('no_log') is False: settings.logging = False
    if args_dict.get('debug'): settings.debug = args_dict['debug']

    # Validation
    if not settings.vt_api_key:
        logger.error("VirusTotal API key is required to proceed.")
        sys.exit(1)
        
    if not settings.no_send and not settings.slack_webhook_url:
        logger.error("Slack Webhook URL is required unless --no_send is used.")
        sys.exit(1)
        
    if not settings.paths:
        logger.error("No paths provided to scan. Please specify paths.")
        sys.exit(1)
        
    if settings.scan_interval == 0.0 and settings.cycles != 0:
        logger.error("To skip the scan interval (-i 0), set --cycles to 0.")
        sys.exit(1)

def main():
    parse_args()
    
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if not settings.debug:
        os.system('cls' if os.name == 'nt' else 'clear')
        
    print("[+][+][+] VirusTotal Scanner v1.0 | By Naman Bhatt [+][+][+]\n")
    print(f"[+] Monitoring the following paths:")
    for i, path in enumerate(settings.paths):
        print(f"      {i+1}. '{path}'")
        
    print(f"[+] Suspicious Extensions: {', '.join(settings.suspicious_extensions)}")
    print(f"[+] Stop Interval: {settings.scan_interval} minutes")
    print(f"[+] Number of Cycles: {settings.cycles if settings.cycles else 'Forever'}")
    print(f"[+] VirusTotal Upload: {'Enabled' if settings.upload else 'Disabled'}")
    if settings.malshare_api_key:
        print(f"[+] MalShare API: Enabled")
        
    if settings.no_send:
        print(f"[+] Slack Alert: Disabled.")
    else:
        print(f"[+] Slack Alert: Enabled. ({settings.max_msg if settings.max_msg else 'Unlimited'} Msg/File)")
        
    print(f"\n[+] Debug Mode: {'Enabled' if settings.debug else 'Disabled'}")
    print(f"[+] Press (Ctrl + C) to stop the script.\n")
    
    engine = ScannerEngine()
    t1 = datetime.datetime.now()
    
    try:
        if settings.cycles == 0:
            while True:
                t2 = datetime.datetime.now()
                engine.scan_paths()
                t3 = datetime.datetime.now()
                
                if settings.scan_interval > 0:
                    print(f"{'='*100}\n\n[+] Scan time: {str(t3-t2).split('.')[0]}")
                print(f"[+] Running time: {str(t3-t1).split('.')[0]}")
                
                if settings.scan_interval > 0:
                    print(f"[+] Sleeping for {settings.scan_interval} minutes...")
                    time.sleep(60 * settings.scan_interval)
        else:
            for i in range(settings.cycles):
                t2 = datetime.datetime.now()
                engine.scan_paths()
                t3 = datetime.datetime.now()
                
                print(f"{'='*100}\n\n[+] Scanned {i+1}/{settings.cycles} times.")
                print(f"[+] Scan time: {str(t3-t2).split('.')[0]}")
                print(f"[+] Running time: {str(t3-t1).split('.')[0]}")
                
                if i + 1 != settings.cycles and settings.scan_interval > 0:
                    print(f"[+] Sleeping for {settings.scan_interval} minutes...")
                    time.sleep(60 * settings.scan_interval)
            print("[+] Scanning completed.")
            
    except KeyboardInterrupt:
        print("\n[+] Scan interrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
