import requests
import time
import os
import datetime
from config.settings import settings
from utils.logger import logger

def rescan_vt(file_hash: str) -> bool:
    if not settings.vt_api_key: return False
    
    rescan_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
    headers = {"x-apikey": settings.vt_api_key, "accept": "application/json"}
    
    try:
        response = requests.post(rescan_url, headers=headers)
        if response.status_code == 200:
            logger.info("Rescan requested successfully for the file.")
            return True
        elif response.status_code == 204:
            logger.error("VirusTotal API request failed with status code 204: Rate limit exceeded.")
            time.sleep(15)
        else:
            response_dict = response.json()
            error_code = response_dict.get('error', {}).get('code', "")
            error_message = response_dict.get('error', {}).get('message', "")
            logger.error(f"VirusTotal API request failed ({error_code}): {error_message}")
    except Exception as e:
        logger.error(f"Exception occurred while requesting rescan: {e}")
    return False

def get_vt_report(file_hash: str, checked_files: dict) -> dict:
    if not settings.vt_api_key: return {}
    
    report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": settings.vt_api_key, "accept": "application/json"}
    
    try:
        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            response_dict = response.json()
            logger.info("Checking the results from VirusTotal database.")
            
            last_analysis_ts = response_dict['data'].get('attributes', {}).get('last_analysis_date', 0)
            last_analysis = datetime.datetime.fromtimestamp(last_analysis_ts)
            delta_from_now = datetime.datetime.now() - last_analysis
            is_old_scan = delta_from_now > datetime.timedelta(days=15)
            
            if is_old_scan:
                if delta_from_now.days == 19924:
                    logger.warning("The analysis of the file is still in progress. Please check later.")
                    logger.info(f"Check the analysis URL: https://www.virustotal.com/gui/file/{file_hash}")
                else:
                    logger.warning(f"Last scan at {last_analysis.strftime('%Y-%m-%d %I:%M:%S %p')} ({delta_from_now.days} days ago).")
                    logger.warning("File was last scanned more than 15 days ago. Requesting rescan.")
                time.sleep(15)
                if delta_from_now.days != 19924 and rescan_vt(file_hash):
                    checked_files[file_hash]['vt_check_again'] = True
                else:
                    checked_files[file_hash]['vt_check_again'] = True
                    checked_files[file_hash]['vt_checked'] = False
                    return {}
            else:
                checked_files[file_hash]['vt_check_again'] = False
            
            checked_files[file_hash]['vt_checked'] = True
            return response_dict
            
        elif response.status_code == 204:
            checked_files[file_hash]['vt_checked'] = False
            checked_files[file_hash]['vt_check_again'] = True
            logger.error("VirusTotal API request failed with status code 204: Rate limit exceeded.")
            time.sleep(15)
            
        else:
            response_dict = response.json()
            checked_files[file_hash]['vt_checked'] = False
            checked_files[file_hash]['vt_check_again'] = True
            if response.status_code == 404 and response_dict.get('error', {}).get('code', "") == "NotFoundError":
                logger.info("File Hash not found in VirusTotal database.")
            else:
                error_code = response_dict.get('error', {}).get('code', "")
                error_message = response_dict.get('error', {}).get('message', "")
                logger.error(f"VirusTotal API request failed ({error_code}): {error_message}")
                
    except Exception as e:
        logger.error(f"Exception occurred while checking VirusTotal: {e}")
        checked_files[file_hash]['vt_checked'] = False
        checked_files[file_hash]['vt_check_again'] = True
        
    return {}

def upload_file_vt(file_path: str, checked_files: dict) -> dict:
    if not settings.vt_api_key: return {}
    
    file_size = os.path.getsize(file_path) / 1024.0 / 1024.0
    if file_size >= 200:
        logger.error(f"File '{os.path.basename(file_path)}' is too large to upload to VirusTotal (>200MB).")
        return {}
    
    headers = {"x-apikey": settings.vt_api_key, "accept": "application/json"}
    
    if file_size < 32:
        upload_url = "https://www.virustotal.com/api/v3/files"
    else:
        get_upload_url = "https://www.virustotal.com/api/v3/files/upload_url"
        try:
            response = requests.get(get_upload_url, headers=headers)
            if response.status_code == 200:
                upload_url = response.json().get('data', "")
            else:
                error_code = response.json().get('error', {}).get('code', "")
                logger.error(f"Failed to get upload URL from VirusTotal with error code: {error_code}")
                return {}
        except Exception as e:
            logger.error(f"Exception occurred while getting upload URL: {e}")
            return {}
    
    try:
        with open(file_path, "rb") as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(upload_url, files=files, headers=headers)
            
        if response.status_code == 200:
            analysis_id = response.json().get('data', {}).get('id', "")
            logger.info(f"File '{os.path.basename(file_path)}' uploaded successfully to VirusTotal for scanning.")
            try:
                while True:
                    time.sleep(15)
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=headers)
                    if analysis_response.status_code == 200:
                        if analysis_response.json().get('data', {}).get('attributes', {}).get('status', "") == "completed":
                            file_sha256 = analysis_response.json().get('meta', {}).get('file_info', {}).get('sha256', "")
                            logger.info(f"File '{os.path.basename(file_path)}' scanned successfully by VirusTotal.")
                            if file_sha256:
                                return get_vt_report(file_sha256, checked_files)
                            break
            except Exception as e:
                logger.error(f"Exception occurred while checking VirusTotal: {e}")
        else:
            error_code = response.json().get('error', {}).get('code', "")
            logger.error(f"VirusTotal API request failed with error code: {error_code}")
            
    except Exception as e:
        logger.error(f"Exception occurred while uploading file to VirusTotal: {e}")
    
    return {}
