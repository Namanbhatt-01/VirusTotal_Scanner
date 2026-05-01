import json
import os
from copy import deepcopy
from utils.crypto import encrypt, decrypt
from utils.logger import logger
from config.settings import settings

def load_data() -> dict:
    if not os.path.exists("history.cache"):
        return {}
    
    try:
        if settings.history_log:
            logger.debug("Loading data from file 'history.cache'")
            with open("history.cache", "r", encoding="utf-8") as f:
                decrypted_data = decrypt(f.read())
                if decrypted_data:
                    data = json.loads(decrypted_data)
                    logger.debug(f"Data loaded successfully. ({len(data.keys())} records found)")
                    return data
    except Exception as e:
        logger.error(f"Error loading the history: {e}")
    return {}

def save_data(data: dict) -> bool:
    try:
        if settings.history_log:
            encrypted_data = encrypt(json.dumps(data, separators=(',', ':')))
            if encrypted_data:
                with open("history.cache", "w", encoding="utf-8") as f:
                    f.write(encrypted_data)
        
        if settings.logging:
            data_copy = deepcopy(data)
            for key in data_copy.keys():
                data_copy[key].pop('vt_check_again', None)
                
            with open("scanned_files.json", "w", encoding="utf-8") as f:
                json.dump(data_copy, f, sort_keys=True, indent=4)
                
        return True
    except Exception as e:
        logger.error(f"Error saving the history: {e}")
        return False
