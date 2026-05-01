import logging
import sys
import datetime
from config.settings import settings

def setup_logger():
    logger = logging.getLogger("VirusTotalScanner")
    
    if not logger.handlers:
        logger.setLevel(logging.DEBUG if settings.debug else logging.INFO)
        
        # Console handler
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG if settings.debug else logging.INFO)
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    return logger

logger = setup_logger()

def log_to_file(message: str) -> bool:
    if settings.logging:
        try:
            with open("logs.txt", "a", encoding="utf-8") as f:
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
                f.write(f"\n[+] Log Time: {timestamp}\n\n{message}\n\n{'='*100}\n")
            return True
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            return False
    return True
