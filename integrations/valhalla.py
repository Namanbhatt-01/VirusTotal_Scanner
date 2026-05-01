import requests
from utils.logger import logger

def get_valhalla(file_hash: str) -> str | bool:
    if not file_hash:
        return False
    
    try:
        valhalla_url = f"https://valhalla.nextron-systems.com/info/search?keyword={file_hash}"
        logger.info("Checking Valhalla Search")
        response = requests.get(valhalla_url)
        if response.status_code == 200:
            if "results:" in response.text.lower() and "no results" not in response.text.lower():
                return valhalla_url
    except Exception as e:
        logger.debug(f"Error querying Valhalla: {e}")
    return False
