import requests
from config.settings import settings
from utils.logger import logger

def get_malshare(file_hash: str) -> str | bool:
    if not settings.malshare_api_key:
        return False
        
    fake_headers = {
        'referer': 'https://www.google.com',
        'pragma': 'no-cache',
        'cache-control': 'no-cache',
        'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
        'accept': 'application/json, text/plain, */*',
        'dnt': '1',
        'sec-ch-ua-mobile': '?0',
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'accept-language': 'en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,es;q=0.6'
    }
    
    try:
        logger.info("Checking MalShare Reports")
        mal_api = f'https://malshare.com/api.php?api_key={settings.malshare_api_key}&action=details&hash={file_hash}'
        response = requests.get(mal_api, timeout=15, headers=fake_headers)
        if response.status_code == 200:
            return f"https://malshare.com/sample.php?action=detail&hash={file_hash}"
    except Exception as e:
        logger.debug(f"Error querying MalShare: {e}")
    return False
