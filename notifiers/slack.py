import requests
import json
from config.settings import settings
from utils.logger import logger

def send_slack_webhook(message: str) -> bool:
    if settings.no_send or not settings.slack_webhook_url:
        return True

    headers = {'Content-Type': 'application/json'}
    payload = {
        "text": "🚨 *VirusTotal Scanner Alert* 🚨\n" + f"```\n{message}\n```"
    }
    
    try:
        response = requests.post(settings.slack_webhook_url, headers=headers, data=json.dumps(payload))
        if response.status_code != 200:
            logger.error(f"Failed to send message to Slack. Status Code: {response.status_code}, Response: {response.text}")
            return False
        else:
            logger.info("Alert sent to Slack successfully.")
            return True
    except Exception as e:
        logger.error(f"Exception occurred while sending alert to Slack: {e}")
    return False

def send_slack_alert(message: str) -> bool:
    if settings.no_send: 
        return True
    
    message = message.replace("\nVirusTotal", "\nVT")
    message = message.replace("\\", "/")
    message = message.replace("  ", " ")
    
    # Slack message limit is generous (often ~40000 chars for text block, but 3000 for some blocks).
    # We will chunk it around 3500 to be safe with the code block markdown.
    chunk_size = 3500
    counter = 0
    
    while len(message) > chunk_size:
        counter += 1
        if settings.max_msg and counter > settings.max_msg:
            return True
            
        index = message[:chunk_size].rfind("\n")
        if index == -1:
            index = chunk_size
            
        chunk = message[:index]
        if not send_slack_webhook(chunk):
            return False
            
        message = message[index:]
        
    if message:
        counter += 1
        if settings.max_msg and counter > settings.max_msg:
            return True
        return send_slack_webhook(message)
        
    return True
