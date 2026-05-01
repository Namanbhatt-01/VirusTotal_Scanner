import hashlib
import os
from utils.logger import logger

def get_sha256(file_path: str) -> str:
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error hashing the file '{file_path}': {e}")
        return ""

def resolve_shortcut(file_path: str) -> str:
    import winshell
    try:
        resolved_path = winshell.shortcut(file_path).path # type: ignore
        if resolved_path:
            return resolved_path
    except Exception as e:
        logger.error(f"Error resolving shortcut '{os.path.basename(file_path)}': {e}")
    return file_path
