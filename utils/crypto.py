import os
import platform
import subprocess
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def get_guid() -> str:
    if platform.system() == "Windows":
        import wmi
        c = wmi.WMI()
        for system in c.Win32_ComputerSystemProduct():
            return system.UUID
    elif platform.system() == "Linux":
        if os.path.isfile('/sys/class/dmi/id/product_uuid'):
            with open('/sys/class/dmi/id/product_uuid') as f:
                return f.read().strip()
    elif platform.system() == "Darwin":
        try:
            uuid_out = subprocess.check_output(['system_profiler', 'SPHardwareDataType']).decode()
            for line in uuid_out.splitlines():
                if "UUID" in line:
                    return line.split(": ")[1].strip()
        except Exception:
            pass
    return os.environ.get('USERNAME', '') + os.environ.get('COMPUTERNAME', '')

def get_default_key() -> str:
    return str(get_guid()) + os.environ.get('USERNAME', '')

def encrypt(source: str, key: str = "") -> str | None:
    if not key:
        key = get_default_key()
    try:
        key_bytes = key.encode("utf-8")
        source_bytes = source.encode("utf-8")

        key_bytes = SHA256.new(key_bytes).digest()
        iv = Random.new().read(AES.block_size)
        encryptor = AES.new(key_bytes, AES.MODE_CBC, iv)
        padding = AES.block_size - len(source_bytes) % AES.block_size
        source_bytes += bytes([padding]) * padding
        data = iv + encryptor.encrypt(source_bytes)
        return base64.b64encode(data).decode("utf-8")
    except Exception:
        return None

def decrypt(source: str, key: str = "") -> str | None:
    if not key:
        key = get_default_key()
    try:
        key_bytes = key.encode("utf-8")
        source_bytes = base64.b64decode(source.encode("utf-8"))

        key_bytes = SHA256.new(key_bytes).digest()
        iv = source_bytes[:AES.block_size]
        decryptor = AES.new(key_bytes, AES.MODE_CBC, iv)
        data = decryptor.decrypt(source_bytes[AES.block_size:])
        padding = data[-1]
        if data[-padding:] != bytes([padding]) * padding:
            return None
        return data[:-padding].decode("utf-8")
    except Exception:
        return None
