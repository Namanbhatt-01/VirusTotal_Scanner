from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # API Keys
    vt_api_key: str = Field(default="")
    slack_webhook_url: str = Field(default="")
    malshare_api_key: Optional[str] = Field(default="")

    # Core execution settings
    paths: List[str] = Field(default_factory=list)
    upload: bool = Field(default=True)
    scan_interval: float = Field(default=0.0) # in minutes
    cycles: int = Field(default=0) # 0 for forever
    
    # Process & Cache Settings
    skip_process: bool = Field(default=False)
    history_log: bool = Field(default=True)
    logging: bool = Field(default=True)
    debug: bool = Field(default=False)
    
    # Notifier Settings
    no_send: bool = Field(default=False)
    max_msg: int = Field(default=1) # 0 for unlimited
    
    # Defaults
    suspicious_extensions: List[str] = Field(
        default=[
            ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
            ".scr", ".pif", ".msi", ".com", ".reg", ".docm", ".xlsm", ".pptm",
            ".jar", ".php", ".py", ".sh", ".ps1"
        ]
    )

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

# Global settings instance
settings = Settings()
