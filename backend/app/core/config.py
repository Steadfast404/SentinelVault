from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator
from typing import List, Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SV_", case_sensitive=False, env_file=".env")
    
    env: str = Field(default="development")
    database_url: str = Field(...)
    database_migrator_url: str = Field(...)
    redis_url: str = Field(...)
    public_base_url: str = Field(...)
    cookie_insecure_dev: bool = Field(default=False)
    
    session_secret: str = Field(...)
    csrf_secret: str = Field(...)
    prelogin_secret: str = Field(...)
    pepper: str = Field(...)
    totp_enc_keys: List[str] = Field(...)
    
    smtp_host: str = Field(default="localhost")
    smtp_port: int = Field(default=1025)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    smtp_tls: bool = Field(default=False)
    
    s3_endpoint: str = Field(default="")
    s3_access_key: str = Field(default="")
    s3_secret_key: str = Field(default="")
    s3_bucket: str = Field(default="")
    
    webauthn_rp_id: str = Field(default="localhost")
    webauthn_rp_name: str = Field(default="SentinelVault")
    
    cors_allowed_origins: List[str] = Field(default=["*"])

    @field_validator("cookie_insecure_dev", "session_secret", "csrf_secret", "prelogin_secret", "pepper", "totp_enc_keys")
    @classmethod
    def validate_production_secrets(cls, v, info):
        # We don't have access to env directly inside the validator without inspecting values,
        # but we can do a model_validator to check env vs secrets.
        return v
        
    @field_validator("cookie_insecure_dev")
    @classmethod
    def validate_cookie(cls, v, info):
        # We'll check this in model_validator too
        return v

settings = Settings(_env_file=".env", _env_file_encoding="utf-8") # Will fail if missing required

# Doing the check after instantiation to easily access env
if settings.env == "production":
    if settings.cookie_insecure_dev:
        raise ValueError("cookie_insecure_dev cannot be True in production")
    secrets = [settings.session_secret, settings.csrf_secret, settings.prelogin_secret, settings.pepper]
    for s in secrets:
        if len(s) < 32 or s.startswith("placeholder"):
            raise ValueError("Insecure secret found in production")
    if not settings.totp_enc_keys or any(len(k) < 32 for k in settings.totp_enc_keys):
        raise ValueError("Insecure totp_enc_keys found in production")
