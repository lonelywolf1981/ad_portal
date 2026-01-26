from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # App
    app_name: str = "AD Portal"
    secret_key: str = Field(..., alias="APP_SECRET_KEY")
    session_cookie: str = "ad_portal_session"
    session_max_age_seconds: int = 8 * 60 * 60  # 8 часов
    cookie_secure: bool = Field(False, alias="APP_COOKIE_SECURE")

    # AD
    ad_host: str = Field(..., alias="AD_HOST")
    ad_port: int = Field(636, alias="AD_PORT")
    ad_use_ssl: bool = Field(True, alias="AD_USE_SSL")
    ad_starttls: bool = Field(False, alias="AD_STARTTLS")
    ad_base_dn: str = Field(..., alias="AD_BASE_DN")
    ad_bind_dn: str = Field(..., alias="AD_BIND_DN")
    ad_bind_password: str = Field(..., alias="AD_BIND_PASSWORD")

    # AD TLS validation (опционально)
    ad_tls_validate: bool = Field(False, alias="AD_TLS_VALIDATE")
    ad_ca_cert_file: str = Field("", alias="AD_CA_CERT_FILE")

    # Авторизация
    ad_allowed_group_dns: str = Field("", alias="AD_ALLOWED_GROUP_DNS")  # ';' separated

    # DB
    sqlite_path: str = Field("data/app.db", alias="SQLITE_PATH")

    class Config:
        populate_by_name = True


def get_settings() -> Settings:
    return Settings()
