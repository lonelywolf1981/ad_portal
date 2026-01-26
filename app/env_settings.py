from pydantic_settings import BaseSettings
from pydantic import Field


class EnvSettings(BaseSettings):
    secret_key: str = Field(..., alias="APP_SECRET_KEY")
    cookie_secure: bool = Field(False, alias="APP_COOKIE_SECURE")
    sqlite_path: str = Field("data/app.db", alias="SQLITE_PATH")

    bootstrap_admin_user: str = Field("admin", alias="BOOTSTRAP_ADMIN_USER")
    bootstrap_admin_password: str = Field("ChangeMe123!", alias="BOOTSTRAP_ADMIN_PASSWORD")

    redis_url: str = Field("redis://redis:6379/0", alias="REDIS_URL")

    class Config:
        populate_by_name = True


def get_env() -> EnvSettings:
    return EnvSettings()
