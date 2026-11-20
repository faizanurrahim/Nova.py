from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str
    database_url: str
    session_secret: str
    storage_bucket: str
    public_base_url: str
    host: str
    port: int
    cookie_secure: bool
    max_archive_size: int

    @classmethod
    def from_env(cls) -> "Settings":
        _load_project_env()
        try:
            port = int(os.getenv("PORT", "3000"))
            max_archive_size = int(os.getenv("MAX_ARCHIVE_SIZE", str(24 * 1024 * 1024)))
        except ValueError as exc:
            raise ConfigurationError("PORT and MAX_ARCHIVE_SIZE must be integers.") from exc

        if not 0 <= port <= 65535:
            raise ConfigurationError("PORT must be between 0 and 65535.")
        if not 1 <= max_archive_size <= 24 * 1024 * 1024:
            raise ConfigurationError("MAX_ARCHIVE_SIZE must be between 1 byte and 24 MiB.")

        secure = os.getenv("COOKIE_SECURE", "false").strip().lower()
        if secure not in {"true", "false"}:
            raise ConfigurationError("COOKIE_SECURE must be true or false.")

        supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
        public_base_url = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
        if supabase_url:
            try:
                parsed_supabase = urlsplit(supabase_url)
            except ValueError as exc:
                raise ConfigurationError("SUPABASE_URL must be an absolute HTTP(S) URL.") from exc
            if (
                parsed_supabase.scheme not in {"https", "http"}
                or not parsed_supabase.hostname
                or parsed_supabase.username
                or parsed_supabase.password
                or parsed_supabase.query
                or parsed_supabase.fragment
            ):
                raise ConfigurationError("SUPABASE_URL must be an absolute HTTP(S) URL.")
        if public_base_url:
            try:
                parsed_public = urlsplit(public_base_url)
            except ValueError as exc:
                raise ConfigurationError("PUBLIC_BASE_URL must be an absolute HTTP(S) URL.") from exc
            if (
                parsed_public.scheme not in {"https", "http"}
                or not parsed_public.hostname
                or parsed_public.username
                or parsed_public.password
                or parsed_public.query
                or parsed_public.fragment
            ):
                raise ConfigurationError("PUBLIC_BASE_URL must be an absolute HTTP(S) URL.")
        storage_bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "novanx-packages")
        if not storage_bucket or len(storage_bucket) > 63 or not storage_bucket[0].isalnum():
            raise ConfigurationError("SUPABASE_STORAGE_BUCKET is invalid.")
        if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in storage_bucket):
            raise ConfigurationError("SUPABASE_STORAGE_BUCKET is invalid.")
        if os.getenv("APP_ENV", "").lower() == "production" and secure != "true":
            raise ConfigurationError("Set COOKIE_SECURE=true for production deployments.")

        return cls(
            supabase_url=supabase_url,
            supabase_anon_key=(
                os.getenv("SUPABASE_PUBLISHABLE_KEY")
                or os.getenv("SUPABASE_ANON_KEY", "")
            ),
            supabase_service_role_key=(
                os.getenv("SUPABASE_SECRET_KEY")
                or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
            ),
            database_url=os.getenv("DATABASE_URL", "").strip(),
            session_secret=os.getenv("SESSION_SECRET", ""),
            storage_bucket=storage_bucket,
            public_base_url=public_base_url,
            host=os.getenv("HOST", "127.0.0.1"),
            port=port,
            cookie_secure=secure == "true",
            max_archive_size=max_archive_size,
        )

    def require_supabase(self, *, privileged: bool = False) -> None:
        missing = []
        if not self.supabase_url or "your-project" in self.supabase_url.casefold():
            missing.append("SUPABASE_URL")
        if not self.supabase_anon_key or self.supabase_anon_key.casefold().startswith("replace-with"):
            missing.append("SUPABASE_PUBLISHABLE_KEY (or legacy SUPABASE_ANON_KEY)")
        if privileged and (
            not self.supabase_service_role_key
            or self.supabase_service_role_key.casefold().startswith("replace-with")
        ):
            missing.append("SUPABASE_SECRET_KEY (or legacy SUPABASE_SERVICE_ROLE_KEY)")
        if missing:
            raise ConfigurationError(
                "Missing required environment variables: " + ", ".join(missing)
            )

    def require_auth(self) -> None:
        self.require_supabase()
        if (
            not self.session_secret
            or len(self.session_secret) < 32
            or self.session_secret.casefold().startswith("replace-with")
        ):
            raise ConfigurationError(
                "SESSION_SECRET must contain at least 32 characters to enable sign-in."
            )

    def require_database(self) -> None:
        if not self.database_url:
            raise ConfigurationError(
                "DATABASE_URL must contain the server-only PostgreSQL connection URI."
            )
        try:
            parsed = urlsplit(self.database_url)
        except ValueError as exc:
            raise ConfigurationError(
                "DATABASE_URL must be a PostgreSQL connection URI."
            ) from exc
        if (
            parsed.scheme not in {"postgres", "postgresql"}
            or not parsed.hostname
            or parsed.path in {"", "/"}
        ):
            raise ConfigurationError(
                "DATABASE_URL must be a PostgreSQL connection URI."
            )


def _load_project_env() -> None:
    env_file = Path.cwd() / ".env"
    if not env_file.is_file():
        return
    for line_number, raw_line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(f"Invalid .env entry on line {line_number}.")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "").isalnum():
            raise ConfigurationError(f"Invalid .env key on line {line_number}.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key not in os.environ:
            os.environ[key] = value
