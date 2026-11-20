from __future__ import annotations

import json
import logging
import re
import socket
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import Settings


class SupabaseError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: int = 502,
        *,
        category: str = "supabase_error",
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.category = category
        self.code = code


class SupabaseClient:
    def __init__(
        self,
        settings: Settings,
        *,
        privileged: bool = False,
        user_access_token: str | None = None,
    ) -> None:
        if privileged and user_access_token:
            raise ValueError("A request cannot use both a user token and privileged credentials.")
        settings.require_supabase(privileged=privileged)
        self.settings = settings
        self.key = (
            settings.supabase_service_role_key
            if privileged
            else settings.supabase_anon_key
        )
        self.user_access_token = user_access_token
        self._legacy_jwt_key = self.key.startswith("eyJ")

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        payload: Any = None,
        raw_body: bytes | None = None,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
        use_key_as_bearer: bool = True,
    ) -> tuple[Any, dict[str, str]]:
        body = raw_body
        request_headers = {
            "apikey": self.key,
            "Accept": "application/json",
        }
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = content_type
        elif raw_body is not None:
            request_headers["Content-Type"] = content_type
        if headers:
            request_headers.update(headers)
        if self.user_access_token:
            request_headers["Authorization"] = f"Bearer {self.user_access_token}"
        elif use_key_as_bearer and self._legacy_jwt_key:
            request_headers.setdefault("Authorization", f"Bearer {self.key}")

        request = Request(
            f"{self.settings.supabase_url}/{path.lstrip('/')}",
            data=body,
            headers=request_headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=25) as response:
                data = response.read()
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except HTTPError as exc:
            upstream_code = ""
            upstream_message = ""
            try:
                try:
                    error = json.loads(exc.read().decode("utf-8"))
                    if isinstance(error, dict):
                        upstream_code = str(
                            error.get("error_code")
                            or error.get("code")
                            or error.get("error")
                            or ""
                        )
                        upstream_message = str(
                            error.get("message")
                            or error.get("msg")
                            or error.get("error_description")
                            or ""
                        )
                except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                    pass
            finally:
                exc.close()
            category = _classify_http_error(exc.code, upstream_code, upstream_message, path)
            safe_message = _safe_log_message(upstream_message)
            logging.warning(
                "Supabase request failed method=%s endpoint=%s status=%s category=%s code=%s message=%s",
                method,
                path.split("?", 1)[0],
                exc.code,
                category,
                _safe_log_code(upstream_code),
                safe_message or "(no message returned)",
            )
            status = 409 if category in {"email_taken", "username_taken"} else (
                400 if category in {"invalid_email", "weak_password"} else exc.code
            )
            raise SupabaseError(
                "Supabase rejected the request.",
                status,
                category=category,
                code=_safe_log_code(upstream_code) or None,
            ) from exc
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            category = (
                "invalid_url"
                if isinstance(reason, (socket.gaierror, ValueError))
                else "network_error"
            )
            logging.warning(
                "Supabase request failed method=%s endpoint=%s category=%s cause=%s",
                method,
                path.split("?", 1)[0],
                category,
                type(reason).__name__,
            )
            raise SupabaseError(
                "Supabase could not be reached.",
                503,
                category=category,
            ) from exc

        if not data:
            return None, response_headers
        try:
            return json.loads(data.decode("utf-8")), response_headers
        except (UnicodeDecodeError, json.JSONDecodeError):
            return data, response_headers

    def rest(
        self,
        table_path: str,
        *,
        method: str = "GET",
        payload: Any = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        extra_headers = {"Accept": "application/json"}
        if method in {"POST", "PATCH", "DELETE"}:
            extra_headers["Prefer"] = "return=representation"
        if headers:
            extra_headers.update(headers)
        return self.request(
            f"rest/v1/{table_path}",
            method=method,
            payload=payload,
            headers=extra_headers,
        )


def _classify_http_error(status: int, code: str, message: str, path: str) -> str:
    searchable = f"{code} {message}".casefold().replace("-", "_")
    endpoint = path.split("?", 1)[0].casefold()
    if code == "42501" or "permission denied for table" in searchable:
        return "permission_denied"
    if "profiles_username_key" in searchable or "username already" in searchable:
        return "username_taken"
    if "user_already_exists" in searchable or "email already" in searchable or "user already registered" in searchable:
        return "email_taken"
    if "email_address_invalid" in searchable or "invalid email" in searchable or "email address is invalid" in searchable:
        return "invalid_email"
    if "weak_password" in searchable or "password should" in searchable or "password is too short" in searchable:
        return "weak_password"
    if "invalid api key" in searchable or "invalid_api_key" in searchable or "api key is invalid" in searchable:
        return "invalid_api_key"
    if "database error saving new user" in searchable:
        return "profile_creation"
    if endpoint.startswith("rest/v1/profiles") and status in {404, 406}:
        return "profile_schema"
    if endpoint.startswith("auth/v1/") and status == 404:
        return "invalid_url"
    if status in {401, 403}:
        return "invalid_api_key"
    if status == 429:
        return "rate_limited"
    if 500 <= status <= 599:
        return "supabase_server_error"
    return "supabase_rejected"


_EMAIL_IN_MESSAGE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_KEY_IN_MESSAGE = re.compile(r"\b(?:sb_(?:publishable|secret)_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_.-]+)\b")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|token|secret|api[_ -]?key)\b(\s*[:=]\s*)\S+"
)


def _safe_log_message(message: str) -> str:
    safe = _EMAIL_IN_MESSAGE.sub("[email redacted]", message)
    safe = _KEY_IN_MESSAGE.sub("[key redacted]", safe)
    safe = _SENSITIVE_ASSIGNMENT.sub(r"\1\2[redacted]", safe)
    return safe[:400]


def _safe_log_code(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", code)[:80]


def first_row(data: Any) -> dict[str, Any] | None:
    if isinstance(data, list):
        return data[0] if data and isinstance(data[0], dict) else None
    return data if isinstance(data, dict) else None
