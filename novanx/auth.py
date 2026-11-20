from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from contextvars import ContextVar
from typing import Any
from urllib.parse import quote

from Nexa import request
from Nexa.nxserver import Response

from .config import Settings
from .database import ProfileRepository
from .supabase import SupabaseClient, SupabaseError

SESSION_COOKIE = "novanx_session"
CSRF_COOKIE = "novanx_csrf"
_refreshed_cookie: ContextVar[str | None] = ContextVar("novanx_refreshed_cookie", default=None)
_verified_access_token: ContextVar[str | None] = ContextVar(
    "novanx_verified_access_token",
    default=None,
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _signed(value: dict[str, Any], secret: str) -> str:
    payload = _b64(json.dumps(value, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest())
    return payload + "." + signature


def _unsign(value: str, secret: str) -> dict[str, Any] | None:
    try:
        payload, signature = value.split(".", 1)
        expected = _b64(
            hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(signature, expected):
            return None
        decoded = json.loads(_unb64(payload).decode("utf-8"))
        return decoded if isinstance(decoded, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _cookie(name: str, value: str, settings: Settings, *, max_age: int, http_only: bool) -> str:
    parts = [
        f"{name}={quote(value, safe='._-')}",
        "Path=/",
        "SameSite=Lax",
        f"Max-Age={max_age}",
    ]
    if http_only:
        parts.append("HttpOnly")
    if settings.cookie_secure:
        parts.append("Secure")
    return "; ".join(parts)


def session_cookie(tokens: dict[str, Any], settings: Settings) -> str:
    settings.require_auth()
    existing_session = browser_session(settings)
    auth_user = tokens.get("user")
    auth_user = auth_user if isinstance(auth_user, dict) else {}
    session = {
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "user": {
            "id": auth_user.get("id", ""),
            "email": auth_user.get("email", ""),
        },
        "csrf_token": request.cookies.get(CSRF_COOKIE)
        or (existing_session or {}).get("csrf_token")
        or secrets.token_urlsafe(32),
    }
    if not session["access_token"] or not session["refresh_token"]:
        raise SupabaseError("Supabase did not return a complete login session.", 502)
    return _cookie(
        SESSION_COOKIE,
        _signed(session, settings.session_secret),
        settings,
        max_age=60 * 60 * 24 * 14,
        http_only=True,
    )


def clear_session_cookie(settings: Settings) -> str:
    return _cookie(SESSION_COOKIE, "", settings, max_age=0, http_only=True)


def csrf_token() -> tuple[str, str | None]:
    token = request.cookies.get(CSRF_COOKIE, "")
    if 32 <= len(token) <= 128 and all(char.isalnum() or char in "-_" for char in token):
        return token, None
    session = browser_session(Settings.from_env())
    session_token = str((session or {}).get("csrf_token", ""))
    if 32 <= len(session_token) <= 128 and all(
        char.isalnum() or char in "-_" for char in session_token
    ):
        return session_token, None
    token = secrets.token_urlsafe(32)
    settings = Settings.from_env()
    return token, _cookie(CSRF_COOKIE, token, settings, max_age=60 * 60 * 24 * 30, http_only=False)


def csrf_valid(form: dict[str, Any]) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie:
        cookie = str((browser_session(Settings.from_env()) or {}).get("csrf_token", ""))
    submitted = form.get("csrf_token", "")
    return (
        isinstance(submitted, str)
        and bool(cookie)
        and hmac.compare_digest(cookie, submitted)
    )


def browser_session(settings: Settings) -> dict[str, Any] | None:
    if not settings.session_secret:
        return None
    cookie_value = request.cookies.get(SESSION_COOKIE, "")
    session = _unsign(cookie_value, settings.session_secret) if cookie_value else None
    return session if session and session.get("access_token") else None


def session_user(settings: Settings) -> dict[str, Any] | None:
    session = browser_session(settings)
    user = (session or {}).get("user")
    if not isinstance(user, dict) or not user.get("id"):
        return None
    return user


def access_token(settings: Settings) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if authorization.startswith("Bearer "):
        return authorization[7:].strip() or None
    session = browser_session(settings)
    return str(session["access_token"]) if session else None


def current_user(settings: Settings) -> dict[str, Any] | None:
    _verified_access_token.set(None)
    token = access_token(settings)
    if not token:
        return None
    client = SupabaseClient(settings)
    try:
        user, _ = client.request(
            "auth/v1/user",
            headers={"Authorization": f"Bearer {token}"},
        )
    except SupabaseError as exc:
        if exc.status == 401:
            if request.headers.get("Authorization", "").startswith("Bearer "):
                return None
            session = browser_session(settings)
            refresh_token = (session or {}).get("refresh_token")
            if not refresh_token:
                return None
            try:
                refreshed = SupabaseAuth(settings).refresh(str(refresh_token))
            except SupabaseError as refresh_error:
                if refresh_error.status in {400, 401, 403}:
                    return None
                raise
            refreshed_user = refreshed.get("user")
            refreshed_access = refreshed.get("access_token")
            if (
                not isinstance(refreshed_user, dict)
                or not refreshed_user.get("id")
                or not isinstance(refreshed_access, str)
                or not refreshed_access
                or not refreshed.get("refresh_token")
            ):
                raise SupabaseError(
                    "Supabase returned an incomplete refreshed session.",
                    502,
                    category="invalid_response",
                )
            _refreshed_cookie.set(session_cookie(refreshed, settings))
            _verified_access_token.set(refreshed_access)
            return refreshed_user
        raise
    if isinstance(user, dict) and user.get("id"):
        _verified_access_token.set(token)
        return user
    return None


def verified_access_token() -> str | None:
    return _verified_access_token.get()


def clear_verified_access_token() -> None:
    _verified_access_token.set(None)


def discard_refreshed_cookie() -> None:
    _refreshed_cookie.set(None)


def attach_cookie(response: Response, cookie: str | None) -> Response:
    if cookie:
        response.headers["Set-Cookie"] = cookie
    return response


def take_refreshed_cookie() -> str | None:
    cookie = _refreshed_cookie.get()
    _refreshed_cookie.set(None)
    return cookie


class SupabaseAuth:
    def __init__(self, settings: Settings) -> None:
        settings.require_auth()
        self.client = SupabaseClient(settings)

    def sign_in(self, email: str, password: str) -> dict[str, Any]:
        data, _ = self.client.request(
            "auth/v1/token?grant_type=password",
            method="POST",
            payload={"email": email, "password": password},
            use_key_as_bearer=False,
        )
        return data if isinstance(data, dict) else {}

    def sign_up(self, email: str, password: str, username: str) -> dict[str, Any]:
        data, _ = self.client.request(
            "auth/v1/signup",
            method="POST",
            payload={"email": email, "password": password, "data": {"username": username}},
            use_key_as_bearer=False,
        )
        if not isinstance(data, dict):
            raise SupabaseError(
                "Supabase returned an invalid signup response.",
                502,
                category="invalid_response",
            )

        user = data.get("user")
        if not isinstance(user, dict) and data.get("id"):
            user = data
        if not isinstance(user, dict) or not user.get("id"):
            raise SupabaseError(
                "Supabase returned an incomplete signup response.",
                502,
                category="invalid_response",
            )

        access = data.get("access_token")
        refresh = data.get("refresh_token")
        if bool(access) != bool(refresh):
            raise SupabaseError(
                "Supabase returned an incomplete signup session.",
                502,
                category="invalid_response",
            )
        return {
            "user": user,
            "access_token": access,
            "refresh_token": refresh,
        }

    def username_exists(self, username: str) -> bool:
        return ProfileRepository(self.client.settings).username_exists(username)

    def profile_for_user(self, user_id: str) -> dict[str, Any] | None:
        return ProfileRepository(self.client.settings).profile_for_user(user_id)

    def sign_out(self, token: str) -> None:
        self.client.request(
            "auth/v1/logout",
            method="POST",
            payload={},
            headers={"Authorization": f"Bearer {token}"},
        )

    def refresh(self, refresh_token: str) -> dict[str, Any]:
        data, _ = self.client.request(
            "auth/v1/token?grant_type=refresh_token",
            method="POST",
            payload={"refresh_token": refresh_token},
            use_key_as_bearer=False,
        )
        return data if isinstance(data, dict) else {}
