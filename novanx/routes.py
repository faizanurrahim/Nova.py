from __future__ import annotations

import html
import json
import logging
import mimetypes
import re
from typing import Any
from urllib.parse import urlencode, urlsplit

from Nexa import Blueprint, render_template, request
from Nexa.nxserver import Response, redirect

from .archive import ArchiveValidationError, PACKAGE_NAME, PACKAGE_VERSION
from .auth import (
    SupabaseAuth,
    attach_cookie,
    clear_session_cookie,
    csrf_token,
    csrf_valid,
    current_user,
    clear_verified_access_token,
    session_cookie,
    session_user,
    discard_refreshed_cookie,
    take_refreshed_cookie,
    verified_access_token,
)
from .config import ConfigurationError, Settings
from .database import ProfileDatabaseError
from .registry import Registry, json_package, public_version
from .supabase import SupabaseError, first_row

settings = Settings.from_env()
pages = Blueprint("pages")
api = Blueprint("api", prefix="/api")
nova_metadata = Blueprint("nova_metadata")


def _escape(value: Any) -> Any:
    if isinstance(value, str):
        return html.escape(value, quote=True)
    if isinstance(value, list):
        return [_escape(item) for item in value]
    if isinstance(value, dict):
        return {html.escape(str(key), quote=True): _escape(item) for key, item in value.items()}
    return value


def _web_url(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if parsed.scheme in {"http", "https"} and parsed.hostname and not parsed.username:
        return value
    return ""


def _page(template: str, **context: Any) -> Response:
    token, new_cookie = csrf_token()
    context["csrf_token"] = html.escape(token, quote=True)
    context.setdefault("user", session_user(settings))
    if "package" in context and isinstance(context["package"], dict):
        package = context["package"]
        package["repository_link"] = _web_url(package.get("repository_url"))
        package["homepage_link"] = _web_url(package.get("homepage_url"))
        context["package"] = _escape(package)
    for key in (
        "packages",
        "versions",
        "popular",
        "recent",
        "user",
        "message",
        "error",
        "query",
        "sort",
        "notice",
        "title",
    ):
        if key in context:
            context[key] = _escape(context[key])

    response = render_template(template, **context)
    if new_cookie:
        response.headers["Set-Cookie"] = new_cookie
    response.headers.update(
        {
            "Content-Type": "text/html; charset=utf-8",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                "default-src 'self'; style-src 'self'; img-src 'self' data:; "
                "form-action 'self'; base-uri 'self'; frame-ancestors 'none'; "
                "object-src 'none'; script-src 'none'"
            ),
        }
    )
    return response


def _api_error(message: str, status: int) -> Response:
    return Response(
        json.dumps({"error": message}, ensure_ascii=False),
        status=status,
        content_type="application/json; charset=utf-8",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )


def _json_response(data: Any, status: int = 200) -> Response:
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        content_type="application/json; charset=utf-8",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )


def _browser_form() -> bool:
    return (
        not request.headers.get("Authorization", "").startswith("Bearer ")
        and "text/html" in request.headers.get("Accept", "")
    )


def _publish_error(message: str, status: int) -> Response:
    if not _browser_form():
        return _api_error(message, status)
    response = _page("unavailable.nxs", message=message)
    response.status = status
    return response


def _publish_success(payload: dict[str, Any]) -> Response:
    if _browser_form():
        return redirect("/dashboard?notice=published")
    return _json_response({"package": payload, "status": "published"}, status=201)


def _settings_error(exc: Exception) -> Response:
    message = str(exc)
    return _api_error(message, 503)


def _user() -> dict[str, Any] | None:
    return current_user(settings)


def _auth_error() -> Response:
    return _api_error("Sign in is required.", 401)


def _form_csrf_ok() -> bool:
    form = request.form
    return csrf_valid(form)


def _protected_user(*, form: bool = False) -> tuple[dict[str, Any] | None, Response | None]:
    user = _user()
    if not user:
        return None, _auth_error()
    if form and not request.headers.get("Authorization", "").startswith("Bearer ") and not _form_csrf_ok():
        return None, _api_error("The form expired. Reload the page and try again.", 403)
    return user, None


def _archive_upload() -> tuple[str, bytes]:
    files = request.files or {}
    item = files.get("archive")
    if isinstance(item, dict):
        filename = item.get("filename")
        data = item.get("data")
        if isinstance(filename, str) and isinstance(data, bytes):
            return filename, data
    if request.content_type and request.content_type.lower().startswith("application/octet-stream"):
        filename = request.headers.get("X-Filename", "package.tar.nx")
        return filename, request.body
    raise ValueError("Choose a .tar.nx archive to upload.")


def _public_base() -> str:
    return settings.public_base_url


def _file_response(data: bytes, name: str, version: str) -> Response:
    filename = f"{name}-{version}.tar.nx"
    return Response(
        data,
        content_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
            "Content-Type": "application/octet-stream",
        },
    )


def _package_version(package: dict[str, Any], version: str | None) -> dict[str, Any] | None:
    versions = package.get("versions", [])
    if version:
        return next((row for row in versions if row.get("version") == version), None)
    return package.get("latest")


def _delete_package(registry: Registry, package: dict[str, Any]) -> None:
    archive_paths = [
        str(version["archive_path"])
        for version in package.get("versions", [])
        if version.get("archive_path")
    ]
    registry.db.rest(f"packages?id=eq.{package['id']}", method="DELETE")
    for archive_path in archive_paths:
        try:
            registry.delete_archive(archive_path)
        except SupabaseError:
            logging.exception("Could not remove a private package archive after package deletion.")


@pages.get("/")
def home() -> Response:
    notice = ""
    popular: list[dict[str, Any]] = []
    recent: list[dict[str, Any]] = []
    stats = {"packages": 0, "downloads": 0, "authors": 0}
    try:
        registry = Registry(settings)
        popular = registry.catalog(sort="popular", limit=4)
        recent = registry.catalog(sort="newest", limit=4)
        stats = registry.stats()
    except (ConfigurationError, SupabaseError) as exc:
        notice = str(exc)
    return _page("index.nxs", popular=popular, recent=recent, stats=stats, notice=notice)


@pages.get("/search")
def search() -> Response:
    query = str(request.args.get("q", "")).strip()[:100]
    sort = str(request.args.get("sort", "relevance"))
    if sort not in {"relevance", "popular", "newest"}:
        sort = "relevance"
    results: list[dict[str, Any]] = []
    notice = ""
    try:
        results = Registry(settings).catalog(query=query, sort=sort, limit=100)
    except (ConfigurationError, SupabaseError) as exc:
        notice = str(exc)
    return _page(
        "search.nxs",
        query=query,
        sort=sort,
        packages=results,
        result_count=len(results),
        notice=notice,
    )


@pages.get("/package/<name>")
def package_page(name: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name):
        response = _page("not_found.nxs", title="Package not found", message="That package name is invalid.")
        response.status = 404
        return response
    try:
        package = Registry(settings).package(name)
    except (ConfigurationError, SupabaseError) as exc:
        response = _page("unavailable.nxs", message=str(exc))
        response.status = 503
        return response
    if not package:
        response = _page("not_found.nxs", title="Package not found", message=f"No package named {name} is published.")
        response.status = 404
        return response
    for version in package.get("versions", []):
        version["download_url"] = (
            f"/api/packages/{name}/download?"
            f"{urlencode({'version': version['version']})}"
        )
    return _page("package.nxs", package=package)


@pages.get("/docs")
def docs() -> Response:
    return _page("docs.nxs")


@pages.route("/login", methods=["GET", "POST"])
def login() -> Response:
    if request.method == "GET":
        return _page("auth.nxs", mode="login", error="", message="")
    return _login_post()


@pages.route("/register", methods=["GET", "POST"])
def register() -> Response:
    if request.method == "GET":
        return _page("auth.nxs", mode="register", error="", message="")
    return _register_post()


def _login_post() -> Response:
    form = request.form
    if not csrf_valid(form):
        return _page("auth.nxs", mode="login", error="Your form expired. Reload and try again.", message="")
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    if len(email) > 320 or not email or not password:
        return _page("auth.nxs", mode="login", error="Enter a valid email address and password.", message="")
    try:
        result = SupabaseAuth(settings).sign_in(email, password)
        response = redirect("/dashboard")
        return attach_cookie(response, session_cookie(result, settings))
    except ConfigurationError as exc:
        return _page("auth.nxs", mode="login", error=str(exc), message="")
    except SupabaseError:
        return _page("auth.nxs", mode="login", error="Sign-in failed. Check your email and password.", message="")


def _register_post() -> Response:
    form = request.form
    if not csrf_valid(form):
        return _register_error("Your form expired. Reload and try again.", 403)
    email = str(form.get("email", "")).strip().lower()
    password = str(form.get("password", ""))
    username = str(form.get("username", "")).strip().lower()
    if len(email) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return _register_error("Enter a valid email address.", 400)
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,29}", username):
        return _register_error(
            "Use a 3–30 character username containing lowercase letters, digits, underscores, or hyphens.",
            400,
        )
    if len(password) < 10 or len(password) > 128:
        return _register_error("Choose a password between 10 and 128 characters.", 400)
    try:
        auth = SupabaseAuth(settings)
        if auth.username_exists(username):
            return _register_error("That username is already taken. Choose another one.", 409)
        result = auth.sign_up(email, password, username)
        user = result["user"]
        identities = user.get("identities")
        if isinstance(identities, list) and not identities:
            return _register_error("An account with this email already exists. Sign in instead.", 409)
        profile = auth.profile_for_user(str(user["id"]))
        if (
            not profile
            or profile.get("id") != str(user["id"])
            or profile.get("username") != username
        ):
            logging.error(
                "Supabase signup returned without a matching profile user_id=%s",
                user["id"],
            )
            return _register_error(
                "Supabase created the account but NovaNX could not verify its profile. Contact support.",
                503,
            )
        if result.get("access_token") and result.get("refresh_token"):
            response = _page(
                "auth.nxs",
                mode="created",
                error="",
                message="Your account is ready and you are signed in.",
            )
            response.status = 201
            return attach_cookie(response, session_cookie(result, settings))
        return _page(
            "auth.nxs",
            mode="login",
            error="",
            message="Check your email to confirm your new NovaNX account, then sign in.",
        )
    except ConfigurationError as exc:
        return _register_error(str(exc), 503)
    except ProfileDatabaseError:
        return _register_error(
            "NovaNX profile storage is temporarily unavailable. Try again later.",
            503,
        )
    except SupabaseError as exc:
        return _register_error(
            _signup_error_message(exc),
            _signup_error_status(exc),
        )


def _register_error(message: str, status: int) -> Response:
    response = _page("auth.nxs", mode="register", error=message, message="")
    response.status = status
    return response


def _signup_error_status(error: SupabaseError) -> int:
    if error.category in {"email_taken", "username_taken"}:
        return 409
    if error.category in {"invalid_email", "weak_password"}:
        return 400
    if error.category == "rate_limited":
        return 429
    if error.category in {"network_error", "supabase_server_error"}:
        return 503
    return 502


def _signup_error_message(error: SupabaseError) -> str:
    messages = {
        "email_taken": "An account with this email already exists. Sign in instead.",
        "username_taken": "That username is already taken. Choose another one.",
        "invalid_email": "Supabase rejected this email address. Check it and try again.",
        "weak_password": "Choose a stronger password that meets the Supabase project's password policy.",
        "invalid_api_key": (
            "NovaNX could not authenticate with Supabase. Check that the configured "
            "publishable key belongs to the configured project."
        ),
        "invalid_url": (
            "NovaNX could not find the Supabase Auth endpoint. Check the configured "
            "Supabase project URL."
        ),
        "network_error": "NovaNX could not reach Supabase. Check the server's network connection and try again.",
        "profile_creation": (
            "Supabase could not create the NovaNX profile. Check Supabase Postgres "
            "logs for the NovaNX profile trigger diagnostics."
        ),
        "profile_schema": (
            "NovaNX profile storage is missing or unavailable. Apply the Supabase "
            "schema before registering accounts."
        ),
        "supabase_server_error": "Supabase is temporarily unavailable. Try again shortly.",
        "rate_limited": "Supabase is temporarily rate-limiting signups. Wait a little and try again.",
        "invalid_response": "Supabase returned an unexpected signup response. Check the server logs.",
    }
    return messages.get(
        error.category,
        "Supabase rejected account creation. Check the server logs for the request's error code.",
    )


@pages.post("/logout")
def logout() -> Response:
    if not csrf_valid(request.form):
        response = _page("unavailable.nxs", message="Your sign-out form expired. Reload and try again.")
        response.status = 403
        return response
    try:
        user = _user()
        token = verified_access_token()
        if user and token:
            SupabaseAuth(settings).sign_out(token)
    except (ConfigurationError, SupabaseError):
        logging.exception("Supabase sign-out failed; clearing the local session cookie.")
    discard_refreshed_cookie()
    clear_verified_access_token()
    return attach_cookie(redirect("/"), clear_session_cookie(settings))


@pages.get("/dashboard")
def dashboard() -> Response:
    try:
        user = _user()
    except ConfigurationError as exc:
        return _dashboard_error_response(str(exc), 503)
    except SupabaseError as exc:
        return _dashboard_supabase_error(exc)
    if not user:
        return redirect("/login")
    user_access_token = verified_access_token()
    if not user_access_token:
        return redirect("/login")
    try:
        profile = SupabaseAuth(settings).profile_for_user(str(user["id"]))
        if not profile:
            response = _page(
                "unavailable.nxs",
                message="Your NovaNX profile is missing. Contact support before publishing packages.",
            )
            response.status = 503
            return response
        packages = Registry(
            settings,
            user_access_token=user_access_token,
        ).packages_for_user(str(user["id"]))
    except ProfileDatabaseError:
        response = _page(
            "unavailable.nxs",
            message="NovaNX profile storage is temporarily unavailable.",
        )
        response.status = 503
        return response
    except ConfigurationError as exc:
        return _dashboard_error_response(str(exc), 503)
    except SupabaseError as exc:
        return _dashboard_supabase_error(exc)
    messages = {
        "published": "Package release published successfully.",
        "updated": "Package details updated.",
        "deleted": "Package deleted.",
        "maintainers": "Maintainer list updated.",
    }
    safe_user = {
        "id": user.get("id", ""),
        "email": user.get("email", ""),
        "username": profile["username"],
    }
    notice = messages.get(str(request.args.get("notice", "")), "")
    return _page("dashboard.nxs", user=safe_user, packages=packages, notice=notice)


def _dashboard_supabase_error(error: SupabaseError) -> Response:
    logging.warning(
        "Dashboard Supabase request failed status=%s category=%s code=%s",
        error.status,
        error.category,
        error.code or "(none)",
    )
    if error.category == "permission_denied":
        return _dashboard_error_response(
            "Your account is not permitted to view some dashboard records.",
            403,
        )
    if error.category == "invalid_api_key":
        return _dashboard_error_response(
            "NovaNX could not authenticate its Supabase request. Check the server configuration.",
            502,
        )
    status = 503 if error.status == 429 or error.status >= 500 else 502
    return _dashboard_error_response(
        "NovaNX could not load your dashboard. Try again later.",
        status,
    )


def _dashboard_error_response(message: str, status: int) -> Response:
    response = _page("unavailable.nxs", message=message)
    response.status = status
    return response


@api.get("/packages/search")
def api_search() -> Response:
    query = str(request.args.get("q", "")).strip()[:100]
    sort = str(request.args.get("sort", "relevance"))
    if sort not in {"relevance", "popular", "newest"}:
        return _api_error("sort must be relevance, popular, or newest.", 400)
    try:
        results = Registry(settings).catalog(query=query, sort=sort, limit=100)
        return _json_response({"results": [json_package(row, _public_base()) for row in results], "total": len(results)})
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


@api.route("/packages/<name>", methods=["GET", "PATCH", "DELETE"])
def api_package(name: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name):
        return _api_error("Invalid package name.", 400)
    if request.method != "GET":
        return _api_package_manage(name)
    try:
        package = Registry(settings).package(name)
        if not package:
            return _api_error("Package not found.", 404)
        return _json_response(json_package(package, _public_base()))
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


@api.route("/packages/<name>/versions", methods=["GET", "POST"])
def api_versions(name: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name):
        return _api_error("Invalid package name.", 400)
    if request.method == "POST":
        return _api_publish_version(name)
    try:
        package = Registry(settings).package(name)
        if not package:
            return _api_error("Package not found.", 404)
        versions = [
            public_version(row, name, _public_base())
            for row in package.get("versions", [])
        ]
        return _json_response({"name": name, "versions": versions})
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


@api.route("/packages/<name>/download", methods=["GET", "POST"])
def api_download(name: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name):
        return _api_error("Invalid package name.", 400)
    version_name = request.args.get("version")
    if not version_name:
        form_value = request.form.get("version")
        if form_value:
            version_name = form_value
        elif isinstance(request.json, dict):
            version_name = request.json.get("version")
    try:
        registry = Registry(settings, privileged=True)
        package = registry.package(name)
        if not package:
            return _api_error("Package not found.", 404)
        version = _package_version(package, str(version_name) if version_name else None)
        if not version:
            return _api_error("Package version not found.", 404)
        return _file_response(registry.download(package, version), name, str(version["version"]))
    except (ConfigurationError, SupabaseError) as exc:
        return _api_error(str(exc), getattr(exc, "status", 503))


@api.post("/packages/publish")
def api_publish() -> Response:
    user, auth_error = _protected_user(form=True)
    if auth_error:
        return auth_error
    try:
        filename, data = _archive_upload()
        published = Registry(settings, privileged=True).publish(filename, data, str(user["id"]))
        return _publish_success(published)
    except ConfigurationError as exc:
        return _publish_error(str(exc), 503)
    except ArchiveValidationError as exc:
        return _publish_error(str(exc), 400)
    except PermissionError as exc:
        return _publish_error(str(exc), 403)
    except ValueError as exc:
        return _publish_error(str(exc), 400)
    except SupabaseError as exc:
        return _publish_error(str(exc), exc.status)


def _api_publish_version(name: str) -> Response:
    user, auth_error = _protected_user(form=True)
    if auth_error:
        return auth_error
    try:
        filename, data = _archive_upload()
        version = str(request.args.get("version", "")).strip() or None
        published = Registry(settings, privileged=True).publish(
            filename, data, str(user["id"]), expected_name=name, expected_version=version
        )
        return _publish_success(published)
    except ConfigurationError as exc:
        return _publish_error(str(exc), 503)
    except ArchiveValidationError as exc:
        return _publish_error(str(exc), 400)
    except PermissionError as exc:
        return _publish_error(str(exc), 403)
    except ValueError as exc:
        return _publish_error(str(exc), 400)
    except SupabaseError as exc:
        return _publish_error(str(exc), exc.status)


@api.post("/packages/<name>/manage")
def api_manage_package(name: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name):
        return _api_error("Invalid package name.", 400)
    user, auth_error = _protected_user(form=True)
    if auth_error:
        return auth_error
    try:
        registry = Registry(settings, privileged=True)
        package = registry.package(name)
        if not package:
            return _api_error("Package not found.", 404)
        action = str(request.form.get("action", ""))
        user_id = str(user["id"])
        if action == "delete":
            if str(package.get("owner_id")) != user_id:
                return _api_error("Only the package owner can delete a package.", 403)
            _delete_package(registry, package)
        elif action in {"update", "deprecate"}:
            if not registry.can(package, user_id, "manage"):
                return _api_error("Package management permission is required.", 403)
            if action == "deprecate":
                deprecated = request.form.get("is_deprecated") == "true"
                registry.db.rest(
                    f"packages?id=eq.{package['id']}",
                    method="PATCH",
                    payload={"is_deprecated": deprecated},
                )
            else:
                description = str(request.form.get("description", "")).strip()
                repository_url = str(request.form.get("repository_url", "")).strip()
                homepage_url = str(request.form.get("homepage_url", "")).strip()
                if len(description) > 500:
                    return _api_error("Description must be 500 characters or fewer.", 400)
                for value in (repository_url, homepage_url):
                    if value and not _web_url(value):
                        return _api_error("Repository and homepage links must be HTTP(S) URLs.", 400)
                registry.db.rest(
                    f"packages?id=eq.{package['id']}",
                    method="PATCH",
                    payload={
                        "description": description,
                        "repository_url": repository_url,
                        "homepage_url": homepage_url,
                    },
                )
                readme = str(request.form.get("readme", ""))
                if readme:
                    latest = package.get("latest")
                    if latest:
                        registry.db.rest(
                            f"package_versions?id=eq.{latest['id']}",
                            method="PATCH",
                            payload={"readme": readme[:512 * 1024]},
                        )
        elif action == "add_maintainer":
            if str(package.get("owner_id")) != user_id:
                return _api_error("Only the package owner can manage maintainers.", 403)
            username = str(request.form.get("username", "")).strip().lower()
            permission = str(request.form.get("permission", "publish"))
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,29}", username):
                return _api_error("Enter a valid NovaNX username.", 400)
            if permission not in {"read", "publish", "manage"}:
                return _api_error("Invalid maintainer permission.", 400)
            profiles, _ = registry.db.rest(
                f"profiles?{urlencode({'select': 'id', 'username': 'eq.' + username, 'limit': '1'})}"
            )
            profile = first_row(profiles)
            if not profile:
                return _api_error("No NovaNX user has that username.", 404)
            registry.db.rest(
                "package_maintainers",
                method="POST",
                payload={
                    "package_id": package["id"],
                    "user_id": profile["id"],
                    "permission": permission,
                },
            )
        elif action == "remove_maintainer":
            if str(package.get("owner_id")) != user_id:
                return _api_error("Only the package owner can manage maintainers.", 403)
            maintainer_id = str(request.form.get("user_id", ""))
            registry.db.rest(
                f"package_maintainers?{urlencode({'package_id': 'eq.' + str(package['id']), 'user_id': 'eq.' + maintainer_id})}",
                method="DELETE",
            )
        else:
            return _api_error("Unknown package management action.", 400)
        notice = "deleted" if action == "delete" else "updated" if action in {"update", "deprecate"} else "maintainers"
        return redirect(f"/dashboard?{urlencode({'notice': notice})}")
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


def _api_package_manage(name: str) -> Response:
    user, auth_error = _protected_user()
    if auth_error:
        return auth_error
    if not request.headers.get("Authorization", "").startswith("Bearer "):
        payload = request.json if isinstance(request.json, dict) else {}
        form_token = request.form.get("csrf_token")
        token = request.headers.get("X-CSRF-Token") or payload.get("csrf_token") or form_token
        if not csrf_valid({"csrf_token": token}):
            return _api_error("The request expired. Reload the page and try again.", 403)
    try:
        registry = Registry(settings, privileged=True)
        package = registry.package(name)
        if not package:
            return _api_error("Package not found.", 404)
        user_id = str(user["id"])
        if request.method == "DELETE":
            if str(package.get("owner_id")) != user_id:
                return _api_error("Only the package owner can delete a package.", 403)
            _delete_package(registry, package)
            return _json_response({"status": "deleted", "name": name})
        if not registry.can(package, user_id, "manage"):
            return _api_error("Package management permission is required.", 403)
        payload = request.json
        if not isinstance(payload, dict):
            return _api_error("A JSON object is required.", 400)
        fields: dict[str, Any] = {}
        if "description" in payload:
            description = payload["description"]
            if not isinstance(description, str) or len(description) > 500:
                return _api_error("Description must be 500 characters or fewer.", 400)
            fields["description"] = description
        for key in ("repository_url", "homepage_url"):
            if key in payload:
                value = payload[key]
                if not isinstance(value, str) or (value and not _web_url(value)):
                    return _api_error(f"{key} must be an HTTP(S) URL.", 400)
                fields[key] = value
        if "is_deprecated" in payload:
            if not isinstance(payload["is_deprecated"], bool):
                return _api_error("is_deprecated must be a boolean.", 400)
            fields["is_deprecated"] = payload["is_deprecated"]
        if not fields:
            return _api_error("No supported package fields were provided.", 400)
        registry.db.rest(
            f"packages?id=eq.{package['id']}",
            method="PATCH",
            payload=fields,
        )
        return _json_response({"status": "updated", "name": name})
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


@nova_metadata.get("/<name>/<version>")
def nova_metadata_route(name: str, version: str) -> Response:
    if not PACKAGE_NAME.fullmatch(name) or not PACKAGE_VERSION.fullmatch(version):
        return _api_error("Invalid package name or version.", 400)
    try:
        package = Registry(settings).package(name)
        if not package:
            return _api_error("Package not found.", 404)
        selected = _package_version(package, version)
        if not selected:
            return _api_error("Package version not found.", 404)
        result = json_package(package, _public_base())
        version_info = public_version(selected, name, _public_base())
        result.update(version_info)
        result["name"] = name
        result["version"] = version
        return _json_response(result)
    except ConfigurationError as exc:
        return _settings_error(exc)
    except SupabaseError as exc:
        return _api_error(str(exc), exc.status)


def register_routes(app: Any) -> None:
    app.register_blueprint(api)
    app.register_blueprint(nova_metadata)
    app.register_blueprint(pages)
    static_root = app.static_dir.resolve()

    @app.after_request
    def add_security_headers(body: Any, status: int, headers: dict[str, str]):
        content_type = headers.pop("Content-Type", "text/html; charset=utf-8")
        headers.update(
            {
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Content-Security-Policy": (
                    "default-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "form-action 'self'; base-uri 'self'; frame-ancestors 'none'; "
                    "object-src 'none'; script-src 'none'"
                ),
            }
        )
        refreshed = take_refreshed_cookie()
        if refreshed:
            headers["Set-Cookie"] = refreshed
        clear_verified_access_token()
        return body, content_type, status, headers

    @app.route("/sw.js")
    def service_worker() -> Response:
        return Response(
            "self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));\n"
            "self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));\n",
            content_type="application/javascript; charset=utf-8",
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/static/<asset>")
    def static_file(asset: str) -> Response:
        file_path = (static_root / asset).resolve()
        try:
            file_path.relative_to(static_root)
        except ValueError:
            return Response("Not found", status=404)
        if not file_path.is_file():
            return Response("Not found", status=404)
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        return Response(
            file_path.read_bytes(),
            content_type=content_type,
            headers={"Content-Type": content_type},
        )
