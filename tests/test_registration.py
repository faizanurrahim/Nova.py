from __future__ import annotations

import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch
from urllib.error import HTTPError, URLError

import psycopg
from Nexa.nxserver import Response

from novanx import auth as auth_module
from novanx import routes
from novanx.auth import SupabaseAuth
from novanx.config import ConfigurationError, Settings
from novanx.database import ProfileDatabaseError, ProfileRepository
from novanx.registry import Registry
from novanx.supabase import SupabaseClient, SupabaseError, _classify_http_error


def test_settings() -> Settings:
    return Settings(
        supabase_url="https://unit-test.supabase.co",
        supabase_anon_key="sb_publishable_unit_test_key",
        supabase_service_role_key="sb_secret_unit_test_key",
        database_url="postgresql://unit:test@localhost/novanx",
        session_secret="unit-test-session-secret-with-more-than-32-characters",
        storage_bucket="novanx-packages",
        public_base_url="",
        host="127.0.0.1",
        port=3000,
        cookie_secure=False,
        max_archive_size=1024 * 1024,
    )


def response_page(_template: str, **context: object) -> Response:
    return Response(
        json.dumps(context),
        content_type="application/json; charset=utf-8",
    )


class RegistrationRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.form = {
            "email": "new.person@example.test",
            "username": "new_person",
            "password": "long-enough-password",
        }
        self.fake_request = SimpleNamespace(form=self.form)
        self.auth = Mock()
        self.auth.username_exists.return_value = False
        self.auth.sign_up.return_value = {
            "user": {"id": "auth-user-id", "email": self.form["email"]},
            "access_token": None,
            "refresh_token": None,
        }
        self.auth.profile_for_user.return_value = {
            "id": "auth-user-id",
            "username": "new_person",
        }
        self.patches = [
            patch.object(routes, "request", self.fake_request),
            patch.object(routes, "csrf_valid", return_value=True),
            patch.object(routes, "_page", side_effect=response_page),
            patch.object(routes, "SupabaseAuth", return_value=self.auth),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()

    def register(self) -> tuple[Response, dict[str, object]]:
        response = routes._register_post()
        return response, json.loads(response.body)

    def test_new_email_and_username_succeed_without_a_session_when_confirmation_is_enabled(self) -> None:
        response, page = self.register()

        self.assertEqual(response.status, 200)
        self.assertEqual(page["mode"], "login")
        self.assertIn("Check your email", str(page["message"]))
        self.auth.username_exists.assert_called_once_with("new_person")
        self.auth.profile_for_user.assert_called_once_with("auth-user-id")
        self.auth.sign_up.assert_called_once_with(
            "new.person@example.test",
            "long-enough-password",
            "new_person",
        )

    def test_registration_with_session_returns_created_status_and_sets_cookie(self) -> None:
        self.auth.sign_up.return_value = {
            "user": {"id": "auth-user-id", "email": self.form["email"]},
            "access_token": "access-token",
            "refresh_token": "refresh-token",
        }
        with patch.object(routes, "session_cookie", return_value="signed-session-cookie"):
            response, page = self.register()

        self.assertEqual(response.status, 201)
        self.assertEqual(page["mode"], "created")
        self.assertEqual(response.headers["Set-Cookie"], "signed-session-cookie")

    def test_existing_email_has_a_specific_error(self) -> None:
        self.auth.sign_up.side_effect = SupabaseError(
            "Supabase rejected the request.", 409, category="email_taken"
        )

        response, page = self.register()

        self.assertEqual(response.status, 409)
        self.assertIn("email already exists", str(page["error"]))

    def test_existing_username_is_rejected_before_auth_signup(self) -> None:
        self.auth.username_exists.return_value = True

        response, page = self.register()

        self.assertEqual(response.status, 409)
        self.assertIn("username is already taken", str(page["error"]))
        self.auth.sign_up.assert_not_called()
        self.auth.profile_for_user.assert_not_called()

    def test_invalid_email_is_rejected_before_auth_signup(self) -> None:
        self.form["email"] = "not-an-email"

        response, page = self.register()

        self.assertEqual(response.status, 400)
        self.assertEqual(page["error"], "Enter a valid email address.")
        self.auth.username_exists.assert_not_called()
        self.auth.sign_up.assert_not_called()

    def test_missing_username_is_rejected_before_auth_signup(self) -> None:
        self.form["username"] = ""

        response, page = self.register()

        self.assertEqual(response.status, 400)
        self.assertIn("3–30 character username", str(page["error"]))
        self.auth.username_exists.assert_not_called()
        self.auth.sign_up.assert_not_called()

    def test_weak_password_is_rejected_before_auth_signup(self) -> None:
        self.form["password"] = "short"

        response, page = self.register()

        self.assertEqual(response.status, 400)
        self.assertIn("between 10 and 128 characters", str(page["error"]))
        self.auth.username_exists.assert_not_called()
        self.auth.sign_up.assert_not_called()

    def test_network_failure_is_not_reported_as_duplicate_email(self) -> None:
        self.auth.sign_up.side_effect = SupabaseError(
            "Supabase could not be reached.", 503, category="network_error"
        )

        response, page = self.register()

        self.assertEqual(response.status, 503)
        self.assertIn("could not reach Supabase", str(page["error"]))
        self.assertNotIn("already exists", str(page["error"]))

    def test_profile_trigger_failure_is_reported_separately(self) -> None:
        self.auth.sign_up.side_effect = SupabaseError(
            "Supabase rejected the request.", 500, category="profile_creation"
        )

        response, page = self.register()

        self.assertEqual(response.status, 502)
        self.assertIn("could not create the NovaNX profile", str(page["error"]))
        self.assertNotIn("already exists", str(page["error"]))

    def test_registration_fails_when_the_auth_trigger_did_not_create_the_profile(self) -> None:
        self.auth.profile_for_user.return_value = None

        with self.assertLogs(level="ERROR"):
            response, page = self.register()

        self.assertEqual(response.status, 503)
        self.assertIn("could not verify its profile", str(page["error"]))

    def test_database_failure_returns_503_without_calling_supabase_auth(self) -> None:
        self.auth.username_exists.side_effect = ProfileDatabaseError(
            "database unavailable"
        )

        response, page = self.register()

        self.assertEqual(response.status, 503)
        self.assertIn("profile storage is temporarily unavailable", str(page["error"]))
        self.auth.sign_up.assert_not_called()

    def test_missing_database_url_returns_503_before_auth_signup(self) -> None:
        self.auth.username_exists.side_effect = ConfigurationError(
            "DATABASE_URL is required."
        )
        with patch.object(routes, "SupabaseAuth", return_value=self.auth):
            response, page = self.register()

        self.assertEqual(response.status, 503)
        self.assertIn("DATABASE_URL", str(page["error"]))
        self.auth.sign_up.assert_not_called()

    def test_supabase_email_confirmation_returns_user_without_access_tokens(self) -> None:
        self.auth.sign_up.return_value = {
            "user": {"id": "auth-user-id", "email": self.form["email"]},
            "access_token": None,
            "refresh_token": None,
        }

        _, page = self.register()

        self.assertIn("Check your email", str(page["message"]))

    def test_duplicate_email_obfuscation_response_is_reported_as_existing_account(self) -> None:
        self.auth.sign_up.return_value = {
            "user": {
                "id": "auth-user-id",
                "email": self.form["email"],
                "identities": [],
            },
            "access_token": None,
            "refresh_token": None,
        }

        response, page = self.register()

        self.assertEqual(response.status, 409)
        self.assertIn("email already exists", str(page["error"]))


class DashboardProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth_user = {"id": "auth-user-id", "email": "person@example.test"}
        self.profile = {
            "id": "auth-user-id",
            "username": "profile_name",
            "avatar_url": None,
        }
        self.auth = Mock()
        self.auth.profile_for_user.return_value = self.profile
        self.registry = Mock()
        self.registry.packages_for_user.return_value = []
        self.patches = [
            patch.object(routes, "_user", return_value=self.auth_user),
            patch.object(routes, "verified_access_token", return_value="verified-user-token"),
            patch.object(routes, "request", SimpleNamespace(args={})),
            patch.object(routes, "SupabaseAuth", return_value=self.auth),
            patch.object(routes, "Registry", return_value=self.registry),
            patch.object(routes, "_page", side_effect=response_page),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()

    def test_dashboard_uses_the_profile_linked_to_the_authenticated_user(self) -> None:
        response = routes.dashboard()
        page = json.loads(response.body)

        self.auth.profile_for_user.assert_called_once_with("auth-user-id")
        routes.Registry.assert_called_once_with(
            routes.settings,
            user_access_token="verified-user-token",
        )
        self.registry.packages_for_user.assert_called_once_with("auth-user-id")
        self.assertEqual(page["user"]["username"], "profile_name")
        self.assertNotIn("verified-user-token", response.body)

    def test_dashboard_reports_a_missing_profile_instead_of_using_auth_metadata(self) -> None:
        self.auth.profile_for_user.return_value = None

        response = routes.dashboard()
        page = json.loads(response.body)

        self.assertEqual(response.status, 503)
        self.assertIn("profile is missing", str(page["message"]))
        self.registry.packages_for_user.assert_not_called()

    def test_dashboard_redirects_when_the_session_is_missing(self) -> None:
        routes._user.return_value = None

        response = routes.dashboard()

        self.assertEqual(response.status, 302)
        routes.Registry.assert_not_called()

    def test_dashboard_reports_rls_denial_without_exposing_raw_database_error(self) -> None:
        self.registry.packages_for_user.side_effect = SupabaseError(
            "Supabase rejected the request.",
            401,
            category="permission_denied",
            code="42501",
        )

        with self.assertLogs(level="WARNING"):
            response = routes.dashboard()
        page = json.loads(response.body)

        self.assertEqual(response.status, 403)
        self.assertIn("not permitted", str(page["message"]))
        self.assertNotIn("42501", response.body)


class SupabaseSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = test_settings()
        auth_module.clear_verified_access_token()
        auth_module.take_refreshed_cookie()

    def tearDown(self) -> None:
        auth_module.clear_verified_access_token()
        auth_module.take_refreshed_cookie()

    def request_with_session(self, *, authorization: str = "") -> SimpleNamespace:
        session = {
            "access_token": "expired-access-token",
            "refresh_token": "valid-refresh-token",
            "user": {"id": "auth-user-id"},
        }
        return SimpleNamespace(
            headers={"Authorization": authorization} if authorization else {},
            cookies={
                auth_module.SESSION_COOKIE: auth_module._signed(
                    session,
                    self.settings.session_secret,
                )
            },
        )

    def test_verified_cookie_token_is_available_to_authenticated_api_calls(self) -> None:
        request = self.request_with_session()
        client = Mock()
        client.request.return_value = (
            {"id": "auth-user-id", "email": "person@example.test"},
            {},
        )
        with (
            patch.object(auth_module, "request", request),
            patch.object(auth_module, "SupabaseClient", return_value=client),
        ):
            user = auth_module.current_user(self.settings)

        self.assertEqual(user["id"], "auth-user-id")
        self.assertEqual(
            auth_module.verified_access_token(),
            "expired-access-token",
        )

    def test_expired_cookie_session_refreshes_and_exposes_only_the_new_server_token(self) -> None:
        request = self.request_with_session()
        client = Mock()
        client.request.side_effect = SupabaseError(
            "expired", 401, category="invalid_api_key"
        )
        refreshed = {
            "user": {"id": "auth-user-id", "email": "person@example.test"},
            "access_token": "refreshed-user-token",
            "refresh_token": "rotated-refresh-token",
        }
        with (
            patch.object(auth_module, "request", request),
            patch.object(auth_module, "SupabaseClient", return_value=client),
            patch.object(auth_module.SupabaseAuth, "refresh", return_value=refreshed) as refresh,
            patch.object(auth_module, "session_cookie", return_value="refreshed-cookie"),
        ):
            user = auth_module.current_user(self.settings)

        self.assertEqual(user["id"], "auth-user-id")
        self.assertEqual(auth_module.verified_access_token(), "refreshed-user-token")
        self.assertEqual(auth_module.take_refreshed_cookie(), "refreshed-cookie")
        refresh.assert_called_once_with("valid-refresh-token")

    def test_invalid_bearer_token_is_not_replaced_by_a_cookie_session(self) -> None:
        request = self.request_with_session(authorization="Bearer invalid-user-token")
        client = Mock()
        client.request.side_effect = SupabaseError(
            "invalid JWT", 401, category="invalid_api_key"
        )
        with (
            patch.object(auth_module, "request", request),
            patch.object(auth_module, "SupabaseClient", return_value=client),
            patch.object(auth_module.SupabaseAuth, "refresh") as refresh,
        ):
            user = auth_module.current_user(self.settings)

        self.assertIsNone(user)
        self.assertIsNone(auth_module.verified_access_token())
        refresh.assert_not_called()

    def test_expired_session_with_invalid_refresh_token_is_rejected(self) -> None:
        request = self.request_with_session()
        client = Mock()
        client.request.side_effect = SupabaseError(
            "expired", 401, category="invalid_api_key"
        )
        with (
            patch.object(auth_module, "request", request),
            patch.object(auth_module, "SupabaseClient", return_value=client),
            patch.object(
                auth_module.SupabaseAuth,
                "refresh",
                side_effect=SupabaseError("invalid refresh token", 400),
            ),
        ):
            user = auth_module.current_user(self.settings)

        self.assertIsNone(user)
        self.assertIsNone(auth_module.verified_access_token())

    def test_auth_network_failure_is_not_treated_as_anonymous(self) -> None:
        request = self.request_with_session()
        client = Mock()
        client.request.side_effect = SupabaseError(
            "unavailable", 503, category="network_error"
        )
        with (
            patch.object(auth_module, "request", request),
            patch.object(auth_module, "SupabaseClient", return_value=client),
        ):
            with self.assertRaises(SupabaseError):
                auth_module.current_user(self.settings)

        self.assertIsNone(auth_module.verified_access_token())


class LogoutTests(unittest.TestCase):
    def test_logout_revokes_the_verified_user_token_and_clears_the_cookie(self) -> None:
        auth = Mock()
        with (
            patch.object(routes, "request", SimpleNamespace(form={}, headers={}, cookies={})),
            patch.object(routes, "csrf_valid", return_value=True),
            patch.object(routes, "_user", return_value={"id": "auth-user-id"}),
            patch.object(routes, "verified_access_token", return_value="verified-user-token"),
            patch.object(routes, "SupabaseAuth", return_value=auth),
        ):
            response = routes.logout()

        auth.sign_out.assert_called_once_with("verified-user-token")
        self.assertEqual(response.status, 302)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("novanx_session=", cookie)
        self.assertIn("Max-Age=0", cookie)
        self.assertNotIn("verified-user-token", cookie)


class SupabaseAuthRequestTests(unittest.TestCase):
    def test_signup_uses_publishable_key_apikey_header_and_json_without_bearer_key(self) -> None:
        response = Mock()
        response.read.return_value = json.dumps(
            {"user": {"id": "user-uuid", "email": "person@example.test"}}
        ).encode()
        response.headers.items.return_value = []
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch("novanx.supabase.urlopen", return_value=context) as open_url:
            auth = SupabaseAuth(test_settings())
            result = auth.sign_up("person@example.test", "some-password", "person")

        sent = open_url.call_args.args[0]
        self.assertEqual(sent.full_url, "https://unit-test.supabase.co/auth/v1/signup")
        self.assertEqual(sent.get_method(), "POST")
        self.assertEqual(sent.get_header("Apikey"), "sb_publishable_unit_test_key")
        self.assertIsNone(sent.get_header("Authorization"))
        self.assertEqual(sent.get_header("Content-type"), "application/json")
        self.assertEqual(
            json.loads(sent.data),
            {
                "email": "person@example.test",
                "password": "some-password",
                "data": {"username": "person"},
            },
        )
        self.assertEqual(result["user"]["id"], "user-uuid")

    def test_profile_lookup_uses_the_direct_database_repository(self) -> None:
        auth = SupabaseAuth(test_settings())
        profile_store = Mock()
        profile_store.profile_for_user.return_value = {
            "id": "auth-user-id",
            "username": "person",
        }
        with patch("novanx.auth.ProfileRepository", return_value=profile_store) as repository:
            profile = auth.profile_for_user("auth-user-id")

        repository.assert_called_once_with(auth.client.settings)
        profile_store.profile_for_user.assert_called_once_with("auth-user-id")
        self.assertEqual(profile["id"], "auth-user-id")

    def test_signup_errors_are_classified_from_supabase_response(self) -> None:
        cases = [
            (422, "user_already_exists", "User already registered", "email_taken"),
            (500, "23505", "duplicate key value violates profiles_username_key", "username_taken"),
            (422, "email_address_invalid", "Email address is invalid", "invalid_email"),
            (422, "weak_password", "Password should be at least 10 characters", "weak_password"),
            (401, "invalid_api_key", "Invalid API key", "invalid_api_key"),
            (401, "42501", "permission denied for table package_maintainers", "permission_denied"),
            (404, "not_found", "Not found", "invalid_url"),
            (500, "unexpected_failure", "Database error saving new user", "profile_creation"),
            (503, "internal_server_error", "Temporary backend failure", "supabase_server_error"),
        ]
        for status, code, message, expected in cases:
            with self.subTest(category=expected):
                self.assertEqual(
                    _classify_http_error(
                        status,
                        code,
                        message,
                        "auth/v1/signup",
                    ),
                    expected,
                )

    def test_network_failure_is_logged_without_request_secrets(self) -> None:
        settings = test_settings()
        client = SupabaseClient(settings)
        with patch("novanx.supabase.urlopen", side_effect=URLError("offline")):
            with self.assertLogs(level="WARNING") as captured:
                with self.assertRaises(SupabaseError) as raised:
                    client.request(
                        "auth/v1/signup",
                        method="POST",
                        payload={
                            "email": "private@example.test",
                            "password": "never-log-this-password",
                        },
                        use_key_as_bearer=False,
                    )

        self.assertEqual(raised.exception.category, "network_error")
        log_output = "\n".join(captured.output)
        self.assertNotIn("private@example.test", log_output)
        self.assertNotIn("never-log-this-password", log_output)

    def test_profile_trigger_error_logs_safe_upstream_code_and_message(self) -> None:
        body = json.dumps(
            {
                "error_code": "unexpected_failure",
                "message": "Database error saving new user for person@example.test",
            }
        ).encode()
        failure = HTTPError(
            "https://unit-test.supabase.co/auth/v1/signup",
            500,
            "Internal Server Error",
            {},
            io.BytesIO(body),
        )
        with patch("novanx.supabase.urlopen", side_effect=failure):
            with self.assertLogs(level="WARNING") as captured:
                with self.assertRaises(SupabaseError) as raised:
                    SupabaseClient(test_settings()).request(
                        "auth/v1/signup",
                        method="POST",
                        payload={"email": "person@example.test", "password": "private"},
                        use_key_as_bearer=False,
                    )

        self.assertEqual(raised.exception.category, "profile_creation")
        log_output = "\n".join(captured.output)
        self.assertIn("unexpected_failure", log_output)
        self.assertIn("Database error saving new user", log_output)
        self.assertNotIn("person@example.test", log_output)
        self.assertNotIn("private", log_output)


class RegistryRlsTests(unittest.TestCase):
    def test_packages_for_user_forwards_the_supabase_user_jwt(self) -> None:
        payloads = [
            [
                {
                    "id": "package-id",
                    "owner_id": "auth-user-id",
                    "name": "example",
                    "download_count": 0,
                }
            ],
            [],
            [],
            [{"id": "auth-user-id", "username": "example_user"}],
            [],
        ]
        contexts = []
        for payload in payloads:
            response = Mock()
            response.read.return_value = json.dumps(payload).encode()
            response.headers.items.return_value = []
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            contexts.append(context)

        with patch("novanx.supabase.urlopen", side_effect=contexts) as open_url:
            packages = Registry(
                test_settings(),
                user_access_token="eyJ.user-access-token",
            ).packages_for_user("auth-user-id")

        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["author"], "example_user")
        requests = [call.args[0] for call in open_url.call_args_list]
        maintainer_request = next(
            item for item in requests if "/rest/v1/package_maintainers?" in item.full_url
        )
        self.assertEqual(
            maintainer_request.get_header("Apikey"),
            "sb_publishable_unit_test_key",
        )
        self.assertEqual(
            maintainer_request.get_header("Authorization"),
            "Bearer eyJ.user-access-token",
        )

    def test_rls_denial_logs_diagnostics_without_access_token(self) -> None:
        access_token = "eyJ.private-user-access-token"
        body = json.dumps(
            {
                "code": "42501",
                "message": f"permission denied for table package_maintainers {access_token}",
            }
        ).encode()
        failure = HTTPError(
            "https://unit-test.supabase.co/rest/v1/package_maintainers",
            401,
            "Unauthorized",
            {},
            io.BytesIO(body),
        )
        with patch("novanx.supabase.urlopen", side_effect=failure):
            with self.assertLogs(level="WARNING") as captured:
                with self.assertRaises(SupabaseError) as raised:
                    SupabaseClient(
                        test_settings(),
                        user_access_token=access_token,
                    ).rest("package_maintainers?select=package_id")

        self.assertEqual(raised.exception.category, "permission_denied")
        self.assertIn("42501", "\n".join(captured.output))
        self.assertNotIn(access_token, "\n".join(captured.output))


class ProfileRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = test_settings()

    def mock_connection(self, result: dict[str, object] | None) -> MagicMock:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value
        cursor.__enter__.return_value = cursor
        cursor.fetchone.return_value = result
        return connection

    def test_username_check_uses_a_parameterized_query(self) -> None:
        connection = self.mock_connection({"?column?": 1})
        with patch("novanx.database.psycopg.connect", return_value=connection) as connect:
            exists = ProfileRepository(self.settings).username_exists("example_user")

        self.assertTrue(exists)
        connect.assert_called_once()
        cursor = connection.cursor.return_value.__enter__.return_value
        self.assertEqual(
            cursor.execute.call_args.args,
            ("select 1 from public.profiles where username = %s limit 1", ("example_user",)),
        )
        self.assertEqual(connect.call_args.kwargs["sslmode"], "require")
        self.assertTrue(connection.__exit__.called)

    def test_profile_lookup_returns_the_profile_for_an_auth_uuid(self) -> None:
        connection = self.mock_connection(
            {"id": "auth-user-id", "username": "example_user"}
        )
        with patch("novanx.database.psycopg.connect", return_value=connection):
            profile = ProfileRepository(self.settings).profile_for_user("auth-user-id")

        cursor = connection.cursor.return_value.__enter__.return_value
        self.assertEqual(
            cursor.execute.call_args.args,
            (
                "select id::text as id, username from public.profiles where id = %s::uuid limit 1",
                ("auth-user-id",),
            ),
        )
        self.assertEqual(profile, {"id": "auth-user-id", "username": "example_user"})

    def test_connection_errors_are_logged_without_connection_details(self) -> None:
        connection_string = self.settings.database_url
        with patch(
            "novanx.database.psycopg.connect",
            side_effect=psycopg.OperationalError(f"failed for {connection_string}"),
        ):
            with self.assertLogs(level="ERROR") as captured:
                with self.assertRaises(ProfileDatabaseError):
                    ProfileRepository(self.settings).username_exists("example_user")

        self.assertNotIn(connection_string, "\n".join(captured.output))

    def test_query_errors_exit_the_connection_context_for_rollback(self) -> None:
        connection = self.mock_connection(None)
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.execute.side_effect = psycopg.OperationalError("query failed")

        with patch("novanx.database.psycopg.connect", return_value=connection):
            with self.assertLogs(level="ERROR"):
                with self.assertRaises(ProfileDatabaseError):
                    ProfileRepository(self.settings).username_exists("example_user")

        self.assertIs(
            connection.__exit__.call_args.args[0],
            psycopg.OperationalError,
        )

    def test_missing_database_url_is_rejected(self) -> None:
        settings = test_settings()
        settings = Settings(
            supabase_url=settings.supabase_url,
            supabase_anon_key=settings.supabase_anon_key,
            supabase_service_role_key=settings.supabase_service_role_key,
            database_url="",
            session_secret=settings.session_secret,
            storage_bucket=settings.storage_bucket,
            public_base_url=settings.public_base_url,
            host=settings.host,
            port=settings.port,
            cookie_secure=settings.cookie_secure,
            max_archive_size=settings.max_archive_size,
        )

        with self.assertRaises(ConfigurationError):
            ProfileRepository(settings)


if __name__ == "__main__":
    unittest.main()
