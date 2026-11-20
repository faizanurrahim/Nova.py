from __future__ import annotations

import unittest

from Nexa import NXserver

from novanx.routes import register_routes


class NexaAfterRequestTests(unittest.TestCase):
    def test_service_worker_is_served_from_the_root_scope(self) -> None:
        app = NXserver("NovaNX test")
        register_routes(app)

        route, params = app.router.match("/sw.js")
        self.assertIsNotNone(route)
        self.assertEqual(params, {})

        response = route.handler()
        body, content_type, status, headers = response.render()
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/javascript; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-cache")
        self.assertIn(b"self.skipWaiting()", body)
        self.assertIn(b"self.clients.claim()", body)

    def test_security_hook_returns_the_active_nexa_four_value_contract(self) -> None:
        app = NXserver("NovaNX test")
        register_routes(app)

        result = app._after_request_handlers[0](
            b"response",
            200,
            {"Content-Type": "application/json; charset=utf-8"},
        )

        self.assertEqual(len(result), 4)
        body, content_type, status, headers = result
        self.assertEqual(body, b"response")
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn("Content-Type", headers)
        self.assertEqual(headers["Content-Security-Policy"], (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; base-uri 'self'; frame-ancestors 'none'; "
            "object-src 'none'; script-src 'none'"
        ))


if __name__ == "__main__":
    unittest.main()
