import re
import tempfile
import unittest
from pathlib import Path

from flask import Flask

from app import create_app


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.admin_password = "CorrectHorse2026!"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret-key-with-more-than-32-characters",
                "USER_STORE_PATH": str(Path(self.temp_dir.name) / "users.json"),
                "INITIAL_ADMIN_USERNAME": "admin",
                "INITIAL_ADMIN_PASSWORD": self.admin_password,
                "INITIAL_ADMIN_EMAIL": "admin@example.com",
                "INITIAL_ADMIN_PHONE": "13800138000",
                "SESSION_COOKIE_SECURE": False,
                "LOGIN_RATE_LIMIT_MAX_ATTEMPTS": 2,
                "LOGIN_RATE_LIMIT_WINDOW_SECONDS": 60,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self):
        response = self.client.get("/login")
        body = response.get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(match)
        return match.group(1)

    def login(self, password=None, follow_redirects=True):
        return self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": password or self.admin_password,
                "csrf_token": self.csrf_token(),
            },
            follow_redirects=follow_redirects,
        )

    def test_login_page_does_not_leak_default_credentials(self):
        response = self.client.get("/login")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("admin123", body)
        self.assertNotIn("默认管理员账号", body)

    def test_successful_login_does_not_render_password(self):
        response = self.login()
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("admin@example.com", body)
        self.assertNotIn(self.admin_password, body)
        self.assertNotIn("password_hash", body)

    def test_cookie_signed_with_old_dev_key_is_rejected(self):
        legacy_app = Flask("legacy")
        legacy_app.secret_key = "dev-key-2025"
        forged_cookie = legacy_app.session_interface.get_signing_serializer(legacy_app).dumps(
            {"username": "admin"}
        )

        self.client.set_cookie("session", forged_cookie)
        response = self.client.get("/")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("admin@example.com", body)
        self.assertNotIn("13800138000", body)

    def test_login_requires_csrf_token(self):
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": self.admin_password},
        )

        self.assertEqual(response.status_code, 400)

    def test_logout_requires_post_and_csrf_token(self):
        self.login()

        get_response = self.client.get("/logout")
        self.assertEqual(get_response.status_code, 405)

        post_response = self.client.post("/logout")
        self.assertEqual(post_response.status_code, 400)

    def test_login_rate_limit_blocks_repeated_failures(self):
        for _ in range(2):
            response = self.client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "wrong-password",
                    "csrf_token": self.csrf_token(),
                },
            )
            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "wrong-password",
                "csrf_token": self.csrf_token(),
            },
        )
        self.assertEqual(response.status_code, 429)

    def test_security_headers_are_present(self):
        response = self.client.get("/")

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])


if __name__ == "__main__":
    unittest.main()
