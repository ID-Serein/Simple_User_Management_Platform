import io
import re
import tempfile
import unittest
import uuid
from pathlib import Path

from app import BASE_DIR, create_app


PNG_BYTES = bytes.fromhex("89504e470d0a1a0a") + (b"\x00" * 32)


class UploadSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.admin_password = "UploadTest2026!"
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "upload-test-secret-with-more-than-32-chars",
                "USER_STORE_PATH": str(Path(self.temp_dir.name) / "users.json"),
                "INITIAL_ADMIN_USERNAME": "admin",
                "INITIAL_ADMIN_PASSWORD": self.admin_password,
                "INITIAL_ADMIN_EMAIL": "admin@example.com",
                "SESSION_COOKIE_SECURE": False,
            }
        )
        self.client = self.app.test_client()
        self.created_files = []

    def tearDown(self):
        for path in self.created_files:
            path.unlink(missing_ok=True)
        self.temp_dir.cleanup()

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        body = response.get_data(as_text=True)
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(match)
        return match.group(1)

    def login(self):
        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": self.admin_password,
                "csrf_token": self.csrf_token("/login"),
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

    def upload(self, filename, content, content_type, include_csrf=True):
        data = {
            "file": (io.BytesIO(content), filename, content_type),
        }
        if include_csrf:
            data["csrf_token"] = self.csrf_token("/upload")

        return self.client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=False,
        )

    def test_upload_requires_login(self):
        response = self.client.get("/upload")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_upload_requires_csrf_token(self):
        self.login()

        response = self.upload("avatar.png", PNG_BYTES, "image/png", include_csrf=False)

        self.assertEqual(response.status_code, 400)

    def test_rejects_html_upload(self):
        self.login()

        response = self.upload("xss.html", b"<script>alert(1)</script>", "text/html")

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("xss.html", response.get_data(as_text=True))

    def test_rejects_fake_image_content(self):
        self.login()

        response = self.upload("avatar.png", b"not a real image payload", "image/png")

        self.assertEqual(response.status_code, 400)

    def test_valid_image_is_saved_with_random_name(self):
        self.login()

        response = self.upload("avatar.png", PNG_BYTES, "image/png")
        body = response.get_data(as_text=True)
        match = re.search(r"/static/uploads/([a-f0-9]{32}\.png)", body)
        self.assertIsNotNone(match)

        saved_path = BASE_DIR / "static" / "uploads" / match.group(1)
        self.created_files.append(saved_path)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(saved_path.exists())
        self.assertNotIn("avatar.png", body)

    def test_traversal_filename_stays_inside_upload_directory(self):
        self.login()
        outside_name = f"poc-upload-traversal-{uuid.uuid4().hex}.png"
        outside_path = BASE_DIR / "static" / outside_name

        response = self.upload(f"../{outside_name}", PNG_BYTES, "image/png")
        body = response.get_data(as_text=True)
        match = re.search(r"/static/uploads/([a-f0-9]{32}\.png)", body)
        self.assertIsNotNone(match)

        saved_path = BASE_DIR / "static" / "uploads" / match.group(1)
        self.created_files.append(saved_path)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(saved_path.exists())
        self.assertFalse(outside_path.exists())


if __name__ == "__main__":
    unittest.main()
