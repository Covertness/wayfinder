from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django_otp.oath import TOTP
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.authtoken.models import Token


class TwoFactorTests(TestCase):
    settings_url = "/wayfinder/settings/two-factor/"
    password = "correct-password"

    def setUp(self):
        self.user = User.objects.create_user(username="alice", password=self.password)
        self.client.force_login(self.user)
        self.now = 1800000000
        self.clock = patch(
            "django_otp.plugins.otp_totp.models.time",
            SimpleNamespace(time=lambda: self.now),
        )
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def code(self, device):
        generator = TOTP(device.bin_key)
        generator.time = self.now
        return f"{generator.token():06d}"

    def post_settings(self, **data):
        return self.client.post(self.settings_url, data, content_type="application/json")

    def setup_device(self):
        response = self.post_settings(action="setup", password=self.password)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["uri"].startswith("otpauth://totp/"))
        self.assertEqual(response.json()["secret"], response.json()["uri"].split("secret=")[1].split("&")[0])
        self.assertIn("no-store", response.headers["Cache-Control"])
        return TOTPDevice.objects.get(user=self.user)

    def enable_device(self):
        device = self.setup_device()
        response = self.post_settings(action="confirm", otp=self.code(device))
        self.assertEqual(response.status_code, 200)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        return device

    def test_setup_requires_password_and_confirmation(self):
        self.assertEqual(self.post_settings(action="setup", password="wrong").status_code, 400)
        self.assertFalse(TOTPDevice.objects.exists())
        device = self.setup_device()
        self.assertFalse(device.confirmed)
        self.assertFalse(self.client.get(self.settings_url).json()["enabled"])
        invalid = f"{(int(self.code(device)) + 1) % 1000000:06d}"
        self.assertEqual(self.post_settings(action="confirm", otp=invalid).status_code, 400)
        device.refresh_from_db()
        self.assertFalse(device.confirmed)
        self.assertEqual(device.throttling_failure_count, 1)

    def test_login_requires_code_and_prevents_replay(self):
        device = self.enable_device()
        self.client.logout()
        credentials = {"username": "alice", "password": self.password}
        response = self.client.post("/auth/login/", credentials, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertIn("otp", response.json())
        self.assertNotIn("_auth_user_id", self.client.session)
        self.now += 30
        code = self.code(device)
        response = self.client.post("/auth/login/", {**credentials, "otp": code}, content_type="application/json")
        self.assertEqual(response.status_code, 204)
        self.client.logout()
        response = self.client.post("/auth/login/", {**credentials, "otp": code}, content_type="application/json")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_existing_users_can_log_in_without_two_factor(self):
        self.client.logout()
        response = self.client.post("/auth/login/", {"username": "alice", "password": self.password}, content_type="application/json")
        self.assertEqual(response.status_code, 204)

    def test_invalid_login_code_is_throttled(self):
        device = self.enable_device()
        self.now += 30
        self.client.logout()
        credentials = {"username": "alice", "password": self.password}
        code = self.code(device)
        invalid = f"{(int(code) + 1) % 1000000:06d}"
        self.assertEqual(self.client.post("/auth/login/", {**credentials, "otp": invalid}, content_type="application/json").status_code, 400)
        device.refresh_from_db()
        self.assertEqual(device.throttling_failure_count, 1)
        self.assertEqual(self.client.post("/auth/login/", {**credentials, "otp": code}, content_type="application/json").status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_disable_requires_password_and_new_code(self):
        device = self.enable_device()
        self.now += 30
        self.assertEqual(self.post_settings(action="disable", password="wrong", otp=self.code(device)).status_code, 400)
        self.assertEqual(self.post_settings(action="disable", password=self.password, otp=self.code(device)).status_code, 200)
        self.assertFalse(TOTPDevice.objects.filter(user=self.user).exists())
        self.assertFalse(self.client.get(self.settings_url).json()["enabled"])

    def test_admin_login_requires_code(self):
        self.user.is_staff = True
        self.user.save()
        device = self.enable_device()
        self.client.logout()
        response = self.client.post("/admin/login/", {"username": "alice", "password": self.password})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.now += 30
        response = self.client.post("/admin/login/", {"username": "alice", "password": self.password, "otp_token": self.code(device)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)

    def test_integration_token_cannot_bypass_two_factor_or_modify_settings(self):
        token = Token.objects.create(user=self.user)
        self.enable_device()
        self.client.logout()
        response = self.client.get("/auth/user/", HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(response.status_code, 403)
        response = self.client.get(self.settings_url, HTTP_AUTHORIZATION=f"Token {token.key}")
        self.assertEqual(response.status_code, 403)
        response = self.client.post("/wayfinder/overland/", {}, content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token.key}")
        self.assertNotIn(response.status_code, (401, 403))

    def test_setup_requires_csrf_protection(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(
            self.settings_url,
            {"action": "setup", "password": self.password},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(TOTPDevice.objects.exists())

    def test_other_user_cannot_modify_device(self):
        device = self.enable_device()
        other = User.objects.create_user(username="bob", password="another-password")
        self.client.force_login(other)
        self.assertEqual(self.post_settings(action="disable", password="another-password", otp=self.code(device)).status_code, 400)
        self.assertTrue(TOTPDevice.objects.filter(pk=device.pk, confirmed=True).exists())

    def test_administrator_can_reset_lost_device(self):
        device = self.enable_device()
        admin = User.objects.create_superuser(username="admin", password="admin-password")
        self.client.force_login(admin)
        response = self.client.post(f"/admin/otp_totp/totpdevice/{device.pk}/delete/", {"post": "yes"})
        self.assertEqual(response.status_code, 302)
        self.client.logout()
        response = self.client.post("/auth/login/", {"username": "alice", "password": self.password}, content_type="application/json")
        self.assertEqual(response.status_code, 204)
