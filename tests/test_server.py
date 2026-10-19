import http.cookiejar
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import server


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "test.sqlite3"
        self.db_patch = patch.object(server, "DB_PATH", self.db_path)
        self.db_patch.start()
        server.init_db()
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.GrapeHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.admin = self.client()
        self.register(self.admin, "admin@example.test", "Administrator")
        with server.database() as db:
            db.execute("UPDATE users SET role = 'admin' WHERE email = 'admin@example.test'")
        self.admin = self.client()
        self.request(self.admin, "/api/login", {"email": "admin@example.test", "password": "correct-horse-battery"})

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        self.db_patch.stop()
        self.temp.cleanup()

    @staticmethod
    def client():
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(self, client, path, body=None, method=None):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Content-Type": "application/json"} if data else {},
            method=method,
        )
        try:
            response = client.open(request)
        except urllib.error.HTTPError as error:
            response = error
        return response.code, json.loads(response.read())

    def register(self, client, email, name="Farmer"):
        return self.request(client, "/api/register", {
            "name": name,
            "email": email,
            "password": "correct-horse-battery",
        })

    def test_registration_persists_prices_and_field_records(self):
        farmer = self.client()
        status, result = self.register(farmer, "farmer@example.test")
        self.assertEqual(status, 201)
        self.assertEqual(result["user"]["role"], "farmer")
        self.assertEqual(self.request(farmer, "/api/prices", {
            "market": "Vijayapura",
            "variety": "Thompson Seedless",
            "price": 8500,
            "unit": "q",
            "price_date": "2026-10-18",
            "source": "Market board",
        }, "POST")[0], 201)
        self.assertEqual(self.request(farmer, "/api/prices")[1]["prices"][0]["price"], 8500)
        status, _ = self.request(farmer, "/api/diagnoses", {
            "plant_part": "leaf",
            "symptoms": ["yellow patches"],
            "recent_weather": "wet",
            "results": ["Downy mildew"],
        }, "POST")
        self.assertEqual(status, 201)
        self.assertEqual(len(self.request(farmer, "/api/diagnoses")[1]["records"]), 1)

    def test_farmer_cannot_read_another_farmers_records_or_delete_price(self):
        first = self.client()
        self.register(first, "first@example.test")
        self.request(first, "/api/prices", {
            "market": "Market A", "variety": "Grapes", "price": 100,
            "unit": "kg", "price_date": "2026-10-18", "source": "",
        }, "POST")
        price_id = self.request(first, "/api/prices")[1]["prices"][0]["id"]
        second = self.client()
        self.register(second, "second@example.test")
        self.assertEqual(self.request(second, "/api/diagnoses")[1]["records"], [])
        self.assertEqual(self.request(second, f"/api/prices/{price_id}", method="DELETE")[0], 403)
        self.assertEqual(self.request(first, f"/api/prices/{price_id}", method="DELETE")[0], 200)

    def test_only_admin_can_assign_roles_and_admins_cannot_remove_last_admin(self):
        farmer = self.client()
        self.register(farmer, "advisor@example.test")
        status, _ = self.request(farmer, "/api/admin/users")
        self.assertEqual(status, 403)
        user_id = next(
            user["id"] for user in self.request(self.admin, "/api/admin/users")[1]["users"]
            if user["email"] == "advisor@example.test"
        )
        status, result = self.request(self.admin, f"/api/admin/users/{user_id}/role", {"role": "advisor"}, "PATCH")
        self.assertEqual(status, 200)
        self.assertEqual(result["user"]["role"], "advisor")
        self.assertEqual(self.request(self.admin, f"/api/admin/users/{self.request(self.admin, '/api/me')[1]['user']['id']}/role", {"role": "farmer"}, "PATCH")[0], 409)

    def test_advisor_can_read_all_field_records_but_cannot_delete_another_users_prices(self):
        farmer = self.client()
        self.register(farmer, "record-owner@example.test")
        self.request(farmer, "/api/diagnoses", {
            "plant_part": "bunch",
            "symptoms": ["berries shrivel"],
            "recent_weather": "",
            "results": ["Downy mildew"],
        }, "POST")
        self.request(farmer, "/api/prices", {
            "market": "Market A", "variety": "Grapes", "price": 100,
            "unit": "kg", "price_date": "2026-10-18", "source": "",
        }, "POST")
        unprivileged_advisor = self.client()
        self.register(unprivileged_advisor, "advisor@example.test")
        farmer_id = self.request(self.admin, "/api/admin/users")[1]["users"]
        owner_id = next(user["id"] for user in farmer_id if user["email"] == "record-owner@example.test")
        advisor_id = next(user["id"] for user in farmer_id if user["email"] == "advisor@example.test")
        self.request(self.admin, f"/api/admin/users/{advisor_id}/role", {"role": "advisor"}, "PATCH")
        advisor = self.client()
        self.request(advisor, "/api/login", {"email": "advisor@example.test", "password": "correct-horse-battery"})
        self.assertEqual(len(self.request(advisor, "/api/diagnoses")[1]["records"]), 1)
        price_id = self.request(advisor, "/api/prices")[1]["prices"][0]["id"]
        self.assertNotEqual(owner_id, self.request(advisor, "/api/me")[1]["user"]["id"])
        self.assertEqual(self.request(advisor, f"/api/prices/{price_id}", method="DELETE")[0], 403)

    def test_protected_data_requires_a_session(self):
        anonymous = self.client()
        self.assertEqual(self.request(anonymous, "/api/prices")[0], 401)
        self.assertEqual(self.request(anonymous, "/api/weather", {}, "POST")[0], 401)

    def test_invalid_market_values_are_rejected(self):
        farmer = self.client()
        self.register(farmer, "invalid@example.test")
        status, _ = self.request(farmer, "/api/prices", {
            "market": "Market A", "variety": "Grapes", "price": -1,
            "unit": "kg", "price_date": "2026-10-18", "source": "",
        }, "POST")
        self.assertEqual(status, 400)


    def test_duplicate_registration_is_rejected(self):
        farmer = self.client()
        self.assertEqual(self.register(farmer, "repeat@example.test")[0], 201)
        duplicate = self.client()
        self.assertEqual(self.register(duplicate, "repeat@example.test")[0], 409)

    def test_registration_rejects_short_passwords(self):
        status, _ = self.request(self.client(), "/api/register", {
            "name": "Farmer", "email": "short@example.test", "password": "short"
        }, "POST")
        self.assertEqual(status, 400)

    def test_registration_rejects_invalid_email_addresses(self):
        status, _ = self.request(self.client(), "/api/register", {
            "name": "Farmer", "email": "not-an-email", "password": "correct-horse-battery"
        }, "POST")
        self.assertEqual(status, 400)

    def test_price_rejects_unsupported_units(self):
        farmer = self.client()
        self.register(farmer, "bad-unit@example.test")
        status, _ = self.request(farmer, "/api/prices", {
            "market": "Market A", "variety": "Grapes", "price": 40,
            "unit": "crate", "price_date": "2026-10-18", "source": ""
        }, "POST")
        self.assertEqual(status, 400)

    def test_price_rejects_future_dates(self):
        from datetime import date, timedelta
        farmer = self.client()
        self.register(farmer, "future-date@example.test")
        status, _ = self.request(farmer, "/api/prices", {
            "market": "Market A", "variety": "Grapes", "price": 40,
            "unit": "kg", "price_date": (date.today() + timedelta(days=1)).isoformat(), "source": ""
        }, "POST")
        self.assertEqual(status, 400)

    def test_diagnosis_rejects_unknown_plant_parts(self):
        farmer = self.client()
        self.register(farmer, "bad-part@example.test")
        status, _ = self.request(farmer, "/api/diagnoses", {
            "plant_part": "root", "symptoms": [], "recent_weather": "", "results": []
        }, "POST")
        self.assertEqual(status, 400)

    def test_weather_rejects_percentages_above_one_hundred(self):
        farmer = self.client()
        self.register(farmer, "bad-weather@example.test")
        status, _ = self.request(farmer, "/api/weather", {
            "rain_chance": 101, "expected_rain": 0, "humidity": 50, "sky": "clear",
            "min_temp": 10, "max_temp": 20, "source": "IMD",
            "issued_on": "2026-10-19", "hints": []
        }, "POST")
        self.assertEqual(status, 400)

if __name__ == "__main__":
    unittest.main()
