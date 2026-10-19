import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from contextlib import closing, contextmanager
from datetime import date
from getpass import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit


BASE_DIR = Path(__file__).resolve().parent
APP_FILE = BASE_DIR / "Tech App for Grape Crop.html"
DB_PATH = Path(os.environ.get("GRAPE_DB_PATH", BASE_DIR / "grape_app.sqlite3"))
SESSION_SECONDS = 60 * 60 * 24 * 7
MAX_BODY_BYTES = 64 * 1024
ROLES = {"farmer", "advisor", "admin"}
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,63}$")
PASSWORD_ITERATIONS = 310_000
ROLE_PERMISSIONS = {
    "farmer": {"prices:read", "prices:create", "prices:delete_own", "records:read_own", "records:create"},
    "advisor": {"prices:read", "prices:create", "prices:delete_own", "records:read_all", "records:create"},
    "admin": {"prices:read", "prices:create", "prices:delete_all", "records:read_all", "records:create", "users:manage"},
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
DB_LOCK = threading.Lock()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


@contextmanager
def database():
    with closing(connect()) as db:
        with db:
            yield db


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DB_LOCK, database() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'farmer'
                    CHECK (role IN ('farmer', 'advisor', 'admin')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS prices (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                market TEXT NOT NULL,
                variety TEXT NOT NULL,
                price REAL NOT NULL CHECK (price > 0),
                unit TEXT NOT NULL CHECK (unit IN ('kg', 'q')),
                price_date TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS prices_date_idx ON prices(price_date DESC);
            CREATE TABLE IF NOT EXISTS diagnoses (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                plant_part TEXT NOT NULL,
                symptoms TEXT NOT NULL,
                recent_weather TEXT NOT NULL DEFAULT '',
                results TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS weather_records (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                rain_chance REAL NOT NULL,
                expected_rain REAL NOT NULL,
                humidity REAL NOT NULL,
                sky TEXT NOT NULL,
                min_temp REAL,
                max_temp REAL,
                source TEXT NOT NULL DEFAULT '',
                issued_on TEXT NOT NULL,
                hints TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def password_digest(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${derived.hex()}"


def password_matches(password, stored):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        ).hex()
        return hmac.compare_digest(computed, digest_hex)
    except (ValueError, TypeError):
        return False


def clean_text(value, field, limit, required=True):
    if not isinstance(value, str):
        raise ApiError(400, f"{field} must be text.")
    value = value.strip()
    if required and not value:
        raise ApiError(400, f"{field} is required.")
    if len(value) > limit:
        raise ApiError(400, f"{field} must be {limit} characters or fewer.")
    return value


def number(value, field, minimum=None, maximum=None, required=True):
    if value is None and not required:
        return None
    if isinstance(value, bool):
        raise ApiError(400, f"{field} must be a number.")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"{field} must be a number.") from None
    if not (result == result and abs(result) != float("inf")):
        raise ApiError(400, f"{field} must be finite.")
    if minimum is not None and result < minimum:
        raise ApiError(400, f"{field} must be at least {minimum}.")
    if maximum is not None and result > maximum:
        raise ApiError(400, f"{field} must be at most {maximum}.")
    return result


def valid_date(value, field):
    value = clean_text(value, field, 10)
    try:
        date.fromisoformat(value)
    except ValueError:
        raise ApiError(400, f"{field} must be a valid YYYY-MM-DD date.") from None
    return value


class GrapeHandler(BaseHTTPRequestHandler):
    server_version = "VineyardFieldbook/1.0"

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)

    def send_json(self, status, data, cookie=None, clear_cookie=False):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if cookie:
            self.send_header("Set-Cookie", f"grape_session={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}")
        elif clear_cookie:
            self.send_header("Set-Cookie", "grape_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(400, "Invalid request length.") from None
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "Request body is too large.")
        if length <= 0:
            raise ApiError(400, "A JSON request body is required.")
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ApiError(400, "Request body must be valid JSON.") from None
        if not isinstance(data, dict):
            raise ApiError(400, "Request body must be a JSON object.")
        return data

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = next(
            (part.strip().split("=", 1)[1] for part in cookie.split(";")
             if part.strip().startswith("grape_session=")),
            "",
        )
        if not token or len(token) > 128:
            raise ApiError(401, "Sign in to continue.")
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with database() as db:
            row = db.execute(
                """SELECT users.id, users.name, users.email, users.role
                   FROM sessions JOIN users ON users.id = sessions.user_id
                   WHERE sessions.token_hash = ? AND sessions.expires_at > ?""",
                (token_hash, int(time.time())),
            ).fetchone()
        if row is None:
            raise ApiError(401, "Your session has expired. Sign in again.")
        return dict(row)

    def require(self, permission):
        user = self.current_user()
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise ApiError(403, "Your account role cannot perform this action.")
        return user

    def check_same_origin(self):
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.netloc.lower() != self.headers.get("Host", "").lower():
                raise ApiError(403, "Cross-origin requests are not allowed.")

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                self.api_get(path)
                return
            if path not in ("/", "/index.html", "/Tech%20App%20for%20Grape%20Crop.html", "/Tech App for Grape Crop.html"):
                self.send_error(404)
                return
            content = APP_FILE.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(content)
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except Exception:
            logging.exception("GET request failed")
            self.send_json(500, {"error": "The server could not complete the request."})

    def do_POST(self):
        try:
            self.check_same_origin()
            self.api_post(urlsplit(self.path).path, self.read_json())
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except Exception:
            logging.exception("POST request failed")
            self.send_json(500, {"error": "The server could not complete the request."})

    def do_PATCH(self):
        try:
            self.check_same_origin()
            self.api_patch(urlsplit(self.path).path, self.read_json())
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except Exception:
            logging.exception("PATCH request failed")
            self.send_json(500, {"error": "The server could not complete the request."})

    def do_DELETE(self):
        try:
            self.check_same_origin()
            self.api_delete(urlsplit(self.path).path)
        except ApiError as error:
            self.send_json(error.status, {"error": error.message})
        except Exception:
            logging.exception("DELETE request failed")
            self.send_json(500, {"error": "The server could not complete the request."})

    def api_get(self, path):
        if path == "/api/me":
            self.send_json(200, {"user": self.current_user()})
        elif path == "/api/prices":
            self.require("prices:read")
            with database() as db:
                rows = db.execute(
                    """SELECT prices.id, prices.user_id, prices.market, prices.variety,
                              prices.price, prices.unit, prices.price_date, prices.source,
                              users.name AS submitted_by
                       FROM prices JOIN users ON users.id = prices.user_id
                       ORDER BY prices.price_date DESC, prices.id DESC"""
                ).fetchall()
            self.send_json(200, {"prices": [dict(row) for row in rows]})
        elif path in ("/api/diagnoses", "/api/weather"):
            user = self.current_user()
            self.require("records:read_all" if user["role"] in ("admin", "advisor") else "records:read_own")
            table = "diagnoses" if path == "/api/diagnoses" else "weather_records"
            with database() as db:
                rows = db.execute(
                    f"""SELECT {table}.*, users.name AS submitted_by
                        FROM {table} JOIN users ON users.id = {table}.user_id
                        {' ' if user['role'] in ('admin', 'advisor') else 'WHERE user_id = ?'}
                        ORDER BY {table}.created_at DESC LIMIT 100""",
                    () if user["role"] in ("admin", "advisor") else (user["id"],),
                ).fetchall()
            self.send_json(200, {"records": [dict(row) for row in rows]})
        elif path == "/api/admin/users":
            self.require("users:manage")
            with database() as db:
                rows = db.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()
            self.send_json(200, {"users": [dict(row) for row in rows]})
        else:
            raise ApiError(404, "API endpoint not found.")

    def api_post(self, path, data):
        if path == "/api/register":
            name = clean_text(data.get("name"), "Name", 80)
            email = clean_text(data.get("email"), "Email", 254).lower()
            password = data.get("password")
            if not EMAIL_RE.fullmatch(email):
                raise ApiError(400, "Enter a valid email address.")
            if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
                raise ApiError(400, "Password must be between 12 and 256 characters.")
            token = secrets.token_urlsafe(32)
            with database() as db:
                try:
                    cursor = db.execute(
                        "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'farmer')",
                        (name, email, password_digest(password)),
                    )
                except sqlite3.IntegrityError:
                    raise ApiError(409, "An account with that email already exists.") from None
                user_id = cursor.lastrowid
                db.execute(
                    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (hashlib.sha256(token.encode()).hexdigest(), user_id, int(time.time()) + SESSION_SECONDS),
                )
            self.send_json(201, {"user": {"id": user_id, "name": name, "email": email, "role": "farmer"}}, cookie=token)
        elif path == "/api/login":
            email = clean_text(data.get("email"), "Email", 254).lower()
            password = data.get("password")
            if not isinstance(password, str) or len(password) > 256:
                raise ApiError(401, "Email or password is incorrect.")
            with database() as db:
                row = db.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone()
                if row is None or not password_matches(password, row["password_hash"]):
                    raise ApiError(401, "Email or password is incorrect.")
                token = secrets.token_urlsafe(32)
                db.execute(
                    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (hashlib.sha256(token.encode()).hexdigest(), row["id"], int(time.time()) + SESSION_SECONDS),
                )
                user = {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}
                db.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))
            self.send_json(200, {"user": user}, cookie=token)
        elif path == "/api/logout":
            token = self.request_token()
            if token:
                with database() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
            self.send_json(200, {"ok": True}, clear_cookie=True)
        elif path == "/api/prices":
            user = self.require("prices:create")
            market = clean_text(data.get("market"), "Market", 120)
            variety = clean_text(data.get("variety"), "Variety", 120)
            price = number(data.get("price"), "Price", minimum=0.01, maximum=1_000_000_000)
            unit = data.get("unit")
            if unit not in ("kg", "q"):
                raise ApiError(400, "Unit must be kg or q.")
            price_date = valid_date(data.get("price_date"), "Price date")
            if price_date > date.today().isoformat():
                raise ApiError(400, "Price date cannot be in the future.")
            source = clean_text(data.get("source", ""), "Source", 160, required=False)
            with database() as db:
                cursor = db.execute(
                    """INSERT INTO prices (user_id, market, variety, price, unit, price_date, source)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (user["id"], market, variety, price, unit, price_date, source),
                )
            self.send_json(201, {"id": cursor.lastrowid})
        elif path == "/api/diagnoses":
            user = self.require("records:create")
            part = clean_text(data.get("plant_part"), "Plant part", 20)
            if part not in ("leaf", "shoot", "bunch"):
                raise ApiError(400, "Plant part must be leaf, shoot, or bunch.")
            symptoms = data.get("symptoms")
            results = data.get("results")
            if not isinstance(symptoms, list) or len(symptoms) > 100 or not all(isinstance(x, str) and len(x) <= 300 for x in symptoms):
                raise ApiError(400, "Symptoms must be a list of at most 100 short text values.")
            if not isinstance(results, list) or len(results) > 20 or not all(isinstance(x, str) and len(x) <= 300 for x in results):
                raise ApiError(400, "Results must be a list of at most 20 short text values.")
            weather = clean_text(data.get("recent_weather", ""), "Recent weather", 20, required=False)
            if weather not in ("", "wet", "cloud", "dry"):
                raise ApiError(400, "Recent weather is invalid.")
            with database() as db:
                cursor = db.execute(
                    """INSERT INTO diagnoses (user_id, plant_part, symptoms, recent_weather, results)
                       VALUES (?, ?, ?, ?, ?)""",
                    (user["id"], part, json.dumps(symptoms), weather, json.dumps(results)),
                )
            self.send_json(201, {"id": cursor.lastrowid})
        elif path == "/api/weather":
            user = self.require("records:create")
            rain_chance = number(data.get("rain_chance"), "Rain chance", 0, 100)
            expected_rain = number(data.get("expected_rain"), "Expected rain", 0, 10000)
            humidity = number(data.get("humidity"), "Humidity", 0, 100)
            sky = data.get("sky")
            if sky not in ("clear", "part", "over"):
                raise ApiError(400, "Sky is invalid.")
            min_temp = number(data.get("min_temp"), "Minimum temperature", -80, 80, required=False)
            max_temp = number(data.get("max_temp"), "Maximum temperature", -80, 80, required=False)
            if min_temp is not None and max_temp is not None and min_temp > max_temp:
                raise ApiError(400, "Minimum temperature cannot exceed maximum temperature.")
            source = clean_text(data.get("source", ""), "Source", 160, required=False)
            issued_on = valid_date(data.get("issued_on"), "Issued date")
            hints = data.get("hints")
            if not isinstance(hints, list) or len(hints) > 10 or not all(isinstance(x, str) and len(x) <= 500 for x in hints):
                raise ApiError(400, "Hints must be a list of at most 10 short text values.")
            with database() as db:
                cursor = db.execute(
                    """INSERT INTO weather_records
                       (user_id, rain_chance, expected_rain, humidity, sky, min_temp, max_temp, source, issued_on, hints)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (user["id"], rain_chance, expected_rain, humidity, sky, min_temp, max_temp, source, issued_on, json.dumps(hints)),
                )
            self.send_json(201, {"id": cursor.lastrowid})
        else:
            raise ApiError(404, "API endpoint not found.")

    def api_patch(self, path, data):
        match = re.fullmatch(r"/api/admin/users/(\d+)/role", path)
        if not match:
            raise ApiError(404, "API endpoint not found.")
        admin = self.require("users:manage")
        user_id = int(match.group(1))
        role = data.get("role")
        if role not in ROLES:
            raise ApiError(400, "Role must be farmer, advisor, or admin.")
        with database() as db:
            target = db.execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
            if target is None:
                raise ApiError(404, "User not found.")
            if target["role"] == "admin" and role != "admin":
                count = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
                if count <= 1:
                    raise ApiError(409, "The last administrator cannot be demoted.")
            db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            result = db.execute("SELECT id, name, email, role FROM users WHERE id = ?", (user_id,)).fetchone()
        self.send_json(200, {"user": dict(result), "notice": "The user must sign in again for the new role to take effect."})

    def api_delete(self, path):
        if path == "/api/prices":
            user = self.current_user()
            self.require("prices:delete_all" if user["role"] == "admin" else "prices:delete_own")
            with database() as db:
                if user["role"] == "admin":
                    db.execute("DELETE FROM prices")
                else:
                    db.execute("DELETE FROM prices WHERE user_id = ?", (user["id"],))
            self.send_json(200, {"ok": True})
            return
        match = re.fullmatch(r"/api/prices/(\d+)", path)
        if match:
            user = self.current_user()
            permission = "prices:delete_all" if user["role"] == "admin" else "prices:delete_own"
            self.require(permission)
            with database() as db:
                price = db.execute("SELECT user_id FROM prices WHERE id = ?", (int(match.group(1)),)).fetchone()
                if price is None:
                    raise ApiError(404, "Price entry not found.")
                if user["role"] != "admin" and price["user_id"] != user["id"]:
                    raise ApiError(403, "You can only remove prices you submitted.")
                db.execute("DELETE FROM prices WHERE id = ?", (int(match.group(1)),))
            self.send_json(200, {"ok": True})
            return
        raise ApiError(404, "API endpoint not found.")

    def request_token(self):
        cookie = self.headers.get("Cookie", "")
        return next(
            (part.strip().split("=", 1)[1] for part in cookie.split(";")
             if part.strip().startswith("grape_session=")),
            "",
        )


def create_admin(email, name):
    name = clean_text(name, "Name", 80)
    password = getpass("Admin password (at least 12 characters): ")
    if len(password) < 12 or len(password) > 256:
        raise SystemExit("Password must be between 12 and 256 characters.")
    with database() as db:
        try:
            db.execute(
                "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
                (name, email.lower(), password_digest(password)),
            )
        except sqlite3.IntegrityError:
            raise SystemExit("That account already exists. Promote an account from the admin panel instead.") from None
    print(f"Administrator account created for {email.lower()}.")


def main():
    init_db()
    if len(sys.argv) > 1:
        if len(sys.argv) == 3 and sys.argv[1] == "--create-admin":
            email = sys.argv[2].strip()
            if not EMAIL_RE.fullmatch(email):
                raise SystemExit("Provide a valid email address.")
            create_admin(email, input("Admin display name: ").strip())
            return
        raise SystemExit("Usage: python server.py [--create-admin EMAIL]")
    host = os.environ.get("GRAPE_HOST", "127.0.0.1")
    port = int(os.environ.get("GRAPE_PORT", "8000"))
    server = ThreadingHTTPServer((host, port), GrapeHandler)
    server.daemon_threads = True
    print(f"Vineyard Fieldbook running at http://{host}:{port}")
    print(f"SQLite database: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
