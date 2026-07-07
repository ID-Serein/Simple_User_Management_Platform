import hmac
import json
import os
import secrets
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_USER_STORE = BASE_DIR / "data" / "users.json"
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


def _load_local_env():
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc


def _build_secret_key():
    secret_key = os.environ.get("FLASK_SECRET_KEY")
    if secret_key:
        if len(secret_key) < 32:
            raise RuntimeError("FLASK_SECRET_KEY must contain at least 32 characters")
        return secret_key

    if os.environ.get("FLASK_ENV") == "production" or _env_bool("REQUIRE_CONFIGURED_SECRET"):
        raise RuntimeError("FLASK_SECRET_KEY is required outside local development")

    return secrets.token_urlsafe(48)


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=_build_secret_key(),
        USER_STORE_PATH=os.environ.get("USER_STORE_PATH", str(DEFAULT_USER_STORE)),
        INITIAL_ADMIN_USERNAME=os.environ.get("INITIAL_ADMIN_USERNAME", "admin"),
        INITIAL_ADMIN_PASSWORD=os.environ.get("INITIAL_ADMIN_PASSWORD"),
        INITIAL_ADMIN_EMAIL=os.environ.get("INITIAL_ADMIN_EMAIL", ""),
        INITIAL_ADMIN_PHONE=os.environ.get("INITIAL_ADMIN_PHONE", ""),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
        SESSION_COOKIE_SECURE=_env_bool("SESSION_COOKIE_SECURE"),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=_env_int("SESSION_MINUTES", 30)),
        LOGIN_RATE_LIMIT_MAX_ATTEMPTS=_env_int("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5),
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=_env_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 60),
        SECURITY_ENABLE_HSTS=_env_bool("SECURITY_ENABLE_HSTS"),
        USER_STORE_READY=False,
    )

    if test_config:
        app.config.update(test_config)

    if len(str(app.config["SECRET_KEY"])) < 32:
        raise RuntimeError("SECRET_KEY must contain at least 32 characters")

    login_attempts = {}

    def ensure_user_store():
        if app.config["USER_STORE_READY"]:
            return
        _initialize_user_store(app.config)
        app.config["USER_STORE_READY"] = True

    def load_users():
        ensure_user_store()
        return _load_users(app.config["USER_STORE_PATH"])

    def current_user():
        username = session.get("username")
        if not username:
            return None

        user = load_users().get(username)
        if not user:
            session.clear()
            return None

        return _public_user(user)

    def csrf_token():
        token = session.get("_csrf_token")
        if not isinstance(token, str) or len(token) < 32:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def validate_csrf():
        expected = session.get("_csrf_token")
        submitted = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, submitted):
            abort(400)

    def rate_limit_key(username):
        remote_addr = request.remote_addr or "unknown"
        normalized_username = (username or "").strip().lower()
        return f"{remote_addr}:{normalized_username}"

    def prune_attempts(key):
        now = time.monotonic()
        window = app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"]
        attempts = [item for item in login_attempts.get(key, []) if now - item < window]
        login_attempts[key] = attempts
        return attempts

    def is_rate_limited(key):
        attempts = prune_attempts(key)
        return len(attempts) >= app.config["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"]

    def record_failed_login(key):
        attempts = prune_attempts(key)
        attempts.append(time.monotonic())
        login_attempts[key] = attempts

    def clear_failed_logins(key):
        login_attempts.pop(key, None)

    @app.context_processor
    def inject_security_helpers():
        return {"csrf_token": csrf_token}

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'",
        )

        if app.config["SECURITY_ENABLE_HSTS"]:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )

        if session.get("username"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")

        return response

    @app.route("/")
    def index():
        user_info = current_user()
        username = user_info["username"] if user_info else None
        return render_template("index.html", username=username, user_info=user_info)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = rate_limit_key(username)

        if is_rate_limited(key):
            return render_template("login.html", error="登录尝试过多，请稍后再试"), 429

        if not _valid_login_input(username, password):
            record_failed_login(key)
            return render_template("login.html", error="用户名或密码错误"), 401

        users = load_users()
        user = users.get(username)
        password_hash = user.get("password_hash") if user else DUMMY_PASSWORD_HASH

        if user and check_password_hash(password_hash, password):
            clear_failed_logins(key)
            session.clear()
            session.permanent = True
            session["username"] = username
            return redirect(url_for("index"))

        record_failed_login(key)
        return render_template("login.html", error="用户名或密码错误"), 401

    @app.route("/logout", methods=["POST"])
    def logout():
        validate_csrf()
        session.clear()
        return redirect(url_for("index"))

    return app


def _valid_login_input(username, password):
    return 1 <= len(username) <= 64 and 1 <= len(password) <= 128


def _initialize_user_store(config):
    user_store_path = Path(config["USER_STORE_PATH"])
    if user_store_path.exists():
        return

    users = {}
    initial_password = config.get("INITIAL_ADMIN_PASSWORD")

    if initial_password:
        if len(initial_password) < 12:
            raise RuntimeError("INITIAL_ADMIN_PASSWORD must contain at least 12 characters")

        username = (config.get("INITIAL_ADMIN_USERNAME") or "admin").strip()
        if not username or len(username) > 64:
            raise RuntimeError("INITIAL_ADMIN_USERNAME must be 1 to 64 characters long")

        users[username] = {
            "username": username,
            "password_hash": generate_password_hash(initial_password),
            "role": "admin",
            "email": config.get("INITIAL_ADMIN_EMAIL", ""),
            "phone": config.get("INITIAL_ADMIN_PHONE", ""),
            "balance": 0,
        }

    _save_users(user_store_path, users)


def _load_users(user_store_path):
    path = Path(user_store_path)
    if not path.exists():
        return {}

    try:
        users = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid user store JSON: {path}") from exc

    if not isinstance(users, dict):
        raise RuntimeError("User store must contain a JSON object")

    return users


def _save_users(user_store_path, users):
    path = Path(user_store_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)


def _public_user(user):
    return {
        "username": user.get("username", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
        "role": user.get("role", "user"),
        "balance": user.get("balance", 0),
    }


app = create_app()


if __name__ == "__main__":
    debug = _env_bool("FLASK_DEBUG")
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")

    if debug and host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Refusing to run Flask debug mode on a non-local interface")

    app.run(
        debug=debug,
        host=host,
        port=_env_int("FLASK_RUN_PORT", 5000),
    )
