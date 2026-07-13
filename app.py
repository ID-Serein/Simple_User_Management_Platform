import hmac
import json
import os
import secrets
import sqlite3
import time
import uuid
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_USER_STORE = BASE_DIR / "data" / "users.json"
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))
ALLOWED_UPLOAD_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_UPLOAD_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
UPLOAD_MAX_BYTES = 2 * 1024 * 1024


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


def init_db():
    """Initialize SQLite database with users table and default users."""
    db_dir = BASE_DIR / "data"
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "users.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()
    print("[init_db] Database initialized with tables and default users.")


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
        MAX_CONTENT_LENGTH=UPLOAD_MAX_BYTES,
        UPLOAD_MAX_BYTES=UPLOAD_MAX_BYTES,
        UPLOAD_FOLDER=str(BASE_DIR / "static" / "uploads"),
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


    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            msg = request.args.get("msg", "")
            return render_template("login.html", msg=msg)

        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        key = rate_limit_key(username)

        if is_rate_limited(key):
            return render_template("login.html", error="登录尝试过多，请稍后再试", msg=""), 429

        if not _valid_login_input(username, password):
            record_failed_login(key)
            return render_template("login.html", error="用户名或密码错误", msg=""), 401

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
        return render_template("login.html", error="用户名或密码错误", msg=""), 401

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        db_path = BASE_DIR / "data" / "users.db"
        conn = sqlite3.connect(str(db_path))
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}")
        try:
            c.execute(sql)
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在")
        conn.close()
        return redirect(url_for("login", msg="注册成功，请登录"))

    @app.route("/logout", methods=["POST"])
    def logout():
        validate_csrf()
        session.clear()
        return redirect(url_for("index"))

    @app.route("/search")
    def search():
        keyword = request.args.get("keyword", "")
        db_path = BASE_DIR / "data" / "users.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}")
        c.execute(sql)
        results = [dict(row) for row in c.fetchall()]
        conn.close()

        user_info = current_user()
        username = user_info["username"] if user_info else None
        return render_template("index.html", username=username, user_info=user_info, search_results=results, keyword=keyword)

    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if "username" not in session:
            return redirect(url_for("login"))

        if request.method == "GET":
            return render_template("upload.html")

        validate_csrf()
        file = request.files.get("file")
        if file is None or file.filename == "":
            return render_template("upload.html", error="请选择一个文件"), 400

        upload_dir = Path(app.config["UPLOAD_FOLDER"])
        upload_dir = _safe_upload_dir(upload_dir)

        is_valid, error, image_ext, payload = _validate_uploaded_image(
            file,
            app.config["UPLOAD_MAX_BYTES"],
        )
        if not is_valid:
            return render_template("upload.html", error=error), 400

        filename = f"{uuid.uuid4().hex}.{image_ext}"
        file_path = (upload_dir / filename).resolve()
        if file_path.parent != upload_dir:
            abort(400)

        file_path.write_bytes(payload)

        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", file_url=file_url, filename=filename)

    @app.route("/page")
    def page():
        name = request.args.get("name", "")
        if not name:
            return "缺少 name 参数", 400

        # help 页面使用完整模板
        if name == "help":
            return render_template("help.html")

        # 直接拼接用户输入到路径（含路径遍历漏洞）
        page_path = os.path.join("pages", name)
        if os.path.isfile(page_path):
            content = Path(page_path).read_text(encoding="utf-8")
        elif os.path.isfile(page_path + ".html"):
            content = Path(page_path + ".html").read_text(encoding="utf-8")
        else:
            content = "页面不存在"

        user_info = current_user()
        username = user_info["username"] if user_info else None
        user_id = _get_user_id(username) if username else None
        return render_template("index.html", username=username, user_info=user_info, user_id=user_id, page_content=content)

    def _get_user_by_id(user_id):
        """根据数字 ID 从用户数据中查找用户（1-based 索引）"""
        users = load_users()
        usernames = sorted(users.keys())
        try:
            idx = int(user_id) - 1
            if idx < 0 or idx >= len(usernames):
                return None
            username = usernames[idx]
            user = users[username]
            user["id"] = idx + 1
            return user
        except (ValueError, IndexError):
            return None

    def _get_user_id(username):
        """获取用户名对应的数字 ID"""
        users = load_users()
        usernames = sorted(users.keys())
        try:
            return usernames.index(username) + 1
        except ValueError:
            return None

    @app.route("/")
    def index():
        user_info = current_user()
        username = user_info["username"] if user_info else None
        user_id = _get_user_id(username) if username else None
        return render_template("index.html", username=username, user_info=user_info, user_id=user_id)

    @app.route("/profile")
    def profile():
        # 检查登录
        current_username = session.get("username")
        if not current_username:
            return redirect(url_for("login"))

        user_id = request.args.get("user_id")
        if not user_id:
            return "缺少 user_id 参数", 400

        # 校验只能查看自己的资料
        users = load_users()
        usernames = sorted(users.keys())
        try:
            idx = int(user_id) - 1
            if idx < 0 or idx >= len(usernames):
                return "用户不存在", 404
            request_username = usernames[idx]
        except (ValueError, IndexError):
            return "用户不存在", 404

        if request_username != current_username:
            return "无权查看其他用户资料", 403

        user = users[request_username]
        user["id"] = idx + 1

        recharged = request.args.get("recharged", "")
        return render_template("profile.html", user=user, recharged=recharged)

    @app.route("/recharge", methods=["POST"])
    def recharge():
        # 检查登录
        current_username = session.get("username")
        if not current_username:
            return redirect(url_for("login"))

        user_id = request.form.get("user_id")
        amount = request.form.get("amount", "0")

        users = load_users()
        usernames = sorted(users.keys())
        try:
            idx = int(user_id) - 1
            if idx < 0 or idx >= len(usernames):
                return "用户不存在", 404
            username = usernames[idx]
        except (ValueError, IndexError):
            return "用户不存在", 404

        # 校验只能给自己充值
        if username != current_username:
            return "无权操作其他用户账户", 403

        try:
            amount_val = float(amount)
        except ValueError:
            return "无效的金额", 400

        # 校验金额为正数
        if amount_val <= 0:
            return "充值金额必须为正数", 400

        # 单次充值上限
        if amount_val > 100000:
            return "单次充值金额不能超过 100000", 400

        users[username]["balance"] = users[username].get("balance", 0) + amount_val
        _save_users(app.config["USER_STORE_PATH"], users)

        return redirect(url_for("profile", user_id=user_id, recharged=amount))

    return app


def _valid_login_input(username, password):
    return 1 <= len(username) <= 64 and 1 <= len(password) <= 128


def _safe_upload_dir(upload_dir):
    base_upload_dir = (BASE_DIR / "static" / "uploads").resolve()
    resolved_upload_dir = Path(upload_dir).resolve()

    if resolved_upload_dir != base_upload_dir:
        raise RuntimeError("UPLOAD_FOLDER must be the static/uploads directory")

    resolved_upload_dir.mkdir(parents=True, exist_ok=True)
    return resolved_upload_dir


def _validate_uploaded_image(file_storage, max_bytes):
    original_name = file_storage.filename or ""
    suffix = Path(original_name).suffix.lower().lstrip(".")
    if suffix not in ALLOWED_UPLOAD_EXTENSIONS:
        return False, "仅支持 jpg、jpeg、png、gif、webp 图片", None, None

    declared_mime = (file_storage.mimetype or "").lower()
    if declared_mime not in ALLOWED_UPLOAD_MIME_TYPES:
        return False, "文件 MIME 类型不合法", None, None

    payload = file_storage.stream.read(max_bytes + 1)
    file_storage.stream.seek(0)
    if not payload:
        return False, "文件内容为空", None, None
    if len(payload) > max_bytes:
        return False, "文件大小不能超过 2MB", None, None

    detected_ext = _detect_image_extension(payload)
    if detected_ext is None:
        return False, "文件内容不是有效图片", None, None

    normalized_suffix = "jpg" if suffix == "jpeg" else suffix
    if normalized_suffix != detected_ext:
        return False, "文件扩展名与图片内容不匹配", None, None

    return True, "", detected_ext, payload


def _detect_image_extension(payload):
    if payload.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(payload) >= 12 and payload.startswith(b"RIFF") and payload[8:12] == b"WEBP":
        return "webp"
    return None


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
init_db()


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
