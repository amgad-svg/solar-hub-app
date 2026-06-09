import csv
import html
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


APP_NAME = "SolarPro ERP"
ROLES = ("مدير", "محاسب", "فني تركيبات")

BASE_DIR = Path(__file__).resolve().parent


def resolve_database_path() -> Path:
    explicit_path = os.environ.get("SQLITE_DB_PATH") or os.environ.get("DATABASE_PATH")
    if explicit_path:
        return Path(explicit_path).expanduser().resolve()

    render_disk = Path("/var/data")
    if render_disk.exists() and os.access(render_disk, os.W_OK):
        return render_disk / "solarpro.sqlite3"

    data_dir = BASE_DIR / "data"
    return data_dir / "solarpro.sqlite3"


DB_PATH = resolve_database_path()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", str(DB_PATH.parent / "backups"))).expanduser().resolve()
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production-" + secrets.token_hex(16))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            qty INTEGER NOT NULL DEFAULT 0,
            cost REAL NOT NULL DEFAULT 0,
            price REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            customer_phone TEXT NOT NULL DEFAULT '',
            date TEXT NOT NULL,
            labor_cost REAL NOT NULL DEFAULT 0,
            expenses_cost REAL NOT NULL DEFAULT 0,
            grand_total REAL NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            product_id INTEGER,
            product_name TEXT NOT NULL,
            qty INTEGER NOT NULL,
            price REAL NOT NULL DEFAULT 0,
            cost REAL NOT NULL DEFAULT 0,
            FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES inventory(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            amount REAL NOT NULL DEFAULT 0,
            category TEXT NOT NULL DEFAULT '',
            date TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            project_details TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'قيد التنفيذ'
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_inventory_name ON inventory(name);
        CREATE INDEX IF NOT EXISTS idx_invoices_date ON invoices(date);
        CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON invoice_items(invoice_id);
        CREATE INDEX IF NOT EXISTS idx_expenses_date ON expenses(date);
        CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(status);
        """
    )

    existing = db.execute("SELECT id FROM users WHERE username = ?", ("amgad",)).fetchone()
    if existing is None:
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("amgad", generate_password_hash("123456"), "مدير"),
        )

    db.commit()
    db.close()


def backup_db_after_invoice():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_name = f"solarpro_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}.sqlite3"
    backup_path = BACKUP_DIR / backup_name

    source = sqlite3.connect(DB_PATH)
    destination = sqlite3.connect(backup_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

    backups = sorted(BACKUP_DIR.glob("solarpro_backup_*.sqlite3"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old_backup in backups[30:]:
        try:
            old_backup.unlink()
        except OSError:
            pass


def csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    csrf_token()
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        submitted = (
            request.form.get("_csrf_token")
            or request.headers.get("X-CSRF-Token")
            or request.headers.get("X-CSRFToken")
        )
        saved = session.get("_csrf_token")
        if not saved or not submitted or not secrets.compare_digest(saved, submitted):
            abort(400, description="Invalid CSRF token.")


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    if "current_user" not in g:
        g.current_user = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return g.current_user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "مدير":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def clean_text(value, field_name, max_len=255, required=True):
    value = (value or "").strip()
    value = re.sub(r"\s+", " ", value)
    if required and not value:
        raise ValueError(f"{field_name} مطلوب.")
    if len(value) > max_len:
        raise ValueError(f"{field_name} طويل جداً.")
    return value


def clean_multiline(value, field_name, max_len=2000, required=False):
    value = (value or "").strip()
    if required and not value:
        raise ValueError(f"{field_name} مطلوب.")
    if len(value) > max_len:
        raise ValueError(f"{field_name} طويل جداً.")
    return value


def parse_int(value, field_name, minimum=0):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} يجب أن يكون رقماً صحيحاً.")
    if number < minimum:
        raise ValueError(f"{field_name} يجب ألا يقل عن {minimum}.")
    return number


def parse_money(value, field_name, minimum=0):
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} يجب أن يكون رقماً.")
    if number < minimum:
        raise ValueError(f"{field_name} يجب ألا يقل عن {minimum}.")
    return round(number, 2)


def format_money(value):
    try:
        return f"${float(value or 0):,.2f}"
    except (TypeError, ValueError):
        return "$0.00"


app.jinja_env.filters["money"] = format_money


def scalar(sql, params=()):
    row = get_db().execute(sql, params).fetchone()
    if row is None:
        return 0
    value = row[0]
    return value if value is not None else 0


def calculate_metrics():
    gross_sales = scalar("SELECT COALESCE(SUM(grand_total), 0) FROM invoices")
    product_profit = scalar("SELECT COALESCE(SUM((price - cost) * qty), 0) FROM invoice_items")
    labor_profit = scalar("SELECT COALESCE(SUM(labor_cost), 0) FROM invoices")
    invoice_direct_expenses = scalar("SELECT COALESCE(SUM(expenses_cost), 0) FROM invoices")
    recorded_expenses = scalar("SELECT COALESCE(SUM(amount), 0) FROM expenses")
    total_expenses = float(recorded_expenses or 0) + float(invoice_direct_expenses or 0)
    net_profit = float(product_profit or 0) + float(labor_profit or 0) - total_expenses
    inventory_pieces = scalar("SELECT COALESCE(SUM(qty), 0) FROM inventory")
    active_projects = scalar("SELECT COUNT(*) FROM customers WHERE status = ?", ("قيد التنفيذ",))
    return {
        "gross_sales": round(float(gross_sales or 0), 2),
        "product_profit": round(float(product_profit or 0), 2),
        "labor_profit": round(float(labor_profit or 0), 2),
        "total_expenses": round(float(total_expenses or 0), 2),
        "net_profit": round(float(net_profit or 0), 2),
        "inventory_pieces": int(inventory_pieces or 0),
        "active_projects": int(active_projects or 0),
    }


def safe_filename(value):
    value = re.sub(r"[^\w\u0600-\u06FF.-]+", "_", str(value), flags=re.UNICODE).strip("_")
    return value or "file"


BASE_HTML = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>{{ title }} · {{ app_name }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: { cairo: ['Cairo', 'sans-serif'] },
                    boxShadow: {
                        glow: '0 0 35px rgba(14, 165, 233, .18)',
                        soft: '0 18px 60px rgba(0,0,0,.35)'
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Cairo', sans-serif; }
        .glass { background: rgba(15, 23, 42, .72); border: 1px solid rgba(148, 163, 184, .16); backdrop-filter: blur(18px); }
        .input { width: 100%; border-radius: 1rem; border: 1px solid rgba(148, 163, 184, .2); background: rgba(15, 23, 42, .92); padding: .8rem 1rem; color: #e5e7eb; outline: none; transition: .2s; }
        .input:focus { border-color: rgba(56, 189, 248, .75); box-shadow: 0 0 0 4px rgba(14, 165, 233, .12); }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: .5rem; border-radius: 1rem; padding: .75rem 1rem; font-weight: 800; transition: .2s; white-space: nowrap; }
        .btn-primary { background: linear-gradient(135deg, #0284c7, #0891b2, #14b8a6); color: white; box-shadow: 0 12px 30px rgba(8,145,178,.24); }
        .btn-primary:hover { transform: translateY(-1px); filter: brightness(1.08); }
        .btn-muted { background: rgba(30, 41, 59, .92); color: #e2e8f0; border: 1px solid rgba(148, 163, 184, .16); }
        .btn-muted:hover { background: rgba(51, 65, 85, .95); }
        .btn-danger { background: rgba(220, 38, 38, .16); color: #fecaca; border: 1px solid rgba(248, 113, 113, .25); }
        .btn-danger:hover { background: rgba(220, 38, 38, .28); }
        .table-head { color: #93c5fd; font-size: .78rem; letter-spacing: .03em; }
        .scrollbar-thin::-webkit-scrollbar { height: 8px; width: 8px; }
        .scrollbar-thin::-webkit-scrollbar-thumb { background: rgba(148,163,184,.35); border-radius: 999px; }
    </style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
    <div class="fixed inset-0 -z-10">
        <div class="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(6,182,212,.18),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(59,130,246,.14),transparent_35%)]"></div>
        <div class="absolute inset-0 bg-[linear-gradient(to_bottom,rgba(15,23,42,.35),rgba(2,6,23,1))]"></div>
    </div>

    <button onclick="toggleSidebar()" class="lg:hidden fixed top-4 right-4 z-50 btn btn-primary px-3 py-2">
        <i class="fa-solid fa-bars"></i>
    </button>

    <aside id="sidebar" class="fixed top-0 right-0 z-40 h-screen w-80 translate-x-full lg:translate-x-0 transition-transform duration-300 glass shadow-soft">
        <div class="flex h-full flex-col">
            <div class="p-6 border-b border-slate-700/50">
                <div class="flex items-center gap-3">
                    <div class="h-12 w-12 rounded-2xl bg-gradient-to-br from-sky-500 to-teal-400 flex items-center justify-center shadow-glow">
                        <i class="fa-solid fa-solar-panel text-white text-xl"></i>
                    </div>
                    <div>
                        <div class="text-xl font-black">{{ app_name }}</div>
                        <div class="text-xs text-slate-400">نظام إدارة الطاقة الشمسية</div>
                    </div>
                </div>
            </div>

            <nav class="flex-1 p-4 space-y-2 overflow-y-auto scrollbar-thin">
                <a href="{{ url_for('dashboard') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'dashboard' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-chart-line w-5"></i><span>لوحة التحكم</span>
                </a>
                <a href="{{ url_for('inventory') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'inventory' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-warehouse w-5"></i><span>المستودع والمخزن</span>
                </a>
                <a href="{{ url_for('sales') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'sales' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-file-invoice-dollar w-5"></i><span>المبيعات والفواتير</span>
                </a>
                <a href="{{ url_for('expenses') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'expenses' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-wallet w-5"></i><span>المصروفات</span>
                </a>
                <a href="{{ url_for('customers') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'customers' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-users-viewfinder w-5"></i><span>العملاء والمشاريع</span>
                </a>
                {% if user and user.role == 'مدير' %}
                <a href="{{ url_for('users') }}" class="flex items-center gap-3 rounded-2xl px-4 py-3 font-bold transition {{ 'bg-sky-500/15 text-sky-200 border border-sky-400/20' if active == 'users' else 'text-slate-300 hover:bg-slate-800/70' }}">
                    <i class="fa-solid fa-user-shield w-5"></i><span>إدارة المستخدمين</span>
                </a>
                {% endif %}
            </nav>

            <div class="p-4 border-t border-slate-700/50">
                <div class="rounded-2xl bg-slate-900/70 p-4 border border-slate-700/60 mb-3">
                    <div class="text-sm text-slate-400">المستخدم الحالي</div>
                    <div class="font-black">{{ user.username if user else '' }}</div>
                    <div class="text-xs text-teal-300">{{ user.role if user else '' }}</div>
                </div>
                <a href="{{ url_for('logout') }}" class="btn btn-muted w-full">
                    <i class="fa-solid fa-right-from-bracket"></i> تسجيل الخروج
                </a>
            </div>
        </div>
    </aside>

    <main class="lg:mr-80 min-h-screen">
        <header class="sticky top-0 z-30 bg-slate-950/72 backdrop-blur-xl border-b border-slate-800/90">
            <div class="px-5 md:px-8 py-5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                <div>
                    <h1 class="text-2xl md:text-3xl font-black">{{ title }}</h1>
                    <p class="text-sm text-slate-400">إدارة احترافية للمخزون، المبيعات، المصروفات، والمشاريع.</p>
                </div>
                <div class="text-xs text-slate-400 flex items-center gap-2">
                    <i class="fa-regular fa-clock"></i>
                    <span>{{ now }}</span>
                </div>
            </div>
        </header>

        <section class="p-5 md:p-8">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="space-y-3 mb-6">
                        {% for category, message in messages %}
                            <div class="rounded-2xl px-4 py-3 border {{ 'bg-emerald-500/10 border-emerald-400/20 text-emerald-100' if category == 'success' else 'bg-rose-500/10 border-rose-400/20 text-rose-100' }}">
                                <i class="fa-solid {{ 'fa-circle-check' if category == 'success' else 'fa-triangle-exclamation' }} ml-2"></i>{{ message }}
                            </div>
                        {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}
            {{ content|safe }}
        </section>
    </main>

    <script>
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('translate-x-full');
        }
        function confirmDelete(message) {
            return confirm(message || 'هل أنت متأكد من الحذف؟');
        }
    </script>
    {{ extra_js|safe }}
</body>
</html>
"""


def render_page(title, active, content_template, extra_js="", **context):
    content = render_template_string(content_template, **context)
    return render_template_string(
        BASE_HTML,
        title=title,
        active=active,
        content=content,
        extra_js=extra_js,
        user=current_user(),
        app_name=APP_NAME,
        now=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


LOGIN_HTML = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>تسجيل الدخول · {{ app_name }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Cairo', sans-serif; }
        .glass { background: rgba(15, 23, 42, .74); border: 1px solid rgba(148, 163, 184, .18); backdrop-filter: blur(22px); }
        .input { width: 100%; border-radius: 1rem; border: 1px solid rgba(148, 163, 184, .22); background: rgba(15, 23, 42, .94); padding: .9rem 1rem; color: #e5e7eb; outline: none; }
        .input:focus { border-color: rgba(56, 189, 248, .8); box-shadow: 0 0 0 4px rgba(14, 165, 233, .12); }
    </style>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100 overflow-hidden">
    <div class="absolute inset-0 bg-[radial-gradient(circle_at_20%_10%,rgba(14,165,233,.28),transparent_35%),radial-gradient(circle_at_90%_90%,rgba(20,184,166,.22),transparent_35%)]"></div>
    <div class="relative min-h-screen grid lg:grid-cols-2">
        <section class="hidden lg:flex flex-col justify-center p-16">
            <div class="max-w-xl">
                <div class="h-16 w-16 rounded-3xl bg-gradient-to-br from-sky-500 to-teal-400 flex items-center justify-center shadow-2xl mb-8">
                    <i class="fa-solid fa-solar-panel text-3xl text-white"></i>
                </div>
                <h1 class="text-5xl font-black leading-tight mb-5">SolarPro ERP</h1>
                <p class="text-xl text-slate-300 leading-9">
                    منصة تشغيلية متكاملة لإدارة شركات الطاقة الشمسية: مخزون، فواتير، أرباح، مصروفات، ومتابعة مشاريع.
                </p>
                <div class="mt-10 grid grid-cols-3 gap-4">
                    <div class="glass rounded-3xl p-5"><i class="fa-solid fa-shield-halved text-sky-300 mb-3"></i><div class="font-black">آمن</div></div>
                    <div class="glass rounded-3xl p-5"><i class="fa-solid fa-cloud text-teal-300 mb-3"></i><div class="font-black">جاهز للسحابة</div></div>
                    <div class="glass rounded-3xl p-5"><i class="fa-solid fa-bolt text-amber-300 mb-3"></i><div class="font-black">سريع</div></div>
                </div>
            </div>
        </section>

        <section class="flex items-center justify-center p-6">
            <form method="post" class="glass rounded-[2rem] shadow-2xl p-8 w-full max-w-md">
                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                <div class="text-center mb-8">
                    <div class="mx-auto h-16 w-16 rounded-3xl bg-gradient-to-br from-sky-500 to-teal-400 flex items-center justify-center shadow-2xl mb-4">
                        <i class="fa-solid fa-lock text-2xl text-white"></i>
                    </div>
                    <h2 class="text-3xl font-black">تسجيل الدخول</h2>
                    <p class="text-slate-400 mt-2">أدخل بيانات الوصول للنظام</p>
                </div>

                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="rounded-2xl bg-rose-500/10 border border-rose-400/20 text-rose-100 px-4 py-3 mb-4">
                                <i class="fa-solid fa-triangle-exclamation ml-2"></i>{{ message }}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}

                <label class="block mb-4">
                    <span class="text-sm text-slate-300 font-bold">اسم المستخدم</span>
                    <input class="input mt-2" name="username" autocomplete="username" required autofocus>
                </label>

                <label class="block mb-6">
                    <span class="text-sm text-slate-300 font-bold">كلمة المرور</span>
                    <input class="input mt-2" name="password" type="password" autocomplete="current-password" required>
                </label>

                <button class="w-full rounded-2xl bg-gradient-to-br from-sky-500 to-teal-400 py-4 font-black text-white shadow-2xl hover:brightness-110 transition">
                    <i class="fa-solid fa-arrow-right-to-bracket ml-2"></i> دخول
                </button>

                <div class="mt-6 rounded-2xl bg-slate-900/75 border border-slate-700/60 p-4 text-sm text-slate-400">
                    بيانات المدير الافتراضية:
                    <span class="text-slate-100 font-bold">amgad</span> /
                    <span class="text-slate-100 font-bold">123456</span>
                </div>
            </form>
        </section>
    </div>
</body>
</html>
"""


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "database": str(DB_PATH)})


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = clean_text(request.form.get("username"), "اسم المستخدم", max_len=80, required=True)
        password = request.form.get("password") or ""
        user = get_db().execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            csrf_token()
            flash("تم تسجيل الدخول بنجاح.", "success")
            return redirect(url_for("dashboard"))

        flash("بيانات الدخول غير صحيحة.", "error")

    return render_template_string(LOGIN_HTML, app_name=APP_NAME)


@app.route("/logout")
def logout():
    session.clear()
    flash("تم تسجيل الخروج.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    metrics = calculate_metrics()
    recent_invoices = get_db().execute(
        "SELECT id, customer_name, customer_phone, date, grand_total FROM invoices ORDER BY id DESC LIMIT 8"
    ).fetchall()
    low_stock = get_db().execute(
        "SELECT id, name, category, qty, price FROM inventory WHERE qty <= 5 ORDER BY qty ASC, name ASC LIMIT 8"
    ).fetchall()

    template = """
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-5 mb-8">
        <div class="glass rounded-3xl p-5 shadow-soft">
            <div class="flex items-center justify-between mb-4">
                <div class="text-slate-400 text-sm">Gross Sales</div>
                <div class="h-11 w-11 rounded-2xl bg-sky-500/15 flex items-center justify-center text-sky-300"><i class="fa-solid fa-sack-dollar"></i></div>
            </div>
            <div class="text-3xl font-black">{{ metrics.gross_sales|money }}</div>
            <div class="text-xs text-slate-500 mt-2">إجمالي قيمة الفواتير</div>
        </div>
        <div class="glass rounded-3xl p-5 shadow-soft">
            <div class="flex items-center justify-between mb-4">
                <div class="text-slate-400 text-sm">Net Profits</div>
                <div class="h-11 w-11 rounded-2xl bg-emerald-500/15 flex items-center justify-center text-emerald-300"><i class="fa-solid fa-chart-simple"></i></div>
            </div>
            <div class="text-3xl font-black">{{ metrics.net_profit|money }}</div>
            <div class="text-xs text-slate-500 mt-2">هامش المنتجات + الأجور - المصروفات</div>
        </div>
        <div class="glass rounded-3xl p-5 shadow-soft">
            <div class="flex items-center justify-between mb-4">
                <div class="text-slate-400 text-sm">Inventory Pieces</div>
                <div class="h-11 w-11 rounded-2xl bg-indigo-500/15 flex items-center justify-center text-indigo-300"><i class="fa-solid fa-boxes-stacked"></i></div>
            </div>
            <div class="text-3xl font-black">{{ metrics.inventory_pieces }}</div>
            <div class="text-xs text-slate-500 mt-2">إجمالي القطع المتبقية</div>
        </div>
        <div class="glass rounded-3xl p-5 shadow-soft">
            <div class="flex items-center justify-between mb-4">
                <div class="text-slate-400 text-sm">Active Projects</div>
                <div class="h-11 w-11 rounded-2xl bg-amber-500/15 flex items-center justify-center text-amber-300"><i class="fa-solid fa-person-digging"></i></div>
            </div>
            <div class="text-3xl font-black">{{ metrics.active_projects }}</div>
            <div class="text-xs text-slate-500 mt-2">مشاريع قيد التنفيذ</div>
        </div>
        <div class="glass rounded-3xl p-5 shadow-soft">
            <div class="flex items-center justify-between mb-4">
                <div class="text-slate-400 text-sm">Total Expenses</div>
                <div class="h-11 w-11 rounded-2xl bg-rose-500/15 flex items-center justify-center text-rose-300"><i class="fa-solid fa-receipt"></i></div>
            </div>
            <div class="text-3xl font-black">{{ metrics.total_expenses|money }}</div>
            <div class="text-xs text-slate-500 mt-2">المصروفات المسجلة والمباشرة</div>
        </div>
    </div>

    <div class="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h2 class="text-xl font-black">آخر الفواتير</h2>
                    <p class="text-sm text-slate-400">أحدث عمليات البيع المسجلة</p>
                </div>
                <a href="{{ url_for('sales') }}" class="btn btn-muted text-sm"><i class="fa-solid fa-plus"></i> فاتورة جديدة</a>
            </div>
            <div class="overflow-x-auto scrollbar-thin">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="table-head border-b border-slate-700/70">
                            <th class="py-3 text-right">#</th>
                            <th class="py-3 text-right">العميل</th>
                            <th class="py-3 text-right">الهاتف</th>
                            <th class="py-3 text-right">التاريخ</th>
                            <th class="py-3 text-right">الإجمالي</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for inv in recent_invoices %}
                        <tr class="border-b border-slate-800/70 hover:bg-slate-800/35">
                            <td class="py-3 font-bold">{{ inv.id }}</td>
                            <td class="py-3">{{ inv.customer_name }}</td>
                            <td class="py-3 text-slate-400">{{ inv.customer_phone }}</td>
                            <td class="py-3 text-slate-400">{{ inv.date }}</td>
                            <td class="py-3 font-black text-emerald-300">{{ inv.grand_total|money }}</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="py-8 text-center text-slate-500">لا توجد فواتير بعد.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="glass rounded-3xl p-6 shadow-soft">
            <h2 class="text-xl font-black mb-1">AI Financial Assistant</h2>
            <p class="text-sm text-slate-400 mb-4">اسأل عن الأرباح، المخزون، المصروفات، أو المشاريع.</p>
            <div id="aiBox" class="h-72 overflow-y-auto scrollbar-thin rounded-3xl bg-slate-950/60 border border-slate-800 p-4 space-y-3 mb-4">
                <div class="max-w-[85%] rounded-2xl bg-sky-500/15 border border-sky-400/20 p-3 text-sm">
                    مرحباً، اسألني مثلاً: ما صافي الربح؟ أو كم مخزون الألواح؟
                </div>
            </div>
            <div class="flex gap-2">
                <input id="aiInput" class="input" placeholder="اكتب سؤالك هنا...">
                <button onclick="askAI()" class="btn btn-primary px-4"><i class="fa-solid fa-paper-plane"></i></button>
            </div>
        </div>
    </div>

    <div class="glass rounded-3xl p-6 shadow-soft mt-6">
        <div class="flex items-center justify-between mb-5">
            <div>
                <h2 class="text-xl font-black">تنبيهات المخزون المنخفض</h2>
                <p class="text-sm text-slate-400">المنتجات التي وصلت إلى 5 قطع أو أقل</p>
            </div>
        </div>
        <div class="grid md:grid-cols-2 xl:grid-cols-4 gap-4">
            {% for item in low_stock %}
            <div class="rounded-3xl border border-amber-400/15 bg-amber-500/10 p-4">
                <div class="font-black">{{ item.name }}</div>
                <div class="text-sm text-slate-400">{{ item.category }}</div>
                <div class="mt-3 flex items-center justify-between">
                    <span class="text-xs text-slate-400">المتبقي</span>
                    <span class="text-2xl font-black text-amber-200">{{ item.qty }}</span>
                </div>
            </div>
            {% else %}
            <div class="col-span-full text-center text-slate-500 py-6">لا توجد تنبيهات مخزون منخفض حالياً.</div>
            {% endfor %}
        </div>
    </div>
    """

    extra_js = """
    <script>
        const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

        function appendAiMessage(text, fromUser=false) {
            const box = document.getElementById('aiBox');
            const div = document.createElement('div');
            div.className = fromUser
                ? 'mr-auto max-w-[85%] rounded-2xl bg-teal-500/15 border border-teal-400/20 p-3 text-sm'
                : 'max-w-[85%] rounded-2xl bg-sky-500/15 border border-sky-400/20 p-3 text-sm';
            div.textContent = text;
            box.appendChild(div);
            box.scrollTop = box.scrollHeight;
        }

        async function askAI() {
            const input = document.getElementById('aiInput');
            const message = input.value.trim();
            if (!message) return;
            appendAiMessage(message, true);
            input.value = '';
            try {
                const res = await fetch('/api/ai-assistant', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
                    body: JSON.stringify({message})
                });
                const data = await res.json();
                appendAiMessage(data.answer || 'لم أستطع معالجة السؤال.');
            } catch (error) {
                appendAiMessage('حدث خطأ في الاتصال بالمساعد.');
            }
        }

        document.getElementById('aiInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') askAI();
        });
    </script>
    """
    return render_page("لوحة التحكم", "dashboard", template, extra_js=extra_js, metrics=metrics, recent_invoices=recent_invoices, low_stock=low_stock)


@app.route("/api/ai-assistant", methods=["POST"])
@login_required
def ai_assistant():
    data = request.get_json(silent=True) or {}
    message = clean_text(data.get("message"), "السؤال", max_len=500, required=True)
    msg = message.lower()
    metrics = calculate_metrics()

    inventory_rows = get_db().execute(
        "SELECT name, category, qty, cost, price FROM inventory ORDER BY name ASC"
    ).fetchall()

    if any(word in msg for word in ["ربح", "profit", "net", "صافي"]):
        answer = (
            f"صافي الربح الحالي هو {format_money(metrics['net_profit'])}. "
            f"الحساب: ربح المنتجات {format_money(metrics['product_profit'])} "
            f"+ أجور التركيب {format_money(metrics['labor_profit'])} "
            f"- المصروفات {format_money(metrics['total_expenses'])}."
        )
        return jsonify({"answer": answer})

    if any(word in msg for word in ["مبيعات", "sales", "gross", "إجمالي"]):
        return jsonify({"answer": f"إجمالي المبيعات المسجلة حتى الآن هو {format_money(metrics['gross_sales'])}."})

    if any(word in msg for word in ["مصروف", "expenses", "expense", "تكاليف"]):
        return jsonify({"answer": f"إجمالي المصروفات الحالية هو {format_money(metrics['total_expenses'])}."})

    if any(word in msg for word in ["مشاريع", "projects", "عملاء", "قيد التنفيذ"]):
        return jsonify({"answer": f"عدد المشاريع قيد التنفيذ حالياً هو {metrics['active_projects']} مشروع."})

    if any(word in msg for word in ["مخزون", "stock", "كمية", "متوفر", "available"]):
        matched = None
        for item in inventory_rows:
            name = item["name"].lower()
            if name and name in msg:
                matched = item
                break
            for token in name.split():
                if len(token) >= 3 and token in msg:
                    matched = item
                    break
            if matched:
                break

        if matched:
            return jsonify(
                {
                    "answer": (
                        f"مخزون {matched['name']} هو {matched['qty']} قطعة. "
                        f"سعر البيع الحالي {format_money(matched['price'])} والتكلفة {format_money(matched['cost'])}."
                    )
                }
            )

        total_pieces = metrics["inventory_pieces"]
        low_stock = [f"{row['name']} ({row['qty']})" for row in inventory_rows if row["qty"] <= 5]
        low_stock_text = "، ".join(low_stock[:8]) if low_stock else "لا توجد منتجات منخفضة المخزون."
        return jsonify({"answer": f"إجمالي قطع المخزون هو {total_pieces}. المنتجات منخفضة المخزون: {low_stock_text}"})

    return jsonify(
        {
            "answer": (
                "يمكنني الإجابة عن: صافي الربح، إجمالي المبيعات، المصروفات، عدد المشاريع النشطة، "
                "أو كمية مخزون منتج معين. جرّب: كم مخزون البطاريات؟"
            )
        }
    )


@app.route("/inventory")
@login_required
def inventory():
    items = get_db().execute("SELECT * FROM inventory ORDER BY id DESC").fetchall()
    template = """
    <div class="grid xl:grid-cols-3 gap-6">
        <form method="post" action="{{ url_for('inventory_create') }}" class="glass rounded-3xl p-6 shadow-soft">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <h2 class="text-xl font-black mb-1">إضافة منتج شمسي</h2>
            <p class="text-sm text-slate-400 mb-5">سجّل صنف جديد داخل المستودع.</p>

            <div class="space-y-4">
                <label class="block">
                    <span class="text-sm text-slate-300 font-bold">اسم المنتج</span>
                    <input class="input mt-2" name="name" required maxlength="180">
                </label>
                <label class="block">
                    <span class="text-sm text-slate-300 font-bold">التصنيف</span>
                    <input class="input mt-2" name="category" placeholder="ألواح / بطاريات / انفرترات..." maxlength="120">
                </label>
                <div class="grid grid-cols-3 gap-3">
                    <label class="block">
                        <span class="text-sm text-slate-300 font-bold">الكمية</span>
                        <input class="input mt-2" type="number" name="qty" min="0" step="1" required>
                    </label>
                    <label class="block">
                        <span class="text-sm text-slate-300 font-bold">التكلفة</span>
                        <input class="input mt-2" type="number" name="cost" min="0" step="0.01" required>
                    </label>
                    <label class="block">
                        <span class="text-sm text-slate-300 font-bold">سعر البيع</span>
                        <input class="input mt-2" type="number" name="price" min="0" step="0.01" required>
                    </label>
                </div>
                <button class="btn btn-primary w-full"><i class="fa-solid fa-plus"></i> حفظ المنتج</button>
            </div>
        </form>

        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
                <div>
                    <h2 class="text-xl font-black">المخزون الحالي</h2>
                    <p class="text-sm text-slate-400">تعديل كامل للاسم، الكمية، التكلفة، وسعر البيع.</p>
                </div>
                <div class="rounded-2xl bg-slate-900/70 border border-slate-700/60 px-4 py-3 text-sm">
                    عدد الأصناف: <span class="font-black text-sky-300">{{ items|length }}</span>
                </div>
            </div>

            <div class="overflow-x-auto scrollbar-thin">
                <table class="w-full text-sm min-w-[900px]">
                    <thead>
                        <tr class="table-head border-b border-slate-700/70">
                            <th class="py-3 text-right">المنتج</th>
                            <th class="py-3 text-right">التصنيف</th>
                            <th class="py-3 text-right">الكمية</th>
                            <th class="py-3 text-right">التكلفة</th>
                            <th class="py-3 text-right">البيع</th>
                            <th class="py-3 text-right">القيمة بالمخزن</th>
                            <th class="py-3 text-right">إجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in items %}
                        <tr class="border-b border-slate-800/70 align-top">
                            <form method="post" action="{{ url_for('inventory_update', item_id=item.id) }}">
                                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                <td class="py-3 pl-3"><input class="input" name="name" value="{{ item.name }}" required></td>
                                <td class="py-3 pl-3"><input class="input" name="category" value="{{ item.category }}"></td>
                                <td class="py-3 pl-3"><input class="input" type="number" min="0" step="1" name="qty" value="{{ item.qty }}" required></td>
                                <td class="py-3 pl-3"><input class="input" type="number" min="0" step="0.01" name="cost" value="{{ item.cost }}" required></td>
                                <td class="py-3 pl-3"><input class="input" type="number" min="0" step="0.01" name="price" value="{{ item.price }}" required></td>
                                <td class="py-3 font-black text-emerald-300">{{ (item.qty * item.cost)|money }}</td>
                                <td class="py-3">
                                    <div class="flex gap-2">
                                        <button class="btn btn-muted py-2 px-3"><i class="fa-solid fa-floppy-disk"></i></button>
                            </form>
                                        <form method="post" action="{{ url_for('inventory_delete', item_id=item.id) }}" onsubmit="return confirmDelete('حذف المنتج من المخزون؟')">
                                            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                            <button class="btn btn-danger py-2 px-3"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </div>
                                </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="7" class="py-10 text-center text-slate-500">لا توجد منتجات بعد.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("المستودع والمخزن", "inventory", template, items=items)


@app.route("/inventory/create", methods=["POST"])
@login_required
def inventory_create():
    try:
        name = clean_text(request.form.get("name"), "اسم المنتج", max_len=180)
        category = clean_text(request.form.get("category"), "التصنيف", max_len=120, required=False)
        qty = parse_int(request.form.get("qty"), "الكمية", minimum=0)
        cost = parse_money(request.form.get("cost"), "التكلفة", minimum=0)
        price = parse_money(request.form.get("price"), "سعر البيع", minimum=0)
        get_db().execute(
            "INSERT INTO inventory (name, category, qty, cost, price) VALUES (?, ?, ?, ?, ?)",
            (name, category, qty, cost, price),
        )
        get_db().commit()
        flash("تمت إضافة المنتج بنجاح.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:item_id>/update", methods=["POST"])
@login_required
def inventory_update(item_id):
    try:
        existing = get_db().execute("SELECT id FROM inventory WHERE id = ?", (item_id,)).fetchone()
        if existing is None:
            abort(404)
        name = clean_text(request.form.get("name"), "اسم المنتج", max_len=180)
        category = clean_text(request.form.get("category"), "التصنيف", max_len=120, required=False)
        qty = parse_int(request.form.get("qty"), "الكمية", minimum=0)
        cost = parse_money(request.form.get("cost"), "التكلفة", minimum=0)
        price = parse_money(request.form.get("price"), "سعر البيع", minimum=0)
        get_db().execute(
            "UPDATE inventory SET name = ?, category = ?, qty = ?, cost = ?, price = ? WHERE id = ?",
            (name, category, qty, cost, price, item_id),
        )
        get_db().commit()
        flash("تم تحديث المنتج.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:item_id>/delete", methods=["POST"])
@login_required
def inventory_delete(item_id):
    get_db().execute("DELETE FROM inventory WHERE id = ?", (item_id,))
    get_db().commit()
    flash("تم حذف المنتج.", "success")
    return redirect(url_for("inventory"))


@app.route("/sales")
@login_required
def sales():
    products = get_db().execute(
        "SELECT id, name, category, qty, cost, price FROM inventory ORDER BY name ASC"
    ).fetchall()
    invoices = get_db().execute(
        "SELECT id, customer_name, customer_phone, date, labor_cost, expenses_cost, grand_total FROM invoices ORDER BY id DESC"
    ).fetchall()
    products_json = json.dumps([dict(row) for row in products], ensure_ascii=False)

    template = """
    <div class="grid xl:grid-cols-5 gap-6">
        <form method="post" action="{{ url_for('invoice_create') }}" class="xl:col-span-3 glass rounded-3xl p-6 shadow-soft" id="invoiceForm">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h2 class="text-xl font-black">إنشاء فاتورة متعددة الأصناف</h2>
                    <p class="text-sm text-slate-400">اختر أكثر من منتج مع خصم الكمية تلقائياً من المخزون.</p>
                </div>
                <button type="button" onclick="addInvoiceRow()" class="btn btn-muted"><i class="fa-solid fa-plus"></i> إضافة صنف</button>
            </div>

            <div class="grid md:grid-cols-2 gap-4 mb-5">
                <label>
                    <span class="text-sm text-slate-300 font-bold">اسم العميل</span>
                    <input class="input mt-2" name="customer_name" required maxlength="180">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">هاتف العميل</span>
                    <input class="input mt-2" name="customer_phone" maxlength="80">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">أجور التركيب</span>
                    <input class="input mt-2" type="number" name="labor_cost" id="laborCost" min="0" step="0.01" value="0" oninput="recalculateInvoice()">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">مصروفات مباشرة داخلية</span>
                    <input class="input mt-2" type="number" name="expenses_cost" id="expensesCost" min="0" step="0.01" value="0" oninput="recalculateInvoice()">
                </label>
            </div>

            <div class="overflow-x-auto scrollbar-thin rounded-3xl border border-slate-800">
                <table class="w-full text-sm min-w-[780px]">
                    <thead class="bg-slate-900/80">
                        <tr class="table-head">
                            <th class="p-3 text-right">المنتج</th>
                            <th class="p-3 text-right">المخزون</th>
                            <th class="p-3 text-right">الكمية</th>
                            <th class="p-3 text-right">سعر البيع</th>
                            <th class="p-3 text-right">الإجمالي</th>
                            <th class="p-3 text-right">حذف</th>
                        </tr>
                    </thead>
                    <tbody id="invoiceItems"></tbody>
                </table>
            </div>

            <div class="mt-5 grid md:grid-cols-3 gap-4">
                <div class="rounded-3xl bg-slate-900/70 border border-slate-700/60 p-4">
                    <div class="text-sm text-slate-400">إجمالي المنتجات</div>
                    <div class="text-2xl font-black" id="productsTotal">$0.00</div>
                </div>
                <div class="rounded-3xl bg-slate-900/70 border border-slate-700/60 p-4">
                    <div class="text-sm text-slate-400">الإجمالي النهائي للعميل</div>
                    <div class="text-2xl font-black text-emerald-300" id="grandTotal">$0.00</div>
                </div>
                <div class="rounded-3xl bg-slate-900/70 border border-slate-700/60 p-4">
                    <div class="text-sm text-slate-400">ملاحظة</div>
                    <div class="text-xs text-slate-400 mt-2">المصروفات المباشرة لا تُضاف إلى إجمالي العميل، لكنها تخصم من الأرباح.</div>
                </div>
            </div>

            <button class="btn btn-primary w-full mt-5"><i class="fa-solid fa-file-circle-plus"></i> حفظ الفاتورة وخصم المخزون</button>
        </form>

        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <h2 class="text-xl font-black mb-1">المنتجات المتاحة</h2>
            <p class="text-sm text-slate-400 mb-5">قائمة سريعة بالمخزون الحي.</p>
            <div class="space-y-3 max-h-[580px] overflow-y-auto scrollbar-thin">
                {% for product in products %}
                <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-4">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <div class="font-black">{{ product.name }}</div>
                            <div class="text-xs text-slate-500">{{ product.category }}</div>
                        </div>
                        <div class="text-left">
                            <div class="text-xl font-black {{ 'text-rose-300' if product.qty <= 0 else 'text-emerald-300' }}">{{ product.qty }}</div>
                            <div class="text-xs text-slate-500">{{ product.price|money }}</div>
                        </div>
                    </div>
                </div>
                {% else %}
                <div class="text-center text-slate-500 py-8">أضف منتجات للمخزون أولاً.</div>
                {% endfor %}
            </div>
        </div>
    </div>

    <div class="glass rounded-3xl p-6 shadow-soft mt-6">
        <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
            <div>
                <h2 class="text-xl font-black">كل الفواتير السابقة</h2>
                <p class="text-sm text-slate-400">عرض وتصدير أي فاتورة إلى Excel أو PDF.</p>
            </div>
        </div>
        <div class="overflow-x-auto scrollbar-thin">
            <table class="w-full text-sm min-w-[980px]">
                <thead>
                    <tr class="table-head border-b border-slate-700/70">
                        <th class="py-3 text-right">#</th>
                        <th class="py-3 text-right">العميل</th>
                        <th class="py-3 text-right">الهاتف</th>
                        <th class="py-3 text-right">التاريخ</th>
                        <th class="py-3 text-right">الأجور</th>
                        <th class="py-3 text-right">مصروفات مباشرة</th>
                        <th class="py-3 text-right">الإجمالي</th>
                        <th class="py-3 text-right">إجراءات</th>
                    </tr>
                </thead>
                <tbody>
                    {% for inv in invoices %}
                    <tr class="border-b border-slate-800/70 hover:bg-slate-800/35">
                        <td class="py-3 font-bold">{{ inv.id }}</td>
                        <td class="py-3">{{ inv.customer_name }}</td>
                        <td class="py-3 text-slate-400">{{ inv.customer_phone }}</td>
                        <td class="py-3 text-slate-400">{{ inv.date }}</td>
                        <td class="py-3">{{ inv.labor_cost|money }}</td>
                        <td class="py-3">{{ inv.expenses_cost|money }}</td>
                        <td class="py-3 font-black text-emerald-300">{{ inv.grand_total|money }}</td>
                        <td class="py-3">
                            <div class="flex flex-wrap gap-2">
                                <a class="btn btn-muted py-2 px-3" href="{{ url_for('invoice_view', invoice_id=inv.id) }}"><i class="fa-solid fa-eye"></i></a>
                                <a class="btn btn-muted py-2 px-3" href="{{ url_for('invoice_export_xlsx', invoice_id=inv.id) }}"><i class="fa-solid fa-file-excel"></i> Excel</a>
                                <a class="btn btn-muted py-2 px-3" href="{{ url_for('invoice_export_pdf', invoice_id=inv.id) }}"><i class="fa-solid fa-file-pdf"></i> PDF</a>
                            </div>
                        </td>
                    </tr>
                    {% else %}
                    <tr><td colspan="8" class="py-10 text-center text-slate-500">لا توجد فواتير بعد.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    """

    extra_js = """
    <script>
        const products = """ + products_json + """;

        function money(n) {
            return '$' + Number(n || 0).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
        }

        function productOptions() {
            return '<option value="">اختر المنتج</option>' + products.map(p => {
                const disabled = Number(p.qty) <= 0 ? 'disabled' : '';
                return `<option value="${p.id}" data-stock="${p.qty}" data-price="${p.price}" data-cost="${p.cost}" ${disabled}>${p.name} — المتاح: ${p.qty}</option>`;
            }).join('');
        }

        function addInvoiceRow() {
            const tbody = document.getElementById('invoiceItems');
            const tr = document.createElement('tr');
            tr.className = 'border-b border-slate-800/70';
            tr.innerHTML = `
                <td class="p-3">
                    <select class="input product-select" name="product_id[]" required onchange="syncProductRow(this)">
                        ${productOptions()}
                    </select>
                </td>
                <td class="p-3 text-slate-300 stock-label">—</td>
                <td class="p-3"><input class="input qty-input" type="number" name="item_qty[]" min="1" step="1" value="1" required oninput="recalculateInvoice()"></td>
                <td class="p-3"><input class="input price-input" type="number" name="item_price[]" min="0" step="0.01" value="0" required oninput="recalculateInvoice()"></td>
                <td class="p-3 font-black text-emerald-300 line-total">$0.00</td>
                <td class="p-3"><button type="button" class="btn btn-danger py-2 px-3" onclick="this.closest('tr').remove(); recalculateInvoice();"><i class="fa-solid fa-xmark"></i></button></td>
            `;
            tbody.appendChild(tr);
        }

        function syncProductRow(select) {
            const row = select.closest('tr');
            const selected = select.options[select.selectedIndex];
            const stock = selected.dataset.stock || 0;
            const price = selected.dataset.price || 0;
            row.querySelector('.stock-label').textContent = stock;
            const qtyInput = row.querySelector('.qty-input');
            qtyInput.max = stock;
            if (Number(qtyInput.value || 0) > Number(stock)) qtyInput.value = stock;
            row.querySelector('.price-input').value = Number(price).toFixed(2);
            recalculateInvoice();
        }

        function recalculateInvoice() {
            let productsTotal = 0;
            document.querySelectorAll('#invoiceItems tr').forEach(row => {
                const qty = Number(row.querySelector('.qty-input')?.value || 0);
                const price = Number(row.querySelector('.price-input')?.value || 0);
                const total = qty * price;
                productsTotal += total;
                row.querySelector('.line-total').textContent = money(total);
            });
            const labor = Number(document.getElementById('laborCost').value || 0);
            document.getElementById('productsTotal').textContent = money(productsTotal);
            document.getElementById('grandTotal').textContent = money(productsTotal + labor);
        }

        addInvoiceRow();
    </script>
    """
    return render_page("المبيعات والفواتير", "sales", template, extra_js=extra_js, products=products, invoices=invoices)


@app.route("/invoices/create", methods=["POST"])
@login_required
def invoice_create():
    db = get_db()
    try:
        customer_name = clean_text(request.form.get("customer_name"), "اسم العميل", max_len=180)
        customer_phone = clean_text(request.form.get("customer_phone"), "هاتف العميل", max_len=80, required=False)
        labor_cost = parse_money(request.form.get("labor_cost"), "أجور التركيب", minimum=0)
        expenses_cost = parse_money(request.form.get("expenses_cost"), "المصروفات المباشرة", minimum=0)

        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("item_qty[]")
        prices = request.form.getlist("item_price[]")

        if not product_ids:
            raise ValueError("يجب إضافة صنف واحد على الأقل للفاتورة.")

        if not (len(product_ids) == len(quantities) == len(prices)):
            raise ValueError("بيانات الأصناف غير مكتملة.")

        items = []
        sold_by_product = {}

        for index, raw_product_id in enumerate(product_ids):
            product_id = parse_int(raw_product_id, "المنتج", minimum=1)
            qty = parse_int(quantities[index], "كمية الصنف", minimum=1)
            price = parse_money(prices[index], "سعر الصنف", minimum=0)

            product = db.execute(
                "SELECT id, name, qty, cost, price FROM inventory WHERE id = ?",
                (product_id,),
            ).fetchone()
            if product is None:
                raise ValueError("أحد المنتجات المختارة غير موجود.")
            if product["qty"] <= 0:
                raise ValueError(f"المنتج {product['name']} غير متوفر في المخزون.")

            sold_by_product[product_id] = sold_by_product.get(product_id, 0) + qty
            if sold_by_product[product_id] > product["qty"]:
                raise ValueError(f"الكمية المطلوبة من {product['name']} أكبر من المتاح في المخزون.")

            items.append(
                {
                    "product_id": product_id,
                    "product_name": product["name"],
                    "qty": qty,
                    "price": price,
                    "cost": float(product["cost"]),
                }
            )

        products_total = sum(item["qty"] * item["price"] for item in items)
        grand_total = round(products_total + labor_cost, 2)
        invoice_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute(
            """
            INSERT INTO invoices (customer_name, customer_phone, date, labor_cost, expenses_cost, grand_total)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (customer_name, customer_phone, invoice_date, labor_cost, expenses_cost, grand_total),
        )
        invoice_id = cursor.lastrowid

        for item in items:
            db.execute(
                """
                INSERT INTO invoice_items (invoice_id, product_id, product_name, qty, price, cost)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    invoice_id,
                    item["product_id"],
                    item["product_name"],
                    item["qty"],
                    item["price"],
                    item["cost"],
                ),
            )
            db.execute(
                "UPDATE inventory SET qty = qty - ? WHERE id = ?",
                (item["qty"], item["product_id"]),
            )

        db.commit()
        backup_db_after_invoice()
        flash(f"تم إنشاء الفاتورة #{invoice_id} ونسخ قاعدة البيانات احتياطياً.", "success")
    except ValueError as exc:
        db.rollback()
        flash(str(exc), "error")
    except sqlite3.Error as exc:
        db.rollback()
        flash(f"خطأ في قاعدة البيانات: {exc}", "error")

    return redirect(url_for("sales"))


def get_invoice_with_items(invoice_id):
    invoice = get_db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if invoice is None:
        abort(404)
    items = get_db().execute(
        "SELECT * FROM invoice_items WHERE invoice_id = ? ORDER BY id ASC",
        (invoice_id,),
    ).fetchall()
    return invoice, items


@app.route("/invoices/<int:invoice_id>")
@login_required
def invoice_view(invoice_id):
    invoice, items = get_invoice_with_items(invoice_id)
    products_total = sum(item["qty"] * item["price"] for item in items)
    profit = sum((item["price"] - item["cost"]) * item["qty"] for item in items) + invoice["labor_cost"] - invoice["expenses_cost"]

    template = """
    <div class="max-w-5xl mx-auto glass rounded-3xl p-6 md:p-8 shadow-soft">
        <div class="flex flex-col md:flex-row md:items-start md:justify-between gap-5 border-b border-slate-700/70 pb-6 mb-6">
            <div>
                <div class="text-sm text-sky-300 font-bold">فاتورة مبيعات</div>
                <h2 class="text-3xl font-black">Invoice #{{ invoice.id }}</h2>
                <p class="text-slate-400 mt-1">{{ invoice.date }}</p>
            </div>
            <div class="flex flex-wrap gap-2">
                <a class="btn btn-muted" href="{{ url_for('invoice_export_xlsx', invoice_id=invoice.id) }}"><i class="fa-solid fa-file-excel"></i> Excel</a>
                <a class="btn btn-muted" href="{{ url_for('invoice_export_pdf', invoice_id=invoice.id) }}"><i class="fa-solid fa-file-pdf"></i> PDF</a>
                <button class="btn btn-primary" onclick="window.print()"><i class="fa-solid fa-print"></i> طباعة</button>
            </div>
        </div>

        <div class="grid md:grid-cols-2 gap-4 mb-6">
            <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                <div class="text-sm text-slate-400">اسم العميل</div>
                <div class="text-xl font-black">{{ invoice.customer_name }}</div>
            </div>
            <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                <div class="text-sm text-slate-400">الهاتف</div>
                <div class="text-xl font-black">{{ invoice.customer_phone or '—' }}</div>
            </div>
        </div>

        <div class="overflow-x-auto scrollbar-thin rounded-3xl border border-slate-800 mb-6">
            <table class="w-full text-sm min-w-[760px]">
                <thead class="bg-slate-900/85">
                    <tr class="table-head">
                        <th class="p-3 text-right">الصنف</th>
                        <th class="p-3 text-right">الكمية</th>
                        <th class="p-3 text-right">سعر البيع</th>
                        <th class="p-3 text-right">التكلفة</th>
                        <th class="p-3 text-right">الإجمالي</th>
                        <th class="p-3 text-right">الربح</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in items %}
                    <tr class="border-b border-slate-800/70">
                        <td class="p-3 font-bold">{{ item.product_name }}</td>
                        <td class="p-3">{{ item.qty }}</td>
                        <td class="p-3">{{ item.price|money }}</td>
                        <td class="p-3">{{ item.cost|money }}</td>
                        <td class="p-3 text-emerald-300 font-black">{{ (item.price * item.qty)|money }}</td>
                        <td class="p-3 text-sky-300 font-black">{{ ((item.price - item.cost) * item.qty)|money }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="grid md:grid-cols-4 gap-4">
            <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                <div class="text-sm text-slate-400">إجمالي المنتجات</div>
                <div class="text-2xl font-black">{{ products_total|money }}</div>
            </div>
            <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                <div class="text-sm text-slate-400">أجور التركيب</div>
                <div class="text-2xl font-black">{{ invoice.labor_cost|money }}</div>
            </div>
            <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                <div class="text-sm text-slate-400">مصروفات مباشرة</div>
                <div class="text-2xl font-black text-rose-300">{{ invoice.expenses_cost|money }}</div>
            </div>
            <div class="rounded-3xl bg-emerald-500/10 border border-emerald-400/20 p-5">
                <div class="text-sm text-emerald-200">الإجمالي النهائي</div>
                <div class="text-2xl font-black text-emerald-300">{{ invoice.grand_total|money }}</div>
                <div class="text-xs text-slate-400 mt-2">ربح الفاتورة: {{ profit|money }}</div>
            </div>
        </div>
    </div>
    """
    return render_page(
        f"فاتورة #{invoice_id}",
        "sales",
        template,
        invoice=invoice,
        items=items,
        products_total=products_total,
        profit=profit,
    )


def column_name(index):
    result = ""
    while index:
        index, rem = divmod(index - 1, 26)
        result = chr(65 + rem) + result
    return result


def xml_escape(value):
    return html.escape(str(value), quote=True)


def make_xlsx(rows, sheet_name="Invoice"):
    output = io.BytesIO()

    sheet_rows = []
    for r_index, row in enumerate(rows, start=1):
        cells = []
        for c_index, value in enumerate(row, start=1):
            ref = f"{column_name(c_index)}{r_index}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(value)}</t></is></c>')
        sheet_rows.append(f'<row r="{r_index}">{"".join(cells)}</row>')

    sheet_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
        <sheetViews><sheetView workbookViewId="0" rightToLeft="1"/></sheetViews>
        <sheetFormatPr defaultRowHeight="18"/>
        <cols>
            <col min="1" max="1" width="24" customWidth="1"/>
            <col min="2" max="8" width="18" customWidth="1"/>
        </cols>
        <sheetData>{''.join(sheet_rows)}</sheetData>
    </worksheet>"""

    workbook_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
        <sheets>
            <sheet name="{xml_escape(sheet_name[:31])}" sheetId="1" r:id="rId1"/>
        </sheets>
    </workbook>"""

    workbook_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    </Relationships>"""

    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
        <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
    </Relationships>"""

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
        <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
        <Default Extension="xml" ContentType="application/xml"/>
        <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
        <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
    </Types>"""

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)

    output.seek(0)
    return output


@app.route("/invoices/<int:invoice_id>/export/xlsx")
@login_required
def invoice_export_xlsx(invoice_id):
    invoice, items = get_invoice_with_items(invoice_id)
    products_total = sum(item["qty"] * item["price"] for item in items)

    rows = [
        [APP_NAME],
        ["فاتورة رقم", invoice["id"]],
        ["التاريخ", invoice["date"]],
        ["اسم العميل", invoice["customer_name"]],
        ["الهاتف", invoice["customer_phone"]],
        [],
        ["الصنف", "الكمية", "سعر البيع", "التكلفة", "إجمالي السطر", "ربح السطر"],
    ]

    for item in items:
        rows.append(
            [
                item["product_name"],
                item["qty"],
                item["price"],
                item["cost"],
                item["qty"] * item["price"],
                (item["price"] - item["cost"]) * item["qty"],
            ]
        )

    rows.extend(
        [
            [],
            ["إجمالي المنتجات", products_total],
            ["أجور التركيب", invoice["labor_cost"]],
            ["مصروفات مباشرة داخلية", invoice["expenses_cost"]],
            ["الإجمالي النهائي للعميل", invoice["grand_total"]],
        ]
    )

    output = make_xlsx(rows, sheet_name=f"Invoice {invoice_id}")
    filename = safe_filename(f"invoice_{invoice_id}_{invoice['customer_name']}.xlsx")
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def pdf_escape(value):
    value = str(value).encode("latin-1", "replace").decode("latin-1")
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_basic_pdf(lines):
    width, height = 595, 842
    y = height - 55
    content_lines = ["BT", "/F1 11 Tf", "50 790 Td", "14 TL"]
    for line in lines:
        content_lines.append(f"({pdf_escape(line)}) Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    content = "\n".join(content_lines).encode("latin-1", "replace")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".encode()
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream")

    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(pdf.tell())
        pdf.write(f"{i} 0 obj\n".encode())
        pdf.write(obj)
        pdf.write(b"\nendobj\n")

    xref_position = pdf.tell()
    pdf.write(f"xref\n0 {len(objects) + 1}\n".encode())
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.write(f"{offset:010d} 00000 n \n".encode())
    pdf.write(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_position}\n%%EOF".encode())
    pdf.seek(0)
    return pdf


def shape_arabic_text(text):
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display

        return get_display(arabic_reshaper.reshape(str(text)))
    except Exception:
        return str(text)


def make_invoice_pdf(invoice, items):
    products_total = sum(item["qty"] * item["price"] for item in items)
    profit = sum((item["price"] - item["cost"]) * item["qty"] for item in items) + invoice["labor_cost"] - invoice["expenses_cost"]

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen import canvas

        output = io.BytesIO()
        c = canvas.Canvas(output, pagesize=A4)
        width, height = A4

        font_name = "Helvetica"
        possible_fonts = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed.ttf",
            str(BASE_DIR / "DejaVuSans.ttf"),
        ]
        for font_path in possible_fonts:
            if Path(font_path).exists():
                pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
                font_name = "DejaVuSans"
                break

        def draw_right(text, x, y, size=11):
            c.setFont(font_name, size)
            display = shape_arabic_text(text)
            c.drawRightString(x, y, display)

        y = height - 50
        draw_right(APP_NAME, width - 45, y, 18)
        y -= 28
        draw_right(f"فاتورة رقم: {invoice['id']}", width - 45, y, 14)
        y -= 22
        draw_right(f"التاريخ: {invoice['date']}", width - 45, y)
        y -= 22
        draw_right(f"العميل: {invoice['customer_name']}", width - 45, y)
        y -= 22
        draw_right(f"الهاتف: {invoice['customer_phone'] or '-'}", width - 45, y)

        y -= 38
        draw_right("الصنف | الكمية | البيع | التكلفة | الإجمالي", width - 45, y, 11)
        y -= 16
        c.line(45, y, width - 45, y)
        y -= 18

        for item in items:
            line = (
                f"{item['product_name']} | {item['qty']} | "
                f"{format_money(item['price'])} | {format_money(item['cost'])} | "
                f"{format_money(item['qty'] * item['price'])}"
            )
            draw_right(line, width - 45, y, 10)
            y -= 18
            if y < 90:
                c.showPage()
                y = height - 50

        y -= 16
        c.line(45, y, width - 45, y)
        y -= 24
        draw_right(f"إجمالي المنتجات: {format_money(products_total)}", width - 45, y)
        y -= 20
        draw_right(f"أجور التركيب: {format_money(invoice['labor_cost'])}", width - 45, y)
        y -= 20
        draw_right(f"مصروفات مباشرة داخلية: {format_money(invoice['expenses_cost'])}", width - 45, y)
        y -= 20
        draw_right(f"الإجمالي النهائي للعميل: {format_money(invoice['grand_total'])}", width - 45, y, 13)
        y -= 20
        draw_right(f"ربح الفاتورة: {format_money(profit)}", width - 45, y, 12)

        c.save()
        output.seek(0)
        return output
    except Exception:
        lines = [
            f"{APP_NAME} - Invoice #{invoice['id']}",
            f"Date: {invoice['date']}",
            f"Customer: {invoice['customer_name']}",
            f"Phone: {invoice['customer_phone'] or '-'}",
            "",
            "Items:",
        ]
        for item in items:
            lines.append(
                f"{item['product_name']} | Qty {item['qty']} | Price {format_money(item['price'])} | Total {format_money(item['qty'] * item['price'])}"
            )
        lines.extend(
            [
                "",
                f"Products Total: {format_money(products_total)}",
                f"Labor Cost: {format_money(invoice['labor_cost'])}",
                f"Direct Expenses: {format_money(invoice['expenses_cost'])}",
                f"Grand Total: {format_money(invoice['grand_total'])}",
                f"Invoice Profit: {format_money(profit)}",
            ]
        )
        return make_basic_pdf(lines)


@app.route("/invoices/<int:invoice_id>/export/pdf")
@login_required
def invoice_export_pdf(invoice_id):
    invoice, items = get_invoice_with_items(invoice_id)
    output = make_invoice_pdf(invoice, items)
    filename = safe_filename(f"invoice_{invoice_id}_{invoice['customer_name']}.pdf")
    return send_file(output, as_attachment=True, download_name=filename, mimetype="application/pdf")


@app.route("/expenses")
@login_required
def expenses():
    rows = get_db().execute("SELECT * FROM expenses ORDER BY date DESC, id DESC").fetchall()
    total = scalar("SELECT COALESCE(SUM(amount), 0) FROM expenses")
    today = datetime.now().strftime("%Y-%m-%d")

    template = """
    <div class="grid xl:grid-cols-3 gap-6">
        <form method="post" action="{{ url_for('expense_create') }}" class="glass rounded-3xl p-6 shadow-soft">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <h2 class="text-xl font-black mb-1">تسجيل مصروف</h2>
            <p class="text-sm text-slate-400 mb-5">مصروفات تشغيلية، محل، أو مشروع.</p>

            <div class="space-y-4">
                <label>
                    <span class="text-sm text-slate-300 font-bold">الوصف</span>
                    <input class="input mt-2" name="description" required maxlength="255">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">التصنيف</span>
                    <input class="input mt-2" name="category" placeholder="تشغيل / إيجار / مشروع..." maxlength="120">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">المبلغ</span>
                    <input class="input mt-2" type="number" name="amount" min="0" step="0.01" required>
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">التاريخ</span>
                    <input class="input mt-2" type="date" name="date" value="{{ today }}" required>
                </label>
                <button class="btn btn-primary w-full"><i class="fa-solid fa-plus"></i> حفظ المصروف</button>
            </div>
        </form>

        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-5">
                <div>
                    <h2 class="text-xl font-black">سجل المصروفات</h2>
                    <p class="text-sm text-slate-400">تعديل أو حذف المصروفات المسجلة.</p>
                </div>
                <div class="rounded-2xl bg-rose-500/10 border border-rose-400/20 px-4 py-3 text-sm">
                    الإجمالي: <span class="font-black text-rose-200">{{ total|money }}</span>
                </div>
            </div>

            <div class="overflow-x-auto scrollbar-thin">
                <table class="w-full text-sm min-w-[850px]">
                    <thead>
                        <tr class="table-head border-b border-slate-700/70">
                            <th class="py-3 text-right">الوصف</th>
                            <th class="py-3 text-right">التصنيف</th>
                            <th class="py-3 text-right">المبلغ</th>
                            <th class="py-3 text-right">التاريخ</th>
                            <th class="py-3 text-right">إجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for exp in rows %}
                        <tr class="border-b border-slate-800/70 align-top">
                            <form method="post" action="{{ url_for('expense_update', expense_id=exp.id) }}">
                                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                <td class="py-3 pl-3"><input class="input" name="description" value="{{ exp.description }}" required></td>
                                <td class="py-3 pl-3"><input class="input" name="category" value="{{ exp.category }}"></td>
                                <td class="py-3 pl-3"><input class="input" type="number" min="0" step="0.01" name="amount" value="{{ exp.amount }}" required></td>
                                <td class="py-3 pl-3"><input class="input" type="date" name="date" value="{{ exp.date[:10] }}" required></td>
                                <td class="py-3">
                                    <div class="flex gap-2">
                                        <button class="btn btn-muted py-2 px-3"><i class="fa-solid fa-floppy-disk"></i></button>
                            </form>
                                        <form method="post" action="{{ url_for('expense_delete', expense_id=exp.id) }}" onsubmit="return confirmDelete('حذف هذا المصروف؟')">
                                            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                            <button class="btn btn-danger py-2 px-3"><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </div>
                                </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="py-10 text-center text-slate-500">لا توجد مصروفات بعد.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("المصروفات", "expenses", template, rows=rows, total=total, today=today)


@app.route("/expenses/create", methods=["POST"])
@login_required
def expense_create():
    try:
        description = clean_text(request.form.get("description"), "الوصف", max_len=255)
        category = clean_text(request.form.get("category"), "التصنيف", max_len=120, required=False)
        amount = parse_money(request.form.get("amount"), "المبلغ", minimum=0)
        date = clean_text(request.form.get("date"), "التاريخ", max_len=20)
        get_db().execute(
            "INSERT INTO expenses (description, amount, category, date) VALUES (?, ?, ?, ?)",
            (description, amount, category, date),
        )
        get_db().commit()
        flash("تم حفظ المصروف.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("expenses"))


@app.route("/expenses/<int:expense_id>/update", methods=["POST"])
@login_required
def expense_update(expense_id):
    try:
        description = clean_text(request.form.get("description"), "الوصف", max_len=255)
        category = clean_text(request.form.get("category"), "التصنيف", max_len=120, required=False)
        amount = parse_money(request.form.get("amount"), "المبلغ", minimum=0)
        date = clean_text(request.form.get("date"), "التاريخ", max_len=20)
        get_db().execute(
            "UPDATE expenses SET description = ?, amount = ?, category = ?, date = ? WHERE id = ?",
            (description, amount, category, date, expense_id),
        )
        get_db().commit()
        flash("تم تحديث المصروف.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("expenses"))


@app.route("/expenses/<int:expense_id>/delete", methods=["POST"])
@login_required
def expense_delete(expense_id):
    get_db().execute("DELETE FROM expenses WHERE id = ?", (expense_id,))
    get_db().commit()
    flash("تم حذف المصروف.", "success")
    return redirect(url_for("expenses"))


@app.route("/customers")
@login_required
def customers():
    rows = get_db().execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    statuses = ("قيد التنفيذ", "مكتمل")

    template = """
    <div class="grid xl:grid-cols-3 gap-6">
        <form method="post" action="{{ url_for('customer_create') }}" class="glass rounded-3xl p-6 shadow-soft">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <h2 class="text-xl font-black mb-1">إضافة عميل / مشروع</h2>
            <p class="text-sm text-slate-400 mb-5">تابع بيانات العملاء ومراحل التركيب.</p>

            <div class="space-y-4">
                <label>
                    <span class="text-sm text-slate-300 font-bold">اسم العميل</span>
                    <input class="input mt-2" name="name" required maxlength="180">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">الهاتف</span>
                    <input class="input mt-2" name="phone" maxlength="80">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">تفاصيل المشروع</span>
                    <textarea class="input mt-2 min-h-32" name="project_details" placeholder="قدرة النظام، عدد الألواح، موقع التركيب..."></textarea>
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">الحالة</span>
                    <select class="input mt-2" name="status">
                        {% for status in statuses %}
                        <option value="{{ status }}">{{ status }}</option>
                        {% endfor %}
                    </select>
                </label>
                <button class="btn btn-primary w-full"><i class="fa-solid fa-user-plus"></i> حفظ العميل</button>
            </div>
        </form>

        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h2 class="text-xl font-black">CRM العملاء والمشاريع</h2>
                    <p class="text-sm text-slate-400">تحديث نطاق المشروع وحالة التركيب.</p>
                </div>
                <div class="rounded-2xl bg-slate-900/70 border border-slate-700/60 px-4 py-3 text-sm">
                    العملاء: <span class="font-black text-sky-300">{{ rows|length }}</span>
                </div>
            </div>

            <div class="space-y-4">
                {% for customer in rows %}
                <div class="rounded-3xl bg-slate-900/65 border border-slate-800 p-5">
                    <form method="post" action="{{ url_for('customer_update', customer_id=customer.id) }}" class="grid md:grid-cols-2 gap-4">
                        <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                        <label>
                            <span class="text-sm text-slate-300 font-bold">الاسم</span>
                            <input class="input mt-2" name="name" value="{{ customer.name }}" required>
                        </label>
                        <label>
                            <span class="text-sm text-slate-300 font-bold">الهاتف</span>
                            <input class="input mt-2" name="phone" value="{{ customer.phone }}">
                        </label>
                        <label class="md:col-span-2">
                            <span class="text-sm text-slate-300 font-bold">تفاصيل المشروع</span>
                            <textarea class="input mt-2 min-h-24" name="project_details">{{ customer.project_details }}</textarea>
                        </label>
                        <label>
                            <span class="text-sm text-slate-300 font-bold">الحالة</span>
                            <select class="input mt-2" name="status">
                                {% for status in statuses %}
                                <option value="{{ status }}" {% if customer.status == status %}selected{% endif %}>{{ status }}</option>
                                {% endfor %}
                            </select>
                        </label>
                        <div class="flex items-end gap-2">
                            <button class="btn btn-muted flex-1"><i class="fa-solid fa-floppy-disk"></i> تحديث</button>
                    </form>
                            <form method="post" action="{{ url_for('customer_delete', customer_id=customer.id) }}" onsubmit="return confirmDelete('حذف هذا العميل؟')" class="flex-1">
                                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                <button class="btn btn-danger w-full"><i class="fa-solid fa-trash"></i> حذف</button>
                            </form>
                        </div>
                </div>
                {% else %}
                <div class="text-center text-slate-500 py-10">لا يوجد عملاء أو مشاريع بعد.</div>
                {% endfor %}
            </div>
        </div>
    </div>
    """
    return render_page("العملاء والمشاريع", "customers", template, rows=rows, statuses=statuses)


@app.route("/customers/create", methods=["POST"])
@login_required
def customer_create():
    try:
        name = clean_text(request.form.get("name"), "اسم العميل", max_len=180)
        phone = clean_text(request.form.get("phone"), "الهاتف", max_len=80, required=False)
        project_details = clean_multiline(request.form.get("project_details"), "تفاصيل المشروع", required=False)
        status = clean_text(request.form.get("status"), "الحالة", max_len=30)
        if status not in ("مكتمل", "قيد التنفيذ"):
            raise ValueError("حالة المشروع غير صحيحة.")
        get_db().execute(
            "INSERT INTO customers (name, phone, project_details, status) VALUES (?, ?, ?, ?)",
            (name, phone, project_details, status),
        )
        get_db().commit()
        flash("تم حفظ العميل.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("customers"))


@app.route("/customers/<int:customer_id>/update", methods=["POST"])
@login_required
def customer_update(customer_id):
    try:
        name = clean_text(request.form.get("name"), "اسم العميل", max_len=180)
        phone = clean_text(request.form.get("phone"), "الهاتف", max_len=80, required=False)
        project_details = clean_multiline(request.form.get("project_details"), "تفاصيل المشروع", required=False)
        status = clean_text(request.form.get("status"), "الحالة", max_len=30)
        if status not in ("مكتمل", "قيد التنفيذ"):
            raise ValueError("حالة المشروع غير صحيحة.")
        get_db().execute(
            "UPDATE customers SET name = ?, phone = ?, project_details = ?, status = ? WHERE id = ?",
            (name, phone, project_details, status, customer_id),
        )
        get_db().commit()
        flash("تم تحديث بيانات العميل.", "success")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("customers"))


@app.route("/customers/<int:customer_id>/delete", methods=["POST"])
@login_required
def customer_delete(customer_id):
    get_db().execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    get_db().commit()
    flash("تم حذف العميل.", "success")
    return redirect(url_for("customers"))


@app.route("/users")
@admin_required
def users():
    rows = get_db().execute("SELECT id, username, role FROM users ORDER BY id ASC").fetchall()

    template = """
    <div class="grid xl:grid-cols-3 gap-6">
        <form method="post" action="{{ url_for('user_create') }}" class="glass rounded-3xl p-6 shadow-soft">
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            <h2 class="text-xl font-black mb-1">إضافة مستخدم</h2>
            <p class="text-sm text-slate-400 mb-5">إدارة المستخدمين متاحة للمدير فقط.</p>

            <div class="space-y-4">
                <label>
                    <span class="text-sm text-slate-300 font-bold">اسم المستخدم</span>
                    <input class="input mt-2" name="username" required maxlength="80" autocomplete="off">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">كلمة المرور</span>
                    <input class="input mt-2" type="password" name="password" required minlength="4" autocomplete="new-password">
                </label>
                <label>
                    <span class="text-sm text-slate-300 font-bold">الدور</span>
                    <select class="input mt-2" name="role">
                        {% for role in roles %}
                        <option value="{{ role }}">{{ role }}</option>
                        {% endfor %}
                    </select>
                </label>
                <button class="btn btn-primary w-full"><i class="fa-solid fa-user-plus"></i> إضافة المستخدم</button>
            </div>
        </form>

        <div class="xl:col-span-2 glass rounded-3xl p-6 shadow-soft">
            <div class="flex items-center justify-between mb-5">
                <div>
                    <h2 class="text-xl font-black">إدارة المستخدمين</h2>
                    <p class="text-sm text-slate-400">إضافة، تعديل، أو حذف الحسابات وتحديد الصلاحيات.</p>
                </div>
            </div>

            <div class="overflow-x-auto scrollbar-thin">
                <table class="w-full text-sm min-w-[760px]">
                    <thead>
                        <tr class="table-head border-b border-slate-700/70">
                            <th class="py-3 text-right">#</th>
                            <th class="py-3 text-right">اسم المستخدم</th>
                            <th class="py-3 text-right">كلمة مرور جديدة</th>
                            <th class="py-3 text-right">الدور</th>
                            <th class="py-3 text-right">إجراءات</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in rows %}
                        <tr class="border-b border-slate-800/70 align-top">
                            <form method="post" action="{{ url_for('user_update', user_id=row.id) }}">
                                <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                <td class="py-3 font-bold">{{ row.id }}</td>
                                <td class="py-3 pl-3"><input class="input" name="username" value="{{ row.username }}" required></td>
                                <td class="py-3 pl-3"><input class="input" type="password" name="password" placeholder="اتركها فارغة لعدم التغيير" autocomplete="new-password"></td>
                                <td class="py-3 pl-3">
                                    <select class="input" name="role">
                                        {% for role in roles %}
                                        <option value="{{ role }}" {% if row.role == role %}selected{% endif %}>{{ role }}</option>
                                        {% endfor %}
                                    </select>
                                </td>
                                <td class="py-3">
                                    <div class="flex gap-2">
                                        <button class="btn btn-muted py-2 px-3"><i class="fa-solid fa-floppy-disk"></i></button>
                            </form>
                                        <form method="post" action="{{ url_for('user_delete', user_id=row.id) }}" onsubmit="return confirmDelete('حذف هذا المستخدم؟')">
                                            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
                                            <button class="btn btn-danger py-2 px-3" {% if row.id == current_user_id %}disabled title="لا يمكن حذف نفسك"{% endif %}><i class="fa-solid fa-trash"></i></button>
                                        </form>
                                    </div>
                                </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """
    return render_page("إدارة المستخدمين", "users", template, rows=rows, roles=ROLES, current_user_id=current_user()["id"])


@app.route("/users/create", methods=["POST"])
@admin_required
def user_create():
    try:
        username = clean_text(request.form.get("username"), "اسم المستخدم", max_len=80)
        password = request.form.get("password") or ""
        role = clean_text(request.form.get("role"), "الدور", max_len=30)
        if len(password) < 4:
            raise ValueError("كلمة المرور يجب ألا تقل عن 4 أحرف.")
        if role not in ROLES:
            raise ValueError("الدور غير صحيح.")

        get_db().execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        get_db().commit()
        flash("تم إنشاء المستخدم.", "success")
    except sqlite3.IntegrityError:
        flash("اسم المستخدم موجود مسبقاً.", "error")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/update", methods=["POST"])
@admin_required
def user_update(user_id):
    try:
        username = clean_text(request.form.get("username"), "اسم المستخدم", max_len=80)
        password = request.form.get("password") or ""
        role = clean_text(request.form.get("role"), "الدور", max_len=30)
        if role not in ROLES:
            raise ValueError("الدور غير صحيح.")

        target = get_db().execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)

        admin_count = scalar("SELECT COUNT(*) FROM users WHERE role = ?", ("مدير",))
        if target["role"] == "مدير" and role != "مدير" and admin_count <= 1:
            raise ValueError("لا يمكن إزالة آخر مدير في النظام.")

        if password:
            if len(password) < 4:
                raise ValueError("كلمة المرور يجب ألا تقل عن 4 أحرف.")
            get_db().execute(
                "UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?",
                (username, generate_password_hash(password), role, user_id),
            )
        else:
            get_db().execute(
                "UPDATE users SET username = ?, role = ? WHERE id = ?",
                (username, role, user_id),
            )

        get_db().commit()
        flash("تم تحديث المستخدم.", "success")
    except sqlite3.IntegrityError:
        flash("اسم المستخدم موجود مسبقاً.", "error")
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def user_delete(user_id):
    if user_id == current_user()["id"]:
        flash("لا يمكنك حذف حسابك الحالي.", "error")
        return redirect(url_for("users"))

    target = get_db().execute("SELECT id, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)

    if target["role"] == "مدير":
        admin_count = scalar("SELECT COUNT(*) FROM users WHERE role = ?", ("مدير",))
        if admin_count <= 1:
            flash("لا يمكن حذف آخر مدير في النظام.", "error")
            return redirect(url_for("users"))

    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    get_db().commit()
    flash("تم حذف المستخدم.", "success")
    return redirect(url_for("users"))


@app.errorhandler(400)
def bad_request(error):
    message = getattr(error, "description", "طلب غير صالح.")
    return (
        render_template_string(
            """
            <!doctype html>
            <html lang="ar" dir="rtl">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>خطأ</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&display=swap" rel="stylesheet">
                <style>body{font-family:Cairo,sans-serif}</style>
            </head>
            <body class="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
                <div class="max-w-lg w-full rounded-3xl bg-slate-900 border border-slate-700 p-8 text-center">
                    <div class="text-5xl font-black text-rose-300 mb-3">400</div>
                    <h1 class="text-2xl font-black mb-2">طلب غير صالح</h1>
                    <p class="text-slate-400 mb-6">{{ message }}</p>
                    <a href="{{ url_for('dashboard') if logged_in else url_for('login') }}" class="inline-flex rounded-2xl bg-sky-600 px-5 py-3 font-black">العودة</a>
                </div>
            </body>
            </html>
            """,
            message=message,
            logged_in=current_user() is not None,
        ),
        400,
    )


@app.errorhandler(403)
def forbidden(_error):
    if current_user():
        return render_page(
            "غير مصرح",
            "",
            """
            <div class="max-w-xl mx-auto glass rounded-3xl p-8 text-center shadow-soft">
                <div class="text-6xl text-rose-300 mb-4"><i class="fa-solid fa-ban"></i></div>
                <h2 class="text-3xl font-black mb-3">غير مصرح</h2>
                <p class="text-slate-400 mb-6">هذه الصفحة متاحة للمدير فقط.</p>
                <a class="btn btn-primary" href="{{ url_for('dashboard') }}">العودة إلى لوحة التحكم</a>
            </div>
            """,
        ), 403
    return redirect(url_for("login"))


@app.errorhandler(404)
def not_found(_error):
    if current_user():
        return render_page(
            "غير موجود",
            "",
            """
            <div class="max-w-xl mx-auto glass rounded-3xl p-8 text-center shadow-soft">
                <div class="text-6xl text-sky-300 mb-4"><i class="fa-solid fa-circle-question"></i></div>
                <h2 class="text-3xl font-black mb-3">الصفحة غير موجودة</h2>
                <p class="text-slate-400 mb-6">الرابط المطلوب غير متاح.</p>
                <a class="btn btn-primary" href="{{ url_for('dashboard') }}">العودة إلى لوحة التحكم</a>
            </div>
            """,
        ), 404
    return redirect(url_for("login"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)