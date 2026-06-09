import os
import re
import csv
import io
import json
import shutil
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask, Response, abort, flash, g, jsonify, redirect,
    render_template_string, request, session, url_for
)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

APP_NAME = "Abu Haitham for Solar Energy"
CURRENCY = "ج.س"
ROLES = ("مدير", "محاسب", "فني تركيبات")
STATUSES = ("قيد التنفيذ", "مكتمل")
BASE_DIR = Path(__file__).resolve().parent


def usable_dir(path: Path, fallback: Path) -> Path:
    for p in (path, fallback):
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


DATA_DIR = (
    Path(os.environ["DATA_DIR"]).expanduser()
    if os.environ.get("DATA_DIR")
    else usable_dir(Path("/var/data"), BASE_DIR / "instance")
    if (Path("/var/data").exists() or os.environ.get("RENDER"))
    else usable_dir(BASE_DIR / "instance", BASE_DIR)
)
DB_PATH = Path(os.environ.get("DATABASE_PATH", DATA_DIR / "solar_system.sqlite3")).expanduser()
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", DATA_DIR / "backups")).expanduser()
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=60 * 60 * 10,
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)


def get_db():
    if "db" not in g:
        con = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=5000")
        g.db = con
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    con = g.pop("db", None)
    if con:
        con.close()


def init_db():
    with sqlite3.connect(DB_PATH, timeout=15) as con:
        con.executescript("""
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('مدير','محاسب','فني تركيبات'))
        );

        CREATE TABLE IF NOT EXISTS inventory(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'عام',
            qty INTEGER NOT NULL DEFAULT 0 CHECK(qty>=0),
            cost REAL NOT NULL DEFAULT 0 CHECK(cost>=0),
            price REAL NOT NULL DEFAULT 0 CHECK(price>=0)
        );

        CREATE TABLE IF NOT EXISTS invoices(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            customer_phone TEXT,
            date TEXT NOT NULL,
            labor_cost REAL NOT NULL DEFAULT 0 CHECK(labor_cost>=0),
            expenses_cost REAL NOT NULL DEFAULT 0 CHECK(expenses_cost>=0),
            grand_total REAL NOT NULL DEFAULT 0 CHECK(grand_total>=0)
        );

        CREATE TABLE IF NOT EXISTS invoice_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            product_id INTEGER,
            product_name TEXT NOT NULL,
            qty INTEGER NOT NULL CHECK(qty>0),
            price REAL NOT NULL CHECK(price>=0),
            cost REAL NOT NULL CHECK(cost>=0),
            FOREIGN KEY(invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES inventory(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS expenses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            description TEXT NOT NULL,
            amount REAL NOT NULL CHECK(amount>=0),
            category TEXT NOT NULL DEFAULT 'عام',
            date TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS customers(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT,
            project_details TEXT,
            status TEXT NOT NULL CHECK(status IN ('مكتمل','قيد التنفيذ')) DEFAULT 'قيد التنفيذ'
        );

        CREATE INDEX IF NOT EXISTS idx_inventory_name ON inventory(name);
        CREATE INDEX IF NOT EXISTS idx_invoice_date ON invoices(date);
        CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice ON invoice_items(invoice_id);
        CREATE INDEX IF NOT EXISTS idx_expense_date ON expenses(date);
        CREATE INDEX IF NOT EXISTS idx_customer_status ON customers(status);
        """)
        if not con.execute("SELECT 1 FROM users WHERE username=?", ("amgad",)).fetchone():
            con.execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                ("amgad", generate_password_hash("123456"), "مدير"),
            )
        con.commit()


with app.app_context():
    init_db()


def csrf_token():
    session.setdefault("_csrf_token", secrets.token_urlsafe(32))
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_guard():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
        if not token and request.is_json:
            token = (request.get_json(silent=True) or {}).get("_csrf_token")
        if token != session.get("_csrf_token"):
            abort(400, "رمز الأمان غير صالح. أعد تحميل الصفحة وحاول مرة أخرى.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp


def user():
    return session.get("user")


def login_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not user():
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return inner


def admin_required(fn):
    @wraps(fn)
    def inner(*a, **kw):
        if not user():
            return redirect(url_for("login", next=request.path))
        if user()["role"] != "مدير":
            abort(403)
        return fn(*a, **kw)
    return inner


def clean(v, limit=255, required=True):
    v = re.sub(r"\s+", " ", (v or "").strip())
    if required and not v:
        raise ValueError("يوجد حقل مطلوب فارغ.")
    if len(v) > limit:
        raise ValueError(f"النص أطول من {limit} حرف.")
    return v


def amount(v, label="المبلغ", minimum=0):
    try:
        n = float(str(v or "0").replace(",", "").strip())
    except ValueError:
        raise ValueError(f"{label} يجب أن يكون رقماً.")
    if n < minimum:
        raise ValueError(f"{label} لا يمكن أن يكون أقل من {minimum}.")
    return round(n, 2)


def qty(v, label="الكمية", minimum=0):
    try:
        n = int(str(v or "0").replace(",", "").strip())
    except ValueError:
        raise ValueError(f"{label} يجب أن تكون رقماً صحيحاً.")
    if n < minimum:
        raise ValueError(f"{label} لا يمكن أن تكون أقل من {minimum}.")
    return n


def q1(sql, p=()):
    return get_db().execute(sql, p).fetchone()


def qa(sql, p=()):
    return get_db().execute(sql, p).fetchall()


def today():
    return date.today().isoformat()


def money(v):
    try:
        v = float(v or 0)
    except Exception:
        v = 0
    return f"{v:,.0f} {CURRENCY}" if v.is_integer() else f"{v:,.2f} {CURRENCY}"


@app.template_filter("money")
def money_filter(v):
    return money(v)


@app.template_filter("num")
def num_filter(v):
    try:
        v = float(v or 0)
    except Exception:
        v = 0
    return f"{v:,.0f}" if v.is_integer() else f"{v:,.2f}"


def backup_db():
    if DB_PATH.exists():
        dst = BACKUP_DIR / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sqlite3"
        shutil.copy2(DB_PATH, dst)
        return dst
    return None


def metrics():
    r = q1("""
    SELECT
    COALESCE((SELECT SUM(grand_total) FROM invoices),0) gross_sales,
    COALESCE((SELECT SUM(qty) FROM inventory),0) inventory_pieces,
    COALESCE((SELECT COUNT(*) FROM customers WHERE status='قيد التنفيذ'),0) active_projects,
    COALESCE((SELECT SUM(amount) FROM expenses),0) total_expenses,
    COALESCE((SELECT SUM((price-cost)*qty) FROM invoice_items),0) product_profit,
    COALESCE((SELECT SUM(labor_cost) FROM invoices),0) labor_profit
    """)
    d = dict(r)
    d["net_profit"] = (
        float(d["product_profit"] or 0)
        + float(d["labor_profit"] or 0)
        - float(d["total_expenses"] or 0)
    )
    return d


BASE = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} - {{ app_name }}</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<script>
tailwind.config={theme:{extend:{fontFamily:{sans:['Cairo','Tajawal','system-ui','sans-serif']},colors:{gold:'#f5c451',ink:'#070a12'},boxShadow:{premium:'0 24px 75px rgba(0,0,0,.38)'}}}}
</script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap');
*{font-family:Cairo,system-ui,sans-serif}
body{background:radial-gradient(circle at 85% 0,rgba(245,196,81,.17),transparent 35%),#070a12}
.glass{background:rgba(15,23,42,.74);border:1px solid rgba(148,163,184,.17);backdrop-filter:blur(18px)}
.soft{background:rgba(2,6,23,.74);border:1px solid rgba(148,163,184,.25);color:#e5e7eb}
.soft:focus{outline:0;border-color:#f5c451;box-shadow:0 0 0 3px rgba(245,196,81,.13)}
.gold{background:linear-gradient(135deg,#f5c451,#d69e2e);color:#111827;font-weight:900}
.link.active,.link:hover{background:rgba(245,196,81,.14);color:#fff;border-color:rgba(245,196,81,.35)}
.tr:hover{background:rgba(245,196,81,.055)}
</style>
</head>
<body class="min-h-screen text-slate-100">
<div class="flex min-h-screen">
<aside class="fixed right-0 top-0 hidden h-screen w-80 flex-col border-l border-white/10 bg-slate-950/95 p-5 lg:flex">
<div class="mb-7 flex gap-3">
<div class="grid h-12 w-12 place-items-center rounded-2xl bg-gold text-slate-950"><i class="fa-solid fa-solar-panel"></i></div>
<div><h1 class="font-black">{{ app_name }}</h1><p class="text-xs text-slate-400">واجهة One Million عربية</p></div>
</div>
<nav class="space-y-2">
{% set L=[('dashboard','لوحة التحكم','fa-chart-line'),('inventory','المستودع والمخزن','fa-warehouse'),('invoices','المبيعات والفواتير','fa-file-invoice-dollar'),('expenses','المصروفات','fa-receipt'),('customers','العملاء والمشاريع','fa-users-gear')] %}
{% for ep,la,ic in L %}
<a class="link {{'active' if active==ep else ''}} flex items-center gap-3 rounded-2xl border border-transparent px-4 py-3 text-sm font-bold text-slate-300" href="{{ url_for(ep) }}">
<i class="fa-solid {{ic}} w-5 text-gold"></i>{{la}}</a>
{% endfor %}
{% if u.role=='مدير' %}
<a class="link {{'active' if active=='users' else ''}} flex items-center gap-3 rounded-2xl border border-transparent px-4 py-3 text-sm font-bold text-slate-300" href="{{ url_for('users') }}">
<i class="fa-solid fa-user-shield w-5 text-gold"></i>إدارة المستخدمين</a>
{% endif %}
</nav>
<div class="mt-auto rounded-3xl bg-white/[.04] p-4">
<b>{{u.username}}</b><p class="text-xs text-slate-400">{{u.role}}</p>
<a class="mt-3 block rounded-2xl bg-red-500/10 p-3 text-center font-bold text-red-200" href="{{ url_for('logout') }}">تسجيل الخروج</a>
</div>
</aside>

<main class="w-full lg:mr-80">
<header class="sticky top-0 z-30 border-b border-white/10 bg-slate-950/80 p-4 backdrop-blur-xl">
<div class="flex items-center justify-between">
<div><h2 class="text-2xl font-black">{{ title }}</h2><p class="text-xs text-slate-400">{{ now }} · العملة: {{ currency }}</p></div>
<button onclick="m.classList.toggle('hidden')" class="rounded-2xl bg-white/10 p-3 lg:hidden"><i class="fa-solid fa-bars"></i></button>
</div>
</header>

<div id="m" class="fixed inset-0 z-50 hidden bg-black/80 p-4 lg:hidden">
<div class="glass h-full rounded-3xl p-4">
<button onclick="m.classList.add('hidden')" class="mb-4 rounded-xl bg-white/10 px-4 py-2">إغلاق</button>
<a class="block p-3" href="{{url_for('dashboard')}}">لوحة التحكم</a>
<a class="block p-3" href="{{url_for('inventory')}}">المستودع</a>
<a class="block p-3" href="{{url_for('invoices')}}">الفواتير</a>
<a class="block p-3" href="{{url_for('expenses')}}">المصروفات</a>
<a class="block p-3" href="{{url_for('customers')}}">العملاء</a>
{% if u.role=='مدير' %}<a class="block p-3" href="{{url_for('users')}}">المستخدمون</a>{% endif %}
</div>
</div>

<section class="p-4 sm:p-6 lg:p-8">
{% with ms=get_flashed_messages(with_categories=true) %}
{% for c,msg in ms %}
<div class="mb-3 rounded-2xl border px-4 py-3 font-bold {{'border-emerald-400/30 bg-emerald-400/10 text-emerald-100' if c=='success' else 'border-red-400/30 bg-red-400/10 text-red-100'}}">{{msg}}</div>
{% endfor %}
{% endwith %}
{{ content|safe }}
</section>
</main>
</div>
<script>
function delmsg(t){return confirm(t||'هل أنت متأكد؟')}
function nf(n){return new Intl.NumberFormat('en-US',{maximumFractionDigits:2}).format(Number(n||0))}
</script>
</body>
</html>
"""


def page(title, body, active, **ctx):
    return render_template_string(
        BASE,
        title=title,
        app_name=APP_NAME,
        active=active,
        content=Markup(render_template_string(body, **ctx)),
        u=user(),
        now=datetime.now().strftime("%Y-%m-%d %H:%M"),
        currency=CURRENCY,
    )


LOGIN = """
<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>دخول</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&display=swap');
*{font-family:Cairo}
body{background:radial-gradient(circle at 20% 0,rgba(245,196,81,.22),transparent 35%),#050814}
.soft{background:#020617;border:1px solid #334155;color:white}
</style>
</head>
<body class="grid min-h-screen place-items-center p-4 text-white">
<form method="post" class="w-full max-w-md rounded-[2rem] border border-white/10 bg-slate-950/75 p-8 shadow-2xl backdrop-blur-xl">
<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
<div class="mb-8 text-center">
<div class="mx-auto mb-4 grid h-16 w-16 place-items-center rounded-3xl bg-yellow-400 text-slate-950"><i class="fa-solid fa-solar-panel text-2xl"></i></div>
<h1 class="text-2xl font-black">{{app_name}}</h1>
<p class="text-sm text-slate-400">تسجيل دخول آمن</p>
</div>
{% with ms=get_flashed_messages(with_categories=true) %}
{% for c,m in ms %}<p class="mb-3 rounded-2xl bg-red-500/10 p-3 text-red-100">{{m}}</p>{% endfor %}
{% endwith %}
<input name="username" class="soft mb-3 w-full rounded-2xl px-4 py-3" placeholder="اسم المستخدم" required>
<input name="password" type="password" class="soft mb-4 w-full rounded-2xl px-4 py-3" placeholder="كلمة المرور" required>
<button class="w-full rounded-2xl bg-yellow-400 py-3 font-black text-slate-950">دخول النظام</button>
</form>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = clean(request.form.get("username"), 80)
        password = request.form.get("password", "")
        r = q1("SELECT * FROM users WHERE username=?", (username,))
        if not r or not check_password_hash(r["password"], password):
            flash("بيانات الدخول غير صحيحة.", "error")
            return redirect(url_for("login"))
        session.clear()
        session.permanent = True
        session["user"] = {"id": r["id"], "username": r["username"], "role": r["role"]}
        csrf_token()
        return redirect(request.args.get("next") or url_for("dashboard"))
    return render_template_string(LOGIN, app_name=APP_NAME)


@app.route("/logout")
def logout():
    session.clear()
    flash("تم تسجيل الخروج.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    m = metrics()
    low = qa("SELECT name,qty FROM inventory WHERE qty<=5 ORDER BY qty,name LIMIT 7")
    recent = qa("SELECT * FROM invoices ORDER BY id DESC LIMIT 5")
    cards = [
        ("إجمالي المبيعات", money(m["gross_sales"]), "fa-sack-dollar", "from-emerald-400/20"),
        ("صافي الأرباح", money(m["net_profit"]), "fa-chart-simple", "from-yellow-400/20"),
        ("قطع المخزون", f"{m['inventory_pieces']:,.0f}", "fa-boxes-stacked", "from-sky-400/20"),
        ("المشاريع النشطة", f"{m['active_projects']:,.0f}", "fa-person-digging", "from-purple-400/20"),
        ("إجمالي المصروفات", money(m["total_expenses"]), "fa-money-bill-wave", "from-red-400/20"),
    ]
    body = """
    <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
    {% for label,val,icon,tint in cards %}
    <div class="glass rounded-3xl bg-gradient-to-br {{tint}} to-transparent p-5 shadow-premium">
    <div class="flex items-center justify-between"><div><p class="text-sm font-bold text-slate-400">{{label}}</p><p class="mt-2 text-2xl font-black">{{val}}</p></div><i class="fa-solid {{icon}} text-2xl text-gold"></i></div>
    </div>
    {% endfor %}
    </div>

    <div class="mt-6 grid gap-6 xl:grid-cols-3">
    <section class="glass rounded-3xl p-5 xl:col-span-2">
    <div class="mb-3 flex justify-between"><h3 class="text-lg font-black"><i class="fa-solid fa-brain ml-2 text-gold"></i>المساعد المالي الذكي</h3><span class="rounded-full bg-gold/10 px-3 py-1 text-xs text-gold">AJAX</span></div>
    <div id="chat" class="mb-3 h-72 overflow-y-auto rounded-3xl bg-slate-950/70 p-4">
    <div class="mb-2 max-w-[85%] rounded-3xl rounded-tr-none bg-white/10 p-3 text-sm">اسأل: ما صافي الأرباح؟ كم مخزون البطاريات؟ إجمالي المصروفات؟ أفضل المنتجات مبيعاً؟</div>
    </div>
    <form id="f" class="flex gap-2"><input id="csrf" type="hidden" value="{{csrf_token()}}"><input id="q" class="soft flex-1 rounded-2xl px-4 py-3" placeholder="اكتب السؤال..."><button class="gold rounded-2xl px-5"><i class="fa-solid fa-paper-plane"></i></button></form>
    </section>

    <aside class="space-y-6">
    <section class="glass rounded-3xl p-5"><h3 class="mb-3 font-black">تنبيهات المخزون</h3>
    {% for x in low %}<div class="mb-2 flex justify-between rounded-2xl bg-white/5 p-3"><b>{{x.name}}</b><span class="text-red-200">{{x.qty}}</span></div>
    {% else %}<p class="text-emerald-200">المخزون مستقر.</p>{% endfor %}
    </section>
    <section class="glass rounded-3xl p-5"><h3 class="mb-3 font-black">آخر الفواتير</h3>
    {% for i in recent %}<a class="mb-2 block rounded-2xl bg-white/5 p-3" href="{{url_for('invoice_detail',invoice_id=i.id)}}"><b>#{{i.id}} {{i.customer_name}}</b><p class="text-xs text-slate-400">{{i.grand_total|money}}</p></a>
    {% else %}<p class="text-slate-400">لا توجد فواتير.</p>{% endfor %}
    </section>
    </aside>
    </div>

    <script>
    function b(t,m=false){let d=document.createElement('div');d.className='mb-2 max-w-[85%] rounded-3xl p-3 text-sm '+(m?'mr-auto rounded-tl-none bg-gold text-slate-950 font-bold':'rounded-tr-none bg-white/10');d.textContent=t;chat.appendChild(d);chat.scrollTop=chat.scrollHeight}
    f.onsubmit=async e=>{e.preventDefault();let s=q.value.trim();if(!s)return;b(s,true);q.value='';let r=await fetch('{{url_for('api_assistant')}}',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf.value},body:JSON.stringify({question:s})});let j=await r.json();b(j.answer||'لا توجد إجابة.')}
    </script>
    """
    return page("لوحة التحكم", body, "dashboard", cards=cards, low=low, recent=recent)


@app.route("/api/assistant", methods=["POST"])
@login_required
def api_assistant():
    question = clean((request.get_json(silent=True) or {}).get("question"), 500).lower()
    m = metrics()

    if any(w in question for w in ["ربح", "أرباح", "صافي", "profit"]):
        return jsonify(answer=f"صافي الأرباح: {money(m['net_profit'])}. المعادلة: ربح المنتجات {money(m['product_profit'])} + أجور التركيب {money(m['labor_profit'])} - المصروفات {money(m['total_expenses'])}.")

    if any(w in question for w in ["مبيعات", "ايراد", "إيراد", "sales"]):
        return jsonify(answer=f"إجمالي المبيعات هو {money(m['gross_sales'])}.")

    if any(w in question for w in ["مصروف", "مصروفات", "expenses"]):
        cats = qa("SELECT category,SUM(amount) total FROM expenses GROUP BY category ORDER BY total DESC LIMIT 5")
        details = "، ".join(f"{c['category']}: {money(c['total'])}" for c in cats) or "لا توجد تفاصيل بعد."
        return jsonify(answer=f"إجمالي المصروفات {money(m['total_expenses'])}. {details}")

    if any(w in question for w in ["مخزون", "متوفر", "كمية", "stock"]):
        rows = qa("SELECT name,qty FROM inventory ORDER BY name")
        words = [w for w in re.split(r"\s+", question) if len(w) >= 3]
        hits = [r for r in rows if r["name"].lower() in question or any(w in r["name"].lower() for w in words)]
        hits = hits[:5] if hits else qa("SELECT name,qty FROM inventory ORDER BY qty ASC,name LIMIT 5")
        return jsonify(answer="، ".join(f"{r['name']}: {r['qty']} قطعة" for r in hits) if hits else "لا يوجد مخزون مسجل.")

    if any(w in question for w in ["أفضل", "افضل", "مبيع", "منتج"]):
        rows = qa("SELECT product_name,SUM(qty) q,SUM(price*qty) s FROM invoice_items GROUP BY product_name ORDER BY q DESC,s DESC LIMIT 5")
        return jsonify(answer=("أفضل المنتجات: " + "، ".join(f"{r['product_name']} ({r['q']} قطعة / {money(r['s'])})" for r in rows)) if rows else "لا توجد مبيعات بعد.")

    return jsonify(answer="يمكنني حساب الأرباح، المبيعات، المصروفات، المخزون، وأفضل المنتجات من البيانات الحية.")


@app.route("/inventory", methods=["GET", "POST"])
@login_required
def inventory():
    if request.method == "POST":
        try:
            get_db().execute(
                "INSERT INTO inventory(name,category,qty,cost,price) VALUES(?,?,?,?,?)",
                (
                    clean(request.form.get("name"), 160),
                    clean(request.form.get("category"), 120, False) or "عام",
                    qty(request.form.get("qty")),
                    amount(request.form.get("cost"), "التكلفة"),
                    amount(request.form.get("price"), "سعر البيع"),
                ),
            )
            flash("تمت إضافة المنتج.", "success")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("inventory"))

    rows = qa("SELECT * FROM inventory ORDER BY name")
    body = """
    <section class="glass mb-6 rounded-3xl p-5">
    <h3 class="mb-4 font-black">إضافة منتج شمسي</h3>
    <form method="post" class="grid gap-3 md:grid-cols-6">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <input name="name" required class="soft rounded-2xl px-4 py-3 md:col-span-2" placeholder="اسم المنتج">
    <input name="category" class="soft rounded-2xl px-4 py-3" placeholder="التصنيف">
    <input name="qty" type="number" min="0" required class="soft rounded-2xl px-4 py-3" placeholder="الكمية">
    <input name="cost" type="number" min="0" step="0.01" required class="soft rounded-2xl px-4 py-3" placeholder="التكلفة">
    <input name="price" type="number" min="0" step="0.01" required class="soft rounded-2xl px-4 py-3" placeholder="سعر البيع">
    <button class="gold rounded-2xl px-5 py-3 md:col-span-6">حفظ</button>
    </form>
    </section>

    <section class="glass overflow-hidden rounded-3xl"><div class="overflow-x-auto">
    <table class="min-w-full text-sm">
    <thead class="bg-white/[.04]"><tr><th class="p-4 text-right">المنتج</th><th class="p-4 text-right">التصنيف</th><th class="p-4 text-right">المتبقي</th><th class="p-4 text-right">التكلفة</th><th class="p-4 text-right">السعر</th><th class="p-4"></th></tr></thead>
    <tbody>
    {% for x in rows %}
    <tr class="tr border-t border-white/5">
    <form method="post" action="{{url_for('inventory_update',id=x.id)}}">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <td class="p-3"><input name="name" value="{{x.name}}" class="soft w-56 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="category" value="{{x.category}}" class="soft w-36 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="qty" type="number" min="0" value="{{x.qty}}" class="soft w-24 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="cost" type="number" min="0" step="0.01" value="{{x.cost}}" class="soft w-32 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="price" type="number" min="0" step="0.01" value="{{x.price}}" class="soft w-32 rounded-xl px-3 py-2"></td>
    <td class="p-3"><div class="flex gap-2"><button class="rounded-xl bg-emerald-500/15 px-3 py-2 text-emerald-200"><i class="fa-solid fa-check"></i></button></form>
    <form method="post" action="{{url_for('inventory_delete',id=x.id)}}" onsubmit="return delmsg('هل تريد حذف المنتج؟')"><input type="hidden" name="_csrf_token" value="{{csrf_token()}}"><button class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200"><i class="fa-solid fa-trash"></i></button></form></div></td>
    </tr>
    {% else %}<tr><td colspan="6" class="p-8 text-center text-slate-400">لا توجد منتجات.</td></tr>{% endfor %}
    </tbody></table></div></section>
    """
    return page("المستودع والمخزن", body, "inventory", rows=rows)


@app.route("/inventory/<int:id>/update", methods=["POST"])
@login_required
def inventory_update(id):
    try:
        get_db().execute(
            "UPDATE inventory SET name=?,category=?,qty=?,cost=?,price=? WHERE id=?",
            (
                clean(request.form.get("name"), 160),
                clean(request.form.get("category"), 120, False) or "عام",
                qty(request.form.get("qty")),
                amount(request.form.get("cost"), "التكلفة"),
                amount(request.form.get("price"), "سعر البيع"),
                id,
            ),
        )
        flash("تم تحديث المنتج.", "success")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:id>/delete", methods=["POST"])
@login_required
def inventory_delete(id):
    if q1("SELECT COUNT(*) c FROM invoice_items WHERE product_id=?", (id,))["c"]:
        flash("لا يمكن حذف منتج مرتبط بفواتير؛ يمكنك تصفير الكمية.", "error")
    else:
        get_db().execute("DELETE FROM inventory WHERE id=?", (id,))
        flash("تم حذف المنتج.", "success")
    return redirect(url_for("inventory"))


@app.route("/invoices")
@login_required
def invoices():
    q = clean(request.args.get("q"), 140, False)

    if q:
        like = f"%{q}%"
        rows = qa("""
        SELECT DISTINCT i.*
        FROM invoices i
        LEFT JOIN invoice_items ii ON ii.invoice_id = i.id
        WHERE
            CAST(i.id AS TEXT) LIKE ?
            OR i.customer_name LIKE ?
            OR COALESCE(i.customer_phone, '') LIKE ?
            OR i.date LIKE ?
            OR CAST(i.labor_cost AS TEXT) LIKE ?
            OR CAST(i.expenses_cost AS TEXT) LIKE ?
            OR CAST(i.grand_total AS TEXT) LIKE ?
            OR COALESCE(ii.product_name, '') LIKE ?
            OR CAST(COALESCE(ii.qty, 0) AS TEXT) LIKE ?
            OR CAST(COALESCE(ii.price, 0) AS TEXT) LIKE ?
            OR CAST(COALESCE(ii.cost, 0) AS TEXT) LIKE ?
        ORDER BY i.id DESC
        """, (like, like, like, like, like, like, like, like, like, like, like))
    else:
        rows = qa("SELECT * FROM invoices ORDER BY id DESC")

    body = """
    <div class="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
    <div><h3 class="text-xl font-black">المبيعات والفواتير</h3><p class="text-sm text-slate-400">فواتير متعددة الأصناف مع خصم مباشر من المخزون.</p></div>
    <a class="gold rounded-2xl px-5 py-3" href="{{url_for('invoice_new')}}"><i class="fa-solid fa-plus ml-2"></i>فاتورة جديدة</a>
    </div>

    <section class="glass mb-6 rounded-3xl p-5">
    <form method="get" action="{{url_for('invoices')}}" class="grid gap-3 md:grid-cols-6">
    <div class="relative md:col-span-5">
    <i class="fa-solid fa-magnifying-glass absolute right-4 top-1/2 -translate-y-1/2 text-gold"></i>
    <input name="q" value="{{q}}" class="soft w-full rounded-2xl py-3 pr-12 pl-4" placeholder="ابحث برقم الفاتورة، اسم العميل، الهاتف، التاريخ، المبلغ، المنتج، أو أي معلومة داخل الفاتورة...">
    </div>
    <button class="gold rounded-2xl px-5 py-3"><i class="fa-solid fa-search ml-2"></i>بحث</button>
    {% if q %}<a class="rounded-2xl border border-white/10 bg-white/5 px-5 py-3 text-center font-bold text-slate-200 md:col-span-6" href="{{url_for('invoices')}}">إلغاء البحث وعرض كل الفواتير</a>{% endif %}
    </form>
    <div class="mt-3 flex flex-wrap items-center gap-2 text-sm text-slate-400">
    {% if q %}<span>نتائج البحث عن: <b class="text-gold">{{q}}</b></span><span class="rounded-full bg-white/5 px-3 py-1">{{rows|length}} نتيجة</span>{% else %}<span>يعرض النظام جميع الفواتير، ويمكن البحث بأي جزء من بيانات الفاتورة أو منتجاتها.</span>{% endif %}
    </div>
    </section>

    <section class="glass overflow-hidden rounded-3xl"><div class="overflow-x-auto"><table class="min-w-full text-sm">
    <thead class="bg-white/[.04]"><tr><th class="p-4 text-right">#</th><th class="p-4 text-right">العميل</th><th class="p-4 text-right">الهاتف</th><th class="p-4 text-right">التاريخ</th><th class="p-4 text-right">الإجمالي</th><th class="p-4 text-right">تصدير</th></tr></thead>
    <tbody>
    {% for i in rows %}
    <tr class="tr border-t border-white/5">
    <td class="p-4 font-black">#{{i.id}}</td>
    <td class="p-4"><a class="font-bold text-gold" href="{{url_for('invoice_detail',invoice_id=i.id)}}">{{i.customer_name}}</a></td>
    <td class="p-4">{{i.customer_phone or '-'}}</td>
    <td class="p-4">{{i.date}}</td>
    <td class="p-4 font-black">{{i.grand_total|money}}</td>
    <td class="p-4"><div class="flex flex-wrap gap-2">
    <a class="rounded-xl bg-emerald-500/15 px-3 py-2 text-emerald-200" href="{{url_for('invoice_excel',invoice_id=i.id)}}">Excel</a>
    <a class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200" href="{{url_for('invoice_pdf',invoice_id=i.id)}}">PDF</a>
    <a class="rounded-xl bg-sky-500/15 px-3 py-2 text-sky-200" target="_blank" href="{{url_for('invoice_print',invoice_id=i.id)}}">طباعة</a>
    </div></td>
    </tr>
    {% else %}<tr><td colspan="6" class="p-8 text-center text-slate-400">لا توجد فواتير مطابقة للبحث.</td></tr>{% endfor %}
    </tbody></table></div></section>
    """
    return page("المبيعات والفواتير", body, "invoices", rows=rows, q=q)


@app.route("/invoices/new", methods=["GET", "POST"])
@login_required
def invoice_new():
    if request.method == "POST":
        try:
            customer = clean(request.form.get("customer_name"), 160)
            phone = clean(request.form.get("customer_phone"), 80, False)
            inv_date = request.form.get("date") or today()
            labor = amount(request.form.get("labor_cost"), "أجور التركيب")
            inv_exp = amount(request.form.get("expenses_cost"), "مصروفات الفاتورة")
            pids = request.form.getlist("product_id[]")
            qs = request.form.getlist("qty[]")
            prices = request.form.getlist("price[]")
            lines = []
            for pid, qv, pv in zip(pids, qs, prices):
                if pid:
                    lines.append({"pid": qty(pid, "المنتج", 1), "qty": qty(qv, "كمية الصنف", 1), "price": amount(pv, "سعر الصنف")})
            if not lines:
                raise ValueError("أضف صنفاً واحداً على الأقل.")

            con = get_db()
            con.execute("BEGIN IMMEDIATE")
            try:
                stock = {}
                for line in lines:
                    item = con.execute("SELECT * FROM inventory WHERE id=?", (line["pid"],)).fetchone()
                    if not item:
                        raise ValueError("يوجد منتج غير موجود.")
                    stock.setdefault(item["id"], {"item": item, "need": 0})["need"] += line["qty"]

                for data in stock.values():
                    if data["need"] > data["item"]["qty"]:
                        raise ValueError(f"الكمية المطلوبة من {data['item']['name']} أكبر من المتاح ({data['item']['qty']}).")

                total = round(sum(l["qty"] * l["price"] for l in lines) + labor + inv_exp, 2)
                cur = con.execute(
                    "INSERT INTO invoices(customer_name,customer_phone,date,labor_cost,expenses_cost,grand_total) VALUES(?,?,?,?,?,?)",
                    (customer, phone, inv_date, labor, inv_exp, total),
                )
                invoice_id = cur.lastrowid

                for line in lines:
                    item = stock[line["pid"]]["item"]
                    con.execute(
                        "INSERT INTO invoice_items(invoice_id,product_id,product_name,qty,price,cost) VALUES(?,?,?,?,?,?)",
                        (invoice_id, item["id"], item["name"], line["qty"], line["price"], item["cost"]),
                    )
                    con.execute("UPDATE inventory SET qty=qty-? WHERE id=?", (line["qty"], item["id"]))

                con.commit()
            except Exception:
                con.rollback()
                raise

            backup_db()
            flash("تم إنشاء الفاتورة ونسخة احتياطية للمخزون والبيانات.", "success")
            return redirect(url_for("invoice_detail", invoice_id=invoice_id))

        except Exception as e:
            flash(str(e), "error")
            return redirect(url_for("invoice_new"))

    products = qa("SELECT * FROM inventory WHERE qty>0 ORDER BY name")
    body = """
    <section class="glass rounded-3xl p-5">
    <form method="post" class="space-y-5">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <div class="grid gap-3 md:grid-cols-5">
    <input name="customer_name" required class="soft rounded-2xl px-4 py-3 md:col-span-2" placeholder="اسم العميل">
    <input name="customer_phone" class="soft rounded-2xl px-4 py-3" placeholder="الهاتف">
    <input name="date" type="date" value="{{today}}" class="soft rounded-2xl px-4 py-3">
    <input name="labor_cost" type="number" min="0" step="0.01" value="0" oninput="calc()" class="soft rounded-2xl px-4 py-3" placeholder="أجور التركيب">
    <input name="expenses_cost" type="number" min="0" step="0.01" value="0" oninput="calc()" class="soft rounded-2xl px-4 py-3 md:col-span-5" placeholder="مصروفات محملة على الفاتورة">
    </div>
    <div class="overflow-x-auto rounded-3xl border border-white/10">
    <table class="min-w-full text-sm"><thead class="bg-white/[.04]"><tr><th class="p-4 text-right">الصنف</th><th class="p-4 text-right">المتوفر</th><th class="p-4 text-right">الكمية</th><th class="p-4 text-right">السعر</th><th class="p-4 text-right">الإجمالي</th><th></th></tr></thead><tbody id="items"></tbody></table>
    </div>
    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
    <button type="button" onclick="addRow()" class="rounded-2xl border border-white/10 bg-white/5 px-5 py-3 font-bold">+ إضافة صنف</button>
    <b class="rounded-2xl bg-gold/10 px-5 py-3 text-gold">إجمالي الفاتورة: <span id="gt">0</span> {{currency}}</b>
    </div>
    <button class="gold w-full rounded-2xl px-5 py-4 text-lg">حفظ الفاتورة</button>
    </form>
    </section>

    <script>
    const products={{products|safe}},cur={{currency|tojson}};
    function opts(){return '<option value="">اختر المنتج</option>'+products.map(p=>`<option value="${p.id}" data-stock="${p.qty}" data-price="${p.price}">${p.name} — متوفر ${p.qty}</option>`).join('')}
    function addRow(){let tr=document.createElement('tr');tr.className='border-t border-white/5 row';tr.innerHTML=`<td class="p-3"><select required onchange="sync(this)" name="product_id[]" class="soft min-w-72 rounded-xl px-3 py-2">${opts()}</select></td><td class="p-3 stock">-</td><td class="p-3"><input name="qty[]" type="number" min="1" value="1" oninput="calc()" class="soft w-24 rounded-xl px-3 py-2"></td><td class="p-3"><input name="price[]" type="number" min="0" step="0.01" value="0" oninput="calc()" class="soft w-36 rounded-xl px-3 py-2"></td><td class="p-3 line font-black">0 ${cur}</td><td class="p-3"><button type="button" onclick="this.closest('tr').remove();calc()" class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200">×</button></td>`;items.appendChild(tr)}
    function sync(s){let o=s.selectedOptions[0],r=s.closest('tr');r.querySelector('.stock').textContent=o.dataset.stock||'-';r.querySelector('[name="qty[]"]').max=o.dataset.stock||'';r.querySelector('[name="price[]"]').value=o.dataset.price||0;calc()}
    function calc(){let t=0;document.querySelectorAll('.row').forEach(r=>{let q=+r.querySelector('[name="qty[]"]').value||0,p=+r.querySelector('[name="price[]"]').value||0,l=q*p;r.querySelector('.line').textContent=nf(l)+' '+cur;t+=l});t+=(+document.querySelector('[name="labor_cost"]').value||0)+(+document.querySelector('[name="expenses_cost"]').value||0);gt.textContent=nf(t)}
    addRow()
    </script>
    """
    return page("فاتورة جديدة", body, "invoices", products=json.dumps([dict(x) for x in products], ensure_ascii=False), today=today(), currency=CURRENCY)


def invoice_data(invoice_id):
    inv = q1("SELECT * FROM invoices WHERE id=?", (invoice_id,))
    if not inv:
        abort(404)
    return inv, qa("SELECT * FROM invoice_items WHERE invoice_id=? ORDER BY id", (invoice_id,))


@app.route("/invoices/<int:invoice_id>")
@login_required
def invoice_detail(invoice_id):
    inv, items = invoice_data(invoice_id)
    subtotal = sum(x["qty"] * x["price"] for x in items)
    body = """
    <section class="glass rounded-3xl p-6">
    <div class="mb-5 flex flex-col gap-3 border-b border-white/10 pb-5 sm:flex-row sm:justify-between">
    <div><h3 class="text-2xl font-black">فاتورة #{{inv.id}}</h3><p class="text-slate-400">{{inv.date}} · {{inv.customer_name}} · {{inv.customer_phone or '-'}}</p></div>
    <div class="flex gap-2"><a class="rounded-xl bg-emerald-500/15 px-4 py-2 text-emerald-200" href="{{url_for('invoice_excel',invoice_id=inv.id)}}">Excel</a><a class="rounded-xl bg-red-500/15 px-4 py-2 text-red-200" href="{{url_for('invoice_pdf',invoice_id=inv.id)}}">PDF</a><a class="rounded-xl bg-sky-500/15 px-4 py-2 text-sky-200" target="_blank" href="{{url_for('invoice_print',invoice_id=inv.id)}}">طباعة</a></div>
    </div>
    <div class="overflow-x-auto rounded-3xl border border-white/10"><table class="min-w-full text-sm">
    <thead class="bg-white/[.04]"><tr><th class="p-4 text-right">الصنف</th><th class="p-4 text-right">الكمية</th><th class="p-4 text-right">السعر</th><th class="p-4 text-right">الإجمالي</th></tr></thead>
    <tbody>{% for x in items %}<tr class="border-t border-white/5"><td class="p-4 font-bold">{{x.product_name}}</td><td class="p-4">{{x.qty}}</td><td class="p-4">{{x.price|money}}</td><td class="p-4 font-black">{{(x.qty*x.price)|money}}</td></tr>{% endfor %}</tbody>
    </table></div>
    <div class="mt-5 grid gap-3 md:grid-cols-4">
    <div class="rounded-2xl bg-white/5 p-4"><p class="text-sm text-slate-400">إجمالي المنتجات</p><b>{{subtotal|money}}</b></div>
    <div class="rounded-2xl bg-white/5 p-4"><p class="text-sm text-slate-400">أجور التركيب</p><b>{{inv.labor_cost|money}}</b></div>
    <div class="rounded-2xl bg-white/5 p-4"><p class="text-sm text-slate-400">مصروفات الفاتورة</p><b>{{inv.expenses_cost|money}}</b></div>
    <div class="rounded-2xl bg-gold/10 p-4 text-gold"><p class="text-sm">الإجمالي النهائي</p><b class="text-xl">{{inv.grand_total|money}}</b></div>
    </div>
    </section>
    """
    return page(f"فاتورة #{invoice_id}", body, "invoices", inv=inv, items=items, subtotal=subtotal)


@app.route("/invoices/<int:invoice_id>/print")
@login_required
def invoice_print(invoice_id):
    inv, items = invoice_data(invoice_id)
    subtotal = sum(x["qty"] * x["price"] for x in items)
    return render_template_string("""
    <!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>فاتورة</title>
    <style>body{font-family:Tahoma,Arial;margin:30px;color:#111}table{width:100%;border-collapse:collapse}td,th{border:1px solid #ccc;padding:9px;text-align:right}.no{margin-bottom:20px}@media print{.no{display:none}}</style>
    </head><body><button class="no" onclick="print()">طباعة / حفظ PDF</button><h1>{{app_name}}</h1><h2>فاتورة #{{inv.id}}</h2>
    <p>العميل: {{inv.customer_name}} | الهاتف: {{inv.customer_phone or '-'}} | التاريخ: {{inv.date}}</p>
    <table><tr><th>الصنف</th><th>الكمية</th><th>السعر</th><th>الإجمالي</th></tr>{% for x in items %}<tr><td>{{x.product_name}}</td><td>{{x.qty}}</td><td>{{x.price|money}}</td><td>{{(x.qty*x.price)|money}}</td></tr>{% endfor %}</table>
    <p>إجمالي المنتجات: {{subtotal|money}}</p><p>أجور التركيب: {{inv.labor_cost|money}}</p><p>مصروفات الفاتورة: {{inv.expenses_cost|money}}</p><h2>الإجمالي النهائي: {{inv.grand_total|money}}</h2>
    </body></html>
    """, app_name=APP_NAME, inv=inv, items=items, subtotal=subtotal)


@app.route("/invoices/<int:invoice_id>/excel")
@login_required
def invoice_excel(invoice_id):
    inv, items = invoice_data(invoice_id)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow([APP_NAME])
    w.writerow(["فاتورة رقم", inv["id"]])
    w.writerow(["العميل", inv["customer_name"], "الهاتف", inv["customer_phone"] or "", "التاريخ", inv["date"]])
    w.writerow([])
    w.writerow(["الصنف", "الكمية", "السعر", "التكلفة", "الإجمالي"])
    for x in items:
        w.writerow([x["product_name"], x["qty"], x["price"], x["cost"], round(x["qty"] * x["price"], 2)])
    w.writerow([])
    w.writerow(["أجور التركيب", inv["labor_cost"]])
    w.writerow(["مصروفات الفاتورة", inv["expenses_cost"]])
    w.writerow(["الإجمالي النهائي", inv["grand_total"]])
    return Response(
        out.getvalue().encode("utf-8-sig"),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=invoice_{invoice_id}.csv"},
    )


def pdf_escape(s):
    return str(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def simple_pdf(lines):
    y = 805
    stream = ["BT", "0 0 0 rg"]
    for text, size in lines:
        stream.append(f"/F1 {size} Tf 1 0 0 1 42 {y} Tm ({pdf_escape(text)}) Tj")
        y -= int(size * 1.8)
        if y < 45:
            break
    stream.append("ET")
    data = "\n".join(stream).encode("latin-1", "replace")
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(data)).encode() + b" >>\nstream\n" + data + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, obj in enumerate(objs, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{i} 0 obj\n".encode())
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode())
    for off in offsets[1:]:
        pdf.extend(f"{off:010d} 00000 n \n".encode())
    pdf.extend(f"trailer << /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(pdf)


@app.route("/invoices/<int:invoice_id>/pdf")
@login_required
def invoice_pdf(invoice_id):
    inv, items = invoice_data(invoice_id)
    lines = [
        (APP_NAME, 18),
        (f"Invoice #{inv['id']} / فاتورة رقم {inv['id']}", 16),
        (f"Customer: {inv['customer_name']} | Phone: {inv['customer_phone'] or '-'}", 12),
        (f"Date: {inv['date']}", 12),
        ("-" * 75, 10),
    ]
    for x in items:
        lines.append((f"{x['product_name']} | Qty {x['qty']} | Price {money(x['price'])} | Total {money(x['qty']*x['price'])}", 11))
    lines += [
        ("-" * 75, 10),
        (f"Labor: {money(inv['labor_cost'])}", 12),
        (f"Invoice expenses: {money(inv['expenses_cost'])}", 12),
        (f"Grand total: {money(inv['grand_total'])}", 15),
    ]
    return Response(
        simple_pdf(lines),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=invoice_{invoice_id}.pdf"},
    )


@app.route("/expenses", methods=["GET", "POST"])
@login_required
def expenses():
    if request.method == "POST":
        try:
            get_db().execute(
                "INSERT INTO expenses(description,amount,category,date) VALUES(?,?,?,?)",
                (
                    clean(request.form.get("description"), 220),
                    amount(request.form.get("amount")),
                    clean(request.form.get("category"), 120, False) or "عام",
                    request.form.get("date") or today(),
                ),
            )
            flash("تم تسجيل المصروف.", "success")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("expenses"))

    rows = qa("SELECT * FROM expenses ORDER BY date DESC,id DESC")
    total = sum(float(x["amount"]) for x in rows)
    body = """
    <section class="glass mb-6 rounded-3xl p-5">
    <div class="mb-4 flex justify-between"><h3 class="font-black">إضافة مصروف</h3><b class="text-red-200">الإجمالي: {{total|money}}</b></div>
    <form method="post" class="grid gap-3 md:grid-cols-5">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <input name="description" required class="soft rounded-2xl px-4 py-3 md:col-span-2" placeholder="الوصف">
    <input name="category" class="soft rounded-2xl px-4 py-3" placeholder="التصنيف">
    <input name="amount" type="number" min="0" step="0.01" required class="soft rounded-2xl px-4 py-3" placeholder="المبلغ">
    <input name="date" type="date" value="{{today}}" class="soft rounded-2xl px-4 py-3">
    <button class="gold rounded-2xl px-5 py-3 md:col-span-5">حفظ</button>
    </form>
    </section>

    <section class="glass overflow-hidden rounded-3xl"><div class="overflow-x-auto">
    <table class="min-w-full text-sm"><thead class="bg-white/[.04]"><tr><th class="p-4 text-right">الوصف</th><th class="p-4 text-right">التصنيف</th><th class="p-4 text-right">المبلغ</th><th class="p-4 text-right">التاريخ</th><th></th></tr></thead>
    <tbody>
    {% for x in rows %}
    <tr class="tr border-t border-white/5">
    <form method="post" action="{{url_for('expense_update',id=x.id)}}">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <td class="p-3"><input name="description" value="{{x.description}}" class="soft w-72 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="category" value="{{x.category}}" class="soft w-40 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="amount" type="number" min="0" step="0.01" value="{{x.amount}}" class="soft w-36 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="date" type="date" value="{{x.date}}" class="soft w-40 rounded-xl px-3 py-2"></td>
    <td class="p-3"><div class="flex gap-2"><button class="rounded-xl bg-emerald-500/15 px-3 py-2 text-emerald-200"><i class="fa-solid fa-check"></i></button></form>
    <form method="post" action="{{url_for('expense_delete',id=x.id)}}" onsubmit="return delmsg()"><input type="hidden" name="_csrf_token" value="{{csrf_token()}}"><button class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200"><i class="fa-solid fa-trash"></i></button></form></div></td>
    </tr>
    {% else %}<tr><td colspan="5" class="p-8 text-center text-slate-400">لا توجد مصروفات.</td></tr>{% endfor %}
    </tbody></table></div></section>
    """
    return page("المصروفات", body, "expenses", rows=rows, total=total, today=today())


@app.route("/expenses/<int:id>/update", methods=["POST"])
@login_required
def expense_update(id):
    try:
        get_db().execute(
            "UPDATE expenses SET description=?,category=?,amount=?,date=? WHERE id=?",
            (
                clean(request.form.get("description"), 220),
                clean(request.form.get("category"), 120, False) or "عام",
                amount(request.form.get("amount")),
                request.form.get("date") or today(),
                id,
            ),
        )
        flash("تم تحديث المصروف.", "success")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("expenses"))


@app.route("/expenses/<int:id>/delete", methods=["POST"])
@login_required
def expense_delete(id):
    get_db().execute("DELETE FROM expenses WHERE id=?", (id,))
    flash("تم حذف المصروف.", "success")
    return redirect(url_for("expenses"))


@app.route("/customers", methods=["GET", "POST"])
@login_required
def customers():
    if request.method == "POST":
        try:
            status = request.form.get("status") if request.form.get("status") in STATUSES else "قيد التنفيذ"
            get_db().execute(
                "INSERT INTO customers(name,phone,project_details,status) VALUES(?,?,?,?)",
                (
                    clean(request.form.get("name"), 160),
                    clean(request.form.get("phone"), 80, False),
                    clean(request.form.get("project_details"), 800, False),
                    status,
                ),
            )
            flash("تم حفظ العميل/المشروع.", "success")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("customers"))

    rows = qa("SELECT * FROM customers ORDER BY id DESC")
    body = """
    <section class="glass mb-6 rounded-3xl p-5"><h3 class="mb-4 font-black">إضافة عميل أو مشروع</h3>
    <form method="post" class="grid gap-3 md:grid-cols-5">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <input name="name" required class="soft rounded-2xl px-4 py-3" placeholder="اسم العميل">
    <input name="phone" class="soft rounded-2xl px-4 py-3" placeholder="الهاتف">
    <input name="project_details" class="soft rounded-2xl px-4 py-3 md:col-span-2" placeholder="تفاصيل المشروع">
    <select name="status" class="soft rounded-2xl px-4 py-3"><option>قيد التنفيذ</option><option>مكتمل</option></select>
    <button class="gold rounded-2xl px-5 py-3 md:col-span-5">حفظ</button>
    </form></section>

    <section class="glass overflow-hidden rounded-3xl"><div class="overflow-x-auto"><table class="min-w-full text-sm">
    <thead class="bg-white/[.04]"><tr><th class="p-4 text-right">العميل</th><th class="p-4 text-right">الهاتف</th><th class="p-4 text-right">المشروع</th><th class="p-4 text-right">الحالة</th><th></th></tr></thead>
    <tbody>
    {% for x in rows %}
    <tr class="tr border-t border-white/5">
    <form method="post" action="{{url_for('customer_update',id=x.id)}}">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <td class="p-3"><input name="name" value="{{x.name}}" class="soft w-48 rounded-xl px-3 py-2"></td>
    <td class="p-3"><input name="phone" value="{{x.phone}}" class="soft w-40 rounded-xl px-3 py-2"></td>
    <td class="p-3"><textarea name="project_details" class="soft w-96 rounded-xl px-3 py-2">{{x.project_details}}</textarea></td>
    <td class="p-3"><select name="status" class="soft rounded-xl px-3 py-2"><option {{'selected' if x.status=='قيد التنفيذ' else ''}}>قيد التنفيذ</option><option {{'selected' if x.status=='مكتمل' else ''}}>مكتمل</option></select></td>
    <td class="p-3"><div class="flex gap-2"><button class="rounded-xl bg-emerald-500/15 px-3 py-2 text-emerald-200"><i class="fa-solid fa-check"></i></button></form>
    <form method="post" action="{{url_for('customer_delete',id=x.id)}}" onsubmit="return delmsg()"><input type="hidden" name="_csrf_token" value="{{csrf_token()}}"><button class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200"><i class="fa-solid fa-trash"></i></button></form></div></td>
    </tr>
    {% else %}<tr><td colspan="5" class="p-8 text-center text-slate-400">لا توجد مشاريع.</td></tr>{% endfor %}
    </tbody></table></div></section>
    """
    return page("العملاء والمشاريع", body, "customers", rows=rows)


@app.route("/customers/<int:id>/update", methods=["POST"])
@login_required
def customer_update(id):
    try:
        status = request.form.get("status") if request.form.get("status") in STATUSES else "قيد التنفيذ"
        get_db().execute(
            "UPDATE customers SET name=?,phone=?,project_details=?,status=? WHERE id=?",
            (
                clean(request.form.get("name"), 160),
                clean(request.form.get("phone"), 80, False),
                clean(request.form.get("project_details"), 800, False),
                status,
                id,
            ),
        )
        flash("تم تحديث المشروع.", "success")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("customers"))


@app.route("/customers/<int:id>/delete", methods=["POST"])
@login_required
def customer_delete(id):
    get_db().execute("DELETE FROM customers WHERE id=?", (id,))
    flash("تم حذف العميل/المشروع.", "success")
    return redirect(url_for("customers"))


@app.route("/users", methods=["GET", "POST"])
@login_required
@admin_required
def users():
    if request.method == "POST":
        try:
            role = request.form.get("role")
            if role not in ROLES:
                raise ValueError("الدور غير صالح.")
            get_db().execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                (
                    clean(request.form.get("username"), 80),
                    generate_password_hash(clean(request.form.get("password"), 160)),
                    role,
                ),
            )
            flash("تمت إضافة المستخدم.", "success")
        except sqlite3.IntegrityError:
            flash("اسم المستخدم موجود مسبقاً.", "error")
        except Exception as e:
            flash(str(e), "error")
        return redirect(url_for("users"))

    rows = qa("SELECT id,username,role FROM users ORDER BY id")
    body = """
    <section class="glass mb-6 rounded-3xl p-5"><h3 class="mb-4 font-black">إضافة مستخدم</h3>
    <form method="post" class="grid gap-3 md:grid-cols-4">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <input name="username" required class="soft rounded-2xl px-4 py-3" placeholder="اسم المستخدم">
    <input name="password" type="password" required class="soft rounded-2xl px-4 py-3" placeholder="كلمة المرور">
    <select name="role" class="soft rounded-2xl px-4 py-3">{% for r in roles %}<option>{{r}}</option>{% endfor %}</select>
    <button class="gold rounded-2xl px-5 py-3">إضافة</button>
    </form></section>

    <section class="glass overflow-hidden rounded-3xl"><div class="overflow-x-auto"><table class="min-w-full text-sm">
    <thead class="bg-white/[.04]"><tr><th class="p-4 text-right">المستخدم</th><th class="p-4 text-right">الدور</th><th class="p-4 text-right">كلمة مرور جديدة</th><th></th></tr></thead>
    <tbody>
    {% for x in rows %}
    <tr class="tr border-t border-white/5">
    <form method="post" action="{{url_for('user_update',id=x.id)}}">
    <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
    <td class="p-3"><input name="username" value="{{x.username}}" class="soft w-48 rounded-xl px-3 py-2"></td>
    <td class="p-3"><select name="role" class="soft rounded-xl px-3 py-2">{% for r in roles %}<option {{'selected' if x.role==r else ''}}>{{r}}</option>{% endfor %}</select></td>
    <td class="p-3"><input name="password" type="password" class="soft w-56 rounded-xl px-3 py-2" placeholder="اختياري"></td>
    <td class="p-3"><div class="flex gap-2"><button class="rounded-xl bg-emerald-500/15 px-3 py-2 text-emerald-200"><i class="fa-solid fa-check"></i></button></form>
    <form method="post" action="{{url_for('user_delete',id=x.id)}}" onsubmit="return delmsg('هل تريد حذف المستخدم؟')"><input type="hidden" name="_csrf_token" value="{{csrf_token()}}"><button class="rounded-xl bg-red-500/15 px-3 py-2 text-red-200"><i class="fa-solid fa-trash"></i></button></form></div></td>
    </tr>
    {% endfor %}
    </tbody></table></div></section>
    """
    return page("إدارة المستخدمين", body, "users", rows=rows, roles=ROLES)


@app.route("/users/<int:id>/update", methods=["POST"])
@login_required
@admin_required
def user_update(id):
    try:
        role = request.form.get("role")
        if role not in ROLES:
            raise ValueError("الدور غير صالح.")
        if id == user()["id"] and role != "مدير":
            raise ValueError("لا يمكنك إزالة صلاحية المدير من حسابك الحالي.")
        username = clean(request.form.get("username"), 80)
        password = (request.form.get("password") or "").strip()

        if password:
            get_db().execute(
                "UPDATE users SET username=?,role=?,password=? WHERE id=?",
                (username, role, generate_password_hash(password), id),
            )
        else:
            get_db().execute(
                "UPDATE users SET username=?,role=? WHERE id=?",
                (username, role, id),
            )

        if id == user()["id"]:
            session["user"].update(username=username, role=role)

        flash("تم تحديث المستخدم.", "success")
    except sqlite3.IntegrityError:
        flash("اسم المستخدم موجود مسبقاً.", "error")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("users"))


@app.route("/users/<int:id>/delete", methods=["POST"])
@login_required
@admin_required
def user_delete(id):
    if id == user()["id"]:
        flash("لا يمكنك حذف حسابك الحالي.", "error")
        return redirect(url_for("users"))

    target = q1("SELECT role FROM users WHERE id=?", (id,))
    if target and target["role"] == "مدير" and q1("SELECT COUNT(*) c FROM users WHERE role='مدير'")["c"] <= 1:
        flash("لا يمكن حذف آخر مدير.", "error")
        return redirect(url_for("users"))

    get_db().execute("DELETE FROM users WHERE id=?", (id,))
    flash("تم حذف المستخدم.", "success")
    return redirect(url_for("users"))


@app.errorhandler(400)
def e400(e):
    tpl = """
    <html lang="ar" dir="rtl"><meta charset="utf-8">
    <body style="font-family:Tahoma;background:#070a12;color:white;display:grid;place-items:center;min-height:100vh">
    <div><h1>طلب غير صالح</h1><p>{{ e.description }}</p><a style="color:#f5c451" href="{{ url_for('dashboard') if session.get('user') else url_for('login') }}">عودة</a></div>
    </body></html>
    """
    return render_template_string(tpl, e=e), 400


@app.errorhandler(403)
def e403(_):
    tpl = """
    <html lang="ar" dir="rtl"><meta charset="utf-8">
    <body style="font-family:Tahoma;background:#070a12;color:white;display:grid;place-items:center;min-height:100vh">
    <div><h1>غير مصرح</h1><p>هذه الصفحة للمدير فقط.</p><a style="color:#f5c451" href="{{ url_for('dashboard') }}">لوحة التحكم</a></div>
    </body></html>
    """
    return render_template_string(tpl), 403


@app.errorhandler(404)
def e404(_):
    tpl = """
    <html lang="ar" dir="rtl"><meta charset="utf-8">
    <body style="font-family:Tahoma;background:#070a12;color:white;display:grid;place-items:center;min-height:100vh">
    <div><h1>الصفحة غير موجودة</h1><a style="color:#f5c451" href="{{ url_for('dashboard') if session.get('user') else url_for('login') }}">عودة</a></div>
    </body></html>
    """
    return render_template_string(tpl), 404


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"},
    )