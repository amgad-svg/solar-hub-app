import os
import sqlite3
import io
import csv
import shutil
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, flash, Response, jsonify, session

app = Flask(__name__)
app.secret_key = 'solar_hub_secure_cloud_ultimate_2026'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'solar_hub.db')
BACKUP_FOLDER = os.path.join(BASE_DIR, 'backups')

if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def backup_database():
    try:
        date_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        backup_filename = f"solar_hub_backup_{date_str}.db"
        backup_path = os.path.join(BACKUP_FOLDER, backup_filename)
        shutil.copyfile(DB_FILE, backup_path)
    except:
        pass

def init_db():
    with get_db_connection() as conn:
        # إنشاء الجداول والتأكد من وجودها إجبارياً لمنع خطأ no such table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
                qty INTEGER NOT NULL, cost REAL NOT NULL, price REAL NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT, customer_name TEXT NOT NULL,
                customer_phone TEXT, date TEXT DEFAULT CURRENT_TIMESTAMP,
                labor_cost REAL DEFAULT 0, grand_total REAL DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS invoice_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id INTEGER,
                product_id TEXT, product_name TEXT, qty INTEGER, price REAL, cost REAL,
                FOREIGN KEY(invoice_id) REFERENCES invoices(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                phone TEXT NOT NULL, project TEXT NOT NULL, status TEXT NOT NULL
            )
        ''')
        
        # التأكد من وجود حساب أمجد الأساسي
        user_check = conn.execute('SELECT COUNT(*) FROM users WHERE username = "amgad"').fetchone()[0]
        if user_check == 0:
            conn.execute("INSERT INTO users (username, password, role) VALUES ('amgad', '123456', 'مدير')")
            
        inv_check = conn.execute('SELECT COUNT(*) FROM inventory').fetchone()[0]
        if inv_check == 0:
            conn.execute("INSERT INTO inventory VALUES ('101', 'لوح جينكو شمسى 550 واط', 'ألواح', 50, 110.0, 150.0)")
            conn.execute("INSERT INTO inventory VALUES ('102', 'إنفيرتر ذكي 5 كيلو واط', 'إنفيرترات', 15, 400.0, 550.0)")
            conn.execute("INSERT INTO inventory VALUES ('103', 'بطارية جيل 200 أمبير', 'بطاريات', 30, 180.0, 240.0)")
        conn.commit()

# واجهة تسجيل الدخول
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8"><title>تسجيل الدخول | Solar Hub</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style> body { font-family: 'Cairo', sans-serif; background-color: #0B132B; } </style>
</head>
<body class="flex items-center justify-center h-screen p-4">
    <div class="w-full max-w-md bg-[#1C2541] p-8 rounded-3xl border border-[#3A506B] shadow-2xl">
        <div class="text-center mb-8">
            <i class="fa-solid fa-solar-panel text-5xl text-[#64DFDF] mb-3"></i>
            <h2 class="text-2xl font-bold text-white">نظام سيلار هب المحاسبي</h2>
            <p class="text-xs text-gray-400 mt-1">يرجى إدخال بيانات الاعتماد للوصول للنظام</p>
        </div>
        
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for message in messages %}
              <div class="p-3 mb-4 bg-red-500/20 text-red-300 border border-red-500/40 rounded-xl text-xs text-center">{{ message }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}

        <form action="/login" method="POST" class="space-y-4 text-xs">
            <div>
                <label class="block text-gray-400 mb-1.5 font-bold">اسم المستخدم</label>
                <input type="text" name="username" required placeholder="amgad" class="w-full bg-[#0B132B] border border-[#3A506B] rounded-xl p-3 text-white focus:outline-none focus:border-[#64DFDF]">
            </div>
            <div>
                <label class="block text-gray-400 mb-1.5 font-bold">كلمة المرور</label>
                <input type="password" name="password" required placeholder="••••••••" class="w-full bg-[#0B132B] border border-[#3A506B] rounded-xl p-3 text-white focus:outline-none focus:border-[#64DFDF]">
            </div>
            <button type="submit" class="w-full bg-[#64DFDF] hover:bg-[#52c7c7] text-[#0B132B] font-bold py-3.5 rounded-xl transition text-sm cursor-pointer mt-2">تسجيل الدخول الآمن</button>
        </form>
    </div>
</body>
</html>
"""

def render_with_layout(active_page, main_content):
    NAV_SIDEBAR = f"""
    <div class="w-64 bg-[#1C2541] flex flex-col justify-between p-4 border-l border-[#3A506B] shrink-0">
        <div>
            <div class="flex items-center gap-3 mb-8 px-2">
                <i class="fa-solid fa-solar-panel text-3xl text-[#64DFDF]"></i>
                <span class="text-xl font-bold text-white">Solar Hub</span>
            </div>
            <nav class="space-y-2">
                <a href="/" class="flex items-center gap-3 px-4 py-3 rounded-xl {'bg-[#3A506B] text-white' if active_page == 'dashboard' else 'text-gray-400 hover:bg-[#3A506B] hover:text-white'} font-medium transition"><i class="fa-solid fa-chart-pie"></i> لوحة التحكم</a>
                <a href="/inventory" class="flex items-center gap-3 px-4 py-3 rounded-xl {'bg-[#3A506B] text-white' if active_page == 'inventory' else 'text-gray-400 hover:bg-[#3A506B] hover:text-white'} font-medium transition"><i class="fa-solid fa-warehouse"></i> المستودع والمخزن</a>
                <a href="/sales" class="flex items-center gap-3 px-4 py-3 rounded-xl {'bg-[#3A506B] text-white' if active_page == 'sales' else 'text-gray-400 hover:bg-[#3A506B] hover:text-white'} font-medium transition"><i class="fa-solid fa-file-invoice-dollar"></i> الفواتير والمبيعات</a>
                <a href="/users_manage" class="flex items-center gap-3 px-4 py-3 rounded-xl {'bg-[#3A506B] text-white' if active_page == 'users_manage' else 'text-gray-400 hover:bg-[#3A506B] hover:text-white'} font-medium transition"><i class="fa-solid fa-user-gear"></i> إدارة المستخدمين</a>
            </nav>
        </div>
        <div class="border-t border-[#3A506B] pt-4 px-2 flex flex-col gap-2">
            <div>
                <p class="text-xs text-gray-400">المستخدِم الحالي:</p>
                <p class="text-sm font-bold text-[#64DFDF]">{session.get('user', 'أمجد')} ({session.get('role', 'مدير')})</p>
            </div>
            <a href="/logout" class="text-xs text-red-400 hover:text-red-300 mt-2"><i class="fa-solid fa-arrow-right-from-bracket ml-1"></i> خروج آمن</a>
        </div>
    </div>
    """
    BASE_HTML = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8"><title>منظومة Solar Hub</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style> body {{ font-family: 'Cairo', sans-serif; background-color: #0B132B; color: #E0E1DD; }} </style>
</head>
<body class="flex h-screen overflow-hidden">
    {NAV_SIDEBAR}
    <div class="flex-1 flex flex-col overflow-y-auto p-8">
        {main_content}
    </div>
</body>
</html>"""
    return render_template_string(BASE_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    init_db() # التأكد من تهيئة الجداول إجبارياً قبل فحص اسم المستخدم
    if request.method == 'POST':
        username = request.form.get('username').strip().lower()
        password = request.form.get('password').strip()
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        if user:
            session['user'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة!")
            return redirect(url_for('login_page'))
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
def dashboard():
    if 'user' not in session: return redirect(url_for('login_page'))
    conn = get_db_connection()
    inventory_data = conn.execute('SELECT * FROM inventory').fetchall()
    sales_data = conn.execute('SELECT * FROM invoices').fetchall()
    total_sales = sum(s['grand_total'] for s in sales_data)
    
    item_profits_row = conn.execute('SELECT SUM((price - cost) * qty) FROM invoice_items').fetchone()
    item_profits = item_profits_row[0] if item_profits_row and item_profits_row[0] is not None else 0
    labor_profits = sum(s['labor_cost'] for s in sales_data)
    net_profit = item_profits + labor_profits
    total_qty = sum(p['qty'] for p in inventory_data)
    
    options_html = "".join([f'<option value="{p["id"]}">{p["name"]} (المتاح: {p["qty"]})</option>' for p in inventory_data])

    BODY = f"""
    <h1 class="text-3xl font-bold text-white mb-6">لوحة الإحصائيات (السحابية المؤمنة)</h1>
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
        <div class="bg-[#1C2541] p-6 rounded-2xl border border-[#3A506B]"><p class="text-xs text-gray-400">إجمالي المبيعات</p><p class="text-2xl font-bold">${total_sales}</p></div>
        <div class="bg-[#1C2541] p-6 rounded-2xl border border-[#3A506B]"><p class="text-xs text-gray-400">صافي الأرباح</p><p class="text-2xl font-bold text-[#64DFDF]">${net_profit}</p></div>
        <div class="bg-[#1C2541] p-6 rounded-2xl border border-[#3A506B]"><p class="text-xs text-gray-400">قطع المخزن المتبقية</p><p class="text-2xl font-bold">${total_qty} قطعة</p></div>
    </div>
    
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div class="lg:col-span-2 bg-[#1C2541] p-6 rounded-2xl border border-[#3A506B]">
            <h2 class="text-lg font-bold mb-4"><i class="fa-solid fa-file-invoice-dollar text-[#64DFDF] ml-1"></i> إصدار فاتورة منظومة شمسية جديدة</h2>
            <form action="/add_multi_invoice" method="POST" class="space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <input type="text" name="customer_name" placeholder="اسم الزبون" required class="bg-[#0B132B] border border-[#3A506B] rounded-xl p-3 text-xs text-white">
                    <input type="text" name="customer_phone" placeholder="رقم هاتف الزبون" required class="bg-[#0B132B] border border-[#3A506B] rounded-xl p-3 text-xs text-white">
                    <input type="number" name="labor_cost" placeholder="أجور فنية وتركيب ($)" class="bg-[#0B132B] border border-[#3A506B] rounded-xl p-3 text-xs text-white">
                </div>
                <div id="itemsContainer"><div class="flex gap-4 item-row"><select name="product_id[]" class="flex-1 bg-[#0B132B] border border-[#3A506B] rounded-xl p-2.5 text-xs text-white">{options_html}</select><input type="number" name="qty[]" value="1" min="1" class="w-24 bg-[#0B132B] border border-[#3A506B] rounded-xl p-2.5 text-xs text-white"></div></div>
                <button type="submit" class="w-full bg-[#64DFDF] text-[#0B132B] font-bold py-3.5 rounded-xl text-xs cursor-pointer">إصدار وحفظ الفاتورة تلقائياً</button>
            </form>
        </div>
        
        <div class="bg-[#1C2541] p-6 rounded-2xl border border-[#3A506B] flex flex-col justify-between h-fit">
            <div>
                <h2 class="text-xl font-bold text-white mb-2 flex items-center gap-2"><i class="fa-solid fa-robot text-[#64DFDF]"></i> المساعد المالي الذكي AI</h2>
                <div class="bg-[#0B132B] p-4 rounded-xl text-xs text-gray-300 min-h-[100px]" id="ai-response">مرحباً أمجد! حساباتك حية ومؤمنة سحابياً بالكامل.</div>
            </div>
            <div class="mt-4 flex gap-2">
                <input type="text" id="ai-input" placeholder="مثال: كم أرباح المحل؟" class="flex-1 bg-[#0B132B] border border-[#3A506B] rounded-xl px-4 py-2 text-xs text-white focus:outline-none">
                <button onclick="askAILive()" class="bg-[#3A506B] text-white px-3 py-1.5 rounded-xl text-xs transition cursor-pointer">استعلام</button>
            </div>
        </div>
    </div>
    <script>
        function askAILive() {{
            const input = document.getElementById('ai-input').value;
            const responseBox = document.getElementById('ai-response');
            if(!input) return;
            responseBox.innerHTML = "جاري الحساب المالي المباشر...";
            fetch('/ai_query?msg=' + encodeURIComponent(input))
                .then(res => res.json())
                .then(data => {{ responseBox.innerHTML = data.reply; }});
            document.getElementById('ai-input').value = '';
        }}
    </script>
    """
    return render_with_layout('dashboard', BODY)

@app.route('/ai_query')
def ai_query():
    msg = request.args.get('msg', '')
    conn = get_db_connection()
    sales_data = conn.execute('SELECT * FROM invoices').fetchall()
    total_sales = sum(s['grand_total'] for s in sales_data)
    item_profits_row = conn.execute('SELECT SUM((price - cost) * qty) FROM invoice_items').fetchone()
    item_profits = item_profits_row[0] if item_profits_row and item_profits_row[0] is not None else 0
    labor_profits = sum(s['labor_cost'] for s in sales_data)
    net_profit = item_profits + labor_profits

    if 'ربح' in msg or 'أرباح' in msg:
        reply = f"صافي أرباح المحل الحالية المسجلة سحابياً هي: <b>${net_profit}</b> من إجمالي مبيعات بلغت <b>${total_sales}</b>."
    else:
        reply = "أنا جاهز لعرض الأرباح والمبيعات الحية، اسألني بدقة وسأجيبك."
    return jsonify({"reply": reply})

@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if 'user' not in session: return redirect(url_for('login_page'))
    conn = get_db_connection()
    if request.method == 'POST':
        p_id, name, cat = request.form.get('id'), request.form.get('name'), request.form.get('category')
        qty, cost, price = int(request.form.get('qty')), float(request.form.get('cost')), float(request.form.get('price'))
        try:
            conn.execute('INSERT INTO inventory VALUES (?, ?, ?, ?, ?, ?)', (p_id, name, cat, qty, cost, price))
            conn.commit()
        except: pass
        return redirect(url_for('inventory'))
    inv = conn.execute('SELECT * FROM inventory').fetchall()
    rows = "".join([f'<tr class="border-b border-[#3A506B]/40"><td class="p-3 text-gray-400 font-mono">#{i["id"]}</td><td class="p-3 font-bold text-white">{i["name"]}</td><td class="p-3">{i["category"]}</td><td class="p-3 text-[#64DFDF] font-bold">{i["qty"]} قطعة</td><td class="p-3">${i["price"]}</td></tr>' for i in inv])
    BODY = f"""<h1 class="text-2xl font-bold mb-6">إدارة أصناف المخزن</h1>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 bg-[#1C2541] rounded-2xl border border-[#3A506B] overflow-hidden"><table class="w-full text-right"><tr class="bg-[#0B132B] text-gray-400 text-xs border-b border-[#3A506B]"><th class="p-3">الكود</th><th class="p-3">الاسم</th><th class="p-3">التصنيف</th><th class="p-3">المتاح</th><th class="p-3">البيع</th></tr>{rows}</table></div>
    </div>"""
    return render_with_layout('inventory', BODY)

@app.route('/sales')
def sales():
    if 'user' not in session: return redirect(url_for('login_page'))
    conn = get_db_connection()
    invoices = conn.execute('SELECT * FROM invoices ORDER BY id DESC').fetchall()
    rows = ""
    for inv in invoices:
        items = conn.execute('SELECT * FROM invoice_items WHERE invoice_id = ?', (inv['id'],)).fetchall()
        summary = ", ".join([f"{i['product_name']} ({i['qty']})" for i in items])
        rows += f'<tr class="border-b border-[#3A506B]/40"><td class="p-3 text-gray-400 font-mono">#{inv["id"]}</td><td class="p-3 text-white font-bold">{inv["customer_name"]}</td><td class="p-3 text-gray-400 font-mono">{inv["customer_phone"]}</td><td class="p-3">{summary}</td><td class="p-3 text-[#64DFDF] font-bold">${inv["grand_total"]}</td></tr>'
    BODY = f"""<h1 class="text-2xl font-bold mb-6">سجل الفواتير والمبيعات السحابي</h1>
    <div class="bg-[#1C2541] rounded-2xl border border-[#3A506B] overflow-hidden"><table class="w-full text-right"><tr class="bg-[#0B132B] text-gray-400 text-xs border-b border-[#3A506B]"><th class="p-3">رقم الفاتورة</th><th class="p-3">العميل</th><th class="p-3">رقم الهاتف</th><th class="p-3">الأصناف والكميات</th><th class="p-3">الإجمالي الشامل</th></tr>{rows}</table></div>"""
    return render_with_layout('sales', BODY)

@app.route('/users_manage', methods=['GET', 'POST'])
def users_manage():
    if 'user' not in session: return redirect(url_for('login_page'))
    conn = get_db_connection()
    if request.method == 'POST':
        new_user = request.form.get('username').strip().lower()
        new_pass = request.form.get('password').strip()
        role = request.form.get('role')
        try:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (new_user, new_pass, role))
            conn.commit()
        except: pass
        return redirect(url_for('users_manage'))
    all_users = conn.execute('SELECT * FROM users').fetchall()
    u_rows = "".join([f'<tr class="border-b border-[#3A506B]/40"><td class="p-3 text-white font-bold">{u["username"]}</td><td class="p-3 text-gray-400">••••••••</td><td class="p-3"><span class="bg-[#3A506B] px-2 py-1 rounded-lg text-white font-bold">{u["role"]}</span></td></tr>' for u in all_users])
    BODY = f"""<h1 class="text-2xl font-bold mb-6">إدارة صلاحيات المستخدمين</h1>
    <div class="bg-[#1C2541] rounded-2xl border border-[#3A506B] overflow-hidden"><table class="w-full text-right"><tr class="bg-[#0B132B] text-gray-400 text-xs border-b border-[#3A506B]"><th class="p-3">اسم المستخدم</th><th class="p-3">كلمة المرور</th><th class="p-3">الصلاحية</th></tr>{u_rows}</table></div>"""
    return render_with_layout('users_manage', BODY)

@app.route('/add_multi_invoice', methods=['POST'])
def add_multi_invoice():
    customer_name = request.form.get('customer_name')
    customer_phone = request.form.get('customer_phone')
    labor_cost = float(request.form.get('labor_cost', 0) or 0)
    product_ids = request.form.getlist('product_id[]')
    quantities = request.form.getlist('qty[]')

    conn = get_db_connection()
    checked_items = []
    grand_materials_total = 0
    for p_id, qty_str in zip(product_ids, quantities):
        qty = int(qty_str)
        product = conn.execute('SELECT * FROM inventory WHERE id = ?', (p_id,)).fetchone()
        if product and product['qty'] >= qty:
            grand_materials_total += product['price'] * qty
            checked_items.append({"product": product, "qty": qty})
            
    grand_total = grand_materials_total + labor_cost
    cursor = conn.cursor()
    cursor.execute('INSERT INTO invoices (customer_name, customer_phone, labor_cost, grand_total) VALUES (?, ?, ?, ?)', (customer_name, customer_phone, labor_cost, grand_total))
    invoice_id = cursor.lastrowid
    for item in checked_items:
        prod, q = item['product'], item['qty']
        conn.execute('UPDATE inventory SET qty = ? WHERE id = ?', (prod['qty'] - q, prod['id']))
        conn.execute('INSERT INTO invoice_items (invoice_id, product_id, product_name, qty, price, cost) VALUES (?, ?, ?, ?, ?, ?)', (invoice_id, prod['id'], prod['name'], q, prod['price'], prod['cost']))
    conn.commit()
    backup_database()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)