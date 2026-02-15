import os
import json
import base64
import hashlib
import secrets
import requests as http_requests
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   session, jsonify, send_file, make_response)
from werkzeug.utils import secure_filename
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# --- Database ---
def get_db():
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company_name TEXT DEFAULT '',
        company_address TEXT DEFAULT '',
        company_email TEXT DEFAULT '',
        company_phone TEXT DEFAULT '',
        logo_data TEXT DEFAULT '',
        brand_color TEXT DEFAULT '#2563eb',
        currency TEXT DEFAULT 'CAD',
        tax_label TEXT DEFAULT 'GST',
        tax_rate REAL DEFAULT 5.0,
        tax_label_2 TEXT DEFAULT '',
        tax_rate_2 REAL DEFAULT 0.0,
        invoice_prefix TEXT DEFAULT 'INV',
        next_invoice_num INTEGER DEFAULT 1001,
        bank_details TEXT DEFAULT '',
        payment_terms TEXT DEFAULT 'Net 30',
        tax_reg_number TEXT DEFAULT '',
        tax_reg_label TEXT DEFAULT 'VAT No.',
        custom_template TEXT DEFAULT '',
        footer_text TEXT DEFAULT '',
        is_superadmin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS invoices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        invoice_number TEXT NOT NULL,
        client_name TEXT NOT NULL,
        client_email TEXT DEFAULT '',
        client_address TEXT DEFAULT '',
        client_phone TEXT DEFAULT '',
        client_tax_id TEXT DEFAULT '',
        issue_date DATE NOT NULL,
        due_date DATE NOT NULL,
        status TEXT DEFAULT 'unpaid',
        subtotal REAL DEFAULT 0,
        tax_1_label TEXT DEFAULT '',
        tax_1_rate REAL DEFAULT 0,
        tax_1_amount REAL DEFAULT 0,
        tax_2_label TEXT DEFAULT '',
        tax_2_rate REAL DEFAULT 0,
        tax_2_amount REAL DEFAULT 0,
        discount_percent REAL DEFAULT 0,
        discount_amount REAL DEFAULT 0,
        total REAL DEFAULT 0,
        currency TEXT DEFAULT 'CAD',
        notes TEXT DEFAULT '',
        source TEXT DEFAULT 'manual',
        created_at TIMESTAMP DEFAULT NOW(),
        paid_at TIMESTAMP DEFAULT NULL
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS invoice_items (
        id SERIAL PRIMARY KEY,
        invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE,
        description TEXT NOT NULL,
        quantity REAL DEFAULT 1,
        unit_price REAL DEFAULT 0,
        amount REAL DEFAULT 0
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS clients (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name TEXT NOT NULL,
        email TEXT DEFAULT '',
        address TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        tax_id TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT NOW()
    )''')
    conn.close()

    # Migrate: add new columns if they don't exist
    conn = get_db()
    cur = conn.cursor()
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS tax_reg_number TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS tax_reg_label TEXT DEFAULT 'VAT No.'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS custom_template TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS footer_text TEXT DEFAULT ''",
        "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS client_tax_id TEXT DEFAULT ''",
        "ALTER TABLE clients ADD COLUMN IF NOT EXISTS tax_id TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN DEFAULT FALSE",
        "UPDATE users SET is_superadmin = TRUE WHERE id = (SELECT MIN(id) FROM users)",
        "ALTER TABLE invoices ADD COLUMN IF NOT EXISTS company_name TEXT DEFAULT ''",
    ]
    for m in migrations:
        try:
            cur.execute(m)
        except Exception:
            pass
    conn.close()

init_db()

# --- Auth helpers ---
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def register_with_hub(company_name, email, currency):
    hub = os.environ.get('FINANCESNAP_URL', 'https://snapsuite.up.railway.app')
    try:
        http_requests.post(f'{hub}/api/register-company', json={
            'app_name': 'InvoiceSnap', 'company_name': company_name,
            'email': email, 'currency': currency,
            'app_url': 'https://invoicesnap.up.railway.app'
        }, timeout=5)
    except: pass

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE id=%s', (session['user_id'],))
    user = cur.fetchone()
    conn.close()
    return user

# --- Auth routes ---
@app.route('/demo')
def demo_auto_login():
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email='demo@snapsuite.app'")
    user = cur.fetchone(); conn.close()
    if user:
        session['user_id'] = user['id']
        return redirect('/')
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cur.fetchone()
        conn.close()
        if user and user['password_hash'] == hash_pw(password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        company = request.form.get('company_name', '')
        currency = request.form.get('currency', 'CAD')
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('login.html', show_register=True)
        conn = get_db()
        cur = conn.cursor()
        try:
            # First user becomes Super Admin
            cur.execute('SELECT COUNT(*) FROM users')
            user_count = cur.fetchone()[0]
            is_superadmin = user_count == 0

            # Set tax defaults based on currency
            tax_label = 'GST'
            tax_rate = 5.0
            tax_label_2 = ''
            tax_rate_2 = 0.0
            if currency == 'INR':
                tax_label = 'CGST'
                tax_rate = 9.0
                tax_label_2 = 'SGST'
                tax_rate_2 = 9.0
            elif currency == 'CAD':
                tax_label = 'GST'
                tax_rate = 5.0
            elif currency == 'EUR':
                tax_label = 'IVA'
                tax_rate = 21.0

            cur.execute('''INSERT INTO users (email, password_hash, company_name, currency,
                          tax_label, tax_rate, tax_label_2, tax_rate_2, is_superadmin)
                          VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
                       (email, hash_pw(password), company, currency,
                        tax_label, tax_rate, tax_label_2, tax_rate_2, is_superadmin))
            user_id = cur.fetchone()[0]
            session['user_id'] = user_id
            conn.close()
            register_with_hub(company, email, currency)
            return redirect(url_for('settings'))
        except psycopg2.IntegrityError:
            conn.close()
            flash('Email already registered', 'error')
    return render_template('login.html', show_register=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Dashboard ---
@app.route('/')
@login_required
def dashboard():
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get filter
    status_filter = request.args.get('status', 'all')
    query = 'SELECT * FROM invoices WHERE user_id=%s'
    params = [user['id']]
    if status_filter != 'all':
        query += ' AND status=%s'
        params.append(status_filter)
    query += ' ORDER BY created_at DESC'
    cur.execute(query, params)
    invoices = cur.fetchall()

    # Summary stats
    cur.execute('''SELECT
        COUNT(*) as total_invoices,
        COALESCE(SUM(total), 0) as total_value,
        COALESCE(SUM(CASE WHEN status='paid' THEN total ELSE 0 END), 0) as total_paid,
        COALESCE(SUM(CASE WHEN status='unpaid' THEN total ELSE 0 END), 0) as total_unpaid,
        COALESCE(SUM(CASE WHEN status='overdue' THEN total ELSE 0 END), 0) as total_overdue,
        COUNT(CASE WHEN status='unpaid' THEN 1 END) as count_unpaid,
        COUNT(CASE WHEN status='overdue' THEN 1 END) as count_overdue,
        COUNT(CASE WHEN status='paid' THEN 1 END) as count_paid
    FROM invoices WHERE user_id=%s''', (user['id'],))
    stats = cur.fetchone()

    # Auto-mark overdue
    cur.execute('''UPDATE invoices SET status='overdue'
                   WHERE user_id=%s AND status='unpaid' AND due_date < CURRENT_DATE''',
                (user['id'],))

    conn.close()

    # Currency symbols
    symbols = {'CAD': 'C$', 'INR': '₹', 'EUR': '€', 'USD': '$', 'GBP': '£'}
    curr_symbol = symbols.get(user['currency'], '$')

    return render_template('dashboard.html', user=user, invoices=invoices,
                         stats=stats, status_filter=status_filter, curr=curr_symbol)

# --- Create Invoice ---
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_invoice():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        # Get form data
        client_name = request.form['client_name']
        client_email = request.form.get('client_email', '')
        client_address = request.form.get('client_address', '')
        client_tax_id = request.form.get('client_tax_id', '')
        issue_date = request.form['issue_date']
        due_date = request.form['due_date']
        notes = request.form.get('notes', '')
        discount_percent = float(request.form.get('discount_percent', 0))

        # Tax from form or user defaults
        tax_1_label = request.form.get('tax_1_label', user['tax_label'])
        tax_1_rate = float(request.form.get('tax_1_rate', user['tax_rate']))
        tax_2_label = request.form.get('tax_2_label', user.get('tax_label_2', ''))
        tax_2_rate = float(request.form.get('tax_2_rate', user.get('tax_rate_2', 0)))

        # Line items
        descriptions = request.form.getlist('item_description[]')
        quantities = request.form.getlist('item_quantity[]')
        prices = request.form.getlist('item_price[]')

        # Calculate totals
        subtotal = 0
        items = []
        for desc, qty, price in zip(descriptions, quantities, prices):
            if desc.strip():
                q = float(qty) if qty else 1
                p = float(price) if price else 0
                amount = q * p
                subtotal += amount
                items.append((desc, q, p, amount))

        discount_amount = subtotal * discount_percent / 100
        taxable = subtotal - discount_amount
        tax_1_amount = taxable * tax_1_rate / 100
        tax_2_amount = taxable * tax_2_rate / 100 if tax_2_rate > 0 else 0
        total = taxable + tax_1_amount + tax_2_amount

        # Generate invoice number
        inv_num = f"{user['invoice_prefix']}-{user['next_invoice_num']}"
        cur.execute('UPDATE users SET next_invoice_num = next_invoice_num + 1 WHERE id=%s', (user['id'],))

        # Save invoice
        cur.execute('''INSERT INTO invoices (user_id, invoice_number, client_name, client_email,
                      client_address, client_tax_id, issue_date, due_date, subtotal, tax_1_label, tax_1_rate,
                      tax_1_amount, tax_2_label, tax_2_rate, tax_2_amount, discount_percent,
                      discount_amount, total, currency, notes, source)
                      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                      RETURNING id''',
                   (user['id'], inv_num, client_name, client_email, client_address, client_tax_id,
                    issue_date, due_date, subtotal, tax_1_label, tax_1_rate, tax_1_amount,
                    tax_2_label, tax_2_rate, tax_2_amount, discount_percent, discount_amount,
                    total, user['currency'], notes, 'manual'))
        invoice_id = cur.fetchone()[0]

        # Save line items
        for desc, qty, price, amount in items:
            cur.execute('''INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, amount)
                          VALUES (%s,%s,%s,%s,%s)''', (invoice_id, desc, qty, price, amount))

        # Save client for future use
        cur.execute('SELECT id FROM clients WHERE user_id=%s AND name=%s', (user['id'], client_name))
        if not cur.fetchone():
            cur.execute('''INSERT INTO clients (user_id, name, email, address, tax_id)
                          VALUES (%s,%s,%s,%s,%s)''', (user['id'], client_name, client_email, client_address, client_tax_id))

        conn.close()
        flash(f'Invoice {inv_num} created!', 'success')
        return redirect(url_for('view_invoice', invoice_id=invoice_id))

    # GET - load clients for autocomplete
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM clients WHERE user_id=%s ORDER BY name', (user['id'],))
    clients = cur.fetchall()
    conn.close()

    today = datetime.now().strftime('%Y-%m-%d')
    due = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
    symbols = {'CAD': 'C$', 'INR': '₹', 'EUR': '€', 'USD': '$', 'GBP': '£'}

    return render_template('create.html', user=user, clients=clients,
                         today=today, due_date=due, curr=symbols.get(user['currency'], '$'))

# --- Scan Invoice ---
@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan_invoice():
    user = get_user()
    if request.method == 'POST':
        file = request.files.get('invoice_file')
        if not file:
            flash('Please upload a file', 'error')
            return redirect(url_for('scan_invoice'))

        # Read file
        file_data = file.read()
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

        # Prepare for Claude API
        import anthropic
        client = anthropic.Anthropic(api_key=os.environ.get('ANTHROPIC_API_KEY'))

        if ext == 'pdf':
            b64 = base64.b64encode(file_data).decode()
            content = [
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": b64}},
                {"type": "text", "text": SCAN_PROMPT}
            ]
        elif ext in ('jpg', 'jpeg', 'png', 'webp'):
            b64 = base64.b64encode(file_data).decode()
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
            content = [
                {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
                {"type": "text", "text": SCAN_PROMPT}
            ]
        else:
            flash('Unsupported file type. Use PDF, JPG, or PNG.', 'error')
            return redirect(url_for('scan_invoice'))

        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": content}]
            )
            result_text = response.content[0].text

            # Extract JSON from response
            if '```json' in result_text:
                result_text = result_text.split('```json')[1].split('```')[0]
            elif '```' in result_text:
                result_text = result_text.split('```')[1].split('```')[0]

            data = json.loads(result_text.strip())
            return render_template('scan_result.html', user=user, data=data,
                                 curr_symbol=get_curr_symbol(user['currency']))
        except Exception as e:
            flash(f'Error scanning invoice: {str(e)}', 'error')
            return redirect(url_for('scan_invoice'))

    return render_template('scan.html', user=user)

SCAN_PROMPT = """Extract all invoice details from this document. Return ONLY valid JSON:
{
    "vendor_name": "company name on invoice",
    "vendor_address": "full address",
    "client_name": "billed to name",
    "client_address": "billed to address",
    "client_email": "email if visible",
    "invoice_number": "invoice number",
    "issue_date": "YYYY-MM-DD",
    "due_date": "YYYY-MM-DD or empty",
    "items": [
        {"description": "item description", "quantity": 1, "unit_price": 0.00, "amount": 0.00}
    ],
    "subtotal": 0.00,
    "tax_details": [
        {"label": "tax name", "rate": 0, "amount": 0.00}
    ],
    "discount": 0.00,
    "total": 0.00,
    "currency": "CAD or INR or EUR etc",
    "payment_terms": "Net 30 etc",
    "notes": "any additional notes"
}
If a field is not visible, use empty string or 0. Always return valid JSON."""

# --- Save scanned invoice ---
@app.route('/save-scanned', methods=['POST'])
@login_required
def save_scanned():
    user = get_user()
    conn = get_db()
    cur = conn.cursor()

    data = json.loads(request.form['scan_data'])

    client_name = request.form.get('client_name', data.get('client_name', ''))
    client_email = request.form.get('client_email', data.get('client_email', ''))
    client_address = request.form.get('client_address', data.get('client_address', ''))
    issue_date = request.form.get('issue_date', data.get('issue_date', datetime.now().strftime('%Y-%m-%d')))
    due_date = request.form.get('due_date', data.get('due_date', ''))
    if not due_date:
        due_date = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')

    # Use scanned values
    subtotal = float(data.get('subtotal', 0))
    total = float(data.get('total', 0))
    tax_details = data.get('tax_details', [])
    tax_1_label = tax_details[0]['label'] if tax_details else ''
    tax_1_rate = float(tax_details[0]['rate']) if tax_details else 0
    tax_1_amount = float(tax_details[0]['amount']) if tax_details else 0
    tax_2_label = tax_details[1]['label'] if len(tax_details) > 1 else ''
    tax_2_rate = float(tax_details[1]['rate']) if len(tax_details) > 1 else 0
    tax_2_amount = float(tax_details[1]['amount']) if len(tax_details) > 1 else 0

    inv_num = data.get('invoice_number', f"{user['invoice_prefix']}-{user['next_invoice_num']}")

    cur.execute('''INSERT INTO invoices (user_id, invoice_number, client_name, client_email,
                  client_address, issue_date, due_date, subtotal, tax_1_label, tax_1_rate,
                  tax_1_amount, tax_2_label, tax_2_rate, tax_2_amount, discount_percent,
                  discount_amount, total, currency, notes, source)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  RETURNING id''',
               (user['id'], inv_num, client_name, client_email, client_address,
                issue_date, due_date, subtotal, tax_1_label, tax_1_rate, tax_1_amount,
                tax_2_label, tax_2_rate, tax_2_amount, 0,
                float(data.get('discount', 0)), total, data.get('currency', user['currency']),
                data.get('notes', ''), 'scanned'))
    invoice_id = cur.fetchone()[0]

    for item in data.get('items', []):
        cur.execute('''INSERT INTO invoice_items (invoice_id, description, quantity, unit_price, amount)
                      VALUES (%s,%s,%s,%s,%s)''',
                   (invoice_id, item['description'], float(item.get('quantity', 1)),
                    float(item.get('unit_price', 0)), float(item.get('amount', 0))))

    conn.close()
    flash(f'Scanned invoice {inv_num} saved!', 'success')
    return redirect(url_for('view_invoice', invoice_id=invoice_id))

# --- View Invoice ---
@app.route('/invoice/<int:invoice_id>')
@login_required
def view_invoice(invoice_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM invoices WHERE id=%s AND user_id=%s', (invoice_id, user['id']))
    invoice = cur.fetchone()
    if not invoice:
        flash('Invoice not found', 'error')
        return redirect(url_for('dashboard'))
    cur.execute('SELECT * FROM invoice_items WHERE invoice_id=%s', (invoice_id,))
    items = cur.fetchall()
    conn.close()
    return render_template('view_invoice.html', user=user, invoice=invoice,
                         items=items, curr=get_curr_symbol(invoice['currency']))

# --- Update Status ---
@app.route('/invoice/<int:invoice_id>/status', methods=['POST'])
@login_required
def update_status(invoice_id):
    user = get_user()
    new_status = request.form['status']
    conn = get_db()
    cur = conn.cursor()
    paid_at = 'NOW()' if new_status == 'paid' else 'NULL'
    cur.execute(f'''UPDATE invoices SET status=%s, paid_at={paid_at}
                   WHERE id=%s AND user_id=%s''', (new_status, invoice_id, user['id']))
    conn.close()
    flash(f'Invoice marked as {new_status}', 'success')
    return redirect(url_for('view_invoice', invoice_id=invoice_id))

# --- Delete Invoice ---
@app.route('/invoice/<int:invoice_id>/delete', methods=['POST'])
@login_required
def delete_invoice(invoice_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM invoices WHERE id=%s AND user_id=%s', (invoice_id, user['id']))
    conn.close()
    flash('Invoice deleted', 'success')
    return redirect(url_for('dashboard'))

# --- Download PDF ---
@app.route('/invoice/<int:invoice_id>/pdf')
@login_required
def download_pdf(invoice_id):
    user = get_user()
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM invoices WHERE id=%s AND user_id=%s', (invoice_id, user['id']))
    invoice = cur.fetchone()
    cur.execute('SELECT * FROM invoice_items WHERE invoice_id=%s', (invoice_id,))
    items = cur.fetchall()
    conn.close()

    if not invoice:
        flash('Invoice not found', 'error')
        return redirect(url_for('dashboard'))

    try:
        pdf_buffer = generate_pdf(user, invoice, items)
        return send_file(pdf_buffer, as_attachment=True,
                        download_name=f"{invoice['invoice_number']}.pdf",
                        mimetype='application/pdf')
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'PDF error: {str(e)}', 'error')
        return redirect(url_for('view_invoice', invoice_id=invoice_id))

def generate_pdf(user, invoice, items):
    from fpdf import FPDF

    # Use ASCII-safe currency symbols for PDF
    pdf_curr_map = {'CAD': 'C$', 'INR': 'Rs.', 'EUR': 'EUR ', 'USD': '$', 'GBP': 'GBP '}
    curr = pdf_curr_map.get(invoice.get('currency', 'CAD'), '$')
    brand = user.get('brand_color', '#2563eb') or '#2563eb'
    # Convert hex to RGB
    br = int(brand[1:3], 16)
    bg = int(brand[3:5], 16)
    bb = int(brand[5:7], 16)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Brand color header bar
    pdf.set_fill_color(br, bg, bb)
    pdf.rect(0, 0, 210, 8, 'F')

    # Company name
    pdf.set_font('Helvetica', 'B', 22)
    pdf.set_text_color(br, bg, bb)
    pdf.set_y(15)
    company_name = user.get('company_name', '') or 'Your Company'
    pdf.cell(0, 10, company_name, ln=True)

    # Company details
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(100, 100, 100)
    if user.get('company_address'):
        for line in str(user['company_address']).split('\n'):
            pdf.cell(0, 5, line, ln=True)
    if user.get('company_email'):
        pdf.cell(0, 5, str(user['company_email']), ln=True)
    if user.get('company_phone'):
        pdf.cell(0, 5, str(user['company_phone']), ln=True)
    if user.get('tax_reg_number'):
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 5, f"{user.get('tax_reg_label', 'VAT No.')}: {user['tax_reg_number']}", ln=True)

    # INVOICE title on the right
    pdf.set_y(15)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 12, 'INVOICE', align='R', ln=True)

    # Invoice meta
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    y = 30
    pdf.set_y(y)
    issue_date = str(invoice.get('issue_date', ''))
    due_date = str(invoice.get('due_date', ''))
    pdf.cell(0, 5, f"Invoice #: {invoice.get('invoice_number', '')}", align='R', ln=True)
    pdf.cell(0, 5, f"Date: {issue_date}", align='R', ln=True)
    pdf.cell(0, 5, f"Due: {due_date}", align='R', ln=True)

    # Status badge
    status = str(invoice.get('status', 'unpaid')).upper()
    status_colors = {'PAID': (34, 197, 94), 'UNPAID': (234, 179, 8), 'OVERDUE': (239, 68, 68)}
    sc = status_colors.get(status, (100, 100, 100))
    pdf.set_y(pdf.get_y() + 2)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(sc[0], sc[1], sc[2])
    pdf.cell(0, 6, f"STATUS: {status}", align='R', ln=True)

    # Bill To
    pdf.set_y(65)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(br, bg, bb)
    pdf.cell(0, 6, 'BILL TO:', ln=True)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 5, str(invoice.get('client_name', '')), ln=True)
    if invoice.get('client_address'):
        for line in str(invoice['client_address']).split('\n'):
            pdf.cell(0, 5, line, ln=True)
    if invoice.get('client_email'):
        pdf.cell(0, 5, str(invoice['client_email']), ln=True)
    if invoice.get('client_tax_id'):
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 5, f"Tax ID: {invoice['client_tax_id']}", ln=True)
        pdf.set_font('Helvetica', '', 10)

    # Items table
    pdf.set_y(pdf.get_y() + 10)

    # Table header
    pdf.set_fill_color(br, bg, bb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(90, 8, ' Description', border=0, fill=True)
    pdf.cell(25, 8, 'Qty', border=0, fill=True, align='C')
    pdf.cell(35, 8, 'Unit Price', border=0, fill=True, align='R')
    pdf.cell(35, 8, 'Amount', border=0, fill=True, align='R')
    pdf.ln()

    # Table rows
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(40, 40, 40)
    for i, item in enumerate(items):
        fill = i % 2 == 0
        if fill:
            pdf.set_fill_color(245, 247, 250)
        desc = str(item.get('description', ''))[:50]
        qty = float(item.get('quantity', 1) or 1)
        price = float(item.get('unit_price', 0) or 0)
        amt = float(item.get('amount', 0) or 0)
        pdf.cell(90, 7, f" {desc}", border=0, fill=fill)
        pdf.cell(25, 7, f"{qty:.0f}" if qty == int(qty) else f"{qty:.2f}", border=0, fill=fill, align='C')
        pdf.cell(35, 7, f"{curr}{price:,.2f}", border=0, fill=fill, align='R')
        pdf.cell(35, 7, f"{curr}{amt:,.2f}", border=0, fill=fill, align='R')
        pdf.ln()

    # Totals section
    pdf.set_y(pdf.get_y() + 5)
    x_label = 125
    x_val = 160

    def add_total_line(label, value, bold=False):
        pdf.set_font('Helvetica', 'B' if bold else '', 10)
        pdf.set_x(x_label)
        pdf.cell(35, 6, label, align='R')
        pdf.cell(35, 6, f"{curr}{float(value or 0):,.2f}", align='R', ln=True)

    add_total_line('Subtotal:', float(invoice.get('subtotal', 0) or 0))

    if float(invoice.get('discount_amount', 0) or 0) > 0:
        add_total_line(f"Discount ({float(invoice.get('discount_percent', 0) or 0):.0f}%):", -float(invoice['discount_amount']))

    if float(invoice.get('tax_1_amount', 0) or 0) > 0:
        add_total_line(f"{invoice.get('tax_1_label', '')} ({float(invoice.get('tax_1_rate', 0) or 0):.1f}%):", float(invoice['tax_1_amount']))

    if float(invoice.get('tax_2_amount', 0) or 0) > 0:
        add_total_line(f"{invoice.get('tax_2_label', '')} ({float(invoice.get('tax_2_rate', 0) or 0):.1f}%):", float(invoice['tax_2_amount']))

    # Total with line
    pdf.set_draw_color(br, bg, bb)
    pdf.set_x(x_label)
    pdf.line(x_label, pdf.get_y(), x_label + 70, pdf.get_y())
    pdf.set_y(pdf.get_y() + 2)
    pdf.set_font('Helvetica', 'B', 13)
    pdf.set_text_color(br, bg, bb)
    pdf.set_x(x_label)
    pdf.cell(35, 8, 'TOTAL:', align='R')
    pdf.cell(35, 8, f"{curr}{float(invoice.get('total', 0) or 0):,.2f}", align='R', ln=True)

    # Bank details
    bank = user.get('bank_details', '') or ''
    if bank:
        pdf.set_y(pdf.get_y() + 15)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'PAYMENT DETAILS:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(80, 80, 80)
        for line in str(bank).split('\n'):
            pdf.cell(0, 4, line, ln=True)

    # Notes
    notes = invoice.get('notes', '') or ''
    if notes:
        pdf.set_y(pdf.get_y() + 10)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(br, bg, bb)
        pdf.cell(0, 5, 'NOTES:', ln=True)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 4, str(notes))

    # Footer bar - only if we have room, otherwise skip
    if pdf.get_y() < 270:
        pdf.set_y(-12)
        pdf.set_fill_color(br, bg, bb)
        pdf.rect(0, 285, 210, 8, 'F')
        pdf.set_font('Helvetica', '', 7)
        pdf.set_text_color(255, 255, 255)
        footer = str(user.get('footer_text', '') or '') or f"Generated by InvoiceSnap  |  {company_name}"
        pdf.cell(0, 4, footer, align='C')

    buffer = BytesIO()
    pdf.output(buffer)
    buffer.seek(0)
    return buffer

# --- Settings ---
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = get_user()
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()

        company_name = request.form.get('company_name', '')
        company_address = request.form.get('company_address', '')
        company_email = request.form.get('company_email', '')
        company_phone = request.form.get('company_phone', '')
        brand_color = request.form.get('brand_color', '#2563eb')
        currency = request.form.get('currency', 'CAD')
        tax_label = request.form.get('tax_label', 'GST')
        tax_rate = float(request.form.get('tax_rate', 5))
        tax_label_2 = request.form.get('tax_label_2', '')
        tax_rate_2 = float(request.form.get('tax_rate_2', 0))
        invoice_prefix = request.form.get('invoice_prefix', 'INV')
        payment_terms = request.form.get('payment_terms', 'Net 30')
        bank_details = request.form.get('bank_details', '')
        tax_reg_number = request.form.get('tax_reg_number', '')
        tax_reg_label = request.form.get('tax_reg_label', 'VAT No.')
        footer_text = request.form.get('footer_text', '')

        # Handle logo upload
        logo_data = user.get('logo_data', '')
        logo_file = request.files.get('logo')
        if logo_file and logo_file.filename:
            img_data = logo_file.read()
            ext = logo_file.filename.rsplit('.', 1)[-1].lower()
            media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
            logo_data = f"data:{media_type};base64,{base64.b64encode(img_data).decode()}"

            # Auto-extract brand color from logo
            extracted = extract_brand_color(img_data)
            if extracted:
                brand_color = extracted

        # Handle custom template upload
        custom_template = user.get('custom_template', '')
        template_file = request.files.get('custom_template')
        if template_file and template_file.filename:
            tpl_data = template_file.read()
            ext = template_file.filename.rsplit('.', 1)[-1].lower()
            if ext == 'pdf':
                custom_template = f"data:application/pdf;base64,{base64.b64encode(tpl_data).decode()}"
            elif ext in ('jpg', 'jpeg', 'png'):
                media_type = f"image/{'jpeg' if ext in ('jpg','jpeg') else ext}"
                custom_template = f"data:{media_type};base64,{base64.b64encode(tpl_data).decode()}"

        cur.execute('''UPDATE users SET company_name=%s, company_address=%s, company_email=%s,
                      company_phone=%s, logo_data=%s, brand_color=%s, currency=%s,
                      tax_label=%s, tax_rate=%s, tax_label_2=%s, tax_rate_2=%s,
                      invoice_prefix=%s, payment_terms=%s, bank_details=%s,
                      tax_reg_number=%s, tax_reg_label=%s, custom_template=%s, footer_text=%s
                      WHERE id=%s''',
                   (company_name, company_address, company_email, company_phone,
                    logo_data, brand_color, currency, tax_label, tax_rate,
                    tax_label_2, tax_rate_2, invoice_prefix, payment_terms,
                    bank_details, tax_reg_number, tax_reg_label, custom_template,
                    footer_text, user['id']))
        conn.close()
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', user=user)

# --- API for SnapSuite ---
@app.route('/api/invoices')
def api_invoices():
    """API endpoint for SnapSuite to pull invoice data"""
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE email=%s', (api_key,))
    user = cur.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid API key'}), 401

    month = request.args.get('month')
    year = request.args.get('year')
    company_name = request.args.get('company_name', '')
    query = 'SELECT * FROM invoices WHERE user_id=%s'
    params = [user['id']]
    if month and year:
        query += ' AND EXTRACT(MONTH FROM issue_date)=%s AND EXTRACT(YEAR FROM issue_date)=%s'
        params.extend([month, year])
    if company_name:
        # Match by company_name, OR match invoices with no company_name if it matches user's default company
        user_company = user.get('company_name', '') or ''
        if user_company.lower().strip() == company_name.lower().strip():
            query += " AND (LOWER(company_name)=LOWER(%s) OR company_name IS NULL OR company_name='')"
        else:
            query += ' AND LOWER(company_name)=LOWER(%s)'
        params.append(company_name)
    cur.execute(query + ' ORDER BY issue_date DESC', params)
    invoices = cur.fetchall()
    conn.close()

    # Convert dates to strings
    for inv in invoices:
        for k, v in inv.items():
            if isinstance(v, (datetime,)):
                inv[k] = v.isoformat()
            elif hasattr(v, 'isoformat'):
                inv[k] = v.isoformat()

    return jsonify({'invoices': invoices, 'count': len(invoices)})

# --- Admin Dashboard (Super Admin only) ---
@app.route('/admin')
@login_required
def admin_dashboard():
    user = get_user()
    if not user.get('is_superadmin'):
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get all companies
    cur.execute('''SELECT u.id, u.email, u.company_name, u.currency, u.created_at,
                  COUNT(i.id) as invoice_count,
                  COALESCE(SUM(i.total), 0) as total_invoiced,
                  COALESCE(SUM(CASE WHEN i.status='paid' THEN i.total ELSE 0 END), 0) as total_paid,
                  COALESCE(SUM(CASE WHEN i.status='unpaid' THEN i.total ELSE 0 END), 0) as total_unpaid,
                  COALESCE(SUM(CASE WHEN i.status='overdue' THEN i.total ELSE 0 END), 0) as total_overdue
                  FROM users u LEFT JOIN invoices i ON u.id = i.user_id
                  GROUP BY u.id ORDER BY u.created_at DESC''')
    companies = cur.fetchall()

    # Platform totals
    cur.execute('''SELECT
        COUNT(*) as total_invoices,
        COALESCE(SUM(total), 0) as total_value,
        COALESCE(SUM(CASE WHEN status='paid' THEN total ELSE 0 END), 0) as total_paid,
        COALESCE(SUM(CASE WHEN status='unpaid' THEN total ELSE 0 END), 0) as total_unpaid,
        COALESCE(SUM(CASE WHEN status='overdue' THEN total ELSE 0 END), 0) as total_overdue,
        (SELECT COUNT(*) FROM users) as total_users
    FROM invoices''')
    platform = cur.fetchone()

    # View specific company's invoices
    company_id = request.args.get('company_id')
    company_invoices = []
    selected_company = None
    if company_id:
        cur.execute('SELECT * FROM users WHERE id=%s', (company_id,))
        selected_company = cur.fetchone()
        cur.execute('SELECT * FROM invoices WHERE user_id=%s ORDER BY created_at DESC', (company_id,))
        company_invoices = cur.fetchall()

    conn.close()
    return render_template('admin.html', user=user, companies=companies,
                         platform=platform, company_invoices=company_invoices,
                         selected_company=selected_company)

# --- Helpers ---
def get_curr_symbol(currency):
    symbols = {'CAD': 'C$', 'INR': '₹', 'EUR': '€', 'USD': '$', 'GBP': '£'}
    return symbols.get(currency, '$')

def extract_brand_color(img_bytes):
    """Extract the dominant non-white/non-black color from a logo."""
    try:
        from PIL import Image
        from collections import Counter
        img = Image.open(BytesIO(img_bytes)).convert('RGB')
        img = img.resize((100, 100))
        pixels = list(img.getdata())
        # Filter out near-white, near-black, and grey pixels
        colored = []
        for r, g, b in pixels:
            brightness = (r + g + b) / 3
            saturation = max(r, g, b) - min(r, g, b)
            if brightness > 30 and brightness < 230 and saturation > 30:
                # Quantize to reduce similar colors
                colored.append((r // 16 * 16, g // 16 * 16, b // 16 * 16))
        if not colored:
            return None
        most_common = Counter(colored).most_common(1)[0][0]
        return f"#{most_common[0]:02x}{most_common[1]:02x}{most_common[2]:02x}"
    except Exception:
        return None

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

# --- Seed Test Data ---
@app.route('/api/seed-test-data', methods=['POST'])
def seed_test_data():
    api_key = request.headers.get('X-API-Key', '')
    if not api_key: return jsonify({'error': 'API key required'}), 401
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute('SELECT * FROM users WHERE email=%s', (api_key,))
    user = cur.fetchone()
    if not user: conn.close(); return jsonify({'error': 'Invalid API key'}), 401
    uid = user['id']

    invoices = [
        ('INV-2026-101','Meridian Architects','meridian@example.com','45 MG Road, Bangalore','9876543210','29ABCDE1234F1Z5',
         '2025-12-01','2025-12-31','paid',50000,'CGST',9,4500,'SGST',9,4500,0,0,59000,'INR','Brand identity design','Bloom Studio'),
        ('INV-2026-102','Zenith Foods Pvt Ltd','zenith@example.com','12 Church St, Bangalore','9876500001','29FGHIJ5678K2Z3',
         '2025-12-15','2026-01-14','paid',120000,'CGST',9,10800,'SGST',9,10800,0,0,141600,'INR','Website redesign + development','Bloom Studio'),
        ('INV-2026-103','Priya Wellness Spa','priya@example.com','88 Lavelle Rd, Bangalore','9812345678','29KLMNO9012P3Z1',
         '2026-01-05','2026-02-04','paid',35000,'CGST',9,3150,'SGST',9,3150,0,0,41300,'INR','Social media content pack','Bloom Studio'),
        ('INV-2026-104','TechNova Solutions','technova@example.com','HSR Layout, Bangalore','9900112233','29PQRST3456U4Z9',
         '2026-01-15','2026-02-14','unpaid',85000,'CGST',9,7650,'SGST',9,7650,0,0,100300,'INR','Mobile app UI/UX design','Bloom Studio'),
        ('INV-2026-105','Green Earth Organics','green@example.com','Koramangala, Bangalore','9988776655','29UVWXY7890Z5Z7',
         '2026-01-20','2026-02-19','unpaid',28000,'CGST',9,2520,'SGST',9,2520,0,0,33040,'INR','Packaging design - 5 SKUs','Bloom Studio'),
        ('INV-2026-106','Meridian Architects','meridian@example.com','45 MG Road, Bangalore','9876543210','29ABCDE1234F1Z5',
         '2026-02-01','2026-03-02','unpaid',75000,'CGST',9,6750,'SGST',9,6750,0,0,88500,'INR','Office interior 3D renders','Bloom Studio'),
        ('INV-2026-107','CloudFirst India','cloud@example.com','Whitefield, Bangalore','9123456780','29QWERT1234Y6Z2',
         '2025-11-01','2025-12-01','overdue',45000,'CGST',9,4050,'SGST',9,4050,0,0,53100,'INR','Pitch deck + investor materials','Bloom Studio'),
        ('INV-2026-108','Namaste Travels','namaste@example.com','Indiranagar, Bangalore','9876012345','29ASDFG5678H7Z4',
         '2025-11-15','2025-12-15','overdue',22000,'CGST',9,1980,'SGST',9,1980,0,0,25960,'INR','Travel brochure design','Bloom Studio'),
    ]
    count = 0
    for inv in invoices:
        cur.execute("""INSERT INTO invoices (user_id,invoice_number,client_name,client_email,client_address,client_phone,client_tax_id,
                       issue_date,due_date,status,subtotal,tax_1_label,tax_1_rate,tax_1_amount,tax_2_label,tax_2_rate,tax_2_amount,
                       discount_percent,discount_amount,total,currency,notes,company_name)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                   (uid,)+inv)
        # Add line items
        cur.execute("SELECT id FROM invoices WHERE invoice_number=%s AND user_id=%s", (inv[0], uid))
        iid = cur.fetchone()['id']
        cur.execute("INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,amount) VALUES (%s,%s,1,%s,%s)",
                   (iid, inv[20], inv[9], inv[9]))
        count += 1
    conn.commit(); conn.close()
    return jsonify({'success': True, 'company': 'Bloom Studio', 'invoices': count})

# --- Demo Setup ---
@app.route('/api/demo-setup', methods=['POST'])
def demo_setup():
    secret = request.headers.get('X-Demo-Secret', '')
    if secret != 'snapsuite-demo-2026': return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db(); cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    demo_email = 'demo@snapsuite.app'
    cur.execute('SELECT * FROM users WHERE email=%s', (demo_email,))
    user = cur.fetchone()
    if not user:
        cur.execute("""INSERT INTO users (email,password_hash,company_name,currency,tax_label,tax_rate,tax_label_2,tax_rate_2,is_superadmin)
                       VALUES (%s,%s,'Bloom Studio','INR','CGST',9,'SGST',9,TRUE) RETURNING *""",
                   (demo_email, hash_pw('demo123')))
        user = cur.fetchone()
        conn.commit()
    uid = user['id']
    cur.execute('SELECT COUNT(*) as cnt FROM invoices WHERE user_id=%s AND company_name=%s', (uid, 'Bloom Studio'))
    if cur.fetchone()['cnt'] == 0:
        invs = [
            ('INV-2026-101','Meridian Architects','2025-12-01','2025-12-31','paid',50000,4500,4500,59000,'Brand identity design'),
            ('INV-2026-102','Zenith Foods Pvt Ltd','2025-12-15','2026-01-14','paid',120000,10800,10800,141600,'Website redesign + development'),
            ('INV-2026-103','Priya Wellness Spa','2026-01-05','2026-02-04','paid',35000,3150,3150,41300,'Social media content pack'),
            ('INV-2026-104','TechNova Solutions','2026-01-15','2026-02-14','unpaid',85000,7650,7650,100300,'Mobile app UI/UX design'),
            ('INV-2026-105','Green Earth Organics','2026-01-20','2026-02-19','unpaid',28000,2520,2520,33040,'Packaging design - 5 SKUs'),
            ('INV-2026-106','Meridian Architects','2026-02-01','2026-03-02','unpaid',75000,6750,6750,88500,'Office interior 3D renders'),
            ('INV-2026-107','CloudFirst India','2025-11-01','2025-12-01','overdue',45000,4050,4050,53100,'Pitch deck + investor materials'),
            ('INV-2026-108','Namaste Travels','2025-11-15','2025-12-15','overdue',22000,1980,1980,25960,'Travel brochure design'),
        ]
        for i in invs:
            cur.execute("""INSERT INTO invoices (user_id,invoice_number,client_name,issue_date,due_date,status,
                           subtotal,tax_1_label,tax_1_rate,tax_1_amount,tax_2_label,tax_2_rate,tax_2_amount,
                           total,currency,notes,company_name)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,'CGST',9,%s,'SGST',9,%s,%s,'INR',%s,'Bloom Studio')""",
                       (uid,i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9]))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'app': 'InvoiceSnap'})
