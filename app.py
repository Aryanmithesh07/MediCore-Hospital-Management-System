import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1")
DB = os.environ.get("HOSPITAL_DB", os.path.join(os.path.dirname(__file__), "hospital.db"))
ROLES = ("Admin", "Doctor", "Billing")
PAYMENT_METHODS = ("Cash", "Card", "Bank Transfer", "Insurance", "Other")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, role TEXT DEFAULT 'Admin', active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, age INTEGER, gender TEXT, phone TEXT, email TEXT, address TEXT, blood_group TEXT,
        emergency_contact TEXT, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT, doctor_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, specialization TEXT, department TEXT, phone TEXT, email TEXT, availability TEXT,
        active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL, appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL,
        reason TEXT, status TEXT DEFAULT 'Scheduled', created_by INTEGER, updated_at TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id));
    CREATE TABLE IF NOT EXISTS bills (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_code TEXT UNIQUE NOT NULL,
        patient_id INTEGER NOT NULL, consultation REAL DEFAULT 0, medicine REAL DEFAULT 0, tests REAL DEFAULT 0,
        room REAL DEFAULT 0, other REAL DEFAULT 0, total REAL DEFAULT 0, payment_status TEXT DEFAULT 'Pending',
        created_at TEXT NOT NULL, amount_paid REAL NOT NULL DEFAULT 0, payment_method TEXT, payment_date TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id));
    CREATE TABLE IF NOT EXISTS prescriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL, medicine TEXT NOT NULL, dosage TEXT, duration TEXT, instructions TEXT,
        created_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Active',
        FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id));
    CREATE TABLE IF NOT EXISTS patient_history (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        diagnosis TEXT, notes TEXT, visit_date TEXT NOT NULL, created_by INTEGER,
        FOREIGN KEY(patient_id) REFERENCES patients(id));
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        action TEXT NOT NULL, entity TEXT NOT NULL, entity_id INTEGER, created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS bill_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL CHECK(transaction_type IN ('Payment','Refund')), amount REAL NOT NULL,
        method TEXT NOT NULL, transaction_date TEXT NOT NULL, created_by INTEGER,
        FOREIGN KEY(bill_id) REFERENCES bills(id));
    """)
    # Additive migrations keep databases made by earlier versions usable.
    migrations = {
        "users": [("active", "INTEGER NOT NULL DEFAULT 1")],
        "patients": [("active", "INTEGER NOT NULL DEFAULT 1")],
        "doctors": [("active", "INTEGER NOT NULL DEFAULT 1")],
        "appointments": [("created_by", "INTEGER"), ("updated_at", "TEXT")],
        "bills": [("amount_paid", "REAL NOT NULL DEFAULT 0"), ("payment_method", "TEXT"), ("payment_date", "TEXT")],
        "prescriptions": [("status", "TEXT NOT NULL DEFAULT 'Active'")],
        "patient_history": [("created_by", "INTEGER")],
    }
    for table, columns in migrations.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    # Migrate every account created by the previous plain-text login implementation.
    legacy_users = conn.execute("SELECT id,password FROM users").fetchall()
    for user_id, stored_password in legacy_users:
        if not (":" in stored_password and "$" in stored_password):
            conn.execute("UPDATE users SET password=? WHERE id=?",
                         (generate_password_hash(stored_password), user_id))
    user = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not user:
        password = os.environ.get("HOSPITAL_ADMIN_PASSWORD", "")
        if len(password) < 12:
            conn.close()
            raise RuntimeError("Set HOSPITAL_ADMIN_PASSWORD to a unique password with at least 12 characters before first launch.")
        conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                     ("admin", generate_password_hash(password), "Admin"))
    conn.execute("UPDATE bills SET amount_paid=total WHERE payment_status='Paid' AND amount_paid=0 AND total>0")
    if conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0] == 0:
        conn.executemany("""INSERT INTO doctors(doctor_code,name,specialization,department,phone,email,availability)
            VALUES(?,?,?,?,?,?,?)""", [
            ("DOC001", "Dr. Anjali Menon", "Cardiology", "Cardiology", "+91 9876543210", "anjali@medicare.com", "Mon-Fri 9:00 AM - 2:00 PM"),
            ("DOC002", "Dr. Rahul Nair", "General Medicine", "OPD", "+91 9876543211", "rahul@medicare.com", "Mon-Sat 10:00 AM - 4:00 PM"),
            ("DOC003", "Dr. Meera Thomas", "Pediatrics", "Pediatrics", "+91 9876543212", "meera@medicare.com", "Tue-Sat 9:00 AM - 1:00 PM")])
    conn.commit()
    conn.close()


@app.before_request
def protect_forms():
    if request.method == "POST":
        token = session.get("csrf_token")
        supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or not supplied or not secrets.compare_digest(token, supplied):
            abort(400, "Invalid or expired form token. Refresh and try again.")


@app.context_processor
def inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


def login_required(*roles):
    def decorate(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                abort(403)
            return func(*args, **kwargs)
        return wrapped
    return decorate


def audit(action, entity, entity_id=None):
    get_db().execute("INSERT INTO audit_log(user_id,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)",
                     (session.get("user_id"), action, entity, entity_id, datetime.now().isoformat(timespec="seconds")))


def clean(name, required=False, maximum=500):
    value = request.form.get(name, "").strip()
    if required and not value:
        raise ValueError(f"{name.replace('_', ' ').capitalize()} is required.")
    if len(value) > maximum:
        raise ValueError(f"{name.replace('_', ' ').capitalize()} must be {maximum} characters or fewer.")
    return value or None


def valid_date(value, label="Date"):
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise ValueError(f"Enter a valid {label.lower()}.")


def money_fields():
    values = []
    for field in ("consultation", "medicine", "tests", "room", "other"):
        try:
            amount = Decimal(request.form.get(field) or "0")
            if not amount.is_finite() or amount < 0 or amount > Decimal("100000000"):
                raise InvalidOperation
            values.append(amount.quantize(Decimal("0.01")))
        except (InvalidOperation, ValueError):
            raise ValueError("Charges must be valid non-negative amounts.")
    return values


def next_code(prefix):
    return prefix + datetime.now().strftime("%y%m%d%H%M%S%f")[-8:] + secrets.token_hex(2).upper()


def active_patient(patient_id):
    return get_db().execute("SELECT * FROM patients WHERE id=? AND active=1", (patient_id,)).fetchone()


def active_doctor(doctor_id):
    return get_db().execute("SELECT * FROM doctors WHERE id=? AND active=1", (doctor_id,)).fetchone()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        stored_password = user["password"] if user else ""
        stored_is_hash = ":" in stored_password and "$" in stored_password
        password_valid = (check_password_hash(stored_password, password) if stored_is_hash
                          else secrets.compare_digest(stored_password, password)) if user else False
        if password_valid:
            # Accounts added directly to SQLite after startup may still have a plain-text password.
            # Upgrade it on successful authentication before establishing the session.
            if not stored_is_hash:
                get_db().execute("UPDATE users SET password=? WHERE id=?",
                                 (generate_password_hash(password), user["id"]))
                get_db().commit()
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"], csrf_token=secrets.token_urlsafe(32))
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required()
def dashboard():
    conn = get_db()
    stats = {"patients": conn.execute("SELECT COUNT(*) FROM patients WHERE active=1").fetchone()[0],
             "doctors": conn.execute("SELECT COUNT(*) FROM doctors WHERE active=1").fetchone()[0],
             "appointments": conn.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date=? AND status='Scheduled'", (date.today().isoformat(),)).fetchone()[0],
             "revenue": conn.execute("SELECT COALESCE(SUM(amount_paid),0) FROM bills").fetchone()[0],
             "outstanding": conn.execute("SELECT COALESCE(SUM(total-amount_paid),0) FROM bills").fetchone()[0]}
    recent = [] if session.get("role") == "Billing" else conn.execute("""SELECT a.*,p.name patient_name,d.name doctor_name FROM appointments a
        JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        ORDER BY a.appointment_date DESC,a.appointment_time DESC LIMIT 6""").fetchall()
    upcoming = [] if session.get("role") == "Billing" else conn.execute("""SELECT a.*,p.name patient_name,d.name doctor_name FROM appointments a
        JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        WHERE a.status='Scheduled' AND a.appointment_date BETWEEN ? AND ?
        ORDER BY a.appointment_date,a.appointment_time LIMIT 8""",
        (date.today().isoformat(), date.fromordinal(date.today().toordinal() + 7).isoformat())).fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent, upcoming=upcoming)


@app.route("/patients")
@login_required("Admin", "Doctor")
def patients():
    q = request.args.get("q", "").strip()
    rows = get_db().execute("""SELECT * FROM patients WHERE active=1 AND (name LIKE ? OR patient_code LIKE ? OR phone LIKE ?)
        ORDER BY id DESC""", (f"%{q}%",) * 3).fetchall()
    return render_template("patients.html", patients=rows, q=q)


def save_patient(patient_id=None):
    d = request.form
    name = clean("name", True, 120)
    age_raw = clean("age", maximum=3)
    if age_raw and (not age_raw.isdigit() or not 0 <= int(age_raw) <= 125):
        raise ValueError("Age must be between 0 and 125.")
    gender = clean("gender", maximum=20)
    if gender and gender not in ("Male", "Female", "Other"):
        raise ValueError("Choose a valid gender.")
    email = clean("email", maximum=254)
    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter a valid email address.")
    values = (name, int(age_raw) if age_raw else None, gender, clean("phone", maximum=40), email,
              clean("address", maximum=1000), clean("blood_group", maximum=4), clean("emergency_contact", maximum=80))
    conn = get_db()
    if patient_id:
        conn.execute("""UPDATE patients SET name=?,age=?,gender=?,phone=?,email=?,address=?,blood_group=?,emergency_contact=? WHERE id=?""", (*values, patient_id))
        audit("updated", "patient", patient_id)
    else:
        cur = conn.execute("""INSERT INTO patients(patient_code,name,age,gender,phone,email,address,blood_group,emergency_contact,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", (next_code("PAT"), *values, date.today().isoformat()))
        audit("created", "patient", cur.lastrowid)
    conn.commit()


@app.route("/patients/add", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def add_patient():
    if request.method == "POST":
        try:
            save_patient()
            flash("Patient registered successfully.", "success")
            return redirect(url_for("patients"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("add_patient.html")


@app.route("/patients/edit/<int:id>", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def edit_patient(id):
    patient = active_patient(id)
    if not patient:
        abort(404)
    if request.method == "POST":
        try:
            save_patient(id)
            flash("Patient details updated.", "success")
            return redirect(url_for("patients"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("add_patient.html", patient=patient, editing=True)


@app.route("/patients/delete/<int:id>", methods=["POST"])
@login_required("Admin")
def delete_patient(id):
    conn = get_db(); conn.execute("UPDATE patients SET active=0 WHERE id=?", (id,)); audit("archived", "patient", id); conn.commit()
    flash("Patient archived; their clinical and billing records were retained.", "success")
    return redirect(url_for("patients"))


@app.route("/doctors")
@login_required("Admin", "Doctor")
def doctors():
    q = request.args.get("q", "").strip()
    rows = get_db().execute("""SELECT * FROM doctors WHERE active=1 AND (name LIKE ? OR doctor_code LIKE ? OR specialization LIKE ?)
        ORDER BY id DESC""", (f"%{q}%",) * 3).fetchall()
    return render_template("doctors.html", doctors=rows, q=q)


def save_doctor(doctor_id=None):
    d = request.form
    values = (clean("name", True, 120), clean("specialization", maximum=120), clean("department", maximum=120),
              clean("phone", maximum=40), clean("email", maximum=254), clean("availability", maximum=200))
    if values[4] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", values[4]):
        raise ValueError("Enter a valid email address.")
    conn = get_db()
    if doctor_id:
        conn.execute("UPDATE doctors SET name=?,specialization=?,department=?,phone=?,email=?,availability=? WHERE id=?", (*values, doctor_id))
        audit("updated", "doctor", doctor_id)
    else:
        cur = conn.execute("""INSERT INTO doctors(doctor_code,name,specialization,department,phone,email,availability) VALUES(?,?,?,?,?,?,?)""", (next_code("DOC"), *values))
        audit("created", "doctor", cur.lastrowid)
    conn.commit()


@app.route("/doctors/add", methods=["GET", "POST"])
@login_required("Admin")
def add_doctor():
    if request.method == "POST":
        try:
            save_doctor(); flash("Doctor added successfully.", "success"); return redirect(url_for("doctors"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("add_doctor.html")


@app.route("/doctors/edit/<int:id>", methods=["GET", "POST"])
@login_required("Admin")
def edit_doctor(id):
    doctor = active_doctor(id)
    if not doctor: abort(404)
    if request.method == "POST":
        try:
            save_doctor(id); flash("Doctor profile updated.", "success"); return redirect(url_for("doctors"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("add_doctor.html", doctor=doctor, editing=True)


@app.route("/doctors/delete/<int:id>", methods=["POST"])
@login_required("Admin")
def delete_doctor(id):
    conn = get_db(); conn.execute("UPDATE doctors SET active=0 WHERE id=?", (id,)); audit("archived", "doctor", id); conn.commit()
    flash("Doctor archived; existing appointments and prescriptions were retained.", "success")
    return redirect(url_for("doctors"))


@app.route("/appointments")
@login_required("Admin", "Doctor")
def appointments():
    q = request.args.get("q", "").strip()
    start, end = request.args.get("from", ""), request.args.get("to", "")
    try:
        if start: start = valid_date(start, "start date")
        if end: end = valid_date(end, "end date")
    except ValueError as exc:
        flash(str(exc), "danger"); start = end = ""
    rows = get_db().execute("""SELECT a.*,p.name patient_name,p.patient_code,d.name doctor_name,d.specialization
        FROM appointments a JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        WHERE (p.name LIKE ? OR d.name LIKE ? OR a.status LIKE ?) AND (?='' OR a.appointment_date>=?) AND (?='' OR a.appointment_date<=?)
        ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (f"%{q}%", f"%{q}%", f"%{q}%", start, start, end, end)).fetchall()
    return render_template("appointments.html", appointments=rows, q=q, date_from=start, date_to=end)


def appointment_form_data(appointment_id=None):
    d = request.form
    patient_id, doctor_id = d.get("patient_id", ""), d.get("doctor_id", "")
    if not patient_id.isdigit() or not active_patient(int(patient_id)):
        raise ValueError("Choose an active patient.")
    if not doctor_id.isdigit() or not active_doctor(int(doctor_id)):
        raise ValueError("Choose an active doctor.")
    appt_date = valid_date(d.get("appointment_date"), "appointment date")
    try:
        time_obj = datetime.strptime(d.get("appointment_time", ""), "%H:%M")
    except ValueError:
        raise ValueError("Choose a valid appointment time.")
    status = d.get("status", "Scheduled")
    if status not in ("Scheduled", "Completed", "Cancelled"):
        raise ValueError("Choose a valid appointment status.")
    if appt_date < date.today().isoformat() and (not appointment_id or status == "Scheduled"):
        raise ValueError("New appointments cannot be scheduled in the past.")
    conn = get_db()
    conflict = conn.execute("""SELECT id FROM appointments WHERE doctor_id=? AND appointment_date=? AND appointment_time=?
        AND status='Scheduled' AND id != COALESCE(?, -1)""", (int(doctor_id), appt_date, time_obj.strftime("%H:%M"), appointment_id)).fetchone()
    if conflict:
        raise ValueError("This doctor already has a scheduled appointment at that time.")
    return int(patient_id), int(doctor_id), appt_date, time_obj.strftime("%H:%M"), clean("reason", maximum=1000), status


def appointment_page(appointment=None):
    conn = get_db()
    patients = conn.execute("SELECT * FROM patients WHERE active=1 ORDER BY name").fetchall()
    doctors = conn.execute("SELECT * FROM doctors WHERE active=1 ORDER BY name").fetchall()
    return render_template("add_appointment.html", patients=patients, doctors=doctors,
                           appointment=appointment, editing=appointment is not None)


@app.route("/appointments/add", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def add_appointment():
    if request.method == "POST":
        try:
            values = appointment_form_data()
            cur = get_db().execute("""INSERT INTO appointments(patient_id,doctor_id,appointment_date,appointment_time,reason,status,created_by,updated_at)
                VALUES(?,?,?,?,?,?,?,?)""", (*values, session["user_id"], datetime.now().isoformat(timespec="seconds")))
            audit("created", "appointment", cur.lastrowid); get_db().commit()
            flash("Appointment booked.", "success"); return redirect(url_for("appointments"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return appointment_page()


@app.route("/appointments/edit/<int:id>", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def edit_appointment(id):
    appointment = get_db().execute("SELECT * FROM appointments WHERE id=?", (id,)).fetchone()
    if not appointment: abort(404)
    if request.method == "POST":
        try:
            values = appointment_form_data(id)
            get_db().execute("""UPDATE appointments SET patient_id=?,doctor_id=?,appointment_date=?,appointment_time=?,reason=?,status=?,updated_at=? WHERE id=?""",
                             (*values, datetime.now().isoformat(timespec="seconds"), id))
            audit("updated", "appointment", id); get_db().commit(); flash("Appointment updated.", "success")
            return redirect(url_for("appointments"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return appointment_page(appointment)


@app.route("/appointments/status/<int:id>/<status>", methods=["POST"])
@login_required("Admin", "Doctor")
def appointment_status(id, status):
    if status not in ("Scheduled", "Completed", "Cancelled"): abort(400)
    cur = get_db().execute("UPDATE appointments SET status=?,updated_at=? WHERE id=?", (status, datetime.now().isoformat(timespec="seconds"), id))
    if not cur.rowcount: abort(404)
    audit("status " + status.lower(), "appointment", id); get_db().commit()
    return redirect(url_for("appointments"))


@app.route("/billing")
@login_required("Admin", "Billing")
def billing():
    q = request.args.get("q", "").strip()
    rows = get_db().execute("""SELECT b.*,p.name patient_name,p.patient_code FROM bills b JOIN patients p ON p.id=b.patient_id
        WHERE p.name LIKE ? OR b.bill_code LIKE ? ORDER BY b.id DESC""", (f"%{q}%",) * 2).fetchall()
    return render_template("billing.html", bills=rows, q=q)


@app.route("/billing/<int:id>/receipt")
@login_required("Admin", "Billing")
def receipt(id):
    conn = get_db()
    bill = conn.execute("""SELECT b.*,p.name patient_name,p.patient_code,p.phone,p.email FROM bills b
        JOIN patients p ON p.id=b.patient_id WHERE b.id=?""", (id,)).fetchone()
    if not bill: abort(404)
    transactions = conn.execute("""SELECT t.*,u.username FROM bill_transactions t LEFT JOIN users u ON u.id=t.created_by
        WHERE t.bill_id=? ORDER BY t.id""", (id,)).fetchall()
    return render_template("receipt.html", bill=bill, transactions=transactions)


@app.route("/billing/add", methods=["GET", "POST"])
@login_required("Admin", "Billing")
def add_bill():
    patients = get_db().execute("SELECT * FROM patients WHERE active=1 ORDER BY name").fetchall()
    if request.method == "POST":
        try:
            pid = request.form.get("patient_id", "")
            if not pid.isdigit() or not active_patient(int(pid)): raise ValueError("Choose an active patient.")
            amounts = money_fields(); total = sum(amounts, Decimal("0.00"))
            status = request.form.get("payment_status", "Pending")
            if status not in ("Pending", "Paid"): raise ValueError("Choose a valid payment status.")
            method = clean("payment_method", maximum=40)
            if status == "Paid" and method not in PAYMENT_METHODS: raise ValueError("Choose a valid payment method.")
            paid = total if status == "Paid" else Decimal("0.00")
            cur = get_db().execute("""INSERT INTO bills(bill_code,patient_id,consultation,medicine,tests,room,other,total,payment_status,created_at,amount_paid,payment_method,payment_date)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (next_code("BILL"), int(pid), *map(float, amounts), float(total), status,
                date.today().isoformat(), float(paid), method if paid else None, date.today().isoformat() if paid else None))
            audit("created", "bill", cur.lastrowid)
            if paid:
                get_db().execute("INSERT INTO bill_transactions(bill_id,transaction_type,amount,method,transaction_date,created_by) VALUES(?,?,?,?,?,?)",
                                 (cur.lastrowid, "Payment", float(paid), method, date.today().isoformat(), session["user_id"]))
            get_db().commit(); flash("Bill created.", "success")
            return redirect(url_for("billing"))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("add_bill.html", patients=patients)


@app.route("/billing/payment/<int:id>", methods=["POST"])
@login_required("Admin", "Billing")
def record_payment(id):
    try:
        amount = Decimal(request.form.get("amount", ""))
        method = clean("payment_method", True, 40)
        if method not in PAYMENT_METHODS: raise ValueError("Choose a valid payment method.")
        if not amount.is_finite() or amount <= 0: raise InvalidOperation
    except (InvalidOperation, ValueError) as exc:
        flash(str(exc) or "Enter a valid positive payment amount.", "danger")
        return redirect(url_for("billing"))
    conn = get_db(); bill = conn.execute("SELECT * FROM bills WHERE id=?", (id,)).fetchone()
    if not bill: abort(404)
    new_paid = Decimal(str(bill["amount_paid"])) + amount
    if new_paid > Decimal(str(bill["total"])):
        flash("Payment exceeds the outstanding balance.", "danger"); return redirect(url_for("billing"))
    status = "Paid" if new_paid == Decimal(str(bill["total"])) else ("Partially Paid" if new_paid > 0 else "Pending")
    conn.execute("UPDATE bills SET amount_paid=?,payment_status=?,payment_method=?,payment_date=? WHERE id=?",
                 (float(new_paid), status, method, date.today().isoformat(), id))
    conn.execute("INSERT INTO bill_transactions(bill_id,transaction_type,amount,method,transaction_date,created_by) VALUES(?,?,?,?,?,?)",
                 (id, "Payment", float(amount), method, date.today().isoformat(), session["user_id"]))
    audit("payment recorded", "bill", id); conn.commit(); flash("Payment recorded.", "success")
    return redirect(url_for("billing"))


@app.route("/billing/refund/<int:id>", methods=["POST"])
@login_required("Admin", "Billing")
def refund_payment(id):
    try:
        amount = Decimal(request.form.get("amount", ""))
        method = clean("payment_method", True, 40)
        if method not in PAYMENT_METHODS: raise ValueError("Choose a valid refund method.")
        if not amount.is_finite() or amount <= 0: raise InvalidOperation
    except (InvalidOperation, ValueError) as exc:
        flash(str(exc) or "Enter a valid positive refund amount.", "danger"); return redirect(url_for("billing"))
    conn = get_db(); bill = conn.execute("SELECT * FROM bills WHERE id=?", (id,)).fetchone()
    if not bill: abort(404)
    new_paid = Decimal(str(bill["amount_paid"])) - amount
    if new_paid < 0:
        flash("Refund exceeds the amount paid.", "danger"); return redirect(url_for("billing"))
    status = "Paid" if new_paid == Decimal(str(bill["total"])) else ("Partially Paid" if new_paid > 0 else "Pending")
    conn.execute("UPDATE bills SET amount_paid=?,payment_status=?,payment_date=? WHERE id=?",
                 (float(new_paid), status, date.today().isoformat(), id))
    conn.execute("INSERT INTO bill_transactions(bill_id,transaction_type,amount,method,transaction_date,created_by) VALUES(?,?,?,?,?,?)",
                 (id, "Refund", float(amount), method, date.today().isoformat(), session["user_id"]))
    audit("refund recorded", "bill", id); conn.commit(); flash("Refund recorded.", "success")
    return redirect(url_for("billing"))


@app.route("/prescriptions")
@login_required("Admin", "Doctor")
def prescriptions():
    rows = get_db().execute("""SELECT pr.*,p.name patient_name,d.name doctor_name FROM prescriptions pr
        JOIN patients p ON p.id=pr.patient_id JOIN doctors d ON d.id=pr.doctor_id ORDER BY pr.id DESC""").fetchall()
    return render_template("prescriptions.html", prescriptions=rows)


@app.route("/prescriptions/add", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def add_prescription():
    conn = get_db(); patients = conn.execute("SELECT * FROM patients WHERE active=1 ORDER BY name").fetchall()
    doctors = conn.execute("SELECT * FROM doctors WHERE active=1 ORDER BY name").fetchall()
    if request.method == "POST":
        try:
            pid, did = request.form.get("patient_id", ""), request.form.get("doctor_id", "")
            if not pid.isdigit() or not active_patient(int(pid)): raise ValueError("Choose an active patient.")
            if not did.isdigit() or not active_doctor(int(did)): raise ValueError("Choose an active doctor.")
            cur = conn.execute("""INSERT INTO prescriptions(patient_id,doctor_id,medicine,dosage,duration,instructions,created_at)
                VALUES(?,?,?,?,?,?,?)""", (int(pid), int(did), clean("medicine", True, 200), clean("dosage", maximum=200),
                clean("duration", maximum=100), clean("instructions", maximum=1000), date.today().isoformat()))
            audit("created", "prescription", cur.lastrowid); conn.commit(); flash("Prescription saved.", "success")
            return redirect(url_for("prescriptions"))
        except ValueError as exc: flash(str(exc), "danger")
    return render_template("add_prescription.html", patients=patients, doctors=doctors)


@app.route("/prescriptions/<int:id>/status/<status>", methods=["POST"])
@login_required("Admin", "Doctor")
def prescription_status(id, status):
    if status not in ("Active", "Completed", "Discontinued"): abort(400)
    cur = get_db().execute("UPDATE prescriptions SET status=? WHERE id=?", (status, id))
    if not cur.rowcount: abort(404)
    audit("prescription " + status.lower(), "prescription", id); get_db().commit()
    return redirect(url_for("prescriptions"))


@app.route("/history/<int:patient_id>", methods=["GET", "POST"])
@login_required("Admin", "Doctor")
def history(patient_id):
    conn = get_db(); patient = active_patient(patient_id)
    if not patient: abort(404)
    if request.method == "POST":
        try:
            diagnosis = clean("diagnosis", True, 300)
            visit_date = valid_date(request.form.get("visit_date") or date.today().isoformat(), "visit date")
            cur = conn.execute("INSERT INTO patient_history(patient_id,diagnosis,notes,visit_date,created_by) VALUES(?,?,?,?,?)",
                               (patient_id, diagnosis, clean("notes", maximum=2000), visit_date, session["user_id"]))
            audit("created", "patient_history", cur.lastrowid); conn.commit(); flash("History entry added.", "success")
        except ValueError as exc: flash(str(exc), "danger")
    rows = conn.execute("SELECT * FROM patient_history WHERE patient_id=? ORDER BY visit_date DESC,id DESC", (patient_id,)).fetchall()
    return render_template("history.html", patient=patient, history=rows)


@app.route("/patients/<int:patient_id>/record")
@login_required("Admin", "Doctor")
def patient_record(patient_id):
    conn = get_db(); patient = active_patient(patient_id)
    if not patient: abort(404)
    appointments = conn.execute("""SELECT a.*,d.name doctor_name FROM appointments a JOIN doctors d ON d.id=a.doctor_id
        WHERE a.patient_id=? ORDER BY appointment_date DESC,appointment_time DESC""", (patient_id,)).fetchall()
    prescriptions = conn.execute("""SELECT pr.*,d.name doctor_name FROM prescriptions pr JOIN doctors d ON d.id=pr.doctor_id
        WHERE pr.patient_id=? ORDER BY pr.id DESC""", (patient_id,)).fetchall()
    bills = conn.execute("SELECT * FROM bills WHERE patient_id=? ORDER BY id DESC", (patient_id,)).fetchall()
    history_rows = conn.execute("SELECT * FROM patient_history WHERE patient_id=? ORDER BY visit_date DESC,id DESC", (patient_id,)).fetchall()
    return render_template("patient_record.html", patient=patient, appointments=appointments, prescriptions=prescriptions,
                           bills=bills, history=history_rows)


@app.route("/api/stats")
@login_required("Admin", "Billing")
def api_stats():
    row = get_db().execute("SELECT COALESCE(SUM(total),0) total,COALESCE(SUM(amount_paid),0) paid FROM bills").fetchone()
    return jsonify({"billed": row["total"], "paid": row["paid"], "outstanding": row["total"] - row["paid"]})


@app.route("/users", methods=["GET", "POST"])
@login_required("Admin")
def users():
    conn = get_db()
    if request.method == "POST":
        username, password, role = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("role", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            flash("Username must be 3–40 characters and use letters, numbers, dot, underscore, or dash.", "danger")
        elif len(password) < 12:
            flash("Choose a password with at least 12 characters.", "danger")
        elif role not in ROLES:
            flash("Choose a valid role.", "danger")
        else:
            try:
                cur = conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                                   (username, generate_password_hash(password), role))
                audit("created", "user", cur.lastrowid); conn.commit(); flash("Staff account created.", "success")
                return redirect(url_for("users"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "danger")
    rows = conn.execute("SELECT id,username,role,active FROM users ORDER BY username").fetchall()
    return render_template("users.html", users=rows)


@app.route("/users/<int:id>/status/<int:active>", methods=["POST"])
@login_required("Admin")
def user_status(id, active):
    if active not in (0, 1) or id == session.get("user_id"):
        abort(400)
    cur = get_db().execute("UPDATE users SET active=? WHERE id=?", (active, id))
    if not cur.rowcount: abort(404)
    audit("activated" if active else "deactivated", "user", id); get_db().commit()
    return redirect(url_for("users"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required()
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        user = get_db().execute("SELECT password FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()
        if not user or not check_password_hash(user["password"], current):
            flash("Current password is incorrect.", "danger")
        elif len(new_password) < 12:
            flash("Choose a new password with at least 12 characters.", "danger")
        elif new_password != confirm:
            flash("The new passwords do not match.", "danger")
        else:
            get_db().execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), session["user_id"]))
            audit("changed password", "user", session["user_id"]); get_db().commit()
            flash("Password updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


@app.route("/audit")
@login_required("Admin")
def audit_events():
    rows = get_db().execute("""SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
        ORDER BY a.id DESC LIMIT 300""").fetchall()
    return render_template("audit.html", events=rows)


@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify(error="Bad request", message=getattr(error, "description", "Invalid request")), 400
    return render_template("error.html", code=400, message=getattr(error, "description", "Invalid request")), 400


@app.errorhandler(403)
@app.errorhandler(404)
def access_error(error):
    code = error.code
    message = "You do not have access to this page." if code == 403 else "The requested record was not found."
    return render_template("error.html", code=code, message=message), code


init_db()
if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
