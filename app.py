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
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL CHECK(length(trim(username)) BETWEEN 3 AND 40 AND username NOT GLOB '*[^A-Za-z0-9_.-]*'),
        password TEXT NOT NULL CHECK(length(password)>0),
        role TEXT NOT NULL DEFAULT 'Admin' CHECK(role IN ('Admin','Doctor','Billing')),
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));
    CREATE TABLE IF NOT EXISTS patients (id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_code TEXT UNIQUE NOT NULL CHECK(length(trim(patient_code)) BETWEEN 1 AND 40),
        name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 120),
        age INTEGER CHECK(age IS NULL OR (typeof(age)='integer' AND age BETWEEN 0 AND 125)),
        gender TEXT CHECK(gender IS NULL OR gender IN ('Male','Female','Other')),
        phone TEXT CHECK(phone IS NULL OR length(phone)<=40),
        email TEXT CHECK(email IS NULL OR length(email)<=254),
        address TEXT CHECK(address IS NULL OR length(address)<=1000),
        blood_group TEXT CHECK(blood_group IS NULL OR blood_group IN ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
        emergency_contact TEXT CHECK(emergency_contact IS NULL OR length(emergency_contact)<=80),
        created_at TEXT NOT NULL CHECK(date(created_at) IS NOT NULL AND date(created_at)=created_at),
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));
    CREATE TABLE IF NOT EXISTS doctors (id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_code TEXT UNIQUE NOT NULL CHECK(length(trim(doctor_code)) BETWEEN 1 AND 40),
        name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 120),
        specialization TEXT CHECK(specialization IS NULL OR length(specialization)<=120),
        department TEXT CHECK(department IS NULL OR length(department)<=120),
        phone TEXT CHECK(phone IS NULL OR length(phone)<=40),
        email TEXT CHECK(email IS NULL OR length(email)<=254),
        availability TEXT CHECK(availability IS NULL OR length(availability)<=200),
        active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)));
    CREATE TABLE IF NOT EXISTS appointments (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL, appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL,
        reason TEXT CHECK(reason IS NULL OR length(reason)<=1000),
        status TEXT NOT NULL DEFAULT 'Scheduled' CHECK(status IN ('Scheduled','Completed','Cancelled')),
        created_by INTEGER, updated_at TEXT,
        CHECK(date(appointment_date) IS NOT NULL AND date(appointment_date)=appointment_date),
        CHECK(length(appointment_time)=5 AND appointment_time GLOB '[0-2][0-9]:[0-5][0-9]' AND substr(appointment_time,1,2)<='23'),
        FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id),
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS bills (id INTEGER PRIMARY KEY AUTOINCREMENT,
        bill_code TEXT UNIQUE NOT NULL CHECK(length(trim(bill_code)) BETWEEN 1 AND 40),
        patient_id INTEGER NOT NULL,
        consultation REAL NOT NULL DEFAULT 0 CHECK(consultation BETWEEN 0 AND 100000000 AND abs(consultation*100-round(consultation*100))<0.000001),
        medicine REAL NOT NULL DEFAULT 0 CHECK(medicine BETWEEN 0 AND 100000000 AND abs(medicine*100-round(medicine*100))<0.000001),
        tests REAL NOT NULL DEFAULT 0 CHECK(tests BETWEEN 0 AND 100000000 AND abs(tests*100-round(tests*100))<0.000001),
        room REAL NOT NULL DEFAULT 0 CHECK(room BETWEEN 0 AND 100000000 AND abs(room*100-round(room*100))<0.000001),
        other REAL NOT NULL DEFAULT 0 CHECK(other BETWEEN 0 AND 100000000 AND abs(other*100-round(other*100))<0.000001),
        total REAL NOT NULL DEFAULT 0 CHECK(total BETWEEN 0 AND 500000000 AND abs(total*100-round(total*100))<0.000001),
        payment_status TEXT NOT NULL DEFAULT 'Pending'
            CHECK(payment_status IN ('Pending','Partially Paid','Paid')),
        created_at TEXT NOT NULL CHECK(date(created_at) IS NOT NULL AND date(created_at)=created_at),
        amount_paid REAL NOT NULL DEFAULT 0, payment_method TEXT CHECK(payment_method IS NULL OR payment_method IN ('Cash','Card','Bank Transfer','Insurance','Other')),
        payment_date TEXT CHECK(payment_date IS NULL OR (date(payment_date) IS NOT NULL AND date(payment_date)=payment_date)),
        CHECK(abs(total-(consultation+medicine+tests+room+other))<0.005),
        CHECK(amount_paid>=0 AND amount_paid<=total AND abs(amount_paid*100-round(amount_paid*100))<0.000001),
        CHECK((payment_status='Pending' AND amount_paid=0) OR
              (payment_status='Partially Paid' AND amount_paid>0 AND amount_paid<total) OR
              (payment_status='Paid' AND total>0 AND amount_paid=total)),
        FOREIGN KEY(patient_id) REFERENCES patients(id));
    CREATE TABLE IF NOT EXISTS prescriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        doctor_id INTEGER NOT NULL, medicine TEXT NOT NULL CHECK(length(trim(medicine)) BETWEEN 1 AND 200),
        dosage TEXT CHECK(dosage IS NULL OR length(dosage)<=200),
        duration TEXT CHECK(duration IS NULL OR length(duration)<=100),
        instructions TEXT CHECK(instructions IS NULL OR length(instructions)<=1000),
        created_at TEXT NOT NULL CHECK(date(created_at) IS NOT NULL AND date(created_at)=created_at),
        status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Completed','Discontinued')),
        CHECK(length(trim(medicine))>0),
        FOREIGN KEY(patient_id) REFERENCES patients(id), FOREIGN KEY(doctor_id) REFERENCES doctors(id));
    CREATE TABLE IF NOT EXISTS patient_history (id INTEGER PRIMARY KEY AUTOINCREMENT, patient_id INTEGER NOT NULL,
        diagnosis TEXT NOT NULL CHECK(length(trim(diagnosis)) BETWEEN 1 AND 300),
        notes TEXT CHECK(notes IS NULL OR length(notes)<=2000), visit_date TEXT NOT NULL, created_by INTEGER,
        CHECK(date(visit_date) IS NOT NULL AND date(visit_date)=visit_date),
        FOREIGN KEY(patient_id) REFERENCES patients(id),
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
    CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
        action TEXT NOT NULL CHECK(length(trim(action))>0), entity TEXT NOT NULL CHECK(length(trim(entity))>0),
        entity_id INTEGER, created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS bill_transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, bill_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL CHECK(transaction_type IN ('Payment','Refund')), amount REAL NOT NULL,
        method TEXT NOT NULL CHECK(method IN ('Cash','Card','Bank Transfer','Insurance','Other')),
        transaction_date TEXT NOT NULL CHECK(date(transaction_date) IS NOT NULL AND date(transaction_date)=transaction_date), created_by INTEGER,
        CHECK(amount>0 AND abs(amount*100-round(amount*100))<0.000001),
        FOREIGN KEY(bill_id) REFERENCES bills(id),
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
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
    # Keep the payment state derived from the ledger balance during upgrades.
    conn.execute("""UPDATE bills SET payment_status=CASE
        WHEN amount_paid=0 THEN 'Pending'
        WHEN amount_paid=total AND total>0 THEN 'Paid'
        ELSE 'Partially Paid' END
        WHERE payment_status NOT IN ('Pending','Partially Paid','Paid')
           OR (payment_status='Pending' AND amount_paid!=0)
           OR (payment_status='Partially Paid' AND (amount_paid<=0 OR amount_paid>=total))
           OR (payment_status='Paid' AND (total<=0 OR amount_paid!=total))""")
    if conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0] == 0:
        conn.executemany("""INSERT INTO doctors(doctor_code,name,specialization,department,phone,email,availability)
            VALUES(?,?,?,?,?,?,?)""", [
            ("DOC001", "Dr. Anjali Menon", "Cardiology", "Cardiology", "+91 9876543210", "anjali@medicare.com", "Mon-Fri 9:00 AM - 2:00 PM"),
            ("DOC002", "Dr. Rahul Nair", "General Medicine", "OPD", "+91 9876543211", "rahul@medicare.com", "Mon-Sat 10:00 AM - 4:00 PM"),
            ("DOC003", "Dr. Meera Thomas", "Pediatrics", "Pediatrics", "+91 9876543212", "meera@medicare.com", "Tue-Sat 9:00 AM - 1:00 PM")])
    # Retain historical rows that reference a doctor deleted outside the app.
    missing_doctors = set()
    for table in ("appointments", "prescriptions"):
        missing_doctors.update(row[0] for row in conn.execute(
            f"SELECT DISTINCT linked.doctor_id FROM {table} linked "
            "LEFT JOIN doctors d ON d.id=linked.doctor_id WHERE d.id IS NULL"))
    for doctor_id in missing_doctors:
        conn.execute("INSERT INTO doctors(id,doctor_code,name,active) VALUES(?,?,?,0)",
                     (doctor_id, f"LEGACY-{doctor_id}", "Archived doctor (legacy record)"))
    # Remove stale actor references where legacy tables did not have FKs.
    for table in ("appointments", "patient_history", "bill_transactions"):
        conn.execute(f"""UPDATE {table} SET created_by=NULL WHERE created_by IS NOT NULL
            AND NOT EXISTS(SELECT 1 FROM users WHERE users.id={table}.created_by)""")
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        conn.close()
        raise RuntimeError(f"Database migration found {len(violations)} unresolved foreign-key violation(s).")
    install_integrity_guards(conn)
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
            user = get_db().execute("SELECT username,role,active FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not user or not user["active"]:
                session.clear()
                return redirect(url_for("login"))
            session["username"], session["role"] = user["username"], user["role"]
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
            cents = amount.quantize(Decimal("0.01"))
            if amount != cents:
                raise InvalidOperation
            values.append(cents)
        except (InvalidOperation, ValueError):
            raise ValueError("Charges must be valid non-negative amounts.")
    return values


def next_code(prefix):
    return prefix + datetime.now().strftime("%y%m%d%H%M%S%f")[-8:] + secrets.token_hex(2).upper()


def active_patient(patient_id):
    return get_db().execute("SELECT * FROM patients WHERE id=? AND active=1", (patient_id,)).fetchone()


def active_doctor(doctor_id):
    return get_db().execute("SELECT * FROM doctors WHERE id=? AND active=1", (doctor_id,)).fetchone()


def install_integrity_guards(conn):
    """Enforce domain rules on databases whose old tables cannot gain CHECKs additively."""
    guards = {
        "users": "NEW.username IS NULL OR length(trim(NEW.username)) NOT BETWEEN 3 AND 40 "
                 "OR NEW.username GLOB '*[^A-Za-z0-9_.-]*' "
                 "OR NEW.password IS NULL OR length(NEW.password)=0 "
                 "OR COALESCE(NEW.role,'') NOT IN ('Admin','Doctor','Billing') "
                 "OR NEW.active IS NULL OR NEW.active NOT IN (0,1)",
        "patients": "NEW.patient_code IS NULL OR length(trim(NEW.patient_code)) NOT BETWEEN 1 AND 40 "
                    "OR NEW.name IS NULL OR length(trim(NEW.name)) NOT BETWEEN 1 AND 120 "
                    "OR (NEW.age IS NOT NULL AND (typeof(NEW.age)!='integer' OR NEW.age<0 OR NEW.age>125)) "
                    "OR (NEW.gender IS NOT NULL AND NEW.gender NOT IN ('Male','Female','Other')) "
                    "OR (NEW.blood_group IS NOT NULL AND NEW.blood_group NOT IN ('A+','A-','B+','B-','AB+','AB-','O+','O-')) "
                    "OR (NEW.phone IS NOT NULL AND length(NEW.phone)>40) "
                    "OR (NEW.email IS NOT NULL AND length(NEW.email)>254) "
                    "OR (NEW.address IS NOT NULL AND length(NEW.address)>1000) "
                    "OR (NEW.emergency_contact IS NOT NULL AND length(NEW.emergency_contact)>80) "
                    "OR date(NEW.created_at) IS NULL OR date(NEW.created_at)!=NEW.created_at "
                    "OR NEW.active IS NULL OR NEW.active NOT IN (0,1)",
        "doctors": "NEW.doctor_code IS NULL OR length(trim(NEW.doctor_code)) NOT BETWEEN 1 AND 40 "
                   "OR NEW.name IS NULL OR length(trim(NEW.name)) NOT BETWEEN 1 AND 120 "
                   "OR (NEW.specialization IS NOT NULL AND length(NEW.specialization)>120) "
                   "OR (NEW.department IS NOT NULL AND length(NEW.department)>120) "
                   "OR (NEW.phone IS NOT NULL AND length(NEW.phone)>40) "
                   "OR (NEW.email IS NOT NULL AND length(NEW.email)>254) "
                   "OR (NEW.availability IS NOT NULL AND length(NEW.availability)>200) "
                   "OR NEW.active IS NULL OR NEW.active NOT IN (0,1)",
        "appointments": "COALESCE(NEW.status,'') NOT IN ('Scheduled','Completed','Cancelled') "
                        "OR NEW.patient_id IS NULL OR NOT EXISTS(SELECT 1 FROM patients WHERE id=NEW.patient_id) "
                        "OR NEW.doctor_id IS NULL OR NOT EXISTS(SELECT 1 FROM doctors WHERE id=NEW.doctor_id) "
                        "OR (NEW.reason IS NOT NULL AND length(NEW.reason)>1000) "
                        "OR date(NEW.appointment_date) IS NULL OR date(NEW.appointment_date)!=NEW.appointment_date "
                        "OR length(NEW.appointment_time)!=5 "
                        "OR NEW.appointment_time NOT GLOB '[0-2][0-9]:[0-5][0-9]' "
                        "OR substr(NEW.appointment_time,1,2)>'23' "
                        "OR (NEW.updated_at IS NOT NULL AND datetime(NEW.updated_at) IS NULL) "
                        "OR (NEW.created_by IS NOT NULL AND NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by))",
        "bills": "NEW.bill_code IS NULL OR length(trim(NEW.bill_code)) NOT BETWEEN 1 AND 40 "
                 "OR NEW.patient_id IS NULL OR NOT EXISTS(SELECT 1 FROM patients WHERE id=NEW.patient_id) "
                 "OR typeof(NEW.consultation) NOT IN ('integer','real') OR NEW.consultation<0 OR NEW.consultation>100000000 "
                 "OR abs(NEW.consultation*100-round(NEW.consultation*100))>=0.000001 "
                 "OR typeof(NEW.medicine) NOT IN ('integer','real') OR NEW.medicine<0 OR NEW.medicine>100000000 "
                 "OR abs(NEW.medicine*100-round(NEW.medicine*100))>=0.000001 "
                 "OR typeof(NEW.tests) NOT IN ('integer','real') OR NEW.tests<0 OR NEW.tests>100000000 "
                 "OR abs(NEW.tests*100-round(NEW.tests*100))>=0.000001 "
                 "OR typeof(NEW.room) NOT IN ('integer','real') OR NEW.room<0 OR NEW.room>100000000 "
                 "OR abs(NEW.room*100-round(NEW.room*100))>=0.000001 "
                 "OR typeof(NEW.other) NOT IN ('integer','real') OR NEW.other<0 OR NEW.other>100000000 "
                 "OR abs(NEW.other*100-round(NEW.other*100))>=0.000001 "
                 "OR typeof(NEW.total) NOT IN ('integer','real') OR NEW.total<0 OR NEW.total>500000000 "
                 "OR abs(NEW.total*100-round(NEW.total*100))>=0.000001 "
                 "OR abs(NEW.total-(NEW.consultation+NEW.medicine+NEW.tests+NEW.room+NEW.other))>=0.005 "
                 "OR typeof(NEW.amount_paid) NOT IN ('integer','real') OR NEW.amount_paid<0 OR NEW.amount_paid>NEW.total "
                 "OR abs(NEW.amount_paid*100-round(NEW.amount_paid*100))>=0.000001 "
                 "OR COALESCE(NEW.payment_status,'') NOT IN ('Pending','Partially Paid','Paid') "
                 "OR NOT ((NEW.payment_status='Pending' AND NEW.amount_paid=0) "
                 "OR (NEW.payment_status='Partially Paid' AND NEW.amount_paid>0 AND NEW.amount_paid<NEW.total) "
                 "OR (NEW.payment_status='Paid' AND NEW.total>0 AND NEW.amount_paid=NEW.total)) "
                 "OR (NEW.payment_method IS NOT NULL AND NEW.payment_method NOT IN ('Cash','Card','Bank Transfer','Insurance','Other')) "
                 "OR date(NEW.created_at) IS NULL OR date(NEW.created_at)!=NEW.created_at "
                 "OR (NEW.payment_date IS NOT NULL AND (date(NEW.payment_date) IS NULL OR date(NEW.payment_date)!=NEW.payment_date))",
        "prescriptions": "NEW.patient_id IS NULL OR NOT EXISTS(SELECT 1 FROM patients WHERE id=NEW.patient_id) "
                         "OR NEW.doctor_id IS NULL OR NOT EXISTS(SELECT 1 FROM doctors WHERE id=NEW.doctor_id) "
                         "OR NEW.medicine IS NULL OR length(trim(NEW.medicine)) NOT BETWEEN 1 AND 200 "
                         "OR (NEW.dosage IS NOT NULL AND length(NEW.dosage)>200) "
                         "OR (NEW.duration IS NOT NULL AND length(NEW.duration)>100) "
                         "OR (NEW.instructions IS NOT NULL AND length(NEW.instructions)>1000) "
                         "OR date(NEW.created_at) IS NULL OR date(NEW.created_at)!=NEW.created_at "
                         "OR COALESCE(NEW.status,'') NOT IN ('Active','Completed','Discontinued')",
        "patient_history": "NEW.patient_id IS NULL OR NOT EXISTS(SELECT 1 FROM patients WHERE id=NEW.patient_id) "
                           "OR NEW.diagnosis IS NULL OR length(trim(NEW.diagnosis)) NOT BETWEEN 1 AND 300 "
                           "OR (NEW.notes IS NOT NULL AND length(NEW.notes)>2000) "
                           "OR date(NEW.visit_date) IS NULL OR date(NEW.visit_date)!=NEW.visit_date "
                           "OR (NEW.created_by IS NOT NULL AND NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by))",
        "audit_log": "(NEW.user_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)) "
                     "OR NEW.action IS NULL OR length(trim(NEW.action))=0 "
                     "OR NEW.entity IS NULL OR length(trim(NEW.entity))=0 "
                     "OR datetime(NEW.created_at) IS NULL",
        "bill_transactions": "COALESCE(NEW.transaction_type,'') NOT IN ('Payment','Refund') "
                             "OR NEW.bill_id IS NULL OR NOT EXISTS(SELECT 1 FROM bills WHERE id=NEW.bill_id) "
                             "OR COALESCE(NEW.method,'') NOT IN ('Cash','Card','Bank Transfer','Insurance','Other') "
                             "OR typeof(NEW.amount) NOT IN ('integer','real') OR NEW.amount<=0 "
                             "OR abs(NEW.amount*100-round(NEW.amount*100))>=0.000001 "
                             "OR date(NEW.transaction_date) IS NULL OR date(NEW.transaction_date)!=NEW.transaction_date "
                             "OR (NEW.created_by IS NOT NULL AND NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.created_by))",
    }
    for table, condition in guards.items():
        invalid = conn.execute(
            f"SELECT id FROM {table} WHERE {condition.replace('NEW.', '')} LIMIT 1").fetchone()
        if invalid:
            raise RuntimeError(
                f"Database migration stopped: {table} record {invalid[0]} violates a data-integrity rule.")
        for operation in ("INSERT", "UPDATE"):
            conn.execute(f"""CREATE TRIGGER IF NOT EXISTS guard_{table}_{operation.lower()}
                BEFORE {operation} ON {table} WHEN {condition}
                BEGIN SELECT RAISE(ABORT, 'Invalid {table} data'); END""")

    duplicate_slot = conn.execute("""SELECT doctor_id,appointment_date,appointment_time
        FROM appointments WHERE status='Scheduled'
        GROUP BY doctor_id,appointment_date,appointment_time HAVING COUNT(*)>1 LIMIT 1""").fetchone()
    if duplicate_slot:
        raise RuntimeError("Database migration stopped: scheduled appointments contain a doctor/time conflict.")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS uq_appointments_scheduled_doctor_slot
        ON appointments(doctor_id,appointment_date,appointment_time) WHERE status='Scheduled'""")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_appointments_patient_date ON appointments(patient_id,appointment_date,appointment_time)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_appointments_doctor_date ON appointments(doctor_id,appointment_date,status)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_bills_patient_id ON bills(patient_id,id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_prescriptions_patient_id ON prescriptions(patient_id,id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_history_patient_date ON patient_history(patient_id,visit_date,id)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_transactions_bill_id ON bill_transactions(bill_id,id)")
    # Older schemas used ON DELETE CASCADE. Keep those deployments from
    # physically removing linked clinical or financial records.
    conn.executescript("""
    CREATE TRIGGER IF NOT EXISTS prevent_patient_delete_with_records
    BEFORE DELETE ON patients
    WHEN EXISTS(SELECT 1 FROM appointments WHERE patient_id=OLD.id)
      OR EXISTS(SELECT 1 FROM prescriptions WHERE patient_id=OLD.id)
      OR EXISTS(SELECT 1 FROM patient_history WHERE patient_id=OLD.id)
      OR EXISTS(SELECT 1 FROM bills WHERE patient_id=OLD.id)
    BEGIN SELECT RAISE(ABORT, 'Cannot delete a patient with linked records'); END;
    CREATE TRIGGER IF NOT EXISTS prevent_doctor_delete_with_records
    BEFORE DELETE ON doctors
    WHEN EXISTS(SELECT 1 FROM appointments WHERE doctor_id=OLD.id)
      OR EXISTS(SELECT 1 FROM prescriptions WHERE doctor_id=OLD.id)
    BEGIN SELECT RAISE(ABORT, 'Cannot delete a doctor with linked records'); END;
    CREATE TRIGGER IF NOT EXISTS prevent_bill_delete_with_transactions
    BEFORE DELETE ON bills
    WHEN EXISTS(SELECT 1 FROM bill_transactions WHERE bill_id=OLD.id)
    BEGIN SELECT RAISE(ABORT, 'Cannot delete a bill with transactions'); END;
    CREATE TRIGGER IF NOT EXISTS protect_last_active_admin_update
    BEFORE UPDATE OF active,role ON users
    WHEN OLD.role='Admin' AND OLD.active=1 AND (NEW.role!='Admin' OR NEW.active!=1)
      AND (SELECT COUNT(*) FROM users WHERE role='Admin' AND active=1)<=1
    BEGIN SELECT RAISE(ABORT, 'Cannot disable or demote the last active administrator'); END;
    CREATE TRIGGER IF NOT EXISTS protect_last_active_admin_delete
    BEFORE DELETE ON users
    WHEN OLD.role='Admin' AND OLD.active=1
      AND (SELECT COUNT(*) FROM users WHERE role='Admin' AND active=1)<=1
    BEGIN SELECT RAISE(ABORT, 'Cannot delete the last active administrator'); END;
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        stored_password = user["password"] if user else ""
        stored_is_hash = ":" in stored_password and "$" in stored_password
        password_valid = (check_password_hash(stored_password, password) if stored_is_hash
                          else secrets.compare_digest(stored_password, password)) if user else False
        if password and password_valid:
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
    blood_group = clean("blood_group", maximum=4)
    if blood_group and blood_group not in ("A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"):
        raise ValueError("Choose a valid blood group.")
    email = clean("email", maximum=254)
    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("Enter a valid email address.")
    values = (name, int(age_raw) if age_raw else None, gender, clean("phone", maximum=40), email,
              clean("address", maximum=1000), blood_group, clean("emergency_contact", maximum=80))
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
    conn = get_db(); cur = conn.execute("UPDATE patients SET active=0 WHERE id=? AND active=1", (id,))
    if not cur.rowcount: abort(404)
    audit("archived", "patient", id); conn.commit()
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
    conn = get_db(); cur = conn.execute("UPDATE doctors SET active=0 WHERE id=? AND active=1", (id,))
    if not cur.rowcount: abort(404)
    audit("archived", "doctor", id); conn.commit()
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
        if start and end and start > end:
            raise ValueError("The start date must be on or before the end date.")
    except ValueError as exc:
        flash(str(exc), "danger"); start = end = ""
    rows = get_db().execute("""SELECT a.*,p.name patient_name,p.patient_code,d.name doctor_name,d.specialization
        FROM appointments a JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        WHERE (p.name LIKE ? OR d.name LIKE ? OR a.status LIKE ?) AND (?='' OR a.appointment_date>=?) AND (?='' OR a.appointment_date<=?)
        ORDER BY a.appointment_date DESC,a.appointment_time DESC""", (f"%{q}%", f"%{q}%", f"%{q}%", start, start, end, end)).fetchall()
    return render_template("appointments.html", appointments=rows, q=q, date_from=start, date_to=end,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M"))


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
    # New bookings always begin in the scheduled state. The status is changed
    # through the appointment actions after the visit is booked.
    current = None
    if appointment_id:
        current = get_db().execute("SELECT status FROM appointments WHERE id=?", (appointment_id,)).fetchone()
        if not current:
            raise ValueError("Appointment no longer exists.")
    status = current["status"] if current else "Scheduled"
    if status not in ("Scheduled", "Completed", "Cancelled"):
        raise ValueError("Choose a valid appointment status.")
    if appt_date < date.today().isoformat() and (not appointment_id or status == "Scheduled"):
        raise ValueError("New appointments cannot be scheduled in the past.")
    if status == "Completed":
        appointment_start = datetime.strptime(f"{appt_date} {time_obj.strftime('%H:%M')}", "%Y-%m-%d %H:%M")
        if appointment_start > datetime.now():
            raise ValueError("A completed appointment cannot be moved to a future date or time.")
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
                           appointment=appointment, editing=appointment is not None,
                           today=date.today().isoformat())


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
        except sqlite3.IntegrityError:
            get_db().rollback()
            flash("That doctor already has a scheduled appointment at the selected time.", "danger")
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
        except sqlite3.IntegrityError:
            get_db().rollback()
            flash("That doctor already has a scheduled appointment at the selected time.", "danger")
    return appointment_page(appointment)


@app.route("/appointments/status/<int:id>/<status>", methods=["POST"])
@login_required("Admin", "Doctor")
def appointment_status(id, status):
    if status not in ("Scheduled", "Completed", "Cancelled"): abort(400)
    conn = get_db()
    appointment = conn.execute("SELECT * FROM appointments WHERE id=?", (id,)).fetchone()
    if not appointment: abort(404)
    current = appointment["status"]
    allowed = {"Scheduled": {"Completed", "Cancelled"}, "Cancelled": {"Scheduled"}, "Completed": set()}
    if status == current:
        return redirect(url_for("appointments"))
    if status not in allowed.get(current, set()):
        abort(400, "This appointment status change is not allowed.")
    if status == "Completed":
        appointment_start = datetime.strptime(
            f"{appointment['appointment_date']} {appointment['appointment_time']}", "%Y-%m-%d %H:%M")
        if appointment_start > datetime.now():
            abort(400, "A future appointment cannot be marked as completed.")
    if status == "Scheduled":
        if appointment["appointment_date"] < date.today().isoformat():
            abort(400, "A past appointment cannot be scheduled again.")
        conflict = conn.execute("""SELECT 1 FROM appointments WHERE doctor_id=? AND appointment_date=?
            AND appointment_time=? AND status='Scheduled' AND id<>?""",
            (appointment["doctor_id"], appointment["appointment_date"], appointment["appointment_time"], id)).fetchone()
        if conflict:
            abort(400, "This doctor already has a scheduled appointment at that time.")
    conn.execute("UPDATE appointments SET status=?,updated_at=? WHERE id=?",
                 (status, datetime.now().isoformat(timespec="seconds"), id))
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
            if total <= 0: raise ValueError("Bill total must be greater than zero.")
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
        cents = amount.quantize(Decimal("0.01"))
        if amount != cents: raise ValueError("Payments must use up to two decimal places.")
        amount = cents
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
        cents = amount.quantize(Decimal("0.01"))
        if amount != cents: raise ValueError("Refunds must use up to two decimal places.")
        amount = cents
    except (InvalidOperation, ValueError) as exc:
        flash(str(exc) or "Enter a valid positive refund amount.", "danger"); return redirect(url_for("billing"))
    conn = get_db(); bill = conn.execute("SELECT * FROM bills WHERE id=?", (id,)).fetchone()
    if not bill: abort(404)
    new_paid = Decimal(str(bill["amount_paid"])) - amount
    if new_paid < 0:
        flash("Refund exceeds the amount paid.", "danger"); return redirect(url_for("billing"))
    status = "Paid" if new_paid == Decimal(str(bill["total"])) else ("Partially Paid" if new_paid > 0 else "Pending")
    conn.execute("UPDATE bills SET amount_paid=?,payment_status=?,payment_method=CASE WHEN ?=0 THEN NULL ELSE payment_method END,payment_date=? WHERE id=?",
                 (float(new_paid), status, float(new_paid), date.today().isoformat(), id))
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
    conn = get_db()
    prescription = conn.execute("SELECT status FROM prescriptions WHERE id=?", (id,)).fetchone()
    if not prescription: abort(404)
    transitions = {"Active": {"Completed", "Discontinued"}, "Completed": {"Active"}, "Discontinued": set()}
    if status not in transitions.get(prescription["status"], set()):
        abort(400, "This prescription status change is not allowed.")
    conn.execute("UPDATE prescriptions SET status=? WHERE id=?", (status, id))
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
            if visit_date > date.today().isoformat():
                raise ValueError("Visit date cannot be in the future.")
            cur = conn.execute("INSERT INTO patient_history(patient_id,diagnosis,notes,visit_date,created_by) VALUES(?,?,?,?,?)",
                               (patient_id, diagnosis, clean("notes", maximum=2000), visit_date, session["user_id"]))
            audit("created", "patient_history", cur.lastrowid); conn.commit(); flash("History entry added.", "success")
        except ValueError as exc: flash(str(exc), "danger")
    rows = conn.execute("SELECT * FROM patient_history WHERE patient_id=? ORDER BY visit_date DESC,id DESC", (patient_id,)).fetchall()
    return render_template("history.html", patient=patient, history=rows, today=date.today().isoformat())


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
    conn = get_db()
    target = conn.execute("SELECT role,active FROM users WHERE id=?", (id,)).fetchone()
    if not target: abort(404)
    if not active and target["active"] and target["role"] == "Admin":
        active_admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='Admin' AND active=1").fetchone()[0]
        if active_admins <= 1:
            flash("The last active administrator cannot be disabled.", "danger")
            return redirect(url_for("users"))
    cur = conn.execute("UPDATE users SET active=? WHERE id=?", (active, id))
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
