from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "hospital-management-demo-secret"
DB = "hospital.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Admin'
    );
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, age INTEGER, gender TEXT, phone TEXT,
        email TEXT, address TEXT, blood_group TEXT, emergency_contact TEXT,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doctor_code TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, specialization TEXT, department TEXT,
        phone TEXT, email TEXT, availability TEXT
    );
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL,
        appointment_date TEXT NOT NULL, appointment_time TEXT NOT NULL,
        reason TEXT, status TEXT DEFAULT 'Scheduled',
        FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
        FOREIGN KEY(doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS bills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bill_code TEXT UNIQUE NOT NULL, patient_id INTEGER NOT NULL,
        consultation REAL DEFAULT 0, medicine REAL DEFAULT 0,
        tests REAL DEFAULT 0, room REAL DEFAULT 0, other REAL DEFAULT 0,
        total REAL DEFAULT 0, payment_status TEXT DEFAULT 'Pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS prescriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL,
        medicine TEXT NOT NULL, dosage TEXT, duration TEXT, instructions TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE,
        FOREIGN KEY(doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS patient_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL, diagnosis TEXT, notes TEXT,
        visit_date TEXT NOT NULL,
        FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
    );
    """)
    if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        conn.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                     ("admin","admin123","Admin"))
    if conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0] == 0:
        conn.executemany("""INSERT INTO doctors
        (doctor_code,name,specialization,department,phone,email,availability)
        VALUES(?,?,?,?,?,?,?)""", [
            ("DOC001","Dr. Anjali Menon","Cardiology","Cardiology","+91 9876543210","anjali@medicare.com","Mon-Fri 9:00 AM - 2:00 PM"),
            ("DOC002","Dr. Rahul Nair","General Medicine","OPD","+91 9876543211","rahul@medicare.com","Mon-Sat 10:00 AM - 4:00 PM"),
            ("DOC003","Dr. Meera Thomas","Pediatrics","Pediatrics","+91 9876543212","meera@medicare.com","Tue-Sat 9:00 AM - 1:00 PM")
        ])
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password)).fetchone()
        conn.close()
        if user:
            session["user_id"], session["username"], session["role"] = user["id"], user["username"], user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    stats = {
        "patients": conn.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
        "doctors": conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0],
        "appointments": conn.execute("SELECT COUNT(*) FROM appointments WHERE appointment_date=?", (datetime.now().strftime("%Y-%m-%d"),)).fetchone()[0],
        "revenue": conn.execute("SELECT COALESCE(SUM(total),0) FROM bills WHERE payment_status='Paid'").fetchone()[0]
    }
    recent = conn.execute("""SELECT a.*, p.name patient_name, d.name doctor_name
        FROM appointments a JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
        ORDER BY a.appointment_date DESC, a.appointment_time DESC LIMIT 6""").fetchall()
    conn.close()
    return render_template("dashboard.html", stats=stats, recent=recent)

@app.route("/patients")
@login_required
def patients():
    q = request.args.get("q","").strip()
    conn = get_db()
    rows = conn.execute("""SELECT * FROM patients WHERE name LIKE ? OR patient_code LIKE ? OR phone LIKE ?
                           ORDER BY id DESC""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    conn.close()
    return render_template("patients.html", patients=rows, q=q)

@app.route("/patients/add", methods=["GET","POST"])
@login_required
def add_patient():
    if request.method == "POST":
        data = request.form
        code = "PAT" + datetime.now().strftime("%y%m%d%H%M%S%f")[-8:]
        conn = get_db()
        conn.execute("""INSERT INTO patients(patient_code,name,age,gender,phone,email,address,blood_group,emergency_contact,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (code,data["name"],data.get("age"),data.get("gender"),data.get("phone"),data.get("email"),
                      data.get("address"),data.get("blood_group"),data.get("emergency_contact"),datetime.now().strftime("%Y-%m-%d")))
        conn.commit(); conn.close()
        flash("Patient registered successfully.", "success")
        return redirect(url_for("patients"))
    return render_template("add_patient.html")

@app.route("/patients/delete/<int:id>", methods=["POST"])
@login_required
def delete_patient(id):
    conn=get_db(); conn.execute("DELETE FROM patients WHERE id=?",(id,)); conn.commit(); conn.close()
    flash("Patient deleted.", "success"); return redirect(url_for("patients"))

@app.route("/doctors")
@login_required
def doctors():
    q=request.args.get("q","").strip()
    conn=get_db()
    rows=conn.execute("""SELECT * FROM doctors WHERE name LIKE ? OR doctor_code LIKE ? OR specialization LIKE ?
                         ORDER BY id DESC""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    conn.close()
    return render_template("doctors.html", doctors=rows, q=q)

@app.route("/doctors/add", methods=["GET","POST"])
@login_required
def add_doctor():
    if request.method=="POST":
        d=request.form; code="DOC"+datetime.now().strftime("%y%m%d%H%M%S%f")[-8:]
        conn=get_db(); conn.execute("""INSERT INTO doctors(doctor_code,name,specialization,department,phone,email,availability)
                                      VALUES(?,?,?,?,?,?,?)""",
                                     (code,d["name"],d.get("specialization"),d.get("department"),d.get("phone"),d.get("email"),d.get("availability")))
        conn.commit(); conn.close(); flash("Doctor added successfully.","success"); return redirect(url_for("doctors"))
    return render_template("add_doctor.html")

@app.route("/doctors/delete/<int:id>", methods=["POST"])
@login_required
def delete_doctor(id):
    conn=get_db(); conn.execute("DELETE FROM doctors WHERE id=?",(id,)); conn.commit(); conn.close()
    flash("Doctor deleted.","success"); return redirect(url_for("doctors"))

@app.route("/appointments")
@login_required
def appointments():
    q=request.args.get("q","").strip()
    conn=get_db()
    rows=conn.execute("""SELECT a.*,p.name patient_name,p.patient_code,d.name doctor_name,d.specialization
                         FROM appointments a JOIN patients p ON p.id=a.patient_id JOIN doctors d ON d.id=a.doctor_id
                         WHERE p.name LIKE ? OR d.name LIKE ? OR a.status LIKE ?
                         ORDER BY a.appointment_date DESC,a.appointment_time DESC""",(f"%{q}%",f"%{q}%",f"%{q}%")).fetchall()
    conn.close(); return render_template("appointments.html",appointments=rows,q=q)

@app.route("/appointments/add", methods=["GET","POST"])
@login_required
def add_appointment():
    conn=get_db()
    patients=conn.execute("SELECT * FROM patients ORDER BY name").fetchall()
    doctors=conn.execute("SELECT * FROM doctors ORDER BY name").fetchall()
    if request.method=="POST":
        d=request.form
        conn.execute("""INSERT INTO appointments(patient_id,doctor_id,appointment_date,appointment_time,reason,status)
                        VALUES(?,?,?,?,?,?)""",(d["patient_id"],d["doctor_id"],d["appointment_date"],d["appointment_time"],d.get("reason"),d.get("status","Scheduled")))
        conn.commit(); conn.close(); flash("Appointment booked.","success"); return redirect(url_for("appointments"))
    conn.close(); return render_template("add_appointment.html",patients=patients,doctors=doctors)

@app.route("/appointments/status/<int:id>/<status>", methods=["POST"])
@login_required
def appointment_status(id,status):
    if status not in ("Scheduled","Completed","Cancelled"): return redirect(url_for("appointments"))
    conn=get_db(); conn.execute("UPDATE appointments SET status=? WHERE id=?",(status,id)); conn.commit(); conn.close()
    return redirect(url_for("appointments"))

@app.route("/billing")
@login_required
def billing():
    q=request.args.get("q","").strip()
    conn=get_db()
    rows=conn.execute("""SELECT b.*,p.name patient_name,p.patient_code FROM bills b JOIN patients p ON p.id=b.patient_id
                         WHERE p.name LIKE ? OR b.bill_code LIKE ? ORDER BY b.id DESC""",(f"%{q}%",f"%{q}%")).fetchall()
    conn.close(); return render_template("billing.html",bills=rows,q=q)

@app.route("/billing/add", methods=["GET","POST"])
@login_required
def add_bill():
    conn=get_db(); patients=conn.execute("SELECT * FROM patients ORDER BY name").fetchall()
    if request.method=="POST":
        d=request.form
        vals=[float(d.get(x) or 0) for x in ("consultation","medicine","tests","room","other")]
        total=sum(vals); code="BILL"+datetime.now().strftime("%y%m%d%H%M%S%f")[-8:]
        conn.execute("""INSERT INTO bills(bill_code,patient_id,consultation,medicine,tests,room,other,total,payment_status,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",(code,d["patient_id"],*vals,total,d.get("payment_status","Pending"),datetime.now().strftime("%Y-%m-%d")))
        conn.commit(); conn.close(); flash("Bill created successfully.","success"); return redirect(url_for("billing"))
    conn.close(); return render_template("add_bill.html",patients=patients)

@app.route("/billing/status/<int:id>/<status>", methods=["POST"])
@login_required
def bill_status(id,status):
    if status not in ("Paid","Pending"): return redirect(url_for("billing"))
    conn=get_db(); conn.execute("UPDATE bills SET payment_status=? WHERE id=?",(status,id)); conn.commit(); conn.close()
    return redirect(url_for("billing"))

@app.route("/prescriptions")
@login_required
def prescriptions():
    conn=get_db()
    rows=conn.execute("""SELECT pr.*,p.name patient_name,d.name doctor_name
                         FROM prescriptions pr JOIN patients p ON p.id=pr.patient_id JOIN doctors d ON d.id=pr.doctor_id
                         ORDER BY pr.id DESC""").fetchall()
    conn.close(); return render_template("prescriptions.html",prescriptions=rows)

@app.route("/prescriptions/add", methods=["GET","POST"])
@login_required
def add_prescription():
    conn=get_db(); patients=conn.execute("SELECT * FROM patients ORDER BY name").fetchall(); doctors=conn.execute("SELECT * FROM doctors ORDER BY name").fetchall()
    if request.method=="POST":
        d=request.form; conn.execute("""INSERT INTO prescriptions(patient_id,doctor_id,medicine,dosage,duration,instructions,created_at)
                                      VALUES(?,?,?,?,?,?,?)""",(d["patient_id"],d["doctor_id"],d["medicine"],d.get("dosage"),d.get("duration"),d.get("instructions"),datetime.now().strftime("%Y-%m-%d")))
        conn.commit(); conn.close(); flash("Prescription saved.","success"); return redirect(url_for("prescriptions"))
    conn.close(); return render_template("add_prescription.html",patients=patients,doctors=doctors)

@app.route("/history/<int:patient_id>", methods=["GET","POST"])
@login_required
def history(patient_id):
    conn=get_db(); patient=conn.execute("SELECT * FROM patients WHERE id=?",(patient_id,)).fetchone()
    if not patient: conn.close(); return redirect(url_for("patients"))
    if request.method=="POST":
        d=request.form; conn.execute("INSERT INTO patient_history(patient_id,diagnosis,notes,visit_date) VALUES(?,?,?,?)",
                                     (patient_id,d.get("diagnosis"),d.get("notes"),d.get("visit_date") or datetime.now().strftime("%Y-%m-%d")))
        conn.commit()
    rows=conn.execute("SELECT * FROM patient_history WHERE patient_id=? ORDER BY visit_date DESC,id DESC",(patient_id,)).fetchall()
    conn.close(); return render_template("history.html",patient=patient,history=rows)

@app.route("/api/stats")
@login_required
def api_stats():
    conn=get_db()
    data=conn.execute("SELECT payment_status,COALESCE(SUM(total),0) total FROM bills GROUP BY payment_status").fetchall()
    conn.close(); return jsonify({r["payment_status"]:r["total"] for r in data})

init_db()
if __name__=="__main__":
    app.run(debug=True)
