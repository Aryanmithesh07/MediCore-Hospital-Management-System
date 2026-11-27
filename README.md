# MediCore Hospital Management System

<<<<<<< HEAD
A Flask and SQLite hospital administration demo for patient and doctor records, appointments, prescriptions, medical history, and billing. The interface uses server-rendered Jinja templates with Bootstrap, custom CSS, and small JavaScript helpers.
=======
Live Demo: 
>>>>>>> b02b56d606086769c5385d71a34f785e37a3ee7d

## Features

- Role-based staff accounts for Admin, Doctor, and Billing roles.
- Password hashing, CSRF protection on every POST form, secure session cookie settings, and basic security response headers.
- Patient and doctor profiles can be created, edited, searched, and archived. Archiving retains linked clinical and billing records.
- Patient record view combines appointments, prescriptions, bills, and history.
- Appointment scheduling, editing, date filtering, status tracking, and doctor/time conflict checks.
- Prescription status tracking and dated medical history entries.
- Itemized billing, partial payments, refunds, payment methods, outstanding balances, and a transaction ledger.
- Admin audit log, dashboard statistics, dark mode, and responsive screens.
- Additive SQLite schema updates for databases from the previous demo version.

## Run locally

Python 3.10+ is recommended.

```sh
cd MediCore-Hospital-Management-System
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="use-a-long-random-secret"
export HOSPITAL_ADMIN_PASSWORD="use-a-unique-password"
python app.py
```

Open `http://127.0.0.1:5000`. The initial account is `admin`; its password is the value of `HOSPITAL_ADMIN_PASSWORD` when the database is first created. A fresh database will not initialize unless this value is set to at least 12 characters. Existing databases keep the existing password, which is migrated to a hash on startup; sign in and change old demo passwords from **Change password**.

Optional settings:

- `HOSPITAL_DB`: SQLite database path (defaults to `hospital.db` beside `app.py`).
- `FLASK_SECRET_KEY`: persistent random secret for sessions. Set this for deployments so sessions stay valid across restarts.
- `COOKIE_SECURE=1`: mark session cookies Secure when served over HTTPS.
- `FLASK_DEBUG=1`: enable Flask debug mode for local development only.

## Roles

| Role | Main access |
| --- | --- |
| Admin | All areas, staff accounts, audit log, archive records |
| Doctor | Patients, doctors, appointments, prescriptions, medical history |
| Billing | Billing and payment records plus dashboard |

Admins can create and disable staff accounts from **Staff Accounts**. Passwords must be at least 12 characters for new accounts.

## Data and limitations

The database is local SQLite. Back it up before upgrades and keep it outside any public web root in a deployed setup. The app is an educational prototype and has not been assessed for production healthcare privacy, regulatory, or operational requirements. It does not send appointment reminders or connect to external payment processors, labs, pharmacies, or insurance services. Deploying with real patient data requires a qualified security and privacy review, encrypted storage and backups, stronger operational controls, and jurisdiction-specific compliance work.
