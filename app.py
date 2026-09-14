import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this")

DB = "logistics.db"


# =========================
# DATABASE
# =========================

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()

    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT DEFAULT 'Active',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS drivers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        license_no TEXT,
        status TEXT DEFAULT 'Available'
    );

    CREATE TABLE IF NOT EXISTS vehicles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plate_no TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        capacity REAL NOT NULL,
        status TEXT DEFAULT 'Available',
        next_maintenance TEXT
    );

    CREATE TABLE IF NOT EXISTS deliveries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer TEXT NOT NULL,
        phone TEXT,
        origin TEXT,
        destination TEXT,
        package_weight REAL DEFAULT 0,
        package_size TEXT,
        priority TEXT DEFAULT 'Normal',
        schedule_date TEXT,
        schedule_time TEXT,
        status TEXT DEFAULT 'Pending',
        driver_id INTEGER,
        vehicle_id INTEGER,
        failure_reason TEXT,
        FOREIGN KEY(driver_id) REFERENCES drivers(id),
        FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
    );

    CREATE TABLE IF NOT EXISTS maintenance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vehicle_id INTEGER NOT NULL,
        service_date TEXT,
        description TEXT,
        next_date TEXT,
        cost REAL DEFAULT 0,
        FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
    );
    """)

    con.commit()
    con.close()


# =========================
# ADMIN ACCOUNT
# =========================

def create_admin():
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        return

    con = db()

    existing = con.execute(
        "SELECT id FROM users WHERE email=?",
        (admin_email,)
    ).fetchone()

    if not existing:
        con.execute("""
            INSERT INTO users
            (name, email, phone, password, role, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "Onwuekwe Victor",
            admin_email,
            "",
            generate_password_hash(admin_password),
            "Administrator",
            "Active"
        ))

        con.commit()

    con.close()


# =========================
# AUTHENTICATION
# =========================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Please login to continue.")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to continue.")
                return redirect(url_for("login"))

            if session.get("role") not in allowed_roles:
                flash("You do not have permission to access this section.")
                return redirect(url_for("portal"))

            return f(*args, **kwargs)

        return decorated_function

    return decorator
# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        con = db()

        user = con.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

        con.close()

        if user and check_password_hash(user["password"], password):

            if user["status"] != "Active":
                flash("Your account is not active.")
                return redirect(url_for("login"))

            session.clear()

            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]
            session["role"] = user["role"]

            flash("Login successful.")

            return redirect(url_for("portal"))

        flash("Invalid email or password.")

    return render_template("login.html")


# =========================
# SIGN UP
# =========================

@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        allowed_roles = [
            "Customer",
            "Driver",
            "Dispatcher",
            "Logistics Manager"
        ]

        if role not in allowed_roles:
            flash("Please select a valid account type.")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("signup"))

        if len(password) < 6:
            flash("Password must contain at least 6 characters.")
            return redirect(url_for("signup"))

        con = db()

        existing = con.execute(
            "SELECT id FROM users WHERE email=?",
            (email,)
        ).fetchone()

        if existing:
            con.close()
            flash("An account with this email already exists.")
            return redirect(url_for("login"))

        con.execute("""
            INSERT INTO users
            (name, email, phone, password, role, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            name,
            email,
            phone,
            generate_password_hash(password),
            role,
            "Active"
        ))

        if role == "Driver":
            con.execute("""
                INSERT INTO drivers
                (name, phone, license_no, status)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                phone,
                "",
                "Available"
            ))

        con.commit()
        con.close()

        flash("Account created successfully. Please login.")
        return redirect(url_for("login"))

    return render_template("signup.html")


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


# =========================
# PORTAL
# =========================

@app.route("/portal")
@login_required
def portal():

    return render_template("portal.html")
@app.route("/")
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def dashboard():
    con=db()
    counts={
        "deliveries": con.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0],
        "drivers": con.execute("SELECT COUNT(*) FROM drivers").fetchone()[0],
        "vehicles": con.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0],
        "failed": con.execute("SELECT COUNT(*) FROM deliveries WHERE status='Failed'").fetchone()[0],
    }
    recent=con.execute("""SELECT d.*, dr.name driver, v.plate_no
        FROM deliveries d LEFT JOIN drivers dr ON d.driver_id=dr.id
        LEFT JOIN vehicles v ON d.vehicle_id=v.id ORDER BY d.id DESC LIMIT 8""").fetchall()
    con.close()
    return render_template("dashboard.html", counts=counts, recent=recent)

  @app.route("/deliveries")
 @login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher", "Driver")
def deliveries():
    con=db()
    rows=con.execute("""SELECT d.*, dr.name driver, v.plate_no FROM deliveries d
        LEFT JOIN drivers dr ON d.driver_id=dr.id LEFT JOIN vehicles v ON d.vehicle_id=v.id
        ORDER BY d.id DESC""").fetchall()
    con.close()
    return render_template("deliveries.html", deliveries=rows)

@app.route("/deliveries/add", methods=["GET","POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def add_delivery():
    if request.method=="POST":
        con=db()
        con.execute("""INSERT INTO deliveries
        (customer,phone,origin,destination,package_weight,package_size,priority,schedule_date,schedule_time)
        VALUES (?,?,?,?,?,?,?,?,?)""", tuple(request.form.get(x) for x in
        ["customer","phone","origin","destination","package_weight","package_size","priority","schedule_date","schedule_time"]))
        con.commit(); con.close()
        flash("Delivery created.")
        return redirect(url_for("deliveries"))
    return render_template("delivery_form.html")

@app.route("/deliveries/<int:id>/assign", methods=["GET", "POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def assign(id):
    con=db()
    if request.method=="POST":
        driver=request.form.get("driver_id") or None
        vehicle=request.form.get("vehicle_id") or None
        con.execute("UPDATE deliveries SET driver_id=?, vehicle_id=?, status='Assigned' WHERE id=?",(driver,vehicle,id))
        if driver: con.execute("UPDATE drivers SET status='Assigned' WHERE id=?",(driver,))
        if vehicle: con.execute("UPDATE vehicles SET status='Assigned' WHERE id=?",(vehicle,))
        con.commit(); con.close()
        flash("Driver and vehicle assigned.")
        return redirect(url_for("deliveries"))
    delivery=con.execute("SELECT * FROM deliveries WHERE id=?",(id,)).fetchone()
    drivers=con.execute("SELECT * FROM drivers WHERE status='Available' OR id=?",(delivery["driver_id"],)).fetchall()
    vehicles=con.execute("SELECT * FROM vehicles WHERE status='Available' OR id=?",(delivery["vehicle_id"],)).fetchall()
    con.close()
    return render_template("assign.html", delivery=delivery, drivers=drivers, vehicles=vehicles)

@app.route("/deliveries/<int:id>/fail", methods=["POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher", "Driver")
def fail_delivery(id):
    reason=request.form.get("reason","No reason provided")
    con=db(); con.execute("UPDATE deliveries SET status='Failed', failure_reason=? WHERE id=?",(reason,id))
    con.commit(); con.close()
    flash("Delivery marked as failed.")
    return redirect(url_for("deliveries"))

@app.route("/deliveries/<int:id>/reschedule", methods=["POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def reschedule(id):
    con=db()
    con.execute("""UPDATE deliveries SET schedule_date=?, schedule_time=?, status='Pending',
        failure_reason=NULL WHERE id=?""",(request.form.get("date"),request.form.get("time"),id))
    con.commit(); con.close()
    flash("Delivery rescheduled.")
    return redirect(url_for("deliveries"))

@app.route("/drivers", methods=["GET", "POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def drivers():
    con=db()
    if request.method=="POST":
        con.execute("INSERT INTO drivers(name,phone,license_no) VALUES(?,?,?)",
                    (request.form["name"],request.form["phone"],request.form["license_no"]))
        con.commit()
    rows=con.execute("SELECT * FROM drivers ORDER BY id DESC").fetchall()
    con.close()
    return render_template("drivers.html", drivers=rows)

@app.route("/vehicles", methods=["GET", "POST"])
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def vehicles():
    con=db()
    if request.method=="POST":
        con.execute("INSERT INTO vehicles(plate_no,type,capacity,next_maintenance) VALUES(?,?,?,?)",
                    (request.form["plate_no"],request.form["type"],request.form["capacity"],request.form["next_maintenance"]))
        con.commit()
    rows=con.execute("SELECT * FROM vehicles ORDER BY id DESC").fetchall()
    con.close()
    return render_template("vehicles.html", vehicles=rows)

@app.route("/maintenance", methods=["GET", "POST"])
@login_required
@role_required("Administrator", "Logistics Manager")
def maintenance():
    con=db()
    if request.method=="POST":
        con.execute("""INSERT INTO maintenance(vehicle_id,service_date,description,next_date,cost)
                       VALUES(?,?,?,?,?)""",
                    (request.form["vehicle_id"],request.form["service_date"],request.form["description"],
                     request.form["next_date"],request.form["cost"]))
        con.execute("UPDATE vehicles SET next_maintenance=? WHERE id=?",
                    (request.form["next_date"],request.form["vehicle_id"]))
        con.commit()
    rows=con.execute("""SELECT m.*,v.plate_no FROM maintenance m
                        JOIN vehicles v ON m.vehicle_id=v.id ORDER BY m.id DESC""").fetchall()
    vehicles=con.execute("SELECT * FROM vehicles ORDER BY plate_no").fetchall()
    con.close()
    return render_template("maintenance.html", maintenance=rows, vehicles=vehicles)

@app.route("/failed")
@login_required
@role_required("Administrator", "Logistics Manager", "Dispatcher")
def failed():
    con=db()
    rows=con.execute("""SELECT d.*,dr.name driver,v.plate_no FROM deliveries d
        LEFT JOIN drivers dr ON d.driver_id=dr.id LEFT JOIN vehicles v ON d.vehicle_id=v.id
        WHERE d.status='Failed' ORDER BY d.id DESC""").fetchall()
    con.close()
    return render_template("failed.html", deliveries=rows)

init_db()
create_admin()
if __name__=="__main__":
    app.run(debug=True)
