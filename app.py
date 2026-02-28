from __future__ import annotations

import json
import sqlite3
from datetime import datetime
import shutil
from pathlib import Path
from functools import wraps
import re
from urllib.parse import urlparse

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from ral_colors import RAL_CLASSIC_CODES, RAL_CLASSIC_COLORS

BASE_DIR = Path(__file__).resolve().parent
DB_FILENAME = "paint_stock.db"
DEFAULT_DB_PATH = BASE_DIR / DB_FILENAME
APP_SETTINGS_PATH = BASE_DIR / "app_settings.json"

app = Flask(__name__)
app.config["SECRET_KEY"] = "powder-paint-stock-secret"

ALLOWED_GLOSS = {"MATT", "SEMI GLOSS", "GLOSS"}


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = get_db_path()
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db_path = str(db_path)
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def load_app_settings() -> dict[str, str]:
    if not APP_SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(APP_SETTINGS_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_app_settings(settings: dict[str, str]) -> None:
    APP_SETTINGS_PATH.write_text(json.dumps(settings, indent=2))


def get_db_path() -> Path:
    settings = load_app_settings()
    configured_dir = settings.get("db_directory")
    if configured_dir:
        return Path(configured_dir).expanduser() / DB_FILENAME
    return DEFAULT_DB_PATH


def init_db(db_path: Path | None = None) -> None:
    db_file = db_path or get_db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_file)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            code TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            customer TEXT,
            status TEXT NOT NULL CHECK (status IN ('OPEN', 'CLOSED')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS boxes (
            id TEXT PRIMARY KEY,
            ral TEXT NOT NULL,
            gloss TEXT NOT NULL,
            current_weight_kg REAL NOT NULL CHECK (current_weight_kg >= 0),
            status TEXT NOT NULL CHECK (status IN ('IN_STOCK', 'CHECKED_OUT')),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_checkouts (
            box_id TEXT PRIMARY KEY,
            job_code TEXT NOT NULL,
            line_name TEXT,
            out_weight_kg REAL NOT NULL CHECK (out_weight_kg >= 0),
            checked_out_at TEXT NOT NULL,
            FOREIGN KEY (box_id) REFERENCES boxes(id)
        );

        CREATE TABLE IF NOT EXISTS movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            box_id TEXT NOT NULL,
            job_code TEXT NOT NULL,
            line_name TEXT,
            action TEXT NOT NULL CHECK (action IN ('OUT', 'IN')),
            weight_kg REAL NOT NULL CHECK (weight_kg >= 0),
            weight_used_kg REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (box_id) REFERENCES boxes(id)
        );
        """
    )

    default_users = [
        ("admin", generate_password_hash("admin123"), "admin", now_iso()),
        ("user", generate_password_hash("user123"), "user", now_iso()),
    ]
    db.executemany(
        """
        INSERT OR IGNORE INTO users(username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        default_users,
    )
    ensure_jobs_columns(db)
    ensure_line_columns(db)
    db.commit()
    db.close()


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ensure_jobs_columns(db: sqlite3.Connection) -> None:
    columns = {
        row[1]
        for row in db.execute("PRAGMA table_info(jobs)").fetchall()
    }
    if "finalized_at" not in columns:
        db.execute("ALTER TABLE jobs ADD COLUMN finalized_at TEXT")


def ensure_line_columns(db: sqlite3.Connection) -> None:
    active_cols = {row[1] for row in db.execute("PRAGMA table_info(active_checkouts)").fetchall()}
    movement_cols = {row[1] for row in db.execute("PRAGMA table_info(movements)").fetchall()}
    if "line_name" not in active_cols:
        db.execute("ALTER TABLE active_checkouts ADD COLUMN line_name TEXT")
    if "line_name" not in movement_cols:
        db.execute("ALTER TABLE movements ADD COLUMN line_name TEXT")


def normalize_directory_input(directory_input: str) -> Path:
    raw = directory_input.strip()
    if not raw:
        raise OSError("Empty path")

    lower_raw = raw.lower()
    if lower_raw.startswith(("smb://", "afp://", "nfs://")):
        # Convert URL-style network locations to mounted filesystem paths.
        # Example: smb://server/share/folder -> /Volumes/share/folder
        parsed = urlparse(raw)
        if not parsed.path or parsed.path == "/":
            raise OSError("Network URL must include a share name")
        segments = [segment for segment in parsed.path.split("/") if segment]
        if not segments:
            raise OSError("Network URL must include a share name")
        share = segments[0]
        suffix = Path(*segments[1:]) if len(segments) > 1 else Path()
        return (Path("/Volumes") / share / suffix).resolve()

    if raw.startswith("\\\\"):
        # Support UNC-style input by translating to POSIX-style network path.
        raw = "//" + raw.lstrip("\\").replace("\\", "/")

    selected = Path(raw).expanduser()
    if not selected.is_absolute():
        selected = (BASE_DIR / selected).resolve()
    return selected


def normalize_ral(ral_value: str) -> str | None:
    value = " ".join(ral_value.upper().split())
    if value in RAL_CLASSIC_CODES:
        return value
    return None


def normalize_gloss(gloss_value: str) -> str | None:
    value = " ".join(gloss_value.strip().upper().split())
    if value in ALLOWED_GLOSS:
        return value.title() if value != "SEMI GLOSS" else "Semi Gloss"
    return None


def current_user() -> dict[str, str] | None:
    username = session.get("username")
    role = session.get("role")
    if not username or not role:
        return None
    return {"username": username, "role": role}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                flash("Please log in.")
                return redirect(url_for("login"))
            if user["role"] not in roles:
                flash("You do not have permission for that action.")
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT username, password_hash, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row or not check_password_hash(row["password_hash"], password):
            flash("Invalid username or password.")
            return render_template("login.html")

        session["username"] = row["username"]
        session["role"] = row["role"]
        flash(f"Logged in as {row['username']} ({row['role']}).")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    db = get_db()
    jobs = db.execute(
        """
        SELECT code, description, customer, status
        FROM jobs
        WHERE status = 'OPEN'
        ORDER BY created_at DESC
        """
    ).fetchall()

    boxes = db.execute(
        """
        SELECT id, ral, gloss, current_weight_kg, status, created_at
        FROM boxes
        ORDER BY status, ral, gloss, id
        """
    ).fetchall()

    active = db.execute(
        """
        SELECT ac.box_id,
               ac.job_code,
               COALESCE(ac.line_name, 'UNASSIGNED') AS line_name,
               ac.out_weight_kg,
               ac.checked_out_at,
               b.ral,
               b.gloss
        FROM active_checkouts ac
        JOIN boxes b ON b.id = ac.box_id
        ORDER BY ac.checked_out_at DESC
        """
    ).fetchall()

    recent_usage = db.execute(
        """
        SELECT box_id,
               job_code,
               COALESCE(line_name, 'UNASSIGNED') AS line_name,
               weight_kg,
               weight_used_kg,
               created_at
        FROM movements
        WHERE action = 'IN'
        ORDER BY id DESC
        LIMIT 20
        """
    ).fetchall()

    job_usage = db.execute(
        """
        SELECT m.job_code,
               COALESCE(m.line_name, 'UNASSIGNED') AS line_name,
               b.ral,
               b.gloss,
               ROUND(SUM(m.weight_used_kg), 3) AS total_used_kg,
               COUNT(*) AS return_events
        FROM movements m
        JOIN boxes b ON b.id = m.box_id
        WHERE m.action = 'IN'
        GROUP BY m.job_code, COALESCE(m.line_name, 'UNASSIGNED'), b.ral, b.gloss
        ORDER BY m.job_code DESC, line_name, b.ral, b.gloss
        """
    ).fetchall()

    stock_summary = db.execute(
        """
        SELECT ral, gloss,
               COUNT(*) AS box_count,
               ROUND(SUM(current_weight_kg), 3) AS total_weight_kg
        FROM boxes
        WHERE status = 'IN_STOCK'
        GROUP BY ral, gloss
        ORDER BY ral, gloss
        """
    ).fetchall()

    return render_template(
        "index.html",
        boxes=boxes,
        active=active,
        recent_usage=recent_usage,
        job_usage=job_usage,
        stock_summary=stock_summary,
        jobs=jobs,
        ral_colors=RAL_CLASSIC_COLORS,
        user=current_user(),
    )


@app.route("/stock-in")
@app.route("/boxes")
@role_required("admin")
def boxes_page():
    db = get_db()
    boxes = db.execute(
        """
        SELECT id, ral, gloss, current_weight_kg, status, created_at
        FROM boxes
        ORDER BY status, ral, gloss, id
        """
    ).fetchall()
    return render_template(
        "boxes.html",
        boxes=boxes,
        ral_colors=RAL_CLASSIC_COLORS,
        user=current_user(),
    )


@app.route("/jobs")
@role_required("admin")
def jobs_page():
    db = get_db()
    jobs = db.execute(
        """
        SELECT j.code,
               j.description,
               j.customer,
               j.status,
               j.created_at,
               j.finalized_at,
               ROUND(COALESCE(SUM(m.weight_used_kg), 0), 3) AS total_used_kg
        FROM jobs j
        LEFT JOIN movements m
          ON m.job_code = j.code AND m.action = 'IN'
        GROUP BY j.code, j.description, j.customer, j.status, j.created_at, j.finalized_at
        ORDER BY j.created_at DESC
        """
    ).fetchall()
    return render_template("jobs.html", jobs=jobs, user=current_user())


@app.post("/jobs/create")
@role_required("admin")
def create_job():
    code = request.form.get("code", "").strip().upper()
    description = request.form.get("description", "").strip()
    customer = request.form.get("customer", "").strip()

    if not code or not description:
        flash("Job code and description are required.")
        return redirect(url_for("jobs_page"))

    db = get_db()
    existing = db.execute("SELECT code FROM jobs WHERE code = ?", (code,)).fetchone()
    if existing:
        flash(f"Job {code} already exists.")
        return redirect(url_for("jobs_page"))

    db.execute(
        """
        INSERT INTO jobs(code, description, customer, status, created_at)
        VALUES (?, ?, ?, 'OPEN', ?)
        """,
        (code, description, customer, now_iso()),
    )
    db.commit()
    flash(f"Job {code} created.")
    return redirect(url_for("jobs_page"))


@app.post("/jobs/<job_code>/finalize")
@role_required("admin")
def finalize_job(job_code: str):
    code = job_code.strip().upper()
    db = get_db()
    job = db.execute(
        "SELECT code, status FROM jobs WHERE code = ?",
        (code,),
    ).fetchone()
    if not job:
        flash(f"Job {code} was not found.")
        return redirect(url_for("jobs_page"))
    if job["status"] == "CLOSED":
        flash(f"Job {code} is already finalized.")
        return redirect(url_for("jobs_page"))

    active = db.execute(
        "SELECT COUNT(*) AS cnt FROM active_checkouts WHERE job_code = ?",
        (code,),
    ).fetchone()
    if active["cnt"] > 0:
        flash(f"Cannot finalize {code}: there are active checkouts on this job.")
        return redirect(url_for("jobs_page"))

    db.execute(
        "UPDATE jobs SET status = 'CLOSED', finalized_at = ? WHERE code = ?",
        (now_iso(), code),
    )
    db.commit()
    flash(f"Job {code} finalized.")
    return redirect(url_for("jobs_page"))


@app.post("/jobs/<job_code>/delete")
@role_required("admin")
def delete_job(job_code: str):
    code = job_code.strip().upper()
    db = get_db()
    job = db.execute(
        "SELECT code FROM jobs WHERE code = ?",
        (code,),
    ).fetchone()
    if not job:
        flash(f"Job {code} was not found.")
        return redirect(url_for("jobs_page"))

    active = db.execute(
        "SELECT COUNT(*) AS cnt FROM active_checkouts WHERE job_code = ?",
        (code,),
    ).fetchone()
    movement_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM movements WHERE job_code = ?",
        (code,),
    ).fetchone()
    if active["cnt"] > 0 or movement_count["cnt"] > 0:
        flash(f"Cannot delete {code}: job has stock movements or active checkouts.")
        return redirect(url_for("jobs_page"))

    db.execute("DELETE FROM jobs WHERE code = ?", (code,))
    db.commit()
    flash(f"Job {code} deleted.")
    return redirect(url_for("jobs_page"))


@app.route("/jobs/<job_code>/usage")
@role_required("admin")
def job_usage_page(job_code: str):
    code = job_code.strip().upper()
    db = get_db()
    job = db.execute(
        """
        SELECT code, description, customer, status, created_at, finalized_at
        FROM jobs
        WHERE code = ?
        """,
        (code,),
    ).fetchone()
    if not job:
        flash(f"Job {code} was not found.")
        return redirect(url_for("jobs_page"))

    usage_rows = db.execute(
        """
        SELECT b.ral,
               b.gloss,
               COALESCE(m.line_name, 'UNASSIGNED') AS line_name,
               ROUND(SUM(m.weight_used_kg), 3) AS used_kg,
               COUNT(*) AS return_events
        FROM movements m
        JOIN boxes b ON b.id = m.box_id
        WHERE m.job_code = ? AND m.action = 'IN'
        GROUP BY b.ral, b.gloss, COALESCE(m.line_name, 'UNASSIGNED')
        ORDER BY line_name, b.ral, b.gloss
        """,
        (code,),
    ).fetchall()
    totals = db.execute(
        """
        SELECT ROUND(COALESCE(SUM(weight_used_kg), 0), 3) AS total_used_kg,
               COUNT(*) AS total_returns
        FROM movements
        WHERE job_code = ? AND action = 'IN'
        """,
        (code,),
    ).fetchone()

    return render_template(
        "job_usage.html",
        job=job,
        usage_rows=usage_rows,
        totals=totals,
        user=current_user(),
    )


@app.route("/analytics")
@role_required("admin")
def analytics_page():
    db = get_db()
    overall = db.execute(
        """
        SELECT ROUND(COALESCE(SUM(weight_used_kg), 0), 3) AS total_used_kg,
               COUNT(*) AS total_returns,
               COUNT(DISTINCT job_code) AS jobs_used
        FROM movements
        WHERE action = 'IN'
        """
    ).fetchone()
    by_type = db.execute(
        """
        SELECT b.ral,
               b.gloss,
               ROUND(SUM(m.weight_used_kg), 3) AS used_kg
        FROM movements m
        JOIN boxes b ON b.id = m.box_id
        WHERE m.action = 'IN'
        GROUP BY b.ral, b.gloss
        ORDER BY used_kg DESC, b.ral, b.gloss
        """
    ).fetchall()
    by_job = db.execute(
        """
        SELECT job_code,
               ROUND(SUM(weight_used_kg), 3) AS used_kg,
               COUNT(*) AS return_events
        FROM movements
        WHERE action = 'IN'
        GROUP BY job_code
        ORDER BY used_kg DESC, job_code
        """
    ).fetchall()
    by_line = db.execute(
        """
        SELECT COALESCE(line_name, 'UNASSIGNED') AS line_name,
               ROUND(SUM(weight_used_kg), 3) AS used_kg,
               COUNT(*) AS return_events
        FROM movements
        WHERE action = 'IN'
        GROUP BY COALESCE(line_name, 'UNASSIGNED')
        ORDER BY used_kg DESC, line_name
        """
    ).fetchall()
    by_month = db.execute(
        """
        SELECT substr(created_at, 1, 7) AS month,
               ROUND(SUM(weight_used_kg), 3) AS used_kg
        FROM movements
        WHERE action = 'IN'
        GROUP BY substr(created_at, 1, 7)
        ORDER BY month DESC
        """
    ).fetchall()
    return render_template(
        "analytics.html",
        overall=overall,
        by_type=by_type,
        by_job=by_job,
        by_line=by_line,
        by_month=by_month,
        user=current_user(),
    )


@app.route("/admin/database")
@role_required("admin")
def admin_database_page():
    db = get_db()
    users = db.execute(
        """
        SELECT username, role, created_at
        FROM users
        ORDER BY role DESC, username
        """
    ).fetchall()
    boxes = db.execute(
        """
        SELECT b.id,
               b.ral,
               b.gloss,
               b.current_weight_kg,
               b.status,
               COALESCE(m.movement_count, 0) AS movement_count
        FROM boxes b
        LEFT JOIN (
            SELECT box_id, COUNT(*) AS movement_count
            FROM movements
            GROUP BY box_id
        ) m ON m.box_id = b.id
        ORDER BY b.status, b.ral, b.gloss, b.id
        """
    ).fetchall()
    db_path = get_db_path()
    return render_template(
        "admin_database.html",
        user=current_user(),
        current_db_path=str(db_path),
        current_db_directory=str(db_path.parent),
        users=users,
        boxes=boxes,
    )


@app.post("/admin/database")
@role_required("admin")
def update_database_directory():
    raw_directory = request.form.get("db_directory", "").strip()
    if not raw_directory:
        flash("Database directory is required.")
        return redirect(url_for("admin_database_page"))

    try:
        target_dir = normalize_directory_input(raw_directory)
    except OSError:
        flash("Invalid database directory or network path.")
        return redirect(url_for("admin_database_page"))

    current_db_path = get_db_path()
    target_db_path = target_dir / DB_FILENAME

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        if current_db_path.resolve() != target_db_path.resolve():
            if current_db_path.exists() and not target_db_path.exists():
                shutil.copy2(current_db_path, target_db_path)
            save_app_settings({"db_directory": str(target_dir)})
            init_db(target_db_path)
            flash(f"Database location updated to {target_db_path}.")
        else:
            flash("Database directory is unchanged.")
    except OSError as exc:
        flash(f"Could not update database directory: {exc}")

    return redirect(url_for("admin_database_page"))


@app.post("/admin/paint/<box_id>/delete")
@role_required("admin")
def delete_paint_box(box_id: str):
    box = box_id.strip()
    if not box:
        flash("Invalid box id.")
        return redirect(url_for("admin_database_page"))

    db = get_db()
    row = db.execute(
        "SELECT id, status FROM boxes WHERE id = ?",
        (box,),
    ).fetchone()
    if not row:
        flash(f"Box {box} was not found.")
        return redirect(url_for("admin_database_page"))

    if row["status"] == "CHECKED_OUT":
        flash(f"Cannot delete {box}: it is currently checked out.")
        return redirect(url_for("admin_database_page"))

    active = db.execute(
        "SELECT COUNT(*) AS cnt FROM active_checkouts WHERE box_id = ?",
        (box,),
    ).fetchone()
    movement_count = db.execute(
        "SELECT COUNT(*) AS cnt FROM movements WHERE box_id = ?",
        (box,),
    ).fetchone()
    if active["cnt"] > 0 or movement_count["cnt"] > 0:
        flash(f"Cannot delete {box}: box has usage history.")
        return redirect(url_for("admin_database_page"))

    db.execute("DELETE FROM boxes WHERE id = ?", (box,))
    db.commit()
    flash(f"Box {box} deleted.")
    return redirect(url_for("admin_database_page"))


@app.post("/admin/users/add")
@role_required("admin")
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip().lower()

    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("admin_database_page"))
    if role not in {"admin", "user"}:
        flash("Role must be admin or user.")
        return redirect(url_for("admin_database_page"))

    db = get_db()
    exists = db.execute(
        "SELECT username FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if exists:
        flash(f"User {username} already exists.")
        return redirect(url_for("admin_database_page"))

    db.execute(
        """
        INSERT INTO users(username, password_hash, role, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (username, generate_password_hash(password), role, now_iso()),
    )
    db.commit()
    flash(f"User {username} added with {role} access.")
    return redirect(url_for("admin_database_page"))


@app.post("/admin/users/role")
@role_required("admin")
def update_user_role():
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "").strip().lower()
    actor = current_user()

    if not username:
        flash("Username is required.")
        return redirect(url_for("admin_database_page"))
    if role not in {"admin", "user"}:
        flash("Role must be admin or user.")
        return redirect(url_for("admin_database_page"))

    db = get_db()
    target = db.execute(
        "SELECT username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not target:
        flash(f"User {username} was not found.")
        return redirect(url_for("admin_database_page"))

    if actor and actor["username"] == username and role != "admin":
        flash("You cannot remove your own admin access.")
        return redirect(url_for("admin_database_page"))

    if target["role"] == "admin" and role != "admin":
        admin_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'",
        ).fetchone()
        if admin_count["cnt"] <= 1:
            flash("At least one admin account is required.")
            return redirect(url_for("admin_database_page"))

    db.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        (role, username),
    )
    db.commit()
    flash(f"Updated {username} to {role} access.")
    return redirect(url_for("admin_database_page"))


@app.post("/admin/users/delete")
@role_required("admin")
def delete_user():
    username = request.form.get("username", "").strip()
    actor = current_user()
    if not username:
        flash("Username is required.")
        return redirect(url_for("admin_database_page"))
    if actor and actor["username"] == username:
        flash("You cannot delete your own account.")
        return redirect(url_for("admin_database_page"))

    db = get_db()
    target = db.execute(
        "SELECT username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not target:
        flash(f"User {username} was not found.")
        return redirect(url_for("admin_database_page"))

    if target["role"] == "admin":
        admin_count = db.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin'",
        ).fetchone()
        if admin_count["cnt"] <= 1:
            flash("Cannot delete the last admin account.")
            return redirect(url_for("admin_database_page"))

    db.execute("DELETE FROM users WHERE username = ?", (username,))
    db.commit()
    flash(f"User {username} deleted.")
    return redirect(url_for("admin_database_page"))


@app.post("/boxes/add")
@role_required("admin")
def add_box():
    box_id = request.form.get("box_id", "").strip()
    ral_raw = request.form.get("ral", "").strip()
    gloss_raw = request.form.get("gloss", "").strip()
    weight = request.form.get("weight_kg", "").strip()

    if not box_id or not ral_raw or not gloss_raw or not weight:
        flash("All box fields are required.")
        return redirect(url_for("index"))

    ral = normalize_ral(ral_raw)
    if ral is None:
        flash("RAL must be selected from the RAL colour chart list.")
        return redirect(url_for("index"))

    gloss = normalize_gloss(gloss_raw)
    if gloss is None:
        flash("Gloss must be one of: Matt, Semi Gloss, Gloss.")
        return redirect(url_for("index"))

    try:
        weight_kg = float(weight)
        if weight_kg < 0:
            raise ValueError
    except ValueError:
        flash("Weight must be a valid non-negative number.")
        return redirect(url_for("index"))

    db = get_db()
    existing = db.execute("SELECT id FROM boxes WHERE id = ?", (box_id,)).fetchone()
    if existing:
        flash(f"Box {box_id} already exists.")
        return redirect(url_for("index"))

    db.execute(
        """
        INSERT INTO boxes(id, ral, gloss, current_weight_kg, status, created_at)
        VALUES (?, ?, ?, ?, 'IN_STOCK', ?)
        """,
        (box_id, ral, gloss, weight_kg, now_iso()),
    )
    db.commit()
    flash(f"Box {box_id} added.")
    return redirect(url_for("index"))


@app.post("/scan/out")
@role_required("admin", "user")
def scan_out():
    box_id = request.form.get("box_id", "").strip()
    job_code = request.form.get("job_code", "").strip().upper()
    line_name = request.form.get("line_name", "").strip().upper()
    out_weight_raw = request.form.get("out_weight_kg", "").strip()

    if not box_id or not job_code or not line_name or not out_weight_raw:
        flash("Scan-out requires box, job, line, and weight.")
        return redirect(url_for("index"))

    if line_name not in {"LINE_1", "LINE_2"}:
        flash("Line must be LINE_1 or LINE_2.")
        return redirect(url_for("index"))

    try:
        out_weight = float(out_weight_raw)
        if out_weight < 0:
            raise ValueError
    except ValueError:
        flash("Out weight must be a valid non-negative number.")
        return redirect(url_for("index"))

    db = get_db()
    job = db.execute(
        "SELECT code, status FROM jobs WHERE code = ?",
        (job_code,),
    ).fetchone()
    if not job:
        flash(f"Job {job_code} does not exist. Create it first in Jobs.")
        return redirect(url_for("index"))
    if job["status"] != "OPEN":
        flash(f"Job {job_code} is closed.")
        return redirect(url_for("index"))

    box = db.execute("SELECT * FROM boxes WHERE id = ?", (box_id,)).fetchone()
    if not box:
        flash(f"Box {box_id} not found.")
        return redirect(url_for("index"))
    if box["status"] == "CHECKED_OUT":
        flash(f"Box {box_id} is already checked out.")
        return redirect(url_for("index"))

    ts = now_iso()
    db.execute(
        """
        INSERT INTO active_checkouts(box_id, job_code, line_name, out_weight_kg, checked_out_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (box_id, job_code, line_name, out_weight, ts),
    )
    db.execute(
        """
        INSERT INTO movements(box_id, job_code, line_name, action, weight_kg, weight_used_kg, created_at)
        VALUES (?, ?, ?, 'OUT', ?, NULL, ?)
        """,
        (box_id, job_code, line_name, out_weight, ts),
    )
    db.execute(
        """
        UPDATE boxes
        SET status = 'CHECKED_OUT', current_weight_kg = ?
        WHERE id = ?
        """,
        (out_weight, box_id),
    )
    db.commit()
    flash(f"Box {box_id} checked out to job {job_code}.")
    return redirect(url_for("index"))


@app.post("/scan/in")
@role_required("admin", "user")
def scan_in():
    box_id = request.form.get("box_id", "").strip()
    in_weight_raw = request.form.get("in_weight_kg", "").strip()

    if not box_id or not in_weight_raw:
        flash("Scan-back requires box and return weight.")
        return redirect(url_for("index"))

    try:
        in_weight = float(in_weight_raw)
        if in_weight < 0:
            raise ValueError
    except ValueError:
        flash("Return weight must be a valid non-negative number.")
        return redirect(url_for("index"))

    db = get_db()
    checkout = db.execute(
        "SELECT * FROM active_checkouts WHERE box_id = ?",
        (box_id,),
    ).fetchone()
    if not checkout:
        flash(f"No active checkout found for box {box_id}.")
        return redirect(url_for("index"))

    used_kg = round(checkout["out_weight_kg"] - in_weight, 3)
    if used_kg < 0:
        flash(
            f"Return weight ({in_weight}) is higher than checkout weight "
            f"({checkout['out_weight_kg']})."
        )
        return redirect(url_for("index"))

    ts = now_iso()
    db.execute(
        """
        INSERT INTO movements(box_id, job_code, line_name, action, weight_kg, weight_used_kg, created_at)
        VALUES (?, ?, ?, 'IN', ?, ?, ?)
        """,
        (
            box_id,
            checkout["job_code"],
            checkout["line_name"] or "UNASSIGNED",
            in_weight,
            used_kg,
            ts,
        ),
    )
    db.execute("DELETE FROM active_checkouts WHERE box_id = ?", (box_id,))
    db.execute(
        """
        UPDATE boxes
        SET status = 'IN_STOCK', current_weight_kg = ?
        WHERE id = ?
        """,
        (in_weight, box_id),
    )
    db.commit()
    flash(
        f"Box {box_id} returned from job {checkout['job_code']}. "
        f"Paint used: {used_kg} kg."
    )
    return redirect(url_for("index"))


if __name__ == "__main__":
    from waitress import serve

    init_db()
    serve(app, host="192.168.1.200", port=8080)
