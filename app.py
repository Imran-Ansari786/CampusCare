import os
import sqlite3
import uuid
from datetime import datetime, timedelta

from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    redirect,
    url_for,
    session,
    flash
)

from database import init_db, get_db

# ==========================================
# APPLICATION CONFIGURATION
# ==========================================
app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "campuscare-development-secret-change-later"
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

init_db()


# ==========================================
# SECURITY: ROLE PERMISSION FUNCTIONS
# ==========================================

def has_role_permission(role, permission_key):
    """Check a role permission stored in the database."""

    conn = get_db()

    try:
        permission = conn.execute("""
            SELECT is_allowed
            FROM role_permissions
            WHERE role = ?
              AND permission_key = ?
        """, (role, permission_key)).fetchone()

        return bool(permission["is_allowed"]) if permission else False

    except sqlite3.Error:
        app.logger.exception("Role permission check failed")
        return False

    finally:
        conn.close()


def login_required(role=None, permission=None):
    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:
                flash("Please login first.", "error")
                return redirect(url_for("login"))

            current_role = session.get("role")

            if role and current_role != role:
                flash(
                    "You are not authorized to access this page.",
                    "error"
                )
                return redirect(url_for("dashboard"))

            # Super Admin retains full access.
            if permission and current_role != "super_admin":

                if not has_role_permission(
                        current_role,
                        permission
                ):
                    flash(
                        "This feature is not allowed for your role.",
                        "error"
                    )
                    return redirect(url_for("dashboard"))

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# SECURITY: LOGIN ACTIVITY PAGE
# ==========================================

@app.route("/admin/login-activity")
@login_required("super_admin")
def admin_login_activity():
    conn = get_db()

    try:
        activities = conn.execute("""
            SELECT
                id,
                user_id,
                email,
                role,
                ip_address,
                user_agent,
                status,
                failure_reason,
                created_at
            FROM login_activity
            ORDER BY id DESC
            LIMIT 200
        """).fetchall()

        total_logins = conn.execute("""
            SELECT COUNT(*)
            FROM login_activity
            WHERE status = 'success'
        """).fetchone()[0]

        failed_logins = conn.execute("""
            SELECT COUNT(*)
            FROM login_activity
            WHERE status = 'failed'
        """).fetchone()[0]

        return render_template(
            "login_activity.html",
            activities=activities,
            total_logins=total_logins,
            failed_logins=failed_logins
        )

    except sqlite3.Error:
        app.logger.exception("Login activity page error")
        flash("Unable to load login activity.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()


# ==========================================
# SECURITY: LOGIN ACTIVITY LOGGER
# ==========================================
def record_login_activity(
        email,
        status,
        user=None,
        user_id=None,
        role=None,
        failure_reason=None
):
    conn = get_db()

    try:
        if user:
            user_id = user["id"]
            role = user["role"]

        conn.execute("""
            INSERT INTO login_activity (
                user_id,
                email,
                role,
                ip_address,
                user_agent,
                status,
                failure_reason
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            email,
            role,
            request.remote_addr,
            request.user_agent.string[:500],
            status,
            failure_reason
        ))

        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Login activity recording failed")

    finally:
        conn.close()


# ==========================================
# DATABASE COMPATIBILITY HELPERS
# ==========================================

def get_table_columns(conn, table_name):
    """Return available columns of a database table."""

    tables = conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
    """, (table_name,)).fetchone()

    if not tables:
        return set()

    return {
        row["name"]
        for row in conn.execute(
            f'PRAGMA table_info("{table_name}")'
        ).fetchall()
    }


def get_notification_table(conn):
    """
    Support both notifications and student_notifications
    database table names.
    """

    if conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'notifications'
    """).fetchone():

        table = "notifications"

    elif conn.execute("""
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'student_notifications'
    """).fetchone():

        table = "student_notifications"

    else:
        return None, set(), None

    columns = get_table_columns(conn, table)

    owner_column = (
        "user_id" if "user_id" in columns
        else "student_id" if "student_id" in columns
        else None
    )

    return table, columns, owner_column


def create_notification(
        conn,
        user_id,
        complaint_id,
        title,
        message,
        notification_type="status"
):
    """Insert notification using the existing database schema."""

    table, columns, owner_column = get_notification_table(conn)

    if not table or not owner_column:
        app.logger.warning("Notification table or owner column not found.")
        return

    values = {
        owner_column: user_id,
        "complaint_id": complaint_id,
        "title": title,
        "message": message,
        "type": notification_type,
        "is_read": 0
    }

    available_values = {
        key: value
        for key, value in values.items()
        if key in columns
    }

    if not available_values:
        return

    column_names = ", ".join(
        f'"{column}"' for column in available_values
    )

    placeholders = ", ".join(
        ["?"] * len(available_values)
    )

    conn.execute(
        f"""
        INSERT INTO "{table}" ({column_names})
        VALUES ({placeholders})
        """,
        tuple(available_values.values())
    )


# ==========================================
# COMPLAINT FORWARDING TABLE
# ==========================================

def init_complaint_forwarding():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS complaint_forwards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id INTEGER NOT NULL,
                hod_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception(
            "Complaint forwarding table creation failed"
        )
        raise

    finally:
        conn.close()


init_complaint_forwarding()


# ==========================================
# SECURITY: DEFAULT ROLE PERMISSIONS
# ==========================================

def init_role_permissions():
    permissions = {
        "student": [
            ("view_dashboard", 1),
            ("submit_complaint", 1),
            ("view_own_complaints", 1),
            ("view_department_complaints", 1)
        ],

        "faculty": [
            ("view_dashboard", 1),
            ("view_complaints", 1),
            ("reply_complaints", 1)
        ],

        "hod": [
            ("view_dashboard", 1),
            ("view_complaints", 1),
            ("reply_complaints", 1),
            ("forward_complaints", 1),
            ("manage_department", 1)
        ]
    }

    conn = get_db()

    try:
        for role, role_permissions in permissions.items():

            for permission_key, allowed in role_permissions:
                conn.execute("""
                    INSERT OR IGNORE INTO role_permissions (
                        role,
                        permission_key,
                        is_allowed
                    )
                    VALUES (?, ?, ?)
                """, (
                    role,
                    permission_key,
                    allowed
                ))

        conn.commit()

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception(
            "Default role permissions initialization failed"
        )
        raise

    finally:
        conn.close()


init_role_permissions()

# ==========================================
# SECURITY: ROLE PERMISSIONS PAGE
# ==========================================

ROLE_PERMISSION_OPTIONS = {
    "student": [
        ("view_dashboard", "View Dashboard"),
        ("submit_complaint", "Submit Complaint"),
        ("view_own_complaints", "View Own Complaints"),
        ("view_department_complaints", "View Department Complaints")
    ],

    "faculty": [
        ("view_dashboard", "View Dashboard"),
        ("view_complaints", "View Complaints"),
        ("reply_complaints", "Reply to Complaints")
    ],

    "hod": [
        ("view_dashboard", "View Dashboard"),
        ("view_complaints", "View Complaints"),
        ("reply_complaints", "Reply to Complaints"),
        ("forward_complaints", "Forward Complaints"),
        ("manage_department", "Manage Department")
    ]
}


@app.route("/admin/role-permissions", methods=["GET", "POST"])
@login_required("super_admin")
def admin_role_permissions():
    conn = get_db()

    try:
        if request.method == "POST":

            role = request.form.get("role", "").strip()
            permission_key = request.form.get(
                "permission_key", ""
            ).strip()
            allowed = request.form.get("is_allowed", "")

            valid_keys = {
                key
                for key, label in ROLE_PERMISSION_OPTIONS.get(role, [])
            }

            if (
                    role not in ROLE_PERMISSION_OPTIONS
                    or permission_key not in valid_keys
                    or allowed not in ("0", "1")
            ):
                flash("Invalid permission update.", "error")
                return redirect(url_for("admin_role_permissions"))

            conn.execute("""
                INSERT INTO role_permissions (
                    role,
                    permission_key,
                    is_allowed,
                    updated_by,
                    updated_at
                )
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)

                ON CONFLICT(role, permission_key)
                DO UPDATE SET
                    is_allowed = excluded.is_allowed,
                    updated_by = excluded.updated_by,
                    updated_at = CURRENT_TIMESTAMP
            """, (
                role,
                permission_key,
                int(allowed),
                session["user_id"]
            ))

            conn.commit()

            flash("Role permission updated successfully.", "success")
            return redirect(url_for("admin_role_permissions"))

        permission_rows = conn.execute("""
            SELECT role, permission_key, is_allowed, updated_at
            FROM role_permissions
        """).fetchall()

        saved_permissions = {
            (row["role"], row["permission_key"]): row["is_allowed"]
            for row in permission_rows
        }

        roles = []

        for role, options in ROLE_PERMISSION_OPTIONS.items():

            role_data = {
                "name": role,
                "label": role.replace("_", " ").title(),
                "permissions": []
            }

            for permission_key, label in options:
                role_data["permissions"].append({
                    "key": permission_key,
                    "label": label,
                    "allowed": saved_permissions.get(
                        (role, permission_key), 0
                    )
                })

            roles.append(role_data)

        return render_template(
            "role_permissions.html",
            roles=roles
        )

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Role permissions page error")
        flash("Unable to load or update permissions.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()


# ==========================================
# NOTIFICATION HELPERS
# ==========================================

def get_unread_notification_count(conn, user_id):
    table, columns, owner_column = get_notification_table(conn)

    if not table or not owner_column:
        return 0

    if "is_read" not in columns:
        return 0

    return conn.execute(
        f"""
        SELECT COUNT(*)
        FROM "{table}"
        WHERE "{owner_column}" = ?
          AND is_read = 0
        """,
        (user_id,)
    ).fetchone()[0]


def get_user_notifications(conn, user_id):
    table, columns, owner_column = get_notification_table(conn)

    if not table or not owner_column:
        return []

    if "complaint_id" in columns:
        return conn.execute(
            f"""
            SELECT
                n.*,
                c.title AS complaint_title
            FROM "{table}" n
            LEFT JOIN complaints c
                ON c.id = n.complaint_id
            WHERE n."{owner_column}" = ?
            ORDER BY n.rowid DESC
            """,
            (user_id,)
        ).fetchall()

    return conn.execute(
        f"""
        SELECT *
        FROM "{table}"
        WHERE "{owner_column}" = ?
        ORDER BY rowid DESC
        """,
        (user_id,)
    ).fetchall()


# ==========================================
# LOGIN PROTECTION
# ==========================================


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# STUDENT REGISTRATION
# ==========================================

@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    conn = get_db()

    if request.method == "GET":

        try:
            departments = conn.execute("""
                SELECT department_name
                FROM departments
                ORDER BY department_name
            """).fetchall()

            return render_template(
                "student_register.html",
                departments=departments
            )

        finally:
            conn.close()

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    admission_no = request.form.get("admission_no", "").strip()
    course = request.form.get("course", "").strip()
    department = request.form.get("department", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    try:

        if not all([
            name, email, admission_no, course,
            department, password, confirm_password
        ]):
            flash("Please fill all required fields.", "error")
            return redirect(url_for("student_register"))

        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Enter a valid email address.", "error")
            return redirect(url_for("student_register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("student_register"))

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("student_register"))

        department_record = conn.execute("""
            SELECT department_name
            FROM departments
            WHERE department_name = ?
        """, (department,)).fetchone()

        if not department_record:
            flash("Please select a valid department.", "error")
            return redirect(url_for("student_register"))

        existing = conn.execute("""
            SELECT id
            FROM users
            WHERE LOWER(email) = ?
               OR admission_no = ?
        """, (email, admission_no)).fetchone()

        if existing:
            flash(
                "Email or admission number is already registered.",
                "error"
            )
            return redirect(url_for("student_register"))

        conn.execute("""
            INSERT INTO users (
                name,
                email,
                password,
                role,
                admission_no,
                college,
                course,
                department,
                section,
                account_status,
                email_verified,
                mobile_verified,
                college_id_verified
            )
            VALUES (
                ?, ?, ?, 'student', ?, ?, ?, ?, NULL,
                'pending', 1, 0, 0
            )
        """, (
            name,
            email,
            generate_password_hash(password),
            admission_no,
            "CampusCare College",
            course,
            department
        ))

        conn.commit()

        flash(
            "Registration successful! Your account is waiting for HOD approval.",
            "success"
        )

        return redirect(url_for("login"))

    except sqlite3.IntegrityError:
        conn.rollback()
        flash(
            "Email or admission number is already registered.",
            "error"
        )
        return redirect(url_for("student_register"))

    except Exception:
        conn.rollback()
        app.logger.exception("Student registration failed")
        flash(
            "Student registration failed. Please try again.",
            "error"
        )
        return redirect(url_for("student_register"))

    finally:
        conn.close()


# ==========================================
# HOD REGISTRATION
# ==========================================
# ==========================================
# HOD REGISTRATION
# ==========================================

@app.route("/hod/register", methods=["GET", "POST"])
def hod_register():
    conn = get_db()

    try:
        departments = conn.execute("""
            SELECT department_name
            FROM departments
            ORDER BY department_name
        """).fetchall()

        if request.method == "POST":

            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            mobile = request.form.get("mobile", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            department = request.form.get("department", "").strip()
            designation = request.form.get("designation", "").strip()
            college = request.form.get("college", "").strip()

            if not all([
                name, email, mobile, password,
                confirm_password, department, college
            ]):
                flash("Please fill all required fields.", "error")

            elif password != confirm_password:
                flash("Passwords do not match.", "error")

            elif len(password) < 8:
                flash("Password must contain at least 8 characters.", "error")

            else:
                department_exists = conn.execute("""
                    SELECT id
                    FROM departments
                    WHERE department_name = ?
                """, (department,)).fetchone()

                if not department_exists:
                    flash("Please select a valid department.", "error")

                else:
                    existing_user = conn.execute("""
                        SELECT id
                        FROM users
                        WHERE LOWER(email) = ?
                           OR mobile = ?
                    """, (email, mobile)).fetchone()

                    if existing_user:
                        flash("Email or mobile number already registered.", "error")

                    else:
                        conn.execute("""
                            INSERT INTO users (
                                name,
                                email,
                                mobile,
                                password,
                                role,
                                department,
                                designation,
                                college,
                                account_status,
                                mobile_verified,
                                email_verified
                            )
                            VALUES (?, ?, ?, ?, 'hod', ?, ?, ?, 'pending', 0, 0)
                        """, (
                            name,
                            email,
                            mobile,
                            generate_password_hash(password),
                            department,
                            designation or "Head of Department",
                            college
                        ))

                        conn.commit()

                        flash(
                            "HOD registration submitted. Please wait for Super Admin approval.",
                            "success"
                        )

                        return redirect(url_for("login"))

        return render_template(
            "hod_register.html",
            departments=departments
        )

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("HOD registration failed")
        flash("Registration failed. Please try again.", "error")

        return render_template(
            "hod_register.html",
            departments=departments
        )

    finally:
        conn.close()


# ==========================================
# STUDENT / FACULTY / HOD LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Please enter email and password.", "error")
        return redirect(url_for("login"))

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT *
            FROM users
            WHERE LOWER(email) = ?
        """, (email,)).fetchone()

        protection = conn.execute("""
            SELECT enabled, max_attempts, lock_duration
            FROM login_protection
            WHERE id = 1
        """).fetchone()

        if not user:
            conn.execute("""
                INSERT INTO login_activity (
                    email, ip_address, user_agent,
                    status, failure_reason
                )
                VALUES (?, ?, ?, 'failed', ?)
            """, (
                email,
                request.remote_addr,
                request.headers.get("User-Agent", ""),
                "Invalid email"
            ))
            conn.commit()

            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        # Check whether account is currently locked
        if protection and protection["enabled"]:
            locked_until = user["locked_until"]

            if locked_until:
                try:
                    lock_time = datetime.fromisoformat(str(locked_until))

                    if datetime.now() < lock_time:
                        remaining = max(
                            1,
                            int((lock_time - datetime.now()).total_seconds() / 60) + 1
                        )

                        flash(
                            f"Account temporarily locked. Try again after {remaining} minute(s).",
                            "error"
                        )
                        return redirect(url_for("login"))

                except (ValueError, TypeError):
                    pass

                # Expired lock: reset attempts
                conn.execute("""
                    UPDATE users
                    SET failed_attempts = 0,
                        locked_until = NULL
                    WHERE id = ?
                """, (user["id"],))
                conn.commit()

        # Check password
        if not check_password_hash(user["password"], password):

            if protection and protection["enabled"]:
                attempts = user["failed_attempts"] + 1
                max_attempts = protection["max_attempts"]

                if attempts >= max_attempts:
                    lock_until = datetime.now() + timedelta(
                        minutes=protection["lock_duration"]
                    )

                    conn.execute("""
                        UPDATE users
                        SET failed_attempts = ?,
                            locked_until = ?
                        WHERE id = ?
                    """, (
                        attempts,
                        lock_until.isoformat(timespec="seconds"),
                        user["id"]
                    ))

                    reason = "Account locked after maximum failed attempts"

                else:
                    conn.execute("""
                        UPDATE users
                        SET failed_attempts = ?
                        WHERE id = ?
                    """, (attempts, user["id"]))

                    reason = "Invalid password"

            else:
                reason = "Invalid password"

            conn.execute("""
                INSERT INTO login_activity (
                    user_id, email, role, ip_address,
                    user_agent, status, failure_reason
                )
                VALUES (?, ?, ?, ?, ?, 'failed', ?)
            """, (
                user["id"],
                email,
                user["role"],
                request.remote_addr,
                request.headers.get("User-Agent", ""),
                reason
            ))

            conn.commit()

            if protection and protection["enabled"] and attempts >= protection["max_attempts"]:
                flash(
                    "Too many failed attempts. Your account has been temporarily locked.",
                    "error"
                )
            else:
                flash("Invalid email or password.", "error")

            return redirect(url_for("login"))

        # Account status check
        if user["account_status"] != "active":
            flash("Your account is not active.", "error")
            return redirect(url_for("login"))

        if user["role"] == "student" and not user["college_id_verified"]:
            flash("Your account is waiting for HOD verification.", "error")
            return redirect(url_for("login"))

        if user["role"] not in ["student", "faculty", "hod"]:
            flash("Please use the correct login page.", "error")
            return redirect(url_for("login"))

        # Successful login: reset failed attempts
        conn.execute("""
            UPDATE users
            SET failed_attempts = 0,
                locked_until = NULL
            WHERE id = ?
        """, (user["id"],))

        conn.execute("""
            INSERT INTO login_activity (
                user_id, email, role, ip_address,
                user_agent, status, failure_reason
            )
            VALUES (?, ?, ?, ?, ?, 'success', NULL)
        """, (
            user["id"],
            email,
            user["role"],
            request.remote_addr,
            request.headers.get("User-Agent", "")
        ))

        conn.commit()

        session.clear()
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]
        session["department"] = user["department"]

        flash("Login successful!", "success")

        return redirect(url_for("dashboard"))

    except Exception:
        conn.rollback()
        app.logger.exception("Login error")
        flash("Unable to process login. Please try again.", "error")
        return redirect(url_for("login"))

    finally:
        conn.close()


# ==========================================
# SUPER ADMIN LOGIN
# ==========================================
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        record_login_activity(
            email=email or None,
            role="super_admin",
            status="failed",
            failure_reason="Email or password missing"
        )

        flash("Please enter email and password.", "error")
        return redirect(url_for("admin_login"))

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT *
            FROM users
            WHERE LOWER(email) = ?
              AND role = 'super_admin'
        """, (email,)).fetchone()

    finally:
        conn.close()

    if not user or not check_password_hash(user["password"], password):
        record_login_activity(
            user_id=user["id"] if user else None,
            email=email,
            role="super_admin",
            status="failed",
            failure_reason="Invalid Super Admin credentials"
        )

        flash("Invalid Super Admin email or password.", "error")
        return redirect(url_for("admin_login"))

    if user["account_status"] != "active":
        record_login_activity(
            user_id=user["id"],
            email=email,
            role="super_admin",
            status="failed",
            failure_reason="Super Admin account not active"
        )

        flash("Your Super Admin account is not active.", "error")
        return redirect(url_for("admin_login"))

    session.clear()

    session["user_id"] = user["id"]
    session["name"] = user["name"]
    session["role"] = user["role"]
    session["department"] = user["department"]

    record_login_activity(
        user_id=user["id"],
        email=email,
        role="super_admin",
        status="success"
    )

    flash("Super Admin login successful!", "success")
    return redirect(url_for("admin_dashboard"))


# ==========================================
# ROLE BASED DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required()
def dashboard():
    role = session.get("role")

    if role == "student":
        return redirect(url_for("student_dashboard"))

    if role == "faculty":
        return redirect(url_for("faculty_dashboard"))

    if role == "hod":
        return redirect(url_for("hod_dashboard"))

    if role == "super_admin":
        return redirect(url_for("admin_dashboard"))

    session.clear()
    return redirect(url_for("login"))


# ==========================================
# STUDENT DASHBOARD
# ==========================================
@app.route("/student/dashboard")
@login_required("student", permission="view_dashboard")
def student_dashboard():
    conn = get_db()

    try:
        student_id = session["user_id"]

        total_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE student_id = ?
        """, (student_id,)).fetchone()[0]

        pending_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE student_id = ?
              AND status = 'Pending'
        """, (student_id,)).fetchone()[0]

        resolved_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE student_id = ?
              AND status = 'Resolved'
        """, (student_id,)).fetchone()[0]

        recent_complaints = conn.execute("""
            SELECT id, category, title, status, created_at
            FROM complaints
            WHERE student_id = ?
            ORDER BY created_at DESC
            LIMIT 5
        """, (student_id,)).fetchall()

        unread_notifications = get_unread_notification_count(
            conn, student_id
        )

        return render_template(
            "student_dashboard.html",
            total_complaints=total_complaints,
            pending_complaints=pending_complaints,
            resolved_complaints=resolved_complaints,
            recent_complaints=recent_complaints,
            unread_notifications=unread_notifications
        )

    except Exception:
        app.logger.exception("Student dashboard error")
        return "Something went wrong while loading dashboard.", 500

    finally:
        conn.close()


@app.route("/student/settings", methods=["GET", "POST"])
@login_required("student")
def student_settings():
    conn = get_db()

    try:
        student_id = session["user_id"]

        columns = [
            row["name"]
            for row in conn.execute("PRAGMA table_info(users)").fetchall()
        ]

        password_column = next(
            (col for col in ("password_hash", "password") if col in columns),
            None
        )

        if not password_column:
            return "Password column not found in users table.", 500

        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not current_password or not new_password or not confirm_password:
                flash("Please fill all password fields.", "error")

            elif len(new_password) < 8:
                flash("New password must contain at least 8 characters.", "error")

            elif new_password != confirm_password:
                flash("New password and confirm password do not match.", "error")

            else:
                user = conn.execute(
                    f"SELECT {password_column} FROM users WHERE id = ? AND role = 'student'",
                    (student_id,)
                ).fetchone()

                if not user:
                    flash("Student account not found.", "error")

                elif not check_password_hash(user[password_column], current_password):
                    flash("Current password is incorrect.", "error")

                else:
                    password_hash = generate_password_hash(new_password)

                    conn.execute(
                        f"UPDATE users SET {password_column} = ? WHERE id = ?",
                        (password_hash, student_id)
                    )
                    conn.commit()
                    flash("Password changed successfully!", "success")

        return render_template("student_settings.html")

    except Exception:
        conn.rollback()
        app.logger.exception("Student settings error")
        return "Something went wrong while loading settings.", 500

    finally:
        conn.close()


# ==========================================
# STUDENT PROFILE
# ==========================================

@app.route("/student/profile", methods=["GET", "POST"])
@login_required("student")
def student_profile():
    conn = get_db()

    try:
        student_id = session["user_id"]

        student = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
              AND role = 'student'
        """, (student_id,)).fetchone()

        if not student:
            flash("Student record not found.", "error")
            return redirect(url_for("student_dashboard"))

        if request.method == "POST":

            mobile = request.form.get("mobile", "").strip()
            semester = request.form.get("semester", "").strip()
            section = request.form.get("section", "").strip()
            address = request.form.get("address", "").strip()
            about_me = request.form.get("about_me", "").strip()

            if not mobile or not semester or not section or not address:
                return render_template(
                    "student_profile.html",
                    student=student,
                    error="Please fill all required fields."
                )

            existing_mobile = conn.execute("""
                SELECT id
                FROM users
                WHERE mobile = ?
                  AND id != ?
            """, (mobile, student_id)).fetchone()

            if existing_mobile:
                return render_template(
                    "student_profile.html",
                    student=student,
                    error="This mobile number is already registered."
                )

            profile_photo = student["profile_photo"]

            photo = request.files.get("profile_photo")

            if photo and photo.filename:

                allowed_extensions = {
                    "jpg", "jpeg", "png", "webp"
                }

                filename = secure_filename(photo.filename)

                if "." not in filename:
                    return render_template(
                        "student_profile.html",
                        student=student,
                        error="Invalid image filename."
                    )

                extension = filename.rsplit(".", 1)[-1].lower()

                if extension not in allowed_extensions:
                    return render_template(
                        "student_profile.html",
                        student=student,
                        error="Only JPG, JPEG, PNG and WEBP images are allowed."
                    )

                upload_folder = os.path.join(
                    app.root_path,
                    "static",
                    "uploads",
                    "profile_photos"
                )

                os.makedirs(upload_folder, exist_ok=True)

                new_filename = f"{uuid.uuid4().hex}.{extension}"

                photo.save(
                    os.path.join(upload_folder, new_filename)
                )

                profile_photo = new_filename

            conn.execute("""
                UPDATE users
                SET mobile = ?,
                    semester = ?,
                    section = ?,
                    address = ?,
                    about_me = ?,
                    profile_photo = ?,
                    profile_completed = 1
                WHERE id = ?
                  AND role = 'student'
            """, (
                mobile,
                semester,
                section,
                address,
                about_me,
                profile_photo,
                student_id
            ))

            conn.commit()

            flash("Profile updated successfully.", "success")
            return redirect(url_for("student_profile"))

        return render_template(
            "student_profile.html",
            student=student
        )

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("This mobile number is already registered.", "error")
        return redirect(url_for("student_profile"))

    except Exception:
        conn.rollback()
        app.logger.exception("Student profile error")
        flash("Could not update your profile.", "error")
        return redirect(url_for("student_profile"))

    finally:
        conn.close()


# ==========================================
# STUDENT - SUBMIT COMPLAINT
# ==========================================

@app.route("/student/submit-complaint", methods=["GET", "POST"])
@login_required("student", permission="submit_complaint")
def submit_complaint():
    conn = get_db()

    try:
        student_id = session["user_id"]

        student = conn.execute("""
            SELECT name, admission_no, course, section, department
            FROM users
            WHERE id = ?
              AND role = 'student'
        """, (student_id,)).fetchone()

        if not student:
            flash("Student record not found.", "error")
            return redirect(url_for("student_dashboard"))

        if request.method == "POST":

            description = request.form.get(
                "description", ""
            ).strip()

            if not description:
                flash("Please enter your complaint.", "error")
                return render_template(
                    "submit_complaint.html",
                    student=student
                )

            department = conn.execute("""
                SELECT id, hod_id
                FROM departments
                WHERE department_name = ?
            """, (student["department"],)).fetchone()

            if not department or not department["hod_id"]:
                flash(
                    "No HOD is assigned to your department yet.",
                    "error"
                )
                return render_template(
                    "submit_complaint.html",
                    student=student
                )

            cursor = conn.execute("""
                INSERT INTO complaints (
                    student_id,
                    category,
                    title,
                    description,
                    department_id,
                    status
                )
                VALUES (?, ?, ?, ?, ?, 'Pending')
            """, (
                student_id,
                "General",
                "Student Complaint",
                description,
                department["id"]
            ))

            complaint_id = cursor.lastrowid

            create_notification(
                conn,
                student_id,
                complaint_id,
                "Complaint Submitted",
                "Your complaint has been submitted successfully.",
                "status"
            )

            conn.commit()

            flash("Complaint submitted successfully!", "success")
            return redirect(url_for("my_complaints"))

        return render_template(
            "submit_complaint.html",
            student=student
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Complaint submission failed")
        flash(
            "Could not submit complaint. Please try again.",
            "error"
        )
        return redirect(url_for("student_dashboard"))

    finally:
        conn.close()


# ==========================================
# STUDENT - MY COMPLAINTS
# ==========================================

@app.route("/student/my-complaints")
@login_required("student", permission="view_own_complaints")
def my_complaints():
    conn = get_db()

    try:
        complaints = conn.execute("""
            SELECT
                c.id,
                c.category,
                c.title,
                c.description,
                c.status,
                c.created_at,
                c.updated_at,
                'Normal' AS priority,
                d.department_name
            FROM complaints c
            LEFT JOIN departments d
                ON d.id = c.department_id
            WHERE c.student_id = ?
            ORDER BY c.created_at DESC
        """, (session["user_id"],)).fetchall()

        return render_template(
            "my_complaints.html",
            complaints=complaints
        )

    finally:
        conn.close()


# ==========================================
# STUDENT - SENT COMPLAINTS
# ==========================================

@app.route("/student/sent-complaints")
@login_required("student")
def sent_complaints():
    conn = get_db()

    try:
        complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.category,
                c.status,
                c.created_at,
                COUNT(DISTINCT cl.id) AS vote_count
            FROM complaints c
            LEFT JOIN complaint_likes cl
                ON cl.complaint_id = c.id
            WHERE c.student_id = ?
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """, (session["user_id"],)).fetchall()

        return render_template(
            "sent_complaints.html",
            complaints=complaints
        )

    finally:
        conn.close()


# ==========================================
# STUDENT - DEPARTMENT COMPLAINT BOX
# ==========================================

@app.route("/student/department-complaints")
@login_required("student", permission="view_department_complaints")
def department_complaints():
    conn = get_db()

    try:
        student_id = session["user_id"]

        student = conn.execute("""
            SELECT department
            FROM users
            WHERE id = ?
              AND role = 'student'
        """, (student_id,)).fetchone()

        if not student or not student["department"]:
            flash("Your department is not assigned.", "error")
            return redirect(url_for("student_dashboard"))

        department = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE department_name = ?
        """, (student["department"],)).fetchone()

        if not department:
            flash("Department not found.", "error")
            return redirect(url_for("student_dashboard"))

        complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.category,
                c.description,
                c.status,
                c.created_at,
                u.name AS student_name,
                COUNT(DISTINCT cl.id) AS vote_count,

                CASE
                    WHEN c.student_id = ? THEN 1
                    ELSE 0
                END AS is_own,

                CASE
                    WHEN my_vote.id IS NOT NULL THEN 1
                    ELSE 0
                END AS has_voted

            FROM complaints c

            JOIN users u
                ON u.id = c.student_id

            LEFT JOIN complaint_likes cl
                ON cl.complaint_id = c.id

            LEFT JOIN complaint_likes my_vote
                ON my_vote.complaint_id = c.id
                AND my_vote.student_id = ?

            WHERE c.department_id = ?

            GROUP BY c.id
            ORDER BY c.created_at DESC
        """, (
            student_id,
            student_id,
            department["id"]
        )).fetchall()

        total_votes = conn.execute("""
            SELECT COUNT(*)
            FROM complaint_likes cl
            JOIN complaints c
                ON c.id = cl.complaint_id
            WHERE c.department_id = ?
        """, (department["id"],)).fetchone()[0]

        resolved_count = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
              AND status = 'Resolved'
        """, (department["id"],)).fetchone()[0]

        return render_template(
            "department_complaints.html",
            complaints=complaints,
            total_votes=total_votes,
            resolved_count=resolved_count,
            department_name=department["department_name"]
        )

    finally:
        conn.close()


# ==========================================
# STUDENT - VOTE ON DEPARTMENT COMPLAINT
# ==========================================

@app.route(
    "/student/complaint/<int:complaint_id>/vote",
    methods=["POST"]
)
@login_required("student")
def vote_complaint(complaint_id):
    conn = get_db()

    try:
        student_id = session["user_id"]

        student = conn.execute("""
            SELECT department
            FROM users
            WHERE id = ?
              AND role = 'student'
        """, (student_id,)).fetchone()

        if not student or not student["department"]:
            flash("Student department not found.", "error")
            return redirect(url_for("department_complaints"))

        complaint = conn.execute("""
            SELECT c.id, c.student_id, c.department_id
            FROM complaints c
            JOIN departments d
                ON d.id = c.department_id
            WHERE c.id = ?
              AND d.department_name = ?
        """, (
            complaint_id,
            student["department"]
        )).fetchone()

        if not complaint:
            flash(
                "Complaint not found in your department.",
                "error"
            )
            return redirect(url_for("department_complaints"))

        if complaint["student_id"] == student_id:
            flash(
                "You cannot vote on your own complaint.",
                "error"
            )
            return redirect(url_for("department_complaints"))

        existing_vote = conn.execute("""
            SELECT id
            FROM complaint_likes
            WHERE complaint_id = ?
              AND student_id = ?
        """, (
            complaint_id,
            student_id
        )).fetchone()

        if existing_vote:

            conn.execute("""
                DELETE FROM complaint_likes
                WHERE complaint_id = ?
                  AND student_id = ?
            """, (
                complaint_id,
                student_id
            ))

            flash("Your vote has been removed.", "success")

        else:

            conn.execute("""
                INSERT INTO complaint_likes (
                    complaint_id,
                    student_id
                )
                VALUES (?, ?)
            """, (
                complaint_id,
                student_id
            ))

            flash("Your vote has been submitted.", "success")

        conn.commit()

    except sqlite3.IntegrityError:
        conn.rollback()
        flash(
            "You have already voted on this complaint.",
            "error"
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Complaint voting error")
        flash("Could not submit your vote.", "error")

    finally:
        conn.close()

    return redirect(url_for("department_complaints"))


# ==========================================
# STUDENT - COMPLAINT DETAILS
# ==========================================

@app.route("/student/complaint/<int:complaint_id>")
@login_required("student")
def student_complaint_detail(complaint_id):
    conn = get_db()

    try:
        complaint = conn.execute("""
            SELECT
                c.*,
                d.department_name AS department,
                u.name AS student_name
            FROM complaints c
            LEFT JOIN departments d
                ON d.id = c.department_id
            LEFT JOIN users u
                ON u.id = c.student_id
            WHERE c.id = ?
              AND c.student_id = ?
        """, (
            complaint_id,
            session["user_id"]
        )).fetchone()

        if not complaint:
            flash("Complaint not found.", "error")
            return redirect(url_for("my_complaints"))

        replies = conn.execute("""
            SELECT
                cr.reply,
                cr.created_at,
                u.name AS responder_name
            FROM complaint_replies cr
            JOIN users u
                ON u.id = cr.faculty_id
            WHERE cr.complaint_id = ?
            ORDER BY cr.created_at DESC
        """, (complaint_id,)).fetchall()

        latest_reply = replies[0] if replies else None

        return render_template(
            "complaint_details.html",
            complaint=complaint,
            replies=replies,
            latest_reply=latest_reply
        )

    finally:
        conn.close()


# ==========================================
# STUDENT - EDIT COMPLAINT
# ==========================================

@app.route(
    "/student/complaint/<int:complaint_id>/edit",
    methods=["GET", "POST"]
)
@login_required("student")
def edit_complaint(complaint_id):
    conn = get_db()

    try:
        complaint = conn.execute("""
            SELECT *
            FROM complaints
            WHERE id = ?
              AND student_id = ?
        """, (
            complaint_id,
            session["user_id"]
        )).fetchone()

        if not complaint:
            flash("Complaint not found.", "error")
            return redirect(url_for("my_complaints"))

        if complaint["status"] != "Pending":
            flash(
                "Only Pending complaints can be edited.",
                "error"
            )
            return redirect(url_for(
                "student_complaint_detail",
                complaint_id=complaint_id
            ))

        if request.method == "POST":

            title = request.form.get("title", "").strip()
            category = request.form.get("category", "").strip()
            description = request.form.get(
                "description", ""
            ).strip()

            if not title or not category or not description:
                flash("Please fill all required fields.", "error")

                return render_template(
                    "edit_complaint.html",
                    complaint=complaint
                )

            conn.execute("""
                UPDATE complaints
                SET title = ?,
                    category = ?,
                    description = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND student_id = ?
                  AND status = 'Pending'
            """, (
                title,
                category,
                description,
                complaint_id,
                session["user_id"]
            ))

            conn.commit()

            flash("Complaint updated successfully.", "success")
            return redirect(url_for("my_complaints"))

        return render_template(
            "edit_complaint.html",
            complaint=complaint
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Complaint edit error")
        flash("Could not update complaint.", "error")
        return redirect(url_for("my_complaints"))

    finally:
        conn.close()


# ==========================================
# STUDENT - DELETE COMPLAINT
# ==========================================

@app.route(
    "/student/complaint/<int:complaint_id>/delete",
    methods=["POST"]
)
@login_required("student")
def delete_complaint(complaint_id):
    conn = get_db()

    try:
        complaint = conn.execute("""
            SELECT id, status
            FROM complaints
            WHERE id = ?
              AND student_id = ?
        """, (
            complaint_id,
            session["user_id"]
        )).fetchone()

        if not complaint:
            flash("Complaint not found.", "error")
            return redirect(url_for("my_complaints"))

        if complaint["status"] != "Pending":
            flash(
                "Only Pending complaints can be deleted.",
                "error"
            )
            return redirect(url_for("my_complaints"))

        conn.execute("""
            DELETE FROM complaint_likes
            WHERE complaint_id = ?
        """, (complaint_id,))

        conn.execute("""
            DELETE FROM complaint_replies
            WHERE complaint_id = ?
        """, (complaint_id,))

        table, columns, _ = get_notification_table(conn)

        if table and "complaint_id" in columns:
            conn.execute(
                f'DELETE FROM "{table}" WHERE complaint_id = ?',
                (complaint_id,)
            )

        conn.execute("""
            DELETE FROM complaints
            WHERE id = ?
              AND student_id = ?
              AND status = 'Pending'
        """, (
            complaint_id,
            session["user_id"]
        ))

        conn.commit()

        flash("Complaint deleted successfully.", "success")

    except Exception:
        conn.rollback()
        app.logger.exception("Complaint deletion error")
        flash("Could not delete complaint.", "error")

    finally:
        conn.close()

    return redirect(url_for("my_complaints"))


# ==========================================
# STUDENT - NOTIFICATIONS
# ==========================================

@app.route("/student/notifications")
@login_required("student")
def student_notifications():
    conn = get_db()

    try:
        notifications = get_user_notifications(
            conn, session["user_id"]
        )

        unread_count = get_unread_notification_count(
            conn, session["user_id"]
        )

        return render_template(
            "student_notifications.html",
            notifications=notifications,
            unread_count=unread_count
        )

    finally:
        conn.close()


# ==========================================
# STUDENT - MARK NOTIFICATIONS AS READ
# ==========================================

@app.route(
    "/student/notifications/mark-all-read",
    methods=["POST"]
)
@login_required("student")
def mark_all_notifications_read():
    conn = get_db()

    try:
        table, columns, owner_column = get_notification_table(conn)

        if table and owner_column and "is_read" in columns:
            conn.execute(
                f"""
                UPDATE "{table}"
                SET is_read = 1
                WHERE "{owner_column}" = ?
                """,
                (session["user_id"],)
            )

            conn.commit()

        flash(
            "All notifications marked as read.",
            "success"
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Notification update error")
        flash(
            "Could not update notifications.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for("student_notifications"))


# ==========================================
# FACULTY DASHBOARD
# ==========================================

@app.route("/faculty/dashboard")
@login_required("faculty", permission="view_dashboard")
def faculty_dashboard():
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Faculty Dashboard | CampusCare</title>
        </head>
        <body>
            <h1>Welcome to CampusCare, {{ name }}</h1>
            <p>Faculty Dashboard</p>
            <a href="{{ url_for('logout') }}">Logout</a>
        </body>
        </html>
    """, name=session.get("name"))


# ==========================================
# HOD DASHBOARD - COMPLETE OVERVIEW
# ==========================================

@app.route("/hod/dashboard")
@login_required("hod", permission="view_dashboard")
def hod_dashboard():
    conn = get_db()

    try:
        hod_id = session["user_id"]

        hod = conn.execute("""
            SELECT id, name, department, designation, account_status
            FROM users
            WHERE id = ?
              AND role = 'hod'
              AND account_status = 'active'
        """, (hod_id,)).fetchone()

        if not hod:
            flash("HOD account not found or inactive.", "error")
            return redirect(url_for("logout"))

        department = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE hod_id = ?
              AND department_name = ?
        """, (hod_id, hod["department"])).fetchone()

        if not department:
            flash("Department is not assigned to this HOD.", "error")
            return redirect(url_for("logout"))

        department_id = department["id"]
        department_name = department["department_name"]

        total_students = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role = 'student'
              AND department = ?
              AND account_status = 'active'
        """, (department_name,)).fetchone()[0]

        pending_student_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role = 'student'
              AND department = ?
              AND account_status = 'pending'
        """, (department_name,)).fetchone()[0]

        rejected_student_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role = 'student'
              AND department = ?
              AND account_status = 'rejected'
        """, (department_name,)).fetchone()[0]

        total_faculty = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role = 'faculty'
              AND department = ?
              AND account_status = 'active'
        """, (department_name,)).fetchone()[0]

        pending_faculty_count = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE role = 'faculty'
              AND department = ?
              AND account_status = 'pending'
        """, (department_name,)).fetchone()[0]

        total_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
        """, (department_id,)).fetchone()[0]

        pending_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
              AND status = 'Pending'
        """, (department_id,)).fetchone()[0]

        in_progress_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
              AND status = 'In Progress'
        """, (department_id,)).fetchone()[0]

        resolved_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
              AND status = 'Resolved'
        """, (department_id,)).fetchone()[0]

        recent_complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.category,
                c.status,
                c.created_at,
                'Normal' AS priority,
                u.name AS student_name
            FROM complaints c
            LEFT JOIN users u
                ON u.id = c.student_id
            WHERE c.department_id = ?
            ORDER BY c.created_at DESC
            LIMIT 5
        """, (department_id,)).fetchall()

        pending_students = conn.execute("""
            SELECT
                id, name, email, admission_no,
                course, department, created_at
            FROM users
            WHERE role = 'student'
              AND department = ?
              AND account_status = 'pending'
            ORDER BY created_at DESC
        """, (department_name,)).fetchall()

        department_students = conn.execute("""
            SELECT
                id, name, email, mobile,
                admission_no, course, section,
                semester, account_status, created_at
            FROM users
            WHERE role = 'student'
              AND department = ?
            ORDER BY
                CASE account_status
                    WHEN 'pending' THEN 1
                    WHEN 'active' THEN 2
                    ELSE 3
                END,
                name COLLATE NOCASE
        """, (department_name,)).fetchall()

        faculty_members = conn.execute("""
            SELECT
                id, name, email, mobile,
                designation, account_status, created_at
            FROM users
            WHERE role = 'faculty'
              AND department = ?
            ORDER BY name COLLATE NOCASE
        """, (department_name,)).fetchall()

        total_votes = conn.execute("""
            SELECT COUNT(*)
            FROM complaint_likes cl
            JOIN complaints c
                ON c.id = cl.complaint_id
            WHERE c.department_id = ?
        """, (department_id,)).fetchone()[0]

        resolution_rate = round(
            (resolved_complaints / total_complaints) * 100, 1
        ) if total_complaints else 0

        monthly_reports = conn.execute("""
            SELECT
                strftime('%Y-%m', created_at) AS month,
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END)
                    AS resolved
            FROM complaints
            WHERE department_id = ?
              AND created_at >= date('now', '-6 months')
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY month
        """, (department_id,)).fetchall()

        return render_template(
            "hod_dashboard.html",
            hod=hod,
            department_name=department_name,
            designation=hod["designation"] or "HOD",
            total_students=total_students,
            pending_student_count=pending_student_count,
            rejected_student_count=rejected_student_count,
            total_faculty=total_faculty,
            pending_faculty_count=pending_faculty_count,
            total_complaints=total_complaints,
            pending_complaints=pending_complaints,
            in_progress_complaints=in_progress_complaints,
            resolved_complaints=resolved_complaints,
            recent_complaints=recent_complaints,
            pending_students=pending_students,
            department_students=department_students,
            faculty_members=faculty_members,
            total_votes=total_votes,
            resolution_rate=resolution_rate,
            monthly_reports=monthly_reports
        )

    except Exception:
        app.logger.exception("HOD dashboard error")
        return "HOD Dashboard Error. Check PyCharm Terminal.", 500

    finally:
        conn.close()


# ==========================================
# HOD - COMPLAINT INBOX
# ==========================================

@app.route("/hod/complaints")
@login_required("hod", permission="view_complaints")
def hod_complaints():
    conn = get_db()

    try:
        hod_id = session["user_id"]

        department = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE hod_id = ?
        """, (hod_id,)).fetchone()

        if not department:
            return "Department not assigned to this HOD.", 403

        complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.description,
                c.status,
                c.created_at,
                u.name AS student_name,
                u.admission_no,
                u.course
            FROM complaints c
            JOIN users u
                ON c.student_id = u.id
            WHERE c.department_id = ?
            ORDER BY c.created_at DESC
        """, (department["id"],)).fetchall()

        return render_template(
            "hod_complaints.html",
            complaints=complaints,
            department_name=department["department_name"]
        )

    finally:
        conn.close()


# ==========================================
# HOD - VIEW, REPLY AND UPDATE COMPLAINT
# ==========================================

@app.route(
    "/hod/complaint/<int:complaint_id>",
    methods=["GET", "POST"]
)
@login_required("hod", permission="reply_complaints")
def hod_complaint_detail(complaint_id):

    conn = get_db()

    try:
        hod_id = session["user_id"]

        # Get HOD department
        department = conn.execute("""
            SELECT id
            FROM departments
            WHERE hod_id = ?
        """, (hod_id,)).fetchone()

        if not department:
            return "Department not assigned to this HOD.", 403

        # Get complaint
        complaint = conn.execute("""
            SELECT
                c.*,
                u.name AS student_name,
                u.email AS student_email,
                u.admission_no,
                u.course,
                u.section
            FROM complaints c
            JOIN users u ON c.student_id = u.id
            WHERE c.id = ?
              AND c.department_id = ?
        """, (complaint_id, department["id"])).fetchone()

        if not complaint:
            return "Complaint not found or unauthorized.", 404

        # ==========================================
        # POST - REPLY AND STATUS UPDATE
        # ==========================================

        if request.method == "POST":

            reply = request.form.get("reply", "").strip()
            status = request.form.get("status", "").strip()

            allowed_statuses = {
                "Pending",
                "In Progress",
                "Resolved"
            }

            if status not in allowed_statuses:
                flash("Invalid complaint status.", "error")
                return redirect(url_for(
                    "hod_complaint_detail",
                    complaint_id=complaint_id
                ))

            if not reply and status == complaint["status"]:
                flash(
                    "Please write a reply or change the status.",
                    "error"
                )
                return redirect(url_for(
                    "hod_complaint_detail",
                    complaint_id=complaint_id
                ))

            # Save HOD reply
            if reply:
                conn.execute("""
                    INSERT INTO complaint_replies (
                        complaint_id,
                        faculty_id,
                        reply
                    )
                    VALUES (?, ?, ?)
                """, (complaint_id, hod_id, reply))

            # Update complaint status
            conn.execute("""
                UPDATE complaints
                SET status = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND department_id = ?
            """, (
                status,
                complaint_id,
                department["id"]
            ))

            # Create student notification
            if reply or status != complaint["status"]:

                if reply:
                    notification_title = "New HOD Reply"
                    notification_message = (
                        f"HOD replied to your complaint: "
                        f"{complaint['title']}"
                    )
                    notification_type = "reply"

                else:
                    notification_title = "Complaint Status Updated"
                    notification_message = (
                        f"Your complaint status is now {status}."
                    )
                    notification_type = (
                        "resolved" if status == "Resolved" else "status"
                    )

                create_notification(
                    conn,
                    complaint["student_id"],
                    complaint_id,
                    notification_title,
                    notification_message,
                    notification_type
                )

            conn.commit()

            flash(
                "Complaint updated successfully!",
                "success"
            )

            return redirect(url_for(
                "hod_complaint_detail",
                complaint_id=complaint_id
            ))

        # ==========================================
        # GET - COMPLAINT REPLIES
        # ==========================================

        replies = conn.execute("""
            SELECT
                cr.reply,
                cr.created_at,
                u.name AS responder_name
            FROM complaint_replies cr
            JOIN users u ON cr.faculty_id = u.id
            WHERE cr.complaint_id = ?
            ORDER BY cr.created_at DESC
        """, (complaint_id,)).fetchall()

        # ==========================================
        # COMPLAINT FORWARDING HISTORY
        # ==========================================

        forward_history = conn.execute("""
            SELECT
                cf.id AS forward_id,
                cf.message AS hod_message,
                cf.created_at AS forwarded_at,
                hod.name AS hod_name,
                cfr.reply AS admin_reply,
                cfr.created_at AS admin_reply_at,
                admin.name AS admin_name
            FROM complaint_forwards cf
            JOIN users hod
                ON hod.id = cf.hod_id
            LEFT JOIN complaint_forward_replies cfr
                ON cfr.forward_id = cf.id
            LEFT JOIN users admin
                ON admin.id = cfr.admin_id
            WHERE cf.complaint_id = ?
            ORDER BY cf.created_at DESC,
                     cfr.created_at DESC
        """, (complaint_id,)).fetchall()

        # ==========================================
        # RENDER COMPLAINT DETAIL PAGE
        # ==========================================

        return render_template(
            "hod_complaint_detail.html",
            complaint=complaint,
            replies=replies,
            forward_history=forward_history
        )

    except Exception:
        conn.rollback()
        app.logger.exception(
            "HOD complaint management error"
        )
        return (
            "Complaint management error. Check terminal.",
            500
        )

    finally:
        conn.close()

# ==========================================
# SUPER ADMIN REPLY TABLE
# ==========================================

def init_complaint_forward_replies():
    conn = get_db()

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS complaint_forward_replies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                forward_id INTEGER NOT NULL,
                admin_id INTEGER NOT NULL,
                reply TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (forward_id)
                    REFERENCES complaint_forwards(id),

                FOREIGN KEY (admin_id)
                    REFERENCES users(id)
            )
        """)

        conn.commit()

    except Exception:
        conn.rollback()
        app.logger.exception(
            "Complaint forward replies table creation failed"
        )
        raise

    finally:
        conn.close()


init_complaint_forward_replies()


# ==========================================
# HOD - FORWARD COMPLAINT TO SUPER ADMIN
# ==========================================

@app.route(
    "/hod/complaint/<int:complaint_id>/forward",
    methods=["POST"]
)
@login_required("hod", permission="forward_complaints")
def hod_forward_complaint(complaint_id):
    message = request.form.get("message", "").strip()

    if not message:
        flash(
            "Please enter a reason before forwarding.",
            "error"
        )
        return redirect(url_for(
            "hod_complaint_detail",
            complaint_id=complaint_id
        ))

    conn = get_db()

    try:
        hod_id = session["user_id"]

        department = conn.execute("""
            SELECT id
            FROM departments
            WHERE hod_id = ?
        """, (hod_id,)).fetchone()

        if not department:
            flash("Department not assigned to this HOD.", "error")
            return redirect(url_for("hod_dashboard"))

        complaint = conn.execute("""
            SELECT id, title
            FROM complaints
            WHERE id = ?
              AND department_id = ?
        """, (
            complaint_id,
            department["id"]
        )).fetchone()

        if not complaint:
            flash(
                "Complaint not found or unauthorized.",
                "error"
            )
            return redirect(url_for("hod_complaints"))

        conn.execute("""
            INSERT INTO complaint_forwards (
                complaint_id,
                hod_id,
                message
            )
            VALUES (?, ?, ?)
        """, (
            complaint_id,
            hod_id,
            message
        ))

        conn.commit()

        flash(
            "Complaint successfully forwarded to Super Admin.",
            "success"
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Complaint forwarding failed")
        flash(
            "Could not forward complaint. Please try again.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for(
        "hod_complaint_detail",
        complaint_id=complaint_id
    ))


# ==========================================
# SUPER ADMIN REPLY TO FORWARDED COMPLAINT
# ==========================================

@app.route(
    "/admin/forward/<int:forward_id>/reply",
    methods=["POST"]
)
@login_required("super_admin")
def admin_reply_forwarded_complaint(forward_id):
    reply = request.form.get("reply", "").strip()

    if not reply:
        flash("Please enter a reply.", "error")
        return redirect(url_for("admin_inbox"))

    if len(reply) > 3000:
        flash("Reply cannot exceed 3000 characters.", "error")
        return redirect(url_for("admin_inbox"))

    conn = get_db()

    try:
        # Check whether forwarding record exists
        forwarded = conn.execute("""
            SELECT id, complaint_id
            FROM complaint_forwards
            WHERE id = ?
        """, (forward_id,)).fetchone()

        if not forwarded:
            flash("Forwarded complaint not found.", "error")
            return redirect(url_for("admin_inbox"))

        admin_id = session["user_id"]

        # Save Super Admin reply
        conn.execute("""
            INSERT INTO complaint_forward_replies (
                forward_id,
                admin_id,
                reply
            )
            VALUES (?, ?, ?)
        """, (
            forward_id,
            admin_id,
            reply
        ))

        conn.commit()

        flash(
            "Reply successfully sent to HOD.",
            "success"
        )

    except Exception:
        conn.rollback()
        app.logger.exception(
            "Super Admin complaint reply failed"
        )

        flash(
            "Could not send reply. Please try again.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for("admin_inbox"))


# ==========================================
# SUPER ADMIN - ADD DEPARTMENT
# ==========================================

@app.route("/admin/department/add", methods=["POST"])
@login_required("super_admin")
def admin_add_department():
    department_name = request.form.get(
        "department_name", ""
    ).strip()

    if not department_name:
        flash("Department name is required.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    try:
        existing = conn.execute("""
            SELECT id
            FROM departments
            WHERE LOWER(department_name) = LOWER(?)
        """, (department_name,)).fetchone()

        if existing:
            flash("This department already exists.", "error")

        else:
            conn.execute("""
                INSERT INTO departments (department_name, hod_id)
                VALUES (?, NULL)
            """, (department_name,))

            conn.commit()
            flash("Department added successfully.", "success")

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Add department error")
        flash("Unable to add department.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - EDIT DEPARTMENT
# ==========================================

@app.route(
    "/admin/department/<int:department_id>/edit",
    methods=["POST"]
)
@login_required("super_admin")
def admin_edit_department(department_id):
    new_name = request.form.get(
        "department_name", ""
    ).strip()

    if not new_name:
        flash("Department name cannot be empty.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    try:
        department = conn.execute("""
            SELECT department_name
            FROM departments
            WHERE id = ?
        """, (department_id,)).fetchone()

        if not department:
            flash("Department not found.", "error")

        else:
            duplicate = conn.execute("""
                SELECT id
                FROM departments
                WHERE LOWER(department_name) = LOWER(?)
                  AND id != ?
            """, (new_name, department_id)).fetchone()

            if duplicate:
                flash(
                    "Another department already uses this name.",
                    "error"
                )

            else:
                old_name = department["department_name"]

                conn.execute("""
                    UPDATE departments
                    SET department_name = ?
                    WHERE id = ?
                """, (new_name, department_id))

                conn.execute("""
                    UPDATE users
                    SET department = ?
                    WHERE department = ?
                """, (new_name, old_name))

                conn.commit()
                flash("Department updated successfully.", "success")

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Edit department error")
        flash("Unable to update department.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - ASSIGN HOD
# ==========================================

@app.route(
    "/admin/department/<int:department_id>/assign-hod",
    methods=["POST"]
)
@login_required("super_admin")
def admin_assign_hod(department_id):
    hod_id = request.form.get("hod_id", type=int)

    if not hod_id:
        flash("Please select an HOD.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    try:
        department = conn.execute("""
            SELECT id, department_name, hod_id
            FROM departments
            WHERE id = ?
        """, (department_id,)).fetchone()

        hod = conn.execute("""
            SELECT id, name, role, account_status
            FROM users
            WHERE id = ?
        """, (hod_id,)).fetchone()

        if not department:
            flash("Department not found.", "error")

        elif (
                not hod
                or hod["role"] != "hod"
                or hod["account_status"] != "active"
        ):
            flash(
                "Only approved active HODs can be assigned.",
                "error"
            )

        else:
            already_assigned = conn.execute("""
                SELECT department_name
                FROM departments
                WHERE hod_id = ?
                  AND id != ?
            """, (hod_id, department_id)).fetchone()

            if already_assigned:
                flash(
                    "This HOD is already assigned to another department.",
                    "error"
                )

            else:
                old_hod_id = department["hod_id"]

                if old_hod_id and old_hod_id != hod_id:
                    conn.execute("""
                        UPDATE users
                        SET department = NULL
                        WHERE id = ?
                          AND department = ?
                    """, (
                        old_hod_id,
                        department["department_name"]
                    ))

                conn.execute("""
                    UPDATE departments
                    SET hod_id = ?
                    WHERE id = ?
                """, (hod_id, department_id))

                conn.execute("""
                    UPDATE users
                    SET department = ?
                    WHERE id = ?
                """, (
                    department["department_name"],
                    hod_id
                ))

                conn.commit()
                flash("HOD assigned successfully.", "success")

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Assign HOD error")
        flash("Unable to assign HOD.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - DELETE DEPARTMENT
# ==========================================

@app.route(
    "/admin/department/<int:department_id>/delete",
    methods=["POST"]
)
@login_required("super_admin")
def admin_delete_department(department_id):
    conn = get_db()

    try:
        department = conn.execute("""
            SELECT id, department_name, hod_id
            FROM departments
            WHERE id = ?
        """, (department_id,)).fetchone()

        if not department:
            flash("Department not found.", "error")

        else:
            complaint_count = conn.execute("""
                SELECT COUNT(*)
                FROM complaints
                WHERE department_id = ?
            """, (department_id,)).fetchone()[0]

            user_count = conn.execute("""
                SELECT COUNT(*)
                FROM users
                WHERE department = ?
            """, (department["department_name"],)).fetchone()[0]

            if (
                    complaint_count > 0
                    or user_count > 0
                    or department["hod_id"]
            ):
                flash(
                    "Cannot delete: this department has linked users, "
                    "complaints or an assigned HOD.",
                    "error"
                )

            else:
                conn.execute("""
                    DELETE FROM departments
                    WHERE id = ?
                """, (department_id,))

                conn.commit()
                flash("Department deleted successfully.", "success")

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Delete department error")
        flash("Unable to delete department.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - FORWARDED COMPLAINT INBOX
# ==========================================

@app.route("/admin/inbox")
@login_required("super_admin")
def admin_inbox():
    conn = get_db()

    try:
        forwarded_complaints = conn.execute("""
            SELECT
                cf.id AS forward_id,
                cf.message AS hod_message,
                cf.created_at AS forwarded_at,

                c.id AS complaint_id,
                c.title,
                c.category,
                c.description,
                c.status,
                c.created_at AS complaint_created_at,

                student.name AS student_name,
                student.email AS student_email,
                student.admission_no,

                hod.name AS hod_name,
                hod.email AS hod_email,

                d.department_name

            FROM complaint_forwards cf

            JOIN complaints c
                ON c.id = cf.complaint_id

            JOIN users student
                ON student.id = c.student_id

            JOIN users hod
                ON hod.id = cf.hod_id

            LEFT JOIN departments d
                ON d.id = c.department_id

            ORDER BY cf.created_at DESC
        """).fetchall()

        return render_template(
            "admin_inbox.html",
            forwarded_complaints=forwarded_complaints
        )

    except Exception:
        app.logger.exception("Super Admin inbox error")
        return "Admin Inbox Error. Check PyCharm Terminal.", 500

    finally:
        conn.close()


# ==========================================
# SUPER ADMIN - FORWARDED COMPLAINT DETAILS
# ==========================================

@app.route("/admin/forward/<int:forward_id>")
@login_required("super_admin")
def admin_forwarded_complaint_detail(forward_id):
    conn = get_db()

    try:
        complaint = conn.execute("""
            SELECT
                cf.id AS forward_id,
                cf.message AS hod_message,
                cf.created_at AS forwarded_at,

                c.id AS complaint_id,
                c.title,
                c.category,
                c.description,
                c.status,
                c.created_at AS complaint_created_at,

                student.name AS student_name,
                student.email AS student_email,
                student.admission_no,

                hod.name AS hod_name,
                hod.email AS hod_email,

                d.department_name

            FROM complaint_forwards cf

            JOIN complaints c
                ON c.id = cf.complaint_id

            JOIN users student
                ON student.id = c.student_id

            JOIN users hod
                ON hod.id = cf.hod_id

            LEFT JOIN departments d
                ON d.id = c.department_id

            WHERE cf.id = ?
        """, (forward_id,)).fetchone()

        if not complaint:
            flash("Forwarded complaint not found.", "error")
            return redirect(url_for("admin_inbox"))

        replies = conn.execute("""
            SELECT
                cfr.reply,
                cfr.created_at,
                u.name AS admin_name
            FROM complaint_forward_replies cfr
            JOIN users u
                ON u.id = cfr.admin_id
            WHERE cfr.forward_id = ?
            ORDER BY cfr.created_at ASC
        """, (forward_id,)).fetchall()

        return render_template(
            "admin_forwarded_complaint_detail.html",
            complaint=complaint,
            replies=replies
        )

    except Exception:
        app.logger.exception("Admin forwarded complaint detail error")
        return "Super Admin Complaint Detail Error. Check PyCharm Terminal.", 500

    finally:
        conn.close()


# ==========================================
# SUPER ADMIN DASHBOARD
# ==========================================

@app.route("/admin/dashboard")
@login_required("super_admin")
def admin_dashboard():
    conn = get_db()

    try:
        total_students = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE LOWER(TRIM(role)) = 'student'
        """).fetchone()[0]

        total_faculty = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE LOWER(TRIM(role)) = 'faculty'
        """).fetchone()[0]

        total_hods = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE LOWER(TRIM(role)) = 'hod'
              AND LOWER(TRIM(account_status)) = 'active'
        """).fetchone()[0]

        total_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
        """).fetchone()[0]

        pending_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE LOWER(TRIM(status)) = 'pending'
        """).fetchone()[0]

        resolved_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE LOWER(TRIM(status)) = 'resolved'
        """).fetchone()[0]

        in_progress_complaints = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE status = 'In Progress'
        """).fetchone()[0]

        pending_users = conn.execute("""
            SELECT COUNT(*)
            FROM users
            WHERE account_status = 'pending'
        """).fetchone()[0]

        pending_hods = conn.execute("""
            SELECT
                id, name, email, department,
                designation, created_at
            FROM users
            WHERE LOWER(TRIM(role)) = 'hod'
              AND LOWER(TRIM(account_status)) = 'pending'
              
            ORDER BY created_at DESC
        """).fetchall()

        departments = conn.execute("""
            SELECT
                d.id,
                d.department_name,
                d.hod_id,
                u.name AS hod_name
            FROM departments d
            LEFT JOIN users u
                ON d.hod_id = u.id
            ORDER BY d.department_name
        """).fetchall()

        unassigned_departments = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE hod_id IS NULL
            ORDER BY department_name
        """).fetchall()

        active_hods = conn.execute("""
            SELECT id, name, department
            FROM users
            WHERE role = 'hod'
              AND account_status = 'active'
            ORDER BY name
        """).fetchall()

        all_users = conn.execute("""
            SELECT
                id, name, email, mobile,
                role, department, account_status,
                created_at
            FROM users
            ORDER BY created_at DESC
        """).fetchall()

        all_complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.category,
                c.description,
                c.status,
                c.created_at,
                u.name AS student_name,
                u.email AS student_email,
                d.department_name
            FROM complaints c
            LEFT JOIN users u
                ON c.student_id = u.id
            LEFT JOIN departments d
                ON c.department_id = d.id
            ORDER BY c.created_at DESC
        """).fetchall()

        recent_complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.status,
                c.created_at,
                u.name AS student_name
            FROM complaints c
            LEFT JOIN users u
                ON c.student_id = u.id
            ORDER BY c.created_at DESC
            LIMIT 5
        """).fetchall()

        department_stats = conn.execute("""
            SELECT
                d.id,
                d.department_name,
                COUNT(c.id) AS complaint_count
            FROM departments d
            LEFT JOIN complaints c
                ON c.department_id = d.id
            GROUP BY d.id, d.department_name
            ORDER BY complaint_count DESC
        """).fetchall()

        role_stats = conn.execute("""
            SELECT role, COUNT(*) AS total
            FROM users
            GROUP BY role
        """).fetchall()

        monthly_complaints = conn.execute("""
            SELECT
                strftime('%Y-%m', created_at) AS month,
                COUNT(*) AS total
            FROM complaints
            WHERE created_at IS NOT NULL
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY month DESC
            LIMIT 6
        """).fetchall()

        return render_template(
            "super_admin_dashboard.html",

            total_students=total_students,
            total_faculty=total_faculty,
            total_hods=total_hods,
            total_complaints=total_complaints,
            pending_complaints=pending_complaints,
            resolved_complaints=resolved_complaints,
            in_progress_complaints=in_progress_complaints,
            pending_users=pending_users,

            active_hods=active_hods,
            pending_hods=pending_hods,

            departments=unassigned_departments,
            all_departments=departments,

            all_users=all_users,

            all_complaints=all_complaints,
            recent_complaints=recent_complaints,

            department_stats=department_stats,
            role_stats=role_stats,
            monthly_complaints=monthly_complaints
        )

    except Exception:
        app.logger.exception("Super Admin dashboard error")
        return "Super Admin Dashboard Error. Check PyCharm Terminal.", 500

    finally:
        conn.close()


@app.route("/admin/settings")
@login_required("super_admin")
def admin_settings():
    return render_template("admin_settings.html")


@app.route("/admin/login-protection", methods=["GET", "POST"])
@login_required("super_admin")
def admin_login_protection():
    conn = get_db()

    try:
        if request.method == "POST":

            enabled = 1 if request.form.get("enabled") == "1" else 0

            try:
                max_attempts = int(request.form.get("max_attempts", 5))
                lock_duration = int(request.form.get("lock_duration", 15))
            except ValueError:
                flash("Please enter valid numbers.", "error")
                return redirect(url_for("admin_login_protection"))

            if not 1 <= max_attempts <= 20:
                flash("Maximum attempts must be between 1 and 20.", "error")
                return redirect(url_for("admin_login_protection"))

            if not 1 <= lock_duration <= 1440:
                flash("Lock duration must be between 1 and 1440 minutes.", "error")
                return redirect(url_for("admin_login_protection"))

            conn.execute("""
                UPDATE login_protection
                SET enabled = ?,
                    max_attempts = ?,
                    lock_duration = ?
                WHERE id = 1
            """, (enabled, max_attempts, lock_duration))

            conn.commit()

            flash("Login protection settings saved successfully.", "success")
            return redirect(url_for("admin_login_protection"))

        settings = conn.execute("""
            SELECT *
            FROM login_protection
            WHERE id = 1
        """).fetchone()

        return render_template(
            "login_protection.html",
            settings=settings
        )

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Login protection settings error")
        flash("Unable to load login protection settings.", "error")
        return redirect(url_for("admin_settings"))

    finally:
        conn.close()


# ==========================================
# SUPER ADMIN - PROFILE
# ==========================================

@app.route("/admin/profile", methods=["GET", "POST"])
@login_required("super_admin")
def admin_profile():
    conn = get_db()

    try:
        # Required profile columns ko check/create karo
        profile_columns = {
            "mobile": "TEXT",
            "college": "TEXT",
            "address": "TEXT",
            "about_me": "TEXT",
            "profile_photo": "TEXT"
        }

        existing_columns = get_table_columns(conn, "users")

        for column, data_type in profile_columns.items():
            if column not in existing_columns:
                conn.execute(
                    f'ALTER TABLE users ADD COLUMN "{column}" {data_type}'
                )

        conn.commit()

        admin_id = session["user_id"]

        admin = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
              AND role = 'super_admin'
        """, (admin_id,)).fetchone()

        if not admin:
            flash("Super Admin profile not found.", "error")
            return redirect(url_for("admin_dashboard"))

        if request.method == "POST":

            name = request.form.get("name", "").strip()
            mobile = request.form.get("mobile", "").strip()
            college = request.form.get("college", "").strip()
            address = request.form.get("address", "").strip()
            about_me = request.form.get("about_me", "").strip()

            if not name:
                flash("Name is required.", "error")
                return redirect(url_for("admin_profile"))

            if mobile and not mobile.replace("+", "").replace(" ", "").isdigit():
                flash("Enter a valid mobile number.", "error")
                return redirect(url_for("admin_profile"))

            if len(mobile.replace(" ", "")) > 15:
                flash("Mobile number is too long.", "error")
                return redirect(url_for("admin_profile"))

            # Existing profile photo
            profile_photo = admin["profile_photo"]

            photo = request.files.get("profile_photo")

            if photo and photo.filename:

                allowed_extensions = {"jpg", "jpeg", "png", "webp"}
                filename = secure_filename(photo.filename)

                if "." not in filename:
                    flash("Invalid image file.", "error")
                    return redirect(url_for("admin_profile"))

                extension = filename.rsplit(".", 1)[-1].lower()

                if extension not in allowed_extensions:
                    flash(
                        "Only JPG, JPEG, PNG and WEBP images are allowed.",
                        "error"
                    )
                    return redirect(url_for("admin_profile"))

                upload_folder = os.path.join(
                    app.root_path,
                    "static",
                    "uploads",
                    "profile_photos"
                )

                os.makedirs(upload_folder, exist_ok=True)

                new_filename = f"{uuid.uuid4().hex}.{extension}"

                photo.save(
                    os.path.join(upload_folder, new_filename)
                )

                profile_photo = new_filename

            conn.execute("""
                UPDATE users
                SET name = ?,
                    mobile = ?,
                    college = ?,
                    address = ?,
                    about_me = ?,
                    profile_photo = ?
                WHERE id = ?
                  AND role = 'super_admin'
            """, (
                name,
                mobile,
                college,
                address,
                about_me,
                profile_photo,
                admin_id
            ))

            conn.commit()

            # Session name update
            session["name"] = name

            flash("Profile updated successfully.", "success")
            return redirect(url_for("admin_profile"))

        # Latest profile details
        admin = conn.execute("""
            SELECT *
            FROM users
            WHERE id = ?
              AND role = 'super_admin'
        """, (admin_id,)).fetchone()

        return render_template(
            "super_admin_profile.html",
            admin=admin
        )

    except Exception:
        conn.rollback()
        app.logger.exception("Super Admin profile error")
        flash("Could not load or update profile.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()


# ==========================================
# SUPER ADMIN - USER MANAGEMENT
# ==========================================

@app.route(
    "/admin/user/<int:user_id>/status",
    methods=["POST"]
)
@login_required("super_admin")
def admin_update_user_status(user_id):
    new_status = request.form.get(
        "status", ""
    ).strip().lower()

    if new_status not in ["active", "suspended"]:
        flash("Invalid account status.", "error")
        return redirect(url_for("admin_dashboard"))

    if user_id == session.get("user_id"):
        flash(
            "You cannot change your own account status.",
            "error"
        )
        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    try:
        user = conn.execute("""
            SELECT id, role, account_status
            FROM users
            WHERE id = ?
        """, (user_id,)).fetchone()

        if not user:
            flash("User not found.", "error")

        elif user["role"] == "super_admin":
            flash(
                "Super Admin accounts cannot be modified here.",
                "error"
            )

        else:
            conn.execute("""
                UPDATE users
                SET account_status = ?
                WHERE id = ?
            """, (new_status, user_id))

            conn.commit()

            flash(
                f"User account {new_status} successfully.",
                "success"
            )

    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("User status update error")
        flash("Unable to update user account.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - APPROVE HOD
# ==========================================

@app.route("/admin/approve-hod/<int:user_id>", methods=["POST"])
@login_required("super_admin")
def approve_hod(user_id):

    department_id = request.form.get("department_id", "").strip()

    if not department_id.isdigit():
        flash("Please select a valid department.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()

    try:
        hod = conn.execute("""
            SELECT id, department
            FROM users
            WHERE id = ?
              AND LOWER(TRIM(role)) = 'hod'
              AND LOWER(TRIM(account_status)) = 'pending'
        """, (user_id,)).fetchone()

        if not hod:
            flash("Pending HOD request not found.", "error")
            return redirect(url_for("admin_dashboard"))

        department = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE id = ?
              AND hod_id IS NULL
        """, (department_id,)).fetchone()

        if not department:
            flash("This department is unavailable.", "error")
            return redirect(url_for("admin_dashboard"))

        if (hod["department"] or "").strip().lower() != department["department_name"].strip().lower():
            flash("Selected department does not match HOD request.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor = conn.execute("""
            UPDATE departments
            SET hod_id = ?
            WHERE id = ?
              AND hod_id IS NULL
        """, (user_id, department_id))

        if cursor.rowcount != 1:
            conn.rollback()
            flash("Department has already been assigned.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor = conn.execute("""
            UPDATE users
            SET account_status = 'active',
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND LOWER(TRIM(role)) = 'hod'
              AND LOWER(TRIM(account_status)) = 'pending'
        """, (session["user_id"], user_id))

        if cursor.rowcount != 1:
            conn.rollback()
            flash("HOD approval failed.", "error")
            return redirect(url_for("admin_dashboard"))

        conn.commit()
        flash("HOD approved successfully!", "success")

    except Exception:
        conn.rollback()
        app.logger.exception("HOD approval failed")
        flash("Could not approve HOD.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# SUPER ADMIN - REJECT HOD
# ==========================================

@app.route(
    "/admin/reject-hod/<int:user_id>",
    methods=["POST"]
)
@login_required("super_admin")
def reject_hod(user_id):
    conn = get_db()

    try:
        cursor = conn.execute("""
            UPDATE users
            SET account_status = 'rejected'
            WHERE id = ?
              AND role = 'hod'
              AND account_status = 'pending'
        """, (user_id,))

        if cursor.rowcount == 1:
            conn.commit()
            flash("HOD registration rejected.", "success")
        else:
            conn.rollback()
            flash("Pending HOD request not found.", "error")

    except Exception:
        conn.rollback()
        app.logger.exception("HOD rejection failed")
        flash("Could not reject HOD request.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


# ==========================================
# HOD - APPROVE STUDENT
# ==========================================

@app.route(
    "/hod/approve-student/<int:user_id>",
    methods=["POST"]
)
@login_required("hod")
def approve_student(user_id):
    conn = get_db()

    try:
        hod_id = session["user_id"]

        hod = conn.execute("""
            SELECT department
            FROM users
            WHERE id = ?
              AND role = 'hod'
              AND account_status = 'active'
        """, (hod_id,)).fetchone()

        if not hod or not hod["department"]:
            flash("HOD department not found.", "error")
            return redirect(url_for("hod_dashboard"))

        department = hod["department"]

        department_record = conn.execute("""
            SELECT id
            FROM departments
            WHERE department_name = ?
              AND hod_id = ?
        """, (department, hod_id)).fetchone()

        if not department_record:
            flash(
                "You are not authorized to manage this department.",
                "error"
            )
            return redirect(url_for("hod_dashboard"))

        cursor = conn.execute("""
            UPDATE users
            SET account_status = 'active',
                college_id_verified = 1,
                approved_by = ?,
                approved_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND role = 'student'
              AND department = ?
              AND account_status = 'pending'
        """, (hod_id, user_id, department))

        if cursor.rowcount == 1:
            conn.commit()
            flash("Student approved successfully!", "success")
        else:
            conn.rollback()
            flash(
                "Student not found or approval is not allowed.",
                "error"
            )

    except Exception:
        conn.rollback()
        app.logger.exception("Student approval failed")
        flash(
            "Something went wrong while approving student.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard"))


# ==========================================
# HOD - REJECT STUDENT
# ==========================================

@app.route(
    "/hod/reject-student/<int:user_id>",
    methods=["POST"]
)
@login_required("hod")
def reject_student(user_id):
    conn = get_db()

    try:
        hod_id = session["user_id"]

        hod = conn.execute("""
            SELECT department
            FROM users
            WHERE id = ?
              AND role = 'hod'
              AND account_status = 'active'
        """, (hod_id,)).fetchone()

        if not hod or not hod["department"]:
            flash("HOD department not found.", "error")
            return redirect(url_for("hod_dashboard"))

        department = hod["department"]

        department_record = conn.execute("""
            SELECT id
            FROM departments
            WHERE department_name = ?
              AND hod_id = ?
        """, (department, hod_id)).fetchone()

        if not department_record:
            flash(
                "You are not authorized to manage this department.",
                "error"
            )
            return redirect(url_for("hod_dashboard"))

        cursor = conn.execute("""
            UPDATE users
            SET account_status = 'rejected'
            WHERE id = ?
              AND role = 'student'
              AND department = ?
              AND account_status = 'pending'
        """, (user_id, department))

        if cursor.rowcount == 1:
            conn.commit()
            flash("Student registration rejected.", "success")
        else:
            conn.rollback()
            flash(
                "Student not found or rejection is not allowed.",
                "error"
            )

    except Exception:
        conn.rollback()
        app.logger.exception("Student rejection failed")
        flash(
            "Something went wrong while rejecting student.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard"))


# ==========================================
# HOD - VIEW STUDENT DETAILS
# ==========================================

@app.route("/hod/student/<int:user_id>")
@login_required("hod")
def hod_student_detail(user_id):
    conn = get_db()

    try:
        hod_id = session["user_id"]

        student = conn.execute("""
            SELECT
                u.id, u.name, u.email, u.mobile,
                u.admission_no, u.course, u.department,
                u.section, u.semester, u.address,
                u.about_me, u.profile_photo,
                u.account_status, u.created_at,
                u.profile_completed
            FROM users u
            JOIN departments d
                ON d.department_name = u.department
            WHERE u.id = ?
              AND u.role = 'student'
              AND d.hod_id = ?
        """, (user_id, hod_id)).fetchone()

        if not student:
            flash("Student not found in your department.", "error")
            return redirect(url_for("hod_dashboard"))

        complaint_stats = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'Pending' THEN 1 ELSE 0 END)
                    AS pending,
                SUM(CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END)
                    AS resolved
            FROM complaints
            WHERE student_id = ?
        """, (user_id,)).fetchone()

        complaints = conn.execute("""
            SELECT id, title, category, status, created_at
            FROM complaints
            WHERE student_id = ?
            ORDER BY created_at DESC
            LIMIT 10
        """, (user_id,)).fetchall()

        return render_template(
            "hod_student_detail.html",
            student=student,
            complaint_stats=complaint_stats,
            complaints=complaints
        )

    finally:
        conn.close()


# ==========================================
# HOD - ACTIVATE / DEACTIVATE STUDENT
# ==========================================

@app.route(
    "/hod/student/<int:user_id>/status",
    methods=["POST"]
)
@login_required("hod")
def hod_student_status(user_id):
    new_status = request.form.get(
        "account_status", ""
    ).strip()

    if new_status not in ("active", "inactive"):
        flash("Invalid student account status.", "error")
        return redirect(url_for("hod_dashboard"))

    conn = get_db()

    try:
        hod_id = session["user_id"]

        cursor = conn.execute("""
            UPDATE users
            SET account_status = ?
            WHERE id = ?
              AND role = 'student'
              AND department = (
                  SELECT department_name
                  FROM departments
                  WHERE hod_id = ?
              )
              AND account_status IN ('active', 'inactive')
        """, (new_status, user_id, hod_id))

        if cursor.rowcount != 1:
            conn.rollback()
            flash("Student not found or action not allowed.", "error")
        else:
            conn.commit()
            flash(
                "Student account status updated successfully.",
                "success"
            )

    except Exception:
        conn.rollback()
        app.logger.exception("Student status update failed")
        flash("Could not update student status.", "error")

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard"))


# ==========================================
# HOD - ADD FACULTY
# ==========================================

@app.route("/hod/faculty/add", methods=["POST"])
@login_required("hod")
def hod_add_faculty():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    mobile = request.form.get("mobile", "").strip()
    designation = request.form.get("designation", "").strip()
    password = request.form.get("password", "")

    if not all([name, email, designation, password]):
        flash("Please fill all required faculty fields.", "error")
        return redirect(url_for("hod_dashboard") + "#faculty")

    if len(password) < 8:
        flash(
            "Password must contain at least 8 characters.",
            "error"
        )
        return redirect(url_for("hod_dashboard") + "#faculty")

    if "@" not in email or "." not in email.split("@")[-1]:
        flash("Enter a valid email address.", "error")
        return redirect(url_for("hod_dashboard") + "#faculty")

    conn = get_db()

    try:
        hod_id = session["user_id"]

        department = conn.execute("""
            SELECT department_name
            FROM departments
            WHERE hod_id = ?
        """, (hod_id,)).fetchone()

        if not department:
            flash("Department not assigned.", "error")
            return redirect(url_for("hod_dashboard"))

        existing = conn.execute("""
            SELECT id
            FROM users
            WHERE LOWER(email) = ?
        """, (email,)).fetchone()

        if existing:
            flash("This email is already registered.", "error")
            return redirect(url_for("hod_dashboard") + "#faculty")

        conn.execute("""
            INSERT INTO users (
                name, email, password, role,
                mobile, college, department,
                designation, account_status,
                email_verified, mobile_verified
            )
            VALUES (?, ?, ?, 'faculty', ?, ?, ?, ?, 'active', 1, 0)
        """, (
            name,
            email,
            generate_password_hash(password),
            mobile or None,
            "CampusCare College",
            department["department_name"],
            designation
        ))

        conn.commit()
        flash("Faculty added successfully!", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash("Faculty email or mobile already exists.", "error")

    except Exception:
        conn.rollback()
        app.logger.exception("Add faculty error")
        flash("Could not add faculty.", "error")

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard") + "#faculty")


# ==========================================
# HOD - EDIT FACULTY
# ==========================================

@app.route(
    "/hod/faculty/<int:user_id>/edit",
    methods=["POST"]
)
@login_required("hod")
def hod_edit_faculty(user_id):
    name = request.form.get("name", "").strip()
    mobile = request.form.get("mobile", "").strip()
    designation = request.form.get("designation", "").strip()

    if not name or not designation:
        flash("Name and designation are required.", "error")
        return redirect(url_for("hod_dashboard") + "#faculty")

    conn = get_db()

    try:
        hod_id = session["user_id"]

        cursor = conn.execute("""
            UPDATE users
            SET name = ?,
                mobile = ?,
                designation = ?
            WHERE id = ?
              AND role = 'faculty'
              AND department = (
                  SELECT department_name
                  FROM departments
                  WHERE hod_id = ?
              )
        """, (
            name,
            mobile or None,
            designation,
            user_id,
            hod_id
        ))

        if cursor.rowcount == 1:
            conn.commit()
            flash("Faculty details updated.", "success")
        else:
            conn.rollback()
            flash("Faculty not found in your department.", "error")

    except Exception:
        conn.rollback()
        app.logger.exception("Faculty edit error")
        flash("Could not update faculty details.", "error")

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard") + "#faculty")


# ==========================================
# HOD - ACTIVATE / DEACTIVATE FACULTY
# ==========================================

@app.route(
    "/hod/faculty/<int:user_id>/status",
    methods=["POST"]
)
@login_required("hod")
def hod_faculty_status(user_id):
    new_status = request.form.get(
        "account_status", ""
    ).strip()

    if new_status not in ("active", "inactive"):
        flash("Invalid faculty status.", "error")
        return redirect(url_for("hod_dashboard") + "#faculty")

    conn = get_db()

    try:
        hod_id = session["user_id"]

        cursor = conn.execute("""
            UPDATE users
            SET account_status = ?
            WHERE id = ?
              AND role = 'faculty'
              AND department = (
                  SELECT department_name
                  FROM departments
                  WHERE hod_id = ?
              )
              AND account_status IN ('active', 'inactive')
        """, (new_status, user_id, hod_id))

        if cursor.rowcount == 1:
            conn.commit()
            flash("Faculty status updated.", "success")
        else:
            conn.rollback()
            flash("Faculty not found or action not allowed.", "error")

    except Exception:
        conn.rollback()
        app.logger.exception("Faculty status update error")
        flash("Could not update faculty status.", "error")

    finally:
        conn.close()

    return redirect(url_for("hod_dashboard") + "#faculty")


# ==========================================
# HOD - REPORTS & ANALYTICS
# ==========================================

@app.route("/hod/reports")
@login_required("hod")
def hod_reports():
    conn = get_db()

    try:
        hod_id = session["user_id"]

        department = conn.execute("""
            SELECT id, department_name
            FROM departments
            WHERE hod_id = ?
        """, (hod_id,)).fetchone()

        if not department:
            flash("Department not assigned.", "error")
            return redirect(url_for("hod_dashboard"))

        department_id = department["id"]

        status_report = conn.execute("""
            SELECT
                status,
                COUNT(*) AS total
            FROM complaints
            WHERE department_id = ?
            GROUP BY status
        """, (department_id,)).fetchall()

        monthly_reports = conn.execute("""
            SELECT
                strftime('%Y-%m', created_at) AS month,
                COUNT(*) AS total,
                SUM(
                    CASE WHEN status = 'Resolved' THEN 1 ELSE 0 END
                ) AS resolved
            FROM complaints
            WHERE department_id = ?
              AND created_at >= date('now', '-12 months')
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY month
        """, (department_id,)).fetchall()

        top_complaints = conn.execute("""
            SELECT
                c.id,
                c.title,
                c.status,
                u.name AS student_name,
                COUNT(cl.id) AS votes
            FROM complaints c
            LEFT JOIN users u
                ON u.id = c.student_id
            LEFT JOIN complaint_likes cl
                ON cl.complaint_id = c.id
            WHERE c.department_id = ?
            GROUP BY c.id
            ORDER BY votes DESC, c.created_at DESC
            LIMIT 10
        """, (department_id,)).fetchall()

        total = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
        """, (department_id,)).fetchone()[0]

        resolved = conn.execute("""
            SELECT COUNT(*)
            FROM complaints
            WHERE department_id = ?
              AND status = 'Resolved'
        """, (department_id,)).fetchone()[0]

        resolution_rate = round(
            resolved * 100 / total, 1
        ) if total else 0

        return render_template(
            "hod_reports.html",
            department_name=department["department_name"],
            status_report=status_report,
            monthly_reports=monthly_reports,
            top_complaints=top_complaints,
            total_complaints=total,
            resolved_complaints=resolved,
            resolution_rate=resolution_rate
        )

    finally:
        conn.close()


# ==========================================
# LOGOUT
# ==========================================
@app.route("/logout")
@login_required()
def logout():
    current_role = session.get("role")

    session.clear()

    flash("You have been logged out successfully.", "success")

    if current_role == "super_admin":
        return redirect(url_for("admin_login"))

    elif current_role in ["student", "faculty", "hod"]:
        return redirect(url_for("login"))

    return redirect(url_for("admin_login"))


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(debug=True)
