
import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash


# ==========================================
# DATABASE CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Always use the database beside this file
DB_NAME = os.path.join(BASE_DIR, "campuscare.db")

# Automatic backup folder
BACKUP_DIR = os.path.join(BASE_DIR, "database_backups")

os.makedirs(BACKUP_DIR, exist_ok=True)


# ==========================================
# DATABASE BACKUP
# ==========================================

def backup_database():

    if not os.path.exists(DB_NAME):
        print("No existing database found. First database will be created.")
        return

    if os.path.getsize(DB_NAME) == 0:
        print("Database file is empty. Backup skipped.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    backup_path = os.path.join(
        BACKUP_DIR,
        f"campuscare_backup_{timestamp}.db"
    )

    source = None
    destination = None

    try:
        source = sqlite3.connect(DB_NAME, timeout=30)
        destination = sqlite3.connect(backup_path, timeout=30)

        # Safe SQLite backup, including committed WAL data
        source.backup(destination)

        print("Database backup created:", backup_path)

    except Exception:
        print("DATABASE BACKUP FAILED!")
        raise

    finally:
        if source:
            source.close()

        if destination:
            destination.close()


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db():

    print("ACTIVE DATABASE:", DB_NAME)

    conn = sqlite3.connect(
        DB_NAME,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    return conn


# ==========================================
# ADD COLUMN IF NOT EXISTS
# ==========================================

def add_column_if_missing(
    cursor,
    table_name,
    column_name,
    column_definition
):

    columns = [
        row[1]
        for row in cursor.execute(
            f"PRAGMA table_info({table_name})"
        ).fetchall()
    ]

    if column_name not in columns:

        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN "
            f"{column_name} {column_definition}"
        )

        print(f"Added column: {table_name}.{column_name}")


# ==========================================
# USERS TABLE MIGRATION
# ==========================================

def migrate_users_table():

    conn = sqlite3.connect(
        DB_NAME,
        timeout=30
    )

    # Must be set before starting the migration transaction
    conn.execute("PRAGMA foreign_keys = OFF")

    try:

        cursor = conn.cursor()

        table = cursor.execute("""
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'users'
        """).fetchone()

        if not table:
            return

        old_sql = table[0] or ""

        existing_info = cursor.execute(
            "PRAGMA table_info(users)"
        ).fetchall()

        existing = {
            row[1] for row in existing_info
        }

        mobile_not_null = False

        for row in existing_info:

            if row[1] == "mobile":
                mobile_not_null = bool(row[3])
                break

        role_migration_needed = (
            "'super_admin'" not in old_sql
            or "'admin'" in old_sql
        )

        if not role_migration_needed and not mobile_not_null:
            print("Users table migration not required.")
            return

        print("Migrating users table...")

        cursor.execute("BEGIN")

        cursor.execute("""
            CREATE TABLE users_new (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT NOT NULL,
                mobile TEXT UNIQUE,
                password TEXT NOT NULL,

                role TEXT NOT NULL CHECK(
                    role IN (
                        'student',
                        'faculty',
                        'hod',
                        'super_admin'
                    )
                ),

                admission_no TEXT UNIQUE,
                college TEXT,
                course TEXT,
                department TEXT,
                section TEXT,
                designation TEXT,

                account_status TEXT NOT NULL DEFAULT 'active',
                mobile_verified INTEGER NOT NULL DEFAULT 0,

                approved_by INTEGER,
                approved_at TIMESTAMP,

                email TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                college_id_verified INTEGER NOT NULL DEFAULT 0,

                profile_photo TEXT,
                semester TEXT,
                address TEXT,
                about_me TEXT,
                profile_completed INTEGER NOT NULL DEFAULT 0,

                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMP,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(approved_by)
                    REFERENCES users_new(id)
            )
        """)

        columns = [
            "id", "name", "mobile", "password", "role",
            "admission_no", "college", "course", "department",
            "section", "designation", "account_status",
            "mobile_verified", "approved_by", "approved_at",
            "email", "email_verified", "college_id_verified",
            "profile_photo", "semester", "address", "about_me",
            "profile_completed", "failed_attempts",
            "locked_until", "created_at"
        ]

        defaults = {

            "designation": "NULL",
            "account_status": "'active'",
            "mobile_verified": "0",

            "approved_by": "NULL",
            "approved_at": "NULL",

            "email": "NULL",
            "email_verified": "0",
            "college_id_verified": "0",

            "profile_photo": "NULL",
            "semester": "NULL",
            "address": "NULL",
            "about_me": "NULL",

            "profile_completed": "0",
            "failed_attempts": "0",
            "locked_until": "NULL",

            "created_at": "CURRENT_TIMESTAMP"
        }

        expressions = []

        for column in columns:

            if column == "role" and column in existing:

                expressions.append("""
                    CASE
                        WHEN role = 'admin'
                        THEN 'super_admin'
                        ELSE role
                    END
                """)

            elif column in existing:

                expressions.append(column)

            else:

                expressions.append(
                    defaults.get(column, "NULL")
                )

        cursor.execute(f"""
            INSERT INTO users_new ({', '.join(columns)})
            SELECT {', '.join(expressions)}
            FROM users
        """)

        old_count = cursor.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

        new_count = cursor.execute(
            "SELECT COUNT(*) FROM users_new"
        ).fetchone()[0]

        # Never replace the old table if records were lost
        if old_count != new_count:
            raise RuntimeError(
                "Migration stopped: user record count mismatch."
            )

        cursor.execute("DROP TABLE users")

        cursor.execute("""
            ALTER TABLE users_new
            RENAME TO users
        """)

        conn.commit()

        print("Users table migrated successfully!")
        print("Users preserved:", new_count)

    except Exception:

        conn.rollback()

        print("Users migration failed. Original transaction rolled back.")

        raise

    finally:

        conn.close()


# ==========================================
# MAIN DATABASE INITIALIZATION
# ==========================================

def init_db():

    print("\n===================================")
    print("CAMPUSCARE DATABASE INITIALIZATION")
    print("===================================")

    print("Database location:", DB_NAME)

    # Backup before any schema migration
    backup_database()

    # Existing users table migration
    migrate_users_table()

    conn = get_db()
    cursor = conn.cursor()

    try:

        # ======================================
        # USERS TABLE
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT NOT NULL,
                mobile TEXT UNIQUE,
                password TEXT NOT NULL,

                role TEXT NOT NULL CHECK(
                    role IN (
                        'student',
                        'faculty',
                        'hod',
                        'super_admin'
                    )
                ),

                admission_no TEXT UNIQUE,
                college TEXT,
                course TEXT,
                department TEXT,
                section TEXT,
                designation TEXT,

                account_status TEXT NOT NULL DEFAULT 'active',
                mobile_verified INTEGER NOT NULL DEFAULT 0,

                approved_by INTEGER,
                approved_at TIMESTAMP,

                email TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                college_id_verified INTEGER NOT NULL DEFAULT 0,

                profile_photo TEXT,
                semester TEXT,
                address TEXT,
                about_me TEXT,
                profile_completed INTEGER NOT NULL DEFAULT 0,

                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMP,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(approved_by)
                    REFERENCES users(id)
            )
        """)

        user_columns = [

            ("designation", "TEXT"),

            ("account_status", "TEXT NOT NULL DEFAULT 'active'"),

            ("mobile_verified", "INTEGER NOT NULL DEFAULT 1"),

            ("approved_by", "INTEGER"),
            ("approved_at", "TIMESTAMP"),

            ("email", "TEXT"),
            ("email_verified", "INTEGER NOT NULL DEFAULT 0"),
            ("college_id_verified", "INTEGER NOT NULL DEFAULT 0"),

            ("profile_photo", "TEXT"),
            ("semester", "TEXT"),
            ("address", "TEXT"),
            ("about_me", "TEXT"),

            ("profile_completed", "INTEGER NOT NULL DEFAULT 0"),

            ("failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("locked_until", "TIMESTAMP")
        ]

        for column, definition in user_columns:

            add_column_if_missing(
                cursor,
                "users",
                column,
                definition
            )

        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
            ON users(email)
            WHERE email IS NOT NULL AND email != ''
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_role
            ON users(role)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_department
            ON users(department)
        """)

        # ======================================
        # DEPARTMENTS TABLE
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS departments (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                department_name TEXT UNIQUE NOT NULL,

                hod_id INTEGER,

                FOREIGN KEY(hod_id)
                    REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_departments_hod
            ON departments(hod_id)
        """)

        # ======================================
        # FACULTY MULTIPLE SECTION ASSIGNMENT
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS faculty_sections (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                faculty_id INTEGER NOT NULL,
                section TEXT NOT NULL,

                FOREIGN KEY(faculty_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                UNIQUE(faculty_id, section)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_faculty_sections_faculty
            ON faculty_sections(faculty_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_faculty_sections_section
            ON faculty_sections(section)
        """)

        # ======================================
        # EMAIL VERIFICATION
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_verifications (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,

                expires_at TIMESTAMP NOT NULL,

                used INTEGER NOT NULL DEFAULT 0,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(user_id)
                    REFERENCES users(id)
            )
        """)

        # ======================================
        # COLLEGE ID RECORDS
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS college_id_records (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                admission_no TEXT UNIQUE NOT NULL,
                student_name TEXT NOT NULL,

                department TEXT NOT NULL,
                course TEXT,

                is_active INTEGER NOT NULL DEFAULT 1,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ======================================
        # OTP VERIFICATION
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS otp_verifications (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                mobile TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                role TEXT NOT NULL,

                expires_at TIMESTAMP NOT NULL,

                verified INTEGER DEFAULT 0,
                attempts INTEGER DEFAULT 0,

                resend_after TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        add_column_if_missing(
            cursor,
            "otp_verifications",
            "resend_after",
            "TEXT"
        )

        add_column_if_missing(
            cursor,
            "otp_verifications",
            "attempts",
            "INTEGER DEFAULT 0"
        )

        add_column_if_missing(
            cursor,
            "otp_verifications",
            "created_at",
            "TIMESTAMP"
        )

        # ======================================
        # COMPLAINTS TABLE
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS complaints (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                student_id INTEGER NOT NULL,

                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,

                department_id INTEGER NOT NULL,

                transport_no TEXT,
                image TEXT,

                priority TEXT DEFAULT 'Medium',
                status TEXT DEFAULT 'Pending',

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP,

                FOREIGN KEY(student_id)
                    REFERENCES users(id),

                FOREIGN KEY(department_id)
                    REFERENCES departments(id)
            )
        """)

        add_column_if_missing(
            cursor,
            "complaints",
            "updated_at",
            "TIMESTAMP"
        )

        add_column_if_missing(
            cursor,
            "complaints",
            "priority",
            "TEXT DEFAULT 'Medium'"
        )

        for index_name, column in [

            ("idx_complaints_student", "student_id"),
            ("idx_complaints_department", "department_id"),
            ("idx_complaints_status", "status"),
            ("idx_complaints_created", "created_at"),
            ("idx_complaints_priority", "priority")

        ]:

            cursor.execute(f"""
                CREATE INDEX IF NOT EXISTS {index_name}
                ON complaints({column})
            """)

        # ======================================
        # COMPLAINT REPLIES
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS complaint_replies (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                complaint_id INTEGER NOT NULL,
                faculty_id INTEGER NOT NULL,

                reply TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(complaint_id)
                    REFERENCES complaints(id),

                FOREIGN KEY(faculty_id)
                    REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_replies_complaint
            ON complaint_replies(complaint_id)
        """)

        # ======================================
        # COMPLAINT VOTING / LIKES
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS complaint_likes (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                complaint_id INTEGER NOT NULL,
                student_id INTEGER NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(complaint_id, student_id),

                FOREIGN KEY(complaint_id)
                    REFERENCES complaints(id),

                FOREIGN KEY(student_id)
                    REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_likes_complaint
            ON complaint_likes(complaint_id)
        """)

        # ======================================
        # OLD STUDENT NOTIFICATIONS TABLE
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_notifications (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                student_id INTEGER NOT NULL,

                title TEXT NOT NULL,
                message TEXT NOT NULL,

                type TEXT DEFAULT 'general',

                is_read INTEGER NOT NULL DEFAULT 0,

                complaint_id INTEGER,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(student_id)
                    REFERENCES users(id),

                FOREIGN KEY(complaint_id)
                    REFERENCES complaints(id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notifications_student
            ON student_notifications(student_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_notifications_read
            ON student_notifications(student_id, is_read)
        """)

        # ======================================
        # NOTIFICATIONS TABLE
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER NOT NULL,

                title TEXT NOT NULL,
                message TEXT NOT NULL,

                type TEXT DEFAULT 'general',

                is_read INTEGER NOT NULL DEFAULT 0,

                complaint_id INTEGER,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(user_id)
                    REFERENCES users(id),

                FOREIGN KEY(complaint_id)
                    REFERENCES complaints(id)
            )
        """)

        notification_columns = [

            ("user_id", "INTEGER"),
            ("title", "TEXT"),
            ("message", "TEXT"),
            ("type", "TEXT DEFAULT 'general'"),
            ("is_read", "INTEGER NOT NULL DEFAULT 0"),
            ("complaint_id", "INTEGER"),
            ("created_at", "TIMESTAMP")

        ]

        for column, definition in notification_columns:

            add_column_if_missing(
                cursor,
                "notifications",
                column,
                definition
            )

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_new_notifications_user
            ON notifications(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_new_notifications_read
            ON notifications(user_id, is_read)
        """)

        # ======================================
        # MIGRATE OLD NOTIFICATIONS
        # ======================================

        cursor.execute("""
            INSERT OR IGNORE INTO notifications (

                id,
                user_id,
                title,
                message,
                type,
                is_read,
                complaint_id,
                created_at

            )

            SELECT

                id,
                student_id,
                title,
                message,
                type,
                is_read,
                complaint_id,
                created_at

            FROM student_notifications
        """)

        # ======================================
        # ADMIN / HOD MESSAGES
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,

                message TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(sender_id)
                    REFERENCES users(id),

                FOREIGN KEY(receiver_id)
                    REFERENCES users(id)
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_receiver
            ON messages(receiver_id)
        """)

        # ======================================
        # SECURITY: LOGIN ACTIVITY
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_activity (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                user_id INTEGER,

                email TEXT,
                role TEXT,

                ip_address TEXT,
                user_agent TEXT,

                status TEXT NOT NULL,
                failure_reason TEXT,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(user_id)
                    REFERENCES users(id)
                    ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_activity_user
            ON login_activity(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_activity_created
            ON login_activity(created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_login_activity_status
            ON login_activity(status)
        """)

        # ======================================
        # SECURITY: LOGIN PROTECTION
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_protection (

                id INTEGER PRIMARY KEY CHECK (id = 1),

                enabled INTEGER NOT NULL DEFAULT 1,

                max_attempts INTEGER NOT NULL DEFAULT 5,

                lock_duration INTEGER NOT NULL DEFAULT 15
            )
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO login_protection (

                id,
                enabled,
                max_attempts,
                lock_duration

            )

            VALUES (1, 1, 5, 15)
        """)

        # ======================================
        # SECURITY: ROLE PERMISSIONS
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                role TEXT NOT NULL,
                permission_key TEXT NOT NULL,

                is_allowed INTEGER NOT NULL DEFAULT 0,

                updated_by INTEGER,

                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(role, permission_key),

                FOREIGN KEY(updated_by)
                    REFERENCES users(id)
            )
        """)

        # ======================================
        # SECURITY: PASSWORD SETTINGS
        # ======================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_settings (

                setting_key TEXT PRIMARY KEY,

                setting_value TEXT NOT NULL,

                updated_by INTEGER,

                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY(updated_by)
                    REFERENCES users(id)
            )
        """)

        default_security_settings = [

            ("password_min_length", "8"),
            ("password_require_uppercase", "1"),
            ("password_require_lowercase", "1"),
            ("password_require_number", "1"),
            ("password_require_special", "1")

        ]

        cursor.executemany("""
            INSERT OR IGNORE INTO security_settings (

                setting_key,
                setting_value

            )

            VALUES (?, ?)
        """, default_security_settings)

        # ======================================
        # SUPER ADMIN DEFAULT ACCOUNT
        # ======================================

        SUPER_ADMIN_EMAIL = "imran016062005@gmail.com"
        SUPER_ADMIN_PASSWORD = "Admin@123"

        super_admin = cursor.execute("""
            SELECT id
            FROM users
            WHERE role = 'super_admin'
            LIMIT 1
        """).fetchone()

        if not super_admin:

            email_owner = cursor.execute("""
                SELECT id
                FROM users
                WHERE LOWER(email) = LOWER(?)
            """, (SUPER_ADMIN_EMAIL,)).fetchone()

            if email_owner:

                raise ValueError(
                    "Super Admin email is already used by another account."
                )

            cursor.execute("""
                INSERT INTO users (

                    name,
                    mobile,
                    email,
                    email_verified,
                    password,
                    role,
                    college,
                    account_status,
                    mobile_verified

                )

                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (

                "Super Admin",
                "9999999999",
                SUPER_ADMIN_EMAIL,
                1,
                generate_password_hash(SUPER_ADMIN_PASSWORD),
                "super_admin",
                "CampusCare College",
                "active",
                1

            ))

            print("Default Super Admin created successfully!")

        else:

            email_owner = cursor.execute("""
                SELECT id
                FROM users
                WHERE LOWER(email) = LOWER(?)
                  AND id != ?
            """, (

                SUPER_ADMIN_EMAIL,
                super_admin["id"]

            )).fetchone()

            if email_owner:

                raise ValueError(
                    "Super Admin email is already used by another account."
                )

            cursor.execute("""
                UPDATE users
                SET email = ?,
                    email_verified = 1,
                    account_status = 'active'
                WHERE id = ?
            """, (

                SUPER_ADMIN_EMAIL,
                super_admin["id"]

            ))

            print("Super Admin email updated successfully!")

        # ======================================
        # DEFAULT DEPARTMENTS
        # ======================================

        departments = [

            "BCA-MCA",
            "BBA-MBA",
            "BTECH-MTECH",

            "TRANSPORT",
            "LIBRARY",
            "HOSTEL",
            "CANTEEN",
            "LAB"

        ]

        for department in departments:

            cursor.execute("""
                INSERT OR IGNORE INTO departments (
                    department_name
                )
                VALUES (?)
            """, (department,))

        # ======================================
        # VERIFY DATABASE INTEGRITY
        # ======================================

        integrity = cursor.execute(
            "PRAGMA integrity_check"
        ).fetchone()[0]

        if integrity != "ok":

            raise RuntimeError(
                "Database integrity check failed: " + str(integrity)
            )

        # ======================================
        # COMMIT
        # ======================================

        conn.commit()

        print("\n===================================")
        print("CampusCare Database Updated!")
        print("Database:", DB_NAME)
        print("Users: Student, Faculty, HOD, Super Admin")
        print("Departments: Enabled")
        print("Faculty Multiple Sections: Enabled")
        print("Complaints: Enabled")
        print("Complaint Priority: Enabled")
        print("Voting: Enabled")
        print("Replies: Enabled")
        print("Notifications: Enabled")
        print("Old Notification Data: Migrated")
        print("Student Profile: Enabled")
        print("Login Activity: Enabled")
        print("Login Protection: Enabled")
        print("Role Permissions: Enabled")
        print("Password Security Settings: Enabled")
        print("Database Integrity: OK")
        print("===================================\n")

    except Exception:

        conn.rollback()

        print("DATABASE INITIALIZATION FAILED!")
        raise

    finally:

        conn.close()


# ==========================================
# RUN DATABASE DIRECTLY
# ==========================================

if __name__ == "__main__":

    init_db()
