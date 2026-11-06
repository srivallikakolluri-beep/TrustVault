import os, sqlite3, uuid, hashlib, hmac, secrets, mimetypes
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, g, request, session, redirect, url_for, render_template, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", ROOT / "trustvault.db"))
STORAGE = Path(os.environ.get("TRUSTVAULT_STORAGE", ROOT / "private_uploads"))
ALLOWED = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}
MAX_BYTES = 10 * 1024 * 1024

def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret"),
        MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    )
    if test_config:
        app.config.update(test_config)
    db_path = Path(app.config.get("DB_PATH", DB_PATH))
    storage = Path(app.config.get("STORAGE", STORAGE))
    storage.mkdir(parents=True, exist_ok=True)

    def connect():
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def init_db():
        db_path.parent.mkdir(parents=True, exist_ok=True)
        with connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents(
                id TEXT PRIMARY KEY,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                original_name TEXT NOT NULL,
                category TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants(
                document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
                granted_by INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                PRIMARY KEY(document_id,user_id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER REFERENCES users(id),
                action TEXT NOT NULL,
                document_id TEXT,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """)
            # Demo accounts are created only on an empty database.
            count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                now = utcnow()
                for username, password, role in [
                    ("admin", "Admin@12345", "admin"),
                    ("owner", "Owner@12345", "owner"),
                    ("viewer", "Viewer@12345", "viewer"),
                ]:
                    con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                (username, generate_password_hash(password), role, now))

    def utcnow():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def audit(actor_id, action, document_id=None, details=""):
        with connect() as con:
            last = con.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            previous = last["entry_hash"] if last else "GENESIS"
            created = utcnow()
            payload = f"{previous}|{actor_id}|{action}|{document_id or ''}|{details}|{created}"
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            con.execute("""INSERT INTO audit_logs(actor_id,action,document_id,details,created_at,previous_hash,entry_hash)
                           VALUES(?,?,?,?,?,?,?)""",
                        (actor_id, action, document_id, details[:500], created, previous, digest))

    def verify_audit_chain():
        with connect() as con:
            rows = con.execute("SELECT * FROM audit_logs ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            payload = f"{previous}|{row['actor_id']}|{row['action']}|{row['document_id'] or ''}|{row['details']}|{row['created_at']}"
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous or not hmac.compare_digest(row["entry_hash"], expected):
                return False
            previous = row["entry_hash"]
        return True

    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        with connect() as con:
            return con.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    @app.before_request
    def protect_posts():
        if request.method == "POST":
            sent = request.form.get("_csrf", "")
            expected = session.get("_csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400, "CSRF validation failed")

    @app.context_processor
    def inject_globals():
        return {"csrf_token": csrf_token, "me": current_user()}

    def has_access(user, doc_id, needed="read"):
        if not user:
            return False
        with connect() as con:
            doc = con.execute("SELECT owner_id FROM documents WHERE id=?", (doc_id,)).fetchone()
            if not doc:
                return False
            if doc["owner_id"] == user["id"]:
                return True
            grant = con.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                                (doc_id, user["id"])).fetchone()
            if not grant:
                return False
            return grant["permission"] == "edit" or needed == "read"

    def get_doc(doc_id):
        with connect() as con:
            return con.execute("""SELECT d.*,u.username AS owner_name FROM documents d
                                  JOIN users u ON u.id=d.owner_id WHERE d.id=?""", (doc_id,)).fetchone()

    def valid_file(file_storage):
        name = secure_filename(file_storage.filename or "")
        if not name or "." not in name:
            return False, "Choose a file with a supported extension."
        ext = name.rsplit(".", 1)[1].lower()
        if ext not in ALLOWED:
            return False, "Allowed formats: PDF, TXT, PNG, JPG, JPEG and DOCX."
        data = file_storage.read(MAX_BYTES + 1)
        file_storage.stream.seek(0)
        if not data or len(data) > MAX_BYTES:
            return False, "File is empty or exceeds the 10 MB limit."
        signatures = {
            "pdf": data.startswith(b"%PDF-"),
            "png": data.startswith(b"\x89PNG\r\n\x1a\n"),
            "jpg": data.startswith(b"\xff\xd8\xff"),
            "jpeg": data.startswith(b"\xff\xd8\xff"),
            "docx": data.startswith(b"PK\x03\x04"),
            "txt": True,
        }
        if not signatures[ext]:
            return False, "File content does not match its extension."
        if ext == "txt":
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                return False, "TXT files must be UTF-8 encoded."
        return True, data

    @app.route("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "viewer")
            if len(username) < 3 or len(password) < 10 or role not in {"owner", "viewer"}:
                flash("Use a username of 3+ characters, password of 10+ characters, and owner/viewer role.")
                return render_template("register.html")
            try:
                with connect() as con:
                    con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                (username, generate_password_hash(password), role, utcnow()))
                flash("Account created. Please sign in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            with connect() as con:
                user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                audit(user["id"], "LOGIN", details="Successful login")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        user = current_user()
        audit(user["id"], "LOGOUT", details="User logged out")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        with connect() as con:
            if user["role"] == "admin":
                docs = con.execute("""SELECT d.*,u.username owner_name FROM documents d
                                      JOIN users u ON u.id=d.owner_id ORDER BY d.created_at DESC""").fetchall()
            else:
                docs = con.execute("""SELECT DISTINCT d.*,u.username owner_name FROM documents d
                    JOIN users u ON u.id=d.owner_id LEFT JOIN grants g ON g.document_id=d.id
                    WHERE d.owner_id=? OR g.user_id=? ORDER BY d.created_at DESC""",
                    (user["id"], user["id"])).fetchall()
            users = con.execute("SELECT id,username,role FROM users ORDER BY username").fetchall() if user["role"] == "admin" else []
            logs = con.execute("""SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
                                  ORDER BY a.id DESC LIMIT 30""").fetchall() if user["role"] == "admin" else []
        return render_template("dashboard.html", docs=docs, users=users, logs=logs,
                               chain_ok=verify_audit_chain())

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        user = current_user()
        if user["role"] not in {"owner", "admin"}:
            abort(403)
        f = request.files.get("file")
        ok, result = valid_file(f) if f else (False, "Select a file.")
        if not ok:
            flash(result)
            return redirect(url_for("dashboard"))
        data = result
        original = secure_filename(f.filename)
        category = request.form.get("category", "General").strip()[:60] or "General"
        doc_id = str(uuid.uuid4())
        stored = f"{uuid.uuid4().hex}.bin"
        (storage / stored).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        now = utcnow()
        with connect() as con:
            con.execute("""INSERT INTO documents(id,owner_id,original_name,category,stored_name,sha256,size,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (doc_id, user["id"], original, category, stored, digest, len(data), now, now))
        audit(user["id"], "UPLOAD", doc_id, f"name={original};sha256={digest}")
        flash("Document uploaded securely.")
        return redirect(url_for("dashboard"))

    @app.route("/document/<doc_id>")
    @login_required
    def document_detail(doc_id):
        user = current_user()
        if not has_access(user, doc_id, "read"):
            audit(user["id"], "ACCESS_DENIED", doc_id, "Document detail denied")
            abort(404)
        doc = get_doc(doc_id)
        audit(user["id"], "VIEW", doc_id, "Document metadata viewed")
        with connect() as con:
            grants = con.execute("""SELECT g.*,u.username FROM grants g JOIN users u ON u.id=g.user_id
                                    WHERE g.document_id=?""", (doc_id,)).fetchall() if doc["owner_id"] == user["id"] else []
            users = con.execute("SELECT id,username,role FROM users WHERE id<>? ORDER BY username",
                                 (user["id"],)).fetchall() if doc["owner_id"] == user["id"] else []
        return render_template("document.html", doc=doc, grants=grants, users=users,
                               can_edit=has_access(user, doc_id, "edit"), is_owner=doc["owner_id"] == user["id"])

    @app.route("/document/<doc_id>/download")
    @login_required
    def download(doc_id):
        user = current_user()
        if not has_access(user, doc_id, "read"):
            audit(user["id"], "ACCESS_DENIED", doc_id, "Download denied")
            abort(404)
        doc = get_doc(doc_id)
        path = storage / doc["stored_name"]
        if not path.is_file():
            abort(404)
        audit(user["id"], "DOWNLOAD", doc_id, f"sha256={doc['sha256']}")
        return send_file(path, as_attachment=True, download_name=doc["original_name"])

    @app.route("/document/<doc_id>/replace", methods=["POST"])
    @login_required
    def replace_document(doc_id):
        user = current_user()
        if not has_access(user, doc_id, "edit"):
            audit(user["id"], "ACCESS_DENIED", doc_id, "Replace denied")
            abort(404)
        f = request.files.get("file")
        ok, result = valid_file(f) if f else (False, "Select a replacement file.")
        if not ok:
            flash(result)
            return redirect(url_for("document_detail", doc_id=doc_id))
        doc = get_doc(doc_id)
        data = result
        new_stored = f"{uuid.uuid4().hex}.bin"
        (storage / new_stored).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        old_path = storage / doc["stored_name"]
        with connect() as con:
            con.execute("""UPDATE documents SET original_name=?,stored_name=?,sha256=?,size=?,updated_at=?
                           WHERE id=?""",
                        (secure_filename(f.filename), new_stored, digest, len(data), utcnow(), doc_id))
        if old_path.exists():
            old_path.unlink()
        audit(user["id"], "EDIT", doc_id, f"new_sha256={digest}")
        flash("Document replaced.")
        return redirect(url_for("document_detail", doc_id=doc_id))

    @app.route("/document/<doc_id>/grant", methods=["POST"])
    @login_required
    def grant(doc_id):
        user = current_user()
        doc = get_doc(doc_id)
        if not doc or doc["owner_id"] != user["id"]:
            abort(404)
        try:
            target_id = int(request.form.get("user_id", ""))
        except ValueError:
            abort(400)
        permission = request.form.get("permission")
        if permission not in {"read", "edit"} or target_id == user["id"]:
            abort(400)
        with connect() as con:
            target = con.execute("SELECT id FROM users WHERE id=?", (target_id,)).fetchone()
            if not target:
                abort(400)
            con.execute("""INSERT INTO grants(document_id,user_id,permission,granted_by,created_at)
                           VALUES(?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET
                           permission=excluded.permission,granted_by=excluded.granted_by,created_at=excluded.created_at""",
                        (doc_id, target_id, permission, user["id"], utcnow()))
        audit(user["id"], "GRANT", doc_id, f"user_id={target_id};permission={permission}")
        flash("Permission saved.")
        return redirect(url_for("document_detail", doc_id=doc_id))

    @app.route("/document/<doc_id>/revoke/<int:target_id>", methods=["POST"])
    @login_required
    def revoke(doc_id, target_id):
        user = current_user()
        doc = get_doc(doc_id)
        if not doc or doc["owner_id"] != user["id"]:
            abort(404)
        with connect() as con:
            con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id, target_id))
        audit(user["id"], "REVOKE", doc_id, f"user_id={target_id}")
        flash("Access revoked.")
        return redirect(url_for("document_detail", doc_id=doc_id))

    @app.route("/document/<doc_id>/delete", methods=["POST"])
    @login_required
    def delete_document(doc_id):
        user = current_user()
        doc = get_doc(doc_id)
        if not doc or doc["owner_id"] != user["id"]:
            abort(404)
        with connect() as con:
            con.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        path = storage / doc["stored_name"]
        if path.exists():
            path.unlink()
        audit(user["id"], "DELETE", doc_id, f"name={doc['original_name']}")
        flash("Document deleted.")
        return redirect(url_for("dashboard"))

    @app.route("/search")
    @login_required
    def search():
        user = current_user()
        term = request.args.get("q", "").strip()
        owner = request.args.get("owner", "").strip()
        category = request.args.get("category", "").strip()
        date = request.args.get("date", "").strip()
        sql = """SELECT DISTINCT d.*,u.username owner_name FROM documents d
                 JOIN users u ON u.id=d.owner_id LEFT JOIN grants g ON g.document_id=d.id
                 WHERE (d.owner_id=? OR g.user_id=?) AND d.original_name LIKE ?"""
        args = [user["id"], user["id"], f"%{term}%"]
        if owner:
            sql += " AND u.username LIKE ?"; args.append(f"%{owner}%")
        if category:
            sql += " AND d.category LIKE ?"; args.append(f"%{category}%")
        if date:
            sql += " AND substr(d.created_at,1,10)=?"; args.append(date)
        with connect() as con:
            docs = con.execute(sql + " ORDER BY d.created_at DESC", args).fetchall()
        return render_template("search.html", docs=docs)

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, message="You are not allowed to perform this action."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="Document or page not found."), 404

    init_db()
    app.verify_audit_chain = verify_audit_chain
    return app

app = create_app()

if __name__ == "__main__":
    # For local development only. Use a production WSGI server and HTTPS for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
