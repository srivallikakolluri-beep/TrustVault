import io
from app import create_app

def setup_client(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DB_PATH": str(tmp_path / "test.db"),
        "STORAGE": str(tmp_path / "uploads"),
    })
    client = app.test_client()
    return app, client

def csrf(client):
    # Load a form to establish a session and token.
    client.get("/login")
    with client.session_transaction() as sess:
        return sess["_csrf"]

def login(client, username, password):
    token = csrf(client)
    return client.post("/login", data={"_csrf": token, "username": username, "password": password},
                       follow_redirects=True)

def test_owner_upload_and_viewer_denied(tmp_path):
    app, c = setup_client(tmp_path)
    login(c, "owner", "Owner@12345")
    token = csrf(c)
    r = c.post("/upload", data={"_csrf": token, "category": "HR",
        "file": (io.BytesIO(b"%PDF-1.4 sample"), "letter.pdf")},
        content_type="multipart/form-data", follow_redirects=True)
    assert b"uploaded securely" in r.data
    with app.test_client() as viewer:
        login(viewer, "viewer", "Viewer@12345")
        with app.app_context():
            from sqlite3 import connect
            con = connect(tmp_path / "test.db")
            doc_id = con.execute("SELECT id FROM documents").fetchone()[0]
            con.close()
        assert viewer.get(f"/document/{doc_id}").status_code == 404
        assert viewer.get(f"/document/{doc_id}/download").status_code == 404

def test_grant_then_revoke_blocks_immediately(tmp_path):
    app, owner = setup_client(tmp_path)
    login(owner, "owner", "Owner@12345")
    token = csrf(owner)
    owner.post("/upload", data={"_csrf": token, "category": "HR",
        "file": (io.BytesIO(b"%PDF-1.4 sample"), "letter.pdf")},
        content_type="multipart/form-data")
    with app.app_context():
        import sqlite3
        con = sqlite3.connect(tmp_path / "test.db")
        doc_id = con.execute("SELECT id FROM documents").fetchone()[0]
        viewer_id = con.execute("SELECT id FROM users WHERE username='viewer'").fetchone()[0]
        con.close()
    owner.post(f"/document/{doc_id}/grant", data={"_csrf": csrf(owner),
        "user_id": viewer_id, "permission": "read"})
    viewer = app.test_client()
    login(viewer, "viewer", "Viewer@12345")
    assert viewer.get(f"/document/{doc_id}/download").status_code == 200
    owner.post(f"/document/{doc_id}/revoke/{viewer_id}", data={"_csrf": csrf(owner)})
    assert viewer.get(f"/document/{doc_id}/download").status_code == 404

def test_viewer_cannot_upload(tmp_path):
    _, c = setup_client(tmp_path)
    login(c, "viewer", "Viewer@12345")
    r = c.post("/upload", data={"_csrf": csrf(c),
        "file": (io.BytesIO(b"hello"), "a.txt")},
        content_type="multipart/form-data")
    assert r.status_code == 403

def test_audit_chain_detects_normal_activity(tmp_path):
    app, c = setup_client(tmp_path)
    login(c, "owner", "Owner@12345")
    assert app.verify_audit_chain() is True

def test_csrf_required(tmp_path):
    _, c = setup_client(tmp_path)
    r = c.post("/login", data={"username": "owner", "password": "Owner@12345"})
    assert r.status_code == 400
