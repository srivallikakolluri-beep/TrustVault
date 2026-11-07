# TrustVault — Secure Document Sharing with Audit Trail

A Flask + SQLite starter implementation of the supplied RISE challenge. It focuses on server-side authorization: every document detail, download, replacement, grant, revoke and delete route checks the authenticated user and the document's owner/grant record.

## Features implemented
- Three roles: `admin`, `owner`, `viewer`.
- Account registration (self-registration is restricted to owner/viewer); admin is seeded only on a fresh database.
- Password hashing, session cookies, CSRF checks on POST routes.
- Private file storage outside the static web directory; random storage names.
- Per-document `read` and `edit` grants to named users.
- Owner can grant, update or revoke access. Each request checks current grants, so revocation applies on the next request.
- File extension, size and basic signature validation.
- Upload, view, download, edit, delete, grant, revoke, login and denied-access audit events.
- SHA-256 hash chain verification displayed in the admin dashboard.
- Search by document name, owner, category and date.
- Pytest security tests.

## Live Demo

 Live URL: https://srivallikakolluri.pythonanywhere.com

 The application is deployed on PythonAnywhere.

 ## Run locally

Python 3.10+ is recommended.

**1. Create virtual environment**

```bash
python -m venv .venv
```

**2. Activate the environment**

Windows:
```powershell
.venv\Scripts\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Set a strong secret before running**

macOS/Linux:
```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Windows PowerShell:
```powershell
$env:SECRET_KEY = "replace-with-a-long-random-secret"
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)



## Demo accounts (fresh database only)
| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@12345` |
| Owner | `owner` | `Owner@12345` |
| Viewer | `viewer` | `Viewer@12345` |

Change these passwords or remove demo users before any real deployment. Do not expose the development server to the public internet.

## Run tests
 ```bash
 python -m pytest -q 
 ``` 

The tests cover unauthorized access, grant/revoke behavior, viewer upload denial, CSRF and audit-chain verification. Run them in your environment and review the output; passing tests are not a guarantee of security.

## Important security limitations / production checklist
This is a learning-project baseline, not a production-certified document vault.
1. The audit hash chain detects accidental or partial tampering, but a database administrator who can rewrite the entire database can recompute it. For stronger evidence, export signed log checkpoints to immutable/WORM storage or a separately controlled logging service.
2. File signature checks are basic. Add malware scanning, robust DOCX/PDF parsing, content-disarm-and-reconstruction if required, and stricter MIME/content policy.
3. Add login throttling, password reset, email verification, account lockout, MFA and security monitoring.
4. Use HTTPS, a production WSGI server, secure cookie settings (`COOKIE_SECURE=1`), secrets manager, backups and restricted filesystem permissions.
5. Admin can inspect document metadata and audit events but does not automatically get document content access. Grant explicit access if an administrator must read a file.
6. `read` permission allows viewing metadata and downloading; `edit` allows replacement and download. Only the owner can grant/revoke and delete.
7. For concurrent production use, use a database with transactions/locking appropriate to the deployment and test revocation race behavior.
8. Ensure audit records are retained according to applicable policy and avoid storing sensitive document contents in logs.

## Suggested demo flow
1. Sign in as `owner`, upload a PDF/TXT file.
2. Open it and grant `viewer` read access.
3. Sign in as `viewer` in a private/incognito window and download.
4. Revoke the grant as `owner`; retry as `viewer` and verify denial.
5. Sign in as `admin` and inspect audit events and chain status.

## Project structure
```text
trustvault/
├── app.py
├── requirements.txt
├── README.md
├── THREATS.md
├── PROMPTS.md
├── templates/
├── static/
└── tests/
```
