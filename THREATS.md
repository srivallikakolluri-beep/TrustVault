# THREATS.md — TrustVault threat model

This is an initial threat register. Update it as you test the deployed application. Record accepted risks honestly.

| Threat | Mitigation in this project | Remaining risk / next action |
|---|---|---|
| User guesses another document ID | Every document route checks owner/grant server-side; denied routes return 404 | Add automated IDOR tests for every endpoint and fuzz identifiers |
| Viewer tries to upload or replace | Role and permission checks are performed on server routes | Add broader role matrix tests |
| Formerly authorized user downloads after revocation | Grant is queried on every request; revoke deletes grant immediately | Test concurrent in-flight downloads and distributed cache invalidation if deployed |
| User uploads executable content disguised as PDF | Allowlist, size limit and basic magic-byte checks | Add malware scanning and hardened parsers; signatures alone are not sufficient |
| CSRF tricks an authenticated owner into changing permissions | POST routes require a session CSRF token | Add origin checks and security review |
| Password database disclosure | Werkzeug password hashing | Add MFA, rate limiting, breach monitoring and secure reset flow |
| Audit log rows are modified | SHA-256 hash chain and admin integrity check | A privileged attacker can rewrite/re-hash the whole DB; export signed checkpoints to independent immutable storage |
| Storage path traversal | Random server-generated storage filename; original filename is only a download label | Add filesystem sandboxing and strict OS permissions |
| Admin account misused to read files | Admin dashboard shows metadata/logs only; no automatic content access | Define audited break-glass procedure if required |
| Secrets exposed | Environment variable supported | Use secrets manager; rotate keys; never commit production secrets |

## Security assumptions
- The server host and Python runtime are trusted.
- The storage directory is not web-served.
- The SQLite database is not directly writable by ordinary users.
- HTTPS and secure cookies are enabled in production.
- Owners are trusted to grant access appropriately.

## Accepted limitations
- This project does not claim to prevent screenshots, photography, copying after authorized download, or compromise of an authorized user's device.
- Hash chaining is tamper-evident only under the stated trust assumptions; it is not equivalent to externally signed immutable audit storage.
