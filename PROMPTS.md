# PROMPTS.md — AI usage record

The challenge asks for dated, truthful entries about AI use. Do not submit invented entries. Add an entry after each meaningful AI-assisted work session and include the real commit URL.

## Entry template (copy for each session)

### YYYY-MM-DD — short task title
- **Prompt / fair summary:** [What you actually asked the AI tool]
- **What it produced:** [Files, design, code or explanation]
- **What was wrong or incomplete:** [Specific issue you found, or "No issue found after these checks" with evidence]
- **What I changed instead:** [Your correction and the commit URL]
- **How I verified it:** [Test name, manual steps, output]
### 2026-11-06 — TrustVault setup and testing
- **Prompt / fair summary:** I asked AI to guide me step by step through setting up and running the TrustVault Flask project on Windows 11.
- **What it produced:** Installation instructions, terminal commands, and guidance for running the Flask application.
- **What was wrong or incomplete:** The initial pytest command failed with `ModuleNotFoundError: No module named 'app'`.
- **What I changed instead:** I changed the test command from pytest -q to python -m pytest -q. No application code change was needed.
- **Commit:** https://github.com/srivallikakolluri-beep/TrustVault/commit/8deb5ac
- **How I verified it:** The Flask application started successfully, and all 5 tests passed.
### 2026-11-06 — Viewer access and permission revocation

- **Prompt / fair summary:** I asked AI to help me understand and test document access permissions for different user roles.
- **What it produced:** Guidance for testing Read, Edit and Revoke permissions.
- **What was wrong or incomplete:** I needed to verify that revoked users could no longer access the document.
- **What I changed instead:** I tested the viewer account after revoking its permission.
- **How I verified it:** After revocation, the viewer dashboard displayed "No documents yet". After granting Read access again, the viewer could see and open the document.
- **Commit:** https://github.com/srivallikakolluri-beep/TrustVault/commit/95fa49f
### 2026-11-06 — Audit trail and hash chain verification

- **Prompt / fair summary:** I asked AI to explain how to check TrustVault audit logs and hash chain integrity.
- **What it produced:** Step-by-step instructions to open the admin audit logs and verify recorded activities.
- **What was wrong or incomplete:** I needed to confirm that actual user actions were recorded and that the hash chain verification passed.
- **What I changed instead:** I logged in as admin and inspected the audit activity records.
- **How I verified it:** The page displayed "Hash chain verified" and showed LOGIN, UPLOAD, GRANT, REVOKE, VIEW and DOWNLOAD events.

## Required focus
At least two entries should discuss authorization, access control or audit integrity. Examples of checks you can perform and then document truthfully:
- Try to download a document as a user without a grant.
- Revoke a user's grant and retry the download.
- Try to edit with read-only permission.
- Modify an audit row in a disposable test database and confirm chain verification fails.

Do not write "AI was helpful" as an entry. Record actual prompts, actual defects, actual fixes and real commit links.
