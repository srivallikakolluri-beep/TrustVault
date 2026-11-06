# PROMPTS.md — AI usage record

The challenge asks for dated, truthful entries about AI use. Do not submit invented entries. Add an entry after each meaningful AI-assisted work session and include the real commit URL.

## Entry template (copy for each session)

### YYYY-MM-DD — short task title
- **Prompt / fair summary:** [What you actually asked the AI tool]
- **What it produced:** [Files, design, code or explanation]
- **What was wrong or incomplete:** [Specific issue you found, or "No issue found after these checks" with evidence]
- **What I changed instead:** [Your correction and the commit URL]
- **How I verified it:** [Test name, manual steps, output]

## Required focus
At least two entries should discuss authorization, access control or audit integrity. Examples of checks you can perform and then document truthfully:
- Try to download a document as a user without a grant.
- Revoke a user's grant and retry the download.
- Try to edit with read-only permission.
- Modify an audit row in a disposable test database and confirm chain verification fails.

Do not write "AI was helpful" as an entry. Record actual prompts, actual defects, actual fixes and real commit links.
