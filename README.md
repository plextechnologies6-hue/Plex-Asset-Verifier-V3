# Plex Technologies – Asset Verification Platform V3

V3 adds:
- Secure login/logout using Flask-Login
- Password hashing
- Role-based access: Admin, Supervisor, Field Officer, Client Viewer
- Admin user management
- Activate/deactivate accounts
- Admin password reset
- PostgreSQL-ready persistence
- Existing multi-client and verification-session workflow

## Render environment variables

Add these to the V3 Render Web Service:

- `DATABASE_URL` = Render Internal Database URL
- `SECRET_KEY` = long random secret
- `ADMIN_EMAIL` = first administrator email
- `ADMIN_PASSWORD` = first administrator password
- `ADMIN_NAME` = optional administrator name

On first startup, if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set and no matching user exists, the application creates the first Admin account.

## Deployment

Build command:
`pip install -r requirements.txt`

Start command:
`gunicorn app:app`

## Security roadmap before real client use

Add CSRF protection, login throttling/lockout, session timeout, secure cookie settings, per-client user assignment, audit logging, object storage for photographs, backups, formal migration tooling, and HTTPS enforcement.


## Branded landing page
The V3 branded release includes a public landing page, dark navy/blue hero, platform capability cards, workflow section, branded authentication page, and responsive layouts.
