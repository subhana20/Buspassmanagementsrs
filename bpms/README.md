# TransitPass — Bus Pass Management System

A runnable web-based implementation of the supplied **Bus Pass Management System SRS v1.0**. It includes passenger, staff/operator and administrator workflows, a persistent SQLite database, secure password hashing, role-based API authorization, document upload validation, QR pass generation, audit trail and CSV reporting.

## Requirements
- Node.js 18 or newer
- npm

## Run locally (Windows / macOS / Linux)
1. Extract the ZIP.
2. Open a terminal in the extracted `bpms` folder.
3. Install dependencies:
   ```bash
   npm install
   ```
4. (Recommended) Copy `.env.example` to `.env` and set a long random `JWT_SECRET`.
5. Start:
   ```bash
   npm start
   ```
6. Open **http://localhost:4000**.

The SQLite database is created automatically at `data/bpms.db`. The `uploads` folder stores supporting documents. Keep both folders in backups.

## Demo accounts
| Role | Email | Password |
|---|---|---|
| Administrator | `admin@bpms.local` | `Admin@123` |
| Staff / Operator | `staff@bpms.local` | `Staff@123` |

Passengers can register through the sign-in page. Change demo passwords before any shared or production deployment.

## Implemented workflows
### Passenger
- Register, sign in, change password
- View profile/dashboard and catalog of active routes/pass types
- Submit a new application with optional PDF/JPG/PNG documents
- Track application number, review status and remarks
- Record a demo/manual payment after approval
- View issued pass and QR code
- Request renewal of active/expired pass

### Staff / Operator
- Dashboard and application queue
- Review submitted details and supporting documents
- Approve, reject or return applications for correction with remarks
- Record pass issuance after approval and recorded payment
- Search/verify pass by pass number or QR payload
- Activate, suspend or cancel passes
- View reports and export application/pass/payment CSV files

### Administrator
- All staff functions
- Manage users, role and account activation
- Create/update/deactivate routes and pass types/fares
- View audit trail

## SRS implementation notes and deployment decisions
- **Payments:** This build includes a clearly labelled demo/manual payment-recording workflow. No real payment gateway credentials/provider were specified in the SRS, so live card/UPI processing is not enabled. Integrate a selected provider and verify signed webhooks before production.
- **Notifications:** Status changes are visible in the passenger portal. Email/SMS delivery is not activated because the SRS leaves provider and templates TBD.
- **Password recovery:** A production-safe self-service reset needs a configured email/SMS provider and verified identity flow. This local build provides authenticated password change; do not expose an insecure unauthenticated reset endpoint.
- **QR:** QR code contains only the unique pass number; the server performs the authoritative validity lookup.
- **HTTPS:** Use HTTPS/TLS at the deployment reverse proxy (e.g. Nginx/Caddy) and set a strong environment secret. Localhost development runs HTTP.
- **Backups:** Back up `data/bpms.db` and `uploads/` regularly. SQLite WAL mode is enabled; use a consistent backup procedure for production.
- **Capacity/performance:** The app uses indexed SQLite tables and compressed static assets. The SRS's 95th-percentile 3-second and concurrent-user targets must be load-tested against the actual deployment dataset and infrastructure; this package does not claim a measured benchmark.
- **Session timeout:** JWT expiry is configurable using `SESSION_HOURS` (default 8 hours).
- **Upload controls:** PDF/JPEG/PNG allowlist, 5 files per application and 5 MB per file by default (`MAX_UPLOAD_MB`). Adjust policy to match final organization rules.
- **Operational policy:** Pass categories, fares, validity and routes are seed examples and must be replaced with the organization's approved policy.

## Security checklist before production
1. Set `NODE_ENV=production` and a cryptographically random `JWT_SECRET` (at least 32 random bytes).
2. Serve only behind HTTPS/TLS; configure secure proxy headers and restrictive CORS if a separate frontend is introduced.
3. Change/remove demo accounts and enforce organization-specific admin provisioning.
4. Configure SMTP variables in `.env` (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`, `APP_BASE_URL`) for one-time email password recovery; configure notification delivery separately.
5. Integrate a real payment provider; never trust client-side payment claims.
6. Add malware scanning and private object storage for uploaded documents; enforce retention policy.
7. Set backup, restore, monitoring, availability and disaster-recovery targets.
8. Load-test with expected concurrency and production-like data.
9. Review dependencies and run `npm audit` before deployment.

## Project structure
```text
bpms/
├── server.js              # REST API, auth, business rules, SQLite schema
├── package.json
├── .env.example
├── README.md
├── data/                  # SQLite DB created at runtime
├── uploads/               # private supporting document storage
└── public/
    ├── index.html
    ├── styles.css
    └── app.js
```

## Requirement coverage overview
- REQ-F-001–005: registration, login, password hashing, authenticated password change, role checks and validation
- REQ-F-006–011: applications, catalog selection, validation, document upload and unique application number
- REQ-F-012–016: staff queue, review actions, reviewer/time/remarks and passenger-visible status
- REQ-F-017–021: configurable fee display, payment record, issuance gates, unique pass number and pass details
- REQ-F-022–026: renewal request, eligibility checks, status changes/history and expiry evaluation
- REQ-F-027–030: pass number/QR payload verification, minimal public-facing result and verification audit
- REQ-F-031–035: catalog configuration, user roles, searches, reports/CSV and audit trail
- REQ-NF-001–014: indexed queries, atomic SQLite transactions for critical operations, role-based access, bcrypt password hashing, upload limits/allowlist, configurable token expiry, audit records and data minimization; HTTPS, load, backup/restore and availability targets require deployment configuration and verification.

## API
All protected endpoints require `Authorization: Bearer <token>`.
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/me`
- `GET /api/catalog`
- `POST/GET /api/applications`, `GET /api/applications/:id`
- `POST /api/applications/:id/review`, `/payment`, `/issue`
- `GET /api/passes`, `GET /api/passes/:id/qr`, `POST /api/passes/verify`
- `POST /api/passes/:id/renew`, `PATCH /api/passes/:id/status`
- `GET /api/admin/dashboard`, `/users`, `/reports`, `/audit`
- `POST/PATCH /api/admin/routes`, `POST/PATCH /api/admin/pass-types`
- `GET /api/admin/export/:kind`
