MASTER PROMPT – SokoLink Secure Local Online Marketplace
> **For Claude Code:** this file is the single source of truth for the project. Read it fully before any task. Follow the phases in order. **At the end of every phase, stop, summarize what was done, and wait for my approval before starting the next phase.** If something here conflicts with a request I make in chat, ask me before proceeding.
---
1. Context
Project: SokoLink, a mobile marketplace where people and small businesses in a town advertise products for sale.
Course: CIS 4163 – Application Security Technologies (University of Rwanda, College of Science and Technology, School of ICT). Lecturer: NGABO Desire.
Student: Jean Paul (Year 4 Computer Science). This is an individual assignment.
Main goal: build the app with security integrated into every phase of the SDLC. Security is a first-class requirement, not an afterthought. Every feature must come with its security controls and its security tests.
Already done (see `README.md` and `docs/`): Requirements and Design, including the security requirements (SR-01 to SR-13), the abuse cases, the data flow diagram and the STRIDE threat model (T1 to T17).
2. Features (scope)
Feature	Description
Product listings	Title, description, price (RWF), photos (max 5), condition, category, approximate location (district/sector)
Categories	Admin-managed list (electronics, clothing, furniture, food, services, …)
Search	Keyword search with filters: category, price range, district
Seller profiles	Name, photo, bio, ratings and reviews, "verified business" badge
Messaging	Private real-time chat between a buyer and a seller about a listing
Order management	Statuses: placed → confirmed → delivered → completed, or cancelled. Payment by mobile money or cash on delivery
Moderation	Users report listings and users; moderators review reports, hide listings, suspend users, approve badges
Out of scope: delivery tracking, web storefront for buyers, card payments.
3. Roles and permissions
Role	Allowed	Forbidden
Buyer	Browse, search, message sellers, place/track/cancel own orders, review a seller only after a completed order	Seeing other users' orders, chats or contact details
Seller	CRUD own listings, reply to buyers, manage own orders, set payout phone number	Editing other sellers' listings or orders
Moderator	Review reports, hide/unhide listings, suspend users, approve badges	Reading private chats unless attached to a report; changing orders or payments
Admin	Manage users, roles, categories, configuration	Changing orders or payments without an audit-log reason
One account can be both buyer and seller. Default deny: anything not explicitly allowed is forbidden.
4. Tech stack
Backend
Python 3.12, Django 5.x, Django REST Framework
Authentication: `djangorestframework-simplejwt` (access token 15 min, refresh token 7 days, rotation + blacklist on)
Password hashing: Argon2 (`argon2-cffi`, set `PASSWORD_HASHERS` with Argon2 first)
Real-time chat: Django Channels + `channels-redis` (WebSockets over TLS in production)
Database: MySQL 8 (`mysqlclient`); full-text search on listing title/description
Images: Pillow; stored in private storage, served through short-lived signed URLs
Config: `django-environ` (all secrets from environment variables)
API docs: `drf-spectacular` (OpenAPI)
Tests: `pytest`, `pytest-django`, `factory_boy`
Mobile
Flutter 3.x / Dart, Android and iOS
State management: Riverpod; navigation: go_router; HTTP: dio
Secure storage: `flutter_secure_storage`; local cache: `sqflite_sqlcipher`
Chat: `web_socket_channel`
External services (behind interfaces, with mock implementations for development and tests)
`PaymentProvider`: mobile money (sandbox only during development)
`SmsProvider`: one-time codes (console backend in development)
`PushProvider`: push notifications
5. Architecture and trust boundaries
```
Users ⇄ [Phone: Flutter app + encrypted SQLite cache]
          ⇅ F3 HTTPS / WSS over TLS
      [Backend in Rwanda: Django API + Channels | MySQL | private image storage | append-only audit log]
          ⇅ F7
      [Third parties: mobile money | SMS | push]
```
Three trust boundaries: phone, backend, third-party services. Never trust anything that crosses a boundary: validate on the server every time.
6. Security rules (non-negotiable)
Apply these in all code. If a task would break one, stop and tell me.
Server-side authorization on every request and every chat message. Use reusable DRF permission classes for both role and ownership checks. Return 404 (not 403) when a user asks for an object they don't own, so existence is not leaked.
The server calculates all prices and totals from stored listing data. Ignore any price or total sent by the client.
No raw SQL built from user input. Use the Django ORM only, including for search.
Validate all input with DRF serializers: types, lengths, allowed values, price > 0, max 5 photos.
All user content is untrusted. Store it as plain text and render it as plain text (Flutter `Text`, never HTML or WebView). Keep Django template auto-escaping on.
Uploads: accept JPEG/PNG only, ≤ 5 MB. Verify the real file type, open and re-encode with Pillow, and strip all EXIF data (especially GPS). Generate random file names.
Payments: an order is paid only after a payment-provider callback whose signature has been verified. Each payment reference is processed only once (idempotency). Amounts come from the server.
One-time codes (OTP): required at sign-up (phone verification), on login from a new device, and on payout number change. Codes are 6 digits, valid 5 minutes, max 5 attempts, stored hashed. Moderators and admins always need OTP.
Rate limiting (DRF throttles) on: login, sign-up, OTP request (max 3 per number per hour), listing creation, messages, search.
Secrets only in environment variables. Never commit `.env`, keys or tokens. Never hard-code keys in the Flutter app; the app talks only to the SokoLink backend.
Logging: log security events (login success/failure, OTP failures, role changes, payout changes, order status changes, moderation actions, payment callbacks) to an append-only audit log model. Never log passwords, OTPs, tokens or payment keys.
Errors: return generic error messages; no stack traces. `DEBUG=False` outside local development.
Privacy: public listings show only district/sector, never an exact address or phone number. Phone numbers are shared only inside an order between its buyer and seller.
Mobile: tokens only in `flutter_secure_storage`; cache in SQLCipher; certificate pinning in release builds; release builds with `--obfuscate --split-debug-info`; no debug logs in release.
Dependencies: pin versions; no new dependency without telling me why.
7. Security requirements (from Phase 1)
ID	Requirement
SR-01	Phone verified by SMS code at sign-up; password ≥ 10 characters; Argon2 hashing
SR-02	OTP on new device and on payout number change; moderators/admins always use OTP
SR-03	Server authorizes every API call and chat message; orders/chats visible only to their buyer and seller
SR-04	Server calculates all prices and totals
SR-05	Order marked paid only after verified callback with a unique reference
SR-06	"Verified business" badge only after a moderator checks documents
SR-07	Images only, ≤ 5 MB, re-encoded, EXIF removed
SR-08	All user content untrusted; shown as plain text; chat links show a warning
SR-09	Public listings show only approximate area
SR-10	All traffic over TLS 1.2+ (including WebSockets)
SR-11	Rate limits on sign-up, OTP, listings, messages, search
SR-12	Security events logged, kept ≥ 1 year
SR-13	Daily backups; restore tested quarterly
8. Threat model (from Phase 2)
Risk = likelihood × impact (1–5 each). Risk ≥ 12 must be fixed before release (T1–T14).
#	Threat	STRIDE	Control	Risk	Test
T1	Fake seller accounts	Spoofing	Phone verification, moderated badge, reviews only after completed orders, new sellers limited to 5 listings/day and first listings held for review	20	ST-01
T2	Seller account takeover, payout changed	Spoofing	OTP on new device + payout change, lockout after 5 failures, alert to old number	16	ST-02
T3	IDOR on orders/chats	Info disclosure	Ownership checks on every request and message	16	ST-03
T4	Price tampering in order	Tampering	Server-side totals	16	ST-04
T5	Scam links in chat	Spoofing	Link warning, flag messages asking for off-app payment	16	ST-05
T6	Fake/replayed payment callback	Tampering	Signature verification, idempotent references	15	ST-06
T7	SQL injection in search	Tampering	ORM only, validation	15	ST-07
T8	Privilege escalation	EoP	Default-deny permissions, admin behind VPN	15	ST-08
T9	Database leak	Info disclosure	Encryption at rest, no public DB port, least-privilege DB user	15	ST-09
T10	Malicious content/files	Tampering	Plain-text rendering, re-encoding, type checks	12	ST-10
T11	EXIF location leak	Info disclosure	Strip EXIF	12	ST-11
T12	Repudiation of orders/messages	Repudiation	Order status history, append-only audit log	12	ST-12
T13	Spam bots, SMS flooding	DoS	Throttles, OTP limits, CAPTCHA on sign-up	12	ST-13
T14	Vulnerable dependencies	Tampering	Pinned versions, pip-audit/OSV in CI	12	ST-14
T15	Lost phone	Info disclosure	SQLCipher, secure storage, remote logout	9	—
T16	MITM	Tampering	TLS 1.2+, certificate pinning	8	—
T17	Secrets in logs	Info disclosure	Logging rules	6	—
When code mitigates a threat, add a comment such as `# Mitigates T4: server-side price calculation` so controls are traceable.
9. Repository structure
```
sokolink/
├── backend/
│   ├── config/             # settings (base/dev/prod), urls, asgi, wsgi
│   ├── accounts/           # users, roles, OTP, devices, auth
│   ├── listings/           # listings, categories, search, images
│   ├── profiles/           # seller profiles, reviews, badges
│   ├── messaging/          # conversations, messages, Channels consumers
│   ├── orders/             # orders, status history, payments
│   ├── moderation/         # reports, moderation actions
│   ├── audit/              # append-only audit log
│   ├── integrations/       # PaymentProvider, SmsProvider, PushProvider + mocks
│   ├── tests/security/     # ST-01 … ST-14
│   ├── requirements.txt
│   └── .env.example
├── mobile/                 # Flutter app (lib/features/<feature>/…)
├── docs/
│   ├── requirements.md
│   ├── threat-model.md
│   ├── security-test-report.md
│   ├── deployment-checklist.md
│   ├── incident-response.md
│   └── status-report.md
├── .github/workflows/ci.yml
├── .gitignore
├── .pre-commit-config.yaml
├── SECURITY.md
├── CLAUDE.md
├── MASTER_PROMPT.md
└── README.md
```
10. Working rules for Claude Code
Work one phase at a time. Start each phase in Plan mode: show the plan, wait for my approval, then implement.
For each feature, deliver: models → serializers → permissions → views/consumers → URLs → functional tests + security tests → Flutter screens → short docs update.
Small, focused commits with Conventional Commit messages, e.g. `feat(orders): server-side total calculation (T4)`.
Run the tests and the security scans before saying a task is done, and show me the results.
Explain security decisions briefly in plain language. I need to understand them for my report.
Never delete or rewrite files in `docs/` without asking.
If something is unclear or a choice has security trade-offs, ask me first.
11. Phased plan
Each phase lists its security tasks and a security gate that must pass before moving on.
Phase 0 – Repository and secure foundation
Create the folder structure (Section 9), `.gitignore` (Python, Flutter, `.env`, keys), `.env.example`, `SECURITY.md`.
Django project with split settings (`base`, `dev`, `prod`). In `prod`: `DEBUG=False`, `SECURE_SSL_REDIRECT`, HSTS, secure cookies, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS='DENY'`, strict `ALLOWED_HOSTS`.
Argon2 password hashing, DRF default permission `IsAuthenticated`, default throttles.
Flutter project skeleton with environment config (no secrets).
`pre-commit` with Gitleaks, Black/Ruff, and `dart format`.
GitHub Actions `ci.yml`: Bandit, Semgrep, pip-audit, OSV-Scanner, Gitleaks, `pytest`, `dart analyze`, `flutter test`. Fail on high-severity findings.
Security gate: CI runs green; secret scan blocks a test secret; no secrets in the repo.
Phase 1 – Data model and documentation
Design all models with ownership fields and indexes: User, Device, OtpCode, Category, Listing, ListingImage, SellerProfile, Review, BusinessBadgeRequest, Conversation, Message, Order, OrderStatusHistory, Payment, Report, ModerationAction, AuditLog.
`AuditLog` is append-only (no update/delete through the app; override `save`/`delete`).
Write `docs/requirements.md` and `docs/threat-model.md` from Sections 7 and 8.
Security gate: every model with user data has an owner field or access rule; sensitive fields identified; migrations reviewed.
Phase 2 – Authentication and authorization (mitigates T1, T2, T8, T13)
Sign-up with phone + SMS OTP, login with JWT, refresh rotation, logout (blacklist), device registration, OTP on new device, lockout after 5 failed logins (15 min).
Roles: buyer/seller (same account), moderator, admin. Reusable permission classes: `IsOwner`, `IsOrderParticipant`, `IsConversationParticipant`, `IsModerator`, `IsAdmin`.
Audit-log all auth events.
Tests: ST-01 (phone verification), ST-02 (lockout, device trust, token rotation), ST-08 (privilege escalation), ST-13 (OTP rate limits, IP spoofing).
Security gate: all auth tests pass; no endpoint reachable without the right role.
Scope notes (moved to later phases):
  - Payout number change with OTP + alert to old number → Phase 6 (requires SellerProfile + payment flow).
  - Flutter sign-up / OTP / login screens → Phase 7 (mobile hardening).
Phase 3 – Listings, categories, search, images (mitigates T1, T7, T10, T11)
Listing CRUD (owner only), categories (admin only), search with ORM full-text + filters, pagination.
New sellers: max 5 listings/day; first 3 listings held as `pending_review`.
Image upload pipeline: type check, size check, Pillow re-encode, EXIF strip, random name, private storage, signed URLs.
Public responses never include exact address or phone.
Flutter: browse, category list, search with filters, listing detail, create/edit listing with photo picker.
Tests: ST-01, ST-07, ST-10, ST-11.
Security gate: injection and upload tests pass; EXIF verified removed.
Phase 4 – Seller profiles, reviews, badges, moderation (mitigates T1, T8, T12)
Seller profile view/edit (own), reviews only from a buyer with a completed order with that seller (one review per order).
Business badge request with document upload → moderator approves/rejects.
Report listing/user → moderation queue → hide listing, suspend user; all actions audit-logged.
Moderator endpoints restricted to moderators; admin panel restricted (VPN in production).
Flutter: seller profile, reviews, report button, badge request screen.
Tests: review-without-order rejected, badge without documents rejected, non-moderator blocked from moderation endpoints.
Security gate: all moderation actions appear in the audit log.
Phase 5 – Messaging (mitigates T3, T5, T13)
Conversations tied to a listing between one buyer and the seller. REST for history, Channels WebSocket for real time.
Authenticate the WebSocket with the JWT; check conversation membership on connect and on every message.
Message validation (length ≤ 2,000), throttling, plain-text storage.
Link detection: flag messages with links or phrases asking for off-app payment; the app shows a warning before opening any link.
Flutter: conversation list, chat screen (plain `Text`), link warning dialog.
Tests: ST-03 (chat part), ST-05, message throttle test.
Security gate: a non-participant cannot read or join any conversation.
Phase 6 – Orders and payments (mitigates T3, T4, T6, T12)
Order creation from a listing; total calculated on the server; status machine with allowed transitions only; every change saved in `OrderStatusHistory` and the audit log.
Payment: create the request on the server, `PaymentProvider` interface with a sandbox/mock implementation, callback endpoint that verifies the signature, idempotency on payment reference, amount check against the order.
Cash on delivery: seller confirms delivery, buyer confirms receipt.
Flutter: place order, order list and detail, pay with mobile money, status updates.
Tests: ST-03 (orders part), ST-04, ST-06, ST-12, illegal status transitions rejected.
Security gate: price tampering, fake callbacks and replays all fail.
Phase 7 – Mobile app hardening (mitigates T15, T16)
SQLCipher cache with key in secure storage; certificate pinning for HTTPS and WSS (release builds); obfuscated release builds; remove debug logs; remote logout (revoke all sessions).
Check against OWASP MASVS.
Security gate: MobSF scan with no high findings.
Phase 8 – Security testing (SDLC Testing phase)
Complete `backend/tests/security/` with ST-01 to ST-14, each named after its threat (e.g. `test_st04_price_tampering.py`).
Run OWASP ZAP (baseline + API scan using the OpenAPI schema) against a local/staging server.
Run MobSF on the APK.
Walk through an OWASP ASVS checklist for the API.
Write `docs/security-test-report.md`: test, threat, result, evidence, fix.
Security gate: all ST-01 to ST-14 pass; no high findings in ZAP/MobSF/SAST.
Phase 9 – Deployment (SDLC Deployment phase)
Dockerfiles and `docker-compose` for local/staging (Django, Daphne/Uvicorn, MySQL, Redis, Nginx).
Nginx: TLS 1.2+, HSTS, security headers, only port 443 public, WebSocket proxy.
MySQL not exposed; least-privilege DB user; encryption at rest; daily encrypted backups + restore script.
Write `docs/deployment-checklist.md` (11 items from the design) and a release workflow that runs all security checks before deploy.
Security gate: checklist complete; restore tested once.
Phase 10 – Maintenance and final documentation (SDLC Maintenance phase)
`docs/incident-response.md` (NIST CSF: identify, protect, detect, respond, recover).
Fraud/abuse alerts: many new listings from a new account, payout number changes, many cancelled orders, flagged messages.
Dependabot (or similar) for weekly dependency updates.
Update `README.md` status, `docs/status-report.md`, and the threat model with anything learned.
Security gate: final review with me; all docs up to date.
12. Security test cases (Phase 8 reference)
Test	Threat	Steps	Pass when
ST-01	T1	New seller posts 20 listings in 1 hour; badge request without documents	Listings held/blocked; badge refused
ST-02	T2	Login from new device; change payout number	OTP required both times; old number alerted
ST-03	T3	User A requests B's order and joins B's chat	404 for API; WebSocket connection refused
ST-04	T4	Place order with modified total	Stored listing price used
ST-05	T5	Send message with a link and "pay me directly"	Message flagged; app shows warning
ST-06	T6	Unsigned callback; replayed real callback	First rejected; replay ignored
ST-07	T7	SQL injection strings in search/filters	Treated as text; no error leaks
ST-08	T8	Buyer calls moderator endpoints; seller A edits B's listing	403/404
ST-09	T9	DB port from outside; storage encryption	Port closed; data encrypted at rest
ST-10	T10	`<script>` in listing/message; non-image renamed `.jpg`	Rendered as text; file rejected
ST-11	T11	Upload photo with GPS EXIF, download published copy	No EXIF in output
ST-12	T12	Try to edit/delete audit log or order history	Not possible
ST-13	T13	20 OTP requests/hour for one number; 1,000 API requests/min	Throttled; others unaffected
ST-14	T14	Dependency scan on release build	No high/critical vulnerabilities
13. Definition of done (every task)
[ ] Feature works and has functional tests.
[ ] Related security controls are implemented and commented with threat IDs.
[ ] Related security tests pass.
[ ] Bandit, Semgrep, pip-audit, Gitleaks and `dart analyze` show no high findings.
[ ] No secrets, no debug output, no raw SQL.
[ ] Docs updated if behaviour or security changed.
[ ] Short summary given to me, including which threats were addressed.
14. References
Humayun et al. (2022), Security Threat and Vulnerability Assessment and Measurement in Secure Software Development – secure SDLC framework (tasks, issues, practices per phase).
Hasan et al. (2025), ISADM: An Integrated STRIDE, ATT&CK, and D3FEND Model – threat modeling and score-based risk threshold.
Aslan et al. (2023), A Comprehensive Review of Cyber Security Vulnerabilities, Threats, Attacks, and Solutions.
Saeed & Asaad (2022), Cyber Security Threats, Vulnerability, Challenges with Proposed Solution.
Bertino et al. (2009), Web Services Threats, Vulnerabilities, and Countermeasures.
Almuhammadi & Alsaleh (2017), Information Security Maturity Model for NIST Cyber Security Framework.
OWASP ASVS and MASVS.
Rwanda Law N° 058/2021 on the protection of personal data and privacy.
