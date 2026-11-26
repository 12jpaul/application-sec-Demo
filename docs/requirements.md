# SokoLink – Security Requirements

Source: MASTER_PROMPT.md §7 (Phase 1 deliverable).

| ID | Requirement | Phase Designed | Phase Implemented | Phase Tested |
|----|-------------|---------------|-------------------|--------------|
| SR-01 | Phone verified by SMS code at sign-up. Password ≥ 10 characters. Argon2 hashing. | 1 | 2 | 2 |
| SR-02 | OTP on new device login and on payout number change. Moderators and admins always use OTP. Codes stored hashed (SHA-256), 5-minute expiry, max 5 attempts. | 1 | 2 | 2 |
| SR-03 | Server authorises every API call and every chat message. Orders and conversations are visible only to their buyer and seller. Default deny: return 404 (not 403) for unauthorised object access. | 1 | 2–5 | 2–5 |
| SR-04 | Server calculates all prices and order totals from stored listing data. Any price or total sent by the client is ignored. | 1 | 6 | 6 |
| SR-05 | An order is marked paid only after a payment-provider callback whose signature has been verified. Each payment reference is processed exactly once (idempotency). Amounts come from the server. | 1 | 6 | 6 |
| SR-06 | "Verified business" badge is granted only after a moderator reviews supporting documents. | 1 | 4 | 4 |
| SR-07 | Image uploads: JPEG/PNG only, ≤ 5 MB. Real file type verified. Re-encoded by Pillow. All EXIF data (including GPS) stripped. Random file names. Private storage; served via signed URLs only. | 1 | 3 | 3 |
| SR-08 | All user-supplied content is treated as untrusted. Stored and rendered as plain text (Flutter `Text()`, never HTML or WebView). Django template auto-escaping always on. Chat messages containing links show a user warning. | 1 | 3–5 | 3–5 |
| SR-09 | Public listings show only district/sector approximation. Exact addresses and phone numbers are never stored in listings. Phone numbers are shared only inside an order between its buyer and seller. | 1 | 3 | 3 |
| SR-10 | All traffic over TLS 1.2+ in production, including WebSocket (WSS) connections. Certificate pinning in release Flutter builds. | 1 | 7, 9 | 7, 8 |
| SR-11 | Rate limits applied to: sign-up, OTP request (max 3 per number per hour), login, listing creation, messages, and search. | 1 | 2–5 | 2–5 |
| SR-12 | Security events logged to the append-only AuditLog model: login success/failure, OTP events, role changes, payout changes, order status changes, moderation actions, payment callbacks. Retained ≥ 1 year. Passwords, OTPs, tokens, and payment keys must never appear in log entries. | 1 | 2 | 2, 8 |
| SR-13 | Daily database backups. Restore procedure tested quarterly. | 1 | 9 | 9 |

## Status key

| Value | Meaning |
|-------|---------|
| **Designed** | Model fields, access rules, and indexes defined in Phase 1 |
| **Implemented** | Serialisers, views, permission classes, and business logic written |
| **Tested** | Security test cases (ST-xx) pass in CI |

## Phase 1 scope

Phase 1 delivers the data model only: models, migrations, and this documentation.
All "Implemented" and "Tested" columns point to future phases.  The Phase 1
security gate requires that every model with user data has an owner field or
access rule, sensitive fields are identified, and migrations are reviewed.
