# SokoLink – Threat Model

Source: MASTER_PROMPT.md §8 (Phase 1 deliverable).
Framework: STRIDE.  Risk = Likelihood × Impact (1–5 each).  Risk ≥ 12 must be fixed before release.

## Trust boundaries

```
Users ⇄ [Phone: Flutter app + encrypted SQLite cache]
          ⇅ F3 HTTPS / WSS over TLS
      [Backend: Django API + Channels | MySQL | private storage | append-only audit log]
          ⇅ F7
      [Third parties: mobile money | SMS | push notifications]
```

Three trust boundaries: phone ↔ backend, backend ↔ third-party services.
Nothing that crosses a boundary is trusted by default; every input is validated server-side.

## Threat register

| # | Threat | STRIDE | Control | Risk | Test | Phase |
|---|--------|--------|---------|------|------|-------|
| T1 | Fake seller accounts | Spoofing | Phone verification; badge requires moderator review; reviews only after completed orders; new sellers limited to 5 listings/day, first listings held as `pending_review` | 20 | ST-01 | 2–4 |
| T2 | Seller account takeover; payout number changed | Spoofing | OTP on new device + payout change; lockout after 5 login failures (15 min); alert SMS to old payout number | 16 | ST-02 | 2 |
| T3 | IDOR on orders/conversations | Info disclosure | Ownership check on every request and every WebSocket message; return 404 for objects the caller does not own | 16 | ST-03 | 2–5 |
| T4 | Price tampering in order | Tampering | Order creation reads `Listing.price`; `Order.unit_price` and `total_amount` are server-calculated; client-submitted totals are ignored | 16 | ST-04 | 6 |
| T5 | Scam links in chat | Spoofing | Backend flags messages with URLs or off-app-payment phrases (`Message.is_flagged`); app shows warning dialog before opening any link | 16 | ST-05 | 5 |
| T6 | Fake or replayed payment callback | Tampering | Signature verification before `Payment.callback_verified = True`; `Payment.provider_reference` is UNIQUE (idempotency); amount compared to `Order.total_amount` | 15 | ST-06 | 6 |
| T7 | SQL injection in search | Tampering | Django ORM QuerySet filtering only; no raw SQL built from user input; all inputs validated by DRF serialisers | 15 | ST-07 | 3 |
| T8 | Privilege escalation | Elevation of privilege | Default-deny DRF permissions (`IsAuthenticated`); role flags additive; admin panel at non-default path behind VPN in production | 15 | ST-08 | 2–4 |
| T9 | Database leak | Info disclosure | Encryption at rest (MySQL); no public DB port; least-privilege DB user; phone numbers excluded from public API responses | 15 | ST-09 | 9 |
| T10 | Malicious content / files | Tampering | Plain-text rendering in Flutter; image re-encoding with Pillow; content-type verification before storage | 12 | ST-10 | 3 |
| T11 | EXIF location leak | Info disclosure | Pillow strips all EXIF data (including GPS) before saving; `ListingImage.file_path` served via signed URL only | 12 | ST-11 | 3 |
| T12 | Repudiation of orders / messages | Repudiation | `OrderStatusHistory` append-only; `AuditLog` append-only (ORM-level `save()`/`delete()` override + custom QuerySet); `ModerationAction` append-only | 12 | ST-12 | 1–6 |
| T13 | Spam bots / SMS flooding | Denial of service | DRF throttles (anon 20/min, user 200/min); OTP throttle (3/hour per number); listing creation throttle; message throttle | 12 | ST-13 | 2–5 |
| T14 | Vulnerable dependencies | Tampering | Pinned versions in `requirements.txt` and `pubspec.yaml`; `pip-audit` + OSV-Scanner in CI; fail on high/critical CVEs | 12 | ST-14 | 0 |
| T15 | Lost phone | Info disclosure | SQLCipher local cache (key in `flutter_secure_storage`); remote logout revokes all sessions | 9 | — | 7 |
| T16 | MITM | Tampering | TLS 1.2+ for all connections; certificate pinning in release Flutter builds | 8 | — | 7 |
| T17 | Secrets in logs | Info disclosure | `sokolink.security` logger rules: log the WHAT and WHO, never the secret; `AuditLog.extra` must never contain passwords, OTPs, tokens, or payment keys | 6 | — | 1–6 |

## Risk ≥ 12 (must fix before release)

Threats T1–T14 all have risk ≥ 12.  Controls for each are listed in the table
above.  Test cases ST-01 to ST-14 (implemented in Phase 8) verify each control.

## Residual risks

| Risk | Accepted because |
|------|-----------------|
| T15 (Lost phone, risk 9) | SQLCipher + secure storage reduce impact to low; remote logout available |
| T16 (MITM, risk 8) | TLS enforced at network layer; cert pinning adds defence-in-depth in Phase 7 |
| T17 (Secrets in logs, risk 6) | Logging rules enforced in code review and CI; risk low with Argon2 and no plaintext storage |
