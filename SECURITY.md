# Security Policy – SokoLink

## Supported versions

This project is under active development as a university assignment.
Only the `main` branch is maintained.

| Branch  | Supported |
|---------|-----------|
| `main`  | ✅ Yes     |
| Others  | ❌ No      |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Doing so could expose other users before a fix is available.

### How to report

1. Email the author privately at the address in the repository profile.
2. Include:
   - A clear description of the vulnerability.
   - Steps to reproduce it (proof-of-concept code is welcome).
   - The potential impact (data exposure, privilege escalation, etc.).
   - Your suggested fix or mitigation, if you have one.
3. You will receive an acknowledgement within **48 hours** and a status update
   within **7 days**.

### What happens next

| Step | Timeline |
|------|----------|
| Acknowledgement | ≤ 48 hours |
| Initial assessment | ≤ 7 days |
| Fix and patch release | ≤ 30 days for high/critical |
| Public disclosure | After the fix is released |

### Scope

**In scope**
- Authentication bypass or account takeover (T1, T2)
- Insecure direct object references (T3)
- Price tampering or payment bypass (T4, T6)
- SQL injection or other injection attacks (T7)
- Privilege escalation (T8)
- Sensitive data exposure (T9, T11)
- Cross-site scripting via the API (T10)

**Out of scope**
- Vulnerabilities in third-party services (mobile money provider, SMS gateway)
- Denial-of-service attacks against infrastructure
- Social engineering of project contributors
- Issues already reported or under active remediation

## Security controls summary

| Ref  | Control |
|------|---------|
| SR-01 | Phone verified by SMS OTP at sign-up; Argon2 password hashing |
| SR-02 | OTP required on new device and payout number change |
| SR-03 | Server-side authorisation on every request and chat message |
| SR-04 | Server calculates all order totals |
| SR-05 | Payment confirmed only after verified callback with unique reference |
| SR-06 | Verified business badge requires moderator approval |
| SR-07 | Images re-encoded and EXIF stripped on upload |
| SR-08 | All user content rendered as plain text |
| SR-09 | Listings show only district/sector, not an exact address |
| SR-10 | All traffic over TLS 1.2+ |
| SR-11 | Rate limits on sign-up, OTP, listings, messages, search |
| SR-12 | Security events logged in append-only audit log, kept ≥ 1 year |
| SR-13 | Daily backups; restore tested quarterly |

## Responsible disclosure

This project follows coordinated vulnerability disclosure.
We ask that you give us a reasonable time to fix an issue before making it
public. We will credit you in the release notes if you wish.
