# Security policy

Farewell is software whose users may be at physical risk if a vulnerability is exploited (journalists, dissidents, lawyers under threat). We take security reports seriously and operate under a transparent, time-bound disclosure model.

## Supported versions

| Version | Supported |
|---|---|
| 1.x (when released) | Yes — security fixes for the active major. |
| 0.x (pre-release) | Best-effort for the current `main` only. Pre-1.0 has no stability guarantees. |

Once we cut 2.0, the previous major version receives security fixes for 12 months, then is end-of-lifed.

## Reporting a vulnerability

**Email**: `security@farewell.pro` — please put `[SECURITY]` in the subject line.

**Please include**:
- A clear description of the vulnerability.
- Steps to reproduce (a minimal repo or test case is ideal).
- The affected component (`farewell_format`, `farewell_crypto`, `farewell_license`, CLI, etc.) and version.
- Your assessment of impact (information disclosure / data loss / denial of service / privilege escalation / cryptographic break / ...).
- Whether you intend to publish your own write-up.

**Please do not**:
- Open a public GitHub issue for a security-relevant finding before we have published a fix.
- Test your finding against any vault you do not own.
- Demand bounty before disclosure — see "Bug bounty" below for the policy.

## Our commitments

- **Acknowledge** your report within **5 business days**.
- **Triage** with a preliminary impact assessment within **10 business days**.
- **Fix** critical vulnerabilities within **30 calendar days** of confirmation; high within 60; medium within 90.
- **Coordinate** the public disclosure date with you. We default to **90-day responsible disclosure** from initial report, but we can extend if a fix is complex and we are clearly making progress, or shorten if the bug is being actively exploited in the wild.
- **Credit** you in the security advisory and release notes, unless you prefer to remain anonymous.

## Scope

In scope:

- All code in this repository (`crates/`, `tools/`, `scripts/`, build pipeline).
- The signed, notarized macOS binary distributed from `farewell.pro` (once it ships).
- The license-signing infrastructure described in [CHARTER §9-§10](CHARTER.md) (when it exists).
- The website `farewell.pro` (when it exists).

Out of scope:

- Vulnerabilities in third-party dependencies that we re-use as-is (please report those upstream, e.g. to `libcrux`, `ed25519-dalek`, etc., though we appreciate a heads-up).
- Issues that require physical access to an unlocked vault with the user's cooperation — that's the user's responsibility per our [threat model](THREAT_MODEL.md).
- Issues that require a compromised OS *before* unlock — explicitly out of scope per [THREAT_MODEL §6.1](THREAT_MODEL.md).
- Side-channel attacks requiring specialized hardware beyond what's documented in [THREAT_MODEL §6.3](THREAT_MODEL.md).
- Social engineering targeting users or maintainers.
- Denial of service via vault-file destruction (the user can always delete their own vault).

If you are unsure whether a finding is in scope, send it anyway — we will be honest about our assessment.

## Bug bounty

A formal bug-bounty program will launch with 1.0. Until then, we cannot pay for findings — but we will:

1. Credit you publicly in the advisory and release notes.
2. Add you to a "Hall of Fame" page on `farewell.pro` once it exists.
3. Provide a free Farewell license (any plan — up to Quintet) for life across all major versions.

When the formal program launches, expected brackets are:

| Severity | Range |
|---|---|
| Critical (cryptographic break, sandbox escape, RCE) | €2,000 – €20,000 |
| High (data leak, privilege escalation, auth bypass) | €500 – €3,000 |
| Medium (information disclosure, parser DoS) | €100 – €700 |
| Low (minor info leak, hardening opportunities) | swag / credit |

Exact amounts will be set when the SRL has revenue history. Numbers above are planning estimates, not commitments.

## Cryptographic break disclosure

If you believe you have found a break in any of the cryptographic primitives we use (AES-256-GCM-SIV, Argon2id, BLAKE3, X25519, Ed25519, ML-KEM-1024, ML-DSA-87) or in our composition of them:

- Treat it as critical and reach out immediately.
- We will trigger the **crypto-agility migration procedure** documented in [THREAT_MODEL §12](THREAT_MODEL.md): emergency advisory within 24-72h, migration release with replacement primitives, forced migration deadline per criticality.
- We will be transparent about which primitives are affected and which remain trustworthy.

## What we will not do

- We will not silently patch a security issue and pretend it never happened.
- We will not negotiate to suppress a published advisory.
- We will not implement a backdoor under any circumstance, including under court order. Romanian law allows us to refuse such requests, and the [no-call-home invariant in THREAT_MODEL §5.8](THREAT_MODEL.md) is enforced by macOS sandbox entitlements — we cannot push a "law enforcement update" because we cannot reach your installation in the first place.
- We will not request authentication information ("send me your passphrase to help debug") from any user. If anyone claiming to be from Farewell asks for this, it is fraud.

## Contact

- General security: `security@farewell.pro`
- General inquiries: `hello@farewell.pro`
