# STRIDE Threat Model: Zero-Trust Access Control Platform (ZTACP)

**System Reference**: `ZTACP-THREAT-001`  
**Classification**: TLP:CLEAR / Production Security Architecture  
**Standard**: Microsoft STRIDE Threat Modeling Methodology / NIST SP 800-207  

---

## 1. System Scope & Boundaries
The Zero-Trust Access Control Platform mediates every enterprise access request. The trust perimeter is eliminated: all components, clients, networks, and storage media are treated as untrusted until proven otherwise.

---

## 2. Threat Analysis by Category

### S - Spoofing (Identity & Telemetry Impersonation)
- **Threat Vector 1**: Adversary crafts falsified device posture telemetry (e.g. claims disk is encrypted and EDR is running when it is not).
  - *Mitigation*: Cryptographic device fingerprinting with client TLS certificate thumbprint binding and hardware-derived hashes; continuous validation against endpoint fleet management records.
- **Threat Vector 2**: Adversary generates forged access tokens purporting to originate from PEP.
  - *Mitigation*: HMAC-SHA256 signatures with 256-bit entropy keys (`jwt_secret_key`); constant-time verification defeating signature forgery.

### T - Tampering (Data Manipulation in Transit and At Rest)
- **Threat Vector 1**: In-flight tampering of claims between PEP and PDP.
  - *Mitigation*: Mutual TLS (mTLS) network enforcement and strictly immutable Pydantic schemas (`frozen=True`, `extra="forbid"`).
- **Threat Vector 2**: Database tampering of policy rules or active sessions.
  - *Mitigation*: SQLite WAL journal mode with parameterized SQL queries preventing SQL injection; strict file permissions on database file.

### R - Repudiation (Disavowal of Privileged Operations)
- **Threat Vector 1**: Privileged administrator denies revoking an active session or altering an ABAC policy rule.
  - *Mitigation*: Immutable, append-only `audit_events` and `access_evaluations` tables recording UTC timestamps, actor IDs, request IDs, and before/after details.

### I - Information Disclosure (PII and Sensitive Attribute Leakage)
- **Threat Vector 1**: Detailed policy decision errors leaking internal infrastructure details or employee clearance levels.
  - *Mitigation*: Non-leaking generic HTTP 403 Forbidden responses to untrusted clients; verbose diagnostic reasons restricted to authenticated audit logs.
- **Threat Vector 2**: Secret key leakage via environment dumps or exception traces.
  - *Mitigation*: Pydantic Settings masking; strict `.gitignore` preventing `.env` and SQLite database commits.

### D - Denial of Service (Availability Depletion)
- **Threat Vector 1**: High-frequency evaluation requests exhausting PDP resources.
  - *Mitigation*: Fast in-memory policy lookup ordered by priority; SQLite connection pooling with WAL mode enabling concurrent read transactions without lock contention.
- **Threat Vector 2**: Memory exhaustion via uncontrolled active session accumulation.
  - *Mitigation*: Ephemeral token TTLs (default 15 minutes) with automatic expiration and indexed database queries.

### E - Elevation of Privilege (Unauthorized Access Expansion)
- **Threat Vector 1**: Stolen valid session token used from an unauthorized attacker endpoint (Pass-the-Cookie / Token Exfiltration).
  - *Mitigation*: Cryptographic device binding (`dfp` claim embedded into token). If a token is presented from an endpoint whose hardware hash does not match, PEP immediately drops the request.
- **Threat Vector 2**: Policy misconfiguration allowing unexpected role bypass.
  - *Mitigation*: Strict Default-Deny rule hierarchy. If no explicit policy matches subject roles, department, and device conditions, the request is definitively denied.
