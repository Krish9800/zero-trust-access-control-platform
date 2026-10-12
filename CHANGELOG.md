# Changelog

All notable changes to the Zero-Trust Access Control Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- **Foundation & Settings**: Dynamic environment-driven configuration using Pydantic Settings, cryptographic secrets management, and default NIST SP 800-207 risk weights.
- **Context Schemas & Enums**: Strictly validated domain models for `SubjectContext`, `DeviceContext`, `NetworkContext`, `ResourceContext`, `AccessRequest`, and `ZeroTrustPolicy`.
- **Dynamic Trust Engine**: Context-aware dynamic scoring computing composite trust scores (0.0 - 100.0) based on endpoint encryption, EDR status, auth factor strength, and network risk.
- **Policy Decision Point (PDP)**: Granular ABAC + RBAC evaluation engine with priority ordering, default-deny enforcement, and step-up authentication challenge logic.
- **Policy Enforcement Point (PEP)**: Reverse-proxy gateway interceptor with ephemeral HMAC-SHA256 signed access tokens bound to device hardware fingerprints.
- **Continuous Session Monitor**: Real-time session tracker detecting endpoint posture degradation (e.g. killed EDR or disk unencryption) and triggering instant revocation.
- **SQLite WAL Persistence**: Acid-compliant persistence engine using SQLite WAL mode for policies, audit trails, active sessions, and security events.
- **FastAPI Control Plane**: REST API endpoints for `/health`, `/api/v1/access/evaluate`, `/api/v1/sessions`, and `/api/v1/policies`.
- **Typer Administration CLI**: Interactive CLI (`ztac`) supporting `eval`, `sessions`, `revoke`, and `policies` commands with Rich terminal formatting.
- **Rootless Containerization**: Production multi-stage Dockerfile running as non-root UID 10001 with dropped Linux capabilities (`cap_drop: ALL`).
- **Adversarial Testbed**: Rigorous security tests validating defense against forged posture claims, pass-the-cookie token theft, and extreme score boundaries.
