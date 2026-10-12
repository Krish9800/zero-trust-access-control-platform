# Zero-Trust Access Control Platform (ZTACP)

[![CI Quality Gate](https://github.com/cybersecurity-engineering/zero-trust-access-control-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersecurity-engineering/zero-trust-access-control-platform/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/architecture-NIST%20SP%20800--207-orange.svg)](https://csrc.nist.gov/pubs/sp/800/207/final)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade, contextual **Zero-Trust Access Control Platform (ZTACP)** built strictly adhering to **NIST SP 800-207 Zero Trust Architecture**.

Eliminates implicit trust perimeters by implementing continuous contextual authentication and authorization, dynamic multi-factor trust scoring, cryptographic device-bound session tokens, and instant real-time session revocation.

---

## Key Architectural Capabilities

- **NIST SP 800-207 Compliant Core**: Decoupled Policy Decision Point (PDP) and Policy Enforcement Point (PEP) architecture.
- **Dynamic Trust Calculation Engine**: Computes continuous real-time trust scores (0.0 - 100.0) weighted across device health, authentication assurance, network threat zone, and access behavior.
- **Granular ABAC + RBAC Rule Engine**: Evaluates access requests with priority sorting, default-deny enforcement, and step-up (`REQUIRE_MFA`, `STEP_UP`) directives.
- **Cryptographic Device-Bound Ephemeral Tokens**: HMAC-SHA256 tokens cryptographically bound to hardware fingerprints, defeating token exfiltration and Pass-the-Cookie attacks.
- **Continuous Posture Monitoring & Instant Revocation**: Real-time session tracker that detects endpoint telemetry degradation (e.g. killed EDR, disabled encryption, Tor exit node shift) and revokes access immediately.
- **SQLite WAL Persistence**: Embedded, ACID-compliant persistence operating in Write-Ahead Logging (WAL) mode for audit trails, active sessions, and policy registry.
- **FastAPI Control Plane**: Production-grade async REST API with automated OpenAPI specifications.
- **Typer & Rich Operator CLI**: Command-line administrative tooling (`ztac eval`, `ztac sessions`, `ztac revoke`, `ztac policies`).
- **Rootless Docker Hardening**: Multi-stage minimal container running as unprivileged user `UID 10001` with `cap_drop: ALL` and read-only root filesystems.

---

## Quick Start

### 1. Local Setup
```bash
# Clone and enter directory
cd zero-trust-access-control-platform

# Create virtual environment and install package
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Run Quality Gates & Tests
```bash
# Code formatting and linting
ruff format --check src tests
ruff check src tests

# Strict type safety
mypy src tests

# SAST security vulnerability audit
bandit -r src/

# Test suite with >= 90% branch and line coverage
pytest
```

### 3. Launch Control Plane API
```bash
uvicorn zero_trust.api.app:create_app --factory --host 0.0.0.0 --port 8000
```
Visit API Documentation at `http://localhost:8000/docs`.

### 4. Use Operator CLI
```bash
# Evaluate an access request simulation
ztac eval --subject "alice@corp.example" --roles "engineer" --resource "/api/v1/vault"

# List configured zero-trust policies
ztac policies

# List active sessions
ztac sessions

# Revoke a session immediately
ztac revoke "<session-id>" --reason "Quarantine endpoint"
```

---

## Security & Threat Modeling
See comprehensive [STRIDE Threat Model](docs/threat_model.md) for detailed analysis of attack vectors, mitigations, and cryptographic boundaries.
