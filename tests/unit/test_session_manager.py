"""Unit tests for Phase 6: Continuous Session Monitor & Real-Time Revocation."""

import pytest

from zero_trust.models.enums import DeviceHealthStatus, NetworkZone
from zero_trust.models.schemas import DeviceContext, NetworkContext
from zero_trust.sessions.manager import SessionManager


@pytest.fixture
def session_mgr() -> SessionManager:
    """Fixture returning an initialized SessionManager."""
    return SessionManager()


def create_healthy_device(
    fingerprint: str = "sha256:0123456789abcdef0123456789abcdef",
) -> DeviceContext:
    """Helper to return a compliant endpoint context."""
    return DeviceContext(
        device_id="DEV-100",
        os_name="macOS",
        os_version="14.5",
        disk_encrypted=True,
        edr_active=True,
        is_jailbroken=False,
        health_status=DeviceHealthStatus.HEALTHY,
        fingerprint_hash=fingerprint,
    )


def create_clean_network() -> NetworkContext:
    """Helper to return a clean corporate network context."""
    return NetworkContext(
        ip_address="10.0.10.15",
        network_zone=NetworkZone.CORPORATE_MANAGED,
        is_vpn_or_proxy=False,
    )


def test_session_registration_and_retrieval(session_mgr: SessionManager) -> None:
    """Verify session registration and retrieval."""
    session = session_mgr.register_session(
        subject_id="alice@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/db/prod",
        session_token="token-value-sample",
        ip_address="10.0.10.15",
    )
    assert session.subject_id == "alice@corp.example"
    assert session.is_revoked is False

    retrieved = session_mgr.get_session(session.session_id)
    assert retrieved is not None
    assert retrieved.session_id == session.session_id

    active_list = session_mgr.list_active_sessions()
    assert len(active_list) == 1


def test_manual_session_revocation(session_mgr: SessionManager) -> None:
    """Verify manual administrative session termination."""
    session = session_mgr.register_session(
        subject_id="bob@corp.example",
        device_id="DEV-200",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/v1/admin",
        session_token="token-sample",
        ip_address="10.0.10.20",
    )
    revoked = session_mgr.revoke_session(session.session_id, "Admin triggered incident quarantine")
    assert revoked is True

    # Check state
    s = session_mgr.get_session(session.session_id)
    assert s is not None
    assert s.is_revoked is True
    assert "quarantine" in (s.revocation_reason or "")
    assert len(session_mgr.list_active_sessions()) == 0

    # Revoking already revoked returns False
    assert session_mgr.revoke_session(session.session_id, "duplicate") is False


def test_continuous_verification_success(session_mgr: SessionManager) -> None:
    """Verify continuous verification succeeds when device remains compliant."""
    session = session_mgr.register_session(
        subject_id="charlie@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/docs",
        session_token="token-charlie",
        ip_address="10.0.10.15",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        create_healthy_device("sha256:0123456789abcdef0123456789abcdef"),
        create_clean_network(),
    )
    assert valid is True
    assert reason is None


def test_continuous_verification_revokes_on_edr_killed(
    session_mgr: SessionManager,
) -> None:
    """Verify instant session termination if EDR agent is stopped midway."""
    session = session_mgr.register_session(
        subject_id="dave@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/secrets",
        session_token="token-dave",
        ip_address="10.0.10.15",
    )
    degraded_device = DeviceContext(
        device_id="DEV-100",
        os_name="macOS",
        os_version="14.5",
        disk_encrypted=True,
        edr_active=False,  # EDR disabled!
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        degraded_device,
        create_clean_network(),
    )
    assert valid is False
    assert "EDR agent terminated" in (reason or "")
    # Verify session is marked revoked
    assert session_mgr.get_session(session.session_id).is_revoked is True  # type: ignore[union-attr]


def test_continuous_verification_revokes_on_disk_unencrypted(
    session_mgr: SessionManager,
) -> None:
    """Verify session termination if disk encryption is turned off."""
    session = session_mgr.register_session(
        subject_id="user@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/docs",
        session_token="token-unenc",
        ip_address="10.0.10.15",
    )
    unenc_device = DeviceContext(
        device_id="DEV-100",
        os_name="macOS",
        os_version="14.5",
        disk_encrypted=False,  # Unencrypted!
        edr_active=True,
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        unenc_device,
        create_clean_network(),
    )
    assert valid is False
    assert "Disk encryption disabled" in (reason or "")


def test_continuous_verification_revokes_on_jailbreak_or_compromise(
    session_mgr: SessionManager,
) -> None:
    """Verify session termination on jailbreak or compromised status."""
    session = session_mgr.register_session(
        subject_id="jb@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/docs",
        session_token="token-jb",
        ip_address="10.0.10.15",
    )
    jb_device = DeviceContext(
        device_id="DEV-100",
        os_name="macOS",
        os_version="14.5",
        disk_encrypted=True,
        edr_active=True,
        is_jailbroken=True,
        fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        jb_device,
        create_clean_network(),
    )
    assert valid is False
    assert "jailbreak" in (reason or "")

    # Non-existent session
    val_none, r_none = session_mgr.continuous_verify_posture(
        "non-existent-id",
        jb_device,
        create_clean_network(),
    )
    assert val_none is False
    assert "does not exist" in (r_none or "")


def test_continuous_verification_revokes_on_tor_proxy_shift(
    session_mgr: SessionManager,
) -> None:
    """Verify session termination if user shifts to Tor / proxy network."""
    session = session_mgr.register_session(
        subject_id="eve@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/data",
        session_token="token-eve",
        ip_address="10.0.10.15",
    )
    proxy_network = NetworkContext(
        ip_address="198.51.100.4",
        network_zone=NetworkZone.UNTRUSTED_ANONYMIZED,
        is_vpn_or_proxy=True,
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        create_healthy_device("sha256:0123456789abcdef0123456789abcdef"),
        proxy_network,
    )
    assert valid is False
    assert "untrusted anonymizer" in (reason or "")


def test_continuous_verification_fingerprint_mismatch(
    session_mgr: SessionManager,
) -> None:
    """Verify session termination on hardware fingerprint mismatch."""
    session = session_mgr.register_session(
        subject_id="frank@corp.example",
        device_id="DEV-100",
        device_fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        resource_id="/api/data",
        session_token="token-frank",
        ip_address="10.0.10.15",
    )
    valid, reason = session_mgr.continuous_verify_posture(
        session.session_id,
        create_healthy_device("sha256:rogue-different-fingerprint-999999"),
        create_clean_network(),
    )
    assert valid is False
    assert "fingerprint mismatch" in (reason or "")
