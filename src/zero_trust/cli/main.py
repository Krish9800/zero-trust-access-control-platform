"""Zero-Trust Access Control Platform Operator CLI.

Provides command-line interfaces for:
- Evaluating access requests interactively (`ztac eval`)
- Listing active sessions (`ztac sessions`)
- Revoking active sessions (`ztac revoke`)
- Listing configured policies (`ztac policies`)
"""

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from zero_trust.api.app import ControlPlaneState
from zero_trust.config.settings import Settings
from zero_trust.models.enums import (
    AccessDecision,
    AuthenticationStrength,
    DeviceHealthStatus,
    NetworkZone,
    SensitivityLevel,
)
from zero_trust.models.schemas import (
    AccessRequest,
    DeviceContext,
    NetworkContext,
    ResourceContext,
    SubjectContext,
)

app = typer.Typer(
    name="ztac",
    help="Zero-Trust Access Control Platform (ZTACP) Administration CLI",
    add_completion=False,
)
console = Console()


def get_cli_state() -> ControlPlaneState:
    """Instantiate standard ControlPlaneState for CLI operations."""
    return ControlPlaneState(settings=Settings())


@app.command("eval")
def eval_access(
    subject_id: Annotated[
        str, typer.Option("--subject", "-s", help="Subject identity identifier")
    ] = "admin@corp.example",
    roles: Annotated[
        str, typer.Option("--roles", "-r", help="Comma-separated subject roles")
    ] = "employee",
    resource_id: Annotated[
        str, typer.Option("--resource", help="Target resource URI")
    ] = "/api/v1/data",
    sensitivity: Annotated[
        str, typer.Option("--sensitivity", help="Sensitivity level (LOW, MEDIUM, HIGH, CRITICAL)")
    ] = "MEDIUM",
    disk_encrypted: Annotated[
        bool, typer.Option("--encrypted/--unencrypted", help="Endpoint disk encryption status")
    ] = True,
    edr_active: Annotated[
        bool, typer.Option("--edr/--no-edr", help="Endpoint EDR active status")
    ] = True,
    network_zone: Annotated[
        str,
        typer.Option(
            "--zone",
            help="Network zone (e.g. CORPORATE_MANAGED, PUBLIC_INTERNET)",
        ),
    ] = "CORPORATE_MANAGED",
) -> None:
    """Simulate and evaluate a zero-trust access request through PDP."""
    state = get_cli_state()

    role_list = [r.strip() for r in roles.split(",") if r.strip()]
    req = AccessRequest(
        subject=SubjectContext(
            subject_id=subject_id,
            roles=role_list,
            auth_strength=AuthenticationStrength.FIDO2_HARDWARE_KEY,
        ),
        device=DeviceContext(
            device_id="CLI-SIMULATED-DEV",
            os_name="Linux",
            os_version="6.8.0",
            disk_encrypted=disk_encrypted,
            edr_active=edr_active,
            health_status=DeviceHealthStatus.HEALTHY,
            fingerprint_hash="sha256:0123456789abcdef0123456789abcdef",
        ),
        network=NetworkContext(
            ip_address="10.0.0.1",
            network_zone=NetworkZone(network_zone),
        ),
        resource=ResourceContext(
            resource_id=resource_id,
            resource_type="api",
            action="read",
            sensitivity_level=SensitivityLevel(sensitivity),
        ),
    )

    result = state.pep.intercept_request(req)

    # Output styled summary table
    table = Table(title="[bold cyan]Zero-Trust Access Evaluation Result[/bold cyan]")
    table.add_column("Field", style="bold yellow")
    table.add_column("Value", style="white")

    color_map = {
        AccessDecision.ALLOW: "[bold green]ALLOW[/bold green]",
        AccessDecision.DENY: "[bold red]DENY[/bold red]",
        AccessDecision.REQUIRE_MFA: "[bold yellow]REQUIRE_MFA[/bold yellow]",
        AccessDecision.STEP_UP: "[bold magenta]STEP_UP[/bold magenta]",
    }

    table.add_row("Evaluation ID", result.evaluation_id)
    table.add_row("Decision", color_map.get(result.decision, result.decision.value))
    table.add_row("Trust Score", f"{result.trust_score.total_score:.2f} / 100.0")
    table.add_row("Matched Policy", result.matched_policy_id or "None (Default)")
    table.add_row("Token Issued", "YES" if result.session_token else "NO")

    console.print(table)
    if result.reasons:
        console.print("\n[bold]Decision Reasons:[/bold]")
        for r in result.reasons:
            console.print(f" - {r}")


@app.command("sessions")
def list_sessions(
    all_sessions: Annotated[
        bool, typer.Option("--all", "-a", help="Include revoked sessions")
    ] = False,
) -> None:
    """List active and historical access sessions."""
    state = get_cli_state()
    sessions = state.db.list_sessions(active_only=not all_sessions)

    table = Table(title="[bold cyan]Zero-Trust Sessions[/bold cyan]")
    table.add_column("Session ID", style="dim")
    table.add_column("Subject ID", style="bold")
    table.add_column("Resource", style="green")
    table.add_column("Network Zone", style="blue")
    table.add_column("Status", style="yellow")

    for s in sessions:
        status_text = "[red]REVOKED[/red]" if s.is_revoked else "[green]ACTIVE[/green]"
        table.add_row(
            s.session_id[:8] + "...",
            s.subject_id,
            s.resource_id,
            s.network_zone.value,
            status_text,
        )

    console.print(table)


@app.command("revoke")
def revoke_session(
    session_id: Annotated[str, typer.Argument(help="UUID of session to revoke")],
    reason: Annotated[
        str, typer.Option("--reason", "-r", help="Reason for revocation")
    ] = "Administrative manual termination",
) -> None:
    """Instantly revoke an active zero-trust session."""
    state = get_cli_state()
    db_session = state.db.get_session(session_id)
    if not db_session:
        console.print(f"[bold red]Error:[/bold red] Session '{session_id}' not found.")
        raise typer.Exit(code=1)

    state.session_manager.revoke_session(session_id, reason)
    from zero_trust.sessions.manager import ActiveSession

    updated_session = ActiveSession(
        session_id=db_session.session_id,
        subject_id=db_session.subject_id,
        device_id=db_session.device_id,
        device_fingerprint_hash=db_session.device_fingerprint_hash,
        resource_id=db_session.resource_id,
        session_token=db_session.session_token,
        ip_address=db_session.ip_address,
        network_zone=db_session.network_zone,
        is_revoked=True,
        revocation_reason=reason,
        created_at=db_session.created_at,
    )
    state.db.save_session(updated_session)
    console.print(
        f"[bold green]Success:[/bold green] Session '{session_id}' revoked. Reason: {reason}"
    )


@app.command("policies")
def list_policies() -> None:
    """List configured zero-trust policies ordered by evaluation priority."""
    state = get_cli_state()
    policies = state.db.list_policies()

    table = Table(title="[bold cyan]Configured Zero-Trust Policies[/bold cyan]")
    table.add_column("Priority", style="bold yellow")
    table.add_column("Policy ID", style="bold")
    table.add_column("Name", style="white")
    table.add_column("Effect", style="green")
    table.add_column("Min Score", style="magenta")

    for p in policies:
        table.add_row(
            str(p.priority),
            p.policy_id,
            p.name,
            p.effect.value,
            f"{p.min_trust_score:.1f}",
        )

    console.print(table)


if __name__ == "__main__":
    app()
