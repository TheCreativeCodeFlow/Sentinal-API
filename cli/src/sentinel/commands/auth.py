"""
Authentication and Audit commands for Sentinel CLI.
"""

from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.output import Formatter


@click.group(name="auth")
def auth_group():
    """Verify credentials, inspect tokens, and view security audits."""
    pass


@auth_group.command(name="verify")
@click.pass_obj
def verify_auth(ctx_obj):
    """Verify the active authentication token against SentinelAPI."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        result = client.verify_auth()

    user = result.get("user") or {}
    pairs = [
        ("Authenticated", result.get("authenticated")),
        ("Development Bypass", result.get("is_development_bypass")),
        ("User ID", user.get("id") or "-"),
        ("Email", user.get("email") or "-"),
        ("Display Name", user.get("display_name") or "-"),
        ("Token ID", result.get("token_id") or "-"),
        ("Token Name", result.get("token_name") or "-"),
        ("Expires At", result.get("expires_at") or "-"),
    ]
    formatter.print_key_values("SentinelAPI Authentication Verification", pairs, data_for_json=result)


@auth_group.command(name="token-status")
@click.pass_obj
def token_status(ctx_obj):
    """Inspect expiration and validity of active API token."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        status_info = client.get_token_status()

    pairs = [
        ("Valid", status_info.get("valid")),
        ("Status", status_info.get("status")),
        ("Token Name", status_info.get("token_name") or "-"),
        ("User ID", status_info.get("user_id") or "-"),
        ("Expires At", status_info.get("expires_at") or "Never"),
        ("Last Used At", status_info.get("last_used_at") or "-"),
        ("Days Until Expiration", status_info.get("days_until_expiration") if status_info.get("days_until_expiration") is not None else "-"),
    ]
    formatter.print_key_values("API Token Status", pairs, data_for_json=status_info)


@auth_group.command(name="audit")
@click.option("--project", "-p", "project_id", type=int, default=None, help="Filter by project ID")
@click.option("--type", "-t", "event_type", default=None, help="Filter by event type (e.g. AUTH, SCAN, RBAC)")
@click.option("--action", "-a", default=None, help="Filter by action (e.g. CREATE, EXECUTE, REVOKE)")
@click.option("--outcome", "-o", default=None, help="Filter by outcome (e.g. SUCCESS, DENIED)")
@click.option("--limit", "-l", default=50, type=int, help="Maximum events to return")
@click.pass_obj
def list_audit(ctx_obj, project_id: Optional[int], event_type: Optional[str], action: Optional[str], outcome: Optional[str], limit: int):
    """View immutable security audit log events."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    resolved_project_id = project_id or config.project_id

    with SentinelClient(config) as client:
        events = client.list_audit_events(
            project_id=resolved_project_id,
            event_type=event_type,
            action=action,
            outcome=outcome,
            limit=limit,
        )

    headers = ["ID", "Timestamp", "Type", "Action", "Outcome", "Actor", "Resource"]
    rows = [
        [
            ev.get("id", "")[:8],
            ev.get("created_at"),
            ev.get("event_type"),
            ev.get("action"),
            ev.get("outcome"),
            ev.get("actor_email") or ev.get("actor_user_id") or "system",
            f"{ev.get('resource_type')}:{ev.get('resource_id') or '-'}",
        ]
        for ev in events
    ]
    formatter.print_table(headers, rows, data_for_json=events)
