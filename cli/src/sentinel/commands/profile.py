"""
Profile commands for Sentinel CLI.
"""

from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import ConfigurationError
from sentinel.output import Formatter


@click.group(name="profile")
def profile_group():
    """List, inspect, and preview scan profiles."""
    pass


@profile_group.command(name="list")
@click.option("--project", "project_opt", type=int, help="Project ID override")
@click.option("--status", type=str, help="Filter by profile status (ACTIVE, DISABLED)")
@click.option("--type", "type_opt", type=str, help="Filter by profile type (QUICK, STANDARD, DEEP, CUSTOM)")
@click.pass_obj
def list_profiles(ctx_obj, project_opt: Optional[int], status: Optional[str], type_opt: Optional[str]):
    """List all scan profiles for a project."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    proj_id = project_opt or config.project_id
    if not proj_id:
        raise ConfigurationError(
            "Project ID required to list scan profiles.",
            reason="Provide --project <id> or set SENTINEL_PROJECT_ID.",
        )

    with SentinelClient(config) as client:
        profiles = client.list_profiles(proj_id, status=status, profile_type=type_opt)

    headers = ["ID", "Name", "Type", "Status", "Description"]
    rows = [
        [
            p.get("id"),
            p.get("name"),
            p.get("profile_type"),
            p.get("status"),
            p.get("description") or "-",
        ]
        for p in profiles
    ]
    formatter.print_table(headers, rows, data_for_json=profiles)


@profile_group.command(name="get")
@click.argument("profile_id")
@click.pass_obj
def get_profile(ctx_obj, profile_id: str):
    """Retrieve details of a specific scan profile."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        profile = client.get_profile(profile_id)

    pairs = [
        ("Profile ID", profile.get("id")),
        ("Project ID", profile.get("project_id")),
        ("Name", profile.get("name")),
        ("Type", profile.get("profile_type")),
        ("Status", profile.get("status")),
        ("Description", profile.get("description") or "-"),
        ("Created At", profile.get("created_at")),
        ("Updated At", profile.get("updated_at")),
    ]
    formatter.print_key_values(f"Scan Profile: {profile.get('name')}", pairs, data_for_json=profile)


@profile_group.command(name="preview")
@click.argument("profile_id")
@click.pass_obj
def preview_profile(ctx_obj, profile_id: str):
    """
    Preview deterministic test selection for a profile without executing target HTTP requests.
    """
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        preview = client.preview_profile(profile_id)

    if config.is_json():
        formatter.output_json(preview)
        return

    if config.quiet:
        sys_out = f"Profile: {preview.get('profile_name')}, Selected: {preview.get('selected_test_count')}\n"
        import sys
        sys.stdout.write(sys_out)
        return

    formatter.print_text(f"Profile: {preview.get('profile_name')}")
    formatter.print_text(f"Type: {preview.get('profile_type')}")
    formatter.print_text(f"Selected Tests: {preview.get('selected_test_count')}\n")

    selected_tests = preview.get("selected_tests") or []
    if not selected_tests:
        formatter.print_text("No tests matched by deterministic selection rules.")
        return

    for t in selected_tests:
        test_type = t.get("test_type", "UNKNOWN")
        endpoint = t.get("endpoint", "")
        reason = t.get("reason", "")
        priority = t.get("priority", "NORMAL")

        formatter.print_text(f"✓ {test_type} [{priority}]")
        if endpoint:
            formatter.print_text(f"  Endpoint: {endpoint}")
        if reason:
            formatter.print_text(f"  {reason}")
        formatter.print_text("")
