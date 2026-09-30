"""
Project commands for Sentinel CLI.
"""

import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import ConfigurationError
from sentinel.output import Formatter


@click.group(name="project")
def project_group():
    """Manage and inspect SentinelAPI projects."""
    pass


@project_group.command(name="list")
@click.pass_obj
def list_projects(ctx_obj):
    """List all accessible projects."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        projects = client.list_projects()

    headers = ["ID", "Name", "Auth Status", "Environment", "Base URL"]
    rows = [
        [
            p.get("id"),
            p.get("name"),
            p.get("authorization_status"),
            p.get("environment"),
            p.get("base_url") or "-",
        ]
        for p in projects
    ]
    formatter.print_table(headers, rows, data_for_json=projects)


@project_group.command(name="get")
@click.argument("project_id", type=int)
@click.pass_obj
def get_project(ctx_obj, project_id: int):
    """Retrieve details for a specific project."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        project = client.get_project(project_id)

    pairs = [
        ("Project ID", project.get("id")),
        ("Name", project.get("name")),
        ("Description", project.get("description") or "-"),
        ("Auth Status", project.get("authorization_status")),
        ("Environment", project.get("environment")),
        ("Base URL", project.get("base_url") or "-"),
        ("Created At", project.get("created_at")),
        ("Updated At", project.get("updated_at")),
    ]
    formatter.print_key_values(f"Project #{project_id}", pairs, data_for_json=project)


@project_group.command(name="current")
@click.pass_obj
def current_project(ctx_obj):
    """Show the currently configured project (from --project or SENTINEL_PROJECT_ID)."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    if not config.project_id:
        raise ConfigurationError(
            "No project configured.",
            reason="Pass --project <id> or set the SENTINEL_PROJECT_ID environment variable.",
        )

    with SentinelClient(config) as client:
        project = client.get_project(config.project_id)

    pairs = [
        ("Active Project ID", project.get("id")),
        ("Name", project.get("name")),
        ("Auth Status", project.get("authorization_status")),
        ("Environment", project.get("environment")),
        ("Base URL", project.get("base_url") or "-"),
    ]
    formatter.print_key_values("Current Configured Project", pairs, data_for_json=project)
