"""
Schedule commands for Sentinel CLI.
Manages and inspects scheduled & continuous security scans.
"""

from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import ConfigurationError
from sentinel.output import Formatter


@click.group(name="schedule")
def schedule_group():
    """Manage and inspect scheduled security scans."""
    pass


@schedule_group.command(name="list")
@click.option("--project", "project_opt", type=int, help="Project ID override")
@click.option("--status", type=str, help="Filter by status (ACTIVE, DISABLED, EXPIRED)")
@click.pass_obj
def list_schedules(ctx_obj, project_opt: Optional[int], status: Optional[str]):
    """List scan schedules for a project."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    proj_id = project_opt or config.project_id
    if not proj_id:
        raise ConfigurationError(
            "Project ID required to list security scan schedules.",
            reason="Provide --project <id> or set SENTINEL_PROJECT_ID.",
        )

    with SentinelClient(config) as client:
        schedules = client.list_schedules(proj_id, status=status)

    headers = ["ID", "Name", "Status", "Type", "Timezone", "Next Run (UTC)", "Profile ID"]
    rows = [
        [
            s.get("id"),
            s.get("name"),
            s.get("status"),
            s.get("schedule_type"),
            s.get("timezone"),
            s.get("next_run_at") or "-",
            s.get("scan_profile_id"),
        ]
        for s in schedules
    ]
    formatter.print_table(headers, rows, data_for_json=schedules)


@schedule_group.command(name="get")
@click.argument("schedule_id")
@click.pass_obj
def get_schedule(ctx_obj, schedule_id: str):
    """Retrieve details for a specific security scan schedule."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        schedule = client.get_schedule(schedule_id)

    pairs = [
        ("Schedule ID", schedule.get("id")),
        ("Project ID", schedule.get("project_id")),
        ("Name", schedule.get("name")),
        ("Description", schedule.get("description") or "-"),
        ("Status", schedule.get("status")),
        ("Schedule Type", schedule.get("schedule_type")),
        ("Timezone", schedule.get("timezone")),
        ("Cron Expression", schedule.get("cron_expression") or "-"),
        ("Next Run (UTC)", schedule.get("next_run_at") or "-"),
        ("Last Run (UTC)", schedule.get("last_run_at") or "-"),
        ("Scan Profile ID", schedule.get("scan_profile_id")),
        ("Security Gate ID", schedule.get("security_gate_id") or "-"),
        ("Max Concurrent Runs", schedule.get("max_concurrent_runs")),
        ("Timeout Seconds", schedule.get("timeout_seconds")),
        ("Created At", schedule.get("created_at")),
    ]
    formatter.print_key_values(f"Scan Schedule: {schedule.get('name')}", pairs, data_for_json=schedule)


@schedule_group.command(name="preview")
@click.argument("schedule_id")
@click.option("--count", type=int, default=5, help="Number of upcoming occurrences to preview")
@click.pass_obj
def preview_schedule(ctx_obj, schedule_id: str, count: int):
    """Preview next run times for a scan schedule without running tests."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        preview = client.preview_schedule(schedule_id, count=count)

    occurrences = preview.get("next_occurrences", [])
    headers = ["#", "Scheduled Run Time (UTC)"]
    rows = [[str(idx + 1), str(occ)] for idx, occ in enumerate(occurrences)]

    formatter.print_table(headers, rows, data_for_json=preview)


@schedule_group.command(name="run")
@click.argument("schedule_id")
@click.pass_obj
def run_schedule(ctx_obj, schedule_id: str):
    """Trigger an immediate manual execution of a scan schedule."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        execution = client.run_schedule(schedule_id)

    pairs = [
        ("Execution ID", execution.get("id")),
        ("Schedule ID", execution.get("schedule_id")),
        ("Status", execution.get("status")),
        ("Trigger Type", execution.get("trigger_type")),
        ("Execution Plan ID", execution.get("execution_plan_id") or "-"),
        ("Gate Evaluation ID", execution.get("gate_evaluation_id") or "-"),
        ("Report ID", execution.get("report_id") or "-"),
        ("Started At", execution.get("started_at") or "-"),
        ("Completed At", execution.get("completed_at") or "-"),
        ("Error Message", execution.get("error_message") or "-"),
    ]
    formatter.print_key_values("Triggered Scheduled Execution", pairs, data_for_json=execution)


@schedule_group.command(name="enable")
@click.argument("schedule_id")
@click.pass_obj
def enable_schedule(ctx_obj, schedule_id: str):
    """Enable an inactive security scan schedule."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        schedule = client.enable_schedule(schedule_id)

    pairs = [
        ("Schedule ID", schedule.get("id")),
        ("Name", schedule.get("name")),
        ("Status", schedule.get("status")),
        ("Next Run (UTC)", schedule.get("next_run_at") or "-"),
    ]
    formatter.print_key_values("Enabled Scan Schedule", pairs, data_for_json=schedule)


@schedule_group.command(name="disable")
@click.argument("schedule_id")
@click.pass_obj
def disable_schedule(ctx_obj, schedule_id: str):
    """Disable an active security scan schedule."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        schedule = client.disable_schedule(schedule_id)

    pairs = [
        ("Schedule ID", schedule.get("id")),
        ("Name", schedule.get("name")),
        ("Status", schedule.get("status")),
        ("Next Run (UTC)", schedule.get("next_run_at") or "-"),
    ]
    formatter.print_key_values("Disabled Scan Schedule", pairs, data_for_json=schedule)


@schedule_group.command(name="executions")
@click.argument("schedule_id")
@click.option("--limit", type=int, default=50, help="Maximum number of executions to return")
@click.pass_obj
def list_executions(ctx_obj, schedule_id: str, limit: int):
    """List execution history for a security scan schedule."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        executions = client.list_scheduled_executions(schedule_id=schedule_id, limit=limit)

    headers = ["Execution ID", "Status", "Trigger", "Plan ID", "Gate Verdict", "Started At"]
    rows = [
        [
            e.get("id"),
            e.get("status"),
            e.get("trigger_type"),
            e.get("execution_plan_id") or "-",
            e.get("gate_verdict") or "-",
            e.get("started_at") or "-",
        ]
        for e in executions
    ]
    formatter.print_table(headers, rows, data_for_json=executions)
