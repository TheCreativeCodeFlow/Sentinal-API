"""
Report commands for Sentinel CLI.
Retrieves immutable report snapshots, manifests, and evidence packages without local modifications.
"""

from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import ConfigurationError
from sentinel.output import Formatter


@click.group(name="report")
def report_group():
    """Retrieve and inspect immutable security reports and evidence packages."""
    pass


@report_group.command(name="list")
@click.option("--project", "project_opt", type=int, help="Project ID override")
@click.pass_obj
def list_reports(ctx_obj, project_opt: Optional[int]):
    """List all security reports for a project."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    proj_id = project_opt or config.project_id
    if not proj_id:
        raise ConfigurationError(
            "Project ID required to list security reports.",
            reason="Provide --project <id> or set SENTINEL_PROJECT_ID.",
        )

    with SentinelClient(config) as client:
        reports = client.list_reports(proj_id)

    headers = ["ID", "Name", "Type", "Status", "Version", "SHA-256 Checksum"]
    rows = [
        [
            r.get("id"),
            r.get("name"),
            r.get("report_type"),
            r.get("status"),
            f"v{r.get('version', 1)}",
            (r.get("latest_snapshot_checksum") or "-")[:16],
        ]
        for r in reports
    ]
    formatter.print_table(headers, rows, data_for_json=reports)


@report_group.command(name="get")
@click.argument("report_id")
@click.pass_obj
def get_report(ctx_obj, report_id: str):
    """Retrieve metadata for a specific security report."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        report = client.get_report(report_id)

    pairs = [
        ("Report ID", report.get("id")),
        ("Project ID", report.get("project_id")),
        ("Name", report.get("name")),
        ("Type", report.get("report_type")),
        ("Status", report.get("status")),
        ("Version", report.get("version")),
        ("Checksum", report.get("latest_snapshot", {}).get("checksum") if report.get("latest_snapshot") else "-"),
        ("Generated At", report.get("generated_at") or "-"),
        ("Created At", report.get("created_at")),
    ]
    formatter.print_key_values(f"Security Report: {report.get('name')}", pairs, data_for_json=report)


@report_group.command(name="json")
@click.argument("report_id")
@click.option("--version", "ver_opt", type=int, default=None, help="Snapshot version (default: latest)")
@click.pass_obj
def get_report_json(ctx_obj, report_id: str, ver_opt: Optional[int]):
    """Output canonical JSON snapshot of a security report."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        snapshot_json = client.get_report_json(report_id, version=ver_opt)

    formatter.output_json(snapshot_json)


@report_group.command(name="manifest")
@click.argument("report_id")
@click.option("--version", "ver_opt", type=int, default=None, help="Snapshot version (default: latest)")
@click.pass_obj
def get_report_manifest(ctx_obj, report_id: str, ver_opt: Optional[int]):
    """Retrieve the cryptographic manifest of a security report evidence package."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        manifest = client.get_report_manifest(report_id, version=ver_opt)

    if config.is_json():
        formatter.output_json(manifest)
        return

    pairs = [
        ("Report ID", manifest.get("report_id")),
        ("Report Name", manifest.get("report_name")),
        ("Version", manifest.get("version")),
        ("Schema Version", manifest.get("schema_version")),
        ("SHA-256 Checksum", manifest.get("checksum")),
        ("Generated At", manifest.get("generated_at")),
        ("Findings Count", manifest.get("findings_count")),
        ("Evidence Count", manifest.get("evidence_records_count")),
    ]
    formatter.print_key_values(f"Evidence Package Manifest: {manifest.get('report_name')}", pairs, data_for_json=manifest)


@report_group.command(name="package")
@click.argument("report_id")
@click.option("--version", "ver_opt", type=int, default=None, help="Snapshot version (default: latest)")
@click.pass_obj
def get_report_package(ctx_obj, report_id: str, ver_opt: Optional[int]):
    """Output complete structured evidence package JSON."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        package = client.get_report_package(report_id, version=ver_opt)

    formatter.output_json(package)
