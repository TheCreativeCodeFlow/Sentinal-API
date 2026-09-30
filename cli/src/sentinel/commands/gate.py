"""
Security Gate commands for Sentinel CLI.
Evaluates CI/CD regression gates and returns deterministic exit codes:
PASS = 0, WARN = 0, FAIL = 1, ERROR = 2
"""

import sys
from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import (
    ConfigurationError,
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    EXIT_WARN,
    GateEvaluationError,
)
from sentinel.output import Formatter


@click.group(name="gate")
def gate_group():
    """Evaluate and inspect CI/CD security regression gates."""
    pass


@gate_group.command(name="list")
@click.option("--project", "project_opt", type=int, help="Project ID override")
@click.pass_obj
def list_gates(ctx_obj, project_opt: Optional[int]):
    """List all security gates for a project."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    proj_id = project_opt or config.project_id
    if not proj_id:
        raise ConfigurationError(
            "Project ID required to list security gates.",
            reason="Provide --project <id> or set SENTINEL_PROJECT_ID.",
        )

    with SentinelClient(config) as client:
        gates = client.list_gates(proj_id)

    headers = ["ID", "Name", "Status", "Baseline ID", "Profile ID"]
    rows = [
        [
            g.get("id"),
            g.get("name"),
            g.get("status"),
            g.get("baseline_id"),
            g.get("scan_profile_id"),
        ]
        for g in gates
    ]
    formatter.print_table(headers, rows, data_for_json=gates)


@gate_group.command(name="get")
@click.argument("gate_id")
@click.pass_obj
def get_gate(ctx_obj, gate_id: str):
    """Retrieve details of a specific security gate."""
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        gate = client.get_gate(gate_id)

    pairs = [
        ("Gate ID", gate.get("id")),
        ("Project ID", gate.get("project_id")),
        ("Name", gate.get("name")),
        ("Status", gate.get("status")),
        ("Description", gate.get("description") or "-"),
        ("Baseline ID", gate.get("baseline_id")),
        ("Profile ID", gate.get("scan_profile_id")),
        ("Failure Rules", gate.get("failure_rules")),
        ("Warning Rules", gate.get("warning_rules")),
        ("Created At", gate.get("created_at")),
    ]
    formatter.print_key_values(f"Security Gate: {gate.get('name')}", pairs, data_for_json=gate)


@gate_group.command(name="evaluate")
@click.argument("gate_id")
@click.option("--comparison", "comparison_id", required=True, help="Baseline comparison ID to evaluate")
@click.pass_obj
def evaluate_gate(ctx_obj, gate_id: str, comparison_id: str):
    """
    Evaluate a security gate against an existing baseline comparison.
    """
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        eval_resp = client.evaluate_gate(gate_id=gate_id, comparison_id=comparison_id)
        eval_id = eval_resp.get("id")
        ci_result = client.get_evaluation_result(eval_id)

    _display_and_exit_gate_result(formatter, config, ci_result)


@gate_group.command(name="run")
@click.argument("gate_id")
@click.option("--execution", "execution_plan_id", required=True, help="Completed execution plan ID to evaluate")
@click.pass_obj
def run_gate(ctx_obj, gate_id: str, execution_plan_id: str):
    """
    Execute full security gate flow against an execution plan:
    1. Resolve baseline from gate
    2. Generate deterministic baseline comparison
    3. Evaluate gate rules
    4. Return machine-readable CI verdict and exit code
    """
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        # 1. Fetch gate to discover baseline
        gate = client.get_gate(gate_id)
        baseline_id = gate.get("baseline_id")
        if not baseline_id:
            raise ConfigurationError(
                f"Security gate '{gate_id}' has no associated baseline.",
                reason="Configure a valid baseline_id for this gate.",
            )

        # 2. Generate baseline comparison
        comparison = client.compare_baseline_with_plan(
            baseline_id=baseline_id,
            execution_plan_id=execution_plan_id,
        )
        comparison_id = comparison.get("id")

        # 3. Evaluate security gate
        eval_resp = client.evaluate_gate(gate_id=gate_id, comparison_id=comparison_id)
        eval_id = eval_resp.get("id")

        # 4. Fetch standardized CI result
        ci_result = client.get_evaluation_result(eval_id)

    _display_and_exit_gate_result(formatter, config, ci_result)


def _display_and_exit_gate_result(formatter: Formatter, config: Config, ci_result: dict):
    """Display evaluation results and terminate with deterministic exit code."""
    status = ci_result.get("status", "ERROR").upper()
    exit_code = ci_result.get("exit_code")
    if exit_code is None:
        if status in ("PASS", "WARN"):
            exit_code = EXIT_PASS
        elif status == "FAIL":
            exit_code = EXIT_FAIL
        else:
            exit_code = EXIT_ERROR

    if config.is_json():
        formatter.output_json(ci_result)
        sys.exit(exit_code)

    if config.quiet:
        sys.stdout.write(f"{status}\n")
        sys.stdout.flush()
        sys.exit(exit_code)

    formatter.print_text("Security Gate Evaluation Result")
    formatter.print_text("===============================")
    formatter.print_text(f"Gate ID        : {ci_result.get('gate_id')}")
    formatter.print_text(f"Evaluation ID  : {ci_result.get('evaluation_id')}")
    formatter.print_text(f"Verdict        : {status}")
    formatter.print_text(f"Exit Code      : {exit_code}\n")

    metrics = ci_result.get("metrics") or {}
    formatter.print_text("Metrics:")
    formatter.print_text(f"  Failures          : {metrics.get('failure_count', 0)}")
    formatter.print_text(f"  Warnings          : {metrics.get('warning_count', 0)}")
    formatter.print_text(f"  Confirmed Findings: {metrics.get('confirmed_findings', 0)}")
    formatter.print_text(f"  Regressions       : {metrics.get('regressions', 0)}")
    formatter.print_text(f"  New Violations    : {metrics.get('new_violations', 0)}")
    formatter.print_text(f"  Failed Tests      : {metrics.get('failed_tests', 0)}")

    failures = ci_result.get("failures") or []
    if failures:
        formatter.print_text("\nRule Violations:")
        for f in failures:
            formatter.print_text(f"  ✕ [{f.get('rule_type')}] {f.get('message')}")

    sys.exit(exit_code)
