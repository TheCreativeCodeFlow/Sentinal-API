"""
Scan command for Sentinel CLI.
Coordinates security scans by launching and monitoring execution plans deterministically via backend API.
"""

import sys
import time
from typing import Optional
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import SentinelError, TimeoutError
from sentinel.output import Formatter

TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED", "ERROR"}


@click.command(name="scan")
@click.option("--profile", "profile_id", required=True, help="Scan profile ID to execute")
@click.option("--project", "project_opt", type=int, help="Project ID override")
@click.option(
    "--mode",
    type=click.Choice(["sequential", "fail_fast", "continue_on_failure"], case_sensitive=False),
    default="sequential",
    help="Execution plan mode",
)
@click.option("--wait", is_flag=True, default=False, help="Wait for scan execution to complete")
@click.option("--timeout", "wait_timeout", type=int, default=None, help="Polling timeout in seconds (default: config timeout or 600)")
@click.pass_obj
def scan_command(
    ctx_obj,
    profile_id: str,
    project_opt: Optional[int],
    mode: str,
    wait: bool,
    wait_timeout: Optional[int],
):
    """
    Launch a deterministic security scan using a configured ScanProfile.
    """
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        # 1. Fetch & Validate Profile
        profile = client.get_profile(profile_id)
        if profile.get("status") == "DISABLED":
            raise SentinelError(
                f"Scan profile '{profile.get('name')}' is DISABLED.",
                reason="Disabled profiles cannot create new execution plans.",
            )

        proj_id = project_opt or config.project_id or profile.get("project_id")

        formatter.print_text("SentinelAPI Security Scan")
        formatter.print_text(f"Profile: {profile.get('name')} ({profile.get('profile_type')})")
        formatter.print_text(f"Project ID: {proj_id}")

        # 2. Create Execution Plan
        plan_name = f"Scan: {profile.get('name')}"
        plan = client.create_plan_from_profile(
            profile_id=profile_id,
            name=plan_name,
            execution_mode=mode.upper(),
        )
        plan_id = plan.get("id")
        formatter.print_text(f"Execution Plan Created: {plan_id}")

        # 3. Start Execution Plan
        started_plan = client.start_execution_plan(plan_id)
        status = started_plan.get("status", "RUNNING")
        formatter.print_text(f"Status: {status}\n")

        if not wait:
            if config.is_json():
                formatter.output_json(started_plan)
            else:
                formatter.print_text("Scan launched in background. Use 'sentinel execution' or --wait to track progress.")
                formatter.print_text(f"Execution ID: {plan_id}")
            return

        # 4. Polling with Progress Bar
        effective_timeout = wait_timeout if wait_timeout is not None else max(config.timeout, 600.0)
        start_time = time.time()
        last_progress = None

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed > effective_timeout:
                    sys.stdout.write("\n")
                    raise TimeoutError(
                        message=f"Scan execution exceeded timeout of {effective_timeout}s.",
                        reason="The scan is still running remotely on SentinelAPI backend.",
                    )

                progress = client.get_execution_progress(plan_id)
                last_progress = progress
                curr_status = progress.get("status", "RUNNING")
                total = progress.get("total_tests", 0)
                completed = progress.get("completed_tests", 0)
                confirmed = progress.get("confirmed_findings", 0)
                inconclusive = progress.get("inconclusive_tests", 0)
                failed = progress.get("failed_tests", 0)

                formatter.print_progress_bar(
                    completed=completed,
                    total=total,
                    status=curr_status,
                    confirmed_findings=confirmed,
                    inconclusive=inconclusive,
                    failed=failed,
                )

                if curr_status in TERMINAL_STATUSES:
                    break

                time.sleep(1.5)

        except KeyboardInterrupt:
            sys.stdout.write("\n")
            formatter.print_text("\nPolling interrupted by user. Remote scan execution continues on backend.")
            formatter.print_text(f"Execution ID: {plan_id}")
            return

        sys.stdout.write("\n\n")

        # 5. Completed summary
        final_plan = client.get_execution_plan(plan_id)
        if config.is_json():
            formatter.output_json(final_plan)
            return

        formatter.print_text("Scan completed\n")
        pairs = [
            ("Execution ID", plan_id),
            ("Final Status", final_plan.get("status")),
            ("Total Tests", final_plan.get("total_tests")),
            ("Completed", final_plan.get("completed_tests")),
            ("Confirmed Findings", final_plan.get("confirmed_findings")),
            ("Inconclusive", final_plan.get("inconclusive_tests")),
            ("Failed Tests", final_plan.get("failed_tests")),
        ]
        for k, v in pairs:
            formatter.print_text(f"{k.ljust(20)}: {v}")
