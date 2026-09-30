"""
Result command for Sentinel CLI.
Retrieves and displays exact machine-readable SecurityGate CI results.
"""

import sys
import click

from sentinel.client import SentinelClient
from sentinel.config import Config
from sentinel.errors import EXIT_ERROR, EXIT_FAIL, EXIT_PASS
from sentinel.output import Formatter


@click.command(name="result")
@click.argument("evaluation_id")
@click.pass_obj
def result_command(ctx_obj, evaluation_id: str):
    """
    Retrieve machine-readable Security Gate evaluation result.
    """
    config: Config = ctx_obj["config"]
    formatter = Formatter(config)

    with SentinelClient(config) as client:
        ci_result = client.get_evaluation_result(evaluation_id)

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

    formatter.print_text("Security Gate CI Result")
    formatter.print_text("=======================")
    formatter.print_text(f"Evaluation ID : {evaluation_id}")
    formatter.print_text(f"Gate ID       : {ci_result.get('gate_id')}")
    formatter.print_text(f"Status        : {status}")
    formatter.print_text(f"Exit Code     : {exit_code}\n")

    metrics = ci_result.get("metrics") or {}
    formatter.print_text("Metrics:")
    for k, v in metrics.items():
        formatter.print_text(f"  {k.ljust(22)}: {v}")

    sys.exit(exit_code)
