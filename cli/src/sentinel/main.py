"""
Main entrypoint for Sentinel CLI.
"""

import sys
import click

from sentinel import __version__
from sentinel.commands.gate import gate_group
from sentinel.commands.profile import profile_group
from sentinel.commands.project import project_group
from sentinel.commands.report import report_group
from sentinel.commands.result import result_command
from sentinel.commands.scan import scan_command
from sentinel.commands.schedule import schedule_group
from sentinel.config import Config
from sentinel.errors import EXIT_ERROR, SentinelError
from sentinel.output import Formatter


@click.group()
@click.option("--api-url", envvar="SENTINEL_API_URL", help="SentinelAPI base URL (default: http://localhost:8000)")
@click.option("--token", envvar="SENTINEL_API_TOKEN", help="SentinelAPI authentication token")
@click.option("--project", "project_id", type=int, envvar="SENTINEL_PROJECT_ID", help="Target project ID")
@click.option("--timeout", type=float, envvar="SENTINEL_TIMEOUT", help="Request/polling timeout in seconds (default: 30)")
@click.option("--json", "json_format", is_flag=True, default=False, help="Emit output as JSON")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Minimal console output")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose diagnostic output (never logs credentials)")
@click.version_option(version=__version__, prog_name="sentinel")
@click.pass_context
def cli(ctx, api_url, token, project_id, timeout, json_format, quiet, verbose):
    """
    SentinelAPI CLI — Deterministic API Security Testing & CI/CD Regression Gates.
    """
    output_format = "json" if json_format else "table"
    config = Config.load(
        api_url=api_url,
        token=token,
        project_id=project_id,
        timeout=timeout,
        output_format=output_format,
        quiet=quiet,
        verbose=verbose,
    )
    ctx.obj = {"config": config}


# Register command groups and individual commands
cli.add_command(project_group)
cli.add_command(profile_group)
cli.add_command(scan_command)
cli.add_command(gate_group)
cli.add_command(result_command)
cli.add_command(report_group)
cli.add_command(schedule_group)



def main():
    """CLI execution entrypoint with top-level error handling."""
    try:
        cli(standalone_mode=False)
    except click.ClickException as e:
        e.show()
        sys.exit(e.exit_code)
    except SentinelError as e:
        config = Config.load()
        formatter = Formatter(config)
        formatter.print_error(e.message, e.reason)
        if config.verbose:
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(e.exit_code)
    except KeyboardInterrupt:
        sys.stderr.write("\nOperation aborted by user.\n")
        sys.exit(130)
    except SystemExit as e:
        sys.exit(e.code)
    except Exception as e:
        sys.stderr.write(f"\nUnexpected error: {e}\n")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
