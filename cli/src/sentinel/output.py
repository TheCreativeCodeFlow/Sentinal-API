"""
Output formatting utilities for Sentinel CLI.
Supports Table, JSON, Quiet, and Progress Bar formatting while ensuring credentials are never exposed.
"""

import json
import sys
from typing import Any, Dict, List, Optional

from sentinel.config import Config


def mask_sensitive(data: Any) -> Any:
    """Recursively mask sensitive credential keys before display."""
    if isinstance(data, dict):
        masked = {}
        for k, v in data.items():
            lower_k = str(k).lower()
            if lower_k in ("authenticated", "authorization_status"):
                masked[k] = mask_sensitive(v)
            elif any(sec in lower_k for sec in ("token", "secret", "password", "apikey", "api_key", "cookie", "authorization")):
                masked[k] = "[REDACTED]"
            elif lower_k in ("auth", "auth_token", "auth_header"):
                masked[k] = "[REDACTED]"
            else:
                masked[k] = mask_sensitive(v)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive(item) for item in data]
    return data


class Formatter:
    """Formats CLI output based on configuration (JSON, Table, Quiet)."""

    def __init__(self, config: Config):
        self.config = config

    def output_json(self, data: Any):
        """Print canonical sanitized JSON to stdout."""
        sanitized = mask_sensitive(data)
        sys.stdout.write(json.dumps(sanitized, indent=2, default=str) + "\n")
        sys.stdout.flush()

    def print_text(self, text: str):
        """Print normal human-readable text unless quiet mode is active."""
        if not self.config.quiet and not self.config.is_json():
            sys.stdout.write(text + "\n")
            sys.stdout.flush()

    def print_error(self, message: str, reason: Optional[str] = None):
        """Print error message to stderr."""
        if self.config.is_json():
            err_dict = {"status": "error", "message": message}
            if reason:
                err_dict["reason"] = reason
            sys.stderr.write(json.dumps(err_dict, indent=2) + "\n")
        else:
            sys.stderr.write(f"\nError: {message}\n")
            if reason:
                sys.stderr.write(f"Reason: {reason}\n")
        sys.stderr.flush()

    def print_table(
        self,
        headers: List[str],
        rows: List[List[Any]],
        data_for_json: Optional[Any] = None,
    ):
        """Render a formatted text table or JSON depending on format."""
        if self.config.is_json():
            self.output_json(data_for_json if data_for_json is not None else rows)
            return

        if self.config.quiet:
            # In quiet mode, print primary identifiers (first column)
            for row in rows:
                if row:
                    sys.stdout.write(f"{row[0]}\n")
            sys.stdout.flush()
            return

        if not rows:
            self.print_text("No records found.")
            return

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                val_str = str(val if val is not None else "")
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(val_str))

        # Build header line
        header_line = "  ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        separator_line = "  ".join("-" * col_widths[i] for i in range(len(headers)))

        self.print_text(header_line)
        self.print_text(separator_line)

        for row in rows:
            row_line = "  ".join(
                str(val if val is not None else "").ljust(col_widths[i])
                for i, val in enumerate(row)
            )
            self.print_text(row_line)

    def print_key_values(self, title: str, pairs: List[tuple], data_for_json: Optional[Any] = None):
        """Render key-value summaries."""
        if self.config.is_json():
            self.output_json(data_for_json if data_for_json is not None else dict(pairs))
            return

        if self.config.quiet:
            return

        self.print_text(f"{title}")
        self.print_text("=" * len(title))
        max_k_len = max((len(k) for k, _ in pairs), default=15)
        for k, v in pairs:
            v_str = str(v if v is not None else "None")
            self.print_text(f"{k.ljust(max_k_len)} : {v_str}")
        self.print_text("")

    def print_progress_bar(
        self,
        completed: int,
        total: int,
        status: str,
        confirmed_findings: int = 0,
        inconclusive: int = 0,
        failed: int = 0,
    ):
        """Render deterministic execution progress bar."""
        if self.config.is_json() or self.config.quiet:
            return

        bar_length = 20
        fraction = (completed / total) if total > 0 else 0
        filled = int(fraction * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        sys.stdout.write(f"\rProgress: [{bar}] {completed}/{total} (Status: {status}) | Findings: {confirmed_findings}  ")
        sys.stdout.flush()
