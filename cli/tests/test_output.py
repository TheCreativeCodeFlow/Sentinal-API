"""
Tests for CLI output formatting and credential redaction.
"""

import json
from sentinel.config import Config
from sentinel.output import Formatter, mask_sensitive


def test_mask_sensitive_data():
    """Verify recursive masking of sensitive credential keys."""
    raw_data = {
        "user": "alice",
        "api_key": "raw_secret_api_key_123",
        "password": "secret_password",
        "nested": {
            "token": "bearer_token_xyz",
            "safe_property": "normal_val",
        },
        "list_items": [
            {"cookie": "session=secret_session"},
            {"ok": "fine"},
        ],
    }
    masked = mask_sensitive(raw_data)
    assert masked["api_key"] == "[REDACTED]"
    assert masked["password"] == "[REDACTED]"
    assert masked["nested"]["token"] == "[REDACTED]"
    assert masked["nested"]["safe_property"] == "normal_val"
    assert masked["list_items"][0]["cookie"] == "[REDACTED]"
    assert masked["list_items"][1]["ok"] == "fine"


def test_formatter_table_and_json(capsys):
    """Verify table rendering and JSON rendering."""
    cfg = Config(api_url="http://testserver", output_format="table")
    formatter = Formatter(cfg)

    headers = ["ID", "Name", "Status"]
    rows = [["1", "Alice", "Active"], ["2", "Bob", "Disabled"]]
    formatter.print_table(headers, rows)

    captured = capsys.readouterr()
    assert "ID" in captured.out
    assert "Alice" in captured.out
    assert "Bob" in captured.out

    # JSON mode
    cfg_json = Config(api_url="http://testserver", output_format="json")
    formatter_json = Formatter(cfg_json)
    formatter_json.output_json({"secret_key": "12345", "name": "Project"})
    captured_json = capsys.readouterr()
    parsed = json.loads(captured_json.out)
    assert parsed["secret_key"] == "[REDACTED]"
    assert parsed["name"] == "Project"


def test_formatter_quiet_mode(capsys):
    """Verify quiet mode suppresses unnecessary decoration."""
    cfg_quiet = Config(api_url="http://testserver", quiet=True)
    formatter_quiet = Formatter(cfg_quiet)

    formatter_quiet.print_text("Some decorative text")
    headers = ["ID", "Name"]
    rows = [["id-100", "Prod API"], ["id-200", "Dev API"]]
    formatter_quiet.print_table(headers, rows)

    captured = capsys.readouterr()
    # In quiet mode, print_text is suppressed and table only outputs IDs
    assert "Some decorative text" not in captured.out
    assert "id-100\n" in captured.out
    assert "id-200\n" in captured.out
