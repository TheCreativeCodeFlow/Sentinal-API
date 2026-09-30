# SentinelAPI CLI (`sentinel`)

A deterministic command-line interface and CI/CD integration client for the **SentinelAPI** Security Testing Platform.

## Architectural Boundary

The CLI is a thin client communicating exclusively via the SentinelAPI REST API. It **never** sends direct requests to target APIs, executes attack payloads locally, or performs security calculations independently.

```text
CLI (sentinel)
      ↓
SentinelAPI REST API
      ↓
Scan Profile
      ↓
Execution Plan
      ↓
TestOrchestrator
      ↓
Deterministic Security Engines
      ↓
Baseline Comparison
      ↓
Security Gate
      ↓
Reports & Evidence Packages
```

---

## Installation

```bash
# From repository root
pip install -e ./cli
```

Verify installation:

```bash
sentinel --version
sentinel --help
```

---

## Configuration

The CLI supports environment variables and command-line flags.

| Flag | Environment Variable | Default | Description |
|---|---|---|---|
| `--api-url` | `SENTINEL_API_URL` | `http://localhost:8000` | SentinelAPI backend URL |
| `--token` | `SENTINEL_API_TOKEN` | `None` | Authentication token |
| `--project` | `SENTINEL_PROJECT_ID` | `None` | Default project ID |
| `--timeout` | `SENTINEL_TIMEOUT` | `30` | Request & polling timeout (sec) |
| `--json` | `SENTINEL_OUTPUT_FORMAT=json` | `table` | Machine-readable JSON output |
| `-q`, `--quiet` | - | `false` | Minimal output mode |
| `-v`, `--verbose` | - | `false` | Verbose diagnostics (never logs tokens) |

**Precedence**: CLI Argument > Environment Variable > Default.

---

## Command Reference

### Projects
```bash
sentinel project list
sentinel project get <project_id>
sentinel project current
```

### Scan Profiles
```bash
sentinel profile list [--project <id>]
sentinel profile get <profile_id>
sentinel profile preview <profile_id>
```

### Security Scans
```bash
# Launch background scan
sentinel scan --profile <profile_id>

# Run scan and wait with deterministic progress bar
sentinel scan --profile <profile_id> --wait --timeout 300

# Run in CI mode with JSON output
sentinel scan --profile <profile_id> --wait --json
```

### Security Gates & CI/CD Evaluation
```bash
# List gates
sentinel gate list [--project <id>]

# Evaluate gate against existing comparison
sentinel gate evaluate <gate_id> --comparison <comparison_id>

# Run complete gate workflow against an execution plan
sentinel gate run <gate_id> --execution <execution_plan_id>
```

### Evaluation Results
```bash
sentinel result <evaluation_id> [--json]
```

### Reports & Evidence Packages
```bash
sentinel report list [--project <id>]
sentinel report get <report_id>
sentinel report json <report_id>
sentinel report manifest <report_id>
sentinel report package <report_id>
```

---

## CI/CD Exit Codes

SentinelAPI CLI strictly guarantees deterministic CI exit codes matching Stage 10.3 / 10.5 standards:

| Verdict / Event | Exit Code | Description |
|---|---|---|
| `PASS` | `0` | All security gate rules satisfied |
| `WARN` | `0` | Non-blocking warning threshold triggered |
| `FAIL` | `1` | Security regression or confirmed finding rule violated |
| `ERROR` | `2` | Evaluation error, missing resource, or cross-project violation |
