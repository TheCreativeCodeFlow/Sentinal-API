# SentinelAPI CI/CD Security Integration Guide

This guide describes how to integrate **SentinelAPI** deterministic security testing and regression gates into automated continuous integration (CI/CD) pipelines.

---

## Architectural Principles

1. **Zero Target HTTP from CI/CD Runners**: The CLI client communicates solely with the SentinelAPI backend REST API over TLS. CI runners never contact target APIs or execute attack exploits directly.
2. **Deterministic Security Gates**: Every pipeline run compares against an approved, immutable `SecurityBaseline`.
3. **Reproducible Exit Codes**:
   - `0`: PASS or WARN (pipeline proceeds)
   - `1`: FAIL (security regression or confirmed finding blocks pipeline)
   - `2`: ERROR (misconfiguration or communication error)

---

## Pipeline Examples

### 1. GitHub Actions

Create `.github/workflows/security-gate.yml`:

```yaml
name: API Security Regression Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install SentinelAPI CLI
        run: |
          pip install -e ./cli

      - name: Run Security Gate
        env:
          SENTINEL_API_URL: ${{ secrets.SENTINEL_API_URL }}
          SENTINEL_API_TOKEN: ${{ secrets.SENTINEL_API_TOKEN }}
          SENTINEL_PROJECT_ID: ${{ vars.SENTINEL_PROJECT_ID }}
        run: |
          # 1. Execute Security Scan using designated ScanProfile
          SCAN_JSON=$(sentinel scan --profile "standard-audit" --wait --json)
          PLAN_ID=$(echo "$SCAN_JSON" | jq -r '.id')
          echo "Completed scan with Execution Plan ID: $PLAN_ID"

          # 2. Evaluate Security Gate against Baseline
          sentinel gate run "production-pr-gate" --execution "$PLAN_ID" --json > gate-result.json
          cat gate-result.json

      - name: Upload Gate Evaluation Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-gate-result
          path: gate-result.json
```

---

### 2. GitLab CI/CD

Add to `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

security_gate:
  stage: security
  image: python:3.11-slim
  variables:
    SENTINEL_API_URL: $SENTINEL_API_URL
    SENTINEL_API_TOKEN: $SENTINEL_API_TOKEN
    SENTINEL_PROJECT_ID: $SENTINEL_PROJECT_ID
  before_script:
    - pip install -e ./cli
    - apt-get update && apt-get install -y jq
  script:
    - SCAN_RESULT=$(sentinel scan --profile "standard-audit" --wait --json)
    - PLAN_ID=$(echo "$SCAN_RESULT" | jq -r '.id')
    - sentinel gate run "production-pr-gate" --execution "$PLAN_ID" --json | tee gate_result.json
  artifacts:
    when: always
    paths:
      - gate_result.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

---

### 3. Jenkins Pipeline

Add to `Jenkinsfile`:

```groovy
pipeline {
    agent any

    environment {
        SENTINEL_API_URL   = credentials('sentinel-api-url')
        SENTINEL_API_TOKEN = credentials('sentinel-api-token')
        SENTINEL_PROJECT_ID = '1'
    }

    stages {
        stage('Security Gate') {
            steps {
                sh '''
                    pip install -e ./cli
                    SCAN_OUT=$(sentinel scan --profile standard-audit --wait --json)
                    PLAN_ID=$(echo "$SCAN_OUT" | jq -r '.id')
                    sentinel gate run production-pr-gate --execution "$PLAN_ID"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json', allowEmptyArchive: true
        }
    }
}
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SENTINEL_API_URL` | Yes | URL of the central SentinelAPI server (e.g. `https://sentinel.internal`) |
| `SENTINEL_API_TOKEN` | Yes | Machine token for CI service account authentication |
| `SENTINEL_PROJECT_ID` | Optional | ID of the target project |
| `SENTINEL_TIMEOUT` | Optional | HTTP and polling timeout threshold (default: 30s) |

---

## Security Considerations

1. **Secret Storage**: Store `SENTINEL_API_TOKEN` in masked CI secrets. Never check credentials into git repositories.
2. **Deterministic Gating**: Baseline comparisons guarantee that only *regressions* and *new violations* block builds, avoiding unexpected flaky pipeline breaks.
3. **Credential Redaction**: All request/response evidence stored in SentinelAPI is sanitized. Raw authorization headers, cookies, and tokens are never returned by the CLI.
