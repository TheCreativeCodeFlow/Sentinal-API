# SentinelAPI — Authoritative API Security Matrix

This document provides the complete, authoritative security classification of all API endpoints across the SentinelAPI control plane and security services.

## AI Security Reasoning (14 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/ai/analyses/{analysis_id}` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/ai/hypotheses/{hypothesis_id}` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/ai/hypotheses/{hypothesis_id}/approve` | Required (Enforced in Prod) | `investigation:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/ai/hypotheses/{hypothesis_id}/audit` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/ai/hypotheses/{hypothesis_id}/convert` | Required (Enforced in Prod) | `investigation:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/ai/hypotheses/{hypothesis_id}/reject` | Required (Enforced in Prod) | `investigation:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/ai/analyses` | Required (Enforced in Prod) | `investigation:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/ai/analyze/finding/{finding_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/ai/analyze/impact/{impact_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/ai/analyze/path/{path_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/ai/hypotheses` | Required (Enforced in Prod) | `investigation:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/ai/hypotheses/path/{path_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/ai/recommendations` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/ai/report-summary` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |

## Attack Paths (5 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/attack-paths/{path_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/attack-paths/{path_id}/rebuild` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/attack-paths/{path_id}/steps` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/projects/{project_id}/attack-paths` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/attack-paths/analyze` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |

## Audit Events (2 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/audit-events` | Required (Enforced in Prod) | `audit:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/audit-events/{event_id}` | Required (Enforced in Prod) | `audit:read` | Entity-scoped | Non-destructive (READ) |

## Authentication (14 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/auth/token-status` | Required (Enforced in Prod) | `project:read` | Global | Non-destructive (READ) |
| `GET` | `/api/v1/auth/verify` | Required (Enforced in Prod) | `project:read` | Global | Non-destructive (READ) |
| `DELETE` | `/api/v1/authorization-matrix/rules/{rule_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/endpoints/{endpoint_id}/auth-policy` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/endpoints/{endpoint_id}/auth-policy` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/authorization-matrix` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/authorization-matrix/rules` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `PUT` | `/api/v1/projects/{project_id}/authorization-matrix/rules` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/authorization-model` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/auth/error` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/auth/protected` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/auth/server-error` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/auth/soft-deny` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/auth/vulnerable` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |

## Authentication Security (1 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/generate-auth-tests` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |

## Baselines & Comparisons (10 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/baseline-comparisons/{comparison_id}` | Required (Enforced in Prod) | `baseline:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/baselines/{baseline_id}` | Required (Enforced in Prod) | `baseline:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/baselines/{baseline_id}` | Required (Enforced in Prod) | `baseline:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/baselines/{baseline_id}/activate` | Required (Enforced in Prod) | `baseline:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/baselines/{baseline_id}/archive` | Required (Enforced in Prod) | `baseline:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/baselines/{baseline_id}/compare` | Required (Enforced in Prod) | `baseline:write` | Entity-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/projects/{project_id}/baseline-comparisons` | Required (Enforced in Prod) | `baseline:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/baselines` | Required (Enforced in Prod) | `baseline:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/baselines` | Required (Enforced in Prod) | `baseline:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/baselines/from-plan` | Required (Enforced in Prod) | `baseline:write` | Project-scoped | State-modifying (WRITE) |

## Correlation & Attack Graph (4 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/attack-graphs/{graph_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/attack-graphs/{graph_id}/edges` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/attack-graphs/{graph_id}/nodes` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/projects/{project_id}/attack-graphs` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |

## Endpoints & APIs (11 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/endpoints/{endpoint_id}/policy` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/endpoints/{endpoint_id}/policy` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `PUT` | `/api/v1/endpoints/{endpoint_id}/resource` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/{api_id}/endpoints/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/{api_id}/endpoints/{endpoint_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/{project_id}/apis/` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/{project_id}/apis/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/{project_id}/apis/{api_id}` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/{project_id}/apis/{api_id}` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/{project_id}/apis/{api_id}` | Required (Enforced in Prod) | `project:write` | Project-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/{project_id}/ingest/` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |

## Execution Plans (6 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/execution-plans/{plan_id}` | Required (Enforced in Prod) | `scan:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/execution-plans/{plan_id}/cancel` | Required (Enforced in Prod) | `scan:cancel` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/execution-plans/{plan_id}/progress` | Required (Enforced in Prod) | `scan:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/execution-plans/{plan_id}/start` | Required (Enforced in Prod) | `scan:execute` | Entity-scoped | Operational (EXECUTE) |
| `POST` | `/api/v1/projects/{project_id}/execution-plans` | Required (Enforced in Prod) | `scan:read` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/execution-plans` | Required (Enforced in Prod) | `scan:read` | Project-scoped | Non-destructive (READ) |

## Findings (5 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/findings/{finding_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/findings/{finding_id}/evidence` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/findings/{finding_id}/replay` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/findings` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/projects/{project_id}/findings/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |

## Health & System (35 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | `project:read` | Global | Non-destructive (READ) |
| `GET` | `/api/v1/executions/{execution_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-gate-evaluations/{evaluation_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-gate-evaluations/{evaluation_id}/items` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-gate-evaluations/{evaluation_id}/result` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/workflow-attack-scenarios/{scenario_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflow-attack-scenarios/{scenario_id}/execute` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/workflow-attack-scenarios/{scenario_id}/executions` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflow-attack-scenarios/{scenario_id}/replay` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflow-executions/{execution_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflow-executions/{execution_id}/replay` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflow-states/{state_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflow-states/{state_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflow-states/{state_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/workflow-steps/{step_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflow-steps/{step_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflow-steps/{step_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/workflow-transitions/{transition_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflow-transitions/{transition_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflow-transitions/{transition_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/demo-target/admin/error-stats` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/admin/protected-system-stats` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/admin/system-stats` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/error-orders/{order_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/filtered-users/{user_id}` | Required (Enforced in Prod) | `project:read` | User-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/orders/{order_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/protected-orders/{order_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/cancel` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/checkout` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/claim` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/pay` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/refund` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/orders/{order_id}/status` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/workflow/reset` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/demo-target/workflow/reset` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |

## Identities & Auth Schemes (7 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/identities/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/identities/{identity_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/identities/{identity_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/identities/{identity_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `PUT` | `/api/v1/identities/{identity_id}/role` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/identities/` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/identities/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |

## Investigations (10 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/investigations/{investigation_id}` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/investigations/{investigation_id}` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/investigations/{investigation_id}/context` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/investigations/{investigation_id}/items` | Required (Enforced in Prod) | `investigation:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/investigations/{investigation_id}/items/{item_id}` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/investigations/{investigation_id}/timeline` | Required (Enforced in Prod) | `investigation:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/investigations` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/investigations` | Required (Enforced in Prod) | `investigation:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/investigations/from-finding/{finding_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/investigations/from-path/{attack_path_id}` | Required (Enforced in Prod) | `investigation:write` | Project-scoped | State-modifying (WRITE) |

## Projects (11 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/projects/{project_id}` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/projects/{project_id}` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/projects/{project_id}` | Required (Enforced in Prod) | `project:delete` | Project-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/projects/{project_id}/audit-events` | Required (Enforced in Prod) | `audit:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/correlation/run` | Required (Enforced in Prod) | `project:write` | Project-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/projects/{project_id}/correlations` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/generate-bfla-tests` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/projects/{project_id}/impact-analysis/run` | Required (Enforced in Prod) | `project:write` | Project-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/projects/{project_id}/security-gate-evaluations` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |

## Property Security (9 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/properties/{property_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/properties/{property_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/properties/{property_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/properties/{property_id}/rules` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/resources/{resource_id}/properties` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/resources/{resource_id}/properties` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/resources/{resource_id}/properties/bulk` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/resources/{resource_id}/property-matrix` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/resources/{resource_id}/property-matrix/bulk` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |

## RBAC & Project Memberships (15 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/permissions` | Required (Enforced in Prod) | `project:read` | Global | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/memberships` | Required (Enforced in Prod) | `project:admin` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/memberships` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `DELETE` | `/api/v1/projects/{project_id}/memberships/{user_id}` | Required (Enforced in Prod) | `project:admin` | Project-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/projects/{project_id}/roles/` | Required (Enforced in Prod) | `role:manage` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/roles/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/roles/seed` | Required (Enforced in Prod) | `role:manage` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/roles/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/roles/{role_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/roles/{role_id}` | Required (Enforced in Prod) | `role:manage` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/roles/{role_id}` | Required (Enforced in Prod) | `role:manage` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/roles/{role_id}/assign/{identity_id}` | Required (Enforced in Prod) | `role:manage` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/roles/{role_id}/members` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/roles/{role_id}/permissions` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/roles/{role_id}/permissions` | Required (Enforced in Prod) | `role:manage` | Entity-scoped | State-modifying (WRITE) |

## Reports (11 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/security-reports` | Required (Enforced in Prod) | `report:generate` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/security-reports` | Required (Enforced in Prod) | `report:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-reports/{report_id}` | Required (Enforced in Prod) | `report:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/security-reports/{report_id}` | Required (Enforced in Prod) | `report:read` | Entity-scoped | State-modifying (WRITE) |
| `PUT` | `/api/v1/security-reports/{report_id}` | Required (Enforced in Prod) | `report:read` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/security-reports/{report_id}` | Required (Enforced in Prod) | `report:read` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/security-reports/{report_id}/archive` | Required (Enforced in Prod) | `report:generate` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/security-reports/{report_id}/generate` | Required (Enforced in Prod) | `report:generate` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/security-reports/{report_id}/json` | Required (Enforced in Prod) | `report:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-reports/{report_id}/manifest` | Required (Enforced in Prod) | `report:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-reports/{report_id}/package` | Required (Enforced in Prod) | `report:export` | Entity-scoped | Non-destructive (READ) |

## Resources & Ownership (11 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DELETE` | `/api/v1/ownerships/{ownership_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/projects/{project_id}/resources/` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/resources/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/resources/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/resources/{resource_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/resources/{resource_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/resources/{resource_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/resources/{resource_id}/discover-properties` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/resources/{resource_id}/endpoints` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/resources/{resource_id}/ownerships/` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/resources/{resource_id}/ownerships/` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |

## Scan Profiles (7 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/scan-profiles` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/scan-profiles` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/scan-profiles/{profile_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/scan-profiles/{profile_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/scan-profiles/{profile_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/scan-profiles/{profile_id}/create-plan` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/scan-profiles/{profile_id}/preview` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |

## Schedules (13 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/security-scan-schedules` | Required (Enforced in Prod) | `schedule:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/security-scan-schedules` | Required (Enforced in Prod) | `schedule:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/projects/{project_id}/security-scheduled-executions` | Required (Enforced in Prod) | `schedule:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-scan-schedules/{schedule_id}` | Required (Enforced in Prod) | `schedule:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/security-scan-schedules/{schedule_id}` | Required (Enforced in Prod) | `schedule:write` | Entity-scoped | State-modifying (WRITE) |
| `PUT` | `/api/v1/security-scan-schedules/{schedule_id}` | Required (Enforced in Prod) | `schedule:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/security-scan-schedules/{schedule_id}` | Required (Enforced in Prod) | `schedule:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/security-scan-schedules/{schedule_id}/disable` | Required (Enforced in Prod) | `schedule:write` | Entity-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/security-scan-schedules/{schedule_id}/enable` | Required (Enforced in Prod) | `schedule:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/security-scan-schedules/{schedule_id}/executions` | Required (Enforced in Prod) | `schedule:read` | Entity-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-scan-schedules/{schedule_id}/preview` | Required (Enforced in Prod) | `schedule:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/security-scan-schedules/{schedule_id}/run` | Required (Enforced in Prod) | `schedule:execute` | Entity-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/security-scheduled-executions/{execution_id}` | Required (Enforced in Prod) | `schedule:read` | Entity-scoped | Non-destructive (READ) |

## Security Gates (8 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/security-gates` | Required (Enforced in Prod) | `gate:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/security-gates` | Required (Enforced in Prod) | `gate:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-gates/{gate_id}` | Required (Enforced in Prod) | `gate:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/security-gates/{gate_id}` | Required (Enforced in Prod) | `gate:read` | Entity-scoped | State-modifying (WRITE) |
| `PUT` | `/api/v1/security-gates/{gate_id}` | Required (Enforced in Prod) | `gate:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/security-gates/{gate_id}` | Required (Enforced in Prod) | `gate:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/security-gates/{gate_id}/evaluate` | Required (Enforced in Prod) | `gate:evaluate` | Entity-scoped | Operational (EXECUTE) |
| `POST` | `/api/v1/security-gates/{gate_id}/evaluate/{comparison_id}` | Required (Enforced in Prod) | `gate:evaluate` | Entity-scoped | Operational (EXECUTE) |

## Security Impact (3 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/projects/{project_id}/security-impacts` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-impacts/{impact_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/security-impacts/{impact_id}/rebuild` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |

## Security Tests (5 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/security-tests/` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/security-tests/` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/security-tests/{test_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/security-tests/{test_id}/execute` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/security-tests/{test_id}/executions` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |

## Test Suites (8 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/projects/{project_id}/test-suites` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/projects/{project_id}/test-suites` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `GET` | `/api/v1/test-suites/{suite_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/test-suites/{suite_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/test-suites/{suite_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `POST` | `/api/v1/test-suites/{suite_id}/tests` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `PATCH` | `/api/v1/test-suites/{suite_id}/tests/{item_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/test-suites/{suite_id}/tests/{item_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |

## Users & API Tokens (8 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `DELETE` | `/api/v1/api-tokens/{token_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/users` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/users` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/users/{user_id}` | Required (Enforced in Prod) | `project:read` | User-scoped | Non-destructive (READ) |
| `PUT` | `/api/v1/users/{user_id}` | Required (Enforced in Prod) | `project:write` | User-scoped | State-modifying (WRITE) |
| `POST` | `/api/v1/users/{user_id}/api-tokens` | Required (Enforced in Prod) | `project:write` | User-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/users/{user_id}/api-tokens` | Required (Enforced in Prod) | `project:read` | User-scoped | Non-destructive (READ) |
| `GET` | `/demo-target/users/{user_id}` | Required (Enforced in Prod) | `project:read` | User-scoped | Non-destructive (READ) |

## Workflows & Workflow Attacks (24 operations)

| Method | Endpoint Path | Authentication | Permission Required | Project Scope | Operation Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/projects/{project_id}/workflows` | Required (Enforced in Prod) | `project:read` | Project-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/projects/{project_id}/workflows` | Required (Enforced in Prod) | `project:write` | Project-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflows/{workflow_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflows/{workflow_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflows/{workflow_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/workflows/{workflow_id}/attack-scenarios` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflows/{workflow_id}/execute` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Operational (EXECUTE) |
| `GET` | `/api/v1/workflows/{workflow_id}/executions` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflows/{workflow_id}/generate-attack-scenarios` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflows/{workflow_id}/states` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflows/{workflow_id}/states` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflows/{workflow_id}/states/{state_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflows/{workflow_id}/states/{state_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflows/{workflow_id}/states/{state_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/workflows/{workflow_id}/steps` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflows/{workflow_id}/steps` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflows/{workflow_id}/steps/{step_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflows/{workflow_id}/steps/{step_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflows/{workflow_id}/steps/{step_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |
| `GET` | `/api/v1/workflows/{workflow_id}/transitions` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `POST` | `/api/v1/workflows/{workflow_id}/transitions` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `GET` | `/api/v1/workflows/{workflow_id}/transitions/{transition_id}` | Required (Enforced in Prod) | `project:read` | Entity-scoped | Non-destructive (READ) |
| `PATCH` | `/api/v1/workflows/{workflow_id}/transitions/{transition_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | State-modifying (WRITE) |
| `DELETE` | `/api/v1/workflows/{workflow_id}/transitions/{transition_id}` | Required (Enforced in Prod) | `project:write` | Entity-scoped | Destructive (DELETE) |

