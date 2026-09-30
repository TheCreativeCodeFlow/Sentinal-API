"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface SecurityBaseline {
  id: string;
  name: string;
  version: number;
  status: string;
}

interface ScanProfile {
  id: string;
  name: string;
  profile_type: string;
  status: string;
}

interface BaselineComparison {
  id: string;
  baseline_id: string;
  execution_plan_id: string;
  status: string;
  created_at: string;
  summary: {
    regressions_count?: number;
    new_violations_count?: number;
    execution_plan_name?: string;
    baseline_name?: string;
  };
}

interface SecurityGateFailureRules {
  max_regressions: number;
  max_new_violations: number;
  max_confirmed_findings: number;
  max_failed_tests: number;
}

interface SecurityGateWarningRules {
  max_inconclusive: number;
  max_errors: number;
  max_not_applicable: number;
}

interface SecurityGate {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "ACTIVE" | "DISABLED";
  baseline_id: string;
  scan_profile_id: string;
  failure_rules: SecurityGateFailureRules;
  warning_rules: SecurityGateWarningRules;
  baseline_name: string | null;
  baseline_version: number | null;
  scan_profile_name: string | null;
  latest_evaluation_status: string | null;
  created_at: string;
  updated_at: string;
}

interface SecurityGateEvaluationItem {
  id: string;
  evaluation_id: string;
  rule_type: string;
  severity: "FAILURE" | "WARNING" | "ERROR";
  triggered: boolean;
  actual_value: number;
  threshold: number;
  message: string;
  finding_id: string | null;
  comparison_item_id: string | null;
  security_test_id: string | null;
}

interface SecurityGateEvaluation {
  id: string;
  gate_id: string;
  project_id: number;
  baseline_comparison_id: string;
  status: "PASS" | "WARN" | "FAIL" | "ERROR";
  failure_count: number;
  warning_count: number;
  confirmed_findings: number;
  regressions: number;
  new_violations: number;
  failed_tests: number;
  inconclusive_tests: number;
  error_tests: number;
  summary: Record<string, unknown>;
  evaluated_at: string;
  gate_name: string | null;
  items: SecurityGateEvaluationItem[];
}

interface CIResultPayload {
  status: string;
  exit_code: number;
  gate_id: string;
  gate_name: string;
  baseline_version: number | null;
  evaluation_id: string;
  metrics: {
    new_violations: number;
    regressions: number;
    confirmed_findings: number;
    failed_tests: number;
    inconclusive_tests: number;
    errors: number;
    not_applicable: number;
  };
  triggered_rules: Array<{
    rule_type: string;
    actual: number;
    threshold: number;
    severity: string;
    message: string;
    finding_ids: string[];
    comparison_item_ids: string[];
    security_test_ids: string[];
  }>;
  evaluated_at: string;
}

function SecurityGatesContent() {
  const searchParams = useSearchParams();
  const preselectedComparisonId = searchParams.get("comparison_id");

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [gates, setGates] = useState<SecurityGate[]>([]);
  const [baselines, setBaselines] = useState<SecurityBaseline[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [comparisons, setComparisons] = useState<BaselineComparison[]>([]);

  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Create Gate Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createBaselineId, setCreateBaselineId] = useState("");
  const [createProfileId, setCreateProfileId] = useState("");
  const [maxRegressions, setMaxRegressions] = useState(0);
  const [maxNewViolations, setMaxNewViolations] = useState(0);
  const [maxConfirmedFindings, setMaxConfirmedFindings] = useState(0);
  const [maxFailedTests, setMaxFailedTests] = useState(0);
  const [maxInconclusive, setMaxInconclusive] = useState(0);
  const [maxErrors, setMaxErrors] = useState(0);
  const [creatingGate, setCreatingGate] = useState(false);

  // Evaluate Modal
  const [showEvaluateModal, setShowEvaluateModal] = useState(false);
  const [evaluatingGate, setEvaluatingGate] = useState<SecurityGate | null>(null);
  const [selectedComparisonId, setSelectedComparisonId] = useState<string>(preselectedComparisonId || "");
  const [evaluating, setEvaluating] = useState(false);

  // Evaluation Detail / CI Result Modal
  const [activeEvaluation, setActiveEvaluation] = useState<SecurityGateEvaluation | null>(null);
  const [ciResult, setCiResult] = useState<CIResultPayload | null>(null);
  const [showEvalDetailModal, setShowEvalDetailModal] = useState(false);
  const [copiedCI, setCopiedCI] = useState(false);

  // Gate History Modal
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [historyGate, setHistoryGate] = useState<SecurityGate | null>(null);
  const [gateEvaluations, setGateEvaluations] = useState<SecurityGateEvaluation[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Initial Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch projects");
        const data: Project[] = await res.json();
        setProjects(data);

        let initialId = data.length > 0 ? data[0].id : null;
        if (typeof window !== "undefined") {
          const stored = localStorage.getItem("selectedProjectId");
          if (stored) {
            const parsed = parseInt(stored, 10);
            if (data.some((p) => p.id === parsed)) {
              initialId = parsed;
            }
          }
        }
        setSelectedProjectId(initialId);
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  // Sync Project Resources
  useEffect(() => {
    if (!selectedProjectId) return;
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", selectedProjectId.toString());
    }

    async function fetchProjectData() {
      setLoading(true);
      setErrorMsg(null);
      try {
        const [gatesRes, baselinesRes, profilesRes, compsRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/security-gates`),
          fetch(`/api/v1/projects/${selectedProjectId}/baselines`),
          fetch(`/api/v1/projects/${selectedProjectId}/scan-profiles`),
          fetch(`/api/v1/projects/${selectedProjectId}/baseline-comparisons`),
        ]);

        if (gatesRes.ok) {
          const gData = await gatesRes.json();
          setGates(gData.gates || []);
        }
        if (baselinesRes.ok) {
          const bData = await baselinesRes.json();
          setBaselines(bData || []);
        }
        if (profilesRes.ok) {
          const pData = await profilesRes.json();
          setProfiles(pData.profiles || []);
        }
        if (compsRes.ok) {
          const cData = await compsRes.json();
          setComparisons(cData || []);
        }
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load security gates data");
      } finally {
        setLoading(false);
      }
    }

    fetchProjectData();
  }, [selectedProjectId]);

  // Handle Create Gate
  async function handleCreateGate(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId || !createBaselineId || !createProfileId || !createName.trim()) {
      setErrorMsg("Please provide all required gate fields.");
      return;
    }

    setCreatingGate(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const payload = {
        name: createName.trim(),
        description: createDesc.trim() || null,
        baseline_id: createBaselineId,
        scan_profile_id: createProfileId,
        status: "ACTIVE",
        failure_rules: {
          max_regressions: Number(maxRegressions),
          max_new_violations: Number(maxNewViolations),
          max_confirmed_findings: Number(maxConfirmedFindings),
          max_failed_tests: Number(maxFailedTests),
        },
        warning_rules: {
          max_inconclusive: Number(maxInconclusive),
          max_errors: Number(maxErrors),
          max_not_applicable: 999999,
        },
      };

      const res = await fetch(`/api/v1/projects/${selectedProjectId}/security-gates`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || "Failed to create security gate");
      }

      const created: SecurityGate = await res.json();
      setGates((prev) => [created, ...prev]);
      setShowCreateModal(false);
      setSuccessMsg(`Security gate "${created.name}" created successfully.`);

      // Reset form
      setCreateName("");
      setCreateDesc("");
      setCreateBaselineId("");
      setCreateProfileId("");
      setMaxRegressions(0);
      setMaxNewViolations(0);
      setMaxConfirmedFindings(0);
      setMaxFailedTests(0);
      setMaxInconclusive(0);
      setMaxErrors(0);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create security gate");
    } finally {
      setCreatingGate(false);
    }
  }

  // Handle Evaluate Gate
  async function handleRunEvaluation(e: React.FormEvent) {
    e.preventDefault();
    if (!evaluatingGate || !selectedComparisonId) {
      setErrorMsg("Please select a completed baseline comparison to evaluate.");
      return;
    }

    setEvaluating(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(
        `/api/v1/security-gates/${evaluatingGate.id}/evaluate/${selectedComparisonId}`,
        { method: "POST" }
      );

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || "Security gate evaluation failed");
      }

      const evaluation: SecurityGateEvaluation = await res.json();

      // Fetch CI result payload
      const ciRes = await fetch(`/api/v1/security-gate-evaluations/${evaluation.id}/result`);
      if (ciRes.ok) {
        const ciData = await ciRes.json();
        setCiResult(ciData);
      }

      setActiveEvaluation(evaluation);
      setShowEvaluateModal(false);
      setShowEvalDetailModal(true);
      setSuccessMsg(`Gate evaluated with result: ${evaluation.status}`);

      // Refresh gates list to show updated evaluation badge
      const refreshRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-gates`);
      if (refreshRes.ok) {
        const refreshedData = await refreshRes.json();
        setGates(refreshedData.gates || []);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Evaluation failed");
    } finally {
      setEvaluating(false);
    }
  }

  // View Gate History
  async function handleViewHistory(gate: SecurityGate) {
    setHistoryGate(gate);
    setShowHistoryModal(true);
    setLoadingHistory(true);
    try {
      const res = await fetch(
        `/api/v1/projects/${gate.project_id}/security-gate-evaluations?gate_id=${gate.id}`
      );
      if (!res.ok) throw new Error("Failed to load evaluation history");
      const data = await res.json();
      setGateEvaluations(data.evaluations || []);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load evaluation history");
    } finally {
      setLoadingHistory(false);
    }
  }

  // View Evaluation Details
  async function handleViewEvaluationDetails(evaluation: SecurityGateEvaluation) {
    setActiveEvaluation(evaluation);
    try {
      const ciRes = await fetch(`/api/v1/security-gate-evaluations/${evaluation.id}/result`);
      if (ciRes.ok) {
        const ciData = await ciRes.json();
        setCiResult(ciData);
      }
    } catch {
      // Continue with evaluation alone
    }
    setShowEvalDetailModal(true);
  }

  // Delete Gate
  async function handleDeleteGate(gateId: string, gateName: string) {
    if (!confirm(`Are you sure you want to delete security gate "${gateName}"?`)) return;
    try {
      const res = await fetch(`/api/v1/security-gates/${gateId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to delete security gate");
      setGates((prev) => prev.filter((g) => g.id !== gateId));
      setSuccessMsg(`Security gate "${gateName}" deleted successfully.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to delete gate");
    }
  }

  function renderStatusBadge(status: string) {
    switch (status) {
      case "PASS":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80">
            PASS (0)
          </span>
        );
      case "WARN":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/80">
            WARN (0)
          </span>
        );
      case "FAIL":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/80">
            FAIL (1)
          </span>
        );
      case "ERROR":
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-red-950/80 text-red-400 border border-red-800/80">
            ERROR (2)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-zinc-800 text-zinc-400 border border-zinc-700">
            PENDING
          </span>
        );
    }
  }

  return (
    <div className="space-y-6">
      {/* Header & Project Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">CI/CD Security Regression Gates</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Deterministic security gates enforcing zero regressions and strict security quality gates before release.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label htmlFor="project-select" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Project:
            </label>
            <select
              id="project-select"
              className="bg-card border border-border text-foreground text-sm rounded-lg px-3 py-1.5 focus:ring-1 focus:ring-primary focus:outline-hidden"
              value={selectedProjectId || ""}
              onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} (#{p.id})
                </option>
              ))}
            </select>
          </div>

          <Button
            onClick={() => setShowCreateModal(true)}
            className="bg-primary text-primary-foreground hover:bg-primary/90 text-sm font-medium"
          >
            + New Security Gate
          </Button>
        </div>
      </div>

      {/* Alerts */}
      {errorMsg && (
        <div className="p-3 text-sm bg-destructive/15 text-destructive border border-destructive/30 rounded-lg flex justify-between items-center">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-xs font-bold hover:underline">
            Dismiss
          </button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 text-sm bg-emerald-950/40 text-emerald-300 border border-emerald-800/60 rounded-lg flex justify-between items-center">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-xs font-bold hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Architecture Notice Banner */}
      <Card className="border-border bg-card/40">
        <CardContent className="p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary font-bold text-lg">
              🛡️
            </div>
            <div>
              <h4 className="text-sm font-semibold">Strict Deterministic Precedence</h4>
              <p className="text-xs text-muted-foreground mt-0.5">
                Evaluations adhere to <code className="text-primary font-mono">ERROR &gt; FAIL &gt; WARN &gt; PASS</code> with automated exit codes (PASS/WARN=0, FAIL=1, ERROR=2) and zero target HTTP requests.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/40 px-3 py-1.5 rounded-md border border-border">
            <span>Machine-readable CI/CD payload ready</span>
          </div>
        </CardContent>
      </Card>

      {/* Gates Table */}
      {loading ? (
        <div className="text-center py-12 text-sm text-muted-foreground">Loading security gates...</div>
      ) : gates.length === 0 ? (
        <Card className="border-border bg-card/30">
          <CardContent className="py-12 text-center space-y-3">
            <div className="text-3xl">⚖️</div>
            <h3 className="text-base font-semibold">No Security Gates Configured</h3>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Define a security gate to compare scans against your active baseline and establish regression policies.
            </p>
            <Button
              onClick={() => setShowCreateModal(true)}
              className="mt-2 text-xs bg-primary text-primary-foreground hover:bg-primary/90"
            >
              Configure First Security Gate
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="border border-border rounded-xl overflow-hidden bg-card/30">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground border-b border-border">
              <tr>
                <th className="px-4 py-3">Gate Name</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Target Baseline</th>
                <th className="px-4 py-3">Scan Profile</th>
                <th className="px-4 py-3">Policies</th>
                <th className="px-4 py-3">Latest Result</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {gates.map((g) => (
                <tr key={g.id} className="hover:bg-accent/40 transition-colors">
                  <td className="px-4 py-3.5">
                    <div className="font-semibold text-foreground">{g.name}</div>
                    {g.description && <div className="text-xs text-muted-foreground mt-0.5">{g.description}</div>}
                  </td>
                  <td className="px-4 py-3.5">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${
                        g.status === "ACTIVE"
                          ? "bg-emerald-950/80 text-emerald-300 border border-emerald-800/80"
                          : "bg-zinc-800 text-zinc-400 border border-zinc-700"
                      }`}
                    >
                      {g.status}
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="font-medium text-foreground">
                      {g.baseline_name || "Baseline"} (v{g.baseline_version || 1})
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <span className="text-foreground">{g.scan_profile_name || "Profile"}</span>
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="text-xs space-y-1">
                      <div className="text-rose-400">
                        Fail: reg &le; {g.failure_rules.max_regressions}, new &le; {g.failure_rules.max_new_violations}
                      </div>
                      <div className="text-amber-400">
                        Warn: inconc &le; {g.warning_rules.max_inconclusive}, err &le; {g.warning_rules.max_errors}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3.5">
                    {g.latest_evaluation_status ? renderStatusBadge(g.latest_evaluation_status) : (
                      <span className="text-xs text-muted-foreground">Not Evaluated</span>
                    )}
                  </td>
                  <td className="px-4 py-3.5 text-right space-x-2">
                    <Button
                      size="sm"
                      onClick={() => {
                        setEvaluatingGate(g);
                        setShowEvaluateModal(true);
                      }}
                      className="bg-primary text-primary-foreground hover:bg-primary/90 text-xs h-7 px-2.5"
                    >
                      Evaluate
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleViewHistory(g)}
                      className="text-xs h-7 px-2.5 border-border"
                    >
                      History
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleDeleteGate(g.id, g.name)}
                      className="text-xs h-7 px-2 text-rose-400 hover:text-rose-300 hover:bg-rose-950/20 border-rose-900/40"
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* CREATE SECURITY GATE MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <Card className="w-full max-w-xl border-border bg-card shadow-2xl">
            <form onSubmit={handleCreateGate}>
              <div className="p-6 border-b border-border flex justify-between items-center">
                <h3 className="text-lg font-bold">Configure Security Gate</h3>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="text-muted-foreground hover:text-foreground text-sm font-bold"
                >
                  ✕
                </button>
              </div>

              <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
                <div>
                  <label htmlFor="create-gate-name" className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                    Gate Name *
                  </label>
                  <Input
                    id="create-gate-name"
                    required
                    placeholder="e.g. Production Release Gate"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                  />
                </div>

                <div>
                  <label htmlFor="create-gate-desc" className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                    Description
                  </label>
                  <Input
                    id="create-gate-desc"
                    placeholder="e.g. Strict zero-regression gate for staging/production"
                    value={createDesc}
                    onChange={(e) => setCreateDesc(e.target.value)}
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="select-baseline" className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                      Target Baseline *
                    </label>
                    <select
                      id="select-baseline"
                      required
                      className="w-full bg-card border border-border text-foreground text-sm rounded-lg px-3 py-2"
                      value={createBaselineId}
                      onChange={(e) => setCreateBaselineId(e.target.value)}
                    >
                      <option value="">Select baseline...</option>
                      {baselines.map((b) => (
                        <option key={b.id} value={b.id}>
                          {b.name} (v{b.version}) - {b.status}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label htmlFor="select-profile" className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                      Scan Profile *
                    </label>
                    <select
                      id="select-profile"
                      required
                      className="w-full bg-card border border-border text-foreground text-sm rounded-lg px-3 py-2"
                      value={createProfileId}
                      onChange={(e) => setCreateProfileId(e.target.value)}
                    >
                      <option value="">Select profile...</option>
                      {profiles.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.profile_type})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Failure Rules Section */}
                <div className="pt-2 border-t border-border">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 mb-2">
                    Failure Thresholds (Trigger FAIL / Exit Code 1)
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label htmlFor="max-regressions" className="text-muted-foreground">Max Regressions Allowed</label>
                      <Input
                        id="max-regressions"
                        type="number"
                        min="0"
                        value={maxRegressions}
                        onChange={(e) => setMaxRegressions(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <label htmlFor="max-new-violations" className="text-muted-foreground">Max New Violations</label>
                      <Input
                        id="max-new-violations"
                        type="number"
                        min="0"
                        value={maxNewViolations}
                        onChange={(e) => setMaxNewViolations(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <label htmlFor="max-confirmed-findings" className="text-muted-foreground">Max Confirmed Findings</label>
                      <Input
                        id="max-confirmed-findings"
                        type="number"
                        min="0"
                        value={maxConfirmedFindings}
                        onChange={(e) => setMaxConfirmedFindings(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <label htmlFor="max-failed-tests" className="text-muted-foreground">Max Failed Tests</label>
                      <Input
                        id="max-failed-tests"
                        type="number"
                        min="0"
                        value={maxFailedTests}
                        onChange={(e) => setMaxFailedTests(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                  </div>
                </div>

                {/* Warning Rules Section */}
                <div className="pt-2 border-t border-border">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2">
                    Warning Thresholds (Trigger WARN / Exit Code 0)
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <label htmlFor="max-inconclusive" className="text-muted-foreground">Max Inconclusive Tests</label>
                      <Input
                        id="max-inconclusive"
                        type="number"
                        min="0"
                        value={maxInconclusive}
                        onChange={(e) => setMaxInconclusive(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <label htmlFor="max-errors" className="text-muted-foreground">Max Execution Errors</label>
                      <Input
                        id="max-errors"
                        type="number"
                        min="0"
                        value={maxErrors}
                        onChange={(e) => setMaxErrors(parseInt(e.target.value, 10) || 0)}
                        className="mt-1"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="p-4 border-t border-border flex justify-end gap-2 bg-muted/20">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowCreateModal(false)}
                  disabled={creatingGate}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={creatingGate}
                  className="bg-primary text-primary-foreground hover:bg-primary/90"
                >
                  {creatingGate ? "Creating..." : "Save Security Gate"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* EVALUATE GATE MODAL */}
      {showEvaluateModal && evaluatingGate && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <Card className="w-full max-w-lg border-border bg-card shadow-2xl">
            <form onSubmit={handleRunEvaluation}>
              <div className="p-6 border-b border-border flex justify-between items-center">
                <h3 className="text-lg font-bold">Evaluate Gate: {evaluatingGate.name}</h3>
                <button
                  type="button"
                  onClick={() => setShowEvaluateModal(false)}
                  className="text-muted-foreground hover:text-foreground text-sm font-bold"
                >
                  ✕
                </button>
              </div>

              <div className="p-6 space-y-4">
                <div className="p-3 bg-muted/40 rounded-lg text-xs space-y-1 border border-border">
                  <div>
                    <span className="text-muted-foreground">Target Baseline: </span>
                    <span className="font-semibold text-foreground">
                      {evaluatingGate.baseline_name} (v{evaluatingGate.baseline_version})
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Scan Profile: </span>
                    <span className="font-semibold text-foreground">{evaluatingGate.scan_profile_name}</span>
                  </div>
                </div>

                <div>
                  <label htmlFor="select-comparison" className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">
                    Select Baseline Comparison *
                  </label>
                  <select
                    id="select-comparison"
                    required
                    className="w-full bg-card border border-border text-foreground text-sm rounded-lg px-3 py-2"
                    value={selectedComparisonId}
                    onChange={(e) => setSelectedComparisonId(e.target.value)}
                  >
                    <option value="">Choose a completed comparison...</option>
                    {comparisons
                      .filter((c) => c.baseline_id === evaluatingGate.baseline_id)
                      .map((c) => (
                        <option key={c.id} value={c.id}>
                          Scan: {c.summary.execution_plan_name || c.execution_plan_id.slice(0, 8)} | Reg:{" "}
                          {c.summary.regressions_count ?? 0}, New: {c.summary.new_violations_count ?? 0}
                        </option>
                      ))}
                  </select>
                  {comparisons.filter((c) => c.baseline_id === evaluatingGate.baseline_id).length === 0 && (
                    <p className="text-xs text-rose-400 mt-1">
                      No comparisons found matching this gate&apos;s baseline. Run a baseline comparison first.
                    </p>
                  )}
                </div>
              </div>

              <div className="p-4 border-t border-border flex justify-end gap-2 bg-muted/20">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowEvaluateModal(false)}
                  disabled={evaluating}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={evaluating || !selectedComparisonId}
                  className="bg-primary text-primary-foreground hover:bg-primary/90"
                >
                  {evaluating ? "Evaluating..." : "Run Gate Evaluation"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* EVALUATION DETAIL / CI RESULT MODAL */}
      {showEvalDetailModal && activeEvaluation && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <Card className="w-full max-w-3xl border-border bg-card shadow-2xl">
            <div className="p-6 border-b border-border flex justify-between items-center">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-bold">Gate Evaluation Result</h3>
                {renderStatusBadge(activeEvaluation.status)}
              </div>
              <button
                type="button"
                onClick={() => setShowEvalDetailModal(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
              {/* Metrics Summary Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 bg-card border border-border rounded-lg text-center">
                  <div className="text-2xl font-bold text-rose-400">{activeEvaluation.regressions}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">Regressions</div>
                </div>
                <div className="p-3 bg-card border border-border rounded-lg text-center">
                  <div className="text-2xl font-bold text-rose-400">{activeEvaluation.new_violations}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">New Violations</div>
                </div>
                <div className="p-3 bg-card border border-border rounded-lg text-center">
                  <div className="text-2xl font-bold text-amber-400">{activeEvaluation.inconclusive_tests}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">Inconclusive</div>
                </div>
                <div className="p-3 bg-card border border-border rounded-lg text-center">
                  <div className="text-2xl font-bold text-red-400">{activeEvaluation.error_tests}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">Errors</div>
                </div>
              </div>

              {/* Triggered Items Breakdown */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
                  Evaluation Rules Evaluation
                </h4>
                {activeEvaluation.items.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No rule violations detected.</p>
                ) : (
                  <div className="border border-border rounded-lg overflow-hidden text-xs">
                    <table className="w-full text-left">
                      <thead className="bg-muted/40 text-muted-foreground border-b border-border">
                        <tr>
                          <th className="px-3 py-2">Rule</th>
                          <th className="px-3 py-2">Actual / Max</th>
                          <th className="px-3 py-2">Severity</th>
                          <th className="px-3 py-2">Traceability</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {activeEvaluation.items.map((it) => (
                          <tr
                            key={it.id}
                            className={it.triggered ? "bg-rose-950/20" : "bg-card"}
                          >
                            <td className="px-3 py-2 font-mono font-medium">
                              {it.rule_type}
                              {it.triggered && (
                                <span className="ml-2 text-rose-400 font-sans font-semibold">TRIGGERED</span>
                              )}
                            </td>
                            <td className="px-3 py-2">
                              {it.actual_value} / {it.threshold}
                            </td>
                            <td className="px-3 py-2">
                              <span
                                className={`px-1.5 py-0.5 rounded font-semibold ${
                                  it.severity === "FAILURE"
                                    ? "bg-rose-950/80 text-rose-300"
                                    : "bg-amber-950/80 text-amber-300"
                                }`}
                              >
                                {it.severity}
                              </span>
                            </td>
                            <td className="px-3 py-2 text-muted-foreground font-mono">
                              {it.finding_id && <div>Finding: {it.finding_id.slice(0, 8)}</div>}
                              {it.security_test_id && <div>Test: {it.security_test_id.slice(0, 8)}</div>}
                              {!it.finding_id && !it.security_test_id && "-"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Machine-Readable CI/CD Payload */}
              {ciResult && (
                <div className="pt-2 border-t border-border">
                  <div className="flex justify-between items-center mb-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                      Machine-Readable CI/CD Output
                    </h4>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(ciResult, null, 2));
                        setCopiedCI(true);
                        setTimeout(() => setCopiedCI(false), 2000);
                      }}
                      className="text-xs h-6 px-2"
                    >
                      {copiedCI ? "Copied!" : "Copy JSON"}
                    </Button>
                  </div>
                  <pre className="p-3 bg-muted/30 border border-border rounded-lg text-xs font-mono text-muted-foreground overflow-x-auto max-h-48">
                    {JSON.stringify(ciResult, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-border flex justify-end bg-muted/20">
              <Button onClick={() => setShowEvalDetailModal(false)}>Close</Button>
            </div>
          </Card>
        </div>
      )}

      {/* GATE EVALUATION HISTORY MODAL */}
      {showHistoryModal && historyGate && (
        <div className="fixed inset-0 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <Card className="w-full max-w-2xl border-border bg-card shadow-2xl">
            <div className="p-6 border-b border-border flex justify-between items-center">
              <div>
                <h3 className="text-lg font-bold">Evaluation History</h3>
                <p className="text-xs text-muted-foreground">{historyGate.name}</p>
              </div>
              <button
                type="button"
                onClick={() => setShowHistoryModal(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="p-6 max-h-[65vh] overflow-y-auto">
              {loadingHistory ? (
                <div className="text-center py-8 text-xs text-muted-foreground">Loading history...</div>
              ) : gateEvaluations.length === 0 ? (
                <div className="text-center py-8 text-xs text-muted-foreground">
                  No evaluations have been run for this gate yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {gateEvaluations.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-3.5 bg-card/60 border border-border rounded-lg flex items-center justify-between hover:bg-accent/40 transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          {renderStatusBadge(ev.status)}
                          <span className="text-xs text-muted-foreground">
                            {new Date(ev.evaluated_at).toLocaleString()}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Regressions: <span className="font-semibold text-rose-400">{ev.regressions}</span> | New
                          Violations: <span className="font-semibold text-rose-400">{ev.new_violations}</span> |
                          Warnings: <span className="font-semibold text-amber-400">{ev.warning_count}</span>
                        </div>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleViewEvaluationDetails(ev)}
                        className="text-xs h-7 px-2.5"
                      >
                        Inspect
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-4 border-t border-border flex justify-end bg-muted/20">
              <Button onClick={() => setShowHistoryModal(false)}>Close</Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

export default function SecurityGatesPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-sm text-muted-foreground">Loading...</div>}>
      <SecurityGatesContent />
    </Suspense>
  );
}
