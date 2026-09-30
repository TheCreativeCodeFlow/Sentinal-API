"use client";

import React, { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

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
  control_count: number;
}

interface SecurityExecutionPlan {
  id: string;
  name: string;
  status: string;
  total_tests: number;
  completed_tests: number;
  confirmed_findings: number;
}

interface ComparisonItem {
  id: string;
  comparison_id: string;
  control_id: string | null;
  security_test_id: string | null;
  finding_id: string | null;
  result: "NEW_VIOLATION" | "REGRESSION" | "UNCHANGED" | "IMPROVED" | "NOT_APPLICABLE";
  previous_behavior: string | null;
  current_behavior: string | null;
  explanation: string;
  evidence_reference: Record<string, unknown>;
  created_at: string;
}

interface BaselineComparison {
  id: string;
  baseline_id: string;
  execution_plan_id: string;
  status: string;
  summary: {
    total_evaluated?: number;
    regressions_count?: number;
    new_violations_count?: number;
    improvements_count?: number;
    unchanged_count?: number;
    not_applicable_count?: number;
    has_regressions?: boolean;
    has_new_violations?: boolean;
    baseline_name?: string;
    baseline_version?: number;
    execution_plan_name?: string;
  };
  created_at: string;
  items: ComparisonItem[];
}

interface ComparisonDetailResponse {
  comparison: BaselineComparison;
  baseline_name: string;
  baseline_version: number;
  plan_name: string;
  plan_status: string;
  regressions: ComparisonItem[];
  new_violations: ComparisonItem[];
  improvements: ComparisonItem[];
  unchanged: ComparisonItem[];
  not_applicable: ComparisonItem[];
}

function BaselineComparisonsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedBaselineId = searchParams.get("baseline_id");

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [comparisons, setComparisons] = useState<BaselineComparison[]>([]);
  const [baselines, setBaselines] = useState<SecurityBaseline[]>([]);
  const [completedPlans, setCompletedPlans] = useState<SecurityExecutionPlan[]>([]);

  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Comparison Modal
  const [showNewModal, setShowNewModal] = useState<boolean>(Boolean(preselectedBaselineId));
  const [selectedBaselineId, setSelectedBaselineId] = useState<string>(preselectedBaselineId || "");
  const [selectedPlanId, setSelectedPlanId] = useState<string>("");
  const [comparing, setComparing] = useState(false);

  // Comparison Detail Modal
  const [detailData, setDetailData] = useState<ComparisonDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"ALL" | "REGRESSIONS" | "NEW_VIOLATIONS" | "IMPROVEMENTS" | "NOT_APPLICABLE">("REGRESSIONS");

  // Load Projects
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

  // When project changes, load comparisons, baselines, and completed plans
  useEffect(() => {
    if (!selectedProjectId) return;
    loadComparisons(selectedProjectId);
    loadBaselinesAndPlans(selectedProjectId);
  }, [selectedProjectId]);

  async function loadComparisons(projectId: number) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/baseline-comparisons`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to load comparisons");
      const data: BaselineComparison[] = await res.json();
      setComparisons(data || []);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load comparisons");
    } finally {
      setLoading(false);
    }
  }

  async function loadBaselinesAndPlans(projectId: number) {
    try {
      const [resB, resP] = await Promise.all([
        fetch(`/api/v1/projects/${projectId}/baselines`, { credentials: "include" }),
        fetch(`/api/v1/projects/${projectId}/execution-plans`, { credentials: "include" }),
      ]);
      if (resB.ok) {
        const bData = await resB.json();
        setBaselines(bData.baselines || []);
      }
      if (resP.ok) {
        const pData = await resP.json();
        const pList: SecurityExecutionPlan[] = pData.execution_plans || [];
        setCompletedPlans(pList.filter((p) => p.status === "COMPLETED"));
      }
    } catch {
      // Background load
    }
  }

  function handleProjectChange(id: number) {
    setSelectedProjectId(id);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  }

  // Run Comparison
  async function handleRunComparison(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedBaselineId || !selectedPlanId) return;

    setComparing(true);
    setErrorMsg(null);

    try {
      const res = await fetch(`/api/v1/baselines/${selectedBaselineId}/compare`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ execution_plan_id: selectedPlanId }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to run baseline comparison");
      }

      const created: BaselineComparison = await res.json();
      setSuccessMsg("Baseline comparison completed successfully.");
      setShowNewModal(false);
      setSelectedPlanId("");
      if (selectedProjectId) {
        loadComparisons(selectedProjectId);
      }
      handleOpenDetail(created.id);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error running comparison");
    } finally {
      setComparing(false);
    }
  }

  // Open Detail Modal
  async function handleOpenDetail(comparisonId: string) {
    setDetailLoading(true);
    setDetailData(null);
    try {
      const res = await fetch(`/api/v1/baseline-comparisons/${comparisonId}`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to load comparison detail");
      const data: ComparisonDetailResponse = await res.json();
      setDetailData(data);
      if (data.regressions.length > 0) {
        setActiveTab("REGRESSIONS");
      } else if (data.new_violations.length > 0) {
        setActiveTab("NEW_VIOLATIONS");
      } else {
        setActiveTab("ALL");
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load comparison details");
    } finally {
      setDetailLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-foreground">Baseline Comparisons</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Evaluate security regressions, resolved vulnerabilities, new violations, and untested controls.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Project Selector */}
          <select
            value={selectedProjectId || ""}
            onChange={(e) => handleProjectChange(Number(e.target.value))}
            className="h-9 px-3 text-xs bg-background border border-border rounded-lg text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>

          <Button
            onClick={() => setShowNewModal(true)}
            disabled={!selectedProjectId || baselines.length === 0 || completedPlans.length === 0}
            className="h-9 text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
            Compare Plan
          </Button>
        </div>
      </div>

      {/* Messages */}
      {errorMsg && (
        <div className="p-3 text-xs bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-muted-foreground hover:text-foreground">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 text-xs bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-muted-foreground hover:text-foreground">✕</button>
        </div>
      )}

      {/* Comparisons List */}
      {loading ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
          Loading baseline comparisons...
        </div>
      ) : comparisons.length === 0 ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl space-y-3">
          <p>No baseline comparisons recorded yet.</p>
          <p className="text-xs text-muted-foreground">
            {baselines.length === 0
              ? "Establish a Security Baseline first."
              : completedPlans.length === 0
              ? "Run an execution plan to completion to compare it against a baseline."
              : "Compare a completed execution plan against any established baseline."}
          </p>
          {baselines.length > 0 && completedPlans.length > 0 && (
            <Button size="sm" variant="outline" onClick={() => setShowNewModal(true)}>
              Compare Baseline
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {comparisons.map((c) => {
            const sum = c.summary || {};
            const regressions = sum.regressions_count || 0;
            const newViolations = sum.new_violations_count || 0;
            const improvements = sum.improvements_count || 0;
            const unchanged = sum.unchanged_count || 0;
            const notApp = sum.not_applicable_count || 0;

            return (
              <Card
                key={c.id}
                className="border border-border bg-card/60 hover:border-border/80 transition-all cursor-pointer hover:shadow-sm"
                onClick={() => handleOpenDetail(c.id)}
              >
                <CardContent className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                        Baseline v{sum.baseline_version || "1"}
                      </span>
                      <h3 className="text-sm font-bold text-foreground">
                        {sum.baseline_name || "Baseline"} vs. {sum.execution_plan_name || "Plan"}
                      </h3>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      Compared on {new Date(c.created_at).toLocaleString()}
                    </p>
                  </div>

                  {/* Summary metric badges */}
                  <div className="flex flex-wrap items-center gap-2">
                    {regressions > 0 && (
                      <span className="text-xs font-bold px-2.5 py-1 rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1">
                        <span>🚨</span> {regressions} Regression{regressions === 1 ? "" : "s"}
                      </span>
                    )}

                    {newViolations > 0 && (
                      <span className="text-xs font-bold px-2.5 py-1 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                        <span>⚠️</span> {newViolations} New Violation{newViolations === 1 ? "" : "s"}
                      </span>
                    )}

                    {improvements > 0 && (
                      <span className="text-xs font-bold px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                        <span>✅</span> {improvements} Improved
                      </span>
                    )}

                    {unchanged > 0 && (
                      <span className="text-xs font-medium px-2 py-1 rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/30">
                        {unchanged} Unchanged
                      </span>
                    )}

                    {notApp > 0 && (
                      <span className="text-xs font-medium px-2 py-1 rounded-md bg-secondary text-muted-foreground border border-border">
                        {notApp} Untested
                      </span>
                    )}

                    <Button size="sm" variant="outline" className="h-8 text-xs ml-2">
                      View Details
                    </Button>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* NEW COMPARISON MODAL */}
      {showNewModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-base font-bold text-foreground">Run Baseline Comparison</h3>
              <button onClick={() => setShowNewModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleRunComparison} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Select Baseline</label>
                <select
                  required
                  value={selectedBaselineId}
                  onChange={(e) => setSelectedBaselineId(e.target.value)}
                  className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                >
                  <option value="">-- Choose Baseline --</option>
                  {baselines.map((b) => (
                    <option key={b.id} value={b.id}>
                      v{b.version} - {b.name} ({b.status})
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Select Completed Execution Plan</label>
                <select
                  required
                  value={selectedPlanId}
                  onChange={(e) => setSelectedPlanId(e.target.value)}
                  className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                >
                  <option value="">-- Choose Execution Plan --</option>
                  {completedPlans.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.completed_tests} tests, {p.confirmed_findings} findings)
                    </option>
                  ))}
                </select>
              </div>

              <div className="p-3 bg-secondary/30 border border-border rounded-lg text-xs text-muted-foreground space-y-1">
                <p>• Unexecuted controls in the plan are categorized as <strong>Untested</strong> and never assumed secure.</p>
                <p>• Prior PASS with current failure indicates a <strong>Regression</strong>.</p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowNewModal(false)}>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={comparing || !selectedBaselineId || !selectedPlanId}
                  className="bg-primary text-primary-foreground"
                >
                  {comparing ? "Comparing..." : "Execute Comparison"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* DETAIL MODAL */}
      {detailData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-xl">
            <div className="flex items-center justify-between p-5 border-b border-border">
              <div>
                <h3 className="text-base font-bold text-foreground">
                  Comparison Breakdown: {detailData.baseline_name} (v{detailData.baseline_version}) vs. {detailData.plan_name}
                </h3>
                <p className="text-xs text-muted-foreground">
                  Evaluated {detailData.comparison.items.length} items deterministically.
                </p>
              </div>
              <button onClick={() => setDetailData(null)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            {/* Tabs */}
            <div className="flex items-center gap-2 px-5 py-2.5 border-b border-border bg-secondary/10 overflow-x-auto">
              {[
                { key: "REGRESSIONS", label: `Regressions (${detailData.regressions.length})`, color: "text-rose-400" },
                { key: "NEW_VIOLATIONS", label: `New Violations (${detailData.new_violations.length})`, color: "text-amber-400" },
                { key: "IMPROVEMENTS", label: `Improvements (${detailData.improvements.length})`, color: "text-emerald-400" },
                { key: "NOT_APPLICABLE", label: `Untested (${detailData.not_applicable.length})`, color: "text-muted-foreground" },
                { key: "ALL", label: `All (${detailData.comparison.items.length})`, color: "text-foreground" },
              ].map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setActiveTab(tab.key as typeof activeTab)}
                  className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors shrink-0 ${
                    activeTab === tab.key
                      ? "bg-primary text-primary-foreground"
                      : "bg-secondary/40 hover:bg-secondary text-muted-foreground"
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="p-5 overflow-y-auto space-y-3 flex-1">
              {detailLoading ? (
                <div className="py-8 text-center text-xs text-muted-foreground">Loading details...</div>
              ) : (
                (() => {
                  let itemsToRender: ComparisonItem[] = [];
                  if (activeTab === "REGRESSIONS") itemsToRender = detailData.regressions;
                  else if (activeTab === "NEW_VIOLATIONS") itemsToRender = detailData.new_violations;
                  else if (activeTab === "IMPROVEMENTS") itemsToRender = detailData.improvements;
                  else if (activeTab === "NOT_APPLICABLE") itemsToRender = detailData.not_applicable;
                  else itemsToRender = detailData.comparison.items;

                  if (itemsToRender.length === 0) {
                    return (
                      <div className="py-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                        No items found for this category.
                      </div>
                    );
                  }

                  return itemsToRender.map((it) => (
                    <div
                      key={it.id}
                      className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                        it.result === "REGRESSION"
                          ? "bg-rose-500/5 border-rose-500/30 text-rose-300"
                          : it.result === "NEW_VIOLATION"
                          ? "bg-amber-500/5 border-amber-500/30 text-amber-300"
                          : it.result === "IMPROVED"
                          ? "bg-emerald-500/5 border-emerald-500/30 text-emerald-300"
                          : "bg-secondary/20 border-border text-muted-foreground"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`font-bold px-2 py-0.5 rounded text-[10px] uppercase font-mono ${
                              it.result === "REGRESSION"
                                ? "bg-rose-500/20 text-rose-400"
                                : it.result === "NEW_VIOLATION"
                                ? "bg-amber-500/20 text-amber-400"
                                : it.result === "IMPROVED"
                                ? "bg-emerald-500/20 text-emerald-400"
                                : "bg-secondary text-secondary-foreground"
                            }`}
                          >
                            {it.result}
                          </span>
                          <span className="font-semibold text-foreground">
                            {it.explanation}
                          </span>
                        </div>

                        {it.finding_id && (
                          <span className="font-mono text-[10px] bg-secondary px-1.5 py-0.5 rounded text-muted-foreground shrink-0">
                            Finding ID: {it.finding_id.slice(0, 8)}...
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-6 text-[11px] text-muted-foreground">
                        <div>
                          Previous Behavior:{" "}
                          <strong className="text-foreground font-mono">
                            {it.previous_behavior || "None"}
                          </strong>
                        </div>
                        <div>
                          Current Behavior:{" "}
                          <strong className="text-foreground font-mono">
                            {it.current_behavior || "None"}
                          </strong>
                        </div>
                        {typeof it.evidence_reference?.endpoint === "string" && (
                          <div className="font-mono text-muted-foreground">
                            Endpoint: {it.evidence_reference.endpoint}
                          </div>
                        )}
                      </div>
                    </div>
                  ));
                })()
              )}
            </div>

            <div className="p-4 border-t border-border flex justify-between items-center">
              <Button
                size="sm"
                className="bg-primary text-primary-foreground hover:bg-primary/90 text-xs"
                onClick={() => router.push(`/security-gates?comparison_id=${detailData.comparison.id}`)}
              >
                Evaluate with Security Gate 🛡️
              </Button>
              <Button size="sm" variant="outline" onClick={() => setDetailData(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function BaselineComparisonsPage() {
  return (
    <React.Suspense
      fallback={
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
          Loading baseline comparisons...
        </div>
      }
    >
      <BaselineComparisonsContent />
    </React.Suspense>
  );
}
