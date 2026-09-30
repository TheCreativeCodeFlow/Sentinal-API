"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface SecurityBaselineControl {
  id: string;
  baseline_id: string;
  control_type: string;
  target_type: string;
  target_id: string;
  expected_behavior: string;
  severity: string;
  enabled: boolean;
  configuration: Record<string, unknown>;
  created_at: string;
}

interface SecurityBaseline {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "DRAFT" | "ACTIVE" | "ARCHIVED";
  source_execution_plan_id: string | null;
  version: number;
  control_count: number;
  controls: SecurityBaselineControl[];
  created_at: string;
  updated_at: string;
}

interface SecurityExecutionPlan {
  id: string;
  name: string;
  status: string;
  total_tests: number;
  completed_tests: number;
  confirmed_findings: number;
  completed_at: string | null;
}

export default function BaselinesPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [baselines, setBaselines] = useState<SecurityBaseline[]>([]);
  const [completedPlans, setCompletedPlans] = useState<SecurityExecutionPlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Capture Baseline Modal
  const [showCaptureModal, setShowCaptureModal] = useState(false);
  const [selectedPlanId, setSelectedPlanId] = useState("");
  const [baselineName, setBaselineName] = useState("");
  const [baselineDesc, setBaselineDesc] = useState("");
  const [capturing, setCapturing] = useState(false);

  // View Controls Modal
  const [activeBaselineForControls, setActiveBaselineForControls] = useState<SecurityBaseline | null>(null);

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

  // Load Baselines and Plans when Project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    loadBaselines(selectedProjectId);
    loadCompletedPlans(selectedProjectId);
  }, [selectedProjectId]);

  async function loadBaselines(projectId: number) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/baselines`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch security baselines");
      const data = await res.json();
      setBaselines(data.baselines || []);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load baselines");
    } finally {
      setLoading(false);
    }
  }

  async function loadCompletedPlans(projectId: number) {
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/execution-plans`, {
        credentials: "include",
      });
      if (res.ok) {
        const data = await res.json();
        const plans: SecurityExecutionPlan[] = data.execution_plans || [];
        setCompletedPlans(plans.filter((p) => p.status === "COMPLETED"));
      }
    } catch {
      // Non-critical background fetch
    }
  }

  function handleProjectChange(id: number) {
    setSelectedProjectId(id);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  }

  // Activate Baseline
  async function handleActivateBaseline(baseline: SecurityBaseline) {
    try {
      const res = await fetch(`/api/v1/baselines/${baseline.id}/activate`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to activate baseline");
      if (selectedProjectId) {
        loadBaselines(selectedProjectId);
      }
      setSuccessMsg(`Baseline v${baseline.version} is now the ACTIVE project baseline.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to activate baseline");
    }
  }

  // Archive Baseline
  async function handleArchiveBaseline(baseline: SecurityBaseline) {
    try {
      const res = await fetch(`/api/v1/baselines/${baseline.id}/archive`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to archive baseline");
      if (selectedProjectId) {
        loadBaselines(selectedProjectId);
      }
      setSuccessMsg(`Baseline v${baseline.version} archived.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to archive baseline");
    }
  }

  // Capture Baseline from Plan
  async function handleCaptureBaseline(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId || !selectedPlanId) return;

    setCapturing(true);
    setErrorMsg(null);

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/baselines/from-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          execution_plan_id: selectedPlanId,
          name: baselineName.trim() || undefined,
          description: baselineDesc.trim() || undefined,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to capture baseline from execution plan");
      }

      const created: SecurityBaseline = await res.json();
      setSuccessMsg(`Captured Baseline v${created.version} with ${created.control_count} controls.`);
      setShowCaptureModal(false);
      setBaselineName("");
      setBaselineDesc("");
      setSelectedPlanId("");
      loadBaselines(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error capturing baseline");
    } finally {
      setCapturing(false);
    }
  }

  function getStatusBadge(s: string) {
    switch (s) {
      case "ACTIVE":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "DRAFT":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "ARCHIVED":
        return "bg-secondary text-muted-foreground border-border";
      default:
        return "bg-secondary text-secondary-foreground border-border";
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-foreground">Security Baselines</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Verified security snapshots captured from completed execution plans. Single active baseline enforced.
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
            onClick={() => setShowCaptureModal(true)}
            disabled={!selectedProjectId || completedPlans.length === 0}
            className="h-9 text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
            </svg>
            Capture from Plan
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

      {/* Baselines Grid */}
      {loading ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
          Loading security baselines...
        </div>
      ) : baselines.length === 0 ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl space-y-3">
          <p>No security baselines established for this project.</p>
          <p className="text-xs text-muted-foreground">
            {completedPlans.length === 0
              ? "Run an execution plan to completion to capture your first security baseline."
              : "Capture a baseline from one of your completed execution plans."}
          </p>
          {completedPlans.length > 0 && (
            <Button size="sm" variant="outline" onClick={() => setShowCaptureModal(true)}>
              Capture from Completed Plan
            </Button>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {baselines.map((b) => (
            <Card
              key={b.id}
              className={`border transition-all flex flex-col justify-between ${
                b.status === "ACTIVE"
                  ? "border-emerald-500/40 bg-emerald-500/5 shadow-xs"
                  : "border-border bg-card/60"
              }`}
            >
              <CardContent className="p-5 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                        v{b.version}
                      </span>
                      <h3 className="text-sm font-bold text-foreground line-clamp-1">{b.name}</h3>
                    </div>
                    {b.description && (
                      <p className="text-xs text-muted-foreground line-clamp-2">{b.description}</p>
                    )}
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getStatusBadge(b.status)}`}>
                    {b.status}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs text-muted-foreground bg-secondary/30 p-2.5 rounded-lg border border-border/50">
                  <span>Verified Controls:</span>
                  <span className="font-mono font-bold text-foreground">{b.control_count} controls</span>
                </div>

                {/* Actions */}
                <div className="pt-2 border-t border-border flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 text-xs px-2.5"
                      onClick={() => setActiveBaselineForControls(b)}
                    >
                      View Controls
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 text-xs px-2.5"
                      onClick={() => router.push(`/baseline-comparisons?baseline_id=${b.id}`)}
                    >
                      Compare
                    </Button>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {b.status !== "ACTIVE" && (
                      <Button
                        size="sm"
                        variant="default"
                        className="h-8 text-xs px-2.5 bg-emerald-600 hover:bg-emerald-500 text-white"
                        onClick={() => handleActivateBaseline(b)}
                      >
                        Activate
                      </Button>
                    )}
                    {b.status === "ACTIVE" && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-8 text-xs px-2.5 text-muted-foreground"
                        onClick={() => handleArchiveBaseline(b)}
                      >
                        Archive
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* CAPTURE BASELINE MODAL */}
      {showCaptureModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-base font-bold text-foreground">Capture Security Baseline</h3>
              <button onClick={() => setShowCaptureModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleCaptureBaseline} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Select Completed Execution Plan</label>
                <select
                  required
                  value={selectedPlanId}
                  onChange={(e) => setSelectedPlanId(e.target.value)}
                  className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                >
                  <option value="">-- Choose an execution plan --</option>
                  {completedPlans.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.completed_tests} tests, {p.confirmed_findings} findings)
                    </option>
                  ))}
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Baseline Name (Optional)</label>
                <Input
                  placeholder="e.g. Q1 Release Security Baseline"
                  value={baselineName}
                  onChange={(e) => setBaselineName(e.target.value)}
                  className="h-9 text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Description (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="Notes on the baseline verification scope..."
                  value={baselineDesc}
                  onChange={(e) => setBaselineDesc(e.target.value)}
                  className="w-full text-xs p-2.5 rounded-lg border border-border bg-background text-foreground"
                />
              </div>

              <div className="p-3 bg-secondary/30 border border-border rounded-lg text-xs text-muted-foreground">
                Capturing will extract verified controls from all completed security tests and establish version increment.
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowCaptureModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" disabled={capturing || !selectedPlanId} className="bg-primary text-primary-foreground">
                  {capturing ? "Capturing..." : "Capture Baseline"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* VIEW CONTROLS MODAL */}
      {activeBaselineForControls && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-xl">
            <div className="flex items-center justify-between p-5 border-b border-border">
              <div>
                <h3 className="text-base font-bold text-foreground">
                  Baseline Controls (v{activeBaselineForControls.version}): {activeBaselineForControls.name}
                </h3>
                <p className="text-xs text-muted-foreground">
                  Total of {activeBaselineForControls.controls?.length || activeBaselineForControls.control_count} verified controls.
                </p>
              </div>
              <button onClick={() => setActiveBaselineForControls(null)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <div className="p-5 overflow-y-auto space-y-2 flex-1">
              {!activeBaselineForControls.controls || activeBaselineForControls.controls.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                  No detailed controls loaded for this baseline.
                </div>
              ) : (
                activeBaselineForControls.controls.map((ctrl) => (
                  <div
                    key={ctrl.id}
                    className="p-3 bg-secondary/20 border border-border rounded-lg flex items-center justify-between text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-foreground">{ctrl.control_type}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-secondary text-secondary-foreground">
                          {ctrl.target_type}: {ctrl.target_id}
                        </span>
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        Expected Behavior: <strong className="text-foreground font-mono">{ctrl.expected_behavior}</strong>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          ctrl.expected_behavior === "PASS"
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                            : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                        }`}
                      >
                        {ctrl.expected_behavior}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="p-4 border-t border-border flex justify-end">
              <Button size="sm" variant="outline" onClick={() => setActiveBaselineForControls(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
