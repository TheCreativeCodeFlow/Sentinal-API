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

interface SecurityExecutionPlan {
  id: string;
  project_id: number;
  suite_id?: string | null;
  suite_name?: string | null;
  profile_id?: string | null;
  profile_name?: string | null;
  source_type?: "PROFILE" | "SUITE" | "CUSTOM";
  name: string;
  status: "DRAFT" | "READY" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  execution_mode: "SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE";
  total_tests: number;
  completed_tests: number;
  confirmed_findings: number;
  inconclusive_tests: number;
  failed_tests: number;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
}

interface SecurityTestSuite {
  id: string;
  name: string;
  status: string;
  test_count: number;
}

interface SecurityTestOption {
  id: string;
  test_type: string;
  endpoint?: { path: string } | null;
  attacker_identity?: { name: string } | null;
}

export default function ExecutionPlansPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [plans, setPlans] = useState<SecurityExecutionPlan[]>([]);
  const [suites, setSuites] = useState<SecurityTestSuite[]>([]);
  const [availableTests, setAvailableTests] = useState<SecurityTestOption[]>([]);

  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // New Plan Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [planSourceType, setPlanSourceType] = useState<"SUITE" | "MANUAL">("SUITE");
  const [selectedSuiteId, setSelectedSuiteId] = useState("");
  const [selectedTestIds, setSelectedTestIds] = useState<string[]>([]);
  const [planName, setPlanName] = useState("");
  const [executionMode, setExecutionMode] = useState<"SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE">("SEQUENTIAL");
  const [creating, setCreating] = useState(false);

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

  // Load Plans, Suites, and Tests when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    loadPlans(selectedProjectId);
    loadSuites(selectedProjectId);
    loadTests(selectedProjectId);
  }, [selectedProjectId]);

  async function loadPlans(projId: number) {
    try {
      setLoading(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/projects/${projId}/execution-plans`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch execution plans");
      const data = await res.json();
      setPlans(data.execution_plans || []);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load execution plans");
    } finally {
      setLoading(false);
    }
  }

  async function loadSuites(projId: number) {
    try {
      const res = await fetch(`/api/v1/projects/${projId}/test-suites`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setSuites(data.test_suites || []);
      }
    } catch {
      // Non-blocking
    }
  }

  async function loadTests(projId: number) {
    try {
      const res = await fetch(`/api/v1/projects/${projId}/security-tests/`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setAvailableTests(data || []);
      }
    } catch {
      // Non-blocking
    }
  }

  const handleProjectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const id = parseInt(e.target.value, 10);
    setSelectedProjectId(id);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  };

  const handleCreatePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) return;

    try {
      setCreating(true);
      setErrorMsg(null);

      const payload: {
        name: string;
        execution_mode: string;
        suite_id?: string;
        security_test_ids?: string[];
      } = {
        name: planName.trim() || "Untitled Execution Plan",
        execution_mode: executionMode,
      };

      if (planSourceType === "SUITE") {
        if (!selectedSuiteId) throw new Error("Please select a test suite.");
        payload.suite_id = selectedSuiteId;
      } else {
        if (selectedTestIds.length === 0) throw new Error("Please select at least one security test.");
        payload.security_test_ids = selectedTestIds;
      }

      const res = await fetch(`/api/v1/projects/${selectedProjectId}/execution-plans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create execution plan");
      }

      const created = await res.json();
      setShowCreateModal(false);
      setPlanName("");
      setSelectedSuiteId("");
      setSelectedTestIds([]);
      router.push(`/execution-plans/${created.id}`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create execution plan");
    } finally {
      setCreating(false);
    }
  };

  const handleStartPlan = async (planId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/execution-plans/${planId}/start`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to start execution plan");
      }
      setSuccessMsg("Execution plan started.");
      if (selectedProjectId) await loadPlans(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to start execution plan");
    }
  };

  const handleCancelPlan = async (planId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/execution-plans/${planId}/cancel`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to cancel execution plan");
      }
      setSuccessMsg("Execution plan cancelled.");
      if (selectedProjectId) await loadPlans(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to cancel execution plan");
    }
  };

  const toggleTestSelection = (testId: string) => {
    if (selectedTestIds.includes(testId)) {
      setSelectedTestIds(selectedTestIds.filter((id) => id !== testId));
    } else {
      setSelectedTestIds([...selectedTestIds, testId]);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "RUNNING":
        return "bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse";
      case "FAILED":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      case "CANCELLED":
        return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
      case "READY":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
      default:
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </span>
            Security Execution Plans
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Orchestrate deterministic runs, track progress in real time, and enforce execution modes.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedProjectId || ""}
            onChange={handleProjectChange}
            className="h-9 px-3 text-xs rounded-lg border border-border bg-card text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary shadow-xs"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} {p.authorization_status === "authorized" ? "✓" : "(unauthorized)"}
              </option>
            ))}
          </select>

          <Button
            onClick={() => setShowCreateModal(true)}
            disabled={!selectedProjectId}
            className="h-9 text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
            </svg>
            New Execution Plan
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

      {/* Plans List */}
      {loading && plans.length === 0 ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
          Loading execution plans...
        </div>
      ) : plans.length === 0 ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl space-y-3">
          <p>No execution plans found for this project.</p>
          <Button size="sm" variant="outline" onClick={() => setShowCreateModal(true)}>
            Create Execution Plan
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {plans.map((plan) => {
            const percent = plan.total_tests > 0 ? Math.round((plan.completed_tests / plan.total_tests) * 100) : 0;
            return (
              <Card
                key={plan.id}
                className="border border-border hover:border-border/80 transition-all cursor-pointer hover:shadow-md bg-card/60"
                onClick={() => router.push(`/execution-plans/${plan.id}`)}
              >
                <CardContent className="p-5 space-y-4">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-foreground line-clamp-1">{plan.name}</h3>
                      {plan.profile_name ? (
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          Profile: <span className="text-cyan-400 font-medium">{plan.profile_name}</span>
                        </p>
                      ) : plan.suite_name ? (
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          Suite: <span className="text-foreground">{plan.suite_name}</span>
                        </p>
                      ) : (
                        <p className="text-[11px] text-muted-foreground mt-0.5">Custom Test Selection</p>
                      )}
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getStatusBadge(plan.status)}`}>
                      {plan.status}
                    </span>
                  </div>

                  {/* Mode & Stats */}
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-secondary text-secondary-foreground font-semibold">
                      {plan.execution_mode}
                    </span>
                    <span>
                      {plan.completed_tests} / {plan.total_tests} Tests
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="space-y-1">
                    <div className="w-full bg-secondary rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-2 rounded-full transition-all duration-500 ${
                          plan.status === "COMPLETED"
                            ? "bg-emerald-500"
                            : plan.status === "FAILED"
                            ? "bg-rose-500"
                            : "bg-blue-500"
                        }`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-muted-foreground">
                      <span>{percent}% Complete</span>
                      {plan.confirmed_findings > 0 && (
                        <span className="text-rose-400 font-bold">
                          {plan.confirmed_findings} Confirmed Finding{plan.confirmed_findings === 1 ? "" : "s"}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions & Timestamps */}
                  <div className="flex items-center justify-between pt-2 border-t border-border/50 text-[11px]">
                    <span className="text-muted-foreground">
                      {new Date(plan.created_at).toLocaleDateString()}
                    </span>

                    <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                      {(plan.status === "DRAFT" || plan.status === "READY") && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => handleStartPlan(plan.id, e)}
                          className="h-7 text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border-emerald-500/20"
                        >
                          Start
                        </Button>
                      )}
                      {(plan.status === "RUNNING" || plan.status === "READY") && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => handleCancelPlan(plan.id, e)}
                          className="h-7 text-xs bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/20"
                        >
                          Cancel
                        </Button>
                      )}
                      {plan.status === "COMPLETED" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            router.push("/baselines");
                          }}
                          className="h-7 text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border-emerald-500/20"
                          title="Capture as Baseline"
                        >
                          Baseline
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => router.push(`/execution-plans/${plan.id}`)}
                        className="h-7 text-xs"
                      >
                        Details →
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* New Execution Plan Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-foreground">Create Security Execution Plan</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleCreatePlan} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Plan Name</label>
                <Input
                  value={planName}
                  onChange={(e) => setPlanName(e.target.value)}
                  placeholder="e.g. Daily Authorization Smoke Test"
                  required
                />
              </div>

              {/* Source Mode Toggle */}
              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Test Source</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setPlanSourceType("SUITE")}
                    className={`p-2 text-xs rounded-lg border font-medium transition-all ${
                      planSourceType === "SUITE"
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border text-muted-foreground hover:bg-accent"
                    }`}
                  >
                    From Test Suite
                  </button>
                  <button
                    type="button"
                    onClick={() => setPlanSourceType("MANUAL")}
                    className={`p-2 text-xs rounded-lg border font-medium transition-all ${
                      planSourceType === "MANUAL"
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border text-muted-foreground hover:bg-accent"
                    }`}
                  >
                    Select Tests Directly
                  </button>
                </div>
              </div>

              {/* Suite Selection */}
              {planSourceType === "SUITE" && (
                <div>
                  <label className="text-xs font-medium text-foreground block mb-1">Select Active Suite</label>
                  <select
                    value={selectedSuiteId}
                    onChange={(e) => setSelectedSuiteId(e.target.value)}
                    required
                    className="w-full h-9 text-xs rounded-lg border border-border bg-background px-3 text-foreground"
                  >
                    <option value="">-- Choose Test Suite --</option>
                    {suites.map((s) => (
                      <option key={s.id} value={s.id} disabled={s.status === "DISABLED"}>
                        {s.name} ({s.test_count} tests) {s.status === "DISABLED" ? "[DISABLED]" : ""}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Manual Test Selection */}
              {planSourceType === "MANUAL" && (
                <div>
                  <label className="text-xs font-medium text-foreground block mb-1">
                    Select Tests ({selectedTestIds.length} chosen)
                  </label>
                  <div className="max-h-48 overflow-y-auto border border-border rounded-lg p-2 space-y-1 bg-background">
                    {availableTests.map((t) => (
                      <label
                        key={t.id}
                        className="flex items-center gap-2 p-1.5 rounded hover:bg-accent/40 cursor-pointer text-xs"
                      >
                        <input
                          type="checkbox"
                          checked={selectedTestIds.includes(t.id)}
                          onChange={() => toggleTestSelection(t.id)}
                          className="rounded border-border text-primary focus:ring-primary"
                        />
                        <span className="font-mono text-[11px] text-blue-400 font-semibold">[{t.test_type}]</span>
                        <span className="truncate text-foreground font-mono">{t.endpoint?.path || "Unknown endpoint"}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}

              {/* Execution Mode */}
              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Execution Mode</label>
                <select
                  value={executionMode}
                  onChange={(e) => setExecutionMode(e.target.value as "SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE")}
                  className="w-full h-9 text-xs rounded-lg border border-border bg-background px-3 text-foreground"
                >
                  <option value="SEQUENTIAL">SEQUENTIAL - Execute all tests sequentially in order</option>
                  <option value="FAIL_FAST">FAIL_FAST - Stop immediately on first test failure/error</option>
                  <option value="CONTINUE_ON_FAILURE">CONTINUE_ON_FAILURE - Log errors and continue to end</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" className="bg-primary text-primary-foreground" disabled={creating}>
                  {creating ? "Creating..." : "Create Plan"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
