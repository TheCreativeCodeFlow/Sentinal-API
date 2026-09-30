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

interface SecurityTestSuiteItem {
  id: string;
  suite_id: string;
  security_test_id: string;
  execution_order: number;
  enabled: boolean;
  created_at: string;
  test_type?: string | null;
  endpoint?: string | null;
  attacker_identity?: string | null;
}

interface SecurityTestSuite {
  id: string;
  project_id: number;
  name: string;
  description?: string | null;
  status: "ACTIVE" | "DISABLED";
  test_count: number;
  items: SecurityTestSuiteItem[];
  created_at: string;
  updated_at: string;
}

interface SecurityTestOption {
  id: string;
  test_type: string;
  endpoint?: { path: string } | null;
  attacker_identity?: { name: string } | null;
}

export default function TestSuitesPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [suites, setSuites] = useState<SecurityTestSuite[]>([]);
  const [activeSuite, setActiveSuite] = useState<SecurityTestSuite | null>(null);
  const [availableTests, setAvailableTests] = useState<SecurityTestOption[]>([]);

  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modals
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createStatus, setCreateStatus] = useState<"ACTIVE" | "DISABLED">("ACTIVE");

  const [showAddTestModal, setShowAddTestModal] = useState(false);
  const [selectedTestId, setSelectedTestId] = useState("");
  const [addTestOrder, setAddTestOrder] = useState<number | undefined>(undefined);

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

  // Load Suites and Tests when Project Changes
  useEffect(() => {
    if (!selectedProjectId) return;
    loadSuites(selectedProjectId);
    loadProjectTests(selectedProjectId);
  }, [selectedProjectId]);

  async function loadSuites(projId: number) {
    try {
      setLoading(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/projects/${projId}/test-suites`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch test suites");
      const data = await res.json();
      setSuites(data.test_suites || []);
      if (activeSuite) {
        const refreshed = (data.test_suites || []).find((s: SecurityTestSuite) => s.id === activeSuite.id);
        setActiveSuite(refreshed || null);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load test suites");
    } finally {
      setLoading(false);
    }
  }

  async function loadProjectTests(projId: number) {
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
    setActiveSuite(null);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  };

  const handleCreateSuite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !createName.trim()) return;

    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/test-suites`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: createName.trim(),
          description: createDesc.trim() || null,
          status: createStatus,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create suite");
      }

      const created = await res.json();
      setSuccessMsg(`Test suite "${created.name}" created successfully.`);
      setShowCreateModal(false);
      setCreateName("");
      setCreateDesc("");
      setCreateStatus("ACTIVE");
      await loadSuites(selectedProjectId);
      setActiveSuite(created);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create suite");
    }
  };

  const handleToggleSuiteStatus = async (suite: SecurityTestSuite) => {
    const newStatus = suite.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${suite.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update suite status");
      await loadSuites(suite.project_id);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to update suite status");
    }
  };

  const handleDeleteSuite = async (suiteId: string) => {
    if (!confirm("Are you sure you want to delete this test suite?")) return;
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${suiteId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete test suite");
      setSuccessMsg("Test suite deleted.");
      if (activeSuite?.id === suiteId) setActiveSuite(null);
      if (selectedProjectId) await loadSuites(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to delete suite");
    }
  };

  const handleAddTestToSuite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeSuite || !selectedTestId) return;

    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${activeSuite.id}/tests`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          security_test_id: selectedTestId,
          execution_order: addTestOrder ? Number(addTestOrder) : undefined,
          enabled: true,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to add test to suite");
      }

      setShowAddTestModal(false);
      setSelectedTestId("");
      setAddTestOrder(undefined);
      setSuccessMsg("Test added to suite.");
      if (selectedProjectId) await loadSuites(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to add test to suite");
    }
  };

  const handleToggleItemEnabled = async (item: SecurityTestSuiteItem) => {
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${item.suite_id}/tests/${item.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ enabled: !item.enabled }),
      });
      if (!res.ok) throw new Error("Failed to toggle test enabled state");
      if (selectedProjectId) await loadSuites(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to update test state");
    }
  };

  const handleRemoveItem = async (item: SecurityTestSuiteItem) => {
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${item.suite_id}/tests/${item.id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to remove test from suite");
      if (selectedProjectId) await loadSuites(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to remove test");
    }
  };

  const handleMoveItemOrder = async (item: SecurityTestSuiteItem, direction: "UP" | "DOWN") => {
    if (!activeSuite) return;
    const currentOrder = item.execution_order;
    const targetOrder = direction === "UP" ? currentOrder - 1 : currentOrder + 1;
    if (targetOrder < 1 || targetOrder > activeSuite.items.length) return;

    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/test-suites/${item.suite_id}/tests/${item.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ execution_order: targetOrder }),
      });
      if (!res.ok) throw new Error("Failed to update test order");
      if (selectedProjectId) await loadSuites(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to reorder test");
    }
  };

  const handleCreatePlanFromSuite = async (suite: SecurityTestSuite) => {
    if (!selectedProjectId) return;
    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/execution-plans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: `${suite.name} - Plan`,
          suite_id: suite.id,
          execution_mode: "SEQUENTIAL",
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create execution plan");
      }

      const plan = await res.json();
      router.push(`/execution-plans/${plan.id}`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create plan");
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
            </span>
            Security Test Suites
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Group, order, and curate deterministic SecurityTests into repeatable test suites.
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
            New Test Suite
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

      {/* Main Grid: Suites on Left, Suite Items Manager on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Suite List */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Configured Suites ({suites.length})
            </h2>
          </div>

          {loading && suites.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
              Loading test suites...
            </div>
          ) : suites.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl space-y-3">
              <p>No test suites created for this project yet.</p>
              <Button size="sm" variant="outline" onClick={() => setShowCreateModal(true)}>
                Create First Suite
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {suites.map((suite) => {
                const isSelected = activeSuite?.id === suite.id;
                return (
                  <Card
                    key={suite.id}
                    className={`cursor-pointer transition-all border ${
                      isSelected
                        ? "border-primary/60 bg-accent/30 shadow-md"
                        : "border-border hover:border-border/80 hover:bg-accent/10"
                    }`}
                    onClick={() => setActiveSuite(suite)}
                  >
                    <CardContent className="p-4 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-sm text-foreground truncate">
                          {suite.name}
                        </span>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                            suite.status === "ACTIVE"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                              : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                          }`}
                        >
                          {suite.status}
                        </span>
                      </div>

                      {suite.description && (
                        <p className="text-xs text-muted-foreground line-clamp-2">
                          {suite.description}
                        </p>
                      )}

                      <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t border-border/50">
                        <span className="font-medium text-foreground">
                          {suite.test_count} {suite.test_count === 1 ? "test" : "tests"}
                        </span>
                        <span>{new Date(suite.created_at).toLocaleDateString()}</span>
                      </div>

                      <div className="flex items-center justify-end gap-2 pt-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => handleToggleSuiteStatus(suite)}
                          className="text-[11px] px-2 py-1 rounded bg-secondary hover:bg-secondary/80 text-secondary-foreground transition-colors"
                        >
                          {suite.status === "ACTIVE" ? "Disable" : "Enable"}
                        </button>
                        <button
                          onClick={() => handleCreatePlanFromSuite(suite)}
                          disabled={suite.status === "DISABLED" || suite.test_count === 0}
                          className="text-[11px] px-2 py-1 rounded bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 transition-colors disabled:opacity-40"
                          title={suite.status === "DISABLED" ? "Cannot plan disabled suite" : "Generate execution plan"}
                        >
                          Create Plan
                        </button>
                        <button
                          onClick={() => handleDeleteSuite(suite.id)}
                          className="text-[11px] px-2 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20 transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Active Suite Details & Item Reordering */}
        <div className="lg:col-span-7 space-y-4">
          {activeSuite ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-card border border-border rounded-xl">
                <div>
                  <h2 className="text-base font-semibold text-foreground flex items-center gap-2">
                    {activeSuite.name}
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        activeSuite.status === "ACTIVE"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                          : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                      }`}
                    >
                      {activeSuite.status}
                    </span>
                  </h2>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {activeSuite.description || "No description provided."}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setShowAddTestModal(true)}
                    className="text-xs gap-1"
                  >
                    + Add Test
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => handleCreatePlanFromSuite(activeSuite)}
                    disabled={activeSuite.status === "DISABLED" || activeSuite.items.length === 0}
                    className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white"
                  >
                    Create Plan
                  </Button>
                </div>
              </div>

              {/* Items List */}
              <div className="space-y-2">
                <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-1">
                  Suite Execution Order ({activeSuite.items.length} items)
                </div>

                {activeSuite.items.length === 0 ? (
                  <div className="p-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl space-y-2">
                    <p>No tests added to this suite yet.</p>
                    <Button size="sm" variant="outline" onClick={() => setShowAddTestModal(true)}>
                      Select Tests to Include
                    </Button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {activeSuite.items.map((item, idx) => (
                      <div
                        key={item.id}
                        className={`flex items-center justify-between p-3 rounded-lg border transition-all ${
                          item.enabled
                            ? "bg-card border-border"
                            : "bg-muted/20 border-border/50 opacity-60"
                        }`}
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className="flex items-center justify-center w-6 h-6 rounded-md bg-secondary text-secondary-foreground font-mono text-xs font-bold shrink-0">
                            {item.execution_order}
                          </span>

                          <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono">
                                {item.test_type || "SECURITY_TEST"}
                              </span>
                              <span className="text-xs font-mono text-foreground truncate">
                                {item.endpoint || "Custom Endpoint"}
                              </span>
                            </div>
                            {item.attacker_identity && (
                              <div className="text-[11px] text-muted-foreground mt-0.5">
                                Attacker: <span className="text-foreground">{item.attacker_identity}</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Item Actions */}
                        <div className="flex items-center gap-2 shrink-0">
                          {/* Order Buttons */}
                          <div className="flex items-center gap-1">
                            <button
                              onClick={() => handleMoveItemOrder(item, "UP")}
                              disabled={idx === 0}
                              className="p-1 rounded hover:bg-secondary text-muted-foreground hover:text-foreground disabled:opacity-20"
                              title="Move Up"
                            >
                              ▲
                            </button>
                            <button
                              onClick={() => handleMoveItemOrder(item, "DOWN")}
                              disabled={idx === activeSuite.items.length - 1}
                              className="p-1 rounded hover:bg-secondary text-muted-foreground hover:text-foreground disabled:opacity-20"
                              title="Move Down"
                            >
                              ▼
                            </button>
                          </div>

                          {/* Enabled Toggle */}
                          <button
                            onClick={() => handleToggleItemEnabled(item)}
                            className={`text-[10px] font-bold px-2 py-1 rounded border transition-colors ${
                              item.enabled
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                                : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                            }`}
                          >
                            {item.enabled ? "ENABLED" : "DISABLED"}
                          </button>

                          {/* Delete Item */}
                          <button
                            onClick={() => handleRemoveItem(item)}
                            className="p-1 text-rose-400 hover:text-rose-300 rounded hover:bg-rose-500/10 transition-colors"
                            title="Remove from suite"
                          >
                            ✕
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center border border-dashed border-border rounded-xl text-center p-6 text-muted-foreground">
              <svg className="w-10 h-10 mb-3 text-muted-foreground/50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              <p className="text-sm font-medium">Select a Test Suite to View and Manage Order</p>
              <p className="text-xs text-muted-foreground/80 mt-1">
                You can configure test execution sequences, enable or disable specific tests, and export plans.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Create Suite Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-foreground">Create Security Test Suite</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleCreateSuite} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Suite Name</label>
                <Input
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  placeholder="e.g. Critical API Regression Suite"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Description (Optional)</label>
                <textarea
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  placeholder="Purpose, boundaries, and scope of this test suite..."
                  rows={3}
                  className="w-full text-xs rounded-lg border border-border bg-background p-2.5 text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary"
                />
              </div>

              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Initial Status</label>
                <select
                  value={createStatus}
                  onChange={(e) => setCreateStatus(e.target.value as "ACTIVE" | "DISABLED")}
                  className="w-full h-9 text-xs rounded-lg border border-border bg-background px-3 text-foreground"
                >
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="DISABLED">DISABLED</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" className="bg-primary text-primary-foreground">
                  Create Suite
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Test to Suite Modal */}
      {showAddTestModal && activeSuite && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-foreground">Add Test to Suite: {activeSuite.name}</h3>
              <button onClick={() => setShowAddTestModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleAddTestToSuite} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-foreground block mb-1">Select Security Test</label>
                <select
                  value={selectedTestId}
                  onChange={(e) => setSelectedTestId(e.target.value)}
                  required
                  className="w-full h-10 text-xs rounded-lg border border-border bg-background px-3 text-foreground"
                >
                  <option value="">-- Choose a configured security test --</option>
                  {availableTests.map((t) => (
                    <option key={t.id} value={t.id}>
                      [{t.test_type}] {t.endpoint?.path || "Unknown endpoint"} {t.attacker_identity ? `(${t.attacker_identity.name})` : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-foreground block mb-1">
                  Execution Order (Optional - defaults to next sequential position)
                </label>
                <Input
                  type="number"
                  min={1}
                  value={addTestOrder ?? ""}
                  onChange={(e) => setAddTestOrder(e.target.value ? parseInt(e.target.value, 10) : undefined)}
                  placeholder={`Default: ${activeSuite.items.length + 1}`}
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowAddTestModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" className="bg-primary text-primary-foreground" disabled={!selectedTestId}>
                  Add to Suite
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
