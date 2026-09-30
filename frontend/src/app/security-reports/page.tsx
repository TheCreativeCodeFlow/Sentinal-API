"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface SecurityReport {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "DRAFT" | "PUBLISHED" | "ARCHIVED";
  report_type: "SECURITY_ASSESSMENT" | "EXECUTION" | "BASELINE_REGRESSION" | "INVESTIGATION";
  source_execution_plan_id: string | null;
  source_gate_evaluation_id: string | null;
  source_investigation_id: string | null;
  version: number;
  created_at: string;
  updated_at: string;
  generated_at: string | null;
  latest_snapshot_checksum: string | null;
}

interface SecurityExecutionPlan {
  id: string;
  name: string;
  status: string;
}

interface SecurityGateEvaluation {
  id: string;
  gate_id: string;
  status: string;
  evaluated_at: string;
}

interface SecurityInvestigation {
  id: string;
  title: string;
  status: string;
}

function SecurityReportsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const preselectedPlanId = searchParams.get("plan_id");

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [plans, setPlans] = useState<SecurityExecutionPlan[]>([]);
  const [gateEvals, setGateEvals] = useState<SecurityGateEvaluation[]>([]);
  const [investigations, setInvestigations] = useState<SecurityInvestigation[]>([]);

  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");

  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [createType, setCreateType] = useState<string>("SECURITY_ASSESSMENT");
  const [createPlanId, setCreatePlanId] = useState<string>(preselectedPlanId || "");
  const [createGateEvalId, setCreateGateEvalId] = useState<string>("");
  const [createInvId, setCreateInvId] = useState<string>("");
  const [creating, setCreating] = useState(false);

  // Action Loading states
  const [generatingId, setGeneratingId] = useState<string | null>(null);
  const [archivingId, setArchivingId] = useState<string | null>(null);

  // Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
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

  // Fetch Project Resources & Reports
  useEffect(() => {
    if (!selectedProjectId) return;
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", selectedProjectId.toString());
    }

    async function loadProjectData() {
      try {
        setLoading(true);
        setErrorMsg(null);

        // Fetch Reports
        const repRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-reports`, {
          credentials: "include",
        });
        if (repRes.ok) {
          const repData: SecurityReport[] = await repRes.json();
          setReports(repData);
        } else {
          setReports([]);
        }

        // Fetch Plans
        const planRes = await fetch(`/api/v1/projects/${selectedProjectId}/execution-plans`, {
          credentials: "include",
        });
        if (planRes.ok) {
          const planData = await planRes.json();
          setPlans(planData.items || planData || []);
        }

        // Fetch Investigations
        const invRes = await fetch(`/api/v1/projects/${selectedProjectId}/investigations`, {
          credentials: "include",
        });
        if (invRes.ok) {
          const invData = await invRes.json();
          setInvestigations(invData || []);
        }

        // Fetch Security Gates & their evaluations
        const gatesRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-gates`, {
          credentials: "include",
        });
        if (gatesRes.ok) {
          const gatesData = await gatesRes.json();
          const evals: SecurityGateEvaluation[] = [];
          for (const g of gatesData) {
            try {
              const evalRes = await fetch(`/api/v1/security-gates/${g.id}/evaluations`, {
                credentials: "include",
              });
              if (evalRes.ok) {
                const evalData = await evalRes.json();
                evals.push(...(evalData || []));
              }
            } catch {
              // ignore
            }
          }
          setGateEvals(evals);
        }
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load report data");
      } finally {
        setLoading(false);
      }
    }

    loadProjectData();
  }, [selectedProjectId]);

  // Handle Create Report
  const handleCreateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    if (!createName.trim()) {
      setErrorMsg("Report name is required.");
      return;
    }
    if (!createPlanId && !createGateEvalId && !createInvId) {
      setErrorMsg("At least one source (Execution Plan, Gate Evaluation, or Investigation) is required.");
      return;
    }

    try {
      setCreating(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/security-reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: createName.trim(),
          description: createDesc.trim() || null,
          report_type: createType,
          source_execution_plan_id: createPlanId || null,
          source_gate_evaluation_id: createGateEvalId || null,
          source_investigation_id: createInvId || null,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to create security report");
      }

      const created: SecurityReport = await res.json();
      setReports((prev) => [created, ...prev]);
      setShowCreateModal(false);
      setCreateName("");
      setCreateDesc("");
      setCreatePlanId("");
      setCreateGateEvalId("");
      setCreateInvId("");
      setSuccessMsg(`Security Report "${created.name}" created successfully as DRAFT.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Creation failed");
    } finally {
      setCreating(false);
    }
  };

  // Handle Generate Report Snapshot
  const handleGenerateReport = async (reportId: string) => {
    try {
      setGeneratingId(reportId);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/security-reports/${reportId}/generate`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to generate report snapshot");
      }

      const snapshot = await res.json();
      setSuccessMsg(`Report generated successfully! Snapshot v${snapshot.version} created (SHA-256: ${snapshot.checksum.substring(0, 12)}...).`);

      // Refresh list
      if (selectedProjectId) {
        const repRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-reports`, {
          credentials: "include",
        });
        if (repRes.ok) {
          setReports(await repRes.json());
        }
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Generation failed");
    } finally {
      setGeneratingId(null);
    }
  };

  // Handle Archive Report
  const handleArchiveReport = async (reportId: string, reportName: string) => {
    if (!confirm(`Are you sure you want to ARCHIVE "${reportName}"? Once archived, the report cannot be regenerated or modified.`)) {
      return;
    }

    try {
      setArchivingId(reportId);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/security-reports/${reportId}/archive`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to archive report");
      }

      setSuccessMsg(`Report "${reportName}" is now permanently archived and immutable.`);

      // Update state locally
      setReports((prev) =>
        prev.map((r) => (r.id === reportId ? { ...r, status: "ARCHIVED" } : r))
      );
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Archiving failed");
    } finally {
      setArchivingId(null);
    }
  };

  // Handle Delete Report
  const handleDeleteReport = async (reportId: string, reportName: string) => {
    if (!confirm(`Are you sure you want to permanently delete draft report "${reportName}"?`)) {
      return;
    }

    try {
      setErrorMsg(null);
      const res = await fetch(`/api/v1/security-reports/${reportId}`, {
        method: "DELETE",
        credentials: "include",
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to delete report");
      }

      setReports((prev) => prev.filter((r) => r.id !== reportId));
      setSuccessMsg(`Report "${reportName}" deleted.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Deletion failed");
    }
  };

  // Download File Helper
  const downloadJson = async (url: string, filename: string) => {
    try {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Download failed");
      }
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const downloadUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(downloadUrl);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to download JSON");
    }
  };

  // Filtered reports
  const filteredReports = reports.filter((r) => {
    if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
    if (typeFilter !== "ALL" && r.report_type !== typeFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Reports & Evidence Packages</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Deterministic security reporting with strict provenance tracking, immutable cryptographic checksums, and credential redaction.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {projects.length > 0 && (
            <div className="flex items-center gap-2">
              <label htmlFor="project-select" className="text-xs font-semibold uppercase text-muted-foreground">
                Project:
              </label>
              <select
                id="project-select"
                className="bg-card border border-border rounded-md px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-2 focus:ring-primary"
                value={selectedProjectId || ""}
                onChange={(e) => setSelectedProjectId(parseInt(e.target.value, 10))}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          )}

          <Button
            onClick={() => setShowCreateModal(true)}
            disabled={!selectedProjectId}
            className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold px-4 py-2 text-sm rounded-md shadow-xs"
          >
            + Create Security Report
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="bg-destructive/15 border border-destructive/30 text-destructive px-4 py-3 rounded-lg text-sm flex justify-between items-center">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="font-bold ml-2">
            ✕
          </button>
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 px-4 py-3 rounded-lg text-sm flex justify-between items-center">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="font-bold ml-2">
            ✕
          </button>
        </div>
      )}

      {/* Filters Bar */}
      <div className="flex flex-wrap items-center gap-4 bg-card/60 p-3 rounded-lg border border-border">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">Status:</span>
          <select
            className="bg-background border border-border rounded px-2.5 py-1 text-xs"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="DRAFT">DRAFT</option>
            <option value="PUBLISHED">PUBLISHED</option>
            <option value="ARCHIVED">ARCHIVED</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-muted-foreground">Type:</span>
          <select
            className="bg-background border border-border rounded px-2.5 py-1 text-xs"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="ALL">All Types</option>
            <option value="SECURITY_ASSESSMENT">SECURITY_ASSESSMENT</option>
            <option value="EXECUTION">EXECUTION</option>
            <option value="BASELINE_REGRESSION">BASELINE_REGRESSION</option>
            <option value="INVESTIGATION">INVESTIGATION</option>
          </select>
        </div>

        <div className="ml-auto text-xs text-muted-foreground">
          Showing <span className="font-semibold text-foreground">{filteredReports.length}</span> of{" "}
          <span className="font-semibold text-foreground">{reports.length}</span> reports
        </div>
      </div>

      {/* Report Listing */}
      {loading ? (
        <div className="text-center py-12 text-muted-foreground text-sm">Loading security reports...</div>
      ) : filteredReports.length === 0 ? (
        <Card className="border border-dashed border-border bg-card/40">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <div className="w-12 h-12 rounded-full bg-accent/40 flex items-center justify-center mb-3 text-muted-foreground font-mono">
              📋
            </div>
            <h3 className="text-base font-semibold">No Security Reports Found</h3>
            <p className="text-sm text-muted-foreground max-w-md mt-1 mb-4">
              Create a security report to consolidate verified execution results, baseline comparisons, gate decisions, sanitized evidence, and remediation plans into a reproducible package.
            </p>
            <Button
              onClick={() => setShowCreateModal(true)}
              disabled={!selectedProjectId}
              className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs"
            >
              + Create First Report
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredReports.map((report) => (
            <Card
              key={report.id}
              className="border border-border bg-card hover:bg-card/80 transition-colors shadow-xs"
            >
              <CardContent className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <Link
                      href={`/security-reports/${report.id}`}
                      className="text-base font-semibold hover:text-primary transition-colors truncate"
                    >
                      {report.name}
                    </Link>

                    {/* Status Badge */}
                    <span
                      className={`px-2 py-0.5 rounded-full text-xs font-semibold uppercase ${
                        report.status === "PUBLISHED"
                          ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                          : report.status === "ARCHIVED"
                          ? "bg-muted text-muted-foreground border border-border"
                          : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                      }`}
                    >
                      {report.status}
                    </span>

                    {/* Report Type Badge */}
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-accent/50 text-foreground border border-border/60">
                      {report.report_type}
                    </span>

                    {/* Version Badge */}
                    <span className="text-xs text-muted-foreground font-mono">
                      v{report.version}
                    </span>
                  </div>

                  {report.description && (
                    <p className="text-xs text-muted-foreground line-clamp-1">{report.description}</p>
                  )}

                  {/* Sources & Metadata Row */}
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-xs text-muted-foreground">
                    {report.source_execution_plan_id && (
                      <span className="flex items-center gap-1">
                        <span className="text-[10px] uppercase font-bold text-foreground">Plan:</span>
                        <Link
                          href={`/execution-plans`}
                          className="hover:underline text-primary/90 font-mono"
                        >
                          {report.source_execution_plan_id.substring(0, 8)}...
                        </Link>
                      </span>
                    )}

                    {report.source_gate_evaluation_id && (
                      <span className="flex items-center gap-1">
                        <span className="text-[10px] uppercase font-bold text-foreground">Gate:</span>
                        <Link
                          href={`/security-gates`}
                          className="hover:underline text-primary/90 font-mono"
                        >
                          {report.source_gate_evaluation_id.substring(0, 8)}...
                        </Link>
                      </span>
                    )}

                    {report.source_investigation_id && (
                      <span className="flex items-center gap-1">
                        <span className="text-[10px] uppercase font-bold text-foreground">Investigation:</span>
                        <Link
                          href={`/investigations`}
                          className="hover:underline text-primary/90 font-mono"
                        >
                          {report.source_investigation_id.substring(0, 8)}...
                        </Link>
                      </span>
                    )}

                    {report.latest_snapshot_checksum && (
                      <span className="flex items-center gap-1 font-mono text-[11px] bg-secondary/40 px-1.5 py-0.5 rounded border border-border/50">
                        <span className="text-muted-foreground">SHA-256:</span>
                        <span className="text-foreground">{report.latest_snapshot_checksum.substring(0, 10)}...</span>
                      </span>
                    )}

                    <span>Created {new Date(report.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex items-center gap-2 shrink-0 flex-wrap">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => router.push(`/security-reports/${report.id}`)}
                    className="text-xs"
                  >
                    View Report
                  </Button>

                  {report.status !== "ARCHIVED" && (
                    <Button
                      size="sm"
                      onClick={() => handleGenerateReport(report.id)}
                      disabled={generatingId === report.id}
                      className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs"
                    >
                      {generatingId === report.id ? "Generating..." : report.generated_at ? "Regenerate" : "Generate"}
                    </Button>
                  )}

                  {report.latest_snapshot_checksum && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => downloadJson(`/api/v1/security-reports/${report.id}/json`, `${report.name.toLowerCase().replace(/\s+/g, "_")}_report.json`)}
                        className="text-xs text-muted-foreground hover:text-foreground"
                        title="Download JSON Report Snapshot"
                      >
                        JSON
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => downloadJson(`/api/v1/security-reports/${report.id}/package`, `${report.name.toLowerCase().replace(/\s+/g, "_")}_package.json`)}
                        className="text-xs text-muted-foreground hover:text-foreground"
                        title="Download Full Evidence Package"
                      >
                        Package
                      </Button>
                    </>
                  )}

                  {report.status === "PUBLISHED" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleArchiveReport(report.id, report.name)}
                      disabled={archivingId === report.id}
                      className="text-xs text-amber-500 hover:text-amber-400 hover:bg-amber-500/10 border-amber-500/30"
                    >
                      Archive
                    </Button>
                  )}

                  {report.status === "DRAFT" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDeleteReport(report.id, report.name)}
                      className="text-xs text-destructive hover:bg-destructive/10"
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* CREATE REPORT MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 overflow-y-auto">
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 shadow-xl space-y-4">
            <div className="flex justify-between items-center border-b pb-3">
              <h2 className="text-lg font-bold">Create Security Report</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-muted-foreground hover:text-foreground font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateReport} className="space-y-4">
              <div>
                <label className="text-xs font-semibold block mb-1">
                  Report Name <span className="text-destructive">*</span>
                </label>
                <Input
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  placeholder="e.g. Q4 API Security Assessment & Evidence Package"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold block mb-1">Description (Optional)</label>
                <Input
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  placeholder="Executive overview or purpose of this security audit package"
                />
              </div>

              <div>
                <label className="text-xs font-semibold block mb-1">Report Type</label>
                <select
                  value={createType}
                  onChange={(e) => setCreateType(e.target.value)}
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary"
                >
                  <option value="SECURITY_ASSESSMENT">SECURITY_ASSESSMENT (Full assessment & impact)</option>
                  <option value="EXECUTION">EXECUTION (Execution plan audit)</option>
                  <option value="BASELINE_REGRESSION">BASELINE_REGRESSION (Baseline & CI gate evaluation)</option>
                  <option value="INVESTIGATION">INVESTIGATION (Focused breach investigation)</option>
                </select>
              </div>

              <div className="border-t pt-3 space-y-3">
                <div className="text-xs font-bold uppercase text-muted-foreground tracking-wider">
                  Report Sources (Select at least one)
                </div>

                <div>
                  <label className="text-xs font-semibold block mb-1">Source Execution Plan</label>
                  <select
                    value={createPlanId}
                    onChange={(e) => setCreatePlanId(e.target.value)}
                    className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="">-- None Selected --</option>
                    {plans.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.status})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold block mb-1">Source Security Gate Evaluation</label>
                  <select
                    value={createGateEvalId}
                    onChange={(e) => setCreateGateEvalId(e.target.value)}
                    className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="">-- None Selected --</option>
                    {gateEvals.map((ge) => (
                      <option key={ge.id} value={ge.id}>
                        Eval {ge.id.substring(0, 8)}... - Status: {ge.status} ({new Date(ge.evaluated_at).toLocaleDateString()})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold block mb-1">Source Investigation</label>
                  <select
                    value={createInvId}
                    onChange={(e) => setCreateInvId(e.target.value)}
                    className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-xs focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="">-- None Selected --</option>
                    {investigations.map((inv) => (
                      <option key={inv.id} value={inv.id}>
                        {inv.title} ({inv.status})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowCreateModal(false)}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={creating}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs"
                >
                  {creating ? "Creating..." : "Create Report"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecurityReportsPage() {
  return (
    <Suspense fallback={<div className="p-6 text-sm text-muted-foreground">Loading Security Reports...</div>}>
      <SecurityReportsContent />
    </Suspense>
  );
}
