"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface FindingItem {
  id: string;
  project_id: number;
  type: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  description: string;
}

interface AttackPathItem {
  id: string;
  project_id: number;
  name: string;
  description?: string | null;
  status: string;
  confidence: string;
  step_count: number;
}

interface InvestigationItem {
  id: string;
  investigation_id: string;
  item_type: string;
  item_id: string;
  position: number;
  created_at: string;
}

interface SecurityInvestigationDetail {
  id: string;
  project_id: number;
  title: string;
  description?: string | null;
  status: "OPEN" | "IN_REVIEW" | "RESOLVED" | "ARCHIVED";
  primary_finding_id?: string | null;
  primary_attack_path_id?: string | null;
  primary_finding_title?: string | null;
  primary_finding_severity?: string | null;
  primary_attack_path_name?: string | null;
  item_count: number;
  items: InvestigationItem[];
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
}

export default function InvestigationsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [investigations, setInvestigations] = useState<SecurityInvestigationDetail[]>([]);
  const [confirmedFindings, setConfirmedFindings] = useState<FindingItem[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPathItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createTitle, setCreateTitle] = useState("");
  const [createDesc, setCreateDesc] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [selectedPathId, setSelectedPathId] = useState<string>("");

  // Fast Investigation Modal
  const [showFastFindingModal, setShowFastFindingModal] = useState(false);
  const [fastFindingId, setFastFindingId] = useState<string>("");

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
          const params = new URLSearchParams(window.location.search);
          const pParam = params.get("project_id");
          if (pParam) initialId = Number(pParam);
        }
        if (initialId !== null) {
          setSelectedProjectId(initialId);
        }
      } catch (err) {
        setErrorMsg(err instanceof Error ? err.message : "Error loading projects");
      }
    }
    loadProjects();
  }, []);

  // Load Investigations, Findings, and Paths when Project Changes
  useEffect(() => {
    if (!selectedProjectId) return;

    let ignore = false;
    async function loadProjectData() {
      setLoading(true);
      setErrorMsg(null);
      try {
        const [invRes, findingsRes, pathsRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/investigations`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/findings`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/attack-paths`, { credentials: "include" }),
        ]);

        if (invRes.ok) {
          const invData = await invRes.json();
          if (!ignore) setInvestigations(invData.investigations || []);
        }

        if (findingsRes.ok) {
          const findingsData: FindingItem[] = await findingsRes.json();
          if (!ignore) {
            setConfirmedFindings(findingsData.filter((f) => f.status === "CONFIRMED"));
          }
        }

        if (pathsRes.ok) {
          const pathsData: AttackPathItem[] = await pathsRes.json();
          if (!ignore) setAttackPaths(pathsData);
        }
      } catch (err) {
        if (!ignore) {
          setErrorMsg(err instanceof Error ? err.message : "Failed to load investigations");
        }
      } finally {
        if (!ignore) setLoading(false);
      }
    }

    loadProjectData();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId]);

  // Filtered Investigations
  const filteredInvestigations = useMemo(() => {
    return investigations.filter((inv) => {
      const matchStatus = statusFilter === "ALL" || inv.status === statusFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        inv.title.toLowerCase().includes(q) ||
        (inv.description && inv.description.toLowerCase().includes(q)) ||
        (inv.primary_finding_title && inv.primary_finding_title.toLowerCase().includes(q)) ||
        (inv.primary_attack_path_name && inv.primary_attack_path_name.toLowerCase().includes(q));
      return matchStatus && matchSearch;
    });
  }, [investigations, statusFilter, searchQuery]);

  // Summary counts
  const totalCount = investigations.length;
  const openCount = investigations.filter((i) => i.status === "OPEN").length;
  const inReviewCount = investigations.filter((i) => i.status === "IN_REVIEW").length;
  const resolvedCount = investigations.filter((i) => i.status === "RESOLVED").length;
  const archivedCount = investigations.filter((i) => i.status === "ARCHIVED").length;

  // Handle Create Investigation
  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !createTitle.trim()) return;

    setActionInProgress("creating");
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/investigations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          title: createTitle.trim(),
          description: createDesc.trim() || null,
          primary_finding_id: selectedFindingId || null,
          primary_attack_path_id: selectedPathId || null,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create investigation");
      }

      const newInv: SecurityInvestigationDetail = await res.json();
      setInvestigations((prev) => [newInv, ...prev]);
      setShowCreateModal(false);
      setCreateTitle("");
      setCreateDesc("");
      setSelectedFindingId("");
      setSelectedPathId("");
      setSuccessMsg(`Investigation "${newInv.title}" initialized.`);
      router.push(`/investigations/${newInv.id}`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create investigation");
    } finally {
      setActionInProgress(null);
    }
  };

  // Handle Fast Create from Finding
  const handleFastCreateFromFinding = async (findingId: string) => {
    if (!selectedProjectId || !findingId) return;

    setActionInProgress("fast_creating");
    setErrorMsg(null);
    try {
      const res = await fetch(
        `/api/v1/projects/${selectedProjectId}/investigations/from-finding/${findingId}`,
        {
          method: "POST",
          credentials: "include",
        }
      );

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to auto-discover investigation");
      }

      const newInv: SecurityInvestigationDetail = await res.json();
      setInvestigations((prev) => {
        const exists = prev.some((i) => i.id === newInv.id);
        return exists ? prev.map((i) => (i.id === newInv.id ? newInv : i)) : [newInv, ...prev];
      });
      setShowFastFindingModal(false);
      setFastFindingId("");
      setSuccessMsg(`Investigation for finding opened.`);
      router.push(`/investigations/${newInv.id}`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to auto-discover investigation");
    } finally {
      setActionInProgress(null);
    }
  };

  // Handle Quick Status Update
  const handleUpdateStatus = async (
    invId: string,
    newStatus: "OPEN" | "IN_REVIEW" | "RESOLVED" | "ARCHIVED"
  ) => {
    setActionInProgress(invId);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/investigations/${invId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ status: newStatus }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to update investigation status");
      }

      const updated: SecurityInvestigationDetail = await res.json();
      setInvestigations((prev) => prev.map((i) => (i.id === invId ? updated : i)));
      setSuccessMsg(`Status updated to ${newStatus}.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to update status");
    } finally {
      setActionInProgress(null);
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Project Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Security Investigations
            </h1>
            <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              STAGE 9.3 WORKSPACE
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Coordinate verified findings, attack paths, deterministic impacts, AI reasoning, and human test approvals in a single workflow.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Project Picker */}
          <select
            className="h-9 rounded-md border border-input bg-background px-3 text-xs shadow-xs focus:ring-1 focus:ring-ring"
            value={selectedProjectId || ""}
            onChange={(e) => setSelectedProjectId(Number(e.target.value))}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                Project: {p.name}
              </option>
            ))}
          </select>

          {/* Action Buttons */}
          <Button
            size="sm"
            variant="outline"
            className="text-xs border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10"
            onClick={() => setShowFastFindingModal(true)}
            disabled={confirmedFindings.length === 0}
          >
            ⚡ Investigate Finding
          </Button>

          <Button
            size="sm"
            className="text-xs bg-primary hover:bg-primary/90 text-primary-foreground font-medium"
            onClick={() => setShowCreateModal(true)}
            disabled={!selectedProjectId}
          >
            + New Investigation
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg bg-destructive/10 border border-destructive text-destructive text-xs flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="font-bold ml-2">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="font-bold ml-2">✕</button>
        </div>
      )}

      {/* KPI Stats Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3 rounded-xl border border-border bg-card/60">
          <span className="text-[10px] uppercase font-bold text-muted-foreground block">Total Cases</span>
          <span className="text-xl font-bold text-foreground mt-0.5 block">{totalCount}</span>
        </div>
        <div className="p-3 rounded-xl border border-blue-500/20 bg-blue-500/5">
          <span className="text-[10px] uppercase font-bold text-blue-400 block">Open</span>
          <span className="text-xl font-bold text-blue-400 mt-0.5 block">{openCount}</span>
        </div>
        <div className="p-3 rounded-xl border border-purple-500/20 bg-purple-500/5">
          <span className="text-[10px] uppercase font-bold text-purple-400 block">In Review</span>
          <span className="text-xl font-bold text-purple-400 mt-0.5 block">{inReviewCount}</span>
        </div>
        <div className="p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5">
          <span className="text-[10px] uppercase font-bold text-emerald-400 block">Resolved</span>
          <span className="text-xl font-bold text-emerald-400 mt-0.5 block">{resolvedCount}</span>
        </div>
        <div className="p-3 rounded-xl border border-zinc-500/20 bg-zinc-500/5">
          <span className="text-[10px] uppercase font-bold text-zinc-400 block">Archived</span>
          <span className="text-xl font-bold text-zinc-400 mt-0.5 block">{archivedCount}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-card/50 p-2.5 rounded-lg border border-border">
        {/* Status Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto">
          {(["ALL", "OPEN", "IN_REVIEW", "RESOLVED", "ARCHIVED"] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded text-xs font-semibold uppercase tracking-wider transition-colors ${
                statusFilter === st
                  ? "bg-primary text-primary-foreground shadow-xs"
                  : "bg-muted text-muted-foreground hover:bg-accent hover:text-foreground"
              }`}
            >
              {st.replace("_", " ")}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="w-full sm:w-72">
          <input
            type="text"
            placeholder="Search investigations..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-8 px-3 rounded-md border border-input bg-background text-xs placeholder:text-muted-foreground focus:ring-1 focus:ring-ring"
          />
        </div>
      </div>

      {/* Investigations List */}
      {loading ? (
        <div className="p-12 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading investigation cases...
        </div>
      ) : filteredInvestigations.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-16 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-indigo-500/10 text-indigo-400 mx-auto flex items-center justify-center text-xl font-bold">
              🔍
            </div>
            <h3 className="font-semibold text-foreground text-sm">No Investigations Found</h3>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Start an investigation from any confirmed finding or attack path to aggregate verified evidence, deterministic exploit graphs, AI reasoning, and approval workflows.
            </p>
            <div className="pt-2 flex justify-center gap-3">
              <Button
                size="sm"
                variant="outline"
                onClick={() => setShowFastFindingModal(true)}
                disabled={confirmedFindings.length === 0}
                className="text-xs"
              >
                Investigate Confirmed Finding
              </Button>
              <Button
                size="sm"
                onClick={() => setShowCreateModal(true)}
                className="text-xs"
              >
                Create Investigation Case
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3.5">
          {filteredInvestigations.map((inv) => {
            const isResolved = inv.status === "RESOLVED";
            const isInReview = inv.status === "IN_REVIEW";
            const isArchived = inv.status === "ARCHIVED";

            return (
              <Card
                key={inv.id}
                className={`p-5 transition-all border-l-4 ${
                  isResolved
                    ? "border-l-emerald-500 bg-card/60"
                    : isInReview
                    ? "border-l-purple-500 bg-card"
                    : isArchived
                    ? "border-l-zinc-600 bg-muted/20 opacity-80"
                    : "border-l-blue-500 bg-card"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                  {/* Left Column: Title & Lineage */}
                  <div className="space-y-2 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Link
                        href={`/investigations/${inv.id}`}
                        className="text-sm font-bold text-foreground hover:text-primary transition-colors hover:underline"
                      >
                        {inv.title}
                      </Link>

                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                          isResolved
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : isInReview
                            ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                            : isArchived
                            ? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                            : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                        }`}
                      >
                        {inv.status.replace("_", " ")}
                      </span>

                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border">
                        {inv.item_count} Attached Elements
                      </span>
                    </div>

                    {inv.description && (
                      <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                        {inv.description}
                      </p>
                    )}

                    {/* Grounded Origins */}
                    <div className="flex items-center gap-3 text-xs text-muted-foreground pt-1 flex-wrap">
                      {inv.primary_finding_title && (
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold text-foreground text-[11px] uppercase tracking-wider">
                            Origin Finding:
                          </span>
                          <span className="font-medium text-foreground truncate max-w-[260px]">
                            {inv.primary_finding_title}
                          </span>
                          {inv.primary_finding_severity && (
                            <span
                              className={`text-[9px] font-bold px-1.5 py-0.2 rounded uppercase border ${
                                inv.primary_finding_severity === "HIGH"
                                  ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                                  : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                              }`}
                            >
                              {inv.primary_finding_severity}
                            </span>
                          )}
                        </div>
                      )}

                      {inv.primary_attack_path_name && (
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold text-foreground text-[11px] uppercase tracking-wider">
                            Origin Path:
                          </span>
                          <span className="font-medium text-foreground truncate max-w-[260px]">
                            {inv.primary_attack_path_name}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Column: Actions & Timestamps */}
                  <div className="flex sm:flex-col items-end justify-between gap-3 shrink-0">
                    <div className="text-[11px] text-muted-foreground text-right space-y-0.5">
                      <div>Created: {new Date(inv.created_at).toLocaleDateString()}</div>
                      {inv.resolved_at && (
                        <div className="text-emerald-400">
                          Resolved: {new Date(inv.resolved_at).toLocaleDateString()}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      {/* Quick Status Select */}
                      <select
                        value={inv.status}
                        onChange={(e) =>
                          handleUpdateStatus(
                            inv.id,
                            e.target.value as "OPEN" | "IN_REVIEW" | "RESOLVED" | "ARCHIVED"
                          )
                        }
                        disabled={actionInProgress === inv.id}
                        className="h-7 px-2 text-[11px] rounded border border-input bg-background text-muted-foreground"
                      >
                        <option value="OPEN">Mark Open</option>
                        <option value="IN_REVIEW">Mark In Review</option>
                        <option value="RESOLVED">Mark Resolved</option>
                        <option value="ARCHIVED">Mark Archived</option>
                      </select>

                      <Link href={`/investigations/${inv.id}`}>
                        <Button size="sm" className="text-xs h-7 px-3 bg-primary hover:bg-primary/90 text-primary-foreground font-medium">
                          Open Workspace →
                        </Button>
                      </Link>
                    </div>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Modal: New Investigation */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <Card className="w-full max-w-lg p-6 bg-background border border-border shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="font-semibold text-sm text-foreground">Create Security Investigation</h3>
                <p className="text-xs text-muted-foreground">
                  Initiate a formal case to aggregate deterministic evidence, graphs, AI analyses, and human test approvals.
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateInvestigation} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Investigation: Cross-Tenant Data Exfiltration Chain"
                  value={createTitle}
                  onChange={(e) => setCreateTitle(e.target.value)}
                  className="w-full h-8 px-3 rounded-md border border-input bg-background text-xs focus:ring-1 focus:ring-ring"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Description / Hypothesis</label>
                <textarea
                  rows={3}
                  placeholder="Context and scope of the investigation..."
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  className="w-full p-2.5 rounded-md border border-input bg-background text-xs focus:ring-1 focus:ring-ring"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">
                  Primary Finding (Optional Grounding)
                </label>
                <select
                  value={selectedFindingId}
                  onChange={(e) => setSelectedFindingId(e.target.value)}
                  className="w-full h-8 px-3 rounded-md border border-input bg-background text-xs focus:ring-1 focus:ring-ring"
                >
                  <option value="">-- None / Manual Investigation --</option>
                  {confirmedFindings.map((f) => (
                    <option key={f.id} value={f.id}>
                      [{f.severity}] {f.title} ({f.type})
                    </option>
                  ))}
                </select>
                <span className="text-[10px] text-muted-foreground block">
                  Selecting a confirmed finding will automatically discover related attack paths, impacts, and AI insights.
                </span>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">
                  Primary Attack Path (Optional Grounding)
                </label>
                <select
                  value={selectedPathId}
                  onChange={(e) => setSelectedPathId(e.target.value)}
                  className="w-full h-8 px-3 rounded-md border border-input bg-background text-xs focus:ring-1 focus:ring-ring"
                >
                  <option value="">-- None --</option>
                  {attackPaths.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.step_count} steps)
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex justify-end gap-2.5 pt-3 border-t border-border">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowCreateModal(false)}
                  disabled={actionInProgress === "creating"}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={actionInProgress === "creating" || !createTitle.trim()}
                  className="text-xs bg-primary hover:bg-primary/90 text-primary-foreground font-medium"
                >
                  {actionInProgress === "creating" ? "Initializing..." : "Create Case"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* Modal: Fast Investigate Confirmed Finding */}
      {showFastFindingModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <Card className="w-full max-w-lg p-6 bg-background border border-border shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="font-semibold text-sm text-foreground">
                  ⚡ Auto-Discover Investigation from Confirmed Finding
                </h3>
                <p className="text-xs text-muted-foreground">
                  Instantly aggregates verified evidence, deterministic correlations, attack graphs, impacts, and AI hypotheses.
                </p>
              </div>
              <button
                onClick={() => setShowFastFindingModal(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Select Confirmed Finding *</label>
                <select
                  value={fastFindingId}
                  onChange={(e) => setFastFindingId(e.target.value)}
                  className="w-full h-9 px-3 rounded-md border border-input bg-background text-xs focus:ring-1 focus:ring-ring"
                >
                  <option value="">-- Choose a verified finding --</option>
                  {confirmedFindings.map((f) => (
                    <option key={f.id} value={f.id}>
                      [{f.severity}] {f.title} ({f.type})
                    </option>
                  ))}
                </select>
              </div>

              {fastFindingId && (
                <div className="p-3 rounded-lg border border-indigo-500/20 bg-indigo-500/5 text-xs text-indigo-300 space-y-1">
                  <div className="font-semibold">Automatic Lineage Discovery:</div>
                  <p className="text-[11px] text-muted-foreground">
                    SentinelAPI will inspect all confirmed finding correlations, attack path steps, security impact dimensions, AI analyses, and generated hypotheses tied to this finding without executing any target traffic.
                  </p>
                </div>
              )}

              <div className="flex justify-end gap-2.5 pt-3 border-t border-border">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowFastFindingModal(false)}
                  disabled={actionInProgress === "fast_creating"}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={() => handleFastCreateFromFinding(fastFindingId)}
                  disabled={actionInProgress === "fast_creating" || !fastFindingId}
                  className="text-xs bg-indigo-600 hover:bg-indigo-500 text-white font-medium"
                >
                  {actionInProgress === "fast_creating" ? "Discovering..." : "Launch Investigation Workspace"}
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
