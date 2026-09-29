"use client";

import React, { useEffect, useState, use } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

interface InvestigationItem {
  id: string;
  investigation_id: string;
  item_type: string;
  item_id: string;
  position: number;
  item_summary?: Record<string, unknown> | null;
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

interface TimelineEvent {
  id: string;
  event_type: string;
  category: "VERIFIED" | "DETERMINISTIC" | "AI" | "HUMAN" | "ENGINE" | string;
  timestamp?: string | null;
  title: string;
  description: string;
  source_type: string;
  source_id: string;
  metadata: Record<string, unknown>;
}

interface InvestigationContextData {
  investigation: SecurityInvestigationDetail;
  primary_finding?: Record<string, unknown> | null;
  primary_attack_path?: Record<string, unknown> | null;
  evidence: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  attack_graphs: Array<Record<string, unknown>>;
  attack_paths: Array<Record<string, unknown>>;
  security_impacts: Array<Record<string, unknown>>;
  ai_analyses: Array<Record<string, unknown>>;
  ai_hypotheses: Array<Record<string, unknown>>;
  security_tests: Array<Record<string, unknown>>;
  workflow_executions: Array<Record<string, unknown>>;
  summary_counts: Record<string, number>;
}

export default function InvestigationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const investigationId = resolvedParams.id;

  const [context, setContext] = useState<InvestigationContextData | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Active Workspace Tab
  const [activeTab, setActiveTab] = useState<
    "lineage" | "evidence" | "impact" | "ai" | "hypotheses" | "tests" | "timeline" | "entities"
  >("lineage");

  // Human Review Modal for Hypotheses (Stage 9.2 governance)
  const [reviewingHypo, setReviewingHypo] = useState<Record<string, unknown> | null>(null);
  const [reviewAction, setReviewAction] = useState<"APPROVED" | "REJECTED">("APPROVED");
  const [reviewerName, setReviewerName] = useState("sec_lead");
  const [reviewReason, setReviewReason] = useState("");

  // Attach Item Modal
  const [showAttachModal, setShowAttachModal] = useState(false);
  const [attachType, setAttachType] = useState<string>("FINDING");
  const [attachId, setAttachId] = useState<string>("");

  // Load Investigation Context & Timeline
  useEffect(() => {
    let ignore = false;
    async function loadData() {
      setErrorMsg(null);
      try {
        const [ctxRes, timeRes] = await Promise.all([
          fetch(`/api/v1/investigations/${investigationId}/context`, { credentials: "include" }),
          fetch(`/api/v1/investigations/${investigationId}/timeline`, { credentials: "include" }),
        ]);

        if (!ctxRes.ok) {
          const err = await ctxRes.json();
          throw new Error(err.detail || "Failed to load investigation context");
        }
        const ctxData: InvestigationContextData = await ctxRes.json();
        if (!ignore) setContext(ctxData);

        if (timeRes.ok) {
          const timeData = await timeRes.json();
          if (!ignore) setTimeline(timeData.events || []);
        }
      } catch (err) {
        if (!ignore) {
          setErrorMsg(err instanceof Error ? err.message : "Error loading investigation");
        }
      } finally {
        if (!ignore) setLoading(false);
      }
    }

    loadData();
    return () => {
      ignore = true;
    };
  }, [investigationId, reloadKey]);

  // Update Status
  const handleUpdateStatus = async (
    newStatus: "OPEN" | "IN_REVIEW" | "RESOLVED" | "ARCHIVED"
  ) => {
    setActionInProgress("status");
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/investigations/${investigationId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ status: newStatus }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to update status");
      }

      setSuccessMsg(`Investigation status updated to ${newStatus}.`);
      setReloadKey((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to update status");
    } finally {
      setActionInProgress(null);
    }
  };

  // Submit Hypothesis Review (Stage 9.2 Human Governance)
  const handleSubmitReview = async () => {
    if (!context || !reviewingHypo) return;
    const hypoId = reviewingHypo.id as string;
    const projectId = context.investigation.project_id;

    setActionInProgress("reviewing");
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/ai/hypotheses/${hypoId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          action: reviewAction,
          reviewer_reference: reviewerName.trim() || "security_analyst",
          reason: reviewReason.trim() || undefined,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to submit review");
      }

      setReviewingHypo(null);
      setReviewReason("");
      setSuccessMsg(`Hypothesis marked as ${reviewAction}.`);
      setReloadKey((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to submit review");
    } finally {
      setActionInProgress(null);
    }
  };

  // Convert Approved Hypothesis to SecurityTest (Stage 9.2 Execution Bridge)
  const handleConvertHypothesis = async (hypoId: string) => {
    if (!context) return;
    const projectId = context.investigation.project_id;

    setActionInProgress(`convert_${hypoId}`);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/ai/hypotheses/${hypoId}/convert`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to convert hypothesis to test");
      }

      const resData = await res.json();
      setSuccessMsg(`Hypothesis converted into SecurityTest (${resData.test_type}) successfully.`);
      setReloadKey((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to convert hypothesis");
    } finally {
      setActionInProgress(null);
    }
  };

  // Attach Item to Investigation
  const handleAttachItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!attachId.trim()) return;

    setActionInProgress("attaching");
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/investigations/${investigationId}/items`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          item_type: attachType,
          item_id: attachId.trim(),
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to attach item");
      }

      setShowAttachModal(false);
      setAttachId("");
      setSuccessMsg(`Attached ${attachType} to investigation.`);
      setReloadKey((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to attach item");
    } finally {
      setActionInProgress(null);
    }
  };

  // Detach Item from Investigation
  const handleDetachItem = async (itemId: string) => {
    if (!confirm("Are you sure you want to detach this item from the investigation?")) return;

    setActionInProgress(`detach_${itemId}`);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/investigations/${investigationId}/items/${itemId}`, {
        method: "DELETE",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to detach item");
      }

      setSuccessMsg("Item detached from investigation.");
      setReloadKey((prev) => prev + 1);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to detach item");
    } finally {
      setActionInProgress(null);
    }
  };

  if (loading) {
    return (
      <div className="p-16 text-center space-y-3">
        <div className="inline-block w-8 h-8 border-4 border-primary border-t-transparent rounded-full animate-spin" />
        <div className="text-sm font-semibold text-muted-foreground">
          Loading investigation workspace...
        </div>
      </div>
    );
  }

  if (!context) {
    return (
      <div className="p-12 text-center space-y-4">
        <div className="text-destructive text-lg font-bold">Investigation Not Found</div>
        <p className="text-xs text-muted-foreground">{errorMsg || "The requested investigation does not exist."}</p>
        <Link href="/investigations">
          <Button size="sm" variant="outline">
            ← Back to Investigations
          </Button>
        </Link>
      </div>
    );
  }

  const { investigation, summary_counts } = context;
  const isResolved = investigation.status === "RESOLVED";
  const isInReview = investigation.status === "IN_REVIEW";
  const isArchived = investigation.status === "ARCHIVED";

  return (
    <div className="space-y-6 pb-16">
      {/* Back Link & Quick Nav */}
      <div className="flex items-center justify-between text-xs">
        <Link
          href="/investigations"
          className="text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
        >
          ← Back to Investigations
        </Link>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground font-mono">Case ID: {investigation.id}</span>
        </div>
      </div>

      {/* Top Workspace Header */}
      <div className="p-6 rounded-xl border border-border bg-card shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                {investigation.title}
              </h1>

              <span
                className={`px-2.5 py-0.5 rounded text-[11px] font-bold uppercase tracking-wider border ${
                  isResolved
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                    : isInReview
                    ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                    : isArchived
                    ? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                    : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                }`}
              >
                {investigation.status.replace("_", " ")}
              </span>

              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                Project #{investigation.project_id}
              </span>
            </div>

            {investigation.description && (
              <p className="text-xs text-muted-foreground leading-relaxed max-w-3xl">
                {investigation.description}
              </p>
            )}

            {/* Lineage badges */}
            <div className="flex items-center gap-3 text-xs text-muted-foreground pt-1 flex-wrap">
              {investigation.primary_finding_title && (
                <div className="flex items-center gap-1.5">
                  <span className="font-semibold text-foreground text-[10px] uppercase tracking-wider">
                    Primary Finding:
                  </span>
                  <span className="font-medium text-foreground">
                    {investigation.primary_finding_title}
                  </span>
                  {investigation.primary_finding_severity && (
                    <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase">
                      {investigation.primary_finding_severity}
                    </span>
                  )}
                </div>
              )}

              {investigation.primary_attack_path_name && (
                <div className="flex items-center gap-1.5">
                  <span className="font-semibold text-foreground text-[10px] uppercase tracking-wider">
                    Primary Attack Path:
                  </span>
                  <span className="font-medium text-foreground">
                    {investigation.primary_attack_path_name}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Status Changer & Attach Action */}
          <div className="flex flex-col sm:flex-row items-end sm:items-center gap-2.5 shrink-0">
            <select
              value={investigation.status}
              onChange={(e) =>
                handleUpdateStatus(
                  e.target.value as "OPEN" | "IN_REVIEW" | "RESOLVED" | "ARCHIVED"
                )
              }
              disabled={actionInProgress === "status"}
              className="h-8 px-2.5 text-xs rounded-md border border-input bg-background text-foreground focus:ring-1 focus:ring-ring font-medium"
            >
              <option value="OPEN">Status: Open</option>
              <option value="IN_REVIEW">Status: In Review</option>
              <option value="RESOLVED">Status: Resolved</option>
              <option value="ARCHIVED">Status: Archived</option>
            </select>

            <Button
              size="sm"
              variant="outline"
              className="text-xs h-8"
              onClick={() => setShowAttachModal(true)}
            >
              + Attach Entity
            </Button>
          </div>
        </div>

        {/* Counter Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2 pt-3 border-t border-border/80">
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Findings</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.findings || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Evidence</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.evidence || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Attack Paths</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.attack_paths || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Impacts</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.security_impacts || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">AI Analyses</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.ai_analyses || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Hypotheses</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.ai_hypotheses || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Sec Tests</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.security_tests || 0}</span>
          </div>
          <div className="p-2 rounded bg-muted/40 text-center">
            <span className="text-[9px] uppercase font-bold text-muted-foreground block">Workflows</span>
            <span className="text-sm font-bold text-foreground">{summary_counts.workflow_executions || 0}</span>
          </div>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-3 rounded-lg bg-destructive/10 border border-destructive text-destructive text-xs flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="font-bold ml-2">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="font-bold ml-2">✕</button>
        </div>
      )}

      {/* Provenance Category Legend Bar */}
      <div className="p-3 rounded-lg border border-border bg-card/60 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-foreground text-[11px] uppercase tracking-wider">
            Provenance Categories:
          </span>
        </div>
        <div className="flex items-center gap-3 flex-wrap text-[10px] font-bold uppercase tracking-wider">
          <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            ✓ VERIFIED FACT
          </span>
          <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
            ⚙ DETERMINISTIC ANALYSIS
          </span>
          <span className="px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
            🧠 AI INTERPRETATION
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
            👤 HUMAN DECISION
          </span>
          <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            ⚡ ENGINE TEST RESULT
          </span>
        </div>
      </div>

      {/* Workspace Tabs */}
      <div className="border-b border-border flex items-center gap-1 overflow-x-auto">
        {[
          { key: "lineage", label: "Security Path & Lineage" },
          { key: "evidence", label: `Evidence (${context.evidence.length})` },
          { key: "impact", label: `Deterministic Impact (${context.security_impacts.length})` },
          { key: "ai", label: `AI Reasoning (${context.ai_analyses.length})` },
          { key: "hypotheses", label: `AI Hypotheses (${context.ai_hypotheses.length})` },
          { key: "tests", label: `Security Tests (${context.security_tests.length})` },
          { key: "timeline", label: `Chronological Timeline (${timeline.length})` },
          { key: "entities", label: `Attached Elements (${investigation.items.length})` },
        ].map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as typeof activeTab)}
            className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wider border-b-2 whitespace-nowrap transition-colors ${
              activeTab === tab.key
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* TAB 1: SECURITY PATH & LINEAGE */}
      {activeTab === "lineage" && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl border border-indigo-500/20 bg-indigo-500/5 text-xs text-indigo-300">
            <strong>Lineage Guarantee:</strong> The security path links confirmed vulnerabilities through deterministic graph edges and ordered attack steps. No probabilistic leaps are made.
          </div>

          {/* Primary Finding Visual Hero */}
          {context.primary_finding ? (
            <Card className="p-5 border-l-4 border-l-emerald-500 bg-card space-y-3">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  GROUNDED ORIGIN FINDING
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  ID: {String(context.primary_finding.id)}
                </span>
              </div>
              <h3 className="text-base font-bold text-foreground">
                {String(context.primary_finding.title)}
              </h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {String(context.primary_finding.description)}
              </p>
              <div className="flex items-center gap-4 text-xs pt-1 flex-wrap">
                <div>
                  <span className="font-semibold text-foreground">Type:</span>{" "}
                  <span className="font-mono">{String(context.primary_finding.type)}</span>
                </div>
                <div>
                  <span className="font-semibold text-foreground">Severity:</span>{" "}
                  <span className="text-rose-400 font-bold">{String(context.primary_finding.severity)}</span>
                </div>
                {Boolean(context.primary_finding.endpoint) && (
                  <div>
                    <span className="font-semibold text-foreground">Endpoint:</span>{" "}
                    <span className="font-mono">{String(context.primary_finding.endpoint)}</span>
                  </div>
                )}
              </div>
            </Card>
          ) : (
            <div className="p-6 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No primary finding anchored. This is a generic project investigation case.
            </div>
          )}

          {/* Attack Path Steps Visual Sequence */}
          {context.attack_paths.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-sm font-bold text-foreground uppercase tracking-wider">
                Confirmed Exploit Sequences ({context.attack_paths.length})
              </h3>
              {context.attack_paths.map((p) => {
                const stepsList = Array.isArray(p.steps) ? (p.steps as Array<Record<string, unknown>>) : [];
                return (
                  <Card key={String(p.id)} className="p-5 space-y-4 bg-card/80 border-border">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <h4 className="text-sm font-bold text-foreground">{String(p.name)}</h4>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                          {String(p.confidence)} CONFIDENCE
                        </span>
                      </div>
                      <span className="text-xs text-muted-foreground font-mono">
                        {stepsList.length} Sequence Steps
                      </span>
                    </div>

                    {Boolean(p.description) && (
                      <p className="text-xs text-muted-foreground leading-relaxed">
                        {String(p.description)}
                      </p>
                    )}

                    {/* Steps Flow */}
                    {stepsList.length > 0 && (
                      <div className="space-y-2 pt-2">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground block">
                          Causal Exploit Chain:
                        </span>
                        <div className="space-y-2">
                          {stepsList.map((st, idx: number) => (
                            <div
                              key={String(st.id || idx)}
                              className="p-3 rounded-lg border border-border bg-muted/30 flex items-start gap-3"
                            >
                              <span className="w-5 h-5 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold shrink-0">
                                {Number(st.position || idx + 1)}
                              </span>
                              <div className="space-y-1 min-w-0 flex-1 text-xs">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-semibold text-foreground">
                                    {String(st.finding_title || `Finding: ${st.finding_id}`)}
                                  </span>
                                  <span className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-muted text-muted-foreground uppercase">
                                    {String(st.relationship_type)}
                                  </span>
                                </div>
                                <p className="text-muted-foreground text-[11px]">{String(st.reason)}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: VERIFIED EVIDENCE */}
      {activeTab === "evidence" && (
        <div className="space-y-4">
          <div className="p-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 text-xs text-emerald-400 flex items-center gap-2">
            <span>🛡️</span>
            <span>All HTTP payloads, authorization headers, and cookies below are sanitized and redacted.</span>
          </div>

          {context.evidence.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No evidence records attached to this case.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {context.evidence.map((ev) => (
                <Card key={String(ev.id)} className="p-5 space-y-3 bg-card border-border">
                  <div className="flex items-center justify-between flex-wrap gap-2 border-b border-border pb-2.5">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        VERIFIED EVIDENCE
                      </span>
                      <span className="font-mono text-xs text-muted-foreground">ID: {String(ev.id)}</span>
                    </div>
                    {Boolean(ev.reproducibility_status) && (
                      <span className="text-[10px] font-mono text-muted-foreground uppercase">
                        Reproducibility: {String(ev.reproducibility_status)}
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 rounded-lg bg-muted/40 space-y-1">
                      <span className="text-[10px] font-bold uppercase text-muted-foreground block">
                        Expected Security Behavior:
                      </span>
                      <p className="font-mono text-foreground">{String(ev.expected_behavior || "None recorded")}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-rose-500/5 border border-rose-500/20 space-y-1">
                      <span className="text-[10px] font-bold uppercase text-rose-400 block">
                        Actual Observed Behavior (Vulnerable):
                      </span>
                      <p className="font-mono text-rose-300">{String(ev.actual_behavior || "None recorded")}</p>
                    </div>
                  </div>

                  {/* Redacted Request & Response */}
                  {Boolean(ev.redacted_request) && (
                    <div className="space-y-1">
                      <span className="text-[10px] font-bold uppercase text-muted-foreground block">
                        Sanitized Request:
                      </span>
                      <pre className="p-3 rounded bg-zinc-950 text-zinc-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                        {String(ev.redacted_request)}
                      </pre>
                    </div>
                  )}

                  {Boolean(ev.redacted_response) && (
                    <div className="space-y-1">
                      <span className="text-[10px] font-bold uppercase text-muted-foreground block">
                        Sanitized Response:
                      </span>
                      <pre className="p-3 rounded bg-zinc-950 text-zinc-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                        {String(ev.redacted_response)}
                      </pre>
                    </div>
                  )}
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: DETERMINISTIC IMPACT */}
      {activeTab === "impact" && (
        <div className="space-y-4">
          {context.security_impacts.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No deterministic security impacts attached to this investigation.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {context.security_impacts.map((imp) => {
                const boundaries = (imp.boundaries_crossed as string[]) || [];
                return (
                  <Card key={String(imp.id)} className="p-5 space-y-3 bg-card border-border">
                    <div className="flex items-center justify-between flex-wrap gap-2 border-b border-border pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/10 text-blue-400 border border-blue-500/20">
                          DETERMINISTIC IMPACT ANALYSIS
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">ID: {String(imp.id)}</span>
                      </div>
                      <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/20">
                        Terminal: {String(imp.terminal_impact)}
                      </span>
                    </div>

                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {String(imp.explanation)}
                    </p>

                    {/* Boundaries Crossed */}
                    {boundaries.length > 0 && (
                      <div className="space-y-1.5 pt-2">
                        <span className="text-[10px] font-bold uppercase text-muted-foreground block">
                          Security Boundaries Crossed:
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {boundaries.map((b) => (
                            <span
                              key={b}
                              className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/20 uppercase"
                            >
                              {b}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: AI REASONING & INTERPRETATIONS */}
      {activeTab === "ai" && (
        <div className="space-y-4">
          <div className="p-3 rounded-lg border border-purple-500/20 bg-purple-500/5 text-xs text-purple-300">
            <strong>Analytical Assistant Only:</strong> The AI reasoning below explains confirmed vulnerabilities and provides remediation hypotheses. It never executes requests, overrides tests, or invents evidence.
          </div>

          {context.ai_analyses.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No AI analyses attached to this case.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {context.ai_analyses.map((an) => {
                const output = (an.output as Record<string, unknown>) || {};
                return (
                  <Card key={String(an.id)} className="p-5 space-y-4 bg-card border-border">
                    <div className="flex items-center justify-between flex-wrap gap-2 border-b border-border pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/10 text-purple-400 border border-purple-500/20">
                          AI INTERPRETATION
                        </span>
                        <span className="font-semibold text-xs text-foreground">
                          {String(an.analysis_type)}
                        </span>
                      </div>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        Model: {String(an.model_name)} ({String(an.model_provider)})
                      </span>
                    </div>

                    {Boolean(output.summary) && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-bold uppercase text-purple-400 block">
                          AI Summary & Deductions:
                        </span>
                        <p className="text-xs text-foreground leading-relaxed bg-purple-500/5 p-3 rounded-lg border border-purple-500/20">
                          {String(output.summary)}
                        </p>
                      </div>
                    )}

                    {Boolean(output.root_cause) && (
                      <div className="space-y-1 text-xs">
                        <span className="text-[10px] font-bold uppercase text-muted-foreground block">
                          Identified Root Cause:
                        </span>
                        <p className="text-muted-foreground">{String(output.root_cause)}</p>
                      </div>
                    )}

                    {Boolean(output.remediation_guidance) && (
                      <div className="space-y-1 text-xs">
                        <span className="text-[10px] font-bold uppercase text-emerald-400 block">
                          Suggested Remediation:
                        </span>
                        <p className="text-muted-foreground">{String(output.remediation_guidance)}</p>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 5: AI HYPOTHESES & HUMAN GOVERNANCE */}
      {activeTab === "hypotheses" && (
        <div className="space-y-4">
          <div className="p-3 rounded-lg border border-amber-500/20 bg-amber-500/5 text-xs text-amber-300">
            <strong>Human Approval Boundary:</strong> AI proposes security testing hypotheses, but zero execution occurs without explicit human approval. Approved hypotheses convert into deterministic SecurityTest records.
          </div>

          {context.ai_hypotheses.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No hypotheses linked to this investigation.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {context.ai_hypotheses.map((h) => {
                const isPending = h.status === "PENDING_REVIEW";
                const isApproved = h.status === "APPROVED";
                const isConverted = h.status === "CONVERTED";
                const isRejected = h.status === "REJECTED";

                return (
                  <Card
                    key={String(h.id)}
                    className={`p-5 space-y-4 border-l-4 ${
                      isPending
                        ? "border-l-amber-500 bg-card"
                        : isApproved
                        ? "border-l-emerald-500 bg-card"
                        : isConverted
                        ? "border-l-purple-500 bg-card"
                        : isRejected
                        ? "border-l-destructive/60 bg-muted/20"
                        : "border-l-zinc-500 bg-muted/20"
                    }`}
                  >
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                            isPending
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                              : isApproved
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                              : isConverted
                              ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                              : "bg-destructive/10 text-destructive border-destructive/20"
                          }`}
                        >
                          {String(h.status).replace("_", " ")}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">
                          Type: {String(h.suggested_test_type)}
                        </span>
                        <span className="text-[10px] text-muted-foreground uppercase font-bold">
                          Confidence: {String(h.confidence)}
                        </span>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <h4 className="text-sm font-semibold text-foreground">{String(h.hypothesis)}</h4>
                      <p className="text-xs text-muted-foreground leading-relaxed">{String(h.reason)}</p>
                    </div>

                    {/* Governance Action Bar */}
                    <div className="flex items-center justify-between gap-3 pt-3 border-t border-border flex-wrap">
                      <div className="text-xs text-muted-foreground">
                        {Boolean(h.reviewed_by) && (
                          <span>
                            Reviewed by <strong>{String(h.reviewed_by)}</strong>
                          </span>
                        )}
                        {Boolean(h.rejection_reason) && (
                          <span className="text-destructive ml-2">({String(h.rejection_reason)})</span>
                        )}
                        {Boolean(h.security_test_id) && (
                          <span className="text-purple-400 ml-2 font-mono">
                            → Converted Test #{String(h.security_test_id)}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        {isPending && (
                          <>
                            <Button
                              size="sm"
                              className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                              onClick={() => {
                                setReviewingHypo(h);
                                setReviewAction("APPROVED");
                                setReviewReason("");
                              }}
                            >
                              Approve
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="text-xs text-destructive border-destructive/30 hover:bg-destructive/10"
                              onClick={() => {
                                setReviewingHypo(h);
                                setReviewAction("REJECTED");
                                setReviewReason("");
                              }}
                            >
                              Reject
                            </Button>
                          </>
                        )}

                        {isApproved && (
                          <Button
                            size="sm"
                            className="text-xs bg-purple-600 hover:bg-purple-500 text-white font-medium"
                            onClick={() => handleConvertHypothesis(String(h.id))}
                            disabled={actionInProgress === `convert_${String(h.id)}`}
                          >
                            Convert to SecurityTest →
                          </Button>
                        )}
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 6: SECURITY TESTS */}
      {activeTab === "tests" && (
        <div className="space-y-4">
          {context.security_tests.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No security tests attached to this case.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3.5">
              {context.security_tests.map((st) => (
                <Card key={String(st.id)} className="p-4 space-y-2 bg-card border-border">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-foreground">
                        {String(st.test_type)} Test #{String(st.id)}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-muted text-muted-foreground">
                        {String(st.status)}
                      </span>
                    </div>

                    {Boolean(st.latest_result) && (
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          st.latest_result === "PASS"
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                        }`}
                      >
                        Result: {String(st.latest_result)}
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-muted-foreground flex items-center gap-4 flex-wrap">
                    {Boolean(st.endpoint) && (
                      <div>
                        <span className="font-semibold text-foreground">Endpoint:</span>{" "}
                        <span className="font-mono">{String(st.endpoint)}</span>
                      </div>
                    )}
                    {Boolean(st.attacker_identity) && (
                      <div>
                        <span className="font-semibold text-foreground">Probe Identity:</span>{" "}
                        <span>{String(st.attacker_identity)}</span>
                      </div>
                    )}
                    <div>
                      <span className="font-semibold text-foreground">Executions:</span>{" "}
                      <span>{String(st.execution_count)}</span>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 7: CHRONOLOGICAL TIMELINE */}
      {activeTab === "timeline" && (
        <div className="space-y-4">
          <div className="p-3 rounded-lg border border-border bg-card/60 text-xs text-muted-foreground">
            Strict chronological reconstruction of verified findings, analytical graph correlations, AI insights, human approvals, and resulting security tests.
          </div>

          {timeline.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No timeline events recorded yet.
            </div>
          ) : (
            <div className="relative pl-6 border-l-2 border-border space-y-6 my-4">
              {timeline.map((ev) => {
                const cat = ev.category;
                const isVerified = cat === "VERIFIED";
                const isDet = cat === "DETERMINISTIC";
                const isAI = cat === "AI";
                const isHuman = cat === "HUMAN";
                const isEngine = cat === "ENGINE";

                return (
                  <div key={ev.id} className="relative group">
                    {/* Timeline Node Dot */}
                    <div
                      className={`absolute -left-[31px] top-1.5 w-4 h-4 rounded-full border-2 bg-background flex items-center justify-center ${
                        isVerified
                          ? "border-emerald-500"
                          : isDet
                          ? "border-blue-500"
                          : isAI
                          ? "border-purple-500"
                          : isHuman
                          ? "border-amber-500"
                          : isEngine
                          ? "border-indigo-500"
                          : "border-zinc-500"
                      }`}
                    >
                      <div
                        className={`w-1.5 h-1.5 rounded-full ${
                          isVerified
                            ? "bg-emerald-500"
                            : isDet
                            ? "bg-blue-500"
                            : isAI
                            ? "bg-purple-500"
                            : isHuman
                            ? "bg-amber-500"
                            : isEngine
                            ? "bg-indigo-500"
                            : "bg-zinc-500"
                        }`}
                      />
                    </div>

                    {/* Timeline Event Card */}
                    <Card className="p-4 space-y-2 bg-card/80 border-border">
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                              isVerified
                                ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                                : isDet
                                ? "bg-blue-500/10 text-blue-400 border-blue-500/20"
                                : isAI
                                ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                                : isHuman
                                ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                                : isEngine
                                ? "bg-indigo-500/10 text-indigo-400 border-indigo-500/20"
                                : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                            }`}
                          >
                            {cat}
                          </span>
                          <span className="font-bold text-xs text-foreground">{ev.title}</span>
                        </div>

                        <span className="text-[11px] font-mono text-muted-foreground">
                          {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : "Unknown Time"}
                        </span>
                      </div>

                      <p className="text-xs text-muted-foreground leading-relaxed">{ev.description}</p>

                      <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-3 pt-1">
                        <span>Source: {ev.source_type}</span>
                        <span>ID: {ev.source_id}</span>
                      </div>
                    </Card>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 8: ATTACHED ELEMENTS & MANAGEMENT */}
      {activeTab === "entities" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              Direct registry of all {investigation.items.length} entities connected to this case.
            </span>
            <Button size="sm" onClick={() => setShowAttachModal(true)} className="text-xs">
              + Attach New Entity
            </Button>
          </div>

          {investigation.items.length === 0 ? (
            <div className="p-12 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
              No items explicitly attached to this case.
            </div>
          ) : (
            <div className="border border-border rounded-lg overflow-hidden bg-card">
              <table className="w-full text-left text-xs">
                <thead className="bg-muted/50 border-b border-border font-semibold uppercase text-muted-foreground text-[10px]">
                  <tr>
                    <th className="px-4 py-2.5">Pos</th>
                    <th className="px-4 py-2.5">Type</th>
                    <th className="px-4 py-2.5">Entity ID</th>
                    <th className="px-4 py-2.5">Attached Date</th>
                    <th className="px-4 py-2.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {investigation.items.map((item) => (
                    <tr key={item.id} className="hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-2.5 font-mono text-muted-foreground">{item.position}</td>
                      <td className="px-4 py-2.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-muted text-foreground uppercase border border-border">
                          {item.item_type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-foreground">{item.item_id}</td>
                      <td className="px-4 py-2.5 text-muted-foreground">
                        {new Date(item.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-[11px] h-6 px-2 text-destructive border-destructive/20 hover:bg-destructive/10"
                          onClick={() => handleDetachItem(item.id)}
                          disabled={actionInProgress === `detach_${item.id}`}
                        >
                          {actionInProgress === `detach_${item.id}` ? "Detaching..." : "Detach"}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Modal: Human Review Approval/Rejection */}
      {reviewingHypo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <Card className="w-full max-w-md p-6 bg-background border border-border shadow-xl space-y-4">
            <div className="border-b border-border pb-3">
              <h3 className="font-semibold text-sm text-foreground">
                Human Governance: {reviewAction === "APPROVED" ? "Approve Hypothesis" : "Reject Hypothesis"}
              </h3>
              <p className="text-xs text-muted-foreground">
                Authorize or dismiss AI testing hypothesis. No test executes autonomously.
              </p>
            </div>

            <div className="p-3 rounded bg-muted/40 text-xs space-y-1">
              <span className="font-semibold text-foreground">Hypothesis:</span>
              <p className="text-muted-foreground">{String(reviewingHypo.hypothesis)}</p>
            </div>

            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Reviewer Identity *</label>
                <input
                  type="text"
                  required
                  value={reviewerName}
                  onChange={(e) => setReviewerName(e.target.value)}
                  className="w-full h-8 px-3 rounded border border-input bg-background text-xs"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Review Justification / Reason</label>
                <textarea
                  rows={2}
                  placeholder={
                    reviewAction === "APPROVED"
                      ? "e.g. Valid lateral movement hypothesis grounded in finding evidence"
                      : "e.g. False path hypothesis; not applicable to current architecture"
                  }
                  value={reviewReason}
                  onChange={(e) => setReviewReason(e.target.value)}
                  className="w-full p-2.5 rounded border border-input bg-background text-xs"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-2 border-t border-border">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setReviewingHypo(null)}
                  disabled={actionInProgress === "reviewing"}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={handleSubmitReview}
                  disabled={actionInProgress === "reviewing"}
                  className={`text-xs font-medium ${
                    reviewAction === "APPROVED"
                      ? "bg-emerald-600 hover:bg-emerald-500 text-white"
                      : "bg-destructive hover:bg-destructive/90 text-white"
                  }`}
                >
                  {actionInProgress === "reviewing"
                    ? "Submitting..."
                    : reviewAction === "APPROVED"
                    ? "Approve Hypothesis"
                    : "Reject Hypothesis"}
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Modal: Attach Entity */}
      {showAttachModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <Card className="w-full max-w-md p-6 bg-background border border-border shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="font-semibold text-sm text-foreground">Attach Entity to Case</h3>
                <p className="text-xs text-muted-foreground">
                  Attach verified project entities under strict tenant isolation.
                </p>
              </div>
              <button
                onClick={() => setShowAttachModal(false)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAttachItem} className="space-y-3.5">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Entity Type</label>
                <select
                  value={attachType}
                  onChange={(e) => setAttachType(e.target.value)}
                  className="w-full h-8 px-3 rounded border border-input bg-background text-xs"
                >
                  <option value="FINDING">FINDING</option>
                  <option value="EVIDENCE">EVIDENCE</option>
                  <option value="ATTACK_GRAPH">ATTACK_GRAPH</option>
                  <option value="ATTACK_PATH">ATTACK_PATH</option>
                  <option value="SECURITY_IMPACT">SECURITY_IMPACT</option>
                  <option value="AI_ANALYSIS">AI_ANALYSIS</option>
                  <option value="AI_HYPOTHESIS">AI_HYPOTHESIS</option>
                  <option value="SECURITY_TEST">SECURITY_TEST</option>
                  <option value="WORKFLOW_EXECUTION">WORKFLOW_EXECUTION</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Entity ID *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. UUID or integer ID"
                  value={attachId}
                  onChange={(e) => setAttachId(e.target.value)}
                  className="w-full h-8 px-3 rounded border border-input bg-background text-xs font-mono"
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-3 border-t border-border">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setShowAttachModal(false)}
                  disabled={actionInProgress === "attaching"}
                  className="text-xs"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={actionInProgress === "attaching" || !attachId.trim()}
                  className="text-xs bg-primary hover:bg-primary/90 text-primary-foreground font-medium"
                >
                  {actionInProgress === "attaching" ? "Attaching..." : "Attach to Case"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  );
}
