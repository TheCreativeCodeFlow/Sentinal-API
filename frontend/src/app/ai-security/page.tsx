"use client";

import React, { useEffect, useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

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
  remediation: string;
  endpoint?: { method: string; path: string } | null;
  attacker_identity?: { name: string; auth_type: string } | null;
}

interface AttackPathStepItem {
  id: string;
  position: number;
  finding_id: string;
  finding_title?: string | null;
  finding_type?: string | null;
  finding_severity?: string | null;
  relationship_type: string;
  reason: string;
}

interface AttackPathItem {
  id: string;
  project_id: number;
  name: string;
  description?: string | null;
  status: string;
  confidence: string;
  step_count: number;
  steps: AttackPathStepItem[];
}

interface SecurityImpactItem {
  id: string;
  project_id: number;
  attack_path_id?: string | null;
  finding_id?: string | null;
  terminal_impact: string;
  explanation: string;
  boundaries_crossed: string[];
}

interface AIAnalysisDetail {
  id: string;
  project_id: number;
  attack_path_id?: string | null;
  finding_id?: string | null;
  analysis_type: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  model_provider: string;
  model_name: string;
  input_context: Record<string, unknown>;
  output?: Record<string, unknown> | null;
  error_message?: string | null;
  created_at: string;
  completed_at?: string | null;
  finding_title?: string | null;
  finding_type?: string | null;
  attack_path_name?: string | null;
}

export default function AISecurityPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPathItem[]>([]);
  const [impacts, setImpacts] = useState<SecurityImpactItem[]>([]);
  const [analyses, setAnalyses] = useState<AIAnalysisDetail[]>([]);

  const [loading, setLoading] = useState(true);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Tab State
  const [activeTab, setActiveTab] = useState<"findings" | "paths" | "recommendations" | "hypotheses" | "history">("findings");

  // Selection states
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [inspectedAnalysis, setInspectedAnalysis] = useState<AIAnalysisDetail | null>(null);

  // Recommendation Target Type
  const [recTargetType, setRecTargetType] = useState<"FINDING" | "ATTACK_PATH">("FINDING");

  // Load Projects on Mount
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
        const data: Project[] = await res.json();
        setProjects(data);
        if (data.length > 0) {
          setSelectedProjectId(data[0].id);
        }
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  // Reload helper
  const reloadAnalysesAndData = async (projectId: number) => {
    try {
      const [findingsRes, pathsRes, impactsRes, analysesRes] = await Promise.all([
        fetch(`/api/v1/projects/${projectId}/findings`, { credentials: "include" }),
        fetch(`/api/v1/projects/${projectId}/attack-paths`, { credentials: "include" }),
        fetch(`/api/v1/projects/${projectId}/security-impacts`, { credentials: "include" }),
        fetch(`/api/v1/projects/${projectId}/ai/analyses`, { credentials: "include" }),
      ]);

      if (findingsRes.ok) {
        const fData: FindingItem[] = await findingsRes.json();
        setFindings(fData.filter((f) => f.status === "CONFIRMED" || f.status === "OPEN"));
      }
      if (pathsRes.ok) {
        const pData: AttackPathItem[] = await pathsRes.json();
        setAttackPaths(pData);
      }
      if (impactsRes.ok) {
        const iData: SecurityImpactItem[] = await impactsRes.json();
        setImpacts(iData);
      }
      if (analysesRes.ok) {
        const aData = await analysesRes.json();
        setAnalyses(aData.analyses || []);
      }
    } catch {
      // Ignore background reload failure
    }
  };

  // Load project-specific data when selectedProjectId changes
  useEffect(() => {
    if (!selectedProjectId) return;

    let ignore = false;
    async function fetchData() {
      try {
        setErrorMsg(null);

        const [findingsRes, pathsRes, impactsRes, analysesRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/findings`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/attack-paths`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/security-impacts`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/ai/analyses`, { credentials: "include" }),
        ]);

        if (ignore) return;

        if (findingsRes.ok) {
          const fData: FindingItem[] = await findingsRes.json();
          setFindings(fData.filter((f) => f.status === "CONFIRMED" || f.status === "OPEN"));
        }
        if (pathsRes.ok) {
          const pData: AttackPathItem[] = await pathsRes.json();
          setAttackPaths(pData);
        }
        if (impactsRes.ok) {
          const iData: SecurityImpactItem[] = await impactsRes.json();
          setImpacts(iData);
        }
        if (analysesRes.ok) {
          const aData = await analysesRes.json();
          setAnalyses(aData.analyses || []);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setErrorMsg(err instanceof Error ? err.message : "Failed to load project security data");
        }
      }
    }

    fetchData();

    return () => {
      ignore = true;
    };
  }, [selectedProjectId]);

  // Trigger Finding Analysis
  const handleAnalyzeFinding = async (findingId: string) => {
    if (!selectedProjectId) return;
    setActionInProgress(`finding-${findingId}`);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/ai/analyze/finding/${findingId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Failed to analyze finding with AI");
      }
      await res.json();
      setSuccessMsg(`AI analysis completed for finding ${findingId}`);
      setSelectedFindingId(findingId);
      // Refresh analyses
      await reloadAnalysesAndData(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error analyzing finding");
    } finally {
      setActionInProgress(null);
    }
  };

  // Trigger Attack Path Explanation
  const handleAnalyzePath = async (pathId: string) => {
    if (!selectedProjectId) return;
    setActionInProgress(`path-${pathId}`);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/ai/analyze/path/${pathId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Failed to explain attack path");
      }
      await res.json();
      setSuccessMsg(`AI narrative synthesized for attack path ${pathId}`);
      setSelectedPathId(pathId);
      await reloadAnalysesAndData(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error explaining attack path");
    } finally {
      setActionInProgress(null);
    }
  };

  // Trigger Attack Hypotheses
  const handleGenerateHypotheses = async (pathId: string) => {
    if (!selectedProjectId) return;
    setActionInProgress(`hypo-${pathId}`);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/ai/hypotheses/path/${pathId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Failed to generate attack hypotheses");
      }
      await res.json();
      setSuccessMsg(`Grounded attack hypotheses generated for path ${pathId}`);
      setSelectedPathId(pathId);
      await reloadAnalysesAndData(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error generating hypotheses");
    } finally {
      setActionInProgress(null);
    }
  };

  // Trigger Security Recommendations
  const handleGenerateRecommendations = async (targetId: string, type: "FINDING" | "ATTACK_PATH") => {
    if (!selectedProjectId) return;
    setActionInProgress(`rec-${targetId}`);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const queryParam = type === "FINDING" ? `finding_id=${targetId}` : `attack_path_id=${targetId}`;
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/ai/recommendations?${queryParam}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Failed to generate recommendations");
      }
      await res.json();
      setSuccessMsg(`Security recommendations generated for ${type.toLowerCase()}`);
      await reloadAnalysesAndData(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error generating recommendations");
    } finally {
      setActionInProgress(null);
    }
  };

  // Trigger Project Executive Report Summary
  const handleGenerateExecutiveReport = async () => {
    if (!selectedProjectId) return;
    setActionInProgress("executive-report");
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/ai/report-summary`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.detail || "Failed to generate executive report");
      }
      await res.json();
      setSuccessMsg("Executive security report summary generated successfully.");
      setActiveTab("history");
      await reloadAnalysesAndData(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error generating executive summary");
    } finally {
      setActionInProgress(null);
    }
  };

  // Lookup latest analysis for currently selected item
  const latestFindingAnalysis = useMemo(() => {
    if (!selectedFindingId) return null;
    return analyses.find((a) => a.finding_id === selectedFindingId && a.analysis_type === "FINDING_EXPLANATION" && a.status === "COMPLETED") || null;
  }, [selectedFindingId, analyses]);

  const latestPathAnalysis = useMemo(() => {
    if (!selectedPathId) return null;
    return analyses.find((a) => a.attack_path_id === selectedPathId && a.analysis_type === "ATTACK_PATH_EXPLANATION" && a.status === "COMPLETED") || null;
  }, [selectedPathId, analyses]);

  const latestHypothesesAnalysis = useMemo(() => {
    if (!selectedPathId) return null;
    return analyses.find((a) => a.attack_path_id === selectedPathId && a.analysis_type === "ATTACK_HYPOTHESIS" && a.status === "COMPLETED") || null;
  }, [selectedPathId, analyses]);

  return (
    <div className="space-y-6">
      {/* Page Title & Mission Statement */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight">AI Security Reasoning</h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-primary/10 text-primary border border-primary/20">
              Stage 9.1
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Deterministic security graph reasoning, verified fact grounding, root cause analysis, and attack narrative synthesis.
          </p>
        </div>

        {/* Global Executive Summary Button */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={handleGenerateExecutiveReport}
            disabled={!selectedProjectId || actionInProgress === "executive-report"}
          >
            {actionInProgress === "executive-report" ? "Generating Briefing..." : "Executive Report Summary"}
          </Button>
        </div>
      </div>

      {/* Safety Boundary Principles Bar */}
      <div className="rounded-xl border border-border bg-card/60 p-4 space-y-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Semantic Boundaries:</span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            VERIFIED FACT
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
            DETERMINISTIC ANALYSIS
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            AI INTERPRETATION
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
            AI HYPOTHESIS (Requires Human Review)
          </span>
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed">
          <strong className="text-foreground">Critical Architectural Boundary:</strong> AI is an analytical assistant only. The deterministic security engine remains the authoritative source of truth. AI never executes target traffic, modifies findings, or overrides deterministic security conclusions.
        </p>
      </div>

      {/* Alerts */}
      {errorMsg && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-xs underline ml-4">Dismiss</button>
        </div>
      )}
      {successMsg && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-400 flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-xs underline ml-4">Dismiss</button>
        </div>
      )}

      {/* Project Selector & Overview Stats */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border border-border bg-card">
        <div className="flex items-center gap-3">
          <label className="text-sm font-medium text-muted-foreground whitespace-nowrap">Target Project:</label>
          <select
            className="bg-background border border-input rounded-md px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-1 focus:ring-ring"
            value={selectedProjectId || ""}
            onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            disabled={loading || projects.length === 0}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.authorization_status})
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="text-muted-foreground">Confirmed Findings:</span>
            <span className="font-bold text-foreground">{findings.length}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-muted-foreground">Attack Paths:</span>
            <span className="font-bold text-foreground">{attackPaths.length}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-muted-foreground">Impact Profiles:</span>
            <span className="font-bold text-foreground">{impacts.length}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-muted-foreground">AI Analyses:</span>
            <span className="font-bold text-foreground">{analyses.length}</span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex border-b border-border space-x-2 overflow-x-auto">
        <button
          onClick={() => setActiveTab("findings")}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "findings"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
          }`}
        >
          Finding Explanations
        </button>
        <button
          onClick={() => setActiveTab("paths")}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "paths"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
          }`}
        >
          Attack Path Narratives
        </button>
        <button
          onClick={() => setActiveTab("recommendations")}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "recommendations"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
          }`}
        >
          Remediation Guidance
        </button>
        <button
          onClick={() => setActiveTab("hypotheses")}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "hypotheses"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
          }`}
        >
          Attack Hypotheses
        </button>
        <button
          onClick={() => setActiveTab("history")}
          className={`px-4 py-2.5 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
            activeTab === "history"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted"
          }`}
        >
          Audit History ({analyses.length})
        </button>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: FINDING EXPLANATIONS */}
      {/* ========================================================================= */}
      {activeTab === "findings" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Finding Selector Column */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              Confirmed Findings ({findings.length})
            </h3>
            {findings.length === 0 ? (
              <Card className="p-6 text-center text-sm text-muted-foreground">
                No confirmed findings discovered for this project yet.
              </Card>
            ) : (
              <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
                {findings.map((f) => {
                  const isSelected = selectedFindingId === f.id;
                  const hasAnalysis = analyses.some((a) => a.finding_id === f.id && a.status === "COMPLETED");

                  return (
                    <div
                      key={f.id}
                      onClick={() => setSelectedFindingId(f.id)}
                      className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? "border-primary bg-primary/5 shadow-xs"
                          : "border-border bg-card hover:border-border/80"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="font-semibold text-sm truncate">{f.title}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-destructive/10 text-destructive border border-destructive/20">
                          {f.severity}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground truncate mb-2">
                        {f.endpoint?.method} {f.endpoint?.path}
                      </div>
                      <div className="flex items-center justify-between pt-1 border-t border-border/50 text-[11px]">
                        <span className="text-muted-foreground">{f.type}</span>
                        {hasAnalysis ? (
                          <span className="text-emerald-400 font-medium">✓ Explained</span>
                        ) : (
                          <span className="text-muted-foreground">Unanalyzed</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Explanation Inspector Column */}
          <div className="lg:col-span-2 space-y-4">
            {selectedFindingId ? (
              (() => {
                const finding = findings.find((f) => f.id === selectedFindingId);
                const out = (latestFindingAnalysis?.output || {}) as {
                  summary?: string;
                  root_cause_analysis?: string;
                  evidence_corroboration?: string;
                  potential_misconfigurations?: string[];
                  recommended_investigation?: string;
                };

                return (
                  <Card className="p-6 space-y-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            VERIFIED FACT
                          </span>
                          <span className="text-xs text-muted-foreground">{finding?.type}</span>
                        </div>
                        <h2 className="text-lg font-bold mt-1">{finding?.title}</h2>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {finding?.endpoint?.method} {finding?.endpoint?.path}
                        </p>
                      </div>

                      <Button
                        size="sm"
                        onClick={() => handleAnalyzeFinding(selectedFindingId)}
                        disabled={actionInProgress === `finding-${selectedFindingId}`}
                      >
                        {actionInProgress === `finding-${selectedFindingId}` ? "Analyzing Evidence..." : "Explain with AI"}
                      </Button>
                    </div>

                    {latestFindingAnalysis ? (
                      <div className="space-y-5">
                        {/* Summary */}
                        <div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Executive Summary</h4>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              AI INTERPRETATION
                            </span>
                          </div>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border">
                            {out.summary}
                          </p>
                        </div>

                        {/* Root Cause Analysis */}
                        <div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Root Cause Analysis</h4>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              AI INTERPRETATION
                            </span>
                          </div>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border leading-relaxed">
                            {out.root_cause_analysis}
                          </p>
                        </div>

                        {/* Evidence Corroboration */}
                        <div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Evidence Corroboration</h4>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                              VERIFIED FACT
                            </span>
                          </div>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border leading-relaxed">
                            {out.evidence_corroboration}
                          </p>
                        </div>

                        {/* Potential Misconfigurations */}
                        {out.potential_misconfigurations && out.potential_misconfigurations.length > 0 && (
                          <div>
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                              Likely Architecture / Code Misconfigurations
                            </h4>
                            <ul className="space-y-1.5">
                              {out.potential_misconfigurations.map((item, idx) => (
                                <li key={idx} className="text-xs text-foreground flex items-start gap-2 bg-muted/20 p-2 rounded border border-border">
                                  <span className="text-primary font-bold">•</span>
                                  <span>{item}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Recommended Investigation */}
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                            Recommended Engineering Investigation
                          </h4>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border">
                            {out.recommended_investigation}
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-12 text-sm text-muted-foreground space-y-3">
                        <p>No AI explanation generated yet for this confirmed finding.</p>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleAnalyzeFinding(selectedFindingId)}
                          disabled={actionInProgress === `finding-${selectedFindingId}`}
                        >
                          Generate AI Explanation
                        </Button>
                      </div>
                    )}
                  </Card>
                );
              })()
            ) : (
              <Card className="p-12 text-center text-sm text-muted-foreground">
                Select a confirmed finding from the left to view or generate an AI security explanation.
              </Card>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: ATTACK PATH NARRATIVES */}
      {/* ========================================================================= */}
      {activeTab === "paths" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Path Selector Column */}
          <div className="space-y-3">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              Deterministic Attack Paths ({attackPaths.length})
            </h3>
            {attackPaths.length === 0 ? (
              <Card className="p-6 text-center text-sm text-muted-foreground">
                No active attack paths detected yet. Run Attack Path Detection in the Attack Graph view first.
              </Card>
            ) : (
              <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
                {attackPaths.map((p) => {
                  const isSelected = selectedPathId === p.id;
                  const hasAnalysis = analyses.some((a) => a.attack_path_id === p.id && a.analysis_type === "ATTACK_PATH_EXPLANATION" && a.status === "COMPLETED");

                  return (
                    <div
                      key={p.id}
                      onClick={() => setSelectedPathId(p.id)}
                      className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? "border-primary bg-primary/5 shadow-xs"
                          : "border-border bg-card hover:border-border/80"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="font-semibold text-sm truncate">{p.name}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                          {p.confidence}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                        {p.description || "Multi-step deterministic attack path"}
                      </p>
                      <div className="flex items-center justify-between pt-1 border-t border-border/50 text-[11px]">
                        <span className="text-muted-foreground">{p.steps?.length || p.step_count || 0} Steps</span>
                        {hasAnalysis ? (
                          <span className="text-emerald-400 font-medium">✓ Narrative Ready</span>
                        ) : (
                          <span className="text-muted-foreground">Unanalyzed</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Narrative Inspector Column */}
          <div className="lg:col-span-2 space-y-4">
            {selectedPathId ? (
              (() => {
                const path = attackPaths.find((p) => p.id === selectedPathId);
                const out = (latestPathAnalysis?.output || {}) as {
                  path_narrative?: string;
                  prerequisite_analysis?: string;
                  step_by_step_breakdown?: Array<{
                    step_position: number;
                    finding_title: string;
                    role_in_chain: string;
                  }>;
                  exploitability_factors?: string;
                  critical_choke_point?: string;
                };

                return (
                  <Card className="p-6 space-y-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            DETERMINISTIC ANALYSIS
                          </span>
                          <span className="text-xs text-muted-foreground">{path?.confidence} CONFIDENCE</span>
                        </div>
                        <h2 className="text-lg font-bold mt-1">{path?.name}</h2>
                        <p className="text-xs text-muted-foreground mt-0.5">{path?.description}</p>
                      </div>

                      <Button
                        size="sm"
                        onClick={() => handleAnalyzePath(selectedPathId)}
                        disabled={actionInProgress === `path-${selectedPathId}`}
                      >
                        {actionInProgress === `path-${selectedPathId}` ? "Synthesizing Narrative..." : "Synthesize Narrative"}
                      </Button>
                    </div>

                    {latestPathAnalysis ? (
                      <div className="space-y-5">
                        {/* Narrative */}
                        <div>
                          <div className="flex items-center gap-2 mb-1.5">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Attack Narrative</h4>
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              AI INTERPRETATION
                            </span>
                          </div>
                          <p className="text-sm text-foreground bg-muted/30 p-3.5 rounded-lg border border-border leading-relaxed">
                            {out.path_narrative}
                          </p>
                        </div>

                        {/* Prerequisite Analysis */}
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">Prerequisite Flow</h4>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border leading-relaxed">
                            {out.prerequisite_analysis}
                          </p>
                        </div>

                        {/* Critical Choke Point (Highlighted) */}
                        {out.critical_choke_point && (
                          <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-rose-400 font-bold text-xs uppercase tracking-wider">🎯 Critical Remediation Choke Point</span>
                            </div>
                            <p className="text-sm text-foreground">{out.critical_choke_point}</p>
                          </div>
                        )}

                        {/* Step by Step Breakdown */}
                        {out.step_by_step_breakdown && (
                          <div>
                            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
                              Step-by-Step Chain Breakdown
                            </h4>
                            <div className="space-y-2">
                              {out.step_by_step_breakdown.map((s, idx) => (
                                <div key={idx} className="p-3 rounded-lg border border-border bg-card flex items-start gap-3">
                                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">
                                    {s.step_position}
                                  </span>
                                  <div className="min-w-0 flex-1">
                                    <h5 className="text-sm font-semibold">{s.finding_title}</h5>
                                    <p className="text-xs text-muted-foreground mt-0.5">{s.role_in_chain}</p>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Exploitability Factors */}
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1.5">
                            Exploitability Factors & Constraints
                          </h4>
                          <p className="text-sm text-foreground bg-muted/30 p-3 rounded-lg border border-border">
                            {out.exploitability_factors}
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-12 text-sm text-muted-foreground space-y-3">
                        <p>No narrative synthesized for this attack path yet.</p>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleAnalyzePath(selectedPathId)}
                          disabled={actionInProgress === `path-${selectedPathId}`}
                        >
                          Synthesize AI Narrative
                        </Button>
                      </div>
                    )}
                  </Card>
                );
              })()
            ) : (
              <Card className="p-12 text-center text-sm text-muted-foreground">
                Select an attack path from the left to view or synthesize its end-to-end security narrative.
              </Card>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: REMEDIATION GUIDANCE */}
      {/* ========================================================================= */}
      {activeTab === "recommendations" && (
        <div className="space-y-6">
          <Card className="p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
              <div>
                <h3 className="text-lg font-bold">Generate Remediation Plan</h3>
                <p className="text-sm text-muted-foreground">
                  Get tactical fixes, architectural design remediations, and code-level authorization guardrails.
                </p>
              </div>

              {/* Target Type Toggle */}
              <div className="flex items-center gap-2">
                <Button
                  variant={recTargetType === "FINDING" ? "primary" : "outline"}
                  size="sm"
                  onClick={() => setRecTargetType("FINDING")}
                >
                  By Finding
                </Button>
                <Button
                  variant={recTargetType === "ATTACK_PATH" ? "primary" : "outline"}
                  size="sm"
                  onClick={() => setRecTargetType("ATTACK_PATH")}
                >
                  By Attack Path
                </Button>
              </div>
            </div>

            {/* Target Selector */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {recTargetType === "FINDING" ? (
                <div>
                  <label className="text-xs font-semibold text-muted-foreground mb-1 block">Select Finding:</label>
                  <select
                    className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm"
                    value={selectedFindingId || ""}
                    onChange={(e) => setSelectedFindingId(e.target.value)}
                  >
                    <option value="">-- Select Confirmed Finding --</option>
                    {findings.map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.title} ({f.severity})
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div>
                  <label className="text-xs font-semibold text-muted-foreground mb-1 block">Select Attack Path:</label>
                  <select
                    className="w-full bg-background border border-input rounded-md px-3 py-2 text-sm"
                    value={selectedPathId || ""}
                    onChange={(e) => setSelectedPathId(e.target.value)}
                  >
                    <option value="">-- Select Attack Path --</option>
                    {attackPaths.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.confidence})
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div className="flex items-end">
                <Button
                  className="w-full sm:w-auto"
                  disabled={
                    (recTargetType === "FINDING" && !selectedFindingId) ||
                    (recTargetType === "ATTACK_PATH" && !selectedPathId) ||
                    actionInProgress?.startsWith("rec-")
                  }
                  onClick={() => {
                    const targetId = recTargetType === "FINDING" ? selectedFindingId! : selectedPathId!;
                    handleGenerateRecommendations(targetId, recTargetType);
                  }}
                >
                  {actionInProgress?.startsWith("rec-") ? "Formulating Guidance..." : "Generate Recommendations"}
                </Button>
              </div>
            </div>
          </Card>

          {/* Render Recommendations if present in analysis history */}
          {(() => {
            const activeId = recTargetType === "FINDING" ? selectedFindingId : selectedPathId;
            const recAnalysis = analyses.find(
              (a) =>
                a.analysis_type === "SECURITY_RECOMMENDATION" &&
                a.status === "COMPLETED" &&
                (recTargetType === "FINDING" ? a.finding_id === activeId : a.attack_path_id === activeId)
            );

            if (!recAnalysis) {
              return (
                <Card className="p-8 text-center text-sm text-muted-foreground">
                  Select a target above and click &quot;Generate Recommendations&quot; to inspect structured remediations.
                </Card>
              );
            }

            const out = (recAnalysis.output || {}) as {
              immediate_mitigations?: string[];
              architectural_remediations?: string[];
              preventative_controls?: string[];
              code_level_guidance?: string;
            };

            return (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Immediate Mitigations */}
                <Card className="p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
                    <h4 className="text-sm font-bold uppercase tracking-wider">Immediate Tactical Mitigations</h4>
                  </div>
                  <ul className="space-y-2">
                    {out.immediate_mitigations?.map((item, idx) => (
                      <li key={idx} className="text-xs text-foreground bg-muted/20 p-2.5 rounded border border-border flex items-start gap-2">
                        <span className="text-amber-400 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Card>

                {/* Architectural Remediations */}
                <Card className="p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-blue-400"></span>
                    <h4 className="text-sm font-bold uppercase tracking-wider">Architectural Remediations</h4>
                  </div>
                  <ul className="space-y-2">
                    {out.architectural_remediations?.map((item, idx) => (
                      <li key={idx} className="text-xs text-foreground bg-muted/20 p-2.5 rounded border border-border flex items-start gap-2">
                        <span className="text-blue-400 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Card>

                {/* Preventative Controls */}
                <Card className="p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
                    <h4 className="text-sm font-bold uppercase tracking-wider">Automated Guardrails & Tests</h4>
                  </div>
                  <ul className="space-y-2">
                    {out.preventative_controls?.map((item, idx) => (
                      <li key={idx} className="text-xs text-foreground bg-muted/20 p-2.5 rounded border border-border flex items-start gap-2">
                        <span className="text-emerald-400 font-bold">•</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </Card>

                {/* Code-Level Guidance */}
                <Card className="p-5 space-y-3">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-purple-400"></span>
                    <h4 className="text-sm font-bold uppercase tracking-wider">Code / Policy Implementation</h4>
                  </div>
                  <pre className="text-xs font-mono bg-muted/40 p-3 rounded-lg border border-border text-foreground overflow-x-auto whitespace-pre-wrap">
                    {out.code_level_guidance || "No code pattern provided."}
                  </pre>
                </Card>
              </div>
            );
          })()}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: ATTACK HYPOTHESES */}
      {/* ========================================================================= */}
      {activeTab === "hypotheses" && (
        <div className="space-y-6">
          <Card className="p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-bold">Attack Hypotheses Generator</h3>
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    AI HYPOTHESIS
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mt-0.5">
                  Propose safe, grounded attack hypotheses based on observed attack paths. Hypotheses require human verification and are never auto-executed.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <select
                  className="bg-background border border-input rounded-md px-3 py-1.5 text-sm"
                  value={selectedPathId || ""}
                  onChange={(e) => setSelectedPathId(e.target.value)}
                >
                  <option value="">-- Choose Attack Path --</option>
                  {attackPaths.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>

                <Button
                  size="sm"
                  disabled={!selectedPathId || actionInProgress === `hypo-${selectedPathId}`}
                  onClick={() => selectedPathId && handleGenerateHypotheses(selectedPathId)}
                >
                  {actionInProgress === `hypo-${selectedPathId}` ? "Reasoning..." : "Generate Hypotheses"}
                </Button>
              </div>
            </div>

            {/* Caveats Disclaimer */}
            <div className="p-3 rounded-lg border border-purple-500/30 bg-purple-500/10 text-xs text-purple-300">
              <strong>Human Review Mandatory:</strong> All generated hypotheses represent unconfirmed, deductive possibilities. SentinelAPI will NOT execute tests against hypotheses automatically without explicit authorization and manual specification.
            </div>
          </Card>

          {/* Hypotheses Cards */}
          {latestHypothesesAnalysis ? (
            (() => {
              const out = (latestHypothesesAnalysis.output || {}) as {
                hypotheses?: Array<{
                  hypothesis: string;
                  reason: string;
                  required_existing_context: string[];
                  suggested_test_type: string;
                  confidence: string;
                  requires_human_review: boolean;
                }>;
                caveats?: string;
              };

              return (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {out.hypotheses?.map((h, idx) => (
                      <Card key={idx} className="p-5 space-y-3.5 border-l-4 border-l-purple-500">
                        <div className="flex items-center justify-between gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-destructive/10 text-destructive border border-destructive/20">
                            REQUIRES HUMAN REVIEW
                          </span>
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-primary/10 text-primary border border-primary/20">
                            CONFIDENCE: {h.confidence}
                          </span>
                        </div>

                        <div>
                          <h4 className="text-sm font-semibold text-foreground leading-snug">{h.hypothesis}</h4>
                          <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{h.reason}</p>
                        </div>

                        <div className="pt-2 border-t border-border space-y-2">
                          <div>
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block mb-1">
                              Context Prerequisites:
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {h.required_existing_context?.map((c, cIdx) => (
                                <span key={cIdx} className="px-2 py-0.5 rounded text-[10px] bg-muted text-foreground border border-border">
                                  {c}
                                </span>
                              ))}
                            </div>
                          </div>

                          <div className="flex items-center justify-between text-xs pt-1">
                            <span className="text-muted-foreground">Suggested Safe Test:</span>
                            <span className="font-mono text-primary text-[11px]">{h.suggested_test_type}</span>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>

                  {out.caveats && (
                    <div className="text-xs text-muted-foreground italic text-center p-3">
                      Note: {out.caveats}
                    </div>
                  )}
                </div>
              );
            })()
          ) : (
            <Card className="p-12 text-center text-sm text-muted-foreground">
              Select an attack path above to generate grounded lateral movement and misconfiguration hypotheses.
            </Card>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: AUDIT HISTORY & RAW INSPECTOR */}
      {/* ========================================================================= */}
      {activeTab === "history" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
              AI Analysis Audit Trail ({analyses.length})
            </h3>
            <span className="text-xs text-muted-foreground">
              Every inference run is persisted with full input context and model provenance.
            </span>
          </div>

          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-muted/50 border-b border-border text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-4 py-3">Analysis Type</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Provider / Model</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {analyses.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-sm text-muted-foreground">
                      No AI security analyses have been executed for this project yet.
                    </td>
                  </tr>
                ) : (
                  analyses.map((a) => (
                    <tr key={a.id} className="hover:bg-accent/40 transition-colors">
                      <td className="px-4 py-3 font-semibold text-xs text-foreground">
                        {a.analysis_type}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground truncate max-w-[200px]">
                        {a.finding_title || a.attack_path_name || (a.finding_id ? `Finding: ${a.finding_id}` : a.attack_path_id ? `Path: ${a.attack_path_id}` : "Project-wide")}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        <span className="font-mono">{a.model_provider}</span> ({a.model_name})
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            a.status === "COMPLETED"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : a.status === "FAILED"
                              ? "bg-destructive/10 text-destructive border border-destructive/20"
                              : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          }`}
                        >
                          {a.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {new Date(a.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setInspectedAnalysis(a)}
                        >
                          Inspect Provenance
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Modal / Drawer for Analysis Inspection */}
          {inspectedAnalysis && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
              <div className="w-full max-w-4xl max-h-[90vh] bg-card border border-border rounded-xl shadow-xl flex flex-col overflow-hidden">
                <div className="flex items-center justify-between p-4 border-b border-border">
                  <div>
                    <h3 className="font-bold text-base">{inspectedAnalysis.analysis_type}</h3>
                    <p className="text-xs text-muted-foreground font-mono">ID: {inspectedAnalysis.id}</p>
                  </div>
                  <button
                    onClick={() => setInspectedAnalysis(null)}
                    className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground text-sm"
                  >
                    ✕
                  </button>
                </div>

                <div className="p-6 overflow-y-auto space-y-6">
                  {/* Meta details */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-3 bg-muted/20 rounded-lg text-xs">
                    <div>
                      <span className="text-muted-foreground block">Status:</span>
                      <span className="font-bold">{inspectedAnalysis.status}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Model Provider:</span>
                      <span className="font-mono">{inspectedAnalysis.model_provider}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Model Name:</span>
                      <span className="font-mono">{inspectedAnalysis.model_name}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Completed:</span>
                      <span>{inspectedAnalysis.completed_at ? new Date(inspectedAnalysis.completed_at).toLocaleTimeString() : "N/A"}</span>
                    </div>
                  </div>

                  {inspectedAnalysis.error_message && (
                    <div className="p-3 rounded-lg border border-destructive/30 bg-destructive/10 text-xs text-destructive">
                      <strong>Error:</strong> {inspectedAnalysis.error_message}
                    </div>
                  )}

                  {/* Validated Output */}
                  <div>
                    <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider mb-2">
                      Validated Schema Output
                    </h4>
                    <pre className="text-xs font-mono bg-muted/40 p-4 rounded-lg border border-border overflow-x-auto whitespace-pre-wrap max-h-72">
                      {JSON.stringify(inspectedAnalysis.output, null, 2)}
                    </pre>
                  </div>

                  {/* Input Context */}
                  <div>
                    <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider mb-2">
                      Bounded Input Context (Sanitized & Redacted)
                    </h4>
                    <pre className="text-xs font-mono bg-muted/40 p-4 rounded-lg border border-border overflow-x-auto whitespace-pre-wrap max-h-72 text-muted-foreground">
                      {JSON.stringify(inspectedAnalysis.input_context, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="p-4 border-t border-border flex justify-end">
                  <Button variant="secondary" size="sm" onClick={() => setInspectedAnalysis(null)}>
                    Close
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
