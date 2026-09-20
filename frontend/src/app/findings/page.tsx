"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
}

interface EvidenceData {
  id: string;
  execution_id: string;
  request_metadata: Record<string, unknown>;
  response_metadata: Record<string, unknown>;
  expected_behavior: string;
  actual_behavior: string;
  redacted_request: string | null;
  redacted_response: string | null;
  reproducibility_status: string;
}

interface FindingItem {
  id: string;
  project_id: number;
  security_test_id: string;
  execution_id: string;
  endpoint_id?: number | null;
  attacker_identity_id?: string | null;
  attacker_role_id?: string | null;
  type: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  description: string;
  remediation: string;
  expected_authorization?: string | null;
  actual_behavior?: string | null;
  created_at: string;
  endpoint_method: string | null;
  endpoint_path: string | null;
  attacker_identity_name: string | null;
  attacker_role_name?: string | null;
  victim_resource_name: string | null;
  victim_resource_instance_id: string | null;
}

interface FindingDetailItem extends FindingItem {
  evidence?: EvidenceData | null;
  expected_behavior?: string | null;
  actual_behavior?: string | null;
}

export default function FindingsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  // Detail Modal state
  const [selectedFinding, setSelectedFinding] = useState<FindingDetailItem | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<string | null>(null);

  const activeProject = projects.find((p) => p.id === selectedProjectId);

  // 1. Load projects
  useEffect(() => {
    let ignore = false;
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch projects");
        const data: Project[] = await res.json();
        if (!ignore) {
          setProjects(data);
          let initialId = data.length > 0 ? data[0].id : null;
          if (typeof window !== "undefined") {
            const params = new URLSearchParams(window.location.search);
            const pParam = params.get("project_id");
            if (pParam) initialId = Number(pParam);
            const tParam = params.get("type_filter");
            if (tParam) setTypeFilter(tParam.toUpperCase());
          }
          if (initialId !== null) {
            setSelectedProjectId((prev) => (prev === null ? initialId : prev));
          } else {
            setLoading(false);
          }
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load projects");
          setLoading(false);
        }
      }
    }
    loadProjects();
    return () => {
      ignore = true;
    };
  }, []);

  // 2. Load findings for selected project
  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;
    async function loadFindings() {
      try {
        let url = `/api/v1/projects/${selectedProjectId}/findings/`;
        const qParams: string[] = [];
        if (typeFilter !== "ALL") qParams.push(`type_filter=${typeFilter}`);
        if (severityFilter !== "ALL") qParams.push(`severity=${severityFilter}`);
        if (statusFilter !== "ALL") qParams.push(`status_filter=${statusFilter}`);
        if (qParams.length > 0) url += `?${qParams.join("&")}`;

        const res = await fetch(url, { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch findings");
        const data = await res.json();
        if (!ignore) {
          setFindings(data);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load findings");
          setLoading(false);
        }
      }
    }
    loadFindings();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, typeFilter, severityFilter, statusFilter, reloadKey]);

  const handleOpenDetail = async (findingId: string) => {
    setLoadingDetail(true);
    setReplayResult(null);
    try {
      const res = await fetch(`/api/v1/findings/${findingId}`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load finding details");
      const detail: FindingDetailItem = await res.json();
      setSelectedFinding(detail);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Failed to load detail"));
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleReplay = async (findingId: string) => {
    if (!activeProject || activeProject.authorization_status.toLowerCase() !== "authorized") {
      alert("Cannot replay: Target project is not currently authorized for security testing.");
      return;
    }
    setReplaying(true);
    setReplayResult(null);
    try {
      const res = await fetch(`/api/v1/findings/${findingId}/replay`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Replay execution failed");
      }
      const data = await res.json();
      setReplayResult(`Replay Completed: Result = ${data.result} (HTTP ${data.http_status || "N/A"}) - ${data.result_reason || ""}`);
      setReloadKey((k) => k + 1);
      // Refresh details
      await handleOpenDetail(findingId);
    } catch (err: unknown) {
      setReplayResult("Replay Failed: " + (err instanceof Error ? err.message : "Unknown error"));
    } finally {
      setReplaying(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
      case "HIGH":
        return "bg-red-500/20 text-red-700 dark:text-red-300 border-red-500/30";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-700 dark:text-amber-300 border-amber-500/30";
      default:
        return "bg-blue-500/20 text-blue-700 dark:text-blue-300 border-blue-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Security Findings</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Confirmed authorization vulnerabilities (BOLA & BFLA) with reproducible evidence and remediation guidance.
          </p>
        </div>
        {projects.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-muted-foreground uppercase">Project:</span>
            <select
              className="h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              value={selectedProjectId || ""}
              onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Type:</span>
          <select
            className="h-8 rounded-md border border-input bg-background px-2.5 text-xs shadow-xs"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="ALL">All Types</option>
            <option value="BOLA">BOLA (Resource Level)</option>
            <option value="BFLA">BFLA (Function Level)</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Severity:</span>
          <select
            className="h-8 rounded-md border border-input bg-background px-2.5 text-xs shadow-xs"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Status:</span>
          <select
            className="h-8 rounded-md border border-input bg-background px-2.5 text-xs shadow-xs"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>

        <div className="ml-auto text-xs text-muted-foreground">
          Showing {findings.length} finding(s)
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-destructive/10 border border-destructive text-destructive text-sm">
          {error}
        </div>
      )}

      {/* Findings List */}
      {loading ? (
        <div className="p-12 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading findings...
        </div>
      ) : findings.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground space-y-2">
            <div className="w-12 h-12 rounded-full bg-emerald-500/10 text-emerald-600 mx-auto flex items-center justify-center text-xl font-bold">
              ✓
            </div>
            <h3 className="font-medium text-foreground">No Findings Found</h3>
            <p className="text-xs max-w-sm mx-auto">
              No authorization vulnerabilities have been confirmed for the current filters. Run BOLA or BFLA tests from the Security Tests tab.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {findings.map((finding) => {
            const isBFLA = finding.type.toUpperCase() === "BFLA";
            return (
              <Card
                key={finding.id}
                className="p-5 border-border hover:border-foreground/20 transition-all cursor-pointer"
                onClick={() => handleOpenDetail(finding.id)}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-xs font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                          finding.severity
                        )}`}
                      >
                        {finding.severity}
                      </span>
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                          isBFLA
                            ? "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20"
                            : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20"
                        }`}
                      >
                        {finding.type}
                      </span>
                      <span className="text-xs font-semibold px-2 py-0.5 rounded bg-muted text-muted-foreground">
                        Confidence: {finding.confidence}
                      </span>
                      <span className="text-xs font-mono font-bold">
                        {finding.endpoint_method} {finding.endpoint_path}
                      </span>
                    </div>

                    <h3 className="font-bold text-foreground text-sm">{finding.title}</h3>
                    <p className="text-xs text-muted-foreground line-clamp-1">{finding.description}</p>

                    <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground pt-1">
                      <div>
                        <span className="font-semibold text-foreground">Attacker:</span>{" "}
                        {finding.attacker_identity_name || "Unknown"}
                        {finding.attacker_role_name && (
                          <span className="ml-1 text-[11px] text-muted-foreground">({finding.attacker_role_name})</span>
                        )}
                      </div>
                      {!isBFLA && finding.victim_resource_name && (
                        <div>
                          <span className="font-semibold text-foreground">Resource:</span>{" "}
                          {finding.victim_resource_name} ({finding.victim_resource_instance_id})
                        </div>
                      )}
                      {isBFLA && finding.expected_authorization && (
                        <div>
                          <span className="font-semibold text-foreground">Expected:</span>{" "}
                          <span className="text-rose-600 font-semibold">{finding.expected_authorization}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    <span className="text-xs text-muted-foreground">
                      {new Date(finding.created_at).toLocaleDateString()}
                    </span>
                    <Button variant="secondary" size="sm">
                      View Details
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl shadow-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-border pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`text-xs font-bold px-2.5 py-0.5 rounded border ${getSeverityBadge(
                      selectedFinding.severity
                    )}`}
                  >
                    {selectedFinding.severity}
                  </span>
                  <span
                    className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                      selectedFinding.type.toUpperCase() === "BFLA"
                        ? "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20"
                        : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20"
                    }`}
                  >
                    {selectedFinding.type}
                  </span>
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-muted">
                    Confidence: {selectedFinding.confidence}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded border border-border">
                    Status: {selectedFinding.status}
                  </span>
                </div>
                <h2 className="text-xl font-bold">{selectedFinding.title}</h2>
              </div>
              <button
                className="text-muted-foreground hover:text-foreground text-sm font-semibold p-1"
                onClick={() => {
                  setSelectedFinding(null);
                  setReplayResult(null);
                }}
              >
                ✕
              </button>
            </div>

            {replayResult && (
              <div
                className={`p-3 rounded-lg text-xs font-mono ${
                  replayResult.includes("CONFIRMED")
                    ? "bg-red-500/10 text-red-700 dark:text-red-300 border border-red-500/20"
                    : "bg-muted text-foreground border border-border"
                }`}
              >
                {replayResult}
              </div>
            )}

            {/* BFLA Violated Boundary Alert Box */}
            {selectedFinding.type.toUpperCase() === "BFLA" && (
              <div className="p-3.5 rounded-lg border border-purple-500/30 bg-purple-500/10 text-purple-900 dark:text-purple-200 text-xs space-y-1">
                <div className="font-semibold flex items-center gap-2">
                  <span>🛡️</span>
                  <span>Violated Authorization Boundary</span>
                </div>
                <p className="leading-relaxed">
                  Principal <strong>{selectedFinding.attacker_identity_name || "Attacker"}</strong>{" "}
                  with assigned role <strong>{selectedFinding.attacker_role_name || "Unassigned"}</strong>{" "}
                  was granted unauthorized access to function endpoint{" "}
                  <code className="font-mono font-bold bg-background/50 px-1 py-0.5 rounded">
                    {selectedFinding.endpoint_method} {selectedFinding.endpoint_path}
                  </code>.
                  The configured boundary rule required access to be{" "}
                  <strong>{selectedFinding.expected_authorization || "DENY"}</strong>.
                </p>
              </div>
            )}

            {/* Finding Attributes Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-card/60 border border-border space-y-1">
                <span className="font-semibold text-muted-foreground uppercase">ATTACKER & ROLE</span>
                <p className="text-foreground font-medium text-sm">
                  {selectedFinding.attacker_identity_name || "Configured Test Identity"}
                  {selectedFinding.attacker_role_name && (
                    <span className="text-xs text-muted-foreground ml-2">
                      (Role: {selectedFinding.attacker_role_name})
                    </span>
                  )}
                </p>
              </div>

              {selectedFinding.type.toUpperCase() === "BOLA" ? (
                <div className="p-3 rounded-lg bg-card/60 border border-border space-y-1">
                  <span className="font-semibold text-muted-foreground uppercase">VICTIM RESOURCE</span>
                  <p className="text-foreground font-medium text-sm">
                    {selectedFinding.victim_resource_name || "Resource"} ({selectedFinding.victim_resource_instance_id})
                  </p>
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-card/60 border border-border space-y-1">
                  <span className="font-semibold text-muted-foreground uppercase">EXPECTED BOUNDARY</span>
                  <p className="text-rose-600 font-mono font-bold text-sm">
                    {selectedFinding.expected_authorization || "DENY"}
                  </p>
                </div>
              )}

              <div className="p-3 rounded-lg bg-card/60 border border-border space-y-1 sm:col-span-2">
                <span className="font-semibold text-muted-foreground uppercase">TARGET ENDPOINT</span>
                <p className="text-foreground font-mono text-sm font-bold">
                  {selectedFinding.endpoint_method} {selectedFinding.endpoint_path}
                </p>
              </div>
            </div>

            {/* Expected vs Actual */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 space-y-1">
                <span className="font-semibold text-emerald-700 dark:text-emerald-300 uppercase">
                  EXPECTED BEHAVIOR
                </span>
                <p className="text-muted-foreground">
                  {selectedFinding.expected_behavior ||
                    (selectedFinding.type.toUpperCase() === "BFLA"
                      ? `Access to function endpoint must be rejected (HTTP 401 or 403) for role '${selectedFinding.attacker_role_name || "unassigned"}'.`
                      : "Cross-owner access must be denied with HTTP 401, 403, or 404 without exposing victim resource data.")}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-red-500/5 border border-red-500/20 space-y-1">
                <span className="font-semibold text-red-700 dark:text-red-300 uppercase">
                  ACTUAL BEHAVIOR
                </span>
                <p className="text-muted-foreground">
                  {selectedFinding.actual_behavior || selectedFinding.description}
                </p>
              </div>
            </div>

            {/* Evidence Section */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-semibold uppercase tracking-wider text-muted-foreground">
                  EVIDENCE (Redacted HTTP Transcripts)
                </span>
                {selectedFinding.evidence?.reproducibility_status && (
                  <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-secondary">
                    Status: {selectedFinding.evidence.reproducibility_status}
                  </span>
                )}
              </div>

              {loadingDetail ? (
                <div className="p-4 text-center text-muted-foreground animate-pulse">Loading evidence...</div>
              ) : selectedFinding.evidence ? (
                <div className="space-y-3">
                  <div>
                    <span className="text-[11px] font-semibold text-muted-foreground">Request Metadata:</span>
                    <pre className="p-3 rounded-md bg-muted/40 font-mono text-[11px] overflow-x-auto text-foreground mt-1 border border-border">
                      {JSON.stringify(selectedFinding.evidence.request_metadata, null, 2)}
                    </pre>
                  </div>

                  {selectedFinding.evidence.redacted_response && (
                    <div>
                      <span className="text-[11px] font-semibold text-muted-foreground">
                        Redacted Response Payload:
                      </span>
                      <pre className="p-3 rounded-md bg-muted/40 font-mono text-[11px] overflow-x-auto text-foreground mt-1 border border-border max-h-40">
                        {selectedFinding.evidence.redacted_response}
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3 text-muted-foreground border border-dashed border-border rounded-md">
                  No raw evidence object attached.
                </div>
              )}
            </div>

            {/* Remediation Section */}
            <div className="p-4 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs space-y-1.5">
              <span className="font-bold text-blue-700 dark:text-blue-300 uppercase tracking-wider">
                REMEDIATION GUIDANCE
              </span>
              <p className="text-foreground leading-relaxed">{selectedFinding.remediation}</p>
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-border">
              <span className="text-[11px] text-muted-foreground">
                Authorized Target Replay Verification
              </span>
              <div className="flex items-center gap-3">
                <Button variant="outline" onClick={() => setSelectedFinding(null)}>
                  Close
                </Button>
                <Button
                  onClick={() => handleReplay(selectedFinding.id)}
                  disabled={replaying || activeProject?.authorization_status.toLowerCase() !== "authorized"}
                  className="bg-red-600 hover:bg-red-700 text-white"
                >
                  {replaying ? "Replaying Probes..." : "Replay Test"}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
