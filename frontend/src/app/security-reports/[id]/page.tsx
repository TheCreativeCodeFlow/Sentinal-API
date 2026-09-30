"use client";

import React, { useEffect, useState, use } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface ProvenanceBadgeProps {
  provenance: "VERIFIED" | "DETERMINISTIC" | "AI" | "HUMAN" | "ENGINE" | string;
}

function ProvenanceBadge({ provenance }: ProvenanceBadgeProps) {
  const styles: Record<string, string> = {
    VERIFIED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    DETERMINISTIC: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    AI: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    HUMAN: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    ENGINE: "bg-muted text-muted-foreground border-border",
  };

  const style = styles[provenance] || "bg-accent/40 text-foreground border-border";

  return (
    <span
      className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold border tracking-wider ${style}`}
    >
      {provenance}
    </span>
  );
}

interface FindingItem {
  finding_id: string;
  title: string;
  severity: string;
  type: string;
  confidence: string;
  description?: string;
  expected_authorization?: string;
  actual_behavior?: string;
  remediation?: string;
  provenance?: string;
}

interface AttackPathStepItem {
  step_id: string;
  position: number;
  finding_id: string;
  relationship_type: string;
  reason?: string;
}

interface AttackPathItem {
  attack_path_id: string;
  name: string;
  confidence: string;
  description?: string;
  provenance?: string;
  steps?: AttackPathStepItem[];
}

interface SecurityImpactItem {
  impact_id: string;
  terminal_impact: string;
  explanation: string;
  initial_access?: boolean;
  authorization_boundary_crossed?: boolean;
  sensitive_data_reached?: boolean;
  cross_identity_impact?: boolean;
  provenance?: string;
}

interface BaselineComparisonItemData {
  comparison_item_id: string;
  result: string;
  explanation: string;
  previous_behavior?: string;
  current_behavior?: string;
  provenance?: string;
}

interface BaselineComparisonData {
  baseline_name?: string;
  baseline_version?: number;
  items?: BaselineComparisonItemData[];
}

interface GateResultData {
  gate_name: string;
  status: string;
  evaluated_at: string;
  failure_count: number;
  warning_count: number;
  confirmed_findings: number;
  regressions: number;
}

interface SanitizedEvidenceItem {
  evidence_id: string;
  finding_id: string;
  request_metadata?: Record<string, unknown>;
  response_metadata?: Record<string, unknown>;
}

interface AIAnalysisItem {
  analysis_id: string;
  analysis_type: string;
  provider: string;
  model: string;
  output: unknown;
}

interface HumanReviewItem {
  review_id: string;
  action: string;
  reviewer_reference: string;
  reason?: string;
  created_at: string;
}

interface RemediationItem {
  finding_id?: string;
  title: string;
  severity: string;
  remediation: string;
}

interface SnapshotJson {
  executive_summary?: {
    findings_count?: number;
    findings_by_severity?: Record<string, number>;
    regressions_count?: number;
    new_violations_count?: number;
    attack_paths_count?: number;
    gate_status?: string;
    project_name?: string;
    scan_profile?: string;
    baseline_version?: number;
  };
  verified_findings?: FindingItem[];
  attack_paths?: AttackPathItem[];
  security_impacts?: SecurityImpactItem[];
  baseline_comparison?: BaselineComparisonData;
  gate_result?: GateResultData;
  sanitized_evidence?: SanitizedEvidenceItem[];
  ai_security_analysis?: AIAnalysisItem[];
  human_reviews?: HumanReviewItem[];
  remediation_recommendations?: RemediationItem[];
}

interface SecurityReportDetail {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "DRAFT" | "PUBLISHED" | "ARCHIVED";
  report_type: string;
  source_execution_plan_id: string | null;
  source_gate_evaluation_id: string | null;
  source_investigation_id: string | null;
  version: number;
  created_at: string;
  updated_at: string;
  generated_at: string | null;
  latest_snapshot: {
    id: string;
    report_id: string;
    version: number;
    generated_at: string;
    checksum: string;
    schema_version: string;
    report_json: SnapshotJson;
  } | null;
}

export default function SecurityReportDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const reportId = resolvedParams.id;
  const router = useRouter();

  const [report, setReport] = useState<SecurityReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<string>("executive");

  // Actions
  const [generating, setGenerating] = useState(false);
  const [archiving, setArchiving] = useState(false);
  const [copiedChecksum, setCopiedChecksum] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState(false);

  // Refresh Report after action
  const refreshReport = async () => {
    try {
      const res = await fetch(`/api/v1/security-reports/${reportId}`, {
        credentials: "include",
      });
      if (!res.ok) {
        throw new Error(`Report not found (Status: ${res.status})`);
      }
      const data: SecurityReportDetail = await res.json();
      setReport(data);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load report");
    }
  };

  useEffect(() => {
    let active = true;
    async function loadInitial() {
      try {
        const res = await fetch(`/api/v1/security-reports/${reportId}`, {
          credentials: "include",
        });
        if (!res.ok) {
          throw new Error(`Report not found (Status: ${res.status})`);
        }
        const data: SecurityReportDetail = await res.json();
        if (active) {
          setReport(data);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (active) {
          setErrorMsg(err instanceof Error ? err.message : "Failed to load report");
          setLoading(false);
        }
      }
    }
    loadInitial();
    return () => {
      active = false;
    };
  }, [reportId]);

  // Handle Generate
  const handleGenerate = async () => {
    try {
      setGenerating(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/security-reports/${reportId}/generate`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to generate report snapshot");
      }
      const snapshot = await res.json();
      setSuccessMsg(`Snapshot v${snapshot.version} successfully generated! Checksum: ${snapshot.checksum.substring(0, 16)}...`);
      await refreshReport();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Generation failed");
    } finally {
      setGenerating(false);
    }
  };

  // Handle Archive
  const handleArchive = async () => {
    if (!report) return;
    if (!confirm(`Are you sure you want to ARCHIVE "${report.name}"? This makes the report permanently immutable.`)) {
      return;
    }
    try {
      setArchiving(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/security-reports/${reportId}/archive`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to archive report");
      }
      setSuccessMsg(`Report "${report.name}" is now ARCHIVED and immutable.`);
      await refreshReport();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Archiving failed");
    } finally {
      setArchiving(false);
    }
  };

  // Download helper
  const downloadJson = async (url: string, filename: string) => {
    try {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) throw new Error("Download failed");
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
      setErrorMsg(err instanceof Error ? err.message : "Download failed");
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px] text-muted-foreground text-sm">
        Loading Security Report details...
      </div>
    );
  }

  if (!report) {
    return (
      <div className="p-8 text-center space-y-4">
        <h2 className="text-xl font-bold text-destructive">Security Report Not Found</h2>
        <p className="text-sm text-muted-foreground">{errorMsg || "The requested report does not exist or has been deleted."}</p>
        <Button onClick={() => router.push("/security-reports")}>Back to Security Reports</Button>
      </div>
    );
  }

  const snapshot = report.latest_snapshot;
  const reportData = snapshot ? snapshot.report_json : null;
  const execSummary = reportData ? reportData.executive_summary : null;
  const verifiedFindings: FindingItem[] = reportData ? reportData.verified_findings || [] : [];
  const attackPaths: AttackPathItem[] = reportData ? reportData.attack_paths || [] : [];
  const securityImpacts: SecurityImpactItem[] = reportData ? reportData.security_impacts || [] : [];
  const baselineComp: BaselineComparisonData | undefined = reportData?.baseline_comparison;
  const gateResult: GateResultData | undefined = reportData?.gate_result;
  const sanitizedEvidence: SanitizedEvidenceItem[] = reportData ? reportData.sanitized_evidence || [] : [];
  const aiSection: AIAnalysisItem[] = reportData ? reportData.ai_security_analysis || [] : [];
  const humanReviews: HumanReviewItem[] = reportData ? reportData.human_reviews || [] : [];
  const remediationItems: RemediationItem[] = reportData ? reportData.remediation_recommendations || [] : [];

  return (
    <div className="space-y-6">
      {/* Back and Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Link href="/security-reports" className="hover:text-foreground">
          ← Security Reports
        </Link>
        <span>/</span>
        <span className="font-mono text-foreground">{report.id}</span>
      </div>

      {/* Report Header Card */}
      <Card className="border border-border bg-card shadow-xs">
        <CardContent className="p-6">
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-2xl font-bold tracking-tight">{report.name}</h1>
                <span
                  className={`px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase ${
                    report.status === "PUBLISHED"
                      ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                      : report.status === "ARCHIVED"
                      ? "bg-muted text-muted-foreground border border-border"
                      : "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                  }`}
                >
                  {report.status}
                </span>

                <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-accent/50 text-foreground border border-border/60">
                  {report.report_type}
                </span>

                <span className="text-xs text-muted-foreground font-mono">
                  Version {report.version}
                </span>
              </div>

              {report.description && (
                <p className="text-sm text-muted-foreground max-w-3xl">{report.description}</p>
              )}

              {/* Integrity & Metadata Row */}
              <div className="flex flex-wrap items-center gap-4 pt-2 text-xs text-muted-foreground">
                {snapshot ? (
                  <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-md">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    <span className="font-semibold text-emerald-400">Snapshot Verified:</span>
                    <span className="font-mono text-foreground font-medium">
                      SHA-256: {snapshot.checksum.substring(0, 16)}...
                    </span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(snapshot.checksum);
                        setCopiedChecksum(true);
                        setTimeout(() => setCopiedChecksum(false), 2000);
                      }}
                      className="text-xs text-primary hover:underline ml-1"
                    >
                      {copiedChecksum ? "Copied!" : "Copy"}
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-md text-amber-400">
                    <span className="font-semibold">Draft Report:</span> No immutable snapshot generated yet.
                  </div>
                )}

                {report.generated_at && (
                  <span>
                    Generated: {new Date(report.generated_at).toLocaleString()}
                  </span>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              {report.status !== "ARCHIVED" && (
                <Button
                  onClick={handleGenerate}
                  disabled={generating}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs"
                >
                  {generating ? "Generating..." : snapshot ? "Regenerate Snapshot" : "Generate Report"}
                </Button>
              )}

              {snapshot && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => downloadJson(`/api/v1/security-reports/${report.id}/json`, `${report.name.toLowerCase().replace(/\\s+/g, "_")}_snapshot.json`)}
                    className="text-xs"
                  >
                    Download JSON
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => downloadJson(`/api/v1/security-reports/${report.id}/package`, `${report.name.toLowerCase().replace(/\\s+/g, "_")}_package.json`)}
                    className="text-xs"
                  >
                    Download Package
                  </Button>
                </>
              )}

              {report.status === "PUBLISHED" && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleArchive}
                  disabled={archiving}
                  className="text-xs text-amber-500 hover:text-amber-400 hover:bg-amber-500/10 border-amber-500/30"
                >
                  Archive
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

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

      {!snapshot ? (
        <Card className="border border-dashed border-border bg-card/40">
          <CardContent className="flex flex-col items-center justify-center py-16 text-center">
            <div className="w-12 h-12 rounded-full bg-accent/40 flex items-center justify-center mb-3 text-muted-foreground font-mono">
              ⚡
            </div>
            <h3 className="text-lg font-semibold">Report Not Yet Generated</h3>
            <p className="text-sm text-muted-foreground max-w-md mt-1 mb-5">
              Click &quot;Generate Report&quot; above to deterministically compile findings, baseline comparisons, gate results, sanitized evidence, and compute the cryptographic SHA-256 snapshot.
            </p>
            <Button
              onClick={handleGenerate}
              disabled={generating}
              className="bg-primary hover:bg-primary/90 text-primary-foreground text-xs"
            >
              {generating ? "Generating..." : "Generate Report Now"}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-6">
          {/* Section Navigation Tabs */}
          <div className="flex flex-wrap items-center gap-1 border-b border-border pb-2">
            {[
              { id: "executive", label: "Executive Summary" },
              { id: "findings", label: `Verified Findings (${verifiedFindings.length})` },
              { id: "attack_paths", label: `Attack Paths (${attackPaths.length})` },
              { id: "gate_baseline", label: "Gate & Baselines" },
              { id: "evidence", label: `Sanitized Evidence (${sanitizedEvidence.length})` },
              { id: "ai_analysis", label: `AI Analysis (${aiSection.length})` },
              { id: "human_review", label: `Human Reviews (${humanReviews.length})` },
              { id: "remediation", label: `Remediation (${remediationItems.length})` },
              { id: "manifest", label: "Manifest & Raw JSON" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors ${
                  activeTab === tab.id
                    ? "bg-primary text-primary-foreground shadow-xs"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent/40"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* TAB 1: EXECUTIVE SUMMARY */}
          {activeTab === "executive" && execSummary && (
            <div className="space-y-6">
              {/* Verdict Summary Card */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card className="border border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                      Security Gate Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xl font-bold uppercase ${
                          execSummary.gate_status === "PASS"
                            ? "text-emerald-400"
                            : execSummary.gate_status === "FAIL"
                            ? "text-destructive"
                            : execSummary.gate_status === "WARN"
                            ? "text-amber-400"
                            : "text-muted-foreground"
                        }`}
                      >
                        {execSummary.gate_status || "N/A"}
                      </span>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                      Confirmed Findings
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{execSummary.findings_count || 0}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      High: {execSummary.findings_by_severity?.HIGH || 0} | Med: {execSummary.findings_by_severity?.MEDIUM || 0} | Low: {execSummary.findings_by_severity?.LOW || 0}
                    </div>
                  </CardContent>
                </Card>

                <Card className="border border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                      Regressions & Violations
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold text-destructive">
                      {(execSummary.regressions_count || 0) + (execSummary.new_violations_count || 0)}
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {execSummary.regressions_count || 0} Regressions, {execSummary.new_violations_count || 0} New
                    </div>
                  </CardContent>
                </Card>

                <Card className="border border-border bg-card">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-xs font-medium text-muted-foreground uppercase">
                      Attack Paths
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{execSummary.attack_paths_count || 0}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Terminal Impacts: {securityImpacts.length}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Executive Overview Box */}
              <Card className="border border-border bg-card">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-semibold">Assessment Scope & Context</CardTitle>
                    <ProvenanceBadge provenance="DETERMINISTIC" />
                  </div>
                </CardHeader>
                <CardContent className="space-y-4 text-sm">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-accent/20 p-4 rounded-lg border border-border/50 text-xs">
                    <div>
                      <span className="text-muted-foreground block">Project:</span>
                      <span className="font-semibold text-foreground">{execSummary.project_name}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Scan Profile:</span>
                      <span className="font-semibold text-foreground">{execSummary.scan_profile || "Custom / Direct"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Baseline Version:</span>
                      <span className="font-semibold text-foreground">{execSummary.baseline_version ? `v${execSummary.baseline_version}` : "None"}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Report Schema:</span>
                      <span className="font-mono text-foreground font-semibold">v1.0 (Canonical JSON)</span>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    This security report was deterministically generated without executing any arbitrary target HTTP traffic. All security findings and evidence are sourced exclusively from verified security engines, established baselines, and authenticated test execution plans.
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* TAB 2: VERIFIED FINDINGS */}
          {activeTab === "findings" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Verified Security Findings</h3>
                  <p className="text-xs text-muted-foreground">
                    Confirmed vulnerabilities directly observed and verified by security test executions.
                  </p>
                </div>
                <ProvenanceBadge provenance="VERIFIED" />
              </div>

              {verifiedFindings.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No confirmed findings recorded for this report scope.
                </div>
              ) : (
                <div className="space-y-3">
                  {verifiedFindings.map((f) => (
                    <Card key={f.finding_id} className="border border-border bg-card">
                      <CardContent className="p-4 space-y-3">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-bold text-sm">{f.title}</span>
                              <span
                                className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                                  f.severity === "HIGH"
                                    ? "bg-destructive/15 text-destructive border border-destructive/30"
                                    : f.severity === "MEDIUM"
                                    ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                                    : "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                                }`}
                              >
                                {f.severity}
                              </span>
                              <span className="text-xs font-mono bg-accent/40 px-2 py-0.5 rounded text-muted-foreground">
                                {f.type}
                              </span>
                              <span className="text-xs text-muted-foreground font-mono">
                                Confidence: {f.confidence}
                              </span>
                            </div>

                            {f.description && (
                              <p className="text-xs text-muted-foreground mt-1.5">{f.description}</p>
                            )}
                          </div>

                          <ProvenanceBadge provenance={f.provenance || "VERIFIED"} />
                        </div>

                        {/* Behavior Comparison */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs bg-accent/20 p-2.5 rounded border border-border/50">
                          <div>
                            <span className="font-semibold text-muted-foreground block text-[11px] uppercase">
                              Expected Behavior:
                            </span>
                            <span className="font-mono text-foreground">{f.expected_authorization || "DENY"}</span>
                          </div>
                          <div>
                            <span className="font-semibold text-destructive block text-[11px] uppercase">
                              Actual Behavior:
                            </span>
                            <span className="font-mono text-destructive font-semibold">
                              {f.actual_behavior || "ALLOW"}
                            </span>
                          </div>
                        </div>

                        {/* Remediation note */}
                        {f.remediation && (
                          <div className="text-xs bg-secondary/30 p-2.5 rounded border border-border/40">
                            <span className="font-semibold text-foreground block text-[11px] uppercase">
                              Recommended Fix:
                            </span>
                            <span className="text-muted-foreground">{f.remediation}</span>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ATTACK PATHS & IMPACT */}
          {activeTab === "attack_paths" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Deterministic Attack Paths & Impact</h3>
                  <p className="text-xs text-muted-foreground">
                    Correlated attack graphs demonstrating vulnerability chainability and tenant boundary breaches.
                  </p>
                </div>
                <ProvenanceBadge provenance="DETERMINISTIC" />
              </div>

              {attackPaths.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No attack paths mapped for this report scope.
                </div>
              ) : (
                <div className="space-y-4">
                  {attackPaths.map((path) => (
                    <Card key={path.attack_path_id} className="border border-border bg-card">
                      <CardContent className="p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm">{path.name}</span>
                            <span className="text-xs font-mono bg-accent/40 px-2 py-0.5 rounded text-muted-foreground">
                              Confidence: {path.confidence}
                            </span>
                          </div>
                          <ProvenanceBadge provenance={path.provenance || "DETERMINISTIC"} />
                        </div>

                        {path.description && (
                          <p className="text-xs text-muted-foreground">{path.description}</p>
                        )}

                        {/* Steps */}
                        <div className="space-y-2 pt-2">
                          <span className="text-xs font-semibold text-muted-foreground uppercase">
                            Execution Steps ({path.steps?.length || 0}):
                          </span>
                          <div className="space-y-1.5">
                            {path.steps?.map((st) => (
                              <div
                                key={st.step_id}
                                className="flex items-center gap-3 text-xs bg-accent/20 p-2 rounded border border-border/40 font-mono"
                              >
                                <span className="font-bold text-primary">#{st.position}</span>
                                <span className="text-foreground">Finding: {st.finding_id?.substring(0, 8)}...</span>
                                <span className="text-muted-foreground">({st.relationship_type})</span>
                                {st.reason && <span className="text-xs text-muted-foreground italic">— {st.reason}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}

              {/* Security Impacts */}
              {securityImpacts.length > 0 && (
                <div className="space-y-3 pt-4 border-t">
                  <h4 className="text-sm font-semibold">Security Impact Analysis</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {securityImpacts.map((imp) => (
                      <div
                        key={imp.impact_id}
                        className="bg-card border border-border p-3 rounded-lg text-xs space-y-2 shadow-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-destructive uppercase">
                            {imp.terminal_impact}
                          </span>
                          <ProvenanceBadge provenance="DETERMINISTIC" />
                        </div>
                        <p className="text-muted-foreground">{imp.explanation}</p>
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {imp.initial_access && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-destructive/15 text-destructive">
                              Initial Access
                            </span>
                          )}
                          {imp.authorization_boundary_crossed && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-destructive/15 text-destructive">
                              Auth Boundary Crossed
                            </span>
                          )}
                          {imp.sensitive_data_reached && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-destructive/15 text-destructive">
                              Sensitive Data Exfiltrated
                            </span>
                          )}
                          {imp.cross_identity_impact && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-destructive/15 text-destructive">
                              Cross-Identity
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: GATE & BASELINES */}
          {activeTab === "gate_baseline" && (
            <div className="space-y-6">
              {/* Gate Evaluation Section */}
              {gateResult ? (
                <Card className="border border-border bg-card">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base font-semibold">
                        Security Gate Evaluation: {gateResult.gate_name}
                      </CardTitle>
                      <ProvenanceBadge provenance="DETERMINISTIC" />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center gap-4">
                      <span
                        className={`text-lg font-bold uppercase px-3 py-1 rounded-md border ${
                          gateResult.status === "PASS"
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                            : gateResult.status === "FAIL"
                            ? "bg-destructive/15 text-destructive border-destructive/30"
                            : "bg-amber-500/15 text-amber-400 border-amber-500/30"
                        }`}
                      >
                        Verdict: {gateResult.status}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        Evaluated at {new Date(gateResult.evaluated_at).toLocaleString()}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs bg-accent/20 p-3 rounded-lg border border-border/50">
                      <div>
                        <span className="text-muted-foreground block">Rule Failures:</span>
                        <span className="font-bold text-destructive">{gateResult.failure_count}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Rule Warnings:</span>
                        <span className="font-bold text-amber-400">{gateResult.warning_count}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Confirmed Findings:</span>
                        <span className="font-bold">{gateResult.confirmed_findings}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground block">Regressions:</span>
                        <span className="font-bold text-destructive">{gateResult.regressions}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <div className="text-xs text-muted-foreground p-4 bg-accent/20 rounded-lg border">
                  No security gate evaluation attached to this report.
                </div>
              )}

              {/* Baseline Comparison Section */}
              {baselineComp && (
                <Card className="border border-border bg-card">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base font-semibold">
                        Baseline Comparison: {baselineComp.baseline_name} (v{baselineComp.baseline_version})
                      </CardTitle>
                      <ProvenanceBadge provenance="DETERMINISTIC" />
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <span className="text-xs font-semibold text-muted-foreground uppercase">
                        Comparison Items ({baselineComp.items?.length || 0}):
                      </span>
                      <div className="space-y-2">
                        {baselineComp.items?.map((it) => (
                          <div
                            key={it.comparison_item_id}
                            className="bg-accent/20 border border-border/40 p-3 rounded-md text-xs space-y-1.5"
                          >
                            <div className="flex items-center justify-between">
                              <span
                                className={`font-bold uppercase px-2 py-0.5 rounded text-[11px] ${
                                  it.result === "REGRESSION" || it.result === "NEW_VIOLATION"
                                    ? "bg-destructive/15 text-destructive"
                                    : it.result === "IMPROVED"
                                    ? "bg-emerald-500/15 text-emerald-400"
                                    : "bg-muted text-muted-foreground"
                                }`}
                              >
                                {it.result}
                              </span>
                              <ProvenanceBadge provenance="DETERMINISTIC" />
                            </div>
                            <p className="text-foreground">{it.explanation}</p>
                            <div className="flex items-center gap-4 text-muted-foreground text-[11px] font-mono">
                              <span>Prev: {it.previous_behavior || "None"}</span>
                              <span>Curr: {it.current_behavior || "None"}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* TAB 5: SANITIZED EVIDENCE VIEWER */}
          {activeTab === "evidence" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Sanitized Evidence Records</h3>
                  <p className="text-xs text-muted-foreground">
                    Deterministic HTTP request and response metadata. Sensitive headers, bearer tokens, and session cookies are securely redacted.
                  </p>
                </div>
                <ProvenanceBadge provenance="VERIFIED" />
              </div>

              {sanitizedEvidence.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No evidence records attached to this report.
                </div>
              ) : (
                <div className="space-y-4">
                  {sanitizedEvidence.map((ev) => (
                    <Card key={ev.evidence_id} className="border border-border bg-card">
                      <CardContent className="p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-foreground">
                            Evidence #{ev.evidence_id.substring(0, 8)}... (Finding: {ev.finding_id.substring(0, 8)}...)
                          </span>
                          <ProvenanceBadge provenance="VERIFIED" />
                        </div>

                        {/* Request Metadata */}
                        {ev.request_metadata && (
                          <div className="space-y-1">
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase">
                              Sanitized Request:
                            </span>
                            <pre className="bg-secondary/40 border border-border/50 p-2.5 rounded-md text-xs font-mono overflow-x-auto text-foreground">
                              {JSON.stringify(ev.request_metadata, null, 2)}
                            </pre>
                          </div>
                        )}

                        {/* Response Metadata */}
                        {ev.response_metadata && (
                          <div className="space-y-1">
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase">
                              Sanitized Response:
                            </span>
                            <pre className="bg-secondary/40 border border-border/50 p-2.5 rounded-md text-xs font-mono overflow-x-auto text-foreground">
                              {JSON.stringify(ev.response_metadata, null, 2)}
                            </pre>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 6: AI ANALYSIS & HYPOTHESES */}
          {activeTab === "ai_analysis" && (
            <div className="space-y-6">
              {/* Mandatory Prominent AI Advisory Banner */}
              <div className="bg-purple-950/30 border-2 border-purple-500/50 p-4 rounded-xl text-purple-300 space-y-1 shadow-sm">
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-wide">
                    ⚠️ AI ANALYSIS — NOT VERIFIED SECURITY FACT
                  </span>
                  <ProvenanceBadge provenance="AI" />
                </div>
                <p className="text-xs text-purple-300/80 leading-relaxed">
                  All analyses, suggestions, and hypotheses generated by AI reasoners are strictly advisory. They have NOT been verified by deterministic execution engines and must be subjected to human review and explicit test execution before consideration as security facts.
                </p>
              </div>

              {aiSection.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No AI hypotheses or reasoner analyses recorded for this project.
                </div>
              ) : (
                <div className="space-y-4">
                  {aiSection.map((ai) => (
                    <Card key={ai.analysis_id} className="border border-purple-500/30 bg-card">
                      <CardContent className="p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm text-purple-400">
                              {ai.analysis_type}
                            </span>
                            <span className="text-xs font-mono bg-purple-500/10 text-purple-300 px-2 py-0.5 rounded border border-purple-500/20">
                              Model: {ai.provider} / {ai.model}
                            </span>
                          </div>
                          <ProvenanceBadge provenance="AI" />
                        </div>

                        <div className="bg-secondary/40 border border-border/50 p-3 rounded-md text-xs font-mono text-foreground overflow-x-auto">
                          {typeof ai.output === "object" ? JSON.stringify(ai.output, null, 2) : String(ai.output)}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 7: HUMAN REVIEW */}
          {activeTab === "human_review" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Human Review & Governance Records</h3>
                  <p className="text-xs text-muted-foreground">
                    Explicit sign-offs, hypothesis approvals, and reviewer rationales submitted by security operators.
                  </p>
                </div>
                <ProvenanceBadge provenance="HUMAN" />
              </div>

              {humanReviews.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No human reviews recorded for this report.
                </div>
              ) : (
                <div className="space-y-3">
                  {humanReviews.map((rev) => (
                    <Card key={rev.review_id} className="border border-border bg-card">
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                                rev.action === "APPROVE"
                                  ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                                  : "bg-destructive/15 text-destructive border border-destructive/30"
                              }`}
                            >
                              Action: {rev.action}
                            </span>
                            <span className="text-xs font-medium text-muted-foreground">
                              Reviewer: {rev.reviewer_reference}
                            </span>
                          </div>
                          <ProvenanceBadge provenance="HUMAN" />
                        </div>

                        <p className="text-xs text-foreground bg-accent/20 p-2.5 rounded border border-border/40">
                          {rev.reason || "No reviewer comments provided."}
                        </p>

                        <div className="text-[11px] text-muted-foreground font-mono">
                          Recorded: {new Date(rev.created_at).toLocaleString()}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 8: REMEDIATION */}
          {activeTab === "remediation" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-semibold">Remediation Action Plan</h3>
                  <p className="text-xs text-muted-foreground">
                    Deterministic, prioritized fix recommendations for all confirmed vulnerabilities.
                  </p>
                </div>
                <ProvenanceBadge provenance="DETERMINISTIC" />
              </div>

              {remediationItems.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground border border-dashed rounded-lg">
                  No remediation actions required.
                </div>
              ) : (
                <div className="space-y-3">
                  {remediationItems.map((rem, idx) => (
                    <Card key={rem.finding_id || idx} className="border border-border bg-card">
                      <CardContent className="p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-sm">{rem.title}</span>
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                                rem.severity === "HIGH"
                                  ? "bg-destructive/15 text-destructive"
                                  : rem.severity === "MEDIUM"
                                  ? "bg-amber-500/15 text-amber-400"
                                  : "bg-blue-500/15 text-blue-400"
                              }`}
                            >
                              {rem.severity}
                            </span>
                          </div>
                          <ProvenanceBadge provenance="DETERMINISTIC" />
                        </div>

                        <div className="text-xs text-foreground bg-accent/20 p-3 rounded border border-border/40 leading-relaxed">
                          {rem.remediation}
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 9: MANIFEST & RAW JSON */}
          {activeTab === "manifest" && (
            <div className="space-y-6">
              {/* Manifest Metadata */}
              <Card className="border border-border bg-card">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-semibold">Evidence Package Manifest</CardTitle>
                    <ProvenanceBadge provenance="ENGINE" />
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs bg-accent/20 p-3 rounded-lg border border-border/50">
                    <div>
                      <span className="text-muted-foreground block">Checksum Algorithm:</span>
                      <span className="font-mono font-bold text-foreground">SHA-256</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Schema Version:</span>
                      <span className="font-mono font-bold text-foreground">{snapshot.schema_version}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground block">Snapshot Version:</span>
                      <span className="font-mono font-bold text-foreground">v{snapshot.version}</span>
                    </div>
                  </div>

                  <div>
                    <span className="text-xs font-semibold text-muted-foreground uppercase block mb-1">
                      Full SHA-256 Checksum:
                    </span>
                    <div className="flex items-center gap-2">
                      <pre className="bg-secondary/40 border border-border/50 p-2.5 rounded-md text-xs font-mono text-emerald-400 flex-1 overflow-x-auto">
                        {snapshot.checksum}
                      </pre>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          navigator.clipboard.writeText(snapshot.checksum);
                          setCopiedChecksum(true);
                          setTimeout(() => setCopiedChecksum(false), 2000);
                        }}
                        className="text-xs shrink-0"
                      >
                        {copiedChecksum ? "Copied!" : "Copy"}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Canonical Snapshot JSON Viewer */}
              <Card className="border border-border bg-card">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base font-semibold">Canonical Report JSON Snapshot</CardTitle>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(snapshot.report_json, null, 2));
                        setCopiedEvidence(true);
                        setTimeout(() => setCopiedEvidence(false), 2000);
                      }}
                      className="text-xs"
                    >
                      {copiedEvidence ? "Copied!" : "Copy Full JSON"}
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  <pre className="bg-secondary/30 border border-border/50 p-4 rounded-lg text-xs font-mono overflow-x-auto text-foreground max-h-[500px] overflow-y-auto">
                    {JSON.stringify(snapshot.report_json, null, 2)}
                  </pre>
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
