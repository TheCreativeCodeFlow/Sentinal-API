"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface EndpointItem {
  id: number;
  method: string;
  path: string;
  summary: string | null;
}

interface AuthPolicy {
  id: string;
  project_id: number;
  endpoint_id: number;
  endpoint_method?: string | null;
  endpoint_path?: string | null;
  authentication_required: boolean;
  authentication_scheme: string;
  expected_denial_status: number;
  notes?: string | null;
}

interface SecurityTestItem {
  id: string;
  endpoint_id: number;
  test_type: string;
  latest_result: string | null;
  status: string;
}

interface FindingItem {
  id: string;
  type: string;
  severity: string;
  status: string;
  title: string;
  description: string;
  endpoint_method: string | null;
  endpoint_path: string | null;
  authentication_mechanism?: string | null;
  expected_authorization?: string | null;
  actual_behavior?: string | null;
  created_at: string;
}

const AUTH_TEST_TYPES = [
  "AUTH_MISSING",
  "AUTH_INVALID",
  "AUTH_MALFORMED",
  "AUTH_EXPIRED",
  "AUTH_SCHEME",
];

const SCHEME_LABELS: Record<string, string> = {
  bearer_token: "Bearer Token (JWT/Opaque)",
  api_key: "API Key (Header)",
  basic_auth: "Basic Auth",
  cookie_session: "Session Cookie",
  none: "None (Public)",
};

export default function AuthenticationSecurityPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [policies, setPolicies] = useState<Record<number, AuthPolicy>>({});
  const [tests, setTests] = useState<SecurityTestItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);

  // Modal / Drawer state for editing endpoint policy
  const [editingEndpoint, setEditingEndpoint] = useState<EndpointItem | null>(null);
  const [editAuthRequired, setEditAuthRequired] = useState(true);
  const [editScheme, setEditScheme] = useState("bearer_token");
  const [editDenialStatus, setEditDenialStatus] = useState(401);
  const [editNotes, setEditNotes] = useState("");
  const [savingPolicy, setSavingPolicy] = useState(false);

  // Action states
  const [generating, setGenerating] = useState(false);
  const [runningAll, setRunningAll] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [replayingFindingId, setReplayingFindingId] = useState<string | null>(null);

  const activeProject = projects.find((p) => p.id === selectedProjectId);
  const isAuthorized = activeProject?.authorization_status.toLowerCase() === "authorized";

  // 1. Load projects
  useEffect(() => {
    let ignore = false;
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
        const data: Project[] = await res.json();
        if (!ignore) {
          setProjects(data);
          if (data.length > 0) {
            setSelectedProjectId((prev) => (prev === null ? data[0].id : prev));
          } else {
            setLoading(false);
          }
        }
      } catch (err) {
        console.error(err);
        if (!ignore) setLoading(false);
      }
    }
    loadProjects();
    return () => {
      ignore = true;
    };
  }, []);

  // 2. Load endpoints, policies, tests, findings for project
  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;

    async function loadProjectData() {
      try {
        // Fetch endpoints
        const epRes = await fetch(`/api/v1/projects/${selectedProjectId}/endpoints`, { credentials: "include" });
        const epData: EndpointItem[] = epRes.ok ? await epRes.json() : [];

        // Fetch tests
        const testRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-tests/`, { credentials: "include" });
        const testData: SecurityTestItem[] = testRes.ok ? await testRes.json() : [];

        // Fetch auth findings
        const findRes = await fetch(`/api/v1/projects/${selectedProjectId}/findings?category=AUTHENTICATION`, { credentials: "include" });
        const findData: FindingItem[] = findRes.ok ? await findRes.json() : [];

        // Fetch policies for endpoints in parallel
        const policyMap: Record<number, AuthPolicy> = {};
        await Promise.all(
          epData.map(async (ep) => {
            try {
              const pRes = await fetch(`/api/v1/endpoints/${ep.id}/auth-policy`, { credentials: "include" });
              if (pRes.ok) {
                const pol = await pRes.json();
                policyMap[ep.id] = pol;
              }
            } catch {
              // ignore individual errors
            }
          })
        );

        if (!ignore) {
          setEndpoints(epData);
          setTests(testData.filter((t) => AUTH_TEST_TYPES.includes(t.test_type)));
          setFindings(findData);
          setPolicies(policyMap);
          setLoading(false);
        }
      } catch (err) {
        console.error(err);
        if (!ignore) setLoading(false);
      }
    }

    loadProjectData();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  // Handle Generate Auth Tests
  const handleGenerateTests = async () => {
    if (!selectedProjectId) return;
    setGenerating(true);
    setActionMessage(null);
    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/generate-auth-tests`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to generate tests");
      }
      const data = await res.json();
      setActionMessage(data.message || `Generated ${data.generated_count} authentication tests.`);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error generating tests: " + (err instanceof Error ? err.message : "Unknown error"));
    } finally {
      setGenerating(false);
    }
  };

  // Handle Run All Auth Tests
  const handleRunAllTests = async () => {
    if (!selectedProjectId || tests.length === 0) return;
    setRunningAll(true);
    setActionMessage(null);
    let completedCount = 0;
    try {
      for (const t of tests) {
        try {
          await fetch(`/api/v1/security-tests/${t.id}/execute`, {
            method: "POST",
            credentials: "include",
          });
          completedCount++;
        } catch (e) {
          console.error(e);
        }
      }
      setActionMessage(`Executed ${completedCount} authentication security tests successfully.`);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Execution error: " + (err instanceof Error ? err.message : "Unknown error"));
    } finally {
      setRunningAll(false);
    }
  };

  // Handle Edit Policy
  const openEditPolicy = (ep: EndpointItem) => {
    const existing = policies[ep.id];
    setEditingEndpoint(ep);
    setEditAuthRequired(existing ? existing.authentication_required : true);
    setEditScheme(existing ? existing.authentication_scheme : "bearer_token");
    setEditDenialStatus(existing ? existing.expected_denial_status : 401);
    setEditNotes(existing?.notes || "");
  };

  const handleSavePolicy = async () => {
    if (!editingEndpoint) return;
    setSavingPolicy(true);
    try {
      const res = await fetch(`/api/v1/endpoints/${editingEndpoint.id}/auth-policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          authentication_required: editAuthRequired,
          authentication_scheme: editScheme,
          expected_denial_status: editDenialStatus,
          notes: editNotes.trim() || null,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to save policy");
      }
      setEditingEndpoint(null);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error saving policy: " + (err instanceof Error ? err.message : "Unknown error"));
    } finally {
      setSavingPolicy(false);
    }
  };

  // Handle Replay Finding
  const handleReplayFinding = async (findingId: string) => {
    setReplayingFindingId(findingId);
    try {
      const res = await fetch(`/api/v1/findings/${findingId}/replay`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Replay failed");
      }
      const data = await res.json();
      alert(`Replay completed. Result: ${data.result} (HTTP ${data.http_status})`);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Replay failed: " + (err instanceof Error ? err.message : "Error"));
    } finally {
      setReplayingFindingId(null);
    }
  };

  // Compute Metrics
  const totalEndpoints = endpoints.length;
  const protectedEndpoints = endpoints.filter((e) => policies[e.id]?.authentication_required !== false).length;
  
  // Endpoints with at least one executed test
  const testedEndpointIds = new Set(
    tests.filter((t) => t.latest_result).map((t) => t.endpoint_id)
  );
  const testedCount = testedEndpointIds.size;
  const coveragePercent = totalEndpoints > 0 ? Math.round((testedCount / totalEndpoints) * 100) : 0;

  // Scheme counts
  const schemeCounts: Record<string, number> = {
    bearer_token: 0,
    api_key: 0,
    basic_auth: 0,
    cookie_session: 0,
    none: 0,
  };
  Object.values(policies).forEach((p) => {
    if (!p.authentication_required) {
      schemeCounts["none"] = (schemeCounts["none"] || 0) + 1;
    } else {
      schemeCounts[p.authentication_scheme] = (schemeCounts[p.authentication_scheme] || 0) + 1;
    }
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Authentication Security Engine</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Systematic validation of endpoint authentication enforcement, credential rejection, and scheme consistency.
          </p>
        </div>
        <div className="flex items-center gap-3">
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
          <Button
            variant="outline"
            onClick={handleGenerateTests}
            disabled={!selectedProjectId || !isAuthorized || generating}
          >
            {generating ? "Generating..." : "⚡ Generate Auth Tests"}
          </Button>
          <Button
            onClick={handleRunAllTests}
            disabled={!selectedProjectId || !isAuthorized || runningAll || tests.length === 0}
          >
            {runningAll ? "Executing Suite..." : `▶ Run Auth Tests (${tests.length})`}
          </Button>
        </div>
      </div>

      {/* Target Status Warning if not authorized */}
      {selectedProjectId && !isAuthorized && (
        <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
              Target Authorization Required
            </div>
            <p className="text-xs opacity-90 mt-0.5">
              Authentication security tests can only execute against targets with explicit project authorization.
            </p>
          </div>
          <Link href="/projects">
            <Button variant="secondary" size="sm">Authorize in Projects</Button>
          </Link>
        </div>
      )}

      {/* Action Notification */}
      {actionMessage && (
        <div className="p-3 rounded-lg border border-primary/20 bg-primary/5 text-primary text-sm flex items-center justify-between">
          <span>{actionMessage}</span>
          <button className="text-xs underline" onClick={() => setActionMessage(null)}>Dismiss</button>
        </div>
      )}

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-xs font-medium text-muted-foreground">Total Endpoints</div>
            <div className="text-2xl font-bold mt-1">{totalEndpoints}</div>
            <div className="text-xs text-muted-foreground mt-1">
              {protectedEndpoints} require authentication
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="text-xs font-medium text-muted-foreground">Test Coverage</div>
            <div className="text-2xl font-bold mt-1">{coveragePercent}%</div>
            <div className="text-xs text-muted-foreground mt-1">
              {testedCount} of {totalEndpoints} endpoints evaluated
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="text-xs font-medium text-muted-foreground">Active Auth Tests</div>
            <div className="text-2xl font-bold mt-1">{tests.length}</div>
            <div className="text-xs text-muted-foreground mt-1">
              5 deterministic probe types
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="text-xs font-medium text-muted-foreground">Confirmed Vulnerabilities</div>
            <div className={`text-2xl font-bold mt-1 ${findings.length > 0 ? "text-red-500" : "text-emerald-500"}`}>
              {findings.length}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {findings.filter((f) => f.severity === "HIGH").length} High Severity
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Scheme Distribution */}
      <Card>
        <CardContent className="p-5">
          <div className="text-sm font-semibold mb-3">Authentication Mechanism Breakdown</div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="p-3 rounded-lg border border-border bg-card/50">
              <div className="text-xs text-muted-foreground">Bearer Token</div>
              <div className="text-xl font-bold mt-1 text-primary">{schemeCounts["bearer_token"] || 0}</div>
              <div className="text-[11px] text-muted-foreground">JWT / Opaque</div>
            </div>
            <div className="p-3 rounded-lg border border-border bg-card/50">
              <div className="text-xs text-muted-foreground">API Key</div>
              <div className="text-xl font-bold mt-1 text-blue-500">{schemeCounts["api_key"] || 0}</div>
              <div className="text-[11px] text-muted-foreground">X-API-Key header</div>
            </div>
            <div className="p-3 rounded-lg border border-border bg-card/50">
              <div className="text-xs text-muted-foreground">Basic Auth</div>
              <div className="text-xl font-bold mt-1 text-amber-500">{schemeCounts["basic_auth"] || 0}</div>
              <div className="text-[11px] text-muted-foreground">RFC 7617</div>
            </div>
            <div className="p-3 rounded-lg border border-border bg-card/50">
              <div className="text-xs text-muted-foreground">Session Cookie</div>
              <div className="text-xl font-bold mt-1 text-purple-500">{schemeCounts["cookie_session"] || 0}</div>
              <div className="text-[11px] text-muted-foreground">Stateful Session</div>
            </div>
            <div className="p-3 rounded-lg border border-border bg-card/50">
              <div className="text-xs text-muted-foreground">Public / None</div>
              <div className="text-xl font-bold mt-1 text-muted-foreground">{schemeCounts["none"] || 0}</div>
              <div className="text-[11px] text-muted-foreground">Unprotected</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Endpoints & Policies Table */}
      <Card>
        <CardContent className="p-5 space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <div className="text-base font-semibold">Endpoint Authentication Policy & Status</div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Configure baseline authentication requirements and review testing status.
              </div>
            </div>
            <Link href="/security-tests">
              <Button variant="outline" size="sm">Manage Tests →</Button>
            </Link>
          </div>

          {loading ? (
            <div className="text-center py-10 text-sm text-muted-foreground">Loading endpoints and policies...</div>
          ) : endpoints.length === 0 ? (
            <div className="text-center py-10 text-sm text-muted-foreground">
              No endpoints found for this project. Ingest an OpenAPI spec or add endpoints first.
            </div>
          ) : (
            <div className="border border-border rounded-lg overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="bg-muted/50 border-b border-border text-xs text-muted-foreground">
                  <tr>
                    <th className="py-2.5 px-3">Method</th>
                    <th className="py-2.5 px-3">Endpoint Path</th>
                    <th className="py-2.5 px-3">Auth Required</th>
                    <th className="py-2.5 px-3">Scheme</th>
                    <th className="py-2.5 px-3">Expected Denial</th>
                    <th className="py-2.5 px-3">Test Results</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {endpoints.map((ep) => {
                    const pol = policies[ep.id];
                    const isReq = pol ? pol.authentication_required : true;
                    const scheme = pol ? pol.authentication_scheme : "bearer_token";
                    const expectedDenial = pol ? pol.expected_denial_status : 401;

                    // Tests for this endpoint
                    const epTests = tests.filter((t) => t.endpoint_id === ep.id);
                    const hasConfirmed = epTests.some((t) => t.latest_result === "CONFIRMED");
                    const hasPass = epTests.some((t) => t.latest_result === "PASS");

                    return (
                      <tr key={ep.id} className="hover:bg-accent/30 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-bold text-xs">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[11px] ${
                              ep.method === "GET"
                                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                                : ep.method === "HEAD"
                                ? "bg-blue-500/10 text-blue-600 dark:text-blue-400"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {ep.method}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-xs">{ep.path}</td>
                        <td className="py-2.5 px-3">
                          {isReq ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400 font-medium">
                              ● Required
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">Public</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-xs font-mono bg-muted/60 px-2 py-0.5 rounded">
                            {SCHEME_LABELS[scheme] || scheme}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-xs font-mono text-muted-foreground">
                          HTTP {expectedDenial}
                        </td>
                        <td className="py-2.5 px-3">
                          {epTests.length === 0 ? (
                            <span className="text-xs text-muted-foreground">No tests</span>
                          ) : hasConfirmed ? (
                            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/10 text-red-600 dark:text-red-400">
                              VULNERABLE
                            </span>
                          ) : hasPass ? (
                            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                              PASS
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">{epTests.length} configured</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => openEditPolicy(ep)}
                          >
                            Edit Policy
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirmed Authentication Vulnerabilities */}
      <Card>
        <CardContent className="p-5 space-y-4">
          <div className="flex justify-between items-center">
            <div>
              <div className="text-base font-semibold">Authentication Findings</div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Vulnerabilities confirmed by the Authentication Security Engine.
              </div>
            </div>
            <Link href="/findings?category=AUTHENTICATION">
              <Button variant="outline" size="sm">Full Findings View →</Button>
            </Link>
          </div>

          {findings.length === 0 ? (
            <div className="text-center py-8 border border-dashed border-border rounded-lg text-sm text-muted-foreground">
              No open authentication findings for this project.
            </div>
          ) : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div
                  key={f.id}
                  className="p-4 rounded-xl border border-red-500/20 bg-red-500/5 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4"
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-red-500 text-white">
                        {f.severity}
                      </span>
                      <span className="font-semibold text-sm">{f.title}</span>
                      {f.authentication_mechanism && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-muted text-muted-foreground">
                          {f.authentication_mechanism}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <span className="font-mono font-bold mr-1">{f.endpoint_method}</span>
                      <span className="font-mono">{f.endpoint_path}</span>
                    </div>
                    <p className="text-xs text-muted-foreground/90 max-w-2xl">{f.description}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleReplayFinding(f.id)}
                      disabled={replayingFindingId === f.id}
                    >
                      {replayingFindingId === f.id ? "Replaying..." : "Replay Finding"}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Policy Modal */}
      {editingEndpoint && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl shadow-lg w-full max-w-md p-6 space-y-4">
            <div>
              <h3 className="text-lg font-bold">Configure Authentication Policy</h3>
              <p className="text-xs text-muted-foreground mt-0.5 font-mono">
                {editingEndpoint.method} {editingEndpoint.path}
              </p>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="authRequired"
                  className="rounded border-input text-primary focus:ring-primary"
                  checked={editAuthRequired}
                  onChange={(e) => setEditAuthRequired(e.target.checked)}
                />
                <label htmlFor="authRequired" className="font-medium cursor-pointer">
                  Authentication Required
                </label>
              </div>

              <div>
                <label className="text-xs font-medium text-muted-foreground">Authentication Scheme</label>
                <select
                  className="w-full mt-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={editScheme}
                  onChange={(e) => setEditScheme(e.target.value)}
                  disabled={!editAuthRequired}
                >
                  <option value="bearer_token">Bearer Token (JWT / Opaque)</option>
                  <option value="api_key">API Key (X-API-Key)</option>
                  <option value="basic_auth">Basic Authentication</option>
                  <option value="cookie_session">Session Cookie</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-muted-foreground">Expected Denial Status Code</label>
                <select
                  className="w-full mt-1 h-9 rounded-md border border-input bg-background px-3 text-sm"
                  value={editDenialStatus}
                  onChange={(e) => setEditDenialStatus(Number(e.target.value))}
                  disabled={!editAuthRequired}
                >
                  <option value={401}>401 Unauthorized (Standard)</option>
                  <option value={403}>403 Forbidden</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-medium text-muted-foreground">Notes / Documentation</label>
                <textarea
                  className="w-full mt-1 rounded-md border border-input bg-background p-2 text-xs"
                  rows={2}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Optional notes regarding this endpoint's authentication requirements"
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button variant="outline" size="sm" onClick={() => setEditingEndpoint(null)}>
                Cancel
              </Button>
              <Button size="sm" onClick={handleSavePolicy} disabled={savingPolicy}>
                {savingPolicy ? "Saving..." : "Save Policy"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
