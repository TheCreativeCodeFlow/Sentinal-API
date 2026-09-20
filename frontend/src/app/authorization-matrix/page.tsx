"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
}

interface RoleItem {
  id: string;
  name: string;
  description: string | null;
}

interface MatrixCellData {
  endpoint_id: number;
  role_id: string | null;
  role_name: string;
  http_method: string;
  expected_access: string; // ALLOW, DENY, UNKNOWN
  test_status: string; // NOT TESTED, PASS, CONFIRMED, INCONCLUSIVE
  security_test_id: string | null;
  latest_execution_id: string | null;
  latest_result: string | null;
  finding_id: string | null;
}

interface EndpointRowData {
  endpoint_id: number;
  method: string;
  path: string;
  summary: string | null;
  authentication_required: boolean;
  policy_notes: string | null;
  cells: Record<string, MatrixCellData>;
}

interface MatrixViewData {
  project_id: number;
  project_name: string;
  roles: RoleItem[];
  endpoints: EndpointRowData[];
  total_cells: number;
  confirmed_count: number;
  pass_count: number;
  untested_count: number;
}

interface EndpointPolicyData {
  id: string;
  project_id: number;
  endpoint_id: number;
  authentication_required: boolean;
  notes: string | null;
  allowed_roles: { name: string; description: string | null }[];
  denied_roles: { name: string; description: string | null }[];
}

export default function AuthorizationMatrixPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [matrixData, setMatrixData] = useState<MatrixViewData | null>(null);
  const [loading, setLoading] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  // Cell inspector / action drawer
  const [activeCell, setActiveCell] = useState<{
    endpoint: EndpointRowData;
    role: RoleItem;
    cell: MatrixCellData;
  } | null>(null);

  // Policy editor drawer
  const [policyEndpoint, setPolicyEndpoint] = useState<EndpointRowData | null>(null);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyAuthRequired, setPolicyAuthRequired] = useState(true);
  const [policyNotes, setPolicyNotes] = useState("");
  const [policyAllowedRoles, setPolicyAllowedRoles] = useState<string[]>([]);
  const [policyDeniedRoles, setPolicyDeniedRoles] = useState<string[]>([]);

  // Generation status
  const [generating, setGenerating] = useState(false);
  const [genMessage, setGenMessage] = useState<string | null>(null);
  const [cellActionMessage, setCellActionMessage] = useState<string | null>(null);

  // Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (res.ok) {
          const data: Project[] = await res.json();
          setProjects(data);
          if (data.length > 0 && selectedProjectId === null) {
            setSelectedProjectId(data[0].id);
          }
        }
      } catch (err) {
        console.error("Failed to load projects", err);
      }
    }
    loadProjects();
  }, [selectedProjectId]);

  // Load Matrix Data
  useEffect(() => {
    if (!selectedProjectId) return;
    async function fetchMatrix() {
      setLoading(true);
      try {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/authorization-matrix`, { credentials: "include" });
        if (res.ok) {
          const data: MatrixViewData = await res.json();
          setMatrixData(data);
        } else {
          setMatrixData(null);
        }
      } catch (err) {
        console.error("Failed to load authorization matrix", err);
        setMatrixData(null);
      } finally {
        setLoading(false);
      }
    }
    fetchMatrix();
  }, [selectedProjectId, reloadKey]);

  // Load Policy when policyEndpoint is set
  useEffect(() => {
    if (!policyEndpoint) return;
    const epId = policyEndpoint.endpoint_id;
    async function fetchPolicy(id: number) {
      setPolicyLoading(true);
      try {
        const res = await fetch(`/api/v1/endpoints/${id}/policy`, { credentials: "include" });
        if (res.ok) {
          const p: EndpointPolicyData = await res.json();
          setPolicyAuthRequired(p.authentication_required);
          setPolicyNotes(p.notes || "");
          // Map role names to IDs
          if (matrixData) {
            const allowedIds = matrixData.roles
              .filter((r) => p.allowed_roles.some((ar) => ar.name === r.name))
              .map((r) => r.id);
            const deniedIds = matrixData.roles
              .filter((r) => p.denied_roles.some((dr) => dr.name === r.name))
              .map((r) => r.id);
            setPolicyAllowedRoles(allowedIds);
            setPolicyDeniedRoles(deniedIds);
          }
        }
      } catch (err) {
        console.error("Failed to load endpoint policy", err);
      } finally {
        setPolicyLoading(false);
      }
    }
    fetchPolicy(epId);
  }, [policyEndpoint, matrixData]);

  // Update expected access for a specific cell
  async function handleSetExpectedAccess(expected: "ALLOW" | "DENY" | "UNKNOWN") {
    if (!activeCell || !selectedProjectId) return;
    setCellActionMessage(null);
    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/authorization-matrix/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          endpoint_id: activeCell.endpoint.endpoint_id,
          role_id: activeCell.role.id,
          http_method: activeCell.endpoint.method,
          expected_access: expected,
        }),
      });
      if (res.ok) {
        setCellActionMessage(`Updated expected access to ${expected}`);
        setReloadKey((prev) => prev + 1);
        setActiveCell((prev) => {
          if (!prev) return null;
          return {
            ...prev,
            cell: { ...prev.cell, expected_access: expected },
          };
        });
      }
    } catch (err) {
      console.error("Failed to update rule", err);
    }
  }

  // Save Policy
  async function handleSavePolicy() {
    if (!policyEndpoint) return;
    try {
      const res = await fetch(`/api/v1/endpoints/${policyEndpoint.endpoint_id}/policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          authentication_required: policyAuthRequired,
          notes: policyNotes,
          allowed_role_ids: policyAllowedRoles,
          denied_role_ids: policyDeniedRoles,
        }),
      });
      if (res.ok) {
        setPolicyEndpoint(null);
        setReloadKey((prev) => prev + 1);
      }
    } catch (err) {
      console.error("Failed to save policy", err);
    }
  }

  // Generate BFLA Tests
  async function handleGenerateTests() {
    if (!selectedProjectId) return;
    setGenerating(true);
    setGenMessage(null);
    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/generate-bfla-tests`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ target_all_safe_endpoints: true }),
      });
      if (res.ok) {
        const data = await res.json();
        setGenMessage(`Generated ${data.generated_count} safe tests (${data.skipped_count} existing tests skipped).`);
        setReloadKey((prev) => prev + 1);
      } else {
        const err = await res.json();
        setGenMessage(`Generation error: ${err.detail || "Request failed"}`);
      }
    } catch (err) {
      console.error("Failed to generate tests", err);
      setGenMessage("Failed to generate BFLA tests.");
    } finally {
      setGenerating(false);
    }
  }

  const selectedProject = projects.find((p) => p.id === selectedProjectId);

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Authorization Matrix</h1>
          <p className="text-sm text-muted-foreground">
            Systematic Identity/Role × Endpoint × Method authorization boundaries with automated test generation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Project Selector */}
          <select
            className="rounded-md border border-input bg-background px-3 py-1.5 text-sm font-medium shadow-xs"
            value={selectedProjectId || ""}
            onChange={(e) => setSelectedProjectId(Number(e.target.value))}
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.authorization_status})
              </option>
            ))}
          </select>

          {/* Generate Tests Button */}
          <Button
            variant="secondary"
            size="sm"
            onClick={handleGenerateTests}
            disabled={generating || !selectedProject || selectedProject.authorization_status.toLowerCase() !== "authorized"}
          >
            {generating ? "Generating..." : "⚡ Generate BFLA Tests"}
          </Button>
        </div>
      </div>

      {/* Generation Notification */}
      {genMessage && (
        <div className="p-3 bg-primary/10 border border-primary/20 rounded-md text-sm text-primary flex items-center justify-between">
          <span>{genMessage}</span>
          <button onClick={() => setGenMessage(null)} className="text-xs opacity-70 hover:opacity-100">
            Dismiss
          </button>
        </div>
      )}

      {/* Target Authorization Warning */}
      {selectedProject && selectedProject.authorization_status.toLowerCase() !== "authorized" && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-700 dark:text-amber-300">
          <strong>Notice:</strong> This project is currently marked as <code>{selectedProject.authorization_status}</code>.
          Authorization testing and test generation require explicit authorization.
        </div>
      )}

      {/* Summary KPI Cards */}
      {matrixData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="text-xs font-semibold text-muted-foreground uppercase">Matrix Cells</div>
              <div className="text-2xl font-bold mt-1">{matrixData.total_cells}</div>
              <div className="text-xs text-muted-foreground mt-0.5">Role × Endpoint combinations</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="text-xs font-semibold text-muted-foreground uppercase">Confirmed BFLA</div>
              <div className="text-2xl font-bold mt-1 text-rose-600 dark:text-rose-400">
                {matrixData.confirmed_count}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">Authorization violations</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="text-xs font-semibold text-muted-foreground uppercase">Passing Boundaries</div>
              <div className="text-2xl font-bold mt-1 text-emerald-600 dark:text-emerald-400">
                {matrixData.pass_count}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">Access properly denied</div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="text-xs font-semibold text-muted-foreground uppercase">Untested Cells</div>
              <div className="text-2xl font-bold mt-1 text-muted-foreground">{matrixData.untested_count}</div>
              <div className="text-xs text-muted-foreground mt-0.5">Ready for boundary tests</div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* 2D Authorization Matrix Table */}
      <Card>
        <CardContent className="p-0 overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-muted-foreground text-sm">Loading authorization matrix...</div>
          ) : !matrixData || matrixData.endpoints.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground text-sm">
              No API endpoints or roles found for this project. Ingest an OpenAPI specification and define roles to view the matrix.
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-muted/40 text-xs font-medium text-muted-foreground">
                  <th className="py-3 px-4 min-w-[280px]">Endpoint / Route</th>
                  <th className="py-3 px-3 w-28 text-center">Policy</th>
                  {matrixData.roles.map((role) => (
                    <th key={role.id} className="py-3 px-4 min-w-[140px] text-center">
                      <div className="font-semibold text-foreground">{role.name}</div>
                      <div className="text-[10px] text-muted-foreground font-mono truncate max-w-[120px]">
                        {role.description || "Role"}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-sm font-mono">
                {matrixData.endpoints.map((ep) => (
                  <tr key={ep.endpoint_id} className="hover:bg-muted/20 transition-colors">
                    {/* Endpoint Cell */}
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-xs px-2 py-0.5 rounded-sm font-semibold uppercase ${
                            ep.method.toUpperCase() === "GET"
                              ? "bg-sky-500/20 text-sky-700 dark:text-sky-300"
                              : "bg-slate-500/20 text-slate-700 dark:text-slate-300"
                          }`}
                        >
                          {ep.method}
                        </span>
                        <span className="font-medium text-foreground text-xs">{ep.path}</span>
                      </div>
                      {ep.summary && (
                        <div className="text-[11px] text-muted-foreground font-sans mt-0.5 truncate max-w-[320px]">
                          {ep.summary}
                        </div>
                      )}
                    </td>

                    {/* Policy Button Cell */}
                    <td className="py-3 px-3 text-center">
                      <Button
                        variant="secondary"
                        size="sm"
                        className="text-xs h-7 px-2"
                        onClick={() => setPolicyEndpoint(ep)}
                      >
                        ⚙️ Policy
                      </Button>
                    </td>

                    {/* Matrix Cells per Role */}
                    {matrixData.roles.map((role) => {
                      const cell = ep.cells[role.id] || {
                        endpoint_id: ep.endpoint_id,
                        role_id: role.id,
                        role_name: role.name,
                        http_method: ep.method,
                        expected_access: "UNKNOWN",
                        test_status: "NOT TESTED",
                        security_test_id: null,
                        latest_execution_id: null,
                        latest_result: null,
                        finding_id: null,
                      };

                      return (
                        <td
                          key={role.id}
                          className="py-2.5 px-3 text-center cursor-pointer hover:bg-accent/50 transition-colors"
                          onClick={() => setActiveCell({ endpoint: ep, role, cell })}
                        >
                          <div className="flex flex-col items-center gap-1">
                            {/* Expected Access Badge */}
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                                cell.expected_access === "ALLOW"
                                  ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                                  : cell.expected_access === "DENY"
                                  ? "bg-rose-500/20 text-rose-700 dark:text-rose-300"
                                  : "bg-slate-500/20 text-slate-600 dark:text-slate-400"
                              }`}
                            >
                              {cell.expected_access}
                            </span>

                            {/* Execution / Test Status Badge */}
                            <span
                              className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${
                                cell.test_status === "CONFIRMED"
                                  ? "bg-rose-600 text-white animate-pulse"
                                  : cell.test_status === "PASS"
                                  ? "bg-emerald-600/30 text-emerald-800 dark:text-emerald-200"
                                  : cell.test_status === "INCONCLUSIVE"
                                  ? "bg-amber-500/30 text-amber-800 dark:text-amber-200"
                                  : "text-muted-foreground"
                              }`}
                            >
                              {cell.test_status}
                            </span>
                          </div>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      {/* Cell Inspector Drawer / Modal */}
      {activeCell && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <Card className="max-w-md w-full shadow-xl border-border bg-card">
            <CardContent className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <h3 className="text-base font-bold">Matrix Cell Inspector</h3>
                <button
                  onClick={() => {
                    setActiveCell(null);
                    setCellActionMessage(null);
                  }}
                  className="text-muted-foreground hover:text-foreground text-sm"
                >
                  ✕
                </button>
              </div>

              {cellActionMessage && (
                <div className="p-2.5 bg-primary/10 border border-primary/20 rounded text-xs text-primary">
                  {cellActionMessage}
                </div>
              )}

              <div className="space-y-2 text-xs">
                <div>
                  <span className="text-muted-foreground">Endpoint: </span>
                  <span className="font-mono font-semibold">
                    {activeCell.endpoint.method} {activeCell.endpoint.path}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Role: </span>
                  <span className="font-semibold">{activeCell.role.name}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Current Expected Access: </span>
                  <span className="font-bold">{activeCell.cell.expected_access}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Test Status: </span>
                  <span className="font-bold">{activeCell.cell.test_status}</span>
                </div>
              </div>

              {/* Set Expected Access */}
              <div className="space-y-2 pt-2 border-t border-border">
                <label className="text-xs font-semibold text-muted-foreground uppercase">
                  Configure Expected Access:
                </label>
                <div className="grid grid-cols-3 gap-2">
                  <Button
                    variant={activeCell.cell.expected_access === "ALLOW" ? "default" : "secondary"}
                    size="sm"
                    onClick={() => handleSetExpectedAccess("ALLOW")}
                  >
                    ALLOW
                  </Button>
                  <Button
                    variant={activeCell.cell.expected_access === "DENY" ? "default" : "secondary"}
                    size="sm"
                    onClick={() => handleSetExpectedAccess("DENY")}
                  >
                    DENY
                  </Button>
                  <Button
                    variant={activeCell.cell.expected_access === "UNKNOWN" ? "default" : "secondary"}
                    size="sm"
                    onClick={() => handleSetExpectedAccess("UNKNOWN")}
                  >
                    UNKNOWN
                  </Button>
                </div>
              </div>

              {/* Quick Actions */}
              <div className="space-y-2 pt-2 border-t border-border">
                {activeCell.cell.finding_id && (
                  <Link href={`/findings`} className="block">
                    <Button variant="destructive" size="sm" className="w-full">
                      ⚠️ Open Confirmed Finding
                    </Button>
                  </Link>
                )}
                <Link
                  href={`/security-tests`}
                  className="block"
                >
                  <Button variant="outline" size="sm" className="w-full">
                    Configure / Run BFLA Test →
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Endpoint Policy Drawer */}
      {policyEndpoint && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <Card className="max-w-lg w-full shadow-xl border-border bg-card">
            <CardContent className="p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-border pb-3">
                <div>
                  <h3 className="text-base font-bold">Endpoint Authorization Policy</h3>
                  <p className="text-xs font-mono text-muted-foreground mt-0.5">
                    {policyEndpoint.method} {policyEndpoint.path}
                  </p>
                </div>
                <button onClick={() => setPolicyEndpoint(null)} className="text-muted-foreground hover:text-foreground text-sm">
                  ✕
                </button>
              </div>

              {policyLoading ? (
                <div className="py-8 text-center text-sm text-muted-foreground">Loading policy...</div>
              ) : (
                <div className="space-y-4 text-xs">
                  {/* Authentication Required Toggle */}
                  <div className="flex items-center justify-between p-3 border border-border rounded-md">
                    <div>
                      <div className="font-semibold text-foreground">Authentication Required</div>
                      <div className="text-muted-foreground text-[11px]">
                        Reject unauthenticated and anonymous requests
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={policyAuthRequired}
                      onChange={(e) => setPolicyAuthRequired(e.target.checked)}
                      className="h-4 w-4 rounded border-input text-primary"
                    />
                  </div>

                  {/* Allowed Roles */}
                  <div>
                    <label className="font-semibold uppercase text-muted-foreground mb-1 block">
                      Explicitly Allowed Roles
                    </label>
                    <div className="space-y-1 max-h-32 overflow-y-auto p-2 border border-border rounded-md">
                      {matrixData?.roles.map((r) => (
                        <label key={r.id} className="flex items-center gap-2 cursor-pointer hover:bg-accent/40 p-1 rounded">
                          <input
                            type="checkbox"
                            checked={policyAllowedRoles.includes(r.id)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setPolicyAllowedRoles([...policyAllowedRoles, r.id]);
                                setPolicyDeniedRoles(policyDeniedRoles.filter((id) => id !== r.id));
                              } else {
                                setPolicyAllowedRoles(policyAllowedRoles.filter((id) => id !== r.id));
                              }
                            }}
                          />
                          <span>{r.name}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Denied Roles */}
                  <div>
                    <label className="font-semibold uppercase text-muted-foreground mb-1 block">
                      Explicitly Denied Roles
                    </label>
                    <div className="space-y-1 max-h-32 overflow-y-auto p-2 border border-border rounded-md">
                      {matrixData?.roles.map((r) => (
                        <label key={r.id} className="flex items-center gap-2 cursor-pointer hover:bg-accent/40 p-1 rounded">
                          <input
                            type="checkbox"
                            checked={policyDeniedRoles.includes(r.id)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setPolicyDeniedRoles([...policyDeniedRoles, r.id]);
                                setPolicyAllowedRoles(policyAllowedRoles.filter((id) => id !== r.id));
                              } else {
                                setPolicyDeniedRoles(policyDeniedRoles.filter((id) => id !== r.id));
                              }
                            }}
                          />
                          <span>{r.name}</span>
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Policy Notes */}
                  <div>
                    <label className="font-semibold uppercase text-muted-foreground mb-1 block">Policy Notes</label>
                    <textarea
                      rows={2}
                      className="w-full rounded-md border border-input bg-background p-2 text-xs"
                      placeholder="e.g. Administrative endpoint requiring RBAC Admin role"
                      value={policyNotes}
                      onChange={(e) => setPolicyNotes(e.target.value)}
                    />
                  </div>

                  {/* Actions */}
                  <div className="flex justify-end gap-2 pt-2 border-t border-border">
                    <Button variant="secondary" size="sm" onClick={() => setPolicyEndpoint(null)}>
                      Cancel
                    </Button>
                    <Button size="sm" onClick={handleSavePolicy}>
                      Save Policy
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
