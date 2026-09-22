"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
  resource_id: string | null;
  resource_name?: string | null;
}

interface Identity {
  id: string;
  name: string;
  auth_type: string;
  role_id?: string | null;
  role_name?: string | null;
  has_credential: boolean;
}

interface Resource {
  id: string;
  name: string;
  resource_type: string;
}

interface ResourceOwnership {
  id: string;
  resource_id: string;
  identity_id: string;
  resource_instance_id: string | null;
  ownership_type: string;
}

interface SecurityTestItem {
  id: string;
  project_id: number;
  endpoint_id: number;
  endpoint_method: string | null;
  endpoint_path: string | null;
  test_type: string;
  attacker_identity_id: string;
  attacker_identity_name: string | null;
  attacker_role_name?: string | null;
  victim_identity_id: string | null;
  victim_identity_name: string | null;
  victim_resource_id: string | null;
  victim_resource_name: string | null;
  victim_resource_instance_id: string | null;
  attacker_resource_instance_id: string | null;
  expected_access?: string | null;
  status: string;
  latest_result: string | null;
  executions_count: number;
  findings_count: number;
  created_at: string;
}

interface ExecutionItem {
  id: string;
  security_test_id: string;
  status: string;
  result: string | null;
  result_reason: string | null;
  http_status: number | null;
  duration_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
  error_category: string | null;
}

export default function SecurityTestsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [tests, setTests] = useState<SecurityTestItem[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [ownerships, setOwnerships] = useState<ResourceOwnership[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  // Filters
  const [testTypeFilter, setTestTypeFilter] = useState<string>("ALL");
  const [resultFilter, setResultFilter] = useState<string>("ALL");

  // Execution state
  const [executingTestId, setExecutingTestId] = useState<string | null>(null);
  const [executionHistoryTest, setExecutionHistoryTest] = useState<SecurityTestItem | null>(null);
  const [executionsList, setExecutionsList] = useState<ExecutionItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Create Test Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedTestType, setSelectedTestType] = useState<"BOLA" | "BFLA" | "PROPERTY_EXPOSURE">("BOLA");
  const [expectedAccess, setExpectedAccess] = useState<"DENY" | "ALLOW">("DENY");
  const [selectedEndpointId, setSelectedEndpointId] = useState<number | "">("");
  const [selectedAttackerId, setSelectedAttackerId] = useState<string>("");
  const [selectedVictimId, setSelectedVictimId] = useState<string>("");
  const [selectedResourceId, setSelectedResourceId] = useState<string>("");
  const [victimInstanceId, setVictimInstanceId] = useState<string>("");
  const [attackerInstanceId, setAttackerInstanceId] = useState<string>("");
  const [submitting, setSubmitting] = useState(false);

  const activeProject = projects.find((p) => p.id === selectedProjectId);
  const isTargetAuthorized = activeProject?.authorization_status.toLowerCase() === "authorized";

  // Load projects
  useEffect(() => {
    let ignore = false;
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch projects");
        const data: Project[] = await res.json();
        if (!ignore) {
          setProjects(data);
          if (data.length > 0) {
            setSelectedProjectId((prev) => (prev === null ? data[0].id : prev));
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

  // Load project data: tests, endpoints, identities, resources
  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;
    async function loadData() {
      try {
        const [testsRes, identRes, resRes, apisRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/security-tests/`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/identities/`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/resources/`, { credentials: "include" }),
          fetch(`/api/v1/${selectedProjectId}/apis/`, { credentials: "include" }),
        ]);

        const tData = testsRes.ok ? await testsRes.json() : [];
        const iData = identRes.ok ? await identRes.json() : [];
        const rData = resRes.ok ? await resRes.json() : [];

        const eps: EndpointItem[] = [];
        if (apisRes.ok) {
          const apis = await apisRes.json();
          for (const api of apis) {
            const epRes = await fetch(`/api/v1/${api.id}/endpoints/`, { credentials: "include" });
            if (epRes.ok) {
              const apiEps = await epRes.json();
              eps.push(...apiEps);
            }
          }
        }

        // Fetch ownerships for resources in this project
        const oList: ResourceOwnership[] = [];
        for (const res of rData) {
          const oRes = await fetch(`/api/v1/resources/${res.id}/ownerships/`, { credentials: "include" });
          if (oRes.ok) {
            oList.push(...(await oRes.json()));
          }
        }

        if (!ignore) {
          setTests(tData);
          setIdentities(iData);
          setResources(rData);
          setEndpoints(eps);
          setOwnerships(oList);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load security tests");
          setLoading(false);
        }
      }
    }
    loadData();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  // When endpoint is selected in create modal, auto-fill resource and ownership instances for BOLA
  const handleEndpointSelect = (epId: number) => {
    setSelectedEndpointId(epId);
    const ep = endpoints.find((e) => e.id === epId);
    if (ep && ep.resource_id && selectedTestType === "BOLA") {
      setSelectedResourceId(ep.resource_id);
      const relOwnerships = ownerships.filter((o) => o.resource_id === ep.resource_id);
      if (relOwnerships.length > 0 && !victimInstanceId) {
        setVictimInstanceId(relOwnerships[0].resource_instance_id || "");
      }
    }
  };

  const handleAuthorizeProject = async () => {
    if (!selectedProjectId) return;
    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authorization_status: "authorized" }),
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to update project authorization status");
      setProjects((prev) =>
        prev.map((p) => (p.id === selectedProjectId ? { ...p, authorization_status: "authorized" } : p))
      );
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Authorization update failed"));
    }
  };

  const handleCreateTest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !selectedEndpointId || !selectedAttackerId) {
      return;
    }
    if (selectedTestType === "BOLA" && !victimInstanceId.trim()) {
      return;
    }

    setSubmitting(true);
    try {
      let payload;
      if (selectedTestType === "BOLA") {
        payload = {
          endpoint_id: Number(selectedEndpointId),
          test_type: "BOLA",
          attacker_identity_id: selectedAttackerId,
          victim_identity_id: selectedVictimId || null,
          victim_resource_id: selectedResourceId || null,
          victim_resource_instance_id: victimInstanceId.trim(),
          attacker_resource_instance_id: attackerInstanceId.trim() || null,
          expected_access: expectedAccess,
        };
      } else if (selectedTestType === "PROPERTY_EXPOSURE") {
        payload = {
          endpoint_id: Number(selectedEndpointId),
          test_type: "PROPERTY_EXPOSURE",
          attacker_identity_id: selectedAttackerId,
          victim_resource_id: selectedResourceId || selectedEpObj?.resource_id || null,
          victim_resource_instance_id: victimInstanceId.trim() || null,
          expected_access: "DENY",
        };
      } else {
        payload = {
          endpoint_id: Number(selectedEndpointId),
          test_type: "BFLA",
          attacker_identity_id: selectedAttackerId,
          expected_access: expectedAccess,
          victim_identity_id: null,
          victim_resource_id: null,
          victim_resource_instance_id: null,
          attacker_resource_instance_id: null,
        };
      }

      const res = await fetch(`/api/v1/projects/${selectedProjectId}/security-tests/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create security test");
      }

      setShowCreateModal(false);
      setSelectedEndpointId("");
      setSelectedAttackerId("");
      setSelectedVictimId("");
      setSelectedResourceId("");
      setVictimInstanceId("");
      setAttackerInstanceId("");
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Failed to create security test: " + (err instanceof Error ? err.message : "Validation error"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleExecuteTest = async (testId: string) => {
    setExecutingTestId(testId);
    try {
      const res = await fetch(`/api/v1/security-tests/${testId}/execute`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Execution failed");
      }
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Test Execution Failed: " + (err instanceof Error ? err.message : "Error executing test"));
    } finally {
      setExecutingTestId(null);
    }
  };

  const handleViewExecutions = async (test: SecurityTestItem) => {
    setExecutionHistoryTest(test);
    setLoadingHistory(true);
    try {
      const res = await fetch(`/api/v1/security-tests/${test.id}/executions`, { credentials: "include" });
      if (res.ok) {
        setExecutionsList(await res.json());
      }
    } catch {
      setExecutionsList([]);
    } finally {
      setLoadingHistory(false);
    }
  };

  // Validation checks for create modal
  const selectedEpObj = endpoints.find((e) => e.id === Number(selectedEndpointId));
  const isSafeMethod = selectedEpObj ? ["GET", "HEAD"].includes(selectedEpObj.method.toUpperCase()) : false;
  const isEpLinked = !!selectedEpObj?.resource_id;
  const selectedAttackerObj = identities.find((i) => i.id === selectedAttackerId);
  const attackerHasAuth = !!selectedAttackerObj;

  const canSubmit =
    selectedTestType === "BOLA"
      ? isTargetAuthorized && isSafeMethod && isEpLinked && attackerHasAuth && !!victimInstanceId.trim()
      : selectedTestType === "PROPERTY_EXPOSURE"
      ? isTargetAuthorized && isSafeMethod && attackerHasAuth && !!selectedEndpointId && (!!selectedResourceId || isEpLinked)
      : isTargetAuthorized && isSafeMethod && attackerHasAuth && !!selectedEndpointId;

  // Filtered test list
  const filteredTests = tests.filter((t) => {
    if (testTypeFilter !== "ALL" && t.test_type.toUpperCase() !== testTypeFilter.toUpperCase()) {
      return false;
    }
    if (resultFilter !== "ALL") {
      if (resultFilter === "UNTESTED") {
        if (t.latest_result) return false;
      } else if (t.latest_result !== resultFilter) {
        return false;
      }
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Controlled Security Testing Engine</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Execute controlled BOLA (Resource Level) and BFLA (Function Level) boundary tests against authorized targets.
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
            onClick={() => setShowCreateModal(true)}
            disabled={!selectedProjectId || !isTargetAuthorized}
          >
            + Configure Test
          </Button>
        </div>
      </div>

      {/* Safety Notice Banner if Project is not Authorized */}
      {selectedProjectId && !isTargetAuthorized && (
        <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="font-semibold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
              Target Authorization Check: Target Not Authorized
            </div>
            <p className="text-xs opacity-90">
              For security compliance, tests can only be run against projects with explicit authorization enabled.
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={handleAuthorizeProject}>
            Authorize Target Now
          </Button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Type:</span>
            <select
              className="h-8 rounded-md border border-input bg-background px-2.5 text-xs shadow-xs"
              value={testTypeFilter}
              onChange={(e) => setTestTypeFilter(e.target.value)}
            >
              <option value="ALL">All Types</option>
              <option value="BOLA">BOLA (Resource Authorization)</option>
              <option value="BFLA">BFLA (Function-Level Authorization)</option>
              <option value="PROPERTY_EXPOSURE">Property Exposure (Field-Level)</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Result:</span>
            <select
              className="h-8 rounded-md border border-input bg-background px-2.5 text-xs shadow-xs"
              value={resultFilter}
              onChange={(e) => setResultFilter(e.target.value)}
            >
              <option value="ALL">All Results</option>
              <option value="CONFIRMED">Vulnerability Confirmed</option>
              <option value="PASS">Passed (Enforced)</option>
              <option value="INCONCLUSIVE">Inconclusive</option>
              <option value="ERROR">Error</option>
              <option value="UNTESTED">Untested</option>
            </select>
          </div>
        </div>

        <div className="text-xs text-muted-foreground">
          Showing {filteredTests.length} of {tests.length} configured test(s)
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-destructive/10 border border-destructive text-destructive text-sm">
          {error}
        </div>
      )}

      {/* Tests Grid / Table */}
      {loading ? (
        <div className="p-12 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading security tests...
        </div>
      ) : filteredTests.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground space-y-3">
            <div className="w-12 h-12 rounded-full bg-primary/10 text-primary mx-auto flex items-center justify-center text-xl font-bold">
              🛡️
            </div>
            <h3 className="font-medium text-foreground">No Security Tests Found</h3>
            <p className="text-xs max-w-md mx-auto">
              {tests.length === 0
                ? "Configure your first controlled BOLA or BFLA test, or generate tests automatically from the Authorization Matrix tab."
                : "No tests matched the selected filter criteria."}
            </p>
            {isTargetAuthorized && tests.length === 0 && (
              <Button size="sm" onClick={() => setShowCreateModal(true)}>
                Configure Security Test
              </Button>
            )}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {filteredTests.map((test) => {
            const isExecuting = executingTestId === test.id;
            const isBFLA = test.test_type.toUpperCase() === "BFLA";
            const isProp = test.test_type.toUpperCase() === "PROPERTY_EXPOSURE";
            return (
              <Card key={test.id} className="overflow-hidden border-border">
                <div className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                          isProp
                            ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20"
                            : isBFLA
                            ? "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20"
                            : "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20"
                        }`}
                      >
                        {test.test_type}
                      </span>
                      <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-secondary text-secondary-foreground">
                        {test.endpoint_method || "GET"}
                      </span>
                      <span className="font-mono text-sm font-semibold">{test.endpoint_path}</span>

                      {/* Result Badge */}
                      {test.latest_result === "CONFIRMED" && (
                        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-red-500/20 text-red-700 dark:text-red-300 border border-red-500/30 animate-pulse">
                          {isProp ? "CONFIRMED PROPERTY EXPOSURE" : isBFLA ? "CONFIRMED BFLA" : "CONFIRMED BOLA"}
                        </span>
                      )}
                      {test.latest_result === "PASS" && (
                        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
                          {isBFLA ? "PASSED (Boundary Enforced)" : "PASSED (Access Denied)"}
                        </span>
                      )}
                      {test.latest_result === "INCONCLUSIVE" && (
                        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30">
                          INCONCLUSIVE
                        </span>
                      )}
                      {test.latest_result === "ERROR" && (
                        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-destructive/20 text-destructive border border-destructive/30">
                          EXECUTION ERROR
                        </span>
                      )}
                      {!test.latest_result && (
                        <span className="text-xs px-2.5 py-0.5 rounded-full bg-muted text-muted-foreground border border-border">
                          Not Executed Yet
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-x-6 gap-y-1 text-xs text-muted-foreground">
                      <div>
                        <span className="font-semibold text-foreground">Attacker:</span>{" "}
                        {test.attacker_identity_name || "Unknown"}
                        {test.attacker_role_name && (
                          <span className="ml-1 text-[11px] text-muted-foreground">({test.attacker_role_name})</span>
                        )}
                      </div>
                      <div>
                        {isBFLA ? (
                          <>
                            <span className="font-semibold text-foreground">Expected Access:</span>{" "}
                            <span
                              className={`font-semibold ${
                                test.expected_access === "ALLOW" ? "text-emerald-600" : "text-rose-600"
                              }`}
                            >
                              {test.expected_access || "DENY"}
                            </span>
                          </>
                        ) : (
                          <>
                            <span className="font-semibold text-foreground">Victim Resource:</span>{" "}
                            {test.victim_resource_name || "Resource"} ({test.victim_resource_instance_id})
                          </>
                        )}
                      </div>
                      <div>
                        <span className="font-semibold text-foreground">Runs:</span> {test.executions_count} run(s)
                        {test.findings_count > 0 && (
                          <span className="ml-2 text-red-600 font-bold">({test.findings_count} finding)</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleViewExecutions(test)}
                    >
                      History ({test.executions_count})
                    </Button>

                    {test.findings_count > 0 && (
                      <Link href={`/findings?project_id=${selectedProjectId}&type_filter=${test.test_type}`}>
                        <Button variant="outline" size="sm" className="border-red-500/30 text-red-600 hover:bg-red-500/10">
                          View Finding
                        </Button>
                      </Link>
                    )}

                    <Button
                      size="sm"
                      onClick={() => handleExecuteTest(test.id)}
                      disabled={isExecuting || !isTargetAuthorized}
                      className={test.latest_result === "CONFIRMED" ? "bg-red-600 hover:bg-red-700 text-white" : ""}
                    >
                      {isExecuting ? "Testing..." : "Execute Test"}
                    </Button>
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Create Security Test Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h2 className="text-lg font-bold">Configure Controlled Security Test</h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Select authorization test type to evaluate boundary compliance safely.
                </p>
              </div>
              <button
                className="text-muted-foreground hover:text-foreground text-sm font-semibold"
                onClick={() => setShowCreateModal(false)}
              >
                ✕
              </button>
            </div>

            {/* Test Type Switcher Tabs */}
            <div className="flex border border-border rounded-lg p-1 bg-muted/40 gap-1">
              <button
                type="button"
                onClick={() => setSelectedTestType("BOLA")}
                className={`flex-1 py-1.5 px-2 rounded-md text-xs font-semibold transition-all ${
                  selectedTestType === "BOLA"
                    ? "bg-card text-foreground shadow-xs"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                BOLA (Resource)
              </button>
              <button
                type="button"
                onClick={() => setSelectedTestType("BFLA")}
                className={`flex-1 py-1.5 px-2 rounded-md text-xs font-semibold transition-all ${
                  selectedTestType === "BFLA"
                    ? "bg-card text-foreground shadow-xs"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                BFLA (Function)
              </button>
              <button
                type="button"
                onClick={() => setSelectedTestType("PROPERTY_EXPOSURE")}
                className={`flex-1 py-1.5 px-2 rounded-md text-xs font-semibold transition-all ${
                  selectedTestType === "PROPERTY_EXPOSURE"
                    ? "bg-card text-foreground shadow-xs"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Property Exposure
              </button>
            </div>

            <form onSubmit={handleCreateTest} className="space-y-4">
              {/* Endpoint selection */}
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">
                  1. Target Endpoint (GET/HEAD only) *
                </label>
                <select
                  className="mt-1 w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring font-mono"
                  value={selectedEndpointId}
                  onChange={(e) => handleEndpointSelect(Number(e.target.value))}
                  required
                >
                  <option value="">-- Select safe GET/HEAD endpoint --</option>
                  {endpoints
                    .filter((ep) => ["GET", "HEAD"].includes(ep.method.toUpperCase()))
                    .map((ep) => (
                      <option key={ep.id} value={ep.id}>
                        {ep.method} {ep.path} {ep.resource_id ? `[Resource linked]` : `(No resource)`}
                      </option>
                    ))}
                </select>
                {selectedTestType === "BOLA" && selectedEpObj && !selectedEpObj.resource_id && (
                  <p className="text-xs text-destructive mt-1">
                    ⚠️ BOLA requires an endpoint linked to a domain resource. Link it under Resources or switch to BFLA testing.
                  </p>
                )}
              </div>

              {/* Attacker Identity */}
              <div>
                <label className="text-xs font-semibold text-muted-foreground uppercase">
                  2. Attacker Identity & Role *
                </label>
                <select
                  className="mt-1 w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                  value={selectedAttackerId}
                  onChange={(e) => setSelectedAttackerId(e.target.value)}
                  required
                >
                  <option value="">-- Select attacker identity --</option>
                  {identities.map((ident) => (
                    <option key={ident.id} value={ident.id}>
                      {ident.name} (Role: {ident.role_name || "Unassigned"}, {ident.auth_type})
                    </option>
                  ))}
                </select>
                <p className="text-xs text-muted-foreground mt-1">
                  {selectedTestType === "BFLA"
                    ? "Evaluates whether this identity/role can access the endpoint according to the authorization matrix."
                    : "The test engine uses this identity's configured credentials to request the victim's resource."}
                </p>
              </div>

              {/* BFLA Specific: Expected Access */}
              {selectedTestType === "BFLA" && (
                <div>
                  <label className="text-xs font-semibold text-muted-foreground uppercase">
                    3. Expected Access Boundary *
                  </label>
                  <select
                    className="mt-1 w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    value={expectedAccess}
                    onChange={(e) => setExpectedAccess(e.target.value as "DENY" | "ALLOW")}
                    required
                  >
                    <option value="DENY">DENY (Boundary Test: Access should be rejected with 401/403)</option>
                    <option value="ALLOW">ALLOW (Baseline Functional Test: Access should succeed with 200)</option>
                  </select>
                  <p className="text-xs text-muted-foreground mt-1">
                    If set to DENY and the endpoint returns HTTP 200 with resource data, a CONFIRMED BFLA vulnerability finding is flagged.
                  </p>
                </div>
              )}

              {/* BOLA Specific: Victim Resource & Instance ID */}
              {selectedTestType === "BOLA" && (
                <>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="text-xs font-semibold text-muted-foreground uppercase">
                        3. Victim Resource
                      </label>
                      <select
                        className="mt-1 w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                        value={selectedResourceId}
                        onChange={(e) => setSelectedResourceId(e.target.value)}
                      >
                        <option value="">-- Auto-select from endpoint --</option>
                        {resources.map((res) => (
                          <option key={res.id} value={res.id}>{res.name}</option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="text-xs font-semibold text-muted-foreground uppercase">
                        Victim Resource Instance ID *
                      </label>
                      <Input
                        className="mt-1 font-mono text-sm"
                        placeholder="e.g. order_alice_101 or 123"
                        value={victimInstanceId}
                        onChange={(e) => setVictimInstanceId(e.target.value)}
                        required
                      />
                      <p className="text-xs text-muted-foreground mt-1">
                        Replaces path parameter like {`{id}`} or {`{order_id}`}.
                      </p>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase">
                      Attacker Baseline Instance ID (Optional)
                    </label>
                    <Input
                      className="mt-1 font-mono text-sm"
                      placeholder="e.g. order_bob_202"
                      value={attackerInstanceId}
                      onChange={(e) => setAttackerInstanceId(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Used to baseline normal authorized behavior for the attacker before executing the cross-owner probe.
                    </p>
                  </div>
                </>
              )}

              {/* Property Exposure Specific: Resource & Instance ID */}
              {selectedTestType === "PROPERTY_EXPOSURE" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase">
                      3. Domain Resource *
                    </label>
                    <select
                      className="mt-1 w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      value={selectedResourceId || selectedEpObj?.resource_id || ""}
                      onChange={(e) => setSelectedResourceId(e.target.value)}
                      required
                    >
                      <option value="">-- Select domain resource --</option>
                      {resources.map((res) => (
                        <option key={res.id} value={res.id}>
                          {res.name}
                        </option>
                      ))}
                    </select>
                    <p className="text-xs text-muted-foreground mt-1">
                      Protected fields defined on this resource with DENY policy will be evaluated.
                    </p>
                  </div>

                  <div>
                    <label className="text-xs font-semibold text-muted-foreground uppercase">
                      Target Instance ID (Optional)
                    </label>
                    <Input
                      className="mt-1 font-mono text-sm"
                      placeholder="e.g. user_bob_002"
                      value={victimInstanceId}
                      onChange={(e) => setVictimInstanceId(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground mt-1">
                      Substituted if the endpoint path contains a parameter like {"{user_id}"}.
                    </p>
                  </div>
                </div>
              )}

              {/* Safety & Pre-flight Validation Checklist */}
              <div className="p-3.5 rounded-lg border border-border bg-card/60 space-y-2 text-xs">
                <div className="font-semibold text-foreground uppercase tracking-wider">
                  Pre-flight Safety Checklist
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div className="flex items-center gap-2">
                    <span>{isTargetAuthorized ? "✅" : "❌"}</span>
                    <span>Target project authorized</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span>{isSafeMethod ? "✅" : "❌"}</span>
                    <span>Safe HTTP method (GET/HEAD)</span>
                  </div>
                  {selectedTestType === "BOLA" ? (
                    <>
                      <div className="flex items-center gap-2">
                        <span>{isEpLinked ? "✅" : "❌"}</span>
                        <span>Endpoint linked to resource</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>{victimInstanceId.trim() ? "✅" : "❌"}</span>
                        <span>Victim instance ID provided</span>
                      </div>
                    </>
                  ) : selectedTestType === "PROPERTY_EXPOSURE" ? (
                    <>
                      <div className="flex items-center gap-2">
                        <span>{attackerHasAuth ? "✅" : "❌"}</span>
                        <span>Attacker identity selected</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>{selectedResourceId || isEpLinked ? "✅" : "❌"}</span>
                        <span>Domain resource configured</span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex items-center gap-2">
                        <span>{attackerHasAuth ? "✅" : "❌"}</span>
                        <span>Attacker identity selected</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span>{expectedAccess ? "✅" : "❌"}</span>
                        <span>Expected access configured ({expectedAccess})</span>
                      </div>
                    </>
                  )}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <Button type="button" variant="outline" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={!canSubmit || submitting}>
                  {submitting ? "Saving..." : `Create ${selectedTestType} Test`}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Execution History Drawer */}
      {executionHistoryTest && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl shadow-xl max-w-3xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h2 className="text-lg font-bold">Execution History</h2>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">
                  [{executionHistoryTest.test_type}] {executionHistoryTest.endpoint_method} {executionHistoryTest.endpoint_path}
                </p>
              </div>
              <button
                className="text-muted-foreground hover:text-foreground text-sm font-semibold"
                onClick={() => setExecutionHistoryTest(null)}
              >
                ✕
              </button>
            </div>

            {loadingHistory ? (
              <div className="p-8 text-center text-muted-foreground animate-pulse">
                Loading executions...
              </div>
            ) : executionsList.length === 0 ? (
              <div className="p-8 text-center text-muted-foreground text-sm">
                No executions recorded yet. Run this test to see execution logs.
              </div>
            ) : (
              <div className="space-y-3">
                {executionsList.map((exec) => (
                  <div
                    key={exec.id}
                    className="p-4 rounded-lg border border-border bg-card/40 space-y-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`font-bold px-2 py-0.5 rounded text-xs ${
                            exec.result === "CONFIRMED"
                              ? "bg-red-500/20 text-red-700 dark:text-red-300"
                              : exec.result === "PASS"
                              ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                              : "bg-amber-500/20 text-amber-700 dark:text-amber-300"
                          }`}
                        >
                          {exec.result || exec.status}
                        </span>
                        {exec.http_status && (
                          <span className="font-mono font-semibold">HTTP {exec.http_status}</span>
                        )}
                        {exec.duration_ms !== null && (
                          <span className="text-muted-foreground font-mono">{exec.duration_ms}ms</span>
                        )}
                      </div>
                      <span className="text-muted-foreground">
                        {exec.completed_at ? new Date(exec.completed_at).toLocaleString() : ""}
                      </span>
                    </div>
                    {exec.result_reason && (
                      <p className="text-foreground/90 font-mono text-[11px] bg-background/50 p-2 rounded border border-border">
                        {exec.result_reason}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
