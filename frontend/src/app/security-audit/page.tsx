"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
}

interface AuditEvent {
  id: string;
  project_id: number | null;
  actor_user_id: string | null;
  actor_email: string | null;
  event_type: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  outcome: "SUCCESS" | "DENIED" | "FAILURE" | string;
  request_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  metadata_json: Record<string, unknown> | null;
  created_at: string;
}

function SecurityAuditContent() {
  const searchParams = useSearchParams();
  const initialProjectId = searchParams.get("project_id");

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(
    initialProjectId ? parseInt(initialProjectId, 10) : null
  );

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [outcomeFilter, setOutcomeFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [refreshKey, setRefreshKey] = useState<number>(0);

  // Modal inspection
  const [inspectingEvent, setInspectingEvent] = useState<AuditEvent | null>(null);

  // Fetch projects
  useEffect(() => {
    let isCancelled = false;
    fetch("/api/v1/projects/")
      .then((res) => res.json())
      .then((data: Project[]) => {
        if (!isCancelled) {
          setProjects(data || []);
          setSelectedProjectId((prev) => (prev !== null ? prev : (data && data.length > 0 ? data[0].id : null)));
        }
      })
      .catch((err) => {
        console.error("Failed to fetch projects", err);
      });
    return () => {
      isCancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!selectedProjectId) return;

    let ignore = false;
    async function loadAuditEvents() {
      setLoading(true);
      setError(null);
      try {
        const url = new URL(`/api/v1/projects/${selectedProjectId}/audit-events`, window.location.origin);
        if (typeFilter) url.searchParams.append("event_type", typeFilter);
        if (outcomeFilter) url.searchParams.append("outcome", outcomeFilter);
        url.searchParams.append("limit", "100");

        const res = await fetch(url.toString(), { credentials: "include" });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        if (!ignore) {
          setAuditEvents(data.events || []);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (!ignore) {
          setLoading(false);
        }
      }
    }

    loadAuditEvents();

    return () => {
      ignore = true;
    };
  }, [selectedProjectId, typeFilter, outcomeFilter, refreshKey]);

  const filteredEvents = auditEvents.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      ev.action.toLowerCase().includes(q) ||
      (ev.resource_id && ev.resource_id.toLowerCase().includes(q)) ||
      (ev.actor_email && ev.actor_email.toLowerCase().includes(q)) ||
      (ev.request_id && ev.request_id.toLowerCase().includes(q))
    );
  });

  const getOutcomeBadge = (outcome: string) => {
    switch (outcome.toUpperCase()) {
      case "SUCCESS":
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">SUCCESS</span>;
      case "DENIED":
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">DENIED</span>;
      default:
        return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">{outcome}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Immutable, append-only security event provenance and actor attribution.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            value={selectedProjectId || ""}
            onChange={(e) => setSelectedProjectId(parseInt(e.target.value, 10))}
            className="h-9 px-3 text-sm rounded-md border border-input bg-background focus:outline-hidden focus:ring-1 focus:ring-ring"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} (#{p.id})
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setRefreshKey((k) => k + 1)}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Immutability Banner */}
      <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 flex items-start gap-3">
        <div className="text-primary mt-0.5">
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div>
          <h4 className="text-sm font-semibold text-foreground">Immutable & Tamper-Evident Trail</h4>
          <p className="text-xs text-muted-foreground mt-0.5">
            Audit events in SentinelAPI are strictly append-only. Modification and deletion endpoints are disabled. Sensitive tokens, credentials, and passwords are automatically redacted before storage.
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <Card>
        <CardContent className="p-4 flex flex-col md:flex-row gap-3 items-center">
          <div className="w-full md:w-1/3">
            <Input
              placeholder="Search action, resource, actor, or request ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-9 text-xs"
            />
          </div>
          <div className="w-full md:w-1/4">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full h-9 px-3 text-xs rounded-md border border-input bg-background"
            >
              <option value="">All Event Types</option>
              <option value="AUTH">AUTH</option>
              <option value="PROJECT">PROJECT</option>
              <option value="SCAN">SCAN</option>
              <option value="GATE">GATE</option>
              <option value="BASELINE">BASELINE</option>
              <option value="REPORT">REPORT</option>
              <option value="SCHEDULE">SCHEDULE</option>
              <option value="RBAC">RBAC</option>
            </select>
          </div>
          <div className="w-full md:w-1/4">
            <select
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              className="w-full h-9 px-3 text-xs rounded-md border border-input bg-background"
            >
              <option value="">All Outcomes</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="DENIED">DENIED</option>
              <option value="FAILURE">FAILURE</option>
            </select>
          </div>
          <div className="w-full md:w-auto ml-auto text-xs text-muted-foreground whitespace-nowrap">
            Showing {filteredEvents.length} events
          </div>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <div className="p-4 rounded-md bg-destructive/10 border border-destructive/20 text-destructive text-sm">
          {error}
        </div>
      )}

      {/* Audit Log Table */}
      <Card>
        <CardContent className="p-0 overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-muted/50 border-b border-border text-muted-foreground font-semibold">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Event / Action</th>
                <th className="py-3 px-4">Outcome</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Resource</th>
                <th className="py-3 px-4">Request ID</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-muted-foreground">
                    Loading audit records...
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-muted-foreground">
                    No audit records found matching your filters.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-accent/40 transition-colors">
                    <td className="py-3 px-4 whitespace-nowrap text-muted-foreground">
                      {new Date(ev.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-medium">
                      <span className="font-mono text-primary mr-1.5">{ev.event_type}:</span>
                      <span>{ev.action}</span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getOutcomeBadge(ev.outcome)}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-muted-foreground">
                      {ev.actor_email || ev.actor_user_id || "system"}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="text-muted-foreground mr-1">{ev.resource_type}</span>
                      {ev.resource_id && (
                        <span className="font-mono text-[10px] bg-muted px-1.5 py-0.5 rounded">
                          {ev.resource_id.length > 12 ? `${ev.resource_id.slice(0, 10)}...` : ev.resource_id}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap font-mono text-[11px] text-muted-foreground">
                      {ev.request_id ? `${ev.request_id.slice(0, 8)}...` : "-"}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setInspectingEvent(ev)}
                      >
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Metadata Detail Modal */}
      {inspectingEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-background border border-border rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div>
                <h3 className="text-base font-semibold">Audit Event Inspection</h3>
                <p className="text-xs text-muted-foreground font-mono">ID: {inspectingEvent.id}</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="h-8 w-8 p-0"
                onClick={() => setInspectingEvent(null)}
              >
                ✕
              </Button>
            </div>
            <div className="p-4 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-muted/30 p-3 rounded-lg border border-border">
                <div>
                  <span className="text-muted-foreground block">Event Type</span>
                  <span className="font-medium">{inspectingEvent.event_type}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block">Action</span>
                  <span className="font-medium">{inspectingEvent.action}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block">Outcome</span>
                  <span>{getOutcomeBadge(inspectingEvent.outcome)}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block">Actor</span>
                  <span className="font-mono">{inspectingEvent.actor_email || inspectingEvent.actor_user_id || "system"}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block">Correlation Request ID</span>
                  <span className="font-mono">{inspectingEvent.request_id || "N/A"}</span>
                </div>
                <div>
                  <span className="text-muted-foreground block">IP Address</span>
                  <span className="font-mono">{inspectingEvent.ip_address || "N/A"}</span>
                </div>
              </div>

              <div>
                <h5 className="font-semibold text-muted-foreground mb-1.5">Sanitized Event Metadata (JSON)</h5>
                <pre className="p-3 rounded-lg bg-muted font-mono text-[11px] overflow-x-auto text-foreground">
                  {JSON.stringify(inspectingEvent.metadata_json || {}, null, 2)}
                </pre>
              </div>
            </div>
            <div className="p-4 border-t border-border flex justify-end">
              <Button size="sm" onClick={() => setInspectingEvent(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecurityAuditPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-sm text-muted-foreground">Loading audit workspace...</div>}>
      <SecurityAuditContent />
    </Suspense>
  );
}
