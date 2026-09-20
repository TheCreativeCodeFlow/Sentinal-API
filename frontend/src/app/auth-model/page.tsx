"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
}

interface AuthModelResourceItem {
  resource_id: string;
  resource_name: string;
  resource_type: string;
  instance_id?: string | null;
  ownership_type: string;
  associated_endpoints: string[];
}

interface AuthModelIdentityNode {
  identity_id: string;
  identity_name: string;
  role_id?: string | null;
  role_name: string;
  auth_type: string;
  environment: string;
  credential_status: string;
  resources: AuthModelResourceItem[];
}

interface AuthorizationModelView {
  project_id: number;
  project_name: string;
  nodes: AuthModelIdentityNode[];
  total_identities: number;
  total_roles: number;
  total_resources: number;
}

export default function AuthorizationModelPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [model, setModel] = useState<AuthorizationModelView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

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

  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;
    async function loadAuthModel() {
      try {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/authorization-model`, {
          credentials: "include",
        });
        if (!res.ok) throw new Error("Failed to load authorization model");
        const data = await res.json();
        if (!ignore) {
          setModel(data);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to fetch authorization model");
          setLoading(false);
        }
      }
    }
    loadAuthModel();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Authorization Model Visualizer</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Structural representation of Identity → Role → Resources security topology.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {projects.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-muted-foreground">Project:</span>
              <select
                className="h-9 px-3 rounded-md border border-border bg-background text-sm font-medium"
                value={selectedProjectId || ""}
                onChange={(e) => setSelectedProjectId(Number(e.target.value))}
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
          )}
          {selectedProjectId && (
            <Button variant="secondary" onClick={() => setReloadKey((k) => k + 1)}>
              Refresh Graph
            </Button>
          )}
        </div>
      </div>

      {loading && (
        <div className="p-12 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading authorization topology...
        </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm border border-destructive/20">
          {error}
        </div>
      )}

      {!loading && !error && model && (
        <>
          {/* Summary metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-xs uppercase text-muted-foreground">Identities</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{model.total_identities}</div>
                <p className="text-xs text-muted-foreground mt-0.5">Modeled Actors</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-xs uppercase text-muted-foreground">Roles</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{model.total_roles}</div>
                <p className="text-xs text-muted-foreground mt-0.5">Security Contexts</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-xs uppercase text-muted-foreground">Resources</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{model.total_resources}</div>
                <p className="text-xs text-muted-foreground mt-0.5">Domain Entities</p>
              </CardContent>
            </Card>
          </div>

          {/* Authorization Model Hierarchy */}
          {model.nodes.length === 0 ? (
            <div className="p-12 text-center border border-dashed border-border rounded-xl">
              <p className="text-muted-foreground mb-4">
                No authorization nodes modeled yet for &quot;{model.project_name}&quot;.
              </p>
              <div className="flex justify-center gap-3">
                <a href="/identities">
                  <Button variant="primary">Create Identities</Button>
                </a>
                <a href="/roles">
                  <Button variant="secondary">Create Roles</Button>
                </a>
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              <h2 className="text-lg font-semibold tracking-tight">
                Authorization Hierarchy (Identity → Role → Resources)
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {model.nodes.map((node) => (
                  <Card key={node.identity_id} className="border-border shadow-xs hover:border-primary/40 transition-colors">
                    <CardHeader className="bg-muted/30 pb-3 border-b border-border">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-background font-semibold uppercase text-muted-foreground">
                          {node.environment}
                        </span>
                        <span className="text-xs font-mono text-muted-foreground">
                          {node.auth_type}
                        </span>
                      </div>
                      <div className="mt-2 font-bold text-base text-foreground flex items-center gap-1.5">
                        <span>👤</span>
                        <span>{node.identity_name}</span>
                      </div>
                    </CardHeader>

                    <CardContent className="pt-4 space-y-4">
                      {/* Flow Arrow */}
                      <div className="flex flex-col items-center">
                        <div className="w-0.5 h-4 bg-border"></div>
                        <span className="text-xs font-mono text-muted-foreground font-bold">↓</span>
                        <div className="w-0.5 h-2 bg-border"></div>
                      </div>

                      {/* Role Node */}
                      <div className="p-3 rounded-lg border border-primary/30 bg-primary/5 text-center">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground block">
                          Assigned Role
                        </span>
                        <span className="font-bold text-sm text-primary">
                          🛡️ {node.role_name}
                        </span>
                      </div>

                      {/* Flow Arrow */}
                      <div className="flex flex-col items-center">
                        <div className="w-0.5 h-4 bg-border"></div>
                        <span className="text-xs font-mono text-muted-foreground font-bold">↓</span>
                        <div className="w-0.5 h-2 bg-border"></div>
                      </div>

                      {/* Owned Resources */}
                      <div className="space-y-2">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-muted-foreground block text-center">
                          Owned Resources ({node.resources.length})
                        </span>

                        {node.resources.length === 0 ? (
                          <div className="p-3 rounded border border-dashed border-border text-center text-xs text-muted-foreground">
                            No owned resource instances
                          </div>
                        ) : (
                          <div className="space-y-2">
                            {node.resources.map((res, idx) => (
                              <div
                                key={idx}
                                className="p-3 rounded-lg border border-border bg-card/80 space-y-2 text-xs"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="font-bold text-foreground">
                                    📦 {res.resource_name}
                                  </span>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted font-mono uppercase">
                                    {res.ownership_type}
                                  </span>
                                </div>

                                <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                                  <span>Instance:</span>
                                  <span className="font-mono font-medium text-foreground bg-accent/40 px-1.5 py-0.2 rounded">
                                    {res.instance_id || "All Records (*)"}
                                  </span>
                                </div>

                                {/* Associated Endpoints */}
                                {res.associated_endpoints.length > 0 && (
                                  <div className="pt-1 border-t border-border/50">
                                    <span className="text-[10px] text-muted-foreground block mb-1">
                                      Associated Endpoints:
                                    </span>
                                    <div className="flex flex-wrap gap-1">
                                      {res.associated_endpoints.map((ep, epIdx) => (
                                        <span
                                          key={epIdx}
                                          className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-muted/70 text-muted-foreground"
                                        >
                                          {ep}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
