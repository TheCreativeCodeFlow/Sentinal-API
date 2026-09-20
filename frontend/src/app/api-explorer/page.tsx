"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface EndpointItem {
  id: number;
  method: string;
  path: string;
  summary?: string | null;
  resource_id?: string | null;
  resource_name?: string | null;
  tags?: string[];
}

interface Project {
  id: number;
  name: string;
}

export default function APIExplorerPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let ignore = false;
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch projects");
        const data = await res.json();
        if (!ignore) {
          setProjects(data);
          if (data.length > 0) {
            setSelectedProjectId((prev) => (prev === null ? data[0].id : prev));
          }
        }
      } catch (e: unknown) {
        if (!ignore) {
          setError(e instanceof Error ? e.message : "Failed to load projects");
        }
      } finally {
        if (!ignore) {
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
    async function loadEndpoints() {
      try {
        const apiRes = await fetch(`/api/v1/${selectedProjectId}/apis/`, { credentials: "include" });
        if (!apiRes.ok) return;
        const apis = await apiRes.json();
        const allEndpoints: EndpointItem[] = [];
        for (const api of apis) {
          const epRes = await fetch(`/api/v1/${api.id}/endpoints/`, { credentials: "include" });
          if (epRes.ok) {
            const eps = await epRes.json();
            allEndpoints.push(...eps);
          }
        }
        if (!ignore) {
          setEndpoints(allEndpoints);
        }
      } catch {
        // Ignore background endpoint fetch errors
      }
    }
    loadEndpoints();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedProjectId) return;
    setUploading(true);
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const formData = new FormData();
        formData.append("file", file);
        const res = await fetch(`/api/v1/${selectedProjectId}/ingest`, {
          method: "POST",
          body: formData,
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Upload failed");
        }
        alert("Specification ingested successfully!");
        setReloadKey((k) => k + 1);
      } catch (err: unknown) {
        alert("Error: " + (err instanceof Error ? err.message : "Ingestion failed"));
      } finally {
        setUploading(false);
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">API Explorer & OpenAPI Ingestion</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Import OpenAPI 3.x specifications and discover endpoint schemas.
          </p>
        </div>
        {projects.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold">Active Project:</span>
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
      </div>

      {loading && <div className="p-8 text-center text-muted-foreground">Loading explorer...</div>}
      {error && <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm">{error}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle>Import OpenAPI Spec</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground">
                Upload an OpenAPI 3.x JSON or YAML file. Sentinel will parse paths, parameters, schemas, and authentication schemes.
              </p>
              <div>
                <Input
                  type="file"
                  accept=".json,.yaml,.yml"
                  disabled={uploading || !selectedProjectId}
                  onChange={handleFileUpload}
                />
              </div>
              {uploading && <p className="text-xs text-primary animate-pulse font-medium">Ingesting specification...</p>}
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Discovered Endpoints ({endpoints.length})</CardTitle>
              {selectedProjectId && (
                <Button variant="secondary" size="sm" onClick={() => setReloadKey((k) => k + 1)}>
                  Refresh Endpoints
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {endpoints.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground text-sm border border-dashed border-border rounded-lg">
                  No endpoints discovered yet for this project. Upload an OpenAPI specification on the left.
                </div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                  {endpoints.map((ep) => (
                    <div
                      key={ep.id}
                      className="p-3 rounded-lg border border-border bg-card/60 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span
                          className={`font-mono font-bold px-2 py-0.5 rounded text-[10px] ${
                            ep.method === "GET"
                              ? "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300"
                              : ep.method === "POST"
                              ? "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300"
                              : ep.method === "DELETE"
                              ? "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300"
                              : "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300"
                          }`}
                        >
                          {ep.method}
                        </span>
                        <span className="font-mono font-medium truncate">{ep.path}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {ep.resource_name ? (
                          <span className="px-2 py-0.5 rounded bg-primary/10 text-primary font-medium text-[11px]">
                            → {ep.resource_name}
                          </span>
                        ) : (
                          <a href="/resources" className="text-muted-foreground hover:text-foreground text-[11px] underline">
                            Map Resource
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
