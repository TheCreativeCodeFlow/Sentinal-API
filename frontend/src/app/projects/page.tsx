"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  description: string | null;
  environment: string;
  authorization_status: string;
  base_url: string | null;
}

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [environment, setEnvironment] = useState("staging");
  const [baseUrl, setBaseUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let ignore = false;
    async function load() {
      try {
        const res = await fetch("/api/v1/projects/", {
          credentials: "include",
        });
        if (!res.ok) throw new Error("Failed to fetch projects");
        const data = await res.json();
        if (!ignore) {
          setProjects(data);
          setError(null);
          setLoading(false);
        }
      } catch (e: unknown) {
        if (!ignore) {
          setError(e instanceof Error ? e.message : "Failed to load projects");
          setLoading(false);
        }
      }
    }
    load();
    return () => {
      ignore = true;
    };
  }, [reloadKey]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSubmitting(true);
    try {
      const res = await fetch("/api/v1/projects/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || null,
          environment,
          base_url: baseUrl.trim() || null,
          authorization_status: "active",
        }),
        credentials: "include",
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to create project");
      }
      setName("");
      setDescription("");
      setBaseUrl("");
      setShowCreateForm(false);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Creation failed"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Are you sure you want to delete this project and all its entities?")) return;
    try {
      const res = await fetch(`/api/v1/projects/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete project");
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Deletion failed"));
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Projects</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage target projects for API security and authorization testing.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="primary"
            onClick={() => setShowCreateForm(!showCreateForm)}
          >
            {showCreateForm ? "Cancel" : "+ New Project"}
          </Button>
          <Button variant="secondary" onClick={() => setReloadKey((k) => k + 1)}>
            Refresh
          </Button>
        </div>
      </div>

      {showCreateForm && (
        <Card className="border-primary/50 shadow-md">
          <CardHeader>
            <CardTitle>Create New Project</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold mb-1">Project Name *</label>
                  <Input
                    required
                    placeholder="e.g. Payments Microservice"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold mb-1">Environment</label>
                  <select
                    className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                  >
                    <option value="development">Development</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1">Description</label>
                <Input
                  placeholder="Optional brief description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs font-semibold mb-1">Base API URL</label>
                <Input
                  placeholder="https://api.example.com"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <Button variant="default" type="button" onClick={() => setShowCreateForm(false)}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" disabled={submitting}>
                  {submitting ? "Saving..." : "Create Project"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {loading && (
        <div className="p-8 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading projects...
        </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
          {error}
        </div>
      )}

      {!loading && !error && projects.length === 0 && (
        <div className="p-12 text-center border border-dashed border-border rounded-xl">
          <p className="text-muted-foreground mb-4">No projects registered yet.</p>
          <Button variant="primary" onClick={() => setShowCreateForm(true)}>
            Create Your First Project
          </Button>
        </div>
      )}

      {!loading && !error && projects.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-border bg-card shadow-xs">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-xs font-semibold uppercase text-muted-foreground bg-muted/40">
                <th className="p-4">Name</th>
                <th className="p-4">Environment</th>
                <th className="p-4">Base URL</th>
                <th className="p-4">Auth Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {projects.map((project) => (
                <tr key={project.id} className="hover:bg-accent/20 transition-colors">
                  <td className="p-4 font-semibold text-foreground">
                    <div>{project.name}</div>
                    {project.description && (
                      <div className="text-xs text-muted-foreground font-normal mt-0.5">
                        {project.description}
                      </div>
                    )}
                  </td>
                  <td className="p-4">
                    <span className="px-2 py-0.5 rounded-full text-xs font-mono uppercase bg-secondary text-secondary-foreground">
                      {project.environment}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-xs text-muted-foreground">
                    {project.base_url || "—"}
                  </td>
                  <td className="p-4">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        project.authorization_status === "active"
                          ? "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300"
                          : "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300"
                      }`}
                    >
                      {project.authorization_status}
                    </span>
                  </td>
                  <td className="p-4 text-right space-x-2">
                    <a href={`/auth-model?project_id=${project.id}`}>
                      <Button variant="secondary" size="sm">Auth Model</Button>
                    </a>
                    <a href={`/identities?project_id=${project.id}`}>
                      <Button variant="default" size="sm">Identities</Button>
                    </a>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(project.id)}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
