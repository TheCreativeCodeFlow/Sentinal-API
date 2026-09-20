"use client";

import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface Project {
  id: number;
  name: string;
  environment: string;
  authorization_status: string;
}

export default function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let ignore = false;
    async function loadData() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load project summary");
        const data = await res.json();
        if (!ignore) {
          setProjects(data);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load dashboard data");
          setLoading(false);
        }
      }
    }
    loadData();
    return () => {
      ignore = true;
    };
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            API Authorization & Access Control Modeling Engine
          </p>
        </div>
        <div className="flex gap-2">
          <a href="/projects">
            <Button variant="primary">Manage Projects</Button>
          </a>
          <a href="/auth-model">
            <Button variant="secondary">View Auth Model</Button>
          </a>
        </div>
      </div>

      {loading && (
        <div className="p-12 text-center text-muted-foreground animate-pulse border border-border rounded-xl">
          Loading system telemetry...
        </div>
      )}

      {error && (
        <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-sm">
          {error}
        </div>
      )}

      {!loading && !error && (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Total Projects
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{projects.length}</div>
                <p className="text-xs text-muted-foreground mt-1">Configured test projects</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Active Environments
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">
                  {new Set(projects.map((p) => p.environment)).size}
                </div>
                <p className="text-xs text-muted-foreground mt-1">Staging, Production & Dev</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Authorization Modeling
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-green-600 dark:text-green-400">Ready</div>
                <p className="text-xs text-muted-foreground mt-1">Stage 2 Engine Active</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Security Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">Baseline</div>
                <p className="text-xs text-muted-foreground mt-1">Tokens masked & protected</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Identities</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Model test users, clients, administrators, and anonymous actors with masked credentials.
                </p>
                <a href="/identities" className="inline-block">
                  <Button variant="secondary" size="sm">Manage Identities →</Button>
                </a>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Roles</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Define Anonymous, User, Admin, and custom access roles; assign memberships to identities.
                </p>
                <a href="/roles" className="inline-block">
                  <Button variant="secondary" size="sm">Manage Roles →</Button>
                </a>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Resources & Endpoints</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Model resources like User, Order, Payment; map API endpoints and establish ownership.
                </p>
                <a href="/resources" className="inline-block">
                  <Button variant="secondary" size="sm">Manage Resources →</Button>
                </a>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Recent Projects</CardTitle>
              <a href="/projects">
                <Button variant="default" size="sm">View All</Button>
              </a>
            </CardHeader>
            <CardContent>
              {projects.length === 0 ? (
                <div className="py-8 text-center text-muted-foreground text-sm">
                  No projects created yet. Start by creating a project to model API authorization.
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {projects.slice(0, 5).map((p) => (
                    <div key={p.id} className="py-3 flex items-center justify-between">
                      <div>
                        <span className="font-medium text-sm">{p.name}</span>
                        <span className="ml-2 text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground uppercase font-mono">
                          {p.environment}
                        </span>
                      </div>
                      <div className="flex gap-2">
                        <a href={`/auth-model?project_id=${p.id}`}>
                          <Button variant="secondary" size="sm">Auth Model</Button>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
