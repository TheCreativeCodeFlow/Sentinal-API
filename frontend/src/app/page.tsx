"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
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
            API Authorization & Controlled BOLA Security Testing Platform
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/security-tests">
            <Button variant="default">Run BOLA Tests</Button>
          </Link>
          <Link href="/findings">
            <Button variant="secondary">View Findings</Button>
          </Link>
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
                  Authorized Targets
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-emerald-600 dark:text-emerald-400">
                  {projects.filter((p) => p.authorization_status.toLowerCase() === "authorized").length}
                </div>
                <p className="text-xs text-muted-foreground mt-1">Ready for security probes</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  BOLA Engine
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">Active</div>
                <p className="text-xs text-muted-foreground mt-1">Stage 3 Controlled Engine</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Secret Protection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-purple-600 dark:text-purple-400">Strict</div>
                <p className="text-xs text-muted-foreground mt-1">Masked headers & transcripts</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Security Tests</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Execute controlled Broken Object Level Authorization (BOLA) probes with baseline comparisons.
                </p>
                <Link href="/security-tests" className="inline-block">
                  <Button variant="secondary" size="sm">Configure Tests →</Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Findings & Evidence</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Review confirmed authorization vulnerabilities with redacted transcripts and replay action.
                </p>
                <Link href="/findings" className="inline-block">
                  <Button variant="secondary" size="sm">Inspect Findings →</Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Auth Model</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Inspect the structural Identity → Role → Resource and endpoint authorization topology.
                </p>
                <Link href="/auth-model" className="inline-block">
                  <Button variant="secondary" size="sm">View Hierarchy →</Button>
                </Link>
              </CardContent>
            </Card>

            <Card className="hover:border-primary/50 transition-colors">
              <CardHeader>
                <CardTitle className="text-base font-semibold">Identities & Roles</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Manage principals, credential rotation, and access roles for security evaluation.
                </p>
                <Link href="/identities" className="inline-block">
                  <Button variant="secondary" size="sm">Manage Users →</Button>
                </Link>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg">Recent Projects</CardTitle>
              <Link href="/projects">
                <Button variant="default" size="sm">View All</Button>
              </Link>
            </CardHeader>
            <CardContent>
              {projects.length === 0 ? (
                <div className="py-8 text-center text-muted-foreground text-sm">
                  No projects created yet. Start by creating an authorized project to test API authorization.
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
                        <span
                          className={`ml-2 text-xs px-2 py-0.5 rounded-full font-mono ${
                            p.authorization_status.toLowerCase() === "authorized"
                              ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                              : "bg-amber-500/20 text-amber-700 dark:text-amber-300"
                          }`}
                        >
                          {p.authorization_status}
                        </span>
                      </div>
                      <div className="flex gap-2">
                        <Link href={`/security-tests`}>
                          <Button variant="secondary" size="sm">Test BOLA</Button>
                        </Link>
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
