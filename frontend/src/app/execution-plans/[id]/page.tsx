"use client";

import React, { useEffect, useState, use } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

interface ExecutionItem {
  id: string;
  execution_plan_id: string;
  security_test_id: string;
  execution_order: number;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED" | "CANCELLED";
  test_execution_id?: string | null;
  result?: "PASS" | "CONFIRMED" | "INCONCLUSIVE" | "ERROR" | null;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  test_type?: string | null;
  endpoint?: string | null;
  attacker_identity?: string | null;
}

interface SecurityExecutionPlanDetail {
  id: string;
  project_id: number;
  suite_id?: string | null;
  suite_name?: string | null;
  name: string;
  status: "DRAFT" | "READY" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  execution_mode: "SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE";
  total_tests: number;
  completed_tests: number;
  confirmed_findings: number;
  inconclusive_tests: number;
  failed_tests: number;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  items: ExecutionItem[];
}

export default function ExecutionPlanDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const unwrappedParams = use(params);
  const planId = unwrappedParams.id;
  const router = useRouter();

  const [plan, setPlan] = useState<SecurityExecutionPlanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [isCancelling, setIsCancelling] = useState(false);

  // Initial Load
  useEffect(() => {
    loadPlan();
  }, [planId]);

  // Polling for Progress when plan is RUNNING
  useEffect(() => {
    if (!plan || plan.status !== "RUNNING") return;

    const interval = setInterval(() => {
      fetchProgress();
    }, 2500);

    return () => clearInterval(interval);
  }, [plan?.status, planId]);

  async function loadPlan() {
    try {
      setLoading(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/execution-plans/${planId}`, { credentials: "include" });
      if (!res.ok) {
        if (res.status === 404) throw new Error("Execution plan not found");
        throw new Error("Failed to load execution plan");
      }
      const data: SecurityExecutionPlanDetail = await res.json();
      setPlan(data);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load execution plan");
    } finally {
      setLoading(false);
    }
  }

  async function fetchProgress() {
    try {
      const res = await fetch(`/api/v1/execution-plans/${planId}/progress`, { credentials: "include" });
      if (res.ok) {
        const prog = await res.json();
        setPlan((prev) => {
          if (!prev) return null;
          return {
            ...prev,
            status: prog.status,
            completed_tests: prog.completed_tests,
            total_tests: prog.total_tests,
            items: prog.items,
            started_at: prog.started_at,
            completed_at: prog.completed_at,
          };
        });
      }
    } catch {
      // Non-blocking background poll
    }
  }

  const handleStart = async () => {
    try {
      setIsStarting(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/execution-plans/${planId}/start`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to start execution plan");
      }

      setSuccessMsg("Execution plan started successfully.");
      await loadPlan();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to start execution plan");
    } finally {
      setIsStarting(false);
    }
  };

  const handleCancel = async () => {
    try {
      setIsCancelling(true);
      setErrorMsg(null);
      const res = await fetch(`/api/v1/execution-plans/${planId}/cancel`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to cancel execution plan");
      }

      setSuccessMsg("Execution plan cancelled.");
      await loadPlan();
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to cancel execution plan");
    } finally {
      setIsCancelling(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "RUNNING":
        return "bg-sky-500/10 text-sky-400 border-sky-500/20 animate-pulse";
      case "FAILED":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20";
      case "CANCELLED":
        return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
      case "READY":
        return "bg-blue-500/10 text-blue-400 border-blue-500/20";
      case "SKIPPED":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      default:
        return "bg-muted text-muted-foreground border-border";
    }
  };

  const getResultBadge = (result?: string | null) => {
    if (!result) return null;
    switch (result) {
      case "PASS":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
      case "CONFIRMED":
        return "bg-rose-500/10 text-rose-400 border-rose-500/20 font-bold";
      case "INCONCLUSIVE":
        return "bg-amber-500/10 text-amber-400 border-amber-500/20";
      case "ERROR":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      default:
        return "bg-secondary text-secondary-foreground border-border";
    }
  };

  if (loading && !plan) {
    return (
      <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
        Loading execution plan details...
      </div>
    );
  }

  if (!plan) {
    return (
      <div className="p-12 text-center text-sm text-rose-400 border border-dashed border-rose-500/20 rounded-xl space-y-3">
        <p>{errorMsg || "Execution plan not found."}</p>
        <Button variant="outline" size="sm" onClick={() => router.push("/execution-plans")}>
          ← Back to Execution Plans
        </Button>
      </div>
    );
  }

  const percent = plan.total_tests > 0 ? Math.round((plan.completed_tests / plan.total_tests) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Link href="/execution-plans" className="hover:text-foreground transition-colors">
              Execution Plans
            </Link>
            <span>/</span>
            <span className="text-foreground font-mono truncate max-w-[200px]">{plan.id}</span>
          </div>

          <h1 className="text-2xl font-bold tracking-tight text-foreground flex items-center gap-3">
            {plan.name}
            <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${getStatusBadge(plan.status)}`}>
              {plan.status}
            </span>
          </h1>

          <div className="flex items-center gap-3 text-xs text-muted-foreground pt-0.5 flex-wrap">
            {plan.suite_name && (
              <span>
                Suite: <span className="text-foreground font-medium">{plan.suite_name}</span>
              </span>
            )}
            <span>•</span>
            <span>
              Mode: <span className="font-mono text-foreground font-semibold">{plan.execution_mode}</span>
            </span>
            <span>•</span>
            <span>Created: {new Date(plan.created_at).toLocaleString()}</span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {(plan.status === "DRAFT" || plan.status === "READY") && (
            <Button
              onClick={handleStart}
              disabled={isStarting}
              className="text-xs font-semibold gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {isStarting ? "Starting..." : "Start Execution"}
            </Button>
          )}

          {(plan.status === "RUNNING" || plan.status === "READY") && (
            <Button
              onClick={handleCancel}
              disabled={isCancelling}
              variant="outline"
              className="text-xs font-semibold text-rose-400 hover:bg-rose-500/10 border-rose-500/30"
            >
              {isCancelling ? "Cancelling..." : "Cancel Execution"}
            </Button>
          )}

          <Button variant="outline" size="sm" onClick={() => loadPlan()} className="text-xs gap-1">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Refresh
          </Button>
        </div>
      </div>

      {/* Messages */}
      {errorMsg && (
        <div className="p-3 text-xs bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-muted-foreground hover:text-foreground">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-3 text-xs bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-lg flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-muted-foreground hover:text-foreground">✕</button>
        </div>
      )}

      {/* Progress & Stat Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {/* Progress Card (spanning 2 cols) */}
        <Card className="md:col-span-2 border border-border bg-card/60">
          <CardContent className="p-5 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-muted-foreground uppercase tracking-wider">Overall Progress</span>
              <span className="font-mono text-base font-bold text-foreground">{percent}%</span>
            </div>

            <div className="w-full bg-secondary rounded-full h-3 overflow-hidden">
              <div
                className={`h-3 rounded-full transition-all duration-500 ${
                  plan.status === "COMPLETED"
                    ? "bg-emerald-500"
                    : plan.status === "FAILED"
                    ? "bg-rose-500"
                    : "bg-blue-500"
                }`}
                style={{ width: `${percent}%` }}
              />
            </div>

            <div className="flex justify-between items-center text-[11px] text-muted-foreground">
              <span>{plan.completed_tests} of {plan.total_tests} Tests Executed</span>
              {plan.status === "RUNNING" && <span className="text-sky-400 animate-pulse font-medium">Running...</span>}
            </div>
          </CardContent>
        </Card>

        {/* Confirmed Findings Stat */}
        <Card className="border border-rose-500/20 bg-rose-500/5">
          <CardContent className="p-5 space-y-1">
            <span className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">Confirmed Findings</span>
            <div className="text-2xl font-bold text-rose-400">{plan.confirmed_findings}</div>
            <p className="text-[10px] text-muted-foreground">Exploitable vulnerabilities detected</p>
          </CardContent>
        </Card>

        {/* Inconclusive Stat */}
        <Card className="border border-border bg-card/60">
          <CardContent className="p-5 space-y-1">
            <span className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider">Inconclusive</span>
            <div className="text-2xl font-bold text-amber-400">{plan.inconclusive_tests}</div>
            <p className="text-[10px] text-muted-foreground">Unclear or non-standard responses</p>
          </CardContent>
        </Card>

        {/* Failed / Errors Stat */}
        <Card className="border border-border bg-card/60">
          <CardContent className="p-5 space-y-1">
            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Failed / Errors</span>
            <div className="text-2xl font-bold text-foreground">{plan.failed_tests}</div>
            <p className="text-[10px] text-muted-foreground">Network drops or target crashes</p>
          </CardContent>
        </Card>
      </div>

      {/* Execution Items Table */}
      <Card className="border border-border bg-card/60">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-foreground uppercase tracking-wider">
            Execution Sequence ({plan.items.length} tests)
          </h2>
          <span className="text-xs text-muted-foreground">
            Strict deterministic ordering • Safe GET/HEAD execution
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-secondary/40 text-muted-foreground border-b border-border uppercase font-semibold text-[10px] tracking-wider">
              <tr>
                <th className="py-3 px-4">#</th>
                <th className="py-3 px-4">Test Type</th>
                <th className="py-3 px-4">Target Endpoint</th>
                <th className="py-3 px-4">Attacker Identity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {plan.items.map((item) => (
                <tr key={item.id} className="hover:bg-accent/10 transition-colors">
                  <td className="py-3 px-4 font-mono font-bold text-foreground">
                    {item.execution_order}
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono font-semibold">
                      {item.test_type || "TEST"}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-foreground truncate max-w-[280px]">
                    {item.endpoint || "Custom Endpoint"}
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">
                    {item.attacker_identity ? (
                      <span className="text-foreground font-medium">{item.attacker_identity}</span>
                    ) : (
                      "N/A"
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getStatusBadge(item.status)}`}>
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {item.result ? (
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getResultBadge(item.result)}`}>
                        {item.result}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/60">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">
                    {item.error_message ? (
                      <span className="text-rose-400 text-[11px] truncate max-w-[200px] block" title={item.error_message}>
                        {item.error_message}
                      </span>
                    ) : item.test_execution_id ? (
                      <span className="text-[11px] font-mono text-muted-foreground">
                        Exec: {item.test_execution_id.slice(0, 8)}...
                      </span>
                    ) : (
                      <span className="text-muted-foreground/60 text-[11px]">Queued</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
