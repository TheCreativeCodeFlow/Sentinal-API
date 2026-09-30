"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface ScanProfile {
  id: string;
  name: string;
  profile_type: string;
  status: string;
}

interface SecurityGate {
  id: string;
  name: string;
  status: string;
}

interface SecurityScanSchedule {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "ACTIVE" | "DISABLED" | "EXPIRED";
  scan_profile_id: string;
  security_gate_id: string | null;
  timezone: string;
  schedule_type: "ONCE" | "HOURLY" | "DAILY" | "WEEKLY" | "CRON";
  cron_expression: string | null;
  scheduled_at: string | null;
  start_at: string | null;
  end_at: string | null;
  max_concurrent_runs: number;
  timeout_seconds: number;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
  scan_profile_name?: string | null;
  gate_name?: string | null;
}

interface ScheduledExecution {
  id: string;
  schedule_id: string | null;
  project_id: number;
  execution_plan_id: string | null;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED" | "SKIPPED";
  trigger_type: "SCHEDULED" | "MANUAL" | "RETRY";
  scheduled_for: string | null;
  started_at: string | null;
  completed_at: string | null;
  baseline_comparison_id: string | null;
  gate_evaluation_id: string | null;
  report_id: string | null;
  error_message: string | null;
  created_at: string;
  schedule_name?: string | null;
  execution_plan_name?: string | null;
  gate_verdict?: string | null;
}

interface SchedulePreview {
  schedule_id: string;
  name: string;
  schedule_type: string;
  timezone: string;
  is_active: boolean;
  is_expired: boolean;
  next_occurrences: string[];
}

const COMMON_TIMEZONES = [
  "UTC",
  "America/New_York",
  "America/Chicago",
  "America/Denver",
  "America/Los_Angeles",
  "Europe/London",
  "Europe/Paris",
  "Europe/Berlin",
  "Asia/Kolkata",
  "Asia/Tokyo",
  "Asia/Singapore",
  "Australia/Sydney",
];

function SecuritySchedulesContent() {
  const searchParams = useSearchParams();
  const preselectedProfileId = searchParams.get("profile_id");

  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [schedules, setSchedules] = useState<SecurityScanSchedule[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [gates, setGates] = useState<SecurityGate[]>([]);
  const [executions, setExecutions] = useState<ScheduledExecution[]>([]);

  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Create / Edit Modal State
  const [showModal, setShowModal] = useState(false);
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [formName, setFormName] = useState("");
  const [formDesc, setFormDesc] = useState("");
  const [formProfileId, setFormProfileId] = useState(preselectedProfileId || "");
  const [formGateId, setFormGateId] = useState("");
  const [formTimezone, setFormTimezone] = useState("UTC");
  const [formScheduleType, setFormScheduleType] = useState<"ONCE" | "HOURLY" | "DAILY" | "WEEKLY" | "CRON">("DAILY");
  const [formCronExpr, setFormCronExpr] = useState("");
  const [formScheduledAt, setFormScheduledAt] = useState("");
  const [formStartAt, setFormStartAt] = useState("");
  const [formEndAt, setFormEndAt] = useState("");
  const [formMaxConcurrent, setFormMaxConcurrent] = useState(1);
  const [formTimeoutSec, setFormTimeoutSec] = useState(600);
  const [saving, setSaving] = useState(false);

  // Preview Modal State
  const [previewData, setPreviewData] = useState<SchedulePreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // Action Loading IDs
  const [runningId, setRunningId] = useState<string | null>(null);

  // Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
        const data: Project[] = await res.json();
        setProjects(data);

        let initialId = data.length > 0 ? data[0].id : null;
        if (typeof window !== "undefined") {
          const stored = localStorage.getItem("selectedProjectId");
          if (stored) {
            const parsed = parseInt(stored, 10);
            if (data.some((p) => p.id === parsed)) {
              initialId = parsed;
            }
          }
        }
        setSelectedProjectId(initialId);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        setErrorMsg(msg);
      }
    }
    loadProjects();
  }, []);

  // Save selectedProjectId
  const handleSelectProject = (id: number) => {
    setSelectedProjectId(id);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  };

  // Load Schedules, Profiles, Gates, and Executions for Project
  useEffect(() => {
    if (!selectedProjectId) return;

    async function loadProjectData() {
      setLoading(true);
      setErrorMsg(null);
      try {
        // Fetch schedules
        const schedRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-scan-schedules`, {
          credentials: "include",
        });
        if (!schedRes.ok) throw new Error("Failed to load security scan schedules");
        const schedData = await schedRes.json();
        setSchedules(schedData.schedules || []);

        // Fetch profiles
        const profRes = await fetch(`/api/v1/projects/${selectedProjectId}/scan-profiles`, {
          credentials: "include",
        });
        if (profRes.ok) {
          const profData = await profRes.json();
          setProfiles(profData.profiles || []);
          if (!formProfileId && profData.profiles?.length > 0) {
            setFormProfileId(profData.profiles[0].id);
          }
        }

        // Fetch gates
        const gateRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-gates`, {
          credentials: "include",
        });
        if (gateRes.ok) {
          const gateData = await gateRes.json();
          setGates(gateData.gates || []);
        }

        // Fetch executions
        const execRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-scheduled-executions?limit=30`, {
          credentials: "include",
        });
        if (execRes.ok) {
          const execData = await execRes.json();
          setExecutions(execData.executions || []);
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        setErrorMsg(msg);
      } finally {
        setLoading(false);
      }
    }

    loadProjectData();
  }, [selectedProjectId, formProfileId]);

  // Open Create Modal
  const openCreateModal = () => {
    setEditingScheduleId(null);
    setFormName("");
    setFormDesc("");
    setFormProfileId(profiles.length > 0 ? profiles[0].id : "");
    setFormGateId("");
    setFormTimezone("UTC");
    setFormScheduleType("DAILY");
    setFormCronExpr("");
    setFormScheduledAt("");
    setFormStartAt("");
    setFormEndAt("");
    setFormMaxConcurrent(1);
    setFormTimeoutSec(600);
    setShowModal(true);
  };

  // Open Edit Modal
  const openEditModal = (s: SecurityScanSchedule) => {
    setEditingScheduleId(s.id);
    setFormName(s.name);
    setFormDesc(s.description || "");
    setFormProfileId(s.scan_profile_id);
    setFormGateId(s.security_gate_id || "");
    setFormTimezone(s.timezone);
    setFormScheduleType(s.schedule_type);
    setFormCronExpr(s.cron_expression || "");
    setFormScheduledAt(s.scheduled_at ? s.scheduled_at.slice(0, 16) : "");
    setFormStartAt(s.start_at ? s.start_at.slice(0, 16) : "");
    setFormEndAt(s.end_at ? s.end_at.slice(0, 16) : "");
    setFormMaxConcurrent(s.max_concurrent_runs);
    setFormTimeoutSec(s.timeout_seconds);
    setShowModal(true);
  };

  // Save Schedule
  const handleSaveSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    if (!formName.trim()) {
      setErrorMsg("Schedule name is required");
      return;
    }
    if (!formProfileId) {
      setErrorMsg("Scan profile is required");
      return;
    }

    setSaving(true);
    setErrorMsg(null);
    try {
      const payload: Record<string, unknown> = {
        name: formName.trim(),
        description: formDesc.trim() || null,
        scan_profile_id: formProfileId,
        security_gate_id: formGateId || null,
        timezone: formTimezone,
        schedule_type: formScheduleType,
        cron_expression: formScheduleType === "CRON" ? formCronExpr.trim() || null : null,
        scheduled_at: formScheduleType === "ONCE" && formScheduledAt ? new Date(formScheduledAt).toISOString() : null,
        start_at: formStartAt ? new Date(formStartAt).toISOString() : null,
        end_at: formEndAt ? new Date(formEndAt).toISOString() : null,
        max_concurrent_runs: Number(formMaxConcurrent),
        timeout_seconds: Number(formTimeoutSec),
      };

      let res;
      if (editingScheduleId) {
        res = await fetch(`/api/v1/security-scan-schedules/${editingScheduleId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          credentials: "include",
        });
      } else {
        payload.status = "ACTIVE";
        res = await fetch(`/api/v1/projects/${selectedProjectId}/security-scan-schedules`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          credentials: "include",
        });
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to save security scan schedule");
      }

      setSuccessMsg(editingScheduleId ? "Schedule updated successfully" : "Schedule created successfully");
      setShowModal(false);

      // Refresh list
      const refreshRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-scan-schedules`, {
        credentials: "include",
      });
      if (refreshRes.ok) {
        const refreshed = await refreshRes.json();
        setSchedules(refreshed.schedules || []);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
    } finally {
      setSaving(false);
    }
  };

  // Delete Schedule
  const handleDeleteSchedule = async (scheduleId: string, name: string) => {
    if (!confirm(`Are you sure you want to delete scan schedule "${name}"? Historical execution records will be preserved.`)) {
      return;
    }

    try {
      const res = await fetch(`/api/v1/security-scan-schedules/${scheduleId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete schedule");

      setSuccessMsg(`Schedule "${name}" deleted.`);
      setSchedules((prev) => prev.filter((s) => s.id !== scheduleId));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
    }
  };

  // Toggle Enable / Disable
  const handleToggleStatus = async (schedule: SecurityScanSchedule) => {
    const action = schedule.status === "ACTIVE" ? "disable" : "enable";
    try {
      const res = await fetch(`/api/v1/security-scan-schedules/${schedule.id}/${action}`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) throw new Error(`Failed to ${action} schedule`);

      const updated: SecurityScanSchedule = await res.json();
      setSchedules((prev) => prev.map((s) => (s.id === updated.id ? updated : s)));
      setSuccessMsg(`Schedule "${schedule.name}" is now ${updated.status}.`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
    }
  };

  // Run Now (Immediate execution)
  const handleRunNow = async (scheduleId: string, name: string) => {
    setRunningId(scheduleId);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/v1/security-scan-schedules/${scheduleId}/run`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to trigger scan execution");
      }

      const execRecord: ScheduledExecution = await res.json();
      setSuccessMsg(`Manual scan run triggered for "${name}" (Status: ${execRecord.status}).`);

      // Refresh executions & schedules
      if (selectedProjectId) {
        const execRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-scheduled-executions?limit=30`, {
          credentials: "include",
        });
        if (execRes.ok) {
          const execData = await execRes.json();
          setExecutions(execData.executions || []);
        }
        const schedRes = await fetch(`/api/v1/projects/${selectedProjectId}/security-scan-schedules`, {
          credentials: "include",
        });
        if (schedRes.ok) {
          const schedData = await schedRes.json();
          setSchedules(schedData.schedules || []);
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
    } finally {
      setRunningId(null);
    }
  };

  // Preview Schedule
  const handleOpenPreview = async (scheduleId: string) => {
    setPreviewLoading(true);
    setPreviewData(null);
    try {
      const res = await fetch(`/api/v1/security-scan-schedules/${scheduleId}/preview?count=5`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to calculate schedule preview");
      const data: SchedulePreview = await res.json();
      setPreviewData(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
    } finally {
      setPreviewLoading(false);
    }
  };

  // Filtered schedules
  const filteredSchedules = schedules.filter((s) => {
    if (statusFilter !== "ALL" && s.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scheduled & Continuous Security Scanning</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Automate recurring API security scans, evaluate CI/CD regression gates, and build evidence packages.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Project Selector */}
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-muted-foreground">Project:</span>
            <select
              value={selectedProjectId || ""}
              onChange={(e) => handleSelectProject(Number(e.target.value))}
              className="bg-card border border-border rounded-lg px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-2 focus:ring-primary"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.authorization_status})
                </option>
              ))}
            </select>
          </div>

          <Button onClick={openCreateModal} className="shrink-0">
            Create Schedule
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="bg-destructive/15 border border-destructive/30 text-destructive text-sm p-4 rounded-xl flex items-center justify-between">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-xs underline font-semibold ml-4">
            Dismiss
          </button>
        </div>
      )}
      {successMsg && (
        <div className="bg-emerald-500/15 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-sm p-4 rounded-xl flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-xs underline font-semibold ml-4">
            Dismiss
          </button>
        </div>
      )}

      {/* Status Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        {["ALL", "ACTIVE", "DISABLED", "EXPIRED"].map((status) => (
          <button
            key={status}
            onClick={() => setStatusFilter(status)}
            className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
              statusFilter === status
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
            }`}
          >
            {status}
          </button>
        ))}
      </div>

      {/* Schedules Table */}
      <Card className="border-border">
        <CardContent className="p-0">
          {loading ? (
            <div className="p-8 text-center text-sm text-muted-foreground">Loading schedules...</div>
          ) : filteredSchedules.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No security scan schedules found for this project.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="bg-accent/40 text-muted-foreground text-xs uppercase border-b border-border">
                  <tr>
                    <th className="px-4 py-3">Schedule Name</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Recurrence</th>
                    <th className="px-4 py-3">Timezone</th>
                    <th className="px-4 py-3">Next Run (UTC)</th>
                    <th className="px-4 py-3">Scan Profile</th>
                    <th className="px-4 py-3">Gate</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredSchedules.map((s) => (
                    <tr key={s.id} className="hover:bg-accent/20 transition-colors">
                      <td className="px-4 py-3 font-medium">
                        <div>{s.name}</div>
                        {s.description && (
                          <div className="text-xs text-muted-foreground truncate max-w-xs">{s.description}</div>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${
                            s.status === "ACTIVE"
                              ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"
                              : s.status === "EXPIRED"
                              ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"
                              : "bg-muted text-muted-foreground border border-border"
                          }`}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-semibold text-xs">{s.schedule_type}</span>
                        {s.cron_expression && (
                          <div className="text-xs font-mono text-muted-foreground">{s.cron_expression}</div>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground font-mono">{s.timezone}</td>
                      <td className="px-4 py-3 text-xs">
                        {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "-"}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {s.scan_profile_name ? (
                          <span className="font-medium">{s.scan_profile_name}</span>
                        ) : (
                          <span className="font-mono text-muted-foreground">{s.scan_profile_id.slice(0, 8)}...</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {s.gate_name ? (
                          <span className="font-medium">{s.gate_name}</span>
                        ) : s.security_gate_id ? (
                          <span className="font-mono text-muted-foreground">{s.security_gate_id.slice(0, 8)}...</span>
                        ) : (
                          <span className="text-muted-foreground italic">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleRunNow(s.id, s.name)}
                            disabled={runningId === s.id}
                            className="h-7 text-xs"
                          >
                            {runningId === s.id ? "Running..." : "Run Now"}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleOpenPreview(s.id)}
                            className="h-7 text-xs"
                          >
                            Preview
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleToggleStatus(s)}
                            className="h-7 text-xs"
                          >
                            {s.status === "ACTIVE" ? "Disable" : "Enable"}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => openEditModal(s)}
                            className="h-7 text-xs"
                          >
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="destructive"
                            onClick={() => handleDeleteSchedule(s.id, s.name)}
                            className="h-7 text-xs"
                          >
                            Delete
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Execution History Section */}
      <div className="space-y-4 pt-4">
        <div>
          <h2 className="text-lg font-bold tracking-tight">Recent Scheduled Executions</h2>
          <p className="text-xs text-muted-foreground">
            Complete lineage trail from trigger to execution plan, gate evaluation, and generated report.
          </p>
        </div>

        <Card className="border-border">
          <CardContent className="p-0">
            {executions.length === 0 ? (
              <div className="p-6 text-center text-sm text-muted-foreground">
                No scheduled executions recorded yet for this project.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead className="bg-accent/40 text-muted-foreground text-xs uppercase border-b border-border">
                    <tr>
                      <th className="px-4 py-3">Execution ID</th>
                      <th className="px-4 py-3">Schedule</th>
                      <th className="px-4 py-3">Trigger</th>
                      <th className="px-4 py-3">Status</th>
                      <th className="px-4 py-3">Started (UTC)</th>
                      <th className="px-4 py-3">Execution Plan</th>
                      <th className="px-4 py-3">Gate Verdict</th>
                      <th className="px-4 py-3">Report</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {executions.map((e) => (
                      <tr key={e.id} className="hover:bg-accent/20 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs">{e.id.slice(0, 8)}...</td>
                        <td className="px-4 py-3 text-xs font-medium">
                          {e.schedule_name || (e.schedule_id ? e.schedule_id.slice(0, 8) : "Deleted Schedule")}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          <span className="font-semibold text-muted-foreground">{e.trigger_type}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${
                              e.status === "COMPLETED"
                                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20"
                                : e.status === "RUNNING"
                                ? "bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20 animate-pulse"
                                : e.status === "SKIPPED"
                                ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20"
                                : e.status === "FAILED"
                                ? "bg-destructive/10 text-destructive border border-destructive/20"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {e.status}
                          </span>
                          {e.error_message && (
                            <div className="text-[11px] text-destructive mt-0.5 max-w-xs truncate" title={e.error_message}>
                              {e.error_message}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {e.started_at ? new Date(e.started_at).toLocaleString() : "-"}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {e.execution_plan_id ? (
                            <Link
                              href={`/execution-plans?plan_id=${e.execution_plan_id}`}
                              className="text-primary hover:underline font-medium"
                            >
                              {e.execution_plan_name || e.execution_plan_id.slice(0, 8)}
                            </Link>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {e.gate_verdict ? (
                            <span
                              className={`font-bold ${
                                e.gate_verdict === "PASS"
                                  ? "text-emerald-600 dark:text-emerald-400"
                                  : e.gate_verdict === "WARN"
                                  ? "text-amber-600 dark:text-amber-400"
                                  : "text-destructive"
                              }`}
                            >
                              {e.gate_verdict}
                            </span>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {e.report_id ? (
                            <Link
                              href={`/security-reports?report_id=${e.report_id}`}
                              className="text-primary hover:underline font-medium"
                            >
                              View Report
                            </Link>
                          ) : (
                            "-"
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Create / Edit Schedule Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-card border border-border rounded-xl max-w-xl w-full p-6 shadow-xl space-y-4 my-8">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h2 className="text-lg font-bold">
                {editingScheduleId ? "Edit Scan Schedule" : "Create Security Scan Schedule"}
              </h2>
              <button onClick={() => setShowModal(false)} className="text-muted-foreground hover:text-foreground">
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveSchedule} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold">Schedule Name *</label>
                <Input
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="e.g. Nightly OWASP Regression Scan"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold">Description</label>
                <Input
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                  placeholder="Optional scan description"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Scan Profile *</label>
                  <select
                    value={formProfileId}
                    onChange={(e) => setFormProfileId(e.target.value)}
                    required
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="" disabled>Select Profile</option>
                    {profiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.profile_type})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold">Security Gate (Optional)</label>
                  <select
                    value={formGateId}
                    onChange={(e) => setFormGateId(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="">None (Scan Only)</option>
                    {gates.map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name} ({g.status})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Recurrence Type *</label>
                  <select
                    value={formScheduleType}
                    onChange={(e) => setFormScheduleType(e.target.value as "ONCE" | "HOURLY" | "DAILY" | "WEEKLY" | "CRON")}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary"
                  >
                    <option value="HOURLY">Hourly (0 * * * *)</option>
                    <option value="DAILY">Daily at Midnight (0 0 * * *)</option>
                    <option value="WEEKLY">Weekly on Sunday (0 0 * * 0)</option>
                    <option value="CRON">Custom Cron Expression</option>
                    <option value="ONCE">Run Once</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold">Timezone *</label>
                  <select
                    value={formTimezone}
                    onChange={(e) => setFormTimezone(e.target.value)}
                    className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-hidden focus:ring-2 focus:ring-primary font-mono text-xs"
                  >
                    {COMMON_TIMEZONES.map((tz) => (
                      <option key={tz} value={tz}>
                        {tz}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {formScheduleType === "CRON" && (
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Standard 5-part Cron Expression *</label>
                  <Input
                    value={formCronExpr}
                    onChange={(e) => setFormCronExpr(e.target.value)}
                    placeholder="e.g. 0 2 * * 1-5 (Weekdays at 2:00 AM)"
                    required
                    className="font-mono text-xs"
                  />
                  <span className="text-[11px] text-muted-foreground">minute hour day-of-month month day-of-week</span>
                </div>
              )}

              {formScheduleType === "ONCE" && (
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Scheduled Run Time *</label>
                  <Input
                    type="datetime-local"
                    value={formScheduledAt}
                    onChange={(e) => setFormScheduledAt(e.target.value)}
                    required
                  />
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Start Window (Optional)</label>
                  <Input
                    type="datetime-local"
                    value={formStartAt}
                    onChange={(e) => setFormStartAt(e.target.value)}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-semibold">End Window / Expire At (Optional)</label>
                  <Input
                    type="datetime-local"
                    value={formEndAt}
                    onChange={(e) => setFormEndAt(e.target.value)}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Max Concurrent Runs</label>
                  <Input
                    type="number"
                    min={1}
                    max={10}
                    value={formMaxConcurrent}
                    onChange={(e) => setFormMaxConcurrent(Number(e.target.value))}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-semibold">Timeout Seconds</label>
                  <Input
                    type="number"
                    min={30}
                    max={86400}
                    value={formTimeoutSec}
                    onChange={(e) => setFormTimeoutSec(Number(e.target.value))}
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 border-t border-border pt-4">
                <Button type="button" variant="outline" onClick={() => setShowModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={saving}>
                  {saving ? "Saving..." : editingScheduleId ? "Update Schedule" : "Create Schedule"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {(previewLoading || previewData) && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-md w-full p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h2 className="text-base font-bold">Upcoming Occurrences Preview</h2>
              <button
                onClick={() => {
                  setPreviewData(null);
                  setPreviewLoading(false);
                }}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>

            {previewLoading ? (
              <div className="p-8 text-center text-sm text-muted-foreground">Calculating next run times...</div>
            ) : previewData ? (
              <div className="space-y-3">
                <div className="text-xs space-y-1 bg-accent/30 p-3 rounded-lg">
                  <div><span className="font-semibold">Schedule:</span> {previewData.name}</div>
                  <div><span className="font-semibold">Type:</span> {previewData.schedule_type}</div>
                  <div><span className="font-semibold">Timezone:</span> <span className="font-mono">{previewData.timezone}</span></div>
                  <div>
                    <span className="font-semibold">Status:</span>{" "}
                    {previewData.is_expired ? "Expired" : previewData.is_active ? "Active" : "Disabled"}
                  </div>
                </div>

                <div className="border border-border rounded-lg overflow-hidden">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-accent/40 text-muted-foreground uppercase border-b border-border">
                      <tr>
                        <th className="px-3 py-2">#</th>
                        <th className="px-3 py-2">Scheduled Run Time (UTC)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {previewData.next_occurrences.length === 0 ? (
                        <tr>
                          <td colSpan={2} className="px-3 py-3 text-center text-muted-foreground">
                            No upcoming runs scheduled (expired or past end window).
                          </td>
                        </tr>
                      ) : (
                        previewData.next_occurrences.map((occ, idx) => (
                          <tr key={idx}>
                            <td className="px-3 py-2 font-mono text-muted-foreground">{idx + 1}</td>
                            <td className="px-3 py-2 font-mono font-medium">
                              {new Date(occ).toLocaleString()} ({new Date(occ).toISOString()})
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="flex justify-end pt-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setPreviewData(null);
                      setPreviewLoading(false);
                    }}
                  >
                    Close
                  </Button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecuritySchedulesPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-muted-foreground">Loading Scan Schedules...</div>}>
      <SecuritySchedulesContent />
    </Suspense>
  );
}
