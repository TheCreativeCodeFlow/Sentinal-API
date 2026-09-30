"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
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
  project_id: number;
  name: string;
  description: string | null;
  profile_type: "QUICK" | "STANDARD" | "DEEP" | "CUSTOM";
  status: "ACTIVE" | "DISABLED";
  configuration: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface TestSelectionReason {
  security_test_id: string;
  test_type: string;
  endpoint: string | null;
  priority: number;
  reason: string;
}

interface ScanProfilePreview {
  profile_id: string;
  profile_name: string;
  profile_type: string;
  selected_test_count: number;
  selected_tests: TestSelectionReason[];
}

interface CreatedExecutionPlan {
  id: string;
  name: string;
  total_tests: number;
}

export default function ScanProfilesPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Filter
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  // Create Profile Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [profileType, setProfileType] = useState<"QUICK" | "STANDARD" | "DEEP" | "CUSTOM">("STANDARD");
  const [profileStatus, setProfileStatus] = useState<"ACTIVE" | "DISABLED">("ACTIVE");
  const [allowedTypes, setAllowedTypes] = useState<string[]>(["BOLA", "BFLA", "AUTH_MISSING"]);
  const [maxTests, setMaxTests] = useState<number>(25);
  const [creating, setCreating] = useState(false);

  // Preview Modal
  const [previewProfile, setPreviewProfile] = useState<ScanProfile | null>(null);
  const [previewData, setPreviewData] = useState<ScanProfilePreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // Generate Plan Modal
  const [planProfile, setPlanProfile] = useState<ScanProfile | null>(null);
  const [planName, setPlanName] = useState("");
  const [executionMode, setExecutionMode] = useState<"SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE">("SEQUENTIAL");
  const [generatingPlan, setGeneratingPlan] = useState(false);

  // Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch projects");
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
        setErrorMsg(err instanceof Error ? err.message : "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  // Load Profiles when Project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    loadProfiles(selectedProjectId);
  }, [selectedProjectId]);

  async function loadProfiles(projectId: number) {
    setLoading(true);
    setErrorMsg(null);
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/scan-profiles`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to fetch scan profiles");
      const data = await res.json();
      setProfiles(data.profiles || []);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to fetch scan profiles");
    } finally {
      setLoading(false);
    }
  }

  function handleProjectChange(id: number) {
    setSelectedProjectId(id);
    if (typeof window !== "undefined") {
      localStorage.setItem("selectedProjectId", id.toString());
    }
  }

  // Create Profile Handler
  async function handleCreateProfile(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedProjectId || !name.trim()) return;

    setCreating(true);
    setErrorMsg(null);

    const config: Record<string, unknown> = {};
    if (profileType === "CUSTOM") {
      config.allowed_test_types = allowedTypes;
      if (maxTests > 0) config.max_tests = maxTests;
    }

    try {
      const res = await fetch(`/api/v1/projects/${selectedProjectId}/scan-profiles`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || null,
          profile_type: profileType,
          status: profileStatus,
          configuration: config,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Failed to create scan profile");
      }

      setSuccessMsg(`Scan profile '${name}' created successfully.`);
      setShowCreateModal(false);
      setName("");
      setDescription("");
      loadProfiles(selectedProjectId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Error creating scan profile");
    } finally {
      setCreating(false);
    }
  }

  // Toggle Profile Status
  async function handleToggleStatus(profile: ScanProfile) {
    const newStatus = profile.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
    try {
      const res = await fetch(`/api/v1/scan-profiles/${profile.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update profile status");
      setProfiles((prev) =>
        prev.map((p) => (p.id === profile.id ? { ...p, status: newStatus } : p))
      );
      setSuccessMsg(`Profile status changed to ${newStatus}.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to toggle status");
    }
  }

  // Delete Profile
  async function handleDeleteProfile(profileId: string) {
    if (!confirm("Are you sure you want to delete this scan profile?")) return;
    try {
      const res = await fetch(`/api/v1/scan-profiles/${profileId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete profile");
      setProfiles((prev) => prev.filter((p) => p.id !== profileId));
      setSuccessMsg("Scan profile deleted successfully.");
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to delete profile");
    }
  }

  // Open Preview Modal
  async function handleOpenPreview(profile: ScanProfile) {
    setPreviewProfile(profile);
    setPreviewLoading(true);
    setPreviewData(null);
    try {
      const res = await fetch(`/api/v1/scan-profiles/${profile.id}/preview`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to load profile preview");
      const data: ScanProfilePreview = await res.json();
      setPreviewData(data);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load preview");
    } finally {
      setPreviewLoading(false);
    }
  }

  // Open Plan Generation Modal
  function handleOpenPlanModal(profile: ScanProfile) {
    setPlanProfile(profile);
    setPlanName(`${profile.name} - Plan`);
    setExecutionMode("SEQUENTIAL");
  }

  // Generate Plan Handler
  async function handleGeneratePlan(e: React.FormEvent) {
    e.preventDefault();
    if (!planProfile) return;

    setGeneratingPlan(true);
    setErrorMsg(null);

    try {
      const res = await fetch(`/api/v1/scan-profiles/${planProfile.id}/create-plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: planName.trim(),
          execution_mode: executionMode,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to create execution plan");
      }

      const created: CreatedExecutionPlan = await res.json();
      setSuccessMsg(`Execution plan '${created.name}' created with ${created.total_tests} tests.`);
      setPlanProfile(null);
      router.push(`/execution-plans/${created.id}`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create execution plan");
    } finally {
      setGeneratingPlan(false);
    }
  }

  const filteredProfiles = profiles.filter((p) => {
    if (typeFilter !== "ALL" && p.profile_type !== typeFilter) return false;
    if (statusFilter !== "ALL" && p.status !== statusFilter) return false;
    return true;
  });

  function getTypeBadge(t: string) {
    switch (t) {
      case "QUICK":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "STANDARD":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      case "DEEP":
        return "bg-purple-500/10 text-purple-400 border-purple-500/30";
      case "CUSTOM":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      default:
        return "bg-secondary text-secondary-foreground border-border";
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-foreground">Scan Profiles</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Deterministic security scan templates and automated test selection criteria.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Project Selector */}
          <select
            value={selectedProjectId || ""}
            onChange={(e) => handleProjectChange(Number(e.target.value))}
            className="h-9 px-3 text-xs bg-background border border-border rounded-lg text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>

          <Button
            onClick={() => setShowCreateModal(true)}
            disabled={!selectedProjectId}
            className="h-9 text-xs font-semibold gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
            </svg>
            New Scan Profile
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

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <span>Type:</span>
          {["ALL", "QUICK", "STANDARD", "DEEP", "CUSTOM"].map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                typeFilter === t
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary/60 text-muted-foreground hover:text-foreground"
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1.5 text-xs text-muted-foreground ml-auto">
          <span>Status:</span>
          {["ALL", "ACTIVE", "DISABLED"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                statusFilter === s
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary/60 text-muted-foreground hover:text-foreground"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Profiles Grid */}
      {loading ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
          Loading scan profiles...
        </div>
      ) : filteredProfiles.length === 0 ? (
        <div className="p-12 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl space-y-3">
          <p>No scan profiles match your criteria.</p>
          <Button size="sm" variant="outline" onClick={() => setShowCreateModal(true)}>
            Create Scan Profile
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredProfiles.map((p) => (
            <Card key={p.id} className="border border-border bg-card/60 flex flex-col justify-between">
              <CardContent className="p-5 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-foreground line-clamp-1">{p.name}</h3>
                    {p.description && (
                      <p className="text-xs text-muted-foreground line-clamp-2">{p.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getTypeBadge(p.profile_type)}`}>
                      {p.profile_type}
                    </span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                        p.status === "ACTIVE"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                          : "bg-secondary text-muted-foreground border-border"
                      }`}
                    >
                      {p.status}
                    </span>
                  </div>
                </div>

                {/* Profile Heuristics summary */}
                <div className="text-[11px] text-muted-foreground bg-secondary/30 p-2.5 rounded-lg border border-border/50 space-y-1">
                  {p.profile_type === "QUICK" && (
                    <p>• Prioritizes Authentication & Authorization (BOLA, BFLA). Excludes deep multi-step workflows.</p>
                  )}
                  {p.profile_type === "STANDARD" && (
                    <p>• Balanced verification: Auth, BOLA, BFLA, Property Exposure, and state bypass checks.</p>
                  )}
                  {p.profile_type === "DEEP" && (
                    <p>• Exhaustive coverage of all attack surfaces, multi-step workflows, and property exposures.</p>
                  )}
                  {p.profile_type === "CUSTOM" && (
                    <p>• Custom rules configured: {JSON.stringify(p.configuration)}</p>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="pt-2 border-t border-border flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-8 text-xs px-2.5"
                      onClick={() => handleOpenPreview(p)}
                    >
                      Preview Tests
                    </Button>
                    <Button
                      size="sm"
                      variant="default"
                      disabled={p.status === "DISABLED"}
                      className="h-8 text-xs px-2.5 bg-primary text-primary-foreground"
                      onClick={() => handleOpenPlanModal(p)}
                    >
                      Create Plan
                    </Button>
                  </div>

                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => handleToggleStatus(p)}
                      title={p.status === "ACTIVE" ? "Disable Profile" : "Enable Profile"}
                      className="p-1.5 text-muted-foreground hover:text-foreground hover:bg-secondary rounded-md"
                    >
                      <span className="text-xs">{p.status === "ACTIVE" ? "⏸" : "▶"}</span>
                    </button>
                    <button
                      onClick={() => handleDeleteProfile(p.id)}
                      title="Delete Profile"
                      className="p-1.5 text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded-md"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* CREATE PROFILE MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 space-y-5 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-base font-bold text-foreground">Create Scan Profile</h3>
              <button onClick={() => setShowCreateModal(false)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleCreateProfile} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Profile Name</label>
                <Input
                  required
                  placeholder="e.g. Nightly Core Scan"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="h-9 text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Description (Optional)</label>
                <textarea
                  rows={2}
                  placeholder="Describe scan scope and objectives..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full text-xs p-2.5 rounded-lg border border-border bg-background text-foreground"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">Profile Type</label>
                  <select
                    value={profileType}
                    onChange={(e) => setProfileType(e.target.value as "QUICK" | "STANDARD" | "DEEP" | "CUSTOM")}
                    className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                  >
                    <option value="QUICK">QUICK (Auth + BOLA/BFLA)</option>
                    <option value="STANDARD">STANDARD (Balanced Audit)</option>
                    <option value="DEEP">DEEP (Full Exhaustive Surface)</option>
                    <option value="CUSTOM">CUSTOM (Rule-driven)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-foreground">Status</label>
                  <select
                    value={profileStatus}
                    onChange={(e) => setProfileStatus(e.target.value as "ACTIVE" | "DISABLED")}
                    className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                  >
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="DISABLED">DISABLED</option>
                  </select>
                </div>
              </div>

              {profileType === "CUSTOM" && (
                <div className="p-3 bg-secondary/30 border border-border rounded-lg space-y-3">
                  <p className="text-xs font-semibold text-foreground">Custom Filter Options</p>
                  <div className="space-y-1">
                    <label className="text-[11px] text-muted-foreground">Allowed Test Types (comma separated)</label>
                    <Input
                      value={allowedTypes.join(", ")}
                      onChange={(e) =>
                        setAllowedTypes(
                          e.target.value
                            .split(",")
                            .map((t) => t.trim())
                            .filter(Boolean)
                        )
                      }
                      className="h-8 text-xs font-mono"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[11px] text-muted-foreground">Max Tests Limit</label>
                    <Input
                      type="number"
                      value={maxTests}
                      onChange={(e) => setMaxTests(parseInt(e.target.value, 10) || 0)}
                      className="h-8 text-xs"
                    />
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
                <Button type="button" variant="outline" size="sm" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" disabled={creating} className="bg-primary text-primary-foreground">
                  {creating ? "Creating..." : "Create Profile"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* PREVIEW TESTS MODAL */}
      {previewProfile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-xl">
            <div className="flex items-center justify-between p-5 border-b border-border">
              <div>
                <h3 className="text-base font-bold text-foreground">
                  Preview Selected Tests: {previewProfile.name}
                </h3>
                <p className="text-xs text-muted-foreground">
                  Deterministic read-only evaluation. Zero target HTTP calls executed.
                </p>
              </div>
              <button onClick={() => setPreviewProfile(null)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <div className="p-5 overflow-y-auto space-y-3 flex-1">
              {previewLoading ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  Evaluating test selection criteria...
                </div>
              ) : !previewData || previewData.selected_tests.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                  No tests matched by this profile in the current project.
                </div>
              ) : (
                <>
                  <div className="flex items-center justify-between text-xs text-muted-foreground pb-2 border-b border-border">
                    <span>
                      Total Tests Selected: <strong className="text-foreground">{previewData.selected_test_count}</strong>
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getTypeBadge(previewData.profile_type)}`}>
                      {previewData.profile_type}
                    </span>
                  </div>

                  <div className="space-y-2">
                    {previewData.selected_tests.map((item, idx) => (
                      <div
                        key={item.security_test_id}
                        className="p-3 bg-secondary/20 border border-border rounded-lg flex items-start justify-between gap-3 text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] bg-secondary px-1.5 py-0.5 rounded font-bold text-muted-foreground">
                              #{idx + 1}
                            </span>
                            <span className="font-bold text-foreground">{item.test_type}</span>
                            <span className="text-[11px] text-muted-foreground font-mono">{item.endpoint || "N/A"}</span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">{item.reason}</p>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-secondary rounded text-secondary-foreground font-semibold shrink-0">
                          Priority {item.priority}
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>

            <div className="p-4 border-t border-border flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">
                All tests will execute strictly via SentinelAPI deterministic test runner.
              </span>
              <Button size="sm" variant="outline" onClick={() => setPreviewProfile(null)}>
                Close Preview
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* GENERATE PLAN MODAL */}
      {planProfile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-base font-bold text-foreground">Create Plan from Profile</h3>
              <button onClick={() => setPlanProfile(null)} className="text-muted-foreground hover:text-foreground">✕</button>
            </div>

            <form onSubmit={handleGeneratePlan} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Execution Plan Name</label>
                <Input
                  required
                  value={planName}
                  onChange={(e) => setPlanName(e.target.value)}
                  className="h-9 text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-foreground">Execution Mode</label>
                <select
                  value={executionMode}
                  onChange={(e) =>
                    setExecutionMode(
                      e.target.value as "SEQUENTIAL" | "FAIL_FAST" | "CONTINUE_ON_FAILURE"
                    )
                  }
                  className="w-full h-9 px-2 text-xs bg-background border border-border rounded-lg text-foreground"
                >
                  <option value="SEQUENTIAL">SEQUENTIAL (Ordered deterministic run)</option>
                  <option value="FAIL_FAST">FAIL_FAST (Halt immediately on first confirmed vulnerability)</option>
                  <option value="CONTINUE_ON_FAILURE">CONTINUE_ON_FAILURE (Run all tests regardless of errors)</option>
                </select>
              </div>

              <div className="p-3 bg-secondary/30 border border-border rounded-lg text-xs text-muted-foreground">
                Plan will select tests matching profile <strong className="text-foreground">{planProfile.name}</strong> and queue them in deterministic sequence.
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
                <Button type="button" variant="outline" size="sm" onClick={() => setPlanProfile(null)}>
                  Cancel
                </Button>
                <Button type="submit" size="sm" disabled={generatingPlan} className="bg-primary text-primary-foreground">
                  {generatingPlan ? "Generating Plan..." : "Generate Execution Plan"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
