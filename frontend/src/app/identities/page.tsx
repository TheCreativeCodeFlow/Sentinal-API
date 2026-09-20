"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
}

interface Role {
  id: string;
  name: string;
}

interface Identity {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  role_id: string | null;
  role_name?: string | null;
  auth_type: string;
  environment: string;
  has_credential: boolean;
  credential_preview?: string | null;
  credential_reference: string | null;
  created_at: string;
  updated_at: string;
}

export default function IdentitiesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reloadKey, setReloadKey] = useState(0);

  // Modal / Form state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingIdentity, setEditingIdentity] = useState<Identity | null>(null);
  const [detailIdentity, setDetailIdentity] = useState<Identity | null>(null);

  // Form inputs
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [roleId, setRoleId] = useState("");
  const [authType, setAuthType] = useState("bearer_token");
  const [environment, setEnvironment] = useState("production");
  const [credentialRef, setCredentialRef] = useState("");
  const [credentialValue, setCredentialValue] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Fetch projects
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

  // Fetch identities & roles for active project
  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;
    async function loadData() {
      try {
        const [identRes, roleRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/identities/`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/roles/`, { credentials: "include" }),
        ]);
        const identData = identRes.ok ? await identRes.json() : [];
        const roleData = roleRes.ok ? await roleRes.json() : [];
        if (!ignore) {
          setIdentities(identData);
          setRoles(roleData);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load identities");
          setLoading(false);
        }
      }
    }
    loadData();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setRoleId("");
    setAuthType("bearer_token");
    setEnvironment("production");
    setCredentialRef("");
    setCredentialValue("");
    setShowCreateModal(false);
    setEditingIdentity(null);
  };

  const openCreate = () => {
    resetForm();
    setShowCreateModal(true);
  };

  const openEdit = (identity: Identity) => {
    setEditingIdentity(identity);
    setName(identity.name);
    setDescription(identity.description || "");
    setRoleId(identity.role_id || "");
    setAuthType(identity.auth_type);
    setEnvironment(identity.environment);
    setCredentialRef(identity.credential_reference || "");
    setCredentialValue("");
    setShowCreateModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !selectedProjectId) return;
    setSubmitting(true);

    try {
      const payload: Record<string, unknown> = {
        name: name.trim(),
        description: description.trim() || null,
        role_id: roleId || null,
        auth_type: authType,
        environment,
        credential_reference: credentialRef.trim() || null,
      };
      if (credentialValue) {
        payload.credential_value = credentialValue;
      }

      if (editingIdentity) {
        const res = await fetch(`/api/v1/identities/${editingIdentity.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Update failed");
        }
      } else {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/identities/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Creation failed");
        }
      }

      resetForm();
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Request failed"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (identityId: string) => {
    if (!confirm("Are you sure you want to delete this identity?")) return;
    try {
      const res = await fetch(`/api/v1/identities/${identityId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Deletion failed");
      setReloadKey((k) => k + 1);
      if (detailIdentity?.id === identityId) {
        setDetailIdentity(null);
      }
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Deletion failed"));
    }
  };

  const handleQuickRoleChange = async (identityId: string, newRoleId: string) => {
    try {
      const res = await fetch(`/api/v1/identities/${identityId}/role`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role_id: newRoleId || null }),
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to assign role");
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Role assignment failed"));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Identities Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Model actors, authentication credentials, and roles for access control testing.
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
          <Button variant="primary" onClick={openCreate} disabled={!selectedProjectId}>
            + New Identity
          </Button>
        </div>
      </div>

      {loading && <div className="p-8 text-center text-muted-foreground">Loading identities...</div>}
      {error && <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm">{error}</div>}

      {/* Identity Create / Edit Form Modal */}
      {showCreateModal && (
        <Card className="border-primary/50 shadow-md">
          <CardHeader>
            <CardTitle>{editingIdentity ? "Edit Identity" : "Create New Identity"}</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold mb-1">Name *</label>
                  <Input
                    required
                    placeholder="e.g. Alice (Admin) or Service Account"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold mb-1">Role</label>
                  <select
                    className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                    value={roleId}
                    onChange={(e) => setRoleId(e.target.value)}
                  >
                    <option value="">-- No Role Assigned --</option>
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>{r.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold mb-1">Authentication Type</label>
                  <select
                    className="w-full h-10 px-3 rounded-md border border-border bg-background text-sm"
                    value={authType}
                    onChange={(e) => setAuthType(e.target.value)}
                  >
                    <option value="bearer_token">Bearer Token (JWT / API Token)</option>
                    <option value="api_key">API Key (Header / Query)</option>
                    <option value="basic_auth">Basic Auth</option>
                    <option value="oauth2">OAuth 2.0</option>
                    <option value="cookie">Session Cookie</option>
                    <option value="none">Anonymous / None</option>
                  </select>
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
                  placeholder="Optional notes or testing persona context"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>

              <div className="p-3 bg-muted/40 rounded-lg border border-border space-y-3">
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-1.5">
                  <span>🔒 Credential Configuration</span>
                  <span className="text-[10px] text-green-700 dark:text-green-400 font-normal">
                    (Values are strictly masked and never logged)
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium mb-1">Credential Reference</label>
                    <Input
                      placeholder="e.g. env:TEST_USER_TOKEN or key_ref_01"
                      value={credentialRef}
                      onChange={(e) => setCredentialRef(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium mb-1">
                      {editingIdentity ? "Update Test Secret (Optional)" : "Test Secret / Token"}
                    </label>
                    <Input
                      type="password"
                      placeholder="••••••••••••••••"
                      value={credentialValue}
                      onChange={(e) => setCredentialValue(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="default" type="button" onClick={resetForm}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" disabled={submitting}>
                  {submitting ? "Saving..." : editingIdentity ? "Update Identity" : "Save Identity"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Identities Table */}
      {!loading && identities.length === 0 && (
        <div className="p-12 text-center border border-dashed border-border rounded-xl">
          <p className="text-muted-foreground mb-4">No identities configured for this project yet.</p>
          <Button variant="primary" onClick={openCreate} disabled={!selectedProjectId}>
            Create an Identity
          </Button>
        </div>
      )}

      {!loading && identities.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-border bg-card shadow-xs">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-xs font-semibold uppercase text-muted-foreground bg-muted/40">
                <th className="p-4">Identity</th>
                <th className="p-4">Role</th>
                <th className="p-4">Auth Type</th>
                <th className="p-4">Environment</th>
                <th className="p-4">Credential Status</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {identities.map((identity) => (
                <tr key={identity.id} className="hover:bg-accent/20 transition-colors">
                  <td className="p-4">
                    <button
                      onClick={() => setDetailIdentity(identity)}
                      className="font-semibold text-foreground text-left hover:underline cursor-pointer"
                    >
                      {identity.name}
                    </button>
                    {identity.description && (
                      <div className="text-xs text-muted-foreground font-normal mt-0.5">
                        {identity.description}
                      </div>
                    )}
                  </td>
                  <td className="p-4">
                    <select
                      className="h-8 px-2 py-0.5 rounded text-xs border border-border bg-background"
                      value={identity.role_id || ""}
                      onChange={(e) => handleQuickRoleChange(identity.id, e.target.value)}
                    >
                      <option value="">Unassigned</option>
                      {roles.map((r) => (
                        <option key={r.id} value={r.id}>{r.name}</option>
                      ))}
                    </select>
                  </td>
                  <td className="p-4 font-mono text-xs">
                    <span className="px-2 py-0.5 rounded bg-muted text-muted-foreground">
                      {identity.auth_type}
                    </span>
                  </td>
                  <td className="p-4 font-mono text-xs uppercase">
                    {identity.environment}
                  </td>
                  <td className="p-4">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-green-500"></span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {identity.credential_reference || "masked"}
                      </span>
                    </div>
                  </td>
                  <td className="p-4 text-right space-x-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => setDetailIdentity(identity)}
                    >
                      Details
                    </Button>
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => openEdit(identity)}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(identity.id)}
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

      {/* Detail Modal / Drawer */}
      {detailIdentity && (
        <Card className="border-primary/40 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Identity Details: {detailIdentity.name}</CardTitle>
            <Button variant="default" size="sm" onClick={() => setDetailIdentity(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-lg bg-muted/30">
              <div>
                <span className="text-xs text-muted-foreground block">ID</span>
                <span className="font-mono text-xs">{detailIdentity.id}</span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block">Role</span>
                <span className="font-semibold">{detailIdentity.role_name || "Unassigned"}</span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block">Auth Mechanism</span>
                <span className="font-mono text-xs">{detailIdentity.auth_type}</span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block">Environment</span>
                <span className="capitalize">{detailIdentity.environment}</span>
              </div>
            </div>

            <div className="p-4 rounded-lg border border-border bg-card space-y-2">
              <h4 className="text-xs font-semibold uppercase text-muted-foreground">Credential Security Assessment</h4>
              <div className="flex items-center justify-between text-xs">
                <span>Stored Credential Reference:</span>
                <span className="font-mono font-medium">{detailIdentity.credential_reference || "None"}</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span>Raw Secret Exposure:</span>
                <span className="text-green-600 dark:text-green-400 font-bold">Protected (Never exposed in API or UI)</span>
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <a href={`/auth-model?project_id=${detailIdentity.project_id}`}>
                <Button variant="secondary" size="sm">Inspect in Auth Model Tree →</Button>
              </a>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
