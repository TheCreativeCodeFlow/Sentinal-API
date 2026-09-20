"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
}

interface RoleMember {
  id: string;
  name: string;
  auth_type: string;
  environment: string;
}

interface Role {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  identities_count?: number;
  created_at: string;
  updated_at: string;
}

export default function RolesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reloadKey, setReloadKey] = useState(0);

  // Form / Modal states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingRole, setEditingRole] = useState<Role | null>(null);
  const [viewingMembersRole, setViewingMembersRole] = useState<Role | null>(null);
  const [roleMembers, setRoleMembers] = useState<RoleMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);

  // Form inputs
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

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

  useEffect(() => {
    if (!selectedProjectId) return;
    let ignore = false;
    async function loadRolesData() {
      try {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/roles/`, { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load roles");
        const data = await res.json();
        if (!ignore) {
          setRoles(data);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load roles");
          setLoading(false);
        }
      }
    }
    loadRolesData();
    return () => {
      ignore = true;
    };
  }, [selectedProjectId, reloadKey]);

  const resetForm = () => {
    setName("");
    setDescription("");
    setShowCreateModal(false);
    setEditingRole(null);
  };

  const openCreate = () => {
    resetForm();
    setShowCreateModal(true);
  };

  const openEdit = (role: Role) => {
    setEditingRole(role);
    setName(role.name);
    setDescription(role.description || "");
    setShowCreateModal(true);
  };

  const openMembers = async (role: Role) => {
    setViewingMembersRole(role);
    setLoadingMembers(true);
    try {
      const res = await fetch(`/api/v1/roles/${role.id}/members`, { credentials: "include" });
      if (res.ok) {
        setRoleMembers(await res.json());
      }
    } catch {
      setRoleMembers([]);
    } finally {
      setLoadingMembers(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !selectedProjectId) return;
    setSubmitting(true);

    try {
      if (editingRole) {
        const res = await fetch(`/api/v1/roles/${editingRole.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name.trim(), description: description.trim() || null }),
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to update role");
        }
      } else {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/roles/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name.trim(), description: description.trim() || null }),
          credentials: "include",
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to create role");
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

  const handleDelete = async (roleId: string) => {
    if (!confirm("Delete this role? Any identities currently assigned will become unassigned.")) return;
    try {
      const res = await fetch(`/api/v1/roles/${roleId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete role");
      setReloadKey((k) => k + 1);
      if (viewingMembersRole?.id === roleId) {
        setViewingMembersRole(null);
      }
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Deletion failed"));
    }
  };

  const handleQuickTemplate = (roleName: string, desc: string) => {
    setName(roleName);
    setDescription(desc);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Roles Management</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Define standard (Anonymous, User, Admin) or custom security roles and inspect memberships.
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
            + New Role
          </Button>
        </div>
      </div>

      {loading && <div className="p-8 text-center text-muted-foreground">Loading roles...</div>}
      {error && <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm">{error}</div>}

      {/* Role Create/Edit Form */}
      {showCreateModal && (
        <Card className="border-primary/50 shadow-md">
          <CardHeader>
            <CardTitle>{editingRole ? "Edit Role" : "Create New Role"}</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {!editingRole && (
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs text-muted-foreground font-medium">Quick presets:</span>
                  <button
                    type="button"
                    onClick={() => handleQuickTemplate("Anonymous", "Unauthenticated public actor")}
                    className="text-xs px-2 py-0.5 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    Anonymous
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickTemplate("User", "Standard authenticated user with personal permissions")}
                    className="text-xs px-2 py-0.5 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    User
                  </button>
                  <button
                    type="button"
                    onClick={() => handleQuickTemplate("Admin", "Full administrative privilege across project APIs")}
                    className="text-xs px-2 py-0.5 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    Admin
                  </button>
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold mb-1">Role Name *</label>
                <Input
                  required
                  placeholder="e.g. Anonymous, User, Admin, Auditor, Support"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-xs font-semibold mb-1">Description</label>
                <Input
                  placeholder="Intended access privileges and scope"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="default" type="button" onClick={resetForm}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" disabled={submitting}>
                  {submitting ? "Saving..." : editingRole ? "Update Role" : "Create Role"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Roles List Table */}
      {!loading && roles.length === 0 && (
        <div className="p-12 text-center border border-dashed border-border rounded-xl">
          <p className="text-muted-foreground mb-4">No roles defined for this project yet.</p>
          <Button variant="primary" onClick={openCreate} disabled={!selectedProjectId}>
            Create First Role
          </Button>
        </div>
      )}

      {!loading && roles.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-border bg-card shadow-xs">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-xs font-semibold uppercase text-muted-foreground bg-muted/40">
                <th className="p-4">Role Name</th>
                <th className="p-4">Description</th>
                <th className="p-4">Assigned Members</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {roles.map((role) => (
                <tr key={role.id} className="hover:bg-accent/20 transition-colors">
                  <td className="p-4">
                    <span className="font-bold text-foreground">{role.name}</span>
                  </td>
                  <td className="p-4 text-muted-foreground text-xs">
                    {role.description || "—"}
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => openMembers(role)}
                      className="px-2.5 py-1 rounded-full text-xs font-medium bg-muted hover:bg-accent cursor-pointer inline-flex items-center gap-1.5"
                    >
                      <span className="font-bold">{role.identities_count || 0}</span>
                      <span className="text-muted-foreground">identities</span>
                    </button>
                  </td>
                  <td className="p-4 text-right space-x-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => openMembers(role)}
                    >
                      View Members
                    </Button>
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => openEdit(role)}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(role.id)}
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

      {/* Role Members Modal */}
      {viewingMembersRole && (
        <Card className="border-primary/40 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Role Membership: {viewingMembersRole.name}</CardTitle>
            <Button variant="default" size="sm" onClick={() => setViewingMembersRole(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            {loadingMembers && <div className="text-center py-4 text-muted-foreground text-xs">Loading members...</div>}
            {!loadingMembers && roleMembers.length === 0 && (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No identities are currently assigned to this role. You can assign roles from the Identities page.
              </p>
            )}
            {!loadingMembers && roleMembers.length > 0 && (
              <div className="divide-y divide-border">
                {roleMembers.map((m) => (
                  <div key={m.id} className="py-2 flex items-center justify-between text-xs">
                    <div>
                      <span className="font-semibold">{m.name}</span>
                      <span className="ml-2 font-mono text-[10px] text-muted-foreground uppercase">{m.environment}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-muted font-mono text-[10px] text-muted-foreground">
                      {m.auth_type}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
