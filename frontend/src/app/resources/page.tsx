"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
}

interface Identity {
  id: string;
  name: string;
}

interface Resource {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  resource_type: string;
  created_at: string;
  updated_at: string;
  ownerships_count?: number;
  endpoints_count?: number;
}

interface ResourceOwnership {
  id: string;
  resource_id: string;
  identity_id: string;
  identity_name?: string | null;
  resource_instance_id: string | null;
  ownership_type: string;
  created_at: string;
}

interface EndpointItem {
  id: number;
  method: string;
  path: string;
  summary: string | null;
  resource_id: string | null;
}

export default function ResourcesPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [resources, setResources] = useState<Resource[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [reloadKey, setReloadKey] = useState(0);

  // Modal / Drawer states
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingResource, setEditingResource] = useState<Resource | null>(null);
  const [managingOwnershipResource, setManagingOwnershipResource] = useState<Resource | null>(null);
  const [resourceOwnerships, setResourceOwnerships] = useState<ResourceOwnership[]>([]);
  const [managingEndpointResource, setManagingEndpointResource] = useState<Resource | null>(null);

  // Resource form state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [resourceType, setResourceType] = useState("entity");
  const [submitting, setSubmitting] = useState(false);

  // Ownership form state
  const [ownerIdentityId, setOwnerIdentityId] = useState("");
  const [instanceId, setInstanceId] = useState("");
  const [ownershipType, setOwnershipType] = useState("owner");
  const [submittingOwnership, setSubmittingOwnership] = useState(false);

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
    async function loadData() {
      try {
        const [resRes, identRes, apiRes] = await Promise.all([
          fetch(`/api/v1/projects/${selectedProjectId}/resources/`, { credentials: "include" }),
          fetch(`/api/v1/projects/${selectedProjectId}/identities/`, { credentials: "include" }),
          fetch(`/api/v1/${selectedProjectId}/apis/`, { credentials: "include" }),
        ]);
        const rData = resRes.ok ? await resRes.json() : [];
        const iData = identRes.ok ? await identRes.json() : [];
        const allEps: EndpointItem[] = [];
        if (apiRes.ok) {
          const apis = await apiRes.json();
          for (const api of apis) {
            const epRes = await fetch(`/api/v1/${api.id}/endpoints/`, { credentials: "include" });
            if (epRes.ok) {
              allEps.push(...(await epRes.json()));
            }
          }
        }
        if (!ignore) {
          setResources(rData);
          setIdentities(iData);
          setEndpoints(allEps);
          setError(null);
          setLoading(false);
        }
      } catch (err: unknown) {
        if (!ignore) {
          setError(err instanceof Error ? err.message : "Failed to load resources");
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
    setResourceType("entity");
    setShowCreateModal(false);
    setEditingResource(null);
  };

  const openCreate = () => {
    resetForm();
    setShowCreateModal(true);
  };

  const openEdit = (res: Resource) => {
    setEditingResource(res);
    setName(res.name);
    setDescription(res.description || "");
    setResourceType(res.resource_type);
    setShowCreateModal(true);
  };

  const openOwnerships = async (res: Resource) => {
    setManagingOwnershipResource(res);
    try {
      const resp = await fetch(`/api/v1/resources/${res.id}/ownerships/`, { credentials: "include" });
      if (resp.ok) setResourceOwnerships(await resp.json());
    } catch {
      setResourceOwnerships([]);
    }
  };

  const handleTemplateSelect = (templateName: string, tType: string, desc: string) => {
    setName(templateName);
    setResourceType(tType);
    setDescription(desc);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !selectedProjectId) return;
    setSubmitting(true);

    try {
      const payload = {
        name: name.trim(),
        description: description.trim() || null,
        resource_type: resourceType,
      };

      if (editingResource) {
        const res = await fetch(`/api/v1/resources/${editingResource.id}`, {
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
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/resources/`, {
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

  const handleDelete = async (resId: string) => {
    if (!confirm("Delete this resource? Associated ownerships and endpoint mappings will be cleared.")) return;
    try {
      const res = await fetch(`/api/v1/resources/${resId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Deletion failed");
      setReloadKey((k) => k + 1);
      if (managingOwnershipResource?.id === resId) setManagingOwnershipResource(null);
      if (managingEndpointResource?.id === resId) setManagingEndpointResource(null);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Deletion failed"));
    }
  };

  const handleCreateOwnership = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!managingOwnershipResource || !ownerIdentityId) return;
    setSubmittingOwnership(true);
    try {
      const res = await fetch(`/api/v1/resources/${managingOwnershipResource.id}/ownerships/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          identity_id: ownerIdentityId,
          resource_instance_id: instanceId.trim() || null,
          ownership_type: ownershipType,
        }),
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to create ownership");
      }
      setInstanceId("");
      await openOwnerships(managingOwnershipResource);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Ownership creation failed"));
    } finally {
      setSubmittingOwnership(false);
    }
  };

  const handleDeleteOwnership = async (ownershipId: string) => {
    try {
      const res = await fetch(`/api/v1/ownerships/${ownershipId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete ownership");
      if (managingOwnershipResource) await openOwnerships(managingOwnershipResource);
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Ownership deletion failed"));
    }
  };

  const handleToggleEndpointAssoc = async (endpointId: number, currentlyAssigned: boolean, targetResourceId: string) => {
    try {
      const res = await fetch(`/api/v1/endpoints/${endpointId}/resource`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resource_id: currentlyAssigned ? null : targetResourceId }),
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to update endpoint mapping");
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      alert("Error: " + (err instanceof Error ? err.message : "Mapping failed"));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold">Resource Modeling</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Define domain resources (User, Order, Payment, Product), bind API endpoints, and establish ownership.
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
            + New Resource
          </Button>
        </div>
      </div>

      {loading && <div className="p-8 text-center text-muted-foreground">Loading resources...</div>}
      {error && <div className="p-4 rounded-lg bg-destructive/10 text-destructive text-sm">{error}</div>}

      {/* Resource Create/Edit Modal */}
      {showCreateModal && (
        <Card className="border-primary/50 shadow-md">
          <CardHeader>
            <CardTitle>{editingResource ? "Edit Resource" : "Create New Resource"}</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {!editingResource && (
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="text-xs text-muted-foreground font-medium">Standard resource templates:</span>
                  <button
                    type="button"
                    onClick={() => handleTemplateSelect("User", "User", "User account profile and settings")}
                    className="text-xs px-2.5 py-1 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    User
                  </button>
                  <button
                    type="button"
                    onClick={() => handleTemplateSelect("Order", "Order", "E-commerce order and checkout record")}
                    className="text-xs px-2.5 py-1 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    Order
                  </button>
                  <button
                    type="button"
                    onClick={() => handleTemplateSelect("Payment", "Payment", "Payment transaction and invoice details")}
                    className="text-xs px-2.5 py-1 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    Payment
                  </button>
                  <button
                    type="button"
                    onClick={() => handleTemplateSelect("Product", "Product", "Catalog item inventory and metadata")}
                    className="text-xs px-2.5 py-1 rounded border border-border bg-muted/50 hover:bg-accent cursor-pointer"
                  >
                    Product
                  </button>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold mb-1">Resource Name *</label>
                  <Input
                    required
                    placeholder="e.g. User, Order, Payment, Product"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold mb-1">Resource Type</label>
                  <Input
                    placeholder="e.g. Order, User, entity, document"
                    value={resourceType}
                    onChange={(e) => setResourceType(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold mb-1">Description</label>
                <Input
                  placeholder="Domain role and authorization boundaries"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="default" type="button" onClick={resetForm}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" disabled={submitting}>
                  {submitting ? "Saving..." : editingResource ? "Update Resource" : "Create Resource"}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Resources Table */}
      {!loading && resources.length === 0 && (
        <div className="p-12 text-center border border-dashed border-border rounded-xl">
          <p className="text-muted-foreground mb-4">No resources modeled yet for this project.</p>
          <Button variant="primary" onClick={openCreate} disabled={!selectedProjectId}>
            Define First Resource
          </Button>
        </div>
      )}

      {!loading && resources.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-border bg-card shadow-xs">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-xs font-semibold uppercase text-muted-foreground bg-muted/40">
                <th className="p-4">Resource</th>
                <th className="p-4">Type</th>
                <th className="p-4">Ownerships</th>
                <th className="p-4">Mapped Endpoints</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {resources.map((res) => (
                <tr key={res.id} className="hover:bg-accent/20 transition-colors">
                  <td className="p-4">
                    <span className="font-bold text-foreground">{res.name}</span>
                    {res.description && (
                      <div className="text-xs text-muted-foreground font-normal mt-0.5">
                        {res.description}
                      </div>
                    )}
                  </td>
                  <td className="p-4">
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-muted text-muted-foreground">
                      {res.resource_type}
                    </span>
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => openOwnerships(res)}
                      className="px-2.5 py-1 rounded-full text-xs font-medium bg-muted hover:bg-accent cursor-pointer inline-flex items-center gap-1.5"
                    >
                      <span className="font-bold">{res.ownerships_count || 0}</span>
                      <span className="text-muted-foreground">owners</span>
                    </button>
                  </td>
                  <td className="p-4">
                    <button
                      onClick={() => setManagingEndpointResource(res)}
                      className="px-2.5 py-1 rounded-full text-xs font-medium bg-primary/10 text-primary hover:bg-primary/20 cursor-pointer inline-flex items-center gap-1.5"
                    >
                      <span className="font-bold">{res.endpoints_count || 0}</span>
                      <span>endpoints</span>
                    </button>
                  </td>
                  <td className="p-4 text-right space-x-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => openOwnerships(res)}
                    >
                      Ownerships
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => setManagingEndpointResource(res)}
                    >
                      Map Endpoints
                    </Button>
                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => openEdit(res)}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(res.id)}
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

      {/* Manage Ownerships Drawer */}
      {managingOwnershipResource && (
        <Card className="border-primary/40 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>
              Ownership Connections: {managingOwnershipResource.name} (Identity → owns → Resource)
            </CardTitle>
            <Button variant="default" size="sm" onClick={() => setManagingOwnershipResource(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Create Ownership form */}
            <form onSubmit={handleCreateOwnership} className="p-3 bg-muted/30 rounded-lg border border-border space-y-3">
              <h4 className="text-xs font-semibold uppercase text-muted-foreground">Assign New Ownership</h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium mb-1">Owner Identity *</label>
                  <select
                    required
                    className="w-full h-9 px-2 rounded-md border border-border bg-background text-xs"
                    value={ownerIdentityId}
                    onChange={(e) => setOwnerIdentityId(e.target.value)}
                  >
                    <option value="">-- Choose Identity --</option>
                    {identities.map((idnt) => (
                      <option key={idnt.id} value={idnt.id}>{idnt.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1">Resource Instance ID</label>
                  <Input
                    placeholder="e.g. Order #123, user_abc, *"
                    value={instanceId}
                    onChange={(e) => setInstanceId(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium mb-1">Ownership Type</label>
                  <select
                    className="w-full h-9 px-2 rounded-md border border-border bg-background text-xs"
                    value={ownershipType}
                    onChange={(e) => setOwnershipType(e.target.value)}
                  >
                    <option value="owner">Owner (Full)</option>
                    <option value="admin">Admin</option>
                    <option value="viewer">Viewer (Read-Only)</option>
                  </select>
                </div>
              </div>
              <div className="flex justify-end">
                <Button variant="primary" size="sm" type="submit" disabled={submittingOwnership || !ownerIdentityId}>
                  {submittingOwnership ? "Connecting..." : "Assign Ownership"}
                </Button>
              </div>
            </form>

            {/* List existing ownerships */}
            {resourceOwnerships.length === 0 ? (
              <p className="text-xs text-muted-foreground py-2 text-center">
                No identity ownerships assigned yet for {managingOwnershipResource.name}.
              </p>
            ) : (
              <div className="divide-y divide-border rounded-lg border border-border">
                {resourceOwnerships.map((o) => (
                  <div key={o.id} className="p-3 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-3">
                      <span className="font-semibold text-foreground">{o.identity_name}</span>
                      <span className="text-muted-foreground">→ owns →</span>
                      <span className="font-mono bg-muted px-2 py-0.5 rounded font-bold">
                        {o.resource_instance_id || "All Instances"}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded uppercase font-semibold bg-secondary text-secondary-foreground">
                        {o.ownership_type}
                      </span>
                    </div>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDeleteOwnership(o.id)}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Manage Endpoint Association Drawer */}
      {managingEndpointResource && (
        <Card className="border-primary/40 shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>
              Associate Endpoints with &quot;{managingEndpointResource.name}&quot;
            </CardTitle>
            <Button variant="default" size="sm" onClick={() => setManagingEndpointResource(null)}>
              Close
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Check/uncheck endpoints that operate on the &quot;{managingEndpointResource.name}&quot; resource (e.g. GET /orders/&#123;id&#125;).
            </p>
            {endpoints.length === 0 ? (
              <p className="text-xs text-muted-foreground py-4 text-center">
                No endpoints ingested for this project yet. Use the API Explorer to upload an OpenAPI spec.
              </p>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                {endpoints.map((ep) => {
                  const isAssigned = ep.resource_id === managingEndpointResource.id;
                  return (
                    <div
                      key={ep.id}
                      className={`p-2.5 rounded-lg border text-xs flex items-center justify-between ${
                        isAssigned
                          ? "border-primary bg-primary/5"
                          : "border-border bg-card"
                      }`}
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold">{ep.method}</span>
                        <span className="font-mono">{ep.path}</span>
                      </div>
                      <Button
                        variant={isAssigned ? "primary" : "secondary"}
                        size="sm"
                        onClick={() => handleToggleEndpointAssoc(ep.id, isAssigned, managingEndpointResource.id)}
                      >
                        {isAssigned ? "Mapped ✓" : "+ Map Endpoint"}
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
