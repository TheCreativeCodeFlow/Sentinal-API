"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
}

interface ResourceItem {
  id: string;
  name: string;
  description: string | null;
}

interface RoleItem {
  id: string;
  name: string;
  description: string | null;
}

interface EndpointItem {
  id: number;
  method: string;
  path: string;
  summary: string | null;
}

interface PropertyRuleItem {
  id: string;
  resource_property_id: string;
  role_id: string;
  access: string; // ALLOW, DENY, UNKNOWN
}

interface ResourceProperty {
  id: string;
  resource_id: string;
  name: string;
  data_type: string;
  sensitivity: string; // PUBLIC, INTERNAL, SENSITIVE, SECRET
  description: string | null;
  created_at: string;
  updated_at: string;
  rules: PropertyRuleItem[];
}

interface PropertyMatrixRow {
  id: string;
  name: string;
  data_type: string;
  sensitivity: string;
  description: string | null;
  rules: Record<string, string>; // role_id -> access
}

interface PropertyMatrixView {
  resource_id: string;
  resource_name: string;
  project_id: number;
  roles: RoleItem[];
  properties: PropertyMatrixRow[];
  total_properties: number;
}

interface CandidateProperty {
  path: string;
  data_type: string;
  suggested_sensitivity: string;
  matched_heuristic: string | null;
  sample_value: string | null;
}

export default function PropertySecurityPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [resources, setResources] = useState<ResourceItem[]>([]);
  const [selectedResourceId, setSelectedResourceId] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [roles, setRoles] = useState<RoleItem[]>([]);
  const [properties, setProperties] = useState<ResourceProperty[]>([]);
  const [matrixData, setMatrixData] = useState<PropertyMatrixView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"inventory" | "matrix">("inventory");
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Add Property Modal
  const [showAddModal, setShowAddModal] = useState(false);
  const [propName, setPropName] = useState("");
  const [propDataType, setPropDataType] = useState("string");
  const [propSensitivity, setPropSensitivity] = useState("INTERNAL");
  const [propDescription, setPropDescription] = useState("");
  const [submittingProp, setSubmittingProp] = useState(false);

  // Edit Property Modal
  const [editingProp, setEditingProp] = useState<ResourceProperty | null>(null);
  const [editName, setEditName] = useState("");
  const [editDataType, setEditDataType] = useState("string");
  const [editSensitivity, setEditSensitivity] = useState("INTERNAL");
  const [editDescription, setEditDescription] = useState("");
  const [submittingEdit, setSubmittingEdit] = useState(false);

  // Discover Properties Modal
  const [showDiscoverModal, setShowDiscoverModal] = useState(false);
  const [discoverSampleJson, setDiscoverSampleJson] = useState("");
  const [discoverEndpointId, setDiscoverEndpointId] = useState<number | "">("");
  const [discovering, setDiscovering] = useState(false);
  const [candidates, setCandidates] = useState<CandidateProperty[]>([]);
  const [selectedCandidates, setSelectedCandidates] = useState<Record<string, boolean>>({});
  const [importingCandidates, setImportingCandidates] = useState(false);

  // Matrix Editing state
  const [pendingMatrixChanges, setPendingMatrixChanges] = useState<Record<string, string>>({});
  const [savingMatrix, setSavingMatrix] = useState(false);

  // 1. Load Projects
  useEffect(() => {
    async function loadProjects() {
      try {
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (res.ok) {
          const data: Project[] = await res.json();
          setProjects(data);
          if (data.length > 0 && selectedProjectId === null) {
            setSelectedProjectId(data[0].id);
          }
        }
      } catch (err: unknown) {
        console.error("Failed to load projects", err);
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, [selectedProjectId]);

  // 2. Load Resources, Endpoints, and Roles when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    async function loadProjectData() {
      try {
        setLoading(true);
        setError(null);
        // Load Resources
        const resResp = await fetch(`/api/v1/projects/${selectedProjectId}/resources/`, { credentials: "include" });
        if (resResp.ok) {
          const resList: ResourceItem[] = await resResp.json();
          setResources(resList);
          if (resList.length > 0) {
            setSelectedResourceId((prev) => (prev && resList.some(r => r.id === prev) ? prev : resList[0].id));
          } else {
            setSelectedResourceId(null);
            setProperties([]);
            setMatrixData(null);
          }
        }

        // Load Roles
        const rolesResp = await fetch(`/api/v1/projects/${selectedProjectId}/roles/`, { credentials: "include" });
        if (rolesResp.ok) {
          setRoles(await rolesResp.json());
        }

        // Load Endpoints
        const epResp = await fetch(`/api/v1/projects/${selectedProjectId}/endpoints/`, { credentials: "include" });
        if (epResp.ok) {
          setEndpoints(await epResp.json());
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load project details");
      } finally {
        setLoading(false);
      }
    }
    loadProjectData();
  }, [selectedProjectId]);

  // 3. Load Properties and Matrix when resource changes
  useEffect(() => {
    let ignore = false;
    async function loadResourceProperties() {
      if (!selectedResourceId) {
        if (!ignore) {
          setProperties([]);
          setMatrixData(null);
        }
        return;
      }
      try {
        setLoading(true);
        setError(null);
        // Load Properties
        const propResp = await fetch(`/api/v1/resources/${selectedResourceId}/properties`, { credentials: "include" });
        if (propResp.ok && !ignore) {
          setProperties(await propResp.json());
        }

        // Load Matrix View
        const matResp = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix`, { credentials: "include" });
        if (matResp.ok && !ignore) {
          const mat: PropertyMatrixView = await matResp.json();
          setMatrixData(mat);
          setPendingMatrixChanges({});
        }
      } catch (err: unknown) {
        if (!ignore) setError(err instanceof Error ? err.message : "Failed to load resource properties");
      } finally {
        if (!ignore) setLoading(false);
      }
    }
    loadResourceProperties();
    return () => {
      ignore = true;
    };
  }, [selectedResourceId]);

  const activeResource = resources.find((r) => r.id === selectedResourceId);

  // Helper for sensitivity badge
  const renderSensitivityBadge = (sens: string) => {
    const s = sens.toUpperCase();
    if (s === "SECRET") {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          SECRET
        </span>
      );
    }
    if (s === "SENSITIVE") {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-orange-500/20 text-orange-400 border border-orange-500/30">
          SENSITIVE
        </span>
      );
    }
    if (s === "INTERNAL") {
      return (
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          INTERNAL
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
        PUBLIC
      </span>
    );
  };

  // Add Property Handler
  const handleAddProperty = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedResourceId || !propName.trim()) return;
    setSubmittingProp(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/resources/${selectedResourceId}/properties`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: propName.trim(),
          data_type: propDataType,
          sensitivity: propSensitivity,
          description: propDescription.trim() || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to create property");
      }
      const newP: ResourceProperty = await res.json();
      setProperties((prev) => [...prev, newP]);
      setShowAddModal(false);
      setPropName("");
      setPropDescription("");
      setActionMessage(`Property '${newP.name}' created successfully.`);
      setTimeout(() => setActionMessage(null), 4000);

      // Refresh matrix
      const matRes = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix`, { credentials: "include" });
      if (matRes.ok) setMatrixData(await matRes.json());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create property");
    } finally {
      setSubmittingProp(false);
    }
  };

  // Edit Property Handler
  const handleEditProperty = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingProp) return;
    setSubmittingEdit(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/properties/${editingProp.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: editName.trim(),
          data_type: editDataType,
          sensitivity: editSensitivity,
          description: editDescription.trim() || null,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to update property");
      }
      const updated: ResourceProperty = await res.json();
      setProperties((prev) => prev.map((p) => (p.id === updated.id ? updated : p)));
      setEditingProp(null);
      setActionMessage(`Property '${updated.name}' updated successfully.`);
      setTimeout(() => setActionMessage(null), 4000);

      // Refresh matrix
      if (selectedResourceId) {
        const matRes = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix`, { credentials: "include" });
        if (matRes.ok) setMatrixData(await matRes.json());
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update property");
    } finally {
      setSubmittingEdit(false);
    }
  };

  // Delete Property Handler
  const handleDeleteProperty = async (propId: string, propName: string) => {
    if (!confirm(`Are you sure you want to delete property '${propName}'? This will also remove any configured authorization rules.`)) {
      return;
    }
    setError(null);
    try {
      const res = await fetch(`/api/v1/properties/${propId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to delete property");
      }
      setProperties((prev) => prev.filter((p) => p.id !== propId));
      setActionMessage(`Property '${propName}' deleted successfully.`);
      setTimeout(() => setActionMessage(null), 4000);

      if (selectedResourceId) {
        const matRes = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix`, { credentials: "include" });
        if (matRes.ok) setMatrixData(await matRes.json());
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete property");
    }
  };

  // Discovery Execution Handler
  const handleRunDiscovery = async () => {
    if (!selectedResourceId) return;
    setDiscovering(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = {};
      if (discoverSampleJson.trim()) {
        payload.sample_json = discoverSampleJson.trim();
      } else if (discoverEndpointId) {
        payload.endpoint_id = Number(discoverEndpointId);
      } else {
        throw new Error("Please provide either sample JSON or choose an endpoint to extract properties from.");
      }

      const res = await fetch(`/api/v1/resources/${selectedResourceId}/discover-properties`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Property discovery failed");
      }

      const result = await res.json();
      setCandidates(result.discovered_properties || []);
      // Select all by default
      const initialSelection: Record<string, boolean> = {};
      (result.discovered_properties || []).forEach((c: CandidateProperty) => {
        initialSelection[c.path] = true;
      });
      setSelectedCandidates(initialSelection);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Property discovery failed");
    } finally {
      setDiscovering(false);
    }
  };

  // Import Selected Candidate Properties
  const handleImportCandidates = async () => {
    if (!selectedResourceId || candidates.length === 0) return;
    const toImport = candidates
      .filter((c) => selectedCandidates[c.path])
      .map((c) => ({
        name: c.path,
        data_type: c.data_type,
        sensitivity: c.suggested_sensitivity,
        description: c.matched_heuristic ? `Discovered property (heuristic: ${c.matched_heuristic})` : "Discovered property",
      }));

    if (toImport.length === 0) {
      setError("Please select at least one property to import.");
      return;
    }

    setImportingCandidates(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/resources/${selectedResourceId}/properties/bulk`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(toImport),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to import properties");
      }
      const imported = await res.json();
      setShowDiscoverModal(false);
      setCandidates([]);
      setDiscoverSampleJson("");
      setDiscoverEndpointId("");
      setActionMessage(`Successfully imported ${imported.length} properties.`);
      setTimeout(() => setActionMessage(null), 4000);

      // Refresh list and matrix
      const propResp = await fetch(`/api/v1/resources/${selectedResourceId}/properties`, { credentials: "include" });
      if (propResp.ok) setProperties(await propResp.json());
      const matResp = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix`, { credentials: "include" });
      if (matResp.ok) setMatrixData(await matResp.json());
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to import properties");
    } finally {
      setImportingCandidates(false);
    }
  };

  // Matrix Cell Change
  const handleMatrixCellChange = (propId: string, roleId: string, access: string) => {
    const key = `${propId}:${roleId}`;
    setPendingMatrixChanges((prev) => ({
      ...prev,
      [key]: access,
    }));
  };

  // Bulk Apply Matrix Preset
  const handleApplyPreset = (presetType: "DENY_SENSITIVE" | "ALLOW_ALL" | "DENY_ALL") => {
    if (!matrixData) return;
    const newChanges: Record<string, string> = { ...pendingMatrixChanges };

    matrixData.properties.forEach((prop) => {
      matrixData.roles.forEach((role) => {
        const key = `${prop.id}:${role.id}`;
        if (presetType === "DENY_SENSITIVE") {
          const isSens = prop.sensitivity === "SENSITIVE" || prop.sensitivity === "SECRET" || prop.sensitivity === "INTERNAL";
          const isAdmin = role.name.toLowerCase().includes("admin");
          if (isSens && !isAdmin) {
            newChanges[key] = "DENY";
          }
        } else if (presetType === "ALLOW_ALL") {
          newChanges[key] = "ALLOW";
        } else if (presetType === "DENY_ALL") {
          newChanges[key] = "DENY";
        }
      });
    });

    setPendingMatrixChanges(newChanges);
  };

  // Save Matrix Changes
  const handleSaveMatrixChanges = async () => {
    if (!selectedResourceId || Object.keys(pendingMatrixChanges).length === 0) return;
    setSavingMatrix(true);
    setError(null);
    try {
      const rulesPayload = Object.entries(pendingMatrixChanges).map(([key, access]) => {
        const [propId, roleId] = key.split(":");
        return {
          property_id: propId,
          role_id: roleId,
          access: access,
        };
      });

      const res = await fetch(`/api/v1/resources/${selectedResourceId}/property-matrix/bulk`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ rules: rulesPayload }),
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Failed to save matrix changes");
      }

      const updatedMat: PropertyMatrixView = await res.json();
      setMatrixData(updatedMat);
      setPendingMatrixChanges({});
      setActionMessage("Property authorization matrix saved successfully.");
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save matrix changes");
    } finally {
      setSavingMatrix(false);
    }
  };

  // Statistics calculation
  const sensitivePropsCount = properties.filter(
    (p) => p.sensitivity === "SENSITIVE" || p.sensitivity === "SECRET"
  ).length;

  return (
    <div className="space-y-6">
      {/* Top Header & Project Selection */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Property-Level Authorization</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Define object property schemas, configure role-based field authorization rules, and discover candidate sensitive properties.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex flex-col gap-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Active Project</span>
            <select
              value={selectedProjectId || ""}
              onChange={(e) => setSelectedProjectId(Number(e.target.value))}
              className="bg-card border border-border text-foreground rounded-lg px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-1 focus:ring-primary"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.authorization_status.toLowerCase() === "authorized" ? "✓" : "(Unauthorized)"}
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col gap-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Domain Resource</span>
            <select
              value={selectedResourceId || ""}
              onChange={(e) => setSelectedResourceId(e.target.value || null)}
              className="bg-card border border-border text-foreground rounded-lg px-3 py-1.5 text-sm font-medium focus:outline-hidden focus:ring-1 focus:ring-primary min-w-[180px]"
            >
              {resources.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
              {resources.length === 0 && <option value="">No resources configured</option>}
            </select>
          </div>
        </div>
      </div>

      {/* Action and Error Alerts */}
      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-lg text-sm flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-rose-200">✕</button>
        </div>
      )}
      {actionMessage && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg text-sm flex items-center justify-between">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <Card className="bg-card/40 border-border">
          <CardContent className="p-4">
            <p className="text-xs font-medium text-muted-foreground uppercase">Domain Resource</p>
            <p className="text-lg font-bold text-foreground mt-1 truncate">
              {activeResource?.name || "None"}
            </p>
          </CardContent>
        </Card>
        <Card className="bg-card/40 border-border">
          <CardContent className="p-4">
            <p className="text-xs font-medium text-muted-foreground uppercase">Total Defined Properties</p>
            <p className="text-2xl font-bold text-foreground mt-1">{properties.length}</p>
          </CardContent>
        </Card>
        <Card className="bg-card/40 border-border">
          <CardContent className="p-4">
            <p className="text-xs font-medium text-muted-foreground uppercase">Sensitive / Secret Fields</p>
            <p className="text-2xl font-bold text-amber-400 mt-1">{sensitivePropsCount}</p>
          </CardContent>
        </Card>
        <Card className="bg-card/40 border-border">
          <CardContent className="p-4">
            <p className="text-xs font-medium text-muted-foreground uppercase">Configured Project Roles</p>
            <p className="text-2xl font-bold text-foreground mt-1">{roles.length}</p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs and Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 border-b border-border sm:border-0 pb-2 sm:pb-0">
          <button
            onClick={() => setActiveTab("inventory")}
            className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${
              activeTab === "inventory"
                ? "bg-primary text-primary-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground hover:bg-accent"
            }`}
          >
            📋 Property Inventory ({properties.length})
          </button>
          <button
            onClick={() => setActiveTab("matrix")}
            className={`px-4 py-2 text-sm font-semibold rounded-lg transition-colors ${
              activeTab === "matrix"
                ? "bg-primary text-primary-foreground shadow-xs"
                : "text-muted-foreground hover:text-foreground hover:bg-accent"
            }`}
          >
            🛡️ Authorization Matrix ({properties.length} × {roles.length})
          </button>
        </div>

        <div className="flex items-center gap-2">
          {activeResource && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowDiscoverModal(true)}
                className="border-primary/40 text-primary hover:bg-primary/10 gap-1.5"
              >
                <span>⚡</span> Discover Properties
              </Button>
              <Button
                size="sm"
                onClick={() => setShowAddModal(true)}
                className="gap-1.5"
              >
                <span>+</span> Add Property
              </Button>
            </>
          )}
        </div>
      </div>

      {/* TAB 1: PROPERTY INVENTORY */}
      {activeTab === "inventory" && (
        <Card className="border-border">
          <CardContent className="p-0">
            {loading ? (
              <div className="p-12 text-center text-muted-foreground animate-pulse">
                Loading properties...
              </div>
            ) : !activeResource ? (
              <div className="p-12 text-center text-muted-foreground">
                <p className="text-base font-semibold">No resource selected</p>
                <p className="text-sm mt-1">Please create or select a domain resource to configure its properties.</p>
                <Link href="/resources">
                  <Button variant="outline" size="sm" className="mt-4">
                    Manage Resources
                  </Button>
                </Link>
              </div>
            ) : properties.length === 0 ? (
              <div className="p-12 text-center text-muted-foreground">
                <p className="text-base font-semibold">No properties defined for &apos;{activeResource.name}&apos;</p>
                <p className="text-sm mt-1">
                  You can manually define properties or click ⚡ Discover Properties to parse an API payload.
                </p>
                <div className="flex items-center justify-center gap-3 mt-4">
                  <Button size="sm" onClick={() => setShowAddModal(true)}>
                    + Add Property
                  </Button>
                  <Button variant="outline" size="sm" onClick={() => setShowDiscoverModal(true)}>
                    ⚡ Discover Properties
                  </Button>
                </div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-muted/50 border-b border-border text-xs font-semibold text-muted-foreground uppercase">
                    <tr>
                      <th className="px-4 py-3">Property Path / Name</th>
                      <th className="px-4 py-3">Data Type</th>
                      <th className="px-4 py-3">Sensitivity</th>
                      <th className="px-4 py-3">Description</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {properties.map((p) => (
                      <tr key={p.id} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-3 font-mono font-medium text-foreground">
                          {p.name}
                        </td>
                        <td className="px-4 py-3 text-muted-foreground">
                          <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{p.data_type}</code>
                        </td>
                        <td className="px-4 py-3">{renderSensitivityBadge(p.sensitivity)}</td>
                        <td className="px-4 py-3 text-muted-foreground max-w-md truncate">
                          {p.description || "—"}
                        </td>
                        <td className="px-4 py-3 text-right space-x-2">
                          <Button
                            variant="default"
                            size="sm"
                            onClick={() => {
                              setEditingProp(p);
                              setEditName(p.name);
                              setEditDataType(p.data_type);
                              setEditSensitivity(p.sensitivity);
                              setEditDescription(p.description || "");
                            }}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="default"
                            size="sm"
                            className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
                            onClick={() => handleDeleteProperty(p.id, p.name)}
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
          </CardContent>
        </Card>
      )}

      {/* TAB 2: PROPERTY AUTHORIZATION MATRIX */}
      {activeTab === "matrix" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-muted/40 p-3 rounded-lg border border-border">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-muted-foreground uppercase">Presets:</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleApplyPreset("DENY_SENSITIVE")}
                className="text-xs h-7"
              >
                🔒 Deny Sensitive for Non-Admin
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleApplyPreset("ALLOW_ALL")}
                className="text-xs h-7"
              >
                Allow All
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleApplyPreset("DENY_ALL")}
                className="text-xs h-7"
              >
                Deny All
              </Button>
            </div>

            <div className="flex items-center gap-2">
              {Object.keys(pendingMatrixChanges).length > 0 && (
                <span className="text-xs text-amber-400 font-medium">
                  {Object.keys(pendingMatrixChanges).length} unsaved change(s)
                </span>
              )}
              <Button
                size="sm"
                onClick={handleSaveMatrixChanges}
                disabled={savingMatrix || Object.keys(pendingMatrixChanges).length === 0}
                className="h-8"
              >
                {savingMatrix ? "Saving..." : "Save Matrix Rules"}
              </Button>
            </div>
          </div>

          <Card className="border-border">
            <CardContent className="p-0">
              {!matrixData || matrixData.properties.length === 0 ? (
                <div className="p-12 text-center text-muted-foreground">
                  <p className="text-base font-semibold">No properties in matrix</p>
                  <p className="text-sm mt-1">Add properties to this resource first to configure role-based rules.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-muted/50 border-b border-border text-xs font-semibold text-muted-foreground">
                      <tr>
                        <th className="px-4 py-3 min-w-[200px]">Property (Field)</th>
                        <th className="px-4 py-3 min-w-[120px]">Sensitivity</th>
                        {matrixData.roles.map((role) => (
                          <th key={role.id} className="px-4 py-3 text-center min-w-[140px]">
                            <div className="font-semibold text-foreground">{role.name}</div>
                            {role.description && (
                              <div className="text-[10px] text-muted-foreground font-normal truncate max-w-[120px] mx-auto">
                                {role.description}
                              </div>
                            )}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {matrixData.properties.map((prop) => (
                        <tr key={prop.id} className="hover:bg-muted/20 transition-colors">
                          <td className="px-4 py-3">
                            <div className="font-mono font-medium text-foreground">{prop.name}</div>
                            <div className="text-xs text-muted-foreground">{prop.data_type}</div>
                          </td>
                          <td className="px-4 py-3">{renderSensitivityBadge(prop.sensitivity)}</td>
                          {matrixData.roles.map((role) => {
                            const key = `${prop.id}:${role.id}`;
                            const currentAccess = pendingMatrixChanges[key] !== undefined
                              ? pendingMatrixChanges[key]
                              : (prop.rules[role.id] || "UNKNOWN");

                            return (
                              <td key={role.id} className="px-4 py-3 text-center">
                                <select
                                  value={currentAccess}
                                  onChange={(e) => handleMatrixCellChange(prop.id, role.id, e.target.value)}
                                  className={`px-2 py-1 rounded text-xs font-bold border transition-colors focus:outline-hidden ${
                                    currentAccess === "DENY"
                                      ? "bg-rose-500/20 text-rose-300 border-rose-500/40"
                                      : currentAccess === "ALLOW"
                                      ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                                      : "bg-muted text-muted-foreground border-border"
                                  }`}
                                >
                                  <option value="UNKNOWN">UNKNOWN</option>
                                  <option value="ALLOW">ALLOW</option>
                                  <option value="DENY">DENY</option>
                                </select>
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* MODAL: ADD PROPERTY */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <Card className="w-full max-w-md border-border shadow-xl">
            <form onSubmit={handleAddProperty}>
              <div className="p-5 border-b border-border flex items-center justify-between">
                <h2 className="text-lg font-bold">Add Property to {activeResource?.name}</h2>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="text-muted-foreground hover:text-foreground text-sm font-semibold"
                >
                  ✕
                </button>
              </div>

              <div className="p-5 space-y-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                    Property Path / Name *
                  </label>
                  <Input
                    placeholder="e.g. role, email, profile.salary, items[].token"
                    value={propName}
                    onChange={(e) => setPropName(e.target.value)}
                    required
                  />
                  <p className="text-[11px] text-muted-foreground mt-1">
                    Supports nested objects (e.g. user.profile.role) and arrays (e.g. accounts[].id).
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Data Type
                    </label>
                    <select
                      value={propDataType}
                      onChange={(e) => setPropDataType(e.target.value)}
                      className="w-full bg-card border border-border text-foreground rounded-md px-3 py-2 text-sm focus:outline-hidden"
                    >
                      <option value="string">string</option>
                      <option value="number">number</option>
                      <option value="boolean">boolean</option>
                      <option value="object">object</option>
                      <option value="array">array</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Sensitivity
                    </label>
                    <select
                      value={propSensitivity}
                      onChange={(e) => setPropSensitivity(e.target.value)}
                      className="w-full bg-card border border-border text-foreground rounded-md px-3 py-2 text-sm focus:outline-hidden"
                    >
                      <option value="PUBLIC">PUBLIC</option>
                      <option value="INTERNAL">INTERNAL</option>
                      <option value="SENSITIVE">SENSITIVE</option>
                      <option value="SECRET">SECRET</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                    Description
                  </label>
                  <Input
                    placeholder="Context or documentation for this field"
                    value={propDescription}
                    onChange={(e) => setPropDescription(e.target.value)}
                  />
                </div>
              </div>

              <div className="p-4 border-t border-border flex items-center justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setShowAddModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={submittingProp || !propName.trim()}>
                  {submittingProp ? "Creating..." : "Create Property"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* MODAL: EDIT PROPERTY */}
      {editingProp && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <Card className="w-full max-w-md border-border shadow-xl">
            <form onSubmit={handleEditProperty}>
              <div className="p-5 border-b border-border flex items-center justify-between">
                <h2 className="text-lg font-bold">Edit Property</h2>
                <button
                  type="button"
                  onClick={() => setEditingProp(null)}
                  className="text-muted-foreground hover:text-foreground text-sm font-semibold"
                >
                  ✕
                </button>
              </div>

              <div className="p-5 space-y-4">
                <div>
                  <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                    Property Path / Name *
                  </label>
                  <Input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Data Type
                    </label>
                    <select
                      value={editDataType}
                      onChange={(e) => setEditDataType(e.target.value)}
                      className="w-full bg-card border border-border text-foreground rounded-md px-3 py-2 text-sm focus:outline-hidden"
                    >
                      <option value="string">string</option>
                      <option value="number">number</option>
                      <option value="boolean">boolean</option>
                      <option value="object">object</option>
                      <option value="array">array</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Sensitivity
                    </label>
                    <select
                      value={editSensitivity}
                      onChange={(e) => setEditSensitivity(e.target.value)}
                      className="w-full bg-card border border-border text-foreground rounded-md px-3 py-2 text-sm focus:outline-hidden"
                    >
                      <option value="PUBLIC">PUBLIC</option>
                      <option value="INTERNAL">INTERNAL</option>
                      <option value="SENSITIVE">SENSITIVE</option>
                      <option value="SECRET">SECRET</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                    Description
                  </label>
                  <Input
                    value={editDescription}
                    onChange={(e) => setEditDescription(e.target.value)}
                  />
                </div>
              </div>

              <div className="p-4 border-t border-border flex items-center justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => setEditingProp(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={submittingEdit || !editName.trim()}>
                  {submittingEdit ? "Updating..." : "Update Property"}
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* MODAL: DISCOVER PROPERTIES */}
      {showDiscoverModal && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <Card className="w-full max-w-2xl border-border shadow-2xl max-h-[90vh] flex flex-col">
            <div className="p-5 border-b border-border flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold flex items-center gap-2">
                  <span>⚡</span> Discover Candidate Properties
                </h2>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Analyze response payloads or schemas. Heuristics automatically suggest sensitivity without creating findings.
                </p>
              </div>
              <button
                type="button"
                onClick={() => {
                  setShowDiscoverModal(false);
                  setCandidates([]);
                }}
                className="text-muted-foreground hover:text-foreground text-sm font-semibold"
              >
                ✕
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-y-auto flex-1">
              {candidates.length === 0 ? (
                <>
                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Option A: Paste Sample JSON Response Body
                    </label>
                    <textarea
                      rows={6}
                      placeholder='{"id": "123", "role": "User", "internal_notes": "...", "billing": {"credit_card": "..."}}'
                      value={discoverSampleJson}
                      onChange={(e) => setDiscoverSampleJson(e.target.value)}
                      className="w-full font-mono text-xs bg-card border border-border rounded-lg p-3 text-foreground focus:outline-hidden focus:ring-1 focus:ring-primary"
                    />
                  </div>

                  <div className="relative flex py-1 items-center">
                    <div className="grow border-t border-border"></div>
                    <span className="shrink mx-4 text-xs text-muted-foreground uppercase font-semibold">OR</span>
                    <div className="grow border-t border-border"></div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold uppercase text-muted-foreground mb-1">
                      Option B: Extract from Existing Endpoint Execution or Schema
                    </label>
                    <select
                      value={discoverEndpointId}
                      onChange={(e) => setDiscoverEndpointId(e.target.value ? Number(e.target.value) : "")}
                      className="w-full bg-card border border-border text-foreground rounded-lg px-3 py-2 text-sm focus:outline-hidden"
                    >
                      <option value="">Select an endpoint...</option>
                      {endpoints.map((ep) => (
                        <option key={ep.id} value={ep.id}>
                          {ep.method} {ep.path} {ep.summary ? `— ${ep.summary}` : ""}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="p-3 bg-muted/40 rounded-lg text-xs text-muted-foreground space-y-1">
                    <p className="font-semibold text-foreground">Sensitive Pattern Heuristics Scanned:</p>
                    <p>token, secret, password, key, ssn, credit_card, salary, internal_notes, role, admin</p>
                  </div>
                </>
              ) : (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-foreground">
                      Discovered {candidates.length} Candidate Propert(ies):
                    </span>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="text-xs h-7"
                        onClick={() => {
                          const all: Record<string, boolean> = {};
                          candidates.forEach((c) => (all[c.path] = true));
                          setSelectedCandidates(all);
                        }}
                      >
                        Select All
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="text-xs h-7"
                        onClick={() => setSelectedCandidates({})}
                      >
                        Clear All
                      </Button>
                    </div>
                  </div>

                  <div className="border border-border rounded-lg overflow-hidden max-h-80 overflow-y-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-muted/60 border-b border-border uppercase font-semibold text-muted-foreground">
                        <tr>
                          <th className="p-2.5 w-8"></th>
                          <th className="p-2.5">Path</th>
                          <th className="p-2.5">Type</th>
                          <th className="p-2.5">Suggested Sensitivity</th>
                          <th className="p-2.5">Matched Heuristic</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {candidates.map((c) => (
                          <tr key={c.path} className="hover:bg-muted/30 transition-colors">
                            <td className="p-2.5">
                              <input
                                type="checkbox"
                                checked={!!selectedCandidates[c.path]}
                                onChange={(e) =>
                                  setSelectedCandidates((prev) => ({
                                    ...prev,
                                    [c.path]: e.target.checked,
                                  }))
                                }
                                className="rounded border-border"
                              />
                            </td>
                            <td className="p-2.5 font-mono font-medium text-foreground">{c.path}</td>
                            <td className="p-2.5 text-muted-foreground">{c.data_type}</td>
                            <td className="p-2.5">{renderSensitivityBadge(c.suggested_sensitivity)}</td>
                            <td className="p-2.5 text-muted-foreground">
                              {c.matched_heuristic ? (
                                <span className="bg-muted px-1.5 py-0.5 rounded text-[11px] font-mono">
                                  {c.matched_heuristic}
                                </span>
                              ) : (
                                "—"
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-border flex items-center justify-between">
              {candidates.length > 0 ? (
                <Button
                  variant="default"
                  size="sm"
                  onClick={() => setCandidates([])}
                >
                  ← Back to Input
                </Button>
              ) : (
                <div></div>
              )}

              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setShowDiscoverModal(false);
                    setCandidates([]);
                  }}
                >
                  Cancel
                </Button>

                {candidates.length === 0 ? (
                  <Button
                    size="sm"
                    onClick={handleRunDiscovery}
                    disabled={discovering || (!discoverSampleJson.trim() && !discoverEndpointId)}
                  >
                    {discovering ? "Scanning Payload..." : "Scan & Discover"}
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    onClick={handleImportCandidates}
                    disabled={importingCandidates || Object.values(selectedCandidates).filter(Boolean).length === 0}
                  >
                    {importingCandidates
                      ? "Importing..."
                      : `Import ${Object.values(selectedCandidates).filter(Boolean).length} Selected`}
                  </Button>
                )}
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
