"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface AttackGraphNodeItem {
  id: string;
  graph_id: string;
  finding_id?: string | null;
  node_type: string;
  label: string;
  metadata?: Record<string, unknown> | null;
  created_at: string;
  finding_severity?: string | null;
  finding_type?: string | null;
}

interface AttackGraphEdgeItem {
  id: string;
  graph_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  confidence: string;
  reason: string;
  metadata?: Record<string, unknown> | null;
  created_at: string;
  source_label?: string | null;
  target_label?: string | null;
}

interface AttackGraphItem {
  id: string;
  project_id: number;
  name: string;
  description?: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  node_count: number;
  edge_count: number;
}

interface AttackGraphDetailItem extends AttackGraphItem {
  nodes: AttackGraphNodeItem[];
  edges: AttackGraphEdgeItem[];
}

interface FindingCorrelationItem {
  id: string;
  project_id: number;
  finding_a_id: string;
  finding_b_id: string;
  relationship_type: string;
  confidence: string;
  reason: string;
  created_at: string;
  finding_a_title?: string | null;
  finding_b_title?: string | null;
  finding_a_type?: string | null;
  finding_b_type?: string | null;
  finding_a_severity?: string | null;
  finding_b_severity?: string | null;
}

interface CorrelationRunResult {
  project_id: number;
  confirmed_findings_count: number;
  correlations_count: number;
  new_correlations_count: number;
  graph_id: string;
  node_count: number;
  edge_count: number;
  correlations: FindingCorrelationItem[];
  graph?: AttackGraphItem | null;
}

interface AttackPathStepItem {
  id: string;
  attack_path_id: string;
  position: number;
  finding_id: string;
  prerequisite_finding_id?: string | null;
  relationship_type: string;
  reason: string;
  created_at: string;
  finding_title?: string | null;
  finding_type?: string | null;
  finding_severity?: string | null;
  prerequisite_finding_title?: string | null;
  endpoint_path?: string | null;
  resource_name?: string | null;
  identity_name?: string | null;
}

interface AttackPathItem {
  id: string;
  project_id: number;
  attack_graph_id: string;
  name: string;
  description?: string | null;
  status: string;
  confidence: string;
  created_at: string;
  updated_at: string;
  step_count: number;
  steps: AttackPathStepItem[];
}

interface FindingDetailItem {
  id: string;
  project_id: number;
  endpoint_id?: number | null;
  attacker_identity_id?: string | null;
  resource_id?: string | null;
  workflow_id?: string | null;
  type: string;
  severity: string;
  confidence: string;
  status: string;
  title: string;
  description: string;
  expected_authorization?: string | null;
  actual_behavior?: string | null;
  exposed_properties?: string | null;
  authentication_mechanism?: string | null;
  remediation: string;
  created_at: string;
  updated_at: string;
  endpoint?: { method: string; path: string } | null;
  attacker_identity?: { name: string; auth_type: string } | null;
  resource?: { name: string; resource_type: string } | null;
}

export default function AttackGraphPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [graphDetail, setGraphDetail] = useState<AttackGraphDetailItem | null>(null);
  const [correlations, setCorrelations] = useState<FindingCorrelationItem[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPathItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [analyzingPaths, setAnalyzingPaths] = useState(false);
  const [rebuildingPathId, setRebuildingPathId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Finding Detail Drawer State
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [findingDetail, setFindingDetail] = useState<FindingDetailItem | null>(null);
  const [loadingFindingDetail, setLoadingFindingDetail] = useState(false);

  // Filters & Selected elements
  const [viewTab, setViewTab] = useState<"paths" | "graph" | "correlations" | "nodes">("paths");
  const [pathConfidenceFilter, setPathConfidenceFilter] = useState<string>("ALL");
  const [relFilter, setRelFilter] = useState<string>("ALL");
  const [nodeTypeFilter, setNodeTypeFilter] = useState<string>("ALL");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // Load projects on mount
  useEffect(() => {
    async function loadProjects() {
      try {
        setLoading(true);
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
        const data: Project[] = await res.json();
        setProjects(data);
        if (data.length > 0) {
          setSelectedProjectId(data[0].id);
        }
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load projects");
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  // Load project graphs, correlations, and attack paths when project changes
  useEffect(() => {
    if (!selectedProjectId) return;

    async function loadProjectData() {
      try {
        setErrorMsg(null);
        setSelectedNodeId(null);
        setSelectedEdgeId(null);

        // Load correlations
        const corrRes = await fetch(`/api/v1/projects/${selectedProjectId}/correlations`, { credentials: "include" });
        if (corrRes.ok) {
          const corrData: FindingCorrelationItem[] = await corrRes.json();
          setCorrelations(corrData);
        }

        // Load graphs
        const graphsRes = await fetch(`/api/v1/projects/${selectedProjectId}/attack-graphs`, { credentials: "include" });
        if (graphsRes.ok) {
          const graphsData: AttackGraphItem[] = await graphsRes.json();
          if (graphsData.length > 0) {
            const activeGraph = graphsData.find((g) => g.status === "ACTIVE") || graphsData[0];
            const detailRes = await fetch(`/api/v1/attack-graphs/${activeGraph.id}`, { credentials: "include" });
            if (detailRes.ok) {
              const detailData: AttackGraphDetailItem = await detailRes.json();
              setGraphDetail(detailData);
            }
          } else {
            setGraphDetail(null);
          }
        }

        // Load attack paths
        const pathsRes = await fetch(`/api/v1/projects/${selectedProjectId}/attack-paths`, { credentials: "include" });
        if (pathsRes.ok) {
          const pathsData: AttackPathItem[] = await pathsRes.json();
          setAttackPaths(pathsData);
        }
      } catch (err: unknown) {
        setErrorMsg(err instanceof Error ? err.message : "Failed to load attack graph data");
      }
    }

    loadProjectData();
  }, [selectedProjectId]);

  // Run Correlation & Build Graph
  const handleRunCorrelation = async () => {
    if (!selectedProjectId) return;
    try {
      setRunning(true);
      setErrorMsg(null);
      setSuccessMsg(null);

      const res = await fetch(`/api/v1/projects/${selectedProjectId}/correlation/run`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to run correlation");
      }

      const data: CorrelationRunResult = await res.json();
      setCorrelations(data.correlations);
      setSuccessMsg(
        `Correlation completed: ${data.confirmed_findings_count} confirmed findings, ${data.correlations_count} correlations (${data.new_correlations_count} new). Graph built with ${data.node_count} nodes & ${data.edge_count} edges.`
      );

      // Fetch newly created/updated graph detail
      if (data.graph_id) {
        const detailRes = await fetch(`/api/v1/attack-graphs/${data.graph_id}`, { credentials: "include" });
        if (detailRes.ok) {
          const detailData: AttackGraphDetailItem = await detailRes.json();
          setGraphDetail(detailData);
        }
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to run correlation engine");
    } finally {
      setRunning(false);
    }
  };

  // Run Attack Path Analysis
  const handleAnalyzeAttackPaths = async () => {
    if (!selectedProjectId) return;
    try {
      setAnalyzingPaths(true);
      setErrorMsg(null);
      setSuccessMsg(null);

      const res = await fetch(`/api/v1/projects/${selectedProjectId}/attack-paths/analyze`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to analyze attack paths");
      }

      const data = await res.json();
      setAttackPaths(data.paths);
      setSuccessMsg(
        `Attack path analysis complete: detected ${data.paths_count} confirmed attack paths.`
      );
      setViewTab("paths");
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to detect attack paths");
    } finally {
      setAnalyzingPaths(false);
    }
  };

  // Rebuild specific attack path
  const handleRebuildPath = async (pathId: string) => {
    try {
      setRebuildingPathId(pathId);
      setErrorMsg(null);

      const res = await fetch(`/api/v1/attack-paths/${pathId}/rebuild`, {
        method: "POST",
        credentials: "include",
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to rebuild attack path");
      }

      const updatedPath: AttackPathItem = await res.json();
      setAttackPaths((prev) => prev.map((p) => (p.id === pathId ? updatedPath : p)));
      setSuccessMsg(`Attack path "${updatedPath.name}" rebuilt and validated offline.`);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to rebuild attack path");
    } finally {
      setRebuildingPathId(null);
    }
  };

  // Open Finding Detail Drawer
  const handleOpenFindingDetail = async (findingId: string) => {
    try {
      setSelectedFindingId(findingId);
      setLoadingFindingDetail(true);
      const res = await fetch(`/api/v1/findings/${findingId}`, { credentials: "include" });
      if (res.ok) {
        const data: FindingDetailItem = await res.json();
        setFindingDetail(data);
      } else {
        setFindingDetail(null);
      }
    } catch {
      setFindingDetail(null);
    } finally {
      setLoadingFindingDetail(false);
    }
  };

  // Distinct relationship types for filtering
  const availableRelTypes = useMemo(() => {
    const types = new Set<string>();
    if (graphDetail?.edges) {
      graphDetail.edges.forEach((e) => types.add(e.relationship_type));
    }
    correlations.forEach((c) => types.add(c.relationship_type));
    return Array.from(types).sort();
  }, [graphDetail, correlations]);

  // Distinct node types for filtering
  const availableNodeTypes = useMemo(() => {
    const types = new Set<string>();
    if (graphDetail?.nodes) {
      graphDetail.nodes.forEach((n) => types.add(n.node_type));
    }
    return Array.from(types).sort();
  }, [graphDetail]);

  // Filtered nodes and edges
  const filteredNodes = useMemo(() => {
    if (!graphDetail?.nodes) return [];
    return graphDetail.nodes.filter((node) => {
      if (nodeTypeFilter !== "ALL" && node.node_type !== nodeTypeFilter) return false;
      return true;
    });
  }, [graphDetail, nodeTypeFilter]);

  const filteredEdges = useMemo(() => {
    if (!graphDetail?.edges) return [];
    const validNodeIds = new Set(filteredNodes.map((n) => n.id));
    return graphDetail.edges.filter((edge) => {
      if (relFilter !== "ALL" && edge.relationship_type !== relFilter) return false;
      if (!validNodeIds.has(edge.source_node_id) || !validNodeIds.has(edge.target_node_id)) {
        return false;
      }
      return true;
    });
  }, [graphDetail, filteredNodes, relFilter]);

  // Filtered attack paths
  const filteredAttackPaths = useMemo(() => {
    return attackPaths.filter((path) => {
      if (pathConfidenceFilter !== "ALL" && path.confidence !== pathConfidenceFilter) {
        return false;
      }
      return true;
    });
  }, [attackPaths, pathConfidenceFilter]);

  // Selected node and edge items
  const selectedNode = useMemo(() => {
    if (!selectedNodeId || !graphDetail?.nodes) return null;
    return graphDetail.nodes.find((n) => n.id === selectedNodeId) || null;
  }, [selectedNodeId, graphDetail]);

  const selectedEdge = useMemo(() => {
    if (!selectedEdgeId || !graphDetail?.edges) return null;
    return graphDetail.edges.find((e) => e.id === selectedEdgeId) || null;
  }, [selectedEdgeId, graphDetail]);

  // Count unique findings participating in correlations
  const correlatedFindingCount = useMemo(() => {
    const ids = new Set<string>();
    correlations.forEach((c) => {
      ids.add(c.finding_a_id);
      ids.add(c.finding_b_id);
    });
    return ids.size;
  }, [correlations]);

  // Deterministic SVG Node Coordinates Layout
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    if (!filteredNodes || filteredNodes.length === 0) return positions;

    const findingNodes = filteredNodes.filter((n) => n.node_type === "FINDING");
    const contextNodes = filteredNodes.filter((n) => n.node_type !== "FINDING");

    const width = 860;
    const height = 560;
    const centerX = width / 2;
    const centerY = height / 2;

    // Inner circle for Finding nodes
    if (findingNodes.length === 1) {
      positions[findingNodes[0].id] = { x: centerX, y: centerY };
    } else {
      const innerRadius = Math.min(150, 40 + findingNodes.length * 20);
      findingNodes.forEach((node, idx) => {
        const angle = (2 * Math.PI * idx) / findingNodes.length;
        positions[node.id] = {
          x: centerX + innerRadius * Math.cos(angle),
          y: centerY + innerRadius * Math.sin(angle),
        };
      });
    }

    // Outer circle for Context nodes
    if (contextNodes.length > 0) {
      const outerRadius = Math.min(240, 180 + contextNodes.length * 8);
      contextNodes.forEach((node, idx) => {
        const angle = (2 * Math.PI * idx) / contextNodes.length - Math.PI / 2;
        positions[node.id] = {
          x: centerX + outerRadius * Math.cos(angle),
          y: centerY + outerRadius * Math.sin(angle),
        };
      });
    }

    return positions;
  }, [filteredNodes]);

  // Node color helper
  const getNodeColor = (node: AttackGraphNodeItem) => {
    switch (node.node_type) {
      case "FINDING":
        if (node.finding_severity === "CRITICAL") return { bg: "#ef4444", border: "#f87171", text: "#fee2e2" };
        if (node.finding_severity === "HIGH") return { bg: "#f43f5e", border: "#fb7185", text: "#ffe4e6" };
        if (node.finding_severity === "MEDIUM") return { bg: "#f59e0b", border: "#fbbf24", text: "#fef3c7" };
        return { bg: "#3b82f6", border: "#60a5fa", text: "#dbeafe" };
      case "ENDPOINT":
        return { bg: "#0284c7", border: "#38bdf8", text: "#e0f2fe" };
      case "IDENTITY":
        return { bg: "#ea580c", border: "#fb923c", text: "#ffedd5" };
      case "RESOURCE":
        return { bg: "#10b981", border: "#34d399", text: "#d1fae5" };
      case "WORKFLOW":
        return { bg: "#8b5cf6", border: "#a78bfa", text: "#ede9fe" };
      case "WORKFLOW_EXECUTION":
        return { bg: "#06b6d4", border: "#22d3ee", text: "#cffafe" };
      case "AUTHENTICATION":
        return { bg: "#ec4899", border: "#f472b6", text: "#fce7f3" };
      case "PROPERTY":
        return { bg: "#eab308", border: "#facc15", text: "#fef9c3" };
      case "ROLE":
        return { bg: "#6366f1", border: "#818cf8", text: "#e0e7ff" };
      default:
        return { bg: "#64748b", border: "#94a3b8", text: "#f1f5f9" };
    }
  };

  // Edge stroke color helper
  const getEdgeColor = (relType: string) => {
    switch (relType) {
      case "AUTH_TO_AUTHORIZATION":
        return "#ec4899"; // pink
      case "AUTHORIZATION_TO_WORKFLOW":
        return "#a855f7"; // purple
      case "PROPERTY_EXPOSURE_CHAIN":
        return "#eab308"; // yellow
      case "SAME_ENDPOINT":
        return "#38bdf8"; // sky blue
      case "SAME_IDENTITY":
        return "#fb923c"; // orange
      case "SAME_RESOURCE":
        return "#34d399"; // emerald
      case "SAME_WORKFLOW":
        return "#8b5cf6"; // violet
      case "SAME_EXECUTION":
        return "#06b6d4"; // cyan
      default:
        return "#64748b"; // slate
    }
  };

  // Finding badge style helper
  const getFindingSeverityBadge = (severity?: string | null) => {
    switch (severity?.toUpperCase()) {
      case "CRITICAL":
        return "bg-red-500/20 text-red-300 border-red-500/40";
      case "HIGH":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      default:
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Deterministic Attack Graph & Attack Path Detection
            </h1>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase">
              Stage 8.2
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Convert finding correlations into explainable, ordered security exploit chains without target traffic.
          </p>
        </div>

        {/* Project Selector & Actions */}
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground whitespace-nowrap">
              Project:
            </label>
            <select
              className="h-9 px-3 py-1 bg-background border border-input rounded-md text-sm font-medium focus:ring-1 focus:ring-primary outline-none"
              value={selectedProjectId || ""}
              onChange={(e) => setSelectedProjectId(Number(e.target.value))}
              disabled={loading || projects.length === 0}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <Button
            size="sm"
            onClick={handleRunCorrelation}
            disabled={running || !selectedProjectId}
            variant="outline"
            className="border-purple-500/30 hover:bg-purple-500/10 text-purple-300"
          >
            {running ? (
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
                Correlating...
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <span>⚡</span>
                Run Correlation
              </span>
            )}
          </Button>

          <Button
            size="sm"
            onClick={handleAnalyzeAttackPaths}
            disabled={analyzingPaths || !selectedProjectId}
            className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium"
          >
            {analyzingPaths ? (
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Detecting Paths...
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <span>⚔️</span>
                Detect Attack Paths
              </span>
            )}
          </Button>
        </div>
      </div>

      {/* Safety & Analytics Principles Banner */}
      <div className="rounded-lg border border-purple-500/30 bg-purple-500/10 p-3.5 text-xs leading-relaxed text-purple-300">
        <div className="flex items-start gap-2">
          <span className="text-base font-bold">🛡️</span>
          <div>
            <strong className="font-semibold text-purple-200">Analytical Safety Guarantee:</strong> Finding correlation and attack path detection operate strictly on confirmed findings without executing requests against the target API. No AI or probabilistic inference is used; all relationships and attack chains are derived through deterministic domain rules.
          </div>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="rounded-md bg-destructive/15 border border-destructive/30 p-3 text-sm text-destructive flex justify-between items-center">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg(null)} className="text-xs font-bold hover:underline">
            Dismiss
          </button>
        </div>
      )}
      {successMsg && (
        <div className="rounded-md bg-emerald-500/15 border border-emerald-500/30 p-3 text-sm text-emerald-400 flex justify-between items-center">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-xs font-bold hover:underline">
            Dismiss
          </button>
        </div>
      )}

      {/* Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-card border border-border rounded-lg p-3.5">
          <span className="text-[10px] uppercase text-muted-foreground block font-bold">Total Confirmed Findings</span>
          <span className="text-2xl font-bold text-foreground">
            {graphDetail?.nodes.filter((n) => n.node_type === "FINDING").length || 0}
          </span>
        </div>
        <div className="bg-card border border-purple-500/30 rounded-lg p-3.5">
          <span className="text-[10px] uppercase text-purple-400 block font-bold">Correlated Findings</span>
          <span className="text-2xl font-bold text-purple-400">{correlatedFindingCount}</span>
        </div>
        <div className="bg-card border border-indigo-500/40 rounded-lg p-3.5 bg-indigo-500/5">
          <span className="text-[10px] uppercase text-indigo-400 block font-bold">Confirmed Attack Paths</span>
          <span className="text-2xl font-bold text-indigo-400">{attackPaths.length}</span>
        </div>
        <div className="bg-card border border-border rounded-lg p-3.5">
          <span className="text-[10px] uppercase text-muted-foreground block font-bold">Attack Graph Nodes</span>
          <span className="text-2xl font-bold text-foreground">{graphDetail?.nodes.length || 0}</span>
        </div>
      </div>

      {/* Navigation Tabs and Controls */}
      <Card className="p-4 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-3">
          {/* Subnav Tabs */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setViewTab("paths")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 ${
                viewTab === "paths"
                  ? "bg-indigo-600 text-white"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              <span>⚔️</span>
              Attack Paths ({attackPaths.length})
            </button>
            <button
              onClick={() => setViewTab("graph")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
                viewTab === "graph"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              Interactive Graph ({filteredNodes.length} Nodes)
            </button>
            <button
              onClick={() => setViewTab("correlations")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
                viewTab === "correlations"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              Correlations Table ({correlations.length})
            </button>
            <button
              onClick={() => setViewTab("nodes")}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md transition-colors ${
                viewTab === "nodes"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground hover:text-foreground"
              }`}
            >
              Graph Nodes ({graphDetail?.nodes.length || 0})
            </button>
          </div>

          {/* Contextual Filters */}
          {viewTab === "paths" ? (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-muted-foreground">Confidence:</span>
              <select
                className="h-8 px-2 bg-background border border-input rounded text-xs outline-none"
                value={pathConfidenceFilter}
                onChange={(e) => setPathConfidenceFilter(e.target.value)}
              >
                <option value="ALL">All Confidences</option>
                <option value="HIGH">HIGH Confidence</option>
                <option value="MEDIUM">MEDIUM Confidence</option>
              </select>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-muted-foreground">Relationship:</span>
                <select
                  className="h-8 px-2 bg-background border border-input rounded text-xs outline-none"
                  value={relFilter}
                  onChange={(e) => setRelFilter(e.target.value)}
                >
                  <option value="ALL">All Relationships ({availableRelTypes.length})</option>
                  {availableRelTypes.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-muted-foreground">Node Type:</span>
                <select
                  className="h-8 px-2 bg-background border border-input rounded text-xs outline-none"
                  value={nodeTypeFilter}
                  onChange={(e) => setNodeTypeFilter(e.target.value)}
                >
                  <option value="ALL">All Types ({availableNodeTypes.length})</option>
                  {availableNodeTypes.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </div>

        {/* View Tab 1: Attack Paths View (Stage 8.2) */}
        {viewTab === "paths" && (
          <div className="space-y-6">
            {/* Core Distinction Callout */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="p-3 rounded-lg border border-purple-500/30 bg-purple-500/5 space-y-1">
                <span className="font-bold text-purple-300 uppercase tracking-wide text-[10px]">
                  Correlated Findings
                </span>
                <p className="text-muted-foreground leading-relaxed">
                  Multiple confirmed findings sharing domain context (e.g. same endpoint, identity, or resource). Demonstrates analytical relationship without implied chronological exploit order.
                </p>
              </div>
              <div className="p-3 rounded-lg border border-indigo-500/30 bg-indigo-500/5 space-y-1">
                <span className="font-bold text-indigo-300 uppercase tracking-wide text-[10px]">
                  Confirmed Attack Path
                </span>
                <p className="text-muted-foreground leading-relaxed">
                  An ordered, causal security chain where an attacker leverages an initial flaw (e.g. Authentication Bypass) to unlock subsequent authorizations, workflows, and property extractions.
                </p>
              </div>
            </div>

            {/* Attack Path List */}
            {filteredAttackPaths.length === 0 ? (
              <div className="text-center py-16 space-y-3 border border-dashed border-border rounded-xl">
                <div className="text-3xl">⚔️</div>
                <div className="font-semibold text-sm text-foreground">No Attack Paths Detected</div>
                <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                  Click <strong>Detect Attack Paths</strong> to evaluate confirmed finding correlations and synthesize sequential exploit chains.
                </p>
                <Button
                  size="sm"
                  onClick={handleAnalyzeAttackPaths}
                  disabled={analyzingPaths || !selectedProjectId}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-medium"
                >
                  Detect Attack Paths Now
                </Button>
              </div>
            ) : (
              <div className="space-y-5">
                {filteredAttackPaths.map((path) => (
                  <div
                    key={path.id}
                    className="p-5 rounded-xl border border-border bg-card/70 space-y-4 shadow-sm"
                  >
                    {/* Path Card Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/60 pb-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="text-sm font-bold text-foreground">{path.name}</h3>
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                              path.confidence === "HIGH"
                                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                                : "bg-amber-500/20 text-amber-300 border-amber-500/30"
                            }`}
                          >
                            {path.confidence} Confidence
                          </span>
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-muted text-muted-foreground uppercase">
                            {path.status}
                          </span>
                          <span className="text-[10px] font-mono text-muted-foreground">
                            {path.steps.length} Steps
                          </span>
                        </div>
                      </div>

                      {/* Rebuild Path Button */}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleRebuildPath(path.id)}
                        disabled={rebuildingPathId === path.id}
                        className="text-xs h-7 px-2.5 border-border hover:bg-muted"
                      >
                        {rebuildingPathId === path.id ? (
                          <span className="flex items-center gap-1">
                            <span className="inline-block w-2.5 h-2.5 border-2 border-current border-t-transparent rounded-full animate-spin" />
                            Rebuilding...
                          </span>
                        ) : (
                          "Rebuild Path"
                        )}
                      </Button>
                    </div>

                    {/* Synthesized Human-Readable Narrative Explanation */}
                    {path.description && (
                      <div className="rounded-lg bg-indigo-500/10 border border-indigo-500/20 p-3 text-xs leading-relaxed text-indigo-200">
                        <strong className="font-semibold text-indigo-300 block mb-1">
                          Deterministic Exploit Sequence Narrative:
                        </strong>
                        {path.description}
                      </div>
                    )}

                    {/* Ordered Visual Chain */}
                    <div className="space-y-3 pt-2">
                      <span className="text-[10px] uppercase font-bold text-muted-foreground block">
                        Ordered Execution Chain
                      </span>

                      <div className="space-y-2">
                        {path.steps.map((step, idx) => {
                          const isLast = idx === path.steps.length - 1;
                          return (
                            <React.Fragment key={step.id}>
                              {/* Step Node Card */}
                              <div
                                onClick={() => handleOpenFindingDetail(step.finding_id)}
                                className="group cursor-pointer p-3.5 rounded-lg border border-border/80 bg-background/80 hover:bg-muted/30 hover:border-indigo-500/50 transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                              >
                                <div className="space-y-1.5">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-muted text-foreground">
                                      Step {step.position}
                                    </span>
                                    <span
                                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getFindingSeverityBadge(
                                        step.finding_severity
                                      )}`}
                                    >
                                      {step.finding_type || "FINDING"}
                                    </span>
                                    <span className="text-xs font-semibold text-foreground group-hover:text-indigo-300 transition-colors">
                                      {step.finding_title || `Finding #${step.finding_id}`}
                                    </span>
                                  </div>

                                  {/* Contextual Badges */}
                                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                                    {step.endpoint_path && (
                                      <span className="font-mono bg-muted/40 px-1.5 py-0.5 rounded">
                                        Endpoint: {step.endpoint_path}
                                      </span>
                                    )}
                                    {step.identity_name && (
                                      <span className="bg-muted/40 px-1.5 py-0.5 rounded">
                                        Identity: {step.identity_name}
                                      </span>
                                    )}
                                    {step.resource_name && (
                                      <span className="bg-muted/40 px-1.5 py-0.5 rounded">
                                        Resource: {step.resource_name}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  <span className="text-xs text-indigo-400 group-hover:underline whitespace-nowrap">
                                    Inspect Details →
                                  </span>
                                </div>
                              </div>

                              {/* Downward Transition Connector */}
                              {!isLast && (
                                <div className="flex flex-col items-center py-1.5">
                                  <div className="flex items-center gap-2 text-xs text-muted-foreground my-1">
                                    <div className="h-4 w-px bg-indigo-500/40" />
                                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                      {path.steps[idx + 1].relationship_type.replace(/_/g, " ")}
                                    </span>
                                    <div className="h-4 w-px bg-indigo-500/40" />
                                  </div>
                                  <span className="text-indigo-400 font-bold text-sm">↓</span>
                                  <p className="text-[11px] text-muted-foreground max-w-xl text-center italic mt-0.5 px-4">
                                    {path.steps[idx + 1].reason}
                                  </p>
                                </div>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* View Tab 2: Interactive Graph Visualizer (Stage 8.1) */}
        {viewTab === "graph" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Graph Canvas / SVG (8 cols) */}
            <div className="lg:col-span-8 bg-card/60 border border-border rounded-xl p-4 flex flex-col items-center justify-center min-h-[580px] relative overflow-hidden">
              {!graphDetail || filteredNodes.length === 0 ? (
                <div className="text-center py-16 space-y-3">
                  <div className="text-3xl">🕸️</div>
                  <div className="font-semibold text-sm text-foreground">No Attack Graph Available</div>
                  <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                    Click <strong>Run Correlation</strong> above to evaluate confirmed security findings and synthesize an explainable attack graph.
                  </p>
                  <Button
                    size="sm"
                    onClick={handleRunCorrelation}
                    disabled={running}
                    className="bg-purple-600 hover:bg-purple-500 text-white font-medium"
                  >
                    Run Correlation Now
                  </Button>
                </div>
              ) : (
                <div className="w-full flex justify-center">
                  <svg
                    viewBox="0 0 860 560"
                    className="w-full max-w-[860px] h-[540px] select-none"
                    style={{ background: "radial-gradient(circle at center, rgba(168, 85, 247, 0.05) 0%, transparent 70%)" }}
                  >
                    <defs>
                      <marker
                        id="arrowhead"
                        markerWidth="6"
                        markerHeight="4"
                        refX="14"
                        refY="2"
                        orient="auto"
                      >
                        <polygon points="0 0, 6 2, 0 4" fill="#94a3b8" />
                      </marker>
                    </defs>

                    {/* Background Grid Circles */}
                    <circle cx="430" cy="280" r="140" fill="none" stroke="currentColor" strokeDasharray="3 3" className="text-border/40" />
                    <circle cx="430" cy="280" r="230" fill="none" stroke="currentColor" strokeDasharray="3 3" className="text-border/30" />

                    {/* Graph Edges */}
                    {filteredEdges.map((edge) => {
                      const src = nodePositions[edge.source_node_id];
                      const tgt = nodePositions[edge.target_node_id];
                      if (!src || !tgt) return null;

                      const isSelected = selectedEdgeId === edge.id;
                      const isHovered =
                        hoveredNodeId === edge.source_node_id || hoveredNodeId === edge.target_node_id;
                      const strokeColor = getEdgeColor(edge.relationship_type);
                      const isCorrelation = !edge.relationship_type.includes("_TO_");

                      return (
                        <g key={edge.id} className="cursor-pointer" onClick={() => setSelectedEdgeId(edge.id)}>
                          <line
                            x1={src.x}
                            y1={src.y}
                            x2={tgt.x}
                            y2={tgt.y}
                            stroke={isSelected ? "#ec4899" : strokeColor}
                            strokeWidth={isSelected ? 3 : isHovered ? 2.5 : 1.5}
                            strokeOpacity={isSelected ? 1 : isHovered ? 0.9 : 0.6}
                            strokeDasharray={isCorrelation ? "4 3" : undefined}
                            markerEnd="url(#arrowhead)"
                          />
                        </g>
                      );
                    })}

                    {/* Graph Nodes */}
                    {filteredNodes.map((node) => {
                      const pos = nodePositions[node.id];
                      if (!pos) return null;

                      const colors = getNodeColor(node);
                      const isSelected = selectedNodeId === node.id;
                      const isHovered = hoveredNodeId === node.id;
                      const isFinding = node.node_type === "FINDING";

                      return (
                        <g
                          key={node.id}
                          transform={`translate(${pos.x}, ${pos.y})`}
                          className="cursor-pointer"
                          onMouseEnter={() => setHoveredNodeId(node.id)}
                          onMouseLeave={() => setHoveredNodeId(null)}
                          onClick={() => {
                            setSelectedNodeId(node.id);
                            if (node.finding_id) {
                              handleOpenFindingDetail(node.finding_id);
                            }
                          }}
                        >
                          <circle
                            r={isFinding ? 18 : 13}
                            fill={colors.bg}
                            stroke={isSelected ? "#ffffff" : colors.border}
                            strokeWidth={isSelected ? 3 : isHovered ? 2.5 : 1.5}
                            filter="drop-shadow(0 2px 4px rgba(0,0,0,0.4))"
                          />
                          <text
                            textAnchor="middle"
                            dy="4"
                            fontSize={isFinding ? "10" : "8"}
                            fontWeight="bold"
                            fill="#ffffff"
                          >
                            {isFinding ? node.finding_type?.slice(0, 4) || "FND" : node.node_type.slice(0, 3)}
                          </text>
                          <text
                            textAnchor="middle"
                            y={isFinding ? 28 : 22}
                            fontSize="9"
                            fontWeight="500"
                            fill="currentColor"
                            className="text-foreground pointer-events-none"
                          >
                            {node.label.length > 22 ? `${node.label.slice(0, 20)}...` : node.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
              )}
            </div>

            {/* Inspector Drawer for Nodes / Edges (4 cols) */}
            <div className="lg:col-span-4 space-y-4">
              {selectedEdge ? (
                <div className="p-4 rounded-xl border border-purple-500/30 bg-card space-y-3">
                  <div className="flex items-center justify-between border-b border-border pb-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-purple-300">
                      Relationship Detail
                    </span>
                    <button
                      onClick={() => setSelectedEdgeId(null)}
                      className="text-xs text-muted-foreground hover:text-foreground"
                    >
                      ✕
                    </button>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Type</span>
                    <span className="font-mono text-sm font-semibold text-purple-300">
                      {selectedEdge.relationship_type}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Confidence</span>
                    <span className="text-xs font-bold text-emerald-400">{selectedEdge.confidence}</span>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Source Node</span>
                    <span className="text-xs text-foreground font-medium">
                      {selectedEdge.source_label || selectedEdge.source_node_id}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Target Node</span>
                    <span className="text-xs text-foreground font-medium">
                      {selectedEdge.target_label || selectedEdge.target_node_id}
                    </span>
                  </div>

                  <div className="pt-2 border-t border-border">
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block mb-1">
                      Deterministic Explainability Reason
                    </span>
                    <p className="text-xs text-purple-200 bg-purple-500/10 p-2.5 rounded border border-purple-500/20 leading-relaxed">
                      {selectedEdge.reason}
                    </p>
                  </div>
                </div>
              ) : selectedNode ? (
                <div className="p-4 rounded-xl border border-border bg-card space-y-3">
                  <div className="flex items-center justify-between border-b border-border pb-2">
                    <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                      Node Detail
                    </span>
                    <button
                      onClick={() => setSelectedNodeId(null)}
                      className="text-xs text-muted-foreground hover:text-foreground"
                    >
                      ✕
                    </button>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Node Type</span>
                    <span className="font-mono text-sm font-semibold text-foreground uppercase">
                      {selectedNode.node_type}
                    </span>
                  </div>

                  <div>
                    <span className="text-[10px] text-muted-foreground uppercase font-bold block">Label</span>
                    <span className="text-sm font-medium text-foreground">{selectedNode.label}</span>
                  </div>

                  {selectedNode.finding_id && (
                    <div className="pt-2">
                      <Button
                        size="sm"
                        onClick={() => handleOpenFindingDetail(selectedNode.finding_id!)}
                        className="w-full text-xs bg-indigo-600 hover:bg-indigo-500 text-white"
                      >
                        Inspect Finding Record →
                      </Button>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-8 text-center text-xs text-muted-foreground border border-dashed border-border rounded-xl">
                  Select a node or relationship edge in the graph canvas to inspect explainability details.
                </div>
              )}
            </div>
          </div>
        )}

        {/* View Tab 3: Correlations Table */}
        {viewTab === "correlations" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>All deterministic pairwise finding correlations</span>
              <span>Total: {correlations.length}</span>
            </div>

            {correlations.length === 0 ? (
              <div className="text-center py-12 text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                No correlations recorded yet. Click &quot;Run Correlation&quot; to evaluate confirmed findings.
              </div>
            ) : (
              <div className="space-y-3">
                {correlations.map((corr) => (
                  <div
                    key={corr.id}
                    className="p-3.5 rounded-lg border border-border bg-card/60 space-y-2"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase">
                          {corr.relationship_type.replace(/_/g, " ")}
                        </span>
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 uppercase">
                          {corr.confidence}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        {new Date(corr.created_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs bg-muted/20 p-2.5 rounded border border-border/40">
                      <div>
                        <span className="text-[10px] text-muted-foreground block font-semibold">FINDING A</span>
                        <span className="font-semibold text-foreground">{corr.finding_a_title || corr.finding_a_id}</span>
                        {corr.finding_a_type && (
                          <span className="text-[10px] font-mono text-muted-foreground block">
                            [{corr.finding_a_severity}] {corr.finding_a_type}
                          </span>
                        )}
                      </div>
                      <div>
                        <span className="text-[10px] text-muted-foreground block font-semibold">FINDING B</span>
                        <span className="font-semibold text-foreground">{corr.finding_b_title || corr.finding_b_id}</span>
                        {corr.finding_b_type && (
                          <span className="text-[10px] font-mono text-muted-foreground block">
                            [{corr.finding_b_severity}] {corr.finding_b_type}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="text-xs text-amber-200/90 bg-amber-500/10 p-2.5 rounded border border-amber-500/20">
                      <strong>Deterministic Reason:</strong> {corr.reason}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* View Tab 4: Nodes Table */}
        {viewTab === "nodes" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>All nodes participating in the active attack graph</span>
              <span>Total: {graphDetail?.nodes.length || 0}</span>
            </div>

            {!graphDetail?.nodes || graphDetail.nodes.length === 0 ? (
              <div className="text-center py-12 text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                No graph nodes generated yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-muted/40 border-b border-border text-[10px] uppercase font-bold text-muted-foreground">
                    <tr>
                      <th className="p-2.5">Node Type</th>
                      <th className="p-2.5">Label</th>
                      <th className="p-2.5">Finding Type / Severity</th>
                      <th className="p-2.5">Created At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40">
                    {graphDetail.nodes.map((node) => (
                      <tr key={node.id} className="hover:bg-muted/20">
                        <td className="p-2.5">
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-muted text-foreground uppercase font-bold">
                            {node.node_type}
                          </span>
                        </td>
                        <td className="p-2.5 font-semibold text-foreground">{node.label}</td>
                        <td className="p-2.5">
                          {node.finding_type ? (
                            <span className="font-mono text-[11px] text-muted-foreground">
                              {node.finding_type} ({node.finding_severity})
                            </span>
                          ) : (
                            <span className="text-muted-foreground">-</span>
                          )}
                        </td>
                        <td className="p-2.5 text-muted-foreground font-mono text-[10px]">
                          {new Date(node.created_at).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Finding Detail Inspection Modal / Drawer */}
      {selectedFindingId && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <span className="text-lg">🛡️</span>
                <h2 className="text-base font-bold text-foreground">
                  Finding Security Detail
                </h2>
              </div>
              <button
                onClick={() => {
                  setSelectedFindingId(null);
                  setFindingDetail(null);
                }}
                className="text-muted-foreground hover:text-foreground text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {loadingFindingDetail ? (
              <div className="text-center py-12 text-sm text-muted-foreground">
                <span className="inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-2" />
                Loading finding details...
              </div>
            ) : findingDetail ? (
              <div className="space-y-4 text-xs">
                {/* Header Information */}
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getFindingSeverityBadge(
                        findingDetail.severity
                      )}`}
                    >
                      {findingDetail.severity}
                    </span>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-muted text-foreground uppercase">
                      {findingDetail.type}
                    </span>
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 uppercase">
                      {findingDetail.confidence} Confidence
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-foreground mt-1">{findingDetail.title}</h3>
                </div>

                {/* Description */}
                <div className="p-3 rounded-lg bg-muted/30 border border-border/60">
                  <span className="text-[10px] uppercase font-bold text-muted-foreground block mb-1">
                    Vulnerability Description
                  </span>
                  <p className="text-foreground leading-relaxed">{findingDetail.description}</p>
                </div>

                {/* Target Context */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div className="p-2.5 rounded bg-muted/20 border border-border/40">
                    <span className="text-[10px] text-muted-foreground block font-bold">ENDPOINT</span>
                    <span className="font-mono text-foreground font-semibold">
                      {findingDetail.endpoint?.path || (findingDetail.endpoint_id ? `#${findingDetail.endpoint_id}` : "-")}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-muted/20 border border-border/40">
                    <span className="text-[10px] text-muted-foreground block font-bold">ATTACKER IDENTITY</span>
                    <span className="text-foreground font-semibold">
                      {findingDetail.attacker_identity?.name || (findingDetail.attacker_identity_id ? `#${findingDetail.attacker_identity_id}` : "-")}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-muted/20 border border-border/40">
                    <span className="text-[10px] text-muted-foreground block font-bold">RESOURCE</span>
                    <span className="text-foreground font-semibold">
                      {findingDetail.resource?.name || (findingDetail.resource_id ? `#${findingDetail.resource_id}` : "-")}
                    </span>
                  </div>
                </div>

                {/* Expected vs Actual Behavior */}
                {(findingDetail.expected_authorization || findingDetail.actual_behavior) && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {findingDetail.expected_authorization && (
                      <div className="p-2.5 rounded bg-muted/20 border border-border/40">
                        <span className="text-[10px] text-muted-foreground block font-bold">EXPECTED AUTHORIZATION</span>
                        <span className="text-foreground">{findingDetail.expected_authorization}</span>
                      </div>
                    )}
                    {findingDetail.actual_behavior && (
                      <div className="p-2.5 rounded bg-muted/20 border border-border/40">
                        <span className="text-[10px] text-muted-foreground block font-bold">ACTUAL BEHAVIOR</span>
                        <span className="text-foreground">{findingDetail.actual_behavior}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Exposed Properties (if any) */}
                {findingDetail.exposed_properties && (
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <span className="text-[10px] font-bold text-amber-300 block mb-1 uppercase">
                      Exposed Resource Properties
                    </span>
                    <pre className="font-mono text-xs text-amber-200 whitespace-pre-wrap">
                      {findingDetail.exposed_properties}
                    </pre>
                  </div>
                )}

                {/* Remediation */}
                <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                  <span className="text-[10px] font-bold text-emerald-300 block mb-1 uppercase">
                    Remediation Advice
                  </span>
                  <p className="text-emerald-200 leading-relaxed">{findingDetail.remediation}</p>
                </div>

                {/* Actions / Evidence Link */}
                <div className="flex items-center justify-between pt-2 border-t border-border">
                  <Link
                    href={`/findings`}
                    className="text-xs text-indigo-400 hover:underline font-semibold"
                  >
                    View in Findings Management →
                  </Link>

                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setSelectedFindingId(null);
                      setFindingDetail(null);
                    }}
                  >
                    Close Inspector
                  </Button>
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-xs text-muted-foreground">
                Finding details could not be retrieved.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
