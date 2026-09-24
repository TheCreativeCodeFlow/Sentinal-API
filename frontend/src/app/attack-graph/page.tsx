"use client";

import React, { useEffect, useState, useMemo } from "react";
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

export default function AttackGraphPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);

  const [graphDetail, setGraphDetail] = useState<AttackGraphDetailItem | null>(null);
  const [correlations, setCorrelations] = useState<FindingCorrelationItem[]>([]);

  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Filters & Selected elements
  const [viewTab, setViewTab] = useState<"graph" | "correlations" | "nodes">("graph");
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

  // Load project graphs and correlations when project changes
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
      case "ROLE":
        return { bg: "#4f46e5", border: "#818cf8", text: "#e0e7ff" };
      case "RESOURCE":
        return { bg: "#059669", border: "#34d399", text: "#d1fae5" };
      case "WORKFLOW":
      case "WORKFLOW_EXECUTION":
        return { bg: "#9333ea", border: "#c084fc", text: "#f3e8ff" };
      case "AUTHENTICATION":
        return { bg: "#d97706", border: "#fbbf24", text: "#fef3c7" };
      case "PROPERTY":
        return { bg: "#db2777", border: "#f472b6", text: "#fce7f3" };
      default:
        return { bg: "#475569", border: "#94a3b8", text: "#f1f5f9" };
    }
  };

  // Edge stroke color helper
  const getEdgeColor = (relType: string) => {
    switch (relType) {
      case "AUTH_TO_AUTHORIZATION":
        return "#f59e0b"; // gold
      case "AUTHORIZATION_TO_WORKFLOW":
        return "#a855f7"; // purple
      case "PROPERTY_EXPOSURE_CHAIN":
        return "#10b981"; // emerald
      case "SAME_IDENTITY":
        return "#f97316"; // orange
      case "SAME_ENDPOINT":
        return "#0284c7"; // light blue
      case "SAME_RESOURCE":
        return "#14b8a6"; // teal
      case "SAME_WORKFLOW":
        return "#8b5cf6"; // violet
      case "SAME_EXECUTION":
        return "#06b6d4"; // cyan
      default:
        return "#64748b"; // slate
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">
              Deterministic Attack Graph & Finding Correlation
            </h1>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase">
              Stage 8.1
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Explainable multi-vulnerability relationships derived analytically without target traffic.
          </p>
        </div>

        {/* Project Selector & Run Action */}
        <div className="flex items-center gap-3">
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
            className="bg-purple-600 hover:bg-purple-500 text-white font-medium"
          >
            {running ? (
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Analyzing...
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <span>⚡</span>
                Run Correlation
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
            <strong className="font-semibold text-purple-200">Analytical Safety Guarantee:</strong> Finding correlation operates strictly on confirmed findings without executing requests against the target API. No AI or probabilistic inference is used; all relationships are derived through deterministic domain rules.
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
        <div className="bg-card border border-border rounded-lg p-3.5">
          <span className="text-[10px] uppercase text-muted-foreground block font-bold">Attack Graph Nodes</span>
          <span className="text-2xl font-bold text-foreground">{graphDetail?.nodes.length || 0}</span>
        </div>
        <div className="bg-card border border-border rounded-lg p-3.5">
          <span className="text-[10px] uppercase text-muted-foreground block font-bold">Relationship Edges</span>
          <span className="text-2xl font-bold text-foreground">{graphDetail?.edges.length || 0}</span>
        </div>
      </div>

      {/* Navigation Tabs and Filter Controls */}
      <Card className="p-4 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-3">
          {/* Subnav Tabs */}
          <div className="flex gap-2">
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

          {/* Filters */}
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
        </div>

        {/* View Tab 1: Interactive Graph Visualizer */}
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
                        <g key={edge.id} className="cursor-pointer" onClick={() => {
                          setSelectedEdgeId(edge.id);
                          setSelectedNodeId(null);
                        }}>
                          <line
                            x1={src.x}
                            y1={src.y}
                            x2={tgt.x}
                            y2={tgt.y}
                            stroke={strokeColor}
                            strokeWidth={isSelected ? 3 : isHovered ? 2.5 : isCorrelation ? 2 : 1.2}
                            strokeDasharray={isCorrelation ? "4 3" : undefined}
                            opacity={isSelected || isHovered ? 1 : 0.65}
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
                      const radius = isFinding ? 22 : 17;

                      return (
                        <g
                          key={node.id}
                          transform={`translate(${pos.x}, ${pos.y})`}
                          className="cursor-pointer transition-transform"
                          onClick={() => {
                            setSelectedNodeId(node.id);
                            setSelectedEdgeId(null);
                          }}
                          onMouseEnter={() => setHoveredNodeId(node.id)}
                          onMouseLeave={() => setHoveredNodeId(null)}
                        >
                          {/* Selection / Hover Glow */}
                          {(isSelected || isHovered) && (
                            <circle
                              r={radius + 6}
                              fill="none"
                              stroke={colors.border}
                              strokeWidth="2"
                              strokeDasharray="3 3"
                              className="animate-pulse"
                            />
                          )}

                          {/* Node Circle */}
                          <circle
                            r={radius}
                            fill={colors.bg}
                            stroke={isSelected ? "#ffffff" : colors.border}
                            strokeWidth={isSelected ? 2.5 : 1.5}
                          />

                          {/* Node Center Icon / Indicator */}
                          <text
                            textAnchor="middle"
                            dy=".3em"
                            fill="#ffffff"
                            fontSize={isFinding ? "10" : "8"}
                            fontWeight="bold"
                            pointerEvents="none"
                          >
                            {isFinding ? "⚠️" : node.node_type[0]}
                          </text>

                          {/* Node Text Label */}
                          <text
                            textAnchor="middle"
                            y={radius + 12}
                            fill="#cbd5e1"
                            fontSize="9"
                            fontWeight={isSelected ? "bold" : "500"}
                            className="pointer-events-none drop-shadow-md"
                          >
                            {node.label.length > 20 ? `${node.label.slice(0, 18)}...` : node.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
              )}

              {/* Legend */}
              <div className="flex flex-wrap items-center justify-center gap-3 pt-3 border-t border-border/50 text-[10px] text-muted-foreground w-full">
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Finding
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-500" /> Endpoint
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-orange-500" /> Identity
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Resource
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-purple-500" /> Workflow
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Auth
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 rounded-full bg-pink-500" /> Property
                </span>
              </div>
            </div>

            {/* Inspector Drawer (4 cols) */}
            <div className="lg:col-span-4 space-y-4">
              {/* Selected Edge Explanation */}
              {selectedEdge ? (
                <Card className="p-4 space-y-3 border-amber-500/30">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 uppercase">
                      Relationship Link
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 uppercase">
                      {selectedEdge.confidence} Confidence
                    </span>
                  </div>

                  <div>
                    <h4 className="text-sm font-bold text-foreground">
                      {selectedEdge.relationship_type.replace(/_/g, " ")}
                    </h4>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Deterministic edge connecting graph elements
                    </p>
                  </div>

                  {/* Deterministic Explanation Callout */}
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-200 space-y-1">
                    <strong className="block text-[10px] uppercase tracking-wider text-amber-400 font-bold">
                      Deterministic Explainability Reason
                    </strong>
                    <p>{selectedEdge.reason}</p>
                  </div>

                  <div className="space-y-1.5 text-xs text-muted-foreground pt-1 border-t border-border/40">
                    <div>
                      <span>Source: </span>
                      <strong className="text-foreground">{selectedEdge.source_label || selectedEdge.source_node_id}</strong>
                    </div>
                    <div>
                      <span>Target: </span>
                      <strong className="text-foreground">{selectedEdge.target_label || selectedEdge.target_node_id}</strong>
                    </div>
                  </div>
                </Card>
              ) : selectedNode ? (
                /* Selected Node Details */
                <Card className="p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-muted text-foreground uppercase">
                      {selectedNode.node_type}
                    </span>
                    {selectedNode.finding_severity && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-destructive/20 text-destructive uppercase">
                        {selectedNode.finding_severity}
                      </span>
                    )}
                  </div>

                  <div>
                    <h4 className="text-base font-bold text-foreground">{selectedNode.label}</h4>
                    {selectedNode.finding_type && (
                      <span className="text-[11px] font-mono text-muted-foreground">
                        Type: {selectedNode.finding_type}
                      </span>
                    )}
                  </div>

                  {/* Connected Edges & Reasons */}
                  <div className="space-y-2 pt-2 border-t border-border/40">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground block">
                      Connected Relationships
                    </span>
                    {graphDetail?.edges
                      .filter((e) => e.source_node_id === selectedNode.id || e.target_node_id === selectedNode.id)
                      .map((edge) => (
                        <div
                          key={edge.id}
                          className="p-2.5 rounded bg-card/60 border border-border text-xs space-y-1 cursor-pointer hover:border-amber-500/50"
                          onClick={() => setSelectedEdgeId(edge.id)}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-foreground text-[11px]">
                              {edge.relationship_type.replace(/_/g, " ")}
                            </span>
                            <span className="text-[9px] font-mono px-1 rounded bg-muted text-muted-foreground">
                              {edge.confidence}
                            </span>
                          </div>
                          <p className="text-[11px] text-muted-foreground line-clamp-2">
                            {edge.reason}
                          </p>
                        </div>
                      ))}
                  </div>

                  {selectedNode.metadata && Object.keys(selectedNode.metadata).length > 0 && (
                    <div className="space-y-1 pt-2 border-t border-border/40">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground block">
                        Node Metadata
                      </span>
                      <pre className="p-2 bg-background border border-input rounded text-[10px] font-mono overflow-x-auto max-h-36 whitespace-pre-wrap text-foreground">
                        {JSON.stringify(selectedNode.metadata, null, 2)}
                      </pre>
                    </div>
                  )}
                </Card>
              ) : (
                /* Default Info Drawer */
                <Card className="p-6 text-center text-xs text-muted-foreground space-y-2 border-dashed">
                  <div className="text-2xl">🔍</div>
                  <div className="font-semibold text-foreground">Inspect Attack Graph</div>
                  <p>Click on any node or edge in the graph to view detailed explainability context, deterministic reasons, and vulnerability attributes.</p>
                </Card>
              )}
            </div>
          </div>
        )}

        {/* View Tab 2: Correlations Table */}
        {viewTab === "correlations" && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Deterministic pairwise relationships identified between confirmed findings</span>
              <span>Total: {correlations.length}</span>
            </div>

            {correlations.length === 0 ? (
              <div className="text-center py-12 text-xs text-muted-foreground border border-dashed border-border rounded-lg">
                No correlations recorded yet for this project.
              </div>
            ) : (
              <div className="space-y-2">
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

        {/* View Tab 3: Nodes Table */}
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
    </div>
  );
}
