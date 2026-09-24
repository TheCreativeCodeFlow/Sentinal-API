"use client";

import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

interface Project {
  id: number;
  name: string;
  authorization_status: string;
  base_url: string | null;
}

interface EndpointItem {
  id: number;
  method: string;
  path: string;
  summary: string | null;
}

interface IdentityItem {
  id: string;
  name: string;
  auth_type: string;
  role_id: string | null;
  role_name?: string | null;
}

interface WorkflowItem {
  id: string;
  project_id: number;
  name: string;
  description: string | null;
  status: "DRAFT" | "ACTIVE" | "DISABLED";
  step_count: number;
  state_count: number;
  transition_count: number;
  created_at: string;
  updated_at: string;
}

interface WorkflowStepItem {
  id: string;
  workflow_id: string;
  step_order: number;
  endpoint_id: number;
  endpoint_path?: string | null;
  endpoint_method?: string | null;
  identity_id?: string | null;
  identity_name?: string | null;
  http_method: string;
  name: string;
  description?: string | null;
  request_template?: Record<string, unknown> | null;
  expected_status_codes: number[];
  created_at: string;
  updated_at: string;
}

interface WorkflowStateItem {
  id: string;
  workflow_id: string;
  name: string;
  description?: string | null;
  is_initial: boolean;
  is_terminal: boolean;
  created_at: string;
  updated_at: string;
}

interface WorkflowTransitionItem {
  id: string;
  workflow_id: string;
  from_state_id: string;
  from_state_name?: string | null;
  to_state_id: string;
  to_state_name?: string | null;
  step_id?: string | null;
  step_name?: string | null;
  expected_behavior: "ALLOW" | "DENY";
  description?: string | null;
  created_at: string;
  updated_at: string;
}

interface WorkflowDetailItem extends WorkflowItem {
  steps: WorkflowStepItem[];
  states: WorkflowStateItem[];
  transitions: WorkflowTransitionItem[];
}

interface WorkflowExecutionItem {
  id: string;
  workflow_id: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  result: "PASS" | "CONFIRMED" | "INCONCLUSIVE" | "ERROR" | null;
  result_reason: string | null;
  triggered_by: "MANUAL" | "REPLAY";
  current_state_id: string | null;
  correlation_id: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  step_count: number;
  findings_count: number;
}

interface WorkflowStepExecutionItem {
  id: string;
  workflow_execution_id: string;
  step_id: string | null;
  step_order: number;
  http_method: string | null;
  endpoint_path: string | null;
  status: "PASS" | "CONFIRMED" | "INCONCLUSIVE" | "ERROR" | "SKIPPED";
  request_summary: Record<string, unknown> | null;
  response_summary: Record<string, unknown> | null;
  status_code: number | null;
  latency_ms: number | null;
  state_before: string | null;
  state_after: string | null;
  transition_expected: string | null;
  transition_result: string | null;
  correlation_id: string | null;
  error_message: string | null;
  created_at: string;
  step_name?: string | null;
}

interface WorkflowExecutionDetailItem extends WorkflowExecutionItem {
  workflow_name?: string | null;
  current_state_name?: string | null;
  step_executions: WorkflowStepExecutionItem[];
  findings: Array<{
    id: string;
    type: string;
    severity: string;
    title: string;
    description: string;
    remediation: string;
    expected_authorization?: string | null;
    actual_behavior?: string | null;
  }>;
}

export default function WorkflowsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [workflows, setWorkflows] = useState<WorkflowItem[]>([]);
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);
  const [workflowDetail, setWorkflowDetail] = useState<WorkflowDetailItem | null>(null);

  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [identities, setIdentities] = useState<IdentityItem[]>([]);

  // Stage 7.2 Executions state
  const [executions, setExecutions] = useState<WorkflowExecutionItem[]>([]);
  const [selectedExecution, setSelectedExecution] = useState<WorkflowExecutionDetailItem | null>(null);
  const [executing, setExecuting] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const [loadingExecutionDetail, setLoadingExecutionDetail] = useState(false);
  const [showEvidenceModal, setShowEvidenceModal] = useState(false);
  const [selectedStepEvidence, setSelectedStepEvidence] = useState<WorkflowStepExecutionItem | null>(null);

  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Active view tab
  const [activeTab, setActiveTab] = useState<"steps" | "states" | "transitions" | "executions">("steps");

  // Modals state
  const [showWfModal, setShowWfModal] = useState(false);
  const [wfName, setWfName] = useState("");
  const [wfDesc, setWfDesc] = useState("");
  const [wfStatus, setWfStatus] = useState<"DRAFT" | "ACTIVE" | "DISABLED">("DRAFT");
  const [editingWfId, setEditingWfId] = useState<string | null>(null);

  // Step modal state
  const [showStepModal, setShowStepModal] = useState(false);
  const [stepOrder, setStepOrder] = useState<number>(1);
  const [stepName, setStepName] = useState("");
  const [stepDesc, setStepDesc] = useState("");
  const [stepEndpointId, setStepEndpointId] = useState<number | "">("");
  const [stepIdentityId, setStepIdentityId] = useState<string>("");
  const [stepMethod, setStepMethod] = useState<"GET" | "HEAD">("GET");
  const [stepCodes, setStepCodes] = useState("200");
  const [stepTemplate, setStepTemplate] = useState('{\n  "headers": {\n    "Authorization": "Bearer {{token}}"\n  }\n}');
  const [editingStepId, setEditingStepId] = useState<string | null>(null);

  // State modal state
  const [showStateModal, setShowStateModal] = useState(false);
  const [stateName, setStateName] = useState("");
  const [stateDesc, setStateDesc] = useState("");
  const [stateIsInitial, setStateIsInitial] = useState(false);
  const [stateIsTerminal, setStateIsTerminal] = useState(false);
  const [editingStateId, setEditingStateId] = useState<string | null>(null);

  // Transition modal state
  const [showTransModal, setShowTransModal] = useState(false);
  const [transFromId, setTransFromId] = useState("");
  const [transToId, setTransToId] = useState("");
  const [transStepId, setTransStepId] = useState("");
  const [transBehavior, setTransBehavior] = useState<"ALLOW" | "DENY">("ALLOW");
  const [transDesc, setTransDesc] = useState("");
  const [editingTransId, setEditingTransId] = useState<string | null>(null);

  // Load Projects on Mount
  useEffect(() => {
    async function loadProjects() {
      try {
        setLoading(true);
        const res = await fetch("/api/v1/projects/", { credentials: "include" });
        if (!res.ok) throw new Error("Failed to load projects");
        const data: Project[] = await res.json();
        setProjects(data);
        if (data.length > 0) {
          setSelectedProjectId((prev) => (prev === null ? data[0].id : prev));
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to load projects";
        setErrorMsg(msg);
      } finally {
        setLoading(false);
      }
    }
    loadProjects();
  }, []);

  // Load Workflows, Endpoints, Identities when Project changes
  useEffect(() => {
    if (!selectedProjectId) return;

    async function loadProjectData() {
      try {
        setErrorMsg(null);
        // Load Workflows
        const wfRes = await fetch(`/api/v1/projects/${selectedProjectId}/workflows`, { credentials: "include" });
        if (wfRes.ok) {
          const wfData: WorkflowItem[] = await wfRes.json();
          setWorkflows(wfData);
          if (wfData.length > 0) {
            setSelectedWorkflowId(wfData[0].id);
          } else {
            setSelectedWorkflowId(null);
            setWorkflowDetail(null);
          }
        }

        // Load Endpoints
        const epRes = await fetch(`/api/v1/projects/${selectedProjectId}/endpoints`, { credentials: "include" });
        if (epRes.ok) {
          const epData: EndpointItem[] = await epRes.json();
          setEndpoints(epData);
        }

        // Load Identities
        const idRes = await fetch(`/api/v1/projects/${selectedProjectId}/identities/`, { credentials: "include" });
        if (idRes.ok) {
          const idData: IdentityItem[] = await idRes.json();
          setIdentities(idData);
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to load project details";
        setErrorMsg(msg);
      }
    }
    loadProjectData();
  }, [selectedProjectId]);

  const [reloadKey, setReloadKey] = useState(0);

  // Load selected Workflow details
  useEffect(() => {
    let ignore = false;
    async function fetchDetail() {
      if (!selectedWorkflowId) {
        setWorkflowDetail(null);
        return;
      }
      try {
        setDetailLoading(true);
        const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}`, { credentials: "include" });
        if (!res.ok) throw new Error("Failed to fetch workflow detail");
        const detail: WorkflowDetailItem = await res.json();
        if (!ignore) {
          setWorkflowDetail(detail);
        }
      } catch (err: unknown) {
        if (!ignore) {
          const msg = err instanceof Error ? err.message : "Failed to fetch workflow detail";
          setErrorMsg(msg);
        }
      } finally {
        if (!ignore) {
          setDetailLoading(false);
        }
      }
    }
    fetchDetail();
    return () => {
      ignore = true;
    };
  }, [selectedWorkflowId, reloadKey]);

  // Load Executions for selected workflow
  const loadExecutions = async (wfId: string) => {
    try {
      const res = await fetch(`/api/v1/workflows/${wfId}/executions`, { credentials: "include" });
      if (res.ok) {
        const data: WorkflowExecutionItem[] = await res.json();
        setExecutions(data);
        if (data.length > 0) {
          loadExecutionDetail(data[0].id);
        } else {
          setSelectedExecution(null);
        }
      }
    } catch {
      // non-critical
    }
  };

  const loadExecutionDetail = async (execId: string) => {
    try {
      setLoadingExecutionDetail(true);
      const res = await fetch(`/api/v1/workflow-executions/${execId}`, { credentials: "include" });
      if (res.ok) {
        const data: WorkflowExecutionDetailItem = await res.json();
        setSelectedExecution(data);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to load execution detail");
    } finally {
      setLoadingExecutionDetail(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    async function fetchExecutions() {
      if (!selectedWorkflowId) {
        setExecutions([]);
        setSelectedExecution(null);
        return;
      }
      try {
        const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}/executions`, { credentials: "include" });
        if (res.ok && !ignore) {
          const data: WorkflowExecutionItem[] = await res.json();
          setExecutions(data);
          if (data.length > 0) {
            const detailRes = await fetch(`/api/v1/workflow-executions/${data[0].id}`, { credentials: "include" });
            if (detailRes.ok && !ignore) {
              const detailData: WorkflowExecutionDetailItem = await detailRes.json();
              setSelectedExecution(detailData);
            }
          } else {
            setSelectedExecution(null);
          }
        }
      } catch {
        // non-critical
      }
    }
    fetchExecutions();
    return () => {
      ignore = true;
    };
  }, [selectedWorkflowId, reloadKey]);

  // Stage 7.2 Run Workflow Handler
  const handleRunWorkflow = async () => {
    if (!selectedWorkflowId) return;
    try {
      setExecuting(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}/execute`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to execute workflow");
      }
      const data: WorkflowExecutionDetailItem = await res.json();
      setSelectedExecution(data);
      setSuccessMsg(`Workflow executed with result: ${data.result}`);
      setActiveTab("executions");
      await loadExecutions(selectedWorkflowId);
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to execute workflow");
    } finally {
      setExecuting(false);
    }
  };

  // Stage 7.2 Replay Execution Handler
  const handleReplayExecution = async (execId: string) => {
    try {
      setReplaying(true);
      setErrorMsg(null);
      setSuccessMsg(null);
      const res = await fetch(`/api/v1/workflow-executions/${execId}/replay`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Failed to replay execution");
      }
      const data: WorkflowExecutionDetailItem = await res.json();
      setSelectedExecution(data);
      setSuccessMsg(`Workflow replayed with result: ${data.result}`);
      if (selectedWorkflowId) {
        await loadExecutions(selectedWorkflowId);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to replay execution");
    } finally {
      setReplaying(false);
    }
  };

  // Reload workflows list
  const reloadWorkflowsList = async (selectId?: string) => {
    if (!selectedProjectId) return;
    const wfRes = await fetch(`/api/v1/projects/${selectedProjectId}/workflows`, { credentials: "include" });
    if (wfRes.ok) {
      const data: WorkflowItem[] = await wfRes.json();
      setWorkflows(data);
      if (selectId) {
        setSelectedWorkflowId(selectId);
      } else if (!data.some((w) => w.id === selectedWorkflowId)) {
        setSelectedWorkflowId(data.length > 0 ? data[0].id : null);
      }
    }
  };

  // Workflow Handlers
  const handleOpenCreateWf = () => {
    setEditingWfId(null);
    setWfName("");
    setWfDesc("");
    setWfStatus("DRAFT");
    setShowWfModal(true);
  };

  const handleOpenEditWf = (wf: WorkflowItem) => {
    setEditingWfId(wf.id);
    setWfName(wf.name);
    setWfDesc(wf.description || "");
    setWfStatus(wf.status);
    setShowWfModal(true);
  };

  const handleSaveWorkflow = async () => {
    if (!selectedProjectId || !wfName.trim()) return;
    setErrorMsg(null);
    try {
      if (editingWfId) {
        const res = await fetch(`/api/v1/workflows/${editingWfId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            name: wfName.trim(),
            description: wfDesc.trim() || null,
            status: wfStatus,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to update workflow");
        }
        setSuccessMsg("Workflow updated successfully.");
        await reloadWorkflowsList(editingWfId);
        setReloadKey((prev) => prev + 1);
      } else {
        const res = await fetch(`/api/v1/projects/${selectedProjectId}/workflows`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            name: wfName.trim(),
            description: wfDesc.trim() || null,
            status: wfStatus,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to create workflow");
        }
        const created: WorkflowItem = await res.json();
        setSuccessMsg("Workflow created successfully.");
        await reloadWorkflowsList(created.id);
      }
      setShowWfModal(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "An error occurred";
      setErrorMsg(msg);
    }
  };

  const handleDeleteWorkflow = async (id: string) => {
    if (!confirm("Are you sure you want to delete this workflow and all its steps, states, and transitions?")) return;
    try {
      const res = await fetch(`/api/v1/workflows/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete workflow");
      setSuccessMsg("Workflow deleted successfully.");
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete workflow";
      setErrorMsg(msg);
    }
  };

  // Step Handlers
  const handleOpenAddStep = () => {
    setEditingStepId(null);
    const nextOrder = workflowDetail && workflowDetail.steps.length > 0
      ? Math.max(...workflowDetail.steps.map((s) => s.step_order)) + 1
      : 1;
    setStepOrder(nextOrder);
    setStepName("");
    setStepDesc("");
    setStepEndpointId(endpoints.length > 0 ? endpoints[0].id : "");
    setStepIdentityId(identities.length > 0 ? identities[0].id : "");
    setStepMethod("GET");
    setStepCodes("200");
    setStepTemplate('{\n  "headers": {\n    "Authorization": "Bearer {{token}}"\n  }\n}');
    setShowStepModal(true);
  };

  const handleOpenEditStep = (step: WorkflowStepItem) => {
    setEditingStepId(step.id);
    setStepOrder(step.step_order);
    setStepName(step.name);
    setStepDesc(step.description || "");
    setStepEndpointId(step.endpoint_id);
    setStepIdentityId(step.identity_id || "");
    setStepMethod((step.http_method as "GET" | "HEAD") || "GET");
    setStepCodes(step.expected_status_codes.join(", "));
    setStepTemplate(step.request_template ? JSON.stringify(step.request_template, null, 2) : "");
    setShowStepModal(true);
  };

  const handleSaveStep = async () => {
    if (!selectedWorkflowId || !stepName.trim() || stepEndpointId === "") return;
    setErrorMsg(null);

    let parsedTemplate = null;
    if (stepTemplate.trim()) {
      try {
        parsedTemplate = JSON.parse(stepTemplate);
      } catch {
        setErrorMsg("Request template must be valid JSON.");
        return;
      }
    }

    const parsedCodes = stepCodes
      .split(",")
      .map((c) => parseInt(c.trim(), 10))
      .filter((c) => !isNaN(c));

    try {
      if (editingStepId) {
        const res = await fetch(`/api/v1/workflow-steps/${editingStepId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            step_order: Number(stepOrder),
            endpoint_id: Number(stepEndpointId),
            identity_id: stepIdentityId || null,
            http_method: stepMethod,
            name: stepName.trim(),
            description: stepDesc.trim() || null,
            request_template: parsedTemplate,
            expected_status_codes: parsedCodes.length > 0 ? parsedCodes : [200],
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to update step");
        }
        setSuccessMsg("Workflow step updated.");
      } else {
        const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}/steps`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            step_order: Number(stepOrder),
            endpoint_id: Number(stepEndpointId),
            identity_id: stepIdentityId || null,
            http_method: stepMethod,
            name: stepName.trim(),
            description: stepDesc.trim() || null,
            request_template: parsedTemplate,
            expected_status_codes: parsedCodes.length > 0 ? parsedCodes : [200],
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to create step");
        }
        setSuccessMsg("Workflow step created.");
      }
      setShowStepModal(false);
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save step";
      setErrorMsg(msg);
    }
  };

  const handleDeleteStep = async (stepId: string) => {
    if (!confirm("Are you sure you want to delete this workflow step?")) return;
    try {
      const res = await fetch(`/api/v1/workflow-steps/${stepId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete step");
      setSuccessMsg("Step deleted.");
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete step";
      setErrorMsg(msg);
    }
  };

  // State Handlers
  const handleOpenAddState = () => {
    setEditingStateId(null);
    setStateName("");
    setStateDesc("");
    setStateIsInitial(false);
    setStateIsTerminal(false);
    setShowStateModal(true);
  };

  const handleOpenEditState = (st: WorkflowStateItem) => {
    setEditingStateId(st.id);
    setStateName(st.name);
    setStateDesc(st.description || "");
    setStateIsInitial(st.is_initial);
    setStateIsTerminal(st.is_terminal);
    setShowStateModal(true);
  };

  const handleSaveState = async () => {
    if (!selectedWorkflowId || !stateName.trim()) return;
    setErrorMsg(null);

    try {
      if (editingStateId) {
        const res = await fetch(`/api/v1/workflow-states/${editingStateId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            name: stateName.trim(),
            description: stateDesc.trim() || null,
            is_initial: stateIsInitial,
            is_terminal: stateIsTerminal,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to update state");
        }
        setSuccessMsg("Workflow state updated.");
      } else {
        const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}/states`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            name: stateName.trim(),
            description: stateDesc.trim() || null,
            is_initial: stateIsInitial,
            is_terminal: stateIsTerminal,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to create state");
        }
        setSuccessMsg("Workflow state created.");
      }
      setShowStateModal(false);
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save state";
      setErrorMsg(msg);
    }
  };

  const handleDeleteState = async (stateId: string) => {
    if (!confirm("Are you sure you want to delete this state? Transitions connected to it will also be deleted.")) return;
    try {
      const res = await fetch(`/api/v1/workflow-states/${stateId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete state");
      setSuccessMsg("State deleted.");
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete state";
      setErrorMsg(msg);
    }
  };

  // Transition Handlers
  const handleOpenAddTransition = () => {
    setEditingTransId(null);
    setTransFromId(workflowDetail && workflowDetail.states.length > 0 ? workflowDetail.states[0].id : "");
    setTransToId(workflowDetail && workflowDetail.states.length > 1 ? workflowDetail.states[1].id : (workflowDetail?.states[0]?.id || ""));
    setTransStepId(workflowDetail && workflowDetail.steps.length > 0 ? workflowDetail.steps[0].id : "");
    setTransBehavior("ALLOW");
    setTransDesc("");
    setShowTransModal(true);
  };

  const handleOpenEditTransition = (tr: WorkflowTransitionItem) => {
    setEditingTransId(tr.id);
    setTransFromId(tr.from_state_id);
    setTransToId(tr.to_state_id);
    setTransStepId(tr.step_id || "");
    setTransBehavior(tr.expected_behavior);
    setTransDesc(tr.description || "");
    setShowTransModal(true);
  };

  const handleSaveTransition = async () => {
    if (!selectedWorkflowId || !transFromId || !transToId) return;
    setErrorMsg(null);

    try {
      if (editingTransId) {
        const res = await fetch(`/api/v1/workflow-transitions/${editingTransId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            from_state_id: transFromId,
            to_state_id: transToId,
            step_id: transStepId || null,
            expected_behavior: transBehavior,
            description: transDesc.trim() || null,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to update transition");
        }
        setSuccessMsg("Workflow transition updated.");
      } else {
        const res = await fetch(`/api/v1/workflows/${selectedWorkflowId}/transitions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            from_state_id: transFromId,
            to_state_id: transToId,
            step_id: transStepId || null,
            expected_behavior: transBehavior,
            description: transDesc.trim() || null,
          }),
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Failed to create transition");
        }
        setSuccessMsg("Workflow transition created.");
      }
      setShowTransModal(false);
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save transition";
      setErrorMsg(msg);
    }
  };

  const handleDeleteTransition = async (transId: string) => {
    if (!confirm("Are you sure you want to delete this transition?")) return;
    try {
      const res = await fetch(`/api/v1/workflow-transitions/${transId}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error("Failed to delete transition");
      setSuccessMsg("Transition deleted.");
      setReloadKey((prev) => prev + 1);
      await reloadWorkflowsList();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to delete transition";
      setErrorMsg(msg);
    }
  };

  const activeWorkflow = workflows.find((w) => w.id === selectedWorkflowId);
  const activeProject = projects.find((p) => p.id === selectedProjectId);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Stateful Workflows & Business Logic Engine
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Model multi-step API sequences, business states, and execute stateful authorization workflows (Stage 7.2)
          </p>
        </div>

        {/* Project Selector */}
        <div className="flex items-center gap-3">
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
      </div>

      {/* Stage 7.2 Safety & Execution Banner */}
      <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-xs leading-relaxed text-blue-300">
        <div className="flex items-start gap-2">
          <span className="text-base font-bold">🛡️</span>
          <div>
            <strong className="font-semibold text-blue-200">Stage 7.2 Stateful Execution Engine Active:</strong> Safely executes defined workflows against target endpoints using non-destructive GET/HEAD requests. Tracks business state transitions across steps, sanitizes evidence, verifies transition invariants, and flags invalid state transitions or unexpected states as findings.
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

      {/* Main Grid: Workflow Selector / Summary & Workflow Builder */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left Column: Workflows List */}
        <div className="lg:col-span-1 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Workflows ({workflows.length})
            </h2>
            <Button size="sm" variant="primary" onClick={handleOpenCreateWf}>
              + New Workflow
            </Button>
          </div>

          {workflows.length === 0 ? (
            <div className="border border-dashed border-border rounded-lg p-6 text-center text-sm text-muted-foreground">
              No workflows modeled yet. Click <strong>+ New Workflow</strong> to create one.
            </div>
          ) : (
            <div className="space-y-2">
              {workflows.map((wf) => {
                const isSelected = wf.id === selectedWorkflowId;
                return (
                  <div
                    key={wf.id}
                    onClick={() => setSelectedWorkflowId(wf.id)}
                    className={`cursor-pointer rounded-lg border p-3 transition-all ${
                      isSelected
                        ? "border-primary bg-accent/40 shadow-xs"
                        : "border-border hover:bg-card/60"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="font-semibold text-sm text-foreground truncate">
                        {wf.name}
                      </div>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${
                          wf.status === "ACTIVE"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : wf.status === "DISABLED"
                            ? "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30"
                            : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        }`}
                      >
                        {wf.status}
                      </span>
                    </div>
                    {wf.description && (
                      <p className="text-xs text-muted-foreground line-clamp-1 mt-1">
                        {wf.description}
                      </p>
                    )}
                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground mt-3 pt-2 border-t border-border/50">
                      <span>{wf.step_count} step{wf.step_count !== 1 ? "s" : ""}</span>
                      <span>•</span>
                      <span>{wf.state_count} state{wf.state_count !== 1 ? "s" : ""}</span>
                      <span>•</span>
                      <span>{wf.transition_count} trans.</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Right Column: Workflow Builder & Entities */}
        <div className="lg:col-span-3 space-y-5">
          {detailLoading && (
            <div className="text-center py-6 text-sm text-muted-foreground">
              Loading workflow details...
            </div>
          )}

          {!detailLoading && activeWorkflow && workflowDetail ? (
            <div className="space-y-5">
              {/* Active Workflow Header Card */}
              <Card>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <h2 className="text-xl font-bold text-foreground">
                        {workflowDetail.name}
                      </h2>
                      <span
                        className={`text-xs font-semibold px-2.5 py-0.5 rounded-full uppercase ${
                          workflowDetail.status === "ACTIVE"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                            : workflowDetail.status === "DISABLED"
                            ? "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30"
                            : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                        }`}
                      >
                        {workflowDetail.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {workflowDetail.description || "No description provided."}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      disabled={executing || workflowDetail.status !== "ACTIVE" || activeProject?.authorization_status !== "authorized"}
                      onClick={handleRunWorkflow}
                      className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                      title={
                        activeProject?.authorization_status !== "authorized"
                          ? "Project must be authorized before executing workflows"
                          : workflowDetail.status !== "ACTIVE"
                          ? "Workflow must be ACTIVE to run"
                          : "Execute stateful workflow"
                      }
                    >
                      {executing ? (
                        <span className="flex items-center gap-1.5">
                          <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Executing...
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5">
                          <span>▶</span>
                          Run Workflow
                        </span>
                      )}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleOpenEditWf(workflowDetail)}
                    >
                      Edit Workflow
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => handleDeleteWorkflow(workflowDetail.id)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>

                {/* Subnav Tabs */}
                <div className="flex border-b border-border mt-6">
                  <button
                    onClick={() => setActiveTab("steps")}
                    className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                      activeTab === "steps"
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    Workflow Steps ({workflowDetail.steps.length})
                  </button>
                  <button
                    onClick={() => setActiveTab("states")}
                    className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                      activeTab === "states"
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    Workflow States ({workflowDetail.states.length})
                  </button>
                  <button
                    onClick={() => setActiveTab("transitions")}
                    className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                      activeTab === "transitions"
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    State Transitions ({workflowDetail.transitions.length})
                  </button>
                  <button
                    onClick={() => setActiveTab("executions")}
                    className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
                      activeTab === "executions"
                        ? "border-primary text-primary"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    Execution History ({executions.length})
                  </button>
                </div>
              </Card>

              {/* Tab 1: Workflow Steps */}
              {activeTab === "steps" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-semibold text-foreground">Ordered Steps</h3>
                      <p className="text-xs text-muted-foreground">
                        Steps must be executed sequentially. Only safe methods (GET, HEAD) are allowed.
                      </p>
                    </div>
                    <Button size="sm" variant="primary" onClick={handleOpenAddStep}>
                      + Add Step
                    </Button>
                  </div>

                  {workflowDetail.steps.length === 0 ? (
                    <div className="border border-dashed border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
                      No steps configured in this workflow. Click <strong>+ Add Step</strong> to define the first step.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {workflowDetail.steps.map((step) => (
                        <div
                          key={step.id}
                          className="rounded-lg border border-border bg-card/60 p-4 transition-all hover:border-border/80"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex items-start gap-3">
                              <div className="w-7 h-7 rounded-full bg-primary/10 border border-primary/20 text-primary flex items-center justify-center text-xs font-bold shrink-0">
                                {step.step_order}
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <h4 className="font-semibold text-sm text-foreground">
                                    {step.name}
                                  </h4>
                                  <span
                                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                                      step.http_method === "GET"
                                        ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                                        : "bg-teal-500/20 text-teal-300 border border-teal-500/30"
                                    }`}
                                  >
                                    {step.http_method}
                                  </span>
                                  <code className="text-xs font-mono bg-muted/60 px-2 py-0.5 rounded text-foreground">
                                    {step.endpoint_path || `Endpoint #${step.endpoint_id}`}
                                  </code>
                                </div>
                                {step.description && (
                                  <p className="text-xs text-muted-foreground mt-1">
                                    {step.description}
                                  </p>
                                )}
                                <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground mt-2">
                                  <span>
                                    Identity:{" "}
                                    <strong className="text-foreground">
                                      {step.identity_name || "Unassigned (Anonymous)"}
                                    </strong>
                                  </span>
                                  <span>
                                    Expected Status:{" "}
                                    <code className="text-foreground">
                                      {step.expected_status_codes.join(", ")}
                                    </code>
                                  </span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => handleOpenEditStep(step)}
                              >
                                Edit
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => handleDeleteStep(step.id)}
                              >
                                Delete
                              </Button>
                            </div>
                          </div>

                          {step.request_template && Object.keys(step.request_template).length > 0 && (
                            <div className="mt-3 pt-3 border-t border-border/40">
                              <span className="text-[11px] font-semibold text-muted-foreground uppercase">
                                Request Template:
                              </span>
                              <pre className="mt-1 p-2 rounded bg-black/40 text-[11px] font-mono text-zinc-300 overflow-x-auto max-h-32">
                                {JSON.stringify(step.request_template, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Workflow States */}
              {activeTab === "states" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-semibold text-foreground">Workflow States</h3>
                      <p className="text-xs text-muted-foreground">
                        Define lifecycle states (e.g. CART_CREATED, PAYMENT_PENDING, ORDER_FULFILLED).
                      </p>
                    </div>
                    <Button size="sm" variant="primary" onClick={handleOpenAddState}>
                      + Add State
                    </Button>
                  </div>

                  {workflowDetail.states.length === 0 ? (
                    <div className="border border-dashed border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
                      No states defined for this workflow. Click <strong>+ Add State</strong> to create one.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {workflowDetail.states.map((st) => (
                        <div
                          key={st.id}
                          className="rounded-lg border border-border bg-card/60 p-4 space-y-2 flex flex-col justify-between"
                        >
                          <div>
                            <div className="flex items-start justify-between gap-2">
                              <div className="font-semibold text-sm text-foreground">
                                {st.name}
                              </div>
                              <div className="flex items-center gap-1.5">
                                {st.is_initial && (
                                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                                    INITIAL
                                  </span>
                                )}
                                {st.is_terminal && (
                                  <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                    TERMINAL
                                  </span>
                                )}
                              </div>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">
                              {st.description || "No description."}
                            </p>
                          </div>
                          <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/40">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleOpenEditState(st)}
                            >
                              Edit
                            </Button>
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => handleDeleteState(st.id)}
                            >
                              Delete
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: State Transitions */}
              {activeTab === "transitions" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-base font-semibold text-foreground">State Transitions</h3>
                      <p className="text-xs text-muted-foreground">
                        Define expected access and business rules between states.
                      </p>
                    </div>
                    <Button
                      size="sm"
                      variant="primary"
                      onClick={handleOpenAddTransition}
                      disabled={workflowDetail.states.length < 2}
                    >
                      + Add Transition
                    </Button>
                  </div>

                  {workflowDetail.states.length < 2 && (
                    <div className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded p-2.5">
                      ⚠️ You need at least 2 states before you can define state transitions.
                    </div>
                  )}

                  {workflowDetail.transitions.length === 0 ? (
                    <div className="border border-dashed border-border rounded-lg p-8 text-center text-sm text-muted-foreground">
                      No transitions configured yet.
                    </div>
                  ) : (
                    <div className="overflow-x-auto rounded-lg border border-border">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-muted/40 uppercase tracking-wider text-muted-foreground border-b border-border">
                          <tr>
                            <th className="px-4 py-3">From State</th>
                            <th className="px-4 py-3">To State</th>
                            <th className="px-4 py-3">Triggering Step</th>
                            <th className="px-4 py-3">Expected Behavior</th>
                            <th className="px-4 py-3">Description</th>
                            <th className="px-4 py-3 text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {workflowDetail.transitions.map((tr) => (
                            <tr key={tr.id} className="hover:bg-muted/20">
                              <td className="px-4 py-3 font-semibold text-foreground">
                                {tr.from_state_name || tr.from_state_id}
                              </td>
                              <td className="px-4 py-3 font-semibold text-foreground">
                                → {tr.to_state_name || tr.to_state_id}
                              </td>
                              <td className="px-4 py-3 text-muted-foreground">
                                {tr.step_name || (tr.step_id ? `Step #${tr.step_id}` : "Any / Direct")}
                              </td>
                              <td className="px-4 py-3">
                                <span
                                  className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                                    tr.expected_behavior === "ALLOW"
                                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                                      : "bg-destructive/20 text-destructive border border-destructive/30"
                                  }`}
                                >
                                  {tr.expected_behavior}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-muted-foreground max-w-xs truncate">
                                {tr.description || "-"}
                              </td>
                              <td className="px-4 py-3 text-right space-x-2 whitespace-nowrap">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => handleOpenEditTransition(tr)}
                                >
                                  Edit
                                </Button>
                                <Button
                                  size="sm"
                                  variant="destructive"
                                  onClick={() => handleDeleteTransition(tr.id)}
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
                </div>
              )}

              {/* Tab 4: Execution History */}
              {activeTab === "executions" && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-semibold text-foreground">
                        Execution History & Findings
                      </h3>
                      <p className="text-xs text-muted-foreground">
                        Ordered execution traces, transition validations, and security findings.
                      </p>
                    </div>
                    <Button
                      size="sm"
                      disabled={executing || workflowDetail.status !== "ACTIVE" || activeProject?.authorization_status !== "authorized"}
                      onClick={handleRunWorkflow}
                      className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium"
                    >
                      {executing ? (
                        <span className="flex items-center gap-1.5">
                          <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Executing...
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5">
                          <span>▶</span>
                          Run Workflow
                        </span>
                      )}
                    </Button>
                  </div>

                  {executions.length === 0 ? (
                    <div className="border border-dashed border-border rounded-lg p-8 text-center text-muted-foreground text-xs">
                      No executions recorded yet. Click &quot;Run Workflow&quot; to execute this workflow against target endpoints.
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      {/* Left: Executions List */}
                      <div className="lg:col-span-1 space-y-2.5">
                        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                          Past Runs ({executions.length})
                        </div>
                        <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                          {executions.map((ex) => {
                            const isSelected = selectedExecution?.id === ex.id;
                            const resultColor =
                              ex.result === "PASS"
                                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                                : ex.result === "CONFIRMED"
                                ? "bg-destructive/20 text-destructive border-destructive/30"
                                : ex.result === "INCONCLUSIVE"
                                ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                                : "bg-zinc-500/20 text-zinc-300 border-zinc-500/30";

                            return (
                              <div
                                key={ex.id}
                                onClick={() => loadExecutionDetail(ex.id)}
                                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                                  isSelected
                                    ? "border-primary bg-accent/40 shadow-xs"
                                    : "border-border hover:bg-card/60"
                                }`}
                              >
                                <div className="flex items-center justify-between gap-2 mb-1.5">
                                  <span
                                    className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${resultColor}`}
                                  >
                                    {ex.result || ex.status}
                                  </span>
                                  <span className="text-[10px] font-mono text-muted-foreground">
                                    {ex.triggered_by}
                                  </span>
                                </div>
                                <div className="text-xs text-foreground font-medium truncate">
                                  {ex.result_reason || "Workflow Execution"}
                                </div>
                                <div className="flex items-center justify-between text-[11px] text-muted-foreground mt-2 pt-2 border-t border-border/50">
                                  <span>{ex.step_count} step{ex.step_count !== 1 ? "s" : ""}</span>
                                  {ex.findings_count > 0 && (
                                    <span className="font-semibold text-destructive">
                                      {ex.findings_count} finding{ex.findings_count !== 1 ? "s" : ""}
                                    </span>
                                  )}
                                  <span>
                                    {ex.started_at ? new Date(ex.started_at).toLocaleTimeString() : "-"}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                      {/* Right: Selected Execution Details */}
                      <div className="lg:col-span-2">
                        {loadingExecutionDetail ? (
                          <div className="border border-border rounded-lg p-12 text-center text-muted-foreground text-xs">
                            Loading execution trace...
                          </div>
                        ) : selectedExecution ? (
                          <div className="space-y-4">
                            {/* Summary Card */}
                            <Card className="p-4 space-y-3">
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2">
                                    <span
                                      className={`text-xs font-bold px-2.5 py-0.5 rounded border uppercase ${
                                        selectedExecution.result === "PASS"
                                          ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                                          : selectedExecution.result === "CONFIRMED"
                                          ? "bg-destructive/20 text-destructive border-destructive/30"
                                          : "bg-amber-500/20 text-amber-300 border-amber-500/30"
                                      }`}
                                    >
                                      {selectedExecution.result || selectedExecution.status}
                                    </span>
                                    <span className="text-xs text-muted-foreground font-medium">
                                      Status: {selectedExecution.status}
                                    </span>
                                    <span className="text-xs text-muted-foreground">
                                      • Trigger: {selectedExecution.triggered_by}
                                    </span>
                                  </div>
                                  <p className="text-xs text-foreground font-medium">
                                    {selectedExecution.result_reason || "Execution completed"}
                                  </p>
                                </div>
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={replaying}
                                  onClick={() => handleReplayExecution(selectedExecution.id)}
                                  className="whitespace-nowrap"
                                >
                                  {replaying ? (
                                    <span className="flex items-center gap-1.5">
                                      <span className="inline-block w-3 h-3 border-2 border-foreground border-t-transparent rounded-full animate-spin" />
                                      Replaying...
                                    </span>
                                  ) : (
                                    <span className="flex items-center gap-1.5">
                                      <span>↺</span>
                                      Replay Run
                                    </span>
                                  )}
                                </Button>
                              </div>

                              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                                <div>
                                  <span className="text-muted-foreground block text-[10px]">CORRELATION ID</span>
                                  <span className="font-mono text-[11px] truncate block" title={selectedExecution.correlation_id || ""}>
                                    {selectedExecution.correlation_id || "-"}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-muted-foreground block text-[10px]">CURRENT STATE</span>
                                  <span className="font-semibold text-[11px] text-foreground">
                                    {selectedExecution.current_state_name || "-"}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-muted-foreground block text-[10px]">STARTED AT</span>
                                  <span className="text-[11px] text-muted-foreground">
                                    {selectedExecution.started_at ? new Date(selectedExecution.started_at).toLocaleTimeString() : "-"}
                                  </span>
                                </div>
                                <div>
                                  <span className="text-muted-foreground block text-[10px]">COMPLETED AT</span>
                                  <span className="text-[11px] text-muted-foreground">
                                    {selectedExecution.completed_at ? new Date(selectedExecution.completed_at).toLocaleTimeString() : "-"}
                                  </span>
                                </div>
                              </div>

                              {selectedExecution.error_message && (
                                <div className="bg-destructive/10 border border-destructive/30 rounded p-2.5 text-xs text-destructive">
                                  <strong>Error:</strong> {selectedExecution.error_message}
                                </div>
                              )}
                            </Card>

                            {/* Findings block (if any) */}
                            {selectedExecution.findings && selectedExecution.findings.length > 0 && (
                              <div className="space-y-2">
                                <div className="text-xs font-semibold text-destructive uppercase tracking-wider flex items-center gap-1.5">
                                  <span>⚠️</span>
                                  Detected Findings ({selectedExecution.findings.length})
                                </div>
                                {selectedExecution.findings.map((finding) => (
                                  <div
                                    key={finding.id}
                                    className="p-3 rounded-lg border border-destructive/40 bg-destructive/10 space-y-1.5"
                                  >
                                    <div className="flex items-center justify-between gap-2">
                                      <div className="font-semibold text-xs text-foreground flex items-center gap-2">
                                        <span className="bg-destructive text-destructive-foreground text-[10px] font-bold px-1.5 py-0.5 rounded uppercase">
                                          {finding.severity}
                                        </span>
                                        <span>{finding.title}</span>
                                      </div>
                                      <span className="text-[10px] font-mono text-muted-foreground">
                                        {finding.type}
                                      </span>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                      {finding.description}
                                    </p>
                                    {finding.remediation && (
                                      <div className="text-[11px] text-emerald-400 bg-background/50 rounded p-1.5 mt-1 border border-border">
                                        <strong>Remediation:</strong> {finding.remediation}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* Step-by-Step Execution Trace */}
                            <div className="space-y-2">
                              <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                                Step Execution Trace ({selectedExecution.step_executions.length})
                              </div>
                              <div className="space-y-2">
                                {selectedExecution.step_executions.map((step) => {
                                  const isPass = step.status === "PASS";
                                  const isConfirmed = step.status === "CONFIRMED";
                                  const isError = step.status === "ERROR";
                                  const statusColor = isPass
                                    ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                                    : isConfirmed
                                    ? "bg-destructive/20 text-destructive border-destructive/30"
                                    : isError
                                    ? "bg-destructive/20 text-destructive border-destructive/30"
                                    : "bg-amber-500/20 text-amber-300 border-amber-500/30";

                                  return (
                                    <div
                                      key={step.id}
                                      className="p-3 rounded-lg border border-border bg-card/60 space-y-2"
                                    >
                                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                                        <div className="flex items-center gap-2">
                                          <span className="font-mono text-xs font-bold text-muted-foreground">
                                            #{step.step_order}
                                          </span>
                                          <span className="font-semibold text-xs text-foreground">
                                            {step.step_name || `Step ${step.step_order}`}
                                          </span>
                                          <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                                            {step.http_method} {step.endpoint_path}
                                          </span>
                                        </div>
                                        <div className="flex items-center gap-2">
                                          <span
                                            className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${statusColor}`}
                                          >
                                            {step.status}
                                          </span>
                                          {step.status_code && (
                                            <span
                                              className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                                                step.status_code < 400
                                                  ? "bg-emerald-500/20 text-emerald-400"
                                                  : "bg-destructive/20 text-destructive"
                                              }`}
                                            >
                                              {step.status_code}
                                            </span>
                                          )}
                                          <Button
                                            size="sm"
                                            variant="outline"
                                            className="text-[11px] h-7 px-2"
                                            onClick={() => {
                                              setSelectedStepEvidence(step);
                                              setShowEvidenceModal(true);
                                            }}
                                          >
                                            Evidence
                                          </Button>
                                        </div>
                                      </div>

                                      {/* Transition details */}
                                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] pt-1 border-t border-border/40 text-muted-foreground">
                                        <div>
                                          <span>State Transition: </span>
                                          <span className="font-semibold text-foreground">
                                            {step.state_before || "START"} &rarr; {step.state_after || "UNCHANGED"}
                                          </span>
                                        </div>
                                        <div>
                                          <span>Expected: </span>
                                          <span className="font-mono text-foreground">
                                            {step.transition_expected || "N/A"}
                                          </span>
                                        </div>
                                        <div className="sm:text-right">
                                          <span>Latency: </span>
                                          <span className="font-mono text-foreground">
                                            {step.latency_ms !== null ? `${step.latency_ms}ms` : "-"}
                                          </span>
                                        </div>
                                      </div>

                                      {step.error_message && (
                                        <div className="bg-destructive/10 text-destructive text-[11px] p-2 rounded border border-destructive/20">
                                          <strong>Error:</strong> {step.error_message}
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="border border-dashed border-border rounded-lg p-12 text-center text-muted-foreground text-xs">
                            Select an execution from the left to view detailed trace, state transitions, and evidence.
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="border border-dashed border-border rounded-lg p-12 text-center text-muted-foreground">
              {workflows.length === 0
                ? "Create a workflow on the left to start modeling steps, states, and business transitions."
                : "Select a workflow from the list to view and configure its details."}
            </div>
          )}
        </div>
      </div>

      {/* ================= MODALS ================= */}

      {/* Workflow Modal */}
      {showWfModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-lg font-bold text-foreground">
              {editingWfId ? "Edit Workflow" : "New Workflow"}
            </h3>
            <div className="space-y-3 text-xs">
              <div>
                <label className="font-semibold block mb-1">Workflow Name *</label>
                <input
                  type="text"
                  className="w-full h-9 px-3 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="e.g. Checkout Flow"
                  value={wfName}
                  onChange={(e) => setWfName(e.target.value)}
                />
              </div>
              <div>
                <label className="font-semibold block mb-1">Description</label>
                <textarea
                  rows={3}
                  className="w-full p-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="Describe the business process"
                  value={wfDesc}
                  onChange={(e) => setWfDesc(e.target.value)}
                />
              </div>
              <div>
                <label className="font-semibold block mb-1">Status</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={wfStatus}
                  onChange={(e) => setWfStatus(e.target.value as "DRAFT" | "ACTIVE" | "DISABLED")}
                >
                  <option value="DRAFT">DRAFT</option>
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="DISABLED">DISABLED</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <Button size="sm" variant="outline" onClick={() => setShowWfModal(false)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" onClick={handleSaveWorkflow}>
                {editingWfId ? "Save Changes" : "Create Workflow"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Step Modal */}
      {showStepModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl my-8">
            <h3 className="text-lg font-bold text-foreground">
              {editingStepId ? "Edit Workflow Step" : "Add Workflow Step"}
            </h3>
            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-1">
                  <label className="font-semibold block mb-1">Order # *</label>
                  <input
                    type="number"
                    min={1}
                    className="w-full h-9 px-3 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                    value={stepOrder}
                    onChange={(e) => setStepOrder(parseInt(e.target.value, 10) || 1)}
                  />
                </div>
                <div className="col-span-2">
                  <label className="font-semibold block mb-1">Step Name *</label>
                  <input
                    type="text"
                    className="w-full h-9 px-3 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                    placeholder="e.g. Inspect Cart"
                    value={stepName}
                    onChange={(e) => setStepName(e.target.value)}
                  />
                </div>
              </div>

              <div>
                <label className="font-semibold block mb-1">Target Endpoint *</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={stepEndpointId}
                  onChange={(e) => setStepEndpointId(Number(e.target.value))}
                >
                  <option value="" disabled>Select an endpoint</option>
                  {endpoints.map((ep) => (
                    <option key={ep.id} value={ep.id}>
                      [{ep.method}] {ep.path} {ep.summary ? `- ${ep.summary}` : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-semibold block mb-1">HTTP Method (Safe only)</label>
                  <select
                    className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                    value={stepMethod}
                    onChange={(e) => setStepMethod(e.target.value as "GET" | "HEAD")}
                  >
                    <option value="GET">GET</option>
                    <option value="HEAD">HEAD</option>
                  </select>
                </div>
                <div>
                  <label className="font-semibold block mb-1">Assigned Identity</label>
                  <select
                    className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                    value={stepIdentityId}
                    onChange={(e) => setStepIdentityId(e.target.value)}
                  >
                    <option value="">Anonymous (No identity)</option>
                    {identities.map((id) => (
                      <option key={id.id} value={id.id}>
                        {id.name} ({id.role_name || id.auth_type})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="font-semibold block mb-1">Expected Status Codes</label>
                <input
                  type="text"
                  className="w-full h-9 px-3 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="e.g. 200, 204"
                  value={stepCodes}
                  onChange={(e) => setStepCodes(e.target.value)}
                />
              </div>

              <div>
                <label className="font-semibold block mb-1">Request Template (JSON)</label>
                <textarea
                  rows={4}
                  className="w-full p-2 font-mono text-[11px] bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder='{"headers": {"Authorization": "Bearer {{token}}"}}'
                  value={stepTemplate}
                  onChange={(e) => setStepTemplate(e.target.value)}
                />
                <p className="text-[10px] text-muted-foreground mt-1">
                  🔒 Raw secrets/passwords are forbidden. Use placeholders like <code>{"{{token}}"}</code> or <code>[REDACTED]</code>.
                </p>
              </div>

              <div>
                <label className="font-semibold block mb-1">Description / Notes</label>
                <textarea
                  rows={2}
                  className="w-full p-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="Optional notes regarding this step"
                  value={stepDesc}
                  onChange={(e) => setStepDesc(e.target.value)}
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <Button size="sm" variant="outline" onClick={() => setShowStepModal(false)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" onClick={handleSaveStep}>
                {editingStepId ? "Save Step" : "Add Step"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* State Modal */}
      {showStateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-lg font-bold text-foreground">
              {editingStateId ? "Edit Workflow State" : "Add Workflow State"}
            </h3>
            <div className="space-y-3 text-xs">
              <div>
                <label className="font-semibold block mb-1">State Name *</label>
                <input
                  type="text"
                  className="w-full h-9 px-3 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none uppercase"
                  placeholder="e.g. CART_INITIALIZED"
                  value={stateName}
                  onChange={(e) => setStateName(e.target.value.toUpperCase())}
                />
              </div>
              <div>
                <label className="font-semibold block mb-1">Description</label>
                <textarea
                  rows={3}
                  className="w-full p-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="Describe when the workflow is in this state"
                  value={stateDesc}
                  onChange={(e) => setStateDesc(e.target.value)}
                />
              </div>
              <div className="space-y-2 pt-2 border-t border-border">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={stateIsInitial}
                    onChange={(e) => setStateIsInitial(e.target.checked)}
                    className="rounded border-input text-primary focus:ring-primary"
                  />
                  <span>Is Initial State (Entry point of workflow)</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={stateIsTerminal}
                    onChange={(e) => setStateIsTerminal(e.target.checked)}
                    className="rounded border-input text-primary focus:ring-primary"
                  />
                  <span>Is Terminal State (Final / Completed state)</span>
                </label>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <Button size="sm" variant="outline" onClick={() => setShowStateModal(false)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" onClick={handleSaveState}>
                {editingStateId ? "Save State" : "Add State"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Transition Modal */}
      {showTransModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <h3 className="text-lg font-bold text-foreground">
              {editingTransId ? "Edit Transition" : "Add State Transition"}
            </h3>
            <div className="space-y-3 text-xs">
              <div>
                <label className="font-semibold block mb-1">From State *</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={transFromId}
                  onChange={(e) => setTransFromId(e.target.value)}
                >
                  <option value="" disabled>Select source state</option>
                  {workflowDetail?.states.map((st) => (
                    <option key={st.id} value={st.id}>
                      {st.name} {st.is_initial ? "(INITIAL)" : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="font-semibold block mb-1">To State *</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={transToId}
                  onChange={(e) => setTransToId(e.target.value)}
                >
                  <option value="" disabled>Select destination state</option>
                  {workflowDetail?.states.map((st) => (
                    <option key={st.id} value={st.id}>
                      {st.name} {st.is_terminal ? "(TERMINAL)" : ""}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="font-semibold block mb-1">Triggering Step (Optional)</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={transStepId}
                  onChange={(e) => setTransStepId(e.target.value)}
                >
                  <option value="">None / Any Step</option>
                  {workflowDetail?.steps.map((s) => (
                    <option key={s.id} value={s.id}>
                      Step #{s.step_order}: {s.name} ({s.endpoint_path})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="font-semibold block mb-1">Expected Behavior *</label>
                <select
                  className="w-full h-9 px-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  value={transBehavior}
                  onChange={(e) => setTransBehavior(e.target.value as "ALLOW" | "DENY")}
                >
                  <option value="ALLOW">ALLOW (Valid transition)</option>
                  <option value="DENY">DENY (Forbidden / Bypass transition)</option>
                </select>
              </div>

              <div>
                <label className="font-semibold block mb-1">Description / Rationale</label>
                <textarea
                  rows={2}
                  className="w-full p-2 bg-background border border-input rounded-md focus:ring-1 focus:ring-primary outline-none"
                  placeholder="Explain why this transition should be allowed or denied"
                  value={transDesc}
                  onChange={(e) => setTransDesc(e.target.value)}
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <Button size="sm" variant="outline" onClick={() => setShowTransModal(false)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" onClick={handleSaveTransition}>
                {editingTransId ? "Save Transition" : "Add Transition"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Evidence Modal */}
      {showEvidenceModal && selectedStepEvidence && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-card border border-border rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl my-8">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-base font-bold text-foreground">
                  Step #{selectedStepEvidence.step_order} Sanitized Evidence
                </h3>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">
                  [{selectedStepEvidence.http_method}] {selectedStepEvidence.endpoint_path}
                </p>
              </div>
              <Button size="sm" variant="outline" onClick={() => setShowEvidenceModal(false)}>
                Close
              </Button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-2.5 rounded bg-muted/40 border border-border text-[11px]">
                <div>
                  <span className="text-muted-foreground block text-[10px]">STATUS CODE</span>
                  <span className="font-mono font-bold text-foreground">
                    {selectedStepEvidence.status_code || "-"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px]">LATENCY</span>
                  <span className="font-mono text-foreground">
                    {selectedStepEvidence.latency_ms !== null ? `${selectedStepEvidence.latency_ms}ms` : "-"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px]">STEP STATUS</span>
                  <span className="font-semibold uppercase text-foreground">
                    {selectedStepEvidence.status}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground block text-[10px]">TRANSITION</span>
                  <span className="font-mono text-foreground truncate block">
                    {selectedStepEvidence.state_before || "START"} &rarr; {selectedStepEvidence.state_after || "UNCHANGED"}
                  </span>
                </div>
              </div>

              <div>
                <label className="font-semibold block mb-1 text-muted-foreground">Sanitized Request Summary</label>
                <pre className="p-3 bg-background border border-input rounded-md text-[11px] font-mono overflow-x-auto max-h-48 text-foreground whitespace-pre-wrap">
                  {selectedStepEvidence.request_summary
                    ? JSON.stringify(selectedStepEvidence.request_summary, null, 2)
                    : "No request summary available"}
                </pre>
              </div>

              <div>
                <label className="font-semibold block mb-1 text-muted-foreground">Sanitized Response Summary</label>
                <pre className="p-3 bg-background border border-input rounded-md text-[11px] font-mono overflow-x-auto max-h-48 text-foreground whitespace-pre-wrap">
                  {selectedStepEvidence.response_summary
                    ? JSON.stringify(selectedStepEvidence.response_summary, null, 2)
                    : "No response summary available"}
                </pre>
              </div>

              {selectedStepEvidence.correlation_id && (
                <div className="text-[10px] text-muted-foreground font-mono">
                  Correlation ID: {selectedStepEvidence.correlation_id}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-3 border-t border-border">
              <Button size="sm" variant="primary" onClick={() => setShowEvidenceModal(false)}>
                Done
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
