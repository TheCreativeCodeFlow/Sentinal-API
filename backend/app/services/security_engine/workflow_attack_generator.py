from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models import (
    Workflow,
    WorkflowStep,
    WorkflowState,
    WorkflowTransition,
    WorkflowAttackScenario,
    WorkflowAttackStep,
    Project,
    Identity,
)


SUPPORTED_SCENARIO_TYPES = [
    "INVALID_STATE_TRANSITION",
    "STEP_REPLAY",
    "STEP_SKIP",
    "STEP_REORDER",
    "IDENTITY_SWITCH",
    "CROSS_IDENTITY_CONTINUATION",
]


class WorkflowAttackGenerator:
    """
    Stateful Attack Scenario Generator.
    Automatically generates safe adversarial test scenarios from an ACTIVE workflow model.
    Does NOT execute scenarios automatically.
    Deduplicates equivalent scenarios.
    """

    def __init__(self, db: Session):
        self.db = db

    def generate_scenarios(
        self,
        workflow: Workflow,
        scenario_types: Optional[List[str]] = None,
    ) -> List[WorkflowAttackScenario]:
        """
        Generates adversarial attack scenarios for an ACTIVE workflow.
        Returns a list of created or existing deduplicated scenarios.
        """
        # 1. Project authorization check
        project = self.db.query(Project).filter(Project.id == workflow.project_id).first()
        if not project or project.authorization_status.lower() != "authorized":
            raise ValueError(
                "Target project has not been explicitly authorized for security testing."
            )

        # 2. Workflow must be ACTIVE
        if workflow.status.upper() != "ACTIVE":
            raise ValueError(
                f"Workflow '{workflow.name}' is in status '{workflow.status}'. "
                "Only ACTIVE workflows can generate attack scenarios."
            )

        # 3. Steps check
        steps = sorted(workflow.steps, key=lambda s: s.step_order)
        if not steps:
            raise ValueError("Workflow contains no steps to generate attack scenarios from.")

        types_to_generate = (
            [t.upper() for t in scenario_types]
            if scenario_types
            else SUPPORTED_SCENARIO_TYPES
        )

        project_identities = (
            self.db.query(Identity)
            .filter(Identity.project_id == workflow.project_id)
            .order_by(Identity.created_at)
            .all()
        )

        results: List[WorkflowAttackScenario] = []

        # A. INVALID_STATE_TRANSITION
        if "INVALID_STATE_TRANSITION" in types_to_generate:
            invalid_trans_scenarios = self._generate_invalid_state_transition_scenarios(
                workflow, steps
            )
            results.extend(invalid_trans_scenarios)

        # B. STEP_REPLAY
        if "STEP_REPLAY" in types_to_generate:
            replay_scenarios = self._generate_step_replay_scenarios(workflow, steps)
            results.extend(replay_scenarios)

        # C. STEP_SKIP
        if "STEP_SKIP" in types_to_generate and len(steps) >= 2:
            skip_scenarios = self._generate_step_skip_scenarios(workflow, steps)
            results.extend(skip_scenarios)

        # D. STEP_REORDER
        if "STEP_REORDER" in types_to_generate and len(steps) >= 2:
            reorder_scenarios = self._generate_step_reorder_scenarios(workflow, steps)
            results.extend(reorder_scenarios)

        # E. IDENTITY_SWITCH
        if "IDENTITY_SWITCH" in types_to_generate and len(project_identities) >= 2 and len(steps) >= 2:
            switch_scenarios = self._generate_identity_switch_scenarios(
                workflow, steps, project_identities
            )
            results.extend(switch_scenarios)

        # F. CROSS_IDENTITY_CONTINUATION
        if (
            "CROSS_IDENTITY_CONTINUATION" in types_to_generate
            and len(project_identities) >= 2
        ):
            cross_scenarios = self._generate_cross_identity_scenarios(
                workflow, steps, project_identities
            )
            results.extend(cross_scenarios)

        return results

    def _find_or_create_scenario(
        self,
        workflow_id: str,
        name: str,
        description: str,
        scenario_type: str,
        attack_steps_data: List[Dict[str, Any]],
    ) -> WorkflowAttackScenario:
        """
        Deduplicates scenarios by (workflow_id, scenario_type, name).
        If matching scenario exists, returns it; otherwise persists new scenario and its steps.
        """
        existing = (
            self.db.query(WorkflowAttackScenario)
            .filter(
                WorkflowAttackScenario.workflow_id == workflow_id,
                WorkflowAttackScenario.scenario_type == scenario_type,
                WorkflowAttackScenario.name == name,
            )
            .first()
        )
        if existing:
            return existing

        scenario = WorkflowAttackScenario(
            workflow_id=workflow_id,
            name=name,
            description=description,
            scenario_type=scenario_type,
            status="ACTIVE",
        )
        self.db.add(scenario)
        self.db.commit()
        self.db.refresh(scenario)

        for step_data in attack_steps_data:
            attack_step = WorkflowAttackStep(
                scenario_id=scenario.id,
                source_step_id=step_data.get("source_step_id"),
                position=step_data["position"],
                action=step_data["action"],
                identity_id=step_data.get("identity_id"),
                expected_behavior=step_data.get("expected_behavior", "DENY"),
                configuration=step_data.get("configuration"),
            )
            self.db.add(attack_step)

        self.db.commit()
        self.db.refresh(scenario)
        return scenario

    def _generate_invalid_state_transition_scenarios(
        self, workflow: Workflow, steps: List[WorkflowStep]
    ) -> List[WorkflowAttackScenario]:
        """
        Finds transitions explicitly marked DENY and constructs sequences attempting that transition.
        """
        scenarios: List[WorkflowAttackScenario] = []
        deny_transitions = [
            t for t in workflow.transitions if t.expected_behavior == "DENY"
        ]

        for trans in deny_transitions:
            from_name = trans.from_state.name if trans.from_state else "UNKNOWN"
            to_name = trans.to_state.name if trans.to_state else "UNKNOWN"
            name = f"Invalid State Transition: {from_name} -> {to_name}"
            desc = (
                f"Adversarial scenario attempting forbidden transition from '{from_name}' "
                f"to '{to_name}' (explicitly marked DENY in state model)."
            )

            # Build sequence: steps leading to from_state + violating step
            attack_steps: List[Dict[str, Any]] = []
            pos = 1

            # If the transition specifies a step, find that step
            violating_step = trans.step
            if not violating_step:
                # Find step with matching target endpoint or default to first/last step
                violating_step = steps[0]

            # Steps before the violating step
            for s in steps:
                if s.id == violating_step.id:
                    break
                attack_steps.append(
                    {
                        "position": pos,
                        "source_step_id": s.id,
                        "action": "EXECUTE",
                        "identity_id": s.identity_id,
                        "expected_behavior": "ALLOW",
                    }
                )
                pos += 1

            # The violating step
            attack_steps.append(
                {
                    "position": pos,
                    "source_step_id": violating_step.id,
                    "action": "EXECUTE",
                    "identity_id": violating_step.identity_id,
                    "expected_behavior": "DENY",
                    "configuration": {
                        "from_state": from_name,
                        "target_state": to_name,
                        "transition_id": trans.id,
                    },
                }
            )

            sc = self._find_or_create_scenario(
                workflow_id=workflow.id,
                name=name,
                description=desc,
                scenario_type="INVALID_STATE_TRANSITION",
                attack_steps_data=attack_steps,
            )
            scenarios.append(sc)

        return scenarios

    def _generate_step_replay_scenarios(
        self, workflow: Workflow, steps: List[WorkflowStep]
    ) -> List[WorkflowAttackScenario]:
        """
        Replays completed steps where repetition should be forbidden by business logic.
        """
        scenarios: List[WorkflowAttackScenario] = []

        # Generate replay for each step in the workflow
        for target_step in steps:
            name = f"Step Replay: Step #{target_step.step_order} ({target_step.name})"
            desc = (
                f"Executes normal sequence up to step #{target_step.step_order} and immediately "
                f"replays it to verify server enforces idempotent state or replay rejection."
            )

            attack_steps: List[Dict[str, Any]] = []
            pos = 1

            # Steps up to target_step
            for s in steps:
                attack_steps.append(
                    {
                        "position": pos,
                        "source_step_id": s.id,
                        "action": "EXECUTE",
                        "identity_id": s.identity_id,
                        "expected_behavior": "ALLOW",
                    }
                )
                pos += 1
                if s.id == target_step.id:
                    break

            # Replay the target step
            attack_steps.append(
                {
                    "position": pos,
                    "source_step_id": target_step.id,
                    "action": "REPLAY",
                    "identity_id": target_step.identity_id,
                    "expected_behavior": "DENY",
                    "configuration": {"replayed_step_order": target_step.step_order},
                }
            )

            sc = self._find_or_create_scenario(
                workflow_id=workflow.id,
                name=name,
                description=desc,
                scenario_type="STEP_REPLAY",
                attack_steps_data=attack_steps,
            )
            scenarios.append(sc)

        return scenarios

    def _generate_step_skip_scenarios(
        self, workflow: Workflow, steps: List[WorkflowStep]
    ) -> List[WorkflowAttackScenario]:
        """
        Skips required intermediate steps and attempts executing subsequent steps.
        """
        scenarios: List[WorkflowAttackScenario] = []

        for skip_idx in range(len(steps) - 1):
            skipped_step = steps[skip_idx]
            target_step = steps[skip_idx + 1]

            name = f"Step Skip: Bypass Step #{skipped_step.step_order} ({skipped_step.name})"
            desc = (
                f"Bypasses prerequisite step #{skipped_step.step_order} ('{skipped_step.name}') "
                f"and executes step #{target_step.step_order} ('{target_step.name}') directly."
            )

            attack_steps: List[Dict[str, Any]] = []
            pos = 1

            # Steps before the skipped step
            for idx in range(skip_idx):
                s = steps[idx]
                attack_steps.append(
                    {
                        "position": pos,
                        "source_step_id": s.id,
                        "action": "EXECUTE",
                        "identity_id": s.identity_id,
                        "expected_behavior": "ALLOW",
                    }
                )
                pos += 1

            # Mark skipped step
            attack_steps.append(
                {
                    "position": pos,
                    "source_step_id": skipped_step.id,
                    "action": "SKIP",
                    "identity_id": skipped_step.identity_id,
                    "expected_behavior": "ALLOW",
                }
            )
            pos += 1

            # Execute target step which was skipped to - expected DENY
            attack_steps.append(
                {
                    "position": pos,
                    "source_step_id": target_step.id,
                    "action": "EXECUTE",
                    "identity_id": target_step.identity_id,
                    "expected_behavior": "DENY",
                    "configuration": {
                        "skipped_step_order": skipped_step.step_order,
                        "target_step_order": target_step.step_order,
                    },
                }
            )

            sc = self._find_or_create_scenario(
                workflow_id=workflow.id,
                name=name,
                description=desc,
                scenario_type="STEP_SKIP",
                attack_steps_data=attack_steps,
            )
            scenarios.append(sc)

        return scenarios

    def _generate_step_reorder_scenarios(
        self, workflow: Workflow, steps: List[WorkflowStep]
    ) -> List[WorkflowAttackScenario]:
        """
        Inverts step ordering by executing a later step before its prerequisite.
        """
        scenarios: List[WorkflowAttackScenario] = []

        step_a = steps[0]
        step_b = steps[1]

        name = f"Step Reorder: Step #{step_b.step_order} Before Step #{step_a.step_order}"
        desc = (
            f"Adversarially reorders sequence by invoking step #{step_b.step_order} ('{step_b.name}') "
            f"before prerequisite step #{step_a.step_order} ('{step_a.name}')."
        )

        attack_steps = [
            {
                "position": 1,
                "source_step_id": step_b.id,
                "action": "EXECUTE",
                "identity_id": step_b.identity_id,
                "expected_behavior": "DENY",
                "configuration": {
                    "original_position": step_b.step_order,
                    "new_position": 1,
                },
            },
            {
                "position": 2,
                "source_step_id": step_a.id,
                "action": "EXECUTE",
                "identity_id": step_a.identity_id,
                "expected_behavior": "ALLOW",
            },
        ]

        sc = self._find_or_create_scenario(
            workflow_id=workflow.id,
            name=name,
            description=desc,
            scenario_type="STEP_REORDER",
            attack_steps_data=attack_steps,
        )
        scenarios.append(sc)
        return scenarios

    def _generate_identity_switch_scenarios(
        self,
        workflow: Workflow,
        steps: List[WorkflowStep],
        identities: List[Identity],
    ) -> List[WorkflowAttackScenario]:
        """
        Executes one workflow step as identity A and switches to identity B for subsequent steps.
        """
        scenarios: List[WorkflowAttackScenario] = []
        id_a = identities[0]
        id_b = identities[1]

        target_step = steps[1]
        name = f"Identity Switch: {id_a.name} to {id_b.name} at Step #{target_step.step_order}"
        desc = (
            f"Initiates workflow with identity '{id_a.name}' and attempts to switch session to "
            f"'{id_b.name}' at step #{target_step.step_order} to detect session binding flaws."
        )

        attack_steps = [
            {
                "position": 1,
                "source_step_id": steps[0].id,
                "action": "EXECUTE",
                "identity_id": id_a.id,
                "expected_behavior": "ALLOW",
            },
            {
                "position": 2,
                "source_step_id": target_step.id,
                "action": "SWITCH_IDENTITY",
                "identity_id": id_b.id,
                "expected_behavior": "DENY",
                "configuration": {
                    "initial_identity_id": id_a.id,
                    "switched_identity_id": id_b.id,
                },
            },
        ]

        sc = self._find_or_create_scenario(
            workflow_id=workflow.id,
            name=name,
            description=desc,
            scenario_type="IDENTITY_SWITCH",
            attack_steps_data=attack_steps,
        )
        scenarios.append(sc)
        return scenarios

    def _generate_cross_identity_scenarios(
        self,
        workflow: Workflow,
        steps: List[WorkflowStep],
        identities: List[Identity],
    ) -> List[WorkflowAttackScenario]:
        """
        Starts a workflow with Identity A and continues resource-dependent steps with Identity B.
        """
        scenarios: List[WorkflowAttackScenario] = []
        id_a = identities[0]
        id_b = identities[1]

        target_step = steps[1] if len(steps) >= 2 else steps[0]
        name = f"Cross-Identity Continuation: {id_b.name} on {id_a.name}'s Resource"
        desc = (
            f"Creates or initializes an entity state with identity '{id_a.name}' and attempts "
            f"to perform follow-up operations using unauthorized identity '{id_b.name}'."
        )

        attack_steps = [
            {
                "position": 1,
                "source_step_id": steps[0].id,
                "action": "EXECUTE",
                "identity_id": id_a.id,
                "expected_behavior": "ALLOW",
            },
            {
                "position": 2,
                "source_step_id": target_step.id,
                "action": "EXECUTE",
                "identity_id": id_b.id,
                "expected_behavior": "DENY",
                "configuration": {
                    "cross_identity": True,
                    "owner_identity_id": id_a.id,
                    "attacker_identity_id": id_b.id,
                },
            },
        ]

        sc = self._find_or_create_scenario(
            workflow_id=workflow.id,
            name=name,
            description=desc,
            scenario_type="CROSS_IDENTITY_CONTINUATION",
            attack_steps_data=attack_steps,
        )
        scenarios.append(sc)
        return scenarios
