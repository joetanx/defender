> Prompt:
> 
> product: autonomous agent for security operations
overview: automous agent system to perform tier 1 security analyst function to triage incidents in SOC, incidents from the SOC will trigger the Azure Function that runs this autonomous agent system
> requirements:
> 1. analyze the incident
> 2. investigate each indicator of compromise in the incident
> 3. threat hunt to search for similar incidents
> 4. judgement on the incident based on results of items 1-3:
>   a. benign events closed with comments of how the decision is arrived
>   b. suspicious events should be escalated and assigned to tier 2 security team
> 
> the files I have is a draft of a functional agent (`function_app.py`) that can connect to the MCP tools (`ms-security-mcp-tools-list.json`).
> i want to move to the agentic system design phase for the 4 items described.
> i thought of 3 options:
> 1. single agent with the instructions of the item 4 items - simple but:
>    a. may have too much data for 1 agent, which can make it reason poorly or miss out some actions
>    b. can run out of context or time out
> 2. concurrent agent flow - create 3 agents for item 1-3, each agent has specific instructions according the items, the incident ID is passed to each agent for them to do their role, the final collector agent perform item 4 to make judgement. this sounds feasible but more delibration needed on whether this pattern of concurrency make sense, how data flow between the 4 agents, what other agents required
> 3. other agent patterns: handoff, group chat, magentic - these sounds powerful but can be complex. i also saw the sub-agent capabilities in n8n which seems powerful as the orchestration agent can iterate multiple tool agents, not sure if that is implementable in microsoft agent framework
>
> the microsoft agent framework documentation is available here:
> - https://learn.microsoft.com/en-us/agent-framework/workflows/
> - https://github.com/microsoft/agent-framework/tree/main/python/samples/02-agents
> - https://github.com/microsoft/agent-framework/tree/main/python/samples/03-workflows

Excellent — I now have a comprehensive picture from your files and the MAF documentation. Let me synthesize a design recommendation tailored specifically to your SOC autonomous agent system.

***

# 🛡️ Agentic System Design: Autonomous Tier-1 SOC Agent

## Context Recap

Based on your [function\_app.py](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/function_app.py?EntityRepresentationId=6a7e14d3-14b0-42b9-ba94-ea7cbbc35281) and [ms-security-mcp-tools-list.json](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/ms-security-mcp-tools-list.json?EntityRepresentationId=f4580a78-0d99-4b00-9bb1-00e62670b74d), you already have:

*   A working Azure Function with MCP tool integration via `MCPStreamableHTTPTool`
*   The Entra Agent Identity auth chain (MI → Blueprint → Agent ID → Agent User token)
*   8 MCP tools: `getIncidentById`, `listAlerts`, `listIncidents`, `runHuntingQuery`, `createCommentForIncident`, `createCommentForAlert`, `updateAlert`, `updateIncident`

The question is: which MAF multi-agent pattern best fits your 4 SOC requirements?

***

## ❌ Option 1: Single Agent — Not Recommended

Your instinct is correct. A single agent handling all 4 tasks will:

*   **Suffer context bloat** — incident data + alerts + hunting results + all tool schemas loaded simultaneously
*   **Reason poorly** — instructions for triage, IoC investigation, threat hunting, and judgment are semantically conflicting for one agent
*   **Risk timeout** — Azure Function default timeout is 5 minutes; a single agent making 6–10 sequential tool calls will be at risk [\[Microsoft...soft Learn \| Learn.Microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/overview/)

***

## ✅ Recommended: **Option 2 Enhanced — Concurrent + Sequential Hybrid with Orchestrator-Workers**

This is the most production-appropriate pattern for your use case. Here's the full design:

***

### 🏗️ Architecture: 4-Agent System

    Azure Function Trigger (Incident ID)
             │
             ▼
    ┌─────────────────────────────────────────────────────┐
    │           ORCHESTRATOR AGENT                        │
    │  • Receives incident ID                             │
    │  • Fans out to 3 specialist agents concurrently     │
    │  • Collects all 3 results                           │
    │  • Passes full context to Judgment Agent            │
    └────────────────┬────────────────────────────────────┘
                     │  (concurrent fan-out)
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
    ┌────────┐  ┌────────┐  ┌──────────────┐
    │ANALYST │  │  IoC   │  │ THREAT HUNT  │
    │ AGENT  │  │ AGENT  │  │   AGENT      │
    │(Item 1)│  │(Item 2)│  │  (Item 3)    │
    └────────┘  └────────┘  └──────────────┘
        │            │             │
        └────────────┴─────────────┘
                     │  (sequential aggregation)
                     ▼
        ┌─────────────────────────┐
        │    JUDGMENT AGENT       │
        │       (Item 4)          │
        │  • Benign → Close       │
        │  • Suspicious → Escalate│
        └─────────────────────────┘

***

### 🤖 Agent Definitions

#### Agent 1: Incident Analyst

*   **Role**: Item 1 — Analyze the incident
*   **Tools**: `getIncidentById` (with `$expand=alerts`), `listAlerts`
*   **Instructions**: *"You are a security incident analyst. Given an incident ID, retrieve the incident and all associated alerts. Extract: severity, affected entities (users, devices, IPs), attack techniques (MITRE), timeline, and data sources. Return a structured incident summary."*
*   **Output**: Structured incident profile (severity, entities, techniques, timeline)

#### Agent 2: IoC Investigator

*   **Role**: Item 2 — Investigate each indicator of compromise
*   **Tools**: `listAlerts` (filter by entity), `runHuntingQuery`
*   **Instructions**: *"You are an IoC investigation specialist. Given an incident ID, retrieve its alerts and extract all indicators (IPs, hashes, URLs, user accounts, devices). For each indicator, run a targeted hunting query to check its activity history, reputation context, and lateral movement. Summarize findings per IoC."*
*   **Output**: Per-IoC verdict (seen before / frequency / associated with other alerts)
*   **Key KQL patterns to inject**: `DeviceNetworkEvents`, `IdentityLogonEvents`, `AlertEvidence`

#### Agent 3: Threat Hunter

*   **Role**: Item 3 — Hunt for similar incidents
*   **Tools**: `listIncidents` (filter by time/severity), `runHuntingQuery`
*   **Instructions**: *"You are a threat hunter. Given an incident ID, retrieve the incident's key attributes. Run hunting queries to find: (a) similar incidents in the last 30 days with matching techniques or entities, (b) related alerts not yet grouped into an incident. Return a threat hunt report indicating whether this appears isolated or part of a campaign."*
*   **Output**: Hunt summary (isolated vs. campaign indicators, related incident IDs)

#### Agent 4: Judgment Agent

*   **Role**: Item 4 — Make triage decision and take action
*   **Tools**: `updateIncident`, `createCommentForIncident`, `updateAlert`
*   **Instructions**: *"You are a Tier-1 SOC triage lead. You receive: (a) incident analysis, (b) IoC investigation results, (c) threat hunt report. Based on all evidence, make a triage decision: if BENIGN, close the incident with classification=falsePositive or informationalExpectedActivity and write a detailed comment explaining your reasoning. If SUSPICIOUS or CONFIRMED THREAT, set status=active, escalate by assigning to the Tier-2 group, and write a comment summarizing the evidence."*
*   **Output**: Actions taken on the incident in Defender

***

### 🔀 MAF Pattern Mapping

The MAF supports this exact hybrid natively: [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/)

| Phase                           | MAF Pattern                     | Builder                      |
| ------------------------------- | ------------------------------- | ---------------------------- |
| Fan-out to Agents 1–3           | **Concurrent**                  | `ConcurrentBuilder`          |
| Agent 4 receives all results    | **Sequential** after concurrent | `WorkflowBuilder.add_edge()` |
| Orchestrator calling sub-agents | **Orchestrator-Workers**        | Workers as `async def` tools |

The **Orchestrator-Workers pattern** (Pattern 4 from MAF production patterns) is the cleanest fit — the orchestrator agent holds sub-agents as callable async tools, invokes them concurrently, then passes results to the Judgment Agent. [\[matthewkruczek.ai\]](https://matthewkruczek.ai/blog/multi-agent-patterns-microsoft.html)

***

### 💡 Why Not the Other Options?

| Pattern           | Verdict       | Reason                                                                                                                                                                                                                                                                                                                      |
| ----------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Handoff**       | ❌ Not ideal   | Handoff is dynamic/conversational routing — good for "I don't know which agent to call." Your SOC flow is *deterministic*: always run all 3, always judge. Handoff adds nondeterminism you don't need. [\[deepwiki.com\]](https://deepwiki.com/microsoft/agent-framework/4.3.2-handoff-pattern) |
| **Group Chat**    | ❌ Overkill    | Group chat is for open-ended collaboration where agents debate. Your agents have no need to "discuss" — they work independently and pass structured outputs.                                                                                                                                                                |
| **Magentic**      | ❌ Too dynamic | Magentic has a manager dynamically decomposing tasks. Your decomposition is *fixed* (always 4 tasks). Magentic adds overhead and unpredictability to a well-defined SOC workflow.                                                                                                                                           |
| **n8n sub-agent** | ⚠️ Not in MAF | The n8n orchestrator→sub-agent pattern is equivalent to MAF's Orchestrator-Workers. You can implement it natively in MAF without n8n. [\[Microsoft...soft Learn \| Learn.Microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/overview/)                                                                           |

***

### 📦 Data Flow Between Agents

A key design concern you raised — here's how data passes:

```python
# Orchestrator calls workers concurrently, collects structured outputs
async def analyze_incident(incident_id: str) -> str:
    """Retrieve and analyze the incident and all its alerts"""
    result = await analyst_agent.run(f"Analyze incident {incident_id}")
    return result.text

async def investigate_ioc(incident_id: str) -> str:
    """Investigate all indicators of compromise in incident"""
    result = await ioc_agent.run(f"Investigate IoCs in incident {incident_id}")
    return result.text

async def threat_hunt(incident_id: str) -> str:
    """Threat hunt for similar incidents"""
    result = await hunt_agent.run(f"Hunt for similar activity to incident {incident_id}")
    return result.text

orchestrator = client.create_agent(
    name="SOCOrchestrator",
    instructions="""You are a SOC orchestrator. For each incident:
    1. Call analyze_incident, investigate_ioc, and threat_hunt CONCURRENTLY
    2. Pass all 3 results to the judgment agent
    3. Return the final triage decision""",
    tools=[analyze_incident, investigate_ioc, threat_hunt, judge_incident]
)
```

The **full conversation history** flows between agents in sequential chains — each downstream agent sees all prior agent outputs.  For the concurrent case, you collect outputs as strings and pass them bundled to the Judgment Agent. [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/sequential)

***

### ⚠️ Additional Design Considerations

**1. Azure Function Timeout**

*   Default: 5 min (Consumption), 30 min (Premium/Dedicated)
*   Concurrent execution of Agents 1–3 will save \~60% of sequential time
*   Recommend: **Premium plan** + async durable function or queue-triggered function for resilience

**2. Shared MCP Client**

*   All agents share the same `MCPStreamableHTTPTool` — the `get_agentuser_token()` auth chain is per-request
*   Consider token caching or passing the `http_client` context to sub-agents to avoid redundant token acquisitions per agent

**3. Tool Scoping per Agent**

*   Restrict each specialist agent to only its required tools to reduce hallucination risk and improve focus:
    *   Analyst: `getIncidentById`, `listAlerts`
    *   IoC Agent: `listAlerts`, `runHuntingQuery`
    *   Hunt Agent: `listIncidents`, `runHuntingQuery`
    *   Judgment Agent: `updateIncident`, `createCommentForIncident`, `updateAlert`

**4. Structured Output Contract**

*   Define a JSON schema for each agent's output (incident summary, IoC report, hunt report) so the Judgment Agent reliably parses them rather than free-text reasoning

**5. Observability**

*   MAF has built-in OpenTelemetry support  — instrument each agent so you can trace which tool calls fired and what each agent concluded, critical for SOC audit trails [\[matthewkruczek.ai\]](https://matthewkruczek.ai/blog/multi-agent-patterns-microsoft.html)

***

### 📁 Reference Samples in MAF Repo

From `03-workflows/orchestrations`: [\[github.com\]](https://github.com/microsoft/agent-framework/tree/main/python/samples/03-workflows/orchestrations)

*   `concurrent_agents.py` — exactly your fan-out pattern
*   `concurrent_custom_aggregator.py` — custom aggregation of concurrent results into Judgment Agent
*   `handoff_autonomous.py` — useful reference but not your primary pattern
*   `magentic.py` — good to read but skip for this use case

***

**Bottom line**: Go with the **Concurrent + Orchestrator-Workers hybrid**. It maps perfectly to your 4 requirements, is natively supported in MAF, avoids the pitfalls of single-agent overload, and keeps your SOC workflow deterministic and auditable. Want me to draft the full `function_app.py` scaffold for this 4-agent system?
