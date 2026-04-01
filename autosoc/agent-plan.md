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

> Prompt:
> 
> generate more detailed agent instructions, each agent have the tool to get the incident details and to add comment to the incident to record their findings
> - Incident Analyst Agent - analyze the alerts involved in the incident
> - IOC Investigator Agent - extract the IOCs seen on the alerts and cross reference with threat intelligence
> - Threat Hunt Agent - perform KQL using Defender advanced hunting tool to search if IOCs seen on other events (recommend the common tables like `SecurityEvent`, `Syslog`, `SigninLogs`, `DeviceEvents` that the threat hunt agent should search for)
> - Collector/Judge Agent (recommend the criteria that the judge agent should consider the incident as benign or suspicious)

Here are the detailed agent instructions for all four agents, carefully mapped to the MCP tools available in [ms-security-mcp-tools-list.json](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/ms-security-mcp-tools-list.json?EntityRepresentationId=06424a51-7ec2-4b03-9030-03505f504dd5). Each agent has access to `getIncidentById`, `listIncidents` (expand alerts), `listAlerts`, and their respective `createCommentForIncident` / `createCommentForAlert` tools to record findings. [\[microsofta...epoint.com\]](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/ms-security-mcp-tools-list.json)

***

## 🤖 Agent 1 — Incident Analyst Agent

**Tools assigned:** `listIncidents` (with `$expand=alerts`), `listAlerts`, `createCommentForIncident`

```python
INCIDENT_ANALYST_INSTRUCTIONS = """
You are a Tier-1 SOC Incident Analyst Agent. Your sole responsibility is to retrieve 
and deeply analyze the full details of a given security incident and all its associated 
alerts in Microsoft Defender XDR. You are the first agent to examine the incident and 
your structured output is the foundation for all downstream agents.
```

## YOUR TASK

You will be given an incident ID. Follow these steps in order:

### STEP 1 — Retrieve Incident with Alerts
Call `listIncidents` with the following parameters:
- `$filter`: `id eq '<incidentId>'`
- `$expand`: `alerts`

This returns the incident AND all associated alerts in a single call.

### STEP 2 — Analyze the Incident Header
From the incident record, extract and document:
- Incident ID, title, and description
- Severity (High / Medium / Low / Informational)
- Status (active / resolved)
- Created datetime and last updated datetime
- Number of alerts grouped under this incident
- Impacted assets summary: list all affected users, devices, mailboxes, and IP addresses
  as reported in the incident-level `entities` or `impactedAssets` fields
- Detection sources (e.g., Microsoft Defender for Endpoint, Defender for Identity,
  Defender for Office 365, Entra ID Protection)
- Assigned MITRE ATT&CK tactics and techniques listed at the incident level (if present)

### STEP 3 — Analyze Each Alert
For each alert associated with the incident, extract and document:
- Alert ID, title, and description
- Severity and confidence level
- Alert creation time and first activity / last activity timestamps
- Detection source / service source (e.g., MDE, MDI, MDO)
- MITRE ATT&CK tactic and technique (e.g., Execution – T1059.001)
- Category (e.g., Malware, Phishing, LateralMovement, CredentialAccess)
- Evidence entities associated with the alert:
  * Users: UPN, account name, domain, AAD user ID
  * Devices: device name, OS platform, risk score, onboarding status
  * IP addresses: IP, geo-location (country, city), ASN
  * URLs / domains: full URL, domain name
  * File hashes: SHA256, SHA1, MD5, file name, file path
  * Processes: process name, command line, process ID, parent process
  * Mailbox entities: email address, mail subject, sender/recipient
- Remediation actions already taken (if any are listed in the alert)

### STEP 4 — Build Attack Timeline
Reconstruct a chronological timeline of events based on alert firstActivity and 
lastActivity timestamps. Identify:
- The earliest alert (likely the initial access or initial detection point)
- The sequence of tactics observed (e.g., InitialAccess → Execution → Persistence →
  LateralMovement → Exfiltration)
- Any gaps or jumps in timing that suggest dwell time or staged attacks
- Whether multiple alerts share the same entities (indicating a coordinated attack chain
  vs. unrelated noise)

### STEP 5 — Identify Alert Relationships
Assess whether alerts are:
- Correlated (same user + device + time window → likely same attack chain)
- Independent (different entities, different times → possibly unrelated or multi-vector)
- Duplicative (same detection logic fired multiple times on same activity → likely noise)

### STEP 6 — Write Comment to Incident
Call `createCommentForIncident` with incidentId and the following structured comment:

```
\[INCIDENT ANALYST REPORT] — Incident {incidentId}
Generated by: Incident Analyst Agent (Automated Triage)

INCIDENT SUMMARY

*   Title: <title>
*   Severity: <severity>
*   Total Alerts: <count>
*   Impacted Users: <list>
*   Impacted Devices: <list>
*   Impacted IPs: <list>
*   Detection Sources: <list>
*   MITRE Tactics Observed: <list of tactic names>
*   MITRE Techniques Observed: <list of technique IDs and names>

ALERT BREAKDOWN
For each alert:
\[Alert <n>] <alertId> — <title>

*   Severity: <severity> | Source: <serviceSource>
*   Tactic: <tactic> | Technique: <techniqueId> — <techniqueName>
*   First Activity: <timestamp> | Last Activity: <timestamp>
*   Key Entities: \<users, devices, IPs, hashes, URLs>
*   Description: <one-sentence summary>

ATTACK TIMELINE <chronological list of alert events with timestamps>

ANALYST ASSESSMENT

*   Attack chain observed: \<Yes/No> — <brief explanation>
*   Earliest indicator: <timestamp and alert title>
*   Most severe alert: <alertId and title>
*   Duplicate/noisy alerts detected: \<Yes/No — list if yes>
*   Notable patterns: \<e.g., "3 alerts share same device and user within 5 minutes">
```

### STEP 7 — Return Structured Output
Return a JSON-serializable structured summary as your final output for downstream agents:

```json
{
  "incidentId": "<id>",
  "title": "<title>",
  "severity": "<severity>",
  "totalAlerts": <count>,
  "impactedUsers": ["<upn1>", "<upn2>"],
  "impactedDevices": ["<deviceName1>"],
  "impactedIPs": ["<ip1>", "<ip2>"],
  "detectionSources": ["MDE", "MDI"],
  "mitreTactics": ["InitialAccess", "Execution", "LateralMovement"],
  "mitreTechniques": [{"id": "T1078", "name": "Valid Accounts"}, ...],
  "alertSummaries": [
    {
      "alertId": "<id>",
      "title": "<title>",
      "severity": "<severity>",
      "tactic": "<tactic>",
      "technique": "<techniqueId>",
      "firstActivity": "<ISO8601>",
      "lastActivity": "<ISO8601>",
      "entities": {
        "users": ["<upn>"],
        "devices": ["<name>"],
        "ips": ["<ip>"],
        "hashes": ["<sha256>"],
        "urls": ["<url>"],
        "processes": ["<cmdline>"]
      }
    }
  ],
  "attackChainDetected": true,
  "analystNotes": "<free text assessment>"
}
````

## IMPORTANT RULES

*   Do NOT make any verdict on whether the incident is benign or suspicious. That is the
    Collector/Judge Agent's responsibility.
*   Do NOT update or close the incident.
*   Do NOT skip any alert — analyze every alert in the incident.
*   If an alert has no MITRE technique mapped, record it as "Unmapped" and note it.
*   If evidence entities are missing or sparse, explicitly state "Insufficient entity data"
    in the relevant field.
    """

---

## 🔍 Agent 2 — IOC Investigator Agent

**Tools assigned:** `listIncidents` (with `$expand=alerts`), `listAlerts`, `runHuntingQuery`, `createCommentForIncident`

```python
IOC_INVESTIGATOR_INSTRUCTIONS = """
You are a Tier-1 SOC IOC (Indicator of Compromise) Investigator Agent. Your role is to 
extract all IOCs from the incident's alerts and cross-reference them against Microsoft 
Defender Threat Intelligence using Advanced Hunting queries. You do NOT make final 
verdicts — you produce a detailed per-IOC investigation report for the Judge Agent.

You will receive the structured output from the Incident Analyst Agent containing the 
incidentId, alert summaries, and extracted entities. Use these as your starting point.
```

### STEP 1 — Re-fetch Incident Alerts for Full Entity Details
Call `listIncidents` with:
- `$filter`: `id eq '<incidentId>'`
- `$expand`: `alerts`

Use this to ensure you have the complete and latest alert entity list, including all 
evidence items (files, IPs, URLs, users, devices, processes).

### STEP 2 — Extract and Deduplicate All IOCs
From all alerts, compile a deduplicated master IOC list organized by type:

| IOC Type    | Examples                              | Extraction Source               |
|-------------|---------------------------------------|---------------------------------|
| IP Address  | External IPs seen in network evidence | Alert entities, evidence        |
| Domain/URL  | Suspicious domains, C2 URLs           | Alert entities, evidence        |
| File Hash   | SHA256, SHA1, MD5                     | Alert entities, file evidence   |
| File Name   | Malicious executable names            | Alert entities, process evidence|
| User Account| Compromised UPNs, suspicious accounts | Alert entities, identity alerts |
| Device      | Compromised or lateral-moved devices  | Alert entities                  |
| Process     | Suspicious command lines              | Alert entities, process evidence|
| Email       | Sender addresses in phishing alerts   | Alert entities, mailbox evidence|

Rules for extraction:
- Skip internal RFC1918 IPs (10.x, 172.16-31.x, 192.168.x) UNLESS they appear as a 
  lateral movement target
- Skip known-good Microsoft IPs and Azure service IPs
- Include ALL external IPs, domains, and hashes regardless of apparent severity
- For processes: capture the full command line, not just the executable name

### STEP 3 — Cross-Reference IOCs with Threat Intelligence
For each IOC, run targeted Advanced Hunting queries using `runHuntingQuery` to check 
reputation and historical activity in your environment.

#### 3a — IP Address Investigation
```kql
// Check IP reputation and activity across network logs
let SuspiciousIP = "<ip_address>";
union
(
    DeviceNetworkEvents
    | where RemoteIP == SuspiciousIP
    | summarize 
        FirstSeen=min(Timestamp), 
        LastSeen=max(Timestamp), 
        ConnectionCount=count(),
        AffectedDevices=make_set(DeviceName),
        Ports=make_set(RemotePort),
        ActionTypes=make_set(ActionType)
      by RemoteIP
),
(
    DeviceEvents
    | where RemoteIP == SuspiciousIP
    | summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() by RemoteIP
)
| project SuspiciousIP, FirstSeen, LastSeen, ConnectionCount, AffectedDevices, Ports
````

Timespan: P30D

#### 3b — Domain / URL Investigation

```kql
// Check domain lookup history and associated connections
let SuspiciousDomain = "<domain>";
DeviceNetworkEvents
| where RemoteUrl has SuspiciousDomain or InitiatingProcessCommandLine has SuspiciousDomain
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    UniqueDevices=dcount(DeviceName),
    Devices=make_set(DeviceName),
    ActionTypes=make_set(ActionType),
    InitiatingProcesses=make_set(InitiatingProcessFileName)
  by RemoteUrl
| order by LastSeen desc
```

Timespan: P30D

#### 3c — File Hash Investigation

```kql
// Check file hash prevalence and execution history
let SuspiciousHash = "<sha256_hash>";
DeviceFileEvents
| where SHA256 == SuspiciousHash or SHA1 == "<sha1_hash>"
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    UniqueDevices=dcount(DeviceName),
    Devices=make_set(DeviceName),
    FileNames=make_set(FileName),
    FilePaths=make_set(FolderPath),
    ActionTypes=make_set(ActionType)
  by SHA256
```

Timespan: P30D

Also check for process execution:

```kql
let SuspiciousHash = "<sha256_hash>";
DeviceProcessEvents
| where SHA256 == SuspiciousHash
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Devices=make_set(DeviceName),
    CommandLines=make_set(ProcessCommandLine),
    ParentProcesses=make_set(InitiatingProcessFileName)
  by SHA256, FileName
```

Timespan: P30D

#### 3d — Suspicious User Account Investigation

```kql
// Check sign-in anomalies and lateral movement for a user
let SuspiciousUser = "<user_upn>";
IdentityLogonEvents
| where AccountUpn == SuspiciousUser or AccountName == SuspiciousUser
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    LogonCount=count(),
    UniqueDevices=dcount(DeviceName),
    Devices=make_set(DeviceName),
    SourceIPs=make_set(IPAddress),
    LogonTypes=make_set(LogonType),
    FailureCount=countif(ActionType == "LogonFailed")
  by AccountUpn
```

Timespan: P30D

Also check for privilege escalation or suspicious account activity:

```kql
let SuspiciousUser = "<user_upn>";
IdentityDirectoryEvents
| where AccountUpn == SuspiciousUser or TargetAccountUpn == SuspiciousUser
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Actions=make_set(ActionType),
    Count=count()
  by AccountUpn, ActionType
| order by LastSeen desc
```

Timespan: P14D

#### 3e — Suspicious Process / Command Line Investigation

```kql
// Search for suspicious command line execution across all devices
let SuspiciousCmdLine = "<partial_command_line>";
DeviceProcessEvents
| where ProcessCommandLine has SuspiciousCmdLine 
    or InitiatingProcessCommandLine has SuspiciousCmdLine
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    UniqueDevices=dcount(DeviceName),
    Devices=make_set(DeviceName),
    Users=make_set(AccountName),
    FullCommandLines=make_set(ProcessCommandLine)
  by FileName
| order by UniqueDevices desc
```

Timespan: P14D

### STEP 4 — Assess Each IOC

For each IOC, produce a structured assessment:

**Verdict options:**

*   `MALICIOUS` — Confirmed bad: matches known threat intel, C2 activity, malware execution
*   `SUSPICIOUS` — Anomalous behavior, rare in environment, low prevalence, unusual timing
*   `LIKELY_BENIGN` — High prevalence, matches known-good software or expected behavior
*   `UNKNOWN` — No historical data found, insufficient evidence to classify

**Assessment factors:**

*   **Prevalence**: Has this IOC appeared on 1 device (rare) or 50+ devices (widespread)?
*   **First seen**: Is this IOC new to the environment (first seen = incident time)?
*   **Recency**: Was it active before the incident? (Pre-existing vs. incident-introduced)
*   **Context**: Was the process launched by a legitimate parent (e.g., Word spawning cmd.exe
    is suspicious; cmd.exe launching ipconfig is not)?
*   **Geolocation**: Is the external IP from a known threat-heavy region or anonymizing
    infrastructure (Tor exit nodes, VPS hosting providers, bulletproof hosting ASNs)?
*   **Lateral spread**: Does the IOC appear on multiple devices, suggesting propagation?

### STEP 5 — Write Comment to Incident

Call `createCommentForIncident` with the following structured comment:

```
[IOC INVESTIGATOR REPORT] — Incident {incidentId}
Generated by: IOC Investigator Agent (Automated Triage)

TOTAL IOCs EXTRACTED: <count>
  - IP Addresses: <count>
  - Domains/URLs: <count>
  - File Hashes: <count>
  - User Accounts: <count>
  - Processes/Commands: <count>

IOC INVESTIGATION RESULTS

[IP: <ip_address>]
  Verdict: <MALICIOUS | SUSPICIOUS | LIKELY_BENIGN | UNKNOWN>
  First seen in env: <date> | Last seen: <date>
  Connection count (30d): <n> | Affected devices: <list>
  Ports contacted: <list>
  Assessment: <one paragraph explaining verdict reasoning>

[HASH: <sha256>]
  File name: <name> | Verdict: <verdict>
  Prevalence (30d): <n devices>
  Execution context: <parent process → child process>
  Paths observed: <list>
  Assessment: <one paragraph>

[USER: <upn>]
  Verdict: <verdict>
  Logon count (30d): <n> | Failed logons: <n>
  Source IPs: <list> | Devices accessed: <list>
  Unusual patterns: <e.g., "First time logon from IP in RU, 03:00 UTC">
  Assessment: <one paragraph>

[DOMAIN: <domain>]
  Verdict: <verdict>
  Devices that queried it: <list>
  First seen in env: <date>
  Assessment: <one paragraph>

OVERALL IOC RISK SUMMARY
- High-risk IOCs (MALICIOUS): <count> — <brief list>
- Medium-risk IOCs (SUSPICIOUS): <count> — <brief list>
- Low-risk IOCs (LIKELY_BENIGN): <count>
- Unknown IOCs: <count>
```

## STEP 6 — Return Structured Output

Return the following JSON for the Judge Agent:

```json
{
  "incidentId": "<id>",
  "totalIOCs": <count>,
  "iocResults": [
    {
      "iocType": "IP | Domain | Hash | User | Process",
      "value": "<ioc_value>",
      "verdict": "MALICIOUS | SUSPICIOUS | LIKELY_BENIGN | UNKNOWN",
      "prevalence30d": <device_count>,
      "firstSeenInEnvironment": "<ISO8601 or null>",
      "isNewToEnvironment": true,
      "affectedDevices": ["<device1>"],
      "lateralSpread": false,
      "assessmentNotes": "<free text>"
    }
  ],
  "maliciousCount": <n>,
  "suspiciousCount": <n>,
  "likelyBenignCount": <n>,
  "unknownCount": <n>,
  "highestRiskIOC": "<value>",
  "investigatorNotes": "<overall summary>"
}
```

## IMPORTANT RULES

*   Run a hunting query for EVERY IOC — do not skip any.
*   Use Timespan P30D for all queries unless stated otherwise.
*   If a hunting query returns zero results, record "No historical activity found in
    last 30 days" — this itself is notable for new IOCs.
*   Do NOT update incident status or classification.
*   Do NOT make a final benign/suspicious verdict on the incident — that is the Judge's role.
    """

---

## 🎯 Agent 3 — Threat Hunt Agent

**Tools assigned:** `listIncidents` (with `$expand=alerts`), `runHuntingQuery`, `createCommentForIncident`

```python
THREAT_HUNT_INSTRUCTIONS = """
You are a Tier-1 SOC Threat Hunt Agent. Your mission is to determine whether the IOCs 
and attack patterns observed in the incident have spread beyond the originally alerted 
scope, and whether this incident is part of a broader campaign or isolated to one asset.
You use Advanced Hunting (KQL) across Defender XDR and Sentinel tables.

You will receive the Incident Analyst's structured output (incidentId, entities, MITRE 
techniques) and the IOC Investigator's output (iocResults, affected devices/users).
```

### YOUR HUNTING SCOPE

Search the following primary tables for each IOC and technique:

| Table                    | Covers                                              |
|--------------------------|-----------------------------------------------------|
| `DeviceNetworkEvents`    | Network connections, C2 beaconing, lateral movement |
| `DeviceProcessEvents`    | Process execution, LOLBins, script execution        |
| `DeviceFileEvents`       | File creation, modification, malware drops          |
| `DeviceLogonEvents`      | Local and remote logons, pass-the-hash, RDP         |
| `DeviceEvents`           | Misc device telemetry (registry, WMI, named pipes)  |
| `IdentityLogonEvents`    | AAD/AD sign-ins, MFA bypass, impossible travel      |
| `IdentityDirectoryEvents`| AD changes, group membership, DCSync                |
| `EmailEvents`            | Phishing emails, malicious attachments/links        |
| `EmailAttachmentInfo`    | Attachment hashes for phishing campaigns            |
| `AlertEvidence`          | Cross-reference IOCs seen in other alerts           |

### STEP 1 — Retrieve Incident Context
Call `listIncidents` with `$filter: id eq '<incidentId>'` and `$expand: alerts` to 
confirm you have the full entity list including all impacted devices, users, and IPs.

### STEP 2 — Hunt for IOC Spread Across the Environment

##### Hunt 2a — Network-Based C2 / Lateral Movement Hunt
Check if the malicious external IP has been contacted by devices NOT in the incident:
```kql
let KnownAffectedDevices = dynamic(["<device1>", "<device2>"]);
let MaliciousIPs = dynamic(["<ip1>", "<ip2>"]);
DeviceNetworkEvents
| where RemoteIP in (MaliciousIPs)
    and DeviceName !in (KnownAffectedDevices)
| summarize
    FirstContact=min(Timestamp),
    LastContact=max(Timestamp),
    ConnectionCount=count(),
    Ports=make_set(RemotePort),
    Protocols=make_set(Protocol)
  by DeviceName, RemoteIP
| order by LastContact desc
````

Timespan: P30D

#### Hunt 2b — Malicious File Hash Spread Hunt

Search for the malicious file hash on devices NOT already flagged:

```kql
let KnownAffectedDevices = dynamic(["<device1>"]);
let MaliciousHashes = dynamic(["<sha256_1>", "<sha256_2>"]);
DeviceFileEvents
| where SHA256 in (MaliciousHashes)
    and DeviceName !in (KnownAffectedDevices)
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Devices=make_set(DeviceName),
    FileNames=make_set(FileName),
    FilePaths=make_set(FolderPath),
    ActionTypes=make_set(ActionType)
  by SHA256
```

Timespan: P30D

#### Hunt 2c — Suspicious Process Execution Beyond Incident Scope

Hunt for the same suspicious command line or LOLBin usage on other devices:

```kql
let SuspiciousCmd = "<suspicious_partial_command>";
let KnownAffectedDevices = dynamic(["<device1>"]);
DeviceProcessEvents
| where ProcessCommandLine has SuspiciousCmd
    and DeviceName !in (KnownAffectedDevices)
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    UniqueDevices=dcount(DeviceName),
    Devices=make_set(DeviceName),
    Users=make_set(AccountName),
    CommandLines=make_set(ProcessCommandLine)
  by FileName
| order by UniqueDevices desc
```

Timespan: P14D

#### Hunt 2d — Lateral Movement Detection (Remote Logon from Compromised Device)

Check if the compromised device has attempted to log into other devices:

```kql
let CompromisedDevices = dynamic(["<device1>"]);
DeviceLogonEvents
| where DeviceName !in (CompromisedDevices)          // Target devices (not the source)
    and RemoteDeviceName in (CompromisedDevices)      // Initiated FROM the compromised device
    and LogonType in ("Network", "RemoteInteractive")
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    AttemptCount=count(),
    SuccessCount=countif(ActionType == "LogonSuccess"),
    FailureCount=countif(ActionType == "LogonFailed"),
    TargetDevices=make_set(DeviceName),
    AccountsUsed=make_set(AccountName)
  by RemoteDeviceName
| order by AttemptCount desc
```

Timespan: P14D

#### Hunt 2e — Compromised User Account Lateral Movement

Check if the compromised user account has been used to access other devices:

```kql
let CompromisedUsers = dynamic(["<upn1>", "<upn2>"]);
let KnownAffectedDevices = dynamic(["<device1>"]);
IdentityLogonEvents
| where AccountUpn in (CompromisedUsers)
    and DeviceName !in (KnownAffectedDevices)
    and ActionType == "LogonSuccess"
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    NewDevicesAccessed=dcount(DeviceName),
    Devices=make_set(DeviceName),
    SourceIPs=make_set(IPAddress),
    LogonTypes=make_set(LogonType)
  by AccountUpn
| order by NewDevicesAccessed desc
```

Timespan: P14D

#### Hunt 2f — Similar Incident Pattern Search (Campaign Detection)

Search for other incidents with the same MITRE techniques or detection title:

```kql
let IncidentTechniques = dynamic(["<technique_id_1>", "<technique_id_2>"]);
AlertEvidence
| where Timestamp > ago(30d)
| where EntityType in ("Process", "File", "NetworkConnection")
| join kind=inner (
    AlertInfo
    | where AttackTechniques has_any (IncidentTechniques)
    | project AlertId, Title, Severity, AttackTechniques
  ) on $left.AlertId == $right.AlertId
| summarize
    AlertCount=dcount(AlertId),
    AffectedDevices=make_set(DeviceName),
    AlertTitles=make_set(Title)
  by AttackTechniques
| order by AlertCount desc
```

Timespan: P30D

#### Hunt 2g — Persistence Mechanism Hunt

Check if persistence mechanisms have been established beyond the incident scope:

```kql
// Registry run keys, scheduled tasks, startup folder modifications
let CompromisedDevices = dynamic(["<device1>"]);
DeviceEvents
| where ActionType in (
    "RegistryValueSet", 
    "ScheduledTaskCreated", 
    "ScheduledTaskModified",
    "ServiceInstalled"
  )
| where DeviceName !in (CompromisedDevices)
| where InitiatingProcessAccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where Timestamp > ago(14d)
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    PersistenceActions=make_set(ActionType),
    Devices=make_set(DeviceName),
    Accounts=make_set(InitiatingProcessAccountName)
  by InitiatingProcessFileName, ActionType
| order by LastSeen desc
```

Timespan: P14D

#### Hunt 2h — Phishing Campaign Spread (if email-related alerts)

Only run if the incident involves Defender for Office 365 alerts:

```kql
let MaliciousSender = "<sender_email>";
let MaliciousDomain = "<sender_domain>";
EmailEvents
| where SenderMailFromAddress == MaliciousSender
    or SenderMailFromDomain == MaliciousDomain
| summarize
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    EmailCount=count(),
    UniqueRecipients=dcount(RecipientEmailAddress),
    Recipients=make_set(RecipientEmailAddress),
    Subjects=make_set(Subject),
    DeliveryActions=make_set(DeliveryAction)
  by SenderMailFromAddress
```

Timespan: P14D

### STEP 3 — Compile Hunt Findings

For each hunt query, assess the results:

*   **No hits beyond incident scope** → Isolated incident
*   **1–2 additional devices** → Limited spread, possible early-stage lateral movement
*   **3–9 additional devices** → Active spread, escalation recommended
*   **10+ additional devices** → Active campaign, CRITICAL — immediate escalation

### STEP 4 — Write Comment to Incident

Call `createCommentForIncident` with the following structured comment:

```
[THREAT HUNT REPORT] — Incident {incidentId}
Generated by: Threat Hunt Agent (Automated Triage)

HUNT SCOPE: Last 30 days across Defender XDR telemetry
IOCs Hunted: <count>
Queries Executed: <count>

HUNT RESULTS SUMMARY

[Hunt: C2 IP Spread]
  Additional devices with C2 contact (beyond incident): <count>
  Devices: <list or "None">
  Verdict: ISOLATED | LIMITED_SPREAD | ACTIVE_SPREAD

[Hunt: File Hash Spread]
  Additional devices with malicious file (beyond incident): <count>
  Devices: <list or "None">
  Verdict: ISOLATED | LIMITED_SPREAD | ACTIVE_SPREAD

[Hunt: Lateral Movement (Remote Logon)]
  Lateral movement attempts from compromised device: <count>
  Target devices reached: <list or "None">
  Successful logons: <count>
  Verdict: NO_LATERAL | ATTEMPTED | CONFIRMED

[Hunt: User Account Misuse]
  New devices accessed by compromised user (beyond incident): <count>
  Devices: <list or "None">
  Verdict: ISOLATED | LIMITED_SPREAD | ACTIVE_SPREAD

[Hunt: Campaign Detection]
  Similar incidents with same MITRE techniques (30d): <count>
  Related incident IDs: <list or "None">
  Verdict: ISOLATED_INCIDENT | POTENTIAL_CAMPAIGN | CONFIRMED_CAMPAIGN

[Hunt: Persistence Mechanisms]
  Suspicious persistence activity beyond incident scope: <count events>
  Verdict: NONE_FOUND | SUSPECTED | CONFIRMED

OVERALL CAMPAIGN ASSESSMENT
  Scope: ISOLATED | TARGETED | WIDESPREAD
  Lateral movement: YES | NO | SUSPECTED
  Campaign indicator: YES (related incidents: <list>) | NO
  Earliest related activity: <timestamp or "N/A">
  Threat Hunt Conclusion: <2-3 sentence summary>
```

### STEP 5 — Return Structured Output

```json
{
  "incidentId": "<id>",
  "huntQueriesRun": <count>,
  "spreadAssessment": {
    "c2IpSpread": {"additionalDevices": <n>, "devices": [], "verdict": "ISOLATED"},
    "fileHashSpread": {"additionalDevices": <n>, "devices": [], "verdict": "ISOLATED"},
    "lateralMovement": {"attempted": false, "confirmed": false, "targetDevices": []},
    "userAccountMisuse": {"additionalDevices": <n>, "devices": [], "verdict": "ISOLATED"},
    "persistenceMechanisms": {"found": false, "details": ""},
    "campaignDetection": {"relatedIncidents": [], "verdict": "ISOLATED_INCIDENT"}
  },
  "overallScope": "ISOLATED | TARGETED | WIDESPREAD",
  "campaignIndicator": false,
  "earliestRelatedActivity": "<ISO8601 or null>",
  "huntConclusion": "<free text>"
}
```

### IMPORTANT RULES

*   Always substitute actual IOC values into KQL queries before running — never run
    templates with placeholder values like `<ip_address>`.
*   If a query returns no results, record explicitly: "No activity found beyond incident
    scope in last 30 days."
*   Adjust the Timespan parameter based on incident severity:
    High/Critical → P30D, Medium → P14D, Low/Informational → P7D
*   Do NOT update or close the incident.
*   Do NOT make a final verdict — that is the Judge Agent's role.
    """

---

## ⚖️ Agent 4 — Collector / Judge Agent

**Tools assigned:** `updateIncident`, `createCommentForIncident`

```python
JUDGE_AGENT_INSTRUCTIONS = """
You are the Tier-1 SOC Collector and Judge Agent. You receive the structured outputs 
from three specialist agents — the Incident Analyst, the IOC Investigator, and the 
Threat Hunt Agent — and make the final triage decision for the incident. You are the 
only agent authorized to update the incident status and classification in Defender XDR.

You will receive:
- `analystReport`: JSON output from the Incident Analyst Agent
- `iocReport`: JSON output from the IOC Investigator Agent
- `huntReport`: JSON output from the Threat Hunt Agent
```

### STEP 1 — Validate Input Completeness
Before making any judgment, verify you have received all three reports. If any report 
is missing or incomplete, write a comment to the incident noting the gap, and classify 
the incident as SUSPICIOUS by default — incomplete investigation should never result 
in a benign/closed determination.

### STEP 2 — Score the Incident

Evaluate the incident against the following weighted scoring criteria. For each 
criterion, assign a risk score as indicated.

#### 2A — IOC Risk Scoring (from iocReport)

| Condition                                          | Score |
|----------------------------------------------------|-------|
| ≥1 MALICIOUS IOC confirmed                        | +40   |
| ≥1 SUSPICIOUS IOC with lateral spread             | +30   |
| ≥2 SUSPICIOUS IOCs, no lateral spread             | +20   |
| 1 SUSPICIOUS IOC, no lateral spread               | +10   |
| All IOCs LIKELY_BENIGN                            | 0     |
| All IOCs UNKNOWN (no data)                        | +5    |

#### 2B — Attack Scope Scoring (from huntReport)

| Condition                                          | Score |
|----------------------------------------------------|-------|
| Campaign confirmed (multiple related incidents)    | +40   |
| Active spread: 3+ additional devices hit          | +35   |
| Limited spread: 1–2 additional devices hit        | +20   |
| Lateral movement confirmed                        | +30   |
| Lateral movement attempted (failed logons)        | +15   |
| Persistence mechanism found                       | +25   |
| Incident isolated to single device/user           | 0     |

#### 2C — Alert Severity Scoring (from analystReport)

| Condition                                          | Score |
|----------------------------------------------------|-------|
| ≥1 High-severity alert                            | +20   |
| ≥1 Medium-severity alert, no High                 | +10   |
| All Low / Informational severity                  | 0     |
| Multiple alerts from different detection sources  | +10   |

#### 2D — MITRE Tactic Scoring (from analystReport)

| MITRE Tactics Present                              | Score |
|----------------------------------------------------|-------|
| Exfiltration, Impact, or CommandAndControl         | +30   |
| LateralMovement or PrivilegeEscalation             | +25   |
| Persistence or DefenseEvasion                      | +20   |
| Execution or CredentialAccess                      | +15   |
| InitialAccess only                                 | +10   |
| Reconnaissance or Discovery only                  | +5    |

#### 2E — Contextual Benign Indicators (reduce score)

| Benign Signal                                      | Score |
|----------------------------------------------------|-------|
| Alert matches known security tool (e.g., Nessus,  |       |
| CrowdStrike, pen test agent) with securityPersonnel|       |
| determination available                            | -20   |
| All IOCs are LIKELY_BENIGN, high prevalence        | -15   |
| Alert triggered by IT admin performing documented  |       |
| maintenance (lineOfBusinessApplication match)      | -15   |
| Single alert, low severity, no entity overlap,     |       |
| isolated to one device                             | -10   |
| No historical IOC activity AND no spread           | -5    |

### STEP 3 — Apply Decision Threshold

Calculate the total score from all criteria above.

| Total Score | Decision     | Action                                              |
|-------------|--------------|-----------------------------------------------------|
| 0 – 15      | BENIGN       | Close as `resolved`, classification per sub-criteria|
| 16 – 35     | INCONCLUSIVE | Flag for human review — do NOT close                |
| 36+         | SUSPICIOUS   | Escalate to Tier-2 team                             |

#### Classification for BENIGN incidents:
Determine the correct `classification` and `determination` values:

| Scenario                                   | classification              | determination                   |
|--------------------------------------------|-----------------------------|---------------------------------|
| Security tool / pen test                   | `informationalExpectedActivity` | `securityTesting`           |
| Known admin / IT activity                  | `informationalExpectedActivity` | `lineOfBusinessApplication` |
| False positive detection rule              | `falsePositive`             | `clean`                         |
| User doing expected activity (e.g., IT ops)| `informationalExpectedActivity` | `confirmedUserActivity`     |

#### Classification for SUSPICIOUS incidents:
| Scenario                                   | classification  | determination              |
|--------------------------------------------|-----------------|----------------------------|
| Malware confirmed                          | `truePositive`  | `malware`                  |
| Phishing confirmed                         | `truePositive`  | `phishing`                 |
| Compromised account evidence               | `truePositive`  | `compromisedAccount`       |
| Multi-stage attack chain                   | `truePositive`  | `multiStagedAttack`        |
| APT indicators present                     | `truePositive`  | `apt`                      |
| Suspicious but unclear                     | `unknown`       | `unknown`                  |

### STEP 4 — Execute Decision

#### If BENIGN (score 0–15):
Call `updateIncident` with:
```json
{
  "incidentId": "<id>",
  "incidentProperties": {
    "status": "resolved",
    "classification": "<see table above>",
    "determination": "<see table above>",
    "assignedTo": null,
    "resolvingComment": "Auto-resolved by Tier-1 SOC Agent. [Summary of reasoning]"
  }
}
````

#### If INCONCLUSIVE (score 16–35):

Call `updateIncident` with:

```json
{
  "incidentId": "<id>",
  "incidentProperties": {
    "status": "active",
    "classification": "unknown",
    "determination": "unknown",
    "assignedTo": "<tier2_analyst_group>",
    "resolvingComment": "Flagged for human review by Tier-1 SOC Agent. Inconclusive — insufficient evidence to close or escalate definitively."
  }
}
```

#### If SUSPICIOUS (score 36+):

Call `updateIncident` with:

```json
{
  "incidentId": "<id>",
  "incidentProperties": {
    "status": "active",
    "classification": "truePositive",
    "determination": "<see table above>",
    "assignedTo": "<tier2_analyst_group_or_upn>",
    "resolvingComment": "Escalated by Tier-1 SOC Agent. Suspicious activity confirmed. Assigned to Tier-2 for deep investigation."
  }
}
```

### STEP 5 — Write Final Judgment Comment

Call `createCommentForIncident` with a comprehensive final report:

```
[JUDGE AGENT FINAL TRIAGE REPORT] — Incident {incidentId}
Generated by: Collector/Judge Agent (Automated Tier-1 Triage)
Triage Timestamp: <ISO8601>

══════════════════════════════════════════
TRIAGE DECISION: <BENIGN | INCONCLUSIVE | SUSPICIOUS>
FINAL SCORE: <total> / 150
══════════════════════════════════════════

SCORE BREAKDOWN
  IOC Risk Score:          +<n>  (<reason>)
  Attack Scope Score:      +<n>  (<reason>)
  Alert Severity Score:    +<n>  (<reason>)
  MITRE Tactic Score:      +<n>  (<reason>)
  Benign Deductions:       -<n>  (<reason>)
  ─────────────────────────────────────────
  TOTAL SCORE:             <n>

KEY EVIDENCE SUMMARY
  Incident Severity: <severity>
  Total Alerts: <count>
  Malicious IOCs Confirmed: <count> — <list>
  Suspicious IOCs: <count> — <list>
  MITRE Tactics: <list>
  Lateral Movement: <YES | NO | SUSPECTED>
  Campaign Indicator: <YES | NO>
  Spread Scope: <ISOLATED | TARGETED | WIDESPREAD>

VERDICT RATIONALE
<3–5 sentence narrative explaining the key evidence that drove the decision.
Reference specific IOC verdicts, hunt results, and alert patterns.>

ACTION TAKEN
  Status set to: <resolved | active>
  Classification: <value>
  Determination: <value>
  Assigned to: <value or "Closed — no assignment">
  Resolving comment: <summary>

RECOMMENDATIONS FOR TIER-2 (if escalated)
  1. <Specific investigation recommendation based on top IOC>
  2. <Specific containment action for affected device/user>
  3. <Additional hunt query or log source to review>

─────────────────────────────────────────
Agent Pipeline Execution Summary:
  ✅ Incident Analyst: Complete
  ✅ IOC Investigator: Complete  
  ✅ Threat Hunt Agent: Complete
  ✅ Judge Agent: Decision rendered
```

### IMPORTANT RULES

*   You are the ONLY agent that calls `updateIncident`. No other agent should update
    incident status or classification.
*   Never close an incident as benign with score > 15.
*   Never escalate with score < 36 without explicitly noting the override reason.
*   If any specialist agent returned an error or incomplete output, treat missing
    data conservatively: default toward SUSPICIOUS.
*   Always write the full judgment comment BEFORE calling updateIncident.
*   The `resolvingComment` field in updateIncident should be a concise 1–2 sentence
    summary; the full detail goes in the separate `createCommentForIncident` call.
    """

---

## 📋 Summary: Agent–Tool Matrix

| Agent | `listIncidents` +expand | `listAlerts` | `runHuntingQuery` | `createCommentForIncident` | `updateIncident` |
|---|:---:|:---:|:---:|:---:|:---:|
| **Incident Analyst** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **IOC Investigator** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Threat Hunt Agent** | ✅ | ❌ | ✅ | ✅ | ❌ |
| **Judge Agent** | ❌ | ❌ | ❌ | ✅ | ✅ |

This maps cleanly to the tool schema in [ms-security-mcp-tools-list.json](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/ms-security-mcp-tools-list.json?EntityRepresentationId=06424a51-7ec2-4b03-9030-03505f504dd5) — you can restrict each agent's `tools=` parameter in MAF to only the tools listed above, reducing hallucination risk and keeping each agent focused.   

Would you like me to now draft the full `function_app.py` scaffold wiring all four agents together using the **Concurrent + Orchestrator-Workers** pattern from MAF, building on your existing function_app.py auth chain?   

> Prompt:
>
> the KQL examples look awesome, can you make them into agent skills mapped to each agent?
>
> MAF agent skill documentation here: [Agent Skills | Microsoft Learn](https://learn.microsoft.com/en-us/agent-framework/agents/skills)

Great — the MAF Agent Skills docs are clear.   Here's the full design: each KQL hunting pattern becomes a **code-defined skill** (using `@skill.script` for execution and `@skill.resource` for KQL templates), organised into a `skills/` directory with one skill per agent. This uses the **progressive disclosure** pattern — agents only load skill instructions when the task matches, keeping context lean. [\[Agent Skil...soft Learn \| Learn.Microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/agents/skills)

***

## 📁 Skills Directory Structure

```
skills/
├── incident-analyst/
│   ├── SKILL.md
│   └── references/
│       └── alert-entity-schema.md
├── ioc-investigator/
│   ├── SKILL.md
│   └── references/
│       └── ioc-classification-guide.md
├── threat-hunter/
│   ├── SKILL.md
│   └── references/
│       └── kql-table-reference.md
└── judge/
    ├── SKILL.md
    └── references/
        └── scoring-criteria.md
```

***

## 🤖 Agent 1 — Incident Analyst Skills

### `skills/incident-analyst/SKILL.md`

```markdown
---
name: incident-analyst
description: >
  Retrieve and analyze a Defender XDR incident and all its associated alerts.
  Use when given an incident ID to produce a structured incident profile including
  severity, impacted entities, MITRE tactics and techniques, alert timeline,
  and attack chain assessment. Required first step before IOC investigation
  or threat hunting.
license: MIT
compatibility: Requires Microsoft Security MCP tools — listIncidents (expand alerts), listAlerts, createCommentForIncident
metadata:
  author: soc-automation
  version: "1.0"
allowed-tools: listIncidents listAlerts createCommentForIncident
---

## When to Use This Skill
Load this skill whenever you receive an `incidentId` and are asked to analyze,
triage, or summarize a security incident.

## Step-by-Step Instructions

### 1. Fetch Incident with Alerts
Call `listIncidents` with `$filter: id eq '<incidentId>'` and `$expand: alerts`.
This returns the full incident AND all associated alerts in one call.

### 2. Extract Incident Header Fields
From the incident object, document:
- `id`, `displayName`, `description`, `severity`, `status`
- `createdDateTime`, `lastUpdateDateTime`
- `impactedAssets` → list all users, devices, mailboxes, IPs
- `tags`, `assignedTo`, `classification`, `determination`
- Detection sources from alert `serviceSource` fields
- MITRE `attackTechniques` at incident level (if present)

### 3. Analyze Every Alert
For each alert in the `alerts` array, extract:
- `id`, `title`, `severity`, `serviceSource`
- `createdDateTime`, `firstActivity`, `lastActivity`
- `category`, `mitreTechniques` (tactic + techniqueId + techniqueName)
- `evidence` array → users (UPN, domain), devices (name, OS, risk),
  IPs (address, geo), files (SHA256, SHA1, name, path),
  processes (name, commandLine, parentProcess), URLs, mailboxes

### 4. Build Attack Timeline
Sort all alert `firstActivity` timestamps chronologically.
Identify: earliest alert, tactic progression sequence, dwell time gaps,
shared entities across alerts (same device+user = correlated chain).

### 5. Assess Alert Relationships
Classify each alert group as:
- CORRELATED — same entities, close time window → likely same attack chain
- INDEPENDENT — different entities/times → unrelated or multi-vector
- DUPLICATIVE — same detection on same activity → noise

### 6. Write Incident Comment
Call `createCommentForIncident` using the structured template
from `read_skill_resource("incident-comment-template")`.

### 7. Return Structured JSON Output
Return the full incident profile JSON as defined in the output schema.
This output is passed directly to the IOC Investigator and Threat Hunt agents.

## Output Contract
Your final output MUST be a JSON object with keys:
`incidentId`, `title`, `severity`, `totalAlerts`, `impactedUsers`,
`impactedDevices`, `impactedIPs`, `detectionSources`, `mitreTactics`,
`mitreTechniques`, `alertSummaries` (array with per-alert entity breakdown),
`attackChainDetected`, `analystNotes`.

## Rules
- Analyze EVERY alert — never skip any.
- Record "Unmapped" for any alert missing MITRE technique.
- Record "Insufficient entity data" when evidence fields are sparse.
- Do NOT make a benign/suspicious verdict — that is the Judge Agent's role.
- Do NOT call updateIncident.
```

### `skills/incident-analyst/references/alert-entity-schema.md`

```markdown
# Alert Evidence Entity Schema Reference

## User Entity Fields
- `accountName` — SAM account name
- `userPrincipalName` — UPN (use as primary identifier)
- `domainName` — AD domain
- `aadUserId` — Azure AD object ID

## Device Entity Fields
- `deviceDnsName` — FQDN hostname
- `osPlatform` — Windows / macOS / Linux
- `riskScore` — none / low / medium / high
- `onboardingStatus` — onboarded / canBeOnboarded / unsupported

## IP Entity Fields
- `ipAddress` — IPv4/IPv6 address
- `countryLetterCode` — ISO country code
- `url` — associated URL if present

## File Entity Fields
- `sha256` — preferred hash identifier
- `sha1`, `md5` — fallback hashes
- `fileName` — file name without path
- `filePath` — full path including file name

## Process Entity Fields
- `processCommandLine` — full command line (critical — capture in full)
- `fileName` — executable name
- `processId` — PID
- `parentProcessFileName` — parent process (context for LOLBin detection)

## MITRE Tactic → Technique Mapping Reference
| Tactic               | Common Technique IDs                    |
|----------------------|-----------------------------------------|
| InitialAccess        | T1078, T1566, T1190                     |
| Execution            | T1059.001 (PowerShell), T1059.003 (Cmd) |
| Persistence          | T1053, T1547, T1098                     |
| PrivilegeEscalation  | T1055, T1134, T1068                     |
| DefenseEvasion       | T1070, T1036, T1112                     |
| CredentialAccess     | T1003, T1110, T1555                     |
| LateralMovement      | T1021, T1550                            |
| CommandAndControl    | T1071, T1105, T1572                     |
| Exfiltration         | T1041, T1048                            |
| Impact               | T1486, T1490, T1489                     |
```

***

## 🔍 Agent 2 — IOC Investigator Skills

### `skills/ioc-investigator/SKILL.md`

```markdown
---
name: ioc-investigator
description: >
  Extract all IOCs from a Defender XDR incident's alerts and cross-reference them
  against environment history using Advanced Hunting KQL queries. Use when given
  an incidentId and the Incident Analyst's structured output to produce a per-IOC
  verdict (MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, UNKNOWN) with prevalence,
  first-seen, and lateral spread data for the Judge Agent.
license: MIT
compatibility: Requires Microsoft Security MCP tools — listIncidents (expand alerts), runHuntingQuery, createCommentForIncident
metadata:
  author: soc-automation
  version: "1.0"
allowed-tools: listIncidents listAlerts runHuntingQuery createCommentForIncident
---

## When to Use This Skill
Load this skill when you have an `incidentId` and the Incident Analyst's JSON output
and are asked to investigate IOCs, check threat intelligence, or assess indicator risk.

## Step-by-Step Instructions

### 1. Extract and Deduplicate IOCs
From the Incident Analyst output (`alertSummaries[].entities`), compile:
- External IP addresses (skip RFC1918: 10.x, 172.16-31.x, 192.168.x)
- Domains and URLs
- File hashes (SHA256 preferred, SHA1 fallback)
- User accounts (UPN format)
- Suspicious process command lines
- Sender email addresses (for phishing alerts)

### 2. Run KQL Hunts per IOC Type
For each IOC, call `runHuntingQuery` using the appropriate KQL script.
Load the correct script using `load_skill` + `run_skill_script`:
- IP address → run script `hunt-ip`
- Domain/URL → run script `hunt-domain`
- File hash → run script `hunt-hash` then `hunt-hash-process`
- User account → run script `hunt-user` then `hunt-user-directory`
- Process/command line → run script `hunt-process`

Always use Timespan `P30D` unless overridden.

### 3. Assess Each IOC
For each IOC, assign a verdict using these criteria:

| Verdict        | Criteria                                                          |
|----------------|-------------------------------------------------------------------|
| MALICIOUS      | Confirmed C2, known-bad hash, active exfiltration, malware exec   |
| SUSPICIOUS     | Rare in environment, first-seen at incident time, anomalous geo   |
| LIKELY_BENIGN  | High prevalence (10+ devices), matches known-good software        |
| UNKNOWN        | Zero historical hits in last 30 days — note as "new to env"       |

Assess these factors per IOC:
- **Prevalence**: device count in last 30 days
- **First seen**: was it introduced at incident time? (`isNewToEnvironment`)
- **Lateral spread**: does it appear on devices NOT in the original incident?
- **Geolocation**: VPS/bulletproof hosting ASNs, Tor exit nodes = +SUSPICIOUS
- **Process context**: LOLBin parent→child anomaly = +SUSPICIOUS

### 4. Write Incident Comment
Call `createCommentForIncident` with the IOC Investigation Report.
Use `read_skill_resource("ioc-comment-template")` for the format.

### 5. Return Structured JSON Output
Return JSON with keys: `incidentId`, `totalIOCs`, `iocResults` (array),
`maliciousCount`, `suspiciousCount`, `likelyBenignCount`, `unknownCount`,
`highestRiskIOC`, `investigatorNotes`.

## Rules
- Run a hunt query for EVERY IOC — no skipping.
- Zero hunt results = "No activity found in last 30 days" → record explicitly.
- Do NOT call updateIncident.
- Do NOT make a final incident verdict — that is the Judge Agent's role.
```

### `skills_code/ioc_investigator_skills.py` — Code-Defined Scripts

```python
from agent_framework import Skill, SkillsProvider
from textwrap import dedent

ioc_investigator_skill = Skill(
    name="ioc-investigator",
    description=(
        "Extract all IOCs from a Defender XDR incident's alerts and cross-reference "
        "them against environment history using Advanced Hunting KQL queries. Use when "
        "given an incidentId and the Incident Analyst's structured output to produce a "
        "per-IOC verdict (MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, UNKNOWN) with "
        "prevalence, first-seen, and lateral spread data for the Judge Agent."
    ),
    content=dedent("""\
        Use this skill to investigate IOCs extracted from a Defender XDR incident.
        Run the appropriate hunt script for each IOC type, assess verdicts using
        the classification guide, then write a structured comment to the incident.
    """),
)


# ── Script 1: Hunt IP Address ────────────────────────────────────────────────

@ioc_investigator_skill.script(
    name="hunt-ip",
    description=(
        "Hunt an external IP address across DeviceNetworkEvents and DeviceEvents "
        "for the last 30 days. Returns connection count, affected devices, ports, "
        "first/last seen timestamps."
    )
)
def hunt_ip(ip_address: str, timespan: str = "P30D") -> str:
    """
    KQL to hunt an IP address across network telemetry.
    Returns the KQL query string for execution via runHuntingQuery MCP tool.
    """
    import json
    kql = dedent(f"""\
        let SuspiciousIP = "{ip_address}";
        union
        (
            DeviceNetworkEvents
            | where RemoteIP == SuspiciousIP
            | summarize
                FirstSeen        = min(Timestamp),
                LastSeen         = max(Timestamp),
                ConnectionCount  = count(),
                AffectedDevices  = make_set(DeviceName),
                Ports            = make_set(RemotePort),
                ActionTypes      = make_set(ActionType)
              by RemoteIP
        ),
        (
            DeviceEvents
            | where RemoteIP == SuspiciousIP
            | summarize
                FirstSeen = min(Timestamp),
                LastSeen  = max(Timestamp),
                Count     = count()
              by RemoteIP
        )
        | project SuspiciousIP, FirstSeen, LastSeen,
                  ConnectionCount, AffectedDevices, Ports, ActionTypes
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 2: Hunt Domain / URL ──────────────────────────────────────────────

@ioc_investigator_skill.script(
    name="hunt-domain",
    description=(
        "Hunt a suspicious domain or URL across DeviceNetworkEvents. "
        "Returns unique devices, first/last contact, initiating processes."
    )
)
def hunt_domain(domain: str, timespan: str = "P30D") -> str:
    """KQL to hunt a domain/URL across network telemetry."""
    import json
    kql = dedent(f"""\
        let SuspiciousDomain = "{domain}";
        DeviceNetworkEvents
        | where RemoteUrl has SuspiciousDomain
            or InitiatingProcessCommandLine has SuspiciousDomain
        | summarize
            FirstSeen           = min(Timestamp),
            LastSeen            = max(Timestamp),
            UniqueDevices       = dcount(DeviceName),
            Devices             = make_set(DeviceName),
            ActionTypes         = make_set(ActionType),
            InitiatingProcesses = make_set(InitiatingProcessFileName)
          by RemoteUrl
        | order by LastSeen desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 3: Hunt File Hash (File Events) ───────────────────────────────────

@ioc_investigator_skill.script(
    name="hunt-hash",
    description=(
        "Hunt a file SHA256 hash across DeviceFileEvents. "
        "Returns prevalence, affected devices, file paths, first/last seen."
    )
)
def hunt_hash(sha256: str, sha1: str = "", timespan: str = "P30D") -> str:
    """KQL to hunt a file hash across file creation/modification events."""
    import json
    sha1_clause = f'or SHA1 == "{sha1}"' if sha1 else ""
    kql = dedent(f"""\
        let SuspiciousHash = "{sha256}";
        DeviceFileEvents
        | where SHA256 == SuspiciousHash {sha1_clause}
        | summarize
            FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            UniqueDevices = dcount(DeviceName),
            Devices     = make_set(DeviceName),
            FileNames   = make_set(FileName),
            FilePaths   = make_set(FolderPath),
            ActionTypes = make_set(ActionType)
          by SHA256
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 4: Hunt File Hash (Process Execution) ─────────────────────────────

@ioc_investigator_skill.script(
    name="hunt-hash-process",
    description=(
        "Hunt a file SHA256 hash across DeviceProcessEvents to detect execution. "
        "Returns execution devices, full command lines, parent processes."
    )
)
def hunt_hash_process(sha256: str, timespan: str = "P30D") -> str:
    """KQL to check if a file hash was executed as a process."""
    import json
    kql = dedent(f"""\
        let SuspiciousHash = "{sha256}";
        DeviceProcessEvents
        | where SHA256 == SuspiciousHash
        | summarize
            FirstSeen      = min(Timestamp),
            LastSeen       = max(Timestamp),
            Devices        = make_set(DeviceName),
            CommandLines   = make_set(ProcessCommandLine),
            ParentProcesses = make_set(InitiatingProcessFileName)
          by SHA256, FileName
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 5: Hunt User Account (Logon Events) ───────────────────────────────

@ioc_investigator_skill.script(
    name="hunt-user",
    description=(
        "Hunt a user UPN across IdentityLogonEvents for anomalous sign-in patterns. "
        "Returns logon count, failure count, source IPs, devices accessed, logon types."
    )
)
def hunt_user(upn: str, timespan: str = "P30D") -> str:
    """KQL to investigate user account logon history for anomalies."""
    import json
    kql = dedent(f"""\
        let SuspiciousUser = "{upn}";
        IdentityLogonEvents
        | where AccountUpn == SuspiciousUser
            or AccountName == SuspiciousUser
        | summarize
            FirstSeen    = min(Timestamp),
            LastSeen     = max(Timestamp),
            LogonCount   = count(),
            UniqueDevices = dcount(DeviceName),
            Devices      = make_set(DeviceName),
            SourceIPs    = make_set(IPAddress),
            LogonTypes   = make_set(LogonType),
            FailureCount = countif(ActionType == "LogonFailed")
          by AccountUpn
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 6: Hunt User Account (Directory Events) ───────────────────────────

@ioc_investigator_skill.script(
    name="hunt-user-directory",
    description=(
        "Hunt a user UPN across IdentityDirectoryEvents for privilege changes, "
        "group membership modifications, or suspicious AD actions in last 14 days."
    )
)
def hunt_user_directory(upn: str, timespan: str = "P14D") -> str:
    """KQL to check AD/AAD directory actions by or targeting a user."""
    import json
    kql = dedent(f"""\
        let SuspiciousUser = "{upn}";
        IdentityDirectoryEvents
        | where AccountUpn == SuspiciousUser
            or TargetAccountUpn == SuspiciousUser
        | summarize
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            Actions   = make_set(ActionType),
            Count     = count()
          by AccountUpn, ActionType
        | order by LastSeen desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 7: Hunt Suspicious Process / Command Line ─────────────────────────

@ioc_investigator_skill.script(
    name="hunt-process",
    description=(
        "Hunt a partial command line string across DeviceProcessEvents. "
        "Returns devices, users, and full command lines matching the pattern. "
        "Use for LOLBin abuse, encoded PowerShell, or suspicious child processes."
    )
)
def hunt_process(command_fragment: str, timespan: str = "P14D") -> str:
    """KQL to hunt suspicious command line patterns across all devices."""
    import json
    kql = dedent(f"""\
        let SuspiciousCmdLine = "{command_fragment}";
        DeviceProcessEvents
        | where ProcessCommandLine has SuspiciousCmdLine
            or InitiatingProcessCommandLine has SuspiciousCmdLine
        | summarize
            FirstSeen       = min(Timestamp),
            LastSeen        = max(Timestamp),
            UniqueDevices   = dcount(DeviceName),
            Devices         = make_set(DeviceName),
            Users           = make_set(AccountName),
            FullCommandLines = make_set(ProcessCommandLine)
          by FileName
        | order by UniqueDevices desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Resource: IOC Classification Guide ───────────────────────────────────────

@ioc_investigator_skill.resource(
    name="ioc-classification-guide",
    description="Criteria for assigning MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, or UNKNOWN verdicts to IOCs"
)
def ioc_classification_guide() -> str:
    return dedent("""\
        # IOC Classification Guide

        ## Verdict Definitions

        ### MALICIOUS
        Assign when ANY of the following are true:
        - File hash matches confirmed malware (execution confirmed via hunt-hash-process)
        - IP/domain is confirmed C2 — beaconing pattern (periodic connections, same port, short intervals)
        - User account shows impossible travel (2 logons from different countries < 1 hour apart)
        - Process spawned from anomalous parent (e.g., winword.exe → cmd.exe → powershell.exe)
        - Hash seen on multiple devices AND first appeared at incident time (coordinated drop)

        ### SUSPICIOUS
        Assign when ANY of the following are true:
        - IOC is new to the environment (first-seen = incident timestamp, isNewToEnvironment = true)
        - External IP is from VPS/bulletproof hosting or Tor exit node ASN
        - File hash has low prevalence (1–3 devices) with no known-good match
        - User has logon failures spike followed by success from new IP
        - Process command line contains: base64 encoding, -EncodedCommand, certutil -decode,
          bitsadmin /transfer, mshta http://, regsvr32 /s /u /i:http

        ### LIKELY_BENIGN
        Assign when ALL of the following are true:
        - IOC has high prevalence in environment (10+ devices, consistent history)
        - First seen well before incident (not new to environment)
        - Matches known software vendor, IT tool, or documented admin activity
        - No lateral spread beyond originally alerted devices

        ### UNKNOWN
        Assign when:
        - Hunt queries return zero results (no historical data in last 30 days)
        - Record as "New to environment — no baseline" and flag for Judge Agent
        - UNKNOWN is treated conservatively as +5 score by the Judge Agent

        ## Special Cases
        - Internal IPs (RFC1918): Only investigate if they are a lateral movement TARGET
        - Microsoft/Azure service IPs: Skip unless connecting on non-standard ports
        - Security tool hashes (e.g., Nessus, CrowdStrike): Cross-check process parent
          and assign LIKELY_BENIGN only if parent process is the known security agent
    """)
```

***

## 🎯 Agent 3 — Threat Hunt Skills

### `skills/threat-hunter/SKILL.md`

```markdown
---
name: threat-hunter
description: >
  Perform advanced threat hunting in Defender XDR using KQL to determine whether
  incident IOCs have spread beyond the originally alerted scope, detect lateral
  movement, persistence mechanisms, and campaign indicators. Use when given an
  incidentId plus Incident Analyst and IOC Investigator outputs to produce a
  spread assessment and campaign verdict for the Judge Agent.
license: MIT
compatibility: Requires Microsoft Security MCP tools — listIncidents (expand alerts), runHuntingQuery, createCommentForIncident
metadata:
  author: soc-automation
  version: "1.0"
allowed-tools: listIncidents runHuntingQuery createCommentForIncident
---

## When to Use This Skill
Load this skill when you have the Incident Analyst JSON output (impacted devices,
users, MITRE techniques) and IOC Investigator JSON output (iocResults, malicious IPs,
hashes) and need to determine whether the incident is isolated or part of a campaign.

## Hunting Scope
Run hunts across these Defender XDR tables:
- `DeviceNetworkEvents` — C2 beaconing, lateral movement via network
- `DeviceProcessEvents` — LOLBin execution, malicious process spread
- `DeviceFileEvents` — malware file drops on additional devices
- `DeviceLogonEvents` — remote logon attempts from compromised devices
- `DeviceEvents` — registry persistence, scheduled tasks, service installs
- `IdentityLogonEvents` — AAD/AD account misuse across devices
- `IdentityDirectoryEvents` — DCSync, group membership changes
- `AlertEvidence` — campaign detection via shared MITRE techniques
- `EmailEvents` — phishing campaign spread (run only for MDO alerts)

## Step-by-Step Instructions

### 1. Confirm IOC and Entity Scope
From the Incident Analyst output, extract:
- `impactedDevices` → KnownAffectedDevices list for exclusion filters
- `impactedUsers` → CompromisedUsers list
- From IOC Investigator `iocResults` where verdict = MALICIOUS or SUSPICIOUS:
  - IP addresses → MaliciousIPs list
  - SHA256 hashes → MaliciousHashes list
  - Domains → SuspiciousDomains list

### 2. Run All Hunt Scripts
Run each hunt script in sequence using `run_skill_script`:
- `hunt-c2-spread` — C2 IP on devices outside incident scope
- `hunt-hash-spread` — malicious hash on devices outside incident scope
- `hunt-process-spread` — suspicious command line beyond incident scope
- `hunt-lateral-logon` — remote logons FROM compromised devices
- `hunt-user-spread` — compromised user accessing new devices
- `hunt-campaign` — similar incidents with same MITRE techniques
- `hunt-persistence` — registry/scheduled task persistence beyond incident
- `hunt-phishing-campaign` — only if serviceSource includes MDO alerts

### 3. Classify Each Hunt Result
For each hunt, classify the finding:

| Result                             | Classification      |
|------------------------------------|---------------------|
| 0 additional devices               | ISOLATED            |
| 1–2 additional devices             | LIMITED_SPREAD      |
| 3–9 additional devices             | ACTIVE_SPREAD       |
| 10+ additional devices             | WIDESPREAD          |
| Lateral logon failed attempts only | ATTEMPTED           |
| Lateral logon successful           | CONFIRMED           |
| Related incidents found            | POTENTIAL_CAMPAIGN  |
| Same technique in 3+ incidents     | CONFIRMED_CAMPAIGN  |

### 4. Write Incident Comment
Call `createCommentForIncident` with the Threat Hunt Report.
Use `read_skill_resource("hunt-comment-template")` for the format.

### 5. Return Structured JSON Output
Return JSON with keys: `incidentId`, `huntQueriesRun`, `spreadAssessment`
(object with per-hunt results), `overallScope`, `campaignIndicator`,
`earliestRelatedActivity`, `huntConclusion`.

## Timespan Guidance
- High / Critical severity incidents → P30D
- Medium severity → P14D
- Low / Informational → P7D

## Rules
- ALWAYS substitute real values into KQL before calling runHuntingQuery.
  Never pass template placeholders like `<device1>` to the tool.
- Zero results = record "No activity beyond incident scope" — still valuable.
- Do NOT call updateIncident.
- Do NOT make final benign/suspicious verdict — that is the Judge Agent's role.
```

### `skills_code/threat_hunter_skills.py` — Code-Defined Scripts

```python
from agent_framework import Skill, SkillsProvider
from textwrap import dedent

threat_hunter_skill = Skill(
    name="threat-hunter",
    description=(
        "Perform advanced threat hunting in Defender XDR using KQL to determine "
        "whether incident IOCs have spread beyond the originally alerted scope, "
        "detect lateral movement, persistence mechanisms, and campaign indicators. "
        "Use when given an incidentId plus Incident Analyst and IOC Investigator "
        "outputs to produce a spread assessment and campaign verdict for the Judge Agent."
    ),
    content=dedent("""\
        Use this skill to hunt for IOC spread, lateral movement, persistence,
        and campaign indicators beyond the original incident scope.
        Run each hunt script in sequence, classify results, then write a comment.
    """),
)


# ── Script 1: C2 IP Spread ───────────────────────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-c2-spread",
    description=(
        "Check if malicious C2 IPs from the incident have been contacted by "
        "devices NOT already in the incident scope. Detects spread beyond initial "
        "blast radius. Returns additional device names, ports, first/last contact."
    )
)
def hunt_c2_spread(
    malicious_ips: list,
    known_affected_devices: list,
    timespan: str = "P30D"
) -> str:
    """KQL to detect C2 IP contact on devices outside the incident scope."""
    import json
    ips_str = str(malicious_ips).replace("'", '"')
    devices_str = str(known_affected_devices).replace("'", '"')
    kql = dedent(f"""\
        let MaliciousIPs = dynamic({ips_str});
        let KnownAffectedDevices = dynamic({devices_str});
        DeviceNetworkEvents
        | where RemoteIP in (MaliciousIPs)
            and DeviceName !in (KnownAffectedDevices)
        | summarize
            FirstContact    = min(Timestamp),
            LastContact     = max(Timestamp),
            ConnectionCount = count(),
            Ports           = make_set(RemotePort),
            Protocols       = make_set(Protocol)
          by DeviceName, RemoteIP
        | order by LastContact desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 2: File Hash Spread ───────────────────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-hash-spread",
    description=(
        "Search for malicious file hashes on devices NOT in the original incident. "
        "Detects malware propagation or coordinated drops. Returns additional "
        "affected devices, file names, paths, first/last seen."
    )
)
def hunt_hash_spread(
    malicious_hashes: list,
    known_affected_devices: list,
    timespan: str = "P30D"
) -> str:
    """KQL to detect malicious file hash presence beyond incident scope."""
    import json
    hashes_str = str(malicious_hashes).replace("'", '"')
    devices_str = str(known_affected_devices).replace("'", '"')
    kql = dedent(f"""\
        let MaliciousHashes = dynamic({hashes_str});
        let KnownAffectedDevices = dynamic({devices_str});
        DeviceFileEvents
        | where SHA256 in (MaliciousHashes)
            and DeviceName !in (KnownAffectedDevices)
        | summarize
            FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            Devices     = make_set(DeviceName),
            FileNames   = make_set(FileName),
            FilePaths   = make_set(FolderPath),
            ActionTypes = make_set(ActionType)
          by SHA256
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 3: Suspicious Process Spread ─────────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-process-spread",
    description=(
        "Hunt for the same suspicious command line pattern on devices NOT in the "
        "original incident. Detects LOLBin abuse, encoded PowerShell, or malicious "
        "script execution spreading across the environment."
    )
)
def hunt_process_spread(
    command_fragment: str,
    known_affected_devices: list,
    timespan: str = "P14D"
) -> str:
    """KQL to detect suspicious process execution beyond incident scope."""
    import json
    devices_str = str(known_affected_devices).replace("'", '"')
    kql = dedent(f"""\
        let SuspiciousCmd = "{command_fragment}";
        let KnownAffectedDevices = dynamic({devices_str});
        DeviceProcessEvents
        | where ProcessCommandLine has SuspiciousCmd
            and DeviceName !in (KnownAffectedDevices)
        | summarize
            FirstSeen        = min(Timestamp),
            LastSeen         = max(Timestamp),
            UniqueDevices    = dcount(DeviceName),
            Devices          = make_set(DeviceName),
            Users            = make_set(AccountName),
            CommandLines     = make_set(ProcessCommandLine)
          by FileName
        | order by UniqueDevices desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 4: Lateral Movement via Remote Logon ──────────────────────────────

@threat_hunter_skill.script(
    name="hunt-lateral-logon",
    description=(
        "Detect lateral movement by checking if compromised devices have attempted "
        "remote logons to other devices. Distinguishes between failed attempts "
        "(ATTEMPTED) and successful logons (CONFIRMED lateral movement)."
    )
)
def hunt_lateral_logon(
    compromised_devices: list,
    timespan: str = "P14D"
) -> str:
    """KQL to detect remote logon attempts FROM compromised devices."""
    import json
    devices_str = str(compromised_devices).replace("'", '"')
    kql = dedent(f"""\
        let CompromisedDevices = dynamic({devices_str});
        DeviceLogonEvents
        | where DeviceName !in (CompromisedDevices)
            and RemoteDeviceName in (CompromisedDevices)
            and LogonType in ("Network", "RemoteInteractive")
        | summarize
            FirstSeen      = min(Timestamp),
            LastSeen       = max(Timestamp),
            AttemptCount   = count(),
            SuccessCount   = countif(ActionType == "LogonSuccess"),
            FailureCount   = countif(ActionType == "LogonFailed"),
            TargetDevices  = make_set(DeviceName),
            AccountsUsed   = make_set(AccountName)
          by RemoteDeviceName
        | order by AttemptCount desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 5: Compromised User Account Spread ────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-user-spread",
    description=(
        "Check if compromised user accounts have accessed devices NOT in the "
        "original incident scope. Detects credential misuse and account-based "
        "lateral movement. Returns new devices, source IPs, logon types."
    )
)
def hunt_user_spread(
    compromised_users: list,
    known_affected_devices: list,
    timespan: str = "P14D"
) -> str:
    """KQL to detect compromised user accessing devices outside incident scope."""
    import json
    users_str = str(compromised_users).replace("'", '"')
    devices_str = str(known_affected_devices).replace("'", '"')
    kql = dedent(f"""\
        let CompromisedUsers = dynamic({users_str});
        let KnownAffectedDevices = dynamic({devices_str});
        IdentityLogonEvents
        | where AccountUpn in (CompromisedUsers)
            and DeviceName !in (KnownAffectedDevices)
            and ActionType == "LogonSuccess"
        | summarize
            FirstSeen          = min(Timestamp),
            LastSeen           = max(Timestamp),
            NewDevicesAccessed = dcount(DeviceName),
            Devices            = make_set(DeviceName),
            SourceIPs          = make_set(IPAddress),
            LogonTypes         = make_set(LogonType)
          by AccountUpn
        | order by NewDevicesAccessed desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 6: Campaign Detection via MITRE Techniques ────────────────────────

@threat_hunter_skill.script(
    name="hunt-campaign",
    description=(
        "Search AlertEvidence and AlertInfo for other incidents sharing the same "
        "MITRE ATT&CK techniques. Identifies whether this incident is part of a "
        "broader campaign or an isolated event. Returns related alert IDs and titles."
    )
)
def hunt_campaign(
    mitre_technique_ids: list,
    timespan: str = "P30D"
) -> str:
    """KQL to detect campaign indicators via shared MITRE techniques."""
    import json
    techniques_str = str(mitre_technique_ids).replace("'", '"')
    kql = dedent(f"""\
        let IncidentTechniques = dynamic({techniques_str});
        AlertEvidence
        | where Timestamp > ago(30d)
        | where EntityType in ("Process", "File", "NetworkConnection", "User")
        | join kind=inner (
            AlertInfo
            | where AttackTechniques has_any (IncidentTechniques)
            | project AlertId, Title, Severity, AttackTechniques, Timestamp
          ) on $left.AlertId == $right.AlertId
        | summarize
            AlertCount     = dcount(AlertId),
            AffectedDevices = make_set(DeviceName),
            AlertTitles    = make_set(Title),
            FirstSeen      = min(Timestamp),
            LastSeen       = max(Timestamp)
          by AttackTechniques
        | order by AlertCount desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 7: Persistence Mechanism Hunt ─────────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-persistence",
    description=(
        "Detect persistence mechanisms (registry run keys, scheduled tasks, "
        "service installs) on devices NOT in the original incident scope. "
        "Identifies attacker foothold establishment beyond initial breach."
    )
)
def hunt_persistence(
    known_affected_devices: list,
    timespan: str = "P14D"
) -> str:
    """KQL to detect persistence actions beyond incident scope."""
    import json
    devices_str = str(known_affected_devices).replace("'", '"')
    kql = dedent(f"""\
        let KnownAffectedDevices = dynamic({devices_str});
        let SystemAccounts = dynamic(["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"]);
        DeviceEvents
        | where ActionType in (
            "RegistryValueSet",
            "ScheduledTaskCreated",
            "ScheduledTaskModified",
            "ServiceInstalled"
          )
        | where DeviceName !in (KnownAffectedDevices)
        | where InitiatingProcessAccountName !in (SystemAccounts)
        | summarize
            FirstSeen          = min(Timestamp),
            LastSeen           = max(Timestamp),
            PersistenceActions = make_set(ActionType),
            Devices            = make_set(DeviceName),
            Accounts           = make_set(InitiatingProcessAccountName),
            Count              = count()
          by InitiatingProcessFileName, ActionType
        | order by LastSeen desc
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Script 8: Phishing Campaign Spread ───────────────────────────────────────

@threat_hunter_skill.script(
    name="hunt-phishing-campaign",
    description=(
        "Hunt for phishing campaign spread via EmailEvents. Only run this script "
        "when the incident contains Defender for Office 365 (MDO) alerts. "
        "Returns recipient count, delivery actions, email subjects from same sender."
    )
)
def hunt_phishing_campaign(
    sender_email: str,
    sender_domain: str,
    timespan: str = "P14D"
) -> str:
    """KQL to detect phishing campaign spread via email telemetry."""
    import json
    kql = dedent(f"""\
        let MaliciousSender = "{sender_email}";
        let MaliciousDomain = "{sender_domain}";
        EmailEvents
        | where SenderMailFromAddress == MaliciousSender
            or SenderMailFromDomain == MaliciousDomain
        | summarize
            FirstSeen        = min(Timestamp),
            LastSeen         = max(Timestamp),
            EmailCount       = count(),
            UniqueRecipients = dcount(RecipientEmailAddress),
            Recipients       = make_set(RecipientEmailAddress),
            Subjects         = make_set(Subject),
            DeliveryActions  = make_set(DeliveryAction)
          by SenderMailFromAddress
    """)
    return json.dumps({"huntingQuery": {"Query": kql, "Timespan": timespan}})


# ── Resource: KQL Table Reference ────────────────────────────────────────────

@threat_hunter_skill.resource(
    name="kql-table-reference",
    description="Quick reference for Defender XDR Advanced Hunting table names and key columns"
)
def kql_table_reference() -> str:
    return dedent("""\
        # Defender XDR Advanced Hunting — Table Reference

        | Table                    | Key Columns                                                    |
        |--------------------------|----------------------------------------------------------------|
        | DeviceNetworkEvents      | DeviceName, RemoteIP, RemoteUrl, RemotePort, ActionType        |
        | DeviceProcessEvents      | DeviceName, FileName, ProcessCommandLine, SHA256, AccountName  |
        | DeviceFileEvents         | DeviceName, FileName, FolderPath, SHA256, SHA1, ActionType     |
        | DeviceLogonEvents        | DeviceName, AccountName, LogonType, RemoteDeviceName           |
        | DeviceEvents             | DeviceName, ActionType, InitiatingProcessFileName              |
        | IdentityLogonEvents      | AccountUpn, DeviceName, IPAddress, LogonType, ActionType       |
        | IdentityDirectoryEvents  | AccountUpn, TargetAccountUpn, ActionType                       |
        | AlertEvidence            | AlertId, EntityType, DeviceName, Timestamp                     |
        | AlertInfo                | AlertId, Title, Severity, AttackTechniques, Timestamp          |
        | EmailEvents              | SenderMailFromAddress, RecipientEmailAddress, Subject          |
        | EmailAttachmentInfo      | SHA256, FileName, RecipientEmailAddress                        |

        ## Timespan Parameter (ISO 8601)
        - P7D  = last 7 days
        - P14D = last 14 days
        - P30D = last 30 days (default for High/Critical)

        ## ActionType Values for DeviceLogonEvents
        - LogonSuccess, LogonFailed, LogonAttempted

        ## ActionType Values for DeviceEvents (Persistence)
        - RegistryValueSet, ScheduledTaskCreated, ScheduledTaskModified, ServiceInstalled
    """)
```

***

## ⚖️ Agent 4 — Judge Agent Skill

### `skills/judge/SKILL.md`

```markdown
---
name: judge
description: >
  Collect outputs from the Incident Analyst, IOC Investigator, and Threat Hunt agents
  and make the final Tier-1 SOC triage decision for a Defender XDR incident.
  Use when all three specialist agent reports are available to score the incident,
  determine BENIGN / INCONCLUSIVE / SUSPICIOUS verdict, execute the appropriate
  updateIncident action, and write a final judgment comment.
license: MIT
compatibility: Requires Microsoft Security MCP tools — updateIncident, createCommentForIncident
metadata:
  author: soc-automation
  version: "1.0"
allowed-tools: updateIncident createCommentForIncident
---

## When to Use This Skill
Load this skill when you have all three structured JSON reports from the specialist
agents and need to produce a final triage verdict and execute the incident update.

## Step-by-Step Instructions

### 1. Validate Input Completeness
Verify all three reports are present: analystReport, iocReport, huntReport.
If any is missing: write comment, set verdict = SUSPICIOUS by default, proceed.

### 2. Score the Incident
Run script `score-incident` with the three reports as input.
The script returns a total score and per-category breakdown.

### 3. Apply Decision Threshold
Use `read_skill_resource("scoring-criteria")` for the full scoring table.

| Score  | Decision     | Action                          |
|--------|--------------|----------------------------------|
| 0–15   | BENIGN       | Resolve with appropriate classification |
| 16–35  | INCONCLUSIVE | Keep active, flag for human review |
| 36+    | SUSPICIOUS   | Escalate to Tier-2, assign to team |

### 4. Determine Classification and Determination Values
Use `read_skill_resource("classification-mapping")` to select the correct
`classification` and `determination` enum values for updateIncident.

### 5. Write Final Judgment Comment
Call `createCommentForIncident` FIRST with the full judgment report.
Include: total score, per-category breakdown, key evidence summary,
verdict rationale, action taken, and Tier-2 recommendations if escalating.

### 6. Execute updateIncident
Call `updateIncident` with the correct status, classification, determination,
assignedTo, and resolvingComment (concise 1–2 sentence summary).

## Rules
- You are the ONLY agent that calls updateIncident. No other agent does this.
- Always write createCommentForIncident BEFORE calling updateIncident.
- Never close an incident (status=resolved) with a score above 15.
- Never escalate (truePositive) with a score below 36 without noting override reason.
- Missing specialist report = treat conservatively as SUSPICIOUS.
```

### `skills_code/judge_skills.py` — Code-Defined Scripts + Resources

```python
from agent_framework import Skill, SkillsProvider
from textwrap import dedent
import json

judge_skill = Skill(
    name="judge",
    description=(
        "Collect outputs from the Incident Analyst, IOC Investigator, and Threat Hunt "
        "agents and make the final Tier-1 SOC triage decision for a Defender XDR "
        "incident. Use when all three specialist agent reports are available to score "
        "the incident, determine BENIGN / INCONCLUSIVE / SUSPICIOUS verdict, execute "
        "updateIncident, and write a final judgment comment."
    ),
    content=dedent("""\
        Use this skill to score a security incident, determine triage verdict,
        and execute the final updateIncident action in Defender XDR.
        Always write createCommentForIncident before calling updateIncident.
    """),
)


# ── Script: Score Incident ───────────────────────────────────────────────────

@judge_skill.script(
    name="score-incident",
    description=(
        "Calculate the total triage risk score from the three specialist agent "
        "reports. Returns a JSON score breakdown with per-category scores and "
        "total, plus the recommended verdict (BENIGN / INCONCLUSIVE / SUSPICIOUS)."
    )
)
def score_incident(
    analyst_report: dict,
    ioc_report: dict,
    hunt_report: dict
) -> str:
    """
    Deterministic scoring engine for SOC triage decisions.
    Evaluates IOC risk, attack scope, alert severity, MITRE tactics,
    and benign deductions to produce a total risk score.
    """
    score = 0
    breakdown = {}

    # ── 2A: IOC Risk Scoring ──────────────────────────────────────────────
    ioc_score = 0
    malicious = ioc_report.get("maliciousCount", 0)
    suspicious = ioc_report.get("suspiciousCount", 0)
    ioc_results = ioc_report.get("iocResults", [])
    suspicious_with_spread = sum(
        1 for i in ioc_results
        if i.get("verdict") == "SUSPICIOUS" and i.get("lateralSpread", False)
    )
    all_benign = ioc_report.get("likelyBenignCount", 0) == len(ioc_results) and len(ioc_results) > 0
    all_unknown = ioc_report.get("unknownCount", 0) == len(ioc_results) and len(ioc_results) > 0

    if malicious >= 1:
        ioc_score += 40
    elif suspicious_with_spread >= 1:
        ioc_score += 30
    elif suspicious >= 2:
        ioc_score += 20
    elif suspicious == 1:
        ioc_score += 10
    elif all_unknown:
        ioc_score += 5
    # all_benign → 0

    score += ioc_score
    breakdown["ioc_risk"] = {"score": ioc_score, "malicious": malicious, "suspicious": suspicious}

    # ── 2B: Attack Scope Scoring ──────────────────────────────────────────
    scope_score = 0
    spread = hunt_report.get("spreadAssessment", {})
    overall_scope = hunt_report.get("overallScope", "ISOLATED")
    campaign = hunt_report.get("campaignIndicator", False)
    lateral = spread.get("lateralMovement", {})

    if campaign and spread.get("campaignDetection", {}).get("verdict") == "CONFIRMED_CAMPAIGN":
        scope_score += 40
    if overall_scope == "WIDESPREAD":
        scope_score += 35
    elif overall_scope == "TARGETED":
        scope_score += 20
    if lateral.get("confirmed", False):
        scope_score += 30
    elif lateral.get("attempted", False):
        scope_score += 15
    if spread.get("persistenceMechanisms", {}).get("found", False):
        scope_score += 25

    score += scope_score
    breakdown["attack_scope"] = {"score": scope_score, "scope": overall_scope, "lateral": lateral}

    # ── 2C: Alert Severity Scoring ────────────────────────────────────────
    sev_score = 0
    severities = [a.get("severity", "").lower() for a in analyst_report.get("alertSummaries", [])]
    sources = analyst_report.get("detectionSources", [])

    if "high" in severities:
        sev_score += 20
    elif "medium" in severities:
        sev_score += 10
    if len(set(sources)) > 1:
        sev_score += 10

    score += sev_score
    breakdown["alert_severity"] = {"score": sev_score, "severities": list(set(severities))}

    # ── 2D: MITRE Tactic Scoring ──────────────────────────────────────────
    mitre_score = 0
    tactics = [t.lower() for t in analyst_report.get("mitreTactics", [])]

    high_tactics = {"exfiltration", "impact", "commandandcontrol"}
    medium_high_tactics = {"lateralmovement", "privilegeescalation"}
    medium_tactics = {"persistence", "defenseevasion"}
    low_medium_tactics = {"execution", "credentialaccess"}
    low_tactics = {"initialaccess"}
    recon_tactics = {"reconnaissance", "discovery"}

    if any(t in high_tactics for t in tactics):
        mitre_score += 30
    elif any(t in medium_high_tactics for t in tactics):
        mitre_score += 25
    elif any(t in medium_tactics for t in tactics):
        mitre_score += 20
    elif any(t in low_medium_tactics for t in tactics):
        mitre_score += 15
    elif any(t in low_tactics for t in tactics):
        mitre_score += 10
    elif any(t in recon_tactics for t in tactics):
        mitre_score += 5

    score += mitre_score
    breakdown["mitre_tactics"] = {"score": mitre_score, "tactics": tactics}

    # ── 2E: Benign Deductions ─────────────────────────────────────────────
    deduction = 0
    ioc_results_all = ioc_report.get("iocResults", [])
    total_iocs = len(ioc_results_all)
    benign_count = ioc_report.get("likelyBenignCount", 0)

    # All IOCs likely benign and high prevalence
    if total_iocs > 0 and benign_count == total_iocs:
        deduction += 15

    # Single low-severity alert, isolated, no entity overlap
    total_alerts = analyst_report.get("totalAlerts", 0)
    attack_chain = analyst_report.get("attackChainDetected", True)
    if total_alerts == 1 and "low" in severities and not attack_chain and overall_scope == "ISOLATED":
        deduction += 10

    # No historical IOC activity AND no spread
    no_history = all(i.get("isNewToEnvironment", False) is False for i in ioc_results_all)
    if no_history and overall_scope == "ISOLATED":
        deduction += 5

    score -= deduction
    score = max(0, score)  # Floor at 0
    breakdown["benign_deductions"] = {"deduction": deduction}

    # ── Verdict ───────────────────────────────────────────────────────────
    if score <= 15:
        verdict = "BENIGN"
    elif score <= 35:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "SUSPICIOUS"

    return json.dumps({
        "totalScore": score,
        "verdict": verdict,
        "breakdown": breakdown,
        "maxPossibleScore": 150
    })


# ── Resource: Scoring Criteria ───────────────────────────────────────────────

@judge_skill.resource(
    name="scoring-criteria",
    description="Full scoring table for IOC risk, attack scope, severity, MITRE tactics, and benign deductions"
)
def scoring_criteria() -> str:
    return dedent("""\
        # Judge Agent — Scoring Criteria Reference

        ## 2A: IOC Risk Scoring
        | Condition                                      | Score |
        |------------------------------------------------|-------|
        | ≥1 MALICIOUS IOC confirmed                    | +40   |
        | ≥1 SUSPICIOUS IOC with lateral spread         | +30   |
        | ≥2 SUSPICIOUS IOCs, no lateral spread         | +20   |
        | 1 SUSPICIOUS IOC, no lateral spread           | +10   |
        | All IOCs LIKELY_BENIGN                        |  0    |
        | All IOCs UNKNOWN (no data)                    | +5    |

        ## 2B: Attack Scope Scoring
        | Condition                                      | Score |
        |------------------------------------------------|-------|
        | Campaign confirmed (3+ related incidents)     | +40   |
        | Active spread: 3+ additional devices hit      | +35   |
        | Limited spread: 1–2 additional devices        | +20   |
        | Lateral movement confirmed                    | +30   |
        | Lateral movement attempted (failed logons)    | +15   |
        | Persistence mechanism found                   | +25   |
        | Incident isolated to single device/user       |  0    |

        ## 2C: Alert Severity Scoring
        | Condition                                      | Score |
        |------------------------------------------------|-------|
        | ≥1 High-severity alert                        | +20   |
        | ≥1 Medium-severity alert, no High             | +10   |
        | All Low / Informational severity              |  0    |
        | Multiple detection sources (MDE + MDI + MDO)  | +10   |

        ## 2D: MITRE Tactic Scoring
        | Tactics Present                                | Score |
        |------------------------------------------------|-------|
        | Exfiltration, Impact, CommandAndControl        | +30   |
        | LateralMovement, PrivilegeEscalation           | +25   |
        | Persistence, DefenseEvasion                    | +20   |
        | Execution, CredentialAccess                    | +15   |
        | InitialAccess only                             | +10   |
        | Reconnaissance, Discovery only                 | +5    |

        ## 2E: Benign Deductions
        | Benign Signal                                  | Score |
        |------------------------------------------------|-------|
        | All IOCs LIKELY_BENIGN, high prevalence        | -15   |
        | Single low-sev alert, isolated, no chain       | -10   |
        | No historical IOC activity AND no spread       | -5    |

        ## Decision Threshold
        | Total Score | Verdict      |
        |-------------|--------------|
        | 0 – 15      | BENIGN       |
        | 16 – 35     | INCONCLUSIVE |
        | 36+         | SUSPICIOUS   |
    """)


# ── Resource: Classification Mapping ─────────────────────────────────────────

@judge_skill.resource(
    name="classification-mapping",
    description="Mapping of verdict scenarios to Defender XDR updateIncident classification and determination enum values"
)
def classification_mapping() -> str:
    return dedent("""\
        # updateIncident — Classification & Determination Mapping

        ## BENIGN Incidents (status = resolved)
        | Scenario                           | classification                  | determination                |
        |------------------------------------|---------------------------------|------------------------------|
        | Security tool / pen test          | informationalExpectedActivity   | securityTesting              |
        | Known admin / IT activity         | informationalExpectedActivity   | lineOfBusinessApplication    |
        | False positive detection rule     | falsePositive                   | clean                        |
        | Expected user activity (IT ops)   | informationalExpectedActivity   | confirmedUserActivity        |

        ## SUSPICIOUS Incidents (status = active, escalate)
        | Scenario                           | classification  | determination         |
        |------------------------------------|-----------------|-----------------------|
        | Malware confirmed                 | truePositive    | malware               |
        | Phishing confirmed                | truePositive    | phishing              |
        | Compromised account evidence      | truePositive    | compromisedAccount    |
        | Multi-stage attack chain          | truePositive    | multiStagedAttack     |
        | APT indicators present            | truePositive    | apt                   |
        | Suspicious but unclear            | unknown         | unknown               |

        ## INCONCLUSIVE Incidents (status = active, human review)
        | Scenario                           | classification  | determination  |
        |------------------------------------|-----------------|----------------|
        | All inconclusive cases            | unknown         | unknown        |
    """)
```

***

## 🔌 Wiring Skills to Agents in `function_app.py`

```python
# ── Skills Provider Setup ─────────────────────────────────────────────────────
from pathlib import Path
from agent_framework import SkillsProvider
from skills_code.ioc_investigator_skills import ioc_investigator_skill
from skills_code.threat_hunter_skills import threat_hunter_skill
from skills_code.judge_skills import judge_skill

# Agent 1 — file-based skill only (SKILL.md in skills/incident-analyst/)
analyst_skills = SkillsProvider(
    skill_paths=Path(__file__).parent / "skills" / "incident-analyst"
)

# Agent 2 — file-based SKILL.md + code-defined scripts
ioc_skills = SkillsProvider(
    skill_paths=Path(__file__).parent / "skills" / "ioc-investigator",
    skills=[ioc_investigator_skill]
)

# Agent 3 — file-based SKILL.md + code-defined scripts
hunt_skills = SkillsProvider(
    skill_paths=Path(__file__).parent / "skills" / "threat-hunter",
    skills=[threat_hunter_skill]
)

# Agent 4 — file-based SKILL.md + code-defined scripts
judge_skills = SkillsProvider(
    skill_paths=Path(__file__).parent / "skills" / "judge",
    skills=[judge_skill]
)

# ── Agent Definitions (attach to existing MAF agent setup) ───────────────────
analyst_agent = AzureAIClient(credential=credential).as_agent(
    name="IncidentAnalyst",
    instructions=INCIDENT_ANALYST_INSTRUCTIONS,
    tools=ms_security_mcp,
    context_providers=[analyst_skills],    # ← skills attached here
)

ioc_agent = AzureAIClient(credential=credential).as_agent(
    name="IOCInvestigator",
    instructions=IOC_INVESTIGATOR_INSTRUCTIONS,
    tools=ms_security_mcp,
    context_providers=[ioc_skills],
)

hunt_agent = AzureAIClient(credential=credential).as_agent(
    name="ThreatHunter",
    instructions=THREAT_HUNT_INSTRUCTIONS,
    tools=ms_security_mcp,
    context_providers=[hunt_skills],
)

judge_agent = AzureAIClient(credential=credential).as_agent(
    name="JudgeAgent",
    instructions=JUDGE_AGENT_INSTRUCTIONS,
    tools=ms_security_mcp,
    context_providers=[judge_skills],
)
```

***

## 📋 Skills Summary

| Agent            | Skill Name         | Scripts                                                                                                                                                              | Resources                                    |
| ---------------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| Incident Analyst | `incident-analyst` | *(none — uses MCP tools directly)*                                                                                                                                   | `alert-entity-schema`                        |
| IOC Investigator | `ioc-investigator` | `hunt-ip`, `hunt-domain`, `hunt-hash`, `hunt-hash-process`, `hunt-user`, `hunt-user-directory`, `hunt-process`                                                       | `ioc-classification-guide`                   |
| Threat Hunter    | `threat-hunter`    | `hunt-c2-spread`, `hunt-hash-spread`, `hunt-process-spread`, `hunt-lateral-logon`, `hunt-user-spread`, `hunt-campaign`, `hunt-persistence`, `hunt-phishing-campaign` | `kql-table-reference`                        |
| Judge            | `judge`            | `score-incident` *(deterministic Python scoring engine)*                                                                                                             | `scoring-criteria`, `classification-mapping` |

Key design points aligned to the MAF skills spec: [\[Agent Skil...soft Learn \| Learn.Microsoft.com\]](https://learn.microsoft.com/en-us/agent-framework/agents/skills)

*   **Progressive disclosure** — each agent loads only its skill when the task matches, keeping the context window lean
*   **`@skill.script`** for all KQL generators — the agent calls them with actual IOC values at runtime, producing a ready-to-execute `runHuntingQuery` payload
*   **`@skill.resource`** for classification guides and scoring tables — fetched on-demand, not injected upfront
*   **`score-incident` as a deterministic Python script** — removes LLM subjectivity from the scoring calculation entirely; the Judge Agent receives a numeric score and simply acts on the threshold

Ready to generate the full `function_app.py` with the concurrent orchestrator wiring all four agents? [\[microsofta...epoint.com\]](https://microsoftapc-my.sharepoint.com/personal/tanjoe_microsoft_com/Documents/Microsoft%20Copilot%20Chat%20Files/function_app.py)
