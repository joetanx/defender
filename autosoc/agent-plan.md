> Prompt:
> 
> i want to build an agent that performs tier 1 soc analyst role to triage each security incident as they arise in the soc platform. what tasks should the agent perform? what instructions should the agent be given?

## Plan: Tier 1 SOC Triage Agent

**TL;DR**: Add a `POST /triage` route to function_app.py with a purpose-built system prompt that drives the agent through a 5-step triage workflow — retrieve, investigate, classify, act, and document — using the Microsoft Security MCP tools already wired up in the project.

### Tasks the Agent Should Perform

1. **Retrieve** the incident with all associated alerts (`listIncidents` with `$filter=id eq '{id}'` and `$expand=alerts`)
2. **Analyze** the incident context: title, severity, category, detection source, all affected entities (users, devices, IPs, file hashes, URLs)
3. **Hunt** — run targeted KQL queries via `runHuntingQuery` for every entity type:
   - *Users*: anomalous sign-ins, impossible travel, failed auth spikes, privilege escalation
   - *Devices*: suspicious child processes, LOLBin abuse (certutil, powershell, wscript), unsigned binaries dropped to temp/startup, unusual outbound connections
   - *IPs/Domains/Hashes*: threat intel correlation in Defender tables, historical connection volume
   - *Lateral movement*: RDP/SMB fan-out from affected devices
4. **Classify** the incident as one of:
   - `truePositive` — confirmed malicious (malware, phishing, apt, compromisedAccount, multiStagedAttack, etc.)
   - `falsePositive` — benign (securityTesting, clean, lineOfBusinessApplication, confirmedUserActivity)
   - `informationalExpectedActivity` — low-risk known activity
   - *Unresolvable* — escalate to Tier 2 due to insufficient data or high complexity
5. **Act based on verdict**:
   - **True Positive / Unresolvable** → add triage comment, set `status=inProgress`, set `assignedTo=<TIER2_GROUP>`, set classification + determination on incident and each alert
   - **False Positive / Informational** → add explanation comment, set `status=resolved`, set `classification`, `determination`, and `resolvingComment` on incident; update each alert to match
6. **Document** every triage in a structured comment containing: affected entities, KQL queries run and their key findings, verdict, confidence level, rationale, and recommended next steps

### Instructions (System Prompt) the Agent Should Be Given

```
You are a Tier 1 SOC analyst responsible for triaging security incidents in Microsoft Defender XDR.
Your goal is to investigate every incident thoroughly and take a definitive action — resolve false
positives, escalate true threats to Tier 2, or close informational noise.

## Triage Workflow — Follow EVERY step in order

### Step 1 — Retrieve the Incident
Call listIncidents with $filter=id eq '<incidentId>' and $expand=alerts.
Extract: title, description, severity, category, createdDateTime, all alert titles/severities/
         serviceSource, and all affected entities (users, devices, IPs, URLs, file hashes).

### Step 2 — Investigate Entities with Hunting Queries
For EVERY affected entity, run runHuntingQuery to gather context. Cover:

  Users:
  - Anomalous sign-ins (impossible travel, new ASN, unfamiliar country) — last 7 days
  - Failed login spikes (>10 failures in 1 hour)
  - Privileged role assignments or admin operation changes
  - Suspicious email activity: phishing links, macro-enabled attachments

  Devices:
  - Suspicious process trees: cmd/powershell spawned from Office apps, browsers, or services
  - LOLBin usage: certutil, mshta, wscript, regsvr32 with external URIs
  - Files written to %TEMP%, %APPDATA%, Startup folders
  - Outbound connections to new/external destinations on unusual ports
  - Lateral movement: WMI/RDP/SMB connections to other internal hosts within 24h

  IPs / Domains / File Hashes:
  - Match against ThreatIntelligenceIndicator table
  - Connection frequency and unique host count to the same destination

### Step 3 — Classify
Based on all evidence, choose ONE classification:
  truePositive        — confirmed malicious activity
  falsePositive       — confirmed benign, incorrectly flagged
  informationalExpectedActivity — known/expected low-risk activity

  And a determination from the allowed values for each (see updateIncident tool).

  If evidence is ambiguous or conflicting → classify as truePositive / unknown and escalate.

### Step 4 — Act

  TRUE POSITIVE or ESCALATION (insufficient data / high severity / APT indicators):
  1. createCommentForIncident with your full structured triage report
  2. updateIncident: status=inProgress, classification=truePositive (or unknown),
     determination=<your best assessment>, assignedTo=<TIER2_GROUP>
  3. updateAlert for each alert: same classification and determination, status=inProgress

  FALSE POSITIVE or INFORMATIONAL:
  1. createCommentForIncident with your explanation and evidence
  2. updateIncident: status=resolved, classification=falsePositive (or informationalExpectedActivity),
     determination=<assessment>, resolvingComment=<one-line rationale>
  3. updateAlert for each alert: matching classification and determination, status=resolved

### Step 5 — Comment Format
Always write your incident comment in this structure:

  ## T1 SOC Triage — <incident title>
  **Date:** <ISO date> | **Verdict:** <classification> | **Confidence:** High / Medium / Low

  ### Affected Entities
  - Users: ...
  - Devices: ...
  - Network: IPs / domains / hashes

  ### Investigation Findings
  For each KQL query run: state what you queried, what you found (or found nothing), and its significance.

  ### Classification Rationale
  Why this verdict? Cite specific evidence from the alerts and hunting results.

  ### Next Steps
  Recommended actions for Tier 2, or reason for closure.

## Hard Constraints
- NEVER isolate devices, block users, or modify security policies — those require human approval.
- NEVER skip hunting queries — always investigate before classifying.
- If a KQL query fails, log the error in your comment and continue with available data.
- When confidence is Low, always escalate to Tier 2 regardless of classification.
- TIER2_GROUP is defined by the environment variable of the same name.
```

### Code Change — `POST /triage` Route in function_app.py

1. Add a new `@app.route(route='triage', methods=['POST'])` function
2. Extract `incidentId` from the JSON request body
3. Reuse the existing `get_agentuser_token()` + `MCPStreamableHTTPTool` pattern
4. Instantiate `AzureAIClient.as_agent()` with the SOC triage instructions above (pulling `TIER2_GROUP` from env)
5. Run the agent with prompt: `"Triage incident {incidentId}. Follow your full triage workflow."`
6. Return a JSON response with the agent's output

Add one new environment variable: **`TIER2_GROUP`** — the `assignedTo` value for Tier 2 (e.g., `tier2-soc@contoso.com` or a security group name)

**Relevant files**
- function_app.py — add `POST /triage` route alongside `agent` and `hello`

**Verification**
1. POST to `/triage` with a known test incident ID and verify the agent fetches it, runs hunting queries, writes a comment, and updates the incident status correctly in Defender XDR
2. Test with a known false-positive incident — confirm it gets resolved and closed autonomously
3. Test with a high-severity incident — confirm it gets escalated to `TIER2_GROUP` with `inProgress`
4. Check Defender XDR portal to confirm incident comments and status fields are updated correctly

**Decisions**
- Trigger: HTTP POST (called by a Logic App or Defender automation rule webhook)
- Escalation path: `updateIncident` with `assignedTo=TIER2_GROUP`
- Fully autonomous false-positive resolution with no human gate
- `TIER2_GROUP` is an env var so it can be changed without code changes

**Further Considerations**
1. **Automation trigger**: A Logic App or Defender XDR automation rule can call `POST /triage` automatically whenever a new incident is created — worth wiring up as the next step after this agent is working
2. **Rate limiting**: If the full triage (hunting queries) takes longer than the Azure Function default timeout (5 min), consider switching to a Durable Function with an async handoff
3. **Scope of KQL queries**: The `runHuntingQuery` tool targets Defender XDR tables + Sentinel workspaces — if your org doesn't have Sentinel, confirm which tables are populated to avoid empty-result hunts

> Prompt:
> 
> agent architecture: single agent, concurrent agents, fan-out to sub agents then fan-in to orchestrator agent? 
> 
> threat hunting KQL queries: let agent decide? or define common hunting queries in skills?
> 
> microsoft agent framework docs for your reference:
> - sequential workflow: https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/sequential?pivots=programming-language-python
> - concurrent workflow: https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/concurrent?pivots=programming-language-python
> - agent skills: https://learn.microsoft.com/en-us/agent-framework/agents/skills?pivots=programming-language-python



Fetched 3 resources

Now I have full context on the framework. Let me update the plan with a concrete recommendation on both questions. 

Updated memory file [](file:///c%3A/Users/Eisen/AppData/Roaming/Code/User/workspaceStorage/ab2836732d83ab6760687d85c9eccb28/GitHub.copilot-chat/memory-tool/memories/MzQwNTVmMjYtMTRjZC00ZGU1LWI4NjQtMjJlNzA5ZWQ5ZmI5/plan.md)

Here's the analysis and updated plan:

## Architecture Decision: Hybrid Sequential + Concurrent Fan-out

**Recommendation: neither pure single-agent nor pure concurrent — use a 3-stage sequential pipeline with a concurrent fan-out at the investigation step.**

### Why

| Option | Problem for this use case |
|---|---|
| Single agent | Hunting queries for users, devices, and IPs are **independent** — running them sequentially is pure latency waste. A single agent also tries to hold all KQL results + classification logic in one context, which gets noisy. |
| Pure concurrent | Investigation is independent, but retrieval must happen first and classification must happen after — you can't fan everything out from the start. |
| Sequential pipeline | Correct for the outer flow (retrieve → investigate → classify/act), but gives up parallelism during investigation. |
| **Hybrid (recommended)** | Outer `SequentialBuilder` for ordered gates; inner `ConcurrentBuilder` fan-out for investigation. Matches the framework's composability model precisely. |

### The Architecture

```
POST /triage
     │
     ▼
[1] RetrieverAgent          (sequential step 1)
     – listIncidents + $expand=alerts
     – extracts all entities, sets up context

     │ full conversation passed to next step
     ▼
[2] HunterExecutor          (sequential step 2 — custom Executor wrapping ConcurrentBuilder)
     ├──► UserHunterAgent       (concurrent)
     │     – loads user-hunting skill
     │     – runs KQL for sign-in anomalies, privilege escalation, phishing
     ├──► DeviceHunterAgent     (concurrent)
     │     – loads device-hunting skill
     │     – runs KQL for suspicious processes, LOLBins, lateral movement
     └──► NetworkHunterAgent    (concurrent)
          – loads network-hunting skill
          – runs KQL for IP/domain/hash TI correlation, exfil patterns

     │ all 3 results aggregated into conversation
     ▼
[3] ClassifierAgent         (sequential step 3)
     – sees full context: incident + alerts + all hunting findings
     – classifies, calls updateIncident/updateAlert, writes structured comment
```

The `HunterExecutor` is a custom [`Executor`](https://learn.microsoft.com/en-us/agent-framework/workflows/orchestrations/concurrent?pivots=programming-language-python#advanced-custom-agent-executors) that receives the retriever's output, launches `ConcurrentBuilder([user_hunter, device_hunter, network_hunter])` internally, aggregates the three hunting reports into a single summary message, then hands that to the classifier.

## KQL Queries Decision: Skills (with agent-substituted entity values)

**Recommendation: define KQL templates in skills, not in the system prompt and not left entirely to the agent.**

### Why not let the agent decide everything

- LLMs write plausible-looking KQL that may be subtly wrong (wrong table names, incorrect operators, missing `project` columns)
- No coverage guarantee — the agent may omit a hunting check depending on context window drift
- Not auditable — you can't tell a SOC manager "we always check X" if it's up to the model each time
- SOC triage is a **runbook-driven** process — skills are the exact right abstraction for runbooks

### Why skills fit perfectly

The framework's **progressive disclosure** pattern maps directly to how runbooks work:
1. Skills are advertised to all hunter agents at startup (~100 tokens each — cheap)
2. Each hunter agent calls `load_skill` for its domain — gets the full KQL template library
3. The agent substitutes actual entity values into the templates and calls `runHuntingQuery`
4. If the agent detects something unusual it can augment with an ad-hoc query — the skill is a floor, not a ceiling

### Skill layout

```
skills/
├── user-hunting/
│   ├── SKILL.md           ← instructions + KQL templates for user entity investigation
│   └── references/
│       └── kql-tables.md  ← Defender table reference (SigninLogs, AADUserRiskEvents, etc.)
├── device-hunting/
│   ├── SKILL.md           ← instructions + KQL templates for device investigation
│   └── references/
│       └── kql-tables.md  ← DeviceProcessEvents, DeviceNetworkEvents, etc.
└── network-hunting/
    ├── SKILL.md           ← instructions + KQL templates for IP/domain/hash investigation
    └── references/
        └── kql-tables.md  ← ThreatIntelligenceIndicator, DeviceNetworkEvents, etc.
```

## Updated Implementation Plan

### Phase 1 — Skill files (`skills/` directory)
1. Create `skills/user-hunting/SKILL.md` — YAML frontmatter + user entity KQL playbook (anomalous sign-ins, impossible travel, priv escalation, phishing activity, MFA gaps)
2. Create `skills/device-hunting/SKILL.md` — device KQL playbook (process trees, LOLBins, persistence, lateral movement via WMI/RDP/SMB)
3. Create `skills/network-hunting/SKILL.md` — network/TI KQL playbook (ThreatIntelligenceIndicator correlations, exfil patterns, DNS anomalies)

### Phase 2 — Agent definitions
4. `RetrieverAgent` — instructions to fetch incident + alerts and extract + list all entities clearly for downstream agents
5. `UserHunterAgent` — instructions to load `user-hunting` skill, substitute extracted user entities, run queries, return structured findings
6. `DeviceHunterAgent` — same pattern with `device-hunting` skill
7. `NetworkHunterAgent` — same pattern with `network-hunting` skill
8. `HunterExecutor` — custom `Executor` subclass that runs `ConcurrentBuilder([user, device, network])` and aggregates the three reports
9. `ClassifierAgent` — instructions to classify based on all prior context, call `updateIncident`/`updateAlert`, write triage comment

### Phase 3 — `POST /triage` route in function_app.py
10. Add route that:
    - Accepts `{ "incidentId": "..." }` JSON body
    - Constructs `SkillsProvider` pointing to `skills/` directory
    - Wires all 5 agents with `AzureAIClient` + `ms_security_mcp` tools + `skills_provider` context provider
    - Builds `SequentialBuilder([retriever, hunter_executor, classifier]).build()`
    - Runs the workflow, returns the classifier's output as JSON

**New env var**: `TIER2_GROUP`

**Relevant files**
- function_app.py — add `POST /triage` route
- `skills/user-hunting/SKILL.md` — new
- `skills/device-hunting/SKILL.md` — new
- `skills/network-hunting/SKILL.md` — new

**Verification**
1. POST to `/triage` with a test incident ID — trace the workflow: confirm retriever fetches entities, 3 hunters run concurrently (check timing), classifier updates the incident
2. POST with a false-positive incident — confirm resolved/closed with explanation comment
3. POST with a high-severity incident — confirm escalated to `TIER2_GROUP` with `inProgress`
4. Check Defender XDR portal to verify comments, status, classification, determination are all set correctly
5. Confirm all 3 hunter skills are loaded and KQL queries reference actual entity values from the incident (not generic placeholders)

**Decisions**
- `HunterExecutor` wraps `ConcurrentBuilder` — this keeps the sequential outer contract clean while enabling parallelism where it matters
- Skills are the floor; `ClassifierAgent` can still ask hunters to re-query if something is ambiguous
- `SkillsProvider` attached to hunter agents only (not retriever or classifier) to keep their context clean

**Further Considerations**
1. **Function timeout**: 3 concurrent hunters × multiple KQL queries may push past the 5-min Azure Function default on complex incidents. Consider Durable Functions or raising `functionTimeout` in `host.json` to `00:10:00`
2. **Skill granularity**: The 3 skills (user/device/network) can be split further later (e.g., separate `lateral-movement` skill) — starting coarse is fine
3. **KQL table availability**: If the tenant has Sentinel attached, `runHuntingQuery` can target Sentinel workspaces too. The skill's `references/kql-tables.md` should note which tables require Sentinel vs. Defender-only
