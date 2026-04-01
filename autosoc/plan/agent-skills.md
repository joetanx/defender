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
