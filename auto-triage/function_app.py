import azure.functions as func
import logging
import os
import time
import msal
from httpx import Client
from typing import Annotated, Optional
from pydantic import Field
from agent_framework import AgentExecutorResponse, tool
from agent_framework.foundry import FoundryChatClient
from agent_framework.orchestrations import ConcurrentBuilder
from azure.identity import ManagedIdentityCredential
from azure.identity.aio import ManagedIdentityCredential as AsyncManagedIdentityCredential

instructions = {
  "context": """
    input: Incident ID
    purpose: gather initial incident context for downstream agents to perform hunting and assessment
    task: identify observed entities (IPs, domains, hashes, users, UPNs, hostnames)
    output: a compact JSON object in this exact structure (omit empty lists, explanation/reasoning is not needed):
    {
      "incident_id": "<id>",
      "overview": "<brief concise summary of the incident>",
      "entities": {
        "<IP addresses>": [...],
        "<domains>": [...],
        "<URLs>": [...],
        "<file hashes>": [...],
        "<hostnames>": [...],
        "<users>": [...],
        "<UPNs>": [...]
      }
    }""",
  "related_alerts": """
    input: JSON object containing entity values extracted from a security incident
    purpose: find other alerts that share any observed entities from the incident
    task: use `runHuntingQuery` tool, substituting all entity values into the has_any filter
    query: ```
      SecurityAlert
      | where parse_json(ExtendedProperties).IncidentId != <incident_id> and Entities has_any (<comma-separated values from all entity lists>)
      | summarize count() by AlertName, Description, ProviderName, ProductName, Status, CompromisedEntity```
    timespan: e.g. P3D, P7D
    output: concise report of query results, also use `createCommentForIncident` with (`Related alerts hunt: <report>`)""",
  "threat_intel": """
    input: JSON object containing entity values extracted from a security incident
    purpose: find threat intelligence indicators for IP addresses, domains, URLs, and file hashes observed in the incident
    task: use `runHuntingQuery` tool, substituting all entity values into the in filter
    query: ```
      ThreatIntelIndicators
      | where ObservableValue in (<comma-separated values from all entity lists>)
      | project Modified, ObservableKey, ObservableValue, IsActive, Confidence
      | summarize arg_max(Modified, *) by ObservableValue```
    timespan: e.g. P7D, P30D
    output: concise report of query results, also use `createCommentForIncident` with (`Threat intel hunt: <report>`)""",
  "windows_signin": """
    input: JSON object containing entity values extracted from a security incident
    purpose: find Windows sign-in failures if hostname or user entities exist, otherwise skip this step
    task: use `runHuntingQuery` tool; include only the has_any filters for entity types that are present in the input
    query: ```
      SecurityEvent
      | where EventID == 4625
      | where Computer has_any (<comma-separated hostname values>) or Account has_any (<comma-separated user values>)
      | summarize Accounts=make_set(Account) by Computer, Activity```
    timespan: e.g. P3D, P7D
    output: concise report of query results, also use `createCommentForIncident` with (`Windows sign-in hunt: <report>`)""",
  "linux_signin": """
    input: JSON object containing entity values extracted from a security incident
    purpose: find Linux sign-in failures if hostname or user entities exist, otherwise skip this step
    task: use `runHuntingQuery` tool; include only the has_any filters for entity types that are present in the input
    query: ```
      Syslog
      | where Facility in ('auth', 'authpriv') and ProcessName =~ 'sshd' and SyslogMessage contains 'failed password'
      | where HostName has_any (<comma-separated hostname values>) or SyslogMessage has_any (<comma-separated user values>)
      | summarize SyslogMessages=make_set(SyslogMessage) by HostName```
    timespan: e.g. P3D, P7D
    output: concise report of query results, also use `createCommentForIncident` with (`Linux sign-in hunt: <report>`)""",
  "entra_signin": """
    input: JSON object containing entity values extracted from a security incident
    purpose: find Entra sign-in failures if user or UPN entities exist, otherwise skip this step
    task: use `runHuntingQuery` tool; include only the has_any filters for entity types that are present in the input
    query: ```
      SigninLogs
      | where ResultSignature == 'FAILURE'
      | where Identity has_any (<comma-separated user values>) or UserPrincipalName has_any (<comma-separated upn values>)
      | summarize SigninFailures=make_set(ResultDescription), IPAddresses=make_set(IPAddress) by Identity, UserPrincipalName```
    timespan: e.g. P3D, P7D
    output: concise report of query results, also use `createCommentForIncident` with (`Entra sign-in hunt: <report>`)""",
  "assessment": f"""
    input: aggregated hunting results and incident context in JSON format
    purpose: classify the security incident based on all available evidence and update the incident accordingly
    classification criteria:
      | Classification | Criteria | Action |
      |---|---|---|
      | False Positive (FP) | No malicious indicators, known benign activity | Close |
      | Benign True Positive (BTP) | Real detection but authorized/expected activity | Close |
      | True Positive (TP) | Confirmed malicious indicators or suspicious behavior | Escalate |
      | Suspicious | Inconclusive but warrants investigation | Escalate |
    action: use `updateIncident` and/or `createCommentForIncident` to update the incident
      If FP or BTP:
      - classification: falsePositive or informationalExpectedActivity
      - determination: notMalicious, notEnoughDataToValidate, securityTesting, confirmedUserActivity, or lineOfBusinessApplication
      - assignedTo: {os.environ['ASSIGNEE_RESOLVED']}
      - resolvingComment: Assessment agent: <summary of why the incident is considered FP or BTP>
      - status: resolved
      If TP or Suspicious:
      - classification: truePositive, unknown, or omit
      - determination: multiStagedAttack, malware, maliciousUserActivity, unwantedSoftware, phishing, or compromisedAccount
      - assignedTo: {os.environ['ASSIGNEE_IN_PROGRESS']}
      - resolvingComment: N/A, resolvingComment is only for resolved incidents; use `createCommentForIncident` with (`Assessment: <summary of why the incident is considered TP or Suspicious>`)
      - status: inProgress"""
}

entraurl = f"https://login.microsoftonline.com/{os.environ['ENTRA_TENANT_ID']}"

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def get_mi_token():
  return ManagedIdentityCredential().get_token('api://AzureADTokenExchange/.default').token

def get_agentbp_token():
  agentbp = msal.ConfidentialClientApplication(
    client_id=os.environ['ENTRA_AGENT_BLUEPRINT_ID'],
    client_credential={'client_assertion': get_mi_token()},
    authority=entraurl
  )
  return agentbp.acquire_token_for_client(
    scopes=['api://AzureADTokenExchange/.default'],
    data={'fmi_path': os.environ['ENTRA_AGENT_IDENTITY_ID']}
  )['access_token']

def get_agentid_token():
  agentid = msal.ConfidentialClientApplication(
    client_id=os.environ['ENTRA_AGENT_IDENTITY_ID'],
    client_credential={'client_assertion': get_agentbp_token()},
    authority=entraurl
  )
  return agentid.acquire_token_for_client(
    scopes=['api://AzureADTokenExchange/.default']
  )['access_token']

def get_agentuser_token():
  agentuser = msal.ConfidentialClientApplication(
    client_id=os.environ['ENTRA_AGENT_IDENTITY_ID'],
    client_credential={'client_assertion': get_agentbp_token()},
    authority=entraurl
  )
  return agentuser.acquire_token_for_client(
    scopes=['https://graph.microsoft.com/.default'],
    data={
      'user_id': os.environ['ENTRA_AGENT_USER_ID'],
      'user_federated_identity_credential': get_agentid_token(),
      'grant_type': 'user_fic'
    }
  )['access_token']

def graph_client() -> Client:
  auth_headers = {"Authorization": f"Bearer {get_agentuser_token()}"}
  return Client(headers=auth_headers)

@tool(name='getIncidentWithAlerts', description='Get a security incident with its associated alerts from Microsoft Graph Security API.')
def get_incident_with_alerts(
  incident_id: Annotated[str, Field(description='The ID of the incident to retrieve.')]
) -> dict:
  for attempt in range(5):
    response = graph_client().get(f"https://graph.microsoft.com/v1.0/security/incidents?$filter=id eq '{incident_id}'&$expand=alerts").json()
    if response['value']:
      return response['value'][0]
    else:
      logging.warning('Incident %s not found, retrying in 60s (attempt %d/5)', incident_id, attempt)
      time.sleep(60)
  logging.error('Incident %s not found after 5 attempts', incident_id)
  return {'error': f'Incident {incident_id} not found after 5 attempts'}

@tool(name='createCommentForIncident', description='Create a comment for a security incident in Microsoft Graph Security API.')
def create_comment_for_incident(
  incident_id: Annotated[str, Field(description='The ID of the incident to comment on.')],
  comment: Annotated[str, Field(description='The comment to be added.')]
) -> dict:
  return graph_client().post(f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}/comments", json={'comment': comment}).json()

@tool(name='updateIncident', description='Update a security incident in Microsoft Graph Security API.')
def update_incident(
  incident_id: Annotated[str, Field(description='The ID of the incident to update.')],
  classification: Annotated[Optional[str], Field(description='The classification of the incident.')] = None,
  determination: Annotated[Optional[str], Field(description='Details to incident classification; options: `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedAccount`, `phishing`, `maliciousUserActivity`, `notMalicious`, `notEnoughDataToValidate`, `confirmedUserActivity`, `lineOfBusinessApplication`')] = None,
  assignedTo: Annotated[Optional[str], Field(description='Incident owner: can be group name or user principal name; `null` if not specified')] = None,
  resolvingComment: Annotated[Optional[str], Field(description='Comment to explain the resolution of the incident and the classification choice.')] = None,
  status: Annotated[Optional[str], Field(description='Incident status; options: `active`, `inProgress`, `resolved`, `redirected`')] = None
) -> dict:
  update_data = {k: v for k, v in {
    'classification': classification,
    'determination': determination,
    'assignedTo': assignedTo,
    'resolvingComment': resolvingComment,
    'status': status
  }.items() if v is not None}
  return graph_client().patch(f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}", json=update_data).json()

@tool(name='runHuntingQuery', description='Run a hunting query against Microsoft Graph Security API.')
def run_hunting_query(
  query: Annotated[str, Field(description='KQL query to execute.')],
  timespan: Annotated[str, Field(description='ISO8601 duration (e.g., P7D, P30D).')]
) -> dict:
  logging.info('Running hunting query: %s', query)
  response = graph_client().post('https://graph.microsoft.com/v1.0/security/runHuntingQuery', json={'query': query, 'timespan': timespan}).json()
  if response['results']:
    return response['results']
  else:
    logging.warning('No results returned for query: %s', query)
    return {'results': 'The query returned no results.'}
@app.route(route='triage', methods=['GET'])
async def triage(req: func.HttpRequest) -> func.HttpResponse:
  incident_id = req.params.get('prompt')
  logging.info('Triage request received for incident ID: %s', incident_id)
  async with (AsyncManagedIdentityCredential() as credential):
    foundry = FoundryChatClient(credential=credential)

    # Phase 1: Gather incident context and extract entities as compact JSON
    async with foundry.as_agent(
      name='ContextAgent',
      instructions=instructions['context'],
      tools=[get_incident_with_alerts]
    ) as context_agent:
      context_result = await context_agent.run(f"Incident ID: {incident_id}")
      logging.info('Context result: %s', context_result.text)
    entities_json = context_result.text

    # Phase 2: Run all hunting queries concurrently — each agent handles one query
    async def aggregate_hunting(results: list[AgentExecutorResponse]) -> str:
      sections = []
      for r in results:
        msgs = getattr(r.agent_response, 'messages', [])
        text = msgs[-1].text if msgs else '(no results)'
        sections.append(f"[{r.executor_id}]\n{text}")
      return "\n\n".join(sections)

    hunting_workflow = (
      ConcurrentBuilder(participants=[
        foundry.as_agent(name='RelatedAlertsAgent', instructions=instructions['related_alerts'], tools=[run_hunting_query, create_comment_for_incident]),
        foundry.as_agent(name='ThreatIntelAgent', instructions=instructions['threat_intel'], tools=[run_hunting_query, create_comment_for_incident]),
        foundry.as_agent(name='WindowsSignInAgent', instructions=instructions['windows_signin'], tools=[run_hunting_query, create_comment_for_incident]),
        foundry.as_agent(name='LinuxSignInAgent', instructions=instructions['linux_signin'], tools=[run_hunting_query, create_comment_for_incident]),
        foundry.as_agent(name='EntraSignInAgent', instructions=instructions['entra_signin'], tools=[run_hunting_query, create_comment_for_incident]),
      ])
      .with_aggregator(aggregate_hunting)
      .build()
    )

    hunting_results = None
    async for event in hunting_workflow.run(entities_json, stream=True):
      if event.type == 'output':
        hunting_results = event.data

    # Phase 3: Assess all evidence and update the incident
    assess_prompt = f"Entities and incident context:\n{entities_json}\n\nHunting results:\n{hunting_results}"
    async with foundry.as_agent(
      name='AssessAgent',
      instructions=instructions['assessment'],
      tools=[create_comment_for_incident, update_incident]
    ) as assess_agent:
      assess_result = await assess_agent.run(assess_prompt)

    return func.HttpResponse(assess_result.text)
