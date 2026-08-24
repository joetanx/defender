# Deploy AutoSOC

This guide adapts the Microsoft Agent 365 sample deployment procedure for AutoSOC. It provisions Azure AI Foundry, Azure Files, Azure Container Apps, Azure Container Registry, a user-assigned managed identity (UAMI), an Agent 365 identity, and the Logic App authentication path used by `POST /api/triage`.

Run the shell commands in Azure Cloud Shell using Bash. Cloud Shell already includes Azure CLI, .NET, Python, PowerShell, `jq`, and `envsubst`, but its local filesystem is ephemeral. Download the generated Agent 365 configuration files before ending the session.

## 1. Prerequisites

You need:

- An Azure subscription and permission to create resource groups, managed identities, role assignments, storage, Container Apps, Container Registry, and Azure AI Foundry resources.
- A Microsoft 365 tenant enabled for Agent 365/Frontier.
- An account allowed to run `a365 setup requirements` and `a365 setup all`. Tenant setup can require Global Administrator, Agent ID Administrator, or Agent ID Developer roles.
- Application Administrator or Cloud Application Administrator to add a federated identity credential to the Agent 365 blueprint.
- An administrator who can grant Microsoft Graph consent and assign the agentic user a supported security role.
- Microsoft Defender XDR advanced hunting access to the tables AutoSOC queries: `SecurityAlert`, `ThreatIntelIndicators`, `SecurityEvent`, `Syslog`, and `SigninLogs`.
- A Sentinel automation rule and Logic App. Their definitions are external to this repository.

The Graph token used by AutoSOC requires:

| Permission | Type | Purpose |
| --- | --- | --- |
| `SecurityIncident.ReadWrite.All` | Delegated | Read incidents and alerts, add comments, and update incidents |
| `ThreatHunting.Read.All` | Delegated | Run advanced hunting queries |

For delegated incident updates, the agentic user must have a supported role such as **Security Operator** or **Security Administrator**. Apply least privilege appropriate to your tenant.

## 2. Set deployment variables

Select the subscription, choose a globally distinguishable project name, and create the resource group:

```sh
az account set --subscription '<subscription-id>'

export LOCATION='southeastasia'
export PROJECT='autosoc-'$(uuidgen | tr '[:upper:]' '[:lower:]' | head -c 8)
export RG='rg-'$PROJECT
export APP_NAME='autosoc'

az group create --name $RG --location $LOCATION
```

Set application choices. The model name must be available in the selected Foundry region.

```sh
export FOUNDRY_MODEL='gpt-5.6-luna'
export ASSIGNEE_IN_PROGRESS='<soc-queue-or-user>'
export ASSIGNEE_RESOLVED='<soc-queue-or-user>'
export HUNT_WORKSPACES_JSON=''
```

Leave `HUNT_WORKSPACES_JSON` blank to query the Graph caller's primary workspace. To run
`SecurityEvent` and `Syslog` hunts across explicit workspaces, set it to a JSON array:

```sh
export HUNT_WORKSPACES_JSON='[
  {"WorkspaceName":"alpha-soc","WorkspaceId":"5bc2e6fa-f7ac-4f50-8c88-da5a3ddd6e56"},
  {"WorkspaceName":"bravo-soc","WorkspaceId":"64e61c7e-7ee6-4f38-b4f6-f1ca9867968e"}
]'
```

The application rejects malformed JSON, invalid or duplicate workspace IDs, and an explicitly
configured empty array. The Graph identity must have access to every listed workspace.

Register the resource providers once per subscription, then wait until each reports `Registered`:

```sh
for PROVIDER in Microsoft.App Microsoft.OperationalInsights Microsoft.ContainerRegistry Microsoft.Storage Microsoft.CognitiveServices; do
  az provider register --namespace $PROVIDER
done

for PROVIDER in Microsoft.App Microsoft.OperationalInsights Microsoft.ContainerRegistry Microsoft.Storage Microsoft.CognitiveServices; do
  az provider show --namespace $PROVIDER --query registrationState --output tsv
done
```

## 3. Create shared Azure resources

### 3.1. Azure AI Foundry

```sh
export FOUNDRY_NAME='foundry-'$PROJECT
export FOUNDRY_PROJECT='proj-'$PROJECT

az cognitiveservices account create \
  --name $FOUNDRY_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --kind AIServices \
  --sku S0 \
  --custom-domain $FOUNDRY_NAME \
  --yes

az cognitiveservices account project create \
  --name $FOUNDRY_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --project-name $FOUNDRY_PROJECT \
  --display-name $FOUNDRY_PROJECT
```

Create the model deployment:

```sh
MODEL_VERSION=$(az cognitiveservices model list \
  --location $LOCATION \
  --query "[?model.name=='${FOUNDRY_MODEL}' && kind=='AIServices'].model.version | [0]" \
  --output tsv)

test -n "$MODEL_VERSION" || { echo "Model $FOUNDRY_MODEL is unavailable in $LOCATION"; exit 1; }

az cognitiveservices account deployment create \
  --name $FOUNDRY_NAME \
  --resource-group $RG \
  --deployment-name $FOUNDRY_MODEL \
  --model-name $FOUNDRY_MODEL \
  --model-version $MODEL_VERSION \
  --model-format OpenAI \
  --capacity 500 \
  --sku GlobalStandard

export FOUNDRY_PROJECT_ENDPOINT=$(az cognitiveservices account project show \
  --name $FOUNDRY_NAME \
  --resource-group $RG \
  --project-name $FOUNDRY_PROJECT \
  --query properties.endpoints \
  --output tsv)
```

### 3.2. Storage, Container Apps environment, and registry

Storage account and registry names cannot contain dashes and must be globally unique.

```sh
export SA_NAME=$(echo 'stor'$PROJECT | tr -d '-')
export CAE_NAME='cae-'$PROJECT
export ACR_NAME=$(echo 'acr'$PROJECT | tr -d '-')

az storage account create \
  --name $SA_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --sku Standard_LRS \
  --tags SecurityControl=Ignore

az containerapp env create \
  --name $CAE_NAME \
  --resource-group $RG \
  --location $LOCATION

az acr create \
  --name $ACR_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --sku Basic \
  --tags SecurityControl=Ignore

export CAE_ID=$(az containerapp env show \
  --name $CAE_NAME --resource-group $RG --query id --output tsv)
export CAE_DOMAIN=$(az containerapp env show \
  --name $CAE_NAME --resource-group $RG --query properties.defaultDomain --output tsv)
```

## 4. Create the AutoSOC managed identity

```sh
export UAMI_NAME='uami-'$APP_NAME
az identity create --name $UAMI_NAME --resource-group $RG

export UAMI_ID=$(az identity show \
  --name $UAMI_NAME --resource-group $RG --query principalId --output tsv)
export UAMI_CLIENT_ID=$(az identity show \
  --name $UAMI_NAME --resource-group $RG --query clientId --output tsv)
export UAMI_RSC_ID=$(az identity show \
  --name $UAMI_NAME --resource-group $RG --query id --output tsv)
```

Grant the UAMI access to Foundry and permission to pull from ACR:

```sh
FOUNDRY_ID=$(az cognitiveservices account show \
  --name $FOUNDRY_NAME --resource-group $RG --query id --output tsv)
ACR_ID=$(az acr show --name $ACR_NAME --query id --output tsv)

az role assignment create \
  --assignee-object-id $UAMI_ID \
  --assignee-principal-type ServicePrincipal \
  --role 'Cognitive Services User' \
  --scope $FOUNDRY_ID

az role assignment create \
  --assignee-object-id $UAMI_ID \
  --assignee-principal-type ServicePrincipal \
  --role AcrPull \
  --scope $ACR_ID
```

## 5. Create and populate the Azure Files share

The image contains Python dependencies but does not copy the application source. The Container App mounts this share at `/app`.

Run these commands from the AutoSOC repository root containing `app`, `Dockerfile`, and `pyproject.toml`:

```sh
export CONN_STR=$(az storage account show-connection-string \
  --name $SA_NAME --resource-group $RG --query connectionString --output tsv)

az storage share create \
  --name $APP_NAME \
  --connection-string "$CONN_STR"

az storage file upload-batch \
  --destination $APP_NAME \
  --source app \
  --connection-string "$CONN_STR"

SA_KEY=$(az storage account keys list \
  --name $SA_NAME --resource-group $RG --query '[0].value' --output tsv)

az containerapp env storage set \
  --name $CAE_NAME \
  --resource-group $RG \
  --storage-name $APP_NAME \
  --azure-file-account-name $SA_NAME \
  --azure-file-account-key "$SA_KEY" \
  --azure-file-share-name $APP_NAME \
  --access-mode ReadOnly
```

Verify that all four application modules were uploaded:

```sh
az storage file list \
  --share-name $APP_NAME \
  --connection-string "$CONN_STR" \
  --query '[].name' \
  --output table
```

## 6. Build the dependency image

From the repository root:

```sh
az acr build \
  --registry $ACR_NAME \
  --image $APP_NAME:latest \
  --file Dockerfile \
  .
```

## 7. Provision the Agent 365 identity

Install the Agent 365 CLI and verify tenant requirements:

```sh
dotnet tool install --global Microsoft.Agents.A365.DevTools.Cli
export PATH=$PATH:/home/system/.dotnet/tools

a365 setup requirements
```

Provision AutoSOC. The endpoint is registered as metadata for the agent identity; AutoSOC accepts its operational requests only at `/api/triage`.

```sh
export TRIAGE_ENDPOINT="https://$APP_NAME.$CAE_DOMAIN/api/triage"
a365 setup all --aiteammate --agent-name $APP_NAME --messaging-endpoint $TRIAGE_ENDPOINT
```

Keep both generated files:

- `a365.config.json`
- `a365.generated.config.json`

Extract the stable values:

```sh
export TENANT_ID=$(python3 -c "import json; print(json.load(open('a365.config.json'))['tenantId'])")
export BLUEPRINT_CLIENT_ID=$(python3 -c "import json; print(json.load(open('a365.generated.config.json'))['agentBlueprintId'])")
```

AutoSOC also needs the **agent identity/instance ID** and the **agentic user ID**. They are different from the blueprint ID. Agent 365 CLI output and generated field names can vary by version, so inspect the generated values:

```sh
a365 config display -g || jq . a365.generated.config.json
```

Set these values from the provisioning output:

```sh
export AGENTIC_INSTANCE_ID='<agent-identity-or-instance-id>'
export AGENTIC_USER_ID=$(python3 -c "import json; print(json.load(open('a365.generated.config.json')).get('AgenticUserId', ''))")

test -n "$AGENTIC_INSTANCE_ID" || { echo 'AGENTIC_INSTANCE_ID is required'; exit 1; }
test -n "$AGENTIC_USER_ID" || { echo 'AgenticUserId is not available yet'; exit 1; }
```

`AgenticUserId` can be populated only after the agent instance is approved. If it is empty, complete the Agent 365 approval/activation flow in Microsoft 365 Admin Center, allow time for identity creation, then rerun or resume the Agent 365 setup and inspect the generated configuration again. Do not substitute `agentBlueprintId` for `AGENTIC_INSTANCE_ID`; observability rejects that mismatch.

### 7.1. Add the UAMI federated credential

The blueprint trusts the UAMI through a federated identity credential. Use the UAMI **principal ID** as the subject:

```sh
az ad app federated-credential create \
  --id $BLUEPRINT_CLIENT_ID \
  --parameters '{
    "name": "containerapp-uami-fic",
    "issuer": "https://login.microsoftonline.com/'"$TENANT_ID"'/v2.0",
    "subject": "'"$UAMI_ID"'",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

### 7.2. Grant Agent 365 observability permission

From the directory containing the Agent 365 config files, run:

```sh
a365 setup permissions bot --agent-name $APP_NAME
```

If your CLI version does not expose that command, add both delegated and application `Agent365.Observability.OtelWrite` permissions to the blueprint app and grant admin consent. The Agent 365 resource application ID is `9b975845-388f-4429-889e-eab1ef63949c`.

### 7.3. Grant Microsoft Graph permissions

In Microsoft Entra admin center:

1. Open **App registrations**, then select the blueprint whose application ID is `$BLUEPRINT_CLIENT_ID`.
2. Open **API permissions** and add Microsoft Graph delegated permissions `SecurityIncident.ReadWrite.All` and `ThreatHunting.Read.All`.
3. Grant tenant-wide administrator consent.
4. Assign the provisioned agentic user the required Defender/Entra security role and verify it can access every hunting table listed in the prerequisites.

AutoSOC requests `https://graph.microsoft.com/.default`, so missing consent does not appear until the first background triage exchanges and uses its Graph token.

## 8. Configure the Logic App identity and API audience

Enable a system-assigned or user-assigned managed identity on the Logic App and export its **client ID**:

```sh
export LOGIC_APP_MI_CLIENT_ID='<logic-app-managed-identity-client-id>'
```

Configure the blueprint app as the AutoSOC API audience. In its **Expose an API** page, set the application ID URI to:

```text
api://<BLUEPRINT_CLIENT_ID>
```

Configure the Logic App HTTP action that calls AutoSOC:

| Setting | Value |
| --- | --- |
| Method | `POST` |
| URI | `https://<APP_NAME>.<CAE_DOMAIN>/api/triage` |
| Authentication | Managed identity |
| Audience | `api://<BLUEPRINT_CLIENT_ID>` |
| Header | `Content-Type: application/json` |
| Body | `{"incidentId":"<Sentinel incident ID>"}` |

If the API is configured to require assignment, define an application role for invocation and assign that role to the Logic App managed identity. AutoSOC independently enforces `AUTOSOC_CALLER_IDS`, so the managed identity client ID must match `LOGIC_APP_MI_CLIENT_ID` in the deployment manifest.

The caller must send the Defender incident's Graph/Sentinel incident ID, not an alert ID or Azure resource ID.

## 9. Deploy the Container App

Confirm every manifest placeholder has a value:

```sh
for NAME in LOCATION RG APP_NAME UAMI_RSC_ID CAE_ID ACR_NAME \
  FOUNDRY_PROJECT_ENDPOINT FOUNDRY_MODEL UAMI_CLIENT_ID \
  ASSIGNEE_IN_PROGRESS ASSIGNEE_RESOLVED LOGIC_APP_MI_CLIENT_ID \
  AGENTIC_INSTANCE_ID AGENTIC_USER_ID TENANT_ID BLUEPRINT_CLIENT_ID; do
  test -n "$(printenv $NAME)" || { echo "Missing $NAME"; exit 1; }
done
```

Substitute the environment variables and fail if any placeholder remains:

```sh
envsubst < containerapp.yaml > containerapp-edited.yaml

if grep -n '\${[^}]*}' containerapp-edited.yaml; then
  echo 'Unresolved containerapp.yaml placeholders remain'
  exit 1
fi

az containerapp create \
  --name $APP_NAME \
  --resource-group $RG \
  --yaml containerapp-edited.yaml
```

Get the deployed endpoint and check health:

```sh
export APP_FQDN=$(az containerapp show \
  --name $APP_NAME --resource-group $RG \
  --query properties.configuration.ingress.fqdn --output tsv)

curl --fail-with-body "https://$APP_FQDN/api/health"
```

Expected fields include `"status":"ok"`, `"agent_initialized":true`, and `"active_triages":0`.

## 10. Validate an end-to-end triage

1. Select a non-production Defender/Sentinel incident suitable for testing.
2. Run the Logic App with that incident ID.
3. Confirm the HTTP action receives `202 Accepted` with the same `incidentId`.
4. Stream Container App logs:

```sh
az containerapp logs show \
  --name $APP_NAME \
  --resource-group $RG \
  --follow
```

5. Confirm logs show context gathering, each hunt, and triage completion.
6. Verify the incident has AutoSOC hunt comments and the expected status, assignment, classification, and determination.
7. Verify Agent 365 telemetry is visible for the provisioned agent identity.

The `202` response means only that work was accepted. Background failures are logged after the Logic App request has completed.

## 11. Update application code

For the current Azure Files development pattern, upload changed modules and restart the Container App revision:

```sh
az storage file upload-batch \
  --destination $APP_NAME \
  --source app \
  --connection-string "$CONN_STR"

az containerapp revision restart \
  --name $APP_NAME \
  --resource-group $RG \
  --revision $(az containerapp revision list \
    --name $APP_NAME --resource-group $RG \
    --query '[?properties.active].name | [0]' --output tsv)
```

Rebuild the ACR image only when dependencies or the Dockerfile change.

## 12. Troubleshooting

| Symptom | Likely cause | Check |
| --- | --- | --- |
| Container fails during startup with `AUTOSOC_CALLER_IDS` error | Logic App client ID was empty during substitution | Inspect the Container App environment and `LOGIC_APP_MI_CLIENT_ID` |
| `/api/triage` returns `401` | JWT signature or audience validation failed | Logic App authentication must use audience `api://<BLUEPRINT_CLIENT_ID>` |
| `/api/triage` returns `403` | Valid token, but `azp`/`appid` is not allowlisted | Compare token caller claim with `AUTOSOC_CALLER_IDS` |
| Request returns `202`, then triage fails immediately | Agent identity/user, FIC, Graph consent, or role is missing | Inspect logs around `get_agentic_user_token` |
| Graph incident reads or updates return `403` | `SecurityIncident.ReadWrite.All` consent or security role is missing | Check blueprint delegated consent and agentic user role |
| Hunting returns `403` or table errors | `ThreatHunting.Read.All` or table access is missing | Test access to all five query tables with the agentic identity |
| Foundry model call fails | UAMI configuration, Foundry role, endpoint, or model name is wrong | Check `UAMI_CLIENT_ID`, Foundry role assignment, endpoint, and deployment |
| Observability exporter returns `403 agent-ID-mismatch` | Blueprint ID was used as the agent instance ID | Set `AGENTIC_INSTANCE_ID` to the provisioned agent identity/instance ID |
| Health endpoint works but source import fails after restart | Azure Files share is empty or mounted incorrectly | List the share and inspect the `/app` volume/storage registration |
| Duplicate incidents run after restart | Duplicate tracking and checkpoints are in memory | This is expected; use durable orchestration for restart-safe idempotency |

## 13. Production hardening

Before production use:

- Bake application source into an immutable image instead of mounting Azure Files read-only.
- Add durable job state and idempotency if incidents must never be retriaged after restart.
- Keep one replica unless shared concurrency and idempotency controls are added.
- Configure network restrictions, private endpoints, and egress controls appropriate to the tenant.
- Review model and telemetry data retention, region, redaction, and compliance settings.
- Alert on background triage failures because the trigger already received `202`.
- Pin and regularly update Python dependency versions.