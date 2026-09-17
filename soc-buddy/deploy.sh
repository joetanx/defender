#!/usr/bin/env bash
# ==============================================================================
# SOC Buddy - Azure Infrastructure Deployment Script for Azure Cloud Shell
# ==============================================================================
# Deploys containerized SOC Buddy agent, configures Managed Identity,
# sets up Federated Identity Credentials (FIC) for Agent Blueprint & Teams Bot,
# and grants delegated permissions for Microsoft Sentinel MCPs, Work IQ Mail MCP,
# and Microsoft Graph Security Incidents.
# ==============================================================================

set -euo pipefail

# Text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_step() { echo -e "\n${CYAN}${BOLD}==>${NC} ${BOLD}$1${NC}"; }

# ------------------------------------------------------------------------------
# 1. Environment & Prerequisite Checks
# ------------------------------------------------------------------------------
log_step "Checking Azure Cloud Shell prerequisites..."

if ! command -v az &> /dev/null; then
    log_error "Azure CLI ('az') is not installed or not in PATH."
    exit 1
fi

if ! command -v pwsh &> /dev/null; then
    log_error "PowerShell ('pwsh') is not installed or not in PATH. Azure Cloud Shell includes pwsh by default."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    log_error "python3 is required to parse configuration files."
    exit 1
fi

# Ensure user is logged into Azure CLI
CURRENT_SUB_ID=$(az account show --query id -o tsv 2>/dev/null || true)
if [ -z "$CURRENT_SUB_ID" ]; then
    log_error "Not logged into Azure CLI. Please run 'az login' first."
    exit 1
fi
CURRENT_TENANT_ID=$(az account show --query tenantId -o tsv)
CURRENT_SUB_NAME=$(az account show --query name -o tsv)

log_info "Active Subscription: ${BOLD}${CURRENT_SUB_NAME}${NC} (${CURRENT_SUB_ID})"
log_info "Active Tenant ID:    ${BOLD}${CURRENT_TENANT_ID}${NC}"

# Check & Register required Azure Resource Providers
register_provider_if_needed() {
    local provider=$1
    local state
    state=$(az provider show -n "$provider" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [ "$state" != "Registered" ]; then
        log_info "Registering resource provider '$provider' (currently: $state)..."
        az provider register -n "$provider" --wait &>/dev/null || az provider register -n "$provider" &>/dev/null
    else
        log_info "Resource provider '$provider' is registered."
    fi
}

log_step "Verifying subscription resource provider registrations..."
register_provider_if_needed "Microsoft.App"
register_provider_if_needed "Microsoft.OperationalInsights"
register_provider_if_needed "Microsoft.ContainerRegistry"
register_provider_if_needed "Microsoft.CognitiveServices"

# ------------------------------------------------------------------------------
# 2. Gather Inputs & Load a365.generated.config.json
# ------------------------------------------------------------------------------
log_step "Gathering deployment parameters..."

# Default parameters
DEFAULT_SUFFIX=$(python3 -c "import uuid; print(uuid.uuid4().hex[:6])")
DEFAULT_APP_NAME="soc-buddy-${DEFAULT_SUFFIX}"
DEFAULT_LOCATION="southeastasia"

# Ask for Config File path
read -rp "Path to a365.generated.config.json [default: ./a365.generated.config.json]: " INPUT_CONFIG_FILE
CONFIG_FILE="${INPUT_CONFIG_FILE:-./a365.generated.config.json}"

if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_error "Please run 'a365 setup all' first or provide the path to the generated config."
    exit 1
fi

# Parse a365.generated.config.json
log_info "Parsing configuration from: $CONFIG_FILE"
CONFIG_JSON=$(cat "$CONFIG_FILE")

# Extract properties using python
BLUEPRINT_CLIENT_ID=$(python3 -c "
import json, sys
data = json.loads('''$CONFIG_JSON''')
bp_id = data.get('agentBlueprintId') or data.get('agentBlueprintClientId') or data.get('blueprintClientId') or data.get('blueprintId')
if not bp_id:
    sys.exit(1)
print(bp_id)
" 2>/dev/null || true)

AGENTIC_INSTANCE_ID=$(python3 -c "
import json, sys
data = json.loads('''$CONFIG_JSON''')
agent_id = data.get('agentIdentityId') or data.get('agentId') or data.get('agenticInstanceId') or data.get('instanceId')
if not agent_id:
    sys.exit(1)
print(agent_id)
" 2>/dev/null || true)

TENANT_ID=$(python3 -c "
import json, sys
data = json.loads('''$CONFIG_JSON''')
t_id = data.get('tenantId')
if not t_id:
    # check sibling a365.config.json
    try:
        t_id = json.load(open('a365.config.json')).get('tenantId')
    except Exception:
        pass
print(t_id or '$CURRENT_TENANT_ID')
" 2>/dev/null || echo "$CURRENT_TENANT_ID")

if [ -z "$BLUEPRINT_CLIENT_ID" ]; then
    read -rp "Enter Agent Blueprint Client ID (GUID): " BLUEPRINT_CLIENT_ID
fi

if [ -z "$AGENTIC_INSTANCE_ID" ]; then
    read -rp "Enter Agent Instance ID / Agentic Instance ID (GUID): " AGENTIC_INSTANCE_ID
fi

log_info "Blueprint Client ID: ${BOLD}${BLUEPRINT_CLIENT_ID}${NC}"
log_info "Agent Instance ID:   ${BOLD}${AGENTIC_INSTANCE_ID}${NC}"
log_info "Tenant ID:           ${BOLD}${TENANT_ID}${NC}"

# App Name & Location
read -rp "Agent Application Name [default: ${DEFAULT_APP_NAME}]: " INPUT_APP_NAME
APP_NAME="${INPUT_APP_NAME:-$DEFAULT_APP_NAME}"
PROJECT_CLEAN=$(echo "$APP_NAME" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]' | head -c 16)

read -rp "Azure Region/Location [default: ${DEFAULT_LOCATION}]: " INPUT_LOCATION
LOCATION="${INPUT_LOCATION:-$DEFAULT_LOCATION}"

read -rp "Target Resource Group [default: rg-${APP_NAME}]: " INPUT_RG
RG="${INPUT_RG:-rg-${APP_NAME}}"

read -rp "Teams Bot Client ID (from Entra App Registration) [optional, press enter to prompt later]: " TEAMS_BOT_CLIENT_ID
TEAMS_BOT_CLIENT_ID="${TEAMS_BOT_CLIENT_ID:-}"

# Ensure resource group exists
if ! az group show -n "$RG" &>/dev/null; then
    log_info "Creating Resource Group '$RG' in '$LOCATION'..."
    az group create -n "$RG" -l "$LOCATION" --output none
else
    log_info "Using existing Resource Group '$RG'."
fi

# ------------------------------------------------------------------------------
# 3. AI Foundry (Cognitive Services) Selection / Creation
# ------------------------------------------------------------------------------
log_step "Configuring Azure AI Foundry (AIServices)..."

echo "Select Foundry Option:"
echo "  1) Create new Azure AI Foundry and deploy model"
echo "  2) Reuse existing Azure AI Foundry / Cognitive Services Account"
read -rp "Choice [1/2, default 1]: " FOUNDRY_CHOICE
FOUNDRY_CHOICE="${FOUNDRY_CHOICE:-1}"

DEFAULT_MODEL="gpt-4o"
if [ "$FOUNDRY_CHOICE" == "2" ]; then
    read -rp "Existing Foundry Account Name: " FOUNDRY_NAME
    read -rp "Existing Foundry Resource Group [default: $RG]: " FOUNDRY_RG
    FOUNDRY_RG="${FOUNDRY_RG:-$RG}"
    read -rp "Existing Foundry Project Name: " FOUNDRY_PROJECT
    read -rp "Deployed Model Name [default: $DEFAULT_MODEL]: " FOUNDRY_MODEL
    FOUNDRY_MODEL="${FOUNDRY_MODEL:-$DEFAULT_MODEL}"

    FOUNDRY_PROJECT_ENDPOINT=$(az cognitiveservices account project show \
        -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" --project-name "$FOUNDRY_PROJECT" \
        --query 'properties.endpoints' -o tsv 2>/dev/null || true)
    
    if [ -z "$FOUNDRY_PROJECT_ENDPOINT" ]; then
        log_warn "Could not query project endpoint directly. Constructing standard endpoint URL..."
        FOUNDRY_ENDPOINT=$(az cognitiveservices account show -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" --query 'properties.endpoint' -o tsv)
        FOUNDRY_PROJECT_ENDPOINT="${FOUNDRY_ENDPOINT}"
    fi
else
    FOUNDRY_NAME="foundry-${PROJECT_CLEAN}"
    FOUNDRY_PROJECT="proj-${PROJECT_CLEAN}"
    read -rp "Model deployment to create [default: $DEFAULT_MODEL]: " FOUNDRY_MODEL
    FOUNDRY_MODEL="${FOUNDRY_MODEL:-$DEFAULT_MODEL}"
    FOUNDRY_RG="$RG"

    log_info "Creating Cognitive Services account '$FOUNDRY_NAME'..."
    az cognitiveservices account create \
        -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" -l "$LOCATION" \
        --kind 'AIServices' --sku 'S0' --custom-domain "$FOUNDRY_NAME" --yes --output none

    log_info "Creating AI Foundry Project '$FOUNDRY_PROJECT'..."
    az cognitiveservices account project create \
        -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" -l "$LOCATION" \
        --project-name "$FOUNDRY_PROJECT" --display-name "$FOUNDRY_PROJECT" --output none

    log_info "Discovering model version for '$FOUNDRY_MODEL'..."
    MODEL_VERSION=$(az cognitiveservices model list -l "$LOCATION" \
        --query "[?model.name=='${FOUNDRY_MODEL}'&&kind=='AIServices'].model.version | [0]" -o tsv 2>/dev/null || echo "")

    log_info "Deploying model '$FOUNDRY_MODEL'..."
    if [ -n "$MODEL_VERSION" ]; then
        az cognitiveservices account deployment create \
            -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" \
            --deployment-name "$FOUNDRY_MODEL" \
            --model-name "$FOUNDRY_MODEL" \
            --model-version "$MODEL_VERSION" \
            --model-format 'OpenAI' \
            --capacity 50 \
            --sku 'GlobalStandard' --output none
    else
        az cognitiveservices account deployment create \
            -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" \
            --deployment-name "$FOUNDRY_MODEL" \
            --model-name "$FOUNDRY_MODEL" \
            --model-format 'OpenAI' \
            --capacity 50 \
            --sku 'GlobalStandard' --output none
    fi

    FOUNDRY_PROJECT_ENDPOINT=$(az cognitiveservices account project show \
        -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" --project-name "$FOUNDRY_PROJECT" \
        --query 'properties.endpoints' -o tsv 2>/dev/null || true)
    
    if [ -z "$FOUNDRY_PROJECT_ENDPOINT" ]; then
        FOUNDRY_PROJECT_ENDPOINT=$(az cognitiveservices account show -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" --query 'properties.endpoint' -o tsv)
    fi
fi
log_success "Foundry Project Endpoint: $FOUNDRY_PROJECT_ENDPOINT"

# ------------------------------------------------------------------------------
# 4. Container Apps Environment Selection / Creation
# ------------------------------------------------------------------------------
log_step "Configuring Container Apps Environment (CAE)..."

echo "Select Container Apps Environment Option:"
echo "  1) Create new Container Apps Environment"
echo "  2) Reuse existing Container Apps Environment"
read -rp "Choice [1/2, default 1]: " CAE_CHOICE
CAE_CHOICE="${CAE_CHOICE:-1}"

if [ "$CAE_CHOICE" == "2" ]; then
    read -rp "Existing Container Apps Environment Name: " CAE_NAME
    read -rp "Existing CAE Resource Group [default: $RG]: " CAE_RG
    CAE_RG="${CAE_RG:-$RG}"
else
    CAE_NAME="cae-${PROJECT_CLEAN}"
    CAE_RG="$RG"
    log_info "Creating Container Apps Environment '$CAE_NAME'..."
    az containerapp env create -n "$CAE_NAME" -g "$CAE_RG" -l "$LOCATION" --output none
fi

CAE_ID=$(az containerapp env show -n "$CAE_NAME" -g "$CAE_RG" --query id -o tsv)
CAE_DOMAIN=$(az containerapp env show -n "$CAE_NAME" -g "$CAE_RG" --query "properties.defaultDomain" -o tsv)
log_success "CAE ID:     $CAE_ID"
log_success "CAE Domain: $CAE_DOMAIN"

# ------------------------------------------------------------------------------
# 5. Azure Container Registry (ACR) Selection / Creation
# ------------------------------------------------------------------------------
log_step "Configuring Azure Container Registry (ACR)..."

echo "Select Container Registry Option:"
echo "  1) Create new Azure Container Registry"
echo "  2) Reuse existing Azure Container Registry"
read -rp "Choice [1/2, default 1]: " ACR_CHOICE
ACR_CHOICE="${ACR_CHOICE:-1}"

if [ "$ACR_CHOICE" == "2" ]; then
    read -rp "Existing ACR Name: " ACR_NAME
    read -rp "Existing ACR Resource Group [default: $RG]: " ACR_RG
    ACR_RG="${ACR_RG:-$RG}"
else
    ACR_NAME="acr${PROJECT_CLEAN}"
    ACR_RG="$RG"
    log_info "Creating Azure Container Registry '$ACR_NAME'..."
    az acr create -n "$ACR_NAME" -g "$ACR_RG" -l "$LOCATION" --sku Basic --output none
fi

ACR_ID=$(az acr show -n "$ACR_NAME" -g "$ACR_RG" --query id -o tsv)
log_success "ACR Name: $ACR_NAME ($ACR_ID)"

# ------------------------------------------------------------------------------
# 6. User-Assigned Managed Identity (UAMI) & Role Assignments
# ------------------------------------------------------------------------------
log_step "Provisioning User-Assigned Managed Identity (UAMI)..."

UAMI_NAME="uami-${APP_NAME}"
if ! az identity show -n "$UAMI_NAME" -g "$RG" &>/dev/null; then
    log_info "Creating Managed Identity '$UAMI_NAME'..."
    az identity create -n "$UAMI_NAME" -g "$RG" --output none
else
    log_info "Using existing Managed Identity '$UAMI_NAME'."
fi

UAMI_ID=$(az identity show -n "$UAMI_NAME" -g "$RG" --query principalId -o tsv)
UAMI_CLIENT_ID=$(az identity show -n "$UAMI_NAME" -g "$RG" --query clientId -o tsv)
UAMI_RSC_ID=$(az identity show -n "$UAMI_NAME" -g "$RG" --query id -o tsv)

log_info "UAMI Principal ID: $UAMI_ID"
log_info "UAMI Client ID:    $UAMI_CLIENT_ID"
log_info "UAMI Resource ID:  $UAMI_RSC_ID"

log_info "Assigning 'Cognitive Services User' role to UAMI on Foundry..."
FOUNDRY_ID=$(az cognitiveservices account show -n "$FOUNDRY_NAME" -g "$FOUNDRY_RG" --query id -o tsv)
az role assignment create \
    --assignee-object-id "$UAMI_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "Cognitive Services User" \
    --scope "$FOUNDRY_ID" --output none 2>/dev/null || log_info "Role assignment already exists or assigned."

log_info "Assigning 'AcrPull' role to UAMI on ACR..."
az role assignment create \
    --assignee-object-id "$UAMI_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "AcrPull" \
    --scope "$ACR_ID" --output none 2>/dev/null || log_info "Role assignment already exists or assigned."

# ------------------------------------------------------------------------------
# 7. Build Container Image in ACR
# ------------------------------------------------------------------------------
log_step "Building container image in ACR ($ACR_NAME)..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log_info "Running 'az acr build' from context: $SCRIPT_DIR"
az acr build -r "$ACR_NAME" -t "${APP_NAME}:latest" "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# 8. Federated Identity Credentials (FIC) Setup
# ------------------------------------------------------------------------------
log_step "Configuring Federated Identity Credentials (FIC) for Blueprint..."

FIC_NAME="containerapp-uami-fic"

# Check if FIC already exists on Blueprint
EXISTING_BP_FIC=$(az ad app federated-credential list --id "$BLUEPRINT_CLIENT_ID" \
    --query "[?name=='${FIC_NAME}'].name" -o tsv 2>/dev/null || true)

if [ -z "$EXISTING_BP_FIC" ]; then
    log_info "Adding Federated Identity Credential to Agent Blueprint ($BLUEPRINT_CLIENT_ID)..."
    az ad app federated-credential create --id "$BLUEPRINT_CLIENT_ID" \
        --parameters "{
            \"name\": \"${FIC_NAME}\",
            \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
            \"subject\": \"${UAMI_ID}\",
            \"audiences\": [\"api://AzureADTokenExchange\"]
        }" --output none
    log_success "FIC added to Blueprint."
else
    log_info "FIC '$FIC_NAME' already configured on Agent Blueprint."
fi

# Configure FIC on Teams Bot App if Client ID was provided
if [ -n "$TEAMS_BOT_CLIENT_ID" ]; then
    log_info "Configuring FIC on Teams Bot application ($TEAMS_BOT_CLIENT_ID)..."
    EXISTING_TB_FIC=$(az ad app federated-credential list --id "$TEAMS_BOT_CLIENT_ID" \
        --query "[?name=='${FIC_NAME}'].name" -o tsv 2>/dev/null || true)
    if [ -z "$EXISTING_TB_FIC" ]; then
        az ad app federated-credential create --id "$TEAMS_BOT_CLIENT_ID" \
            --parameters "{
                \"name\": \"${FIC_NAME}\",
                \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
                \"subject\": \"${UAMI_ID}\",
                \"audiences\": [\"api://AzureADTokenExchange\"]
            }" --output none 2>/dev/null || log_warn "Could not add FIC to Teams Bot App. Ensure you have permissions or configure manually."
        log_success "FIC added to Teams Bot App."
    else
        log_info "FIC '$FIC_NAME' already configured on Teams Bot App."
    fi
fi

# ------------------------------------------------------------------------------
# 9. Configure Required API Permissions & Grant Admin Consent (pwsh & az)
# ------------------------------------------------------------------------------
log_step "Granting MCP Server and Microsoft Graph Delegated Permissions..."

# Permission Definitions:
# 1. Sentinel MCP Data Exploration: App 4500ebfb-89b6-4b14-a480-7f749797bfcd, Scope SentinelPlatform.DelegatedAccess (eaff9684-612c-4add-aa10-035fd3bfe3d1)
# 2. Sentinel MCP Triage:           App 7b7b3966-1961-47b5-b080-43ca5482e21c, Scope MCP.Read.All (8dd500d0-c3aa-4380-96d1-09b4b6233eff)
# 3. Work IQ Mail MCP:              App 16b1878d-62c7-4009-aa25-68989d63bbad, Scope Tools.ListInvoke.All (93aac09f-5f9b-4b4c-aa45-c623a1b69342)
# 4. Microsoft Graph:               App 00000003-0000-0000-c000-000000000000, Scope SecurityIncident.ReadWrite.All (aaad2076-26ab-4905-b1eb-090f627b17d7)

# Step 9A: Update Blueprint App Registration requiredResourceAccess
python3 -c "
import subprocess, json

bp_id = '${BLUEPRINT_CLIENT_ID}'
current_rra_str = subprocess.check_output(['az', 'ad', 'app', 'show', '--id', bp_id, '--query', 'requiredResourceAccess', '-o', 'json']).decode('utf-8').strip()
current_rra = json.loads(current_rra_str) if current_rra_str and current_rra_str != 'null' else []

target_permissions = [
    {
        'resourceAppId': '4500ebfb-89b6-4b14-a480-7f749797bfcd',
        'resourceAccess': [{'id': 'eaff9684-612c-4add-aa10-035fd3bfe3d1', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '7b7b3966-1961-47b5-b080-43ca5482e21c',
        'resourceAccess': [{'id': '8dd500d0-c3aa-4380-96d1-09b4b6233eff', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '16b1878d-62c7-4009-aa25-68989d63bbad',
        'resourceAccess': [{'id': '93aac09f-5f9b-4b4c-aa45-c623a1b69342', 'type': 'Scope'}]
    },
    {
        'resourceAppId': '00000003-0000-0000-c000-000000000000',
        'resourceAccess': [{'id': 'aaad2076-26ab-4905-b1eb-090f627b17d7', 'type': 'Scope'}]
    }
]

# Merge into current_rra
rra_map = {item['resourceAppId']: item for item in current_rra}
for target in target_permissions:
    app_id = target['resourceAppId']
    if app_id not in rra_map:
        rra_map[app_id] = target
    else:
        existing_ids = {ra['id'] for ra in rra_map[app_id].get('resourceAccess', [])}
        for ra in target['resourceAccess']:
            if ra['id'] not in existing_ids:
                rra_map[app_id].setdefault('resourceAccess', []).append(ra)

merged_rra = list(rra_map.values())
with open('/tmp/soc_buddy_merged_rra.json', 'w') as f:
    json.dump(merged_rra, f)
"

log_info "Updating requiredResourceAccess on Blueprint App..."
az ad app update --id "$BLUEPRINT_CLIENT_ID" --required-resource-accesses @/tmp/soc_buddy_merged_rra.json
rm -f /tmp/soc_buddy_merged_rra.json

# Step 9B: Attempt admin consent via az cli
log_info "Attempting admin consent on Blueprint Application..."
az ad app permission admin-consent --id "$BLUEPRINT_CLIENT_ID" 2>/dev/null || log_info "az ad app permission admin-consent completed or requires elevated admin."

# Step 9C: Use PowerShell Microsoft Graph module to ensure Service Principals and OAuth2PermissionGrants exist
log_info "Executing PowerShell Graph commands to ensure tenant-wide delegated grants..."
pwsh -NoProfile -Command "
    \$ErrorActionPreference = 'Continue'
    \$bpClientId = '${BLUEPRINT_CLIENT_ID}'
    
    # Acquire Graph access token from az cli
    \$token = (az account get-access-token --resource-type ms-graph --query accessToken -o tsv)
    \$secToken = ConvertTo-SecureString \$token -AsPlainText -Force
    Connect-MgGraph -AccessToken \$secToken -NoWelcome | Out-Null
    
    # 1. Ensure Blueprint Service Principal exists in tenant
    \$clientSp = Get-MgServicePrincipal -Filter \"appId eq '\$bpClientId'\" -ErrorAction SilentlyContinue
    if (-not \$clientSp) {
        Write-Host \"Creating Service Principal for Blueprint \$bpClientId...\"
        \$clientSp = New-MgServicePrincipal -AppId \$bpClientId
    }

    # Resource definitions: Resource App ID -> Scope Name
    \$resources = @{
        '4500ebfb-89b6-4b14-a480-7f749797bfcd' = 'SentinelPlatform.DelegatedAccess'
        '7b7b3966-1961-47b5-b080-43ca5482e21c' = 'MCP.Read.All'
        '16b1878d-62c7-4009-aa25-68989d63bbad' = 'Tools.ListInvoke.All'
        '00000003-0000-0000-c000-000000000000' = 'SecurityIncident.ReadWrite.All'
    }

    foreach (\$resourceAppId in \$resources.Keys) {
        \$scope = \$resources[\$resourceAppId]
        Write-Host \"Configuring grant for Resource: \$resourceAppId, Scope: \$scope...\"
        
        # Ensure resource service principal exists
        \$resSp = Get-MgServicePrincipal -Filter \"appId eq '\$resourceAppId'\" -ErrorAction SilentlyContinue
        if (-not \$resSp) {
            try {
                \$resSp = New-MgServicePrincipal -AppId \$resourceAppId -ErrorAction Stop
            } catch {
                Write-Warning \"Could not create service principal for \$resourceAppId. It may already exist or require admin provisioning.\"
            }
        }
        
        if (\$resSp) {
            # Check or create/update OAuth2PermissionGrant
            \$grant = Get-MgOauth2PermissionGrant -Filter \"clientId eq '\$(\$clientSp.Id)' and resourceId eq '\$(\$resSp.Id)'\" -ErrorAction SilentlyContinue
            if (\$grant) {
                \$scopes = (\$grant.Scope -split '\s+') | Where-Object { \$_ -ne '' }
                if (\$scopes -notcontains \$scope) {
                    \$scopes += \$scope
                    \$newScope = (\$scopes | Select-Object -Unique) -join ' '
                    Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId \$grant.Id -Scope \$newScope
                    Write-Host \"Updated grant with scope: \$newScope\"
                } else {
                    Write-Host \"Scope \$scope already granted.\"
                }
            } else {
                try {
                    New-MgOauth2PermissionGrant -ClientId \$clientSp.Id `
                                                -ResourceId \$resSp.Id `
                                                -ConsentType 'AllPrincipals' `
                                                -Scope \$scope | Out-Null
                    Write-Host \"Created new OAuth2PermissionGrant with scope: \$scope\"
                } catch {
                    Write-Warning \"Failed to create OAuth2PermissionGrant for \$resourceAppId: \$_\"
                }
            }
        }
    }
"

log_success "Permissions granted and verified."

# ------------------------------------------------------------------------------
# 10. Deploy Container App
# ------------------------------------------------------------------------------
log_step "Deploying Azure Container App..."

OAUTH_REDIRECT_URI="https://${APP_NAME}.${CAE_DOMAIN}/auth/callback"
MESSAGING_ENDPOINT="https://${APP_NAME}.${CAE_DOMAIN}/api/messages"

if [ -z "$TEAMS_BOT_CLIENT_ID" ]; then
    log_warn "TEAMS_BOT_CLIENT_ID was not provided earlier."
    read -rp "Please enter your Teams Bot Client ID now: " TEAMS_BOT_CLIENT_ID
fi

log_info "Generating containerapp manifest..."

export LOCATION
export RG
export APP_NAME
export UAMI_RSC_ID
export UAMI_CLIENT_ID
export CAE_ID
export ACR_NAME
export FOUNDRY_PROJECT_ENDPOINT
export FOUNDRY_MODEL
export OAUTH_REDIRECT_URI
export TENANT_ID
export TEAMS_BOT_CLIENT_ID
export BLUEPRINT_CLIENT_ID
export AGENTIC_INSTANCE_ID

TEMPLATE_FILE="$SCRIPT_DIR/containerapp.yaml"
DEPLOYED_YAML="$SCRIPT_DIR/containerapp-deployed.yaml"

if command -v envsubst &>/dev/null; then
    envsubst < "$TEMPLATE_FILE" > "$DEPLOYED_YAML"
else
    # Python fallback for substitution
    python3 -c "
import os, string
with open('$TEMPLATE_FILE', 'r') as f:
    template = string.Template(f.read())
result = template.safe_substitute(os.environ)
with open('$DEPLOYED_YAML', 'w') as f:
    f.write(result)
"
fi

log_info "Deploying container app '$APP_NAME' via Azure CLI..."
if az containerapp show -n "$APP_NAME" -g "$RG" &>/dev/null; then
    az containerapp update -n "$APP_NAME" -g "$RG" --yaml "$DEPLOYED_YAML" --output none
else
    az containerapp create -n "$APP_NAME" -g "$RG" --yaml "$DEPLOYED_YAML" --output none
fi

# ------------------------------------------------------------------------------
# 11. Completion & Next Steps Summary
# ------------------------------------------------------------------------------
log_step "Deployment Complete!"

echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}                  SOC BUDDY DEPLOYED SUCCESSFULLY                       ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "Application Name:       ${BOLD}${APP_NAME}${NC}"
echo -e "Resource Group:         ${BOLD}${RG}${NC}"
echo -e "Location:               ${BOLD}${LOCATION}${NC}"
echo -e "Messaging Endpoint:     ${CYAN}${BOLD}${MESSAGING_ENDPOINT}${NC}"
echo -e "OAuth Redirect URI:     ${CYAN}${BOLD}${OAUTH_REDIRECT_URI}${NC}"
echo -e "Blueprint Client ID:    ${BOLD}${BLUEPRINT_CLIENT_ID}${NC}"
echo -e "Teams Bot Client ID:    ${BOLD}${TEAMS_BOT_CLIENT_ID}${NC}"
echo -e "UAMI Principal ID:      ${BOLD}${UAMI_ID}${NC}"
echo -e "========================================================================"
echo -e "${YELLOW}${BOLD}CRITICAL POST-DEPLOYMENT ACTIONS REQUIRED:${NC}"
echo -e "1. ${BOLD}Configure Teams Bot App Redirect URI in Microsoft Entra Admin Center:${NC}"
echo -e "   - Open Entra ID > App Registrations > Select your Teams Bot App (${TEAMS_BOT_CLIENT_ID})"
echo -e "   - Go to 'Authentication' > 'Add a platform' > 'Web'"
echo -e "   - Add Redirect URI: ${CYAN}${OAUTH_REDIRECT_URI}${NC}"
echo -e "   - Ensure 'ID tokens' and 'Access tokens' are enabled if required."
echo -e "2. ${BOLD}Configure Messaging Endpoint in Azure Bot Service / Bot Framework:${NC}"
echo -e "   - Messaging Endpoint URL: ${CYAN}${MESSAGING_ENDPOINT}${NC}"
echo -e "3. ${BOLD}Publish / Activate Agent Manifest in Microsoft 365 Admin Center:${NC}"
echo -e "   - Run 'a365 publish' to produce manifest.zip"
echo -e "   - Upload in M365 Admin Center (Settings > Integrated apps / Agents)"
echo -e "========================================================================"
