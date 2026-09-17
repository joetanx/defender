# SOC Buddy

SOC Buddy is an AI-powered Security Operations Center (SOC) companion for security teams using **Microsoft Sentinel** and **Microsoft Defender XDR**. Built with **Microsoft Agent 365**, **LangChain**, and **Azure Container Apps**, SOC Buddy helps analysts triage incidents, execute KQL threat hunts, inspect evidence, manage incident lifecycle states, and draft communications directly within **Microsoft Teams**.

---

## Key Highlights

- **Zero Client Secrets**: Uses Entra Federated Identity Credentials (FIC) and Azure User-Assigned Managed Identity (UAMI) for all service-to-service and agent authentications.
- **Strict On-Behalf-Of (OBO) Access**: All security data queries, incident updates, and email interactions execute under the delegated identity of the signed-in SOC analyst.
- **Remote MCP Tools**: Connects dynamically via Model Context Protocol (MCP) to:
  - Microsoft Sentinel Data Exploration MCP (KQL queries, table inspection)
  - Microsoft Sentinel Defender Triage MCP (Incidents, alerts, entities, evidence)
  - Work IQ Mail MCP (Incident notifications, email threads, drafting updates)
- **Microsoft Graph Security**: Native SDK integration to add comments and patch incident status, assignment, classification, and determination.
- **Enterprise Observability**: Integrated with Microsoft Agent 365 OpenTelemetry for end-to-end tracing and auditing.

---

## Repository Structure

```
soc-buddy/
├── deploy.sh                  # Automated Azure Cloud Shell deployment script
├── SETUP_GUIDE.md             # End-to-end prerequisites and step-by-step setup guide
├── DOCUMENTATION.md           # Architecture, identity flow, and tool catalog reference
├── containerapp.yaml          # Azure Container Apps template definition
├── Dockerfile                 # Multi-stage production container image build
├── pyproject.toml             # Python dependencies and build configuration
└── app/
    └── app.py                 # Core SOC Buddy service application
```

---

## Quick Start

### 1. Provision Agent Identity
Before running the deployment script, provision your Agent 365 identity using the `a365` CLI (in Azure Cloud Shell or locally):
```bash
a365 setup requirements
a365 setup all --aiteammate -n soc-buddy
```
This generates `a365.generated.config.json`. For detailed setup instructions, refer to the [Setup Guide](SETUP_GUIDE.md).

### 2. Deploy Infrastructure via Azure Cloud Shell
Launch [Azure Cloud Shell](https://shell.azure.com) (Bash), clone or upload this repository, ensure `a365.generated.config.json` is in the folder, and run:
```bash
chmod +x deploy.sh
./deploy.sh
```

The script will:
1. Verify resource provider registrations (`Microsoft.App`, `Microsoft.OperationalInsights`, `Microsoft.ContainerRegistry`, `Microsoft.CognitiveServices`).
2. Read your `a365.generated.config.json`.
3. Allow you to create new or reuse existing **Azure AI Foundry**, **Container Apps Environment**, and **Container Registry**.
4. Create a User-Assigned Managed Identity (UAMI) with `Cognitive Services User` and `AcrPull` roles.
5. Build the container image in ACR.
6. Configure Federated Identity Credentials (FIC) on the Agent Blueprint and Teams Bot app registrations.
7. Grant delegated permissions for Sentinel MCPs, Work IQ Mail MCP, and Microsoft Graph Security using Azure CLI and PowerShell Microsoft Graph SDK.
8. Deploy the container app.

### 3. Connect Teams Bot and Publish
- Add the output OAuth Redirect URI (`https://<app>.<domain>/auth/callback`) to your Teams Bot App Registration in Entra.
- Set the Bot messaging endpoint in Azure Bot Service to `https://<app>.<domain>/api/messages`.
- Publish `manifest.zip` in Microsoft 365 Admin Center (`admin.cloud.microsoft/#/agents/all`).

---

## Documentation Links

- **[Setup Guide](SETUP_GUIDE.md)**: Detailed prerequisites, Entra roles, separate setup steps, and troubleshooting.
- **[Technical Architecture & Identity Documentation](DOCUMENTATION.md)**: In-depth breakdown of Bot Framework authentication, human OAuth code flow, Agent Blueprint FIC, OpenTelemetry S2S tokens, OBO token exchanges, and complete tool catalog.
