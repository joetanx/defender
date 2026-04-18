## 1. Diagrams

### 1.1. Autonomous triage workflow

```mermaid
flowchart LR
  subgraph Sentinel
    I1(Incident)
    subgraph "Logic App (Playbook)"
      I2(Incident ID)
      I3(HTTP trigger)
    end
    I1 -->|Automation rule| I2 --> I3
  end
  subgraph Microsoft Agent Framework
    A1(Context)
    A2(Related alerts)
    A3(Threat indicators)
    A4(Sign-failures)
    A5(Assessment)
  end
  I3 --> A1
  A1 --> A2 --> A5
  A1 --> A3 --> A5
  A1 --> A4 --> A5
  A5 -->|Update incident + comments| I1
```

### 1.2. Identity and access management

```mermaid
flowchart TD
  M("Managed identity (Function)")
  F("Project model<br>(Foundry)")
  A1(Agent ID blueprint)
  A2(Agent identity)
  A3(Agent user)
  G("Graph security API (Defender)")
  M ----->|Azure IAM Role:<br>Cognitive Services User| F
  M -->|Token exchange| A1 -->|Token exchange| A2  -->|Graph API<br>delegated permissions| G
  A2 -->|Token exchange| A3
  A1 -->|Token exchange| A3 -->|Defender unified RBAC roles| G
```

### 1.3. Agents and tools

```mermaid
flowchart LR
  subgraph Agents
    A1(Context)
    A2(Related alerts)
    A3(Threat indicators)
    A4(Sign-failures)
    A5(Assessment)
  end
  subgraph "Tools (Graph security APIs)"
    T1(Get incidents with alerts)
    T2(Run hunting query)
    T3(Create comment for incident)
    T4(Update incident)
  end
  A1 --> T1
  A2 --> T2
  A2 --> T3
  A3 --> T2
  A3 --> T3
  A4 --> T2
  A4 --> T3
  A5 --> T3
  A5 --> T4
```

## 2. Foundry

Get the foundry project endpoint:

![](https://github.com/user-attachments/assets/9bef2460-bf13-40ac-b80f-554660e5303b)

Get the name of the model to be used:

> [!Tip]
>
> The model selected can affect if the workflow runs properly; the mini/nano models can work for smaller incidents, but struggle for large-scale incidents (e.g. many linked alerts, large hunting query results)

![](https://github.com/user-attachments/assets/c1720b9f-d81b-44de-a5b6-4a185138e47e)

Give `Cognitive Services User` permission to function app managed identity:

(this step needs to be performed after the function app is created)

![](https://github.com/user-attachments/assets/033a2994-4cb4-47c0-a962-97244226d90d)

## 3. Function app

> [!Important]
>
> The function app uses Entra Agent User - read up about provisioning Entra Agent Identity objects [here](https://github.com/joetanx/mslab/blob/main/entra/agent-id/provisioning.md)
>
> The IDs of Entra tenant, Agent Bluepint, Agent Identity, Agent User are required in the function app configuration

### 3.1. Create function app

Select `App Service` hosting plan:

![](https://github.com/user-attachments/assets/f639c728-2975-4656-88a2-a3f8423e1b14)

Operating System: Linux

Runtime stack: Python

![](https://github.com/user-attachments/assets/957489af-033b-4a61-932b-45303e6f6e18)

Enable system-assigned managed identity - the agent code uses this MI to authenticate to Foundry and the agent identity blueprint

![](https://github.com/user-attachments/assets/5b192775-3961-4f5b-8ff8-9a226db0f474)

### 3.2. Setup function app

SSH to the function app container: Development Tools → SSH

![](https://github.com/user-attachments/assets/99c79984-2c77-401d-880d-3669c779f8c9)

The following command installs Microsoft Agent Framework at `/home/site/wwwroot/.python_packages/lib/site-packages` (which persists container restarts)

> [!Tip]
>
> It is also possible to use VS Code to deploy the `function_app.py` with `requirements.txt` and let Kudo handle the deployment
>
> But it's simpler to just use manual setup and the Azure code editor for demo

```sh
touch /home/site/wwwroot/function_app.py
echo agent-framework > /home/site/wwwroot/requirements.txt
pip install -r /home/site/wwwroot/requirements.txt --target /home/site/wwwroot/.python_packages/lib/site-packages
```

Paste in the function code: Functions → App files → select `function_app.py` → paste [function_app.py](./function_app.py)

> [!Warning]
>
> Review the code before deploying - the code provides functions agents setup, but it doesn't have production-ready practices like error handling

![](https://github.com/user-attachments/assets/db216953-1bfb-44ad-95ec-e6a391a2dd8c)

Populate the following environment variables:
- `ASSIGNEE_IN_PROGRESS`
- `ASSIGNEE_RESOLVED`
- `ENTRA_AGENT_BLUEPRINT_ID`
- `ENTRA_AGENT_IDENTITY_ID`
- `ENTRA_AGENT_USER_ID`
- `ENTRA_TENANT_ID`
- `FOUNDRY_MODEL`
- `FOUNDRY_PROJECT_ENDPOINT`

> [!Tip]
>
> The environment variables can also be edited as json under `advanced edit`

![](https://github.com/user-attachments/assets/c7f0cfa1-080f-43e6-b0e6-bd8ea2b70e22)

## 4. Sentinel setup

### 4.1. Playbook

Create `Playbook with incident trigger`:

![](https://github.com/user-attachments/assets/ec10feab-3f7a-43ac-bf4d-7b35584334c0)

![](https://github.com/user-attachments/assets/75ee4bdb-5c92-48e1-93f4-7fd231c805f4)

The logic app is configured with Sentinel incident trigger, add `HTTP` action:

URI: `https://<azure-function-domain>/api/<function-name>`

Queries: `prompt`: `Provider Incident Id`

![](https://github.com/user-attachments/assets/d3f7b3ac-0e64-4000-a8a2-895af781c44a)

### 4.2. Automation rule

Trigger: `When incident is created`

Actions: `Run Logic Apps playbook`, select the playbook configured

![](https://github.com/user-attachments/assets/ab46ca67-33bb-496c-9c9f-db182fe55685)
