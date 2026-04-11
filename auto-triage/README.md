## 1. Autonomous triage workflow

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

## 2. Identity and access management

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
