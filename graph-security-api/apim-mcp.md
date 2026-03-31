## 1. Create Azure API management service

> [!Note]
>
> The APIM name must be globally unique as it forms the gateway URL: `https://<apim-name>.azure-api.net`
>
> PowerShell `[guid]::NewGuid()` can help generate random suffix like the one in the screenshot

![](https://github.com/user-attachments/assets/f8b80ce1-568c-425b-b880-514f15b22708)

![](https://github.com/user-attachments/assets/003acbaa-da74-4a27-bcc1-f0a012864f4e)

![](https://github.com/user-attachments/assets/faa3d899-b1b0-451a-b765-919b3391c0dd)

## 2. Create API in APIM

Select [`HTTP`](https://learn.microsoft.com/en-us/azure/api-management/add-api-manually):

![](https://github.com/user-attachments/assets/7724894c-db6a-4d84-bad3-fab36a130636)

This configuration essentially "maps" `https://graph.microsoft.com/v1.0/security` to `https://<apim-name>.azure-api.net/security`
- Web service URL: `https://graph.microsoft.com/v1.0/security`
- API URL suffix: `security`

![](https://github.com/user-attachments/assets/5b0c5361-abb6-440d-b2ec-df52aac68a86)

Graph API is already authentication protected via Entra, there's no need for `Subscription required`:

![](https://github.com/user-attachments/assets/5eef0813-ac09-45e3-98d7-64ac79bdee20)

### 2.1. Create definitions

#### 2.1.1. Comment

Used by:
- [Create comment for alert](#222-create-comment-for-alert)
- [Create comment for incident](#226-create-comment-for-incident)

```json
{
    "type": "object",
    "properties": {
        "comment": {
            "type": "string",
            "description": "The comment to be added."
        }
    },
    "required": [ "comment" ]
}
```

![](https://github.com/user-attachments/assets/dbd97bde-c0fc-486d-b725-75bb5ed0044f)

#### 2.1.2. Alert properties

Used by: [Update alert](#223-update-alert)

```json
{
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "description": "The status of the alert; possible values: `new`, `inProgress`, `resolved`, `unknownFutureValue`."
        },
        "classification": {
            "type": "string",
            "description": "Specifies the classification of the alert; possible values: `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`, `unknownFutureValue`."
        },
        "determination": {
            "type": "string",
            "description": "Specifies the determination of the alert; possible values: `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedUser`, `phishing`, `maliciousUserActivity`, `clean`, `insufficientData`, `confirmedUserActivity`, `lineOfBusinessApplication`, `unknownFutureValue`."
        },
        "assignedTo": {
            "type": "string",
            "description": "Owner of the incident, or `null` if no owner is assigned."
        }
    },
    "required": [ "" ]
}
```

![](https://github.com/user-attachments/assets/02133a81-ba23-4aff-9e3a-4b4dcbc9e09e)

#### 2.1.3. Incident properties

Used by: [Update incident](#227-update-incident)

```json
{
    "type": "object",
    "properties": {
        "status": {
            "type": "string",
            "description": "The status of the incident; possible values: `active`, `inProgress`, `resolved`, `redirected`, `unknownFutureValue`."
        },
        "classification": {
            "type": "string",
            "description": "Specifies the classification of the incident; possible values: `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`, `unknownFutureValue`."
        },
        "determination": {
            "type": "string",
            "description": "Specifies the determination of the incident; possible values: `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedAccount`, `phishing`, `maliciousUserActivity`, `notMalicious`, `notEnoughDataToValidate`, `confirmedUserActivity`, `lineOfBusinessApplication`, `unknownFutureValue`."
        },
        "assignedTo": {
            "type": "string",
            "description": "Owner of the incident; `null` if not specified."
        },
        "resolvingComment": {
            "type": "string",
            "description": "Comment to explain the resolution of the incident and the classification choice."
        }
    },
    "required": [ "" ]
}
```

![](https://github.com/user-attachments/assets/0d9e62d9-21c8-4280-b7e7-055d9ac14807)

#### 2.1.4. Hunting query

Used by: [Run hunting query](#228-run-hunting-query)

```json
{
    "type": "object",
    "properties": {
        "Query": {
            "type": "string",
            "description": "KQL query to execute"
        },
        "Timespan": {
            "type": "string",
            "description": "ISO8601 duration (e.g., P7D) or omit to filter in KQL"
        }
    },
    "required": [ "Query" ]
}
```

![](https://github.com/user-attachments/assets/a5e4d474-1559-4402-a88b-83eee3fefa87)

### 2.2. Create operations

> [!Note]
>
> It is also possible to use wildcard operation to just passthrough everything

#### 2.2.1. List alerts

Description: _Gets a list of alerts in Defender XDR, most recent alerts are on top. Provide OData query parameters to filter response._

Query parameters:

|Name|Description|Type|
|---|---|---|
|`$count`|Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response.|boolean|
|`$filter`|Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, and `status`. Example: `status eq 'new' and createdDateTime ge 2026-03-01T23:559:59Z`.|string|
|`$skip`|Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest.|integer|
|`$top`|Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items.|integer|

![](https://github.com/user-attachments/assets/ee3f5722-523c-46db-8bbe-866e6a4977e9)

#### 2.2.2. Create comment for alert

Description: _Add a comment to an alert._

Template (URL) parameter:

|Name|Description|Type|
|---|---|---|
|`alertId`|ID of the intended alert; use `id`, not `providerAlertId` from list tools results.|string|

![](https://github.com/user-attachments/assets/a91d6052-d1f4-4b25-9fdc-bfbb77d6e5d3)

##### Request

Body description: Provide JSON object with 1 parameter: `comment` (**Required**)

Representation:

|Content type|Sample|Definition|
|---|---|---|
|`application/json`|<pre><code>{ "comment": "IP address reputation found suspicious" }</pre></code>|[comment](#211-comment)|

![](https://github.com/user-attachments/assets/4f89612b-c08c-49a6-83d1-d04cdeacbc0d)

#### 2.2.3. Update alert

Description: _Update the properties of an alert._

Template (URL) parameter:

|Name|Description|Type|
|---|---|---|
|`alertId`|ID of the intended alert; use `id`, not `providerAlertId` from list tools results.|string|

![](https://github.com/user-attachments/assets/fdc8fa92-8c92-47cd-9149-28ec94656de0)

##### Request

Body description: Provide JSON object with 4 parameters: `status`, `classification`, `determination` and `assignedTo` (ALL _Optional_)

Representation:

|Content type|Sample|Definition|
|---|---|---|
|`application/json`|<pre><code>{ "status": "resolved", "classification": "informationalExpectedActivity", "determination": "securityTesting", "assignedTo": "tanjoe@MngEnvMCAP398230.onmicrosoft.com" }</pre></code>|[alertProperties](#212-alert-properties)|

![](https://github.com/user-attachments/assets/bb15d60a-3aa9-40a6-a29e-4aa119d43705)

#### 2.2.4. List incidents

Description: _Gets a list of incidents in Defender XDR, most recent incidents are on top. Provide OData query parameters to filter response._

Query parameters:

|Name|Description|Type|
|---|---|---|
|`$count`|Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response.|boolean|
|`$filter`|Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, and `status`. Example: `status eq 'new' and createdDateTime ge 2026-03-01T23:559:59Z`.|string|
|`$skip`|Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest.|integer|
|`$top`|Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items.|integer|
|`$expand`|Set to `alerts` to include the alerts related to each incident in the result; omit if alerts are not needed.|string|

![](https://github.com/user-attachments/assets/a664c0a3-9748-49e1-a911-63a06af862bb)

#### 2.2.5. Get incident by ID

Description: _Get an incident using the incident ID. Consider using the list-incident tool with `$filter` for `id` and `$expand` parameters instead to get an incident **with** associated alerts._

Template (URL) parameter:

|Name|Description|Type|
|---|---|---|
|`incidentId`|ID of the intended incident.|integer|

![](https://github.com/user-attachments/assets/c9269470-c0da-4868-9bac-478ae48bce3a)

#### 2.2.6. Create comment for incident

Description: _Add a comment to an incident._

Template (URL) parameter:

|Name|Description|Type|
|---|---|---|
|`incidentId`|ID of the intended incident.|integer|

![](https://github.com/user-attachments/assets/55a30022-5b47-41fc-8845-7bbc5849f666)

##### Request

Body description: Provide JSON object with 1 parameter: `comment` (**Required**)

Representation:

|Content type|Sample|Definition|
|---|---|---|
|`application/json`|<pre><code>{ "comment": "To be escalated, one or more entities found suspicious" }</pre></code>|[comment](#211-comment)|

![](https://github.com/user-attachments/assets/0bbcd755-8bf0-4777-a803-ae2e1ee8a034)

#### 2.2.7. Update incident

Description: _Update the properties of an incident._

Template (URL) parameter:

|Name|Description|Type|
|---|---|---|
|`incidentId`|ID of the intended incident.|integer|

![](https://github.com/user-attachments/assets/76b71239-8828-4423-b648-6afd3b52267d)

##### Request

Body description: Provide JSON object with 5 parameters: `status`, `classification`, `determination`, `assignedTo` and `resolvingComment` (ALL _Optional_)

Representation:

|Content type|Sample|Definition|
|---|---|---|
|`application/json`|<pre><code>{ "status": "inProgress", "classification": "truePositive", "determination": "apt", "assignedTo": "tanjoe@MngEnvMCAP398230.onmicrosoft.com", "resolvingComment": "To be escalated, one or more entities found suspicious" }</pre></code>|[incidentProperties](#213-incident-properties)|

![](https://github.com/user-attachments/assets/9e8d9715-9572-4304-a887-215e0027c7ad)

#### 2.2.8. Run hunting query

Description: _Run an advanced hunting query using KQL on Defender tables and Sentinel workspaces to search security data._

![](https://github.com/user-attachments/assets/441baf9b-209d-45f4-a0cc-a5825e3964e5)

##### Request

Body description: Provide JSON object with 2 parameters: `Query` (**Required**) and `Timespan` (_Optional_)

Representation:

|Content type|Sample|Definition|
|---|---|---|
|`application/json`|<pre><code>{ "Query": "workspace('alpha-soc').Syslog \| where SyslogMessage contains 'failed password'", "Timespan": "P7D"}</pre></code>|[huntingQuery](#214-hunting-query)|

### 2.3. Test access

```pwsh
PS C:\Users\tanjoe> $headers = @{ Authorization='Bearer '+$token.access_token }
PS C:\Users\tanjoe> $endpointuri='https://alpha-a18d6b52.azure-api.net/security/runHuntingQuery'
PS C:\Users\tanjoe> $body=@{
>>   Query = "workspace('alpha-soc').Syslog | where SyslogMessage contains 'failed password'"
>>   Timespan = 'P3D'
>> }
PS C:\Users\tanjoe> Invoke-RestMethod $endpointuri -Method Post -Headers $headers -Body $($body | ConvertTo-Json) -ContentType 'application/json'

@odata.context                                                                          schema                                                                                                                               results
--------------                                                                          ------                                                                                                                               -------
https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.security.huntingQueryResults {@{name=TenantId; type=String}, @{name=SourceSystem; type=String}, @{name=TimeGenerated; type=DateTime}, @{name=MG; type=String}...} {@{TenantId=5bc2e6fa-f7ac-4f50-8c88-da5a3ddd6e56; SourceSystem=LogsIngestionAPI; TimeGenerated=2026-03-04T00:26:03.4989771Z; MG=; Computer=alpha-vm-langflow; EventTime=2026-03-04T00:25:27.2899965Z; ...
```

## 3. Create product

![](https://github.com/user-attachments/assets/bcd8f01a-84a5-4b40-bb9a-06dc80174ca4)

## 4. Create MCP server

![](https://github.com/user-attachments/assets/3eecfcac-d9ca-4e15-90b5-c91e87c38c08)

![](https://github.com/user-attachments/assets/88e143e5-2ba4-4f5e-a3a8-91888b6a6f8d)

### 4.1. Test MCP server

#### 4.1.1. initialize

```sh
json=$(cat << EOF
{
  "method": "initialize",
  "params": {
    "clientInfo": {
      "version": "1.0.0",
      "name": "test-client"
    },
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "roots": {
        "listChanged": true
      }
    }
  },
  "id": 1,
  "jsonrpc": "2.0"
}
EOF
)
curl https://alpha-a18d6b52.azure-api.net/ms-security/mcp -H "Content-Type: application/json" -d "$json"
```

Response:

```
event: message
data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"Azure API Management","version":"1.0.0"}}}

event: close
data:
```

Data [JSON formatted](https://jsonformatter.org/):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "tools": {
        "listChanged": true
      }
    },
    "serverInfo": {
      "name": "Azure API Management",
      "version": "1.0.0"
    }
  }
}
```

#### 4.1.2. tools/list

```sh
json=$(cat << EOF
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
EOF
)
curl https://alpha-a18d6b52.azure-api.net/ms-security/mcp -H "Content-Type: application/json" -d "$json"
```

Response:

```
event: message
data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"getIncidentById","description":"Get an incident using the incident ID. Consider using the list-incident tool with \u0060$filter\u0060 for \u0060id\u0060 and \u0060$expand\u0060 parameters instead to get an incident **with** associated alerts.","inputSchema":{"type":"object","properties":{"incidentId":{"type":"string","description":"ID of the intended incident."}},"required":["incidentId"],"additionalProperties":false}},{"name":"listAlerts","description":"Gets a list of alerts in Defender XDR, most recent alerts are on top. Provide OData query parameters to filter response.","inputSchema":{"type":"object","properties":{"$top":{"type":"string","description":"Limits the number of items returned in the response. Example: set to \u006010\u0060 returns only the first 5 items."},"$filter":{"type":"string","description":"Filters the collection based on Boolean conditions. Supports comparison operators (\u0060eq\u0060, \u0060ne\u0060, \u0060gt\u0060, \u0060lt\u0060), logical operators (\u0060and\u0060, \u0060or\u0060, \u0060not\u0060), and functions (\u0060startsWith\u0060, \u0060endsWith\u0060, \u0060contains\u0060). \u0060$filter\u0060 supports the following properties: \u0060assignedTo\u0060, \u0060classification\u0060, \u0060createdDateTime\u0060, \u0060lastUpdateDateTime\u0060, \u0060severity\u0060, \u0060serviceSource\u0060, and \u0060status\u0060. Example: \u0060status eq \u0027new\u0027 and createdDateTime ge 2026-03-01T23:559:59Z\u0060."},"$count":{"type":"string","description":"Returns the total count of items in a collection alongside the results. Set to \u0060true\u0060 to include the count in the response."},"$skip":{"type":"string","description":"Skips a specified number of items in the result set. Useful for pagination. Example: set to \u006010\u0060 skips the first 10 items and returns the rest."}},"required":[],"additionalProperties":false}},{"name":"listIncidents","description":"Gets a list of incidents in Defender XDR, most recent incidents are on top. Provide OData query parameters to filter response.","inputSchema":{"type":"object","properties":{"$top":{"type":"string","description":"Limits the number of items returned in the response. Example: set to \u006010\u0060 returns only the first 5 items."},"$filter":{"type":"string","description":"Filters the collection based on Boolean conditions. Supports comparison operators (\u0060eq\u0060, \u0060ne\u0060, \u0060gt\u0060, \u0060lt\u0060), logical operators (\u0060and\u0060, \u0060or\u0060, \u0060not\u0060), and functions (\u0060startsWith\u0060, \u0060endsWith\u0060, \u0060contains\u0060). \u0060$filter\u0060 supports the following properties: \u0060assignedTo\u0060, \u0060classification\u0060, \u0060createdDateTime\u0060, \u0060determination\u0060, \u0060lastUpdateDateTime\u0060, \u0060severity\u0060, and \u0060status\u0060. Example: \u0060status eq \u0027active\u0027 and createdDateTime ge 2026-03-01T23:559:59Z\u0060."},"$expand":{"type":"string","description":"Set to \u0060alerts\u0060 to include the alerts related to each incident in the result; omit if alerts are not needed."},"$count":{"type":"string","description":"Returns the total count of items in a collection alongside the results. Set to \u0060true\u0060 to include the count in the response."},"$skip":{"type":"string","description":"Skips a specified number of items in the result set. Useful for pagination. Example: set to \u006010\u0060 skips the first 10 items and returns the rest."}},"required":[],"additionalProperties":false}},{"name":"runHuntingQuery","description":"Run an advanced hunting query using KQL on Defender tables and Sentinel workspaces to search security data.","inputSchema":{"type":"object","properties":{"huntingQuery":{"type":"object","properties":{"Query":{"type":"string","description":"KQL query to execute"},"Timespan":{"type":"string","description":"ISO8601 duration (e.g., P7D) or omit to filter in KQL"}},"required":["Query","Timespan"],"additionalProperties":false}},"required":["huntingQuery"],"additionalProperties":false}},{"name":"createCommentForAlert","description":"Add a comment to an alert.","inputSchema":{"type":"object","properties":{"comment":{"type":"object","properties":{"comment":{"type":"string","description":"The comment to be added."}},"required":["comment"],"additionalProperties":false},"alertId":{"type":"string","description":"ID of the intended alert; use \u0060id\u0060, not \u0060providerAlertId\u0060 from list tools results."}},"required":["alertId","comment"],"additionalProperties":false}},{"name":"createCommentForIncident","description":"Add a comment to an incident.","inputSchema":{"type":"object","properties":{"comment":{"type":"object","properties":{"comment":{"type":"string","description":"The comment to be added."}},"required":["comment"],"additionalProperties":false},"incidentId":{"type":"string","description":"ID of the intended incident."}},"required":["incidentId","comment"],"additionalProperties":false}},{"name":"updateAlert","description":"Update the properties of an alert.","inputSchema":{"type":"object","properties":{"alertId":{"type":"string","description":"ID of the intended alert; use \u0060id\u0060, not \u0060providerAlertId\u0060 from list tools results."},"alertProperties":{"type":"object","properties":{"classification":{"type":"string","description":"Specifies the classification of the alert. The possible values are: \u0060unknown\u0060, \u0060falsePositive\u0060, \u0060truePositive\u0060, \u0060informationalExpectedActivity\u0060, \u0060unknownFutureValue\u0060."},"determination":{"type":"string","description":"Specifies the determination of the alert. The possible values are: \u0060unknown\u0060, \u0060apt\u0060, \u0060malware\u0060, \u0060securityPersonnel\u0060, \u0060securityTesting\u0060, \u0060unwantedSoftware\u0060, \u0060other\u0060, \u0060multiStagedAttack\u0060, \u0060compromisedUser\u0060, \u0060phishing\u0060, \u0060maliciousUserActivity\u0060, \u0060clean\u0060, \u0060insufficientData\u0060, \u0060confirmedUserActivity\u0060, \u0060lineOfBusinessApplication\u0060, \u0060unknownFutureValue\u0060."},"assignedTo":{"type":"string","description":"Owner of the incident, or \u0060null\u0060 if no owner is assigned."},"status":{"type":"string","description":"The status of the alert. The possible values are: \u0060new\u0060, \u0060inProgress\u0060, \u0060resolved\u0060, \u0060unknownFutureValue\u0060."}},"required":["status","classification","determination","assignedTo"],"additionalProperties":false}},"required":["alertId","alertProperties"],"additionalProperties":false}},{"name":"updateIncident","description":"Update the properties of an incident.","inputSchema":{"type":"object","properties":{"incidentId":{"type":"string","description":"ID of the intended incident."},"incidentProperties":{"type":"object","properties":{"classification":{"type":"string","description":"Specifies the classification of the incident; pssible values: \u0060unknown\u0060, \u0060falsePositive\u0060, \u0060truePositive\u0060, \u0060informationalExpectedActivity\u0060, \u0060unknownFutureValue\u0060."},"determination":{"type":"string","description":"Specifies the determination of the incident; possible values: \u0060unknown\u0060, \u0060apt\u0060, \u0060malware\u0060, \u0060securityPersonnel\u0060, \u0060securityTesting\u0060, \u0060unwantedSoftware\u0060, \u0060other\u0060, \u0060multiStagedAttack\u0060, \u0060compromisedAccount\u0060, \u0060phishing\u0060, \u0060maliciousUserActivity\u0060, \u0060notMalicious\u0060, \u0060notEnoughDataToValidate\u0060, \u0060confirmedUserActivity\u0060, \u0060lineOfBusinessApplication\u0060, \u0060unknownFutureValue\u0060."},"assignedTo":{"type":"string","description":"Owner of the incident; \u0060null\u0060 if not specified."},"resolvingComment":{"type":"string","description":"Comment to explain the resolution of the incident and the classification choice."},"status":{"type":"string","description":"The status of the incident; possible values: \u0060active\u0060, \u0060resolved\u0060, \u0060redirected\u0060, \u0060unknownFutureValue\u0060."}},"required":["status","classification","determination","assignedTo","resolvingComment"],"additionalProperties":false}},"required":["incidentId","incidentProperties"],"additionalProperties":false}}]}}

event: close
data:
```

<details><summary>Data <a href="https://jsonformatter.org/">JSON formatted</a>:</summary>

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "getIncidentById",
        "description": "Get an incident using the incident ID. Consider using the list-incident tool with `$filter` for `id` and `$expand` parameters instead to get an incident **with** associated alerts.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "incidentId": {
              "type": "string",
              "description": "ID of the intended incident."
            }
          },
          "required": [
            "incidentId"
          ],
          "additionalProperties": false
        }
      },
      {
        "name": "listAlerts",
        "description": "Gets a list of alerts in Defender XDR, most recent alerts are on top. Provide OData query parameters to filter response.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "$top": {
              "type": "string",
              "description": "Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items."
            },
            "$filter": {
              "type": "string",
              "description": "Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, and `status`. Example: `status eq 'new' and createdDateTime ge 2026-03-01T23:559:59Z`."
            },
            "$count": {
              "type": "string",
              "description": "Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response."
            },
            "$skip": {
              "type": "string",
              "description": "Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest."
            }
          },
          "required": [],
          "additionalProperties": false
        }
      },
      {
        "name": "listIncidents",
        "description": "Gets a list of incidents in Defender XDR, most recent incidents are on top. Provide OData query parameters to filter response.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "$top": {
              "type": "string",
              "description": "Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items."
            },
            "$filter": {
              "type": "string",
              "description": "Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `determination`, `lastUpdateDateTime`, `severity`, and `status`. Example: `status eq 'active' and createdDateTime ge 2026-03-01T23:559:59Z`."
            },
            "$expand": {
              "type": "string",
              "description": "Set to `alerts` to include the alerts related to each incident in the result; omit if alerts are not needed."
            },
            "$count": {
              "type": "string",
              "description": "Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response."
            },
            "$skip": {
              "type": "string",
              "description": "Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest."
            }
          },
          "required": [],
          "additionalProperties": false
        }
      },
      {
        "name": "runHuntingQuery",
        "description": "Run an advanced hunting query using KQL on Defender tables and Sentinel workspaces to search security data.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "huntingQuery": {
              "type": "object",
              "properties": {
                "Query": {
                  "type": "string",
                  "description": "KQL query to execute"
                },
                "Timespan": {
                  "type": "string",
                  "description": "ISO8601 duration (e.g., P7D) or omit to filter in KQL"
                }
              },
              "required": [
                "Query",
                "Timespan"
              ],
              "additionalProperties": false
            }
          },
          "required": [
            "huntingQuery"
          ],
          "additionalProperties": false
        }
      },
      {
        "name": "createCommentForAlert",
        "description": "Add a comment to an alert.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "comment": {
              "type": "object",
              "properties": {
                "comment": {
                  "type": "string",
                  "description": "The comment to be added."
                }
              },
              "required": [
                "comment"
              ],
              "additionalProperties": false
            },
            "alertId": {
              "type": "string",
              "description": "ID of the intended alert; use `id`, not `providerAlertId` from list tools results."
            }
          },
          "required": [
            "alertId",
            "comment"
          ],
          "additionalProperties": false
        }
      },
      {
        "name": "createCommentForIncident",
        "description": "Add a comment to an incident.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "comment": {
              "type": "object",
              "properties": {
                "comment": {
                  "type": "string",
                  "description": "The comment to be added."
                }
              },
              "required": [
                "comment"
              ],
              "additionalProperties": false
            },
            "incidentId": {
              "type": "string",
              "description": "ID of the intended incident."
            }
          },
          "required": [
            "incidentId",
            "comment"
          ],
          "additionalProperties": false
        }
      },
      {
        "name": "updateAlert",
        "description": "Update the properties of an alert.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "alertId": {
              "type": "string",
              "description": "ID of the intended alert; use `id`, not `providerAlertId` from list tools results."
            },
            "alertProperties": {
              "type": "object",
              "properties": {
                "classification": {
                  "type": "string",
                  "description": "Specifies the classification of the alert. The possible values are: `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`, `unknownFutureValue`."
                },
                "determination": {
                  "type": "string",
                  "description": "Specifies the determination of the alert. The possible values are: `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedUser`, `phishing`, `maliciousUserActivity`, `clean`, `insufficientData`, `confirmedUserActivity`, `lineOfBusinessApplication`, `unknownFutureValue`."
                },
                "assignedTo": {
                  "type": "string",
                  "description": "Owner of the incident, or `null` if no owner is assigned."
                },
                "status": {
                  "type": "string",
                  "description": "The status of the alert. The possible values are: `new`, `inProgress`, `resolved`, `unknownFutureValue`."
                }
              },
              "required": [
                "status",
                "classification",
                "determination",
                "assignedTo"
              ],
              "additionalProperties": false
            }
          },
          "required": [
            "alertId",
            "alertProperties"
          ],
          "additionalProperties": false
        }
      },
      {
        "name": "updateIncident",
        "description": "Update the properties of an incident.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "incidentId": {
              "type": "string",
              "description": "ID of the intended incident."
            },
            "incidentProperties": {
              "type": "object",
              "properties": {
                "classification": {
                  "type": "string",
                  "description": "Specifies the classification of the incident; pssible values: `unknown`, `falsePositive`, `truePositive`, `informationalExpectedActivity`, `unknownFutureValue`."
                },
                "determination": {
                  "type": "string",
                  "description": "Specifies the determination of the incident; possible values: `unknown`, `apt`, `malware`, `securityPersonnel`, `securityTesting`, `unwantedSoftware`, `other`, `multiStagedAttack`, `compromisedAccount`, `phishing`, `maliciousUserActivity`, `notMalicious`, `notEnoughDataToValidate`, `confirmedUserActivity`, `lineOfBusinessApplication`, `unknownFutureValue`."
                },
                "assignedTo": {
                  "type": "string",
                  "description": "Owner of the incident; `null` if not specified."
                },
                "resolvingComment": {
                  "type": "string",
                  "description": "Comment to explain the resolution of the incident and the classification choice."
                },
                "status": {
                  "type": "string",
                  "description": "The status of the incident; possible values: `active`, `resolved`, `redirected`, `unknownFutureValue`."
                }
              },
              "required": [
                "status",
                "classification",
                "determination",
                "assignedTo",
                "resolvingComment"
              ],
              "additionalProperties": false
            }
          },
          "required": [
            "incidentId",
            "incidentProperties"
          ],
          "additionalProperties": false
        }
      }
    ]
  }
}
```

</details>

## 5. Using the MCP server in Foundry agent

![](https://github.com/user-attachments/assets/af709b3a-0f2a-4cc4-b8fc-3e2f385da7ef)

### 5.1. Using with authorization code flow

#### 5.1.1. Client app and permissions

Auth code flow requires a client app and uses delegated permission to act on behalf of the user

![](https://github.com/user-attachments/assets/6cf04b77-15f6-4737-ae52-e5b5e4335397)

#### 5.1.2. Foundry tool configuration

![](https://github.com/user-attachments/assets/563afd3d-36fe-4994-92d4-5cac14621132)

![](https://github.com/user-attachments/assets/698179fb-151c-44d5-8b95-3058fd8e3796)

#### 5.1.3. Using tool in agent

![](https://github.com/user-attachments/assets/a613ee99-e8c6-46fa-85b5-286d73a98087)

![](https://github.com/user-attachments/assets/601cd6e3-9ef6-4ce5-b6cd-7a6471551178)

![](https://github.com/user-attachments/assets/241bd004-578b-48c2-ab13-41616ceeff98)

![](https://github.com/user-attachments/assets/25aa6769-9737-4558-9314-3d92e745708d)

![](https://github.com/user-attachments/assets/a7e54f8b-a9f1-4e6d-8855-8ec13c0fa29d)

![](https://github.com/user-attachments/assets/41da5901-47ec-4dad-ab1d-42ceb54daeb2)

### 5.2. Using with agent identity

- All unpublished or in-development agents within the same project share a common identity. (read: [Shared project identity](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/agent-identity?tabs=rest-api#shared-project-identity))
- Publishing an agent automatically creates a dedicated agent identity blueprint and agent identity. (read: [Distinct agent identity](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/agent-identity?tabs=rest-api#distinct-agent-identity))

#### 5.2.1. Agent identity and permissions

Agents in Foundry uses the autonomous agent flow, agent identity uses application permission to perform actions:
- [Official doc](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-autonomous-app-oauth-flow)
- [Write-up on agent identity flows](https://github.com/joetanx/mslab/blob/main/entra/agent-id/auth-flows.md)

Permissions are granted to the agent identity using graph API:
- [official doc](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/autonomous-agent-request-authorization-entra-admin)
- [Write-up on granting application permissions to agent identity](https://github.com/joetanx/mslab/blob/main/entra/agent-id/permissions-and-consent.md#53-grant-a-list-of-application-permissions-to-agent-identity)

![](https://github.com/user-attachments/assets/c5bd38fc-d9e0-4d67-a3ac-8f5984c63c39)

![](https://github.com/user-attachments/assets/4743baee-0921-4c43-bae9-dcdc36352cbb)

#### 5.2.2. Foundry tool configuration

![](https://github.com/user-attachments/assets/774e0d32-ca0b-4d09-81e0-71491e809657)

> [!Important]
> 
> The scope should not include the `.default` path (e.g. `https://graph.microsoft.com/.default`)
>
> If the scope if invalid, the agent fails with a _not-very-descriptive_ timeout error:
> 
> ![](https://github.com/user-attachments/assets/62ee55ce-69c9-4d4e-9918-261badf58556)
>
> The hint of why the agent fail is seen from another _not-very-descriptive_ resource not found error in the service principal sign-in logs:
> 
> ![](https://github.com/user-attachments/assets/4f6a5f7f-adf2-4dab-a63b-113ed2eab47c)

#### 5.2.3. Using tool in agent

![](https://github.com/user-attachments/assets/f2bbae39-0538-48bf-85b8-a8c07b410e90)

![](https://github.com/user-attachments/assets/e0ba23f8-9274-46be-ac0d-acc765baeead)

> [!Note]
>
> Notice the non-deterministic nature of agents:
> - The auth-code example output showed only active incidents, but the agent identity example output showed all incidents
> - This is unrelated to the authentication method
> - Inspect the response from the MCP tool with the `Logs` function to verify what was the raw data retrieved
>
> ![](https://github.com/user-attachments/assets/b062a8cf-8505-4068-8d35-e2924c273828)
