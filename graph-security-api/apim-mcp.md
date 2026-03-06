## 1. Create Azure API managegement services

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

### 2.1. Add requires APIs to operations

> [!Note]
>
> It is also possible to use wildcard operation to just passthrough everything

#### 2.1.1. List alerts

Description: _Gets a list of alerts in Defender XDR, most recent alerts are on top. Provide OData query parameters to filter response._

Query parameters:

|Name|Description|Type|
|---|---|---|
|`$count`|Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response.|boolean|
|`$filter`|Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, and `status`. Example: `status eq 'new' and createdDateTime ge 2026-03-01T23:559:59Z`.|string|
|`$skip`|Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest.|integer|
|`$top`|Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items.|integer|

![](https://github.com/user-attachments/assets/3b7d1b34-555f-4b6f-a277-770a7b580a6b)

#### 2.1.2. List incidents

Description: _Gets a list of incidents in Defender XDR, most recent incidents are on top. Provide OData query parameters to filter response._

Query parameters:

|Name|Description|Type|
|---|---|---|
|`$count`|Returns the total count of items in a collection alongside the results. Set to `true` to include the count in the response.|boolean|
|`$filter`|Filters the collection based on Boolean conditions. Supports comparison operators (`eq`, `ne`, `gt`, `lt`), logical operators (`and`, `or`, `not`), and functions (`startsWith`, `endsWith`, `contains`). `$filter` supports the following properties: `assignedTo`, `classification`, `createdDateTime`, `lastUpdateDateTime`, `severity`, `serviceSource`, and `status`. Example: `status eq 'new' and createdDateTime ge 2026-03-01T23:559:59Z`.|string|
|`$skip`|Skips a specified number of items in the result set. Useful for pagination. Example: set to `10` skips the first 10 items and returns the rest.|integer|
|`$top`|Limits the number of items returned in the response. Example: set to `10` returns only the first 5 items.|integer|
|`$expand`|Set to `alerts` to include the alerts related to each incident in the result; omit if alerts are not needed.|string|

![](https://github.com/user-attachments/assets/4fb1ff1f-6366-4f44-8830-6b576858606e)

#### 2.1.3. Get incident by ID

Description: _Get an incident using the incident ID. Consider using the list-incident tool with `$filter` for `id` and `$expand` parameters instead to get an incident **with** associated alerts._

![](https://github.com/user-attachments/assets/a5721fff-4e2c-46d3-8ad6-2a925869ecb9)

#### 2.1.4. Run hunting query

Description: _Run an advanced hunting query using KQL across supported Defender tables to search security data._

![](https://github.com/user-attachments/assets/18fc77f8-fc29-4f39-bc1c-a3570e102c49)

##### Request

Body description: Provide JSON object with 2 parameters: `Query` (**Required**) and `Timespan` (_Optional_)

##### Representation

Content type: `application/json`

Sample:

```json
{
  "Query":  "workspace('alpha-soc').Syslog | where SyslogMessage contains 'failed password'",
  "Timespan":  "P7D"
}
```

Definition:

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
    "required": [
        "Query"
    ]
}
```

![](https://github.com/user-attachments/assets/50964d3d-bb05-45ee-997a-12c6ee06500b)

### 2.2. Test access

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

![](https://github.com/user-attachments/assets/13c8f81d-e7b3-4654-a351-328b983c944a)

![](https://github.com/user-attachments/assets/601cd6e3-9ef6-4ce5-b6cd-7a6471551178)

![](https://github.com/user-attachments/assets/241bd004-578b-48c2-ab13-41616ceeff98)
