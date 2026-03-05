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

#### List alerts

![](https://github.com/user-attachments/assets/955a9da4-135e-4b23-8cb1-67da9ee6a87c)

#### List incidents

![](https://github.com/user-attachments/assets/dafef238-f9da-4865-a0a9-431466f66320)

#### Get incident

![](https://github.com/user-attachments/assets/8c532c43-d226-476e-b54d-c0c9c930f8ff)

#### Run hunting query

![](https://github.com/user-attachments/assets/34cd511a-0e1b-4c4e-8b64-5861f1d9eb0e)

### 2.2. Test access

```pwsh
PS C:\Users\tanjoe> $headers = @{ Authorization='Bearer '+$token.access_token }
PS C:\Users\tanjoe> $endpointuri='https://alpha-a18d6b52.azure-api.net/v1.0/security/runHuntingQuery'
PS C:\Users\tanjoe> $body=@{
>>   Query = 'SecurityIncident'
>>   Timespan = 'P3D'
>> }
PS C:\Users\tanjoe> Invoke-RestMethod $endpointuri -Method Post -Headers $headers -Body $($body | ConvertTo-Json) -ContentType 'application/json'

@odata.context                                                                          schema
--------------                                                                          ------
https://graph.microsoft.com/v1.0/$metadata#microsoft.graph.security.huntingQueryResults {@{name=TenantId; type=String}, @{name=TimeGenerated; type=DateTime}, @{name=IncidentName; type=String}, @{name=Titl...
```

## 3. Create product

![](https://github.com/user-attachments/assets/bcd8f01a-84a5-4b40-bb9a-06dc80174ca4)

## 4. Create MCP server

![](https://github.com/user-attachments/assets/3eecfcac-d9ca-4e15-90b5-c91e87c38c08)

![](https://github.com/user-attachments/assets/09d6d1a6-1cfb-4497-bc84-7f86923c2c7e)

![](https://github.com/user-attachments/assets/601cd6e3-9ef6-4ce5-b6cd-7a6471551178)
