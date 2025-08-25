## 1. Introduction

https://learn.microsoft.com/en-us/unified-secops/mto-overview

Multi-tenant management for Microsoft Defender XDR and Microsoft Sentinel in the Defender portal provides the SOC teams with a single, unified view of all tenants

This view enables the SOC teams to quickly investigate incidents and perform advanced hunting across data from multiple tenants, improving security operations

## 2. Set up multitenant management

### 2.1. Microsoft Entra B2B

https://learn.microsoft.com/en-us/unified-secops/mto-requirements

Verify tenant access at https://myaccount.microsoft.com/organizations

![](https://github.com/user-attachments/assets/f56bb503-eb8b-44a4-93a1-259f37e8e23d)

### 2.2. Adding tenants

Login to http://mto.security.microsoft.com and select `Add tenants`:

![](https://github.com/user-attachments/assets/29f4bcf7-5256-4e57-b6d6-22a569349de3)

Check the desired tenants and select `Add tenant`:

![](https://github.com/user-attachments/assets/e9be9b85-b340-498d-aaba-faa8d615d4e0)

The added tenants are listed in `Tenant selection`:

![](https://github.com/user-attachments/assets/54ffd0d3-270b-404c-94be-49e727b1c2d2)

### 2.3. Removing tenants

Multi-tenant management → Settings → Check desired tenants → Remove tenants

![](https://github.com/user-attachments/assets/aef3bc8d-34a6-40bb-9bb9-cd5ca9488c07)

### 3. Switching tenants in Defender portal

The tenant switcher button is available in the Defender portal home page:

![](https://github.com/user-attachments/assets/f1154842-6bd9-43a0-9f27-100dab88df69)

Select `Switch tenant` and select the desired tenant to switch:

![](https://github.com/user-attachments/assets/7122b37b-da03-4a05-b0da-a4ee52f5546a)

The Defender portal is changed to the desired tenant:

![](https://github.com/user-attachments/assets/8f0c86eb-e1a0-4d98-ae7f-4051b712fc85)
