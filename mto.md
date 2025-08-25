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

![](https://github.com/user-attachments/assets/279c14c9-e488-4102-88c1-9c902f07dedb)

Select `Switch tenant` and select the desired tenant to switch:

![](https://github.com/user-attachments/assets/5108c9e7-eac0-4593-8a54-53b3a925bb7e)

The Defender portal is changed to the desired tenant:

![](https://github.com/user-attachments/assets/032e08bc-3f87-4565-affb-c128e99777c1)
