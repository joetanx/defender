## 1. Introduction

The Microsoft Unified Security Experience (USX) aims to consolidate all security experience in the Defender portal (https://security.microsoft.com)

The unified RBAC model provides a single permissions management experience that provides one central location for administrators to control user permissions across different security solutions

This enables granular access control in assigning **least privilege** permissions to users or security groups to grant access to specific Defender products

More details: https://learn.microsoft.com/en-us/defender-xdr/manage-rbac

> [!Important]
>
> Entra ID roles such as **Security Administrator** or **Security Operator** are on a higher permission level than unified RBAC roles

### 1.1. Important note on legacy roles configurations

MDE previously had its own custom role management settings as mentioned in:
- https://learn.microsoft.com/en-us/defender-xdr/m365d-permissions
- https://learn.microsoft.com/en-us/defender-xdr/custom-roles

unified RBAC is now activated by default and cannot be deactivated, the **Roles** setting now just contains placeholder information:

![](https://github.com/user-attachments/assets/40465799-832c-4198-81d5-8a0525c6b826)


## 2. Activate Microsoft Defender XDR unified RBAC

More details: https://learn.microsoft.com/en-us/defender-xdr/activate-defender-rbac

> [!Important]
>
> **Global Administrator** or **Security Administrator** in Entra ID is required to activate unified RBAC
>
> Once the appropriate roles are configured by the Global Administrator or Security Administrator, those roles can then manage permissions for other users and security groups

There are 2 ways to reach the workload settings page:

1. Navigation pane → System → Permissions → Microsoft Defender XDR → Roles → Workload settings

![](https://github.com/user-attachments/assets/62d7cbef-7b11-49fb-93b8-854c59a9781a)

![](https://github.com/user-attachments/assets/00d915a7-f9e7-435d-a40f-606db8976a69)

2. Navigation pane → System → Settings → Microsoft Defender XDR → Permissions and roles

![](https://github.com/user-attachments/assets/98783bb3-2d1e-4181-878f-d600538a25b2)

Both paths leads to the _Activate unified role-based access control_ page

![](https://github.com/user-attachments/assets/8660037b-9232-4133-a66f-0ef1b83bc54a)

> [!Note]
> 
> Unified RBAC model is now the default permissions model for new MDE tenants; it does not need to be activated

## 3. Create custom roles with Microsoft Defender XDR unified RBAC

Details on procedure to create customer roles in unified RBAC: https://learn.microsoft.com/en-us/defender-xdr/create-custom-rbac-roles

Navigation pane → System → Permissions → Microsoft Defender XDR → Roles → Create custom role

![](https://github.com/user-attachments/assets/62d7cbef-7b11-49fb-93b8-854c59a9781a)

![](https://github.com/user-attachments/assets/2b5f3d2f-84f7-4040-8459-0ebf01a87c4f)

### 3.1. Provide a role name

![](https://github.com/user-attachments/assets/4bab3463-a894-46b6-b343-25ba71a2265f)

### 3.2. Select permissions

The permissions are grouped into 3 permission groups:

|Security operations|Security posture|Authorization and settings|
|---|---|--|
|![](https://github.com/user-attachments/assets/8bfa2161-bd76-4753-9f9e-c2a830bdc248)|![](https://github.com/user-attachments/assets/8c3d333b-ce35-412f-953e-26c61292cbc4)|![](https://github.com/user-attachments/assets/fca90603-57bf-4faf-835c-41b1853f0dad)|

Select from read-only and read and manage options, or use custom permissions for granular assignment

Details on the granular custom permissions: https://learn.microsoft.com/en-us/defender-xdr/custom-permissions-details

### 3.3. Configure permission assignments

> [!Note]
>
> One or more assignments can be added to each custom role

#### 3.3.1. Select the users or groups to grant the permissions to

![](https://github.com/user-attachments/assets/05a58c6a-b765-4a4d-b862-1c27ee4971ab)

#### 3.3.2. Select the data sources that the permissions should apply to

The data sources are the Defender products that the users should have access to, the available data sources changes according to the permissions selected

Available data sources for security operations permissions:

(And also for auhorization and settings permissions, because it precludes _Security data basics (read)_ permission)

![](https://github.com/user-attachments/assets/b423316a-4bc7-4742-9161-29aeaf4986e8)

Available data sources for security posture permissions:

![](https://github.com/user-attachments/assets/15d33ea7-3ad2-42a7-86dc-ce0b7077509b)

#### 3.3.3. Select identity scope

Identity scoping restricts the identities that a user have permissions to

This applies only to MDI and the setting is grayed out if MDI is not selected in data sources

![](https://github.com/user-attachments/assets/3f3ce891-7c5a-43b3-a5f2-4cb1ad27cc0e)

## 4. Scoping devices for MDE

The unified RBAC roles define the actions that selected principals can performed in Defender portal

Device groups can be used to limit access to related alerts and data of the devices onboarded to MDE to user groups

### 4.1. Create device groups

Details on device groups: https://learn.microsoft.com/en-us/defender-endpoint/machine-groups

Navigation pane → System → Settings → Endpoints → Device groups → Add device group

![](https://github.com/user-attachments/assets/5768f23d-547b-4917-ad46-8dffd3edd3c5)

![](https://github.com/user-attachments/assets/aaa883b2-e095-45b8-8f77-f373801d669f)

### 4.2. General settings

Provide a device group name and specify the remediation level:

![](https://github.com/user-attachments/assets/27819917-d848-4847-a89b-3ba4c5b88f81)

### 4.3. Devices setting

Specify the matching rule that determines which devices belong to the group

The devices can be grouped based on names, domains, tags and OS

![](https://github.com/user-attachments/assets/65f0a1e0-221f-46f3-a03a-174fb42d4dd7)

> [!Tip]
>
> Tags are case sensitive!

> [!Note]
>
> The tags here refers to the devices tags in MDE, which is unrelated to the tags in Azure
>
> [Dynamic rules](https://learn.microsoft.com/en-us/defender-xdr/configure-asset-rules) can be configured to automatically tag devices
>
> Navigation pane → System → Settings → Microsoft Defender XDR → Asset Rule Management
>
> ![](https://github.com/user-attachments/assets/abbd4a97-1823-45c8-9846-2695fbe5ae59)

### 4.4. Preview devices

Verify whether the device matching rule selects the correct devices:

![](https://github.com/user-attachments/assets/c341b591-41b7-4bff-9c90-e3011cc63e58)

### 4.5. Assign user access

Select the Entra ID user groups that should have access to the device group:

![](https://github.com/user-attachments/assets/41c6f0f5-a7b2-430a-bba3-9b8d4f443b50)

### 4.6. Ungrouped devices (default)

After the first device group is created, a default ungrouped devices group is created to _catch_ devices not matched by any of the preceding rules:

![](https://github.com/user-attachments/assets/d6b304ad-c710-48dd-88b1-3715fed3aa63)

There are no user groups assigned to the ungrouped devices by default, which means **any user** (with the appropriate unified RBAC roles) can access ungroup devices

Assign at least one user group to limit access to the ungrouped devices:

(Security Administrator at the Entra ID level would still have access to the ungrouped devices)

![](https://github.com/user-attachments/assets/568ea7e8-4c97-4836-bb7b-b0f027a52c8a)

## 5. [Defender for Cloud in Defender portal (preview)](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-portal/defender-for-cloud-defender-portal)

### 5.1. [Enable preview features](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-portal/enable-preview-features)

![](https://github.com/user-attachments/assets/24102065-00b5-449c-a301-5af31cddd44d)

![](https://github.com/user-attachments/assets/05b94cdb-f292-45c9-8412-a464a1f69890)

![](https://github.com/user-attachments/assets/f57f01c9-1343-444d-82b6-241c555887ff)

![](https://github.com/user-attachments/assets/6307ea9f-5afc-4abc-a84c-77b47b6037c2)
