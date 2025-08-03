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

![](https://github.com/user-attachments/assets/c8eb6ea2-e069-4588-afbd-7a5d96dfeb15)

![](https://github.com/user-attachments/assets/41270a6d-f5a0-401d-b487-706925e4bd09)

2. Navigation pane → System → Settings → Microsoft Defender XDR → Permissions and roles

![](https://github.com/user-attachments/assets/acb6831b-d877-477b-ae84-98d9c5e54926)

Both paths leads to the _Activate unified role-based access control_ page

![](https://github.com/user-attachments/assets/8660037b-9232-4133-a66f-0ef1b83bc54a)

> [!Note]
> 
> Unified RBAC model is now the default permissions model for new MDE tenants; it does not need to be activated

## 3. Create custom roles with Microsoft Defender XDR unified RBAC

Details on procedure to create customer roles in unified RBAC: https://learn.microsoft.com/en-us/defender-xdr/create-custom-rbac-roles

Navigation pane → System → Permissions → Microsoft Defender XDR → Roles → Create custom role

![](https://github.com/user-attachments/assets/c8eb6ea2-e069-4588-afbd-7a5d96dfeb15)

![](https://github.com/user-attachments/assets/41270a6d-f5a0-401d-b487-706925e4bd09)

### 3.1. Provide a role name

![](https://github.com/user-attachments/assets/4bab3463-a894-46b6-b343-25ba71a2265f)

### 3.2. Select permissions

The permissions are grouped into 3 permission groups:

|Group|Permissions|
|---|---|
|Security operations|![](https://github.com/user-attachments/assets/ed440ef4-a283-4d8d-b22b-cb7f623e03bd)|
|Security posture|![](https://github.com/user-attachments/assets/859fe486-1d63-42f4-b43a-f0ac755125ad)|
|Authorization and settings|![](https://github.com/user-attachments/assets/b310c3d6-99be-47ea-a34b-1c7f199347bd)|

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

(And also auhorization and settings permissions, because it precludes security operations read-only permissions)

![](https://github.com/user-attachments/assets/b423316a-4bc7-4742-9161-29aeaf4986e8)

Available data sources for security posture permissions:

<img width="644" height="199" alt="image" src="https://github.com/user-attachments/assets/15d33ea7-3ad2-42a7-86dc-ce0b7077509b" />

### 3.3.3. Select identity scope

Identity scoping restricts the identities that a user have permissions to

This applies only to MDI and the setting is grayed out if MDI is not selected in data sources

![](https://github.com/user-attachments/assets/3f3ce891-7c5a-43b3-a5f2-4cb1ad27cc0e)

