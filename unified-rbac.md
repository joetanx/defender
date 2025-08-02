## 1. Introduction

The Microsoft Unified Security Experience (USX) aims to consolidate all security experience in the Defender portal (https://security.microsoft.com)

The Unified RBAC model provides a single permissions management experience that provides one central location for administrators to control user permissions across different security solutions

This enables granular access control in assigning **least privilege** permissions to users or security groups to grant access to specific Defender products

More details: https://learn.microsoft.com/en-us/defender-xdr/manage-rbac

> [!Important]
>
> Entra ID roles such as **Security Administrator** or **Security Operator** are on a higher permission level than Unified RBAC roles

### 1.1. Important note on legacy roles configurations

MDE previously had its own custom role management settings as mentioned in:
- https://learn.microsoft.com/en-us/defender-xdr/m365d-permissions
- https://learn.microsoft.com/en-us/defender-xdr/custom-roles

Unified RBAC is now activated by default and cannot be deactivated, the **Roles** setting now just contains placeholder information:

![](https://github.com/user-attachments/assets/40465799-832c-4198-81d5-8a0525c6b826)


## 2. Getting Started

### 2.1. Activate Microsoft Defender XDR Unified RBAC

More details: https://learn.microsoft.com/en-us/defender-xdr/activate-defender-rbac

> [!Important]
>
> **Global Administrator** or **Security Administrator** in Entra ID is required to activate Unified RBAC
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

### 2.2. Create custom roles with Microsoft Defender XDR Unified RBAC

https://learn.microsoft.com/en-us/defender-xdr/custom-permissions-details

https://learn.microsoft.com/en-us/defender-xdr/create-custom-rbac-roles
