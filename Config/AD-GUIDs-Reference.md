# Active Directory GUIDs Reference for RBAC Configuration

This file lists the most common GUIDs to use in the `ObjectType` and `InheritedObjectType` fields
of the RBAC-Config.json configuration file.

> **Empty GUID** `00000000-0000-0000-0000-000000000000` = no filter (all objects/properties).

> **Tip**: To find a GUID not listed here, run the following on a DC:
> ```powershell
> # Object class
> Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
>   -Filter { Name -eq "ClassName" } -Properties schemaIDGUID |
>   Select Name, @{N='GUID';E={[Guid]$_.schemaIDGUID}}
>
> # Extended Right
> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" `
>   -Filter { objectClass -eq "controlAccessRight" } -Properties rightsGuid, displayName |
>   Select displayName, rightsGuid | Sort displayName
> ```

---

## 1. Object Classes (InheritedObjectType / ObjectType with CreateChild/DeleteChild)

| Class | GUID |
|---|---|
| user | `bf967aba-0de6-11d0-a285-00aa003049e2` |
| computer | `bf967a86-0de6-11d0-a285-00aa003049e2` |
| group | `bf967a9c-0de6-11d0-a285-00aa003049e2` |
| organizationalUnit | `bf967aa5-0de6-11d0-a285-00aa003049e2` |
| contact | `5cb41ed0-0e4c-11d0-a286-00aa003049e2` |
| printQueue | `bf967aa8-0de6-11d0-a285-00aa003049e2` |
| volume | `bf967abb-0de6-11d0-a285-00aa003049e2` |
| dnsNode | `e0fa1e8c-9b45-11d0-afdd-00c04fd930c9` |
| dnsZone | `e0fa1e8b-9b45-11d0-afdd-00c04fd930c9` |
| msDS-GroupManagedServiceAccount | `7b8b558a-93a5-4af7-adca-c017e67f1057` |
| msDS-ManagedServiceAccount | `ce206244-5827-4a86-ba1c-1c0c386c1b64` |
| subnet | `b7b13124-b82e-11d0-afee-0000f80367c1` |
| site | `bf967ab3-0de6-11d0-a285-00aa003049e2` |
| siteLink | `d50c2cde-8951-11d1-aebc-0000f80367c1` |

---

## 2. Extended Rights (ObjectType with ADRights "ExtendedRight")

### Passwords
| Right | GUID |
|---|---|
| Reset Password | `00299570-246d-11d0-a768-00aa006e0529` |
| Change Password | `ab721a53-1e2f-11d0-9819-00aa0040529b` |

### Certificates
| Right | GUID |
|---|---|
| Enroll | `0e10c968-78fb-11d2-90d4-00c04f79dc55` |
| AutoEnroll | `a05b8cc2-17bc-4802-a710-e7c15ab866a2` |

### Validated Writes (ADRights "Self")
| Right | GUID |
|---|---|
| Validated write to DNS host name | `72e39547-7b18-11d1-adef-00c04fd8d5cd` |
| Validated write to SPN | `f3a64788-5306-11d1-a9c5-0000f80367c1` |

### Messaging / Exchange
| Right | GUID |
|---|---|
| Send As | `ab721a54-1e2f-11d0-9819-00aa0040529b` |
| Receive As | `ab721a56-1e2f-11d0-9819-00aa0040529b` |

### Replication
| Right | GUID |
|---|---|
| Replicating Directory Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| Replicating Directory Changes All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| Replicating Directory Changes In Filtered Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

### Miscellaneous
| Right | GUID |
|---|---|
| Allowed to Authenticate | `68b1d179-0d15-4d4f-ab71-46152e79a7bc` |
| Apply Group Policy | `edacfd8f-ffb3-11d1-b41d-00a0c968f939` |
| Unexpire Password | `ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501` |

---

## 3. Property Sets (ObjectType with ReadProperty/WriteProperty)

Allow granting access to a group of attributes with a single ACE.

| Property Set | GUID |
|---|---|
| General Information | `59ba2f42-79a2-11d0-9020-00c04fc2d3cf` |
| Personal Information | `77b5b886-944a-11d1-aebd-0000f80367c1` |
| Public Information | `e48d0154-bcf8-11d1-8702-00c04fb96050` |
| Web Information | `e45795b3-9455-11d1-aebd-0000f80367c1` |
| Phone and Mail Options | `e45795b2-9455-11d1-aebd-0000f80367c1` |
| Logon Information | `5f202010-79a5-11d0-9020-00c04fc2d4cf` |
| Account Restrictions | `4c164200-20c0-11d0-a768-00aa006e0529` |
| Group Membership | `bc0ac240-79a9-11d0-9020-00c04fc2d4cf` |
| Remote Access Information | `037088f8-0ae1-11d2-b422-00a0c968f939` |
| Domain Password & Lockout Policies | `c7407360-20bf-11d0-a768-00aa006e0529` |

---

## 4. Common Attributes (ObjectType with ReadProperty/WriteProperty)

To control access to an individual attribute.

### Group management
| Attribute | GUID |
|---|---|
| member | `bf9679c0-0de6-11d0-a285-00aa003049e2` |
| memberOf | `bf967991-0de6-11d0-a285-00aa003049e2` |
| groupType | `9a9a021e-4a5b-11d1-a9c3-0000f80367c1` |
| managedBy | `0296c120-40da-11d1-a9c0-0000f80367c1` |

### Account security
| Attribute | GUID |
|---|---|
| userAccountControl | `bf967a68-0de6-11d0-a285-00aa003049e2` |
| lockoutTime | `28630ebf-41d5-11d1-a9c1-0000f80367c1` |
| pwdLastSet | `bf967a0a-0de6-11d0-a285-00aa003049e2` |
| sAMAccountName | `3e0abfd0-126a-11d0-a060-00aa006c33ed` |
| userPrincipalName | `28630ebb-41d5-11d1-a9c1-0000f80367c1` |
| servicePrincipalName | `f3a64788-5306-11d1-a9c5-0000f80367c1` |

### Identity / Profile
| Attribute | GUID |
|---|---|
| displayName | `bf967953-0de6-11d0-a285-00aa003049e2` |
| description | `bf967950-0de6-11d0-a285-00aa003049e2` |
| department | `bf96794f-0de6-11d0-a285-00aa003049e2` |
| manager | `bf9679b5-0de6-11d0-a285-00aa003049e2` |

### DNS / GPO
| Attribute | GUID |
|---|---|
| dNSHostName | `72e39547-7b18-11d1-adef-00c04fd8d5cd` |
| gPLink | `f30e3bbe-9ff0-11d1-b603-0000f80367c1` |

---

## Usage example in RBAC-Config.json

```json
{
  "Type": "AD",
  "TargetOU": "OU=Users,DC=forest,DC=lol",
  "ADRights": "ExtendedRight",
  "ObjectType": "00299570-246d-11d0-a768-00aa006e0529",       // Reset Password
  "InheritanceType": "Descendents",
  "InheritedObjectType": "bf967aba-0de6-11d0-a285-00aa003049e2", // on user objects only
  "AccessControlType": "Allow"
}
```

Sources: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
