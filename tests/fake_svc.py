"""Stand-in for netexec / enum4linux-ng / smbclient / dig / ssh-audit / ldapsearch / showmount / snmpwalk / curl(ftp)
/ dnsrecon / impacket-rpcdump / ffuf / gobuster (vhost).

Invoked as: python fake_svc.py <tool> <args...>. Output modelled on the real tools (colour codes included
for NetExec). FAKE_SVC_LOG: append one JSON line [tool, args] per call.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakelog  # noqa: E402

NXC_BANNER = ("\x1b[1;34mSMB\x1b[0m         10.129.73.247   445    DC01             [*] Windows Server 2019 Build 17763 x64 "
              "(name:DC01) (domain:corp.local) (signing:False) (SMBv1:True)\n")
NXC_NULL = NXC_BANNER + (
    "SMB         10.129.73.247   445    DC01             [+] corp.local\\: \n"
    "SMB         10.129.73.247   445    DC01             [*] Enumerated shares\n"
    "SMB         10.129.73.247   445    DC01             Share           Permissions     Remark\n"
    "SMB         10.129.73.247   445    DC01             -----           -----------     ------\n"
    "SMB         10.129.73.247   445    DC01             ADMIN$                          Remote Admin\n"
    "SMB         10.129.73.247   445    DC01             Public          READ            Public files\n"
    "SMB         10.129.73.247   445    DC01             IPC$            READ            Remote IPC\n")
NXC_GUEST = NXC_BANNER + "SMB         10.129.73.247   445    DC01             [-] corp.local\\guest: STATUS_ACCOUNT_DISABLED \n"
E4L = {"sessions": {"sessions_possible": True, "null": True, "random_user": False},
       "smb_dialects": {"Supported dialects": {"SMB 1.0": True, "SMB 3.1.1": True}, "SMB signing required": False},
       "smb_domain_info": {"DNS domain": "corp.local"}, "os_info": {"OS": "Windows Server 2019"},
       "shares": {"Public": {"type": "Disk", "comment": "Public files", "access": {"mapping": "OK", "listing": "OK"}},
                  "ADMIN$": {"type": "Disk", "comment": "", "access": {"mapping": "DENIED", "listing": "N/A"}}},
       "users": {"500": {"username": "Administrator"}, "1103": {"username": "svc_backup"}},
       "groups": {"512": {"groupname": "Domain Admins"}}, "policy": {"Domain password information": {"Minimum password length": 7}}}
SSH_AUDIT = {"banner": {"raw": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "software": "OpenSSH_8.9p1"},
             "kex": [{"algorithm": "curve25519-sha256", "notes": {}},
                     {"algorithm": "diffie-hellman-group14-sha1", "notes": {"fail": ["using broken SHA-1 hash algorithm"]}}],
             "key": [{"algorithm": "ssh-rsa", "notes": {"warn": ["using weak hashing algorithm"]}}],
             "enc": [{"algorithm": "aes256-gcm@openssh.com", "notes": {}}], "mac": [],
             "fingerprints": [{"hash": "SHA256:abc", "hash_alg": "SHA256", "hostkey": "ssh-ed25519"}]}
ROOTDSE = """dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
defaultNamingContext: DC=corp,DC=local
dnsHostName: dc01.corp.local
domainControllerFunctionality: 7
supportedLDAPVersion: 3
supportedLDAPVersion: 2
serverName: CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=loc
 al

"""
LDAP_ANON = "dn: DC=corp,DC=local\nobjectClass: domain\n\ndn: CN=Users,DC=corp,DC=local\nobjectClass: container\n\n"
AXFR = """; <<>> DiG 9.18 <<>> @10.129.73.247 corp.local AXFR
corp.local.		3600	IN	SOA	dc01.corp.local. hostmaster.corp.local. 1 900 600 86400 3600
corp.local.		3600	IN	NS	dc01.corp.local.
dev.corp.local.		3600	IN	A	10.129.73.250
corp.local.		3600	IN	SOA	dc01.corp.local. hostmaster.corp.local. 1 900 600 86400 3600
;; XFR size: 4 records (messages 1, bytes 200)
"""

RPCDUMP = """Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Retrieving endpoint list from 10.129.73.247
Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
          ncacn_ip_tcp:10.129.73.247[49668]
          ncalrpc:[LRPC-0123]

Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol
Provider: samsrv.dll
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0
Bindings:
          ncacn_np:\\\\DC01[\\pipe\\lsass]

Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
          ncacn_np:\\\\DC01[\\pipe\\spoolss]

Protocol: N/A
Provider: N/A
UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0
Bindings:
          ncalrpc:[LRPC-abc]

[*] Received 4 endpoints.
"""
DNSRECON = [{"arguments": "dnsrecon -d corp.local", "date": "2026-11-28", "type": "ScanInfo"},
            {"type": "SOA", "domain": "corp.local", "mname": "dc01.corp.local", "address": "10.129.73.247"},
            {"type": "NS", "domain": "corp.local", "target": "dc01.corp.local", "address": "10.129.73.247"},
            {"type": "A", "domain": "corp.local", "name": "corp.local", "address": "10.129.73.247"},
            {"type": "A", "domain": "corp.local", "name": "intranet.corp.local", "address": "10.129.73.247"},
            {"type": "SRV", "domain": "corp.local", "name": "_kerberos._tcp.corp.local", "target": "dc01.corp.local",
             "address": "10.129.73.247", "port": "88"}]


def main() -> int:
    tool, args = sys.argv[1], sys.argv[2:]
    fakelog.write("FAKE_SVC_LOG", [tool, args])
    signed = bool(os.environ.get("FAKE_SVC_SIGNING"))  # simulate a later scan where signing is enforced
    if tool == "netexec":
        banner = NXC_BANNER.replace("signing:False", "signing:True") if signed else NXC_BANNER
        if "-u" not in args:
            print(banner, end="")
        elif args[args.index("-u") + 1] == "":
            print(NXC_NULL.replace(NXC_BANNER, banner), end="")
        else:
            print(NXC_GUEST.replace(NXC_BANNER, banner), end="")
    elif tool == "enum4linux-ng":
        data = json.loads(json.dumps(E4L))
        data["smb_dialects"]["SMB signing required"] = signed
        Path(args[args.index("-oJ") + 1] + ".json").write_text(json.dumps(data))
        print("ENUM4LINUX - next generation")
    elif tool == "smbclient":
        print("Disk|Public|Public files\nIPC|IPC$|Remote IPC")
    elif tool == "dig":
        if "SRV" in args:
            name = next(a for a in args if a.startswith("_"))
            port = {"_ldap": 389, "_kerberos": 88, "_kpasswd": 464, "_gc": 3268}[name.split(".")[0]]
            if name.endswith("corp.local"):
                print(f"0 100 {port} dc01.corp.local.")
        elif "version.bind" in args:
            print('"9.18.18-0ubuntu0.22.04.2-Ubuntu"')
        elif "-x" in args:
            print("dc01.corp.local.")
        elif "AXFR" in args:
            print(AXFR, end="")
        elif "SOA" in args:
            print("dc01.corp.local. hostmaster.corp.local. 1 900 600 86400 3600")
        elif "NS" in args:
            print("dc01.corp.local.")
    elif tool == "ssh-audit":
        print(json.dumps(SSH_AUDIT))
        return 2
    elif tool == "ldapsearch":
        print(ROOTDSE if "base" in args else LDAP_ANON, end="")
    elif tool == "showmount":
        print("Export list for 10.129.73.247:\n/srv/share *\n/home 10.0.0.0/24")
    elif tool == "snmpwalk":
        print('.1.3.6.1.2.1.1.1.0 = STRING: "Linux box 5.15.0"\n.1.3.6.1.2.1.1.5.0 = STRING: "box"')
    elif tool == "curl":  # FTP anonymous check
        print("< 220 (vsFTPd 3.0.3)\n> USER anonymous\n< 331 Please specify the password.\n> PASS x\n"
              "< 230 Login successful.", file=sys.stderr)
        print("pub\nreadme.txt")
    elif tool == "dnsrecon":
        domain = args[args.index("-d") + 1]
        records = DNSRECON if domain == "corp.local" else DNSRECON[:1]
        Path(args[args.index("-j") + 1]).write_text(json.dumps(records))
        print(f"[*] std: Performing General Enumeration against: {domain}...")
    elif tool == "impacket-rpcdump":
        print(RPCDUMP, end="")
    elif tool == "ffuf":  # vhost mode: the Host header carries FUZZ.<base>
        base = next(a for a in args if a.startswith("Host: FUZZ.")).split("FUZZ.", 1)[1]
        results = [{"input": {"FUZZ": "dev"}, "status": 200, "length": 5120, "words": 300, "redirectlocation": ""},
                   {"input": {"FUZZ": "staging"}, "status": 302, "length": 0, "words": 1,
                    "redirectlocation": "http://staging." + base + "/login"}]
        Path(args[args.index("-o") + 1]).write_text(json.dumps({"results": results}))
    elif tool == "gobuster":  # vhost mode, no wildcard filtering: catch-all answers included
        base = args[args.index("--domain") + 1]
        lines = [f"Found: {w}.{base} Status: 200 [Size: 1000]" for w in ("www", "mail", "test", "ftp")]
        lines.append(f"Found: dev.{base} Status: 200 [Size: 5120]")
        Path(args[args.index("-o") + 1]).write_text("\n".join(lines) + "\n")
    else:
        print(f"unknown fake tool {tool}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
