"""Stand-in for netexec / enum4linux-ng / smbclient / dig / ssh-audit / ldapsearch / showmount / snmpwalk / curl(ftp).

Invoked as: python fake_svc.py <tool> <args...>. Output modelled on the real tools (colour codes included
for NetExec). FAKE_SVC_LOG: append one JSON line [tool, args] per call.
"""

import json
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


def main() -> int:
    tool, args = sys.argv[1], sys.argv[2:]
    fakelog.write("FAKE_SVC_LOG", [tool, args])
    if tool == "netexec":
        if "-u" not in args:
            print(NXC_BANNER, end="")
        elif args[args.index("-u") + 1] == "":
            print(NXC_NULL, end="")
        else:
            print(NXC_GUEST, end="")
    elif tool == "enum4linux-ng":
        Path(args[args.index("-oJ") + 1] + ".json").write_text(json.dumps(E4L))
        print("ENUM4LINUX - next generation")
    elif tool == "smbclient":
        print("Disk|Public|Public files\nIPC|IPC$|Remote IPC")
    elif tool == "dig":
        if "version.bind" in args:
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
    else:
        print(f"unknown fake tool {tool}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
