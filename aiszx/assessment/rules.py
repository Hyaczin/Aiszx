"""Assessment rules: knowledge → finding drafts.

Principles (from the specification):
* an open port is not a vulnerability: rules need an observation that shows a weakness
* classification separates what was *observed* from what is *inferred*:
  confirmed_observation, potential_vulnerability, unverified_hypothesis, requires_manual_validation
* nothing claims access is possible; next steps describe what a human should validate
* version-based matches are always unverified hypotheses with low confidence

Each rule has a stable id (used in finding fingerprints). Add rules with ``@rule("ID")``.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from aiszx.assessment.knowledge import Knowledge, Observation
from aiszx.assessment.model import CONFIRMED, HYPOTHESIS, MANUAL, POTENTIAL, FindingDraft

Rule = Callable[[Knowledge], list[FindingDraft]]
RULES: dict[str, Rule] = {}

SESSION_COOKIES = re.compile(r"sess|sid|token|auth|jwt|login", re.IGNORECASE)
INTERESTING_PATHS = re.compile(r"admin|backup|\.git|\.svn|\.env|config|upload|dev|test|phpinfo|server-status|"
                               r"api|console|manager|wp-admin|\.bak|\.old|db|sql|dump|private|secret", re.IGNORECASE)


def rule(rule_id: str):
    def register(fn: Rule) -> Rule:
        RULES[rule_id] = fn
        fn.rule_id = rule_id  # type: ignore[attr-defined]
        return fn
    return register


def _svc_key(url: str | None) -> str | None:
    m = re.match(r"^\w+://[^/:]+:(\d+)", url or "")
    return f"tcp/{m.group(1)}" if m else None


def _true(obs: list[Observation]) -> list[Observation]:
    return [o for o in obs if o.value is True]


# --- SMB ------------------------------------------------------------------------------

@rule("SMB-001")
def smb_signing(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("smb.signing_required") if o.value is False]
    if not obs:
        return []
    agree = {o.module for o in obs}
    return [FindingDraft(
        "SMB-001", "SMB signing not required", "medium", "high" if len(agree) > 1 else "medium", POTENTIAL,
        "The SMB server does not require message signing.",
        impact="Unsigned SMB sessions can be relayed (NTLM relay) if an attacker can make a client or host authenticate "
               "to them; impact depends on what the relayed identity can access.",
        recommendation="Require SMB signing on servers and clients (Group Policy: 'Digitally sign communications (always)').",
        next_steps=["Confirm with a second tool that signing is not required",
                    "Assess whether relay is feasible in this environment (authorised, manual testing only)"],
        service_key="tcp/445", evidence=obs, details={"sources": sorted(agree)})]


@rule("SMB-002")
def smb_v1(k: Knowledge) -> list[FindingDraft]:
    obs = _true(k.find("smb.smbv1_enabled"))
    if not obs:
        return []
    return [FindingDraft(
        "SMB-002", "SMBv1 protocol enabled", "medium", "medium", POTENTIAL,
        "The server accepts the deprecated SMBv1 protocol.",
        impact="SMBv1 lacks modern protections and has a history of critical vulnerabilities; whether this host is "
               "affected by any specific one is not determined.",
        recommendation="Disable SMBv1 unless a documented legacy dependency requires it.",
        next_steps=["Determine OS/patch level to judge exposure to known SMBv1 issues (manual, no exploitation)"],
        service_key="tcp/445", evidence=obs)]


@rule("SMB-003")
def smb_null_session(k: Knowledge) -> list[FindingDraft]:
    obs = _true(k.find("smb.null_session"))
    if not obs:
        return []
    return [FindingDraft(
        "SMB-003", "SMB null session accepted", "medium", "high", CONFIRMED,
        "The server accepted an unauthenticated (null) SMB session.",
        impact="Anonymous sessions may expose shares, users, groups and policy information.",
        recommendation="Restrict anonymous access (RestrictAnonymous / 'Network access' policies).",
        next_steps=["Review what the null session exposes (see the SMB enumeration output)"],
        service_key="tcp/445", evidence=obs)]


@rule("SMB-004")
def smb_readable_shares(k: Knowledge) -> list[FindingDraft]:
    by_share: dict[str, list[Observation]] = {}
    for key in ("smb.null_readable_shares", "smb.guest_readable_shares", "smb.null_listable_shares"):
        for o in k.find(key):
            for share in o.value or []:
                if share.upper() != "IPC$":
                    by_share.setdefault(share, []).append(o)
    return [FindingDraft(
        "SMB-004", f"SMB share '{share}' readable without credentials", "medium", "high", CONFIRMED,
        f"The share '{share}' can be listed or read anonymously or as guest.",
        impact="Anonymous read access can expose sensitive files (configuration, backups, credentials).",
        recommendation="Remove anonymous/guest access to the share or restrict its permissions.",
        next_steps=[f"Manually review the contents of '{share}' for sensitive data (read-only)"],
        service_key="tcp/445", discriminator=share, evidence=obs) for share, obs in sorted(by_share.items())]


@rule("SMB-005")
def smb_guest(k: Knowledge) -> list[FindingDraft]:
    obs = _true(k.find("smb.guest_session"))
    if not obs:
        return []
    return [FindingDraft(
        "SMB-005", "SMB guest session accepted", "medium", "high", CONFIRMED,
        "The server accepted a session as the guest account.",
        impact="Guest access grants whatever the guest account and 'Everyone' can reach.",
        recommendation="Disable the guest account and guest fallback.",
        next_steps=["Review which shares and information the guest session reaches"],
        service_key="tcp/445", evidence=obs)]


@rule("SMB-006")
def smb_users(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("smb.users_enumerable") if o.value]
    if not obs:
        return []
    users = sorted({u for o in obs for u in o.value})
    return [FindingDraft(
        "SMB-006", "Domain/local users enumerable anonymously", "medium", "high", CONFIRMED,
        f"{len(users)} account name(s) were listed through an anonymous session.",
        impact="Valid account names make targeted attacks (e.g. password guessing) easier; any such testing needs "
               "explicit authorisation and lockout-policy awareness.",
        recommendation="Prevent anonymous enumeration of SAM accounts and shares.",
        next_steps=["Note the password/lockout policy before any authorised credential testing"],
        service_key="tcp/445", evidence=obs, details={"users": users[:100]})]


# --- DNS / LDAP -----------------------------------------------------------------------

@rule("DNS-001")
def dns_axfr(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft(
        "DNS-001", f"DNS zone transfer allowed for {o.value.get('domain')}", "medium", "high", CONFIRMED,
        f"The DNS server returned the full zone {o.value.get('domain')} ({o.value.get('records')} records) to an "
        "unauthenticated AXFR request.",
        impact="The whole zone (host names, internal addresses, services) is disclosed.",
        recommendation="Restrict zone transfers to authorised secondary name servers.",
        next_steps=["Review the transferred records for additional in-scope hosts and naming patterns"],
        service_key="tcp/53", discriminator=str(o.value.get("domain")), evidence=[o])
        for o in k.find("dns.zone_transfer_allowed") if isinstance(o.value, dict)]


@rule("DNS-002")
def dns_version(k: Knowledge) -> list[FindingDraft]:
    obs = k.find("dns.version_disclosed")
    if not obs:
        return []
    return [FindingDraft("DNS-002", "DNS server version disclosed", "info", "high", CONFIRMED,
                         f"version.bind returned {obs[0].value}.",
                         recommendation="Hide the server version (BIND: `version \"none\";`).",
                         service_key="tcp/53", evidence=obs)]


@rule("LDAP-001")
def ldap_anonymous(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("ldap.anonymous_read") if isinstance(o.value, dict) and o.value.get("readable")]
    if not obs:
        return []
    return [FindingDraft(
        "LDAP-001", "Anonymous LDAP read access", "medium", "high", CONFIRMED,
        f"An anonymous bind could read {obs[0].value.get('entries')} entr(y/ies) of the directory.",
        impact="Directory contents (users, groups, computers, attributes) may be disclosed without credentials.",
        recommendation="Disallow anonymous reads beyond the RootDSE (dsHeuristics / ACLs).",
        next_steps=["Review which object classes and attributes are readable anonymously"],
        service_key=_svc_key(obs[0].url), evidence=obs)]


@rule("LDAP-002")
def ldap_dc(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("ldap.domain_controller")]
    domain = next((o.value for o in k.find("ldap.domain")), None)
    if not obs:
        return []
    return [FindingDraft(
        "LDAP-002", f"Active Directory domain controller ({domain or 'domain unknown'})", "info", "high", CONFIRMED,
        f"RootDSE identifies the host as a domain controller ({obs[0].value or 'name unknown'}).",
        next_steps=["Prioritise AD-specific enumeration within the authorised scope"],
        service_key=_svc_key(obs[0].url), evidence=obs + k.find("ldap.domain"), details={"domain": domain})]


# --- FTP / NFS / SNMP / SSH / r-services ------------------------------------------------

@rule("FTP-001")
def ftp_anonymous(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft(
        "FTP-001", "Anonymous FTP login allowed", "medium", "high", CONFIRMED,
        "The FTP server accepted the anonymous account.",
        impact="Files may be readable (and possibly writable) without credentials.",
        recommendation="Disable anonymous FTP unless it is an intentional public service with reviewed content.",
        next_steps=["Review the listing for sensitive files; check write permission manually only if authorised"],
        service_key=_svc_key(o.url), evidence=[o]) for o in _true(k.find("ftp.anonymous_login"))]


@rule("NFS-001")
def nfs_world(k: Knowledge) -> list[FindingDraft]:
    out = []
    for o in k.find("nfs.world_mountable"):
        for path in o.value or []:
            out.append(FindingDraft(
                "NFS-001", f"NFS export {path} mountable by any host", "medium", "high", POTENTIAL,
                f"The export {path} is offered to every client ('*').",
                impact="Any host on the network can mount the export; file access depends on export options "
                       "(e.g. root_squash) and file permissions.",
                recommendation="Restrict the export to specific clients and review its options.",
                next_steps=[f"Check export options of {path} (no_root_squash?) and contents (read-only, authorised)"],
                service_key="tcp/2049", discriminator=path, evidence=[o]))
    return out


@rule("SNMP-001")
def snmp_readable(k: Knowledge) -> list[FindingDraft]:
    obs = _true(k.find("snmp.readable"))
    if not obs:
        return []
    return [FindingDraft("SNMP-001", "SNMP readable with a configured community string", "info", "high", CONFIRMED,
                         "SNMP answered system queries with one of the authorised community strings.",
                         impact="SNMP can disclose system, network and process information.",
                         recommendation="Use SNMPv3 with authentication; restrict SNMP to management hosts.",
                         service_key="udp/161", evidence=obs)]


@rule("SSH-001")
def ssh_weak(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("ssh.weak_algorithms") if o.value]
    out = []
    for o in obs:
        algos = sorted({a for v in o.value.values() for a in v if a})
        out.append(FindingDraft(
            "SSH-001", "SSH server offers algorithms flagged as weak", "low", "high", CONFIRMED,
            f"ssh-audit flagged {len(algos)} offered algorithm(s): {', '.join(algos[:8])}"
            + (" ..." if len(algos) > 8 else ""),
            impact="Weak algorithms reduce the security margin of SSH sessions; practical impact is usually limited.",
            recommendation="Disable the flagged algorithms (see ssh-audit recommendations).",
            service_key=_svc_key(o.url), evidence=[o], details={"algorithms": o.value}))
    return out


@rule("RSVC-001")
def rservices(k: Knowledge) -> list[FindingDraft]:
    obs = k.find("rservices.exposed")
    if not obs:
        return []
    names = ", ".join(f"{s['service']} ({s['port']}/tcp)" for s in obs[0].value)
    return [FindingDraft(
        "RSVC-001", "Legacy r-services exposed (rexec/rlogin/rsh)", "medium", "medium", MANUAL,
        f"Exposed: {names}. These protocols send credentials in cleartext and can grant access through host-based "
        "trust (.rhosts / hosts.equiv).",
        impact="If trust relationships or weak credentials exist, remote command execution may be possible; this has "
               "NOT been tested.",
        recommendation="Disable r-services; use SSH.",
        next_steps=["With authorisation, review host-based trust configuration and which accounts these services "
                    "accept (manual testing only)"],
        service_key="tcp/512", evidence=obs)]


# --- Web ----------------------------------------------------------------------------

@rule("HTTP-001")
def http_cookies(k: Knowledge) -> list[FindingDraft]:
    out = []
    for o in k.find("http.cookie_flags"):
        for issue in o.value or []:
            if "httponly" not in issue.get("missing", []) or not SESSION_COOKIES.search(issue.get("cookie", "")):
                continue
            out.append(FindingDraft(
                "HTTP-001", f"Session cookie {issue['cookie']} without HttpOnly", "low", "high", CONFIRMED,
                f"{o.url} sets {issue['cookie']} without the HttpOnly flag (also missing: "
                f"{', '.join(m for m in issue['missing'] if m != 'httponly') or 'nothing else'}).",
                impact="If a cross-site scripting flaw exists, scripts can read the session cookie.",
                recommendation="Set HttpOnly (and Secure, SameSite) on session cookies.",
                location=o.url, discriminator=issue["cookie"], evidence=[o]))
    return out


@rule("HTTP-002")
def http_headers(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft("HTTP-002", "Security headers missing", "info", "high", CONFIRMED,
                         f"{o.url} does not send: {', '.join(o.value)}.",
                         recommendation="Add the missing headers where applicable.",
                         location=o.url, evidence=[o]) for o in k.find("http.missing_security_headers") if o.value]


@rule("HTTP-003")
def http_version(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft("HTTP-003", "Web server version disclosed", "info", "high", CONFIRMED,
                         f"{o.url} announces '{o.value}'.",
                         recommendation="Reduce server banners (e.g. Apache ServerTokens Prod).",
                         location=o.url, evidence=[o]) for o in k.find("http.server_version_disclosed")]


@rule("HTTP-004")
def http_listing(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft("HTTP-004", "Directory listing enabled", "low", "high", CONFIRMED,
                         f"{o.url} returns an automatic directory index.",
                         impact="File names (and possibly backups or sensitive files) are browsable.",
                         recommendation="Disable automatic indexes.",
                         next_steps=["Review listed files for sensitive content"],
                         location=o.url, evidence=[o]) for o in _true(k.find("http.directory_listing"))]


@rule("HTTP-005")
def http_login(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft("HTTP-005", "Login form exposed", "info", "high", MANUAL,
                         f"{o.url} presents a password form.",
                         next_steps=[f"Manually test the login at {o.url} for logic flaws, default credentials "
                                     "documented for the product, and injection (authorised testing only)"],
                         location=o.url, evidence=[o]) for o in _true(k.find("http.login_form"))]


@rule("HTTP-006")
def http_paths(k: Knowledge) -> list[FindingDraft]:
    out = []
    for r in k.resources:
        status = r.get("status_code")
        if not INTERESTING_PATHS.search(r.get("path", "")) or status in (404, None) and r.get("source_tool") != "robots.txt":
            continue
        out.append(FindingDraft(
            "HTTP-006", f"Interesting path {r['path']}", "info", "medium", MANUAL,
            f"{r['url']} ({status or 'from ' + r['source_tool']}) matches a name that often holds administrative "
            "functions, backups or configuration.",
            next_steps=[f"Browse {r['url']} manually and assess access control"],
            location=r["url"], discriminator=r["path"], details={"resource": r}))
    return out


@rule("HTTP-007")
def nikto(k: Knowledge) -> list[FindingDraft]:
    by_url: dict[str, list[Observation]] = {}
    for o in k.find("nikto.item"):
        by_url.setdefault(o.url or "?", []).append(o)
    return [FindingDraft("HTTP-007", f"Nikto reported {len(obs)} item(s)", "info", "low", HYPOTHESIS,
                         "Nikto items: " + "; ".join((o.value or {}).get("msg", "")[:90] for o in obs[:5]),
                         next_steps=["Validate each Nikto item manually; many are informational or false positives"],
                         location=url, evidence=obs, details={"items": [o.value for o in obs]})
            for url, obs in by_url.items()]


@rule("HTTP-008")
def hostname_hints(k: Knowledge) -> list[FindingDraft]:
    names = sorted({n for o in k.find("http.hostname_hints") for n in (o.value or [])})
    if not names:
        return []
    return [FindingDraft("HTTP-008", "Untested virtual host names referenced", "info", "high", MANUAL,
                         f"Redirects or certificates reference: {', '.join(names)}.",
                         next_steps=[f"Review with `hints list {k.target}`; if in scope: `hints accept {k.target} "
                                     f"{' '.join(names[:5])}`, then `enumerate {k.target}`"],
                         discriminator=",".join(names), evidence=k.find("http.hostname_hints"))]


@rule("TLS-001")
def tls_cert(k: Knowledge) -> list[FindingDraft]:
    out = []
    for e in k.endpoints:
        tls = json.loads(e.get("tls_json") or "{}")
        verification = (tls.get("verification") or "").lower()
        if verification and "ok" not in verification:
            out.append(FindingDraft("TLS-001", "TLS certificate not trusted", "info", "high", CONFIRMED,
                                    f"{e['url']}: certificate verification failed ({tls.get('verification')}).",
                                    recommendation="Use a certificate from a trusted CA (if the service is user-facing).",
                                    location=e["url"], details={"tls": tls}))
    return out


# --- exposure and correlation --------------------------------------------------------

@rule("SVC-001")
def database_exposed(k: Knowledge) -> list[FindingDraft]:
    out = []
    for s in k.services:
        cats = set(s.categories) & {"mssql", "mysql", "postgresql"}
        if s.state == "open" and cats:
            out.append(FindingDraft(
                "SVC-001", f"Database service reachable ({s.key} {s.banner or s.name})", "low", "high", CONFIRMED,
                f"{next(iter(cats))} is reachable from the tester's network position.",
                impact="Database services exposed to the network increase attack surface; this is not a vulnerability "
                       "by itself.",
                recommendation="Limit database access to the application hosts that need it.",
                next_steps=[f"Review whether {s.key} should be reachable; any authentication testing requires authorisation"],
                service_key=s.key, details={"service": s.to_dict()}))
    return out


@rule("COR-001")
def relay_context(k: Knowledge) -> list[FindingDraft]:
    signing_off = [o for o in k.find("smb.signing_required") if o.value is False]
    domain = k.find("ldap.domain") or k.find("smb.domain")
    if not (signing_off and domain):
        return []
    return [FindingDraft(
        "COR-001", "AD environment with SMB signing not required", "medium", "medium", MANUAL,
        f"The host belongs to the domain {domain[0].value} and does not require SMB signing.",
        impact="In Active Directory environments this combination is a common prerequisite for relay attacks.",
        next_steps=["Map other domain hosts' signing settings (`discover` + `enumerate -m smb` within scope)"],
        service_key="tcp/445", evidence=signing_off + domain[:1])]



# --- Milestone 10: names, Windows/AD without credentials, data services ----------------

_FAILED = re.compile(r"error|not authori[sz]ed|unauthori[sz]ed|auth(entication)? required|requires authentication|"
                     r"NOAUTH|denied|failed|refused", re.IGNORECASE)


def _nse(k: Knowledge, script: str) -> list[Observation]:
    """NSE output that actually answered (not a placeholder, not an auth error)."""
    return [o for o in k.find(f"nse.{script}") if isinstance(o.value, str) and o.value.strip()
            and not _FAILED.search(o.value)]


@rule("VHOST-001")
def vhosts_found(k: Knowledge) -> list[FindingDraft]:
    obs = k.find("http.vhost_found")
    names = sorted({n for o in obs for n in (o.value or [])})
    if not names:
        return []
    return [FindingDraft("VHOST-001", f"{len(names)} additional virtual host(s) answered", "info", "medium", MANUAL,
                         f"Name-based virtual-host discovery found: {', '.join(names[:15])}"
                         + (" ..." if len(names) > 15 else "") + ".",
                         impact="Additional sites on the same server widen the web attack surface.",
                         next_steps=[f"Review with `hints list {k.target}`; accept in-scope names with "
                                     f"`hints accept {k.target} NAME`, then `enumerate {k.target}`"],
                         discriminator=",".join(names), evidence=obs)]


@rule("AD-001")
def ad_srv(k: Knowledge) -> list[FindingDraft]:
    out = []
    for o in k.find("dns.ad_srv"):
        v = o.value if isinstance(o.value, dict) else {}
        if not v.get("services"):
            continue
        dcs = v.get("domain_controllers") or []
        out.append(FindingDraft(
            "AD-001", f"Active Directory DNS records for {v.get('domain')}", "info", "high", CONFIRMED,
            f"The DNS server publishes AD SRV records ({', '.join(v['services'])}); domain controller(s): "
            f"{', '.join(dcs) or 'not listed'}.",
            next_steps=["Confirm which listed domain controllers are in scope before testing them"]
                       + [f"`hints list {k.target}` shows the names; register in-scope DCs as targets"],
            service_key="tcp/53", discriminator=str(v.get("domain")), evidence=[o], details=v))
    return out


@rule("RPC-001")
def rpc_coercion_interfaces(k: Knowledge) -> list[FindingDraft]:
    obs = [o for o in k.find("rpc.notable_interfaces") if o.value]
    if not obs:
        return []
    names = sorted({i.get("name") for o in obs for i in o.value})
    return [FindingDraft(
        "RPC-001", "RPC interfaces associated with authentication coercion are exposed", "low", "medium", MANUAL,
        f"The endpoint mapper lists: {', '.join(names)}.",
        impact="These interfaces (e.g. the print spooler) have been abused to make a host authenticate to an "
               "attacker-controlled system, which can be combined with relaying. Exposure alone is not a vulnerability.",
        recommendation="Disable the print spooler where it is not needed (especially on domain controllers); apply "
                       "current patches and EPA/SMB signing to limit relaying.",
        next_steps=["Confirm with the system owner whether these services are required on this host"],
        service_key=_svc_key(obs[0].url), discriminator=",".join(names), evidence=obs)]


@rule("WINRM-001")
def winrm_exposed(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft(
        "WINRM-001", f"WinRM reachable ({s.key})", "info", "high", CONFIRMED,
        "Windows Remote Management is reachable from the tester's network position.",
        impact="WinRM gives remote shell access to accounts that are allowed to use it; it matters once valid "
               "credentials exist. No authentication was attempted.",
        recommendation="Restrict WinRM to management networks and the accounts that need it.",
        service_key=s.key, details={"service": s.to_dict()})
        for s in k.services if s.state == "open" and "winrm" in s.categories]


@rule("RDP-001")
def rdp_without_nla(k: Knowledge) -> list[FindingDraft]:
    out = []
    for o in k.find("nse.rdp-enum-encryption"):
        text = o.value if isinstance(o.value, str) else ""
        if re.search(r"(Native RDP|SSL):\s*SUCCESS", text):
            out.append(FindingDraft(
                "RDP-001", "RDP accepts connections without Network Level Authentication", "medium", "medium", POTENTIAL,
                "rdp-enum-encryption shows the server accepts a security layer other than CredSSP (NLA).",
                impact="Without NLA the login screen is reached before authenticating, which exposes more code to "
                       "unauthenticated users and leaks host information.",
                recommendation="Require Network Level Authentication for Remote Desktop.",
                service_key=_svc_key(o.url), evidence=[o]))
    return out


def _open_service(rule_id: str, title: str, severity: str, script: str, impact: str, recommendation: str,
                  classification: str = CONFIRMED):
    @rule(rule_id)
    def check(k: Knowledge) -> list[FindingDraft]:
        return [FindingDraft(rule_id, title, severity, "high" if classification == CONFIRMED else "medium",
                             classification, f"{script} answered without credentials:\n{o.value[:400]}",
                             impact=impact, recommendation=recommendation,
                             next_steps=["Confirm the exposure with the system owner; do not read or change data "
                                         "without explicit authorisation"],
                             service_key=_svc_key(o.url), evidence=[o])
                for o in _nse(k, script)]
    check.__name__ = f"open_{rule_id.lower().replace('-', '_')}"
    return check


_open_service("REDIS-001", "Redis answers without authentication", "high", "redis-info",
              "Anyone who can reach the port can read and modify the data store; misconfigured Redis servers are a "
              "well-known route to code execution.",
              "Enable authentication (requirepass / ACLs), bind to localhost or trusted networks, enable protected-mode.")
_open_service("MONGO-001", "MongoDB lists databases without authentication", "high", "mongodb-databases",
              "Database contents may be readable and writable without credentials.",
              "Enable authorization (security.authorization: enabled) and restrict network access.")
_open_service("MEMCACHED-001", "Memcached reachable without authentication", "medium", "memcached-info",
              "Cached data (often sessions or tokens) may be readable; exposed memcached is also used for traffic "
              "amplification.",
              "Bind memcached to localhost or a private interface; enable SASL where supported.")
_open_service("RSYNC-001", "rsync modules listed anonymously", "medium", "rsync-list-modules",
              "Listed modules may allow anonymous file download or upload, depending on their configuration.",
              "Require authentication for rsync modules (auth users / secrets file) and restrict hosts allow.",
              classification=MANUAL)
_open_service("DOCKER-001", "Docker Engine API reachable without authentication", "critical", "docker-version",
              "Control of the Docker API is equivalent to root on the host (containers can mount the host "
              "filesystem).",
              "Never expose the Docker API without TLS client authentication; bind it to a local socket.")


@rule("ES-001")
def elasticsearch_open(k: Knowledge) -> list[FindingDraft]:
    return [FindingDraft(
        "ES-001", "Elasticsearch answers without authentication", "high", "high", CONFIRMED,
        f"Cluster {(o.value or {}).get('cluster_name')!r} (version {(o.value or {}).get('version') or '?'}) answered "
        f"GET / and listed {(o.value or {}).get('indices', 0)} index(es) without credentials.",
        impact="Index contents may be readable and writable by anyone who can reach the port.",
        recommendation="Enable Elasticsearch security (authentication and TLS) and restrict network access.",
        next_steps=["Confirm the exposure with the system owner; do not read documents without explicit authorisation"],
        service_key=_svc_key(o.url), evidence=[o], details=o.value if isinstance(o.value, dict) else {})
        for o in k.find("elasticsearch.unauthenticated")]
