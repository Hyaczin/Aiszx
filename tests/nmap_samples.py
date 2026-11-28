"""Representative nmap XML output (modelled on nmap 7.9x) with an {addr} placeholder."""

HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
        '<nmaprun scanner="nmap" args="{args}" start="1764072000" startstr="Tue Nov 25 12:00:00 2026" '
        'version="7.95" xmloutputversion="1.05">\n')
FINISHED = ('<runstats><finished time="1764072060" timestr="Tue Nov 25 12:01:00 2026" summary="Nmap done" '
            'elapsed="60.00" exit="success"/><hosts up="1" down="0" total="1"/></runstats>\n</nmaprun>\n')

DISCOVERY_UP = HEAD + """<host><status state="up" reason="echo-reply" reason_ttl="63"/>
<address addr="{addr}" addrtype="ipv4"/><hostnames/></host>
""" + FINISHED

DISCOVERY_DOWN = HEAD + FINISHED.replace('up="1" down="0"', 'up="0" down="1"')

TCP = HEAD + """<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports><extraports state="closed" count="65530"><extrareasons reason="reset" count="65530"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="https" method="table" conf="3"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="microsoft-ds" method="table" conf="3"/></port>
<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack" reason_ttl="127"/><service name="wsman" method="table" conf="3"/></port>
</ports></host>
""" + FINISHED

SERVICES = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="{addr}" addrtype="ipv4"/><hostnames><hostname name="box.htb" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.10" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service>
<script id="ssh-hostkey" output="&#xa;  256 aa:bb (ECDSA)&#xa;  256 cc:dd (ED25519)"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="http" product="nginx" version="1.18.0" extrainfo="Ubuntu" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service>
<script id="http-title" output="Did not follow redirect to http://box.htb/"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="63"/>
<service name="http" product="Apache httpd" version="2.4.52" tunnel="ssl" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="127"/>
<service name="microsoft-ds" method="table" conf="3"/></port>
<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack" reason_ttl="127"/>
<service name="http" product="Microsoft HTTPAPI httpd" version="2.0" extrainfo="SSDP/UPnP" ostype="Windows" method="probed" conf="10"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="95" line="1"/><osmatch name="Linux 4.15" accuracy="90" line="2"/></os>
</host>
""" + FINISHED

UDP = HEAD + """<scaninfo type="udp" protocol="udp" numservices="20" services="53,67-69,123,135,137-139,161-162,445,500,514,520,631,1434,1900,4500,49152"/>
<host><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports><extraports state="closed" count="17"/>
<port protocol="udp" portid="53"><state state="open" reason="udp-response" reason_ttl="63"/><service name="domain" product="ISC BIND" version="9.18.18" method="probed" conf="10"/></port>
<port protocol="udp" portid="123"><state state="open|filtered" reason="no-response" reason_ttl="0"/><service name="ntp" method="table" conf="3"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response" reason_ttl="0"/><service name="snmp" method="table" conf="3"/></port>
</ports></host>
""" + FINISHED

RANGE = HEAD + """<host><status state="up" reason="echo-reply" reason_ttl="63"/><address addr="10.10.10.5" addrtype="ipv4"/><hostnames/></host>
<host><status state="up" reason="reset" reason_ttl="127"/><address addr="10.10.10.7" addrtype="ipv4"/><hostnames><hostname name="dc01.htb" type="PTR"/></hostnames></host>
<host><status state="down" reason="no-response" reason_ttl="0"/><address addr="10.10.10.9" addrtype="ipv4"/><hostnames/></host>
""" + FINISHED

# cut in the middle of the third port: an interrupted scan
TRUNCATED = TCP.split('<port protocol="tcp" portid="443">')[0] + '<port protocol="tcp" portid="443"><state state="op'

GNMAP_TCP = ("# Nmap 7.95 scan initiated Tue Nov 25 12:00:00 2026 as: nmap {args}\n"
             "Host: {addr} ()\tStatus: Up\n"
             "Host: {addr} ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 8080/open/tcp//http-proxy///"
             "\tIgnored State: closed (65532)\n")

# A host with many service types (Milestone 6 tests)
TCP_WIDE = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports>""" + "".join(
    f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack" reason_ttl="63"/></port>'
    for p in (21, 22, 53, 389, 445, 512, 2049, 3306)) + """</ports></host>
""" + FINISHED

SERVICES_WIDE = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports>
<port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" product="vsftpd" version="3.0.3" method="probed" conf="10"/></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/></port>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="ISC BIND" version="9.18" method="probed" conf="10"/></port>
<port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" method="probed" conf="10"/></port>
<port protocol="tcp" portid="512"><state state="open" reason="syn-ack"/><service name="exec" product="netkit-rsh rexecd" method="probed" conf="10"/></port>
<port protocol="tcp" portid="2049"><state state="open" reason="syn-ack"/><service name="nfs" version="3-4" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" product="MySQL" version="8.0.36" method="probed" conf="10"/></port>
</ports></host>
""" + FINISHED

NSE = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports><port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/><service name="x" method="table" conf="3"/>
{scripts}</port></ports></host>
""" + FINISHED


# A Windows/AD host with Milestone 10 services (FAKE_NMAP_M10)
M10_PORTS = (53, 80, 135, 389, 445, 873, 2375, 3389, 5985, 6379, 9200, 11211, 27017)
TCP_M10 = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports>""" + "".join(
    f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack" reason_ttl="127"/></port>'
    for p in M10_PORTS) + """</ports></host>
""" + FINISHED

SERVICES_M10 = HEAD + """<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="{addr}" addrtype="ipv4"/><hostnames/>
<ports>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Simple DNS Plus" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Microsoft IIS httpd" version="10.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="135"><state state="open" reason="syn-ack"/><service name="msrpc" product="Microsoft Windows RPC" method="probed" conf="10"/></port>
<port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/><service name="ldap" product="Microsoft Windows Active Directory LDAP" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" method="probed" conf="10"/></port>
<port protocol="tcp" portid="873"><state state="open" reason="syn-ack"/><service name="rsync" product="rsync" version="protocol version 31" method="probed" conf="10"/></port>
<port protocol="tcp" portid="2375"><state state="open" reason="syn-ack"/><service name="docker" product="Docker" version="24.0.7" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/><script id="rdp-ntlm-info" output="&#xa;  Target_Name: CORP&#xa;  NetBIOS_Computer_Name: DC01&#xa;  DNS_Domain_Name: corp.local&#xa;  DNS_Computer_Name: dc01.corp.local&#xa;  DNS_Tree_Name: corp.local&#xa;"/><script id="ssl-cert" output="Subject: commonName=dc01.corp.local&#xa;Not valid after:  2027-05-01T00:00:00"/></port>
<port protocol="tcp" portid="5985"><state state="open" reason="syn-ack"/><service name="http" product="Microsoft HTTPAPI httpd" version="2.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="6379"><state state="open" reason="syn-ack"/><service name="redis" product="Redis key-value store" version="7.0.11" method="probed" conf="10"/></port>
<port protocol="tcp" portid="9200"><state state="open" reason="syn-ack"/><service name="http" product="Elasticsearch REST API" version="7.17.9" method="probed" conf="10"/></port>
<port protocol="tcp" portid="11211"><state state="open" reason="syn-ack"/><service name="memcache" product="Memcached" version="1.6.21" method="probed" conf="10"/></port>
<port protocol="tcp" portid="27017"><state state="open" reason="syn-ack"/><service name="mongodb" product="MongoDB" version="6.0.5" method="probed" conf="10"/></port>
</ports></host>
""" + FINISHED
