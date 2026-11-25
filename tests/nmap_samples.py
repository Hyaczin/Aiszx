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
