"""Stand-in for nmap used by the tests. Writes canned -oA output and logs its arguments.

Environment:
  FAKE_NMAP_LOG    append one JSON line with argv per invocation
  FAKE_NMAP_HANG   for TCP port scans: write truncated XML + grepable output, then sleep (to be interrupted)
  FAKE_NMAP_FAIL   exit with this code after printing an error
  FAKE_NMAP_PIDFILE  with FAKE_NMAP_HANG: write this process's pid here before sleeping
  FAKE_NMAP_WIDE / FAKE_NMAP_M10  other service mixes (Milestones 6 and 10)
"""

import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakelog  # noqa: E402
import nmap_samples as S  # noqa: E402


def main() -> int:
    argv = sys.argv[1:]
    fakelog.write("FAKE_NMAP_LOG", argv)
    if os.environ.get("FAKE_NMAP_FAIL"):
        print("You requested a scan type which requires root privileges.", file=sys.stderr)
        return int(os.environ["FAKE_NMAP_FAIL"])

    if argv and argv[0] == "--resume":
        header = Path(argv[1]).read_text().splitlines()[0]
        base = re.search(r"-oA (\S+)", header).group(1)
        addr = re.search(r"Host: (\S+)", Path(argv[1]).read_text()).group(1)
        Path(base + ".xml").write_text(S.TCP.format(addr=addr, args="nmap --resume"))
        Path(base + ".gnmap").write_text(S.GNMAP_TCP.format(addr=addr, args=header.split(" as: nmap ", 1)[1]))
        Path(base + ".resumed").write_text(base)
        print("resumed")
        return 0

    base = argv[argv.index("-oA") + 1]
    target = argv[-1]
    args = " ".join(argv)
    wide = os.environ.get("FAKE_NMAP_WIDE")
    m10 = os.environ.get("FAKE_NMAP_M10")  # Milestone 10 service mix
    if "--script" in argv:
        port = argv[argv.index("-p") + 1]
        scripts = "".join(f'<script id="{s}" output="info from {s}"/>' for s in argv[argv.index("--script") + 1].split(","))
        Path(base + ".xml").write_text(S.NSE.format(addr=target, args=args, port=port, scripts=scripts))
        Path(base + ".nmap").write_text("nse\n")
        Path(base + ".gnmap").write_text("")
        return 0
    if "-sn" in argv:
        xml = S.RANGE if "/" in target else S.DISCOVERY_UP
    elif "-sU" in argv:
        xml = S.UDP
    elif "-sV" in argv:
        xml = S.SERVICES_M10 if m10 else S.SERVICES_WIDE if wide else S.SERVICES
    else:
        xml = S.TCP_M10 if m10 else S.TCP_WIDE if wide else S.TCP
        if os.environ.get("FAKE_NMAP_HANG"):
            Path(base + ".xml").write_text(S.TRUNCATED.format(addr=target, args=args))
            Path(base + ".gnmap").write_text(S.GNMAP_TCP.format(addr=target, args=args))
            Path(base + ".nmap").write_text("partial\n")
            if os.environ.get("FAKE_NMAP_PIDFILE"):  # lets a crash test find and stop the orphaned scanner
                Path(os.environ["FAKE_NMAP_PIDFILE"]).write_text(str(os.getpid()))
            sys.stdout.flush()
            time.sleep(60)
            return 0
    Path(base + ".xml").write_text(xml.format(addr=target, args=args))
    Path(base + ".nmap").write_text(f"Nmap scan report for {target}\n")
    Path(base + ".gnmap").write_text(S.GNMAP_TCP.format(addr=target, args=args))
    print(f"Nmap done: 1 IP address (1 host up) scanned for {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
