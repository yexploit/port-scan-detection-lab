import argparse
import csv
import time
from collections import defaultdict, Counter

from scapy.all import sniff, rdpcap, IP, TCP, UDP
from pyfiglet import Figlet
from colorama import Fore, Style, init
import shutil


# -----------------------------
# Configuration
# -----------------------------
# How many distinct ports/hosts in a window before we suspect scanning
PORT_THRESHOLD = 20          # distinct destination ports
HOST_THRESHOLD = 10          # distinct destination hosts
WINDOW_SECONDS = 60          # time window in seconds

EVENTS_CSV = "portscan_events.csv"


init(autoreset=True)


def center_text(text: str) -> str:
    """Center text based on current terminal width."""
    try:
        width = shutil.get_terminal_size().columns
    except OSError:
        width = 80
    return text.center(width)


def banner() -> None:
    """Display PORTSCAN / DETECT banner using pyfiglet + colorama."""
    f = Figlet(font="slant")

    portscan_lines = f.renderText("PORTSCAN").splitlines()
    detect_lines = f.renderText("DETECT").splitlines()

    print("\n")
    for p, d in zip(portscan_lines, detect_lines):
        line = Fore.CYAN + p + "  " + Fore.RED + d
        print(center_text(line))

    print("\n")
    print(center_text(Style.BRIGHT + "PORT SCAN DETECTION LAB"))
    print(center_text(Fore.RED + "By yexploit"))
    print("\n")


class SlidingWindow:
    """Maintain events in a sliding time window."""

    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self.events: list[tuple[float, str, str, int, str]] = []

    def add(self, ts: float, src: str, dst: str, dport: int, proto: str) -> None:
        self.events.append((ts, src, dst, dport, proto))
        self._trim(ts)

    def _trim(self, current_ts: float) -> None:
        cutoff = current_ts - self.window_seconds
        # Remove events older than cutoff
        while self.events and self.events[0][0] < cutoff:
            self.events.pop(0)

    def get_events_for_src(self, src: str) -> list[tuple[float, str, str, int, str]]:
        return [e for e in self.events if e[1] == src]


def write_events_header(path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "timestamp",
                "src_ip",
                "dst_ip",
                "dst_port",
                "protocol",
                "ports_in_window",
                "hosts_in_window",
            ]
        )


def append_event(
    path: str,
    ts: float,
    src: str,
    dst: str,
    dport: int,
    proto: str,
    ports_count: int,
    hosts_count: int,
) -> None:
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                src,
                dst,
                dport,
                proto,
                ports_count,
                hosts_count,
            ]
        )


class PortscanDetector:
    """Simple port scan detector using a sliding window over packets."""

    def __init__(self, window_seconds: int) -> None:
        self.window = SlidingWindow(window_seconds)
        self.alerted_sources: set[str] = set()

    def handle_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        proto = None
        dport = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            dport = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto = "UDP"
            dport = int(pkt[UDP].dport)
        else:
            return

        ts = float(pkt.time)
        src = ip.src
        dst = ip.dst

        # Record event in sliding window
        self.window.add(ts, src, dst, dport, proto)
        src_events = self.window.get_events_for_src(src)

        dst_ports = {e[3] for e in src_events}
        dst_hosts = {e[2] for e in src_events}

        ports_count = len(dst_ports)
        hosts_count = len(dst_hosts)

        # Simple heuristic: many ports or many hosts in window -> likely port scan
        if (
            (ports_count >= PORT_THRESHOLD or hosts_count >= HOST_THRESHOLD)
            and src not in self.alerted_sources
        ):
            print(
                f"[ALERT] Possible port scan from {src}: "
                f"{ports_count} ports and {hosts_count} hosts in {WINDOW_SECONDS}s window"
            )
            self.alerted_sources.add(src)

        # Log every event with context for later visualization
        append_event(EVENTS_CSV, ts, src, dst, dport, proto, ports_count, hosts_count)


def analyze_pcap(pcap_file: str) -> None:
    print(f"[*] Reading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    detector = PortscanDetector(WINDOW_SECONDS)
    write_events_header(EVENTS_CSV)

    for pkt in packets:
        detector.handle_packet(pkt)

    print("[*] PCAP analysis complete. Events written to", EVENTS_CSV)


def live_capture(interface: str) -> None:
    print(f"[*] Starting live capture on interface: {interface}")
    detector = PortscanDetector(WINDOW_SECONDS)
    write_events_header(EVENTS_CSV)

    def _callback(pkt):
        detector.handle_packet(pkt)

    bpf = "tcp or udp"
    sniff(iface=interface, filter=bpf, prn=_callback, store=False)


def main() -> None:
    banner()
    parser = argparse.ArgumentParser(
        description="Port Scan Detection Analyzer (PCAP or live traffic)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--interface", help="Interface for live capture (e.g., eth0)")
    group.add_argument("-r", "--read-pcap", help="PCAP file to analyze")

    args = parser.parse_args()

    print("[*] Port Scan Detection Analyzer")
    print(
        f"[*] Thresholds: {PORT_THRESHOLD} ports or {HOST_THRESHOLD} hosts "
        f"within {WINDOW_SECONDS} seconds"
    )

    if args.interface:
        live_capture(args.interface)
    else:
        analyze_pcap(args.read_pcap)


if __name__ == "__main__":
    main()

