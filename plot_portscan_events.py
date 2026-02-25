import csv
import datetime
from collections import defaultdict, Counter

import matplotlib.pyplot as plt


EVENTS_CSV = "portscan_events.csv"


def parse_time(ts_str: str) -> datetime.datetime:
    return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")


def load_events(path: str = EVENTS_CSV):
    times = []
    src_ips = []
    ports_counts = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            times.append(parse_time(row["timestamp"]))
            src_ips.append(row["src_ip"])
            ports_counts.append(int(row["ports_in_window"]))

    return times, src_ips, ports_counts


def plot_port_activity_over_time(times, ports_counts):
    counts_per_minute = defaultdict(int)
    max_ports_per_minute = defaultdict(int)

    for t, p_count in zip(times, ports_counts):
        bucket = t.replace(second=0, microsecond=0)
        counts_per_minute[bucket] += 1
        if p_count > max_ports_per_minute[bucket]:
            max_ports_per_minute[bucket] = p_count

    xs = sorted(counts_per_minute.keys())
    ys_events = [counts_per_minute[x] for x in xs]
    ys_ports = [max_ports_per_minute[x] for x in xs]

    plt.figure(figsize=(10, 4))
    plt.plot(xs, ys_events, marker="o", label="Events")
    plt.plot(xs, ys_ports, marker="x", label="Max distinct ports in window")
    plt.title("Port Scan Activity Over Time")
    plt.xlabel("Time (per minute)")
    plt.ylabel("Count")
    plt.legend()
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def plot_top_scanners(src_ips, top_n: int = 10):
    counts = Counter(src_ips)
    most_common = counts.most_common(top_n)
    if not most_common:
        print("No events to plot.")
        return

    labels = [ip for ip, _ in most_common]
    values = [c for _, c in most_common]

    plt.figure(figsize=(8, 4))
    plt.bar(labels, values)
    plt.title("Top Suspected Port Scanning IPs")
    plt.xlabel("Source IP")
    plt.ylabel("Events")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()


def main():
    try:
        times, src_ips, ports_counts = load_events()
    except FileNotFoundError:
        print("portscan_events.csv not found. Run portscan_analyzer.py first.")
        return

    if not times:
        print("No events in CSV.")
        return

    plot_port_activity_over_time(times, ports_counts)
    plot_top_scanners(src_ips)


if __name__ == "__main__":
    main()

