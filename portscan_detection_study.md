## Port Scan Detection Engineering Lab

### 1. Introduction

Port scanning is a common reconnaissance technique used by attackers to discover open services and potential entry points on target systems. Tools such as Nmap allow rapid scanning of many ports and hosts using different scan types (e.g., TCP connect, SYN, UDP). From a defender’s perspective, port scans are often the earliest observable sign of malicious activity and are therefore an important focus for detection engineering.

This project presents a controlled, lab-based **Port Scan Detection Engineering Lab**. The objectives are to:

- Generate realistic port scan traffic using Nmap from a Kali Linux attacker VM.  
- Capture and analyze network traffic and/or logs from a target VM.  
- Design and implement detection logic in both:
  - A custom Python analyzer using Scapy on PCAPs.  
  - SIEM queries for Splunk or ELK (Elasticsearch/Kibana).  
- Discuss strategies to detect reconnaissance while minimizing false positives.

All experiments are performed in an isolated virtual lab and are intended solely for educational, defensive purposes.

---

### 2. Lab Architecture

#### 2.1 Components

- **Attacker VM**  
  - Kali Linux  
  - Tool: Nmap (various scan types)  
  - Role: Actively perform port scans against the target.

- **Target VM**  
  - Linux or Metasploitable server  
  - Exposes a small set of services (e.g., SSH, HTTP, FTP)  
  - Runs on the same internal/host-only network as Kali.

- **Collector / SIEM**  
  - Optional Splunk or ELK stack, ingesting:
    - Firewall/network device logs, or  
    - PCAPs converted into flow logs.

Traffic captures are performed using `tcpdump` or Wireshark on the target, attacker, or a monitoring interface on the host.

#### 2.2 Network Layout (Textual Example)

Example Host-only network: `192.168.58.0/24`

- Kali (attacker): `192.168.58.10`  
- Target server: `192.168.58.20`  
- Optional SIEM node: `192.168.58.30`

Network mode is set to **Host-only** or **Internal** in the hypervisor to avoid scanning external networks.

#### 2.3 Safety and Ethics

- Perform all scanning only within the controlled lab network you own.  
- Do not bridge the scanning interface to the physical LAN or Internet.  
- Do not scan systems without explicit permission.  
- Use dedicated lab VMs and revert to snapshots after testing if necessary.

---

### 3. Port Scan Simulation with Nmap

Several Nmap scan types can be used to generate diverse patterns for detection:

- **TCP Connect Scan** (`-sT`)  
  - Completes the full TCP handshake to each target port.  
  - Generates standard `SYN`, `SYN/ACK`, `ACK`, and possibly `RST` packets.

- **SYN Scan** (`-sS`)  
  - Sends `SYN` packets and infers port state based on replies without completing the full handshake.  
  - More stealthy; often leaves many half-open connections.

- **UDP Scan** (`-sU`)  
  - Probes UDP ports; responses or ICMP errors inform port state.  
  - Typically slower but useful for detecting UDP reconnaissance.

Example conceptual commands from Kali (do not run outside lab):

```bash
nmap -sT -p 1-1000 192.168.58.20
nmap -sS -p 1-1000 192.168.58.20
nmap -sU -p 1-200 192.168.58.20
```

The target or monitor host captures the resulting traffic for analysis.

---

### 4. Packet Capture and Traffic Characteristics

#### 4.1 Capture Setup

Use `tcpdump` or Wireshark on the target or a monitoring host:

```bash
sudo tcpdump -i eth0 -w portscan_lab.pcap
```

Run the Nmap scans while capturing, then stop `tcpdump` and save the PCAP for offline analysis.

#### 4.2 Observed Patterns

Typical features of port scan traffic:

- High number of short-lived connection attempts from a single source IP.  
- Many distinct destination ports probed on the same host (vertical scan).  
- Many destination hosts probed on one or a few ports (horizontal scan).  
- For SYN scans:
  - Large number of `SYN` packets with fewer completed handshakes.  
  - Possible `RST` responses when ports are closed.

These behavioral patterns form the basis for both signature-style rules and statistical anomaly detection.

---

### 5. Python-Based Port Scan Analyzer

#### 5.1 Goals

The Python script `portscan_analyzer.py` provides offline or live detection using packet data. It:

- Reads from a PCAP (`-r`) or live interface (`-i`) via Scapy.  
- Maintains a sliding window of recent packets.  
- For each source IP, tracks:
  - Number of distinct destination ports probed.  
  - Number of distinct destination hosts contacted.  
- Raises an alert if those counts exceed configurable thresholds within the time window.  
- Logs contextual events to `portscan_events.csv` for visualization.

#### 5.2 Detection Heuristic

Key configuration parameters:

- `PORT_THRESHOLD` (default 20): minimum number of unique destination ports in a window to suspect a vertical scan.  
- `HOST_THRESHOLD` (default 10): minimum number of unique destination hosts in a window to suspect a horizontal scan.  
- `WINDOW_SECONDS` (default 60): duration of the sliding window.

If either threshold is exceeded for a source IP inside the window, the analyzer prints an alert:

> `[ALERT] Possible port scan from <src_ip>: <ports> ports and <hosts> hosts in <window>s window`

#### 5.3 Usage

Offline analysis:

```bash
python3 portscan_analyzer.py -r portscan_lab.pcap
```

Live capture:

```bash
sudo python3 portscan_analyzer.py -i eth0
```

The script writes:

- Alerts to the console.  
- Detailed events to `portscan_events.csv`:
  - Timestamp, source IP, destination IP, destination port, protocol, counts of distinct ports and hosts in the current window.

---

### 6. Visualization

The script `plot_portscan_events.py` reads `portscan_events.csv` and provides a basic CLI dashboard using matplotlib.

#### 6.1 Plots

- **Port Scan Activity Over Time**  
  - Time-series per minute with:
    - Total number of recorded events.  
    - Maximum number of distinct ports probed within the detection window.  
  - Helps visualize when scans occurred and their intensity.

- **Top Suspected Scanning IPs**  
  - Bar chart of source IPs sorted by number of events.  
  - Quickly identifies the most active scanners.

Run:

```bash
python3 plot_portscan_events.py
```

after generating `portscan_events.csv` with the analyzer.

---

### 7. SIEM Detection with Splunk or ELK

#### 7.1 Data Assumptions

In a SIEM environment, port scan detection relies on:

- Network, firewall, or IDS logs containing at least:
  - `src_ip`, `dest_ip`, `dest_port`, `protocol`, timestamp.  
  - Optionally TCP flags or `action` (allowed/blocked).

The file `splunk_elk_portscan_queries.txt` provides example queries.

#### 7.2 Splunk Queries

Example Splunk search for vertical port scans (many ports per source IP in 5 minutes):

```spl
index=net action=allowed OR action=blocked
| bucket _time span=5m
| stats dc(dest_port) AS uniq_ports count AS total_events BY _time, src_ip
| where uniq_ports >= 20
| sort - uniq_ports
```

For horizontal scans (many destination hosts per source IP and port):

```spl
index=net action=allowed OR action=blocked
| bucket _time span=5m
| stats dc(dest_ip) AS uniq_hosts count AS total_events BY _time, src_ip, dest_port
| where uniq_hosts >= 10
| sort - uniq_hosts
```

SYN scan heuristic (if TCP flags are logged):

```spl
index=net protocol=TCP
| search flags="S*"
| bucket _time span=5m
| stats dc(dest_port) AS uniq_ports count AS syn_count BY _time, src_ip
| where uniq_ports >= 20 AND syn_count > 30
| sort - uniq_ports
```

#### 7.3 ELK / Elasticsearch

In ELK, similar logic is implemented using aggregations:

- Filter on candidate traffic (e.g., `event.action:(allowed OR blocked) AND network.transport:(tcp OR udp)`).  
- Aggregate by `source.ip` and 5-minute time buckets.  
- Compute unique counts of `destination.port` and `destination.ip`.  
- Apply thresholds to highlight potential scanners.

These visualizations can be built as Kibana Lens or traditional visualizations with bar charts, line charts, and data tables.

---

### 8. Results (Example Narrative)

In lab experiments:

- Nmap scans from Kali (`-sT`, `-sS`, `-sU`) against the target produced clearly visible spikes in network connection attempts.  
- The Python analyzer flagged the Kali IP as a suspected scanner when:
  - Over 20 distinct TCP ports were contacted within 60 seconds in vertical scans.  
  - Many hosts were probed during horizontal scan tests.  
- The resulting `portscan_events.csv` showed the progression of ports and hosts probed over time, which was visualized using `plot_portscan_events.py`.  
- Splunk queries run against simulated flow/firewall logs successfully identified scanning hosts, with filters and thresholds helping reduce false positives from regular application behavior.

---

### 9. Conclusion

This Port Scan Detection Engineering Lab demonstrates how a combination of packet-level analysis and SIEM queries can effectively identify reconnaissance activity in a controlled network environment. By using Nmap to generate realistic scan traffic and analyzing it with both a Python-based detector and Splunk/ELK searches, this project illustrates key detection strategies that can be adapted to larger, real-world deployments.

The approach emphasizes behavioral indicators—such as counts of distinct ports and hosts over time—rather than relying solely on static signatures. This makes the detection logic more robust against changes in specific tools while still providing interpretable, rule-based methods suitable for academic and operational use.

---

### 10. Future Work

Potential extensions for this project include:

- **Integration with IDS/IPS**: Incorporate Suricata or Zeek to generate richer logs and leverage built-in scan detection scripts.  
- **Adaptive Thresholds**: Use baselining or anomaly detection to dynamically adjust thresholds per network segment or host type.  
- **Machine Learning**: Experiment with clustering or supervised learning models on flow features (e.g., counts, rates, unique destinations) to distinguish benign scanning (e.g., vulnerability management tools) from malicious reconnaissance.  
- **Automated Response**: Connect SIEM alerts to orchestration tools (SOAR) to automatically rate-limit or temporarily block suspected scanning IPs in the lab.

