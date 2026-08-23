# Home SOC Lab — RDP Brute-Force Detection with Splunk

A self-built Security Operations Center (SOC) lab simulating a real-world attack scenario: an external attacker brute-forcing RDP credentials against a Windows endpoint, detected and alerted on via Splunk Enterprise.

This project demonstrates end-to-end security monitoring — from attack simulation, to telemetry collection, to detection engineering, to alerting — entirely built on a home lab using VMware Workstation.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │        Isolated Lab Network (NAT)        │
                    │           192.168.130.0/24               │
                    │                                           │
  ┌─────────────┐   │   ┌──────────────┐      ┌─────────────┐  │
  │   Kali      │   │   │  Windows 11  │      │   Ubuntu    │  │
  │   Linux     │───┼──▶│  (Target)    │─────▶│   Server    │  │
  │ (Attacker)  │   │   │              │      │  (Splunk)   │  │
  │             │   │   │ Sysmon +     │      │             │  │
  │ Nmap +      │   │   │ PowerShell   │      │  Splunk     │  │
  │ Hydra       │   │   │ Script Block │      │  Enterprise │  │
  │             │   │   │ Logging +    │      │  10.4.2     │  │
  │ .136        │   │   │ Universal    │      │             │  │
  │             │   │   │ Forwarder    │      │  .134       │  │
  │             │   │   │ .135         │      │  Port 9997  │  │
  └─────────────┘   │   └──────────────┘      └─────────────┘  │
                    └─────────────────────────────────────────┘
                              My Laptop (Host / Control)
```

| Component | Role | IP Address | Key Tools |
|---|---|---|---|
| Ubuntu Server | SIEM — stores & indexes all forwarded logs | 192.168.130.134 | Splunk Enterprise 10.4.2 |
| Windows 11 | Monitored endpoint | 192.168.130.135 | Sysmon (SwiftOnSecurity config), PowerShell Script Block Logging, Splunk Universal Forwarder |
| Kali Linux | Attacker box | 192.168.130.136 | Nmap, Hydra |

---

## Attack Scenario

**Objective:** Simulate an external attacker attempting to gain access to a Windows machine via RDP credential brute-forcing, and build a Splunk detection to catch it in real time.

### Attack Flow

1. **Reconnaissance** — Kali scans the target for open RDP (port 3389)
   ```bash
   nmap -p 3389 192.168.130.135
   ```

2. **Brute-force attack** — Hydra attempts multiple username/password combinations against RDP
   ```bash
   hydra -t 1 -W 3 -L users.txt -P passwords.txt rdp://192.168.130.135
   ```

3. **Windows logs the failures** — Each failed authentication attempt generates **Event ID 4625** (An account failed to log on) in the Windows Security event log, including the source IP, attempted username, and failure reason.

4. **Telemetry is forwarded** — The Splunk Universal Forwarder on the Windows endpoint ships Security, System, Application, Sysmon, and PowerShell Operational logs to the Splunk indexer over port 9997.

5. **Splunk correlates events** — A scheduled search runs every 5 minutes, grouping failed logon attempts by source IP within a rolling 5-minute window.

6. **Alert fires** — When more than 5 failed attempts are detected from a single source within the window, an alert triggers and is logged to Splunk's Triggered Alerts.

---

## Detection Logic

**Search (runs every 5 minutes via cron `*/5 * * * *`):**

```spl
index=main EventCode=4625
| bin _time span=5m
| stats count by Source_Network_Address, _time
| where count > 5
```

**Why this works:**
- `EventCode=4625` isolates failed logon attempts specifically
- `bin _time span=5m` buckets events into 5-minute windows, so bursts of activity are grouped together rather than scattered across a long time range
- `stats count by Source_Network_Address, _time` counts failed attempts per attacking IP, per time bucket
- `where count > 5` flags any IP that failed more than 5 times in a single 5-minute window — a strong signal of automated brute-forcing rather than a user mistyping their password

**Alert configuration:**
- **Type:** Scheduled, cron `*/5 * * * *`
- **Trigger condition:** Number of Results > 0
- **Action:** Add to Triggered Alerts (High severity)

---

## Results

During testing, Hydra executed 15 login attempts against the Windows 11 target in under 90 seconds across three candidate usernames (`vinay`, `admin`, `administrator`). All 15 attempts failed and were logged as Event ID 4625, correctly forwarded to Splunk, and correctly flagged by the detection search:

| Source_Network_Address | _time | count |
|---|---|---|
| 192.168.130.136 | 2026-08-23 08:35:00 | 15 |

The alert fired as expected, confirming the detection pipeline works end-to-end — from raw attack, to endpoint telemetry, to SIEM correlation, to alert.

---

## Build Notes & Troubleshooting

Building this lab surfaced several real-world infrastructure issues, each resolved along the way:

- **Sysmon events not forwarding** — the Splunk Universal Forwarder service ran under a restricted virtual account (`NT SERVICE\SplunkForwarder`) by default, which lacked permission to read the Sysmon Operational log channel. Fixed by reconfiguring the service to run as `LocalSystem`.
- **Splunk receiver not binding to port 9997** — under memory pressure (Ubuntu VM running on 2GB RAM), Splunk's TCP input listener failed to bind reliably. Resolved by increasing the VM's allocated memory to ~3GB and restarting the service.
- **Hydra's RDP module and NLA** — Hydra's experimental FreeRDP-based RDP module initially failed to complete the connection handshake against a target with Network Level Authentication (NLA) enabled. Disabling NLA on the Windows target (`UserAuthentication` registry value) allowed the brute-force attempts to reach the standard NTLM authentication path, which Windows logs natively as Event ID 4625.
- **Timezone/window drift in Splunk searches** — Splunk's relative time ranges (e.g., "Last 60 minutes") can roll past a test window between running an attack and checking results. Using wider fixed windows (or custom absolute time ranges) during testing avoided false "no results."

These are documented here because they reflect genuine operational troubleshooting — the kind of debugging real SOC analysts and lab builders encounter when standing up monitoring infrastructure.

---

## Skills Demonstrated

- SIEM deployment and configuration (Splunk Enterprise)
- Endpoint telemetry engineering (Sysmon, Windows Event Logs, PowerShell Script Block Logging)
- Log forwarding architecture (Splunk Universal Forwarder, TCP inputs)
- Offensive security tooling (Nmap, Hydra) for adversary simulation
- Detection engineering (SPL — Splunk Search Processing Language)
- Alert design and tuning (threshold-based brute-force detection)
- Infrastructure troubleshooting (Windows service permissions, VM resource management, network configuration)

---

## Repository Structure

```
soc-home-lab/
├── README.md                  ← this file
├── docs/
│   ├── architecture.md        ← detailed network/component breakdown
│   ├── detection-writeup.md   ← full technique-to-detection walkthrough
│   └── screenshots/           ← evidence: attack, logs, search, alert
├── config/
│   ├── inputs.conf            ← Universal Forwarder log source config
│   └── sysmonconfig.xml       ← SwiftOnSecurity Sysmon config used
└── detections/
    └── rdp-bruteforce.spl     ← the saved SPL detection query
```

---

## Future Improvements

- Expand detection to cover additional MITRE ATT&CK techniques (e.g., PowerShell abuse via T1059.001, using the existing Script Block Logging pipeline)
- Add a second correlation search combining Sysmon process creation with RDP logon events for post-compromise activity
- Build a Splunk dashboard visualizing failed logon attempts by source IP over time
- Automate the attack simulation with Atomic Red Team for repeatable, documented technique coverage

---

*This is a personal home lab project built for learning and portfolio purposes. All systems involved are isolated virtual machines on a private NAT network with no exposure to production systems or the public internet.*
