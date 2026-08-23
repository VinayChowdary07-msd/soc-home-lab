# Detection Write-Up: RDP Brute-Force via Hydra

## Summary

| Field | Value |
|---|---|
| **Technique** | Brute Force — Credential access via repeated authentication attempts |
| **MITRE ATT&CK** | T1110.001 (Password Guessing) / T1110.003 (Password Spraying) |
| **Target Protocol** | RDP (TCP/3389) |
| **Attack Tool** | THC-Hydra v9.7 |
| **Detection Data Source** | Windows Security Event Log (Event ID 4625) |
| **Detection Method** | Splunk scheduled search, rolling 5-minute correlation |

---

## 1. Attack Simulation

From the Kali Linux attacker VM (`192.168.130.136`), reconnaissance confirmed RDP was exposed on the target Windows 11 endpoint (`192.168.130.135`):

```bash
nmap -p 3389 192.168.130.135
```
```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

A brute-force attack was then launched using Hydra against a small candidate username/password list:

```bash
echo -e "vinay\nadministrator\nadmin" > users.txt
echo -e "password\n123456\nadmin123\nletmein\nqwerty" > passwords.txt
hydra -t 1 -W 3 -L users.txt -P passwords.txt rdp://192.168.130.135
```

**Note on tooling:** Hydra's RDP module relies on FreeRDP and is explicitly marked "experimental" by its maintainers. In testing, the attack initially failed to reach the standard NTLM authentication path while Network Level Authentication (NLA) was enabled on the target, since NLA requires a CredSSP handshake to complete before Windows performs a full logon attempt. Disabling NLA on the target (a config choice, not a Hydra fix) allowed the attack to reach standard NTLM auth, which Windows audits natively.

---

## 2. Telemetry Generated

Each failed authentication attempt produced a **Windows Security Event ID 4625** ("An account failed to log on") on the target endpoint. Sample event:

```
LogName=Security
EventCode=4625
Account For Which Logon Failed:
    Account Name: admin
Failure Information:
    Failure Reason: Unknown user name or bad password.
    Status: 0xC000006D
    Sub Status: 0xC0000064
Network Information:
    Workstation Name: kali
    Source Network Address: 192.168.130.136
Detailed Authentication Information:
    Logon Process: NtLmSsp
    Authentication Package: NTLM
```

Key fields for detection:
- **`EventCode`** = 4625 (failed logon)
- **`Source_Network_Address`** = the attacker's IP — critical for attribution and correlation
- **`Account Name`** (attempted) — varies per attempt since Hydra rotated across 3 candidate usernames
- **`Logon_Type`** = 3 (network logon), consistent with a remote authentication attempt rather than console/interactive access

In this test run, 15 attempts were made across ~90 seconds, all from the same source IP, targeting 3 different usernames — a pattern consistent with automated credential brute-forcing rather than legitimate user error.

---

## 3. Log Forwarding Path

```
Windows Security Event Log
        ↓
Splunk Universal Forwarder (monitoring WinEventLog://Security)
        ↓  (TCP 9997)
Splunk Enterprise Indexer (Ubuntu, index=main)
```

The Universal Forwarder was configured via `inputs.conf` to monitor the Security channel (alongside Sysmon, PowerShell Operational, Application, and System logs) and forward to the indexer at `192.168.130.134:9997`.

**Operational note:** the forwarder's Windows service must run with sufficient privileges to read all configured event log channels. Running under the default restricted service account caused Sysmon-specific events to silently fail to forward (no error, just missing data) — switching the service to run as `LocalSystem` resolved this. This is a common real-world gotcha when deploying forwarders with least-privilege service accounts.

---

## 4. Detection Query

```spl
index=main EventCode=4625
| bin _time span=5m
| stats count by Source_Network_Address, _time
| where count > 5
```

**Query breakdown:**

| Clause | Purpose |
|---|---|
| `index=main EventCode=4625` | Isolate failed logon events only |
| `bin _time span=5m` | Group events into discrete 5-minute time buckets |
| `stats count by Source_Network_Address, _time` | Count failed attempts per source IP, per bucket |
| `where count > 5` | Flag only IPs exceeding a reasonable failure threshold within one window |

**Threshold rationale:** A single legitimate user might fail a login once or twice (mistyped password, expired credentials). More than 5 failures from the *same source IP* within a 5-minute window is a strong statistical signal of automated attack behavior rather than human error — this is a widely used baseline threshold in real SOC brute-force detection rules, though it should be tuned against an organization's actual authentication failure baseline in production.

### Test Result

| Source_Network_Address | _time | count |
|---|---|---|
| 192.168.130.136 | 2026-08-23 08:35:00 | 15 |

The detection correctly identified the Kali attacker IP with 15 failures — 3x the alert threshold — confirming the query behaves as intended against real attack traffic.

---

## 5. Alert Configuration

| Setting | Value |
|---|---|
| Title | RDP Brute Force Detection |
| Type | Scheduled |
| Schedule | Cron `*/5 * * * *` (every 5 minutes) |
| Trigger Condition | Number of Results > 0 |
| Trigger Action | Add to Triggered Alerts (High severity) |

The alert was validated live: after re-running the Hydra attack, the scheduled search correctly fired on its next cron cycle and logged an entry to Splunk's Triggered Alerts, confirmed across 6 consecutive scheduled runs.

---

## 6. Tuning Considerations (Lessons Learned)

A few refinements worth noting for a production-grade version of this detection:

1. **Search window scope:** the alert's underlying search currently scans a "Last 4 hours" window on each run. This means a single burst of failed logons can cause the alert to keep re-firing on every subsequent 5-minute cron cycle until the original events age out of the 4-hour lookback — even with no new attack activity. A tighter time window (e.g., matching the cron interval, "Last 5 minutes") would make the alert reflect only genuinely new activity per cycle, avoiding redundant re-triggers and alert fatigue.
2. **Account name normalization:** some 4625 events recorded a blank (`-`) account name field rather than the attempted username, depending on the exact failure stage. Detection logic should key off `Source_Network_Address` (as done here) rather than `Account_Name` alone, since source IP is consistently populated across all failure types, while account name is not.
3. **Correlate with success:** a stronger detection would also check for a *successful* logon (`EventCode=4624`) from the same source shortly after a failure burst — this would distinguish "brute-force attempt, no breach" from "brute-force attempt that succeeded," which is a much higher-severity finding.

---

## Appendix: Environment

| Component | Details |
|---|---|
| Splunk Enterprise | 10.4.2 |
| Splunk Universal Forwarder | 10.4.2 |
| Sysmon | With SwiftOnSecurity community config |
| Windows Target OS | Windows 11 Pro |
| Attacker OS | Kali Linux (official VMware image) |
| Network | VMware Workstation NAT, 192.168.130.0/24 |
