# Active Directory & Windows Telemetry: Threat Detection & Security Insights with Splunk

## Project Overview
This project simulates enterprise-level identity monitoring and security analytics using **Splunk Enterprise** as a centralized SIEM and the **Splunk Universal Forwarder** to collect and ingest Windows Security Event logs (`Security.evtx`).

The objective is to establish end-to-end detection engineering: ingesting live endpoint events, simulating credential-based attacks, mapping malicious techniques to the **MITRE ATT&CK framework**, and developing targeted detection logic (SPL) to mitigate identity-based risks.

---

## Architectural Topology
* **SIEM Platform (Monitoring Server):** Splunk Enterprise deployed on Ubuntu Linux (Log Ingestion on TCP/9997, Web UI on TCP/8000).
* **Telemetry Source (Endpoint / Domain Simulation):** Windows 10 client forwarding Windows Security Event logs (`WinEventLog:Security`) via Splunk Universal Forwarder.
* **Network Infrastructure:** Isolated VirtualBox Private NAT Network ensuring bidirectional communication between hosts.

+--------------------------+          TCP/9997           +---------------------------+
|    Windows 10 Victim     |  ------------------------>  |     Ubuntu Splunk SIEM    |
| (Universal Forwarder)    |   (WinEventLog:Security)    | (Ingestion & Dashboards)  |
+--------------------------+                             +---------------------------+

---

## Ingestion Pipeline Configuration

### 1. Splunk Indexer Receiver Setup (Ubuntu)
Splunk was configured to listen for incoming forwarder connections on port `9997`:
* **Path:** `Settings` > `Forwarding and receiving` > `Receive data` > `Listen on port 9997`.

### 2. Universal Forwarder Ingestion Configuration (Windows 10)
Configured via `inputs.conf` located in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[default]
host = Win10Victim

[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
index = main
```
### 3. Attack Simulation & MITRE ATT&CK Mapping 

1. Brute-Force & Password Spraying (MITRE ATT&CK T1110)

Technique: T1110.001 - Password Guessing / Password Spraying.

Execution: Executed high-frequency authentication attempts across non-existent user accounts (FakeAdmin1..12) using bad password seeds via PowerShell:
```
1..12 | ForEach-Object { net use \\127.0.0.1 /user:FakeAdmin"$_" "WrongPass2026!" 2>$null }
```
Telemetric Artifact: Rapid bursts of Windows Event ID 4625 (An account failed to log on) with status code 0xC000006A (bad username/password).

2. Unauthorized Account Creation & Local Group Escalation (MITRE ATT&CK T1136 & T1098)

Technique: T1136.001 (Create Local Account) & T1098 (Account Manipulation).

Execution: Adversary staging a backdoor administrative account and persisting by elevating privileges into the local Administrators security group:
```
net user RogueAnalyst "P@ssw0rdSecure2026!" /add
net localgroup Administrators RogueAnalyst /add
```
Telemetric Artifacts:

Event ID 4720: A user account was created.

Event ID 4732: A member was added to a security-enabled local group.

### 4. Detection Engineering & Analytics 

Query 1: High-Frequency Failed Authentication (Brute-Force Detection)
Logic: Aggregates failed logon attempts (4625) by targeted account, originating IP, and workstation name. Enforces an alert threshold (> 5 attempts) to isolate brute-force spikes from routine human typographical error.

```
index=main sourcetype="WinEventLog:Security" EventCode=4625
| eval TargetUser = coalesce(TargetUserName, Target_Account, user, "Unknown")
| eval SourceIP = coalesce(IpAddress, src_ip, Source_Network_Address, "Local/127.0.0.1")
| eval Workstation = coalesce(WorkstationName, Workstation_Name, host)
| stats count as Failed_Attempts, values(Workstation) as Workstation by TargetUser, SourceIP
| sort - Failed_Attempts
```

Query 2: Account Lifecycle & Privilege Escalation Audit
Logic: Tracks the creation of new security principals (4720) and immediate administrative privilege delegation (4732), correlating the executing user with the target backdoor account.

```
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| eval Activity=case(EventCode=4720, "User Account Provisioned", EventCode=4732, "Privilege Elevation (Administrators)")
| eval Target = coalesce(TargetUserName, MemberName, "RogueAnalyst")
| eval Operator = coalesce(SubjectUserName, user, "Administrator")
| table _time, EventCode, Activity, Operator, Target
| sort - _time
```

---

## Key SOC Findings & Investigative Triage

| Incident / Telemetry Indicator | Target Account | MITRE ATT&CK Tactic & Technique | Triage Severity | Recommended L1/L2 SOC Action |
| :--- | :--- | :--- | :--- | :--- |
| **Event ID 4625 (>5 Failures)** | `Unknown` / Target Seed | Credential Access (T1110) | **Medium** | Verify `SourceIP`, check for account lockout status, correlate with perimeter firewall traffic. |
| **Event ID 4720** | `RogueAnalyst` | Persistence (T1136.001) | **High** | Validate account creation against change control tickets; disable unauthorized account immediately. |
| **Event ID 4732** | `RogueAnalyst` | Privilege Escalation (T1098) | **Critical** | Remove account from local Administrators group, isolate host from network, and collect memory dump for forensic analysis. |

---

## Evidence & Verification

### 1. Brute-Force & Credential Access Detection
Detection of high-frequency logon failures using Event ID 4625 aggregated by source IP and target principal.

![Brute Force Detection](evidence/Active%20Detection%20Brute%20Force.png)

### 2. Unauthorized Account Provisioning & Privilege Escalation
Telemetry correlation showing the creation of `RogueAnalyst` (Event ID 4720) and subsequent addition to the local Administrators group (Event ID 4732).

![Privilege Escalation Detection 1](evidence/Privilege%20Escalation%201.png)

Detailed event breakdown and timestamp sequencing:

![Privilege Escalation Detection 2](evidence/Privilege%20Escalation%202.png)
