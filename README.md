# Windows Security Telemetry & Identity Attack Detection (Splunk)

I built a small two-VM lab: a Windows 10 machine sends its Security event log to Splunk on Ubuntu through the Splunk Universal Forwarder. Then I ran simple identity attacks on the Windows machine (failed logons, creating a backdoor admin account) and wrote SPL searches to detect them.

**Tools:** Splunk Enterprise 10.4, Splunk Universal Forwarder, VirtualBox, PowerShell.

---

## Lab setup

```
+--------------------------+        TCP/9997         +---------------------------+
|   Windows 10 (victim)    |  -------------------->  |   Ubuntu (Splunk SIEM)    |
|   Universal Forwarder    |  WinEventLog:Security   |   Web UI on TCP/8000      |
+--------------------------+                         +---------------------------+
          VirtualBox NAT Network (both VMs can reach each other)
```

**Splunk (Ubuntu):** Settings → Forwarding and receiving → Receive data → listen on port `9997`.

**Forwarder (Windows):** `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

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

---

## Attack 1: Failed logons with fake accounts (password spraying)

One password tried against 12 accounts that don't exist (`FakeAdmin1` … `FakeAdmin12`), from PowerShell on the Windows VM:

```powershell
1..12 | ForEach-Object { net use \\127.0.0.1 /user:FakeAdmin"$_" "WrongPass2026!" 2>$null }
```

Each attempt should create an Event **4625** (an account failed to log on). MITRE: **T1110.003 – Password Spraying** (same password, many usernames).

**Detection:**

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| eval TargetUser = coalesce(TargetUserName, Target_Account, user, "Unknown")
| eval SourceIP = coalesce(IpAddress, src_ip, Source_Network_Address, "Local/127.0.0.1")
| eval Workstation = coalesce(WorkstationName, Workstation_Name, host)
| stats count as Failed_Attempts, values(Workstation) as Workstation by TargetUser, SourceIP
| sort - Failed_Attempts
```

**Result:** 8 failed logons, 7 of them from `127.0.0.1`.

**Things I noticed in the result:**
- `TargetUser` shows **Unknown**, which means none of the field names in my `coalesce()` matched the username field in this Splunk version. Next fix: check the raw event, find the real field name (for example `Account_Name`), and add it.
- I ran 12 attempts but got 8 events, so some attempts didn't generate a 4625. I'd check this by looking at the raw events and the `Failure Reason` / status code. A user that doesn't exist (`0xC0000064`) and a wrong password (`0xC000006A`) have different codes, and that difference is useful when telling spraying apart from a real user who forgot their password.

![Failed logon detection](evidence/Active%20Detection%20Brute%20Force.png)

---

## Attack 2: Backdoor admin account

```powershell
net user RogueAnalyst "P@ssw0rdSecure2026!" /add
net localgroup Administrators RogueAnalyst /add
```

| Event ID | Meaning | MITRE |
| :--- | :--- | :--- |
| **4720** | A user account was created | T1136.001 – Create Account: Local Account |
| **4732** | A member was added to a security-enabled local group (Administrators) | T1098 – Account Manipulation |

**Detection:**

```spl
index=main sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| eval Activity=case(EventCode=4720, "User account created", EventCode=4732, "Added to Administrators")
| eval Target = coalesce(TargetUserName, MemberName, "RogueAnalyst")
| eval Operator = coalesce(SubjectUserName, user, "Administrator")
| table _time, EventCode, Activity, Operator, Target
| sort - _time
```

A new account that gets admin rights within seconds of being created is a classic persistence pattern, and both events appear one after the other in the timeline.

![Account creation and privilege escalation](evidence/Privilege%20Escalation%201.png)

![Event details](evidence/Privilege%20Escalation%202.png)

---

## How I'd triage these alerts

| Alert | Severity | First steps |
| :--- | :--- | :--- |
| Many 4625 from one source | Medium | Check the source IP and usernames, check for account lockouts, look for a successful logon (4624) right after |
| 4720 (new account) | High | Confirm whether there's an approved change request; if not, disable the account |
| 4732 (added to Administrators) | Critical | Remove it from the group, isolate the host, and find out which account made the change |

**Author:** Alejandro José Vargas
