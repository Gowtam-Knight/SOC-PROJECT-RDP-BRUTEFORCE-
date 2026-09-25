# Splunk SIEM Detection Engineering & SPL Query Playbook

This document details all Splunk Search Processing Language (SPL) queries engineered and utilized throughout the investigation to detect, visualize, and alert on RDP Brute-Force attacks.

---

## 1. Quick Baseline: Identify All Failed Logon Events

### SPL Query:
```spl
index=wineventlog EventCode=4625
| stats count by src_ip, user, Workstation_Name, Logon_Type
| sort - count
```
### Description:
Provides an immediate macro overview of all authentication failures across the network, grouping by source IP, targeted username, workstation name, and logon type.

---

## 2. RDP Specific Brute-Force Failure Triage (Logon Type 10)

### SPL Query:
```spl
index=wineventlog EventCode=4625 (Logon_Type=10 OR LogonType=10)
| stats count as Failed_Attempts,
        earliest(_time) as First_Seen,
        latest(_time) as Last_Seen,
        values(Sub_Status) as Failure_Codes
        by src_ip, user
| eval Duration_Minutes=round((Last_Seen-First_Seen)/60, 2)
| convert ctime(First_Seen) ctime(Last_Seen)
| where Failed_Attempts >= 10
| sort - Failed_Attempts
```
### Description:
Filters specifically for **Logon Type 10 (RemoteInteractive / RDP)**. It calculates the attack duration in minutes, extracts the Windows SubStatus error code (e.g. `0xC000006A`), and filters for volume exceeding 10 failed attempts.

---

## 3. SubStatus Code Analysis (Valid vs. Invalid Users)

### SPL Query:
```spl
index=wineventlog EventCode=4625 (Logon_Type=10 OR LogonType=10)
| eval Reason=case(
    Sub_Status="0xc0000064" OR SubStatus="0xc0000064", "Username does not exist",
    Sub_Status="0xc000006a" OR SubStatus="0xc000006a", "Valid user - Wrong password",
    Sub_Status="0xc0000234" OR SubStatus="0xc0000234", "Account Locked Out",
    Sub_Status="0xc0000072" OR SubStatus="0xc0000072", "Account Disabled",
    1=1, "Other SubStatus (".Sub_Status.")"
)
| stats count by Reason, user, src_ip
| sort - count
```
### Description:
Distinguishes whether an attacker is **enumerating usernames** (guessing non-existent accounts) or possesses **valid corporate usernames** and is performing credential stuffing.

---

## 4. Visualizing Attack Velocity (Timechart)

### SPL Query:
```spl
index=wineventlog EventCode=4625 (Logon_Type=10 OR LogonType=10)
| timechart span=1m count by user
```
### Description:
Plots a 1-minute interval timechart showing the sudden spike in brute-force activity. In normal baselines, failures are 0-1 per minute; an automated tool like Hydra produces 50-200 spikes per minute.

---

## 5. High-Priority Correlation: Brute-Force Followed by Successful Logon

### SPL Query:
```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) (Logon_Type=10 OR LogonType=10)
| eval Status=if(EventCode=4625, "Failure", "Success")
| stats count(eval(Status="Failure")) as Total_Failures,
        count(eval(Status="Success")) as Total_Successes,
        values(user) as Affected_Users,
        earliest(_time) as Attack_Start,
        latest(_time) as Attack_End
        by src_ip
| where Total_Failures >= 5 AND Total_Successes >= 1
| convert ctime(Attack_Start) ctime(Attack_End)
```
### Description:
Identifies successful initial access compromises. If a source IP registers 5+ failures and then 1+ successes, the attacker likely cracked the password and attained interactive RDP control.

---

## 6. Identifying Post-Exploitation Privilege Assignment (Event 4672)

### SPL Query:
```spl
index=wineventlog EventCode=4672
| stats count values(PrivilegeList) as Assigned_Privileges by user, ComputerName, _time
| sort - _time
```
### Description:
Validates whether the compromised account was granted sensitive administrator privileges (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, etc.) immediately following the RDP logon.
