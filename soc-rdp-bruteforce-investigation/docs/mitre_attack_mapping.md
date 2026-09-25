# MITRE ATT&CK Framework Mapping

This document aligns the adversary tactics, techniques, and procedures (TTPs) observed during the RDP Brute-Force incident with the official **MITRE ATT&CK Enterprise Matrix**.

| Tactic | Technique ID | Technique Name | Observed Adversary Activity | Defensive Telemetry |
| :--- | :--- | :--- | :--- | :--- |
| **Discovery** | `T1046` | Network Service Discovery | Adversary performed Nmap port scanning on TCP port 3389 across the subnet to locate listening RDP instances. | Firewall connection logs, Network flow data |
| **Credential Access** | `T1110.001` | Brute Force: Password Guessing | Adversary executed automated dictionary-based guessing using THC-Hydra against default accounts. | Windows Security Event ID `4625` (SubStatus `0xC000006A`) |
| **Credential Access** | `T1110.003` | Brute Force: Password Spraying | Adversary tested common enterprise passwords against multiple enumerated users to evade account lockouts. | Windows Security Event ID `4625` with multiple `TargetUserName`s |
| **Initial Access / Lateral Movement** | `T1021.001` | Remote Services: Remote Desktop Protocol | Adversary used compromised credentials via `xfreerdp` to establish an interactive remote desktop connection. | Windows Security Event ID `4624` (Logon Type 10), TerminalServices ID `1149` |
| **Persistence / Privilege Escalation** | `T1078.002` | Valid Accounts: Domain Accounts | Adversary attempted to maintain access using valid administrative account privileges. | Windows Security Event ID `4672` (Special privileges assigned) |

---

## Defensive Matrix Coverage

```
+-------------------------------------------------------------------------+
| [Discovery]           [Credential Access]        [Initial Access / Lat] |
| T1046 (Port Scan) ->  T1110.001 (Hydra Brute) -> T1021.001 (RDP Logon)   |
| Detection: NetFlow    Detection: Event 4625      Detection: Event 4624  |
+-------------------------------------------------------------------------+
```
