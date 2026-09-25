# Security Operations Center (SOC) Incident Response Report

| Incident Reference | SOC-INC-2026-0925-RDP |
| :--- | :--- |
| **Severity Level** | **High (Severity 2)** |
| **Incident Category** | Unauthorized Access Attempt / Credential Access |
| **Detection Source** | Splunk SIEM Enterprise (Alert: `SOC_Alert_RDP_Brute_Force`) |
| **Affected Asset** | `WIN-TARGET-01` (`192.168.80.128`) |
| **Attacking IP** | `192.168.80.129` |
| **Status** | Closed / Remediated |

---

## 1. Executive Summary

On September 25, 2026, the Security Operations Center detected an anomalous spike in failed authentication telemetry originating from internal IP `192.168.10.50` targeting `WIN-TARGET-01` (`192.168.80.128`). SIEM correlation confirmed an automated brute-force / password spraying attack against the Remote Desktop Protocol (TCP port 3389). Over 120 failed logon attempts (Event ID 4625, Logon Type 10) were recorded within a 4-minute window. Containment protocols were initiated immediately: the attacker's IP was isolated via host and perimeter firewall rules, account lockout thresholds were enforced, and Remote Desktop settings were hardened with Network Level Authentication (NLA). No unauthorized data exfiltration occ

## 2. Threat Actor TTPs (MITRE ATT&CK Mapping)

- **T1046 - Network Service Discovery:** Attacker scanned port 3389 to identify active RDP listening services.
- **T1110.001 - Password Guessing:** High-speed automated password dictionary attack against administrative accounts using THC-Hydra.
- **T1021.001 - Remote Desktop Protocol:** Utilization of RDP as the initial vector of compromise.

---

## 3. Incident Timeline

| Timestamp (UTC) | Event Code | Activity Description |
| :--- | :--- | :--- |
| **08:17:10** | Port Scan | Nmap SYN scan from `192.168.10.50` on port 3389 observed. |
| **08:17:26** | Event 4625 | Automated brute-force initiated by Hydra against user `Administrator`. High failure rate (~30 attempts/min). |
| **08:17:38** | Event 4625 | SubStatus `0xC000006A` logged consecutively (valid account, incorrect password). |
| **08:21:05** | Splunk Alert | SIEM alert `SOC_Alert_RDP_Brute_Force_Detected` triggered in Splunk Console. |
| **08:23:33** | SOC Triage | Analyst assigned to ticket; validated source IP `192.168.10.50` as an unauthorized Kali Linux workstation. |
| **08:28:14** | Containment | Windows Defender Firewall rule deployed to drop all inbound traffic from `192.168.10.50`. |
| **08:35:00** | Remediation | Account lockout policy configured (threshold: 5 attempts / 15 min lockout). NLA enforced. |

---

## 4. Forensic Evidence & Key Indicators

- **Source IP Address:** `192.168.10.50`
- **Source Workstation Name:** `KALI`
- **Target System:** `WIN-TARGET-01`
- **Target Usernames:** `Administrator`, `guest`, `support`, `backup`
- **Logon Type:** `10` (RemoteInteractive - Terminal Services / Remote Desktop)
- **Windows Error Codes:**
  - `0xC000006A` (Bad Password - Confirms attacker targeted legitimate existing usernames)
  - `0xC0000064` (User does not exist - Attacker user enumeration phase)

---

## 5. Containment, Eradication & Remediation

1. **Immediate Isolation:** Dropped all network connectivity between the attacker IP and target subnet.
2. **Account Hardening:** Implemented a GPO Account Lockout Policy locking accounts after 5 invalid attempts for a duration of 30 minutes.
3. **Network Level Authentication:** Enabled mandatory NLA to force clients to authenticate against the CredSSP protocol prior to initiating an interactive session.
4. **Perimeter Defense:** Restricted RDP access strictly behind an enterprise VPN gateway with Multi-Factor Authentication (MFA).

---

## 6. Sign-off & Verification

- **Lead Analyst:** SOC Tier 2 Security Analyst
- **Reviewer:** Incident Response Team Lead
- **Conclusion:** Remediation verified. Monitoring resumed with zero recurrence.
