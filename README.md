# 🛡️ RDP Brute-Force Attack Detection & Incident Investigation Using Splunk

**A Hands-On SOC Detection Engineering and Incident Response Project**

<p align="center">

  ![Security](https://img.shields.io/badge/Domain-SOC%20Operations-1f6feb?style=for-the-badge)
  ![SIEM](https://img.shields.io/badge/SIEM-Splunk-65A637?style=for-the-badge&logo=splunk&logoColor=white)
  ![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)
  ![Lab](https://img.shields.io/badge/Environment-Authorized%20Lab-orange?style=for-the-badge)

</p>

## 📌 Project Overview

This project demonstrates an end-to-end Security Operations Center (SOC) workflow for detecting, investigating, and responding to Remote Desktop Protocol (RDP) brute-force activity against a Windows endpoint.

A controlled attack simulation was performed from Kali Linux against a Windows target to generate authentication events. Windows Security logs were collected using the Splunk Universal Forwarder and analyzed in Splunk Enterprise using Search Processing Language (SPL).

The investigation focuses on identifying repeated authentication failures, examining suspicious source IP addresses, correlating failed and successful logons, and documenting appropriate containment and remediation actions.

The project follows a practical SOC investigation lifecycle, from telemetry collection and detection to incident analysis, response, and security hardening.

**Project type:** Blue Team / SOC Operations / Detection Engineering  
**Target role:** SOC Analyst L1 / Junior Security Analyst  
**Environment:** Isolated, authorized cybersecurity lab

## 🎯 Objectives

- Configure Windows Security event collection for authentication monitoring.
- Forward endpoint logs to Splunk Enterprise using the Universal Forwarder.
- Simulate RDP authentication attacks in a controlled environment.
- Analyze Windows Security Event IDs associated with failed and successful logons.
- Develop SPL queries to identify suspicious authentication patterns.
- Investigate source IP addresses, targeted accounts, event timestamps, and failure reasons.
- Develop repeatable detection logic and alerting rules.
- Map observed behavior to relevant MITRE ATT&CK techniques.
- Document incident triage, containment, remediation, and lessons learned.

## 🏗️ Lab Architecture

The lab consists of three logical components: an attack simulation machine, a monitored Windows endpoint, and a centralized SIEM.

| Component | IP address | Purpose |
|---|---|---|
| Kali Linux | `192.168.10.50` | Authorized attack simulation |
| Windows endpoint | `192.168.10.100` | RDP target and event generation |
| Splunk Enterprise | `192.168.10.10` | Log ingestion, searching, and detection |
| Splunk Universal Forwarder | Installed on Windows | Endpoint telemetry forwarding |

**Data flow**

1. Kali Linux generates RDP authentication attempts against the Windows endpoint.
2. Windows records relevant authentication activity in its Security event log.
3. The Splunk Universal Forwarder collects configured Windows event channels.
4. Events are forwarded to Splunk Enterprise over TCP port `9997`, when configured.
5. Splunk searches and detection rules identify suspicious authentication patterns.
6. The analyst reviews the evidence and documents the response.

```text
+-------------------------+
| Kali Linux              |
| 192.168.10.50           |
| Authorized simulation   |
+------------+------------+
             |
             | RDP / TCP 3389
             v
+-------------------------+
| Windows Endpoint        |
| 192.168.10.100          |
| Windows Security Logs   |
| Splunk Universal        |
| Forwarder               |
+------------+------------+
             |
             | Forwarded events / TCP 9997
             v
+-------------------------+
| Splunk Enterprise       |
| 192.168.10.10           |
| SPL searches            |
| Detection and triage    |
+-------------------------+
```

*Note: Replace the example addresses with the addresses actually used in your final lab screenshots and configuration files.*

## 🧰 Tools and Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM searches, event analysis, visualizations, and alerting |
| Splunk Universal Forwarder | Windows event collection and forwarding |
| Windows Event Viewer | Verification of authentication events |
| Kali Linux | Controlled attack simulation |
| Nmap | RDP service discovery |
| THC-Hydra | Authorized RDP authentication testing |
| Windows Firewall | Network-level containment |
| Windows Advanced Audit Policy | Authentication event generation |
| MITRE ATT&CK | Adversary behavior classification |
| Sigma | Portable detection-rule representation |

## 🔬 Investigation Workflow

### Phase 1 — Environment Setup and Telemetry Collection

The Windows endpoint was configured to record relevant security events, and the Splunk Universal Forwarder was configured to collect the required event channels.

The forwarding configuration was used to send endpoint events to Splunk Enterprise.

Configuration files are documented in the `configs/` directory.

Key validation steps:

- Verify that the Windows Security channel is being collected.
- Confirm the configured Splunk receiving port.
- Confirm that events arrive at the intended Splunk index.
- Check event timestamps, hostnames, and source fields.
- Validate the actual field names before writing detection queries.

### Phase 2 — RDP Service Discovery and Attack Simulation

Within the authorized lab, service discovery was performed to verify RDP availability.

Example service-discovery command:

```bash
nmap -sV -p 3389 192.168.10.100
```

A controlled authentication-testing exercise was then performed against the lab endpoint using a test account and an approved password list.

The purpose was to generate authentication events for defensive analysis, not to obtain unauthorized access.

**Expected evidence:**

- RDP service availability.
- Repeated authentication failures, if recorded by the target.
- Source address associated with the attempts.
- Target account and failure reason.
- Event timestamps that can be correlated in Splunk.

### Phase 3 — Windows Event Log Analysis

Windows Security events were reviewed to identify authentication activity.

| Event ID | Meaning | Investigative use |
|---|---|---|
| `4625` | Failed logon | Identify repeated authentication failures |
| `4624` | Successful logon | Investigate potentially successful access |
| `4740` | User account locked out | Identify account-lockout activity |
| `4672` | Special privileges assigned to a new logon | Review potentially sensitive logon sessions |

For RDP-focused investigations, Logon Type `10` represents a RemoteInteractive logon. However, failed attempts may appear under other logon types depending on the authentication pathway and Windows configuration.

The investigation should therefore verify the actual event records rather than assume that every RDP-related failure has Logon Type `10`.

Relevant failure status codes include:

- `0xC000006A` — Incorrect password.
- `0xC0000064` — The specified user account does not exist.

These codes should be interpreted in the context of the complete event and its account and source fields.

### Phase 4 — Splunk Detection Engineering

The following searches illustrate the detection logic used in the investigation.

**Important:** Replace `soc-windows` and any field names with the values confirmed in your own Splunk environment. The searches should be tested against actual events before being presented as validated detections.

#### Detection 1: Repeated Failed RDP Logons

```spl
index=soc-windows EventCode=4625
| eval logon_type=coalesce(Logon_Type, LogonType, LogonTypeCode)
| where logon_type="10"
| eval src_ip=coalesce(src_ip, Source_Network_Address, IpAddress)
| eval user=coalesce(user, TargetUserName, Account_Name)
| stats count as failed_attempts
        earliest(_time) as first_seen
        latest(_time) as last_seen
        values(Sub_Status) as sub_status_codes
        by src_ip user
| eval duration_minutes=round((last_seen-first_seen)/60,2)
| where failed_attempts>=10
| convert ctime(first_seen) ctime(last_seen)
| sort - failed_attempts
```

**Detection objective:** Identify accounts experiencing repeated failed RemoteInteractive logons.

**Analyst review:**

- Which source IP generated the failures?
- Which account was targeted?
- How many failures occurred?
- Over what period did the activity occur?
- Do the failure codes indicate an incorrect password or an invalid account?

A threshold of 10 is an example starting point, not a universal production threshold. Tune it to the lab's event volume and expected baseline.

#### Detection 2: Authentication Failure Trends

```spl
index=soc-windows EventCode=4625
| timechart span=1m count as failed_logons
```

**Detection objective:** Visualize changes in failed-logon volume over time.

Use the timechart to investigate bursts of authentication failures and compare the event timeline with the recorded attack simulation.

For a dashboard, consider additional panels showing:

- Failed logons by source IP.
- Failed logons by account.
- Authentication activity over time.
- Failure status codes.
- Successful versus failed logons.

#### Detection 3: Investigate Failures Followed by Success

A suspicious sequence of failed logons followed by a successful logon can indicate a potentially compromised account. However, failures and successes must be correlated by account, source, and time; counting both event types in the same dataset does not establish their order.

The following SPL illustrates a time-bucketed starting point for investigating this pattern:

```spl
index=soc-windows (EventCode=4625 OR EventCode=4624)
| eval logon_type=coalesce(Logon_Type, LogonType, LogonTypeCode)
| where logon_type="10"
| eval src_ip=coalesce(src_ip, Source_Network_Address, IpAddress)
| eval user=coalesce(user, TargetUserName, Account_Name)
| eval status=if(EventCode=4625,"Failure","Success")
| bin _time span=5m
| stats
    count(eval(status="Failure")) as failures
    count(eval(status="Success")) as successes
    values(status) as observed_statuses
    by _time src_ip user
| where failures>=5 AND successes>=1
| sort 0 _time
```

**Detection objective:** Find five-minute buckets containing multiple failed logons and at least one successful logon for the same source and account.

**Limitation:** This search identifies co-occurrence within a time bucket; it does not independently prove that the failures preceded the success or that the success resulted from the attack. A production detection should use time-aware correlation and investigate session details, event timestamps, and other supporting evidence.

### Phase 5 — Alerting and Detection Validation

The project includes a location for Splunk saved searches and detection documentation.

Before describing an alert as operational, verify that it:

1. Runs against the correct index and actual field names.
2. Triggers on representative lab events.
3. Does not fire repeatedly on every scheduled execution without appropriate suppression.
4. Includes useful context, such as source IP, account, event count, and time range.
5. Has a documented severity, threshold, and analyst response.
6. Has been tested against both expected attack behavior and benign authentication activity.

Detection queries and alert configurations are maintained in `detections/` and `configs/`.

### Phase 6 — Incident Triage and Response

When suspicious activity is detected, the analyst follows a structured investigation process.

**1. Identification**

- Confirm the event IDs and authentication outcome.
- Identify the affected endpoint and targeted account.
- Review the source IP, timestamps, failure reasons, and event volume.

**2. Investigation**

- Search for related authentication activity.
- Determine whether a successful logon occurred.
- Review relevant process, network, and endpoint events.
- Distinguish confirmed evidence from assumptions.

**3. Containment**

- Block the source address when appropriate and authorized.
- Restrict RDP access to approved hosts or management networks.
- Disable or temporarily restrict an account if compromise is suspected and the response is approved.
- Preserve relevant logs before making changes.

**4. Remediation and recovery**

- Reset compromised credentials when indicated.
- Review account-lockout and authentication policies.
- Enforce Network Level Authentication where supported.
- Validate firewall restrictions and least-privilege access.
- Confirm that monitoring continues to collect the relevant events.

**5. Documentation**

- Record the timeline, affected assets, evidence, actions taken, and outstanding uncertainties.
- Document the final incident disposition.
- Recommend improvements to detection thresholds and prevention controls.

Any containment action described in the final report should reflect an action actually performed in the lab. Proposed actions should be labeled as recommendations.

## 🧭 MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | `T1110` | Repeated password-guessing attempts |
| Remote Services: Remote Desktop Protocol | `T1021.001` | Use of RDP as a remote service |
| Valid Accounts | `T1078` | Relevant only if valid credentials are successfully used |

MITRE ATT&CK mappings describe observed or simulated behavior. The use of a technique should be supported by evidence from the lab, and a successful compromise should not be claimed solely because authentication failures were generated.

## 🛠️ Hardening and Mitigation

The project documents the following defensive controls:

- Restrict inbound RDP to approved source addresses and management networks.
- Enable Network Level Authentication where appropriate.
- Apply a suitable account-lockout policy while considering denial-of-service risks.
- Use strong, unique credentials and multi-factor authentication where supported.
- Monitor failed logons, suspicious successful logons, and account lockouts.
- Reduce unnecessary exposure of RDP to untrusted networks.
- Retain and protect security logs for incident investigation.

Example Windows Firewall rule for a controlled lab:

```powershell
New-NetFirewallRule `
  -DisplayName "BLOCK-ATTACKER-IP" `
  -Direction Inbound `
  -Action Block `
  -RemoteAddress 192.168.10.50
```

Run administrative commands only on the intended lab endpoint. Validate the rule's scope and precedence, and verify the result after applying it.

## 📂 Repository Structure

```text
soc-rdp-bruteforce-investigation/
├── README.md
├── LICENSE
├── .gitignore
├── architecture/
│   ├── network_architecture.md
│   └── architecture_diagram.txt
├── configs/
│   ├── inputs.conf
│   ├── outputs.conf
│   └── savedsearches.conf
├── detections/
│   ├── splunk_alerts_and_rules.md
│   └── sigma_rule_rdp_bruteforce.yml
├── docs/
│   ├── incident_response_report.md
│   ├── mitre_attack_mapping.md
│   └── remediation_hardening_guide.md
├── commands/
│   ├── kali_attack_commands.md
│   └── windows_investigation_commands.md
└── screenshots/
    ├── README.md
    ├── 01_lab_setup/
    ├── 02_attack_simulation/
    ├── 03_windows_event_viewer/
    └── 04_splunk_analysis/
```

Each directory should contain the files described above. Remove empty folders or clearly label planned material until the relevant artifacts have been added.

## 📸 Evidence and Screenshots

Screenshots should demonstrate the actual implementation, not merely illustrate what a successful result would look like.

Recommended evidence:

1. Lab network configuration and endpoint connectivity.
2. Splunk Universal Forwarder configuration and receiving status.
3. Windows Event Viewer showing relevant authentication events.
4. Splunk search results for failed logons.
5. A timeline visualization of authentication activity.
6. Investigation results showing source IPs and targeted accounts.
7. Alert results, if the alert has been tested successfully.
8. Firewall or hardening configuration, if applied.

Redact credentials, tokens, sensitive host information, and any data that should not be published.

## 📈 Project Outcomes

The project is designed to demonstrate practical skills in:

- Windows Security event analysis.
- Splunk SIEM data ingestion and SPL searches.
- Authentication-attack detection.
- Source-IP and account-based investigation.
- Event timeline analysis and correlation.
- Detection-rule development and validation.
- Incident response documentation.
- Windows endpoint hardening.
- MITRE ATT&CK-based investigation.

**Report actual results here:** Include the number of events observed, the tested detection threshold, the alert-validation result, and any false positives or limitations found during the lab. Do not report detection accuracy or successful containment unless measured or verified.

## ⚠️ Limitations

- The lab represents a controlled environment and does not establish performance in a production SOC.
- Detection quality depends on event collection, field extraction, thresholds, and log coverage.
- Logon Type 10 filtering alone may not capture every relevant RDP authentication failure.
- Correlation results require validation against event timestamps and supporting evidence.
- MITRE ATT&CK mappings describe behavior; they do not independently prove a successful compromise.

## 🔮 Future Improvements

- Develop a Splunk dashboard for authentication monitoring.
- Add source-IP and account-based threshold tuning.
- Improve time-aware correlation between failed and successful logons.
- Add Sigma rule validation and document its required field mappings.
- Integrate additional endpoint telemetry for process and network investigation.
- Add alert severity, triage steps, and false-positive handling.
- Create a repeatable test plan for detection validation.

## 👨‍💻 Skills Demonstrated

**SOC Operations | SIEM Monitoring | Splunk SPL | Windows Event Logs | Authentication Analysis | Detection Engineering | Incident Triage | Incident Response | MITRE ATT&CK | Windows Hardening**

## ⚖️ Ethical Use

This project was designed for defensive learning and authorized testing in a controlled lab. Attack simulations must be performed only against systems for which explicit authorization has been granted.

---

**Author:** Gowtam  
**Focus:** Cybersecurity, Blue Team Operations, and SOC Detection Engineering
