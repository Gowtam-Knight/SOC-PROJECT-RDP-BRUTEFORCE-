🛡️ SOC Detection & Investigation: RDP Brute-Force Attack Simulation & Incident Response
Splunk SIEM Windows Server Kali Linux MITRE ATT&CK Security-Level

📌 Executive Summary & Project Overview
This project showcases an end-to-end Security Operations Center (SOC) Detection and Incident Investigation workflow. An adversary (Kali Linux) launches an automated RDP Brute-Force (Credential Stuffing / Password Guessing) attack against a target Windows system. Real-time telemetry is forwarded using the Splunk Universal Forwarder into a Splunk Enterprise SIEM Indexer, where advanced Search Processing Language (SPL) queries, anomaly correlation, timecharts, and detection alert rules are constructed to triage, analyze, contain, and remediate the incident.

       [Attacker Network]                      [Target & Defense Network]
  +--------------------------+                 +--------------------------+
  |    Kali Linux (Attacker) |                 |  Windows Endpoint Target |
  |    IP: 192.168.10.50     |                 |    IP: 192.168.10.100    |
  +--------------------------+                 +--------------------------+
               |                                            |
               |                                            | (Universal Forwarder)
               | TCP 3389 (RDP Brute Force)                 | Port 9997 (Splunk Indexing)
               +--------------------->                      V
                                               +--------------------------+
                                               |  Splunk Enterprise SIEM  |
                                               |    IP: 192.168.10.10     |
                                               +--------------------------+
🎯 Key Learning Objectives & SOC Skills Demonstrated
SIEM Telemetry Pipeline: Configured Windows Advanced Audit Policies and deployed Splunk Universal Forwarder (inputs.conf) to monitor security event channels in real time.
Threat Emulation: Simulated adversary TTPs mapped to the MITRE ATT&CK Matrix using Nmap, THC-Hydra, and Crowbar.
Log Forensics & Triage: Analyzed Windows Security Event IDs:
4625: An account failed to log on (filtered specifically for Logon Type 10 - RemoteInteractive).
4624: Successful logon (detecting credential compromise post-brute-force).
4740: Account lockout events.
4672: Special privileges assigned to new logon.
Detection Engineering: Engineered production-grade Splunk SPL queries, field calculations, timecharts, and correlation rules for immediate alerting.
Incident Response & Hardening: Authored an official Incident Response Report and applied containment measures (Firewall rules, Account Lockout policies, Network Level Authentication).
🗂️ Repository Structure
soc-rdp-bruteforce-investigation/
├── README.md                                  # Complete project documentation & portfolio showcase
├── LICENSE                                    # MIT License
├── .gitignore                                 # Production gitignore (excluding EFI/VM boot files)
├── architecture/
│   ├── network_architecture.md                # Network topology, IP addressing & data pipeline
│   └── architecture_diagram.txt               # ASCII network schematic
├── configs/
│   ├── inputs.conf                            # Splunk Universal Forwarder channel configuration
│   ├── outputs.conf                           # Forwarder-to-Indexer destination configuration
│   └── savedsearches.conf                     # Splunk SIEM alert correlation rules
├── detections/
│   ├── splunk_alerts_and_rules.md             # Complete SPL search query playbook
│   └── sigma_rule_rdp_bruteforce.yml          # Vendor-agnostic Sigma detection rule
├── docs/
│   ├── incident_response_report.md            # Formal Tier 1/2 Incident Response Report
│   ├── mitre_attack_mapping.md                # Mapping to MITRE ATT&CK Matrix
│   └── remediation_hardening_guide.md         # Windows & RDP mitigation playbook
├── commands/
│   ├── kali_attack_commands.md                # Documented adversary simulation commands
│   └── windows_investigation_commands.md      # Defender commands (auditpol, wevtutil, netsh)
└── screenshots/
    ├── README.md                              # Screenshot guide & verification index
    ├── 01_lab_setup/                          # Network, forwarder & environment setup images
    ├── 02_attack_simulation/                  # Reconnaissance & brute force execution images
    ├── 03_windows_event_viewer/               # Event Viewer logs (4625, 4624, Logon Type 10)
    └── 04_splunk_analysis/                    # Splunk query results, charts & alert triggers
🔍 Investigation Walkthrough
Phase 1: Attack Emulation (Adversary Perspective)
From the Kali Linux machine (192.168.10.50), service discovery confirmed port 3389 was open on 192.168.10.100:

nmap -sV -p 3389 192.168.10.100
An automated dictionary attack was launched targeting the Administrator account:

hydra -l Administrator -P /tmp/passwords.txt rdp://192.168.10.100 -s 3389 -t 4 -V
Phase 2: Host Event Log Analysis
On the target Windows machine, Windows Event Viewer recorded high-volume authentication failures under Event ID 4625:

Logon Type: 10 (RemoteInteractive / RDP)
Source Network Address (src_ip): 192.168.10.50
SubStatus Codes:
0xC000006A: User name is valid, but password was incorrect.
0xC0000064: User name does not exist (enumeration phase).
Phase 3: Splunk SIEM Detection & Investigation
Query 1: Detect High-Volume Failed RDP Logons
index=wineventlog EventCode=4625 (Logon_Type=10 OR LogonType=10)
| stats count as Failed_Attempts,
        earliest(_time) as First_Seen,
        latest(_time) as Last_Seen,
        values(Sub_Status) as SubStatus_Codes
        by src_ip, user
| eval Attack_Duration_Mins=round((Last_Seen-First_Seen)/60, 2)
| convert ctime(First_Seen) ctime(Last_Seen)
| where Failed_Attempts >= 10
| sort - Failed_Attempts
Query 2: Spike Analysis Over Time (Timechart)
index=wineventlog EventCode=4625 (Logon_Type=10 OR LogonType=10)
| timechart span=1m count by user
Query 3: Critical Compromise Alert (Failures Followed by Success)
index=wineventlog (EventCode=4625 OR EventCode=4624) (Logon_Type=10 OR LogonType=10)
| eval Status=if(EventCode=4625, "Failure", "Success")
| stats count(eval(Status="Failure")) as Failures,
        count(eval(Status="Success")) as Successes
        by src_ip, user
| where Failures >= 5 AND Successes >= 1
🛡️ Containment & Hardening Highlights
Firewall Isolation: Applied immediate rule blocking inbound traffic from 192.168.10.50:
netsh advfirewall firewall add rule name="BLOCK-ATTACKER-IP" dir=in action=block remoteip=192.168.10.50
Account Lockout Policy: Configured threshold to lock accounts after 5 failed attempts for 30 minutes.
Network Level Authentication (NLA): Enforced NLA to prevent unauthenticated RDP sessions.
📜 Incident Report & Documentation
Full Incident Response Report
MITRE ATT&CK Matrix Mapping
Splunk SPL Playbook
Windows Hardening Playbook
Sigma Detection Rule
