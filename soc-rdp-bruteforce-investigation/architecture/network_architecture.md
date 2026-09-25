# Lab Network Architecture & Component Breakdown

This document provides the full structural and networking specifications for the **SOC RDP Brute-Force Attack Simulation and Investigation** lab.

---

## 1. Network Topology Overview

The laboratory is segmented into an isolated Virtual Host-Only / Internal NAT network (`192.168.10.0/24`) designed to safely simulate real-world cyber attacks without generating unauthorized external traffic.

```
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
```

---

## 2. Node Specifications

| Hostname | Role | Operating System | IP Address | Key Software / Services |
| :--- | :--- | :--- | :--- | :--- |
| **KALI-ATTACKER** | Threat Actor | Kali Linux 2024.x | `192.168.10.50` | Nmap, Hydra, Crowbar, RockYou Wordlist, xfreerdp |
| **WIN-TARGET-01** | Victim Endpoint | Windows Server 2022 / Windows 10 | `192.168.10.100` | Remote Desktop (Port 3389), Splunk Universal Forwarder |
| **SPLUNK-SIEM** | SOC SIEM Platform | Ubuntu Server / Enterprise VM | `192.168.10.10` | Splunk Enterprise 9.x, Indexer (9997), Web Interface (8000) |

---

## 3. Communication & Port Matrix

| Source Host | Destination Host | Protocol | Destination Port | Description |
| :--- | :--- | :--- | :--- | :--- |
| `192.168.10.50` | `192.168.10.100` | TCP | `3389` | Adversary reconnaissance and RDP credential stuffing / brute-force attack |
| `192.168.10.100` | `192.168.10.10` | TCP | `9997` | Encrypted/raw telemetry ingestion (Windows Security Event Logs to Splunk Indexer) |
| SOC Analyst Host | `192.168.10.10` | TCP | `8000` | Splunk Web Management Console for query analysis, alerting, and dashboarding |

---

## 4. Telemetry Collection Pipeline

1. **Host Auditing Configuration:** The Windows Target has Advanced Audit Policies enabled for:
   - Audit Credential Validation (Success and Failure)
   - Audit Logon (Success and Failure)
   - Audit Account Lockout (Success and Failure)
2. **Event Generation:** Each authentication attempt triggers a Windows Security Event:
   - Event ID `4625`: Logon Failure (with Logon Type 10)
   - Event ID `4624`: Logon Success
   - Event ID `4740`: Account Lockout
3. **Log Shipping:** The **Splunk Universal Forwarder** monitors the local Windows Event Channels via `inputs.conf` and pushes raw events across TCP `9997` to the Splunk indexer into the `wineventlog` index.
4. **Log Normalization & Indexing:** The Splunk Indexer parses, timestamps, and indexes the incoming events into standardized fields (`src_ip`, `user`, `Logon_Type`, `Sub_Status`, `Workstation_Name`).
