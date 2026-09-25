# Project Screenshots Organization

This directory houses all visual evidence and verification screenshots captured during the laboratory execution. The screenshots are organized into chronological, functional categories:

## Directory Structure

```
screenshots/
├── 01_lab_setup/              # Virtual machines, network interfaces, inputs.conf, Splunk indexer listening configuration
├── 02_attack_simulation/      # Nmap reconnaissance scans, THC-Hydra execution, terminal logs showing brute force
├── 03_windows_event_viewer/   # Windows Event Viewer demonstrating Event IDs 4625, 4624, 4740 with Logon Type 10
└── 04_splunk_analysis/        # Splunk searches, statistical tables, attack duration calculation, dashboards & alerts
```

### Organizing Your Original Image Files
Place your original captured screenshot files into their matching folder:
- **`01_lab_setup/`**: Screenshots of IP configuration (`ipconfig`, `ifconfig`), Splunk Forwarder setup.
- **`02_attack_simulation/`**: Screenshots of Kali Linux running Nmap and Hydra against port 3389.
- **`03_windows_event_viewer/`**: Screenshots of Windows Event Viewer displaying Event ID 4625 details.
- **`04_splunk_analysis/`**: Screenshots of Splunk Search & Reporting showing SPL results, charts, and alerts.
