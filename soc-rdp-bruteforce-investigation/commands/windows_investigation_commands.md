# Windows Defender & Investigation Commands

This document contains defensive and triage commands executed on the target Windows system for audit policy enforcement, forensic event log querying, and host-level containment.

---

## 1. Advanced Audit Policy Configuration

To ensure high-fidelity telemetry is captured for Splunk SIEM ingestion, execute in an elevated Command Prompt (`cmd.exe`):

```cmd
:: Enable Success and Failure logging for user logons
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Enable Success and Failure logging for Credential Validation
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

:: Enable Account Lockout monitoring
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

:: Verify active audit policy status
auditpol /get /category:"Logon/Logoff"
```

---

## 2. Event Log Triage via Command Line

### Querying Event 4625 with `wevtutil`
```cmd
:: Extract the last 10 failed logon events in XML/Text format
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /f:text /c:10 /rd:true
```

### PowerShell Live Investigation of Failed Logons
```powershell
# Query Event ID 4625 for Logon Type 10 (Remote Desktop)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | 
Select-Object TimeCreated, 
    @{N='TargetUser';E={$_.Properties[5].Value}}, 
    @{N='LogonType';E={$_.Properties[8].Value}}, 
    @{N='SubStatus';E={$_.Properties[7].Value}}, 
    @{N='SourceIp';E={$_.Properties[19].Value}}, 
    @{N='WorkstationName';E={$_.Properties[11].Value}} | 
Format-Table -AutoSize
```

### Finding Locked Out Accounts (Event ID 4740)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 10 | 
Select-Object TimeCreated, Message | Format-List
```

---

## 3. Host-Level Emergency Containment & Hardening

### Block Attacker IP via Windows Defender Firewall
```cmd
:: Immediately block inbound traffic from the attacking host
netsh advfirewall firewall add rule name="SOC-BLOCK-ATTACKER-IP" dir=in action=block remoteip=192.168.10.50
```

### Enforce Network Level Authentication (NLA) via Registry
```cmd
:: Enforce NLA to prevent unauthorized unauthenticated RDP handshakes
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
```

### Emergency Disable Remote Desktop
```cmd
:: Immediately shut down RDP service access during active breach
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
```
