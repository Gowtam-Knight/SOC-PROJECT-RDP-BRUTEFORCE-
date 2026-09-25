# Windows & RDP Hardening Playbook

This playbook provides actionable steps to eliminate the vulnerability surface that enables RDP brute force attacks.

---

## 1. Configure Account Lockout Policy

Prevent indefinite password guessing by locking out accounts after repeated failures:

1. Open **Local Security Policy** (`secpol.msc`).
2. Navigate to: `Security Settings` -> `Account Policies` -> `Account Lockout Policy`.
3. Configure the following recommended thresholds:
   - **Account lockout threshold:** `5 invalid logon attempts`
   - **Account lockout duration:** `30 minutes`
   - **Reset account lockout counter after:** `30 minutes`

---

## 2. Enforce Network Level Authentication (NLA)

NLA requires the connecting user to authenticate themselves to the Network (via CredSSP) before a full Remote Desktop session is established, blocking automated unauthenticated exploit handshakes.

1. Open **System Properties** (`sysdm.cpl`).
2. Navigate to the **Remote** tab.
3. Under Remote Desktop, select **"Allow remote connections to this computer"**.
4. Check **"Allow connections only from computers running Remote Desktop with Network Level Authentication (recommended)"**.

---

## 3. Firewall & Network Restrictions

Never expose TCP port 3389 directly to untrusted networks or the public internet:
- **Scope to Jumpbox/Bastion Host:** Allow inbound port 3389 only from designated management subnets or jump hosts.
- **Implement Multi-Factor Authentication (MFA):** Require Duo Security, Microsoft Entra ID, or hardware tokens for all remote access.
- **Utilize an RDP Gateway or SSL VPN:** Tunnel RDP over HTTPS (TCP 443) behind strict identity verification.

---

## 4. Renaming Default Administrative Accounts

Adversaries routinely target standard usernames like `Administrator`, `admin`, or `root`.
- In `secpol.msc`, navigate to `Local Policies` -> `Security Options`.
- Locate **"Accounts: Rename administrator account"** and change to a non-obvious enterprise naming standard.
- Disable the default **Guest** account.
