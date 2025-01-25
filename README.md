# BDNetScan

**BDNetScan** is an all-in-one **network scanning** and **brute-forcing** tool designed primarily for **Kali Linux** environments. It automates various tasks, such as enumerating a target list, performing different levels of Nmap scans (Basic or Full), generating reports of open ports, and finally, attempting brute-force attacks with **Hydra** on common protocols.

## Table of Contents

1. [Features](#features)  
2. [Installation](#installation)  
3. [Requirements](#requirements)  
4. [Usage](#usage)  
5. [Protocols Scanned](#protocols-scanned)  
6. [How It Works](#how-it-works)  
7. [Credits](#credits)

---

## Features

- **Root Check**: Ensures you are running the script with appropriate privileges.  
- **IP Range Validation**: Accepts a valid CIDR notation (e.g., `192.168.1.0/24`).  
- **Output Directory Creation**: Automatically creates an output directory for scan results.  
- **Scan Type Selection**: Offers both *Basic* (quick) and *Full* (comprehensive) Nmap scans.  
- **Open Ports Reporting**: Generates detailed lists of hosts for each protocol found open.  
- **Brute-Force**: Utilizes **Hydra** to attempt password brute-forcing on discovered open services.  
- **Password Lists**: Allows you to supply your own password list or generate one from preset lists.  
- **Results Archiving**: Compresses final scan results into a convenient ZIP file for easy sharing.  

---

## Installation

1. **Clone this repository** (assuming you have `git` installed):
   ```bash
   git clone https://github.com/BenTheShield/BDNetScan.git
   ```

2. **Navigate to the directory**:
   ```bash
   cd BDNetScan
   ```

3. **Make the script executable**:
   ```bash
   chmod +x BDNetScan.sh
   ```

4. **Run it**:
   ```bash
   sudo ./BDNetScan.sh
   ```

---

## Requirements

- **Kali Linux** (or a comparable Linux distribution with the following tools installed):
  - **nmap**  
  - **hydra**  
  - **zip**  
  - **xsltproc** (for converting `.xml` to `.html` in Full Scan)  
  - **searchsploit** (for exploit matching; part of the `exploitdb` package)  
  - **awk**, **grep**, **realpath**, **gunzip**, and other common Linux CLI tools  

> **Note**: Many of these tools come pre-installed with Kali Linux. If something is missing, you can install it using `apt`:
> ```bash
> sudo apt update
> sudo apt install nmap hydra zip xsltproc exploitdb
> ```

---

## Usage

1. **Run the script**:
   ```bash
   sudo ./BDNetScan.sh
   ```
2. **Input an IP range** when prompted (e.g., `192.168.1.0/24`).  
3. **Specify an output directory** (e.g., `scan_results`).  
4. **Choose a Scan Type**:
   - **Basic** – Quick, minimal scripting  
   - **Full** – Extensive scanning, uses NSE scripts for vulnerabilities plus `searchsploit`  
5. **Open Ports Report**: The script will generate a list of all hosts with open ports for:
   - SSH (22)
   - FTP (21)
   - RDP (3389)
   - MySQL (3306)
   - SMB (445)
6. **Brute-Force**: Provide your own password list or select from built-in options (like `rockyou.txt`).  
7. **Save Results**: Optionally compress the entire output folder into a ZIP file for easy storage or sharing.

---

## Protocols Scanned

- **SSH (22)**  
- **FTP (21)**  
- **RDP (3389)**  
- **MySQL (3306)**  
- **SMB (445)**  

During the scan, **Nmap** also checks additional ports based on whether you perform a Basic or Full scan. The script then identifies which hosts have these ports open and places them into dedicated text files.

---

## How It Works

1. **Root Check**: The script checks if you're root; if not, you can choose to re-run via `sudo`.  
2. **Input Handling**: It validates your IP range and ensures the output directory is valid.  
3. **Target List**: `nmap -sL` is used to list all IPs in the subnet, creating a `targets_list` file.  
4. **Scan Selection**:
   - **Basic Scan**: Quick scanning of TCP/UDP ports (either all ports or common ports).  
   - **Full Scan**: Similar to Basic but adds advanced scripts (`brute`, `vuln`) and uses **SearchSploit** to find related exploits.  
5. **Open Ports Report**: Collects IPs with open ports of interest into labeled files (e.g., `ssh_open_ports.txt`).  
6. **Brute Forcing**: Launches **Hydra** using user-specified or built-in password lists on the discovered open ports.  
7. **Results Packaging**: Optionally zips the entire scan directory.

---

## Credits

- **Author**: [BenTheShield](https://github.com/BenTheShield/)  
- **Contributors**: Open to community feedback and pull requests.  
- **License**: Feel free to use, modify, or distribute under the MIT License
