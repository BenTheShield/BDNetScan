#!/bin/bash
# Last Modified: 31/01/2025
# Credits @ https://github.com/BenTheShield/

# Define colors for better readability
GREEN="\033[1;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

# Welcome Message
echo -e "${CYAN}Welcome to BDNetScan - The Ultimate Network Scanning Tool${RESET}"

# 1) Root Check
function ROOT_CHECK() {
    if [ "$USER" != "root" ]; then
        echo -e "${RED}[!] To run this tool, you must be logged in as root.${RESET}"
        echo -e "${YELLOW}[?] Switch to root? [y/n]${RESET}"
        read -r yesorno
        if [[ "$yesorno" =~ ^[yY]$ ]]; then
            echo -e "${GREEN}[+] Switching to root...${RESET}"
            script_path=$(realpath "$0")
            exec sudo bash "$script_path" "$@"
        else
            echo -e "${RED}[-] Exiting...${RESET}"
            exit 1
        fi
    fi
}

# 2) Validate IP Range
function VALIDATE_IP_RANGE() {
    while true; do
        echo -e "${YELLOW}[?] Please enter an IP range (e.g., 192.168.1.0/24): ${RESET}"
        read -r ip_range
        
      
        if [[ $ip_range =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
            ip="${ip_range%/*}"
            subnet="${ip_range#*/}"
            
            valid=true
            IFS='.' read -r -a octets <<< "$ip"
            for octet in "${octets[@]}"; do
                if ((octet < 0 || octet > 255)); then
                    valid=false
                    break
                fi
            done
            
            # If valid, break the loop
            if $valid; then
                echo -e "${GREEN}[+] Selected IP range: $ip_range${RESET}"
                break
            fi
        fi
        
        # Invalid input feedback
        echo -e "${RED}[-] Invalid IP range. Please try again.${RESET}"
    done
}


# 3) Output Directory
function OUTPUT_DIR() {
    while true; do
        echo -e "${YELLOW}[?] Please enter an output directory name: ${RESET}"
        read -r directory
        if [ -z "$directory" ]; then
            echo -e "${RED}[-] Directory name cannot be empty. Try again.${RESET}"
        elif [ -d "$directory" ]; then
            echo -e "${RED}[-] This directory already exists. Please choose a different name.${RESET}"
        else
            mkdir -p "$directory"
            output_directory="$(realpath "$directory")" 
            echo -e "${GREEN}[+] Successfully created directory: $output_directory${RESET}"
            break
        fi
    done
}



# 4) Preparing the Scan List
function PREPARING_SCAN_LIST() {
    if [ -z "$output_directory" ]; then
        echo -e "${RED}[-] Output directory is not set. Exiting.${RESET}"
        exit 1
    fi
    if [ ! -d "$output_directory" ]; then
        echo -e "${RED}[-] Output directory does not exist. Exiting.${RESET}"
        exit 1
    fi

    echo -e "${BLUE}[!] Creating a target list according to your network range...${RESET}"
    echo -e "${BLUE}[!] This may take a few minutes depending on the network range.${RESET}"
    nmap -sL "$ip_range" > "$output_directory/.targets"
    awk '{print $5}' "$output_directory/.targets" | grep ^[0-9] > "$output_directory/targets_list" # Getting the IP address from the output
    echo -e "${GREEN}[+] Target list created in: $output_directory${RESET}"
}

# 5) Scan Type Selection
function SCAN_TYPE() {
    echo -e "${YELLOW}[*] Please select the scan type. If you are unsure, choose Help to read more.${RESET}"
    while true; do
        echo -ne "${YELLOW}[?] Choose [B]asic, [F]ull, or [H]elp: ${RESET}"
        read -r CHK
        case $CHK in
            "B"|"b")
                BASIC_SCAN
                break
                ;;
            "F"|"f")
                FULL_SCAN
                break
                ;;
            "help"|"Help"|"HELP"|"H"|"h")
                echo -e "${BLUE}The [B]asic Scan includes Nmap scanning with brute-force (via Hydra)"
                echo -e "The [F]ull Scan includes everything in Basic Scan, plus vulnerability scanning and SearchSploit integration.${RESET}"
                ;;
            *)
                echo -e "${RED}[-] Wrong Choice. Please try again.${RESET}"
                ;;
        esac
    done
}

# 5.1) Basic Scan
function BASIC_SCAN() {
    echo -e "${GREEN}[+] You have selected the Basic Scan option.${RESET}"
    echo "1) Scan all TCP and UDP ports (65,535)."
    echo "2) Scan common TCP and UDP ports (1,024)."
    echo "3) Scan all TCP ports (65,535)."
    echo "4) Scan common TCP ports (1,024)."
    echo "5) Scan all UDP ports (65,535)."
    echo "6) Scan common UDP ports (1,024)."
    echo -e "${BLUE}Please note: Scanning UDP ports can take longer. Scanning all 65,535 ports (TCP/UDP) may also be time-consuming.${RESET}"

    read -p "[?] Enter your choice (1-6): " ports_type
    case $ports_type in
        1) scan_flag="-sS -sU -p-" ;;  # All TCP and UDP ports
        2) scan_flag="-sS -sU" ;;      # Common TCP and UDP ports (nmap default)
        3) scan_flag="-sS -p-" ;;      # All TCP ports
        4) scan_flag="-sS" ;;          # Common TCP ports (nmap default)
        5) scan_flag="-sU -p-" ;;      # All UDP ports
        6) scan_flag="-sU" ;;          # Common UDP ports (nmap default)
        *)
            echo -e "${RED}[-] Wrong choice. Returning...${RESET}"
            return
            ;;
    esac

    echo -e "${GREEN}[+] Starting Basic Nmap scan (without NSE scripts)...${RESET}"
    for ip in $(cat "$output_directory/targets_list"); do
        echo -e "${BLUE}[*] Scanning $ip${RESET}"
        sudo nmap $scan_flag -sV "$ip" > "$output_directory/$ip"
    done
    echo -e "${GREEN}[+] Basic scan completed. Results are in: $output_directory${RESET}"
}


# 5.2) Full Scan
function FULL_SCAN() {
    echo -e "${GREEN}[+] You have selected the Full Scan option.${RESET}"
    echo "1) Scan all TCP and UDP ports (65,535)."
    echo "2) Scan common TCP and UDP ports (1,024)."
    echo "3) Scan all TCP ports (65,535)."
    echo "4) Scan common TCP ports (1,024)."
    echo "5) Scan all UDP ports (65,535)."
    echo "6) Scan common UDP ports (1,024)."
    echo -e "${BLUE}Please note: Scanning UDP ports can take longer. Scanning all 65,535 ports (TCP/UDP) may also be time-consuming.${RESET}"

    read -p "[?] Enter your choice (1-6): " ports_type
    case $ports_type in
        1) scan_flag="-sS -sU -p-" ;; # All TCP and UDP ports
        2) scan_flag="-sS -sU" ;;     # Common TCP and UDP ports (nmap default)
        3) scan_flag="-sS -p-" ;;     # All TCP ports
        4) scan_flag="-sS" ;;         # Common TCP ports (nmap default)
        5) scan_flag="-sU -p-" ;;     # All UDP ports
        6) scan_flag="-sU" ;;         # Common UDP ports (nmap default)
        *)
            echo -e "${RED}[-] Wrong choice. Returning...${RESET}"
            return
            ;;
    esac

    echo -e "${GREEN}[+] Starting Full Nmap scan with brute-force and vulnerability scripting...${RESET}"
    mkdir -p "$output_directory/nmap_xml"
    mkdir -p "$output_directory/nmap_html"
    mkdir -p "$output_directory/searchsploit"

    for ip in $(cat "$output_directory/targets_list"); do
        echo -e "${BLUE}[*] Scanning $ip${RESET}"
        sudo nmap $scan_flag -sV --script=brute,vuln -oX "$output_directory/nmap_xml/$ip.xml" "$ip" > "$output_directory/$ip"

        # Convert the XML output to HTML format to make sure it's human readable. 
        sudo xsltproc "$output_directory/nmap_xml/$ip.xml" -o "$output_directory/nmap_html/$ip.html"
        sleep 1

        # Using SearchSploit for exploit matching
        echo -e "${BLUE}[*] Running SearchSploit for $ip${RESET}"
        searchsploit --nmap "$output_directory/nmap_xml/$ip.xml" > "$output_directory/searchsploit/$ip.log" 2>/dev/null
    done

    echo -e "${GREEN}[+] Full scan completed. Results are available in:${RESET}"
    echo "    - XML: $output_directory/nmap_xml"
    echo "    - HTML: $output_directory/nmap_html (human-readable)" 
    echo "    - SearchSploit Logs: $output_directory/searchsploit"
}


# 6) Genereting Report

function OPEN_PORTS_REPORT() {
    echo -e "${BLUE}[!] Generating reports for open ports...${RESET}"
    cd "$output_directory" || exit 1

    # Temporary files for tracking results
    temp_ssh="temp_ssh_open_ports.txt"
    temp_ftp="temp_ftp_open_ports.txt"
    temp_rdp="temp_rdp_open_ports.txt"
    temp_mysql="temp_mysql_open_ports.txt"
    temp_smb="temp_smb_open_ports.txt"

    # Clear temporary files
    > "$temp_ssh"
    > "$temp_ftp"
    > "$temp_rdp"
    > "$temp_mysql"
    > "$temp_smb"

    # Checking the default ports for the following protocols.
    for file in $(ls | grep '^[0-9]'); do
        # Check for port 22 (SSH)
        if grep -qw '22/tcp.*open' "$file"; then
            echo "$file" >> "$temp_ssh"
        fi
        # Check for port 21 (FTP)
        if grep -qw '21/tcp.*open' "$file"; then
            echo "$file" >> "$temp_ftp"
        fi
        # Check for port 3389 (RDP)
        if grep -qw '3389/tcp.*open' "$file"; then
            echo "$file" >> "$temp_rdp"
        fi
        # Check for port 3306 (MySQL)
        if grep -qw '3306/tcp.*open' "$file"; then
            echo "$file" >> "$temp_mysql"
        fi
        # Check for port 445 (SMB)
        if grep -qw '445/tcp.*open' "$file"; then
            echo "$file" >> "$temp_smb"
        fi
    done

    # Generate reports ONLY if results are found - It will be used later on the script, on the Hydra attack. 
    if [ -s "$temp_ssh" ]; then
        echo "This file contains all IP addresses that have SSH (Port 22) open:" > ssh_open_ports.txt
        cat "$temp_ssh" >> ssh_open_ports.txt
        echo "  - ssh_open_ports.txt (port 22)"
    fi

    if [ -s "$temp_ftp" ]; then
        echo "This file contains all IP addresses that have FTP (Port 21) open:" > ftp_open_ports.txt
        cat "$temp_ftp" >> ftp_open_ports.txt
        echo "  - ftp_open_ports.txt (port 21)"
    fi

    if [ -s "$temp_rdp" ]; then
        echo "This file contains all IP addresses that have RDP (Port 3389) open:" > rdp_open_ports.txt
        cat "$temp_rdp" >> rdp_open_ports.txt
        echo "  - rdp_open_ports.txt (port 3389)"
    fi

    if [ -s "$temp_mysql" ]; then
        echo "This file contains all IP addresses that have MySQL (Port 3306) open:" > mysql_open_ports.txt
        cat "$temp_mysql" >> mysql_open_ports.txt
        echo "  - mysql_open_ports.txt (port 3306)"
    fi

    if [ -s "$temp_smb" ]; then
        echo "This file contains all IP addresses that have SMB (Port 445) open:" > smb_open_ports.txt
        cat "$temp_smb" >> smb_open_ports.txt
        echo "  - smb_open_ports.txt (port 445)"
    fi

    # Clean up temporary files
    rm -f "$temp_ssh" "$temp_ftp" "$temp_rdp" "$temp_mysql" "$temp_smb"
    cd ..
}

# 7) Menu Password List
final_user_list="./usernames/usernames.txt" # Using Default Usernames List 
function MENU_PASSWORDLIST() {
    echo -e "${GREEN}[+] Nmap scanning successfully finished. Starting Brute-Force Attack..${RESET}"
    while true; do
        echo -ne "${YELLOW}[?] Do you have your own password list you want to use? [Y] or [N]: ${RESET}"
        read -r PASSLIST
        case $PASSLIST in
            "Y"|"y")
                echo -ne "${YELLOW}[*] Please enter the FULL PATH of your password list file: ${RESET}"
                read -r PASSLIST_FULL_PATH
                if [ -f "$PASSLIST_FULL_PATH" ]; then
                    cp "$PASSLIST_FULL_PATH" "./$output_directory"
                    final_password_list="$PASSLIST_FULL_PATH"
                    echo -e "${GREEN}[+] Selected password list: $PASSLIST_FULL_PATH${RESET}"
                else
                    echo -e "${RED}[-] Password list file cannot be found at this location. Try again.${RESET}"
                    continue
                fi
                break
                ;;
            "N"|"n")
                GEN_PASSLIST
                break
                ;;
            *)
                echo -e "${RED}[-] Invalid choice. Try again.${RESET}"
                ;;
        esac
    done
}

# 7.1) Generate Password List
function GEN_PASSLIST() {
    while true; do
        echo -e "${YELLOW}Please choose the password list you would like to use:${RESET}"
        echo "1) 10k most common password list"
        echo "2) 1M most common password list"
        echo "3) 10M most common password list"
        echo "4) rockyou.txt password list"
        echo "0) Exit"
        echo -ne "${YELLOW}[?] Enter your choice: ${RESET}"
        read -r password_choice

        case $password_choice in
            1)
                final_password_list="$(realpath passwords/10k-most-common.txt)"
                ;;
            2)
                final_password_list="$(realpath passwords/10-million-password-list-top-100000.txt)"
                ;;
            3)
                final_password_list="$(realpath passwords/10-million-password-list-top-1000000.txt)"
                ;;
            4)
                sudo gunzip "/usr/share/wordlists/rockyou.txt.gz" 2>/dev/null # Since this script running on Kali Linux, The wordlist should be available by default.
                sleep 3
                cp "/usr/share/wordlists/rockyou.txt" "./passwords/"
                final_password_list="$(realpath passwords/rockyou.txt)"
                ;;
            0)
                echo -e "${YELLOW}[+] Going back to the previous menu.${RESET}"
                return
                ;;
            *)
                echo -e "${RED}[-] Invalid choice. Please try again.${RESET}"
                continue
                ;;
        esac

        if [ ! -f "$final_password_list" ]; then
            echo -e "${RED}[-] Selected password list file does not exist: $final_password_list${RESET}"
            continue
        fi

        echo -e "${GREEN}[+] Selected password list: $final_password_list${RESET}"
        break
    done
}


# 8) Hydra Attack
function HYDRA() {
    echo -e "${GREEN}[+] Starting Hydra Attack...${RESET}"
    cd "$output_directory" || exit 1
    for report in $(ls | grep -E '^(mysql|ssh|ftp|smb|rdp)_open_ports\.txt'); do
        # Extract protocol from the filename (e.g., 'ssh' from ssh_open_ports.txt)
        protocol=$(echo "$report" | awk -F'_' '{print $1}')
        # Read IPs from the report file, skipping the first line
        tail -n +2 "$report" | while IFS= read -r ip; do
            echo -e "${BLUE}[*] Running Hydra on $ip (protocol: $protocol)...${RESET}"
            hydra -L "../$final_user_list" -P "$final_password_list" "$protocol://$ip"
            sleep 5
        done
    done
}

# 9) Save Results
function SAVE_RESULTS() {

    if [ ! -d "$output_directory" ]; then
        echo -e "${RED}[-] Output directory does not exist: $output_directory${RESET}"
        return
    elif [ -z "$(ls -A "$output_directory" 2>/dev/null)" ]; then
        echo -e "${RED}[-] Output directory is empty: $output_directory${RESET}"
        return
    fi

    echo -ne "${YELLOW}[?] Do you want to save the results in a ZIP file? [Y/N]: ${RESET}"
    read -r save_choice

    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
        zip_name="results_$(basename "$output_directory").zip"
        echo -e "${GREEN}[+] Compressing results from $output_directory into $zip_name...${RESET}"
        zip -r "$zip_name" "$output_directory" > /dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}[+] Results successfully saved in $zip_name${RESET}"
        else
            echo -e "${RED}[-] Failed to compress results. Please check the directory.${RESET}"
        fi
    else
        echo -e "${RED}[-] Skipping saving results as a ZIP file.${RESET}"
    fi
}


#Main Script Execution
ROOT_CHECK
VALIDATE_IP_RANGE
OUTPUT_DIR
PREPARING_SCAN_LIST
SCAN_TYPE
OPEN_PORTS_REPORT
MENU_PASSWORDLIST
HYDRA
SAVE_RESULTS
