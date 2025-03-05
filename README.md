
## Overview
This tool is designed for King of the Hill (KotH) competitions to help automate system enumeration, privilege escalation, and persistence on both Windows and Linux. It enables Red Team players to quickly gain control of a target machine, escalate privileges, and maintain access, while identifying potential weaknesses for defense.

## Usage
### Running the Script
Ensure Python 3 is installed on the target system. Run the script with:
```bash
python3 sys_helper.py
```

### Persistence Execution
- **Linux:** The tool creates a backdoor shell script at `/tmp/.backdoor.sh`.
  - To activate manually:
    ```bash
    /tmp/.backdoor.sh
    ```
- **Windows:** The tool adds a registry key to execute a PowerShell-based reverse shell.
  - To check manually:
    ```powershell
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    ```

- For better security clear logs after execution:
  ```bash
  echo > ~/.bash_history && history -c
  ```
