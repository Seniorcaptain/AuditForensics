🚀 How to Use the Tool
Step 1: Install Dependencies
bash
# Install required Python packages
pip install impacket python-ldap pywinrm ldap3 dnspython

# Or on Kali/Debian-based systems
sudo apt update && sudo apt install -y python3-impacket python3-ldap python3-winrm python3-dnspython



Step 2: Save the Script
Save the script as remote_audit.py on your Linux machine (e.g., Kali, Ubuntu).

Step 3: Make It Executable
bash
chmod +x remote_audit.py


Step 4: Run the Audit
bash
# Basic audit (using WinRM)
python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd

# With domain for AD checks
python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd -d domain.local

# Using SMB only (no WinRM)
python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd --no-winrm

# With custom SMB port
python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd --port 445




🔧 Troubleshooting
WinRM Connection Failed
Solution 1: Enable WinRM on the target (requires admin):

powershell
winrm quickconfig
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value *
Solution 2: Use --no-winrm flag for SMB-only mode.



LDAP/AD Checks Fail
Solution: Ensure you provide the domain name:

bash
python3 remote_audit.py -t 192.168.1.100 -u Administrator -p P@ssw0rd -d domain.local
Port Scanning Takes Too Long
Solution: The tool scans 13 common ports. You can modify the common_ports list in the audit_network_security method.

Permission Issues
Solution: Ensure the account used has:

Local admin privileges

Domain admin (for full AD enumeration)

Remote management permissions
