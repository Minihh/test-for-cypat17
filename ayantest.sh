#!/bin/bash

# Ensure script is run with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or use sudo."
    exit
fi

# Change passwords for all non-system users
echo "Changing passwords for all non-system users..."
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    echo "Setting a new password for user '$user'..."
    echo "$user:C1SC0!!!" | sudo chpasswd
done

# 1. Install and enable UFW (Uncomplicated Firewall) with GUFW
echo "Installing and enabling UFW and GUFW..."
apt update
apt install -y ufw gufw
ufw enable

# 2. Configure Auditd for System Auditing
echo "Installing and starting auditd for system auditing..."
apt install -y auditd audispd-plugins
systemctl enable auditd
systemctl start auditd
# Example audit rules: log user logins and file deletions
echo "-w /var/log/auth.log -p wa -k auth" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete" >> /etc/audit/audit.rules
systemctl restart auditd

# 3. Enable automatic updates and upgrade system packages
echo "Enabling automatic updates and upgrading packages..."
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
apt upgrade -y

# 4. Search for MP3 files
echo "Searching for MP3 files..."
find / -type f -name "*.mp3"

# 5. Disable SSH root login
echo "Disabling SSH root login..."
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart ssh

# 6. Disable Nginx if it's running
if systemctl is-active --quiet nginx; then
    echo "Disabling Nginx..."
    systemctl stop nginx
    systemctl disable nginx
else
    echo "Nginx is not running."
fi

# 7. Enforce strong password policies
echo "Configuring password policies..."
# Set minimum password length to 8, disable null password authentication
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs
echo "password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
echo "password required pam_unix.so nullok_secure" >> /etc/pam.d/common-password
# Set password expiration rules
chage --maxdays 90 --mindays 10 --warndays 7 $(logname)

# 8. Enforce login limits and account lockout policy
echo "Setting account lockout policy..."
echo "auth required pam_tally2.so deny=3 unlock_time=600 onerr=fail audit" >> /etc/pam.d/common-auth

# 9. Automatic logout for inactive sessions
echo "Setting automatic logout for inactive sessions..."
echo "export TMOUT=300" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile

# 10. Install X2Go (Remote Desktop)
echo "Installing X2Go for remote desktop access..."
apt install -y x2goserver x2goclient

# 11. Scan for rootkits
echo "Installing and scanning for rootkits..."
apt install -y chkrootkit
chkrootkit

# 12. Remove world-writable files
echo "Removing world-writable files..."
find / -xdev -type f -perm -0002 -exec chmod o-w {} +

# 13. Disable unused network protocols
echo "Disabling unused network protocols..."
for proto in dccp sctp rds tipc; do
    echo "blacklist $proto" >> /etc/modprobe.d/blacklist.conf
done

# 14. Set default file permissions with umask
echo "Setting default file permissions..."
echo "umask 027" >> /etc/profile

# 15. Lock the root account
echo "Locking the root account..."
passwd -l root

# 16. Configure time synchronization with chrony
echo "Installing and configuring time synchronization with chrony..."
apt install -y chrony
systemctl enable chrony
systemctl start chrony

# 17. Kernel hardening via sysctl
echo "Setting kernel hardening parameters..."
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -p

# 18. Secure /etc/passwd and /etc/shadow permissions
echo "Setting secure permissions for /etc/passwd and /etc/shadow..."
chmod 644 /etc/passwd
chmod 600 /etc/shadow

# 19. Restrict su command to wheel group
echo "Restricting su command to wheel group..."
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
usermod -aG wheel $(logname)

# 20. Set login banner message
echo "Setting login banner message..."
echo "Authorized access only. Unauthorized use is prohibited." > /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
systemctl restart ssh

# 21. Configure log rotation for system logs
echo "Configuring log rotation for system logs..."
apt install -y logrotate
logrotate -f /etc/logrotate.conf

# 22 Enable IPv4 TCP SYN Cookies
echo "Enabling IPv4 TCP SYN cookies..."
sysctl -w net.ipv4.tcp_syncookies=1
# Make the change persistent across reboots by adding it to /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
# Apply the changes immediately
sysctl --system

# 23 Disable IPv4 forwarding
echo "Disabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=0
# Make the change persistent across reboots by adding it to /etc/sysctl.conf
echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
# Apply the changes immediately
sysctl --system

# 24. Disable and remove FTP service if installed
echo "Checking for FTP services..."

# Check if vsftpd is installed
if dpkg -l | grep -q vsftpd; then
    echo "vsftpd is installed. Removing vsftpd..."
    systemctl stop vsftpd
    systemctl disable vsftpd
    apt remove -y vsftpd
fi

# Check if proftpd is installed
if dpkg -l | grep -q proftpd; then
    echo "proftpd is installed. Removing proftpd..."
    systemctl stop proftpd
    systemctl disable proftpd
    apt remove -y proftpd
fi

# Check if pure-ftpd is installed
if dpkg -l | grep -q pure-ftpd; then
    echo "pure-ftpd is installed. Removing pure-ftpd..."
    systemctl stop pure-ftpd
    systemctl disable pure-ftpd
    apt remove -y pure-ftpd
fi

echo "FTP services have been disabled or removed."

# 25. Remove netcat backdoor if found
echo "Checking for and removing netcat backdoor..."
# Check if nc.traditional is running or listening
if ss -tlnp | grep -q 'nc.traditional'; then
    echo "Netcat backdoor found, removing..."
    
    # Kill any running instances of nc.traditional
    sudo pkill -f nc.traditional
    
    # Check if nc.traditional is still available
    which nc.traditional &>/dev/null && sudo rm -f /usr/bin/nc.traditional
    
    # Remove any cron job entries for nc.traditional
    sudo sed -i '/\/usr\/bin\/nc.traditional/d' /etc/crontab
    
    echo "Netcat backdoor removed successfully."
else
    echo "No netcat backdoor found."
fi


echo "System hardening script completed successfully."

