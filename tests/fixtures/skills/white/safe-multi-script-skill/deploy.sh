#!/bin/bash
# Deployment helper script
# This script sets up the environment for deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

show_help() {
    cat << EOF
Usage: $0 [command]

Commands:
  setup      Setup the deployment environment
  cleanup    Clean temporary files
  version    Show version information
  help       Show this help message

Examples:
  $0 setup
  $0 cleanup
EOF
}

setup_environment() {
    echo "Setting up deployment environment..."
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        echo "  Python: $(python3 --version)"
    else
        echo "  Warning: Python3 not found"
    fi
    
    # Check for required tools
    for tool in curl jq; do
        if command -v "$tool" &> /dev/null; then
            echo "  $tool: OK"
        else
            echo "  $tool: not found (optional)"
        fi
    done
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p temp
    
    echo "Environment setup complete!"
}

cleanup() {
    echo "Cleaning temporary files..."
    
    rm -rf logs/*.log 2>/dev/null || true
    rm -rf temp/* 2>/dev/null || true
    
    echo "Cleanup complete!"
}

show_version() {
    echo "Deployment Helper Script v1.0.0"
    echo "Compatible with Python 3.9+"
}

case "${1:-help}" in
    setup)
        setup_environment
        ;;
    cleanup)
        cleanup
        ;;
    version)
        show_version
        ;;
    help|*)
        show_help
        ;;
esac
