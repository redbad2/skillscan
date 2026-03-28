#!/bin/bash
# Safe helper script for file counting
# This script provides basic file system utilities

show_help() {
    echo "Usage: $0 [command] [directory]"
    echo ""
    echo "Commands:"
    echo "  count    Count files in directory"
    echo "  size     Show total size of directory"
    echo "  help     Show this help message"
}

count_files() {
    local dir="${1:-.}"
    if [ -d "$dir" ]; then
        echo "Counting files in: $dir"
        find "$dir" -type f | wc -l
    else
        echo "Error: Directory not found: $dir"
        return 1
    fi
}

show_size() {
    local dir="${1:-.}"
    if [ -d "$dir" ]; then
        echo "Size of $dir:"
        du -sh "$dir" 2>/dev/null || echo "Unable to calculate size"
    else
        echo "Error: Directory not found: $dir"
        return 1
    fi
}

case "${1:-help}" in
    count)
        count_files "$2"
        ;;
    size)
        show_size "$2"
        ;;
    help|*)
        show_help
        ;;
esac
