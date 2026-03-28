# Safe English Skill

A simple skill that performs file scanning and reports findings.

## Description

This skill provides utilities to scan directories for specific file types and generate summary reports. It is designed for legitimate file management tasks.

## Usage

Call this skill to scan directories for specific file types.

### Requirements

- Python 3.8+
- Read access to target directories

### Example

```python
from scanner import scan
result = scan("/path/to/scan")
print(f"Found {result['count']} files")
```

## Permissions

This skill only requires read access to the directories being scanned. It does not modify any files or access network resources.

## Author

John Developer <john@example.com>

## Version

1.0.0
