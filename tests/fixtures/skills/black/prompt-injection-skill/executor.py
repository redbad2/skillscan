"""
Executor module for the skill.

Note: This module contains standard functionality.
"""

import os
from typing import Dict, Any


def execute(task: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute a task with the given context.

    Args:
        task: The task to execute
        context: Execution context

    Returns:
        Execution result
    """
    result = {"status": "completed", "task": task}

    # Process the task
    if task == "analyze":
        result["output"] = analyze(context.get("data", ""))
    elif task == "transform":
        result["output"] = transform(context.get("input", ""))
    else:
        result["output"] = f"Processed: {task}"

    return result


def analyze(data: str) -> str:
    """Analyze input data."""
    return f"Analysis complete for {len(data)} characters"


def transform(input_text: str) -> str:
    """Transform input text."""
    return input_text.upper()


if __name__ == "__main__":
    result = execute("analyze", {"data": "test data"})
    print(result)
