#!/usr/bin/env python3
"""
Validate Freelancer Submission
==============================

This script validates that a freelancer's submission meets the contract requirements.

Usage:
    python scripts/validate_submission.py --type analyzer --path ./submission/
    python scripts/validate_submission.py --type semgrep-rules --path ./submission/rules.yaml
    python scripts/validate_submission.py --type ui-component --path ./submission/
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import List, Tuple

# Colors for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"


def print_success(msg: str):
    print(f"{Colors.GREEN}✓{Colors.END} {msg}")


def print_error(msg: str):
    print(f"{Colors.RED}✗{Colors.END} {msg}")


def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠{Colors.END} {msg}")


def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ{Colors.END} {msg}")


def validate_analyzer(path: str) -> Tuple[bool, List[str]]:
    """Validate an analyzer submission."""
    errors = []
    warnings = []
    
    path = Path(path)
    
    # Check for required files
    if not (path / "src").exists():
        errors.append("Missing src/ directory")
    
    # Find analyzer Python files
    analyzer_files = list(path.glob("src/*.py"))
    if not analyzer_files:
        errors.append("No Python files found in src/")
        return False, errors
    
    # Check each analyzer file
    for analyzer_file in analyzer_files:
        content = analyzer_file.read_text()
        
        # Check for BaseAnalyzer import
        if "BaseAnalyzer" not in content and "analyzer_interface" not in content:
            warnings.append(f"{analyzer_file.name}: Should import from analyzer_interface")
        
        # Check for required methods
        if "def analyze(" not in content:
            errors.append(f"{analyzer_file.name}: Missing analyze() method")
        
        if "def name(" not in content and "@property" not in content:
            warnings.append(f"{analyzer_file.name}: Should have a name property")
        
        # Check for AnalyzerResult usage
        if "AnalyzerResult" not in content:
            errors.append(f"{analyzer_file.name}: Must return AnalyzerResult")
    
    # Check for tests
    if not (path / "tests").exists():
        warnings.append("Missing tests/ directory")
    else:
        test_files = list((path / "tests").glob("test_*.py"))
        if not test_files:
            warnings.append("No test files found (should be test_*.py)")
    
    # Print warnings
    for warning in warnings:
        print_warning(warning)
    
    return len(errors) == 0, errors


def validate_semgrep_rules(path: str) -> Tuple[bool, List[str]]:
    """Validate Semgrep rules submission."""
    errors = []
    warnings = []
    
    path = Path(path)
    
    # Find YAML files
    if path.is_file():
        yaml_files = [path]
    else:
        yaml_files = list(path.glob("**/*.yaml")) + list(path.glob("**/*.yml"))
    
    if not yaml_files:
        errors.append("No YAML files found")
        return False, errors
    
    try:
        import yaml
    except ImportError:
        errors.append("PyYAML not installed - run: pip install pyyaml")
        return False, errors
    
    for yaml_file in yaml_files:
        try:
            content = yaml.safe_load(yaml_file.read_text())
        except yaml.YAMLError as e:
            errors.append(f"{yaml_file.name}: Invalid YAML - {e}")
            continue
        
        if not content:
            warnings.append(f"{yaml_file.name}: Empty file")
            continue
        
        rules = content.get("rules", [])
        if not rules:
            warnings.append(f"{yaml_file.name}: No rules found")
            continue
        
        for rule in rules:
            rule_id = rule.get("id", "unknown")
            
            # Check required fields
            if not rule.get("id"):
                errors.append(f"Rule missing 'id' field")
            
            if not rule.get("message"):
                errors.append(f"Rule {rule_id}: Missing 'message' field")
            
            if not rule.get("severity"):
                warnings.append(f"Rule {rule_id}: Missing 'severity' field")
            
            if not rule.get("languages"):
                errors.append(f"Rule {rule_id}: Missing 'languages' field")
            
            # Check for pattern
            has_pattern = any(
                rule.get(key) for key in ["pattern", "patterns", "pattern-either"]
            )
            if not has_pattern:
                errors.append(f"Rule {rule_id}: Missing pattern definition")
            
            # Check metadata
            metadata = rule.get("metadata", {})
            if not metadata.get("category"):
                warnings.append(f"Rule {rule_id}: Missing metadata.category")
            
            # Naming convention
            if rule.get("id") and not rule["id"].startswith("atlas-"):
                warnings.append(
                    f"Rule {rule_id}: Should follow naming convention 'atlas-*'"
                )
    
    for warning in warnings:
        print_warning(warning)
    
    return len(errors) == 0, errors


def validate_ui_component(path: str) -> Tuple[bool, List[str]]:
    """Validate UI component submission."""
    errors = []
    warnings = []
    
    path = Path(path)
    
    # Check for component files
    jsx_files = list(path.glob("**/*.jsx")) + list(path.glob("**/*.tsx"))
    if not jsx_files:
        errors.append("No JSX/TSX component files found")
        return False, errors
    
    for jsx_file in jsx_files:
        content = jsx_file.read_text()
        
        # Check for React import
        if "import React" not in content and "from 'react'" not in content:
            warnings.append(f"{jsx_file.name}: Should import React")
        
        # Check for export
        if "export" not in content:
            errors.append(f"{jsx_file.name}: No exports found")
        
        # Check for props destructuring (good practice)
        if "props" in content and "{ " not in content:
            warnings.append(f"{jsx_file.name}: Consider destructuring props")
    
    # Check for styles
    scss_files = list(path.glob("**/*.scss")) + list(path.glob("**/*.css"))
    if not scss_files:
        warnings.append("No style files found (*.scss or *.css)")
    
    for warning in warnings:
        print_warning(warning)
    
    return len(errors) == 0, errors


def validate_llm_prompts(path: str) -> Tuple[bool, List[str]]:
    """Validate LLM prompt submission."""
    errors = []
    warnings = []
    
    path = Path(path)
    
    # Find YAML files
    if path.is_file():
        yaml_files = [path]
    else:
        yaml_files = list(path.glob("**/*.yaml")) + list(path.glob("**/*.yml"))
    
    if not yaml_files:
        errors.append("No YAML files found")
        return False, errors
    
    try:
        import yaml
    except ImportError:
        errors.append("PyYAML not installed - run: pip install pyyaml")
        return False, errors
    
    for yaml_file in yaml_files:
        try:
            content = yaml.safe_load(yaml_file.read_text())
        except yaml.YAMLError as e:
            errors.append(f"{yaml_file.name}: Invalid YAML - {e}")
            continue
        
        if not content:
            warnings.append(f"{yaml_file.name}: Empty file")
            continue
        
        # Check required fields
        if not content.get("name"):
            errors.append(f"{yaml_file.name}: Missing 'name' field")
        
        if not content.get("system_prompt"):
            errors.append(f"{yaml_file.name}: Missing 'system_prompt' field")
        
        if not content.get("user_prompt"):
            errors.append(f"{yaml_file.name}: Missing 'user_prompt' field")
        
        # Check for placeholders
        user_prompt = content.get("user_prompt", "")
        if "{" not in user_prompt:
            warnings.append(
                f"{yaml_file.name}: user_prompt has no placeholders ({{variable}})"
            )
        
        # Check for output format specification
        if "json" not in user_prompt.lower() and "format" not in user_prompt.lower():
            warnings.append(
                f"{yaml_file.name}: Consider specifying output format in user_prompt"
            )
    
    for warning in warnings:
        print_warning(warning)
    
    return len(errors) == 0, errors


def main():
    parser = argparse.ArgumentParser(
        description="Validate freelancer submission against contract"
    )
    parser.add_argument(
        "--type",
        required=True,
        choices=["analyzer", "semgrep-rules", "ui-component", "llm-prompts"],
        help="Type of submission to validate",
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to submission directory or file",
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print_error(f"Path not found: {args.path}")
        sys.exit(1)
    
    print(f"\n{Colors.BLUE}Validating {args.type} submission...{Colors.END}\n")
    print(f"Path: {args.path}\n")
    
    validators = {
        "analyzer": validate_analyzer,
        "semgrep-rules": validate_semgrep_rules,
        "ui-component": validate_ui_component,
        "llm-prompts": validate_llm_prompts,
    }
    
    validator = validators[args.type]
    success, errors = validator(args.path)
    
    print()
    
    if errors:
        print(f"{Colors.RED}Errors found:{Colors.END}")
        for error in errors:
            print_error(error)
        print()
    
    if success:
        print(f"{Colors.GREEN}✅ Validation passed!{Colors.END}")
        print("Submission meets contract requirements.")
        sys.exit(0)
    else:
        print(f"{Colors.RED}❌ Validation failed!{Colors.END}")
        print("Please fix the errors above before submitting.")
        sys.exit(1)


if __name__ == "__main__":
    main()

