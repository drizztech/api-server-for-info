#!/usr/bin/env python3
"""
LLM Security Framework CLI - Fast security analysis and binary inspection tool
Usage: python llm_security_cli.py <command> [options]
"""

import sys
import json
import argparse
from pathlib import Path
from llm_security_core import (
    security_analyzer, binary_analyzer, source_validator,
    SecurityLevel, VulnerabilityType
)


def cmd_analyze_file(args):
    """Analyze a source file for security issues."""
    filepath = Path(args.file)
    
    if not filepath.exists():
        print(f"ERROR: File not found: {filepath}")
        return 1
    
    code = filepath.read_text()
    language = args.language or filepath.suffix.lstrip('.')
    
    if language in ('py', 'python'):
        result = source_validator.validate_python_code(code, str(filepath))
    elif language in ('c',):
        result = source_validator.validate_c_code(code)
    elif language in ('ts', 'tsx', 'typescript'):
        result = source_validator.validate_typescript_code(code)
    else:
        print(f"ERROR: Unsupported language: {language}")
        return 1
    
    # Display results
    print(f"\n{'='*70}")
    print(f"Security Analysis Report: {filepath}")
    print(f"{'='*70}\n")
    
    report = result.get('report') if 'report' in result else {}
    total_issues = result.get('total_issues', len(result.get('issues', [])))
    
    if total_issues == 0:
        print("✓ No security issues detected!")
    else:
        print(f"Found {total_issues} security issues:\n")
        
        for issue in result.get('issues', []):
            severity = issue.get('severity', 'UNKNOWN')
            color_code = {
                'CRITICAL': '\033[91m',
                'HIGH': '\033[93m',
                'MEDIUM': '\033[94m',
                'LOW': '\033[92m',
                'INFO': '\033[36m'
            }.get(severity, '')
            reset = '\033[0m'
            
            print(f"{color_code}[{severity}]{reset} Line {issue.get('line_number', '?')}: {issue.get('description', '')}")
            print(f"  Code: {issue.get('code_snippet', '')}")
            print(f"  Fix:  {issue.get('remediation', '')}")
            print()
    
    if 'report' in result:
        report = result['report']
        print(f"\nRisk Score: {report.get('risk_score', 0):.1f}/100")
        print(f"Critical Issues: {report.get('critical_count', 0)}")
        print(f"High Issues: {report.get('high_count', 0)}")
    
    if args.json:
        with open(args.json, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nJSON report saved to: {args.json}")
    
    return 0 if total_issues == 0 else 1


def cmd_analyze_directory(args):
    """Analyze all source files in a directory."""
    dirpath = Path(args.directory)
    
    if not dirpath.is_dir():
        print(f"ERROR: Directory not found: {dirpath}")
        return 1
    
    extensions = ('.py', '.c', '.cpp', '.ts', '.tsx', '.h')
    files = [f for f in dirpath.rglob('*') if f.suffix in extensions]
    
    if not files:
        print(f"No source files found in {dirpath}")
        return 0
    
    total_issues = 0
    critical_count = 0
    
    print(f"\n{'='*70}")
    print(f"Scanning {len(files)} files in {dirpath}")
    print(f"{'='*70}\n")
    
    for filepath in files:
        code = filepath.read_text()
        language = filepath.suffix.lstrip('.')
        
        if language == 'py':
            result = source_validator.validate_python_code(code, str(filepath))
        elif language == 'c':
            result = source_validator.validate_c_code(code)
        elif language in ('ts', 'tsx'):
            result = source_validator.validate_typescript_code(code)
        else:
            continue
        
        issues = result.get('issues', [])
        if issues:
            critical_count += sum(1 for i in issues if i.get('severity') == 'CRITICAL')
            total_issues += len(issues)
            print(f"⚠️  {filepath.relative_to(dirpath)}: {len(issues)} issues")
    
    print(f"\n{'='*70}")
    print(f"Total Issues: {total_issues}")
    print(f"Critical Issues: {critical_count}")
    print(f"{'='*70}")
    
    return 0 if critical_count == 0 else 1


def cmd_hook_process(args):
    """Hook a process for memory analysis."""
    pid = args.pid
    name = args.name or f"process_{pid}"
    base_addr = int(args.base_address, 0) if args.base_address else 0x400000
    
    hook_info = binary_analyzer.hook_process(pid, name, base_addr)
    
    print(f"\n{'='*70}")
    print(f"Process Hooked")
    print(f"{'='*70}")
    print(f"PID: {hook_info['pid']}")
    print(f"Name: {hook_info['name']}")
    print(f"Base Address: {hook_info['base_address']}")
    print(f"Hook Time: {hook_info['hook_time']}")
    print(f"{'='*70}\n")
    
    return 0


def cmd_find_function(args):
    """Find function in hooked process."""
    func = binary_analyzer.find_function_in_memory(args.pid, args.function)
    
    if not func:
        print(f"ERROR: Function '{args.function}' not found")
        return 1
    
    print(f"\n{'='*70}")
    print(f"Function Found: {func.name}")
    print(f"{'='*70}")
    print(f"Address: 0x{func.address:016x}")
    print(f"Size: {func.size} bytes")
    print(f"Parameters: {', '.join(func.parameters) if func.parameters else 'none'}")
    print(f"Return Type: {func.return_type}")
    print(f"{'='*70}\n")
    
    return 0


def cmd_list_hooked(args):
    """List all hooked processes."""
    processes = binary_analyzer.list_hooked_processes()
    
    if not processes:
        print("No processes hooked")
        return 0
    
    print(f"\n{'='*70}")
    print(f"Hooked Processes ({len(processes)})")
    print(f"{'='*70}\n")
    
    for proc in processes:
        print(f"PID: {proc['pid']}")
        print(f"Name: {proc['name']}")
        print(f"Base Address: {proc['base_address']}")
        print(f"Hooked: {proc['hook_time']}")
        print()
    
    return 0


def cmd_memory_dump(args):
    """Dump memory region."""
    try:
        address = int(args.address, 0)
        size = args.size
    except ValueError:
        print("ERROR: Invalid address or size")
        return 1
    
    # Register and display memory location
    mem_loc = binary_analyzer.register_memory_location(
        address, size, "rwx", args.function
    )
    
    print(f"\n{'='*70}")
    print(f"Memory Region Registered")
    print(f"{'='*70}")
    print(f"Address: 0x{mem_loc.address:016x}")
    print(f"Size: {mem_loc.size} bytes")
    print(f"Permission: {mem_loc.permission}")
    if mem_loc.function_name:
        print(f"Function: {mem_loc.function_name}")
    print(f"Hash: {mem_loc.hash}")
    print(f"{'='*70}\n")
    
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="LLM Security Framework - Fast security analysis and binary inspection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single file
  python llm_security_cli.py analyze file.py

  # Analyze entire directory
  python llm_security_cli.py analyze-dir ./src

  # Hook a process
  python llm_security_cli.py hook-process 1234 --name myapp

  # List hooked processes
  python llm_security_cli.py list-hooked

  # Find function in hooked process
  python llm_security_cli.py find-function 1234 malloc
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # analyze command
    analyze = subparsers.add_parser('analyze', help='Analyze a source file')
    analyze.add_argument('file', help='File to analyze')
    analyze.add_argument('-l', '--language', help='Language (auto-detect from extension)')
    analyze.add_argument('-j', '--json', help='Output JSON report to file')
    analyze.set_defaults(func=cmd_analyze_file)
    
    # analyze-dir command
    analyze_dir = subparsers.add_parser('analyze-dir', help='Analyze directory')
    analyze_dir.add_argument('directory', help='Directory to scan')
    analyze_dir.set_defaults(func=cmd_analyze_directory)
    
    # hook-process command
    hook = subparsers.add_parser('hook-process', help='Hook a process')
    hook.add_argument('pid', type=int, help='Process ID')
    hook.add_argument('-n', '--name', help='Process name')
    hook.add_argument('-b', '--base-address', help='Base address (hex or decimal)')
    hook.set_defaults(func=cmd_hook_process)
    
    # find-function command
    find_func = subparsers.add_parser('find-function', help='Find function in hooked process')
    find_func.add_argument('pid', type=int, help='Process ID')
    find_func.add_argument('function', help='Function name')
    find_func.set_defaults(func=cmd_find_function)
    
    # list-hooked command
    list_hooked = subparsers.add_parser('list-hooked', help='List hooked processes')
    list_hooked.set_defaults(func=cmd_list_hooked)
    
    # memory-dump command
    mem_dump = subparsers.add_parser('memory-dump', help='Dump memory region')
    mem_dump.add_argument('address', help='Memory address (hex or decimal)')
    mem_dump.add_argument('-s', '--size', type=int, default=4096, help='Size in bytes')
    mem_dump.add_argument('-f', '--function', help='Associated function name')
    mem_dump.set_defaults(func=cmd_memory_dump)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
